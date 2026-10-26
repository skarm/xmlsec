package saml_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/evidence/collect"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/idp"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/saml/sp"
	"github.com/skarm/xmlsec/saml/state"
	"github.com/skarm/xmlsec/transform"
)

// BenchmarkLogin includes SP initiation, IdP verification and issuance, and SP consumption.
func BenchmarkLogin(b *testing.B) {
	s := setup(b)
	b.ReportAllocs()

	for b.Loop() {
		_, req, browser := begin(b, s, metadata.HTTPRedirect)

		issued, err := s.idp.Issue(b.Context(), req, auth(), testcert.Now().Add(2*time.Second))
		if err != nil {
			b.Fatal(err)
		}

		if _, err := s.sp.ConsumePOST(b.Context(), postBody(b, issued), sp.ConsumeOptions{At: testcert.Now().Add(3 * time.Second), BrowserBinding: browser}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSPBegin(b *testing.B) {
	s := setup(b)
	browser := make([]byte, 32)
	opts := sp.BeginOptions{IDP: idpID, Binding: metadata.HTTPRedirect, BrowserBinding: browser, At: testcert.Now()}

	b.ReportAllocs()
	pending := 0

	for b.Loop() {
		// Keep the real bounded store, but renew fixtures outside the timer
		// before it fills so long benchmarks do not measure ErrCapacity.
		if pending == 4096 {
			b.StopTimer()
			s = setup(b)
			pending = 0
			b.StartTimer()
		}

		if _, err := s.sp.Begin(b.Context(), opts); err != nil {
			b.Fatal(err)
		}

		pending++
	}
}

func BenchmarkIDPAcceptRedirect(b *testing.B) {
	s := setup(b)
	out, _, _ := begin(b, s, metadata.HTTPRedirect)
	query := out.RawQuery()

	b.ReportAllocs()

	for b.Loop() {
		if _, err := s.idp.AcceptRedirect(b.Context(), query, spID, ssoRedirect, testcert.Now()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIDPIssue(b *testing.B) {
	s := setup(b)
	b.ReportAllocs()

	for b.Loop() {
		b.StopTimer()
		_, request, _ := begin(b, s, metadata.HTTPRedirect)
		b.StartTimer()

		if _, err := s.idp.Issue(b.Context(), request, auth(), testcert.Now().Add(2*time.Second)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSPConsumePOST(b *testing.B) {
	s := setup(b)
	b.ReportAllocs()

	for b.Loop() {
		b.StopTimer()
		_, request, browser := begin(b, s, metadata.HTTPRedirect)

		issued, err := s.idp.Issue(b.Context(), request, auth(), testcert.Now().Add(2*time.Second))
		if err != nil {
			b.Fatal(err)
		}

		form := postBody(b, issued)

		b.StartTimer()

		if _, err := s.sp.ConsumePOST(b.Context(), form, sp.ConsumeOptions{At: testcert.Now().Add(3 * time.Second), BrowserBinding: browser}); err != nil {
			b.Fatal(err)
		}
	}
}

// TestSustainedLoad is an opt-in offline soak. The same shared objects survive
// every phase. Latencies use bounded logarithmic buckets (at most 2.2% rounding),
// and ten-second memory sampling is not an allocation profile. Run one scenario
// per process to attribute process CPU/RSS with the operating system tools.
func TestSustainedLoad(t *testing.T) {
	duration, err := time.ParseDuration(os.Getenv("XMLSEC_SOAK_DURATION"))
	if os.Getenv("XMLSEC_SOAK_DURATION") == "" {
		t.Skip("set XMLSEC_SOAK_DURATION and XMLSEC_SOAK_SCENARIO for offline load")
	}
	if err != nil || duration <= 0 {
		t.Fatal("invalid duration")
	}
	scenario := os.Getenv("XMLSEC_SOAK_SCENARIO")
	t.Attr("soak.scenario", scenario)
	t.Attr("soak.duration", duration.String())
	var operation func(context.Context, uint64) error
	var sizes func() any
	switch scenario {
	case "transform":
		operation = soakTransform(t)
	case "http":
		operation = soakHTTP(t)
	case "saml":
		operation, sizes = soakSAML(t)
	default:
		t.Fatal("scenario must be transform, http or saml")
	}
	path := os.Getenv("XMLSEC_SOAK_OUT")
	if path == "" {
		path = filepath.Join(t.ArtifactDir(), "soak.jsonl")
	}
	output, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := output.Close(); err != nil {
			t.Error(err)
		}
	})
	t.Log("soak report:", path)

	encoder := json.NewEncoder(output)
	original := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(original)
	runtime.GC()
	var initial runtime.MemStats
	runtime.ReadMemStats(&initial)
	goroutines := runtime.NumGoroutine()
	var serial atomic.Uint64
	for index, phase := range []struct {
		procs   int
		workers int
	}{{1, 1}, {2, 4}, {4, 12}, {2, 4}} {
		runtime.GOMAXPROCS(phase.procs)
		ctx, cancel := context.WithTimeout(t.Context(), duration/4)
		start := time.Now()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		cpuBefore := soakCPU()
		gcBefore := soakPauseSnapshot()
		var hist [2048]atomic.Uint64
		var completed, failed, expected atomic.Uint64
		var wg sync.WaitGroup
		var first atomic.Pointer[error]
		for range phase.workers {
			wg.Go(func() {
				for ctx.Err() == nil {
					n := serial.Add(1)
					began := time.Now()
					e := operation(ctx, n)
					if e != nil && ctx.Err() != nil && (errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded)) {
						return
					}
					if e != nil {
						if scenario == "http" && n%128 == 0 && errors.Is(e, evidence.ErrResource) {
							expected.Add(1)
						} else {
							failed.Add(1)
							first.CompareAndSwap(nil, &e)
						}
					} else {
						completed.Add(1)
					}
					bucket := min(len(hist)-1, max(0, int(math.Log2(float64(max(1, time.Since(began).Nanoseconds())))*32)))
					hist[bucket].Add(1)
				}
			})
		}
		peak := before.HeapAlloc
		ticker := time.NewTicker(10 * time.Second)
		active := true
		for active {
			select {
			case <-ctx.Done():
				active = false
			case <-ticker.C:
				var sample runtime.MemStats
				runtime.ReadMemStats(&sample)
				peak = max(peak, sample.HeapAlloc)
				t.Logf("soak %s phase=%d elapsed=%s completed=%d heap=%d goroutines=%d", scenario, index, time.Since(start).Round(time.Second), completed.Load(), sample.HeapAlloc, runtime.NumGoroutine())
			}
		}
		ticker.Stop()
		canceled := time.Now()
		cancel()
		wg.Wait()
		drain := time.Since(canceled)
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		peak = max(peak, after.HeapAlloc)
		count := completed.Load() + failed.Load() + expected.Load()
		percentile := func(p uint64) float64 {
			target := (count*p + 99) / 100
			var sum uint64
			for i := range hist {
				sum += hist[i].Load()
				if sum >= target {
					return math.Exp2(float64(i+1)/32) / 1000
				}
			}
			return 0
		}
		result := map[string]any{"scenario": scenario, "phase": index, "procs": phase.procs, "workers": phase.workers, "seconds": time.Since(start).Seconds(), "completed": completed.Load(), "errors": failed.Load(), "expected_dependency_errors": expected.Load(), "ops_second": float64(completed.Load()) / time.Since(start).Seconds(), "p50_us": percentile(50), "p95_us": percentile(95), "p99_us": percentile(99), "allocated_bytes": after.TotalAlloc - before.TotalAlloc, "allocated_bytes_second": float64(after.TotalAlloc-before.TotalAlloc) / time.Since(start).Seconds(), "heap_current": after.HeapAlloc, "heap_sampled_peak": peak, "heap_sys": after.HeapSys, "cpu_runtime_seconds": soakCPU() - cpuBefore, "gc_pause_ms": float64(after.PauseTotalNs-before.PauseTotalNs) / 1e6, "gcs": after.NumGC - before.NumGC, "goroutines": runtime.NumGoroutine(), "cancel_drain_ms": float64(drain) / 1e6}
		result["gc_pause_percentiles_ms"] = soakPausePercentiles(gcBefore, soakPauseSnapshot())
		if sizes != nil {
			result["store_entries"] = sizes()
		}
		if err := encoder.Encode(result); err != nil {
			t.Fatal(err)
		}
		t.Logf("phase result: %v", result)
		if e := first.Load(); e != nil {
			t.Fatal(*e)
		}
	}
	runtime.GC()
	var final runtime.MemStats
	runtime.ReadMemStats(&final)
	result := map[string]any{"post_gc_heap": final.HeapAlloc, "initial_post_gc_heap": initial.HeapAlloc, "goroutines_before": goroutines, "goroutines_after": runtime.NumGoroutine(), "operations": serial.Load()}
	if err := encoder.Encode(result); err != nil {
		t.Fatal(err)
	}
	t.Logf("final result: %v", result)
	runtime.KeepAlive(operation)
	runtime.KeepAlive(sizes)
}

func soakCPU() float64 {
	samples := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}, {Name: "/cpu/classes/idle:cpu-seconds"}}
	metrics.Read(samples)
	return samples[0].Value.Float64() - samples[1].Value.Float64()
}

func soakTransform(t *testing.T) func(context.Context, uint64) error {
	t.Helper()
	engine, err := transform.NewEngine(transform.Config{})
	if err != nil {
		t.Fatal(err)
	}
	parse := func(n int) *transform.Document {
		d, e := engine.Parse(t.Context(), []byte("<r>"+strings.Repeat(`<item a="2">text</item>`, n)+"</r>"))
		if e != nil {
			t.Fatal(e)
		}
		return d
	}
	small, large := parse(1024), parse(8192)
	query, err := engine.CompileXPath(t.Context(), `sum(/r/item/@a)`, transform.XPathOptions{Version: transform.XPath31})
	if err != nil {
		t.Fatal(err)
	}
	sheet, err := engine.CompileXSLT(t.Context(), []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out><xsl:for-each select="r/item"><v><xsl:value-of select="@a"/></v></xsl:for-each></out></xsl:template></xsl:stylesheet>`), transform.XSLTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, n uint64) error {
		input := small
		if n%128 == 0 {
			input = large
		}
		if n%2 == 0 {
			_, e := query.Evaluate(ctx, input, transform.XPathContext{})
			return e
		}
		dst := io.Discard
		if n%63 == 0 {
			dst = &soakSlowWriter{ctx: ctx}
		}
		_, e := sheet.Write(ctx, dst, input, transform.XSLTContext{})
		return e
	}
}

type soakSlowWriter struct {
	ctx     context.Context
	delayed bool
}

func (w *soakSlowWriter) Write(p []byte) (int, error) {
	if w.delayed {
		return len(p), w.ctx.Err()
	}
	w.delayed = true
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case <-w.ctx.Done():
		return 0, w.ctx.Err()
	case <-timer.C:
		return len(p), nil
	}
}

func soakHTTP(t *testing.T) func(context.Context, uint64) error {
	t.Helper()
	small, large := bytes.Repeat([]byte{0x37}, 4096), bytes.Repeat([]byte{0x59}, 1<<20)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/error":
			http.Error(w, "dependency failure", http.StatusServiceUnavailable)
		case "/large":
			_, _ = w.Write(large)
		case "/slow":
			for range 16 {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(time.Millisecond):
				}
				if _, e := w.Write(small); e != nil {
					return
				}
			}
		default:
			_, _ = w.Write(small)
		}
	}))
	// This soak measures real socket traffic and transport connection limits.
	server.Start()
	transport := &http.Transport{MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4}
	t.Cleanup(transport.CloseIdleConnections)
	uris := []string{server.URL + "/small", server.URL + "/large", server.URL + "/slow", server.URL + "/error"}
	collector, err := collect.NewHTTP(collect.Config{Client: &http.Client{Transport: transport}, AllowedURIs: uris, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, n uint64) error {
		u := uris[0]
		switch {
		case n%128 == 0:
			u = uris[3]
		case n%64 == 0:
			u = uris[2]
		case n%32 == 0:
			u = uris[1]
		}
		observations, e := collector.Collect(ctx, []collect.Request{{Kind: evidence.CRL, URI: u}})
		if e == nil && (len(observations) != 1 || observations[0].Size() == 0) {
			return errors.New("empty observation")
		}
		return e
	}
}

func soakSAML(t testing.TB) (func(context.Context, uint64) error, func() any) {
	t.Helper()
	s := setup(t)
	requests, err := state.NewMemoryStore(state.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sr, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ir, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s.sp, err = sp.NewServiceProvider(sp.Config{EntityID: spID, Metadata: s.registry, Signing: protocol.SigningKey{Key: s.cert.LeafKey, CertificateDER: s.cert.Leaf.Raw}, Requests: requests, Replay: sr, RequestLifetime: 5 * time.Second, Limits: protocol.Limits{MaxMessageAge: time.Second, MaxAssertionLifetime: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	config := s.idpConfig
	config.Replay = ir
	config.AssertionLifetime = 5 * time.Second
	config.Limits = protocol.Limits{MaxMessageAge: time.Second, MaxAssertionLifetime: 5 * time.Second}
	s.idp, err = idp.NewIdentityProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	browser := bytes.Repeat([]byte{0xa7}, 32)
	return func(ctx context.Context, n uint64) error {
			at := testcert.Now().Add(time.Since(start)).Truncate(time.Second)
			out, e := s.sp.Begin(ctx, sp.BeginOptions{IDP: idpID, Binding: metadata.HTTPRedirect, BrowserBinding: browser, At: at, NameIDFormat: protocol.NameIDPersistent, RequestedContexts: []string{authClass}, ForceAuthn: true, AllowCreateNameID: true})
			if e != nil {
				return e
			}
			request, e := s.idp.AcceptRedirect(ctx, out.RawQuery(), spID, ssoRedirect, at)
			if e != nil {
				return e
			}
			authentication := auth()
			authentication.AuthnInstant = at
			if n%64 == 0 {
				authentication.Attributes = []protocol.Attribute{{Name: "large", Values: []string{strings.Repeat("x", 4096)}}}
			}
			issued, e := s.idp.Issue(ctx, request, authentication, at)
			if e != nil {
				return e
			}
			var form bytes.Buffer
			if _, e = issued.WritePOST(ctx, &form); e != nil {
				return e
			}
			_, e = s.sp.ConsumePOST(ctx, form.Bytes(), sp.ConsumeOptions{At: at, BrowserBinding: browser})
			return e
		}, func() any {
			return map[string]int{"pending": requests.Len(), "sp_replay": sr.Len(), "idp_replay": ir.Len()}
		}
}

// BenchmarkSPBeginPOST measures signed POST request creation, including pending state.
func BenchmarkSPBeginPOST(b *testing.B) {
	s := setup(b)
	browser := make([]byte, 32)
	options := sp.BeginOptions{IDP: idpID, Binding: metadata.HTTPPost, BrowserBinding: browser, At: testcert.Now()}
	b.ReportAllocs()
	pending := 0
	for b.Loop() {
		if pending == 4096 {
			b.StopTimer()
			s = setup(b)
			pending = 0
			b.StartTimer()
		}
		if _, err := s.sp.Begin(b.Context(), options); err != nil {
			b.Fatal(err)
		}
		pending++
	}
}

// BenchmarkLoginParallel covers shared metadata, request/replay stores and compression.
func BenchmarkLoginParallel(b *testing.B) {
	operation, _ := soakSAML(b)
	var serial atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := operation(b.Context(), serial.Add(1)); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkIssuedPOST compares collection with direct output using the same
// immutable signed message and limits. Fixture signing is outside the timer.
func BenchmarkIssuedPOST(b *testing.B) {
	for _, size := range []int{0, 512 << 10} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			s := setup(b)
			out, request, _ := begin(b, s, metadata.HTTPRedirect)
			authentication := auth()
			if size > 0 {
				authentication.Attributes = make([]protocol.Attribute, 64)
				for i := range authentication.Attributes {
					authentication.Attributes[i] = protocol.Attribute{Name: fmt.Sprintf("a%d", i), Values: []string{strings.Repeat("x", 4096), strings.Repeat("é", 2048)}}
				}
			}
			issued, err := s.idp.Issue(b.Context(), request, authentication, testcert.Now().Add(2*time.Second))
			if err != nil {
				b.Fatal(err)
			}
			relay := out.RelayState()
			for name, write := range map[string]func() error{
				"URLBuffer": func() error {
					_, err := binding.EncodePOST(b.Context(), issued.Document(), binding.Response, &relay, binding.POSTLimits{})
					return err
				},
				"URLWriter": func() error { _, err := issued.WritePOST(b.Context(), io.Discard); return err },
				"HTMLBuffer": func() error {
					_, err := binding.RenderPOSTForm(b.Context(), issued.Destination(), issued.Document(), binding.Response, &relay, binding.POSTLimits{})
					return err
				},
				"HTMLWriter": func() error { _, err := issued.WritePOSTForm(b.Context(), io.Discard); return err },
			} {
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						if err := write(); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func soakPauseSnapshot() metrics.Float64Histogram {
	sample := []metrics.Sample{{Name: "/gc/pauses:seconds"}}
	metrics.Read(sample)
	value := sample[0].Value.Float64Histogram()
	return metrics.Float64Histogram{Counts: append([]uint64(nil), value.Counts...), Buckets: append([]float64(nil), value.Buckets...)}
}

func soakPausePercentiles(before, after metrics.Float64Histogram) map[string]float64 {
	counts := make([]uint64, len(after.Counts))
	var total uint64
	for i := range counts {
		counts[i] = after.Counts[i] - before.Counts[i]
		total += counts[i]
	}
	quantile := func(percent uint64) float64 {
		if total == 0 {
			return 0
		}
		var sum uint64
		for i, count := range counts {
			sum += count
			if sum >= (total*percent+99)/100 {
				return after.Buckets[i+1] * 1000
			}
		}
		return 0
	}
	return map[string]float64{"p50": quantile(50), "p95": quantile(95), "p99": quantile(99)}
}

// BenchmarkSoakInstrumentation isolates the latency/count bookkeeping around
// the same complete login. Runtime memory sampling and OS RSS collection are
// outside this benchmark and their overhead is reported separately.
func BenchmarkSoakInstrumentation(b *testing.B) {
	for _, instrumented := range []bool{false, true} {
		b.Run(strconv.FormatBool(instrumented), func(b *testing.B) {
			operation, _ := soakSAML(b)
			var serial uint64
			var completed atomic.Uint64
			var histogram [2048]atomic.Uint64
			b.ReportAllocs()
			for b.Loop() {
				serial++
				if !instrumented {
					if err := operation(b.Context(), serial); err != nil {
						b.Fatal(err)
					}
					continue
				}
				began := time.Now()
				if err := operation(b.Context(), serial); err != nil {
					b.Fatal(err)
				}
				completed.Add(1)
				bucket := min(len(histogram)-1, max(0, int(math.Log2(float64(max(1, time.Since(began).Nanoseconds())))*32)))
				histogram[bucket].Add(1)
			}
		})
	}
}
