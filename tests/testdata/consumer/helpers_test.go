package consumer_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"runtime"
	"runtime/metrics"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform"
)

func newEngine(t *testing.T, config transform.Config) *transform.Engine {
	t.Helper()
	e, err := transform.NewEngine(config)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func compileSheet(t *testing.T, e *transform.Engine, body string) *transform.Stylesheet {
	t.Helper()
	s, err := e.CompileXSLT(t.Context(), []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:f="urn:functions" exclude-result-prefixes="xs f" version="3.0">`+body+`</xsl:stylesheet>`), transform.XSLTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type gatedInput struct {
	first *strings.Reader
	rest  *strings.Reader
	ready func() bool
	early bool
}

func (r *gatedInput) Read(p []byte) (int, error) {
	if r.first.Len() > 0 {
		return r.first.Read(p)
	}
	if !r.ready() {
		r.early = true
		return 0, errors.New("read beyond first record before producing output")
	}
	return r.rest.Read(p)
}

type prefixFailure struct {
	remaining int
	failure   error
}

func (w *prefixFailure) Write(p []byte) (int, error) {
	n := min(len(p), w.remaining)
	w.remaining -= n
	if n < len(p) {
		return n, w.failure
	}
	return n, nil
}

type readFunc func([]byte) (int, error)

func (f readFunc) Read(p []byte) (int, error) { return f(p) }

type trackedInput struct {
	io.Reader
	close func() error
}

func (r *trackedInput) Close() error { return r.close() }

type streamingSink struct {
	bytes      int
	largest    int
	afterWrite func()
}

func (w *streamingSink) Write(p []byte) (int, error) {
	w.bytes += len(p)
	w.largest = max(w.largest, len(p))
	if w.afterWrite != nil {
		w.afterWrite()
	}
	return len(p), nil
}

type streamingInput struct {
	source io.Reader
	bytes  int
}

func (r *streamingInput) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.bytes += n
	return n, err
}

// allocatedDuring excludes fixture construction and tolerates background runtime
// work by taking the smallest of three complete serializations.
func allocatedDuring(t *testing.T, run func() error) uint64 {
	t.Helper()
	allocated := ^uint64(0)
	for range 3 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		if err := run(); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)
	}
	return allocated
}

// retainedHeapDuring keeps only the returned value alive across two collections.
// Sources must be constructed inside run, without captured references to them.
func retainedHeapDuring(t *testing.T, run func() any) int64 {
	t.Helper()
	runtime.GC()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	result := run()
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(run)
	runtime.KeepAlive(result)
	return int64(after.HeapAlloc) - int64(before.HeapAlloc)
}

// peakHeapDuring samples the same live-and-unswept object bytes as HeapAlloc,
// including a final sample. runtime/metrics avoids ReadMemStats's stop-the-world
// pause on every sample. It measures observed Go heap growth, not RSS or an
// exact live-object maximum. Keep memory tests sequential: parallel tests run
// only after them so unrelated allocations cannot contaminate the measurements.
func peakHeapDuring(t *testing.T, run func() error) uint64 {
	t.Helper()
	samples := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	// Initialize the runtime metric before establishing the fixture baseline.
	metrics.Read(samples)
	runtime.GC()
	runtime.GC()
	metrics.Read(samples)
	before := samples[0].Value.Uint64()
	ready, stop := make(chan struct{}), make(chan struct{})
	done := make(chan uint64, 1)
	go func() {
		ticker := time.NewTicker(100 * time.Microsecond)
		defer ticker.Stop()
		peak := before
		close(ready)
		for {
			metrics.Read(samples)
			peak = max(peak, samples[0].Value.Uint64())
			select {
			case <-stop:
				metrics.Read(samples)
				peak = max(peak, samples[0].Value.Uint64())
				done <- peak - before
				return
			case <-ticker.C:
			}
		}
	}()
	<-ready
	err := run()
	close(stop)
	peak := <-done
	if err != nil {
		t.Fatal(err)
	}
	return peak
}

// TestPeakHeapDetectsScratch is a positive control for the memory probe: a
// full-size live temporary must remain visible through the final sample.
func TestPeakHeapDetectsScratch(t *testing.T) {
	const size = 8 << 20
	var scratch []byte
	peak := peakHeapDuring(t, func() error {
		scratch = make([]byte, size)
		return nil
	})
	runtime.KeepAlive(scratch)
	if peak < size/2 {
		t.Fatalf("memory probe missed an 8 MiB temporary: observed %d bytes", peak)
	}
}

// repeatedInput generates a long message without allocating it as a fixture.
type repeatedInput struct {
	remaining int
	block     []byte
}

func (r *repeatedInput) Read(dst []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(dst), r.remaining)
	for filled := 0; filled < n; {
		filled += copy(dst[filled:n], r.block)
	}
	r.remaining -= n
	return n, nil
}

func nativeIOSigner(t testing.TB) (crypto.Signer, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "stream consumer"}, NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return key, raw
}
