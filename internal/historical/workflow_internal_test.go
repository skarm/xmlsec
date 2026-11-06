package historical

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

func TestNormalizeSnapshotsPolicyAndBounds(t *testing.T) {
	t.Parallel()

	base := testWorkflowConfig(t)
	delay, accuracy, freshness := time.Hour, time.Minute, time.Second
	at := testcert.Now()
	base.TimestampDelay = &delay
	base.MissingAccuracy = &accuracy
	base.SignerHistory = pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: at}}, TrustAnchorSunsets: map[string]time.Time{"anchor": at}, RevocationFreshness: &freshness}
	got, err := Normalize(base)
	if err != nil {
		t.Fatal(err)
	}
	delay = 0
	accuracy = 0
	freshness = 0
	base.SignerHistory.CryptoConstraints[0].Hash = crypto.SHA512
	delete(base.SignerHistory.TrustAnchorSunsets, "anchor")
	if got.MaxObjects != 512 || got.MaxEdges != 4096 || got.MaxBytes != 16<<20 || got.MaxTimestamps != 16 || *got.TimestampDelay != time.Hour || *got.MissingAccuracy != time.Minute || *got.SignerHistory.RevocationFreshness != time.Second || got.SignerHistory.CryptoConstraints[0].Hash != crypto.SHA256 || !got.SignerHistory.TrustAnchorSunsets["anchor"].Equal(at) {
		t.Fatal("policy/defaults alias caller state")
	}
	for _, limits := range []struct{ objects, edges, bytes, timestamps int }{{1, 1, 1, 1}, {2048, 8192, 64 << 20, 64}} {
		exact := got
		exact.MaxObjects = limits.objects
		exact.MaxEdges = limits.edges
		exact.MaxBytes = limits.bytes
		exact.MaxTimestamps = limits.timestamps
		normalized, err := Normalize(exact)
		if err != nil || normalized.MaxObjects != limits.objects || normalized.MaxEdges != limits.edges || normalized.MaxBytes != limits.bytes || normalized.MaxTimestamps != limits.timestamps {
			t.Fatal("exact workflow limits rejected", limits, err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   error
	}{
		{"missing signer", func(c *Config) { c.Signer = nil }, ErrInput},
		{"object overflow", func(c *Config) { c.MaxObjects = 2049 }, ErrLimit},
		{"edge budget below objects", func(c *Config) { c.MaxEdges = 1 }, ErrLimit},
		{"byte overflow", func(c *Config) { c.MaxBytes = (64 << 20) + 1 }, ErrLimit},
		{"timestamp overflow", func(c *Config) { c.MaxTimestamps = 65 }, ErrLimit},
		{"negative precision", func(c *Config) { value := -time.Nanosecond; c.MissingAccuracy = &value }, ErrInput},
		{"precision overflow", func(c *Config) { value := 24*time.Hour + 1; c.MissingAccuracy = &value }, ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			bad := got
			tc.mutate(&bad)
			if _, err := Normalize(bad); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		})
	}
}

func TestWorkflowCancellationNeverProducesPassingReport(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	now := testcert.Now()
	report, err := Validate(ctx, Config{}, Input{}, now, pki.Evidence{}, pki.Evidence{})
	// Verification reports retain diagnostics on failure.
	//noinspection GoDfaErrorMayBeNotNil
	if !errors.Is(err, context.Canceled) || report == nil || report.Indication != Indeterminate || !errors.Is(report.Cause, context.Canceled) || !report.At.Equal(now) || report.Proofs != nil || report.Current != nil || report.Past != nil {
		t.Fatal("failed workflow granted state", report, err)
	}
}

// Graph tests start after the workflow's independent authentication stages.
func TestGraphExactBindingOwnershipAndProofExtraction(t *testing.T) {
	t.Parallel()

	now := testcert.Now()
	past := now.Add(-time.Hour)
	payload := []byte("original application bytes")
	container := []byte("encoded signed hash reference")
	signature := []byte("signature value")
	token := []byte("validated timestamp encoding")
	dataKey, containerKey, signatureKey, source := sha256.Sum256(payload), sha256.Sum256(container), sha256.Sum256(signature), sha256.Sum256(token)
	hash := sha256.Sum256(payload)
	digestObjectKey := sha256.Sum256(hash[:])
	input := Input{Signature: signatureKey, Objects: []Object{
		{Bytes: signature, Kind: historicalproof.Signature, Contains: [][32]byte{containerKey}},
		{Bytes: container, Kind: historicalproof.Data, Refs: []HashReference{{Hash: crypto.SHA256, Digest: hash[:], Target: dataKey}}},
		{Bytes: payload, Kind: historicalproof.Data},
		{Bytes: token, Kind: historicalproof.Timestamp},
	}}
	graph, err := newGraph(t.Context(), Config{MaxObjects: 8, MaxEdges: 16, MaxBytes: 4096, MaxTimestamps: 4}, input, now)
	if err != nil {
		t.Fatal(err)
	}
	expected := bytes.Clone(payload)
	clear(payload)
	input.Objects[0].Contains[0] = [32]byte{}
	clear(input.Objects[1].Refs[0].Digest)
	if !bytes.Equal(graph.objects[dataKey].Bytes, expected) || graph.checkBindings() != nil {
		t.Fatal("graph borrowed mutable adapter input")
	}
	if err := graph.extract(t.Context(), Candidate{Covered: [][32]byte{signatureKey}}, source, past); err != nil {
		t.Fatal(err)
	}
	set, err := graph.set(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range [][32]byte{signatureKey, containerKey, dataKey} {
		if at, ok := set.Earliest(key); !ok || !at.Equal(past) {
			t.Fatal("missing exact/transitive proof", at, ok)
		}
	}
	if at, ok := set.EarliestKind(digestObjectKey, historicalproof.Digest); !ok || !at.Equal(past) {
		t.Fatal("hash-reference role lost", at, ok)
	}
	if err := graph.extract(t.Context(), Candidate{Covered: [][32]byte{source}}, source, past); !errors.Is(err, ErrInput) {
		t.Fatal("timestamp covered itself", err)
	}
}

func TestGraphRejectsConflictsMissingBindingsAndCycles(t *testing.T) { //nolint:tparallel // Subtests share the graph config before the parent changes its budgets.
	t.Parallel()

	a, b := []byte("first"), []byte("second")
	ak, bk := sha256.Sum256(a), sha256.Sum256(b)
	config := Config{MaxObjects: 8, MaxEdges: 16, MaxBytes: 4096, MaxTimestamps: 4}
	for _, tc := range []struct {
		name      string
		objects   []Object
		signature [32]byte
		want      error
	}{
		{"kind collision", []Object{{Bytes: a, Kind: historicalproof.Signature}, {Bytes: a, Kind: historicalproof.Data}}, ak, ErrInput},
		{"missing signature", []Object{{Bytes: a, Kind: historicalproof.Data}}, bk, ErrInput},
		{"missing contained object", []Object{{Bytes: a, Kind: historicalproof.Signature, Contains: [][32]byte{bk}}}, ak, ErrInput},
		{"cycle", []Object{{Bytes: a, Kind: historicalproof.Signature, Contains: [][32]byte{bk}}, {Bytes: b, Kind: historicalproof.Data, Contains: [][32]byte{ak}}}, ak, ErrInput},
		{"unbound hash", []Object{{Bytes: a, Kind: historicalproof.Signature, Refs: []HashReference{{Hash: crypto.SHA256, Digest: make([]byte, 32), Target: bk}}}, {Bytes: b, Kind: historicalproof.Data}}, ak, ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if graph, err := newGraph(t.Context(), config, Input{Signature: tc.signature, Objects: tc.objects}, testcert.Now()); graph != nil || !errors.Is(err, tc.want) {
				t.Fatal(graph, err)
			}
		})
	}
	valid := Input{Signature: ak, Objects: []Object{{Bytes: a, Kind: historicalproof.Signature}, {Bytes: b, Kind: historicalproof.Data}}}
	config.MaxObjects = 1
	if graph, err := newGraph(t.Context(), config, valid, testcert.Now()); graph != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("object cap", graph, err)
	}
	config.MaxObjects = 8
	config.MaxEdges = 0
	valid.Objects[0].Contains = [][32]byte{bk}
	if graph, err := newGraph(t.Context(), config, valid, testcert.Now()); graph != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("edge cap", graph, err)
	}
}

func TestContainmentDepthIncludesCachedSharedTails(t *testing.T) {
	t.Parallel()

	for _, depth := range []int{64, 65, 66} {
		t.Run(strconv.Itoa(depth), func(t *testing.T) {
			t.Parallel()

			objects, keys := containmentChain(depth)
			for _, cached := range []bool{false, true} {
				walk := containmentWalk{ctx: t.Context(), objects: objects, states: make(map[[32]byte]uint8, len(objects)), maximum: 8192}
				if cached {
					// Complete the tail first, deterministically exercising the old done-cache bypass.
					if _, err := walk.visit(keys[32], 0); err != nil {
						t.Fatal("valid tail", err)
					}
				}
				height, err := walk.visit(keys[0], 0)
				if depth == 64 {
					if err != nil || height != 64 {
						t.Fatal("exact depth boundary", cached, height, err)
					}
				} else if !errors.Is(err, ErrLimit) {
					t.Fatal("height bypassed depth limit", cached, height, err)
				}
			}
		})
	}
	objects, keys := containmentChain(32)
	first, second, root := sha256.Sum256([]byte("first parent")), sha256.Sum256([]byte("second parent")), sha256.Sum256([]byte("shared root"))
	objects[first] = Object{Contains: [][32]byte{keys[0]}}
	objects[second] = Object{Contains: [][32]byte{keys[0]}}
	objects[root] = Object{Contains: [][32]byte{first, second}}
	walk := containmentWalk{ctx: t.Context(), objects: objects, states: make(map[[32]byte]uint8, len(objects)), maximum: 8192}
	if height, err := walk.visit(root, 0); err != nil || height != 34 {
		t.Fatal("shared acyclic tail rejected or miscounted", height, err)
	}
	objects[keys[32]] = Object{Contains: [][32]byte{keys[0]}}
	cyclic := containmentWalk{ctx: t.Context(), objects: objects, states: make(map[[32]byte]uint8, len(objects)), maximum: 8192}
	if _, err := cyclic.visit(root, 0); !errors.Is(err, ErrInput) {
		t.Fatal("containment cycle lost", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	walk.ctx = ctx
	if _, err := walk.visit(root, 0); !errors.Is(err, context.Canceled) {
		t.Fatal("cached result bypassed cancellation", err)
	}
}

func TestGraphProofAdmissionMatchesLinearHistory(t *testing.T) {
	t.Parallel()
	for _, maximum := range []int{16, 64, 512} {
		g := graph{maximum: maximum}
		var want []historicalproof.Fact
		random := rand.New(rand.NewPCG(13, 71))
		kinds := []historicalproof.Kind{historicalproof.Data, historicalproof.Certificate, historicalproof.Digest}
		for i := range 4096 {
			fact := historicalproof.Fact{Kind: kinds[random.IntN(len(kinds))], At: time.Unix(int64(random.IntN(1024)), 0)}
			fact.Digest[0] = byte(random.IntN(128))
			fact.Source[0] = byte(i)
			duplicate := slices.ContainsFunc(want, func(old historicalproof.Fact) bool {
				return old.Digest == fact.Digest && old.Kind == fact.Kind && !old.At.After(fact.At)
			})
			var wantErr error
			if !duplicate {
				if len(want) == maximum {
					wantErr = ErrLimit
				} else {
					want = append(want, fact)
				}
			}
			if err := g.add(fact); !errors.Is(err, wantErr) || !slices.Equal(g.facts, want) {
				t.Fatalf("maximum=%d step=%d: admission differs: %v, want %v", maximum, i, err, wantErr)
			}
		}
	}
}

func TestGraphProofAdmissionIncludesInitialObservations(t *testing.T) {
	t.Parallel()
	initial := make([]historicalproof.Fact, 128)
	for i := range initial {
		initial[i] = historicalproof.Fact{Kind: historicalproof.Data, At: time.Unix(1000, 0)}
		initial[i].Digest[0] = byte(i)
	}
	g := graph{maximum: len(initial) + 1, facts: slices.Clone(initial)}
	if err := g.add(initial[0]); err != nil || len(g.facts) != len(initial) {
		t.Fatal("initial observation was duplicated", err)
	}
	older := initial[0]
	older.At = older.At.Add(-time.Hour)
	if err := g.add(older); err != nil || len(g.facts) != g.maximum {
		t.Fatal("earlier proof was lost", err)
	}
	if err := g.add(initial[0]); err != nil || len(g.facts) != g.maximum {
		t.Fatal("later proof consumed budget", err)
	}
	older.At = older.At.Add(-time.Hour)
	if err := g.add(older); !errors.Is(err, ErrLimit) || len(g.facts) != g.maximum {
		t.Fatal("history limit was bypassed", err)
	}
}

func TestProofOriginsKeepEarliestTimeAndFirstSource(t *testing.T) {
	t.Parallel()
	g := graph{objects: make(map[[32]byte]Object)}
	random := rand.New(rand.NewPCG(17, 23))
	for i := range 1024 {
		fact := historicalproof.Fact{At: time.Unix(int64(random.IntN(4)), 0), Kind: historicalproof.Data}
		fact.Digest[0] = byte(random.IntN(128))
		fact.Source[0], fact.Source[1] = byte(i), byte(i>>8)
		g.facts = append(g.facts, fact)
	}
	if origins := g.proofOrigins(); origins != nil {
		t.Fatal("history without hash references allocated origins")
	}
	for _, fact := range g.facts {
		g.objects[fact.Digest] = Object{Refs: []HashReference{{}}}
	}
	origins := g.proofOrigins()
	if len(origins) != len(g.objects) {
		t.Fatal("missing hash-reference container origins")
	}
	for digest, origin := range origins {
		want := time.Unix(4, 0)
		for _, fact := range g.facts {
			if fact.Digest == digest && fact.At.Before(want) {
				want = fact.At
			}
		}
		if !origin.at.Equal(want) || origin.source != g.containerSource(digest, want, [32]byte{}) {
			t.Fatal("origin index changed time or first-source precedence")
		}
	}
}

func BenchmarkGraphAdmission(b *testing.B) {
	for _, count := range []int{16, 1024} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			objects := make([]Object, count)
			keys := make([][32]byte, count)
			for i := range objects {
				objects[i] = Object{Bytes: []byte("graph node " + strconv.Itoa(i)), Kind: historicalproof.Data}
				keys[i] = sha256.Sum256(objects[i].Bytes)
			}
			objects[0].Kind = historicalproof.Signature
			objects[0].Contains = keys[1:]
			input := Input{Signature: keys[0], Objects: objects}
			config := Config{MaxObjects: 2048, MaxEdges: 8192, MaxBytes: 1 << 20, MaxTimestamps: 4}
			now := testcert.Now()
			b.ReportAllocs()
			for b.Loop() {
				graph, err := newGraph(b.Context(), config, input, now)
				if err != nil || len(graph.objects) != count {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkGraphExtraction(b *testing.B) {
	for _, count := range []int{16, 1024, 2048} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			objects := make([]Object, count)
			keys := make([][32]byte, count)
			for i := range objects {
				objects[i] = Object{Bytes: []byte("covered node " + strconv.Itoa(i)), Kind: historicalproof.Data}
				keys[i] = sha256.Sum256(objects[i].Bytes)
			}
			objects[0].Kind = historicalproof.Signature
			objects[0].Contains = keys[1:]
			input := Input{Signature: keys[0], Objects: objects}
			config := Config{MaxObjects: 2048, MaxEdges: 8192, MaxBytes: 1 << 20, MaxTimestamps: 4}
			now := testcert.Now()
			candidate := Candidate{Covered: keys[:1]}
			source := sha256.Sum256([]byte("authenticated timestamp"))
			b.ReportAllocs()
			for b.Loop() {
				graph, err := newGraph(b.Context(), config, input, now)
				if err != nil {
					b.Fatal(err)
				}
				if err := graph.extract(b.Context(), candidate, source, now.Add(-time.Hour)); err != nil {
					b.Fatal(err)
				}
				if len(graph.facts) != 2*count {
					b.Fatal("missing covered facts")
				}
			}
		})
	}
}

func BenchmarkGraphHashReferences(b *testing.B) {
	for _, count := range []int{16, 1024, 2048} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			objects := make([]Object, count)
			keys := make([][32]byte, count)
			for i := range objects {
				objects[i] = Object{Bytes: []byte("hash container " + strconv.Itoa(i)), Kind: historicalproof.Data}
				keys[i] = sha256.Sum256(objects[i].Bytes)
			}
			objects[0].Kind = historicalproof.Signature
			objects[0].Contains = keys[1:]
			imprint := sha256.Sum256(objects[0].Bytes)
			for i := 1; i < count; i++ {
				objects[i].Refs = []HashReference{{Hash: crypto.SHA256, Digest: imprint[:], Target: keys[0]}}
			}
			input := Input{Signature: keys[0], Objects: objects}
			config := Config{MaxObjects: 2048, MaxEdges: 8192, MaxBytes: 1 << 20, MaxTimestamps: 4}
			now := testcert.Now()
			candidate := Candidate{Covered: keys[:1]}
			source := sha256.Sum256([]byte("authenticated timestamp"))
			b.ReportAllocs()
			for b.Loop() {
				graph, err := newGraph(b.Context(), config, input, now)
				if err != nil {
					b.Fatal(err)
				}
				if err := graph.extract(b.Context(), candidate, source, now.Add(-time.Hour)); err != nil {
					b.Fatal(err)
				}
				if len(graph.facts) != 2*count+1 {
					b.Fatal("missing hash-reference proof")
				}
			}
		})
	}
}

func testWorkflowConfig(t testing.TB) Config {
	t.Helper()
	chain := testcert.New(t)
	signer, err := pki.NewVerifier(pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{{1, 2, 3, 4}}})
	if err != nil {
		t.Fatal(err)
	}
	return Config{Signer: signer, TSA: tsa}
}

func containmentChain(depth int) (map[[32]byte]Object, [][32]byte) {
	objects := make(map[[32]byte]Object, depth+1)
	keys := make([][32]byte, depth+1)
	for i := range keys {
		keys[i] = sha256.Sum256([]byte("depth node " + strconv.Itoa(i)))
	}
	for i, key := range keys {
		object := Object{Bytes: []byte("depth node " + strconv.Itoa(i)), Kind: historicalproof.Data}
		if i < depth {
			object.Contains = [][32]byte{keys[i+1]}
		}
		objects[key] = object
	}
	return objects, keys
}

// Independent linear oracle retained from the pre-memo helper. These tests check
// admission state, not acceptance/authentication of an entire historical Input.
func linearAdmissionOracle(objects []Object, raw []byte, kind historicalproof.Kind) []Object {
	digest := sha256.Sum256(raw)
	for index, object := range objects {
		if sha256.Sum256(object.Bytes) == digest {
			if object.Kind == objectData {
				objects[index].Kind = kind
			}
			return objects
		}
	}
	return append(objects, Object{Bytes: raw, Kind: kind})
}

func checkAdmissionObjects(t *testing.T, got, want []Object) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("admission changed order/bytes/kind/metadata: got%+v want%+v", got, want)
	}
	for i := range got {
		if len(got[i].Bytes) > 0 && &got[i].Bytes[0] != &want[i].Bytes[0] {
			t.Fatalf("object%d copied or replaced first bytes", i)
		}
		if len(got[i].Contains) > 0 && &got[i].Contains[0] != &want[i].Contains[0] {
			t.Fatalf("object%d copied containment", i)
		}
		if len(got[i].Refs) > 0 && &got[i].Refs[0] != &want[i].Refs[0] {
			t.Fatalf("object%d copied references", i)
		}
	}
}

func TestAdmissionPrefixMatchesLinearFirstOccurrence(t *testing.T) {
	chain := testcert.New(t)
	certificate := chain.Leaf.Raw
	child := sha256.Sum256(certificate)
	parent := []byte(`<r><certificate>` + base64.StdEncoding.EncodeToString(certificate) + `</certificate><digest>` + base64.StdEncoding.EncodeToString(child[:]) + `</digest></r>`)
	metadata := Object{Bytes: parent, Kind: objectData, Contains: [][32]byte{child}, Refs: []HashReference{{Hash: crypto.SHA256, Digest: child[:], Target: child}}}
	initial := []Object{{Bytes: certificate, Kind: objectData}, {Bytes: bytes.Clone(certificate), Kind: historicalproof.Certificate}, metadata}
	want := slices.Clone(initial)
	w := validationWorkflow{input: Input{Objects: slices.Clone(initial)}}
	for _, step := range []struct {
		raw  []byte
		kind historicalproof.Kind
	}{
		{bytes.Clone(certificate), historicalproof.Certificate},
		{parent, objectData},
		{certificate, objectData},
		{[]byte("new exact data object"), objectData},
		{parent, objectData},
	} {
		want = linearAdmissionOracle(want, step.raw, step.kind)
		w.admit(step.raw, step.kind)
		checkAdmissionObjects(t, w.input.Objects, want)
	}
	if w.admitted[child] != 0 || w.input.Objects[0].Kind != historicalproof.Certificate || w.input.Objects[1].Kind != historicalproof.Certificate {
		t.Fatal("first duplicate promotion or retained non-Data kind changed")
	}
}

func TestAdmissionPrefixDoesNotSeedEarlyHitTail(t *testing.T) {
	raw := [][]byte{[]byte("first"), []byte("middle"), []byte("last"), []byte("miss")}
	initial := []Object{{Bytes: raw[0], Kind: objectData}, {Bytes: raw[1], Kind: objectData}, {Bytes: raw[2], Kind: objectData}}
	w := validationWorkflow{input: Input{Objects: slices.Clone(initial)}}
	want := slices.Clone(initial)
	for i, position := range []int{0, 0, 2, 3, 0, 1} {
		w.admit(raw[position], objectData)
		want = linearAdmissionOracle(want, raw[position], objectData)
		checkAdmissionObjects(t, w.input.Objects, want)
		if i < 2 && (w.admittedPrefix != 1 || len(w.admitted) != 1) {
			t.Fatal("first hit scanned or memoized the tail", w.admittedPrefix, len(w.admitted))
		}
	}
	if w.admittedPrefix != len(w.input.Objects) || len(w.admitted) != 4 {
		t.Fatal("late hit/miss did not complete the prefix")
	}
}

func TestAdmissionPrefixKeepsContainmentFirstParent(t *testing.T) {
	certificate := testcert.New(t).Leaf.Raw
	child := sha256.Sum256(certificate)
	parent := []byte(`<r><certificate>` + base64.StdEncoding.EncodeToString(certificate) + `</certificate></r>`)
	parentKey := sha256.Sum256(parent)
	initial := []Object{{Bytes: parent, Kind: objectData}, {Bytes: bytes.Clone(parent), Kind: objectData}}
	w := validationWorkflow{input: Input{Objects: slices.Clone(initial)}}
	w.containCertificates(parentKey, [][]byte{certificate})
	if len(w.input.Objects) != 3 || !slices.Equal(w.input.Objects[0].Contains, [][32]byte{child}) || len(w.input.Objects[1].Contains) != 0 {
		t.Fatal("legacy first-parent containment changed", w.input.Objects)
	}
	if &w.input.Objects[0].Bytes[0] != &initial[0].Bytes[0] || &w.input.Objects[1].Bytes[0] != &initial[1].Bytes[0] || &w.input.Objects[2].Bytes[0] != &certificate[0] {
		t.Fatal("containment changed byte ownership")
	}
	if w.admitted[parentKey] != 0 {
		t.Fatal("duplicate parent replaced the first memo position")
	}
}

func TestAdmissionPrefixIsLocalToWorkflow(t *testing.T) {
	a, b := []byte("a"), []byte("b")
	first := validationWorkflow{input: Input{Objects: []Object{{Bytes: a, Kind: objectData}}}}
	second := validationWorkflow{input: Input{Objects: []Object{{Bytes: b, Kind: objectData}}}}
	first.admit(a, objectData)
	first.admit(b, objectData)
	second.admit(b, objectData)
	second.admit(a, objectData)
	checkAdmissionObjects(t, first.input.Objects, []Object{{Bytes: a, Kind: objectData}, {Bytes: b, Kind: objectData}})
	checkAdmissionObjects(t, second.input.Objects, []Object{{Bytes: b, Kind: objectData}, {Bytes: a, Kind: objectData}})
	if first.admitted[sha256.Sum256(a)] != 0 || second.admitted[sha256.Sum256(a)] != 1 {
		t.Fatal("workflow indexes leaked positions")
	}
}

func historicalLimitCertificates(t testing.TB, chain testcert.Chain, count, padding int) [][]byte {
	t.Helper()
	var extra []pkix.Extension
	if padding > 0 {
		value, err := asn1.Marshal(bytes.Repeat([]byte{7}, padding))
		if err != nil {
			t.Fatal(err)
		}
		extra = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}, Value: value}}
	}
	raw := make([][]byte, count)
	seen := map[[32]byte]bool{sha256.Sum256(chain.Leaf.Raw): true}
	total := 0
	for i := range raw {
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(10000 + i)), Subject: pkix.Name{CommonName: fmt.Sprintf("bounded preflight certificate %d", i)}, NotBefore: chain.Leaf.NotBefore, NotAfter: chain.Leaf.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, ExtraExtensions: extra}
		cert := testcert.Issue(t, template, chain.Root, chain.LeafKey.Public(), chain.RootKey)
		if err := cert.CheckSignatureFrom(chain.Root); err != nil {
			t.Fatal(err)
		}
		raw[i] = cert.Raw
		key := sha256.Sum256(raw[i])
		if seen[key] {
			t.Fatal("fixture DER identities must be distinct")
		}
		seen[key] = true
		total += len(raw[i])
	}
	if total > 128<<10 {
		t.Fatal("fixture must remain below128KiB")
	}
	return raw
}

func historicalLimitWorkflow(t *testing.T, chain testcert.Chain, group string, raw [][]byte, maximum int) validationWorkflow {
	t.Helper()
	policy := pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL, MaxEvidenceBytes: maximum, MaxCRLs: 1, MaxOCSPResponses: 1}
	signer, err := pki.NewVerifier(policy)
	if err != nil {
		t.Fatal(err)
	}
	tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: policy, AllowedPolicies: []asn1.ObjectIdentifier{{1, 2, 3, 4}}})
	if err != nil {
		t.Fatal(err)
	}
	signature := []byte("already authenticated format adapter signature")
	w := validationWorkflow{ctx: t.Context(), config: Config{Signer: signer, TSA: tsa}, now: testcert.Now(), report: &Report{}, input: Input{Signature: sha256.Sum256(signature), Certificate: bytes.Clone(chain.Leaf.Raw), SignatureMethod: chain.Leaf.SignatureAlgorithm, Hashes: []crypto.Hash{crypto.SHA256}, Objects: []Object{{Bytes: signature, Kind: historicalproof.Signature}}}}
	if group == "signer" {
		w.signerEvidence.Intermediates = raw
	} else {
		w.tsaEvidence.Intermediates = raw
	}
	return w
}

// Invalid raw Evidence must not populate the pregraph object set.
func TestEvidenceLimitsBeforeAdmission(t *testing.T) {
	chain := testcert.New(t)
	counted := historicalLimitCertificates(t, chain, 65, 0)
	padded := historicalLimitCertificates(t, chain, 2, 2048)
	sum := len(padded[0]) + len(padded[1])
	cases := []struct {
		name    string
		raw     [][]byte
		maximum int
		over    bool
	}{
		{"count64", counted[:64], 128 << 10, false},
		{"count65", counted, 128 << 10, true},
		{"bytes_exact", padded, sum, false},
		{"bytes_over_one", padded, sum - 1, true},
	}
	for _, group := range []string{"signer", "TSA"} {
		for _, tc := range cases {
			t.Run(group+"/"+tc.name, func(t *testing.T) {
				w := historicalLimitWorkflow(t, chain, group, tc.raw, tc.maximum)
				snapshots := make([][]byte, len(tc.raw))
				for i, b := range tc.raw {
					snapshots[i] = bytes.Clone(b)
				}
				defer func() {
					for i, b := range tc.raw {
						if !bytes.Equal(b, snapshots[i]) {
							t.Errorf("caller DER%d changed", i)
						}
					}
				}()
				e := pki.Evidence{Intermediates: tc.raw}
				var directErr error
				if group == "signer" {
					_, directErr = w.config.Signer.NewHistoricalSession(t.Context(), w.config.SignerHistory, w.now, e)
				} else {
					_, directErr = w.config.TSA.NewHistoricalSession(t.Context(), w.config.TSAHistory, w.now, e)
				}
				if tc.over {
					if !errors.Is(directErr, pki.ErrLimit) {
						t.Fatalf("direct session should reject configured bound: %v", directErr)
					}
				} else if directErr != nil {
					t.Fatal("direct session positive control", directErr)
				}
				before := len(w.input.Objects)
				if err := w.initialize(); err != nil {
					if tc.over && errors.Is(err, pki.ErrLimit) && len(w.input.Objects) == before && w.report.Proofs == nil && w.report.Current == nil && w.report.Past == nil {
						return
					}
					t.Fatal("initialize", err)
				}
				err := w.admitEvidence()
				t.Logf("validDER=%d bytes=%d cap=%d beforeObjects=%d afterObjects=%d admission=%v directSession=%v", len(tc.raw), historicalLimitBytes(tc.raw), tc.maximum, before, len(w.input.Objects), err, directErr)
				if tc.over {
					if (!errors.Is(err, pki.ErrLimit) && !errors.Is(err, ErrLimit)) || len(w.input.Objects) != before {
						t.Fatalf("over-limit DER reached admitted state before session guard: objects=%d->%d err=%v", before, len(w.input.Objects), err)
					}
				} else if err != nil || len(w.input.Objects) != before+1+len(tc.raw) {
					t.Fatalf("positive admission: objects=%d err=%v", len(w.input.Objects), err)
				}
			})
		}
	}
}

func historicalLimitBytes(raw [][]byte) int {
	total := 0
	for _, b := range raw {
		total += len(b)
	}
	return total
}

func TestEvidenceLimitsStillCheckTimestampAdditions(t *testing.T) {
	issuer := newTimestampIssuer(t)
	raw := make([][]byte, 64)
	for i := range raw {
		raw[i] = issuer.chain.Root.Raw
	}
	w := historicalLimitWorkflow(t, issuer.chain, "TSA", raw, 128<<10)
	zero := time.Duration(0)
	w.config.MissingAccuracy = &zero
	stamp := issuer.issueStamp(t, 17, testcert.Now().Add(-time.Second), &zero, false, w.input.Objects[0].Bytes)
	stamp.candidate.Covered = [][32]byte{w.input.Signature}
	w.input.Timestamps = []Candidate{stamp.candidate}
	if err := w.initialize(); err != nil {
		t.Fatal("initial64 evidence", err)
	}
	if err := w.admitEvidence(); err != nil {
		t.Fatal(err)
	}
	if err := w.prepareTimestamps(); err != nil {
		t.Fatal("timestamp preparation", err)
	}
	if len(w.prepared) != 1 || len(w.tsaEvidence.Intermediates) <= 64 {
		t.Fatal("fixture did not add an authenticated token certificate")
	}
	if err := w.preparePaths(); !errors.Is(err, pki.ErrLimit) {
		t.Fatal("late session bound lost", err)
	}
	if w.graph != nil || w.report.Proofs != nil || w.report.Current != nil || w.report.Past != nil {
		t.Fatal("late limit published acceptance")
	}
	if len(raw) != 64 {
		t.Fatal("caller evidence slice changed")
	}
}

func TestEvidenceLimitsBeforeRevocationInspection(t *testing.T) {
	chain := testcert.New(t)
	crl := testcert.CRL(t, chain)
	for _, group := range []string{"signer", "TSA"} {
		for _, kind := range []string{"CRL", "OCSP"} {
			t.Run(group+"/"+kind, func(t *testing.T) {
				w := historicalLimitWorkflow(t, chain, group, nil, 128<<10)
				target := &w.signerEvidence
				if group == "TSA" {
					target = &w.tsaEvidence
				}
				if kind == "CRL" {
					target.CRLs = [][]byte{crl, crl}
				} else {
					target.OCSPResponses = [][]byte{{0x30, 0}, {0x30, 0}}
				}
				before := len(w.input.Objects)
				if err := w.initialize(); !errors.Is(err, pki.ErrLimit) || len(w.input.Objects) != before {
					t.Fatal("configured count checked after admission/inspection", kind, err, len(w.input.Objects))
				}
			})
		}
		t.Run(group+"/under-limit OCSP still inspected", func(t *testing.T) {
			w := historicalLimitWorkflow(t, chain, group, nil, 128<<10)
			if group == "TSA" {
				w.tsaEvidence.OCSPResponses = [][]byte{{0x30, 0}}
			} else {
				w.signerEvidence.OCSPResponses = [][]byte{{0x30, 0}}
			}
			if err := w.initialize(); err != nil {
				t.Fatal("under-limit metadata", err)
			}
			if err := w.admitEvidence(); !errors.Is(err, pki.ErrEvidence) || errors.Is(err, pki.ErrLimit) {
				t.Fatal("under-limit material parser changed", err)
			}
		})
	}
}

func TestWorkflowTimestampSourcesRetainCountLimit(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	signer, err := pki.NewVerifier(pki.Config{Roots: [][]byte{issuer.chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	signatureBytes := []byte("authenticated format signature encoding")
	signature := sha256.Sum256(signatureBytes)
	stamp := issuer.issueStamp(t, 1, testcert.Now().Add(-30*time.Second), new(time.Duration(0)), false, signatureBytes)
	stamp.candidate.Covered = [][32]byte{signature}
	source, err := evidence.NewObservation(t.Context(), evidence.Timestamp, stamp.candidate.Token.DER(), evidence.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	input := Input{
		Signature: signature, Certificate: issuer.chain.Leaf.Raw, SignatureMethod: issuer.chain.Leaf.SignatureAlgorithm,
		Hashes: []crypto.Hash{crypto.SHA256}, Objects: []Object{{Bytes: signatureBytes, Kind: historicalproof.Signature}},
		Timestamps: []Candidate{stamp.candidate},
	}
	crl := testcert.CRL(t, issuer.chain)
	for _, count := range []int{1024, 1025} {
		for _, group := range []string{"signer", "TSA"} {
			t.Run(group+"/"+strconv.Itoa(count), func(t *testing.T) {
				t.Parallel()

				sources := make([]*evidence.Observation, count)
				for index := range sources {
					sources[index] = source
				}
				signerEvidence, tsaEvidence := pki.Evidence{CRLs: [][]byte{crl}}, pki.Evidence{CRLs: [][]byte{crl}}
				if group == "signer" {
					signerEvidence.Sources = sources
				} else {
					tsaEvidence.Sources = sources
				}
				report, err := Validate(t.Context(), Config{Signer: signer, TSA: issuer.verifier}, input, testcert.Now(), signerEvidence, tsaEvidence)
				if count == 1024 {
					if err != nil || report.Indication != Passed || report.Current == nil || len(report.Stamps) != 1 || report.Stamps[0].Indication != Passed {
						t.Fatal("permitted observations changed valid signed-input acceptance", report, err)
					}

					return
				}
				// Verification reports retain diagnostics on failure.
				//noinspection GoDfaErrorMayBeNotNil
				if !errors.Is(err, ErrLimit) || report.Indication == Passed || !errors.Is(report.Cause, ErrLimit) || report.Current != nil || report.Past != nil || report.Proofs != nil {
					t.Fatal("timestamp filtering bypassed evidence source count", report, err)
				}
				if len(sources) != count || sources[0] != source || sources[len(sources)-1] != source {
					t.Fatal("source filtering mutated caller observations")
				}
			})
		}
	}
}
