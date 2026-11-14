package historical //nolint:testpackage // Exercises graph admission and workflow limits directly.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
)

func TestGraphExtractPreservesHashReferenceProofSource(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		children int
	}{
		{"small_container", 1},
		{"many_children", 70},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			now := testcert.Now()
			first, second := now.Add(-2*time.Hour), now.Add(-time.Hour)
			firstSource := sha256.Sum256([]byte("earlier authenticated token"))
			secondSource := sha256.Sum256([]byte("later authenticated token"))
			payload, container := []byte("application data"), []byte("signature with a hash reference")
			payloadKey, containerKey := sha256.Sum256(payload), sha256.Sum256(container)
			objects := make([]Object, 0, 2+tc.children)
			objects = append(objects,
				Object{Bytes: container, Kind: historicalproof.Signature, Refs: []HashReference{{Hash: crypto.SHA256, Digest: payloadKey[:], Target: payloadKey}}},
				Object{Bytes: payload, Kind: historicalproof.Data},
			)
			for index := range tc.children {
				child := []byte("contained object " + strconv.Itoa(index))
				objects = append(objects, Object{Bytes: child, Kind: historicalproof.Data})
				objects[0].Contains = append(objects[0].Contains, sha256.Sum256(child))
			}
			g, err := newGraph(t.Context(), Config{MaxObjects: 100, MaxEdges: 512, MaxBytes: 4096}, Input{Signature: containerKey, Objects: objects}, now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := g.extractCovered(t.Context(), Candidate{Covered: [][sha256.Size]byte{containerKey}}, firstSource, first); err != nil {
				t.Fatal(err)
			}
			if err := g.extract(t.Context(), Candidate{Covered: [][sha256.Size]byte{containerKey, containerKey}}, secondSource, second); err != nil {
				t.Fatal(err)
			}
			set, err := g.set(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range [][sha256.Size]byte{payloadKey, sha256.Sum256(payloadKey[:])} {
				if got, ok := set.Earliest(key); !ok || !got.Equal(first) {
					t.Fatalf("earliest proof for %x = %v, %t, want %v", key, got, ok, first)
				}
				var found bool
				for _, fact := range set.Facts() {
					if fact.Digest == key && fact.At.Equal(first) {
						if fact.Source != firstSource {
							t.Fatalf("proof source for %x = %x, want %x", key, fact.Source, firstSource)
						}
						found = true
					}
				}
				if !found {
					t.Fatalf("no fact for %x at %v", key, first)
				}
			}
		})
	}
}

func TestGraphExtractHonorsHashReferenceReliability(t *testing.T) {
	t.Parallel()

	now := testcert.Now()
	first, second := now.Add(-2*time.Hour), now.Add(-time.Hour)
	payload, container := []byte("document payload"), []byte("signature with a hash reference")
	payloadKey, containerKey := sha256.Sum256(payload), sha256.Sum256(container)
	source, digestKey := sha256.Sum256([]byte("authenticated token")), sha256.Sum256(payloadKey[:])
	for _, tc := range []struct {
		name          string
		cutoff        time.Time
		wantDigest    bool
		wantPayloadAt time.Time
	}{
		{"hash_current", now.Add(time.Hour), true, first},
		{"hash_expired_at_observation", second, true, now},
		{"hash_expired_at_timestamp", first, false, now},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			objects := []Object{
				{Bytes: container, Kind: historicalproof.Signature, Refs: []HashReference{{Hash: crypto.SHA256, Digest: payloadKey[:], Target: payloadKey}}},
				{Bytes: payload, Kind: historicalproof.Data},
			}
			cfg := Config{MaxObjects: 2, MaxEdges: 8, MaxBytes: 256, SignerHistory: pki.HistoricalOptions{
				CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: tc.cutoff}},
			}}
			g, err := newGraph(t.Context(), cfg, Input{Signature: containerKey, Objects: objects}, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := g.extract(t.Context(), Candidate{Covered: [][sha256.Size]byte{containerKey}}, source, first); err != nil {
				t.Fatal(err)
			}
			set, err := g.set(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := set.EarliestKind(digestKey, historicalproof.Digest); ok != tc.wantDigest || ok && !got.Equal(first) {
				t.Errorf("digest proof = %v, %t, want existence %t at %v", got, ok, tc.wantDigest, first)
			}
			if got, ok := set.EarliestKind(payloadKey, historicalproof.Data); !ok || !got.Equal(tc.wantPayloadAt) {
				t.Errorf("payload proof = %v, %t, want %v", got, ok, tc.wantPayloadAt)
			}
		})
	}
}

func TestGraphExtractRespectsFactLimit(t *testing.T) {
	t.Parallel()

	now := testcert.Now()
	payload, container := []byte("document payload"), []byte("signature with a hash reference")
	payloadKey, containerKey := sha256.Sum256(payload), sha256.Sum256(container)
	objects := []Object{
		{Bytes: container, Kind: historicalproof.Signature, Refs: []HashReference{{Hash: crypto.SHA256, Digest: payloadKey[:], Target: payloadKey}}},
		{Bytes: payload, Kind: historicalproof.Data},
	}
	for _, tc := range []struct {
		name      string
		limit     int
		wantFacts int
	}{
		{"direct_coverage", 2, 2},
		{"digest_proof", 3, 3},
		{"referenced_object_proof", 4, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g, err := newGraph(t.Context(), Config{MaxObjects: 2, MaxEdges: tc.limit, MaxBytes: 256}, Input{Signature: containerKey, Objects: objects}, now)
			if err != nil {
				t.Fatal(err)
			}
			source := sha256.Sum256([]byte("authenticated token"))
			if err := g.extract(t.Context(), Candidate{Covered: [][sha256.Size]byte{containerKey}}, source, now.Add(-time.Hour)); !errors.Is(err, ErrLimit) {
				t.Fatalf("extract error = %v, want %v", err, ErrLimit)
			}
			if got := len(g.facts); got != tc.wantFacts {
				t.Fatalf("proof count = %d, want %d", got, tc.wantFacts)
			}
		})
	}
}

func TestNewGraphRequiresConsistentHashReferencesOnDuplicateObject(t *testing.T) {
	t.Parallel()

	payload, otherPayload := []byte("original payload"), []byte("other payload")
	key, otherKey := sha256.Sum256(payload), sha256.Sum256(otherPayload)
	signature := []byte("signature with a reference")
	signatureKey := sha256.Sum256(signature)
	original := HashReference{Hash: crypto.SHA256, Digest: key[:], Target: key}
	for _, tc := range []struct {
		name string
		ref  HashReference
		want error
	}{
		{"identical_reference", original, nil},
		{"different_reference_target", HashReference{Hash: crypto.SHA256, Digest: otherKey[:], Target: otherKey}, ErrInput},
		{"different_reference_hash", HashReference{Hash: crypto.SHA384, Digest: key[:], Target: key}, ErrInput},
		{"different_reference_digest", HashReference{Hash: crypto.SHA256, Digest: otherKey[:], Target: key}, ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			objects := []Object{
				{Bytes: signature, Kind: historicalproof.Signature, Refs: []HashReference{original}},
				{Bytes: signature, Kind: historicalproof.Signature, Refs: []HashReference{tc.ref}},
				{Bytes: payload, Kind: historicalproof.Data},
				{Bytes: otherPayload, Kind: historicalproof.Data},
			}
			g, err := newGraph(t.Context(), Config{MaxObjects: 4, MaxEdges: 4, MaxBytes: 256}, Input{Signature: signatureKey, Objects: objects}, testcert.Now())
			if !errors.Is(err, tc.want) || (g == nil) != (tc.want != nil) {
				t.Fatalf("newGraph = %v, %v; want %v", g, err, tc.want)
			}
			if g != nil && (len(g.objects) != 3 || len(g.facts) != 3) {
				t.Fatalf("duplicate encoding produced %d objects and %d facts, want 3 each", len(g.objects), len(g.facts))
			}
		})
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
	config.MaxBytes = len(a) + len(b) - 1
	if graph, err := newGraph(t.Context(), config, valid, testcert.Now()); graph != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("byte cap", graph, err)
	}

	config.MaxBytes++
	valid.Objects = append(valid.Objects, valid.Objects[0])
	if graph, err := newGraph(t.Context(), config, valid, testcert.Now()); graph == nil || err != nil {
		t.Fatal("duplicate counted against unique-byte cap", graph, err)
	}
	valid.Objects = valid.Objects[:2]

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
