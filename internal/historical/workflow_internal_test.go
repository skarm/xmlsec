package historical

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

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

func TestNormalizeSnapshotsPolicyAndBounds(t *testing.T) {
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
			bad := got
			tc.mutate(&bad)
			if _, err := Normalize(bad); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		})
	}
}

func TestWorkflowCancellationNeverProducesPassingReport(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	now := testcert.Now()
	report, err := Validate(ctx, Config{}, Input{}, now, pki.Evidence{}, pki.Evidence{})
	if !errors.Is(err, context.Canceled) || report == nil || report.Indication != Indeterminate || !errors.Is(report.Cause, context.Canceled) || !report.At.Equal(now) || report.Proofs != nil || report.Current != nil || report.Past != nil {
		t.Fatal("failed workflow granted state", report, err)
	}
}

// Graph tests start after the workflow's independent authentication stages.
func TestGraphExactBindingOwnershipAndProofExtraction(t *testing.T) {
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

func TestGraphRejectsConflictsMissingBindingsAndCycles(t *testing.T) {
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

func TestContainmentDepthIncludesCachedSharedTails(t *testing.T) {
	for _, depth := range []int{64, 65, 66} {
		t.Run(strconv.Itoa(depth), func(t *testing.T) {
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
