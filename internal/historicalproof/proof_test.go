package historicalproof_test

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
)

func proofDigest(value int) [32]byte {
	var digest [32]byte
	binary.BigEndian.PutUint64(digest[:8], uint64(value))
	return digest
}

func TestProofRolesTimeAndOwnership(t *testing.T) {
	now := time.Unix(1700000000, 0).In(time.FixedZone("offset", 3*60*60))
	first, second, source := proofDigest(1), proofDigest(2), proofDigest(3)
	facts := []historicalproof.Fact{
		{Digest: second, Source: source, At: now.Add(-time.Hour), Kind: historicalproof.Certificate},
		{Digest: first, Source: source, At: now.Add(-2 * time.Hour), Kind: historicalproof.CRL},
		{Digest: first, Source: source, At: now.Add(-time.Hour), Kind: historicalproof.Certificate},
		{Digest: first, Source: source, At: now.Add(-2 * time.Hour), Kind: historicalproof.CRL},
	}
	before := slices.Clone(facts)
	set, err := historicalproof.New(t.Context(), now, facts)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Valid() || set.Now().Location() != time.UTC || !set.Now().Equal(now) || len(set.Facts()) != 3 || !slices.Equal(facts, before) {
		t.Fatal("proof normalization/deduplication changed input or count")
	}
	for _, tc := range []struct {
		digest [32]byte
		kind   historicalproof.Kind
		at     time.Time
		found  bool
	}{
		{first, "", now.Add(-2 * time.Hour), true},
		{first, historicalproof.Certificate, now.Add(-time.Hour), true},
		{second, historicalproof.Certificate, now.Add(-time.Hour), true},
		{first, historicalproof.Timestamp, time.Time{}, false},
		{proofDigest(99), "", time.Time{}, false},
	} {
		at, found := set.EarliestKind(tc.digest, tc.kind)
		if found != tc.found || !at.Equal(tc.at) {
			t.Fatalf("role %q: %v %v", tc.kind, at, found)
		}
	}
	boundary := now.Add(-2 * time.Hour)
	if !set.HasAtOrBefore(first, boundary) || set.HasAtOrBefore(first, boundary.Add(-time.Nanosecond)) {
		t.Fatal("inclusive proof boundary changed")
	}
	facts[0].Digest = proofDigest(80)
	snapshot := set.Facts()
	snapshot[0].At = now
	snapshot[0].Kind = historicalproof.Data
	if at, ok := set.Earliest(first); !ok || !at.Equal(boundary) {
		t.Fatal("mutable proof snapshot", at, ok)
	}
	if at, ok := set.EarliestKind(first, historicalproof.Certificate); !ok || !at.Equal(now.Add(-time.Hour)) {
		t.Fatal("diagnostic snapshot changed the certificate role", at, ok)
	}
	var absent *historicalproof.Set
	if absent.Valid() || !absent.Now().IsZero() || absent.Facts() != nil || absent.HasAtOrBefore(first, now) {
		t.Fatal("nil set became evidence")
	}
}

func TestProofValidationAndLimits(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	good := historicalproof.Fact{Digest: proofDigest(1), At: now, Kind: historicalproof.Data}
	for _, tc := range []struct {
		name string
		fact historicalproof.Fact
	}{
		{"zero digest", historicalproof.Fact{At: now, Kind: historicalproof.Data}},
		{"zero time", historicalproof.Fact{Digest: good.Digest, Kind: historicalproof.Data}},
		{"future", historicalproof.Fact{Digest: good.Digest, At: now.Add(time.Nanosecond), Kind: historicalproof.Data}},
		{"unproven past", historicalproof.Fact{Digest: good.Digest, At: now.Add(-time.Second), Kind: historicalproof.Data}},
		{"unknown role", historicalproof.Fact{Digest: good.Digest, At: now, Kind: "untrusted"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if set, err := historicalproof.New(t.Context(), now, []historicalproof.Fact{tc.fact}); set != nil || !errors.Is(err, historicalproof.ErrProof) {
				t.Fatal(set, err)
			}
		})
	}
	facts := make([]historicalproof.Fact, 8192)
	for i := range facts {
		facts[i] = historicalproof.Fact{Digest: proofDigest(i/4 + 1), Source: proofDigest(3000), At: now.Add(-time.Duration(i%4) * time.Second), Kind: historicalproof.Certificate}
	}
	set, err := historicalproof.New(t.Context(), now, facts)
	if err != nil || len(set.Facts()) != 8192 {
		t.Fatal("exact fact/object limits rejected", err)
	}
	if got, err := historicalproof.New(t.Context(), now, append(facts, good)); got != nil || !errors.Is(err, historicalproof.ErrProof) {
		t.Fatal("fact overflow accepted", err)
	}
	objects := make([]historicalproof.Fact, 2049)
	for i := range objects {
		objects[i] = historicalproof.Fact{Digest: proofDigest(i + 1), At: now, Kind: historicalproof.Data}
	}
	if got, err := historicalproof.New(t.Context(), now, objects); got != nil || !errors.Is(err, historicalproof.ErrProof) {
		t.Fatal("object overflow accepted", err)
	}
	if got, err := historicalproof.New(nil, now, nil); got != nil || !errors.Is(err, historicalproof.ErrProof) {
		t.Fatal(got, err)
	}
	if got, err := historicalproof.New(t.Context(), time.Time{}, nil); got != nil || !errors.Is(err, historicalproof.ErrProof) {
		t.Fatal(got, err)
	}
}

func TestProofCanceledEmptyInput(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if set, err := historicalproof.New(ctx, time.Unix(1700000000, 0), nil); set != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("empty proof input bypassed cancellation", set, err)
	}
}

func BenchmarkProofLookup(b *testing.B) {
	now := time.Unix(1700000000, 0).UTC()
	for _, objects := range []int{1, 16, 2048} {
		b.Run(strconv.Itoa(objects), func(b *testing.B) {
			facts := make([]historicalproof.Fact, objects*4)
			for i := range facts {
				facts[i] = historicalproof.Fact{Digest: proofDigest(i/4 + 1), Source: proofDigest(3000), At: now.Add(-time.Duration(i%4) * time.Second), Kind: historicalproof.Certificate}
			}
			set, err := historicalproof.New(b.Context(), now, facts)
			if err != nil {
				b.Fatal(err)
			}
			for _, mode := range []string{"hit", "kind", "miss"} {
				b.Run(mode, func(b *testing.B) {
					digest := proofDigest(objects)
					kind := historicalproof.Kind("")
					if mode == "kind" {
						kind = historicalproof.Certificate
					}
					if mode == "miss" {
						digest = proofDigest(objects + 1)
					}
					b.ReportAllocs()
					for b.Loop() {
						_, found := set.EarliestKind(digest, kind)
						if found != (mode != "miss") {
							b.Fatal("lookup result", found)
						}
					}
				})
			}
		})
	}
}

func TestProofSearchSeparatesObjectsAndRoles(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	facts := make([]historicalproof.Fact, 512)
	for i := range facts {
		kind := historicalproof.Certificate
		if i%2 != 0 {
			kind = historicalproof.CRL
		}
		facts[i] = historicalproof.Fact{Digest: proofDigest(i/4 + 1), Source: proofDigest(9000), At: now.Add(-time.Duration(i%4+1) * time.Hour), Kind: kind}
	}
	set, err := historicalproof.New(t.Context(), now, facts)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range []int{0, 1, 63, 128, 129} {
		for _, kind := range []historicalproof.Kind{"", historicalproof.Certificate, historicalproof.CRL, historicalproof.Timestamp} {
			var want time.Time
			for _, fact := range facts {
				if fact.Digest == proofDigest(object) && (kind == "" || fact.Kind == kind) && (want.IsZero() || fact.At.Before(want)) {
					want = fact.At
				}
			}
			got, found := set.EarliestKind(proofDigest(object), kind)
			if !got.Equal(want) || found == want.IsZero() {
				t.Fatalf("object%d role%q got%v %v want%v", object, kind, got, found, want)
			}
		}
	}
}

func BenchmarkProofSkewedLookup(b *testing.B) {
	now := time.Unix(1700000000, 0).UTC()
	facts := make([]historicalproof.Fact, 8192)
	for i := range facts {
		facts[i] = historicalproof.Fact{Digest: proofDigest(1), Source: proofDigest(3000), At: now.Add(-time.Duration(i) * time.Second), Kind: historicalproof.Certificate}
	}
	set, err := historicalproof.New(b.Context(), now, facts)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		at, found := set.Earliest(proofDigest(1))
		if !found || !at.Equal(now.Add(-8191*time.Second)) {
			b.Fatal(at, found)
		}
	}
}
