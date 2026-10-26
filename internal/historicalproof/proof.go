// Package historicalproof stores exact-object existence facts produced by the
// library's validation workflows. Its constructors are intentionally internal:
// acquisition metadata and caller-provided times cannot mint authenticated PoE.
package historicalproof

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sort"
	"time"
)

// ErrProof reports an invalid or over-budget proof set.
var ErrProof = errors.New("invalid historical proof set")

// Kind identifies the exact role established by a validation workflow.
// It is separate from untrusted evidence observation categories.
type Kind string

const (
	// Certificate identifies an exact certificate encoding.
	Certificate Kind = "certificate"
	// CRL identifies an exact certificate revocation list encoding.
	CRL Kind = "crl"
	// OCSP identifies an exact OCSP response encoding.
	OCSP Kind = "ocsp"
	// Signature identifies an exact document signature value.
	Signature Kind = "signature"
	// Timestamp identifies an exact timestamp token encoding.
	Timestamp Kind = "timestamp"
	// Digest identifies an authenticated hash-reference value.
	Digest Kind = "digest"
	// Data identifies exact application or transformed reference bytes.
	Data Kind = "data"
)

// Fact binds one exact object's SHA-256 to its proven existence upper bound.
// Source is the exact validating timestamp; zero denotes observation at Now.
// Kind distinguishes certificate, crl, ocsp, signature, timestamp and digest.
type Fact struct {
	Digest [32]byte
	Source [32]byte
	At     time.Time
	Kind   Kind
}

// Set is an immutable, bounded proof snapshot. A zero value is invalid.
type Set struct {
	now   time.Time
	facts []Fact
}

// New snapshots facts after the format and trust workflows have authenticated
// their bindings. At most 8192 facts and 2048 distinct objects are retained.
func New(ctx context.Context, now time.Time, facts []Fact) (*Set, error) {
	if ctx == nil || now.IsZero() || len(facts) > 8192 {
		return nil, ErrProof
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	objects := make(map[[32]byte]struct{}, min(len(facts), 2048))

	owned := make([]Fact, 0, len(facts))
	for _, fact := range facts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if fact.Digest == ([32]byte{}) || fact.At.IsZero() || fact.At.After(now) || !fact.Kind.Valid() || fact.Source == ([32]byte{}) && !fact.At.Equal(now) {
			return nil, ErrProof
		}

		objects[fact.Digest] = struct{}{}
		if len(objects) > 2048 {
			return nil, ErrProof
		}

		fact.At = fact.At.UTC()
		owned = append(owned, fact)
	}

	slices.SortFunc(owned, compare)
	owned = slices.Compact(owned)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &Set{now: now.UTC(), facts: owned}, nil
}

// Valid reports whether the role belongs to the closed proof vocabulary.
// A Kind converted from arbitrary text must still pass this check.
func (k Kind) Valid() bool {
	return k == Certificate || k == CRL || k == OCSP || k == Signature || k == Timestamp || k == Digest || k == Data
}

// Valid reports whether this set was constructed by a library workflow.
func (s *Set) Valid() bool { return s != nil && !s.now.IsZero() }

// Now is the explicit present-time observation used by this workflow.
func (s *Set) Now() time.Time {
	if !s.Valid() {
		return time.Time{}
	}

	return s.now
}

// Facts returns an owned diagnostic copy, never a mutable authentication store.
func (s *Set) Facts() []Fact {
	if !s.Valid() {
		return nil
	}

	return slices.Clone(s.facts)
}

// Earliest returns the earliest proven existence upper bound of exact bytes.
func (s *Set) Earliest(digest [32]byte) (time.Time, bool) {
	return s.EarliestKind(digest, "")
}

// EarliestKind also requires the named object role when kind is nonempty.
func (s *Set) EarliestKind(digest [32]byte, kind Kind) (time.Time, bool) {
	if !s.Valid() {
		return time.Time{}, false
	}

	var earliest time.Time
	// Small workflow snapshots are cheaper to scan than to binary-search.
	if len(s.facts) <= 64 {
		for _, fact := range s.facts {
			if fact.Digest == digest && (kind == "" || fact.Kind == kind) && (earliest.IsZero() || fact.At.Before(earliest)) {
				earliest = fact.At
			}
		}

		return earliest, !earliest.IsZero()
	}

	// Facts are ordered by digest, role, time and source. The first fact of
	// each matching role is therefore its earliest proof; skip its history.
	start, _ := slices.BinarySearchFunc(s.facts, Fact{Digest: digest, Kind: kind}, func(fact, key Fact) int {
		if order := slices.Compare(fact.Digest[:], key.Digest[:]); order != 0 {
			return order
		}

		return cmp.Compare(fact.Kind, key.Kind)
	})

	for start < len(s.facts) {
		fact := s.facts[start]
		if fact.Digest != digest || kind != "" && fact.Kind != kind {
			break
		}

		if kind != "" {
			return fact.At, true
		}

		if earliest.IsZero() || fact.At.Before(earliest) {
			earliest = fact.At
		}

		start += sort.Search(len(s.facts)-start, func(i int) bool {
			next := s.facts[start+i]
			return next.Digest != digest || next.Kind != fact.Kind
		})
	}

	return earliest, !earliest.IsZero()
}

// HasAtOrBefore applies the inclusive PoE boundary required by time sliding.
func (s *Set) HasAtOrBefore(digest [32]byte, at time.Time) bool {
	earliest, ok := s.Earliest(digest)
	return ok && !earliest.After(at)
}

func compare(a, b Fact) int {
	if c := slices.Compare(a.Digest[:], b.Digest[:]); c != 0 {
		return c
	}

	if a.Kind < b.Kind {
		return -1
	}

	if a.Kind > b.Kind {
		return 1
	}

	if c := a.At.Compare(b.At); c != 0 {
		return c
	}

	return slices.Compare(a.Source[:], b.Source[:])
}
