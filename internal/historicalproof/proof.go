// Package historicalproof stores exact-object existence facts produced by the
// library's validation workflows. Its constructors are intentionally internal:
// acquisition metadata and caller-provided times cannot mint authenticated PoE.
package historicalproof

import (
	"context"
	"errors"
	"slices"
	"time"
)

// ErrProof reports an invalid or over-budget proof set.
var ErrProof = errors.New("invalid historical proof set")

// Fact binds one exact object's SHA-256 to its proven existence upper bound.
// Source is the exact validating timestamp; zero denotes observation at Now.
// Kind distinguishes certificate, crl, ocsp, signature, timestamp and digest.
type Fact struct {
	Digest [32]byte
	Source [32]byte
	At     time.Time
	Kind   string
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

	objects := make(map[[32]byte]struct{}, min(len(facts), 2048))

	owned := make([]Fact, 0, len(facts))
	for _, fact := range facts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if fact.Digest == ([32]byte{}) || fact.At.IsZero() || fact.At.After(now) || !validKind(fact.Kind) || fact.Source == ([32]byte{}) && !fact.At.Equal(now) {
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

	return &Set{now: now.UTC(), facts: owned}, nil
}

func validKind(kind string) bool {
	return kind == "certificate" || kind == "crl" || kind == "ocsp" || kind == "signature" || kind == "timestamp" || kind == "digest" || kind == "data"
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
func (s *Set) EarliestKind(digest [32]byte, kind string) (time.Time, bool) {
	if !s.Valid() {
		return time.Time{}, false
	}

	var earliest time.Time
	for _, fact := range s.facts {
		if fact.Digest == digest && (kind == "" || fact.Kind == kind) && (earliest.IsZero() || fact.At.Before(earliest)) {
			earliest = fact.At
		}
	}

	return earliest, !earliest.IsZero()
}

// HasAtOrBefore applies the inclusive PoE boundary required by time sliding.
func (s *Set) HasAtOrBefore(digest [32]byte, at time.Time) bool {
	earliest, ok := s.Earliest(digest)
	return ok && !earliest.After(at)
}
