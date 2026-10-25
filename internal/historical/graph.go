package historical

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/pki"
)

type graph struct {
	objects     map[[32]byte]Object
	facts       []historicalproof.Fact
	now         time.Time
	maximum     int
	constraints []pki.CryptoConstraint
}

func newGraph(ctx context.Context, c Config, in Input, now time.Time) (*graph, error) {
	if len(in.Objects) > c.MaxObjects || len(in.Timestamps) > c.MaxTimestamps {
		return nil, ErrLimit
	}

	g := &graph{objects: make(map[[32]byte]Object, len(in.Objects)), now: now, maximum: c.MaxEdges}
	g.constraints = slices.Clone(c.SignerHistory.CryptoConstraints)
	remaining, edges := c.MaxBytes, 0

	for _, item := range in.Objects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if err := g.admitObject(item, &remaining, &edges, c.MaxEdges); err != nil {
			return nil, err
		}
	}

	if _, ok := g.objects[in.Signature]; !ok {
		return nil, fmt.Errorf("%w: no exact signature object", ErrInput)
	}

	if err := g.checkBindings(); err != nil {
		return nil, err
	}

	if err := g.checkAcyclic(ctx, c.MaxEdges); err != nil {
		return nil, err
	}

	return g, nil
}

func (g *graph) admitObject(item Object, remaining, edges *int, maximum int) error {
	if len(item.Bytes) == 0 && item.Kind != objectData || len(item.Bytes) > *remaining || !item.Kind.Valid() {
		return ErrInput
	}

	key := sha256.Sum256(item.Bytes)
	if previous, ok := g.objects[key]; ok {
		return checkObjectIdentity(previous, item)
	}

	*remaining -= len(item.Bytes)
	if len(item.Contains)+len(item.Refs) > maximum-*edges {
		return ErrLimit
	}

	*edges += len(item.Contains) + len(item.Refs)
	item.Bytes = bytes.Clone(item.Bytes)
	item.Contains = slices.Clone(item.Contains)

	item.Refs = slices.Clone(item.Refs)
	for i := range item.Refs {
		item.Refs[i].Digest = bytes.Clone(item.Refs[i].Digest)
	}

	g.objects[key] = item
	g.facts = append(g.facts, historicalproof.Fact{Digest: key, At: g.now, Kind: item.Kind})

	return nil
}

func checkObjectIdentity(previous, item Object) error {
	if !bytes.Equal(previous.Bytes, item.Bytes) || previous.Kind != item.Kind || !slices.Equal(previous.Contains, item.Contains) || len(previous.Refs) != len(item.Refs) {
		return fmt.Errorf("%w: conflicting exact-object binding", ErrInput)
	}

	for i, ref := range previous.Refs {
		other := item.Refs[i]
		if ref.Hash != other.Hash || ref.Target != other.Target || !bytes.Equal(ref.Digest, other.Digest) {
			return ErrInput
		}
	}

	return nil
}

func (g *graph) checkBindings() error {
	for key, item := range g.objects {
		for _, child := range item.Contains {
			if _, ok := g.objects[child]; !ok || key == child {
				return ErrInput
			}
		}

		for _, ref := range item.Refs {
			if err := g.checkHashReference(ref); err != nil {
				return err
			}
		}
	}

	return nil
}

func (g *graph) checkHashReference(ref HashReference) error {
	target, ok := g.objects[ref.Target]
	if !ok || ref.Hash == 0 || !ref.Hash.Available() || len(ref.Digest) != ref.Hash.Size() {
		return ErrInput
	}

	h := ref.Hash.New()

	_, _ = h.Write(target.Bytes)
	if !bytes.Equal(h.Sum(nil), ref.Digest) {
		return fmt.Errorf("%w: unbound object hash", ErrInput)
	}

	return nil
}

func (g *graph) checkAcyclic(ctx context.Context, maximum int) error {
	state := make(map[[32]byte]uint8, len(g.objects))

	var visit func([32]byte, int) error

	visit = func(key [32]byte, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if depth > 64 || depth > maximum {
			return ErrLimit
		}

		if state[key] == 1 {
			return fmt.Errorf("%w: containment cycle", ErrInput)
		}

		if state[key] == 2 {
			return nil
		}

		state[key] = 1
		for _, child := range g.objects[key].Contains {
			if err := visit(child, depth+1); err != nil {
				return err
			}
		}

		state[key] = 2

		return nil
	}
	for key := range g.objects {
		if err := visit(key, 0); err != nil {
			return err
		}
	}

	return nil
}

func (g *graph) set(ctx context.Context) (*historicalproof.Set, error) {
	return historicalproof.New(ctx, g.now, g.facts)
}

func (g *graph) extract(ctx context.Context, candidate Candidate, source [32]byte, upper time.Time) error {
	seen, err := g.extractCovered(ctx, candidate, source, upper)
	if err != nil {
		return err
	}

	return g.extractReferences(ctx, seen, source)
}

func (g *graph) extractCovered(ctx context.Context, candidate Candidate, source [32]byte, upper time.Time) (map[[32]byte]bool, error) {
	seen := make(map[[32]byte]bool)
	stack := slices.Clone(candidate.Covered)

	for len(stack) != 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		key := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if seen[key] {
			continue
		}

		item, ok := g.objects[key]
		if !ok || key == source {
			return nil, fmt.Errorf("%w: timestamp coverage", ErrInput)
		}

		seen[key] = true
		if len(seen) > g.maximum {
			return nil, ErrLimit
		}

		if err := g.add(historicalproof.Fact{Digest: key, Source: source, At: upper, Kind: item.Kind}); err != nil {
			return nil, err
		}

		stack = append(stack, item.Contains...)
	}

	return seen, nil
}

// Hash indirection follows §5.6.2.3(4), using separately established
// existence of the actual object. It never treats a digest as object bytes.
func (g *graph) extractReferences(ctx context.Context, seen map[[32]byte]bool, source [32]byte) error {
	for changed := true; changed; {
		changed = false

		set, err := g.set(ctx)
		if err != nil {
			return err
		}

		for key := range seen {
			containerTime, ok := set.Earliest(key)
			if !ok {
				continue
			}

			proofSource := g.containerSource(key, containerTime, source)
			for _, ref := range g.objects[key].Refs {
				updated, err := g.extractReference(ctx, set, ref, proofSource, containerTime)
				if err != nil {
					return err
				}

				changed = changed || updated
			}
		}
	}

	return nil
}

func (g *graph) containerSource(key [32]byte, at time.Time, fallback [32]byte) [32]byte {
	for _, fact := range g.facts {
		if fact.Digest == key && fact.At.Equal(at) {
			return fact.Source
		}
	}

	return fallback
}

func (g *graph) extractReference(ctx context.Context, set *historicalproof.Set, ref HashReference, source [32]byte, at time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if !hashReliable(ref.Hash, at, g.constraints) {
		return false, nil
	}

	digestKey := sha256.Sum256(ref.Digest)
	if err := g.add(historicalproof.Fact{Digest: digestKey, Source: source, At: at, Kind: historicalproof.Digest}); err != nil {
		return false, err
	}

	actual, exists := set.Earliest(ref.Target)
	if !exists || actual.Before(at) || !hashReliable(ref.Hash, actual, g.constraints) {
		return false, nil
	}

	if actual.After(at) {
		if err := g.add(historicalproof.Fact{Digest: ref.Target, Source: source, At: at, Kind: g.objects[ref.Target].Kind}); err != nil {
			return false, err
		}

		return true, nil
	}

	return false, nil
}

func (g *graph) add(fact historicalproof.Fact) error {
	for _, existing := range g.facts {
		if existing.Digest == fact.Digest && existing.Kind == fact.Kind && !existing.At.After(fact.At) {
			return nil
		}
	}

	if len(g.facts) >= g.maximum {
		return ErrLimit
	}

	g.facts = append(g.facts, fact)

	return nil
}
