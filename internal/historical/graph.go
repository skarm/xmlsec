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
	// Facts keep their original order and sources; this lazily built index
	// only rejects redundant facts after larger histories have been admitted.
	earliest map[proofIdentity]time.Time
}

type proofIdentity struct {
	digest [32]byte
	kind   historicalproof.Kind
}

type proofOrigin struct {
	at     time.Time
	source [32]byte
}

type containmentWalk struct {
	ctx     context.Context
	objects map[[32]byte]Object
	// 1 means active; completed entries store their subtree height plus 2.
	states  map[[32]byte]uint8
	maximum int
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
	walk := containmentWalk{ctx: ctx, objects: g.objects, states: make(map[[32]byte]uint8, len(g.objects)), maximum: maximum}
	for key := range g.objects {
		if _, err := walk.visit(key, 0); err != nil {
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

func (g *graph) extractCovered(ctx context.Context, candidate Candidate, source [32]byte, upper time.Time) (map[[32]byte]struct{}, error) {
	seen := make(map[[32]byte]struct{})
	stack := slices.Clone(candidate.Covered)

	for len(stack) != 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		key := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if _, exists := seen[key]; exists {
			continue
		}

		item, ok := g.objects[key]
		if !ok || key == source {
			return nil, fmt.Errorf("%w: timestamp coverage", ErrInput)
		}

		seen[key] = struct{}{}
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
func (g *graph) extractReferences(ctx context.Context, seen map[[32]byte]struct{}, source [32]byte) error {
	for changed := true; changed; {
		changed = false

		set, err := g.set(ctx)
		if err != nil {
			return err
		}

		var sources map[[32]byte]proofOrigin
		if len(seen) > 64 {
			sources = g.proofOrigins()
		}

		for key := range seen {
			refs := g.objects[key].Refs
			if len(refs) == 0 {
				continue
			}

			containerTime, ok := set.Earliest(key)
			if !ok {
				continue
			}

			var proofSource [32]byte
			if origin, ok := sources[key]; ok {
				proofSource = origin.source
			} else {
				proofSource = g.containerSource(key, containerTime, source)
			}

			for _, ref := range refs {
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

// proofOrigins indexes the first source of each hash-reference container's
// earliest proof. Later appends cannot precede an existing first matching fact.
// Histories without hash references do not need an index allocation.
func (g *graph) proofOrigins() map[[32]byte]proofOrigin {
	var origins map[[32]byte]proofOrigin

	for _, fact := range g.facts {
		if len(g.objects[fact.Digest].Refs) == 0 {
			continue
		}

		if origins == nil {
			origins = make(map[[32]byte]proofOrigin, min(len(g.facts), len(g.objects)))
		}

		previous, exists := origins[fact.Digest]
		if !exists || fact.At.Before(previous.at) {
			origins[fact.Digest] = proofOrigin{fact.At, fact.Source}
		}
	}

	return origins
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
	key := proofIdentity{fact.Digest, fact.Kind}

	if g.earliest == nil && len(g.facts) > 64 {
		g.earliest = make(map[proofIdentity]time.Time, len(g.facts))

		for _, existing := range g.facts {
			identity := proofIdentity{existing.Digest, existing.Kind}

			if at, ok := g.earliest[identity]; !ok || existing.At.Before(at) {
				g.earliest[identity] = existing.At
			}
		}
	}

	if g.earliest != nil {
		if at, ok := g.earliest[key]; ok && !at.After(fact.At) {
			return nil
		}
	} else {
		for _, existing := range g.facts {
			if existing.Digest == fact.Digest && existing.Kind == fact.Kind && !existing.At.After(fact.At) {
				return nil
			}
		}
	}

	if len(g.facts) >= g.maximum {
		return ErrLimit
	}

	g.facts = append(g.facts, fact)
	if g.earliest != nil {
		g.earliest[key] = fact.At
	}

	return nil
}

func (w *containmentWalk) visit(key [32]byte, depth int) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}

	if depth > 64 || depth > w.maximum {
		return 0, ErrLimit
	}

	state := w.states[key]
	if state == 1 {
		return 0, fmt.Errorf("%w: containment cycle", ErrInput)
	}

	if state >= 2 {
		height := int(state) - 2
		if height > 64-depth || height > w.maximum-depth {
			return 0, ErrLimit
		}

		return height, nil
	}

	w.states[key] = 1
	height := 0

	for _, child := range w.objects[key].Contains {
		childHeight, err := w.visit(child, depth+1)
		if err != nil {
			return 0, err
		}

		height = max(height, childHeight+1)
	}
	// #nosec G115 -- Each child passed the depth/height checks above; height is 0..64.
	w.states[key] = uint8(height) + 2

	return height, nil
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
