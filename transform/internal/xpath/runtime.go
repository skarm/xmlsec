package xpath

import (
	"context"
	"strings"
	"sync"
)

// A bounded FIFO keeps dynamic collation URIs from accumulating for the lifetime
// of a reusable evaluator. Oversized keys remain valid but are not retained.
const (
	collationCacheCapacity = 128
	collationCacheKeyBytes = 4096
	maxIdlePathProbes      = 4
)

// evaluationRuntime owns reusable execution resources for an evaluator family.
// Configuration copies share this owner; no cache outlives its evaluator family.
type evaluationRuntime struct {
	probes        chan *pathProbe
	probesOnce    sync.Once
	regexOnce     sync.Once
	regexes       *regexLRUCache
	collations    sync.Map
	collationMu   sync.Mutex
	collationKeys [][2]string
	collationNext int
}

func (r *evaluationRuntime) borrowProbe() *pathProbe {
	r.probesOnce.Do(func() { r.probes = make(chan *pathProbe, maxIdlePathProbes) })

	select {
	case p := <-r.probes:
		return p
	default:
		return &pathProbe{}
	}
}

func (r *evaluationRuntime) regexCache() *regexLRUCache {
	r.regexOnce.Do(func() { r.regexes = newRegexLRUCache(xpathRegexCacheCapacity) })
	return r.regexes
}

func (r *evaluationRuntime) resolveCollation(uri, baseURI string) (*collationImpl, error) {
	key := [2]string{uri, baseURI}
	if cached, ok := r.collations.Load(key); ok {
		if coll, valid := cached.(*collationImpl); valid {
			return coll, nil
		}
	}

	cacheable := len(uri) <= collationCacheKeyBytes && len(baseURI) <= collationCacheKeyBytes-len(uri)
	if cacheable {
		// Both keys and parsed collation options can retain slices of these strings.
		// Own the small inputs so they cannot pin a caller's much larger buffer.
		uri, baseURI = strings.Clone(uri), strings.Clone(baseURI)
		key = [2]string{uri, baseURI}
	}

	coll, err := resolveCollation(uri, baseURI)
	if err != nil {
		return nil, err
	}

	if !cacheable {
		return coll, nil
	}

	// Resolve outside the lock; readers keep the sync.Map fast path. Serialize
	// insertion and eviction so concurrent misses cannot exceed the capacity.
	r.collationMu.Lock()
	defer r.collationMu.Unlock()

	if stored, ok := r.collations.Load(key); ok {
		return stored.(*collationImpl), nil //nolint:forcetypeassert
	}

	if len(r.collationKeys) == collationCacheCapacity {
		r.collations.Delete(r.collationKeys[r.collationNext])
		r.collationKeys[r.collationNext] = key
		r.collationNext = (r.collationNext + 1) % collationCacheCapacity
	} else {
		r.collationKeys = append(r.collationKeys, key)
	}

	r.collations.Store(key, coll)

	return coll, nil
}

func resolveContextCollation(ctx context.Context, uri, baseURI string) (*collationImpl, error) {
	if ec := getFnContext(ctx); ec != nil && ec.runtime != nil {
		return ec.runtime.resolveCollation(uri, baseURI)
	}

	return resolveCollation(uri, baseURI)
}
