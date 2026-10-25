// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"container/list"
	"sync"
)

// Per-evaluator limits bound both entry count and conservative storage weight.
const (
	xpathRegexCacheCapacity = 1024
	xpathRegexCacheBytes    = 8 << 20
)

type regexLRUEntry struct {
	key   xpathRegexCacheKey
	value *compiledXPathRegex
	bytes int
}

// regexLRUCache shares immutable compiled patterns under count and weight limits.
// Programs exceeding the weight budget remain usable without being cached.
type regexLRUCache struct {
	mu    sync.Mutex
	cap   int
	bytes int
	ll    *list.List // front = most recently used
	items map[xpathRegexCacheKey]*list.Element
}

func newRegexLRUCache(capacity int) *regexLRUCache {
	if capacity < 1 {
		capacity = 1
	}

	return &regexLRUCache{
		cap:   capacity,
		ll:    list.New(),
		items: make(map[xpathRegexCacheKey]*list.Element, capacity),
	}
}

// Load returns the cached compiled regex for key, marking it most-recently-used.
func (c *regexLRUCache) Load(key xpathRegexCacheKey) (*compiledXPathRegex, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return nil, false
	}

	c.ll.MoveToFront(el)

	return el.Value.(*regexLRUEntry).value, true //nolint:forcetypeassert
}

// LoadOrStore returns the existing value for key, marking it most-recently-used,
// or admits value under both limits. Oversized programs are returned uncached.
// The bool reports whether an existing value was loaded. Admission evicts the
// least-recently-used entries as needed.
func (c *regexLRUCache) LoadOrStore(key xpathRegexCacheKey, value *compiledXPathRegex) (*compiledXPathRegex, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*regexLRUEntry).value, true //nolint:forcetypeassert
	}

	weight := 2*(len(key.pattern)+len(key.flags)) + 256 + value.program.CacheCost(xpathRegexCacheBytes+1)
	if weight > xpathRegexCacheBytes {
		return value, false
	}

	for oldest := c.ll.Back(); oldest != nil && (c.ll.Len() >= c.cap || weight > xpathRegexCacheBytes-c.bytes); oldest = c.ll.Back() {
		entry := oldest.Value.(*regexLRUEntry) //nolint:forcetypeassert // Only regexLRUEntry values are inserted.
		c.ll.Remove(oldest)
		delete(c.items, entry.key)
		c.bytes -= entry.bytes
	}

	el := c.ll.PushFront(&regexLRUEntry{key: key, value: value, bytes: weight})

	c.items[key] = el
	c.bytes += weight

	return value, false
}
