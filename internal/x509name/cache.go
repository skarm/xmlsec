package x509name

import "sync"

const (
	maximumCachedNames    = 64
	maximumNameCacheBytes = 1 << 20
)

// This process cache is deliberately bounded by both entry count and retained
// bytes. It stores only successful public DN comparisons, never control errors.
//
//nolint:gochecknoglobals // Bounded shared, synchronized comparison cache.
var nameCache struct {
	sync.Mutex
	entries [maximumCachedNames]cacheEntry
	next    int
	bytes   int
}

type cacheEntry struct {
	raw string
	key string
}

func nameCacheGet(raw []byte) (string, bool) {
	nameCache.Lock()

	for _, entry := range nameCache.entries {
		if entry.raw != "" && entry.raw == string(raw) {
			nameCache.Unlock()
			return entry.key, true
		}
	}

	nameCache.Unlock()

	return "", false
}

func nameCachePut(raw, key string) {
	size := len(raw) + len(key)
	if size > maximumNameCacheBytes {
		return
	}

	nameCache.Lock()

	evict := func(i int) {
		old := nameCache.entries[i]
		nameCache.bytes -= len(old.raw) + len(old.key)
		nameCache.entries[i] = cacheEntry{}
	}
	evict(nameCache.next)

	for nameCache.bytes+size > maximumNameCacheBytes {
		nameCache.next = (nameCache.next + 1) % len(nameCache.entries)
		evict(nameCache.next)
	}

	nameCache.entries[nameCache.next] = cacheEntry{raw, key}
	nameCache.bytes += size
	nameCache.next = (nameCache.next + 1) % len(nameCache.entries)
	nameCache.Unlock()
}
