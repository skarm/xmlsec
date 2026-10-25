package x509name

import "sync"

type cacheEntry struct {
	raw string
	key string
}

// This process cache is deliberately bounded by both entry count and retained
// bytes. It stores only successful public DN comparisons, never control errors.
//
//nolint:gochecknoglobals // Bounded shared, synchronized comparison cache.
var nameCache struct {
	sync.Mutex
	entries [64]cacheEntry
	next    int
	bytes   int
}

func nameCacheGet(raw []byte) (string, bool) {
	nameCache.Lock()
	defer nameCache.Unlock()

	for _, entry := range nameCache.entries {
		if entry.raw != "" && entry.raw == string(raw) {
			return entry.key, true
		}
	}

	return "", false
}

func nameCachePut(raw, key string) {
	size := len(raw) + len(key)
	if size > 1<<20 {
		return
	}

	nameCache.Lock()
	defer nameCache.Unlock()

	evict := func(i int) {
		old := nameCache.entries[i]
		nameCache.bytes -= len(old.raw) + len(old.key)
		nameCache.entries[i] = cacheEntry{}
	}
	evict(nameCache.next)

	for nameCache.bytes+size > 1<<20 {
		nameCache.next = (nameCache.next + 1) % len(nameCache.entries)
		evict(nameCache.next)
	}

	nameCache.entries[nameCache.next] = cacheEntry{raw, key}
	nameCache.bytes += size
	nameCache.next = (nameCache.next + 1) % len(nameCache.entries)
}
