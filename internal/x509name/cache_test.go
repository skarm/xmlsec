package x509name //nolint:testpackage // Checks retention limits in the private comparison cache.

import (
	"strings"
	"testing"
)

func TestNameCacheDoesNotRetainOversizedEntry(t *testing.T) {
	t.Parallel()

	const raw = "oversized cache entry"
	nameCachePut(raw, strings.Repeat("x", maximumNameCacheBytes))
	if got, hit := nameCacheGet([]byte(raw)); hit {
		t.Fatalf("oversized entry retained (%d key bytes)", len(got))
	}
}
