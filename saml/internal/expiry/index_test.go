package expiry //nolint:testpackage // Checks heap ordering, index consistency and release of deleted keys.

import (
	"math/rand/v2"
	"testing"
	"time"
)

// Compare arbitrary updates, early deletions and expiry against a plain map.
// Equal deadlines need no stable ordering, but every returned key must be due.
func TestIndexAgainstMap(t *testing.T) {
	var queue Index[int]
	want := make(map[int]time.Time)
	random := rand.New(rand.NewPCG(11, 37))
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for range 20000 {
		key := random.IntN(1024)
		at := base.Add(time.Duration(random.IntN(100)) * time.Second)
		switch random.IntN(4) {
		case 0, 1:
			queue.Set(key, at)
			want[key] = at
		case 2:
			queue.Delete(key)
			delete(want, key)
		case 3:
			for {
				key, ok := queue.PopExpired(at)
				if !ok {
					break
				}
				deadline, found := want[key]
				if !found || deadline.After(at) {
					t.Fatalf("unexpected expired key %d at %s", key, at)
				}
				delete(want, key)
			}
			for key, deadline := range want {
				if !deadline.After(at) {
					t.Fatalf("due key %d was not returned", key)
				}
			}
		}
		queue.Trim()
		if queue.AllExpired(at) {
			for _, deadline := range want {
				if deadline.After(at) {
					t.Fatal("bulk expiration would discard a live key")
				}
			}
		}
		if len(queue.items) != len(want) || len(queue.positions) != len(want) {
			t.Fatal("index retained a deleted key or lost a live key")
		}
		for i, entry := range queue.items {
			if queue.positions[entry.key] != i || !want[entry.key].Equal(entry.at) {
				t.Fatal("index lost key or deadline after a heap move")
			}
			if i > 0 && entry.at.Before(queue.items[(i-1)/2].at) {
				t.Fatal("expiration heap is out of order")
			}
		}
	}
}

func TestIndexReleasesDeletedKeys(t *testing.T) {
	var queue Index[*int]
	for i := range 4096 {
		queue.Set(&i, time.Unix(int64(i), 0))
	}
	storage := queue.items[:cap(queue.items)]
	for range 4096 {
		if _, ok := queue.PopExpired(time.Unix(4096, 0)); !ok {
			t.Fatal("missing expired key")
		}
	}
	for _, entry := range storage {
		if entry.key != nil || !entry.at.IsZero() {
			t.Fatal("removed entry still retains a reference")
		}
	}
	queue.Trim()
	if cap(queue.items) != 0 || len(queue.positions) != 0 || queue.peak != 0 {
		t.Fatal("index did not shrink after draining")
	}
	key := 1
	queue.Set(&key, time.Unix(1, 0))
	if got, ok := queue.PopExpired(time.Unix(1, 0)); !ok || got != &key {
		t.Fatal("index cannot be reused after trimming")
	}
}

func TestIndexBulkExpiry(t *testing.T) {
	var queue Index[int]
	first, second, later := time.Unix(1, 0), time.Unix(2, 0), time.Unix(3, 0)
	queue.Set(1, first)
	queue.Set(2, second)
	if queue.AllExpired(first) || !queue.AllExpired(second) {
		t.Fatal("bulk expiry ignored the last live deadline")
	}
	queue.Set(1, later)
	if queue.AllExpired(second) || !queue.AllExpired(later) {
		t.Fatal("updating a deadline allowed premature bulk expiry")
	}
	queue.Delete(1)
	if !queue.AllExpired(later) {
		t.Fatal("bulk expiry lost remaining entries after deletion")
	}
	queue.Reset()
	if queue.AllExpired(later) || len(queue.items) != 0 || len(queue.positions) != 0 {
		t.Fatal("reset retained indexed entries")
	}
	queue.Set(3, first)
	if !queue.AllExpired(first) {
		t.Fatal("index was not reusable after reset")
	}
}

type deadlineEntry struct {
	key string
	at  time.Time
}

func TestIndexZeroDeadlineUpperBound(t *testing.T) {
	t.Parallel()

	zero := time.Time{}
	earlier, later := zero.Add(-time.Hour), zero.Add(time.Hour)
	for _, test := range []struct {
		name    string
		initial []deadlineEntry
		updates []deadlineEntry
		remove  string
	}{
		{name: "zero then earlier", initial: []deadlineEntry{{"zero", zero}, {"earlier", earlier}}},
		{name: "earlier zero then earlier", initial: []deadlineEntry{{"earlier", earlier}, {"zero", zero}, {"oldest", earlier.Add(-time.Hour)}}},
		{name: "zero only", initial: []deadlineEntry{{"zero", zero}}},
		{name: "zero then later", initial: []deadlineEntry{{"zero", zero}, {"later", later}}},
		{name: "latest replaced earlier", initial: []deadlineEntry{{"a", later}, {"zero", zero}}, updates: []deadlineEntry{{"a", earlier}}},
		{name: "latest extended", initial: []deadlineEntry{{"a", earlier}, {"zero", zero}}, updates: []deadlineEntry{{"a", later}}},
		{name: "latest removed", initial: []deadlineEntry{{"a", later}, {"zero", zero}}, remove: "a"},
		{name: "empty"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var queue Index[string]
			want := make(map[string]time.Time)
			for _, entry := range append(test.initial, test.updates...) {
				queue.Set(entry.key, entry.at)
				want[entry.key] = entry.at
			}
			if test.remove != "" {
				queue.Delete(test.remove)
				delete(want, test.remove)
			}
			for key, deadline := range want {
				if deadline.After(queue.latest) {
					t.Errorf("latest %v is below live deadline %q=%v", queue.latest, key, deadline)
				}
			}
			for _, at := range []time.Time{earlier.Add(-2 * time.Hour), earlier, zero, later} {
				checkIndexDeadlineBoundary(t, &queue, want, at)
			}
			if len(want) != 0 || queue.AllExpired(later) || !queue.latest.IsZero() {
				t.Fatal("drained index retained entries or latest deadline")
			}
		})
	}
}

func checkIndexDeadlineBoundary(t *testing.T, queue *Index[string], want map[string]time.Time, at time.Time) {
	t.Helper()

	if queue.AllExpired(at) {
		for key, deadline := range want {
			if deadline.After(at) {
				t.Errorf("AllExpired(%v) would discard live %q=%v", at, key, deadline)
			}
		}
	}
	for {
		key, ok := queue.PopExpired(at)
		if !ok {
			break
		}
		deadline, exists := want[key]
		if !exists || deadline.After(at) {
			t.Fatalf("unexpected expired key %q at %v", key, at)
		}
		delete(want, key)
	}
	for key, deadline := range want {
		if !deadline.After(at) {
			t.Fatalf("due key %q was not returned at %v", key, at)
		}
	}
}

func TestIndexZeroDeadlineResetAndReuse(t *testing.T) {
	t.Parallel()

	var queue Index[string]
	zero := time.Time{}
	queue.Set("zero", zero)
	queue.Delete("zero")
	if queue.AllExpired(zero) || !queue.latest.IsZero() {
		t.Fatal("deleting the final record retained a deadline")
	}
	queue.Set("later", zero.Add(time.Hour))
	queue.Reset()
	if queue.AllExpired(zero) || len(queue.items) != 0 || !queue.latest.IsZero() {
		t.Fatal("reset retained indexed state")
	}
	queue.Set("earlier", zero.Add(-time.Hour))
	if !queue.AllExpired(zero.Add(-time.Hour)) {
		t.Fatal("reset prevented reuse with an earlier deadline")
	}
}
