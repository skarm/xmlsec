package expiry_test

import (
	"math/rand/v2"
	"sort"
	"testing"
	"time"

	"github.com/skarm/xmlsec/saml/internal/expiry"
)

func TestQueueOrderingAndReuse(t *testing.T) {
	var q expiry.Queue[int]
	if _, ok := q.Peek(); ok {
		t.Fatal("nonempty zero value")
	}

	if _, _, ok := q.Pop(); ok {
		t.Fatal("popped zero value")
	}

	rng := rand.New(rand.NewPCG(11, 29))
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Interleave insertion and removal; ties must retain every key exactly once.
	remaining := map[int]time.Time{}

	for id := range 2000 {
		at := base.Add(time.Duration(rng.IntN(25)) * time.Second)
		q.Push(id, at)

		remaining[id] = at
		if rng.IntN(3) == 0 {
			checkPop(t, &q, remaining)
		}
	}

	for len(remaining) != 0 {
		q.Trim()
		checkPop(t, &q, remaining)
	}

	q.Trim()

	if _, _, ok := q.Pop(); ok {
		t.Fatal("queue not empty")
	}

	q.Push(3000, base)
	checkPop(t, &q, map[int]time.Time{3000: base})
}

func checkPop(t *testing.T, q *expiry.Queue[int], remaining map[int]time.Time) {
	t.Helper()

	dates := make([]time.Time, 0, len(remaining))
	for _, at := range remaining {
		dates = append(dates, at)
	}

	sort.Slice(dates, func(i, j int) bool { return dates[i].Before(dates[j]) })

	first, ok := q.Peek()
	if !ok || !first.Equal(dates[0]) {
		t.Fatalf("peek=%v, expected=%v", first, dates[0])
	}

	id, at, ok := q.Pop()

	expected, exists := remaining[id]
	if !ok || !exists || !at.Equal(expected) || !at.Equal(dates[0]) {
		t.Fatalf("invalid pop: %d %v", id, at)
	}

	delete(remaining, id)
}

func TestTrimPreservesLiveEntries(t *testing.T) {
	var q expiry.Queue[int]

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 8192 {
		q.Push(i, base.Add(time.Duration(i)*time.Second))
	}

	for i := range 8000 {
		id, _, ok := q.Pop()
		if !ok || id != i {
			t.Fatal("queue ordering changed", id, i)
		}
	}

	q.Trim()
	q.Push(8192, base.Add(8192*time.Second))

	for i := 8000; i <= 8192; i++ {
		id, at, ok := q.Pop()
		if !ok || id != i || !at.Equal(base.Add(time.Duration(i)*time.Second)) {
			t.Fatal("trim lost live entries", id, i, at)
		}
	}

	q.Trim()

	if _, ok := q.Peek(); ok {
		t.Fatal("trim retained removed entries")
	}
}

func BenchmarkPushPop(b *testing.B) {
	var q expiry.Queue[int]

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 1024 {
		q.Push(i, base.Add(time.Duration(i)*time.Second))
	}

	b.ReportAllocs()

	i := 0
	for b.Loop() {
		q.Push(i+1024, base.Add(time.Duration(i+1024)*time.Second))

		key, _, ok := q.Pop()
		if !ok || key != i {
			b.Fatal("invalid expiration order")
		}

		i++
	}
}
