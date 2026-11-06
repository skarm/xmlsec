package expiry

import (
	"time"
)

// Only workspaces above this many entry slots are compacted after a usage spike; this is not a limit on live records.
const (
	retainedCapacityThreshold = 1024
)

// Shrink at quarter occupancy while preserving every live entry and the Index conservative latest-deadline bound.
const (
	retainedCapacityDivisor = 4
)

// Queue is a min-heap ordered by expiration. Its zero value is ready to use.
// Equal expiration times have no guaranteed order. Queue is not concurrent-safe.
type Queue[K any] struct{ items []item[K] }

type item[K any] struct {
	key K
	at  time.Time
}

// Trim releases excess capacity after a usage spike. Small queues keep their
// storage; larger queues shrink at or below one-quarter occupancy, leaving room
// for reuse. The heap order and all live entries are preserved.
func (q *Queue[K]) Trim() {
	const (
		retainedCapacityGrowthFactor = 2
	)

	if cap(q.items) <= retainedCapacityThreshold || len(q.items) > cap(q.items)/retainedCapacityDivisor {
		return
	}

	if len(q.items) == 0 {
		q.items = nil
		return
	}

	items := make([]item[K], len(q.items), max(retainedCapacityThreshold, retainedCapacityGrowthFactor*len(q.items)))
	copy(items, q.items)
	q.items = items
}

// Peek returns the earliest expiration without removing it.
func (q *Queue[K]) Peek() (time.Time, bool) {
	if len(q.items) == 0 {
		return time.Time{}, false
	}

	return q.items[0].at, true
}

// Push adds a key and expiration in O(log n) time without interface boxing.
func (q *Queue[K]) Push(key K, at time.Time) {
	x := item[K]{key, at}
	q.items = append(q.items, x)

	i := len(q.items) - 1
	for i > 0 {
		parent := (i - 1) / 2
		if !at.Before(q.items[parent].at) {
			break
		}

		q.items[i] = q.items[parent]
		i = parent
	}

	q.items[i] = x
}

// Pop removes the earliest entry in O(log n) time and clears retained references.
func (q *Queue[K]) Pop() (K, time.Time, bool) {
	if len(q.items) == 0 {
		var zero K
		return zero, time.Time{}, false
	}

	first := q.items[0]
	last := len(q.items) - 1
	x := q.items[last]
	q.items[last] = item[K]{}

	q.items = q.items[:last]
	if last > 0 {
		i := 0
		for {
			child := 2*i + 1
			if child >= last {
				break
			}

			if child+1 < last && q.items[child+1].at.Before(q.items[child].at) {
				child++
			}

			if !q.items[child].at.Before(x.at) {
				break
			}

			q.items[i] = q.items[child]
			i = child
		}

		q.items[i] = x
	}

	return first.key, first.at, true
}
