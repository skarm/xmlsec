package expiry

import "time"

// Index is an expiration heap with one entry per key. Updating or deleting a
// live record takes O(log n); early deletion never leaves a retained tombstone.
// Its zero value is ready to use. Like Queue, it is not concurrent-safe.
type Index[K comparable] struct {
	items     []item[K]
	positions map[K]int
	peak      int
	latest    time.Time // conservative upper bound, including overwritten deadlines
}

// Set inserts a key or replaces its expiration.
func (q *Index[K]) Set(key K, at time.Time) {
	if len(q.items) == 0 || at.After(q.latest) {
		q.latest = at
	}

	if i, ok := q.positions[key]; ok {
		q.items[i].at = at
		q.fix(i)

		return
	}

	if q.positions == nil {
		q.positions = make(map[K]int)
	}

	i := len(q.items)
	q.items = append(q.items, item[K]{key: key, at: at})
	q.positions[key] = i
	q.peak = max(q.peak, len(q.items))
	q.up(i)
}

// Delete removes a key and clears the heap's references to it.
func (q *Index[K]) Delete(key K) {
	i, ok := q.positions[key]
	if !ok {
		return
	}

	delete(q.positions, key)

	last := len(q.items) - 1
	if i != last {
		q.items[i] = q.items[last]
		q.positions[q.items[i].key] = i
	}

	q.items[last] = item[K]{}

	q.items = q.items[:last]
	if last == 0 {
		q.latest = time.Time{}
	}

	if i < last {
		q.fix(i)
	}
}

// AllExpired reports when every indexed record is known to be expired. Stores
// can then clear their maps in bulk instead of removing an entire heap one key
// at a time. A replaced or deleted deadline can make this conservatively false.
func (q *Index[K]) AllExpired(at time.Time) bool {
	return len(q.items) != 0 && !at.Before(q.latest)
}

// Reset releases all indexed keys and their storage.
func (q *Index[K]) Reset() { *q = Index[K]{} }

// PopExpired removes the earliest key only when its expiration is at or before at.
func (q *Index[K]) PopExpired(at time.Time) (K, bool) {
	if len(q.items) == 0 || at.Before(q.items[0].at) {
		var zero K
		return zero, false
	}

	key := q.items[0].key
	q.Delete(key)

	return key, true
}

// Trim releases excess heap and index capacity after a usage spike.
func (q *Index[K]) Trim() {
	queue := Queue[K]{items: q.items}
	queue.Trim()

	q.items = queue.items
	if q.peak > retainedCapacityThreshold && len(q.items) <= q.peak/retainedCapacityDivisor {
		q.positions = make(map[K]int, len(q.items))
		for i, entry := range q.items {
			q.positions[entry.key] = i
		}

		q.peak = len(q.items)
	}
}

func (q *Index[K]) swap(i, j int) {
	q.items[i], q.items[j] = q.items[j], q.items[i]
	q.positions[q.items[i].key], q.positions[q.items[j].key] = i, j
}

func (q *Index[K]) up(i int) {
	for i > 0 {
		parent := (i - 1) / 2
		if !q.items[i].at.Before(q.items[parent].at) {
			break
		}

		q.swap(i, parent)
		i = parent
	}
}

func (q *Index[K]) fix(i int) {
	if i > 0 && q.items[i].at.Before(q.items[(i-1)/2].at) {
		q.up(i)
		return
	}

	for {
		child := 2*i + 1
		if child >= len(q.items) {
			return
		}

		if child+1 < len(q.items) && q.items[child+1].at.Before(q.items[child].at) {
			child++
		}

		if !q.items[child].at.Before(q.items[i].at) {
			return
		}

		q.swap(i, child)
		i = child
	}
}
