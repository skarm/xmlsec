package replay

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/skarm/xmlsec/saml/internal/expiry"
)

var (
	// ErrReplay reports SAML identifier already consumed.
	ErrReplay = errors.New("SAML identifier already consumed")
	// ErrCapacity reports replay store capacity reached.
	ErrCapacity = errors.New("replay store capacity reached")
	// ErrPolicy reports invalid replay-store policy or entry.
	ErrPolicy = errors.New("invalid replay-store policy or entry")
)

// Entry pairs a scoped SAML identifier with its expiration for atomic consumption.
type Entry struct {
	// Scope separates identifier namespaces, such as the entity and message role.
	Scope string
	// ID is the identifier to consume exactly once within Scope.
	ID string
	// ExpiresAt is the time after which this identifier no longer blocks reuse.
	ExpiresAt time.Time
}

// Store consumes every supplied entry atomically or consumes none. Call Consume
// only after cryptographic and protocol validation. Combining request and
// assertion identifiers in one operation prevents concurrent request reuse that
// separate check-and-insert calls cannot prevent.
type Store interface {
	// Consume atomically records every supplied entry or none at the supplied time. It
	// returns ErrReplay if an unexpired identifier was consumed already.
	Consume(context.Context, []Entry, time.Time) error
}

// Config sets capacity and lifetime bounds for an in-memory replay store. Zero fields
// select defaults.
type Config struct {
	// Capacity bounds stored entries; zero selects 100000. Unexpired entries
	// are never evicted to make room.
	Capacity int
	// MaxTTL bounds the lifetime of an inserted entry; zero selects one hour.
	MaxTTL time.Duration
}

// MemoryStore provides concurrent bounded replay protection within one process.
// Consume removes expired entries.
type MemoryStore struct {
	mu       sync.Mutex
	capacity int
	peak     int // maximum entry count since the last compaction
	maxTTL   time.Duration
	entries  map[key]time.Time
	expiry   expiry.Queue[key]
}

type key struct {
	scope string
	id    string
}

// NewMemoryStore creates an empty bounded replay store using default limits for zero Config
// fields.
func NewMemoryStore(c Config) (*MemoryStore, error) {
	if c.Capacity == 0 {
		c.Capacity = 100000
	}

	if c.MaxTTL == 0 {
		c.MaxTTL = time.Hour
	}

	if c.Capacity < 1 || c.Capacity > 10000000 || c.MaxTTL < time.Second || c.MaxTTL > 7*24*time.Hour {
		return nil, ErrPolicy
	}

	return &MemoryStore{capacity: c.Capacity, maxTTL: c.MaxTTL, entries: make(map[key]time.Time)}, nil
}

// Consume atomically consumes all supplied scoped identifiers or none. It prunes expired
// entries and never evicts unexpired identifiers.
func (m *MemoryStore) Consume(ctx context.Context, entries []Entry, now time.Time) error {
	if m == nil || ctx == nil || now.IsZero() || len(entries) < 1 || len(entries) > 16 {
		return ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	var snapshot [16]Entry

	copied := snapshot[:copy(snapshot[:], entries)]

	seen := make(map[key]struct{}, len(copied))
	for _, e := range copied {
		if e.Scope == "" || e.ID == "" || len(e.Scope) > 1024 || len(e.ID) > 1024 || !e.ExpiresAt.After(now) || e.ExpiresAt.After(now.Add(m.maxTTL)) {
			return ErrPolicy
		}

		k := key{e.Scope, e.ID}
		if _, exists := seen[k]; exists {
			return ErrPolicy
		}

		seen[k] = struct{}{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := m.prune(ctx, now); err != nil {
		return err
	}

	for k := range seen {
		if _, ok := m.entries[k]; ok {
			return ErrReplay
		}
	}

	if len(copied) > m.capacity-len(m.entries) {
		return ErrCapacity
	} // never evict unexpired IDs

	for _, e := range copied {
		k := key{strings.Clone(e.Scope), strings.Clone(e.ID)}
		m.entries[k] = e.ExpiresAt
		m.expiry.Push(k, e.ExpiresAt)
	}

	m.peak = max(m.peak, len(m.entries))
	// The commit is atomic. Cancellation after this point does not roll it back.
	return nil
}

// Len returns the stored entry count without pruning expired entries.
func (m *MemoryStore) Len() int {
	if m == nil {
		return 0
	}

	m.mu.Lock()
	v := len(m.entries)
	m.mu.Unlock()

	return v
}

func (m *MemoryStore) prune(ctx context.Context, at time.Time) error {
	for removed := 0; ; removed++ {
		if removed%256 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}

		first, ok := m.expiry.Peek()
		if !ok || first.After(at) {
			break
		}

		key, _, _ := m.expiry.Pop()
		delete(m.entries, key)
	}

	if m.peak > 1024 && len(m.entries) <= m.peak/4 {
		entries := make(map[key]time.Time, len(m.entries))
		for key, value := range m.entries {
			if len(entries)%256 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}

			entries[key] = value
		}

		m.entries, m.peak = entries, len(entries)
	}

	m.expiry.Trim()

	return ctx.Err()
}
