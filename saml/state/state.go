package state

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/skarm/xmlsec/saml/internal/expiry"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

var (
	// ErrPolicy reports invalid SAML request state.
	ErrPolicy = errors.New("invalid SAML request state")
	// ErrMissing reports SAML request state missing or expired.
	ErrMissing = errors.New("SAML request state missing or expired")
	// ErrExists reports SAML request state already exists.
	ErrExists = errors.New("SAML request state already exists")
	// ErrCapacity reports SAML request state capacity reached.
	ErrCapacity = errors.New("SAML request state capacity reached")
)

// Pending retains a solicited request, its browser-secret digest, requested
// authentication conditions and expiration.
type Pending struct {
	// SP is the requesting service provider's entity identifier.
	SP string
	// IDP is the selected identity provider's entity identifier.
	IDP string
	// RequestID is the XML ID of the soliciting authentication request.
	RequestID string
	// RelayState is the opaque binding value used to look up this request.
	RelayState string
	// ACS is the exact assertion consumer endpoint selected for the request.
	ACS string
	// NameIDFormat is the requested subject identifier format URI, if specified.
	NameIDFormat string
	// IssuedAt is the authentication request issuance time.
	IssuedAt time.Time
	// ExpiresAt is the pending request's expiration time.
	ExpiresAt time.Time
	// BrowserSHA256 binds the request to the browser secret without storing the secret.
	BrowserSHA256 [32]byte
	// RequestedContexts contains the authentication context class URIs requested with exact
	// comparison.
	RequestedContexts []string
	// ForceAuthn records whether the request requires fresh authentication.
	ForceAuthn bool
}

// Clone returns an owned copy of the request state and its context list.
func (p Pending) Clone() Pending {
	p.RequestedContexts = append([]string(nil), p.RequestedContexts...)
	return p
}

// own detaches strings before persistence; callers may supply short substrings
// backed by a much larger request. Read-only snapshots can share these strings.
func (p Pending) own() Pending {
	p = p.Clone()
	p.SP = strings.Clone(p.SP)
	p.IDP = strings.Clone(p.IDP)
	p.RequestID = strings.Clone(p.RequestID)
	p.RelayState = strings.Clone(p.RelayState)
	p.ACS = strings.Clone(p.ACS)

	p.NameIDFormat = strings.Clone(p.NameIDFormat)
	for i, value := range p.RequestedContexts {
		p.RequestedContexts[i] = strings.Clone(value)
	}

	return p
}

// Store retains pending requests. Put inserts without replacing an unexpired
// request. Get reads without consuming, so an unauthenticated response cannot
// invalidate a legitimate request. After protocol and browser-correlation checks,
// the separate replay.Store performs atomic one-time consumption.
type Store interface {
	// Put inserts owned state at the supplied time without replacing an unexpired request.
	Put(context.Context, Pending, time.Time) error
	// Get returns owned unexpired state for an SP entity ID and RelayState at the supplied
	// time without consuming it.
	Get(context.Context, string, string, time.Time) (Pending, error)
}

// Config sets capacity and lifetime bounds for an in-memory request store. Zero fields
// select defaults.
type Config struct {
	// Capacity bounds stored entries; zero selects 10000. Unexpired entries
	// are never evicted to make room.
	Capacity int
	// MaxTTL bounds the lifetime of an inserted entry; zero selects 15 minutes.
	MaxTTL time.Duration
}

// MemoryStore retains bounded pending requests for concurrent use within one
// process. Put and Get remove expired entries. Before copying input, it checks URI
// fields against the protocol's 2048-byte limit, or 4096 bytes for ACS.
type MemoryStore struct {
	mu       sync.Mutex
	capacity int
	peak     int // maximum entry count since the last compaction
	maxTTL   time.Duration
	entries  map[stateKey]Pending
	expiry   expiry.Queue[stateKey]
}

type stateKey struct {
	sp    string
	relay string
}

// NewMemoryStore creates an empty bounded request store using default limits for zero Config
// fields.
func NewMemoryStore(c Config) (*MemoryStore, error) {
	if c.Capacity == 0 {
		c.Capacity = 10000
	}

	if c.MaxTTL == 0 {
		c.MaxTTL = 15 * time.Minute
	}

	if c.Capacity < 1 || c.Capacity > 1000000 || c.MaxTTL < time.Second || c.MaxTTL > time.Hour {
		return nil, ErrPolicy
	}

	return &MemoryStore{capacity: c.Capacity, maxTTL: c.MaxTTL, entries: map[stateKey]Pending{}}, nil
}

// Put inserts owned request state after pruning expired entries. Existing unexpired keys
// are never overwritten.
func (m *MemoryStore) Put(ctx context.Context, p Pending, at time.Time) error {
	if m == nil || ctx == nil || at.IsZero() || !valid(p, at, m.maxTTL) {
		return ErrPolicy
	}

	if e := ctx.Err(); e != nil {
		return e
	}

	p = p.own()

	m.mu.Lock()
	defer m.mu.Unlock()

	if e := ctx.Err(); e != nil {
		return e
	}

	if err := m.prune(ctx, at); err != nil {
		return err
	}

	k := stateKey{p.SP, p.RelayState}
	if _, ok := m.entries[k]; ok {
		return ErrExists
	}

	if len(m.entries) >= m.capacity {
		return ErrCapacity
	}

	m.entries[k] = p
	m.peak = max(m.peak, len(m.entries))
	m.expiry.Push(k, p.ExpiresAt)

	return nil
}

func valid(p Pending, at time.Time, maxTTL time.Duration) bool {
	if !xmlutil.URI(p.SP) || !xmlutil.URI(p.IDP) || !xmlutil.ID(p.RequestID) || len(p.RelayState) < 16 || len(p.RelayState) > 80 || !xmlutil.Endpoint(p.ACS, true) || p.IssuedAt.IsZero() || p.IssuedAt.After(at) || !p.ExpiresAt.After(at) || p.ExpiresAt.Sub(p.IssuedAt) > maxTTL || len(p.RequestedContexts) > 8 || p.NameIDFormat != "" && !xmlutil.URI(p.NameIDFormat) {
		return false
	}

	for _, uri := range p.RequestedContexts {
		if !xmlutil.URI(uri) {
			return false
		}
	}

	return true
}

// Get returns an owned copy of unexpired request state without consuming it.
func (m *MemoryStore) Get(ctx context.Context, sp, relay string, at time.Time) (Pending, error) {
	if m == nil || ctx == nil || at.IsZero() || sp == "" || relay == "" || len(relay) > 80 {
		return Pending{}, ErrPolicy
	}

	if e := ctx.Err(); e != nil {
		return Pending{}, e
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if e := ctx.Err(); e != nil {
		return Pending{}, e
	}

	if err := m.prune(ctx, at); err != nil {
		return Pending{}, err
	}

	p, ok := m.entries[stateKey{sp, relay}]
	if !ok {
		return Pending{}, ErrMissing
	}

	return p.Clone(), nil
}

// Len returns the stored entry count without pruning expired entries.
func (m *MemoryStore) Len() int {
	if m == nil {
		return 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.entries)
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
		entries := make(map[stateKey]Pending, len(m.entries))
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

// BrowserDigest hashes a browser correlation secret of 16 to 1024 bytes. The caller must
// generate and protect the secret.
func BrowserDigest(secret []byte) ([32]byte, error) {
	if len(secret) < 16 || len(secret) > 1024 {
		return [32]byte{}, ErrPolicy
	}

	return sha256.Sum256(secret), nil
}
