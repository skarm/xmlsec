package authority

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/profile"
)

// ErrNotFound indicates that an assertion is not held by the authority.
var ErrNotFound = errors.New("SAML assertion not found")

// URIHandler serves the assertion URI binding. Authenticate establishes the
// HTTP principal (or an explicitly permitted anonymous principal). Lookup must
// authorize disclosure to that principal and preserve the URI-to-assertion
// association forever: an ID may return the same assertion or an error, never
// a replacement. Signed assertions must be supplied by the application.
type URIHandler struct {
	// Authenticate returns the HTTP principal allowed to request assertions. It is
	// required and must explicitly permit anonymous access if desired.
	Authenticate func(*http.Request) (string, error)
	// Lookup receives the principal and exact assertion ID. It must authorize
	// disclosure and return the immutable signed assertion, or ErrNotFound.
	Lookup func(context.Context, string, string) (*document.Document, error)
}

// ServeHTTP returns 403 for denied requests, 404 for unknown assertions and
// application/samlassertion+xml with no-store for an authorized exact-ID lookup.
func (h URIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const (
		cacheControlNoStore = "no-cache, no-store"
		cachePragma         = "no-cache"
		headerCacheControl  = "Cache-Control"
		headerPragma        = "Pragma"
	)

	w.Header().Set(headerCacheControl, cacheControlNoStore)
	w.Header().Set(headerPragma, cachePragma)

	id, err := binding.ReadAssertionID(r)
	if err != nil {
		http.Error(w, "invalid assertion request", http.StatusBadRequest)
		return
	}

	if h.Authenticate == nil || h.Lookup == nil {
		http.Error(w, "assertion access denied", http.StatusForbidden)
		return
	}

	peer, err := h.Authenticate(r)
	if err != nil {
		http.Error(w, "assertion access denied", http.StatusForbidden)
		return
	}

	d, err := h.Lookup(r.Context(), peer, id)
	if errors.Is(err, ErrNotFound) {
		http.NotFound(w, r)
		return
	}

	if err != nil {
		http.Error(w, "assertion access denied", http.StatusForbidden)
		return
	}

	if d == nil {
		http.Error(w, "assertion unavailable", http.StatusInternalServerError)
		return
	}

	got, _ := d.Root().Attribute(document.Name{Local: lexicon.SAMLAttrID})
	if got != id {
		http.Error(w, "assertion unavailable", http.StatusInternalServerError)
		return
	}

	if err = binding.WriteAssertion(r.Context(), w, d); err != nil {
		return
	}
}

// MemoryAssertions is a bounded immutable-ID store. It deliberately has no
// replacement or eviction operation: capacity exhaustion cannot rebind an old
// URI. A durable implementation must retain the same immutability contract.
// Authorization is separate; Get must be wrapped in a principal-specific policy.
type MemoryAssertions struct {
	// mu protects concurrent lookup and insertion.
	mu sync.RWMutex
	// capacity bounds retained immutable assertion IDs.
	capacity int
	// values permanently binds each stored ID to one immutable assertion.
	values map[string]*document.Document
}

// NewMemoryAssertions allocates a store with an explicit positive capacity.
func NewMemoryAssertions(capacity int) (*MemoryAssertions, error) {
	const (
		maximumAssertionStoreCapacity = 100000
	)

	if capacity < 1 || capacity > maximumAssertionStoreCapacity {
		return nil, ErrDenied
	}

	return &MemoryAssertions{capacity: capacity, values: make(map[string]*document.Document)}, nil
}

// Add associates an exact assertion once. Re-adding the same immutable snapshot
// is idempotent; an attempt to replace it, even with another document having the
// same ID, fails. Only insert assertions that the application has authenticated.
func (m *MemoryAssertions) Add(ctx context.Context, d *document.Document) error {
	const (
		xmlNameAssertion = "Assertion"
	)

	if m == nil || ctx == nil || d == nil || d.Root().Name() != (document.Name{Space: lexicon.NamespaceSAMLAssertion, Local: xmlNameAssertion}) {
		return ErrDenied
	}

	id, _ := d.Root().Attribute(document.Name{Local: lexicon.SAMLAttrID})
	if !profile.ID(id) {
		return ErrDenied
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	if old, exists := m.values[id]; exists {
		if old == d {
			return nil
		}

		return ErrDenied
	}

	if len(m.values) >= m.capacity {
		return ErrDenied
	}

	m.values[id] = d

	return nil
}

// Get returns the immutable snapshot, without authorizing disclosure to a peer.
func (m *MemoryAssertions) Get(ctx context.Context, id string) (*document.Document, error) {
	if m == nil || ctx == nil || !profile.ID(id) {
		return nil, ErrDenied
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	d := m.values[id]

	if d == nil {
		return nil, ErrNotFound
	}

	return d, nil
}
