package metadata

import (
	"context"
	"time"
)

// Resolver returns already-authenticated or explicitly trusted metadata. A
// network implementation must authenticate, bound and cache metadata itself;
// Lookup must not infer trust from the entityID merely being an HTTPS URL.
type Resolver interface {
	// Lookup returns trusted metadata for an entity ID that is valid at the supplied time.
	// It must honor cancellation and must not infer trust from the URI scheme.
	Lookup(context.Context, string, time.Time) (*Entity, error)
}

// Lookup implements Resolver with cancellation and snapshot expiration checks.
func (s *Snapshot) Lookup(ctx context.Context, id string, at time.Time) (*Entity, error) {
	if ctx == nil {
		return nil, ErrMetadata
	}

	if e := ctx.Err(); e != nil {
		return nil, e
	}

	return s.Find(id, at)
}
