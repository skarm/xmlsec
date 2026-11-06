// Package artifact implements single-use SAML artifact issuance and authenticated
// SOAP resolution. Resolving an artifact does not validate the enclosed protocol.
package artifact

import (
	"context"
	"crypto"
	"errors"
	"sync"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/expiry"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
)

// Issue and direct store insertion share the same five-minute lifetime ceiling; artifact expiration remains exclusive.
const (
	maximumArtifactLifetime = 5 * time.Minute
)

// The type 0x0004 source identifier is exactly 20 octets, whether derived from metadata entityID or supplied by local agreement; it is a routing hint, not authentication.
const (
	artifactSourceBytes = 20
)

// ErrArtifact reports a rejected artifact, expired entry or exhausted store.
var ErrArtifact = errors.New("SAML artifact rejected")

// Entry binds an artifact to its exact intended recipient and short expiry.
type Entry struct {
	// Artifact is the opaque lookup key issued to the browser.
	Artifact binding.Artifact
	// Recipient is the exact entity ID authorized to resolve the artifact.
	Recipient string
	// Message is the immutable protocol message to release once.
	Message *document.Document
	// ExpiresAt is the exclusive expiration time of the artifact.
	ExpiresAt time.Time
}

// Store must atomically enforce single use across all callers and instances.
// Take returns nil for missing, expired, consumed or wrong-recipient artifacts.
// A wrong recipient must not consume an otherwise valid entry.
type Store interface {
	Put(context.Context, Entry, time.Time) error
	Take(context.Context, binding.Artifact, string, time.Time) (*document.Document, error)
	// Resolve must publish the signed reply and consume the artifact atomically.
	// A callback failure must preserve the artifact. The callback sees nil for
	// unknown, consumed, expired and unauthorized artifacts.
	Resolve(context.Context, binding.Artifact, string, time.Time, func(*document.Document) (*document.Document, error)) (*document.Document, error)
}

// MemoryStore is a bounded, concurrency-safe single-process implementation.
// Distributed services must use a shared durable Store with the same contract.
type MemoryStore struct {
	// mu serializes artifact consumption, reply creation and expiry maintenance.
	mu sync.Mutex
	// entries retains live messages and consumed tombstones until expiration.
	entries map[binding.Artifact]Entry
	// expiry indexes expiration once the store grows past the scan threshold.
	expiry expiry.Index[binding.Artifact]
	// indexed records whether expiry has been initialized from all entries.
	indexed bool
	// capacity bounds live entries and retained tombstones together.
	capacity int
}

// NewMemoryStore creates a store; zero capacity selects 10,000 entries.
func NewMemoryStore(capacity int) (*MemoryStore, error) {
	const (
		defaultStoreCapacity = 10000
		maximumStoreCapacity = 1000000
	)

	if capacity == 0 {
		capacity = defaultStoreCapacity
	}

	if capacity < 1 || capacity > maximumStoreCapacity {
		return nil, ErrArtifact
	}

	return &MemoryStore{entries: make(map[binding.Artifact]Entry), capacity: capacity}, nil
}

// Put stores an immutable message for no more than five minutes. It never evicts
// an unexpired artifact or replaces a colliding handle.
func (s *MemoryStore) Put(ctx context.Context, e Entry, at time.Time) error {
	const (
		expiryIndexThreshold = 64
	)

	if ctx == nil || s == nil || s.capacity == 0 || at.IsZero() || !profile.URI(e.Recipient) || e.Message == nil || e.Message.Root().Name().Space != protocol.ProtocolNamespace || !at.Before(e.ExpiresAt) || e.ExpiresAt.Sub(at) > maximumArtifactLifetime {
		return ErrArtifact
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	if s.indexed {
		if s.expiry.AllExpired(at) {
			clear(s.entries)
			s.expiry.Reset()
		} else {
			for {
				a, ok := s.expiry.PopExpired(at)
				if !ok {
					break
				}

				delete(s.entries, a)
			}
		}

		s.expiry.Trim()
	} else {
		// Small stores fit in a few map groups; avoid a second index until
		// repeated scans become more expensive than maintaining a heap.
		for a, entry := range s.entries {
			if !at.Before(entry.ExpiresAt) {
				delete(s.entries, a)
			}
		}
	}

	if len(s.entries) >= s.capacity {
		return ErrArtifact
	}

	if _, ok := s.entries[e.Artifact]; ok {
		return ErrArtifact
	}

	s.entries[e.Artifact] = e
	if s.indexed {
		s.expiry.Set(e.Artifact, e.ExpiresAt)
	} else if len(s.entries) >= expiryIndexThreshold {
		for a, entry := range s.entries {
			s.expiry.Set(a, entry.ExpiresAt)
		}

		s.indexed = true
	}

	return nil
}

// Take atomically releases a message once to its authenticated recipient.
func (s *MemoryStore) Take(ctx context.Context, a binding.Artifact, recipient string, at time.Time) (*document.Document, error) {
	if ctx == nil || s == nil || at.IsZero() {
		return nil, ErrArtifact
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	e, ok := s.entries[a]
	if !ok {
		return nil, nil
	}

	if !at.Before(e.ExpiresAt) {
		delete(s.entries, a)
		s.expiry.Delete(a)

		return nil, nil
	}

	if e.Recipient != recipient {
		return nil, nil
	}

	message := e.Message
	// Keep the handle reserved until expiration so a consumed artifact cannot
	// be rebound to a different message by a later Put.
	e.Message = nil
	s.entries[a] = e

	return message, nil
}

// Resolve holds a transaction through reply creation and commits consumption
// only after successful signing. It retains a tombstone until the entry expires.
func (s *MemoryStore) Resolve(ctx context.Context, a binding.Artifact, recipient string, at time.Time, reply func(*document.Document) (*document.Document, error)) (*document.Document, error) {
	if ctx == nil || s == nil || at.IsZero() || reply == nil {
		return nil, ErrArtifact
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	e, ok := s.entries[a]

	var message *document.Document
	if ok && at.Before(e.ExpiresAt) && e.Recipient == recipient {
		message = e.Message
	}

	d, err := reply(message)
	if err != nil {
		return nil, err
	}

	if d == nil {
		return nil, ErrArtifact
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if message != nil {
		e.Message = nil
		s.entries[a] = e
	}

	return d, nil
}

// Issuer creates artifacts and replies to previously authenticated resolution
// requests. Endpoint and ReturnEndpoint come from trusted metadata/configuration.
type Issuer struct {
	// EntityID identifies the local issuing provider.
	EntityID string
	// Endpoint is the trusted local ArtifactResolutionService URL.
	Endpoint string
	// ReturnEndpoint is the trusted recipient URL used as the response destination.
	ReturnEndpoint string
	// EndpointIndex identifies Endpoint in the issuer's metadata.
	EndpointIndex uint16
	// Signing supplies the key and policy for artifact responses.
	Signing protocol.SigningKey
	// Store retains messages and atomically consumes resolved artifacts.
	Store Store
	// Limits must match the incoming ArtifactResolve verifier's freshness policy.
	Limits protocol.Limits
	// SourceID optionally selects a locally agreed opaque source identifier.
	// Nil uses the recommended entityID hash; authentication still uses EntityID.
	SourceID *[artifactSourceBytes]byte
}

// Issue binds a new artifact to an exact recipient for the requested lifetime.
func (s Issuer) Issue(ctx context.Context, message *document.Document, recipient string, at time.Time, lifetime time.Duration) (binding.Artifact, error) {
	if nilcheck.IsNil(s.Store) || lifetime <= 0 || lifetime > maximumArtifactLifetime {
		return binding.Artifact{}, ErrArtifact
	}

	a, err := binding.NewArtifact(s.EntityID, s.EndpointIndex)
	if err != nil {
		return a, err
	}

	if s.SourceID != nil {
		a.SourceID = *s.SourceID
	}

	err = s.Store.Put(ctx, Entry{Artifact: a, Recipient: recipient, Message: message, ExpiresAt: at.Add(lifetime)}, at)

	return a, err
}

// Respond validates source/index and authorization before consuming the entry.
// Missing, wrong-recipient and already used artifacts all produce Success with
// no message, as required by Core 3.5.3. A signing failure never returns plaintext.
func (s Issuer) Respond(ctx context.Context, r *protocol.VerifiedArtifactResolve, at time.Time) (*document.Document, error) {
	if r == nil || nilcheck.IsNil(s.Store) || at.IsZero() {
		return nil, ErrArtifact
	}

	request := r.Request()

	age, _, skew, err := protocol.AcceptanceWindow(s.Limits)
	if err != nil || request.Destination != s.Endpoint || request.IssueInstant.After(at.Add(skew)) || request.IssueInstant.Before(at.Add(-age-skew)) {
		return nil, ErrArtifact
	}

	reply := func(message *document.Document) (*document.Document, error) {
		return protocol.SignStatusResponse(ctx, protocol.StatusResponse{Issuer: s.EntityID, Destination: s.ReturnEndpoint, IssueInstant: at, Kind: protocol.ArtifactResponse, InResponseTo: request.ID, Status: protocol.Status{Code: protocol.Success}, Message: message}, s.Signing)
	}

	a, err := binding.ParseArtifact(request.Artifact)
	if err != nil {
		return reply(nil)
	}

	source := binding.ArtifactSource(s.EntityID)
	if s.SourceID != nil {
		source = *s.SourceID
	}

	if a.SourceID != source || a.EndpointIndex != s.EndpointIndex {
		return reply(nil)
	}

	return s.Store.Resolve(ctx, a, request.Issuer, at, reply)
}

// Resolver authenticates a SOAP artifact exchange. PeerEntityID, keys, and
// endpoints must be taken from a current trusted peer metadata role. No received
// URL is fetched. Endpoint selection uses the artifact's index and source ID.
type Resolver struct {
	// EntityID identifies the local provider making resolution requests.
	EntityID string
	// PeerEntityID is the expected artifact issuer from trusted metadata.
	PeerEntityID string
	// ReturnEndpoint is the expected local response destination.
	ReturnEndpoint string
	// Endpoints supplies the peer's trusted artifact resolution endpoints.
	Endpoints []metadata.Endpoint
	// Signing supplies the key and policy for resolution requests.
	Signing protocol.SigningKey
	// Keys contains trusted peer keys for authenticating the response.
	Keys []crypto.PublicKey
	// Options supplies response verification policy; Resolve sets correlation and
	// time.
	Options protocol.ExchangeOptions
	// SOAP supplies the HTTP transport and SOAP parsing policy.
	SOAP binding.SOAPClient
	// SourceID is an optional trusted opaque source ID agreed with the peer.
	SourceID *[artifactSourceBytes]byte
}

// Resolve sends a signed ArtifactResolve and verifies the correlated response.
// The returned message is still unverified under its own protocol profile.
func (r Resolver) Resolve(ctx context.Context, a binding.Artifact, at time.Time) (*document.Document, error) {
	const (
		maximumResolverEndpoints = 128
	)

	started := time.Now()

	source := binding.ArtifactSource(r.PeerEntityID)
	if r.SourceID != nil {
		source = *r.SourceID
	}

	if at.IsZero() || a.SourceID != source || len(r.Endpoints) > maximumResolverEndpoints {
		return nil, ErrArtifact
	}

	endpoint := ""

	for _, e := range r.Endpoints {
		if e.Binding == metadata.SOAP && e.Indexed && e.Index == a.EndpointIndex {
			if endpoint != "" {
				return nil, ErrArtifact
			}

			endpoint = e.Location
		}
	}

	if endpoint == "" {
		return nil, ErrArtifact
	}

	id, err := profile.NewID()
	if err != nil {
		return nil, err
	}

	d, err := protocol.SignArtifactResolve(ctx, protocol.ArtifactResolve{ID: id, Issuer: r.EntityID, Destination: endpoint, IssueInstant: at, Artifact: a.String()}, r.Signing)
	if err != nil {
		return nil, err
	}

	envelope, err := protocol.SignSOAP(ctx, d, r.Signing)
	if err != nil {
		return nil, err
	}

	response, err := r.SOAP.RoundTrip(ctx, endpoint, envelope)
	if err != nil {
		return nil, err
	}

	payload, err := response.Payload(ctx)
	if err != nil {
		return nil, err
	}

	o := r.Options
	o.Binding = metadata.SOAP
	o.Issuer = r.PeerEntityID
	o.Destination = r.ReturnEndpoint
	o.At = at.Add(time.Since(started))
	o.ExpectedRequestID = id

	verified, err := protocol.VerifyStatusResponse(ctx, payload, r.Keys, o)
	if err != nil {
		return nil, err
	}

	if verified.Kind() != protocol.ArtifactResponse || verified.Status().Code != protocol.Success {
		return nil, ErrArtifact
	}

	return verified.Message(), nil
}
