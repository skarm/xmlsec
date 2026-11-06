// Package session applies SAML logout and identifier-management protocols to
// application-owned sessions and provider relationships. Its Store is a security
// boundary: applications must consult the same session state for authorization.
package session

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/saml/internal/expiry"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
)

const (
	// Pending logout and NameID-management exchanges share a five-minute exclusive expiry; issuance and store validation enforce the same ceiling.
	pendingRequestLifetime = 5 * time.Minute

	// Retain accepted logout and NameID-management exchange IDs for two hours; this replay window does not extend an application session.
	controlReplayLifetime = 2 * time.Hour

	// Separate identity components before replay/session scoping so adjoining variable-length identifiers cannot share the same key encoding.
	scopeSeparator = "\u0000"
)

var (
	// ErrState reports invalid, missing, expired or replayed exchange state.
	ErrState = errors.New("SAML session state rejected")
	// ErrReplay indicates that a control request has already been applied.
	ErrReplay = errors.New("SAML control request replay")
)

// Relationship is the current identifier binding to one peer. Principal is an
// application-local account ID and must not change when the federated name does.
// Termination removes this binding and preserves existing sessions (Errata E8).
type Relationship struct {
	// Principal is the stable application-local account ID.
	Principal string
	// Peer is the entity ID of the provider sharing this identifier binding.
	Peer string
	// NameID is the complete current federated identifier.
	NameID protocol.NameIdentifier
	// ExpiresAt is the exclusive expiration time of the relationship.
	ExpiresAt time.Time
	// terminated retains a withdrawn binding without deleting its existing
	// sessions.
	terminated bool
}

// Session records an application session issued by or to Peer. AuthoritySession
// groups the participants authenticated under the same IdP session. Index is the
// SessionIndex communicated to Peer; ID is the application's local session ID.
type Session struct {
	// ID is the application's local session identifier.
	ID string
	// Principal is the stable application-local account ID.
	Principal string
	// Peer is the provider to which this session is bound.
	Peer string
	// AuthoritySession groups participants authenticated under the same IdP
	// session.
	AuthoritySession string
	// Index is the SAML SessionIndex communicated to Peer.
	Index string
	// NameID is established from the authenticated assertion. The store retains
	// its canonical current form across management changes. Add rejects stale
	// or different bindings rather than guessing from Principal.
	NameID protocol.NameIdentifier
	// ExpiresAt is the exclusive session expiration time and cannot exceed the
	// relationship's expiration.
	ExpiresAt time.Time
}

// Participant identifies another peer affected by authority-initiated logout.
type Participant struct {
	// Peer is the entity ID of the provider to notify.
	Peer string
	// NameID is the complete identifier established with Peer.
	NameID protocol.NameIdentifier
	// SessionIndexes selects the peer sessions affected by logout.
	SessionIndexes []string
}

// LogoutResult contains locally invalidated session IDs and peers to notify.
type LogoutResult struct {
	// Status is the local or aggregate logout outcome, including PartialLogout when
	// needed.
	Status protocol.Status
	// SessionIDs lists application session IDs invalidated locally.
	SessionIDs []string
	// Participants lists peer sessions affected by the same authority logout.
	Participants []Participant
}

// Pending binds an outgoing exchange to the exact peer, request, response kind,
// old identifier and requested change. A failed response must not apply a change.
type Pending struct {
	// ID is the outgoing request's exact XML identifier.
	ID string
	// Peer is the expected response issuer.
	Peer string
	// Kind is the expected response element's local name.
	Kind string
	// NameID retains the complete identifier before the requested change.
	NameID protocol.NameIdentifier
	// NewID retains the requested replacement identifier or SP alias.
	NewID string
	// Terminate records a request to end the identifier binding.
	Terminate bool
	// LocalIsIDP selects whether NewID changes NameID content or SPProvidedID.
	LocalIsIDP bool
	// ExpiresAt is the exclusive expiration time for response correlation.
	ExpiresAt time.Time
	// SessionIndexes retains the sessions selected by an outgoing logout.
	SessionIndexes []string
	// NotOnOrAfter and ClockSkew retain an outgoing logout's block deadline
	// independently of pending correlation. Zero NotOnOrAfter uses the replay
	// lifetime as a fallback; management exchanges leave both fields zero.
	NotOnOrAfter time.Time
	// ClockSkew retains the accepted tolerance for an outgoing logout's block
	// deadline.
	ClockSkew time.Duration
}

// Store must atomically apply state changes and replay markers. Finish must
// atomically correlate and consume pending state and, on a successful management
// response, apply its identifier change. Shared deployments need a durable store.
type Store interface {
	// Provider returns the immutable local entity/role owning this state.
	Provider() (string, metadata.RoleType)
	// Logout retains the session block through NotOnOrAfter plus clockSkew.
	// The times are the current time and replay expiration; clockSkew must
	// cover the policy used to accept late assertions for these sessions.
	Logout(ctx context.Context, request *protocol.VerifiedLogoutRequest, authority bool, at, until time.Time, clockSkew time.Duration) (LogoutResult, error)
	Manage(context.Context, *protocol.VerifiedManageNameIDRequest, bool, time.Time, time.Time) (protocol.Status, error)
	// Start also invalidates outgoing logout sessions and retains their block
	// independently of pending state, including after Finish or pending expiry.
	Start(context.Context, Pending, time.Time) error
	Finish(context.Context, *protocol.VerifiedStatusResponse, time.Time) (Pending, error)
	Withdraw(context.Context, string, string, time.Time) (LogoutResult, error)
}

// Service implements both participant and authority processing. Notify must send
// an authenticated, correlated LogoutRequest to the trusted peer endpoint and
// return its verified status. Missing/failed notifications produce PartialLogout.
type Service struct {
	// EntityID identifies the local session provider.
	EntityID string
	// Endpoint is the trusted local endpoint at which incoming messages were
	// received and authenticated. It prevents cross-service request substitution.
	Endpoint string
	// ResponseEndpoint is the metadata ResponseLocation; empty uses Endpoint.
	ResponseEndpoint string
	// Role selects local IdP or SP semantics for session and identifier changes.
	Role metadata.RoleType
	// Store atomically applies session changes, correlation and replay protection.
	Store Store
	// Signing supplies the response signing key and policy.
	Signing protocol.SigningKey
	// Limits must match the incoming protocol verifier's acceptance policy.
	// ClockSkew must also cover the policy used to accept late assertions.
	Limits protocol.Limits
	// Notify sends an authenticated, correlated logout to a participant. Nil or an
	// error produces PartialLogout.
	Notify func(context.Context, Participant) (protocol.Status, error)
}

// Logout applies the authenticated request once, attempts every other affected
// participant at an authority, and signs the final status. responseEndpoint must
// be selected from the requesting peer's current trusted metadata, including its
// ResponseLocation when appropriate. It never uses a received response URL.
func (s Service) Logout(ctx context.Context, r *protocol.VerifiedLogoutRequest, responseEndpoint string, at time.Time) (*document.Document, LogoutResult, error) {
	if !s.valid() || r == nil || !s.freshLogout(r.Request(), at) || r.Request().Destination != s.Endpoint || s.Role == metadata.IdentityProvider && len(r.Request().SessionIndexes) == 0 || s.Role == metadata.ServiceProvider && r.Request().NotOnOrAfter.IsZero() {
		return nil, LogoutResult{}, ErrState
	}

	replies, err := s.prepareReplies(ctx, protocol.LogoutResponse, r.Request().ID, responseEndpoint, at)
	if err != nil {
		return nil, LogoutResult{}, err
	}

	result, err := s.Store.Logout(ctx, r, s.Role == metadata.IdentityProvider, at, at.Add(controlReplayLifetime), s.Limits.ClockSkew)
	if err != nil {
		return nil, result, err
	}

	for _, participant := range result.Participants {
		if participant.Peer == s.EntityID {
			continue
		}

		status := protocol.Status{}
		if s.Notify != nil {
			status, err = s.Notify(ctx, participant)
		} else {
			err = ErrState
		}

		if err != nil || status.Code != protocol.Success || slices.Contains(status.Subcodes, protocol.PartialLogout) {
			result.Status = protocol.Status{Code: protocol.Success, Subcodes: []string{protocol.PartialLogout}}
		}
	}

	d, err := replies.selectReply(result.Status)

	return d, result, err
}

// Manage applies the role-specific NameID or SPProvidedID change atomically and
// responds to both successful and unknown-principal requests.
func (s Service) Manage(ctx context.Context, r *protocol.VerifiedManageNameIDRequest, responseEndpoint string, at time.Time) (*document.Document, error) {
	if !s.valid() || r == nil || !s.fresh(r.Request().MessageHeader, at) || r.Request().Destination != s.Endpoint {
		return nil, ErrState
	}

	replies, err := s.prepareReplies(ctx, protocol.ManageNameIDResponse, r.Request().ID, responseEndpoint, at)
	if err != nil {
		return nil, err
	}

	status, err := s.Store.Manage(ctx, r, s.Role == metadata.ServiceProvider, at, at.Add(controlReplayLifetime))
	if err != nil {
		return nil, err
	}

	return replies.selectReply(status)
}

// BeginManage signs a change and persists its correlation state. The local copy
// is updated only after Complete receives the successful authenticated response.
func (s Service) BeginManage(ctx context.Context, peer string, request protocol.ManageNameIDRequest, at time.Time) (*document.Document, error) {
	if !s.valid() || !s.fresh(request.MessageHeader, at) || request.Issuer != s.EntityID {
		return nil, ErrState
	}

	request.NameID = qualifiedName(request.NameID, s.EntityID, peer, s.Role)

	if s.Role == metadata.IdentityProvider && !request.Terminate {
		replacement := request.NameID

		replacement.Value = request.NewID
		if err := replacement.Validate(); err != nil {
			return nil, err
		}
	}

	d, err := protocol.SignManageNameIDRequest(ctx, request, s.Signing)
	if err != nil {
		return nil, err
	}

	id, _ := d.Root().Attribute(document.Name{Local: lexicon.SAMLAttrID})

	if !profile.URI(peer) || peer == s.EntityID {
		return nil, ErrState
	}

	err = s.Store.Start(ctx, Pending{ID: id, Peer: peer, Kind: protocol.ManageNameIDResponse, NameID: request.NameID, NewID: request.NewID, Terminate: request.Terminate, LocalIsIDP: s.Role == metadata.IdentityProvider, ExpiresAt: at.Add(pendingRequestLifetime)}, at)
	if err != nil {
		return nil, err
	}

	return d, nil
}

// Complete consumes the exact outgoing exchange once. The caller must verify
// response signature, destination and request correlation before calling it.
func (s Service) Complete(ctx context.Context, response *protocol.VerifiedStatusResponse, at time.Time) (Pending, error) {
	expected := s.ResponseEndpoint
	if expected == "" {
		expected = s.Endpoint
	}

	if !s.valid() || response == nil || !s.fresh(response.Header(), at) || response.Header().Destination != expected {
		return Pending{}, ErrState
	}

	return s.Store.Finish(ctx, response, at)
}

// InitiateLogout terminates an IdP's application-authenticated authority session
// and attempts logout at every participant. A nonempty authoritySession prevents
// logout at another device/session of the same account. Failed notifications are
// reported with PartialLogout; every participant is attempted.
func (s Service) InitiateLogout(ctx context.Context, principal, authoritySession string, at time.Time) (LogoutResult, error) {
	if !s.valid() || s.Role != metadata.IdentityProvider {
		return LogoutResult{}, ErrState
	}

	r, err := s.Store.Withdraw(ctx, principal, authoritySession, at)
	if err != nil {
		return r, err
	}

	for _, p := range r.Participants {
		if p.Peer == s.EntityID {
			continue
		}

		status := protocol.Status{}
		if s.Notify != nil {
			status, err = s.Notify(ctx, p)
		} else {
			err = ErrState
		}

		if err != nil || status.Code != protocol.Success || slices.Contains(status.Subcodes, protocol.PartialLogout) {
			r.Status = protocol.Status{Code: protocol.Success, Subcodes: []string{protocol.PartialLogout}}
		}
	}

	return r, nil
}

// BeginLogout signs a provider-initiated request and retains its correlation.
// Start invalidates the matching initiating local sessions and blocks delayed
// assertions atomically with pending state. The block survives Complete and
// pending expiry; the authority's final status is consumed through Complete.
func (s Service) BeginLogout(ctx context.Context, peer string, request protocol.LogoutRequest, at time.Time) (*document.Document, error) {
	if !s.valid() || !s.freshLogout(request, at) || request.Issuer != s.EntityID || s.Role == metadata.ServiceProvider && len(request.SessionIndexes) == 0 || s.Role == metadata.IdentityProvider && request.NotOnOrAfter.IsZero() {
		return nil, ErrState
	}

	request.NameID = qualifiedName(request.NameID, s.EntityID, peer, s.Role)

	d, err := protocol.SignLogoutRequest(ctx, request, s.Signing)
	if err != nil {
		return nil, err
	}

	id, _ := d.Root().Attribute(document.Name{Local: lexicon.SAMLAttrID})

	err = s.Store.Start(ctx, Pending{ID: id, Peer: peer, Kind: protocol.LogoutResponse, NameID: request.NameID, LocalIsIDP: s.Role == metadata.IdentityProvider, SessionIndexes: slices.Clone(request.SessionIndexes), ExpiresAt: at.Add(pendingRequestLifetime), NotOnOrAfter: request.NotOnOrAfter, ClockSkew: s.Limits.ClockSkew}, at)
	if err != nil {
		return nil, err
	}

	return d, nil
}

func (s Service) valid() bool {
	if !profile.URI(s.EntityID) || !profile.Endpoint(s.Endpoint, true) || nilcheck.IsNil(s.Store) {
		return false
	}

	entity, role := s.Store.Provider()

	return entity == s.EntityID && role == s.Role && (role == metadata.ServiceProvider || role == metadata.IdentityProvider)
}

func (s Service) fresh(h protocol.MessageHeader, at time.Time) bool {
	age, _, skew, err := protocol.AcceptanceWindow(s.Limits)
	return err == nil && !at.IsZero() && !h.IssueInstant.IsZero() && !h.IssueInstant.After(at.Add(skew)) && !h.IssueInstant.Before(at.Add(-age-skew))
}

func (s Service) freshLogout(r protocol.LogoutRequest, at time.Time) bool {
	return s.fresh(r.MessageHeader, at) && (r.NotOnOrAfter.IsZero() || at.Add(-s.Limits.ClockSkew).Before(r.NotOnOrAfter))
}

// MemoryStore is a bounded, concurrency-safe reference session/relationship
// store. Zero values are not usable. Expired records are removed on mutations.
type MemoryStore struct {
	// mu serializes all state transitions and index updates.
	mu sync.Mutex
	// capacity bounds records independently in each category.
	capacity int
	// entityID is the immutable local provider identity.
	entityID string
	// role fixes local IdP or SP identifier-management semantics.
	role metadata.RoleType
	// relationships retains current and terminated principal-to-peer bindings.
	relationships map[string]Relationship
	// sessions indexes application sessions by local session ID.
	sessions map[string]Session
	// seen retains accepted control request IDs through their replay deadlines.
	seen map[string]time.Time
	// pending retains outgoing requests awaiting correlated responses.
	pending map[string]Pending
	// logoutMarks blocks delayed assertions from recreating logged-out sessions.
	logoutMarks map[string]logoutMark
	// expiry indexes expiration across all record categories.
	expiry expiry.Index[recordKey]
	// names indexes complete peer-qualified identifiers to relationship keys.
	names map[nameKey]string
}

type recordKind uint8

const (
	relationshipRecord recordKind = iota
	sessionRecord
	seenRecord
	pendingRecord
	logoutRecord
)

type recordKey struct {
	kind recordKind
	id   string
}

type nameKey struct {
	peer string
	name protocol.NameIdentifier
}

func identifierKey(peer string, name protocol.NameIdentifier) nameKey {
	if name.Format == "" {
		name.Format = protocol.NameIDUnspecified
	}

	return nameKey{peer, name}
}

type logoutMark struct {
	// peer identifies the provider whose delayed sessions are blocked.
	peer string
	// name is the complete identifier selected by logout.
	name protocol.NameIdentifier
	// indices selects blocked session indices; empty selects all matching sessions.
	indices []string
	// until is the exclusive expiration of the block, including clock tolerance.
	until time.Time
}

// Config binds a session store to one local provider and role. This context
// resolves the implicit qualifiers allowed by persistent NameID formats.
type Config struct {
	// EntityID identifies the local provider owning the store.
	EntityID string
	// Role selects the local IdentityProvider or ServiceProvider role.
	Role metadata.RoleType
	// Capacity bounds records per category. Zero selects 10,000; live records are
	// never evicted to make room.
	Capacity int
}

// NewMemoryStore creates a bounded in-process store; zero capacity selects 10,000 records
// per category. No live sessions, relationships or replay records are evicted.
func NewMemoryStore(c Config) (*MemoryStore, error) {
	const (
		defaultSessionCapacity = 10000
		maximumSessionCapacity = 1000000
	)

	if !profile.URI(c.EntityID) || c.Role != metadata.ServiceProvider && c.Role != metadata.IdentityProvider {
		return nil, ErrState
	}

	capacity := c.Capacity
	if capacity == 0 {
		capacity = defaultSessionCapacity
	}

	if capacity < 1 || capacity > maximumSessionCapacity {
		return nil, ErrState
	}

	return &MemoryStore{capacity: capacity, entityID: c.EntityID, role: c.Role, relationships: map[string]Relationship{}, sessions: map[string]Session{}, seen: map[string]time.Time{}, pending: map[string]Pending{}, logoutMarks: map[string]logoutMark{}, names: map[nameKey]string{}}, nil
}

// Provider returns the immutable local provider context.
func (s *MemoryStore) Provider() (string, metadata.RoleType) {
	if s == nil {
		return "", ""
	}

	return s.entityID, s.role
}

// Register establishes a binding explicitly after authenticated account linking.
// It rejects reassignment, duplicate peer identifiers and replacing an existing
// binding. Name changes must use the management transaction instead.
func (s *MemoryStore) Register(ctx context.Context, r Relationship, at time.Time) error {
	const (
		maximumPrincipalBytes = 1024
	)

	if err := s.check(ctx, at); err != nil {
		return err
	}

	r.NameID = qualifiedName(r.NameID, s.entityID, r.Peer, s.role)
	r.terminated = false

	if r.Principal == "" || len(r.Principal) > maximumPrincipalBytes || !profile.URI(r.Peer) || !validName(r.NameID) || !at.Before(r.ExpiresAt) {
		return ErrState
	}

	if err := s.lock(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()

	s.prune(at)

	k := relationshipKey(r.Principal, r.Peer)

	old, exists := s.relationships[k]
	if exists && (!old.terminated || sameName(old.NameID, r.NameID)) || !exists && len(s.relationships) >= s.capacity {
		return ErrState
	}

	if _, exists := s.names[identifierKey(r.Peer, r.NameID)]; exists {
		return ErrState
	}

	s.setRelationship(k, r)

	return nil
}

// Add records an application session for an existing unexpired relationship.
func (s *MemoryStore) Add(ctx context.Context, session Session, at time.Time) error {
	const (
		maximumAuthoritySessionBytes = 1024
		maximumSessionIDBytes        = 1024
		maximumSessionIndexBytes     = 4096
	)

	if err := s.check(ctx, at); err != nil {
		return err
	}

	session.NameID = qualifiedName(session.NameID, s.entityID, session.Peer, s.role)

	if session.ID == "" || len(session.ID) > maximumSessionIDBytes || len(session.Index) > maximumSessionIndexBytes || len(session.AuthoritySession) > maximumAuthoritySessionBytes || !at.Before(session.ExpiresAt) {
		return ErrState
	}

	if err := s.lock(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()

	s.prune(at)

	r, ok := s.relationships[relationshipKey(session.Principal, session.Peer)]
	if !ok || r.terminated || !sameName(session.NameID, r.NameID) || session.ExpiresAt.After(r.ExpiresAt) || len(s.sessions) >= s.capacity {
		return ErrState
	}

	for _, mark := range s.logoutMarks {
		if mark.peer == session.Peer && sameName(mark.name, r.NameID) && (len(mark.indices) == 0 || slices.Contains(mark.indices, session.Index)) {
			return ErrState
		}
	}

	if _, ok := s.sessions[session.ID]; ok {
		return ErrState
	}

	s.sessions[session.ID] = session
	s.expiry.Set(recordKey{sessionRecord, session.ID}, session.ExpiresAt)

	return nil
}

// Active reports whether the application's session is currently usable.
func (s *MemoryStore) Active(ctx context.Context, id string, at time.Time) bool {
	if s.check(ctx, at) != nil {
		return false
	}

	if err := s.lock(ctx); err != nil {
		return false
	}

	e, ok := s.sessions[id]
	s.mu.Unlock()

	return ok && at.Before(e.ExpiresAt)
}

// Lookup returns the current binding for an application account and peer.
func (s *MemoryStore) Lookup(ctx context.Context, principal, peer string, at time.Time) (Relationship, bool) {
	if s.check(ctx, at) != nil {
		return Relationship{}, false
	}

	if err := s.lock(ctx); err != nil {
		return Relationship{}, false
	}

	r, ok := s.relationships[relationshipKey(principal, peer)]
	s.mu.Unlock()

	return r, ok && !r.terminated && at.Before(r.ExpiresAt)
}

// Logout invalidates the selected local sessions and, at an authority, sessions
// of other participants under the same AuthoritySession. No index selects all
// sessions for the issuer and NameID. Cross-account or cross-authority sessions
// are never selected. Replay marking and invalidation happen under one lock.
// clockSkew extends an explicit NotOnOrAfter through the assertion acceptance
// window. If NotOnOrAfter is absent, until supplies the fallback block deadline.
func (s *MemoryStore) Logout(ctx context.Context, verified *protocol.VerifiedLogoutRequest, authority bool, at, until time.Time, clockSkew time.Duration) (LogoutResult, error) {
	if verified == nil {
		return LogoutResult{}, ErrState
	}

	if err := s.check(ctx, at); err != nil {
		return LogoutResult{}, err
	}

	if authority != (s.role == metadata.IdentityProvider) {
		return LogoutResult{}, ErrState
	}

	r := verified.Request()
	r.NameID = qualifiedName(r.NameID, s.entityID, r.Issuer, s.role)

	deadline, err := logoutDeadline(at, r.NotOnOrAfter, until, clockSkew)
	if err != nil {
		return LogoutResult{}, err
	}

	if err := s.lock(ctx); err != nil {
		return LogoutResult{}, err
	}
	defer s.mu.Unlock()

	s.prune(at)

	if len(s.logoutMarks) >= s.capacity {
		return LogoutResult{}, ErrState
	}

	if err := s.consume(r.Issuer, r.ID, at, until); err != nil {
		return LogoutResult{}, err
	}

	markKey := r.Issuer + scopeSeparator + r.ID
	s.logoutMarks[markKey] = logoutMark{peer: r.Issuer, name: r.NameID, indices: slices.Clone(r.SessionIndexes), until: deadline}
	s.expiry.Set(recordKey{logoutRecord, markKey}, deadline)

	result := LogoutResult{Status: protocol.Status{Code: protocol.Success}}

	principal, ok := s.find(r.Issuer, r.NameID)
	if !ok {
		result.Status = unknown()
		return result, nil
	}

	groups := map[string]bool{}
	selected := map[string]bool{}

	for id, e := range s.sessions {
		if e.Principal == principal && e.Peer == r.Issuer && sameName(e.NameID, r.NameID) && (len(r.SessionIndexes) == 0 || slices.Contains(r.SessionIndexes, e.Index)) {
			selected[id] = true

			if e.AuthoritySession != "" {
				groups[e.AuthoritySession] = true
			}
		}
	}

	participants := map[string]int{}

	for id, e := range s.sessions {
		if !selected[id] && !(authority && e.Principal == principal && e.AuthoritySession != "" && groups[e.AuthoritySession]) {
			continue
		}

		result.SessionIDs = append(result.SessionIDs, id)

		if authority && e.Peer != r.Issuer {
			s.addParticipant(&result, participants, principal, e)
		}

		s.remove(recordKey{sessionRecord, id})
	}

	slices.Sort(result.SessionIDs)
	slices.SortFunc(result.Participants, func(a, b Participant) int {
		if a.Peer < b.Peer {
			return -1
		}

		if a.Peer > b.Peer {
			return 1
		}

		return 0
	})

	for i := range result.Participants {
		slices.Sort(result.Participants[i].SessionIndexes)
	}

	return result, nil
}

// Manage updates exactly the recognized current binding, including SPProvidedID.
// Incoming requests from an IdP change Value; those from an SP change its alias.
func (s *MemoryStore) Manage(ctx context.Context, verified *protocol.VerifiedManageNameIDRequest, idpSender bool, at, until time.Time) (protocol.Status, error) {
	if verified == nil {
		return protocol.Status{}, ErrState
	}

	if err := s.check(ctx, at); err != nil {
		return protocol.Status{}, err
	}

	if idpSender != (s.role == metadata.ServiceProvider) {
		return protocol.Status{}, ErrState
	}

	r := verified.Request()
	r.NameID = qualifiedName(r.NameID, s.entityID, r.Issuer, s.role)

	if err := s.lock(ctx); err != nil {
		return protocol.Status{}, err
	}
	defer s.mu.Unlock()

	s.prune(at)

	if err := s.consume(r.Issuer, r.ID, at, until); err != nil {
		return protocol.Status{}, err
	}

	current, ok := s.managedName(r.Issuer, r.NameID)
	if !ok {
		return unknown(), nil
	}

	return s.change(r.Issuer, current, r.NewID, r.Terminate, idpSender), nil
}

// Start records an outgoing management/logout correlation without evicting live
// exchanges. Expiry is at most five minutes. IDs are unique for the whole store.
func (s *MemoryStore) Start(ctx context.Context, p Pending, at time.Time) error {
	if err := s.check(ctx, at); err != nil {
		return err
	}

	p.NameID = qualifiedName(p.NameID, s.entityID, p.Peer, s.role)
	if !s.validPending(p, at) {
		return ErrState
	}

	var deadline time.Time

	if p.Kind == protocol.LogoutResponse {
		var err error

		deadline, err = logoutDeadline(at, p.NotOnOrAfter, at.Add(controlReplayLifetime), p.ClockSkew)
		if err != nil {
			return err
		}
	}

	if err := s.lock(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()

	s.prune(at)

	if len(s.pending) >= s.capacity {
		return ErrState
	}

	if _, ok := s.pending[p.ID]; ok {
		return ErrState
	}

	if _, ok := s.find(p.Peer, p.NameID); !ok {
		return ErrState
	}

	if p.Kind == protocol.LogoutResponse {
		if len(s.logoutMarks) >= s.capacity {
			return ErrState
		}

		markKey := "outgoing" + scopeSeparator + p.Peer + scopeSeparator + p.ID
		if _, exists := s.logoutMarks[markKey]; exists {
			return ErrState
		}

		for _, existing := range s.pending {
			if existing.Peer == p.Peer && sameName(existing.NameID, p.NameID) && existing.Terminate {
				return ErrState
			}
		}
	}

	p.SessionIndexes = slices.Clone(p.SessionIndexes)

	s.pending[p.ID] = p
	s.expiry.Set(recordKey{pendingRecord, p.ID}, p.ExpiresAt)

	if p.Terminate {
		// Sending termination is unilateral: after the message is released,
		// neither a missing reply nor pending-state expiry permits a later
		// LogoutRequest or new assertion under this identifier (E8/E55).
		principal, _ := s.find(p.Peer, p.NameID)
		k := relationshipKey(principal, p.Peer)
		r := s.relationships[k]
		r.terminated = true
		s.setRelationship(k, r)
	}

	if p.Kind == protocol.LogoutResponse {
		markKey := "outgoing" + scopeSeparator + p.Peer + scopeSeparator + p.ID
		s.logoutMarks[markKey] = logoutMark{peer: p.Peer, name: p.NameID, indices: slices.Clone(p.SessionIndexes), until: deadline}
		s.expiry.Set(recordKey{logoutRecord, markKey}, deadline)

		principal, _ := s.find(p.Peer, p.NameID)
		for id, e := range s.sessions {
			if e.Peer == p.Peer && e.Principal == principal && sameName(e.NameID, p.NameID) && (len(p.SessionIndexes) == 0 || slices.Contains(p.SessionIndexes, e.Index)) {
				s.remove(recordKey{sessionRecord, id})
			}
		}
	}

	return nil
}

// Finish atomically correlates, consumes and applies a successful outgoing
// change. A replay, wrong issuer/kind or expired response cannot update state.
func (s *MemoryStore) Finish(ctx context.Context, response *protocol.VerifiedStatusResponse, at time.Time) (Pending, error) {
	if response == nil {
		return Pending{}, ErrState
	}

	if err := s.check(ctx, at); err != nil {
		return Pending{}, err
	}

	if err := s.lock(ctx); err != nil {
		return Pending{}, err
	}
	defer s.mu.Unlock()

	s.prune(at)

	p, ok := s.pending[response.InResponseTo()]
	if !ok || p.Peer != response.Header().Issuer || p.Kind != response.Kind() {
		return Pending{}, ErrState
	}

	if response.Status().Code == protocol.Success && p.Kind == protocol.ManageNameIDResponse && !p.Terminate {
		status := s.change(p.Peer, p.NameID, p.NewID, p.Terminate, p.LocalIsIDP)
		if status.Code != protocol.Success {
			return Pending{}, ErrState
		}
	}

	s.remove(recordKey{pendingRecord, p.ID})

	return p, nil
}

func (s *MemoryStore) check(ctx context.Context, at time.Time) error {
	if ctx == nil || s == nil || s.capacity == 0 || at.IsZero() {
		return ErrState
	}

	return ctx.Err()
}

// Recheck cancellation after waiting for another transaction and before any
// reads, pruning or mutations. The caller owns the lock only on success.
func (s *MemoryStore) lock(ctx context.Context) error {
	s.mu.Lock()
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return err
	}

	return nil
}

func (s *MemoryStore) prune(at time.Time) {
	if s.expiry.AllExpired(at) {
		clear(s.relationships)
		clear(s.sessions)
		clear(s.pending)
		clear(s.seen)
		clear(s.logoutMarks)
		clear(s.names)
		s.expiry.Reset()

		return
	}

	for {
		key, ok := s.expiry.PopExpired(at)
		if !ok {
			break
		}

		s.remove(key)
	}

	s.expiry.Trim()
}

func (s *MemoryStore) setRelationship(key string, r Relationship) {
	if old, ok := s.relationships[key]; ok {
		delete(s.names, identifierKey(old.Peer, old.NameID))
	}

	s.relationships[key] = r
	s.names[identifierKey(r.Peer, r.NameID)] = key
	s.expiry.Set(recordKey{relationshipRecord, key}, r.ExpiresAt)
}

func (s *MemoryStore) remove(key recordKey) {
	s.expiry.Delete(key)

	switch key.kind {
	case relationshipRecord:
		r := s.relationships[key.id]
		delete(s.names, identifierKey(r.Peer, r.NameID))
		delete(s.relationships, key.id)
	case sessionRecord:
		delete(s.sessions, key.id)
	case seenRecord:
		delete(s.seen, key.id)
	case pendingRecord:
		delete(s.pending, key.id)
	case logoutRecord:
		delete(s.logoutMarks, key.id)
	}
}

func (s *MemoryStore) consume(issuer, id string, at, until time.Time) error {
	key := issuer + scopeSeparator + id

	if !at.Before(until) || until.Sub(at) > controlReplayLifetime {
		return ErrState
	}

	if _, ok := s.seen[key]; ok {
		return ErrReplay
	}

	if len(s.seen) >= s.capacity {
		return ErrState
	}

	s.seen[key] = until
	s.expiry.Set(recordKey{seenRecord, key}, until)

	return nil
}

func (s *MemoryStore) find(peer string, name protocol.NameIdentifier) (string, bool) {
	key, ok := s.names[identifierKey(peer, name)]

	r := s.relationships[key]
	if !ok || r.terminated {
		return "", false
	}

	return r.Principal, true
}

func (s *MemoryStore) managedName(peer string, name protocol.NameIdentifier) (protocol.NameIdentifier, bool) {
	for _, r := range s.relationships {
		if r.terminated || r.Peer != peer {
			continue
		}

		candidate := name
		if candidate.Format == protocol.NameIDPersistent {
			// Core 3.6.3 permits a qualifier to be omitted when its value
			// would be the containing message's authenticated Issuer.
			if candidate.NameQualifier == "" && r.NameID.NameQualifier == peer {
				candidate.NameQualifier = peer
			}

			if candidate.SPNameQualifier == "" && r.NameID.SPNameQualifier == peer {
				candidate.SPNameQualifier = peer
			}
		}

		if sameName(r.NameID, candidate) {
			return r.NameID, true
		}
	}

	return protocol.NameIdentifier{}, false
}

func (s *MemoryStore) change(peer string, old protocol.NameIdentifier, value string, terminate, idpSender bool) protocol.Status {
	principal, ok := s.find(peer, old)
	if !ok {
		return unknown()
	}

	k := relationshipKey(principal, peer)

	r := s.relationships[k]
	if terminate {
		r.terminated = true
		s.setRelationship(k, r)
	} else {
		if idpSender {
			r.NameID.Value = value
		} else {
			r.NameID.SPProvidedID = value
		}

		if r.NameID.Validate() != nil {
			return protocol.Status{Code: protocol.Requester}
		}

		if other, exists := s.names[identifierKey(peer, r.NameID)]; exists && other != k {
			return protocol.Status{Code: protocol.Requester}
		}

		s.setRelationship(k, r)

		for id, e := range s.sessions {
			if e.Peer == peer && e.Principal == principal && sameName(e.NameID, old) {
				e.NameID = r.NameID
				s.sessions[id] = e
			}
		}

		for id, mark := range s.logoutMarks {
			if mark.peer == peer && sameName(mark.name, old) {
				mark.name = r.NameID
				s.logoutMarks[id] = mark
			}
		}
	}

	return protocol.Status{Code: protocol.Success}
}

// Withdraw atomically invalidates an application-selected authority session and
// returns all affected peers. It does not select other authority sessions.
func (s *MemoryStore) Withdraw(ctx context.Context, principal, group string, at time.Time) (LogoutResult, error) {
	if err := s.check(ctx, at); err != nil {
		return LogoutResult{}, err
	}

	if s.role != metadata.IdentityProvider {
		return LogoutResult{}, ErrState
	}

	if principal == "" || group == "" {
		return LogoutResult{}, ErrState
	}

	if err := s.lock(ctx); err != nil {
		return LogoutResult{}, err
	}
	defer s.mu.Unlock()

	s.prune(at)

	r := LogoutResult{Status: protocol.Status{Code: protocol.Success}}
	peers := map[string]int{}

	for id, e := range s.sessions {
		if e.Principal != principal || e.AuthoritySession != group {
			continue
		}

		r.SessionIDs = append(r.SessionIDs, id)
		s.remove(recordKey{sessionRecord, id})

		s.addParticipant(&r, peers, principal, e)
	}

	return r, nil
}

func relationshipKey(principal, peer string) string { return principal + scopeSeparator + peer }
func sameName(a, b protocol.NameIdentifier) bool {
	if a.Format == "" {
		a.Format = protocol.NameIDUnspecified
	}

	if b.Format == "" {
		b.Format = protocol.NameIDUnspecified
	}

	return a == b
}

func qualifiedName(n protocol.NameIdentifier, local, peer string, role metadata.RoleType) protocol.NameIdentifier {
	if n.Format != protocol.NameIDPersistent {
		return n
	}

	idp, sp := local, peer
	if role == metadata.ServiceProvider {
		idp, sp = peer, local
	}

	if n.NameQualifier == "" {
		n.NameQualifier = idp
	}

	if n.SPNameQualifier == "" {
		n.SPNameQualifier = sp
	}

	return n
}

func validName(n protocol.NameIdentifier) bool {
	return n.Validate() == nil
}

func unknown() protocol.Status {
	return protocol.Status{Code: protocol.Requester, Subcodes: []string{protocol.UnknownPrincipal}}
}

func (s *MemoryStore) addParticipant(result *LogoutResult, positions map[string]int, principal string, e Session) {
	rel, ok := s.relationships[relationshipKey(principal, e.Peer)]
	if !ok || rel.terminated || !sameName(rel.NameID, e.NameID) {
		result.Status = protocol.Status{Code: protocol.Success, Subcodes: []string{protocol.PartialLogout}}
		return
	}

	for _, p := range s.pending {
		if p.Terminate && p.Peer == e.Peer && sameName(p.NameID, rel.NameID) {
			result.Status = protocol.Status{Code: protocol.Success, Subcodes: []string{protocol.PartialLogout}}
			return
		}
	}

	pos, exists := positions[e.Peer]
	if !exists {
		pos = len(result.Participants)
		positions[e.Peer] = pos
		result.Participants = append(result.Participants, Participant{Peer: e.Peer, NameID: rel.NameID})
	}

	if e.Index != "" && !slices.Contains(result.Participants[pos].SessionIndexes, e.Index) {
		result.Participants[pos].SessionIndexes = append(result.Participants[pos].SessionIndexes, e.Index)
	}
}

func (s *MemoryStore) validPending(p Pending, at time.Time) bool {
	const (
		maximumNewIDBytes            = 4096
		maximumPendingSessionIndexes = 128
	)

	if p.Kind == protocol.LogoutResponse && (p.Terminate || p.NewID != "") {
		return false
	}

	if len(p.SessionIndexes) > maximumPendingSessionIndexes || p.Kind == protocol.LogoutResponse && !p.LocalIsIDP && len(p.SessionIndexes) == 0 {
		return false
	}

	if p.LocalIsIDP != (s.role == metadata.IdentityProvider) || !profile.ID(p.ID) || !profile.URI(p.Peer) || !validName(p.NameID) || !at.Before(p.ExpiresAt) || p.ExpiresAt.Sub(at) > pendingRequestLifetime || p.Kind != protocol.ManageNameIDResponse && p.Kind != protocol.LogoutResponse {
		return false
	}

	return p.Kind != protocol.ManageNameIDResponse || p.Terminate != (p.NewID != "") && len(p.NewID) <= maximumNewIDBytes && p.NotOnOrAfter.IsZero() && p.ClockSkew == 0
}

func logoutDeadline(at, notOnOrAfter, fallback time.Time, clockSkew time.Duration) (time.Time, error) {
	const maximumClosedSessionLifetime = 7 * 24 * time.Hour

	if protocol.ValidatePolicy(protocol.Limits{ClockSkew: clockSkew}) != nil || notOnOrAfter.After(at.Add(maximumClosedSessionLifetime)) {
		return time.Time{}, ErrState
	}

	deadline := fallback
	if !notOnOrAfter.IsZero() {
		deadline = notOnOrAfter.Add(clockSkew)
	}

	if !at.Before(deadline) {
		return time.Time{}, ErrState
	}

	return deadline, nil
}
