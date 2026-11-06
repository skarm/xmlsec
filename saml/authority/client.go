package authority

import (
	"context"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
)

// Separate one-time assertion IDs from request/envelope replay IDs in authority client scopes; equal peer-provided IDs must not consume another message class.
const (
	scopeAssertionSuffix = ":assertion"
)

// Separate request IDs from response/assertion replay IDs in authority client scopes; correlation and atomic replay checks remain independent.
const (
	scopeRequestSuffix = ":request"
)

// Client performs authenticated, correlated synchronous queries and mapping.
// Metadata is refreshed for each exchange. The HTTP transport supplies TLS and
// optional Basic/client-certificate authentication; credentials are never taken
// from received XML. Replay must be a shared atomic store in multi-instance use.
type Client struct {
	// EntityID identifies the local requester and assertion audience.
	EntityID string
	// Peer is the expected authority entity ID.
	Peer string
	// Role selects the authority role in authenticated peer metadata.
	Role metadata.RoleType
	// Metadata resolves current trusted peer metadata for each exchange.
	Metadata metadata.Resolver
	// Signing supplies the request signing key and policy.
	Signing protocol.SigningKey
	// Replay atomically consumes correlation and one-time assertion IDs.
	Replay replay.Store
	// Options supplies response, assertion and query-matching policy.
	Options protocol.QueryResponseOptions
	// SOAP supplies the transport for queries and mapping requests.
	SOAP binding.SOAPClient
	// URI supplies the transport for assertion-ID retrieval.
	URI binding.URIClient
}

// Query sends one of the three queries or an assertion-ID request. It verifies
// every result and atomically consumes response/request and OneTimeUse IDs.
func (c Client) Query(ctx context.Context, q protocol.Query, at time.Time) (*protocol.VerifiedQueryResponse, error) {
	started := time.Now()

	endpoint, role, err := c.endpoint(ctx, queryService(q.Kind), metadata.SOAP, at)
	if err != nil {
		return nil, err
	}

	q.MessageHeader, err = c.header(q.MessageHeader, endpoint, at)
	if err != nil {
		return nil, err
	}

	d, err := protocol.SignQuery(ctx, q, c.Signing)
	if err != nil {
		return nil, err
	}

	d, err = c.roundTrip(ctx, endpoint, d)
	if err != nil {
		return nil, err
	}

	now := at.Add(time.Since(started))
	if !now.Before(role.ExpiresAt()) {
		return nil, metadata.ErrExpired
	}

	o := c.Options
	o.Issuer = c.Peer
	o.ExpectedRequestID = q.ID
	o.At = now
	o.Binding = metadata.SOAP
	o.Audience = c.EntityID

	r, err := protocol.VerifyQueryResponse(ctx, d, role.SigningKeys(), q, o)
	if err != nil {
		return nil, err
	}

	age, _, skew, err := protocol.AcceptanceWindow(o.Limits)
	if err != nil {
		return nil, err
	}

	end := now.Add(age + 2*skew)

	entries := []replay.Entry{{Scope: scope(c.EntityID, c.Peer), ID: r.Header().ID, ExpiresAt: end}, {Scope: scope(c.EntityID, c.Peer) + scopeRequestSuffix, ID: q.ID, ExpiresAt: end}}
	for _, a := range r.Assertions() {
		if a.OneTimeUse() {
			if a.NotOnOrAfter().IsZero() {
				return nil, protocol.ErrConditions
			}

			entries = append(entries, replay.Entry{Scope: scope(c.EntityID, a.Issuer()) + scopeAssertionSuffix, ID: a.ID(), ExpiresAt: a.NotOnOrAfter().Add(skew)})
		}
	}

	if c.Replay == nil {
		return nil, ErrDenied
	}

	if err = c.Replay.Consume(ctx, entries, now); err != nil {
		return nil, err
	}

	return r, nil
}

// Map requests a NameID mapping from a trusted IdP's NameIDMappingService.
// Successful encrypted output is intentionally opaque and can be forwarded to
// the target SP. It does not establish a local login or change an existing NameID.
func (c Client) Map(ctx context.Context, q protocol.NameIDMappingRequest, at time.Time) (*protocol.VerifiedNameIDMappingResponse, error) {
	started := time.Now()

	endpoint, role, err := c.endpoint(ctx, metadata.NameIDMappingService, metadata.SOAP, at)
	if err != nil {
		return nil, err
	}

	q.MessageHeader, err = c.header(q.MessageHeader, endpoint, at)
	if err != nil {
		return nil, err
	}

	d, err := protocol.SignNameIDMappingRequest(ctx, q, c.Signing)
	if err != nil {
		return nil, err
	}

	d, err = c.roundTrip(ctx, endpoint, d)
	if err != nil {
		return nil, err
	}

	o := c.Options.ExchangeOptions
	o.Issuer = c.Peer
	o.ExpectedRequestID = q.ID
	o.At = at.Add(time.Since(started))

	o.Binding = metadata.SOAP
	if !o.At.Before(role.ExpiresAt()) {
		return nil, metadata.ErrExpired
	}

	r, err := protocol.VerifyNameIDMappingResponse(ctx, d, role.SigningKeys(), o)
	if err != nil {
		return nil, err
	}

	if r.Status().Code == protocol.Success {
		if err = protocol.CheckMappedPolicy(ctx, r.Identifier(), q.Policy); err != nil {
			return nil, err
		}
	}

	if c.Replay == nil {
		return nil, ErrDenied
	}

	age, _, skew, err := protocol.AcceptanceWindow(o.Limits)
	if err != nil {
		return nil, err
	}

	err = c.Replay.Consume(ctx, []replay.Entry{{Scope: scope(c.EntityID, c.Peer), ID: r.Header().ID, ExpiresAt: o.At.Add(age + 2*skew)}, {Scope: scope(c.EntityID, c.Peer) + scopeRequestSuffix, ID: q.ID, ExpiresAt: o.At.Add(age + 2*skew)}}, o.At)

	return r, err
}

// Assertion retrieves an existing assertion using the URI binding and verifies
// its signature and conditions. AssertionTrust can authorize a separate issuer.
func (c Client) Assertion(ctx context.Context, id string, at time.Time) (*protocol.VerifiedAuthorityAssertion, error) {
	started := time.Now()

	endpoint, role, err := c.endpoint(ctx, metadata.AssertionIDRequestService, metadata.URI, at)
	if err != nil {
		return nil, err
	}

	d, err := c.URI.Resolve(ctx, endpoint, id)
	if err != nil {
		return nil, err
	}

	now := at.Add(time.Since(started))
	if !now.Before(role.ExpiresAt()) {
		return nil, metadata.ErrExpired
	}

	who := c.Peer
	keys := role.SigningKeys()

	if c.Options.AssertionTrust != nil {
		cs := d.Root().Children()
		if len(cs) == 0 {
			return nil, ErrDenied
		}

		who = cs[0].Text()

		keys, err = c.Options.AssertionTrust(ctx, who)
		if err != nil {
			return nil, err
		}
	}

	a, err := protocol.VerifyAuthorityAssertion(ctx, d, keys, protocol.AssertionOptions{Issuer: who, Audience: c.EntityID, At: now, Limits: c.Options.Limits, Policy: c.Options.Policy, Decryption: c.Options.Decryption})
	if err != nil {
		return nil, err
	}

	if a.OneTimeUse() {
		if c.Replay == nil || a.NotOnOrAfter().IsZero() {
			return nil, ErrDenied
		}

		_, _, skew, err := protocol.AcceptanceWindow(c.Options.Limits)
		if err != nil {
			return nil, err
		}

		err = c.Replay.Consume(ctx, []replay.Entry{{Scope: scope(c.EntityID, a.Issuer()) + scopeAssertionSuffix, ID: id, ExpiresAt: a.NotOnOrAfter().Add(skew)}}, now)
		if err != nil {
			return nil, err
		}
	}

	return a, nil
}

func (c Client) roundTrip(ctx context.Context, endpoint string, d *document.Document) (*document.Document, error) {
	envelope, err := protocol.SignSOAP(ctx, d, c.Signing)
	if err != nil {
		return nil, err
	}

	m, err := c.SOAP.RoundTrip(ctx, endpoint, envelope)
	if err != nil {
		return nil, err
	}

	return m.Payload(ctx)
}

func (c Client) header(h protocol.MessageHeader, endpoint string, at time.Time) (protocol.MessageHeader, error) {
	if h.Issuer != "" && h.Issuer != c.EntityID || h.Destination != "" && h.Destination != endpoint || !profile.URI(c.EntityID) {
		return h, ErrDenied
	}

	if h.ID == "" {
		var err error

		h.ID, err = profile.NewID()
		if err != nil {
			return h, err
		}
	}

	h.Issuer = c.EntityID
	h.Destination = endpoint
	h.IssueInstant = at

	return h, nil
}

func (c Client) endpoint(ctx context.Context, service, bindingURI string, at time.Time) (string, *metadata.Role, error) {
	if c.Metadata == nil || service == "" || ctx == nil || at.IsZero() {
		return "", nil, ErrDenied
	}

	entity, err := c.Metadata.Lookup(ctx, c.Peer, at)
	if err != nil {
		return "", nil, err
	}

	role, err := entity.Role(c.Role, at)
	if err != nil {
		return "", nil, err
	}

	for _, e := range role.Endpoints(service) {
		if e.Binding == bindingURI {
			return e.Location, role, nil
		}
	}

	return "", nil, ErrDenied
}

func queryService(k protocol.QueryKind) string {
	switch k {
	case protocol.AuthenticationQuery:
		return metadata.AuthnQueryService
	case protocol.AttributeQuery:
		return metadata.AttributeService
	case protocol.AuthorizationQuery:
		return metadata.AuthzService
	case protocol.AssertionRequest:
		return metadata.AssertionIDRequestService
	default:
		return ""
	}
}
