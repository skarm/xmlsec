package session

import (
	"context"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
)

// BackChannel performs authenticated SLO and NameID SOAP exchanges using current
// trusted metadata. It implements the notification operation used by Service.
// Metadata and signing providers must support concurrent operations.
type BackChannel struct {
	// EntityID identifies the local provider making the request.
	EntityID string
	// Role selects the local provider role used to resolve peer metadata.
	Role metadata.RoleType
	// Metadata supplies current authenticated peer endpoints and keys.
	Metadata metadata.Resolver
	// Signing supplies the request signing key and policy.
	Signing protocol.SigningKey
	// Options supplies response verification and freshness policy.
	Options protocol.ExchangeOptions
	// SOAP supplies the HTTP transport and SOAP processing limits.
	SOAP binding.SOAPClient
}

// Logout sends an authority-initiated request to one participant and validates
// the signed, correlated response. NotOnOrAfter is always present. Lifetime is
// the configured maximum accepted assertion lifetime, ensuring that delayed
// assertions cannot recreate the logged-out session during their validity.
func (c BackChannel) Logout(ctx context.Context, participant Participant, at time.Time) (protocol.Status, error) {
	endpoint, _, _, err := c.endpoints(ctx, participant.Peer, metadata.SingleLogoutService, at)
	if err != nil {
		return protocol.Status{}, err
	}

	_, lifetime, skew, err := protocol.AcceptanceWindow(c.Options.Limits)
	if err != nil {
		return protocol.Status{}, err
	}

	id, err := profile.NewID()
	if err != nil {
		return protocol.Status{}, err
	}

	d, err := protocol.SignLogoutRequest(ctx, protocol.LogoutRequest{ID: id, Issuer: c.EntityID, Destination: endpoint, IssueInstant: at, NameID: participant.NameID, SessionIndexes: participant.SessionIndexes, NotOnOrAfter: at.Add(lifetime + skew)}, c.Signing)
	if err != nil {
		return protocol.Status{}, err
	}

	r, err := c.Exchange(ctx, participant.Peer, d, at)
	if err != nil {
		return protocol.Status{}, err
	}

	return r.Status(), nil
}

// Exchange transmits a locally signed control request whose destination already
// matches the peer's current SOAP endpoint. It validates the returned issuer,
// local endpoint, request ID and response kind. Service.Complete applies an
// outgoing managed identifier change only after this succeeds.
func (c BackChannel) Exchange(ctx context.Context, peer string, request *document.Document, at time.Time) (*protocol.VerifiedStatusResponse, error) {
	const (
		xmlNameDestination = "Destination"
	)

	started := time.Now()

	if request == nil {
		return nil, ErrState
	}

	kind := request.Root().Name()
	service, responseKind := "", ""

	if kind.Space != protocol.ProtocolNamespace {
		return nil, ErrState
	}

	switch kind.Local {
	case lexicon.SAMLElementLogoutRequest:
		service = metadata.SingleLogoutService
		responseKind = protocol.LogoutResponse
	case lexicon.SAMLElementManageNameIDRequest:
		service = metadata.ManageNameIDService
		responseKind = protocol.ManageNameIDResponse
	default:
		return nil, ErrState
	}

	endpoint, returnEndpoint, role, err := c.endpoints(ctx, peer, service, at)
	if err != nil {
		return nil, err
	}

	destination, _ := request.Root().Attribute(document.Name{Local: xmlNameDestination})

	id, _ := request.Root().Attribute(document.Name{Local: lexicon.SAMLAttrID})
	if destination != endpoint || !profile.ID(id) {
		return nil, ErrState
	}

	envelope, err := protocol.SignSOAP(ctx, request, c.Signing)
	if err != nil {
		return nil, err
	}

	m, err := c.SOAP.RoundTrip(ctx, endpoint, envelope)
	if err != nil {
		return nil, err
	}

	d, err := m.Payload(ctx)
	if err != nil {
		return nil, err
	}

	o := c.Options
	o.Binding = metadata.SOAP
	o.Issuer = peer
	o.Destination = returnEndpoint
	o.ExpectedRequestID = id

	o.At = at.Add(time.Since(started))
	if !o.At.Before(role.ExpiresAt()) {
		return nil, metadata.ErrExpired
	}

	r, err := protocol.VerifyStatusResponse(ctx, d, role.SigningKeys(), o)
	if err != nil {
		return nil, err
	}

	if r.Kind() != responseKind {
		return nil, ErrState
	}

	return r, nil
}

func (c BackChannel) endpoints(ctx context.Context, peer, service string, at time.Time) (string, string, *metadata.Role, error) {
	if ctx == nil || c.Metadata == nil || at.IsZero() || !profile.URI(c.EntityID) || !profile.URI(peer) || c.Role != metadata.ServiceProvider && c.Role != metadata.IdentityProvider {
		return "", "", nil, ErrState
	}

	local, err := c.Metadata.Lookup(ctx, c.EntityID, at)
	if err != nil {
		return "", "", nil, err
	}

	remote, err := c.Metadata.Lookup(ctx, peer, at)
	if err != nil {
		return "", "", nil, err
	}

	if local == nil || remote == nil {
		return "", "", nil, ErrState
	}

	var own, other *metadata.Role
	if c.Role == metadata.IdentityProvider {
		own, err = local.Role(metadata.IdentityProvider, at)
		if err == nil {
			other, err = remote.Role(metadata.ServiceProvider, at)
		}
	} else {
		own, err = local.Role(metadata.ServiceProvider, at)
		if err == nil {
			other, err = remote.Role(metadata.IdentityProvider, at)
		}
	}

	if err != nil {
		return "", "", nil, err
	}

	selectEndpoint := func(role *metadata.Role, response bool) (string, error) {
		value := ""

		for _, e := range role.Endpoints(service) {
			if e.Binding != metadata.SOAP {
				continue
			}

			if value != "" {
				return "", ErrState
			}

			value = e.Location
			if response && e.ResponseLocation != "" {
				value = e.ResponseLocation
			}
		}

		if value == "" {
			return "", ErrState
		}

		return value, nil
	}

	endpoint, err := selectEndpoint(other, false)
	if err != nil {
		return "", "", nil, err
	}

	back, err := selectEndpoint(own, true)
	if err != nil {
		return "", "", nil, err
	}

	return endpoint, back, other, nil
}
