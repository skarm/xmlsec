// Package authority implements synchronous SAML assertion query/request and
// NameID Mapping workflows. Applications authorize every disclosure and own the
// authoritative identity, attribute and decision databases. Querying past
// authentication must never be treated as initiating a new login.
package authority

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
)

// ErrDenied indicates that a peer or disclosure was not authorized.
var ErrDenied = errors.New("SAML authority operation denied")

// Trust resolves keys only from authenticated configuration, never received
// KeyInfo. Providers must support concurrent calls and honor cancellation.
type Trust func(context.Context, string, time.Time) ([]crypto.PublicKey, error)

// Config supplies the authority's policy and application backends. Query returns
// authorized, already signed assertions about existing facts, or an empty set.
// Mapping authorizes both the source principal and target federation and returns
// an identifier. AllowCreate is permission, never an instruction to bypass account
// policy. Backends may return *protocol.StatusError for an authenticated failure.
type Config struct {
	// EntityID identifies the local authority.
	EntityID string
	// Endpoint is the trusted local SOAP service URL.
	Endpoint string
	// Signing supplies the authority's response signing key and policy.
	Signing protocol.SigningKey
	// Trust resolves trusted request verification keys for the expected peer.
	Trust Trust
	// AssertionTrust optionally resolves assertion issuer keys. Nil uses the local
	// signing key for the local issuer and Trust for other issuers.
	AssertionTrust Trust
	// Replay atomically records accepted requests before backend execution.
	Replay replay.Store
	// Options supplies request verification policy; Respond sets the peer,
	// destination, binding and time.
	Options protocol.ExchangeOptions
	// Matcher supplies application semantics for matching returned assertions to
	// queries.
	Matcher protocol.QueryMatchOptions
	// Kinds explicitly lists enabled query kinds; Query requires at least one.
	Kinds []protocol.QueryKind
	// Query authorizes disclosure and returns already signed assertions. Nil
	// disables queries.
	Query func(context.Context, *protocol.VerifiedQuery) ([]*document.Document, error)
	// Mapping authorizes an identifier mapping and returns its identifier document.
	// Nil disables mapping.
	Mapping func(context.Context, *protocol.VerifiedNameIDMappingRequest) (*document.Document, error)
	// EncryptAssertions optionally encrypts verified assertions for the requester.
	// It must select EncryptAssertion only. NameID/attribute encryption is also
	// available when producing assertions with protocol.SignAuthorityAssertion.
	EncryptAssertions func(context.Context, string) (*protocol.EncryptionOptions, error)
	// AllowPlaintextMapping opts into the deployment-specific exception to the
	// recommendation to encrypt mapped identifiers (Core 3.8 / Profiles 7.4.2).
	AllowPlaintextMapping bool
}

// Service verifies a request before invoking an application backend. Replay
// consumption occurs before a backend can create an identifier. A failed backend
// does not make the same signed request executable again.
type Service struct {
	// c retains the validated configuration snapshot and application adapters.
	c Config
	// kinds contains the explicitly enabled query forms.
	kinds map[protocol.QueryKind]bool
}

// NewService validates and snapshots role selection. Signing providers, replay
// storage and callbacks remain application-owned concurrent adapters.
func NewService(c Config) (*Service, error) {
	if !profile.URI(c.EntityID) || !profile.Endpoint(c.Endpoint, true) || c.Trust == nil || c.Replay == nil || c.Query == nil && c.Mapping == nil {
		return nil, ErrDenied
	}

	if _, _, _, err := protocol.AcceptanceWindow(c.Options.Limits); err != nil {
		return nil, err
	}

	kinds := map[protocol.QueryKind]bool{}

	for _, k := range c.Kinds {
		switch k {
		case protocol.AuthenticationQuery, protocol.AttributeQuery, protocol.AuthorizationQuery, protocol.AssertionRequest:
			kinds[k] = true
		default:
			return nil, ErrDenied
		}
	}

	if c.Query != nil && len(kinds) == 0 {
		return nil, ErrDenied
	}

	c.Kinds = nil
	c.Signing.CertificateDER = bytes.Clone(c.Signing.CertificateDER)
	c.Signing.InclusivePrefixes = slices.Clone(c.Signing.InclusivePrefixes)
	c.Signing.Policy = xmlsig.ClonePolicy(c.Signing.Policy)
	c.Options.Policy = xmlsig.ClonePolicy(c.Options.Policy)

	var err error

	c.Options.Decryption, err = protocol.CloneDecryption(c.Options.Decryption)
	if err != nil {
		return nil, err
	}

	return &Service{c: c, kinds: kinds}, nil
}

// Respond authenticates one SOAP payload for the expected peer and returns a
// signed SOAP response. Use binding.ReadSOAPRequest/WriteSOAPResponse at HTTP
// boundaries. Invalid unauthenticated messages do not reach application backends.
func (s *Service) Respond(ctx context.Context, d *document.Document, peer string, at time.Time) (*document.Document, error) {
	if s == nil || ctx == nil || d == nil || at.IsZero() {
		return nil, ErrDenied
	}

	keys, err := s.c.Trust(ctx, peer, at)
	if err != nil {
		return nil, err
	}

	o := s.c.Options
	o.Issuer = peer
	o.Destination = s.c.Endpoint
	o.At = at
	o.Binding = metadata.SOAP

	if d.Root().Name() == (document.Name{Space: protocol.ProtocolNamespace, Local: lexicon.SAMLElementNameIDMappingRequest}) {
		return s.respondMapping(ctx, d, peer, at, keys, o)
	}

	return s.respondQuery(ctx, d, peer, at, keys, o)
}

func (s *Service) consume(ctx context.Context, peer, id string, at time.Time) error {
	age, _, skew, err := protocol.AcceptanceWindow(s.c.Options.Limits)
	if err != nil {
		return err
	}

	return s.c.Replay.Consume(ctx, []replay.Entry{{Scope: scope(s.c.EntityID, peer), ID: id, ExpiresAt: at.Add(age + 2*skew)}}, at)
}

func scope(a, b string) string {
	const (
		scopeAuthorityPrefix = "authority:"
		scopeSeparator       = "\u0000"
	)

	v := sha256.Sum256([]byte(a + scopeSeparator + b))

	return scopeAuthorityPrefix + hex.EncodeToString(v[:])
}

func backendStatus(err error) (protocol.Status, error) {
	const (
		statusRequestDenied = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	)

	if err == nil {
		return protocol.Status{Code: protocol.Success}, nil
	}

	if status, ok := errors.AsType[*protocol.StatusError](err); ok {
		if status.Code == protocol.Success || status.Code == "" {
			return protocol.Status{}, ErrDenied
		}

		return protocol.Status{Code: status.Code, Subcodes: status.Subcodes, Message: status.Message}, nil
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return protocol.Status{}, err
	}

	if errors.Is(err, ErrDenied) {
		return protocol.Status{Code: protocol.Requester, Subcodes: []string{statusRequestDenied}}, nil
	}

	return protocol.Status{Code: protocol.Responder}, nil
}

func (s *Service) respondMapping(ctx context.Context, d *document.Document, peer string, at time.Time, keys []crypto.PublicKey, o protocol.ExchangeOptions) (*document.Document, error) {
	const (
		xmlNameEncryptedID = "EncryptedID"
	)

	if s.c.Mapping == nil {
		return nil, ErrDenied
	}

	r, err := protocol.VerifyNameIDMappingRequest(ctx, d, keys, o)
	if err != nil {
		return nil, err
	}

	if err = s.consume(ctx, peer, r.Request().ID, at); err != nil {
		return nil, err
	}

	id, backendErr := s.c.Mapping(ctx, r)

	status, err := backendStatus(backendErr)
	if err != nil {
		return nil, err
	}

	if status.Code == protocol.Success {
		if id == nil {
			return nil, ErrDenied
		}

		if id.Root().Name().Local != xmlNameEncryptedID && !s.c.AllowPlaintextMapping {
			return nil, ErrDenied
		}

		if err = protocol.CheckMappedPolicy(ctx, id, r.Request().Policy); err != nil {
			return nil, err
		}
	} else {
		id = r.ErrorIdentifier()
	}

	out, err := protocol.SignNameIDMappingResponse(ctx, protocol.NameIDMappingResponse{Issuer: s.c.EntityID, IssueInstant: at, InResponseTo: r.Request().ID, Status: status, Identifier: id}, s.c.Signing)
	if err != nil {
		return nil, err
	}

	return protocol.SignSOAP(ctx, out, s.c.Signing)
}

func (s *Service) respondQuery(ctx context.Context, d *document.Document, peer string, at time.Time, keys []crypto.PublicKey, o protocol.ExchangeOptions) (*document.Document, error) {
	kind := protocol.QueryKind(d.Root().Name().Local)
	if !s.kinds[kind] || s.c.Query == nil {
		return nil, ErrDenied
	}

	r, err := protocol.VerifyQuery(ctx, d, keys, o)
	if err != nil {
		return nil, err
	}

	q := r.Query()
	if err = s.consume(ctx, peer, q.ID, at); err != nil {
		return nil, err
	}

	assertions, backendErr := s.c.Query(ctx, r)

	status, err := backendStatus(backendErr)
	if err != nil {
		return nil, err
	}

	if status.Code != protocol.Success {
		assertions = nil
	}

	assertions = slices.Clone(assertions)

	verified, err := s.verifyAssertions(ctx, assertions, peer, at, o)
	if err != nil {
		return nil, err
	}

	if status.Code == protocol.Success {
		if err = protocol.MatchQueryResponse(ctx, q, verified, s.c.Matcher); err != nil {
			var failure *protocol.StatusError
			if !errors.As(err, &failure) {
				return nil, err
			}

			status = protocol.Status{Code: failure.Code, Subcodes: failure.Subcodes}
			assertions = nil
		}
	}

	if len(assertions) > 0 && s.c.EncryptAssertions != nil {
		policy, err := s.c.EncryptAssertions(ctx, peer)
		if err != nil {
			return nil, err
		}

		for i, v := range verified {
			assertions[i], err = protocol.EncryptAuthorityAssertion(ctx, v, policy)
			if err != nil {
				return nil, err
			}
		}
	}

	key := s.forwardingKey(at)

	out, err := protocol.SignQueryResponse(ctx, protocol.QueryResponse{Issuer: s.c.EntityID, IssueInstant: at, InResponseTo: q.ID, Status: status, Assertions: assertions}, key)
	if err != nil {
		return nil, err
	}

	return protocol.SignSOAP(ctx, out, key)
}

func (s *Service) forwardingKey(at time.Time) protocol.SigningKey {
	const (
		xmlNameIssuer = "Issuer"
	)

	key := s.c.Signing
	if key.PreserveKeys != nil {
		return key
	}

	key.PreserveKeys = func(ctx context.Context, parent document.Element) ([]crypto.PublicKey, error) {
		children := parent.Children()
		if len(children) == 0 || children[0].Name() != (document.Name{Space: protocol.AssertionNamespace, Local: xmlNameIssuer}) {
			return nil, ErrDenied
		}

		return s.assertionKeys(ctx, children[0].Text(), at)
	}

	return key
}

func (s *Service) verifyAssertions(ctx context.Context, assertions []*document.Document, peer string, at time.Time, o protocol.ExchangeOptions) ([]*protocol.VerifiedAuthorityAssertion, error) {
	verified := make([]*protocol.VerifiedAuthorityAssertion, 0, len(assertions))

	for _, a := range assertions {
		if a == nil || len(a.Root().Children()) == 0 {
			return nil, ErrDenied
		}

		who := a.Root().Children()[0].Text()

		ak, err := s.assertionKeys(ctx, who, at)
		if err != nil {
			return nil, err
		}

		v, err := protocol.VerifyAuthorityAssertion(ctx, a, ak, protocol.AssertionOptions{Issuer: who, Audience: peer, At: at, Limits: o.Limits, Policy: o.Policy})
		if err != nil {
			return nil, err
		}

		verified = append(verified, v)
	}

	return verified, nil
}

func (s *Service) assertionKeys(ctx context.Context, issuer string, at time.Time) ([]crypto.PublicKey, error) {
	if s.c.AssertionTrust != nil {
		return s.c.AssertionTrust(ctx, issuer, at)
	}

	if issuer != s.c.EntityID {
		return s.c.Trust(ctx, issuer, at)
	}

	if s.c.Signing.Secret != nil {
		return []crypto.PublicKey{*s.c.Signing.Secret}, nil
	}

	if nilcheck.IsNil(s.c.Signing.Key) {
		return nil, ErrDenied
	}

	return []crypto.PublicKey{s.c.Signing.Key.Public()}, nil
}
