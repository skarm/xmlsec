package sp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"reflect"
	"slices"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/saml/artifact"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/ecp"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/proof"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/saml/state"
	"github.com/skarm/xmlsec/xmldsig"
)

var (
	// ErrPolicy reports SAML SP policy rejected.
	ErrPolicy = errors.New("SAML SP policy rejected")
	// ErrCorrelation reports SAML browser/request correlation failed.
	ErrCorrelation = errors.New("SAML browser/request correlation failed")
)

// Config supplies trusted metadata, signing keys, request and replay stores, and
// response validation policy.
type Config struct {
	// EntityID is the local entity identifier used for issuer and audience checks.
	EntityID string
	// Metadata supplies authenticated or explicitly trusted metadata and must honor
	// cancellation.
	Metadata metadata.Resolver
	// Signing supplies the local signer and its matching certificate.
	Signing protocol.SigningKey
	// VerificationPolicy sets algorithms accepted for peer XML signatures.
	VerificationPolicy xmldsig.Policy
	// Requests stores browser-bound pending requests; use shared storage across service
	// instances.
	Requests state.Store
	// Replay atomically consumes scoped identifiers; use shared storage across service
	// instances.
	Replay replay.Store
	// Limits bounds protocol message age, assertion lifetime and attribute values.
	Limits protocol.Limits
	// POSTLimits bounds POST binding messages and generated forms.
	POSTLimits binding.POSTLimits
	// RedirectLimits sets Redirect binding signature policy and query, inflation and XML
	// limits. An empty policy inherits Signing.Policy; an explicit policy must permit
	// the outgoing signature together with Signing.Policy.
	RedirectLimits binding.Options
	// RequestLifetime bounds pending requests; zero selects five minutes.
	// Values must be between one second and ten minutes.
	RequestLifetime time.Duration
	// AllowUnsignedResponse permits an unsigned Response envelope; the Assertion still
	// requires authentication.
	AllowUnsignedResponse bool
	// AllowUnsignedAssertion accepts an unsigned assertion only under an
	// authenticated Response. A present assertion signature is still required
	// to validate.
	AllowUnsignedAssertion bool
	// Decryption selects explicit local RSA providers and exact algorithms.
	// Only providers authorized by this SP's trusted encryption metadata are used.
	Decryption *protocol.DecryptionOptions
	// RequireEncryption rejects plaintext at selected assertion positions.
	RequireEncryption protocol.EncryptionTargets
}

// BeginOptions selects an IdP, binding and authentication conditions and supplies the
// browser correlation secret.
type BeginOptions struct {
	// At is the explicit trusted time used by this operation.
	At time.Time
	// ACSIndex selects an exact metadata endpoint index. Nil uses the default endpoint;
	// a pointer to zero selects index zero explicitly.
	ACSIndex *uint16
	// IDP selects the trusted identity provider by its metadata entity identifier.
	IDP string
	// Binding selects HTTP-Redirect (default), HTTP-POST or PAOS (ECP).
	Binding string
	// ResponseBinding selects HTTP-POST (default), HTTP-Artifact or PAOS.
	// PAOS initiation always selects PAOS responses.
	ResponseBinding string
	// NameIDFormat optionally requests an exact subject identifier format URI.
	NameIDFormat string
	// BrowserBinding is a server-generated, unpredictable browser or session secret.
	BrowserBinding []byte
	// RequestedContexts lists requested authentication context class URIs for exact
	// comparison.
	RequestedContexts []string
	// ChannelBindings enables the negotiated ECP 2.0 channel binding option.
	// Supply data from the actual client/SP TLS connection; PAOS is required.
	ChannelBindings []protocol.ChannelBinding
	// ForceAuthn requests fresh authentication.
	ForceAuthn bool
	// IsPassive forbids interaction with the subject when true.
	IsPassive bool
	// AllowCreateNameID permits the IdP to create a new subject identifier when true.
	AllowCreateNameID bool
	// HolderOfKey requires ECP HoK; the handler must check client negotiation.
	HolderOfKey bool
}

// ConsumeOptions supplies trusted verification time, browser correlation secret and an
// optional expected client address.
type ConsumeOptions struct {
	// At is the explicit trusted time used by this operation.
	At time.Time
	// BrowserBinding is an unpredictable, application-protected browser correlation secret.
	BrowserBinding []byte
	// ClientAddress is the expected client address when validating subject confirmation.
	ClientAddress string
	proof         *proof.Verified
}

// ServiceProvider initiates solicited SAML login and validates and consumes correlated
// responses.
type ServiceProvider struct{ c Config }

// NewServiceProvider validates and snapshots ServiceProvider policy and required trusted adapters.
func NewServiceProvider(c Config) (*ServiceProvider, error) {
	const (
		defaultRequestLifetime = 5 * time.Minute
		maximumRequestLifetime = 10 * time.Minute
		minimumRequestLifetime = time.Second
	)

	if !profile.URI(c.EntityID) || nilcheck.IsNil(c.Metadata) || nilcheck.IsNil(c.Requests) || nilcheck.IsNil(c.Replay) || nilcheck.IsNil(c.Signing.Key) || c.Signing.Secret != nil || protocol.ValidatePolicy(c.Limits) != nil {
		return nil, ErrPolicy
	}

	if c.RequestLifetime == 0 {
		c.RequestLifetime = defaultRequestLifetime
	}

	if c.RequestLifetime < minimumRequestLifetime || c.RequestLifetime > maximumRequestLifetime {
		return nil, ErrPolicy
	}

	if e := signature.Key(c.Signing.Key.Public()); e != nil {
		return nil, e
	}

	if c.Signing.SignatureMethod == "" {
		switch c.Signing.Key.Public().(type) {
		case *rsa.PublicKey:
			c.Signing.SignatureMethod = xmldsig.RSASHA256
		case *ecdsa.PublicKey:
			c.Signing.SignatureMethod = xmldsig.ECDSASHA256
		default:
			return nil, ErrPolicy
		}
	}

	c.VerificationPolicy = xmlsig.ClonePolicy(c.VerificationPolicy)
	c.Signing.CertificateDER = bytes.Clone(c.Signing.CertificateDER)
	c.Signing.InclusivePrefixes = append([]string(nil), c.Signing.InclusivePrefixes...)
	c.Signing.Policy = xmlsig.ClonePolicy(c.Signing.Policy)
	c.RedirectLimits.Policy = xmlsig.ClonePolicy(c.RedirectLimits.Policy)

	var err error

	c.Decryption, err = protocol.CloneDecryption(c.Decryption)
	if err != nil || c.RequireEncryption&^(protocol.EncryptAssertion|protocol.EncryptNameID|protocol.EncryptAttributes) != 0 || c.RequireEncryption != 0 && c.Decryption == nil {
		return nil, ErrPolicy
	}

	return &ServiceProvider{c: c}, nil
}

// Begin creates a signed solicited request and records its browser-bound pending state
// before returning transport data.
func (s *ServiceProvider) Begin(ctx context.Context, o BeginOptions) (*Outbound, error) {
	const (
		fieldRelayState         = "RelayState"
		fieldSAMLEncoding       = "SAMLEncoding"
		fieldSAMLRequest        = "SAMLRequest"
		fieldSAMLResponse       = "SAMLResponse"
		fieldSignature          = "Signature"
		fieldSignatureAlgorithm = "SigAlg"
		relayStateRandomBytes   = 32
	)

	if s == nil || ctx == nil || o.At.IsZero() || !profile.URI(o.IDP) {
		return nil, ErrPolicy
	}

	if e := ctx.Err(); e != nil {
		return nil, e
	}

	browser, e := state.BrowserDigest(o.BrowserBinding)
	if e != nil {
		return nil, e
	}

	if err := normalizeBeginBindings(&o); err != nil {
		return nil, err
	}

	own, other, e := s.roles(ctx, o.IDP, o.At)
	if e != nil {
		return nil, e
	}

	if !keyAllowed(s.c.Signing.Key.Public(), own) {
		return nil, ErrPolicy
	}

	acs, e := beginACS(own, o)
	if e != nil {
		return nil, e
	}

	if returned1, matched := s.beginNameIDFormat(&o, own, other); matched {
		return nil, returned1
	}

	destination := ""

	if returned1Value, matchedBranch := beginEndpoints(other, &o, &destination); matchedBranch {
		return nil, returned1Value
	}

	if destination == "" {
		return nil, ErrPolicy
	}

	u, e := url.Parse(destination)
	if e != nil {
		return nil, ErrPolicy
	}

	values, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return nil, ErrPolicy
	}

	for _, k := range []string{fieldSAMLRequest, fieldSAMLResponse, fieldRelayState, fieldSignatureAlgorithm, fieldSignature, fieldSAMLEncoding} {
		if _, ok := values[k]; ok {
			return nil, ErrPolicy
		}
	}

	requestID, e := profile.NewID()
	if e != nil {
		return nil, e
	}

	relayBytes := make([]byte, relayStateRandomBytes)
	if _, e = rand.Read(relayBytes); e != nil {
		return nil, e
	}

	relay := base64.RawURLEncoding.EncodeToString(relayBytes)

	expires := o.At.Add(s.c.RequestLifetime)
	if own.ExpiresAt().Before(expires) {
		expires = own.ExpiresAt()
	}

	if other.ExpiresAt().Before(expires) {
		expires = other.ExpiresAt()
	}

	spec := protocol.AuthnRequest{ID: requestID, Issuer: s.c.EntityID, Destination: destination, ACS: acs.Location, ResponseBinding: o.ResponseBinding, IssueInstant: o.At, NameIDFormat: o.NameIDFormat, RequestedContexts: append([]string(nil), o.RequestedContexts...), ForceAuthn: o.ForceAuthn, IsPassive: o.IsPassive, AllowCreateNameID: o.AllowCreateNameID}
	spec.SOAPContext = o.Binding == metadata.HTTPArtifact

	spec.ChannelBindings = protocol.CloneChannelBindings(o.ChannelBindings)

	var signed *document.Document

	switch o.Binding {
	case metadata.HTTPRedirect:
		signed, e = protocol.BuildAuthnRequest(ctx, spec)
	case metadata.PAOS:
		if o.HolderOfKey {
			signed, e = ecp.HoKChallenge(ctx, spec, s.c.Signing, &relay, "")
		} else {
			signed, e = ecp.Challenge(ctx, spec, s.c.Signing, &relay, "")
		}
	default:
		signed, e = protocol.SignAuthnRequest(ctx, spec, s.c.Signing)
	}

	if e != nil {
		return nil, e
	}

	out := &Outbound{destination: destination, binding: o.Binding, requestID: requestID, relay: relay, expires: expires, doc: signed, limits: s.c.POSTLimits}
	out.issuer = s.c.EntityID

	out.recipient = o.IDP
	if o.Binding == metadata.HTTPRedirect {
		out.query, e = s.signRedirect(ctx, signed, &relay)
	} else if o.Binding != metadata.PAOS {
		_, e = binding.WritePOST(ctx, io.Discard, signed, binding.Request, &relay, s.c.POSTLimits)
	}

	if e != nil {
		return nil, e
	}

	pending := state.Pending{SP: s.c.EntityID, IDP: o.IDP, RequestID: requestID, RelayState: relay, ACS: acs.Location, IssuedAt: o.At, ExpiresAt: expires, BrowserSHA256: browser, NameIDFormat: pendingNameID(o.NameIDFormat), RequestedContexts: append([]string(nil), o.RequestedContexts...), ForceAuthn: o.ForceAuthn}

	pending.ResponseBinding = o.ResponseBinding

	pending.ChannelBindings = protocol.CloneChannelBindings(spec.ChannelBindings)

	pending.RequireHolderOfKey = o.HolderOfKey
	if e = s.c.Requests.Put(ctx, pending, o.At); e != nil {
		return nil, e
	}

	return out, nil
}

func (s *ServiceProvider) signRedirect(ctx context.Context, d *document.Document, relay *string) (string, error) {
	opt := s.c.RedirectLimits
	if emptyRedirectPolicy(opt.Policy) {
		opt.Policy = s.c.Signing.Policy
	}

	var err error

	opt.Policy, err = xmldsig.IntersectPolicies(s.c.Signing.Policy, opt.Policy)
	if err != nil {
		return "", err
	}

	opt.SignatureMethod = s.c.Signing.SignatureMethod

	return binding.SignRedirect(ctx, d, binding.Request, relay, s.c.Signing.Key, opt)
}

func emptyRedirectPolicy(p xmldsig.Policy) bool {
	// Empty algorithm lists select defaults, so their allocated-empty and nil
	// forms both retain the historical inheritance of the signing policy.
	if len(p.AllowedSignatureMethods) == 0 {
		p.AllowedSignatureMethods = nil
	}

	if len(p.AllowedDigestMethods) == 0 {
		p.AllowedDigestMethods = nil
	}

	return reflect.ValueOf(p).IsZero()
}

func pendingNameID(s string) string {
	if s == protocol.NameIDUnspecified {
		return ""
	}

	return s
}

func (s *ServiceProvider) beginNameIDFormat(o *BeginOptions, own *metadata.Role, other *metadata.Role) (returned1 error, matched bool) {
	if o.NameIDFormat == protocol.NameIDEncrypted {
		decryption, err := s.decryptionFor(own)
		if err != nil || decryption == nil {
			return ErrPolicy, true
		}

		return nil, false
	}

	if o.NameIDFormat != "" && o.NameIDFormat != protocol.NameIDUnspecified {
		if len(own.NameIDFormats()) > 0 && !contains(own.NameIDFormats(), o.NameIDFormat) || len(other.NameIDFormats()) > 0 && !contains(other.NameIDFormats(), o.NameIDFormat) {
			return ErrPolicy, true
		}
	}

	return
}

func beginACS(own *metadata.Role, o BeginOptions) (metadata.Endpoint, error) {
	if o.HolderOfKey {
		if endpoint, err := own.HoKACS(o.ResponseBinding, o.ACSIndex); err == nil {
			return endpoint, nil
		}
	}

	return own.ACS(o.ResponseBinding, o.ACSIndex)
}

func beginEndpoints(other *metadata.Role, o *BeginOptions, destination *string) (returned1Value error, matchedBranch bool) {
	requestBinding := o.Binding
	if requestBinding == metadata.PAOS {
		requestBinding = metadata.SOAP
	}

	endpoints := other.Endpoints(metadata.SingleSignOnService)

	preferHoK := o.HolderOfKey && slices.ContainsFunc(endpoints, func(ep metadata.Endpoint) bool { return ep.HolderOfKey() && ep.TransportBinding() == requestBinding })
	for _, ep := range endpoints {
		if ep.HolderOfKey() == preferHoK && ep.TransportBinding() == requestBinding {
			if (*destination) != "" {
				return ErrPolicy, true
			}

			*destination = ep.Location
		}
	}

	return
}

// ConsumePOST returns an assertion only AFTER browser correlation, metadata,
// all protocol checks, and an atomic replay-store commit. RelayState by itself
// is insufficient and is never used as an open redirect destination.
func (s *ServiceProvider) ConsumePOST(ctx context.Context, form []byte, o ConsumeOptions) (*protocol.VerifiedAssertion, error) {
	if s == nil || ctx == nil || o.At.IsZero() {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if _, err := state.BrowserDigest(o.BrowserBinding); err != nil {
		return nil, err
	}

	message, e := binding.DecodePOST(ctx, form, binding.Response, s.c.POSTLimits)
	if e != nil {
		return nil, e
	}

	relay, present := message.RelayState()
	if !present {
		return nil, ErrCorrelation
	}

	return s.consumeDocument(ctx, message.UnverifiedDocument(), relay, metadata.HTTPPost, o)
}

// ConsumePAOS validates an ECP response using the same browser binding, metadata,
// assertion policy and atomic replay checks as HTTP-POST Web SSO.
func (s *ServiceProvider) ConsumePAOS(ctx context.Context, raw []byte, o ConsumeOptions) (*protocol.VerifiedAssertion, error) {
	d, relay, err := ecp.DecodeResponse(ctx, raw, "", binding.SOAPOptions{})
	if err != nil {
		return nil, err
	}

	if relay == nil {
		return nil, ErrCorrelation
	}

	return s.consumeDocument(ctx, d, *relay, metadata.PAOS, o)
}

// ConsumeECP validates a PAOS response with possession established for its exact
// SOAP snapshot. SAML signatures, pending HoK requirements and replay are checked.
func (s *ServiceProvider) ConsumeECP(ctx context.Context, p *proof.Verified, o ConsumeOptions) (*protocol.VerifiedAssertion, error) {
	if p == nil {
		return nil, ErrPolicy
	}

	d, relay, err := ecp.ExtractResponse(ctx, p.Message(), "")
	if err != nil {
		return nil, err
	}

	if relay == nil {
		return nil, ErrCorrelation
	}

	o.proof = p

	return s.consumeDocument(ctx, d, *relay, metadata.PAOS, o)
}

// ConsumeArtifact validates a resolved artifact's SAML response. Resolution must
// already have authenticated the peer and single-use artifact. RelayState and
// browser binding are correlated with the enclosed response's own request ID.
func (s *ServiceProvider) ConsumeArtifact(ctx context.Context, message *document.Document, relay string, o ConsumeOptions) (*protocol.VerifiedAssertion, error) {
	return s.consumeDocument(ctx, message, relay, metadata.HTTPArtifact, o)
}

func (s *ServiceProvider) consumeDocument(ctx context.Context, message *document.Document, relay, responseBinding string, o ConsumeOptions) (*protocol.VerifiedAssertion, error) {
	const (
		minimumRelayStateBytes = 16
		scopeAssertionKind     = "assertion"
		scopeRequestKind       = "request"
		scopeResponseKind      = "response"
	)

	if s == nil || ctx == nil || o.At.IsZero() || message == nil {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	browser, e := state.BrowserDigest(o.BrowserBinding)
	if e != nil {
		return nil, e
	}

	if len(relay) < minimumRelayStateBytes {
		return nil, ErrCorrelation
	}

	pending, e := s.c.Requests.Get(ctx, s.c.EntityID, relay, o.At)
	if e != nil {
		return nil, e
	}

	if pending.SP != s.c.EntityID || pending.RelayState != relay || !o.At.Before(pending.ExpiresAt) || pending.IssuedAt.After(o.At) || subtle.ConstantTimeCompare(pending.BrowserSHA256[:], browser[:]) != 1 {
		return nil, ErrCorrelation
	}

	expectedBinding := pending.ResponseBinding
	if expectedBinding == "" {
		expectedBinding = metadata.HTTPPost
	}

	if responseBinding != expectedBinding {
		return nil, ErrPolicy
	}

	own, other, e := s.roles(ctx, pending.IDP, o.At)
	if e != nil {
		return nil, e
	}

	allowedACS := false

	for _, ep := range own.Endpoints(metadata.AssertionConsumerService) {
		if ep.AcceptsTransport(responseBinding, pending.RequireHolderOfKey) && ep.Location == pending.ACS {
			allowedACS = true
		}
	}

	if !allowedACS {
		return nil, ErrPolicy
	}

	opt := protocol.ResponseOptions{Issuer: pending.IDP, Audience: s.c.EntityID, Destination: pending.ACS, ExpectedRequestID: pending.RequestID, At: o.At, RequestIssueInstant: pending.IssuedAt, ForceAuthn: pending.ForceAuthn, ExpectedAuthnContexts: append([]string(nil), pending.RequestedContexts...), ExpectedAddress: o.ClientAddress, Limits: s.c.Limits, Policy: s.c.VerificationPolicy, AllowUnsignedResponse: s.c.AllowUnsignedResponse}
	opt.AllowUnsignedAssertion = s.c.AllowUnsignedAssertion
	opt.ExpectedChannelBindings = protocol.CloneChannelBindings(pending.ChannelBindings)
	opt.Proof = o.proof
	opt.RequireHolderOfKey = pending.RequireHolderOfKey

	opt.RequireEncryption = s.c.RequireEncryption

	opt.Decryption, e = s.decryptionFor(own)
	if e != nil {
		return nil, e
	}

	responseNameIDPolicy(pending.NameIDFormat, own, &opt)

	result, e := protocol.VerifyResponse(ctx, message, other.SigningKeys(), opt)
	if e != nil {
		return nil, e
	}

	if len(other.Endpoints(metadata.SingleLogoutService)) > 0 && result.SessionIndex() == "" {
		return nil, protocol.ErrProfile
	}

	age, _, skew, e := protocol.AcceptanceWindow(s.c.Limits)
	if e != nil {
		return nil, e
	}
	// Retain all replay identities through every configured acceptance window.
	expires := result.NotOnOrAfter().Add(skew)
	if pending.ExpiresAt.After(expires) {
		expires = pending.ExpiresAt
	}

	if o.At.Add(age + skew).After(expires) {
		expires = o.At.Add(age + skew)
	}

	entries := []replay.Entry{{Scope: scope(scopeRequestKind, s.c.EntityID, pending.IDP), ID: pending.RequestID, ExpiresAt: expires}, {Scope: scope(scopeAssertionKind, s.c.EntityID, pending.IDP), ID: result.AssertionID(), ExpiresAt: expires}, {Scope: scope(scopeResponseKind, s.c.EntityID, pending.IDP), ID: result.ResponseID(), ExpiresAt: expires}}
	if e = s.c.Replay.Consume(ctx, entries, o.At); e != nil {
		return nil, e
	}

	return result, nil
}

func (s *ServiceProvider) roles(ctx context.Context, idp string, at time.Time) (*metadata.Role, *metadata.Role, error) {
	a, e := s.c.Metadata.Lookup(ctx, s.c.EntityID, at)
	if e != nil {
		return nil, nil, e
	}

	own, e := a.Role(metadata.ServiceProvider, at)
	if e != nil {
		return nil, nil, e
	}

	b, e := s.c.Metadata.Lookup(ctx, idp, at)
	if e != nil {
		return nil, nil, e
	}

	other, e := b.Role(metadata.IdentityProvider, at)
	if e != nil {
		return nil, nil, e
	}

	return own, other, nil
}

// Outbound retains an immutable signed request and its binding-specific transport
// data.
type Outbound struct {
	destination       string
	binding           string
	requestID         string
	relay             string
	query             string
	limits            binding.POSTLimits
	doc               *document.Document
	expires           time.Time
	issuer, recipient string
}

// IssueArtifact creates a one-time AuthnRequest artifact bound to the selected
// IdP. Deliver it at Destination using binding.ArtifactURL or ArtifactForm.
func (o *Outbound) IssueArtifact(ctx context.Context, issuer artifact.Issuer, at time.Time, lifetime time.Duration) (binding.Artifact, error) {
	if o == nil || o.binding != metadata.HTTPArtifact || issuer.EntityID != o.issuer {
		return binding.Artifact{}, ErrPolicy
	}

	return issuer.Issue(ctx, o.doc, o.recipient, at, lifetime)
}

// PAOS returns the immutable ECP challenge envelope for an HTTP 200 response
// with Content-Type application/vnd.paos+xml. Negotiate ECP before calling Begin.
func (o *Outbound) PAOS() (*document.Document, error) {
	if o == nil || o.binding != metadata.PAOS {
		return nil, ErrPolicy
	}

	return o.doc, nil
}

// Destination returns the validated destination endpoint.
func (o *Outbound) Destination() string {
	if o == nil {
		return ""
	}

	return o.destination
}

// Binding returns the selected SAML binding URI.
func (o *Outbound) Binding() string {
	if o == nil {
		return ""
	}

	return o.binding
}

// RequestID returns the generated request identifier.
func (o *Outbound) RequestID() string {
	if o == nil {
		return ""
	}

	return o.requestID
}

// RelayState returns the generated opaque request correlation value.
func (o *Outbound) RelayState() string {
	if o == nil {
		return ""
	}

	return o.relay
}

// RawQuery returns the signed raw Redirect query.
func (o *Outbound) RawQuery() string {
	if o == nil {
		return ""
	}

	return o.query
}

// WritePOST writes the signed POST request directly to dst, which remains open.
// The immutable XML snapshot is retained; a complete form is not. Errors may
// leave partial output which the caller must discard. Redirect requests are rejected.
func (o *Outbound) WritePOST(ctx context.Context, dst io.Writer) (int64, error) {
	if o == nil || o.binding != metadata.HTTPPost {
		return 0, ErrPolicy
	}

	return binding.WritePOST(ctx, dst, o.doc, binding.Request, &o.relay, o.limits)
}

// WritePOSTForm writes a complete HTML POST form to the metadata-selected
// endpoint. It leaves dst open and may leave partial output on failure.
func (o *Outbound) WritePOSTForm(ctx context.Context, dst io.Writer) (int64, error) {
	if o == nil || o.binding != metadata.HTTPPost {
		return 0, ErrPolicy
	}

	return binding.WritePOSTForm(ctx, dst, o.destination, o.doc, binding.Request, &o.relay, o.limits)
}

// ExpiresAt returns the exclusive expiration boundary.
func (o *Outbound) ExpiresAt() time.Time {
	if o == nil {
		return time.Time{}
	}

	return o.expires
}

// RedirectURL returns the destination URL with the signed query appended for a Redirect
// request. RelayState is an opaque signed query value, not a return destination.
func (o *Outbound) RedirectURL() (string, error) {
	if o == nil || o.binding != metadata.HTTPRedirect {
		return "", ErrPolicy
	}

	u, e := url.Parse(o.destination)
	if e != nil {
		return "", ErrPolicy
	}

	if u.RawQuery != "" {
		u.RawQuery += "&"
	}

	u.RawQuery += o.query

	return u.String(), nil
}

func keyAllowed(key crypto.PublicKey, role *metadata.Role) bool {
	b, e := x509.MarshalPKIXPublicKey(key)
	if e != nil {
		return false
	}

	for _, candidate := range role.SigningKeys() {
		v, e := x509.MarshalPKIXPublicKey(candidate)
		if e == nil && bytes.Equal(b, v) {
			return true
		}
	}

	return false
}

func contains(a []string, s string) bool {
	return slices.Contains(a, s)
}

func scope(kind, sp, idp string) string {
	const (
		scopeSPPrefix  = "saml:sp:"
		scopeSeparator = "\u0000"
	)

	sum := sha256.Sum256([]byte(sp + scopeSeparator + idp))

	return scopeSPPrefix + kind + ":" + hex.EncodeToString(sum[:])
}

func (s *ServiceProvider) decryptionFor(own *metadata.Role) (*protocol.DecryptionOptions, error) {
	if s.c.Decryption == nil {
		return nil, nil
	}

	decryption := *s.c.Decryption

	decryption.Keys = nil
	for _, candidate := range s.c.Decryption.Keys {
		encoded, err := x509.MarshalPKIXPublicKey(candidate.Public())
		if err != nil {
			return nil, ErrPolicy
		}

		for _, allowed := range own.EncryptionKeys() {
			other, err := x509.MarshalPKIXPublicKey(allowed)
			if err == nil && bytes.Equal(encoded, other) {
				decryption.Keys = append(decryption.Keys, candidate)
				break
			}
		}
	}

	if len(decryption.Keys) != 0 {
		return &decryption, nil
	}

	return nil, nil
}

func normalizeBeginBindings(o *BeginOptions) error {
	if (len(o.ChannelBindings) != 0 || o.HolderOfKey) && o.Binding != metadata.PAOS {
		return ErrPolicy
	}

	if o.Binding == "" {
		o.Binding = metadata.HTTPRedirect
	}

	if o.Binding != metadata.HTTPRedirect && o.Binding != metadata.HTTPPost && o.Binding != metadata.PAOS && o.Binding != metadata.HTTPArtifact {
		return ErrPolicy
	}

	if o.ResponseBinding == "" {
		o.ResponseBinding = metadata.HTTPPost
	}

	if o.Binding == metadata.PAOS {
		o.ResponseBinding = metadata.PAOS
	}

	if !contains([]string{metadata.HTTPPost, metadata.HTTPArtifact, metadata.PAOS}, o.ResponseBinding) {
		return ErrPolicy
	}

	if o.ResponseBinding == metadata.PAOS && o.Binding != metadata.PAOS {
		return ErrPolicy
	}

	return nil
}

func responseNameIDPolicy(nameIDFormat string, own *metadata.Role, options *protocol.ResponseOptions) {
	if nameIDFormat == protocol.NameIDEncrypted {
		options.RequireEncryption |= protocol.EncryptNameID
		options.AllowedNameIDFormats = own.NameIDFormats()
	} else if nameIDFormat != "" && nameIDFormat != protocol.NameIDUnspecified {
		options.AllowedNameIDFormats = []string{nameIDFormat}
	} else {
		options.AllowedNameIDFormats = own.NameIDFormats()
	}
}
