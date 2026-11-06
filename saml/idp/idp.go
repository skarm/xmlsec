package idp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
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
	"github.com/skarm/xmlsec/xmldsig"
)

// ErrPolicy reports SAML IdP policy rejected.
var ErrPolicy = errors.New("SAML IdP policy rejected")

// Config supplies trusted metadata, signing keys, replay storage and assertion
// lifetime policy.
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
	// Replay atomically consumes scoped identifiers; use shared storage across service
	// instances.
	Replay replay.Store
	// Limits bounds protocol message age, assertion lifetime and attribute values.
	Limits protocol.Limits
	// POSTLimits bounds POST binding messages and generated forms.
	POSTLimits binding.POSTLimits
	// RedirectLimits sets Redirect binding signature policy and query, inflation and XML
	// limits.
	RedirectLimits binding.Options
	// AssertionLifetime defaults to five minutes and must be at least one second
	// and no greater than Limits.MaxAssertionLifetime.
	AssertionLifetime time.Duration
	// Encryption selects targets and exact ciphers. A nil Recipient selects
	// the first supported RSA key from trusted SP encryption metadata. An
	// explicit Recipient must occur in that metadata. Nil disables encryption
	// and rejects requests that require EncryptedID. A configured policy adds
	// EncryptNameID when the request uses NameIDEncrypted.
	Encryption *protocol.EncryptionOptions
}

// IdentityProvider issues solicited SAML responses for identities authenticated by the
// application.
type IdentityProvider struct{ c Config }

// NewIdentityProvider validates and snapshots IdentityProvider policy and required trusted adapters.
func NewIdentityProvider(c Config) (*IdentityProvider, error) {
	const (
		defaultAssertionLifetime = 5 * time.Minute
	)

	if !profile.URI(c.EntityID) || nilcheck.IsNil(c.Metadata) || nilcheck.IsNil(c.Signing.Key) || c.Signing.Secret != nil || nilcheck.IsNil(c.Replay) || protocol.ValidatePolicy(c.Limits) != nil {
		return nil, ErrPolicy
	}

	if e := signature.Key(c.Signing.Key.Public()); e != nil {
		return nil, e
	}

	if c.AssertionLifetime == 0 {
		c.AssertionLifetime = defaultAssertionLifetime
	}

	_, maximum, _, e := protocol.AcceptanceWindow(c.Limits)
	if e != nil || c.AssertionLifetime < time.Second || c.AssertionLifetime > maximum {
		return nil, ErrPolicy
	}

	c.Signing.CertificateDER = bytes.Clone(c.Signing.CertificateDER)
	c.Signing.InclusivePrefixes = append([]string(nil), c.Signing.InclusivePrefixes...)
	c.Signing.Policy = xmlsig.ClonePolicy(c.Signing.Policy)
	c.VerificationPolicy = xmlsig.ClonePolicy(c.VerificationPolicy)

	c.Encryption, e = protocol.CloneEncryption(c.Encryption)
	if e != nil {
		return nil, ErrPolicy
	}

	return &IdentityProvider{c: c}, nil
}

// AcceptPOST requires a known SP entity and the metadata-selected endpoint at
// which the application actually received the message. XML Issuer/ACS are not
// treated as trusted configuration before signature verification.
func (i *IdentityProvider) AcceptPOST(ctx context.Context, form []byte, sp, destination string, at time.Time) (*Request, error) {
	opt, role, e := i.requestPolicy(ctx, sp, destination, metadata.HTTPPost, at)
	if e != nil {
		return nil, e
	}

	message, e := binding.DecodePOST(ctx, form, binding.Request, i.c.POSTLimits)
	if e != nil {
		return nil, e
	}

	r, e := protocol.VerifyAuthnRequest(ctx, message.UnverifiedDocument(), role.SigningKeys(), opt)
	if e != nil {
		return nil, e
	}

	if r.ResponseBinding() == metadata.PAOS {
		return nil, ErrPolicy
	}

	relay, present := message.RelayState()

	return i.wrap(r, relay, present, at)
}

// AcceptRedirect authenticates a request using trusted SP metadata and validates the
// selected IdP endpoint.
func (i *IdentityProvider) AcceptRedirect(ctx context.Context, rawQuery, sp, destination string, at time.Time) (*Request, error) {
	opt, role, e := i.requestPolicy(ctx, sp, destination, metadata.HTTPRedirect, at)
	if e != nil {
		return nil, e
	}

	r, e := protocol.VerifyRedirectRequest(ctx, rawQuery, role.SigningKeys(), opt, i.c.RedirectLimits)
	if e != nil {
		return nil, e
	}

	if r.ResponseBinding() == metadata.PAOS {
		return nil, ErrPolicy
	}

	relay, present := r.RelayState()

	return i.wrap(r, relay, present, at)
}

// Issue signs and self-verifies a response, then atomically consumes the
// AuthnRequest before releasing it. A Request from another IdP instance cannot
// be substituted, even if it was validated under a weaker/different trust policy.
func (i *IdentityProvider) Issue(ctx context.Context, request *Request, a Authentication, at time.Time) (*Issued, error) {
	if !i.acceptsIssueRequest(ctx, request, at) || request.channelErr != nil {
		return nil, ErrPolicy
	}

	if !request.associatedKey(a.HolderOfKeyCertificate) {
		return nil, ErrPolicy
	}

	if e := ctx.Err(); e != nil {
		return nil, e
	}

	r := request.verified

	own, other, e := i.roles(ctx, r.Issuer(), at)
	if e != nil {
		return nil, e
	}

	if !keyAllowed(i.c.Signing.Key.Public(), own) {
		return nil, ErrPolicy
	}

	if len(own.Endpoints(metadata.SingleLogoutService)) > 0 && a.SessionIndex == "" {
		return nil, ErrPolicy
	}

	found := false

	for _, ep := range other.Endpoints(metadata.AssertionConsumerService) {
		if ep.AcceptsTransport(r.ResponseBinding(), request.proof != nil) && ep.Location == r.ACS() {
			found = true
		}
	}

	if !found {
		return nil, ErrPolicy
	}

	_, _, skew, e := protocol.AcceptanceWindow(i.c.Limits)
	if e != nil {
		return nil, e
	}

	if !authenticationAllowed(a, at, skew, r) {
		return nil, ErrPolicy
	}

	if len(r.RequestedContexts()) > 0 && !contains(r.RequestedContexts(), a.AuthnContext) {
		return nil, ErrPolicy
	}

	if a.NameIDFormat == "" {
		a.NameIDFormat = protocol.NameIDUnspecified
	}

	if !nameIDPolicyAllows(r.NameIDFormat(), a.NameIDFormat) || len(own.NameIDFormats()) > 0 && !contains(own.NameIDFormats(), a.NameIDFormat) || len(other.NameIDFormats()) > 0 && !contains(other.NameIDFormats(), a.NameIDFormat) {
		return nil, ErrPolicy
	}

	assertionID, e := profile.NewID()
	if e != nil {
		return nil, e
	}

	responseID, e := profile.NewID()
	if e != nil {
		return nil, e
	}

	end := i.assertionExpiry(own, other, at)

	spec := protocol.Response{Limits: i.c.Limits, ID: responseID, Issuer: i.c.EntityID, Audience: r.Issuer(), Destination: r.ACS(), InResponseTo: r.ID(), IssueInstant: at, Assertion: protocol.AssertionData{ID: assertionID, NameID: a.NameID, NameIDFormat: a.NameIDFormat, NotBefore: at, NotOnOrAfter: end, AuthnInstant: a.AuthnInstant, AuthnContext: a.AuthnContext, SessionIndex: a.SessionIndex, SessionNotOnOrAfter: a.SessionNotOnOrAfter, Attributes: a.Attributes}}
	spec.SOAPContext = r.ResponseBinding() == metadata.PAOS || r.ResponseBinding() == metadata.HTTPArtifact
	spec.Assertion.NameQualifier = a.NameQualifier
	spec.Assertion.SPNameQualifier = a.SPNameQualifier
	spec.Assertion.SPProvidedID = a.SPProvidedID
	spec.Assertion.ChannelBindings = protocol.CloneChannelBindings(request.channels)
	spec.Assertion.HolderOfKeyCertificate = bytes.Clone(a.HolderOfKeyCertificate)

	spec.Encryption, e = i.encryptionFor(other, r.NameIDFormat() == protocol.NameIDEncrypted)
	if e != nil {
		return nil, e
	}

	d, e := protocol.SignResponse(ctx, spec, i.c.Signing)
	if e != nil {
		return nil, e
	}

	issued, e := i.finishIssue(ctx, request, d, end, at)
	if e != nil {
		return nil, e
	}

	issued.hokCertificate = bytes.Clone(a.HolderOfKeyCertificate)

	return issued, nil
}

func (i *IdentityProvider) finishIssue(ctx context.Context, request *Request, d *document.Document, end, at time.Time) (*Issued, error) {
	const (
		scopeIDPRequestPrefix = "saml:idp:request:"
		scopeSeparator        = "\u0000"
	)

	r := request.verified

	var relay *string
	if request.relayPresent {
		s := request.relay
		relay = &s
	}

	_, e := binding.WritePOST(ctx, io.Discard, d, binding.Response, relay, i.c.POSTLimits)
	if e != nil {
		return nil, e
	}

	sum := sha256.Sum256([]byte(i.c.EntityID + scopeSeparator + r.Issuer()))

	expires := request.expires

	_, _, skew, e := protocol.AcceptanceWindow(i.c.Limits)
	if e != nil {
		return nil, e
	}

	if end.Add(skew).After(expires) {
		expires = end.Add(skew)
	}

	if e = i.c.Replay.Consume(ctx, []replay.Entry{{Scope: scopeIDPRequestPrefix + hex.EncodeToString(sum[:]), ID: r.ID(), ExpiresAt: expires}}, at); e != nil {
		return nil, e
	}

	return &Issued{doc: d, destination: r.ACS(), relay: request.relay, relayPresent: request.relayPresent, limits: i.c.POSTLimits, responseBinding: r.ResponseBinding(), issuer: i.c.EntityID, recipient: r.Issuer(), channels: protocol.CloneChannelBindings(request.channels)}, nil
}

// Reject returns an authenticated SAML authentication-error response and consumes
// the request exactly once. Use a Requester/Responder status and a relevant SAML
// subcode (for example AuthnFailed or InvalidNameIDPolicy). It supports the same
// POST, Artifact and ECP delivery as a successful Issue operation.
func (i *IdentityProvider) Reject(ctx context.Context, request *Request, status protocol.Status, at time.Time) (*Issued, error) {
	if !i.acceptsIssueRequest(ctx, request, at) || status.Code != protocol.Requester && status.Code != protocol.Responder {
		return nil, ErrPolicy
	}

	r := request.verified

	own, _, err := i.roles(ctx, r.Issuer(), at)
	if err != nil {
		return nil, err
	}

	if !keyAllowed(i.c.Signing.Key.Public(), own) {
		return nil, ErrPolicy
	}

	d, err := protocol.SignStatusResponse(ctx, protocol.StatusResponse{Issuer: i.c.EntityID, Destination: r.ACS(), IssueInstant: at, Kind: lexicon.SAMLElementResponse, InResponseTo: r.ID(), Status: status, SOAPContext: r.ResponseBinding() == metadata.PAOS || r.ResponseBinding() == metadata.HTTPArtifact}, i.c.Signing)
	if err != nil {
		return nil, err
	}

	return i.finishIssue(ctx, request, d, at, at)
}

func (i *IdentityProvider) roles(ctx context.Context, sp string, at time.Time) (*metadata.Role, *metadata.Role, error) {
	own, e := i.c.Metadata.Lookup(ctx, i.c.EntityID, at)
	if e != nil {
		return nil, nil, e
	}

	idprole, e := own.Role(metadata.IdentityProvider, at)
	if e != nil {
		return nil, nil, e
	}

	other, e := i.c.Metadata.Lookup(ctx, sp, at)
	if e != nil {
		return nil, nil, e
	}

	sprole, e := other.Role(metadata.ServiceProvider, at)

	return idprole, sprole, e
}

func (i *IdentityProvider) requestPolicy(ctx context.Context, sp, destination, bindingURI string, at time.Time) (protocol.RequestOptions, *metadata.Role, error) {
	return i.requestPolicyWithProof(ctx, sp, destination, bindingURI, at, false)
}

func (i *IdentityProvider) requestPolicyWithProof(ctx context.Context, sp, destination, bindingURI string, at time.Time, holder bool) (protocol.RequestOptions, *metadata.Role, error) {
	if i == nil || ctx == nil || at.IsZero() || !profile.URI(sp) {
		return protocol.RequestOptions{}, nil, ErrPolicy
	}

	own, other, e := i.roles(ctx, sp, at)
	if e != nil {
		return protocol.RequestOptions{}, nil, e
	}

	found := false

	for _, ep := range own.Endpoints(metadata.SingleSignOnService) {
		if ep.AcceptsTransport(bindingURI, holder) && ep.Location == destination {
			found = true
		}
	}

	if !found {
		return protocol.RequestOptions{}, nil, ErrPolicy
	}

	opt := protocol.RequestOptions{Issuer: sp, Destination: destination, ACS: other.Endpoints(metadata.AssertionConsumerService), At: at, Limits: i.c.Limits, Policy: i.c.VerificationPolicy}

	opt.TransportBinding = bindingURI

	opt.AllowHolderOfKeyACS = holder
	if bindingURI == metadata.SOAP {
		opt.ResponseBinding = metadata.PAOS
	}

	return opt, other, nil
}

// AcceptSOAP authenticates an ECP AuthnRequest at a trusted SOAP SSO endpoint.
// The ECP must already have removed its PAOS and ECP routing headers.
// If channel comparison fails after request authentication, both Request and
// error are returned. Only Reject may use that Request to generate a signed
// SAML error; Issue rejects it. Unauthenticated failures return no Request.
func (i *IdentityProvider) AcceptSOAP(ctx context.Context, raw []byte, sp, destination string, at time.Time) (*Request, error) {
	const (
		xmlNameChannelBindings = "ChannelBindings"
	)

	opt, role, err := i.requestPolicy(ctx, sp, destination, metadata.SOAP, at)
	if err != nil {
		return nil, err
	}

	m, err := binding.DecodeSOAP(ctx, raw, binding.SOAPOptions{Understood: []document.Name{{Space: protocol.ChannelBindingNamespace, Local: xmlNameChannelBindings}}})
	if err != nil {
		return nil, err
	}
	// Own-channel headers require the complete SOAP integrity proof accepted by
	// AcceptECP, not just the SP's signature over the inner SAML request.
	own, err := ecp.ReadIDPChannelHeaders(m.Headers())
	if err != nil || len(own) != 0 {
		return nil, ErrPolicy
	}

	d, err := m.Payload(ctx)
	if err != nil {
		return nil, err
	}

	return i.acceptSOAPMessage(ctx, m, d, opt, role, at)
}

func (i *IdentityProvider) acceptSOAPMessage(ctx context.Context, m *binding.SOAPMessage, d *document.Document, opt protocol.RequestOptions, role *metadata.Role, at time.Time) (*Request, error) {
	r, err := protocol.VerifyAuthnRequest(ctx, d, role.SigningKeys(), opt)
	if err != nil {
		return nil, err
	}

	request, err := i.wrap(r, "", false, at)
	if err != nil {
		return nil, err
	}

	channels, err := ecp.ReadChannelHeaders(m.Headers(), false)
	if err == nil {
		request.channels, err = ecp.MatchChannelBindings(r.ChannelBindings(), channels)
	}

	if err != nil {
		request.channelErr = err
		return request, err
	}

	return request, nil
}

// AcceptECP accepts HoK proof for this SOAP AuthnRequest, independently verifies
// the SP's SAML signature, and compares channel bindings. localChannels must be
// derived from the actual client/IdP TLS connection. Any supplied own-channel
// binding must match, even if the SP did not request channel bindings.
func (i *IdentityProvider) AcceptECP(ctx context.Context, p *proof.Verified, sp, destination string, at time.Time, localChannels []protocol.ChannelBinding) (*Request, error) {
	if p == nil || p.Message() == nil {
		return nil, ErrPolicy
	}

	opt, role, err := i.requestPolicyWithProof(ctx, sp, destination, metadata.SOAP, at, true)
	if err != nil {
		return nil, err
	}

	d, err := p.Payload(ctx)
	if err != nil {
		return nil, err
	}

	r, err := i.acceptSOAPMessage(ctx, p.Message(), d, opt, role, at)
	if err != nil {
		return r, err
	}

	r.proof = p

	own, err := ecp.ReadIDPChannelHeaders(p.Message().Headers())
	if err == nil && len(own) != 0 {
		if !p.XML() {
			err = ErrPolicy
		} else {
			for _, channel := range own {
				if _, err = ecp.MatchChannelBindings(localChannels, []protocol.ChannelBinding{channel}); err != nil {
					break
				}
			}
		}
	}

	if err != nil {
		r.channelErr = err
		return r, err
	}

	return r, nil
}

// AcceptArtifact validates a resolved AuthnRequest under the HTTP Artifact SSO
// endpoint's current metadata. The message itself must carry its XML signature;
// resolution alone never substitutes for its authentication or replay checks.
func (i *IdentityProvider) AcceptArtifact(ctx context.Context, message *document.Document, relay *string, sp, destination string, at time.Time) (*Request, error) {
	opt, role, err := i.requestPolicy(ctx, sp, destination, metadata.HTTPArtifact, at)
	if err != nil {
		return nil, err
	}

	r, err := protocol.VerifyAuthnRequest(ctx, message, role.SigningKeys(), opt)
	if err != nil {
		return nil, err
	}

	if relay == nil {
		return i.wrap(r, "", false, at)
	}

	if len(*relay) > profile.HTTPRelayStateMaxBytes {
		return nil, ErrPolicy
	}

	return i.wrap(r, *relay, true, at)
}

func (i *IdentityProvider) wrap(r *protocol.VerifiedRequest, relay string, present bool, at time.Time) (*Request, error) {
	age, _, skew, e := protocol.AcceptanceWindow(i.c.Limits)
	if e != nil {
		return nil, e
	}

	expires := r.IssueInstant().Add(age + skew)
	if !at.Before(expires) {
		return nil, ErrPolicy
	}

	return &Request{owner: i, verified: r, relay: relay, relayPresent: present, expires: expires}, nil
}

func (i *IdentityProvider) acceptsIssueRequest(ctx context.Context, request *Request, at time.Time) bool {
	return !(i == nil || ctx == nil || request == nil || request.owner != i || request.verified == nil || at.IsZero() || !at.Before(request.expires))
}

// Request retains an authenticated request bound to the IdentityProvider that accepted
// it.
type Request struct {
	owner        *IdentityProvider
	verified     *protocol.VerifiedRequest
	relay        string
	relayPresent bool
	expires      time.Time
	channels     []protocol.ChannelBinding
	channelErr   error
	proof        *proof.Verified
}

// HolderOfKeyCertificate returns the proven certificate. Before Issue the
// application must independently establish its association with the principal.
func (r *Request) HolderOfKeyCertificate() []byte {
	if r == nil {
		return nil
	}

	return r.proof.Certificate()
}

func (r *Request) associatedKey(certificate []byte) bool {
	if r.proof == nil {
		return len(certificate) == 0
	}

	return len(certificate) != 0 && bytes.Equal(certificate, r.proof.Certificate())
}

// ID returns the accepted AuthnRequest identifier.
func (r *Request) ID() string {
	if r == nil {
		return ""
	}

	return r.verified.ID()
}

// SP returns the authenticated SP entity identifier.
func (r *Request) SP() string {
	if r == nil {
		return ""
	}

	return r.verified.Issuer()
}

// ACS returns the validated assertion consumer service endpoint.
func (r *Request) ACS() string {
	if r == nil {
		return ""
	}

	return r.verified.ACS()
}

// RequestedNameIDFormat returns the requested NameID format URI.
func (r *Request) RequestedNameIDFormat() string {
	if r == nil {
		return ""
	}

	return r.verified.NameIDFormat()
}

// RequestedContexts returns an owned copy of the requested authentication context URIs.
func (r *Request) RequestedContexts() []string {
	if r == nil {
		return nil
	}

	return r.verified.RequestedContexts()
}

// ForceAuthn returns whether fresh authentication is required.
func (r *Request) ForceAuthn() bool { return r != nil && r.verified.ForceAuthn() }

// IsPassive returns whether user interaction is forbidden.
func (r *Request) IsPassive() bool { return r != nil && r.verified.IsPassive() }

// AllowCreateNameID returns whether creating a NameID is permitted.
func (r *Request) AllowCreateNameID() bool { return r != nil && r.verified.AllowCreateNameID() }

// ExpiresAt returns the exclusive expiration boundary.
func (r *Request) ExpiresAt() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.expires
}

// Authentication supplies the identity and authentication conditions established by
// the application for response issuance.
type Authentication struct {
	// HolderOfKeyCertificate is the certificate the application has independently
	// associated with this principal. For HoK it must match the request's proof.
	HolderOfKeyCertificate []byte
	// NameID is the subject identifier established by the application.
	NameID string
	// NameIDFormat identifies the subject identifier format to issue.
	NameIDFormat string
	// NameQualifier, SPNameQualifier and SPProvidedID retain the application's
	// current managed identifier, including the SP's alias.
	NameQualifier, SPNameQualifier, SPProvidedID string
	// AuthnInstant is the time at which the application authenticated the subject.
	AuthnInstant time.Time
	// AuthnContext identifies the authentication context established by the application.
	AuthnContext string
	// SessionIndex identifies the authority session. It is required when local
	// metadata advertises SingleLogoutService (Profiles 4.1.4.2 / Errata E38).
	SessionIndex string
	// SessionNotOnOrAfter is an optional session expiration time. Zero omits it.
	SessionNotOnOrAfter time.Time
	// Attributes contains the subject attributes authorized for release to the service
	// provider.
	Attributes []protocol.Attribute
	// FreshAuthentication reports fresh application authentication and is required
	// for a ForceAuthn request. The library does not infer this fact.
	FreshAuthentication bool
	// InteractionUsed reports application interaction. A passive request rejects this value
	// when true.
	InteractionUsed bool
	// CreatedNameID reports creation of a new identifier. The request must permit it.
	CreatedNameID bool
}

// Issued retains an immutable signed response and the policy needed to serialize its
// POST binding.
type Issued struct {
	doc                                *document.Document
	limits                             binding.POSTLimits
	relay                              string
	relayPresent                       bool
	destination                        string
	responseBinding, issuer, recipient string
	channels                           []protocol.ChannelBinding
	hokCertificate                     []byte
}

// Document returns the immutable document snapshot.
func (r *Issued) Document() *document.Document {
	if r == nil {
		return nil
	}

	return r.doc
}

// ECP wraps the signed response with the mandatory ECP response header. This
// response was signed in SOAP context when the request selected PAOS.
func (r *Issued) ECP(ctx context.Context) (*document.Document, error) {
	if r == nil || r.responseBinding != metadata.PAOS {
		return nil, ErrPolicy
	}

	if len(r.hokCertificate) != 0 {
		return ecp.ResponseHoK(ctx, r.doc, r.destination, r.hokCertificate, r.channels)
	}

	return ecp.ResponseWithBindings(ctx, r.doc, r.destination, r.channels)
}

// IssueArtifact creates the requested one-time response artifact. The issuer's
// identity must match the IdP; the artifact is bound to the requesting SP.
func (r *Issued) IssueArtifact(ctx context.Context, issuer artifact.Issuer, at time.Time, lifetime time.Duration) (binding.Artifact, error) {
	if r == nil || r.responseBinding != metadata.HTTPArtifact || issuer.EntityID != r.issuer {
		return binding.Artifact{}, ErrPolicy
	}

	return issuer.Issue(ctx, r.doc, r.recipient, at, lifetime)
}

// WritePOST writes the signed response directly to dst without retaining a
// complete encoded form. It leaves dst open. Errors may leave partial output
// which the caller must discard; the authenticated request is already consumed.
func (r *Issued) WritePOST(ctx context.Context, dst io.Writer) (int64, error) {
	if r == nil || r.responseBinding != "" && r.responseBinding != metadata.HTTPPost {
		return 0, ErrPolicy
	}

	return binding.WritePOST(ctx, dst, r.doc, binding.Response, r.relayState(), r.limits)
}

// WritePOSTForm writes a complete HTML form to the metadata-selected endpoint.
// It leaves dst open and may leave partial output on failure.
func (r *Issued) WritePOSTForm(ctx context.Context, dst io.Writer) (int64, error) {
	if r == nil || r.responseBinding != "" && r.responseBinding != metadata.HTTPPost {
		return 0, ErrPolicy
	}

	return binding.WritePOSTForm(ctx, dst, r.destination, r.doc, binding.Response, r.relayState(), r.limits)
}

// Destination returns the validated destination endpoint.
func (r *Issued) Destination() string {
	if r == nil {
		return ""
	}

	return r.destination
}

func (r *Issued) relayState() *string {
	if !r.relayPresent {
		return nil
	}

	return &r.relay
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

func authenticationAllowed(a Authentication, at time.Time, skew time.Duration, r *protocol.VerifiedRequest) bool {
	return !(a.AuthnInstant.IsZero() || a.AuthnInstant.After(at.Add(skew)) || !profile.URI(a.AuthnContext) || r.ForceAuthn() && (!a.FreshAuthentication || a.AuthnInstant.Before(r.IssueInstant().Add(-skew))) || r.IsPassive() && a.InteractionUsed || !r.AllowCreateNameID() && a.CreatedNameID)
}

func (i *IdentityProvider) encryptionFor(role *metadata.Role, requireNameID bool) (*protocol.EncryptionOptions, error) {
	if i.c.Encryption == nil {
		if requireNameID {
			return nil, ErrPolicy
		}

		return nil, nil
	}

	policy := *i.c.Encryption
	if requireNameID {
		policy.Targets |= protocol.EncryptNameID
	}

	var selected *rsa.PublicKey

	for _, key := range role.EncryptionKeys() {
		candidate, ok := key.(*rsa.PublicKey)
		if !ok || signature.Key(candidate) != nil {
			continue
		}

		if policy.Recipient != nil && (candidate.E != policy.Recipient.E || candidate.N.Cmp(policy.Recipient.N) != 0) {
			continue
		}

		selected = candidate

		break
	}

	if selected == nil {
		return nil, ErrPolicy
	}

	policy.Recipient = selected

	return &policy, nil
}

func nameIDPolicyAllows(requested, actual string) bool {
	return actual != protocol.NameIDEncrypted && (requested == "" || requested == protocol.NameIDUnspecified || requested == protocol.NameIDEncrypted || requested == actual)
}

func (i *IdentityProvider) assertionExpiry(own, other *metadata.Role, at time.Time) time.Time {
	end := at.Add(i.c.AssertionLifetime)
	if own.ExpiresAt().Before(end) {
		end = own.ExpiresAt()
	}

	if other.ExpiresAt().Before(end) {
		end = other.ExpiresAt()
	}

	return end
}
