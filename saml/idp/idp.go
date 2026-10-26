package idp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/metadata"
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
}

// IdentityProvider issues solicited SAML responses for identities authenticated by the
// application.
type IdentityProvider struct{ c Config }

// NewIdentityProvider validates and snapshots IdentityProvider policy and required trusted adapters.
func NewIdentityProvider(c Config) (*IdentityProvider, error) {
	if !profile.URI(c.EntityID) || nilcheck.IsNil(c.Metadata) || nilcheck.IsNil(c.Signing.Key) || nilcheck.IsNil(c.Replay) || protocol.ValidatePolicy(c.Limits) != nil {
		return nil, ErrPolicy
	}

	if e := signature.Key(c.Signing.Key.Public()); e != nil {
		return nil, e
	}

	if c.AssertionLifetime == 0 {
		c.AssertionLifetime = 5 * time.Minute
	}

	_, maximum, _, e := protocol.AcceptanceWindow(c.Limits)
	if e != nil || c.AssertionLifetime < time.Second || c.AssertionLifetime > maximum {
		return nil, ErrPolicy
	}

	c.Signing.CertificateDER = bytes.Clone(c.Signing.CertificateDER)
	c.Signing.Policy = xmlsig.ClonePolicy(c.Signing.Policy)
	c.VerificationPolicy = xmlsig.ClonePolicy(c.VerificationPolicy)

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

	relay, present := r.RelayState()

	return i.wrap(r, relay, present, at)
}

// Issue signs and self-verifies a response, then atomically consumes the
// AuthnRequest before releasing it. A Request from another IdP instance cannot
// be substituted, even if it was validated under a weaker/different trust policy.
func (i *IdentityProvider) Issue(ctx context.Context, request *Request, a Authentication, at time.Time) (*Issued, error) {
	if !i.acceptsIssueRequest(ctx, request, at) {
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

	found := false

	for _, ep := range other.Endpoints(metadata.AssertionConsumerService) {
		if ep.Binding == metadata.HTTPPost && ep.Location == r.ACS() {
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

	if r.NameIDFormat() != "" && r.NameIDFormat() != protocol.NameIDUnspecified && a.NameIDFormat != r.NameIDFormat() || len(own.NameIDFormats()) > 0 && !contains(own.NameIDFormats(), a.NameIDFormat) || len(other.NameIDFormats()) > 0 && !contains(other.NameIDFormats(), a.NameIDFormat) {
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

	end := at.Add(i.c.AssertionLifetime)
	if own.ExpiresAt().Before(end) {
		end = own.ExpiresAt()
	}

	if other.ExpiresAt().Before(end) {
		end = other.ExpiresAt()
	}

	spec := protocol.Response{Limits: i.c.Limits, ID: responseID, Issuer: i.c.EntityID, Audience: r.Issuer(), Destination: r.ACS(), InResponseTo: r.ID(), IssueInstant: at, Assertion: protocol.AssertionData{ID: assertionID, NameID: a.NameID, NameIDFormat: a.NameIDFormat, NotBefore: at, NotOnOrAfter: end, AuthnInstant: a.AuthnInstant, AuthnContext: a.AuthnContext, SessionIndex: a.SessionIndex, SessionNotOnOrAfter: a.SessionNotOnOrAfter, Attributes: a.Attributes}}

	d, e := protocol.SignResponse(ctx, spec, i.c.Signing)
	if e != nil {
		return nil, e
	}

	var relay *string
	if request.relayPresent {
		s := request.relay
		relay = &s
	}

	_, e = binding.WritePOST(ctx, io.Discard, d, binding.Response, relay, i.c.POSTLimits)
	if e != nil {
		return nil, e
	}

	sum := sha256.Sum256([]byte(i.c.EntityID + "\x00" + r.Issuer()))

	expires := request.expires
	if end.Add(skew).After(expires) {
		expires = end.Add(skew)
	}

	if e = i.c.Replay.Consume(ctx, []replay.Entry{{Scope: "saml:idp:request:" + hex.EncodeToString(sum[:]), ID: r.ID(), ExpiresAt: expires}}, at); e != nil {
		return nil, e
	}

	return &Issued{doc: d, destination: r.ACS(), relay: request.relay, relayPresent: request.relayPresent, limits: i.c.POSTLimits}, nil
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
	if i == nil || ctx == nil || at.IsZero() || !profile.URI(sp) {
		return protocol.RequestOptions{}, nil, ErrPolicy
	}

	own, other, e := i.roles(ctx, sp, at)
	if e != nil {
		return protocol.RequestOptions{}, nil, e
	}

	found := false

	for _, ep := range own.Endpoints(metadata.SingleSignOnService) {
		if ep.Binding == bindingURI && ep.Location == destination {
			found = true
		}
	}

	if !found {
		return protocol.RequestOptions{}, nil, ErrPolicy
	}

	return protocol.RequestOptions{Issuer: sp, Destination: destination, ACS: other.Endpoints(metadata.AssertionConsumerService), At: at, Limits: i.c.Limits, Policy: i.c.VerificationPolicy}, other, nil
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

// Request retains an authenticated request bound to the IdentityProvider that accepted
// it.
type Request struct {
	owner        *IdentityProvider
	verified     *protocol.VerifiedRequest
	relay        string
	relayPresent bool
	expires      time.Time
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
	// NameID is the subject identifier established by the application.
	NameID string
	// NameIDFormat identifies the subject identifier format to issue.
	NameIDFormat string
	// AuthnInstant is the time at which the application authenticated the subject.
	AuthnInstant time.Time
	// AuthnContext identifies the authentication context established by the application.
	AuthnContext string
	// SessionIndex is an optional identifier for the authenticated session.
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
	doc          *document.Document
	limits       binding.POSTLimits
	relay        string
	relayPresent bool
	destination  string
}

// Document returns the immutable document snapshot.
func (r *Issued) Document() *document.Document {
	if r == nil {
		return nil
	}

	return r.doc
}

// WritePOST writes the signed response directly to dst without retaining a
// complete encoded form. It leaves dst open. Errors may leave partial output
// which the caller must discard; the authenticated request is already consumed.
func (r *Issued) WritePOST(ctx context.Context, dst io.Writer) (int64, error) {
	if r == nil {
		return 0, ErrPolicy
	}

	return binding.WritePOST(ctx, dst, r.doc, binding.Response, r.relayState(), r.limits)
}

// WritePOSTForm writes a complete HTML form to the metadata-selected endpoint.
// It leaves dst open and may leave partial output on failure.
func (r *Issued) WritePOSTForm(ctx context.Context, dst io.Writer) (int64, error) {
	if r == nil {
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
