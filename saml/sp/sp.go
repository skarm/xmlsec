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
	"slices"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/saml/metadata"
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
	// limits.
	RedirectLimits binding.Options
	// RequestLifetime bounds pending requests; zero selects five minutes.
	// Values must be between one second and ten minutes.
	RequestLifetime time.Duration
	// AllowUnsignedResponse permits an unsigned Response envelope; the Assertion still
	// requires authentication.
	AllowUnsignedResponse bool
}

// ServiceProvider initiates solicited SAML login and validates and consumes correlated
// responses.
type ServiceProvider struct{ c Config }

// NewServiceProvider validates and snapshots ServiceProvider policy and required trusted adapters.
func NewServiceProvider(c Config) (*ServiceProvider, error) {
	if !xmlutil.URI(c.EntityID) || nilcheck.IsNil(c.Metadata) || nilcheck.IsNil(c.Requests) || nilcheck.IsNil(c.Replay) || nilcheck.IsNil(c.Signing.Key) || protocol.ValidatePolicy(c.Limits) != nil {
		return nil, ErrPolicy
	}

	if c.RequestLifetime == 0 {
		c.RequestLifetime = 5 * time.Minute
	}

	if c.RequestLifetime < time.Second || c.RequestLifetime > 10*time.Minute {
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
	c.Signing.Policy = xmlsig.ClonePolicy(c.Signing.Policy)
	c.RedirectLimits.Policy = xmlsig.ClonePolicy(c.Signing.Policy)

	return &ServiceProvider{c: c}, nil
}

// Begin creates a signed solicited request and records its browser-bound pending state
// before returning transport data.
func (s *ServiceProvider) Begin(ctx context.Context, o BeginOptions) (*Outbound, error) {
	if s == nil || ctx == nil || o.At.IsZero() || !xmlutil.URI(o.IDP) {
		return nil, ErrPolicy
	}

	if e := ctx.Err(); e != nil {
		return nil, e
	}

	browser, e := state.BrowserDigest(o.BrowserBinding)
	if e != nil {
		return nil, e
	}

	if o.Binding == "" {
		o.Binding = metadata.HTTPRedirect
	}

	if o.Binding != metadata.HTTPRedirect && o.Binding != metadata.HTTPPost {
		return nil, ErrPolicy
	}

	own, other, e := s.roles(ctx, o.IDP, o.At)
	if e != nil {
		return nil, e
	}

	if !keyAllowed(s.c.Signing.Key.Public(), own) {
		return nil, ErrPolicy
	}

	acs, e := own.ACS(metadata.HTTPPost, o.ACSIndex)
	if e != nil {
		return nil, e
	}

	if returned1, matched := beginNameIDFormat(&o, own, other); matched {
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

	for _, k := range []string{"SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature", "SAMLEncoding"} {
		if _, ok := values[k]; ok {
			return nil, ErrPolicy
		}
	}

	requestID, e := xmlutil.NewID()
	if e != nil {
		return nil, e
	}

	relayBytes := make([]byte, 32)
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

	spec := protocol.AuthnRequest{ID: requestID, Issuer: s.c.EntityID, Destination: destination, ACS: acs.Location, IssueInstant: o.At, NameIDFormat: o.NameIDFormat, RequestedContexts: append([]string(nil), o.RequestedContexts...), ForceAuthn: o.ForceAuthn, IsPassive: o.IsPassive, AllowCreateNameID: o.AllowCreateNameID}

	var signed *document.Document
	if o.Binding == metadata.HTTPRedirect {
		signed, e = protocol.BuildAuthnRequest(ctx, spec)
	} else {
		signed, e = protocol.SignAuthnRequest(ctx, spec, s.c.Signing)
	}

	if e != nil {
		return nil, e
	}

	out := &Outbound{destination: destination, binding: o.Binding, requestID: requestID, relay: relay, expires: expires, doc: signed, limits: s.c.POSTLimits}
	if o.Binding == metadata.HTTPRedirect {
		opt := s.c.RedirectLimits
		opt.SignatureMethod = s.c.Signing.SignatureMethod
		out.query, e = binding.SignRedirect(ctx, signed, binding.Request, &relay, s.c.Signing.Key, opt)
	} else {
		_, e = binding.WritePOST(ctx, io.Discard, signed, binding.Request, &relay, s.c.POSTLimits)
	}

	if e != nil {
		return nil, e
	}

	pending := state.Pending{SP: s.c.EntityID, IDP: o.IDP, RequestID: requestID, RelayState: relay, ACS: acs.Location, IssuedAt: o.At, ExpiresAt: expires, BrowserSHA256: browser, NameIDFormat: pendingNameID(o.NameIDFormat), RequestedContexts: append([]string(nil), o.RequestedContexts...), ForceAuthn: o.ForceAuthn}
	if e = s.c.Requests.Put(ctx, pending, o.At); e != nil {
		return nil, e
	}

	return out, nil
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

// A returned URL is only a metadata-selected endpoint plus a signed query. It
// does not include a user-controlled return URL from RelayState.

func pendingNameID(s string) string {
	if s == protocol.NameIDUnspecified {
		return ""
	}

	return s
}

func beginNameIDFormat(o *BeginOptions, own *metadata.Role, other *metadata.Role) (returned1 error, matched bool) {
	if o.NameIDFormat != "" && o.NameIDFormat != protocol.NameIDUnspecified {
		if len(own.NameIDFormats()) > 0 && !contains(own.NameIDFormats(), o.NameIDFormat) || len(other.NameIDFormats()) > 0 && !contains(other.NameIDFormats(), o.NameIDFormat) {
			return ErrPolicy, true
		}
	}

	return
}

func beginEndpoints(other *metadata.Role, o *BeginOptions, destination *string) (returned1Value error, matchedBranch bool) {
	for _, ep := range other.Endpoints(metadata.SingleSignOnService) {
		if ep.Binding == o.Binding {
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

	if e := ctx.Err(); e != nil {
		return nil, e
	}

	browser, e := state.BrowserDigest(o.BrowserBinding)
	if e != nil {
		return nil, e
	}

	message, e := binding.DecodePOST(ctx, form, binding.Response, s.c.POSTLimits)
	if e != nil {
		return nil, e
	}

	relay, ok := message.RelayState()
	if !ok || len(relay) < 16 {
		return nil, ErrCorrelation
	}

	pending, e := s.c.Requests.Get(ctx, s.c.EntityID, relay, o.At)
	if e != nil {
		return nil, e
	}

	if pending.SP != s.c.EntityID || pending.RelayState != relay || !o.At.Before(pending.ExpiresAt) || pending.IssuedAt.After(o.At) || subtle.ConstantTimeCompare(pending.BrowserSHA256[:], browser[:]) != 1 {
		return nil, ErrCorrelation
	}

	own, other, e := s.roles(ctx, pending.IDP, o.At)
	if e != nil {
		return nil, e
	}

	allowedACS := false

	for _, ep := range own.Endpoints(metadata.AssertionConsumerService) {
		if ep.Binding == metadata.HTTPPost && ep.Location == pending.ACS {
			allowedACS = true
		}
	}

	if !allowedACS {
		return nil, ErrPolicy
	}

	opt := protocol.ResponseOptions{Issuer: pending.IDP, Audience: s.c.EntityID, Destination: pending.ACS, ExpectedRequestID: pending.RequestID, At: o.At, RequestIssueInstant: pending.IssuedAt, ForceAuthn: pending.ForceAuthn, ExpectedAuthnContexts: append([]string(nil), pending.RequestedContexts...), ExpectedAddress: o.ClientAddress, Limits: s.c.Limits, Policy: s.c.VerificationPolicy, AllowUnsignedResponse: s.c.AllowUnsignedResponse}
	if pending.NameIDFormat != "" {
		opt.AllowedNameIDFormats = []string{pending.NameIDFormat}
	} else {
		opt.AllowedNameIDFormats = own.NameIDFormats()
	}

	result, e := protocol.VerifyResponse(ctx, message.UnverifiedDocument(), other.SigningKeys(), opt)
	if e != nil {
		return nil, e
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

	entries := []replay.Entry{{Scope: scope("request", s.c.EntityID, pending.IDP), ID: pending.RequestID, ExpiresAt: expires}, {Scope: scope("assertion", s.c.EntityID, pending.IDP), ID: result.AssertionID(), ExpiresAt: expires}, {Scope: scope("response", s.c.EntityID, pending.IDP), ID: result.ResponseID(), ExpiresAt: expires}}
	if e = s.c.Replay.Consume(ctx, entries, o.At); e != nil {
		return nil, e
	}

	return result, nil
}

func scope(kind, sp, idp string) string {
	sum := sha256.Sum256([]byte(sp + "\x00" + idp))
	return "saml:sp:" + kind + ":" + hex.EncodeToString(sum[:])
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

// BeginOptions selects an IdP, binding and authentication conditions and supplies the
// browser correlation secret.
type BeginOptions struct {
	// IDP selects the trusted identity provider by its metadata entity identifier.
	IDP string
	// Binding selects HTTP-Redirect (the default) or HTTP-POST.
	Binding string
	// ACSIndex selects an exact metadata endpoint index. Nil uses the default endpoint;
	// a pointer to zero selects index zero explicitly.
	ACSIndex *uint16
	// BrowserBinding is a server-generated, unpredictable browser or session secret.
	BrowserBinding []byte
	// At is the explicit trusted time used by this operation.
	At time.Time
	// NameIDFormat optionally requests an exact subject identifier format URI.
	NameIDFormat string
	// RequestedContexts lists requested authentication context class URIs for exact
	// comparison.
	RequestedContexts []string
	// ForceAuthn requests fresh authentication.
	ForceAuthn bool
	// IsPassive forbids interaction with the subject when true.
	IsPassive bool
	// AllowCreateNameID permits the IdP to create a new subject identifier when true.
	AllowCreateNameID bool
}

// Outbound retains an immutable signed request and its binding-specific transport
// data.
type Outbound struct {
	destination string
	binding     string
	requestID   string
	relay       string
	query       string
	limits      binding.POSTLimits
	doc         *document.Document
	expires     time.Time
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
// request.
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

// ConsumeOptions supplies trusted verification time, browser correlation secret and an
// optional expected client address.
type ConsumeOptions struct {
	// At is the explicit trusted time used by this operation.
	At time.Time
	// BrowserBinding is an unpredictable, application-protected browser correlation secret.
	BrowserBinding []byte
	// ClientAddress is the expected client address when validating subject confirmation.
	ClientAddress string
}
