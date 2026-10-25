package protocol

import (
	"context"
	"crypto"
	"strconv"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/xmldsig"
)

// RequestOptions supplies trusted issuer, destination, endpoint and time expectations
// for request validation.
type RequestOptions struct {
	// Issuer is the expected requesting service provider's entity identifier.
	Issuer string
	// Destination is the trusted identity provider endpoint expected in the request.
	Destination string
	// ACS lists assertion consumer endpoints from trusted SP metadata.
	ACS []metadata.Endpoint
	// At is the explicit trusted time used by this operation.
	At time.Time
	// Limits bounds request age and supported protocol values.
	Limits Limits
	// Policy sets request signature algorithms and key limits.
	Policy xmldsig.Policy
}

// VerifiedRequest retains an immutable AuthnRequest authenticated and accepted under
// RequestOptions.
type VerifiedRequest struct {
	instant     time.Time
	doc         *document.Document
	id          string
	issuer      string
	destination string
	acs         string
	format      string
	qualifier   string
	relay       string
	contexts    []string
	force       bool
	passive     bool
	allowCreate bool
	hasRelay    bool
}

// VerifyAuthnRequest requires an XML signature. There is deliberately no public
// "already verified" boolean with which callers could bypass authentication.
func VerifyAuthnRequest(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o RequestOptions) (*VerifiedRequest, error) {
	return verifyRequest(ctx, d, keys, o, false)
}

// VerifyRedirectRequest authenticates the received Redirect signature before decoding and
// validating the AuthnRequest.
func VerifyRedirectRequest(ctx context.Context, rawQuery string, keys []crypto.PublicKey, o RequestOptions, limits binding.Options) (*VerifiedRequest, error) {
	if len(keys) == 0 || len(keys) > 16 {
		return nil, ErrSignature
	}

	for _, k := range keys {
		limits.Policy = o.Policy

		r, e := binding.VerifyRedirect(ctx, rawQuery, k, limits)
		if e != nil {
			if ctx != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}

			continue
		}

		if r.Kind() != binding.Request {
			return nil, ErrProfile
		}

		verified, e := verifyRequest(ctx, r.Document(), nil, o, true)
		if e != nil {
			return nil, e
		}

		verified.relay, verified.hasRelay = r.RelayState()

		return verified, nil
	}

	return nil, ErrSignature
}

// ID returns the authenticated AuthnRequest identifier.
func (r *VerifiedRequest) ID() string {
	if r == nil {
		return ""
	}

	return r.id
}

// Issuer returns the authenticated issuer identifier.
func (r *VerifiedRequest) Issuer() string {
	if r == nil {
		return ""
	}

	return r.issuer
}

// Destination returns the validated destination endpoint.
func (r *VerifiedRequest) Destination() string {
	if r == nil {
		return ""
	}

	return r.destination
}

// ACS returns the validated assertion consumer service endpoint.
func (r *VerifiedRequest) ACS() string {
	if r == nil {
		return ""
	}

	return r.acs
}

// IssueInstant returns the message issue instant.
func (r *VerifiedRequest) IssueInstant() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.instant
}

// ForceAuthn returns whether fresh authentication is required.
func (r *VerifiedRequest) ForceAuthn() bool { return r != nil && r.force }

// IsPassive returns whether user interaction is forbidden.
func (r *VerifiedRequest) IsPassive() bool { return r != nil && r.passive }

// AllowCreateNameID returns whether creating a NameID is permitted.
func (r *VerifiedRequest) AllowCreateNameID() bool { return r != nil && r.allowCreate }

// NameIDFormat returns the accepted NameID format URI.
func (r *VerifiedRequest) NameIDFormat() string {
	if r == nil {
		return ""
	}

	return r.format
}

// RequestedContexts returns an owned copy of the requested authentication context URIs.
func (r *VerifiedRequest) RequestedContexts() []string {
	if r == nil {
		return nil
	}

	return append([]string(nil), r.contexts...)
}

// RelayState returns the opaque relay state, with a separate presence flag where
// applicable.
func (r *VerifiedRequest) RelayState() (string, bool) {
	if r == nil {
		return "", false
	}

	return r.relay, r.hasRelay
}

func verifyRequest(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o RequestOptions, transportVerified bool) (*VerifiedRequest, error) {
	limits, err := normalize(o.Limits)
	if err != nil {
		return nil, err
	}

	if err := validateRequestInputs(ctx, d, o); err != nil {
		return nil, err
	}

	root := d.Root()

	id, instant, children, err := readAuthnRequestHeader(root, o, limits)
	if err != nil {
		return nil, err
	}

	position, err := authenticateAuthnRequest(ctx, d, root, children, keys, o.Policy, transportVerified)
	if err != nil {
		return nil, err
	}

	acs, err := selectRequestACS(root, o.ACS)
	if err != nil {
		return nil, err
	}

	request := &VerifiedRequest{doc: d, id: id, instant: instant, issuer: o.Issuer, destination: o.Destination, acs: acs, format: NameIDUnspecified}
	if err := readAuthnRequestFlags(root, request); err != nil {
		return nil, err
	}

	if err := readAuthnRequestChildren(children, position, o.Issuer, request); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return request, nil
}

func validateRequestInputs(ctx context.Context, d *document.Document, options RequestOptions) error {
	if ctx == nil || d == nil || options.At.IsZero() || !profile.URI(options.Issuer) || !profile.Endpoint(options.Destination, true) || len(options.ACS) == 0 || len(options.ACS) > 128 {
		return ErrProfile
	}

	return nil
}

func readAuthnRequestHeader(root document.Element, options RequestOptions, limits Limits) (string, time.Time, []document.Element, error) {
	if xmlutil.Attrs(root, []string{"ID", nameVersion, nameIssueInstant, nameDestination}, []string{"AssertionConsumerServiceURL", "AssertionConsumerServiceIndex", "ProtocolBinding", "ForceAuthn", "IsPassive"}) != nil {
		return "", time.Time{}, nil, ErrProfile
	}

	id, instant, err := header(root, "AuthnRequest", options.At, limits)
	if err != nil {
		return "", time.Time{}, nil, err
	}

	if xmlutil.Attr(root, nameDestination) != options.Destination {
		return "", time.Time{}, nil, ErrProfile
	}

	children, err := xmlutil.Children(root)
	if err != nil || len(children) == 0 || issuer(children[0], options.Issuer) != nil {
		return "", time.Time{}, nil, ErrProfile
	}

	return id, instant, children, nil
}

func authenticateAuthnRequest(ctx context.Context, d *document.Document, root document.Element, children []document.Element, keys []crypto.PublicKey, policy xmldsig.Policy, transportVerified bool) (int, error) {
	if transportVerified {
		if signingCount(d, 0) != nil {
			return 0, ErrProfile
		}

		return 1, nil
	}

	if signingCount(d, 1) != nil || len(children) < 2 || children[1].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature) {
		return 0, ErrProfile
	}

	if err := targetSignature(ctx, d, root, keys, policy); err != nil {
		return 0, err
	}

	return 2, nil
}

func selectRequestACS(root document.Element, authorized []metadata.Endpoint) (string, error) {
	acs := xmlutil.Attr(root, "AssertionConsumerServiceURL")
	indexString, hasIndex := root.Attribute(document.Name{Local: "AssertionConsumerServiceIndex"})

	bindingURI := xmlutil.Attr(root, "ProtocolBinding")
	if bindingURI != "" && bindingURI != metadata.HTTPPost {
		return "", ErrProfile
	}

	if hasIndex && (acs != "" || bindingURI != "") {
		return "", ErrProfile
	}

	if acs != "" && bindingURI != metadata.HTTPPost {
		return "", ErrProfile
	}

	var index *uint16

	if hasIndex {
		number, err := strconv.ParseUint(indexString, 10, 16)
		if err != nil {
			return "", ErrProfile
		}

		value := uint16(number)
		index = &value
	}

	var candidates []metadata.Endpoint

	for _, endpoint := range authorized {
		if acs == "" || endpoint.Location == acs {
			candidates = append(candidates, endpoint)
		}
	}

	chosen, err := metadata.SelectACS(candidates, metadata.HTTPPost, index)
	if err != nil {
		return "", ErrProfile
	}

	if !profile.Endpoint(chosen.Location, true) {
		return "", ErrProfile
	}

	return chosen.Location, nil
}

func readAuthnRequestFlags(root document.Element, request *VerifiedRequest) error {
	var err error

	request.force, err = profile.Bool(xmlutil.Attr(root, "ForceAuthn"))
	if err != nil {
		return err
	}

	request.passive, err = profile.Bool(xmlutil.Attr(root, "IsPassive"))
	if err != nil || request.force && request.passive {
		return ErrProfile
	}

	return nil
}

func readAuthnRequestChildren(children []document.Element, position int, expectedIssuer string, request *VerifiedRequest) error {
	if position < len(children) && children[position].Name() == xmlutil.Name(ProtocolNamespace, "NameIDPolicy") {
		if err := readRequestNameIDPolicy(children[position], expectedIssuer, request); err != nil {
			return err
		}

		position++
	}

	if position < len(children) && children[position].Name() == xmlutil.Name(ProtocolNamespace, "RequestedAuthnContext") {
		if err := readRequestedAuthnContext(children[position], request); err != nil {
			return err
		}

		position++
	}

	if position != len(children) {
		return ErrProfile
	}

	return nil
}

func readRequestNameIDPolicy(policy document.Element, expectedIssuer string, request *VerifiedRequest) error {
	if xmlutil.Attrs(policy, nil, []string{"Format", nameSPNameQualifier, "AllowCreate"}) != nil || !xmlutil.EmptyContent(policy) {
		return ErrProfile
	}

	if format := xmlutil.Attr(policy, "Format"); format != "" {
		if !profile.URI(format) {
			return ErrProfile
		}

		request.format = format
	}

	request.qualifier = xmlutil.Attr(policy, nameSPNameQualifier)
	if request.qualifier != "" && request.qualifier != expectedIssuer {
		return ErrProfile
	}

	var err error

	request.allowCreate, err = profile.Bool(xmlutil.Attr(policy, "AllowCreate"))

	return err
}

func readRequestedAuthnContext(element document.Element, request *VerifiedRequest) error {
	if xmlutil.Attrs(element, nil, []string{"Comparison"}) != nil || xmlutil.Attr(element, "Comparison") != "" && xmlutil.Attr(element, "Comparison") != "exact" {
		return ErrProfile
	}

	contexts, err := xmlutil.Children(element)
	if err != nil || len(contexts) == 0 || len(contexts) > 8 {
		return ErrProfile
	}

	return appendRequestContexts(contexts, request)
}

func appendRequestContexts(contexts []document.Element, request *VerifiedRequest) error {
	for _, element := range contexts {
		if element.Name() != xmlutil.Name(AssertionNamespace, "AuthnContextClassRef") {
			return ErrProfile
		}

		value, err := xmlutil.Simple(element, 2048)
		if err != nil || !profile.URI(value) {
			return ErrProfile
		}

		request.contexts = append(request.contexts, value)
	}

	return nil
}

// AuthnRequest supplies identifiers, endpoints and authentication conditions for a
// solicited request.
type AuthnRequest struct {
	// ID is the required request XML ID.
	ID string
	// Issuer is the requesting service provider's entity identifier URI.
	Issuer string
	// Destination is the trusted identity provider endpoint URL.
	Destination string
	// ACS is the requested assertion consumer endpoint URL.
	ACS string
	// NameIDFormat optionally requests an exact subject identifier format URI.
	NameIDFormat string
	// IssueInstant is the required request issuance time.
	IssueInstant time.Time
	// ForceAuthn requests fresh authentication.
	ForceAuthn bool
	// IsPassive forbids interaction with the subject when true.
	IsPassive bool
	// AllowCreateNameID permits creation of a new subject identifier when true.
	AllowCreateNameID bool
	// RequestedContexts lists authentication context class URIs for exact comparison.
	RequestedContexts []string
}

// BuildAuthnRequest builds an unsigned AuthnRequest in the supported solicited profile.
func BuildAuthnRequest(ctx context.Context, s AuthnRequest) (*document.Document, error) {
	if ctx == nil || s.IssueInstant.IsZero() || !profile.URI(s.Issuer) || !profile.Endpoint(s.Destination, true) || !profile.Endpoint(s.ACS, true) || s.ForceAuthn && s.IsPassive {
		return nil, ErrProfile
	}

	if s.ID == "" {
		var e error

		s.ID, e = profile.NewID()
		if e != nil {
			return nil, e
		}
	}

	if !profile.ID(s.ID) {
		return nil, ErrProfile
	}

	n := xmlutil.Node("samlp", ProtocolNamespace, "AuthnRequest")

	n.NS = []tree.Namespace{{Prefix: "samlp", URI: ProtocolNamespace}, {Prefix: "saml", URI: AssertionNamespace}, {Prefix: "ds", URI: xmlutil.DS}}
	for _, a := range [][2]string{{"ID", s.ID}, {nameVersion, version20}, {nameIssueInstant, profile.Time(s.IssueInstant)}, {nameDestination, s.Destination}, {"AssertionConsumerServiceURL", s.ACS}, {"ProtocolBinding", metadata.HTTPPost}, {"ForceAuthn", strconv.FormatBool(s.ForceAuthn)}, {"IsPassive", strconv.FormatBool(s.IsPassive)}} {
		xmlutil.Set(n, a[0], a[1])
	}

	iss := xmlutil.Node("saml", AssertionNamespace, "Issuer")
	xmlutil.Text(iss, s.Issuer)
	xmlutil.Add(n, iss)

	if s.NameIDFormat != "" || s.AllowCreateNameID {
		if s.NameIDFormat != "" && !profile.URI(s.NameIDFormat) {
			return nil, ErrProfile
		}

		p := xmlutil.Node("samlp", ProtocolNamespace, "NameIDPolicy")
		if s.NameIDFormat != "" {
			xmlutil.Set(p, "Format", s.NameIDFormat)
		}

		xmlutil.Set(p, "AllowCreate", strconv.FormatBool(s.AllowCreateNameID))
		xmlutil.Add(n, p)
	}

	if len(s.RequestedContexts) > 0 {
		if len(s.RequestedContexts) > 8 {
			return nil, ErrProfile
		}

		p := xmlutil.Node("samlp", ProtocolNamespace, "RequestedAuthnContext")
		xmlutil.Set(p, "Comparison", "exact")

		for _, s := range s.RequestedContexts {
			if !profile.URI(s) {
				return nil, ErrProfile
			}

			c := xmlutil.Node("saml", AssertionNamespace, "AuthnContextClassRef")
			xmlutil.Text(c, s)
			xmlutil.Add(p, c)
		}

		xmlutil.Add(n, p)
	}

	return xmlutil.Document(ctx, n)
}

// SignAuthnRequest builds and signs an AuthnRequest using the explicitly configured key.
func SignAuthnRequest(ctx context.Context, s AuthnRequest, key SigningKey) (*document.Document, error) {
	d, e := BuildAuthnRequest(ctx, s)
	if e != nil {
		return nil, e
	}

	k, e := signing(key)
	if e != nil {
		return nil, e
	}

	out, e := xmlsig.Sign(ctx, d, d.Root(), k, true)
	if e != nil {
		return nil, e
	}

	_, e = VerifyAuthnRequest(ctx, out, []crypto.PublicKey{key.Key.Public()}, RequestOptions{Issuer: s.Issuer, Destination: s.Destination, At: s.IssueInstant, ACS: []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: s.ACS}}, Policy: key.Policy})
	if e != nil {
		return nil, e
	}

	return out, nil
}
