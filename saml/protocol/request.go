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

// Local SAML vocabulary tokens shared by protocol producers and parsers. Each call site still verifies the assertion/protocol namespace or resolves the QName prefix.
const (
	xmlNameAssertionConsumerServiceIndex = "AssertionConsumerServiceIndex"
	xmlNameForceAuthn                    = "ForceAuthn"
	xmlNameIsPassive                     = "IsPassive"
)

// Profile bound shared by these producer/parser paths; byte/count/time units follow the name, and default values apply only to zero options.
const (
	maximumRequestedWebContexts = 8
)

const (
	nameACS             = "AssertionConsumerServiceURL"
	nameProtocolBinding = "ProtocolBinding"
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
	// ResponseBinding optionally fixes the expected response binding, notably
	// PAOS for ECP. Empty permits the supported binding requested by the peer.
	ResponseBinding string
	// TransportBinding selects the trusted receiving transport. SOAP and Artifact
	// permit an omitted Destination; any present value is still checked.
	TransportBinding string
	// AllowHolderOfKeyACS permits HoK metadata endpoints for the requested
	// transport. The caller must independently establish ECP proof of possession.
	AllowHolderOfKeyACS bool
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
	instant         time.Time
	doc             *document.Document
	id              string
	issuer          string
	destination     string
	acs             string
	responseBinding string
	format          string
	qualifier       string
	relay           string
	contexts        []string
	force           bool
	passive         bool
	allowCreate     bool
	hasRelay        bool
	channels        []ChannelBinding
}

// VerifyAuthnRequest requires an XML signature. There is deliberately no public
// "already verified" boolean with which callers could bypass authentication.
func VerifyAuthnRequest(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o RequestOptions) (*VerifiedRequest, error) {
	return verifyRequest(ctx, d, keys, o, false)
}

// VerifyRedirectRequest authenticates the received Redirect signature before decoding and
// validating the AuthnRequest.
func VerifyRedirectRequest(ctx context.Context, rawQuery string, keys []crypto.PublicKey, o RequestOptions, limits binding.Options) (*VerifiedRequest, error) {
	if len(keys) == 0 || len(keys) > maximumRedirectVerificationKeys {
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

// ResponseBinding returns the metadata-authorized assertion response binding.
func (r *VerifiedRequest) ResponseBinding() string { return r.responseBinding }

// ChannelBindings returns authenticated SP channel data from Extensions.
func (r *VerifiedRequest) ChannelBindings() []ChannelBinding {
	return CloneChannelBindings(r.channels)
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

// AuthnRequest supplies identifiers, endpoints and authentication conditions for a
// solicited request.
type AuthnRequest struct {
	// IssueInstant is the required request issuance time.
	IssueInstant time.Time
	// ID is the required request XML ID.
	ID string
	// Issuer is the requesting service provider's entity identifier URI.
	Issuer string
	// Destination is the trusted identity provider endpoint URL.
	Destination string
	// ACS is the requested assertion consumer endpoint URL.
	ACS string
	// ResponseBinding selects HTTP-POST (default), HTTP-Artifact or PAOS. The
	// recipient must authorize an ACS for the selected binding in metadata.
	ResponseBinding string
	// NameIDFormat optionally requests an exact subject identifier format URI.
	NameIDFormat string
	// RequestedContexts lists authentication context class URIs for exact comparison.
	RequestedContexts []string
	// ChannelBindings binds a signed ECP request to its client/SP transport.
	ChannelBindings []ChannelBinding
	// ForceAuthn requests fresh authentication.
	ForceAuthn bool
	// IsPassive forbids interaction with the subject when true.
	IsPassive bool
	// AllowCreateNameID permits creation of a new subject identifier when true.
	AllowCreateNameID bool
	// SOAPContext signs in the SOAP namespace context for artifact resolution.
	SOAPContext bool
}

// BuildAuthnRequest builds an unsigned AuthnRequest in the supported solicited profile.
func BuildAuthnRequest(ctx context.Context, s AuthnRequest) (*document.Document, error) {
	if s.ResponseBinding == "" {
		s.ResponseBinding = metadata.HTTPPost
	}

	if !allowed(s.ResponseBinding, []string{metadata.HTTPPost, metadata.HTTPArtifact, metadata.PAOS}) || len(s.ChannelBindings) != 0 && s.ResponseBinding != metadata.PAOS {
		return nil, ErrProfile
	}

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

	n := xmlutil.Node(prefixProtocol, ProtocolNamespace, lexicon.SAMLElementAuthnRequest)

	n.NS = []tree.Namespace{{Prefix: prefixProtocol, URI: ProtocolNamespace}, {Prefix: prefixAssertion, URI: AssertionNamespace}, {Prefix: lexicon.PrefixDSig, URI: xmlutil.DS}}
	if s.SOAPContext {
		n.NS = append(n.NS, tree.Namespace{Prefix: prefixSOAP, URI: binding.SOAPNamespace})
	}

	for _, a := range [][2]string{{lexicon.SAMLAttrID, s.ID}, {nameVersion, version20}, {nameIssueInstant, profile.Time(s.IssueInstant)}, {nameDestination, s.Destination}, {nameACS, s.ACS}, {nameProtocolBinding, s.ResponseBinding}, {xmlNameForceAuthn, strconv.FormatBool(s.ForceAuthn)}, {xmlNameIsPassive, strconv.FormatBool(s.IsPassive)}} {
		xmlutil.Set(n, a[0], a[1])
	}

	iss := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameIssuer)
	xmlutil.Text(iss, s.Issuer)
	xmlutil.Add(n, iss)

	if err := appendChannelContainer(n, xmlNameExtensions, s.ChannelBindings, false); err != nil {
		return nil, err
	}

	if s.NameIDFormat != "" || s.AllowCreateNameID {
		if s.NameIDFormat != "" && !profile.URI(s.NameIDFormat) {
			return nil, ErrProfile
		}

		p := xmlutil.Node(prefixProtocol, ProtocolNamespace, xmlNameNameIDPolicy)
		if s.NameIDFormat != "" {
			xmlutil.Set(p, nameFormat, s.NameIDFormat)
		}

		xmlutil.Set(p, xmlNameAllowCreate, strconv.FormatBool(s.AllowCreateNameID))
		xmlutil.Add(n, p)
	}

	if len(s.RequestedContexts) > 0 {
		if len(s.RequestedContexts) > maximumRequestedWebContexts {
			return nil, ErrProfile
		}

		p := xmlutil.Node(prefixProtocol, ProtocolNamespace, xmlNameRequestedAuthnContext)
		xmlutil.Set(p, xmlNameComparison, contextExact)

		for _, s := range s.RequestedContexts {
			if !profile.URI(s) {
				return nil, ErrProfile
			}

			c := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameAuthnContextClassRef)
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

	responseBinding := s.ResponseBinding
	if responseBinding == "" {
		responseBinding = metadata.HTTPPost
	}

	_, e = VerifyAuthnRequest(ctx, out, []crypto.PublicKey{verificationKey(key)}, RequestOptions{Issuer: s.Issuer, Destination: s.Destination, At: s.IssueInstant, ACS: []metadata.Endpoint{{Binding: responseBinding, Location: s.ACS}}, Policy: key.Policy})
	if e != nil {
		return nil, e
	}

	return out, nil
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

	acs, err := selectRequestACS(root, o.ACS, o.ResponseBinding, o.AllowHolderOfKeyACS)
	if err != nil {
		return nil, err
	}

	request := &VerifiedRequest{doc: d, id: id, instant: instant, issuer: o.Issuer, destination: o.Destination, acs: acs.Location, responseBinding: acs.TransportBinding(), format: NameIDUnspecified}
	if err := readAuthnRequestFlags(root, request); err != nil {
		return nil, err
	}

	if err := readAuthnRequestChildren(children, position, o.Issuer, request); err != nil {
		return nil, err
	}

	if transportVerified && len(request.channels) != 0 {
		return nil, ErrSignature
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return request, nil
}

func validateRequestInputs(ctx context.Context, d *document.Document, options RequestOptions) error {
	const (
		maximumAuthorizedACS = 128
	)

	if ctx == nil || d == nil || options.At.IsZero() || !profile.URI(options.Issuer) || !profile.Endpoint(options.Destination, true) || len(options.ACS) == 0 || len(options.ACS) > maximumAuthorizedACS {
		return ErrProfile
	}

	return nil
}

func readAuthnRequestHeader(root document.Element, options RequestOptions, limits Limits) (string, time.Time, []document.Element, error) {
	required := []string{lexicon.SAMLAttrID, nameVersion, nameIssueInstant}

	optional := []string{nameACS, xmlNameAssertionConsumerServiceIndex, nameProtocolBinding, xmlNameForceAuthn, xmlNameIsPassive}
	if options.TransportBinding == metadata.SOAP || options.TransportBinding == metadata.HTTPArtifact {
		optional = append(optional, nameDestination)
	} else {
		required = append(required, nameDestination)
	}

	if xmlutil.Attrs(root, required, optional) != nil {
		return "", time.Time{}, nil, ErrProfile
	}

	id, instant, err := header(root, lexicon.SAMLElementAuthnRequest, options.At, limits)
	if err != nil {
		return "", time.Time{}, nil, err
	}

	if destination, present := root.Attribute(document.Name{Local: nameDestination}); present && destination != options.Destination {
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

		return unsignedMessagePrefixChildren, nil
	}

	if signingCount(d, 1) != nil || len(children) < signedMessagePrefixChildren || children[1].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature) {
		return 0, ErrProfile
	}

	if err := targetSignature(ctx, d, root, keys, policy); err != nil {
		return 0, err
	}

	return signedMessagePrefixChildren, nil
}

func selectRequestACS(root document.Element, authorized []metadata.Endpoint, expectedBinding string, allowHoK bool) (metadata.Endpoint, error) {
	acs, hasACS := root.Attribute(document.Name{Local: nameACS})
	indexString, hasIndex := root.Attribute(document.Name{Local: xmlNameAssertionConsumerServiceIndex})

	bindingURI, hasBinding := root.Attribute(document.Name{Local: nameProtocolBinding})
	if expectedBinding != "" && hasBinding && bindingURI != expectedBinding {
		return metadata.Endpoint{}, ErrProfile
	}

	if hasBinding && !allowed(bindingURI, []string{metadata.HTTPPost, metadata.HTTPArtifact, metadata.PAOS}) {
		return metadata.Endpoint{}, ErrProfile
	}

	if hasIndex && (hasACS || hasBinding) {
		return metadata.Endpoint{}, ErrProfile
	}

	var index *uint16

	if hasIndex {
		number, err := profile.Index(indexString)
		if err != nil {
			return metadata.Endpoint{}, ErrProfile
		}

		index = &number
	}

	var candidates []metadata.Endpoint

	for _, endpoint := range authorized {
		if !hasACS || endpoint.Location == acs {
			candidates = append(candidates, endpoint)
		}
	}

	if !hasBinding {
		bindingURI = expectedBinding
		if bindingURI == "" {
			bindingURI = metadata.HTTPPost
		}
	}

	chosen, err := metadata.SelectACS(candidates, bindingURI, index)
	if allowHoK {
		if hok, hokErr := metadata.SelectHoKACS(candidates, bindingURI, index); hokErr == nil {
			chosen, err = hok, nil
		}
	}

	if err != nil {
		return metadata.Endpoint{}, ErrProfile
	}

	if !profile.Endpoint(chosen.Location, true) {
		return metadata.Endpoint{}, ErrProfile
	}

	return chosen, nil
}

func readAuthnRequestFlags(root document.Element, request *VerifiedRequest) error {
	var err error

	request.force, err = xmlutil.BoolAttr(root, xmlNameForceAuthn)
	if err != nil {
		return err
	}

	request.passive, err = xmlutil.BoolAttr(root, xmlNameIsPassive)
	if err != nil || request.force && request.passive {
		return ErrProfile
	}

	return nil
}

func readAuthnRequestChildren(children []document.Element, position int, expectedIssuer string, request *VerifiedRequest) error {
	if position < len(children) && children[position].Name() == xmlutil.Name(ProtocolNamespace, xmlNameExtensions) {
		if request.ResponseBinding() != metadata.PAOS {
			return ErrProfile
		}

		var err error

		request.channels, err = readChannelContainer(children[position], false)
		if err != nil {
			return err
		}

		position++
	}

	if position < len(children) && children[position].Name() == xmlutil.Name(ProtocolNamespace, xmlNameNameIDPolicy) {
		if err := readRequestNameIDPolicy(children[position], expectedIssuer, request); err != nil {
			return err
		}

		position++
	}

	if position < len(children) && children[position].Name() == xmlutil.Name(ProtocolNamespace, xmlNameRequestedAuthnContext) {
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
	if xmlutil.Attrs(policy, nil, []string{nameFormat, nameSPNameQualifier, xmlNameAllowCreate}) != nil || !xmlutil.EmptyContent(policy) {
		return ErrProfile
	}

	if format := xmlutil.Attr(policy, nameFormat); format != "" {
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

	request.allowCreate, err = xmlutil.BoolAttr(policy, xmlNameAllowCreate)

	return err
}

func readRequestedAuthnContext(element document.Element, request *VerifiedRequest) error {
	if xmlutil.Attrs(element, nil, []string{xmlNameComparison}) != nil || xmlutil.Attr(element, xmlNameComparison) != "" && xmlutil.Attr(element, xmlNameComparison) != contextExact {
		return ErrProfile
	}

	contexts, err := xmlutil.Children(element)
	if err != nil || len(contexts) == 0 || len(contexts) > maximumRequestedWebContexts {
		return ErrProfile
	}

	return appendRequestContexts(contexts, request)
}

func appendRequestContexts(contexts []document.Element, request *VerifiedRequest) error {
	for _, element := range contexts {
		if element.Name() != xmlutil.Name(AssertionNamespace, xmlNameAuthnContextClassRef) {
			return ErrProfile
		}

		value, err := xmlutil.Simple(element, maximumURITextBytes)
		if err != nil || !profile.URI(value) {
			return ErrProfile
		}

		request.contexts = append(request.contexts, value)
	}

	return nil
}
