package protocol

import (
	"context"
	"crypto"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/xmldsig"
)

// Local SAML vocabulary tokens shared by protocol producers and parsers. Each call site still verifies the assertion/protocol namespace or resolves the QName prefix.
const (
	xmlNameConsent       = "Consent"
	xmlNameStatusMessage = "StatusMessage"
)

// Name identifiers and status messages have separate UTF-8 byte ceilings; the
// status-code count bounds nested subordinate codes in both wire directions.
const (
	maximumNameIdentifierBytes = 4096
	maximumStatusMessageBytes  = 4096
	maximumStatusSubcodes      = 8
)

const (
	// Requester indicates a request that could not be performed as sent.
	Requester = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	// Responder indicates a failure at the responding provider.
	Responder = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	// UnknownPrincipal indicates an unrecognized subject.
	UnknownPrincipal = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
	// PartialLogout indicates that not all sessions could be terminated.
	PartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
	// UnsupportedBinding indicates an unsupported requested protocol binding.
	UnsupportedBinding = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
)

// MessageHeader identifies a locally produced protocol message. An empty ID is
// replaced by a cryptographically random XML ID. Destination is a trusted endpoint.
type MessageHeader struct {
	// ID is the XML message identifier. Empty generates a cryptographically random
	// ID when signing.
	ID string
	// Issuer is the sending provider's entity ID.
	Issuer string
	// Destination is the recipient endpoint selected from trusted configuration.
	Destination string
	// IssueInstant is the message creation time.
	IssueInstant time.Time
	// Consent records the SAML consent identifier; it does not itself authorize an operation.
	Consent string
	// Extensions retains foreign-namespace extension XML for application processing.
	Extensions *document.Document
}

// ExchangeOptions fixes the peer, endpoint, time and credentials for a control
// exchange. Responses additionally require ExpectedRequestID. It supplies no trust
// from KeyInfo or from received endpoints. Replay protection belongs to the caller.
type ExchangeOptions struct {
	// Issuer is the required expected peer entity ID.
	Issuer string
	// Destination is the trusted local endpoint used to check the received
	// destination.
	Destination string
	// ExpectedRequestID is the request ID required for response correlation.
	ExpectedRequestID string
	// Binding selects a trusted SOAP transport context, in which Destination
	// may be absent. A present value is always checked. Signatures are required.
	Binding string
	// At is the explicit verification time and must be nonzero.
	At time.Time
	// Limits bounds message structure and freshness. Zero fields select the
	// protocol defaults.
	Limits Limits
	// Policy restricts signature and reference processing algorithms.
	Policy xmldsig.Policy
	// Decryption permits processing encrypted identifiers after signature
	// verification. Nil supplies no decryption keys.
	Decryption *DecryptionOptions
	// redirect records that the Redirect binding has already authenticated the
	// request.
	redirect bool
}

// NameIdentifier retains the full SAML NameID, including both qualifiers and the
// service provider's alias. Compare the complete value when identifying a subject.
// An absent Format has the SAML unspecified format semantics.
type NameIdentifier struct {
	// Value is the identifier's text content.
	Value string
	// Format is the identifier format URI. Empty has the SAML unspecified-format
	// semantics.
	Format string
	// NameQualifier scopes the identifier to its naming authority.
	NameQualifier string
	// SPNameQualifier scopes the identifier to a service provider or affiliation.
	SPNameQualifier string
	// SPProvidedID is the service provider's alias for the identifier.
	SPProvidedID string
}

// Validate checks bounded NameID structure and the persistent, transient and
// entity format constraints. Other format-specific semantics and the association
// with a real principal remain the application's responsibility.
func (id NameIdentifier) Validate() error {
	const (
		maximumEntityNameRunes   = 1024
		maximumOpaqueNameIDRunes = 256
	)

	if id.Value == "" || !utf8.ValidString(id.Value) || len(id.Value) > maximumNameIdentifierBytes || id.Format != "" && (!profile.URI(id.Format) || id.Format == NameIDEncrypted) || len(id.NameQualifier) > maximumNameQualifierBytes || len(id.SPNameQualifier) > maximumNameQualifierBytes || len(id.SPProvidedID) > maximumNameIdentifierBytes {
		return ErrProfile
	}

	for _, text := range []string{id.Value, id.Format, id.NameQualifier, id.SPNameQualifier, id.SPProvidedID} {
		if !utf8.ValidString(text) {
			return ErrProfile
		}

		for _, r := range text {
			if !xmlchar.IsChar(r) {
				return ErrProfile
			}
		}
	}

	switch id.Format {
	case NameIDPersistent:
		if utf8.RuneCountInString(id.Value) > maximumOpaqueNameIDRunes {
			return ErrProfile
		}
	case NameIDTransient:
		if utf8.RuneCountInString(id.Value) > maximumOpaqueNameIDRunes || !xmlchar.IsValidNCName(id.Value) {
			return ErrProfile
		}
	case lexicon.SAMLNameIDFormatEntity:
		if utf8.RuneCountInString(id.Value) > maximumEntityNameRunes || !profile.URI(id.Value) || id.NameQualifier != "" || id.SPNameQualifier != "" || id.SPProvidedID != "" {
			return ErrProfile
		}
	}

	return nil
}

// NewPersistentNameID generates an opaque pairwise identifier. Persist its
// association with the application's account and the two providers; never derive
// a persistent-format identifier from a public username (Core 8.3.7).
func NewPersistentNameID(idp, sp string) (NameIdentifier, error) {
	if !profile.URI(idp) || !profile.URI(sp) {
		return NameIdentifier{}, ErrProfile
	}

	value, err := profile.NewID()
	if err != nil {
		return NameIdentifier{}, err
	}

	return NameIdentifier{Value: value, Format: NameIDPersistent, NameQualifier: idp, SPNameQualifier: sp}, nil
}

// Status describes an authenticated SAML status. Subcodes are ordered outermost
// first. Success with PartialLogout is a partial outcome, not complete logout.
type Status struct {
	// Code is the top-level SAML status code URI.
	Code string
	// Subcodes contains subordinate status code URIs, ordered outermost first.
	Subcodes []string
	// Message is optional diagnostic text and grants no authority.
	Message string
}

// StatusResponse produces LogoutResponse, ManageNameIDResponse or ArtifactResponse.
// Message is permitted only for ArtifactResponse. An empty artifact response is a
// successful resolution with no message, not an authentication result.
type StatusResponse struct {
	MessageHeader
	// Kind selects LogoutResponse, ManageNameIDResponse or ArtifactResponse.
	Kind string
	// InResponseTo is the exact request ID being answered.
	InResponseTo string
	// Status is the protocol outcome to sign.
	Status Status
	// Message is the optional protocol payload of an ArtifactResponse. Other
	// response kinds must leave it nil.
	Message *document.Document
	// SOAPContext signs the response in the final SOAP namespace context.
	SOAPContext bool
}

// VerifiedStatusResponse is an immutable authenticated control response. An
// embedded artifact message still requires its own protocol/profile validation.
type VerifiedStatusResponse struct {
	header          MessageHeader
	kind, requestID string
	status          Status
	message         *document.Document
}

// Header returns the authenticated message header.
func (r *VerifiedStatusResponse) Header() MessageHeader { return r.header }

// Kind returns the response element's local name.
func (r *VerifiedStatusResponse) Kind() string { return r.kind }

// InResponseTo returns the correlated request ID.
func (r *VerifiedStatusResponse) InResponseTo() string { return r.requestID }

// Status returns an owned copy of the status.
func (r *VerifiedStatusResponse) Status() Status {
	s := r.status
	s.Subcodes = slices.Clone(s.Subcodes)

	return s
}

// Message returns the immutable embedded artifact message, or nil for an empty
// resolution. The artifact envelope signature does not validate its assertions.
func (r *VerifiedStatusResponse) Message() *document.Document { return r.message }

// SignStatusResponse signs a correlated response with a locally provisioned key.
func SignStatusResponse(ctx context.Context, s StatusResponse, key SigningKey) (*document.Document, error) {
	if s.Kind == lexicon.SAMLElementResponse && (s.Status.Code == "" || s.Status.Code == Success) {
		return nil, ErrProfile
	}

	if !responseKind(s.Kind) || !profile.ID(s.InResponseTo) || s.Kind != ArtifactResponse && s.Message != nil {
		return nil, ErrProfile
	}

	n, err := exchangeRoot(s.MessageHeader, s.Kind)
	if err != nil {
		return nil, err
	}

	xmlutil.Set(n, nameInResponseTo, s.InResponseTo)

	if s.SOAPContext {
		n.NS = append(n.NS, tree.Namespace{Prefix: prefixSOAP, URI: binding.SOAPNamespace})
	}

	status, err := statusNode(s.Status)
	if err != nil {
		return nil, err
	}

	xmlutil.Add(n, status)

	if s.Message != nil {
		if s.Message.Root().Name().Space != ProtocolNamespace || s.Status.Code != "" && s.Status.Code != Success {
			return nil, ErrProfile
		}

		_, child := tree.Unwrap(s.Message.Root())
		xmlutil.Add(n, tree.ImportSubtree(child))
	}

	return signExchange(ctx, n, key, nil)
}

// VerifyStatusResponse verifies the signature, peer, destination, freshness,
// status structure and request correlation, including non-success responses.
func VerifyStatusResponse(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o ExchangeOptions) (*VerifiedStatusResponse, error) {
	const (
		maximumStatusPayloadChildren = 2
	)

	if d == nil || !responseKind(d.Root().Name().Local) || !profile.ID(o.ExpectedRequestID) {
		return nil, ErrProfile
	}

	kind := d.Root().Name().Local

	h, cs, err := verifyExchange(ctx, d, kind, keys, o, nil, true)
	if err != nil {
		return nil, err
	}

	if xmlutil.Attr(d.Root(), nameInResponseTo) != o.ExpectedRequestID {
		return nil, ErrCorrelation
	}

	if len(cs) == 0 || len(cs) > maximumStatusPayloadChildren || len(cs) == maximumStatusPayloadChildren && kind != ArtifactResponse {
		return nil, ErrProfile
	}

	s, err := readStatus(cs[0])
	if err != nil {
		return nil, err
	}

	r := &VerifiedStatusResponse{header: h, kind: kind, requestID: o.ExpectedRequestID, status: s}
	if len(cs) == maximumStatusPayloadChildren {
		if s.Code != Success || cs[1].Name().Space != ProtocolNamespace {
			return nil, ErrProfile
		}

		r.message, err = tree.ScopeDocument(d, cs[1])
	}

	return r, err
}

// VerifyRedirectStatusResponse authenticates the exact Redirect query signature.
// RelayState is returned separately and must match the initiating exchange.
func VerifyRedirectStatusResponse(ctx context.Context, query string, keys []crypto.PublicKey, o ExchangeOptions, limits binding.Options) (*VerifiedStatusResponse, *string, error) {
	d, relay, err := exchangeRedirect(ctx, query, keys, o, limits, binding.Response)
	if err != nil {
		return nil, nil, err
	}

	o.redirect = true
	r, err := VerifyStatusResponse(ctx, d, nil, o)

	return r, relay, err
}

func responseKind(kind string) bool {
	return kind == LogoutResponse || kind == ManageNameIDResponse || kind == ArtifactResponse || kind == lexicon.SAMLElementResponse
}

func exchangeRoot(h MessageHeader, kind string) (*tree.Node, error) {
	return messageRoot(h, kind, false)
}

func soapExchangeRoot(h MessageHeader, kind string) (*tree.Node, error) {
	return messageRoot(h, kind, true)
}

func messageRoot(h MessageHeader, kind string, soap bool) (*tree.Node, error) {
	if !profile.URI(h.Issuer) || (!soap || h.Destination != "") && !profile.Endpoint(h.Destination, true) || h.IssueInstant.IsZero() {
		return nil, ErrProfile
	}

	if h.ID == "" {
		var err error

		h.ID, err = profile.NewID()
		if err != nil {
			return nil, err
		}
	}

	if !profile.ID(h.ID) {
		return nil, ErrProfile
	}

	n := xmlutil.Node(prefixProtocol, ProtocolNamespace, kind)

	n.NS = []tree.Namespace{{Prefix: prefixProtocol, URI: ProtocolNamespace}, {Prefix: prefixAssertion, URI: AssertionNamespace}, {Prefix: lexicon.PrefixDSig, URI: xmlutil.DS}}
	for _, a := range [][2]string{{lexicon.SAMLAttrID, h.ID}, {nameVersion, version20}, {nameIssueInstant, profile.Time(h.IssueInstant)}} {
		xmlutil.Set(n, a[0], a[1])
	}

	if h.Destination != "" {
		xmlutil.Set(n, nameDestination, h.Destination)
	}

	if h.Consent != "" {
		if !profile.URI(h.Consent) {
			return nil, ErrProfile
		}

		xmlutil.Set(n, xmlNameConsent, h.Consent)
	}

	i := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameIssuer)
	xmlutil.Text(i, h.Issuer)
	xmlutil.Add(n, i)

	if h.Extensions != nil {
		if err := validateExtensions(h.Extensions.Root()); err != nil {
			return nil, err
		}

		appendDocument(n, h.Extensions)
	}

	return n, nil
}

func signExchange(ctx context.Context, root *tree.Node, key SigningKey, encryption *EncryptionOptions) (*document.Document, error) {
	d, err := xmlutil.Document(ctx, root)
	if err != nil {
		return nil, err
	}

	if encryption != nil {
		o, err := CloneEncryption(encryption)
		if err != nil || o.Recipient == nil || o.Targets != EncryptNameID {
			return nil, ErrEncryption
		}

		for _, name := range []struct{ ns, plain, wrapper string }{{AssertionNamespace, xmlNameNameID, xmlNameEncryptedID}, {ProtocolNamespace, xmlNameNewID, xmlNameNewEncryptedID}} {
			target, err := xmlutil.Direct(d.Root(), xmlutil.Name(name.ns, name.plain))
			if err != nil {
				continue
			}

			d, err = encryptSAML(ctx, d, target, name.wrapper, o)
			if err != nil {
				return nil, err
			}
		}
	}

	k, err := signing(key)
	if err != nil {
		return nil, err
	}

	return xmlsig.Sign(ctx, d, d.Root(), k, true)
}

func verifyExchange(ctx context.Context, d *document.Document, kind string, keys []crypto.PublicKey, o ExchangeOptions, optional []string, response bool) (MessageHeader, []document.Element, error) {
	var zero MessageHeader
	if ctx == nil || d == nil || o.At.IsZero() || !profile.URI(o.Issuer) || !(o.Binding == metadata.SOAP && o.Destination == "") && !profile.Endpoint(o.Destination, true) {
		return zero, nil, ErrProfile
	}

	l, err := normalize(o.Limits)
	if err != nil {
		return zero, nil, err
	}

	attrs := append(slices.Clone(optional), xmlNameConsent)
	if response {
		attrs = append(attrs, nameInResponseTo)
	}

	root := d.Root()
	required := []string{lexicon.SAMLAttrID, nameVersion, nameIssueInstant}

	if o.Binding == metadata.SOAP {
		attrs = append(attrs, nameDestination)
	} else {
		required = append(required, nameDestination)
	}

	destination, present := root.Attribute(document.Name{Local: nameDestination})
	if xmlutil.Attrs(root, required, attrs) != nil || present && (o.Destination == "" || destination != o.Destination) {
		return zero, nil, ErrProfile
	}

	id, instant, err := header(root, kind, o.At, l)
	if err != nil {
		return zero, nil, err
	}

	cs, err := xmlutil.Children(root)
	if err != nil || len(cs) == 0 || issuer(cs[0], o.Issuer) != nil {
		return zero, nil, ErrProfile
	}

	position := unsignedMessagePrefixChildren

	if o.redirect {
		if len(cs) > 1 && cs[1].Name() == xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature) {
			return zero, nil, ErrProfile
		}
	} else {
		if len(cs) < signedMessagePrefixChildren || cs[1].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature) {
			return zero, nil, ErrSignature
		}

		if err := targetSignature(ctx, d, root, keys, o.Policy); err != nil {
			return zero, nil, err
		}

		position = signedMessagePrefixChildren
	}

	extensions, position, err := exchangeExtensions(d, cs, position)
	if err != nil {
		return zero, nil, err
	}

	consent := xmlutil.Attr(root, xmlNameConsent)
	if consent != "" && !profile.URI(consent) {
		return zero, nil, ErrProfile
	}

	return MessageHeader{ID: id, Issuer: o.Issuer, Destination: o.Destination, IssueInstant: instant, Consent: consent, Extensions: extensions}, cs[position:], ctx.Err()
}

func validateExtensions(e document.Element) error {
	const (
		maximumExtensionElements = 128
	)

	if e.Name() != xmlutil.Name(ProtocolNamespace, xmlNameExtensions) || xmlutil.Attrs(e, nil, nil) != nil {
		return ErrProfile
	}

	cs, err := xmlutil.Children(e)
	if err != nil || len(cs) == 0 || len(cs) > maximumExtensionElements {
		return ErrProfile
	}

	for _, c := range cs {
		if c.Name().Space == "" || c.Name().Space == ProtocolNamespace {
			return ErrProfile
		}
	}

	return nil
}

func exchangeRedirect(ctx context.Context, query string, keys []crypto.PublicKey, o ExchangeOptions, limits binding.Options, kind binding.Kind) (*document.Document, *string, error) {
	if len(keys) == 0 || len(keys) > maximumRedirectVerificationKeys {
		return nil, nil, ErrSignature
	}

	limits.Policy = o.Policy
	for _, key := range keys {
		r, err := binding.VerifyRedirect(ctx, query, key, limits)
		if err != nil {
			if ctx != nil && ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}

			continue
		}

		if r.Kind() != kind {
			return nil, nil, ErrProfile
		}

		var relay *string
		if s, ok := r.RelayState(); ok {
			relay = &s
		}

		return r.Document(), relay, nil
	}

	return nil, nil, ErrSignature
}

func nameIDNode(id NameIdentifier) (*tree.Node, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}

	n := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameNameID)

	for _, a := range [][2]string{{nameFormat, id.Format}, {nameNameQualifier, id.NameQualifier}, {nameSPNameQualifier, id.SPNameQualifier}, {nameSPProvidedID, id.SPProvidedID}} {
		if a[1] != "" {
			xmlutil.Set(n, a[0], a[1])
		}
	}

	xmlutil.Text(n, id.Value)

	return n, nil
}

func readNameID(e document.Element) (NameIdentifier, error) {
	var id NameIdentifier
	if e.Name() != xmlutil.Name(AssertionNamespace, xmlNameNameID) || xmlutil.Attrs(e, nil, []string{nameFormat, nameNameQualifier, nameSPNameQualifier, nameSPProvidedID}) != nil {
		return id, ErrProfile
	}

	s, err := xmlutil.SimpleText(e, maximumNameIdentifierBytes)
	if err != nil {
		return id, ErrProfile
	}

	id = NameIdentifier{Value: s, Format: xmlutil.Attr(e, nameFormat), NameQualifier: xmlutil.Attr(e, nameNameQualifier), SPNameQualifier: xmlutil.Attr(e, nameSPNameQualifier), SPProvidedID: xmlutil.Attr(e, nameSPProvidedID)}
	_, err = nameIDNode(id)

	return id, err
}

func statusNode(s Status) (*tree.Node, error) {
	const (
		statusVersionMismatch = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
	)

	if s.Code == "" {
		s.Code = Success
	}

	if !slices.Contains([]string{Success, Requester, Responder, statusVersionMismatch}, s.Code) || len(s.Subcodes) > maximumStatusSubcodes || len(s.Message) > maximumStatusMessageBytes {
		return nil, ErrProfile
	}

	n := xmlutil.Node(prefixProtocol, ProtocolNamespace, xmlNameStatus)
	parent := n

	for _, value := range append([]string{s.Code}, s.Subcodes...) {
		if !profile.URI(value) {
			return nil, ErrProfile
		}

		c := xmlutil.Node(prefixProtocol, ProtocolNamespace, xmlNameStatusCode)
		xmlutil.Set(c, xmlNameValue, value)
		xmlutil.Add(parent, c)
		parent = c
	}

	if s.Message != "" {
		m := xmlutil.Node(prefixProtocol, ProtocolNamespace, xmlNameStatusMessage)
		xmlutil.Text(m, s.Message)
		xmlutil.Add(n, m)
	}

	return n, nil
}

func readStatus(e document.Element) (Status, error) {
	const (
		maximumStatusChildren = 3
		xmlNameStatusDetail   = "StatusDetail"
	)

	var s Status
	if e.Name() != xmlutil.Name(ProtocolNamespace, xmlNameStatus) || xmlutil.Attrs(e, nil, nil) != nil {
		return s, ErrProfile
	}

	cs, err := xmlutil.Children(e)
	if err != nil || len(cs) == 0 || len(cs) > maximumStatusChildren {
		return s, ErrProfile
	}

	c := cs[0]
	for depth := 0; ; depth++ {
		if depth > maximumStatusSubcodes || c.Name() != xmlutil.Name(ProtocolNamespace, xmlNameStatusCode) || xmlutil.Attrs(c, []string{xmlNameValue}, nil) != nil {
			return s, ErrProfile
		}

		v := xmlutil.Attr(c, xmlNameValue)
		if depth == 0 {
			s.Code = v
		} else {
			s.Subcodes = append(s.Subcodes, v)
		}

		cc, err := xmlutil.Children(c)
		if err != nil || len(cc) > 1 {
			return s, ErrProfile
		}

		if len(cc) == 0 {
			break
		}

		c = cc[0]
	}

	i := 1
	if i < len(cs) && cs[i].Name() == xmlutil.Name(ProtocolNamespace, xmlNameStatusMessage) {
		s.Message, err = xmlutil.Simple(cs[i], maximumStatusMessageBytes)
		if err != nil {
			return s, ErrProfile
		}

		i++
	}

	if i < len(cs) {
		if i != len(cs)-1 || cs[i].Name() != xmlutil.Name(ProtocolNamespace, xmlNameStatusDetail) || xmlutil.Attrs(cs[i], nil, nil) != nil {
			return s, ErrProfile
		}

		if _, err := xmlutil.Children(cs[i]); err != nil {
			return s, ErrProfile
		}
	}

	_, err = statusNode(s)

	return s, err
}

func exchangeExtensions(d *document.Document, cs []document.Element, position int) (*document.Document, int, error) {
	if position >= len(cs) || cs[position].Name() != xmlutil.Name(ProtocolNamespace, xmlNameExtensions) {
		return nil, position, nil
	}

	if err := validateExtensions(cs[position]); err != nil {
		return nil, position, err
	}

	extension, err := tree.ScopeDocument(d, cs[position])

	return extension, position + 1, err
}
