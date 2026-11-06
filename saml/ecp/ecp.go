// Package ecp implements the SAML 2.0 Enhanced Client or Proxy profile and PAOS
// routing. It never authenticates an end user; IdP application authentication and
// SP assertion verification are separate, mandatory operations.
package ecp

import (
	"context"
	"errors"
	"math"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
)

// Byte ceiling for the optional PAOS messageID echoed between ECP hops; SAML XML request IDs retain their independent NCName/profile checks.
const (
	maximumPAOSMessageIDBytes = 1024
)

// ECP SOAP relay text has a separate 4096-byte ceiling; this must not be substituted for the 80-byte HTTP binding RelayState limit.
const (
	maximumRelayStateBytes = 4096
)

// Liberty PAOS version token shared by advertisement and negotiation; only the configured PAOS namespace/version is supported.
const (
	paosVersionParameter = "ver="
)

// Local wire token shared by ECP/PAOS processing; each use still checks the vocabulary namespace and the relevant SOAP processing role.
const (
	fieldRelayState                    = "RelayState"
	soapActorAttribute                 = "actor"
	soapMustUnderstandAttribute        = "mustUnderstand"
	xmlNameAssertionConsumerServiceURL = "AssertionConsumerServiceURL"
	xmlNameInResponseTo                = "InResponseTo"
	xmlNameIsPassive                   = "IsPassive"
	xmlNameIssuer                      = "Issuer"
	xmlNameMessageID                   = "messageID"
	xmlNameMethod                      = "Method"
	xmlNameRefToMessageID              = "refToMessageID"
	xmlNameRequest                     = "Request"
	xmlNameRequestAuthenticated        = "RequestAuthenticated"
	xmlNameResponse                    = "Response"
	xmlNameResponseConsumerURL         = "responseConsumerURL"
	xmlNameService                     = "service"
	xmlNameSubjectConfirmation         = "SubjectConfirmation"
)

// Negotiation header shared by PAOS advertisement and parsing; its version/service tokens are checked independently of HTTP Accept.
const (
	headerPAOS = "Paos"
)

// PAOS negotiation evaluates HTTP media ranges and quality values; advertisement or a matching Accept header is not proof of possession.
const (
	headerAccept = "Accept"
)

// SOAP 1.1 mustUnderstand accepts the numeric lexical forms 0 and 1 here; ECP creation emits mandatory 1 and validates the processing actor separately.
const (
	soapBooleanTrue = "1"
)

// Suggested prefix for emitted ECP headers; expanded namespace/local names determine acceptance, independently of prefix spelling.
const (
	prefixECP = "ecp"
)

// Suggested prefix for emitted PAOS headers; expanded namespace/local names determine acceptance, independently of prefix spelling.
const (
	prefixPAOS = "paos"
)

const (
	prefixSOAP = "env"
	// Namespace identifies the ECP SOAP headers and PAOS service.
	Namespace = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
	// PAOSNamespace is the Liberty PAOS 1.0 header namespace/version.
	PAOSNamespace = "urn:liberty:paos:2003-08"
	// MediaType is the registered PAOS SOAP media type.
	MediaType = lexicon.MediaTypePAOS
)

// ErrECP reports a malformed or incorrectly routed ECP exchange.
var ErrECP = errors.New("SAML ECP exchange rejected")

// Advertise adds the HTTP negotiation headers required by Profiles 4.2.3.1 and
// Approved Errata E21/E54. It retains existing Accept alternatives.
func Advertise(h http.Header) {
	const (
		paosServiceDelimiter       = "\"; \""
		paosVersionQuotedParameter = paosVersionParameter + `"`
	)

	h.Add(headerAccept, MediaType)
	h.Set(headerPAOS, paosVersionQuotedParameter+PAOSNamespace+paosServiceDelimiter+Namespace+`"`)
}

// acceptsPAOS checks Accept media ranges. A q=0 entry disables that range;
// an explicit range takes precedence over wildcards.
func acceptsPAOS(h http.Header) bool {
	const (
		applicationMediaSpecificity = 1
		defaultMediaQuality         = 1.0
		exactMediaSpecificity       = 2
		mediaRangeAny               = "*/*"
		mediaRangeApplication       = "application/*"
		qualityFloatBitSize         = 64
		qualityParameter            = "q"
		unmatchedMediaQuality       = -1.0
		unmatchedMediaSpecificity   = -1
		wildcardMediaSpecificity    = 0
	)

	quality := unmatchedMediaQuality
	specificity := unmatchedMediaSpecificity

	for _, line := range h.Values(headerAccept) {
		for part := range strings.SplitSeq(line, ",") {
			media, p, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				return false
			}

			spec := unmatchedMediaSpecificity

			switch media {
			case MediaType:
				spec = exactMediaSpecificity
			case mediaRangeApplication:
				spec = applicationMediaSpecificity
			case mediaRangeAny:
				spec = wildcardMediaSpecificity
			}

			q := defaultMediaQuality
			if raw, ok := p[qualityParameter]; ok {
				q, err = strconv.ParseFloat(raw, qualityFloatBitSize)
				if err != nil || q < 0 || q > 1 || math.IsNaN(q) || math.IsInf(q, 0) {
					return false
				}
			}

			if spec > specificity || spec == specificity && q > quality {
				specificity = spec
				quality = q
			}
		}
	}

	if specificity < 0 || quality <= 0 {
		return false
	}

	return specificity >= 0 && quality > 0
}

// Negotiated reports PAOS media, service and version support in the HTTP headers.
func Negotiated(h http.Header) bool {
	const (
		maximumNegotiationHeaderBytes = 8192
		minimumPAOSParameters         = 2
	)

	if !acceptsPAOS(h) {
		return false
	}

	values := h.Values(headerPAOS)
	if len(values) != 1 || len(values[0]) > maximumNegotiationHeaderBytes {
		return false
	}

	parts := strings.Split(values[0], ";")
	if len(parts) < minimumPAOSParameters {
		return false
	}

	version := strings.TrimSpace(parts[0])
	if !strings.HasPrefix(version, paosVersionParameter) {
		return false
	}

	v, err := strconv.Unquote(strings.TrimSpace(strings.TrimPrefix(version, paosVersionParameter)))
	if err != nil || v != PAOSNamespace {
		return false
	}

	for _, p := range parts[1:] {
		service, err := strconv.Unquote(strings.TrimSpace(strings.Split(p, ",")[0]))
		if err == nil && service == Namespace {
			return true
		}
	}

	return false
}

// Challenge wraps and signs an AuthnRequest for PAOS delivery. The caller must
// persist request/browser correlation before returning it. messageID optionally
// requests a matching PAOS refToMessageID; RelayState is echoed as an XML header.
func Challenge(ctx context.Context, request protocol.AuthnRequest, key protocol.SigningKey, relay *string, messageID string) (*document.Document, error) {
	return challenge(ctx, request, key, relay, messageID, false)
}

func challenge(ctx context.Context, request protocol.AuthnRequest, key protocol.SigningKey, relay *string, messageID string, hok bool) (*document.Document, error) {
	request.ResponseBinding = metadata.PAOS

	d, err := protocol.SignAuthnRequest(ctx, request, key)
	if err != nil {
		return nil, err
	}

	return wrapChallenge(ctx, d, key, relay, messageID, hok)
}

// WrapChallenge adds ECP/PAOS headers to an existing signed PAOS AuthnRequest.
func WrapChallenge(ctx context.Context, request *document.Document, key protocol.SigningKey, relay *string, messageID string) (*document.Document, error) {
	return wrapChallenge(ctx, request, key, relay, messageID, false)
}

func wrapChallenge(ctx context.Context, request *document.Document, key protocol.SigningKey, relay *string, messageID string, hok bool) (*document.Document, error) {
	const (
		xmlNameProtocolBinding = "ProtocolBinding"
	)

	if request == nil || request.Root().Name() != xmlutil.Name(protocol.ProtocolNamespace, lexicon.SAMLElementAuthnRequest) || xmlutil.Attr(request.Root(), xmlNameProtocolBinding) != metadata.PAOS || len(messageID) > maximumPAOSMessageIDBytes {
		return nil, ErrECP
	}

	acs := xmlutil.Attr(request.Root(), xmlNameAssertionConsumerServiceURL)
	if !profile.Endpoint(acs, false) {
		return nil, ErrECP
	}

	paos := header(PAOSNamespace, prefixPAOS, xmlNameRequest)
	xmlutil.Set(paos, xmlNameResponseConsumerURL, acs)
	xmlutil.Set(paos, xmlNameService, Namespace)

	if messageID != "" {
		xmlutil.Set(paos, xmlNameMessageID, messageID)
	}

	req := header(Namespace, prefixECP, xmlNameRequest)

	passive, err := xmlutil.BoolAttr(request.Root(), xmlNameIsPassive)
	if err != nil {
		return nil, err
	}

	xmlutil.Set(req, xmlNameIsPassive, strconv.FormatBool(passive))

	issuer, err := xmlutil.Direct(request.Root(), xmlutil.Name(protocol.AssertionNamespace, xmlNameIssuer))
	if err != nil {
		return nil, err
	}

	_, node := tree.Unwrap(issuer)
	xmlutil.Add(req, tree.ImportSubtree(node))

	headers, err := headerElements(ctx, paos, req)
	if err != nil {
		return nil, err
	}

	channels, err := requestChannels(request)
	if err != nil {
		return nil, err
	}

	channelElements, err := channelHeaders(ctx, channels, true)
	if err != nil {
		return nil, err
	}

	headers = append(headers, channelElements...)

	if hok {
		h := header(Namespace, prefixECP, xmlNameSubjectConfirmation)
		xmlutil.Set(h, xmlNameMethod, protocol.HolderOfKey)

		more, err := headerElements(ctx, h)
		if err != nil {
			return nil, err
		}

		headers = append(headers, more...)
	}

	if relay != nil {
		h, err := relayHeader(ctx, *relay)
		if err != nil {
			return nil, err
		}

		headers = append(headers, h)
	}

	return protocol.SignSOAP(ctx, request, key, headers...)
}

// Exchange retains SP routing state independently of the IdP response. It is
// created only from a challenge received over the application's trusted SP HTTP
// exchange. resourceURL is that request's absolute HTTPS URL, used only to resolve
// a relative responseConsumerURL allowed by Profiles 4.2.4.4 / Errata E35.
type Exchange struct {
	relay                     document.Element
	request                   *document.Document
	acs, requestID, messageID string
	forward                   []document.Element
	channels                  []protocol.ChannelBinding
	certificate               []byte
	passive                   bool
	holder                    bool
	bearer, modern            bool
}

// ParseChallenge validates required header shapes, SOAP actors, ACS and message
// type before producing the envelope to send to an independently trusted IdP.
func ParseChallenge(ctx context.Context, raw []byte, resourceURL string, limits binding.SOAPOptions) (*Exchange, error) {
	x, err := parseChallenge(ctx, raw, resourceURL, nil, limits)
	if err == nil {
		if !x.bearer {
			return nil, ErrECP
		}

		x.holder = false
	}

	return x, err
}

func parseChallenge(ctx context.Context, raw []byte, resourceURL string, channels []protocol.ChannelBinding, limits binding.SOAPOptions) (*Exchange, error) {
	const (
		maximumECPRequestChildren = 2
		xmlNameFormat             = "Format"
		xmlNameIDPList            = "IDPList"
	)

	limits.Understood = append(slices.Clone(limits.Understood), knownHeaders()...)

	m, err := binding.DecodeSOAP(ctx, raw, limits)
	if err != nil {
		return nil, err
	}

	x := &Exchange{passive: true}

	x.holder, x.bearer, err = offeredHoK(m.Headers())
	if err != nil {
		return nil, err
	}

	x.modern = slices.ContainsFunc(m.Headers(), func(h document.Element) bool {
		return h.Name() == xmlutil.Name(Namespace, xmlNameSubjectConfirmation)
	})

	if err := rejectIDPChannelHeaders(m.Headers()); err != nil {
		return nil, err
	}

	x.channels, err = requestedChannels(m.Headers(), channels)
	if err != nil {
		return nil, err
	}

	paos, request, relay, forward, err := challengeHeaders(m.Headers())
	if err != nil {
		return nil, err
	}

	x.relay = relay
	x.forward = forward

	if validateChallengeHeaders(paos, request) != nil {
		return nil, ErrECP
	}

	x.messageID = xmlutil.Attr(paos, xmlNameMessageID)
	if len(x.messageID) > maximumPAOSMessageIDBytes {
		return nil, ErrECP
	}

	base, err := url.Parse(resourceURL)
	if err != nil || !profile.Endpoint(resourceURL, false) {
		return nil, ErrECP
	}

	ref, err := url.Parse(xmlutil.Attr(paos, xmlNameResponseConsumerURL))
	if err != nil || ref.String() == "" {
		return nil, ErrECP
	}

	x.acs = base.ResolveReference(ref).String()
	if !profile.Endpoint(x.acs, false) {
		return nil, ErrECP
	}

	if _, present := request.Attribute(document.Name{Local: xmlNameIsPassive}); present {
		x.passive, err = xmlutil.BoolAttr(request, xmlNameIsPassive)
		if err != nil {
			return nil, err
		}
	}

	cs, err := xmlutil.Children(request)
	if err != nil || len(cs) < 1 || len(cs) > maximumECPRequestChildren || cs[0].Name() != xmlutil.Name(protocol.AssertionNamespace, xmlNameIssuer) {
		return nil, ErrECP
	}

	if xmlutil.Attrs(cs[0], nil, []string{xmlNameFormat}) != nil || xmlutil.Attr(cs[0], xmlNameFormat) != "" && xmlutil.Attr(cs[0], xmlNameFormat) != lexicon.SAMLNameIDFormatEntity {
		return nil, ErrECP
	}

	if len(cs) == maximumECPRequestChildren && cs[1].Name() != xmlutil.Name(protocol.ProtocolNamespace, xmlNameIDPList) {
		return nil, ErrECP
	}

	x.request, err = m.Payload(ctx)
	if err != nil {
		return nil, err
	}

	if x.request.Root().Name() != xmlutil.Name(protocol.ProtocolNamespace, lexicon.SAMLElementAuthnRequest) {
		return nil, ErrECP
	}

	if err := matchingIssuers(x.request.Root(), cs[0]); err != nil {
		return nil, err
	}

	x.requestID = xmlutil.Attr(x.request.Root(), lexicon.SAMLAttrID)
	if !profile.ID(x.requestID) {
		return nil, ErrECP
	}

	if acs := xmlutil.Attr(x.request.Root(), xmlNameAssertionConsumerServiceURL); acs != "" && acs != x.acs {
		return nil, ErrECP
	}

	return x, nil
}

// IsPassive reports whether the ECP may interact with the user. An omitted ECP
// IsPassive header attribute defaults to true, unlike AuthnRequest.IsPassive.
func (x *Exchange) IsPassive() bool { return x.passive }

// Endpoint returns the SP-controlled ACS retained before contacting the IdP.
func (x *Exchange) Endpoint() string { return x.acs }

// ToIDP removes PAOS Request, ECP Request and RelayState headers while preserving
// the immutable SAML body and headers addressed to other SOAP actors.
func (x *Exchange) ToIDP(ctx context.Context) (*document.Document, error) {
	headers := x.forward
	if x.modern {
		headers = nil
	}

	if len(x.channels) != 0 {
		var err error

		headers, err = channelHeaders(ctx, x.channels, false)
		if err != nil {
			return nil, err
		}
	}

	return binding.WrapSOAP(ctx, x.request, headers...)
}

// Response adds the mandatory ECP response routing header. The caller must have
// authenticated the request and signed the SAML response for its authorized ACS.
// protocol.Response.SOAPContext must be set when signing an Inclusive C14N
// assertion. responseDestination is obtained from that verified request.
func Response(ctx context.Context, message *document.Document, responseDestination string) (*document.Document, error) {
	return responseEnvelope(ctx, message, responseDestination, nil, false, document.Element{})
}

// ResponseWithBindings adds the IdP's channel verification signal to a signed
// response whose assertions contain the same authenticated Advice. The bindings
// must be the result of MatchChannelBindings, not merely copied input headers.
// The caller must have authenticated the AuthnRequest's XML signature; the
// optional RequestAuthenticated header reports that fact to extension-aware ECPs.
func ResponseWithBindings(ctx context.Context, message *document.Document, responseDestination string, channels []protocol.ChannelBinding) (*document.Document, error) {
	return responseEnvelope(ctx, message, responseDestination, channels, true, document.Element{})
}

func responseEnvelope(ctx context.Context, message *document.Document, responseDestination string, channels []protocol.ChannelBinding, requestAuthenticated bool, confirmation document.Element) (*document.Document, error) {
	const (
		xmlNameDestination = "Destination"
	)

	if message == nil || message.Root().Name() != xmlutil.Name(protocol.ProtocolNamespace, lexicon.SAMLElementResponse) || !profile.Endpoint(responseDestination, false) || xmlutil.Attr(message.Root(), xmlNameDestination) != responseDestination {
		return nil, ErrECP
	}

	h := header(Namespace, prefixECP, xmlNameResponse)
	xmlutil.Set(h, xmlNameAssertionConsumerServiceURL, responseDestination)

	elements, err := headerElements(ctx, h)
	if err != nil {
		return nil, err
	}

	cb, err := channelHeaders(ctx, channels, true)
	if err != nil {
		return nil, err
	}

	elements = append(elements, cb...)

	if confirmation.Valid() {
		h := header(Namespace, prefixECP, xmlNameSubjectConfirmation)
		xmlutil.Set(h, xmlNameMethod, protocol.HolderOfKey)

		_, n := tree.Unwrap(confirmation)
		xmlutil.Add(h, tree.ImportSubtree(n))

		more, err := headerElements(ctx, h)
		if err != nil {
			return nil, err
		}

		elements = append(elements, more...)
	}

	if requestAuthenticated {
		auth := header(Namespace, prefixECP, xmlNameRequestAuthenticated)
		// CS01 2.3.6.1 permits omission of mustUnderstand. Older ECP
		// clients can ignore this signal without failing the bearer flow.
		auth.Attrs = slices.DeleteFunc(auth.Attrs, func(a tree.Attribute) bool {
			return a.Name == xmlutil.Name(binding.SOAPNamespace, soapMustUnderstandAttribute)
		})

		more, err := headerElements(ctx, auth)
		if err != nil {
			return nil, err
		}

		elements = append(elements, more...)
	}

	return binding.WrapSOAP(ctx, message, elements...)
}

// Finish removes the IdP's ECP Response header and prepares the PAOS return to
// the original SP. On an ACS mismatch it returns a SOAP Fault envelope and error,
// never the SAML response; deliver that fault only to Endpoint(). The original SP
// RelayState always takes precedence over a RelayState supplied by the IdP.
func (x *Exchange) Finish(ctx context.Context, raw []byte, limits binding.SOAPOptions) (*document.Document, error) {
	const (
		faultCodeClient = "Client"
	)

	limits.Understood = append(slices.Clone(limits.Understood), knownHeaders()...)

	m, err := binding.DecodeSOAP(ctx, raw, limits)
	if err != nil {
		if fault, ok := errors.AsType[*binding.SOAPFault](err); ok {
			return forwardFault(ctx, m, fault)
		}

		return nil, err
	}

	if err := rejectIDPChannelHeaders(m.Headers()); err != nil {
		return nil, err
	}

	response, relay, forward, err := responseHeaders(m.Headers())
	if err != nil {
		return nil, err
	}

	confirmed, err := ReadChannelHeaders(m.Headers(), true)
	if err != nil {
		return nil, err
	}

	if len(x.channels) != 0 && len(confirmed) == 0 {
		fault := binding.SOAPFault{Code: xmlutil.Name(binding.SOAPNamespace, faultCodeClient), Message: "IdP did not confirm ECP channel bindings"}

		d, err := binding.FaultSOAP(ctx, fault)
		if err != nil {
			return nil, err
		}

		return d, &fault
	}

	if len(x.channels) != 0 || x.modern {
		forward = nil
	}

	if validateHeader(response, []string{xmlNameAssertionConsumerServiceURL}, nil) != nil || !xmlutil.EmptyContent(response) {
		return nil, ErrECP
	}

	if xmlutil.Attr(response, xmlNameAssertionConsumerServiceURL) != x.acs {
		fault := binding.SOAPFault{Code: xmlutil.Name(binding.SOAPNamespace, faultCodeClient), Message: "ECP response destination mismatch"}

		d, err := binding.FaultSOAP(ctx, fault)
		if err != nil {
			return nil, err
		}

		return d, &fault
	}

	d, err := m.Payload(ctx)
	if err != nil {
		return nil, err
	}

	if d.Root().Name() != xmlutil.Name(protocol.ProtocolNamespace, lexicon.SAMLElementResponse) || xmlutil.Attr(d.Root(), xmlNameInResponseTo) != x.requestID {
		return nil, ErrECP
	}

	if err := x.checkConfirmation(m.Headers(), d); err != nil {
		return nil, err
	}

	if x.messageID != "" {
		h := header(PAOSNamespace, prefixPAOS, xmlNameResponse)
		xmlutil.Set(h, xmlNameRefToMessageID, x.messageID)

		es, err := headerElements(ctx, h)
		if err != nil {
			return nil, err
		}

		forward = append(forward, es...)
	}

	if x.relay.Valid() {
		relay = x.relay
	}

	if relay.Valid() {
		forward = append(forward, relay)
	}

	return binding.WrapSOAP(ctx, d, forward...)
}

func forwardFault(ctx context.Context, m *binding.SOAPMessage, fault *binding.SOAPFault) (*document.Document, error) {
	if m != nil {
		payload, err := m.Payload(ctx)
		if err != nil {
			return nil, errors.Join(fault, err)
		}

		d, err := binding.WrapSOAP(ctx, payload)

		return d, errors.Join(fault, err)
	}

	d, err := binding.FaultSOAP(ctx, *fault)

	return d, errors.Join(fault, err)
}

// DecodeResponse extracts an ECP-to-SP PAOS response and its RelayState. The SP
// must still perform full Web SSO assertion, correlation and replay checks.
// expectedMessageID is required only if the SP used PAOS messageID.
func DecodeResponse(ctx context.Context, raw []byte, expectedMessageID string, limits binding.SOAPOptions) (*document.Document, *string, error) {
	limits.Understood = append(slices.Clone(limits.Understood), knownHeaders()...)

	m, err := binding.DecodeSOAP(ctx, raw, limits)
	if err != nil {
		return nil, nil, err
	}

	return ExtractResponse(ctx, m, expectedMessageID)
}

// ExtractResponse preserves the SOAP snapshot authenticated by an ECP proof.
// It checks routing headers only; the SAML body still requires verification.
func ExtractResponse(ctx context.Context, m *binding.SOAPMessage, expectedMessageID string) (*document.Document, *string, error) {
	if m == nil {
		return nil, nil, ErrECP
	}

	var (
		relay    *string
		response document.Element
	)

	for _, h := range m.Headers() {
		switch h.Name() {
		case xmlutil.Name(Namespace, fieldRelayState):
			if relay != nil || validateRelay(h) != nil {
				return nil, nil, ErrECP
			}

			text, err := xmlutil.SimpleText(h, maximumRelayStateBytes)
			if err != nil {
				return nil, nil, err
			}

			relay = &text
		case xmlutil.Name(PAOSNamespace, xmlNameResponse):
			if response.Valid() || validateHeader(h, nil, []string{xmlNameRefToMessageID}) != nil || !xmlutil.EmptyContent(h) {
				return nil, nil, ErrECP
			}

			response = h
		case xmlutil.Name(Namespace, xmlNameRequest), xmlutil.Name(Namespace, xmlNameResponse), xmlutil.Name(PAOSNamespace, xmlNameRequest):
			return nil, nil, ErrECP
		case channelHeaderName(), xmlutil.Name(Namespace, xmlNameRequestAuthenticated), xmlutil.Name(Namespace, xmlNameSubjectConfirmation):
			return nil, nil, ErrECP
		}
	}

	if expectedMessageID != "" && (!response.Valid() || xmlutil.Attr(response, xmlNameRefToMessageID) != expectedMessageID) {
		return nil, nil, ErrECP
	}

	d, err := m.Payload(ctx)
	if err != nil {
		return nil, nil, err
	}

	if d.Root().Name() != xmlutil.Name(protocol.ProtocolNamespace, lexicon.SAMLElementResponse) {
		return nil, nil, ErrECP
	}

	return d, relay, nil
}

func knownHeaders() []document.Name {
	return []document.Name{xmlutil.Name(PAOSNamespace, xmlNameRequest), xmlutil.Name(PAOSNamespace, xmlNameResponse), xmlutil.Name(Namespace, xmlNameRequest), xmlutil.Name(Namespace, xmlNameResponse), xmlutil.Name(Namespace, fieldRelayState), channelHeaderName(), xmlutil.Name(Namespace, xmlNameRequestAuthenticated), xmlutil.Name(Namespace, xmlNameSubjectConfirmation)}
}

func header(ns, prefix, local string) *tree.Node {
	n := xmlutil.Node(prefix, ns, local)
	n.NS = []tree.Namespace{{Prefix: prefix, URI: ns}, {Prefix: prefixSOAP, URI: binding.SOAPNamespace}}
	n.Attrs = append(n.Attrs, tree.Attribute{Name: xmlutil.Name(binding.SOAPNamespace, soapMustUnderstandAttribute), Prefix: prefixSOAP, Value: soapBooleanTrue}, tree.Attribute{Name: xmlutil.Name(binding.SOAPNamespace, soapActorAttribute), Prefix: prefixSOAP, Value: binding.SOAPNext})

	return n
}

func headerElements(ctx context.Context, nodes ...*tree.Node) ([]document.Element, error) {
	var out []document.Element

	for _, n := range nodes {
		d, err := xmlutil.Document(ctx, n)
		if err != nil {
			return nil, err
		}

		out = append(out, d.Root())
	}

	return out, nil
}

func relayHeader(ctx context.Context, value string) (document.Element, error) {
	if len(value) > maximumRelayStateBytes {
		return document.Element{}, ErrECP
	}

	n := header(Namespace, prefixECP, fieldRelayState)
	xmlutil.Text(n, value)

	d, err := xmlutil.Document(ctx, n)
	if err != nil {
		return document.Element{}, err
	}

	return d.Root(), nil
}

func validateRelay(h document.Element) error {
	if validateHeader(h, nil, nil) != nil {
		return ErrECP
	}

	_, err := xmlutil.SimpleText(h, maximumRelayStateBytes)

	return err
}

func validateHeader(h document.Element, required, optional []string) error {
	if !h.Valid() {
		return ErrECP
	}

	seen := map[string]bool{}

	for _, a := range h.Attributes() {
		if a.Name.Space == binding.SOAPNamespace {
			if a.Name.Local == soapMustUnderstandAttribute && a.Value == soapBooleanTrue || a.Name.Local == soapActorAttribute && a.Value == binding.SOAPNext {
				seen[a.Name.Space+a.Name.Local] = true
				continue
			}

			return ErrECP
		}

		if a.Name.Space != "" {
			return ErrECP
		}

		ok := slices.Contains(append(append([]string(nil), required...), optional...), a.Name.Local)

		if !ok {
			return ErrECP
		}

		seen[a.Name.Local] = true
	}

	if !seen[binding.SOAPNamespace+soapMustUnderstandAttribute] || !seen[binding.SOAPNamespace+soapActorAttribute] {
		return ErrECP
	}

	for _, name := range required {
		if !seen[name] {
			return ErrECP
		}
	}

	return nil
}

func challengeHeaders(headers []document.Element) (document.Element, document.Element, document.Element, []document.Element, error) {
	var (
		relay         document.Element
		forward       []document.Element
		paos, request document.Element
	)

	for _, h := range headers {
		switch h.Name() {
		case xmlutil.Name(Namespace, xmlNameSubjectConfirmation):
			// offeredHoK validates and consumes these headers.
		case channelHeaderName():
			// requestedChannels validates and consumes these headers.
		case xmlutil.Name(PAOSNamespace, xmlNameRequest):
			if paos.Valid() {
				return document.Element{}, document.Element{}, document.Element{}, nil, ErrECP
			}

			paos = h
		case xmlutil.Name(Namespace, xmlNameRequest):
			if request.Valid() {
				return document.Element{}, document.Element{}, document.Element{}, nil, ErrECP
			}

			request = h
		case xmlutil.Name(Namespace, fieldRelayState):
			if relay.Valid() || validateRelay(h) != nil {
				return document.Element{}, document.Element{}, document.Element{}, nil, ErrECP
			}

			relay = h
		case xmlutil.Name(Namespace, xmlNameResponse), xmlutil.Name(PAOSNamespace, xmlNameResponse), xmlutil.Name(Namespace, xmlNameRequestAuthenticated):
			return document.Element{}, document.Element{}, document.Element{}, nil, ErrECP
		default:
			if actor, _ := h.Attribute(xmlutil.Name(binding.SOAPNamespace, soapActorAttribute)); actor != binding.SOAPNext {
				forward = append(forward, h)
			}
		}
	}

	return paos, request, relay, forward, nil
}

func matchingIssuers(body, header document.Element) error {
	const (
		maximumIssuerBytes = 2048
	)

	requestIssuer, err := xmlutil.Direct(body, xmlutil.Name(protocol.AssertionNamespace, xmlNameIssuer))
	if err != nil {
		return ErrECP
	}

	headerIssuer, err := xmlutil.SimpleText(header, maximumIssuerBytes)
	if err != nil || !profile.URI(headerIssuer) {
		return ErrECP
	}

	bodyIssuer, err := xmlutil.SimpleText(requestIssuer, maximumIssuerBytes)
	if err != nil || bodyIssuer != headerIssuer {
		return ErrECP
	}

	return nil
}

func validateChallengeHeaders(paos, request document.Element) error {
	const (
		xmlNameProviderName = "ProviderName"
	)

	if validateHeader(paos, []string{xmlNameResponseConsumerURL, xmlNameService}, []string{xmlNameMessageID}) != nil || !xmlutil.EmptyContent(paos) || xmlutil.Attr(paos, xmlNameService) != Namespace || validateHeader(request, nil, []string{xmlNameIsPassive, xmlNameProviderName}) != nil {
		return ErrECP
	}

	return nil
}

func responseHeaders(headers []document.Element) (document.Element, document.Element, []document.Element, error) {
	var (
		response, relay document.Element
		forward         []document.Element
		authenticated   bool
	)

	for _, h := range headers {
		switch h.Name() {
		case xmlutil.Name(Namespace, xmlNameSubjectConfirmation):
			// checkConfirmation consumes these headers before returning to SP.
		case channelHeaderName():
			// ReadChannelHeaders consumes these; they are never forwarded.
		case xmlutil.Name(Namespace, xmlNameRequestAuthenticated):
			if authenticated || authenticatedHeader(h) != nil {
				return document.Element{}, document.Element{}, nil, ErrECP
			}

			authenticated = true
		case xmlutil.Name(Namespace, xmlNameResponse):
			if response.Valid() {
				return document.Element{}, document.Element{}, nil, ErrECP
			}

			response = h
		case xmlutil.Name(Namespace, fieldRelayState):
			if relay.Valid() || validateRelay(h) != nil {
				return document.Element{}, document.Element{}, nil, ErrECP
			}

			relay = h
		case xmlutil.Name(PAOSNamespace, xmlNameRequest), xmlutil.Name(PAOSNamespace, xmlNameResponse), xmlutil.Name(Namespace, xmlNameRequest):
			return document.Element{}, document.Element{}, nil, ErrECP
		default:
			if actor, _ := h.Attribute(xmlutil.Name(binding.SOAPNamespace, soapActorAttribute)); actor != binding.SOAPNext {
				forward = append(forward, h)
			}
		}
	}

	return response, relay, forward, nil
}
