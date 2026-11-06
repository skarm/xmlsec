package ecp

import (
	"bytes"
	"context"
	"crypto/x509"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/saml/proof"
	"github.com/skarm/xmlsec/saml/protocol"
)

// AdvertiseHoK announces the client's ECP 2013 HoK and channel-binding support.
func AdvertiseHoK(h http.Header) {
	AdvertiseChannelBindings(h)
	h.Set(headerPAOS, h.Get(headerPAOS)+", "+strconv.Quote(protocol.HolderOfKey))
}

// HoKNegotiated checks the explicit client option before offering HoK.
func HoKNegotiated(h http.Header) bool {
	if !Negotiated(h) {
		return false
	}

	for _, service := range strings.Split(h.Get(headerPAOS), ";")[1:] {
		options := strings.Split(service, ",")

		name, err := strconv.Unquote(strings.TrimSpace(options[0]))
		if err != nil || name != Namespace {
			continue
		}

		for _, option := range options[1:] {
			value, err := strconv.Unquote(strings.TrimSpace(option))
			if err == nil && value == protocol.HolderOfKey {
				return true
			}
		}
	}

	return false
}

// HoKChallenge offers HoK. The HTTP handler must first check HoKNegotiated.
// The SP must retain a requirement for HoK with its pending authentication state.
func HoKChallenge(ctx context.Context, request protocol.AuthnRequest, key protocol.SigningKey, relay *string, messageID string) (*document.Document, error) {
	return challenge(ctx, request, key, relay, messageID, true)
}

// ParseHoKChallenge selects HoK and the client's exact attesting certificate.
// channels, when requested by the SP, come from the actual client/SP TLS channel.
func ParseHoKChallenge(ctx context.Context, raw []byte, resourceURL string, certificate []byte, channels []protocol.ChannelBinding, limits binding.SOAPOptions) (*Exchange, error) {
	if _, err := x509.ParseCertificate(certificate); err != nil {
		return nil, ErrECP
	}

	x, err := parseChallenge(ctx, raw, resourceURL, channels, limits)
	if err != nil {
		return nil, err
	}

	if !x.holder {
		return nil, ErrECP
	}

	x.certificate = bytes.Clone(certificate)

	return x, nil
}

// VerifyEnvelopedXML recognizes ECP headers and verifies the declared W3C
// enveloped-signature form. The scope of CS01 2.3.11's restriction needs
// clarification; this API does not claim full ECP conformance.
func VerifyEnvelopedXML(ctx context.Context, raw []byte, o proof.Options) (*proof.Verified, error) {
	o.SOAP.Understood = append(slices.Clone(o.SOAP.Understood), knownHeaders()...)
	return proof.VerifyEnvelopedXML(ctx, raw, o)
}

// VerifyCS01CompatXML recognizes ECP headers and verifies only the explicitly
// agreed CS01 no-Transforms compatibility form with nonstandard self-exclusion.
func VerifyCS01CompatXML(ctx context.Context, raw []byte, o proof.Options) (*proof.Verified, error) {
	o.SOAP.Understood = append(slices.Clone(o.SOAP.Understood), knownHeaders()...)
	return proof.VerifyCS01CompatXML(ctx, raw, o)
}

// VerifyTLSRequest obtains proof from the actual server-side TLS request.
func VerifyTLSRequest(ctx context.Context, r *http.Request, o proof.Options) (*proof.Verified, error) {
	o.SOAP.Understood = append(slices.Clone(o.SOAP.Understood), knownHeaders()...)
	return proof.VerifyTLSRequest(ctx, r, o)
}

// WriteIDPResponse writes an ECP SOAP response, including its mandatory headers.
// The response must already be signed for the authenticated request's ACS.
func WriteIDPResponse(ctx context.Context, w http.ResponseWriter, envelope *document.Document) error {
	return binding.WriteSOAPResponseWithOptions(ctx, w, envelope, binding.SOAPOptions{Understood: knownHeaders()})
}

type xmlProofSigner func(context.Context, *document.Document, proof.Signing) (*document.Document, error)

// ToIDPEnvelopedXML signs the IdP-bound message with a declared W3C enveloped
// transform, including any supplied client/IdP channel bindings.
func (x *Exchange) ToIDPEnvelopedXML(ctx context.Context, key proof.Signing, idpChannels []protocol.ChannelBinding) (*document.Document, error) {
	return x.toIDPXML(ctx, key, idpChannels, proof.SignEnvelopedXML)
}

// ToIDPCS01CompatXML creates the explicitly agreed CS01 no-Transforms
// compatibility form. Its self-exclusion rule is not ordinary W3C processing.
func (x *Exchange) ToIDPCS01CompatXML(ctx context.Context, key proof.Signing, idpChannels []protocol.ChannelBinding) (*document.Document, error) {
	return x.toIDPXML(ctx, key, idpChannels, proof.SignCS01CompatXML)
}

func (x *Exchange) toIDPXML(ctx context.Context, key proof.Signing, idpChannels []protocol.ChannelBinding, sign xmlProofSigner) (*document.Document, error) {
	if x == nil || !x.holder || !bytes.Equal(x.certificate, key.Certificate) {
		return nil, ErrECP
	}

	d, err := x.ToIDP(ctx)
	if err != nil {
		return nil, err
	}

	if len(idpChannels) != 0 {
		raw, err := d.XML(ctx)
		if err != nil {
			return nil, err
		}

		m, err := binding.DecodeSOAP(ctx, raw, binding.SOAPOptions{Understood: knownHeaders()})
		if err != nil {
			return nil, err
		}

		body, err := m.Payload(ctx)
		if err != nil {
			return nil, err
		}

		extra, err := channelHeaders(ctx, idpChannels, false)
		if err != nil {
			return nil, err
		}

		for i, h := range extra {
			_, original := tree.Unwrap(h)
			n := tree.ImportSubtree(original)
			n.Attrs = slices.DeleteFunc(n.Attrs, func(a tree.Attribute) bool { return a.Name == xmlutil.Name(binding.SOAPNamespace, soapActorAttribute) })

			one, err := headerElements(ctx, n)
			if err != nil {
				return nil, err
			}

			extra[i] = one[0]
		}

		d, err = binding.WrapSOAP(ctx, body, append(m.Headers(), extra...)...)
		if err != nil {
			return nil, err
		}
	}

	return sign(ctx, d, key)
}

// ResponseHoK adds confirmation data identical to the assertion producer's data.
// certificate must be the proven key explicitly associated with the principal.
func ResponseHoK(ctx context.Context, message *document.Document, destination string, certificate []byte, channels []protocol.ChannelBinding) (*document.Document, error) {
	if message == nil {
		return nil, ErrECP
	}

	data, err := protocol.HolderOfKeyData(ctx, certificate, destination, xmlutil.Attr(message.Root(), xmlNameInResponseTo))
	if err != nil {
		return nil, err
	}

	return responseEnvelope(ctx, message, destination, channels, true, data)
}

// FinishEnvelopedXML checks IdP routing and the HoK certificate, then signs
// the SP-bound message with a declared W3C enveloped transform. Routing faults
// are returned without a proof signature.
func (x *Exchange) FinishEnvelopedXML(ctx context.Context, raw []byte, key proof.Signing, limits binding.SOAPOptions) (*document.Document, error) {
	return x.finishXML(ctx, raw, key, limits, proof.SignEnvelopedXML)
}

// FinishCS01CompatXML checks IdP routing and the HoK certificate, then signs
// using the explicitly agreed CS01 no-Transforms compatibility form. Routing
// faults are returned without a proof signature.
func (x *Exchange) FinishCS01CompatXML(ctx context.Context, raw []byte, key proof.Signing, limits binding.SOAPOptions) (*document.Document, error) {
	return x.finishXML(ctx, raw, key, limits, proof.SignCS01CompatXML)
}

func (x *Exchange) finishXML(ctx context.Context, raw []byte, key proof.Signing, limits binding.SOAPOptions, sign xmlProofSigner) (*document.Document, error) {
	if x == nil || !x.holder || !bytes.Equal(x.certificate, key.Certificate) {
		return nil, ErrECP
	}

	d, err := x.Finish(ctx, raw, limits)
	if err != nil {
		return d, err
	}

	return sign(ctx, d, key)
}

func offeredHoK(headers []document.Element) (bool, bool, error) {
	seen := map[string]bool{}

	for _, h := range headers {
		if h.Name() != xmlutil.Name(Namespace, xmlNameSubjectConfirmation) {
			continue
		}

		method := xmlutil.Attr(h, xmlNameMethod)
		if validateHeader(h, []string{xmlNameMethod}, nil) != nil || !xmlutil.EmptyContent(h) || seen[method] || method != protocol.HolderOfKey && method != protocol.Bearer {
			return false, false, ErrECP
		}

		seen[method] = true
	}

	return seen[protocol.HolderOfKey], len(seen) == 0 || seen[protocol.Bearer], nil
}

func (x *Exchange) checkConfirmation(headers []document.Element, response *document.Document) error {
	const (
		xmlNameStatus                  = "Status"
		xmlNameSubjectConfirmationData = "SubjectConfirmationData"
		xmlNameValue                   = "Value"
	)

	var found document.Element

	for _, h := range headers {
		if h.Name() != xmlutil.Name(Namespace, xmlNameSubjectConfirmation) {
			continue
		}

		if found.Valid() || validateHeader(h, []string{xmlNameMethod}, nil) != nil {
			return ErrECP
		}

		found = h
	}

	success := false

	for _, c := range response.Root().Children() {
		if c.Name() == xmlutil.Name(protocol.ProtocolNamespace, xmlNameStatus) {
			cs, err := xmlutil.Children(c)
			success = err == nil && len(cs) != 0 && xmlutil.Attr(cs[0], xmlNameValue) == protocol.Success
		}
	}

	if !success {
		return nil
	}

	if !x.holder {
		if found.Valid() {
			return ErrECP
		}

		return nil
	}

	if !found.Valid() || xmlutil.Attr(found, xmlNameMethod) != protocol.HolderOfKey {
		return ErrECP
	}

	cs, err := xmlutil.Children(found)
	if err != nil || len(cs) != 1 || cs[0].Name() != xmlutil.Name(protocol.AssertionNamespace, xmlNameSubjectConfirmationData) {
		return ErrECP
	}

	if err := protocol.MatchConfirmationCertificate(cs[0], x.certificate); err != nil {
		return ErrECP
	}

	return nil
}
