package ecp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/saml/protocol"
)

// Channel-binding type is an opaque agreed identifier in the extension namespace, not an XML Encryption object Type or a key-selection hint.
const (
	channelTypeAttribute = "Type"
)

// Local name of the SAML channel-binding extension; its presence does not prove a match with the current authenticated transport.
const (
	xmlNameChannelBindings = "ChannelBindings"
)

// SOAP 1.1 mustUnderstand accepts the numeric lexical forms 0 and 1 here; ECP creation emits mandatory 1 and validates the processing actor separately.
const (
	soapBooleanFalse = "0"
)

// TLSServerEndPoint is the RFC 5929 channel binding required by ECP 2.0 CS01.
const TLSServerEndPoint = "tls-server-end-point"

// TLSExporterBinding derives the RFC 9266 binding from a completed TLS 1.3
// connection. The caller must use it for one authentication instance and close
// that connection afterwards (RFC 9266 4.1). Legacy TLS requires additional EMS
// and renegotiation guarantees and is deliberately rejected by this helper.
func TLSExporterBinding(state *tls.ConnectionState) (protocol.ChannelBinding, error) {
	const (
		tlsExporterBytes = 32
		tlsExporterLabel = "EXPORTER-Channel-Binding"
		tlsExporterType  = "tls-exporter"
	)

	if state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 {
		return protocol.ChannelBinding{}, ErrECP
	}

	data, err := state.ExportKeyingMaterial(tlsExporterLabel, nil, tlsExporterBytes)
	if err != nil {
		return protocol.ChannelBinding{}, err
	}

	return protocol.ChannelBinding{Type: tlsExporterType, Data: data}, nil
}

// ServerCertificateBinding hashes the actual TLS server's DER certificate using
// RFC 5929 section 4.1. It does not authenticate the certificate. A client must
// use its verified TLS peer certificate; a server uses the certificate selected
// for that same connection. Do not obtain it by probing another connection.
// Signature algorithms without a single defined hash are rejected, not guessed.
func ServerCertificateBinding(cert *x509.Certificate) (protocol.ChannelBinding, error) {
	if cert == nil {
		return protocol.ChannelBinding{}, ErrECP
	}

	parsed, err := x509.ParseCertificate(cert.Raw)
	if err != nil {
		return protocol.ChannelBinding{}, ErrECP
	}

	var data []byte

	switch parsed.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1,
		x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		hash := sha256.Sum256(parsed.Raw)
		data = hash[:]
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		hash := sha512.Sum384(parsed.Raw)
		data = hash[:]
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		hash := sha512.Sum512(parsed.Raw)
		data = hash[:]
	default:
		return protocol.ChannelBinding{}, ErrECP
	}

	return protocol.ChannelBinding{Type: TLSServerEndPoint, Data: data}, nil
}

// AdvertiseChannelBindings negotiates the ECP 2.0 channel binding option. The
// caller must supply actual transport data to ParseChallengeWithBindings.
func AdvertiseChannelBindings(h http.Header) {
	Advertise(h)
	h.Set(headerPAOS, h.Get(headerPAOS)+`, "`+protocol.ChannelBindingNamespace+`"`)
}

// NegotiatedChannelBindings reports the client's explicit ECP channel-binding
// option. A service provider must check this before requesting bindings.
func NegotiatedChannelBindings(h http.Header) bool {
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
			if err == nil && value == protocol.ChannelBindingNamespace {
				return true
			}
		}
	}

	return false
}

// ParseChallengeWithBindings uses channel data from the authenticated SP HTTP
// exchange. It requires the SP to request at least one supported binding, and
// fails if the SP ignores negotiation. Finish requires the IdP's confirmation.
func ParseChallengeWithBindings(ctx context.Context, raw []byte, resourceURL string, bindings []protocol.ChannelBinding, limits binding.SOAPOptions) (*Exchange, error) {
	if len(bindings) == 0 || protocol.ValidateChannelBindings(bindings, false) != nil {
		return nil, ErrECP
	}

	x, err := parseChallenge(ctx, raw, resourceURL, bindings, limits)
	if err == nil {
		if !x.bearer {
			return nil, ErrECP
		}

		x.holder = false
	}

	return x, err
}

func channelHeaderName() document.Name {
	return xmlutil.Name(protocol.ChannelBindingNamespace, xmlNameChannelBindings)
}

func channelHeaders(ctx context.Context, values []protocol.ChannelBinding, empty bool) ([]document.Element, error) {
	const (
		prefixChannelBinding = "cb"
	)

	if err := protocol.ValidateChannelBindings(values, empty); err != nil {
		return nil, err
	}

	var out []document.Element

	for _, value := range values {
		n := header(protocol.ChannelBindingNamespace, prefixChannelBinding, xmlNameChannelBindings)
		if value.Type != "" {
			xmlutil.Set(n, channelTypeAttribute, value.Type)
		}

		if !empty {
			xmlutil.Text(n, base64.StdEncoding.EncodeToString(value.Data))
		}

		elements, err := headerElements(ctx, n)
		if err != nil {
			return nil, err
		}

		out = append(out, elements...)
	}

	return out, nil
}

// ReadChannelHeaders validates ECP next-actor channel headers. Their bytes are
// untrusted until compared with the authenticated request or local transport.
// allowEmpty admits an IdP verification signal; false requires actual data.
func ReadChannelHeaders(headers []document.Element, allowEmpty bool) ([]protocol.ChannelBinding, error) {
	return readChannelHeaders(headers, allowEmpty, false)
}

// ReadIDPChannelHeaders reads client/IdP bindings, distinguished by an absent
// SOAP actor. Compare these with the actual local transport, never SP metadata.
func ReadIDPChannelHeaders(headers []document.Element) ([]protocol.ChannelBinding, error) {
	return readChannelHeaders(headers, false, true)
}

func rejectIDPChannelHeaders(headers []document.Element) error {
	values, err := ReadIDPChannelHeaders(headers)
	if err != nil || len(values) != 0 {
		return ErrECP
	}

	return nil
}

func readChannelHeaders(headers []document.Element, allowEmpty, own bool) ([]protocol.ChannelBinding, error) {
	const (
		maximumChannelBindingTextBytes = 8192
	)

	var values []protocol.ChannelBinding

	for _, h := range headers {
		if h.Name() != channelHeaderName() {
			continue
		}

		_, actorPresent := h.Attribute(xmlutil.Name(binding.SOAPNamespace, soapActorAttribute))
		if own == actorPresent {
			continue
		}

		if own {
			for _, a := range h.Attributes() {
				if a.Name == xmlutil.Name(binding.SOAPNamespace, soapMustUnderstandAttribute) && (a.Value == soapBooleanFalse || a.Value == soapBooleanTrue) || a.Name == (document.Name{Local: channelTypeAttribute}) {
					continue
				}

				return nil, ErrECP
			}
		} else if validateHeader(h, nil, []string{channelTypeAttribute}) != nil {
			return nil, ErrECP
		}

		text, err := xmlutil.SimpleText(h, maximumChannelBindingTextBytes)
		if err != nil {
			return nil, err
		}

		text = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}

			return r
		}, text)

		data, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil {
			return nil, ErrECP
		}

		values = append(values, protocol.ChannelBinding{Type: xmlutil.Attr(h, channelTypeAttribute), Data: data})
	}

	return values, protocol.ValidateChannelBindings(values, allowEmpty)
}

// MatchChannelBindings implements the IdP binary comparison in CS01 2.3.6.2.
// An unspecified Type relies on the deployment's out-of-band binding agreement.
// Both sides must supply data or both must omit the extension.
func MatchChannelBindings(signed, received []protocol.ChannelBinding) ([]protocol.ChannelBinding, error) {
	if protocol.ValidateChannelBindings(signed, false) != nil || protocol.ValidateChannelBindings(received, false) != nil {
		return nil, ErrECP
	}

	if len(signed) == 0 && len(received) == 0 {
		return nil, nil
	}

	for _, a := range signed {
		for _, b := range received {
			if (a.Type == b.Type || a.Type == "" || b.Type == "") && bytes.Equal(a.Data, b.Data) {
				return protocol.CloneChannelBindings([]protocol.ChannelBinding{a}), nil
			}
		}
	}

	return nil, ErrECP
}

func requestedChannels(headers []document.Element, trusted []protocol.ChannelBinding) ([]protocol.ChannelBinding, error) {
	requested, err := ReadChannelHeaders(headers, true)
	if err != nil || len(requested) == 0 && len(trusted) != 0 || len(requested) != 0 && len(trusted) == 0 {
		return nil, ErrECP
	}

	for _, a := range requested {
		if len(a.Data) != 0 {
			return nil, ErrECP
		}

		for _, b := range trusted {
			if a.Type == b.Type || a.Type == "" {
				return protocol.CloneChannelBindings([]protocol.ChannelBinding{b}), nil
			}
		}
	}

	if len(requested) != 0 {
		return nil, ErrECP
	}

	return nil, nil
}

func requestChannels(request *document.Document) ([]protocol.ChannelBinding, error) {
	const (
		xmlNameExtensions = "Extensions"
	)

	var values []protocol.ChannelBinding

	for _, c := range request.Root().Children() {
		if c.Name() != xmlutil.Name(protocol.ProtocolNamespace, xmlNameExtensions) {
			continue
		}

		for _, h := range c.Children() {
			if h.Name() != channelHeaderName() {
				return nil, ErrECP
			}

			values = append(values, protocol.ChannelBinding{Type: xmlutil.Attr(h, channelTypeAttribute)})
		}
	}

	return values, protocol.ValidateChannelBindings(values, true)
}

func authenticatedHeader(h document.Element) error {
	for _, a := range h.Attributes() {
		if a.Name.Space != binding.SOAPNamespace || a.Name.Local != soapActorAttribute && a.Name.Local != soapMustUnderstandAttribute {
			return ErrECP
		}
	}

	actor, _ := h.Attribute(xmlutil.Name(binding.SOAPNamespace, soapActorAttribute))

	understand, present := h.Attribute(xmlutil.Name(binding.SOAPNamespace, soapMustUnderstandAttribute))
	if actor != binding.SOAPNext || present && understand != soapBooleanFalse && understand != soapBooleanTrue || !xmlutil.EmptyContent(h) {
		return ErrECP
	}

	return nil
}
