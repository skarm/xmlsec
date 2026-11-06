package protocol

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

// HoK xsi:type must resolve to this SAML assertion type; matching the QName does not replace exact certificate-byte possession checks.
const (
	confirmationDataTypeName = "KeyInfoConfirmationDataType"
)

// HoK certificates are bounded by decoded DER bytes, independently of the
// larger base64 text ceiling used while reading XML.
const (
	maximumHoKCertificateBytes = 64 << 10
)

// HolderOfKey is the SAML proof-of-possession subject-confirmation method.
const HolderOfKey = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"

const xsiNamespace = lexicon.NamespaceXSI

// HolderOfKeyData constructs the same confirmation data as the assertion
// producer, including for assertions encrypted before an ECP header is formed.
func HolderOfKeyData(ctx context.Context, certificate []byte, recipient, requestID string) (document.Element, error) {
	if !profile.Endpoint(recipient, false) || !profile.ID(requestID) {
		return document.Element{}, ErrProfile
	}

	n := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameSubjectConfirmationData)

	n.NS = []tree.Namespace{{Prefix: prefixAssertion, URI: AssertionNamespace}, {Prefix: lexicon.PrefixDSig, URI: xmlutil.DS}}
	if err := setConfirmationKey(n, certificate); err != nil {
		return document.Element{}, err
	}

	xmlutil.Set(n, nameRecipient, recipient)
	xmlutil.Set(n, nameInResponseTo, requestID)

	d, err := xmlutil.Document(ctx, n)
	if err != nil {
		return document.Element{}, err
	}

	return d.Root(), nil
}

func confirmationNode(s Response) (*tree.Node, error) {
	conf := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameSubjectConfirmation)
	data := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameSubjectConfirmationData)

	method := Bearer
	if len(s.Assertion.HolderOfKeyCertificate) != 0 {
		method = HolderOfKey

		if err := setConfirmationKey(data, s.Assertion.HolderOfKeyCertificate); err != nil {
			return nil, err
		}
	}

	xmlutil.Set(conf, nameMethod, method)
	xmlutil.Set(data, nameRecipient, s.Destination)
	xmlutil.Set(data, nameInResponseTo, s.InResponseTo)

	if method == Bearer {
		xmlutil.Set(data, nameNotOnOrAfter, profile.Time(s.Assertion.NotOnOrAfter))
	}

	xmlutil.Add(conf, data)

	return conf, nil
}

func setConfirmationKey(data *tree.Node, raw []byte) error {
	const (
		prefixSchemaInstance                = "xsi"
		qualifiedConfirmationDataTypeSuffix = ":" + confirmationDataTypeName
	)

	if len(raw) == 0 || len(raw) > maximumHoKCertificateBytes {
		return ErrProfile
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil || signature.Key(cert.PublicKey) != nil {
		return ErrProfile
	}

	data.NS = append(data.NS, tree.Namespace{Prefix: prefixSchemaInstance, URI: xsiNamespace})
	data.Attrs = append(data.Attrs, tree.Attribute{Name: xmlutil.Name(xsiNamespace, lexicon.AttrType), Prefix: prefixSchemaInstance, Value: prefixAssertion + qualifiedConfirmationDataTypeSuffix})
	info := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementKeyInfo)
	x509data := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementX509Data)
	leaf := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementX509Certificate)
	xmlutil.Text(leaf, base64.StdEncoding.EncodeToString(cert.Raw))
	xmlutil.Add(x509data, leaf)
	xmlutil.Add(info, x509data)
	xmlutil.Add(data, info)

	return nil
}

func parseHoKConfirmation(c document.Element, o ResponseOptions, l Limits, r *VerifiedAssertion) error {
	if o.Proof == nil && len(o.producedCertificate) == 0 || xmlutil.Attrs(c, []string{nameMethod}, nil) != nil || xmlutil.Attr(c, nameMethod) != HolderOfKey {
		return ErrConditions
	}

	cs, err := xmlutil.Children(c)
	if err != nil || len(cs) != 1 || cs[0].Name() != xmlutil.Name(AssertionNamespace, xmlNameSubjectConfirmationData) {
		return ErrProfile
	}

	data := cs[0]
	// HoK timestamps are optional and have certificate-specific semantics. Our
	// producer omits them and the assertion Conditions supply the validity bound.
	if err := confirmationAttributes(data); err != nil {
		return err
	}

	if recipient, present := data.Attribute(document.Name{Local: nameRecipient}); present && recipient != o.Destination {
		return ErrCorrelation
	}

	if request, present := data.Attribute(document.Name{Local: nameInResponseTo}); present && request != o.ExpectedRequestID {
		return ErrCorrelation
	}

	expected := o.producedCertificate
	if o.Proof != nil {
		expected = o.Proof.Certificate()
	}

	if err := MatchConfirmationCertificate(data, expected); err != nil {
		return ErrConditions
	}

	if err := confirmationTimes(data, o, l, r); err != nil {
		return err
	}

	r.confirmation = HolderOfKey
	r.hokCertificate = bytes.Clone(expected)

	return nil
}

// MatchConfirmationCertificate implements the X509Certificate matching form.
// Multiple KeyInfo elements are alternatives; no PKIX/name trust is inferred.
func MatchConfirmationCertificate(data document.Element, expected []byte) error {
	if data.Name() != xmlutil.Name(AssertionNamespace, xmlNameSubjectConfirmationData) || confirmationAttributes(data) != nil {
		return ErrProfile
	}

	certificates, err := confirmationCertificates(data)
	if err != nil {
		return err
	}

	for _, certificate := range certificates {
		if bytes.Equal(certificate, expected) {
			return nil
		}
	}

	return ErrConditions
}

func confirmationCertificates(data document.Element) ([][]byte, error) {
	const (
		maximumHoKKeyInfos = 8
	)

	cs, err := xmlutil.Children(data)
	if err != nil || len(cs) == 0 || len(cs) > maximumHoKKeyInfos {
		return nil, ErrProfile
	}

	var result [][]byte

	for _, info := range cs {
		if info.Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementKeyInfo) || xmlutil.Attrs(info, nil, []string{lexicon.SecurityAttrID}) != nil {
			return nil, ErrProfile
		}

		x, err := xmlutil.Children(info)
		if err != nil || len(x) != 1 || x[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementX509Data) || xmlutil.Attrs(x[0], nil, nil) != nil {
			return nil, ErrProfile
		}

		certificates, err := confirmationX509Data(x[0])
		if err != nil {
			return nil, err
		}

		result = append(result, certificates...)
	}

	if result == nil {
		return nil, ErrProfile
	}

	return result, nil
}

func confirmationX509Data(data document.Element) ([][]byte, error) {
	const (
		maximumEncodedHoKCertificateBytes = 128 << 10
		maximumHoKCertificateFields       = 8
	)

	fields, err := xmlutil.Children(data)
	if err != nil || len(fields) == 0 || len(fields) > maximumHoKCertificateFields {
		return nil, ErrProfile
	}

	var result [][]byte

	for _, field := range fields {
		if field.Name() == xmlutil.Name(xmlutil.DS, lexicon.DSigElementX509CRL) {
			return nil, ErrProfile
		}

		if field.Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementX509Certificate) {
			continue
		}

		text, err := xmlutil.Simple(field, maximumEncodedHoKCertificateBytes)
		if err != nil {
			return nil, err
		}

		text = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}

			return r
		}, text)

		raw, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil || len(raw) == 0 || len(raw) > maximumHoKCertificateBytes {
			return nil, ErrProfile
		}
		// HoK 2.5 compares decoded bytes; parsing/re-encoding would change it.
		result = append(result, raw)
	}

	return result, nil
}

func confirmationAttributes(data document.Element) error {
	for _, a := range data.Attributes() {
		if a.Name == xmlutil.Name(xsiNamespace, lexicon.AttrType) {
			prefix, local, ok := strings.Cut(a.Value, ":")
			if !ok {
				local = prefix
				prefix = ""
			}

			ns, _ := data.Namespace(prefix)
			if ns != AssertionNamespace || local != confirmationDataTypeName {
				return ErrProfile
			}

			continue
		}

		if a.Name.Space != "" || !allowed(a.Name.Local, []string{nameRecipient, nameInResponseTo, nameNotBefore, nameNotOnOrAfter, nameAddress}) {
			return ErrProfile
		}
	}

	return nil
}

func confirmationTimes(data document.Element, o ResponseOptions, l Limits, r *VerifiedAssertion) error {
	if addr, ok := data.Attribute(document.Name{Local: nameAddress}); ok {
		actual, expected := net.ParseIP(addr), net.ParseIP(o.ExpectedAddress)
		if actual == nil || expected == nil || !actual.Equal(expected) {
			return ErrConditions
		}
	}

	r.expires = o.At.Add(l.MaxAssertionLifetime + l.ClockSkew)

	if value, present := data.Attribute(document.Name{Local: nameNotOnOrAfter}); present {
		end, err := profile.ParseTime(value)
		if err != nil || !o.At.Add(-l.ClockSkew).Before(end) {
			return ErrConditions
		}

		r.expires = end
	}

	if value, present := data.Attribute(document.Name{Local: nameNotBefore}); present {
		start, err := profile.ParseTime(value)
		if err != nil || o.At.Add(l.ClockSkew).Before(start) {
			return ErrConditions
		}

		if _, endPresent := data.Attribute(document.Name{Local: nameNotOnOrAfter}); endPresent && !start.Before(r.expires) {
			return ErrConditions
		}
	}

	return nil
}

// SubjectConfirmationMethod returns the authenticated confirmation method.
func (r *VerifiedAssertion) SubjectConfirmationMethod() string {
	if r == nil {
		return ""
	}

	return r.confirmation
}

// HolderOfKeyCertificate returns the exact matched certificate, not a trust chain.
func (r *VerifiedAssertion) HolderOfKeyCertificate() []byte {
	if r == nil {
		return nil
	}

	return bytes.Clone(r.hokCertificate)
}
