package xades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/fips140"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/xmldsig"
)

func parseBaselineSigned(ctx context.Context, layout baselineLayout, certificate *x509.Certificate, options BaselineVerifyOptions, verified *xmldsig.SignatureResult) (*BaselineResult, error) {
	limits, err := normalizeDataTimestampLimits(options.DataTimestamps)
	if err != nil {
		return nil, err
	}

	result := &BaselineResult{basic: &BasicResult{}}
	if err := parseBaselineSignatureClaims(ctx, layout.signature, certificate, options, verified, result); err != nil {
		return nil, err
	}

	if result.signingTime == "" || len(result.certificates) == 0 {
		return nil, ErrProfile
	}

	if layout.data.Valid() {
		if err := parseBaselineDataClaims(ctx, layout.data, verified, limits, options, result); err != nil {
			return nil, err
		}
	}

	if err := checkBaselineDataBindings(layout, verified, result, options); err != nil {
		return nil, err
	}

	if len(result.data) == 1 {
		result.basic.mimeType = result.data[0].MIMEType
	}

	return result, nil
}

func parseBaselineSignatureClaims(ctx context.Context, element document.Element, certificate *x509.Certificate, options BaselineVerifyOptions, verified *xmldsig.SignatureResult, result *BaselineResult) error {
	values, err := baselineContent(element)
	if err != nil {
		return err
	}

	previous := -1

	for _, child := range values {
		if err := ctx.Err(); err != nil {
			return err
		}

		order := slices.Index([]document.Name{name("SigningTime"), name("SigningCertificateV2"), name("SignaturePolicyIdentifier"), name("SignatureProductionPlaceV2"), name("SignerRoleV2")}, child.Name())
		if order < 0 || order <= previous {
			return ErrProfile
		}

		previous = order
		switch order {
		case 0:
			result.signingTime, result.basic.claimedTime, err = parseBaselineTime(child)
		case 1:
			result.certificates, err = parseBaselineCertificates(ctx, child, certificate, options, verified)
		case 2:
			result.policy, err = parseBaselinePolicy(ctx, child, options)
		case 3:
			result.place, err = parseProductionPlace(child)
		case 4:
			err = parseBaselineRoles(ctx, child, result)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func parseBaselineDataClaims(ctx context.Context, element document.Element, verified *xmldsig.SignatureResult, limits DataTimestampLimits, options BaselineVerifyOptions, result *BaselineResult) error {
	values, err := baselineContent(element)
	if err != nil {
		return err
	}

	previous := 0

	for _, child := range values {
		stage, err := parseBaselineDataClaim(ctx, child, verified, limits, options, result)
		if err != nil {
			return err
		}

		if stage < previous {
			return ErrProfile
		}

		previous = stage
	}

	return nil
}

func parseBaselineDataClaim(ctx context.Context, child document.Element, verified *xmldsig.SignatureResult, limits DataTimestampLimits, options BaselineVerifyOptions, result *BaselineResult) (int, error) {
	switch child.Name() {
	case name("DataObjectFormat"):
		value, err := parseDataObjectFormat(child)
		if err != nil {
			return 0, err
		}

		result.data = append(result.data, value)

		return 0, nil
	case name("CommitmentTypeIndication"):
		value, err := parseCommitment(child)
		if err != nil {
			return 0, err
		}

		result.commitments = append(result.commitments, value)

		return 1, nil
	case name("AllDataObjectsTimeStamp"), name("IndividualDataObjectsTimeStamp"):
		if len(result.dataTimestamps) >= limits.MaxTimestamps {
			return 0, ErrProfile
		}

		value, err := parseBaselineDataTimestamp(ctx, child, verified, limits, options)
		if err != nil {
			return 0, err
		}

		result.dataTimestamps = append(result.dataTimestamps, value)

		if child.Name() == name("IndividualDataObjectsTimeStamp") {
			return 3, nil
		}

		return 2, nil
	default:
		return 0, ErrProfile
	}
}

func buildBaselineProperties(ctx context.Context, certificate *x509.Certificate, signatureID, propertiesID string, properties BaselineProperties, options BaselineVerifyOptions) (*document.Document, error) {
	qp := xnode("QualifyingProperties")
	qp.NS = []tree.Namespace{{Prefix: nameXades, URI: Namespace}, {Prefix: "ds", URI: xmldsig.Namespace}, {Prefix: prefixXades141, URI: Namespace141}}
	attr(qp, "Target", "#"+signatureID)

	sp := xnode("SignedProperties")
	attr(sp, "Id", propertiesID)
	add(qp, sp)

	ssp, err := buildBaselineSignatureClaims(ctx, certificate, properties, options)
	if err != nil {
		return nil, err
	}

	add(sp, ssp)

	data, err := buildBaselineDataClaims(ctx, properties, options)
	if err != nil {
		return nil, err
	}

	if len(data.Children) > 0 {
		add(sp, data)
	}

	return tree.FromNodes([]*tree.Node{qp}, document.DefaultLimits()), nil
}

func buildBaselineSignatureClaims(ctx context.Context, certificate *x509.Certificate, properties BaselineProperties, options BaselineVerifyOptions) (*tree.Node, error) {
	value, err := baselineSigningTimeText(properties)
	if err != nil {
		return nil, err
	}

	ssp := xnode("SignedSignatureProperties")
	leaf(ssp, "SigningTime", value)

	sc := xnode("SigningCertificateV2")

	identifiers := append([]CertificateIdentifier{{DER: certificate.Raw, DigestMethod: properties.SigningCertificateDigest}}, properties.AdditionalCertificates...)
	if len(identifiers) > 64 {
		return nil, ErrProfile
	}

	for _, identifier := range identifiers {
		value, err := buildBaselineCertificate(ctx, identifier, options)
		if err != nil {
			return nil, err
		}

		add(sc, value)
	}

	add(ssp, sc)

	if properties.Policy != nil {
		value, err := buildBaselinePolicy(ctx, *properties.Policy, options)
		if err != nil {
			return nil, err
		}

		add(ssp, value)
	}

	if properties.ProductionPlace != nil {
		value, err := buildProductionPlace(*properties.ProductionPlace)
		if err != nil {
			return nil, err
		}

		add(ssp, value)
	}

	if len(properties.ClaimedRoles)+len(properties.CertifiedRoles)+len(properties.SignedAssertions) > 0 {
		value, err := buildBaselineRoles(ctx, properties)
		if err != nil {
			return nil, err
		}

		add(ssp, value)
	}

	return ssp, nil
}

func baselineSigningTimeText(properties BaselineProperties) (string, error) {
	value := properties.SigningTimeLexical
	if value != "" {
		if !properties.SigningTime.IsZero() {
			return "", ErrProfile
		}
	} else {
		if properties.SigningTime.IsZero() {
			return "", ErrProfile
		}

		value = properties.SigningTime.UTC().Format(time.RFC3339Nano)
	}

	_, err := parseBaselineUTC(value)

	return value, err
}

func buildBaselineCertificate(ctx context.Context, identifier CertificateIdentifier, options BaselineVerifyOptions) (*tree.Node, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c, err := cert(identifier.DER)
	if err != nil {
		return nil, err
	}

	out := xnode("Cert")

	digest, err := baselineDigestNode(ctx, "CertDigest", identifier.DigestMethod, c.Raw, options)
	if err != nil {
		return nil, err
	}

	add(out, digest)

	if identifier.IncludeIssuerSerial {
		encoded, err := baselineIssuerSerial(c)
		if err != nil {
			return nil, err
		}

		leaf(out, "IssuerSerialV2", base64.StdEncoding.EncodeToString(encoded))
	}

	return out, nil
}

func buildProductionPlace(value ProductionPlace) (*tree.Node, error) {
	out := xnode("SignatureProductionPlaceV2")
	names := productionPlaceNames()

	for i, field := range []string{value.City, value.StreetAddress, value.StateOrProvince, value.PostalCode, value.CountryName} {
		if field != "" {
			leaf(out, names[i], field)
		}
	}

	if len(out.Children) == 0 {
		return nil, ErrProfile
	}

	return out, nil
}

func buildBaselineDataClaims(ctx context.Context, properties BaselineProperties, options BaselineVerifyOptions) (*tree.Node, error) {
	limits, err := normalizeDataTimestampLimits(options.DataTimestamps)
	if err != nil {
		return nil, err
	}

	if len(properties.DataTimestamps) > limits.MaxTimestamps {
		return nil, ErrProfile
	}

	out := xnode("SignedDataObjectProperties")

	for _, format := range properties.DataObjects {
		value, err := buildDataObjectFormat(format)
		if err != nil {
			return nil, err
		}

		add(out, value)
	}

	for _, commitment := range properties.Commitments {
		value, err := buildCommitment(ctx, commitment)
		if err != nil {
			return nil, err
		}

		add(out, value)
	}

	for _, individual := range []bool{false, true} {
		if err := appendBaselineDataTimes(ctx, out, properties.DataTimestamps, individual, limits); err != nil {
			return nil, err
		}
	}

	return out, nil
}

func appendBaselineDataTimes(ctx context.Context, parent *tree.Node, values []DataTimestampProperty, individual bool, limits DataTimestampLimits) error {
	for _, value := range values {
		if value.Individual != individual {
			continue
		}

		node, err := buildBaselineDataTimestamp(ctx, value, limits)
		if err != nil {
			return err
		}

		add(parent, node)
	}

	return nil
}

func baselineContent(element document.Element) ([]document.Element, error) {
	_, node := tree.Unwrap(element)
	if node == nil {
		return nil, ErrProfile
	}

	for _, child := range node.Children {
		if child.Kind == tree.TextNode && !tree.IsXMLSpace(child.Data) {
			return nil, ErrProfile
		}
	}

	return element.Children(), nil
}

func baselineURI(value string) bool {
	if len(value) > 8192 {
		return false
	}

	_, err := url.Parse(value)

	return err == nil && !strings.ContainsRune(value, 0)
}

func leaf(parent *tree.Node, local, value string) *tree.Node {
	n := xnode(local)
	text(n, value)
	add(parent, n)

	return n
}

func baselinePropertyValue(ctx context.Context, value PropertyValue, expected document.Name) (*tree.Node, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if value.XML.Valid() {
		if value.Text != "" || value.XML.Name() != expected {
			return nil, ErrProfile
		}

		_, n := tree.Unwrap(value.XML)

		return tree.ImportSubtree(n), nil
	}

	n := xnode(expected.Local)

	n.Name = expected
	if expected.Space == Namespace141 {
		n.Prefix = prefixXades141
	}

	text(n, value.Text)

	return n, nil
}

func baselineHash(method string, options BaselineVerifyOptions) (crypto.Hash, error) {
	switch method {
	case xmldsig.SHA256:
		return crypto.SHA256, nil
	case xmldsig.SHA384:
		return crypto.SHA384, nil
	case xmldsig.SHA512:
		return crypto.SHA512, nil
	case xmldsig.SHA1:
		if !fips140.Enabled() && slices.Contains(options.Signature.Policy.AllowedDigestMethods, method) {
			return crypto.SHA1, nil
		}
	}

	return 0, ErrProfile
}

func baselineDigestNode(ctx context.Context, local, method string, data []byte, options BaselineVerifyOptions) (*tree.Node, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if method == "" {
		method = xmldsig.SHA256
	}

	h, err := baselineHash(method, options)
	if err != nil {
		return nil, err
	}

	sum, err := signature.Sum(h, data)
	if err != nil {
		return nil, err
	}

	node := xnode(local)
	dm := dsnode("DigestMethod")
	attr(dm, "Algorithm", method)
	add(node, dm)

	dv := dsnode("DigestValue")
	text(dv, base64.StdEncoding.EncodeToString(sum))
	add(node, dv)

	return node, nil
}

func parseBaselineDigest(ctx context.Context, element document.Element, options BaselineVerifyOptions) (string, []byte, error) {
	if attrs(element) != nil {
		return "", nil, ErrProfile
	}

	elements, err := children(element, ds("DigestMethod"), ds("DigestValue"))
	if err != nil {
		return "", nil, err
	}

	if attrs(elements[0], "Algorithm") != nil || len(elements[0].Children()) != 0 || !tree.IsXMLSpace(elements[0].Text()) {
		return "", nil, ErrProfile
	}

	method := localAttribute(elements[0], "Algorithm")

	h, err := baselineHash(method, options)
	if err != nil {
		return "", nil, err
	}

	if attrs(elements[1]) != nil {
		return "", nil, ErrProfile
	}

	sum, err := decodeElementBase64(ctx, elements[1], 256, h.Size())
	if err != nil || len(sum) != h.Size() {
		return "", nil, errors.Join(ErrProfile, err)
	}

	return method, sum, nil
}

func parseBaselineCertificates(ctx context.Context, element document.Element, signer *x509.Certificate, options BaselineVerifyOptions, verified *xmldsig.SignatureResult) ([]CertificateReference, error) {
	if attrs(element) != nil {
		return nil, ErrProfile
	}

	entries, err := baselineContent(element)
	if err != nil || len(entries) == 0 || len(entries) > 64 {
		return nil, ErrProfile
	}

	embedded, err := baselineEmbeddedCertificates(ctx, verified.Signature(), signer.Raw)
	if err != nil {
		return nil, err
	}

	candidates := make([][]byte, 0, 1+len(options.CertificateValues)+len(embedded))
	candidates = append(candidates, signer.Raw)
	candidates = append(candidates, options.CertificateValues...)

	candidates = append(candidates, embedded...)
	if len(candidates) > 256 {
		return nil, ErrProfile
	}

	out := make([]CertificateReference, 0, len(entries))

	for i, entry := range entries {
		pool := candidates
		if i == 0 {
			pool = [][]byte{signer.Raw}
		}

		value, err := parseBaselineCertificate(ctx, entry, pool, options)
		if err != nil {
			return nil, err
		}

		out = append(out, value)
	}

	return out, nil
}

func parseBaselineCertificate(ctx context.Context, entry document.Element, candidates [][]byte, options BaselineVerifyOptions) (CertificateReference, error) {
	var out CertificateReference
	if err := ctx.Err(); err != nil {
		return out, err
	}

	values, err := baselineContent(entry)
	if entry.Name() != name("Cert") || baselineAttrs(entry, nil, "URI") != nil || err != nil || len(values) < 1 || len(values) > 2 || values[0].Name() != name("CertDigest") {
		return out, ErrProfile
	}

	method, sum, err := parseBaselineDigest(ctx, values[0], options)
	if err != nil {
		return out, err
	}

	matched, err := matchBaselineCertificate(candidates, method, sum, options)
	if err != nil {
		return out, err
	}

	out = CertificateReference{digestMethod: method, digest: sum, certificate: matched, uri: localAttribute(entry, "URI")}
	if !baselineURI(out.uri) {
		return out, ErrProfile
	}

	if len(values) == 2 {
		if values[1].Name() != name("IssuerSerialV2") || attrs(values[1]) != nil {
			return out, ErrProfile
		}

		out.issuerSerial, err = decodeElementBase64(ctx, values[1], 32768, 16384)
		if err != nil {
			return out, err
		}

		if err := checkBaselineIssuerSerial(out.issuerSerial); err != nil {
			return out, err
		}
	}

	return out, nil
}

func matchBaselineCertificate(candidates [][]byte, method string, sum []byte, options BaselineVerifyOptions) ([]byte, error) {
	h, err := baselineHash(method, options)
	if err != nil {
		return nil, err
	}

	for _, candidate := range candidates {
		if len(candidate) > 1<<20 {
			return nil, ErrCertificate
		}

		digest, err := signature.Sum(h, candidate)
		if err != nil {
			return nil, err
		}

		if subtle.ConstantTimeCompare(digest, sum) == 1 {
			c, err := cert(candidate)
			if err != nil {
				return nil, err
			}

			return c.Raw, nil
		}
	}

	return nil, ErrCertificate
}

func baselineIssuerSerial(certificate *x509.Certificate) ([]byte, error) {
	issuer, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 4, IsCompound: true, Bytes: certificate.RawIssuer})
	if err != nil {
		return nil, err
	}

	names, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: issuer})
	if err != nil {
		return nil, err
	}

	serial, err := asn1.Marshal(certificate.SerialNumber)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(names, serial...)})
}

func checkBaselineIssuerSerial(raw []byte) error {
	value, err := der.Read(raw, 16384)
	if err != nil {
		return errors.Join(ErrProfile, err)
	}

	fields, err := der.Sequence(value, 2, 2)
	if err != nil {
		return ErrProfile
	}

	names, err := der.Sequence(fields[0], 1, 32)
	if err != nil {
		return ErrProfile
	}

	for _, name := range names {
		if name.Class != 2 || name.Tag != 4 || !name.IsCompound {
			return ErrProfile
		}

		v, err := der.Explicit(name, 4)
		if err != nil || !der.Is(v, 0, asn1.TagSequence, true) {
			return ErrProfile
		}
	}

	var serial *big.Int
	if der.Decode(fields[1], &serial) != nil || serial == nil || serial.Sign() <= 0 {
		return ErrProfile
	}

	return nil
}

func productionPlaceNames() []string {
	return []string{"City", "StreetAddress", "StateOrProvince", "PostalCode", "CountryName"}
}

func parseProductionPlace(element document.Element) (*ProductionPlace, error) {
	if attrs(element) != nil {
		return nil, ErrProfile
	}

	values, err := baselineContent(element)
	if err != nil || len(values) == 0 {
		return nil, ErrProfile
	}

	place := &ProductionPlace{}
	dest := []*string{&place.City, &place.StreetAddress, &place.StateOrProvince, &place.PostalCode, &place.CountryName}
	previous := -1

	for _, value := range values {
		index := -1

		for i, local := range productionPlaceNames() {
			if value.Name() == name(local) {
				index = i
				break
			}
		}

		if index < 0 || index >= len(dest) || index <= previous {
			return nil, ErrProfile
		}

		previous = index

		field, parseErr := simple(value)
		err = parseErr

		for i, destination := range dest {
			if i == index {
				*destination = field
			}
		}

		if err != nil {
			return nil, err
		}
	}

	return place, nil
}

func baselineEmbeddedCertificates(ctx context.Context, sig document.Element, signer []byte) ([][]byte, error) {
	keyInfo, err := childNamed(sig, ds("KeyInfo"))
	if err != nil {
		return nil, ErrProfile
	}

	var out [][]byte

	dataCount := 0
	found := false

	for _, data := range keyInfo.Children() {
		if data.Name() != ds("X509Data") {
			continue
		}

		dataCount++

		for _, value := range data.Children() {
			if value.Name() != ds("X509Certificate") {
				continue
			}

			raw, err := decodeElementBase64(ctx, value, 2<<20, 1<<20)
			if err != nil {
				return nil, err
			}

			out = append(out, raw)
			if bytes.Equal(raw, signer) {
				found = true
			}

			if len(out) > 64 {
				return nil, ErrProfile
			}
		}
	}

	if dataCount != 1 || !found {
		return nil, ErrCertificate
	}

	return out, nil
}
