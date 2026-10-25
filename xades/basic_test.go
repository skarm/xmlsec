package xades_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

const signedPropertiesLocal = "SignedProperties"

func TestBasicRoundTrip(t *testing.T) {
	d, r, _, der := sign(t)
	if len(r.Signature().References()) != 2 || !r.Signature().CoversElement(d.Root()) || !r.Signature().CoversElement(r.SignedProperties()) {
		t.Fatal("coverage")
	}

	if r.MIMEType() != "application/xml" || r.ClaimedSigningTime().Location() != time.UTC {
		t.Fatal("properties")
	}

	if !bytes.Equal(r.CertificateDER(), der) {
		t.Fatal("cert")
	}

	r.CertificateDER()[0] ^= 1
	if !bytes.Equal(r.CertificateDER(), der) {
		t.Fatal("mutable cert")
	}

	raw, _ := d.XML(t.Context())

	parsed, e := document.Parse(t.Context(), raw, document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	r, e = xades.VerifyBasicEnveloped(context.Background(), parsed, xmldsig.Signatures(parsed)[0], der, xades.VerifyOptions{})
	if e != nil || r == nil {
		t.Fatal(e)
	}
	// Expired at the claimed time is intentionally not a trust check here.
	cert, _ := x509.ParseCertificate(der)
	if !r.ClaimedSigningTime().After(cert.NotAfter) {
		t.Fatal("fixture")
	}

	if len(xmldsig.Signatures(input(t))) != 0 {
		t.Fatal("input changed")
	}
}

func TestBasicProfileRejects(t *testing.T) {
	d, _, k, der := sign(t)
	raw, _ := d.XML(t.Context())
	other := certificate(t, k, 2)

	tests := []struct {
		name, from, to string
		cert           []byte
	}{
		{"target", `Target="#signature"`, `Target="#other"`, der},
		{"wrong-type", `Type="` + xades.SignedPropertiesType + `"`, `Type="urn:wrong"`, der},
		{"format", `ObjectReference="#data-reference"`, `ObjectReference="#signed-properties"`, der},
		{"unsigned-augmentation", `</xades:QualifyingProperties>`, `<xades:UnsignedProperties/></xades:QualifyingProperties>`, der},
		{"wrong-certificate", "", "", other},
		{"swap-keyinfo", base64.StdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(other), der},
		{"payload", `>123<`, `>999<`, der},
		{"no-utc", "13:30:15.000123456Z", "13:30:15.000123456+00:00", der},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := string(raw)
			if tt.from != "" {
				if !strings.Contains(b, tt.from) {
					t.Fatal("fixture string missing")
				}

				b = strings.Replace(b, tt.from, tt.to, 1)
			}

			p, e := document.Parse(t.Context(), []byte(b), document.DefaultLimits())
			if e != nil {
				t.Fatal(e)
			}

			result, e := xades.VerifyBasicEnveloped(context.Background(), p, xmldsig.Signatures(p)[0], tt.cert, xades.VerifyOptions{})
			if e == nil || result != nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestSignedWrongCertificateDigest(t *testing.T) {
	d, _, k, der := sign(t)
	sig := xmldsig.Signatures(d)[0]
	raw, _ := d.XML(t.Context())
	s := string(raw)
	si := sig.Children()[0]
	// Clear only mutable XMLDSig digest/signature leaves, NOT the certificate digest.
	for _, r := range si.Children()[2:] {
		a := r.Children()
		value := a[len(a)-1].Text()
		s = strings.Replace(s, ">"+value+"</ds:DigestValue>", "></ds:DigestValue>", 1)
	}

	value := sig.Children()[1].Text()
	s = strings.Replace(s, ">"+value+"</ds:SignatureValue>", "></ds:SignatureValue>", 1)
	start := strings.Index(s, "<xades:CertDigest>")
	end := strings.Index(s[start:], "</xades:CertDigest>") + start
	part := s[start:end]
	dv := strings.Index(part, "<ds:DigestValue>") + len("<ds:DigestValue>")
	dvEnd := strings.Index(part, "</ds:DigestValue>")
	part = part[:dv] + base64.StdEncoding.EncodeToString(make([]byte, 32)) + part[dvEnd:]
	s = s[:start] + part + s[end:]

	template, e := document.Parse(t.Context(), []byte(s), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	opts := xmldsig.SignatureOptions{AdditionalIDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{{Space: xades.Namespace, Local: signedPropertiesLocal}}}}}

	signed, e := xmldsig.SignTemplate(context.Background(), template, xmldsig.Signatures(template)[0], k, xmldsig.TemplateSignOptions{Validation: opts})
	if e != nil {
		t.Fatal(e)
	}

	if _, e := xmldsig.VerifySignature(context.Background(), signed, xmldsig.Signatures(signed)[0], &k.PublicKey, opts); e != nil {
		t.Fatal("crypto not valid:", e)
	}

	r, e := xades.VerifyBasicEnveloped(context.Background(), signed, xmldsig.Signatures(signed)[0], der, xades.VerifyOptions{})
	if r != nil || !errors.Is(e, xades.ErrCertificate) {
		t.Fatalf("%v", e)
	}
}

func TestBasicInvalidCreation(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := certificate(t, k, 1)
	at := time.Now().UTC()

	o := xades.SignOptions{SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: at}
	for _, tc := range []struct {
		name   string
		change func(*xades.SignOptions)
	}{{"bad-mime", func(o *xades.SignOptions) { o.MIMEType = "bad\nheader" }}, {"collision", func(o *xades.SignOptions) { o.SignedPropertiesID = "signature" }}, {"zero-time", func(o *xades.SignOptions) { o.ClaimedSigningTime = time.Time{} }}, {"bad-id", func(o *xades.SignOptions) { o.SignatureID = "a:b" }}} {
		t.Run(tc.name, func(t *testing.T) {
			x := o
			tc.change(&x)

			d, r, e := xades.SignBasicEnveloped(context.Background(), input(t), k, der, x)
			if e == nil || d != nil || r != nil {
				t.Fatal("accepted")
			}
		})
	}

	var nilKey *ecdsa.PrivateKey
	if _, _, e := xades.SignBasicEnveloped(context.Background(), input(t), nilKey, der, o); e == nil {
		t.Fatal("typed nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, e := xades.SignBasicEnveloped(ctx, input(t), k, der, o); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func FuzzVerifyBasic(f *testing.F) {
	certificate, err := os.ReadFile("../testdata/next/ec256.cert.der")
	if err != nil {
		f.Fatal(err)
	}

	seed, err := os.ReadFile("../testdata/next/ec256.xades.python.xml")
	if err != nil {
		f.Fatal(err)
	}

	ctx := context.Background()

	seedDoc, err := document.Parse(ctx, seed, document.DefaultLimits())
	if err != nil {
		f.Fatal(err)
	}

	selected := xmldsig.Signatures(seedDoc)
	if len(selected) != 1 {
		f.Fatal("expected one signature")
	}

	if _, err = xades.VerifyBasicEnveloped(ctx, seedDoc, selected[0], certificate, xades.VerifyOptions{}); err != nil {
		f.Fatal(err)
	}

	f.Add(seed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}

		d, err := document.Parse(ctx, raw, document.DefaultLimits())
		if err != nil {
			return
		}

		signatures := xmldsig.Signatures(d)
		if len(signatures) != 1 {
			return
		}

		_, _ = xades.VerifyBasicEnveloped(ctx, d, signatures[0], certificate, xades.VerifyOptions{})
	})
}

func BenchmarkVerifyBasic(b *testing.B) {
	d, _, _, cert := sign(b)
	selected := xmldsig.Signatures(d)[0]

	b.ReportAllocs()

	for b.Loop() {
		if _, err := xades.VerifyBasicEnveloped(context.Background(), d, selected, cert, xades.VerifyOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

func TestAuthenticatedSigningTimeLexicalForm(t *testing.T) {
	d, _, key, certificate := sign(t)
	options := xmldsig.SignatureOptions{AdditionalIDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{{Space: xades.Namespace, Local: signedPropertiesLocal}}}}}

	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"2026-10-07T13:30:15Z", true},
		{"2026-10-07T13:30:15.100Z", true},
		{"2026-10-07T24:00:00Z", true},
		{"2026-10-07T3:30:15Z", false},
		{"2026-10-07T13:30:15,1Z", false},
		{"2026-10-07T13:30:15.1234567891Z", false},
		{"2026-10-07T24:00:00.1Z", false},
		{"0000-10-07T13:30:15Z", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			template := signingTimeTemplate(t, d, tc.value)

			signed, err := xmldsig.SignTemplate(context.Background(), template, xmldsig.Signatures(template)[0], key, xmldsig.TemplateSignOptions{Validation: options})
			if err != nil {
				t.Fatal(err)
			}

			selected := xmldsig.Signatures(signed)[0]
			if _, err := xmldsig.VerifySignature(context.Background(), signed, selected, key.Public(), options); err != nil {
				t.Fatal("control must have a valid signature", err)
			}

			result, err := xades.VerifyBasicEnveloped(context.Background(), signed, selected, certificate, xades.VerifyOptions{})
			if !tc.valid {
				if result != nil || !errors.Is(err, xades.ErrProfile) {
					t.Fatalf("invalid/unsupported dateTime accepted: result=%v, error=%v", result != nil, err)
				}

				return
			}

			if err != nil || result == nil {
				t.Fatal("valid dateTime rejected", err)
			}

			if tc.value == "2026-10-07T24:00:00Z" && !result.ClaimedSigningTime().Equal(time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)) {
				t.Fatal("midnight was not normalized", result.ClaimedSigningTime())
			}
		})
	}
}

func signingTimeTemplate(t *testing.T, d *document.Document, lexical string) *document.Document {
	t.Helper()

	draft, err := tree.Clone(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}

	clearSignatureValues(xmldsig.Signatures(draft)[0])
	changeSigningTime(tree.Root(draft), lexical)

	raw, err := draft.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	template, err := document.Parse(t.Context(), raw, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	return template
}

func clearSignatureValues(sig document.Element) {
	_, value := tree.Unwrap(sig.Children()[1])
	value.Children = nil

	for _, ref := range sig.Children()[0].Children()[2:] {
		fields := ref.Children()
		_, digest := tree.Unwrap(fields[len(fields)-1])
		digest.Children = nil
	}
}

func changeSigningTime(n *tree.Node, value string) {
	if n.Name == (document.Name{Space: xades.Namespace, Local: "SigningTime"}) {
		n.Children = []*tree.Node{{Kind: tree.TextNode, Data: value, Parent: n}}

		return
	}

	for _, child := range n.Children {
		changeSigningTime(child, value)
	}
}

func certificate(t testing.TB, key *ecdsa.PrivateKey, serial int64) []byte {
	t.Helper()

	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "xades test"}, NotBefore: at, NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}

	der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}

	return der
}

func input(t testing.TB) *document.Document {
	t.Helper()

	d, e := document.Parse(t.Context(), []byte(`<invoice xmlns="urn:test:invoice" ID="invoice-1"><Amount>123</Amount></invoice>`), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	return d
}

func sign(t testing.TB) (*document.Document, *xades.BasicResult, *ecdsa.PrivateKey, []byte) {
	t.Helper()

	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	der := certificate(t, k, 1)

	d, r, e := xades.SignBasicEnveloped(context.Background(), input(t), k, der, xades.SignOptions{SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: time.Date(2026, 10, 7, 18, 30, 15, 123456, time.FixedZone("+05", 5*3600))})
	if e != nil {
		t.Fatal(e)
	}

	return d, r, k, der
}

func TestCertificateEncodingConsistency(t *testing.T) {
	chain := testcert.New(t)
	for _, test := range testcert.CertificateEncodings(t, chain) {
		t.Run(test.Name, func(t *testing.T) {
			before := bytes.Clone(test.DER)
			signed, result, err := xades.SignBasicEnveloped(t.Context(), input(t), chain.LeafKey, test.DER, xades.SignOptions{SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: testcert.Now()})
			if !test.Valid {
				if signed != nil || result != nil || !errors.Is(err, xades.ErrCertificate) {
					t.Fatal("XAdES accepted invalid certificate DER", err)
				}
				return
			}
			if err != nil || !bytes.Equal(result.CertificateDER(), test.DER) {
				t.Fatal("XAdES signing changed certificate bytes", err)
			}
			verified, err := xades.VerifyBasicEnveloped(t.Context(), signed, xmldsig.Signatures(signed)[0], test.DER, xades.VerifyOptions{})
			if err != nil || verified == nil || !bytes.Equal(verified.CertificateDER(), test.DER) || !bytes.Equal(test.DER, before) {
				t.Fatal("XAdES pin verification changed DER", err)
			}
		})
	}
}

func TestBaselineTopologies(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der := certificate(t, key, 1)
	for _, method := range []string{c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments, c14n.Exclusive, c14n.ExclusiveWithComments} {
		for _, topology := range []string{"nested-enveloped", "sibling", "enveloping", "external"} {
			t.Run(method+"/"+topology, func(t *testing.T) {
				options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, Canonicalization: reference.Transform{Algorithm: method}}, Properties: xades.BaselineProperties{SigningTime: time.Date(2026, 10, 25, 1, 2, 3, 0, time.UTC)}}
				var doc *document.Document
				var parent document.Element
				switch topology {
				case "nested-enveloped":
					doc = baselineDocument(t, `<Envelope><Payload ID="payload"><Amount>123</Amount></Payload></Envelope>`)
					parent = doc.Root().Children()[0]
					options.Template.References = []xmldsig.ReferenceTemplate{{URI: "#payload", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}, {Algorithm: method}}}}
					options.Validation.Signature.RequiredElements = []document.Element{parent}
				case "sibling":
					doc = baselineDocument(t, `<Envelope><Payload ID="payload"><Amount>123</Amount></Payload><Slot/></Envelope>`)
					parent = doc.Root().Children()[1]
					options.Template.References = []xmldsig.ReferenceTemplate{{URI: "#payload", Transforms: []reference.Transform{{Algorithm: method}}}}
					options.Validation.Signature.RequiredElements = []document.Element{doc.Root().Children()[0]}
				case "enveloping":
					value := "123"
					options.Template.Objects = []xmldsig.ObjectTemplate{{ID: "payload", Text: &value}}
					options.Template.References = []xmldsig.ReferenceTemplate{{URI: "#payload", Transforms: []reference.Transform{{Algorithm: method}}}}
				case "external":
					options.Template.References = []xmldsig.ReferenceTemplate{{URI: "urn:payload"}}
					options.Validation.Signature.External = &xmldsig.ExternalReferences{AllowedURIs: []string{"urn:payload"}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
						return io.NopCloser(strings.NewReader("123")), nil
					})}
				}
				signed, result, err := xades.SignBaseline(t.Context(), doc, parent, key, der, options)
				if err != nil {
					t.Fatal(err)
				}
				if result.Basic() == nil || len(result.Basic().Signature().References()) != 2 || len(result.DataObjects()) != 1 || len(result.CertificateReferences()) != 1 {
					t.Fatal("missing verified bindings")
				}
				if !result.Basic().Signature().References()[1].CoversElement(result.Basic().SignedProperties()) {
					t.Fatal("typed property reference lacks whole element")
				}
				verify := options.Validation
				verify.Signature.RequiredElements = nil
				selected := result.Basic().Signature().Signature()
				if _, err := xades.VerifyBaseline(t.Context(), signed, selected, der, verify); err != nil {
					t.Fatal(err)
				}
				if doc != nil && len(xmldsig.Signatures(doc)) != 0 {
					t.Fatal("input changed")
				}
				if _, err := xades.VerifyBasicEnveloped(t.Context(), signed, selected, der, xades.VerifyOptions{}); err == nil {
					t.Fatal("closed API expanded")
				}
			})
		}
	}
}

func TestBaselineSignedProperties(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := certificate(t, key, 1)
	extra := certificate(t, key, 2)
	claim := baselineDocument(t, `<x:ClaimedRole xmlns:x="http://uri.etsi.org/01903/v1.3.2#" xmlns:r="urn:role" r:scope="local">director<r:Code>42</r:Code></x:ClaimedRole>`)
	policy := []byte("policy-v1")
	properties := xades.BaselineProperties{SigningTime: time.Date(2026, 10, 25, 1, 2, 3, 0, time.UTC), SigningCertificateDigest: xmldsig.SHA512, AdditionalCertificates: []xades.CertificateIdentifier{{DER: extra, DigestMethod: xmldsig.SHA384, IncludeIssuerSerial: true}}, DataObjects: []xades.DataObjectFormat{{ObjectReference: "#data", Description: "invoice", MIMEType: "application/xml", ObjectIdentifier: &xades.ObjectIdentifier{Identifier: "urn:oid:1.2.840.113549", Qualifier: "OIDAsURN", Description: "format", Documentation: []string{"https://example.test/format"}}}}, ProductionPlace: &xades.ProductionPlace{City: "Perm", StreetAddress: "Main street", StateOrProvince: "Perm", PostalCode: "614000", CountryName: "RU"}, ClaimedRoles: []xades.PropertyValue{{Text: "author"}, {XML: claim.Root()}}, Commitments: []xades.CommitmentType{{Identifier: xades.ObjectIdentifier{Identifier: "urn:commitment:approval"}, ObjectReferences: []string{"#data"}, Qualifiers: []xades.PropertyValue{{Text: "approved"}}}, {Identifier: xades.ObjectIdentifier{Identifier: "urn:commitment:origin"}, All: true}}, Policy: &xades.SignaturePolicy{Identifier: xades.ObjectIdentifier{Identifier: "urn:policy:1"}, DigestMethod: xmldsig.SHA384, Qualifiers: []xades.PolicyQualifier{{URI: "https://example.test/policy"}, {Notice: &xades.PolicyNotice{Organization: "Example", NoticeNumbers: []string{"-1", "123456789012345678901234567890"}, ExplicitText: "terms"}}, {Specification: &xades.ObjectIdentifier{Identifier: "urn:oid:1.2.3", Qualifier: "OIDAsURN"}}}}}
	options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{ID: "data", URI: "#invoice-1", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}, {Algorithm: c14n.Exclusive}}}}, Certificates: [][]byte{der, extra}}, Properties: properties, Validation: xades.BaselineVerifyOptions{PolicyDocument: policy}}
	original := input(t)
	signed, result, err := xades.SignBaseline(t.Context(), original, original.Root(), key, der, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, certificate := range baselineTestNode(tree.Root(signed), xades.Namespace, "SigningCertificateV2").Children {
		for _, attribute := range certificate.Attrs {
			if attribute.Name == (document.Name{Local: "URI"}) {
				t.Fatal("baseline generator emitted prohibited Cert.URI")
			}
		}
	}

	if result.ProductionPlace().StreetAddress != "Main street" || len(result.ClaimedRoles()) != 2 || len(result.Commitments()) != 2 || len(result.CertificateReferences()) != 2 || result.SignaturePolicy().DigestMethod != xmldsig.SHA384 {
		t.Fatal("properties missing")
	}
	if !bytes.Equal(result.CertificateReferences()[1].CertificateDER(), extra) || len(result.CertificateReferences()[1].IssuerSerialV2()) == 0 {
		t.Fatal("extra DER not bound")
	}
	// Public accessors own mutable collections and bytes; XML handles are immutable.
	result.CertificateReferences()[0].Digest()[0] ^= 1
	result.DataObjects()[0].ObjectIdentifier.Documentation[0] = "changed"
	result.SignaturePolicy().Digest[0] ^= 1
	result.SignaturePolicy().Qualifiers[1].Notice.NoticeNumbers[0] = "999"
	if result.DataObjects()[0].ObjectIdentifier.Documentation[0] != "https://example.test/format" || result.SignaturePolicy().Qualifiers[1].Notice.NoticeNumbers[0] != "-1" {
		t.Fatal("mutable result")
	}
	for _, wrong := range []xades.BaselineVerifyOptions{{PolicyDocument: []byte("different")}, {}} {
		if got, err := xades.VerifyBaseline(t.Context(), signed, result.Basic().Signature().Signature(), der, wrong); err == nil || got != nil {
			t.Fatal("unchecked explicit policy")
		}
	}
	if _, err := xades.VerifyBaseline(t.Context(), signed, result.Basic().Signature().Signature(), extra, options.Validation); err == nil {
		t.Fatal("signer digest rebound to additional certificate")
	}
}

func TestBaselineIndependentSignatures(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := certificate(t, key, 1)
	doc := baselineDocument(t, `<Envelope><Payload ID="payload">123</Payload><Slot/></Envelope>`)
	options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{ID: "first", SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#payload"}}}, SignedPropertiesID: "first-properties", Properties: xades.BaselineProperties{SigningTime: time.Now().UTC()}}
	first, result, err := xades.SignBaseline(t.Context(), doc, doc.Root().Children()[1], key, der, options)
	if err != nil {
		t.Fatal(err)
	}
	options.Template.ID = "second"
	options.SignedPropertiesID = "second-properties"
	options.Template.References[0].ID = "second-data"
	options.Preserve = []xmldsig.SignatureRequirement{{Signature: result.Basic().Signature().Signature(), PublicKey: key.Public(), Options: xmldsig.SignatureOptions{AdditionalIDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{{Space: xades.Namespace, Local: signedPropertiesLocal}}}}}}}
	second, result, err := xades.SignBaseline(t.Context(), first, first.Root().Children()[1], key, der, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(xmldsig.Signatures(second)) != 2 || result.Basic().Signature().Signature().Same(xmldsig.Signatures(second)[0]) {
		t.Fatal("selection lost")
	}
	for _, selected := range xmldsig.Signatures(second) {
		if _, err := xades.VerifyBaseline(t.Context(), second, selected, der, xades.BaselineVerifyOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

func baselineDocument(t testing.TB, source string) *document.Document {
	t.Helper()
	doc, err := document.Parse(t.Context(), []byte(source), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestBaselineAuthenticatedPropertyRejects(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := certificate(t, key, 1)
	source := input(t)
	options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{ID: "data", URI: "#invoice-1", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}, {Algorithm: c14n.Exclusive}}}}}, Properties: xades.BaselineProperties{SigningTime: time.Now().UTC()}}
	signed, _, err := xades.SignBaseline(t.Context(), source, source.Root(), key, der, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*tree.Node)
	}{
		{"duplicate signing time", func(root *tree.Node) {
			ssp := baselineTestNode(root, xades.Namespace, "SignedSignatureProperties")
			duplicate := tree.ImportSubtree(ssp.Children[0])
			duplicate.Parent = ssp
			ssp.Children = append(ssp.Children, duplicate)
		}},
		{"foreign property namespace", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace, "SigningTime")
			n.Name.Space = "urn:spoof"
			n.NS = append(n.NS, tree.Namespace{Prefix: "fake", URI: "urn:spoof"})
			n.Prefix = "fake"
		}},
		{"wrong reference type", func(root *tree.Node) {
			for _, n := range baselineTestNode(root, xmldsig.Namespace, "SignedInfo").Children {
				for i, a := range n.Attrs {
					if a.Name.Local == "Type" {
						n.Attrs[i].Value = "urn:wrong"
					}
				}
			}
		}},
		{"object format targets properties", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace, "DataObjectFormat")
			n.Attrs[0].Value = "#signed-properties"
		}},
		{"object format targets payload not reference", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace, "DataObjectFormat")
			n.Attrs[0].Value = "#invoice-1"
		}},
		{"additional unsigned data reference", func(root *tree.Node) {
			si := baselineTestNode(root, xmldsig.Namespace, "SignedInfo")
			duplicate := tree.ImportSubtree(si.Children[2])
			duplicate.Attrs = []tree.Attribute{{Name: document.Name{Local: "URI"}, Value: "#invoice-1"}, {Name: document.Name{Local: "Id"}, Value: "unqualified-data"}}
			duplicate.Parent = si
			si.Children = append(si.Children, duplicate)
		}},
		{"signer certificate absent", func(root *tree.Node) {
			n := baselineTestNode(root, xmldsig.Namespace, "X509Certificate")
			n.Children = []*tree.Node{{Kind: tree.TextNode, Data: base64.StdEncoding.EncodeToString(certificate(t, key, 2)), Parent: n}}
		}},
		{"wrong authenticated certificate digest", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace, "CertDigest")
			n.Children[1].Children[0].Data = base64.StdEncoding.EncodeToString(make([]byte, 32))
		}},
		{"duplicate qualifying properties", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace, "QualifyingProperties")
			duplicate := tree.ImportSubtree(n)
			duplicate.Children = nil
			duplicate.Parent = n.Parent
			n.Parent.Children = append(n.Parent.Children, duplicate)
		}},
		{"container mixed text", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace, "SignedSignatureProperties")
			n.Children = append(n.Children, &tree.Node{Kind: tree.TextNode, Data: "spoof", Parent: n})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed, selected, validation := baselineResign(t, signed, key, tc.mutate, xmldsig.SignatureOptions{})
			if _, err := xmldsig.VerifySignature(t.Context(), changed, selected, key.Public(), validation); err != nil {
				t.Fatal("control must be cryptographically valid", err)
			}
			if result, err := xades.VerifyBaseline(t.Context(), changed, selected, der, xades.BaselineVerifyOptions{}); err == nil || result != nil {
				t.Fatal("accepted authenticated invalid property")
			}
		})
	}
}

func TestBaselineTypedPropertyReferenceCoverage(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := certificate(t, key, 1)
	source := input(t)
	signed, _, err := xades.SignBaseline(t.Context(), source, source.Root(), key, der, xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#invoice-1", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}, {Algorithm: c14n.Exclusive}}}}}, Properties: xades.BaselineProperties{SigningTime: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	for _, filtered := range []bool{false, true} {
		t.Run(strconv.FormatBool(filtered), func(t *testing.T) {
			program := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: `not(ancestor-or-self::x:SigningTime)`, Namespaces: map[string]string{"x": xades.Namespace, "ds": xmldsig.Namespace, "xml": document.XMLNamespace, "": "urn:test:invoice"}}}}
			engine, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{program}})
			if err != nil {
				t.Fatal(err)
			}
			validation := xmldsig.SignatureOptions{Processing: reference.DefaultOptions()}
			validation.Processing.Extension = engine
			validation.Processing.AllowedTransforms = append(validation.Processing.AllowedTransforms, reference.XPath)
			changed, selected, validation := baselineResign(t, signed, key, func(root *tree.Node) {
				si := baselineTestNode(root, xmldsig.Namespace, "SignedInfo")
				typed := si.Children[3]
				fullDoc, err := tree.Clone(t.Context(), tree.FromNodes([]*tree.Node{typed}, document.DefaultLimits()))
				if err != nil {
					t.Fatal(err)
				}
				full := tree.Root(fullDoc)
				full.Parent = si
				si.Children = append(si.Children, full)
				if filtered {
					transforms := typed.Children[0]
					node := &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: xmldsig.Namespace, Local: "Transform"}, Prefix: "ds", Attrs: []tree.Attribute{{Name: document.Name{Local: "Algorithm"}, Value: reference.XPath}}, Parent: transforms}
					if err := transformxml.AppendParameters(t.Context(), node, program); err != nil {
						t.Fatal(err)
					}
					transforms.Children = append([]*tree.Node{node}, transforms.Children...)
				}
			}, validation)
			core, err := xmldsig.VerifySignature(t.Context(), changed, selected, key.Public(), validation)
			if err != nil {
				t.Fatal(err)
			}
			property := baselineTestNode(tree.Root(changed), xades.Namespace, signedPropertiesLocal)
			element := tree.Wrap(changed, property)
			if !core.CoversElement(element) {
				t.Fatal("whole coverage control absent")
			}
			result, err := xades.VerifyBaseline(t.Context(), changed, selected, der, xades.BaselineVerifyOptions{Signature: validation})
			if filtered {
				if err == nil || result != nil || core.References()[1].CoversElement(element) {
					t.Fatal("filtered typed reference was accepted")
				}
			} else if err != nil || result == nil {
				t.Fatal("repeated full typed references rejected", err)
			}
		})
	}
}

func baselineTestNode(root *tree.Node, namespace, local string) *tree.Node {
	if root.Name == (document.Name{Space: namespace, Local: local}) {
		return root
	}
	for _, child := range root.Children {
		if found := baselineTestNode(child, namespace, local); found != nil {
			return found
		}
	}
	return nil
}

func baselineResign(t *testing.T, source *document.Document, key *ecdsa.PrivateKey, mutate func(*tree.Node), validation xmldsig.SignatureOptions) (*document.Document, document.Element, xmldsig.SignatureOptions) {
	t.Helper()
	draft, err := tree.Clone(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	mutate(tree.Root(draft))
	selected := xmldsig.Signatures(draft)[0]
	clearSignatureValues(selected)
	raw, err := draft.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	draft, err = document.Parse(t.Context(), raw, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	validation.AdditionalIDRules = append(validation.AdditionalIDRules, reference.IDAttributeRule{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{{Space: xades.Namespace, Local: signedPropertiesLocal}}})
	signed, err := xmldsig.SignTemplate(t.Context(), draft, xmldsig.Signatures(draft)[0], key, xmldsig.TemplateSignOptions{Validation: validation})
	if err != nil {
		t.Fatal(err)
	}
	return signed, xmldsig.Signatures(signed)[0], validation
}

func TestBaselineSigningTimePrecision(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := certificate(t, key, 1)
	for _, tc := range []struct {
		lexical     string
		other       time.Time
		comparison  int
		convenience bool
	}{
		{"2026-10-25T01:02:03.123456789000000000Z", time.Date(2026, 10, 25, 1, 2, 3, 123456789, time.UTC), 0, true},
		{"2026-10-25T01:02:03.123456789000000001Z", time.Date(2026, 10, 25, 1, 2, 3, 123456789, time.UTC), 1, false},
		{"2026-10-25T01:02:03.123456788999999999Z", time.Date(2026, 10, 25, 1, 2, 3, 123456789, time.UTC), -1, false},
		{"2026-10-25T01:02:03+00:00", time.Date(2026, 10, 25, 1, 2, 3, 0, time.UTC), 0, true},
		{"2026-10-25T01:02:03-00:00", time.Date(2026, 10, 25, 1, 2, 3, 0, time.UTC), 0, true},
		{"2026-10-25T24:00:00.000000000000Z", time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC), 0, true},
		{"9999-12-31T24:00:00Z", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), 0, false},
		{"100000000000000000000-01-01T00:00:00Z", time.Now(), 1, false},
		{"-100000000000000000000-01-01T00:00:00Z", time.Now(), -1, false},
		{"-0001-12-31T24:00:00Z", time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), 0, true},
	} {
		t.Run(tc.lexical, func(t *testing.T) {
			source := input(t)
			_, result, err := xades.SignBaseline(t.Context(), source, source.Root(), key, der, xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#invoice-1", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}}}}}, Properties: xades.BaselineProperties{SigningTimeLexical: tc.lexical}})
			if err != nil {
				t.Fatal(err)
			}
			if result.SigningTimeLexical() != tc.lexical {
				t.Fatal("precision or lexical lost")
			}
			comparison, err := result.CompareSigningTime(tc.other)
			if err != nil || comparison != tc.comparison {
				t.Fatal(comparison, err)
			}
			if tc.convenience {
				if !result.Basic().ClaimedSigningTime().Equal(tc.other) {
					t.Fatal("wrong convenience value")
				}
			} else if !result.Basic().ClaimedSigningTime().IsZero() {
				t.Fatal("fraction/year silently truncated")
			}
		})
	}
	for _, lexical := range []string{"0000-01-01T00:00:00Z", "-0000-01-01T00:00:00Z", "02026-01-01T00:00:00Z", "2026-02-29T00:00:00Z", "2024-02-30T00:00:00Z", "2024-01-01T24:00:00.1Z", "2024-01-01T23:59:60Z", "2024-01-01T00:00:00.Z", "2024-01-01T00:00:00,1Z", "2024-01-01T00:00:00." + strings.Repeat("1", 4096) + "Z"} {
		t.Run("reject/"+lexical[:min(len(lexical), 40)], func(t *testing.T) {
			source := input(t)
			doc, result, err := xades.SignBaseline(t.Context(), source, source.Root(), key, der, xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256}, Properties: xades.BaselineProperties{SigningTimeLexical: lexical}})
			if err == nil || doc != nil || result != nil {
				t.Fatal("invalid UTC dateTime accepted")
			}
		})
	}
}

func TestBaselinePolicySpecificationBinding(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := certificate(t, key, 1)
	source := input(t)
	calls := 0
	validation := xades.BaselineVerifyOptions{PolicyDocument: []byte("policy"), PolicySpecificationDigest: func(ctx context.Context, specification xades.ObjectIdentifier, data []byte, algorithm crypto.Hash) ([]byte, error) {
		calls++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if specification.Identifier != "urn:oid:1.2.3" || !bytes.Equal(data, []byte("policy")) {
			return nil, errors.New("wrong specification/input")
		}
		hash := algorithm.New()
		_, _ = hash.Write(data)
		return hash.Sum(nil), nil
	}}
	options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#invoice-1", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}}}}}, Properties: xades.BaselineProperties{SigningTime: time.Now().UTC(), Policy: &xades.SignaturePolicy{Identifier: xades.ObjectIdentifier{Identifier: "urn:policy"}, Transforms: []reference.Transform{{Algorithm: xades.PolicyDocumentDigestAsSpecified}}, Qualifiers: []xades.PolicyQualifier{{Specification: &xades.ObjectIdentifier{Identifier: "urn:oid:1.2.3", Qualifier: "OIDAsURN"}}}}}, Validation: validation}
	signed, result, err := xades.SignBaseline(t.Context(), source, source.Root(), key, der, options)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("specification digest not used for generation and verification", calls)
	}
	raw, err := signed.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Replace(raw, []byte(">123<"), []byte(">999<"), 1)
	changed, err := document.Parse(t.Context(), corrupt, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	if _, err := xades.VerifyBaseline(t.Context(), changed, xmldsig.Signatures(changed)[0], der, validation); err == nil || calls != 0 {
		t.Fatal("callback ran before authentication", calls, err)
	}
	for _, bad := range []xades.BaselineVerifyOptions{{PolicyDocument: []byte("policy")}, {PolicyDocument: []byte("wrong"), PolicySpecificationDigest: validation.PolicySpecificationDigest}, {PolicyDocument: []byte("policy"), PolicySpecificationDigest: func(context.Context, xades.ObjectIdentifier, []byte, crypto.Hash) ([]byte, error) {
		return []byte{0}, nil
	}}} {
		if result, err := xades.VerifyBaseline(t.Context(), signed, result.Basic().Signature().Signature(), der, bad); err == nil || result != nil {
			t.Fatal("unchecked specification digest")
		}
	}
}

func TestBaselineCounterSignatureBinding(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := certificate(t, key, 1)
	source := input(t)
	base, _, err := xades.SignBaseline(t.Context(), source, source.Root(), key, der, xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#invoice-1", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}}}}}, Properties: xades.BaselineProperties{SigningTime: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	draft, err := tree.Clone(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	signatureValue := baselineTestNode(tree.Root(draft), xmldsig.Namespace, "SignatureValue")
	signatureValue.Attrs = append(signatureValue.Attrs, tree.Attribute{Name: document.Name{Local: "Id"}, Value: "parent-value"})
	qp := baselineTestNode(tree.Root(draft), xades.Namespace, "QualifyingProperties")
	unsigned := baselineTestAppend(qp, xades.Namespace, "UnsignedProperties", "xades")
	usp := baselineTestAppend(unsigned, xades.Namespace, "UnsignedSignatureProperties", "xades")
	baselineTestAppend(usp, xades.Namespace, "CounterSignature", "xades")
	raw, err := draft.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	draft, err = document.Parse(t.Context(), raw, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	container := baselineTestNode(tree.Root(draft), xades.Namespace, "CounterSignature")
	preserve := xmldsig.SignatureRequirement{Signature: xmldsig.Signatures(draft)[0], PublicKey: key.Public(), Options: xmldsig.SignatureOptions{AdditionalIDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{{Space: xades.Namespace, Local: signedPropertiesLocal}}}}}}
	signed, counter, err := xades.SignBaseline(t.Context(), draft, tree.Wrap(draft, container), key, der, xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{ID: "counter", SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#parent-value", Type: xades.CountersignedSignatureType}}}, SignedPropertiesID: "counter-properties", Properties: xades.BaselineProperties{SigningTime: time.Now().UTC()}, Preserve: []xmldsig.SignatureRequirement{preserve}})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := xades.VerifyBaseline(t.Context(), signed, xmldsig.Signatures(signed)[0], der, xades.BaselineVerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(parent.CounterSignatures()) != 1 || !parent.CounterSignatures()[0].Same(counter.Basic().Signature().Signature()) {
		t.Fatal("counter selection lost")
	}
	if err := xades.VerifyCounterSignature(t.Context(), parent.Basic(), counter.Basic().Signature()); err != nil {
		t.Fatal(err)
	}
	if err := xades.VerifyCounterSignature(t.Context(), parent.Basic(), parent.Basic().Signature()); err == nil {
		t.Fatal("parent accepted as its own counter")
	}
	// A cryptographically valid typed reference to SignedProperties is still not
	// a countersignature of SignatureValue.
	changed, err := tree.Clone(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	counterHandle := xmldsig.Signatures(changed)[1]
	_, counterNode := tree.Unwrap(counterHandle)
	si := baselineTestNode(counterNode, xmldsig.Namespace, "SignedInfo")
	for i, a := range si.Children[2].Attrs {
		if a.Name.Local == "URI" {
			si.Children[2].Attrs[i].Value = "#signed-properties"
		}
	}
	clearSignatureValues(counterHandle)
	raw, err = changed.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	changed, err = document.Parse(t.Context(), raw, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	validation := preserve.Options
	preserve.Signature = xmldsig.Signatures(changed)[0]
	changed, err = xmldsig.SignTemplate(t.Context(), changed, xmldsig.Signatures(changed)[1], key, xmldsig.TemplateSignOptions{Validation: validation, Preserve: []xmldsig.SignatureRequirement{preserve}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xmldsig.VerifySignature(t.Context(), changed, xmldsig.Signatures(changed)[1], key.Public(), validation); err != nil {
		t.Fatal(err)
	}
	if result, err := xades.VerifyBaseline(t.Context(), changed, xmldsig.Signatures(changed)[1], der, xades.BaselineVerifyOptions{}); err == nil || result != nil {
		t.Fatal("typed non-SignatureValue accepted")
	}
}

func TestBaselineThirdPartyRoleContainers(t *testing.T) {
	chain := testcert.New(t)
	attribute := baselineAttributeCertificate(t, chain)
	certified := baselineDocument(t, `<x:CertifiedRole xmlns:x="http://uri.etsi.org/01903/v1.3.2#"><x:X509AttributeCertificate>`+base64.StdEncoding.EncodeToString(attribute)+`</x:X509AttributeCertificate></x:CertifiedRole>`)
	other := baselineDocument(t, `<x:CertifiedRole xmlns:x="http://uri.etsi.org/01903/v1.3.2#"><x:OtherAttributeCertificate xmlns:role="urn:authority" role:kind="private"><role:Attribute>director</role:Attribute></x:OtherAttributeCertificate></x:CertifiedRole>`)
	assertion := baselineDocument(t, `<x:SignedAssertion xmlns:x="http://uri.etsi.org/01903/v1.3.2#"><claim xmlns="urn:assertion">separate-domain-verifier-required</claim></x:SignedAssertion>`)
	options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#invoice-1", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}}}}}, Properties: xades.BaselineProperties{SigningTime: testcert.Now(), ClaimedRoles: []xades.PropertyValue{{Text: "author"}}, CertifiedRoles: []xades.PropertyValue{{XML: certified.Root()}, {XML: other.Root()}}, SignedAssertions: []xades.PropertyValue{{XML: assertion.Root()}}}}
	source := input(t)
	_, result, err := xades.SignBaseline(t.Context(), source, source.Root(), chain.LeafKey, chain.Leaf.Raw, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ClaimedRoles()) != 1 || len(result.CertifiedRoles()) != 2 || len(result.SignedAssertions()) != 1 {
		t.Fatal("role containers missing")
	}
	for _, xml := range []string{`<x:CertifiedRole xmlns:x="http://uri.etsi.org/01903/v1.3.2#"/>`, `<x:CertifiedRole xmlns:x="http://uri.etsi.org/01903/v1.3.2#"><x:OtherAttributeCertificate/><x:OtherAttributeCertificate/></x:CertifiedRole>`, `<x:CertifiedRole xmlns:x="http://uri.etsi.org/01903/v1.3.2#"><x:X509AttributeCertificate>` + base64.StdEncoding.EncodeToString(chain.Leaf.Raw) + `</x:X509AttributeCertificate></x:CertifiedRole>`} {
		bad := baselineDocument(t, xml)
		options.Properties.CertifiedRoles = []xades.PropertyValue{{XML: bad.Root()}}
		if doc, result, err := xades.SignBaseline(t.Context(), source, source.Root(), chain.LeafKey, chain.Leaf.Raw, options); err == nil || doc != nil || result != nil {
			t.Fatal("invalid certified-role envelope accepted")
		}
	}
}

func baselineTestAppend(parent *tree.Node, namespace, local, prefix string) *tree.Node {
	node := &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: namespace, Local: local}, Prefix: prefix, Parent: parent}
	parent.Children = append(parent.Children, node)
	return node
}

func baselineAttributeCertificate(t *testing.T, chain testcert.Chain) []byte {
	t.Helper()
	algorithm := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}))
	holderName := der.Wrap(2, 4, true, chain.Leaf.RawSubject)
	holder := der.Seq(der.Wrap(2, 1, true, holderName))
	issuerName := der.Seq(der.Wrap(2, 4, true, chain.Root.RawSubject))
	issuer := der.Wrap(2, 0, true, issuerName)
	before, err := asn1.MarshalWithParams(testcert.Now().Add(-time.Hour), "generalized")
	if err != nil {
		t.Fatal(err)
	}
	after, err := asn1.MarshalWithParams(testcert.Now().Add(time.Hour), "generalized")
	if err != nil {
		t.Fatal(err)
	}
	attributeValue, err := asn1.MarshalWithParams("director", "utf8")
	if err != nil {
		t.Fatal(err)
	}
	info := der.Seq(der.Int(1), holder, issuer, algorithm, der.Int(42), der.Seq(before, after), der.Seq(der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 3, 4}), der.Set(attributeValue))))
	digest := sha256.Sum256(info)
	signature, err := ecdsa.SignASN1(rand.Reader, chain.RootKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	value, err := asn1.Marshal(asn1.BitString{Bytes: signature, BitLength: len(signature) * 8})
	if err != nil {
		t.Fatal(err)
	}
	return der.Seq(info, algorithm, value)
}

func TestBaselinePropertyOptionsRejectsBeforeSigner(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := certificate(t, key, 1)
	source := input(t)
	for _, tc := range []struct {
		name   string
		change func(*xades.BaselineSignOptions)
	}{
		{"empty production place", func(o *xades.BaselineSignOptions) { o.Properties.ProductionPlace = &xades.ProductionPlace{} }},
		{"missing data format qualifier", func(o *xades.BaselineSignOptions) {
			o.Properties.DataObjects = []xades.DataObjectFormat{{ObjectReference: "#data"}}
		}},
		{"invalid MIME", func(o *xades.BaselineSignOptions) {
			o.Properties.DataObjects = []xades.DataObjectFormat{{ObjectReference: "#data", MIMEType: "bad\nheader"}}
		}},
		{"missing OID qualifier", func(o *xades.BaselineSignOptions) {
			o.Properties.DataObjects = []xades.DataObjectFormat{{ObjectReference: "#data", ObjectIdentifier: &xades.ObjectIdentifier{Identifier: "urn:oid:1.2.3"}}}
		}},
		{"invalid OID arc", func(o *xades.BaselineSignOptions) {
			o.Properties.DataObjects = []xades.DataObjectFormat{{ObjectReference: "#data", ObjectIdentifier: &xades.ObjectIdentifier{Identifier: "urn:oid:1.40.3", Qualifier: "OIDAsURN"}}}
		}},
		{"unknown OID qualifier", func(o *xades.BaselineSignOptions) {
			o.Properties.DataObjects = []xades.DataObjectFormat{{ObjectReference: "#data", ObjectIdentifier: &xades.ObjectIdentifier{Identifier: "urn:format", Qualifier: "unknown"}}}
		}},
		{"commitment all and refs", func(o *xades.BaselineSignOptions) {
			o.Properties.Commitments = []xades.CommitmentType{{Identifier: xades.ObjectIdentifier{Identifier: "urn:commitment"}, All: true, ObjectReferences: []string{"#data"}}}
		}},
		{"commitment no selection", func(o *xades.BaselineSignOptions) {
			o.Properties.Commitments = []xades.CommitmentType{{Identifier: xades.ObjectIdentifier{Identifier: "urn:commitment"}}}
		}},
		{"commitment unknown reference", func(o *xades.BaselineSignOptions) {
			o.Properties.Commitments = []xades.CommitmentType{{Identifier: xades.ObjectIdentifier{Identifier: "urn:commitment"}, ObjectReferences: []string{"#missing"}}}
		}},
		{"commitment OID qualifier", func(o *xades.BaselineSignOptions) {
			o.Properties.Commitments = []xades.CommitmentType{{Identifier: xades.ObjectIdentifier{Identifier: "urn:oid:1.2.3", Qualifier: "OIDAsURN"}, All: true}}
		}},
		{"implied explicit fields", func(o *xades.BaselineSignOptions) {
			o.Properties.Policy = &xades.SignaturePolicy{Implied: true, Identifier: xades.ObjectIdentifier{Identifier: "urn:policy"}}
		}},
		{"policy document missing", func(o *xades.BaselineSignOptions) {
			o.Properties.Policy = &xades.SignaturePolicy{Identifier: xades.ObjectIdentifier{Identifier: "urn:policy"}}
		}},
		{"policy notice integer", func(o *xades.BaselineSignOptions) {
			o.Validation.PolicyDocument = []byte("policy")
			o.Properties.Policy = &xades.SignaturePolicy{Identifier: xades.ObjectIdentifier{Identifier: "urn:policy"}, Qualifiers: []xades.PolicyQualifier{{Notice: &xades.PolicyNotice{NoticeNumbers: []string{"1.2"}}}}}
		}},
		{"policy spec URI qualifier", func(o *xades.BaselineSignOptions) {
			o.Validation.PolicyDocument = []byte("policy")
			o.Properties.Policy = &xades.SignaturePolicy{Identifier: xades.ObjectIdentifier{Identifier: "urn:policy"}, Qualifiers: []xades.PolicyQualifier{{Specification: &xades.ObjectIdentifier{Identifier: "https://example.test/oid/1.2.3", Qualifier: "OIDAsURI"}}}}
		}},
		{"certificate SHA1 default", func(o *xades.BaselineSignOptions) { o.Properties.SigningCertificateDigest = xmldsig.SHA1 }},
		{"duplicate format reference", func(o *xades.BaselineSignOptions) {
			o.Properties.DataObjects = []xades.DataObjectFormat{{ObjectReference: "#data", Description: "one"}, {ObjectReference: "#data", Description: "two"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{ID: "data", URI: "#invoice-1", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}}}}}, Properties: xades.BaselineProperties{SigningTime: time.Now().UTC()}}
			tc.change(&options)
			calls := 0
			signer := baselineRecordingSigner{Signer: key, calls: &calls}
			doc, result, err := xades.SignBaseline(t.Context(), source, source.Root(), signer, der, options)
			if err == nil || doc != nil || result != nil || calls != 0 {
				t.Fatal("invalid property reached private signer", calls, err)
			}
		})
	}
}

type baselineRecordingSigner struct {
	crypto.Signer
	calls *int
}

func (s baselineRecordingSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	*s.calls++
	return s.Signer.Sign(random, digest, options)
}

func TestBaselineCertificatePrependAndAnyTypePolicy(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := certificate(t, key, 1)
	extra := certificate(t, key, 2)
	source := input(t)
	qualifier := baselineDocument(t, `<x:SigPolicyQualifier xmlns:x="http://uri.etsi.org/01903/v1.3.2#" xmlns:d="urn:domain" d:hint="metadata">notice<x:SPURI>https://example.test/policy</x:SPURI><d:Extra>preserved</d:Extra></x:SigPolicyQualifier>`)
	options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, Certificates: [][]byte{extra}, References: []xmldsig.ReferenceTemplate{{URI: "#invoice-1", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}}}}}, Properties: xades.BaselineProperties{SigningTime: time.Now().UTC(), AdditionalCertificates: []xades.CertificateIdentifier{{DER: extra}}, Policy: &xades.SignaturePolicy{Identifier: xades.ObjectIdentifier{Identifier: "urn:policy"}, Qualifiers: []xades.PolicyQualifier{{XML: qualifier.Root()}}}}, Validation: xades.BaselineVerifyOptions{PolicyDocument: []byte("policy")}}
	signed, result, err := xades.SignBaseline(t.Context(), source, source.Root(), key, der, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.CertificateReferences()) != 2 || !bytes.Equal(result.CertificateReferences()[0].CertificateDER(), der) || !result.SignaturePolicy().Qualifiers[0].XML.Valid() {
		t.Fatal("signer prepend or AnyType context lost")
	}
	if _, err := xades.VerifyBaseline(t.Context(), signed, result.Basic().Signature().Signature(), der, options.Validation); err != nil {
		t.Fatal(err)
	}
}
