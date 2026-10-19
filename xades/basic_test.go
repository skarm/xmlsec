package xades_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
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
