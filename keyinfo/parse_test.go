package keyinfo_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/reference"
)

const (
	ns   = keyinfo.Namespace
	ns11 = keyinfo.Namespace11
)

const (
	uriUrnFirst  = "urn:first"
	uriUrnRemote = "urn:remote"
)

func TestBuildParsePublicKeys(t *testing.T) {
	r, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}

	ed, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	keys := []struct {
		name string
		key  crypto.PublicKey
	}{{"RSA", &r.PublicKey}, {"P256", &ec(t, elliptic.P256()).PublicKey}, {"P384", &ec(t, elliptic.P384()).PublicKey}, {"P521", &ec(t, elliptic.P521()).PublicKey}, {"Ed25519", ed}}
	for _, test := range keys {
		for _, format := range []keyinfo.KeyFormat{keyinfo.XMLKeyValue, keyinfo.DERKeyValue} {
			t.Run(test.name+"/"+string(format), func(t *testing.T) { testBuildParsePublicKeysCase(t, &test, &format) })
		}
	}
}

func testBuildParsePublicKeysCase(t *testing.T, test *struct {
	name string
	key  crypto.PublicKey
}, format *keyinfo.KeyFormat,
) {
	d, e := keyinfo.Build(context.Background(), keyinfo.Template{ID: "ki", Names: []string{"  significant name\n"}, Keys: []keyinfo.PublicKeyValue{{Key: test.key, Format: (*format)}}})
	if test.name == "Ed25519" && (*format) == keyinfo.XMLKeyValue {
		if !errors.Is(e, keyinfo.ErrUnsupported) {
			t.Fatal(e)
		}

		return
	}

	if e != nil {
		t.Fatal(e)
	}

	out, e := keyinfo.Parse(context.Background(), d, d.Root(), keyinfo.Options{})
	if e != nil {
		t.Fatal(e)
	}

	cs := out.Candidates()
	if len(cs) != 1 || out.KeyNames()[0] != "  significant name\n" {
		t.Fatalf("bad hints: %+v", out)
	}

	expected, _ := x509.MarshalPKIXPublicKey(test.key)
	if !bytes.Equal(expected, cs[0].SPKI()) {
		t.Fatal("wrong key")
	}

	h := sha256.Sum256(expected)
	if cs[0].FingerprintSHA256() != hex.EncodeToString(h[:]) {
		t.Fatal("wrong fingerprint")
	}

	c, e := cs[0].Certificate()
	if e != nil || c != nil || cs[0].Source().Node().Document() != d {
		t.Fatal("unexpected source/certificate", e)
	}

	if e := out.CheckKeyDeclarations(0); e != nil {
		t.Fatal(e)
	}
}

func TestReturnedDataCannotChangeHints(t *testing.T) {
	k := ec(t, elliptic.P256())
	der := cert(t, k)

	d, e := keyinfo.Build(context.Background(), keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &k.PublicKey}}, Certificates: [][]byte{der}, Names: []string{"original"}})
	if e != nil {
		t.Fatal(e)
	}

	info, e := keyinfo.Parse(context.Background(), d, d.Root(), keyinfo.Options{})
	if e != nil {
		t.Fatal(e)
	}

	original := asXML(t, d)
	c := info.Candidates()[1]
	fp := c.FingerprintSHA256()
	p, _ := c.PublicKey()
	p.(*ecdsa.PublicKey).X.SetInt64(0) //nolint:staticcheck // Deliberately mutate legacy coordinates to test malformed keys and snapshot ownership.

	raw := c.SPKI()
	raw[0] ^= 255
	raw = c.CertificateDER()
	raw[0] ^= 255

	certificate, e := c.Certificate()
	if e != nil {
		t.Fatal(e)
	}

	certificate.Raw[0] ^= 255
	certificate.PublicKey.(*ecdsa.PublicKey).Y.SetInt64(0) //nolint:staticcheck // Deliberately mutate legacy coordinates to test malformed keys and snapshot ownership.

	group := info.X509Groups()[0]
	group.CertificatesDER()[0][0] ^= 255
	info.KeyNames()[0] = "edited"

	info.Candidates()[1] = keyinfo.Candidate{}
	if c.FingerprintSHA256() != fp || info.KeyNames()[0] != "original" || asXML(t, d) != original {
		t.Fatal("mutation escaped")
	}

	fresh, _ := c.Certificate()
	if !bytes.Equal(fresh.Raw, der) {
		t.Fatal("certificate mutated")
	}

	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			for range 20 {
				key, e := c.PublicKey()
				if e != nil {
					t.Error(e)
					return
				}

				key.(*ecdsa.PublicKey).X.SetInt64(0) //nolint:staticcheck // Deliberately mutate legacy coordinates to test malformed keys and snapshot ownership.

				c.CertificateDER()[0] = 0
			}
		})
	}

	wg.Wait()
}

func TestNamesAndCertificateSelectors(t *testing.T) {
	k := ec(t, elliptic.P256())
	der := cert(t, k)
	digest := sha256.Sum256(der)
	xml := wrap(`<ds:KeyName> A &amp; B </ds:KeyName><ds:X509Data><ds:X509Certificate>` + enc(der) + `</ds:X509Certificate><ds:X509SKI>AQID</ds:X509SKI><ds:X509SubjectName>CN=keyinfo-test</ds:X509SubjectName><ds:X509IssuerSerial><ds:X509IssuerName>CN=issuer</ds:X509IssuerName><ds:X509SerialNumber>000123456789012345678901234567890</ds:X509SerialNumber></ds:X509IssuerSerial><k:X509Digest Algorithm="http://www.w3.org/2001/04/xmlenc#sha256">` + enc(digest[:]) + `</k:X509Digest></ds:X509Data>`)
	r := parseInfo(t, xml)

	g := r.X509Groups()[0]
	if r.KeyNames()[0] != " A & B " || len(r.Candidates()) != 1 || g.IssuerSerials()[0].Serial != "123456789012345678901234567890" {
		t.Fatal("selectors changed")
	}

	g.CertificateDigests()[0].Value[0] ^= 255
	g.SubjectKeyIdentifiers()[0][0] = 99
	g.SubjectNames()[0] = "changed"

	g.IssuerSerials()[0].Issuer = "changed"
	if !bytes.Equal(g.CertificateDigests()[0].Value, digest[:]) || g.SubjectKeyIdentifiers()[0][0] != 1 || g.SubjectNames()[0] != "CN=keyinfo-test" || g.IssuerSerials()[0].Issuer != "CN=issuer" {
		t.Fatal("selector copies")
	}
	// Hints may name a cert not embedded in this XML. Parsing does not trust them.
	r = parseInfo(t, wrap(`<ds:X509Data><ds:X509SubjectName>CN=not-embedded</ds:X509SubjectName></ds:X509Data>`))
	if len(r.Candidates()) != 0 || len(r.X509Groups()) != 1 {
		t.Fatal("synthesized key")
	}
}

func TestRejectMalformedOrUnsupportedKeyInfo(t *testing.T) {
	k := ec(t, elliptic.P256())
	badPoint := make([]byte, 65)
	badPoint[0] = 4

	cases := []struct {
		name, body string
		err        error
	}{
		{"empty", "", keyinfo.ErrInput},
		{"unknown", `<surprise xmlns="urn:other"/>`, keyinfo.ErrUnsupported},
		{"unqualified", `<KeyValue/>`, keyinfo.ErrUnsupported},
		{"wrong-order", `<ds:KeyValue><ds:RSAKeyValue><ds:Exponent>Aw==</ds:Exponent><ds:Modulus>Cw==</ds:Modulus></ds:RSAKeyValue></ds:KeyValue>`, keyinfo.ErrInput},
		{"even-exponent", `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>Cw==</ds:Modulus><ds:Exponent>Ag==</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>`, keyinfo.ErrKey},
		{"even-modulus", `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>DA==</ds:Modulus><ds:Exponent>Aw==</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>`, keyinfo.ErrKey},
		{"padded-integer", `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>AAs=</ds:Modulus><ds:Exponent>Aw==</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>`, keyinfo.ErrInput},
		{"huge-exponent", `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>////////</ds:Modulus><ds:Exponent>AQAAAAAAAAA=</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>`, keyinfo.ErrKey},
		{"extra-key", `<ds:KeyValue>` + derXML(t, &k.PublicKey) + derXML(t, &k.PublicKey) + `</ds:KeyValue>`, keyinfo.ErrInput},
		{"DER-in-KeyValue", `<ds:KeyValue>` + derXML(t, &k.PublicKey) + `</ds:KeyValue>`, keyinfo.ErrUnsupported},
		{"DSA", `<ds:KeyValue><ds:DSAKeyValue/></ds:KeyValue>`, keyinfo.ErrUnsupported},
		{"bad-base64", `<k:DEREncodedKeyValue>AB==</k:DEREncodedKeyValue>`, keyinfo.ErrInput},
		{"nested-name", `<ds:KeyName><ds:KeyName>x</ds:KeyName></ds:KeyName>`, keyinfo.ErrInput},
		{"nested-der", `<k:DEREncodedKeyValue><ds:KeyName>x</ds:KeyName></k:DEREncodedKeyValue>`, keyinfo.ErrInput},
		{"bad-der", `<k:DEREncodedKeyValue>AQID</k:DEREncodedKeyValue>`, keyinfo.ErrKey},
		{"empty-x509", `<ds:X509Data/>`, keyinfo.ErrInput},
		{"bad-cert", `<ds:X509Data><ds:X509Certificate>AQID</ds:X509Certificate></ds:X509Data>`, keyinfo.ErrInput},
		{"bad-crl", `<ds:X509Data><ds:X509CRL>AQID</ds:X509CRL></ds:X509Data>`, keyinfo.ErrInput},
		{"ec-explicit", `<ds:KeyValue><k:ECKeyValue><k:ECParameters/><k:PublicKey>AQID</k:PublicKey></k:ECKeyValue></ds:KeyValue>`, keyinfo.ErrUnsupported},
		{"ec-point", `<ds:KeyValue><k:ECKeyValue><k:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><k:PublicKey>` + enc(badPoint) + `</k:PublicKey></k:ECKeyValue></ds:KeyValue>`, keyinfo.ErrKey},
		{"ec-unknown", `<ds:KeyValue><k:ECKeyValue><k:NamedCurve URI="urn:unknown"/><k:PublicKey>AQID</k:PublicKey></k:ECKeyValue></ds:KeyValue>`, keyinfo.ErrUnsupported},
		{"missing-uri", `<k:KeyInfoReference/>`, keyinfo.ErrInput},
		{"missing-retrieval-uri", `<ds:RetrievalMethod/>`, keyinfo.ErrInput},
		{"reference-child", `<k:KeyInfoReference URI="#none"><ds:KeyName>x</ds:KeyName></k:KeyInfoReference>`, keyinfo.ErrInput},
		{"bad-type", `<ds:RetrievalMethod URI="urn:key" Type="urn:unsupported"/>`, keyinfo.ErrUnsupported},
		{"unsupported-transform", `<ds:RetrievalMethod URI="urn:key"><ds:Transforms><ds:Transform Algorithm="urn:unknown"/></ds:Transforms></ds:RetrievalMethod>`, keyinfo.ErrUnsupported},
		{"attributes", `<ds:KeyName Algorithm="unexpected">name</ds:KeyName>`, keyinfo.ErrInput},
		{"mixed-text", `text` + derXML(t, &k.PublicKey), keyinfo.ErrInput},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) { requireErr(t, wrap(test.body), keyinfo.Options{}, test.err) })
	}
}

func TestSameDocumentReferencesAndCycles(t *testing.T) {
	k := ec(t, elliptic.P256())
	prefix := `<root xmlns:ds="` + ns + `" xmlns:k="` + ns11 + `">`

	cases := []struct {
		name, xml string
		opt       keyinfo.Options
		err       error
	}{
		{"chain", prefix + `<ds:KeyInfo Id="a"><k:KeyInfoReference URI="#b"/></ds:KeyInfo><ds:KeyInfo Id="b">` + derXML(t, &k.PublicKey) + `</ds:KeyInfo></root>`, keyinfo.Options{}, nil},
		{"cycle", prefix + `<ds:KeyInfo Id="a"><k:KeyInfoReference URI="#b"/></ds:KeyInfo><ds:KeyInfo Id="b"><k:KeyInfoReference URI="#a"/></ds:KeyInfo></root>`, keyinfo.Options{}, keyinfo.ErrCycle},
		{"duplicate-id", prefix + `<ds:KeyInfo Id="a"><ds:KeyName>a</ds:KeyName></ds:KeyInfo><ds:KeyInfo Id="a"><ds:KeyName>b</ds:KeyName></ds:KeyInfo></root>`, keyinfo.Options{}, keyinfo.ErrInput},
		{"wrong-target", prefix + `<ds:KeyInfo><k:KeyInfoReference URI="#v"/></ds:KeyInfo><k:DEREncodedKeyValue Id="v">AQID</k:DEREncodedKeyValue></root>`, keyinfo.Options{}, keyinfo.ErrInput},
		{"percent-id", prefix + `<ds:KeyInfo><k:KeyInfoReference URI="#%62"/></ds:KeyInfo><ds:KeyInfo Id="b">` + derXML(t, &k.PublicKey) + `</ds:KeyInfo></root>`, keyinfo.Options{}, nil},
		{"xpointer", prefix + `<ds:KeyInfo><k:KeyInfoReference URI="#xpointer(id('b'))"/></ds:KeyInfo><ds:KeyInfo Id="b">` + derXML(t, &k.PublicKey) + `</ds:KeyInfo></root>`, keyinfo.Options{}, nil},
		{"not-arbitrary-Id", prefix + `<ds:KeyInfo><ds:RetrievalMethod URI="#v"/></ds:KeyInfo><ds:X509Data Id="v"/></root>`, keyinfo.Options{}, keyinfo.ErrInput},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			d := parseXML(t, test.xml)

			r, e := keyinfo.Parse(context.Background(), d, d.Root().Children()[0], test.opt)
			if test.err != nil {
				if r != nil || !errors.Is(e, test.err) {
					t.Fatalf("got %v %v", r, e)
				}

				return
			}

			if e != nil || len(r.Candidates()) != 1 {
				t.Fatalf("got %v %v", r, e)
			}
		})
	}
}

func TestRawCertificateRetrieval(t *testing.T) {
	k := ec(t, elliptic.P256())
	der := cert(t, k)
	uri := "urn:cert"
	makeXML := func(uri, transforms string) string {
		return wrap(`<ds:RetrievalMethod URI="` + uri + `" Type="` + keyinfo.RawX509Certificate + `">` + transforms + `</ds:RetrievalMethod>`)
	}

	base64T := `<ds:Transforms><ds:Transform Algorithm="` + reference.Base64 + `"/></ds:Transforms>`
	for _, test := range []struct {
		name, transform string
		data            []byte
	}{{"raw", "", der}, {"base64", base64T, []byte(enc(der))}} {
		t.Run(test.name, func(t *testing.T) {
			d := parseXML(t, makeXML(uri, test.transform))

			r, e := keyinfo.Parse(context.Background(), d, d.Root(), keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uri}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(test.data)), nil
			})}})
			if e != nil {
				t.Fatal(e)
			}

			c := r.Candidates()[0]
			if !bytes.Equal(c.CertificateDER(), der) || c.ResourceURI() != uri {
				t.Fatal("raw cert mismatch")
			}
		})
	}
	// Same-document base64 uses selected text nodes; the container QName is opt-in.
	xml := `<root xmlns:ds="` + ns + `" xmlns:k="` + ns11 + `"><ds:KeyInfo><ds:RetrievalMethod URI="#blob" Type="` + keyinfo.RawX509Certificate + `">` + base64T + `</ds:RetrievalMethod></ds:KeyInfo><data ID="blob">` + enc(der) + `</data></root>`
	d := parseXML(t, xml)

	r, e := keyinfo.Parse(context.Background(), d, d.Root().Children()[0], keyinfo.Options{AdditionalIDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "ID"}, Elements: []document.Name{{Local: "data"}}}}})
	if e != nil || !bytes.Equal(r.Candidates()[0].CertificateDER(), der) {
		t.Fatal(e)
	}
}

func TestExternalLifecycleLimitsAndCaching(t *testing.T) {
	k := ec(t, elliptic.P256())
	remote := []byte(wrap(derXML(t, &k.PublicKey)))
	xml := wrap(`<k:KeyInfoReference URI="urn:remote"/><k:KeyInfoReference URI="urn:remote"/>`)
	calls := 0
	source := resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return io.NopCloser(bytes.NewReader(remote)), nil
	})
	d := parseXML(t, xml)
	opt := keyinfo.Options{External: &keyinfo.ExternalResources{Resolver: source, AllowedURIs: []string{uriUrnRemote}}}

	r, e := keyinfo.Parse(context.Background(), d, d.Root(), opt)
	if e != nil || calls != 1 || len(r.Candidates()) != 2 || len(r.ExternalURIs()) != 1 {
		t.Fatalf("cache: %v %v calls=%d", r, e, calls)
	}

	opt.Limits.MaxCandidates = 1
	requireErr(t, xml, opt, keyinfo.ErrLimit)
	opt.Limits = keyinfo.Limits{}
	opt.Limits.MaxTotalBytes = 100
	requireErr(t, xml, opt, keyinfo.ErrLimit)
	opt.Limits = keyinfo.Limits{}
	opt.Limits.MaxExternalBytes = len(remote) - 1
	requireErr(t, xml, opt, keyinfo.ErrLimit)
	requireErr(t, xml, keyinfo.Options{}, keyinfo.ErrPolicy)
	requireErr(t, xml, keyinfo.Options{External: &keyinfo.ExternalResources{Resolver: source, AllowedURIs: []string{"urn:not-remote"}}}, keyinfo.ErrPolicy)

	for _, test := range []struct {
		name                string
		read                func([]byte) (int, error)
		closeErr, errorWant error
	}{
		{"no-progress", func([]byte) (int, error) { return 0, nil }, nil, io.ErrNoProgress},
		{"read-error", func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }, nil, io.ErrUnexpectedEOF},
		{"invalid-count", func([]byte) (int, error) { return -1, nil }, nil, keyinfo.ErrResource},
		{"too-large-count", func(b []byte) (int, error) { return len(b) + 1, nil }, nil, keyinfo.ErrResource},
		{"close-error", bytes.NewReader(remote).Read, io.ErrClosedPipe, io.ErrClosedPipe},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := &reader{read: test.read, closeErr: test.closeErr}
			o := keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnRemote}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) { return stream, nil })}}
			requireErr(t, xml, o, test.errorWant)

			if !stream.closed {
				t.Fatal("not closed")
			}
		})
	}

	t.Run("resolver-error-closes-reader", func(t *testing.T) {
		stream := &reader{}
		o := keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnRemote}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) { return stream, io.ErrUnexpectedEOF })}}
		requireErr(t, xml, o, io.ErrUnexpectedEOF)

		if !stream.closed {
			t.Fatal("not closed")
		}
	})
	t.Run("typed-nil-reader", func(t *testing.T) {
		var stream *reader

		requireErr(t, xml, keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnRemote}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) { return stream, nil })}}, keyinfo.ErrResource)
	})
}

func TestExternalCycleAndDepthBeforeIO(t *testing.T) {
	xml := wrap(`<k:KeyInfoReference URI="urn:first"/>`)
	calls := 0
	opt := keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnFirst, "urn:second"}, Resolver: resolverFunc(func(_ context.Context, u string) (io.ReadCloser, error) {
		calls++

		next := uriUrnFirst
		if u == uriUrnFirst {
			next = "urn:second"
		}

		return io.NopCloser(strings.NewReader(wrap(`<k:KeyInfoReference URI="` + next + `"/>`))), nil
	})}}
	requireErr(t, xml, opt, keyinfo.ErrCycle)

	if calls != 2 {
		t.Fatal("cache/cycle", calls)
	}

	calls = 0
	opt.Limits.MaxDepth = 1
	requireErr(t, xml, opt, keyinfo.ErrLimit)

	if calls != 1 {
		t.Fatalf("fetched past depth boundary: %d", calls)
	}

	calls = 0
	opt.Limits = keyinfo.Limits{MaxExternalResources: 1}
	requireErr(t, xml, opt, keyinfo.ErrLimit)

	if calls != 1 {
		t.Fatal(calls)
	}
}

func TestCancellationBadPolicyAndForeignSnapshot(t *testing.T) {
	d := parseXML(t, wrap(`<ds:KeyName>x</ds:KeyName>`))
	other := parseXML(t, asXML(t, d))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if r, e := keyinfo.Parse(ctx, d, d.Root(), keyinfo.Options{}); r != nil || !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}

	if r, e := keyinfo.Parse(context.Background(), d, other.Root(), keyinfo.Options{}); r != nil || !errors.Is(e, keyinfo.ErrInput) {
		t.Fatal(e)
	}

	if _, e := keyinfo.Parse(nil, d, d.Root(), keyinfo.Options{}); !errors.Is(e, keyinfo.ErrInput) {
		t.Fatal(e)
	}

	for _, limit := range []keyinfo.Limits{{MaxDepth: -1}, {MaxDepth: 33}, {MaxElements: -1}, {MaxRSABits: 511}, {MaxBlobBytes: 9 << 20}} {
		requireErr(t, asXML(t, d), keyinfo.Options{Limits: limit}, keyinfo.ErrPolicy)
	}

	for _, uri := range []string{"relative", "https://user:pw@example.org/key", "https://example.org/key#ki", "urn:bad\nuri"} {
		requireErr(t, asXML(t, d), keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uri}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) { t.Fatal("unexpected I/O"); return nil, nil })}}, keyinfo.ErrPolicy)
	}
}

func TestConflictingBareDeclarations(t *testing.T) {
	a, b := ec(t, elliptic.P256()), ec(t, elliptic.P256())

	r := parseInfo(t, wrap(derXML(t, &a.PublicKey)+derXML(t, &b.PublicKey)))
	if !errors.Is(r.CheckKeyDeclarations(0), keyinfo.ErrKey) || !errors.Is(r.CheckKeyDeclarations(2), keyinfo.ErrKey) {
		t.Fatal("conflict ignored")
	}
}

func BenchmarkParseKeyInfo(b *testing.B) {
	k := ec(b, elliptic.P256())

	d, e := keyinfo.Build(context.Background(), keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &k.PublicKey}}})
	if e != nil {
		b.Fatal(e)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, e := keyinfo.Parse(context.Background(), d, d.Root(), keyinfo.Options{}); e != nil {
			b.Fatal(e)
		}
	}
}

func FuzzParseKeyInfo(f *testing.F) {
	for _, s := range []string{wrap(`<ds:KeyName>name</ds:KeyName>`), `<ds:KeyInfo xmlns:ds="` + ns + `" xmlns:k="` + ns11 + `" Id="x"><k:KeyInfoReference URI="#x"/></ds:KeyInfo>`, wrap(`<k:DEREncodedKeyValue>AQID</k:DEREncodedKeyValue>`)} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}

		d, e := document.Parse(t.Context(), b, document.DefaultLimits())
		if e != nil {
			return
		}

		r, e := keyinfo.Parse(context.Background(), d, d.Root(), keyinfo.Options{Limits: keyinfo.Limits{MaxBlobBytes: 8192, MaxTotalBytes: 16384, MaxElements: 128}})
		if e != nil && r != nil {
			t.Fatal("partial result")
		}

		if e == nil {
			for _, c := range r.Candidates() {
				k, e := c.PublicKey()
				if e != nil || k == nil {
					t.Fatal("invalid key in result")
				}
			}
		}
	})
}

func parseXML(t testing.TB, s string) *document.Document {
	t.Helper()

	d, e := document.Parse(t.Context(), []byte(s), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	return d
}

func wrap(s string) string {
	return `<ds:KeyInfo xmlns:ds="` + ns + `" xmlns:k="` + ns11 + `">` + s + `</ds:KeyInfo>`
}

func asXML(t testing.TB, d *document.Document) string {
	t.Helper()

	b, e := d.XML(t.Context())
	if e != nil {
		t.Fatal(e)
	}

	return string(b)
}

func ec(t testing.TB, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	k, e := ecdsa.GenerateKey(c, rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	return k
}

func parseInfo(t testing.TB, s string) *keyinfo.Result {
	t.Helper()
	d := parseXML(t, s)

	r, e := keyinfo.Parse(context.Background(), d, d.Root(), keyinfo.Options{})
	if e != nil {
		t.Fatal(e)
	}

	return r
}

func cert(t testing.TB, k *ecdsa.PrivateKey) []byte {
	t.Helper()

	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	c := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "keyinfo-test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, SubjectKeyId: []byte{1, 2, 3}}

	der, e := x509.CreateCertificate(rand.Reader, c, c, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}

	return der
}

func enc(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func derXML(t testing.TB, key crypto.PublicKey) string {
	t.Helper()

	der, e := x509.MarshalPKIXPublicKey(key)
	if e != nil {
		t.Fatal(e)
	}

	return `<k:DEREncodedKeyValue>` + enc(der) + `</k:DEREncodedKeyValue>`
}

func requireErr(t testing.TB, xml string, opt keyinfo.Options, want error) {
	t.Helper()
	d := parseXML(t, xml)

	r, e := keyinfo.Parse(context.Background(), d, d.Root(), opt)
	if r != nil || !errors.Is(e, want) {
		t.Fatalf("got result=%v err=%v; want %v", r, e, want)
	}
}

type resolverFunc func(context.Context, string) (io.ReadCloser, error)

func (f resolverFunc) Resolve(ctx context.Context, u string) (io.ReadCloser, error) { return f(ctx, u) }

type reader struct {
	read     func([]byte) (int, error)
	closed   bool
	closeErr error
}

func (r *reader) Read(b []byte) (int, error) { return r.read(b) }

func (r *reader) Close() error { r.closed = true; return r.closeErr }
