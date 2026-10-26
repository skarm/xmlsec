package keyinfo_test

import (
	"bytes"
	"context"
	"crypto"

	// #nosec G406 -- Explicit bounded legacy compatibility only.
	"crypto/dsa" //nolint:staticcheck // XMLDSig 1.1 requires legacy DSA verification; generation is disabled.
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
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
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

func TestLegacyDSAKeyInfo(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "legacy-dsig", "dsa-public.pem"))
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("DSA public fixture")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	for _, format := range []keyinfo.KeyFormat{keyinfo.XMLKeyValue, keyinfo.DERKeyValue} {
		d, err := keyinfo.Build(t.Context(), keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: key, Format: format}}})
		if err != nil {
			t.Fatal(err)
		}

		result, err := keyinfo.Parse(t.Context(), d, d.Root(), keyinfo.Options{})
		if err != nil || len(result.Candidates()) != 1 {
			t.Fatal(result, err)
		}

		candidate := result.Candidates()[0]
		if !bytes.Equal(candidate.SPKI(), block.Bytes) {
			t.Fatal("SPKI differs from independent JDK key")
		}

		copyKey, err := candidate.PublicKey()
		if err != nil {
			t.Fatal(err)
		}

		copyKey.(*dsa.PublicKey).Y.SetInt64(0)

		fresh, err := candidate.PublicKey()
		if err != nil || fresh.(*dsa.PublicKey).Y.Cmp(key.(*dsa.PublicKey).Y) != 0 {
			t.Fatal("candidate key changed", err)
		}

		if _, err := keyinfo.Parse(t.Context(), d, d.Root(), keyinfo.Options{AllowedKeyData: []document.Name{{Space: ns, Local: "RSAKeyValue"}}}); !errors.Is(err, keyinfo.ErrPolicy) {
			t.Fatal("DSA allowlist bypass", err)
		}

		if format == keyinfo.XMLKeyValue {
			testLegacyDSAKeyInfoMutations(t, d, key.(*dsa.PublicKey))
			testLegacyDSAParameterContext(t, d, key.(*dsa.PublicKey))
		}
	}
}

func testLegacyDSAParameterContext(t *testing.T, full *document.Document, key *dsa.PublicKey) {
	t.Helper()
	expected := parseInfo(t, asXML(t, full)).Candidates()[0].SPKI()

	for _, fields := range [][]string{{"P", "Q"}, {"G"}, {"P", "Q", "G"}} {
		xml := asXML(t, full)

		for _, name := range fields {
			value := map[string]*big.Int{"P": key.P, "Q": key.Q, "G": key.G}[name]
			xml = strings.Replace(xml, "<ds:"+name+">"+enc(value.Bytes())+"</ds:"+name+">", "", 1)
		}

		doc := parseXML(t, xml)

		result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{DSAParameters: &key.Parameters})
		if err != nil || len(result.Candidates()) != 1 || !bytes.Equal(result.Candidates()[0].SPKI(), expected) {
			t.Fatal("parameter context did not reconstruct the independent key", err)
		}

		requireErr(t, xml, keyinfo.Options{}, keyinfo.ErrUnsupported)
	}

	missingQ := strings.Replace(asXML(t, full), "<ds:Q>"+enc(key.Q.Bytes())+"</ds:Q>", "", 1)
	requireErr(t, missingQ, keyinfo.Options{DSAParameters: &key.Parameters}, keyinfo.ErrInput)
	requireErr(t, asXML(t, full), keyinfo.Options{DSAParameters: &dsa.Parameters{P: big.NewInt(1), Q: key.Q, G: key.G}}, keyinfo.ErrPolicy)
	// An external callback cannot mutate the supplied context after Parse starts.
	contextParameters := dsa.Parameters{P: new(big.Int).Set(key.P), Q: new(big.Int).Set(key.Q), G: new(big.Int).Set(key.G)}
	remote := wrap(`<ds:KeyValue><ds:DSAKeyValue><ds:Y>` + enc(key.Y.Bytes()) + `</ds:Y></ds:DSAKeyValue></ds:KeyValue>`)
	root := parseXML(t, wrap(`<k:KeyInfoReference URI="urn:key"/>`))
	options := keyinfo.Options{DSAParameters: &contextParameters, External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		contextParameters.P.SetInt64(0)
		contextParameters.G.SetInt64(0)

		return io.NopCloser(strings.NewReader(remote)), nil
	})}}

	result, err := keyinfo.Parse(t.Context(), root, root.Root(), options)
	if err != nil || len(result.Candidates()) != 1 || !bytes.Equal(result.Candidates()[0].SPKI(), expected) {
		t.Fatal("mutable parameter context escaped its snapshot", err)
	}
}

func testLegacyDSAKeyInfoMutations(t *testing.T, d *document.Document, k *dsa.PublicKey) {
	t.Helper()
	source := asXML(t, d)
	p := base64.StdEncoding.EncodeToString(k.P.Bytes())
	j := base64.StdEncoding.EncodeToString(new(big.Int).Div(new(big.Int).Sub(k.P, big.NewInt(1)), k.Q).Bytes())
	withJ := strings.Replace(source, "</ds:DSAKeyValue>", "<ds:J>"+j+"</ds:J></ds:DSAKeyValue>", 1)

	jdoc := parseXML(t, withJ)
	if _, err := keyinfo.Parse(t.Context(), jdoc, jdoc.Root(), keyinfo.Options{}); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		xml  string
		want error
	}{
		{strings.Replace(source, p, base64.StdEncoding.EncodeToString(append([]byte{0}, k.P.Bytes()...)), 1), keyinfo.ErrInput},
		{strings.Replace(source, base64.StdEncoding.EncodeToString(k.G.Bytes()), "AQ==", 1), keyinfo.ErrKey},
		{strings.Replace(withJ, j, "AQ==", 1), keyinfo.ErrKey},
		{strings.Replace(source, "</ds:DSAKeyValue>", "<ds:Seed>AQ==</ds:Seed></ds:DSAKeyValue>", 1), keyinfo.ErrInput},
	} {
		bad := parseXML(t, test.xml)
		if _, err := keyinfo.Parse(t.Context(), bad, bad.Root(), keyinfo.Options{}); !errors.Is(err, test.want) {
			t.Fatal(err)
		}
	}
}

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
	d, e := keyinfo.Build(t.Context(), keyinfo.Template{ID: "ki", Names: []string{"  significant name\n"}, Keys: []keyinfo.PublicKeyValue{{Key: test.key, Format: *format}}})
	if test.name == "Ed25519" && (*format) == keyinfo.XMLKeyValue {
		if !errors.Is(e, keyinfo.ErrUnsupported) {
			t.Fatal(e)
		}

		return
	}

	if e != nil {
		t.Fatal(e)
	}

	out, e := keyinfo.Parse(t.Context(), d, d.Root(), keyinfo.Options{})
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

	d, e := keyinfo.Build(t.Context(), keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &k.PublicKey}}, Certificates: [][]byte{der}, Names: []string{"original"}})
	if e != nil {
		t.Fatal(e)
	}

	info, e := keyinfo.Parse(t.Context(), d, d.Root(), keyinfo.Options{})
	if e != nil {
		t.Fatal(e)
	}

	original := asXML(t, d)
	c := info.Candidates()[1]
	fp := c.FingerprintSHA256()
	p, _ := c.PublicKey()
	*p.(*ecdsa.PublicKey) = ecdsa.PublicKey{}

	raw := c.SPKI()
	raw[0] ^= 255
	raw = c.CertificateDER()
	raw[0] ^= 255

	certificate, e := c.Certificate()
	if e != nil {
		t.Fatal(e)
	}

	certificate.Raw[0] ^= 255
	*certificate.PublicKey.(*ecdsa.PublicKey) = ecdsa.PublicKey{}

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

				*key.(*ecdsa.PublicKey) = ecdsa.PublicKey{}

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
	g.SubjectNames()[0] = nameChanged

	g.IssuerSerials()[0].Issuer = nameChanged
	if !bytes.Equal(g.CertificateDigests()[0].Value, digest[:]) || g.SubjectKeyIdentifiers()[0][0] != 1 || g.SubjectNames()[0] != "CN=keyinfo-test" || g.IssuerSerials()[0].Issuer != subjectIssuer {
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
		name string
		body string
		err  error
	}{
		{nameEmpty, "", keyinfo.ErrInput},
		{"unknown", `<surprise xmlns="urn:other"/>`, keyinfo.ErrUnsupported},
		{"unqualified", `<KeyValue/>`, keyinfo.ErrUnsupported},
		{"wrong-order", `<ds:KeyValue><ds:RSAKeyValue><ds:Exponent>Aw==</ds:Exponent><ds:Modulus>Cw==</ds:Modulus></ds:RSAKeyValue></ds:KeyValue>`, keyinfo.ErrInput},
		{"even-exponent", `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>Cw==</ds:Modulus><ds:Exponent>Ag==</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>`, keyinfo.ErrKey},
		{"even-modulus", `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>DA==</ds:Modulus><ds:Exponent>Aw==</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>`, keyinfo.ErrKey},
		{"padded-integer", `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>AAs=</ds:Modulus><ds:Exponent>Aw==</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>`, keyinfo.ErrInput},
		{"huge-exponent", `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>////////</ds:Modulus><ds:Exponent>AQAAAAAAAAA=</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>`, keyinfo.ErrKey},
		{"extra-key", `<ds:KeyValue>` + derXML(t, &k.PublicKey) + derXML(t, &k.PublicKey) + `</ds:KeyValue>`, keyinfo.ErrInput},
		{"DER-in-KeyValue", `<ds:KeyValue>` + derXML(t, &k.PublicKey) + `</ds:KeyValue>`, keyinfo.ErrUnsupported},
		{"empty-DSA", `<ds:KeyValue><ds:DSAKeyValue/></ds:KeyValue>`, keyinfo.ErrInput},
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
		name string
		xml  string
		opt  keyinfo.Options
		err  error
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

			r, e := keyinfo.Parse(t.Context(), d, d.Root().Children()[0], test.opt)
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
		name      string
		transform string
		data      []byte
	}{{"raw", "", der}, {"base64", base64T, []byte(enc(der))}} {
		t.Run(test.name, func(t *testing.T) {
			d := parseXML(t, makeXML(uri, test.transform))

			r, e := keyinfo.Parse(t.Context(), d, d.Root(), keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uri}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
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

	r, e := keyinfo.Parse(t.Context(), d, d.Root().Children()[0], keyinfo.Options{AdditionalIDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "ID"}, Elements: []document.Name{{Local: "data"}}}}})
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

	r, e := keyinfo.Parse(t.Context(), d, d.Root(), opt)
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
		name      string
		read      func([]byte) (int, error)
		closeErr  error
		errorWant error
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
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if r, e := keyinfo.Parse(ctx, d, d.Root(), keyinfo.Options{}); r != nil || !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}

	if r, e := keyinfo.Parse(t.Context(), d, other.Root(), keyinfo.Options{}); r != nil || !errors.Is(e, keyinfo.ErrInput) {
		t.Fatal(e)
	}

	if _, e := keyinfo.Parse(nil, d, d.Root(), keyinfo.Options{}); !errors.Is(e, keyinfo.ErrInput) {
		t.Fatal(e)
	}

	for _, limit := range []keyinfo.Limits{{MaxDepth: -1}, {MaxDepth: 33}, {MaxElements: -1}, {MaxRSABits: 511}, {MaxBlobBytes: 9 << 20}} {
		requireErr(t, asXML(t, d), keyinfo.Options{Limits: limit}, keyinfo.ErrPolicy)
	}

	for _, uri := range []string{"relative", "https://user:pw@example.org/key", "https://example.org/key#ki#second", "urn:bad\nuri"} {
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

	d, e := keyinfo.Build(b.Context(), keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &k.PublicKey}}})
	if e != nil {
		b.Fatal(e)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, e := keyinfo.Parse(b.Context(), d, d.Root(), keyinfo.Options{}); e != nil {
			b.Fatal(e)
		}
	}
}

func FuzzParseKeyInfo(f *testing.F) {
	for _, s := range []string{wrap(`<ds:KeyName>name</ds:KeyName>`), `<ds:KeyInfo xmlns:ds="` + ns + `" xmlns:k="` + ns11 + `" Id="x"><k:KeyInfoReference URI="#x"/></ds:KeyInfo>`, wrap(`<k:DEREncodedKeyValue>AQID</k:DEREncodedKeyValue>`)} {
		f.Add([]byte(s))
	}

	f.Add([]byte(wrap(`<ds:RetrievalMethod URI=""><ds:Transforms><ds:Transform Algorithm="` + reference.Base64 + `"/></ds:Transforms></ds:RetrievalMethod>`)))
	f.Add([]byte(`<ds:KeyInfo xmlns:ds="` + ns + `" Id="x"><ds:RetrievalMethod URI="#x"><ds:Transforms><ds:Transform Algorithm="` + c14n.Exclusive + `"/></ds:Transforms></ds:RetrievalMethod></ds:KeyInfo>`))
	chain := testcert.New(f)

	x509Doc, err := keyinfo.Build(f.Context(), keyinfo.Template{X509Data: []keyinfo.X509Data{{
		Certificates: [][]byte{chain.Leaf.Raw}, CRLs: [][]byte{testcert.CRL(f, chain)},
		SubjectNames: []string{chain.Leaf.Subject.String()}, SubjectKeyIdentifiers: [][]byte{chain.Leaf.SubjectKeyId},
		IssuerSerials: []keyinfo.IssuerSerial{{Issuer: chain.Leaf.Issuer.String(), Serial: chain.Leaf.SerialNumber.String()}},
	}}})
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(asXML(f, x509Doc)))

	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}

		d, e := document.Parse(t.Context(), b, document.DefaultLimits())
		if e != nil {
			return
		}

		processing := reference.DefaultOptions()
		for _, opt := range []keyinfo.Options{{}, {RetrievalProcessing: &processing}} {
			opt.Limits = keyinfo.Limits{MaxBlobBytes: 8192, MaxTotalBytes: 16384, MaxElements: 128, MaxTransformBytes: 32768, MaxTransformNodes: 4096}

			r, e := keyinfo.Parse(t.Context(), d, d.Root(), opt)
			if e != nil && r != nil {
				t.Fatal("partial result")
			}

			if e == nil {
				for _, c := range r.Candidates() {
					key, err := c.PublicKey()
					if err != nil || key == nil {
						t.Fatal("invalid key in result")
					}
				}

				fuzzRebuildX509Groups(t, r)
			}
		}
	})
}

func fuzzRebuildX509Groups(t *testing.T, result *keyinfo.Result) {
	t.Helper()

	groups := result.X509Groups()
	if len(groups) == 0 {
		return
	}

	template := keyinfo.Template{}
	for _, group := range groups {
		template.X509Data = append(template.X509Data, keyinfo.X509Data{
			Certificates: group.CertificatesDER(), CRLs: group.CRLsDER(), IssuerSerials: group.IssuerSerials(),
			SubjectNames: group.SubjectNames(), SubjectKeyIdentifiers: group.SubjectKeyIdentifiers(), CertificateDigests: group.CertificateDigests(),
		})
	}

	doc, err := keyinfo.Build(t.Context(), template)
	if errors.Is(err, keyinfo.ErrLimit) {
		return // The builder bounds group/entry counts separately from Parse.
	}

	if err != nil {
		t.Fatal("cannot rebuild parsed X509Data", err)
	}

	parsed, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{})
	if err != nil || len(parsed.X509Groups()) != len(groups) {
		t.Fatal("rebuilt X509Data did not parse", err)
	}
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

	r, e := keyinfo.Parse(t.Context(), d, d.Root(), keyinfo.Options{})
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

	r, e := keyinfo.Parse(t.Context(), d, d.Root(), opt)
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
