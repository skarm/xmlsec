package xmldsig_test

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
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	nameUnknownAlgorithm = "unknown-algorithm"
	uriUrnPayload        = "urn:payload"
)

func TestVerifySignatureWithExplicitKeyInfoTrust(t *testing.T) {
	k := coreEC(t)

	ki, e := keyinfo.Build(context.Background(), keyinfo.Template{ID: "key", Names: []string{"not an identity"}, Keys: []keyinfo.PublicKeyValue{{Key: &k.PublicKey}}})
	if e != nil {
		t.Fatal(e)
	}

	signed, sel := makeKeyInfoSigned(t, k, ki)
	before := coreXML(t, signed)
	opt := xmldsig.KeyInfoVerifyOptions{Signature: xmldsig.SignatureOptions{ExpectedURIs: []string{namePayload}, RequiredElements: []document.Element{signed.Root().Children()[0]}}, SelectTrustedKey: keySelector(t, &k.PublicKey)}

	r, e := xmldsig.VerifySignatureWithKeyInfo(context.Background(), signed, sel, opt)
	if e != nil || !r.CoversElement(signed.Root().Children()[0]) || r.CoversElement(signed.Root()) || coreXML(t, signed) != before {
		t.Fatalf("result=%v error=%v", r, e)
	}

	t.Run("key-data-policy-before-trust", func(t *testing.T) {
		called := false
		o := opt
		o.KeyInfo.AllowedKeyData = []document.Name{{Space: keyinfo.Namespace, Local: "X509Data"}}

		o.SelectTrustedKey = func(context.Context, *keyinfo.Result) (int, error) { called = true; return 0, nil }
		if result, err := xmldsig.VerifySignatureWithKeyInfo(context.Background(), signed, sel, o); result != nil || !errors.Is(err, keyinfo.ErrPolicy) || called {
			t.Fatal("disallowed key data reached trust callback", err)
		}
	})
	t.Run("no-default-trust", func(t *testing.T) {
		o := opt
		o.SelectTrustedKey = nil

		r, e := xmldsig.VerifySignatureWithKeyInfo(context.Background(), signed, sel, o)
		if r != nil || !errors.Is(e, xmldsig.ErrKeyInfoTrust) {
			t.Fatal(e)
		}
	})
	t.Run("wrong-pin", func(t *testing.T) {
		o := opt
		o.SelectTrustedKey = keySelector(t, &coreEC(t).PublicKey)

		r, e := xmldsig.VerifySignatureWithKeyInfo(context.Background(), signed, sel, o)
		if r != nil || !errors.Is(e, xmldsig.ErrKeyInfoTrust) {
			t.Fatal(e)
		}
	})
	t.Run("invalid-index", func(t *testing.T) {
		o := opt
		o.SelectTrustedKey = func(context.Context, *keyinfo.Result) (int, error) { return 99, nil }

		r, e := xmldsig.VerifySignatureWithKeyInfo(context.Background(), signed, sel, o)
		if r != nil || !errors.Is(e, xmldsig.ErrKeyInfoTrust) {
			t.Fatal(e)
		}
	})
	t.Run("fresh-key-after-callback", func(t *testing.T) {
		o := opt

		o.SelectTrustedKey = func(_ context.Context, info *keyinfo.Result) (int, error) {
			p, _ := info.Candidates()[0].PublicKey()
			p.(*ecdsa.PublicKey).X.SetInt64(0) //nolint:staticcheck // Deliberately mutate legacy coordinates to test malformed keys and snapshot ownership.

			return 0, nil
		}
		if _, e := xmldsig.VerifySignatureWithKeyInfo(context.Background(), signed, sel, o); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("freeze-reference-policy", func(t *testing.T) {
		o := opt
		o.Signature.ExpectedURIs = []string{namePayload}

		o.SelectTrustedKey = func(context.Context, *keyinfo.Result) (int, error) {
			o.Signature.ExpectedURIs[0] = "#tampered"
			return 0, nil
		}
		if _, e := xmldsig.VerifySignatureWithKeyInfo(context.Background(), signed, sel, o); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("preserve-empty-expected", func(t *testing.T) {
		o := opt
		o.Signature.ExpectedURIs = []string{}
		o.SelectTrustedKey = func(context.Context, *keyinfo.Result) (int, error) {
			t.Fatal("selector called for invalid policy")
			return 0, nil
		}

		r, e := xmldsig.VerifySignatureWithKeyInfo(context.Background(), signed, sel, o)
		if r != nil || !errors.Is(e, xmldsig.ErrPolicy) {
			t.Fatal(e)
		}
	})
	t.Run("payload-change", func(t *testing.T) {
		d := coreParse(t, strings.Replace(before, "hello", "hacked", 1))
		o := opt
		o.Signature.RequiredElements = nil

		r, e := xmldsig.VerifySignatureWithKeyInfo(context.Background(), d, xmldsig.Signatures(d)[0], o)
		if r != nil || e == nil {
			t.Fatal("payload accepted")
		}
	})
	t.Run("old-explicit-key-api-unchanged", func(t *testing.T) {
		if _, e := xmldsig.VerifySignature(context.Background(), signed, sel, &k.PublicKey, opt.Signature); e != nil {
			t.Fatal(e)
		}
	})
}

func TestKeyInfoIntegrationRejectsContradictoryDeclarations(t *testing.T) {
	ctx := context.Background()
	k := coreEC(t)
	other := coreEC(t)

	ki, e := keyinfo.Build(ctx, keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &k.PublicKey}, {Key: &other.PublicKey}}})
	if e != nil {
		t.Fatal(e)
	}

	doc, sel := makeKeyInfoSigned(t, k, ki)
	// A correct signature with an explicitly supplied key can still be checked.
	if _, e := xmldsig.VerifySignature(ctx, doc, sel, &k.PublicKey, xmldsig.SignatureOptions{}); e != nil {
		t.Fatal(e)
	}

	r, e := xmldsig.VerifySignatureWithKeyInfo(ctx, doc, sel, xmldsig.KeyInfoVerifyOptions{SelectTrustedKey: keySelector(t, &k.PublicKey)})
	if r != nil || !errors.Is(e, keyinfo.ErrKey) {
		t.Fatal("contradictory declarations accepted", e)
	}
}

func TestKeyInfoLinkedFromSignature(t *testing.T) {
	ctx := context.Background()
	k := coreEC(t)

	info, e := keyinfo.Build(ctx, keyinfo.Template{ID: "shared", Keys: []keyinfo.PublicKeyValue{{Key: &k.PublicKey}}})
	if e != nil {
		t.Fatal(e)
	}

	d := coreParse(t, `<root><payload ID="payload">hello</payload>`+coreXML(t, info)+`</root>`)

	linked, e := keyinfo.Build(ctx, keyinfo.Template{KeyInfoReferences: []string{"#shared"}})
	if e != nil {
		t.Fatal(e)
	}

	draft, sel, e := xmldsig.BuildTemplate(ctx, d, d.Root(), xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, KeyInfo: linked, References: []xmldsig.ReferenceTemplate{{URI: namePayload}}})
	if e != nil {
		t.Fatal(e)
	}

	signed, e := xmldsig.SignTemplate(ctx, draft, sel, k, xmldsig.TemplateSignOptions{})
	if e != nil {
		t.Fatal(e)
	}

	if _, e := xmldsig.VerifySignatureWithKeyInfo(ctx, signed, xmldsig.Signatures(signed)[0], xmldsig.KeyInfoVerifyOptions{SelectTrustedKey: keySelector(t, &k.PublicKey)}); e != nil {
		t.Fatal(e)
	}
	// A KeyInfo from another signature is NOT searched automatically.
	noInfo, e := keyinfo.Build(ctx, keyinfo.Template{Names: []string{"irrelevant"}})
	if e != nil {
		t.Fatal(e)
	}

	missing, selected := makeKeyInfoSigned(t, k, noInfo)
	if r, e := xmldsig.VerifySignatureWithKeyInfo(ctx, missing, selected, xmldsig.KeyInfoVerifyOptions{SelectTrustedKey: keySelector(t, &k.PublicKey)}); e == nil || r != nil {
		t.Fatal("guessed key")
	}
}

func TestKeyInfoResourceOrderAndInvalidPreflight(t *testing.T) {
	ctx := context.Background()
	k := coreEC(t)

	ki, e := keyinfo.Build(ctx, keyinfo.Template{KeyInfoReferences: []string{"urn:key"}})
	if e != nil {
		t.Fatal(e)
	}

	remote, e := keyinfo.Build(ctx, keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &k.PublicKey}}})
	if e != nil {
		t.Fatal(e)
	}

	remoteBytes, _ := remote.XML(ctx)
	payload := []byte("unparsed signed binary")
	ext := &xmldsig.ExternalReferences{AllowedURIs: []string{uriUrnPayload}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(payload)), nil
	})}

	draft, sel, e := xmldsig.BuildTemplate(ctx, nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, KeyInfo: ki, References: []xmldsig.ReferenceTemplate{{URI: uriUrnPayload}}})
	if e != nil {
		t.Fatal(e)
	}

	signed, e := xmldsig.SignTemplate(ctx, draft, sel, k, xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{External: ext}})
	if e != nil {
		t.Fatal(e)
	}

	for _, name := range []string{"success", "reject-trust", "invalid-signature", nameUnknownAlgorithm} {
		t.Run(name, func(t *testing.T) {
			testKeyInfoResourceOrderAndInvalidPreflightCase(t, &signed, &name, &payload, &remoteBytes, &k, &ctx)
		})
	}
}

func testKeyInfoResourceOrderAndInvalidPreflightCase(t *testing.T, signed **document.Document, name *string, payload *[]byte, remoteBytes *[]byte, k **ecdsa.PrivateKey, ctx *context.Context) {
	var sequence []string

	local := (*signed)

	xml := coreXML(t, (*signed))
	if (*name) == nameUnknownAlgorithm {
		local = coreParse(t, strings.Replace(xml, xmldsig.ECDSASHA256, "urn:unsupported", 1))
	}

	if (*name) == "invalid-signature" {
		start := strings.Index(xml, "<ds:SignatureValue>") + len("<ds:SignatureValue>")

		rep := "A"
		if xml[start] == 'A' {
			rep = "B"
		}

		local = coreParse(t, xml[:start]+rep+xml[start+1:])
	}

	payloadResolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		sequence = append(sequence, "payload")
		return io.NopCloser(bytes.NewReader((*payload))), nil
	})
	keyResolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		sequence = append(sequence, "key")
		return io.NopCloser(bytes.NewReader((*remoteBytes))), nil
	})
	o := xmldsig.KeyInfoVerifyOptions{Signature: xmldsig.SignatureOptions{ExpectedURIs: []string{uriUrnPayload}, External: &xmldsig.ExternalReferences{AllowedURIs: []string{uriUrnPayload}, Resolver: payloadResolver}}, KeyInfo: keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{"urn:key"}, Resolver: keyResolver}}, SelectTrustedKey: func(ctx context.Context, info *keyinfo.Result) (int, error) {
		sequence = append(sequence, "trust")

		if (*name) == "reject-trust" {
			return -1, errors.New("untrusted")
		}

		return keySelector(t, &(*k).PublicKey)(ctx, info)
	}}
	r, e := xmldsig.VerifySignatureWithKeyInfo((*ctx), local, xmldsig.Signatures(local)[0], o)

	want := "key,trust"
	if (*name) == "success" {
		want = "key,trust,payload"

		if e != nil {
			t.Fatal(e)
		}
	} else if e == nil || r != nil {
		t.Fatal("bad document accepted")
	}

	if (*name) == nameUnknownAlgorithm {
		want = ""
	}

	if strings.Join(sequence, ",") != want {
		t.Fatalf("wrong evaluation order %v; want %s", sequence, want)
	}
}

func TestKeyInfoExplicitPKIXSelection(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)

	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	leafKey := coreEC(t)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}

	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}

	issuer, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}

	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "expected-partner"}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}

	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, issuer, &leafKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	// Put the root FIRST: certificate order must not select a signing identity.
	ki, e := keyinfo.Build(ctx, keyinfo.Template{Certificates: [][]byte{caDER, leafDER}})
	if e != nil {
		t.Fatal(e)
	}

	doc, sel := makeKeyInfoSigned(t, leafKey, ki)

	verifier, e := pki.NewVerifier(pki.Config{Roots: [][]byte{caDER}})
	if e != nil {
		t.Fatal(e)
	}

	selector := func(ctx context.Context, info *keyinfo.Result) (int, error) {
		for i, c := range info.Candidates() {
			cert, e := c.Certificate()
			if e != nil || cert == nil || cert.Subject.CommonName != "expected-partner" {
				continue
			}

			if _, _, e := verifier.Verify(ctx, c.CertificateDER(), now, pki.Evidence{}); e == nil {
				return i, nil
			}
		}

		return -1, errors.New("no authorized partner certificate")
	}
	if _, e := xmldsig.VerifySignatureWithKeyInfo(ctx, doc, sel, xmldsig.KeyInfoVerifyOptions{SelectTrustedKey: selector}); e != nil {
		t.Fatal(e)
	}
}

func TestKeyInfoBuilderMutualExclusion(t *testing.T) {
	ki, e := keyinfo.Build(context.Background(), keyinfo.Template{Names: []string{"x"}})
	if e != nil {
		t.Fatal(e)
	}

	for _, test := range []struct {
		name  string
		ki    *document.Document
		certs [][]byte
	}{{"both", ki, [][]byte{{1}}}, {"wrong-root", coreParse(t, `<not-KeyInfo/>`), nil}} {
		t.Run(test.name, func(t *testing.T) {
			_, _, e := xmldsig.BuildTemplate(context.Background(), nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, KeyInfo: test.ki, Certificates: test.certs, References: []xmldsig.ReferenceTemplate{{URI: nameData}}, Objects: []xmldsig.ObjectTemplate{{ID: nameData2, Binary: []byte("x")}}})
			if e == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func FuzzVerifyWithKeyInfo(f *testing.F) {
	dir := filepath.Join("..", "testdata", "keyinfo")

	raw, e := os.ReadFile(filepath.Join(dir, "p256-xml.signature.xml"))
	if e != nil {
		f.Fatal(e)
	}

	der, e := os.ReadFile(filepath.Join(dir, "p256-xml.spki.der"))
	if e != nil {
		f.Fatal(e)
	}

	key, e := x509.ParsePKIXPublicKey(der)
	if e != nil {
		f.Fatal(e)
	}

	selectKey := keySelector(f, key)
	f.Add(raw)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}

		d, e := document.Parse(t.Context(), b, document.DefaultLimits())
		if e != nil {
			return
		}

		sigs := xmldsig.Signatures(d)
		if len(sigs) != 1 {
			return
		}

		r, e := xmldsig.VerifySignatureWithKeyInfo(context.Background(), d, sigs[0], xmldsig.KeyInfoVerifyOptions{Signature: xmldsig.SignatureOptions{ExpectedURIs: []string{nameData}}, SelectTrustedKey: selectKey})
		if e != nil && r != nil {
			t.Fatal("partial success")
		}
	})
}

func keySelector(t testing.TB, expected crypto.PublicKey) xmldsig.TrustedKeySelector {
	t.Helper()

	spki, e := x509.MarshalPKIXPublicKey(expected)
	if e != nil {
		t.Fatal(e)
	}

	pin := sha256.Sum256(spki)

	return func(ctx context.Context, r *keyinfo.Result) (int, error) {
		if e := ctx.Err(); e != nil {
			return -1, e
		}

		for i, c := range r.Candidates() {
			if sha256.Sum256(c.SPKI()) == pin {
				return i, nil
			}
		}

		return -1, errors.New("expected partner key not found")
	}
}

func makeKeyInfoSigned(t testing.TB, k crypto.Signer, ki *document.Document) (*document.Document, document.Element) {
	t.Helper()

	ctx := context.Background()
	d := coreParse(t, `<root><payload ID="payload">hello</payload></root>`)

	draft, selected, e := xmldsig.BuildTemplate(ctx, d, d.Root(), xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, KeyInfo: ki, References: []xmldsig.ReferenceTemplate{{URI: namePayload, Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}}})
	if e != nil {
		t.Fatal(e)
	}

	signed, e := xmldsig.SignTemplate(ctx, draft, selected, k, xmldsig.TemplateSignOptions{})
	if e != nil {
		t.Fatal(e)
	}

	return signed, xmldsig.Signatures(signed)[0]
}
