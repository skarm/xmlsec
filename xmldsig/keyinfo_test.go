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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	nameUnknownAlgorithm = "unknown-algorithm"
	stage4KindManifest   = "manifest"
	uriUrnPayload        = "urn:payload"
	uriUrnKey            = "urn:key"
)

type stage4Vectors struct {
	PublicKey string             `json:"public_key_pem"`
	Cases     []stage4Case       `json:"cases"`
	Contexts  []stage4URIContext `json:"uri_contexts"`
}

type stage4Case struct {
	Name         string
	Kind         string
	XML          string
	Resources    map[string][]byte
	Programs     []reference.Transform
	DigestInputs [][]byte `json:"digest_inputs"`
}

type stage4URIContext struct {
	Name     string
	XML      string
	Relative string
	Resolved string
	BaseURI  string `json:"base_uri"`
}

func loadStage4Vectors(t testing.TB) (stage4Vectors, crypto.PublicKey) {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "testdata", "next", "dsig-stage4-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}

	var vectors stage4Vectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(vectors.PublicKey))
	if block == nil {
		t.Fatal("independent stage 4 public key missing")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(vectors.Cases) != 11 || len(vectors.Contexts) != 4 {
		t.Fatal("incomplete independent stage 4 corpus")
	}

	return vectors, key
}

func stage4Options(t testing.TB, test stage4Case) xmldsig.SignatureOptions {
	t.Helper()

	opt := xmldsig.SignatureOptions{Processing: reference.DefaultOptions(), ExpectedURIs: []string{"#payload"}}
	if test.Kind == stage4KindManifest {
		opt.ExpectedURIs = []string{uriExternalManifest}
		opt.Manifests = xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, AllowExternal: true, AllowTransformed: true}
	}

	if len(test.Programs) != 0 {
		engine, err := transform.NewEngine(transform.Config{AllowedPrograms: test.Programs})
		if err != nil {
			t.Fatal(err)
		}

		opt.Processing.Extension = engine
		for _, program := range test.Programs {
			opt.Processing.AllowedTransforms = append(opt.Processing.AllowedTransforms, program.Algorithm)
		}
	}

	if len(test.Resources) != 0 {
		external := &xmldsig.ExternalReferences{Resolver: xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			data, ok := test.Resources[uri]
			if !ok {
				return nil, xmldsig.ErrPolicy
			}

			return io.NopCloser(bytes.NewReader(data)), nil
		})}
		for uri := range test.Resources {
			external.AllowedURIs = append(external.AllowedURIs, uri)
		}

		opt.External = external
	}

	return opt
}

func TestXMLDSigStage4IndependentVectors(t *testing.T) {
	vectors, key := loadStage4Vectors(t)
	for _, test := range vectors.Cases {
		t.Run(test.Name, func(t *testing.T) {
			opt := stage4Options(t, test)
			doc := coreParse(t, test.XML)
			selected := xmldsig.Signatures(doc)[0]

			result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), doc, selected, key, opt)
			if err != nil || result == nil || report.SignatureValue != xmldsig.Valid {
				t.Fatal("independent signature", report, err)
			}

			var replay bytes.Buffer
			if _, err := result.References()[0].WriteDigestInput(t.Context(), &replay); err != nil || !bytes.Equal(replay.Bytes(), test.DigestInputs[0]) {
				t.Fatal("digest input differs from xmlsec1 --store-references", err)
			}

			if test.Kind == stage4KindManifest && (len(result.Manifests()) != 1 || !result.Manifests()[0].Transformed() || report.ManifestValidation != xmldsig.Valid) {
				t.Fatal("derived Manifest evidence missing", report)
			}

			keyOptions := keyinfo.Options{RetrievalProcessing: &opt.Processing}
			if opt.External != nil {
				keyOptions.External = &keyinfo.ExternalResources{AllowedURIs: opt.External.AllowedURIs, Resolver: opt.External.Resolver}
			}

			if _, err := xmldsig.VerifySignatureWithKeyInfo(t.Context(), doc, selected, xmldsig.KeyInfoVerifyOptions{Signature: opt, KeyInfo: keyOptions, SelectTrustedKey: keySelector(t, key)}); err != nil {
				t.Fatal("independent key discovery", err)
			}

			replayStage4References(t, result)
			testStage4VectorMutations(t, test, key, opt)
		})
	}
}

func replayStage4References(t *testing.T, result *xmldsig.SignatureResult) {
	t.Helper()

	refs := result.References()
	for _, manifest := range result.Manifests() {
		refs = append(refs, manifest.References()...)
	}

	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for _, ref := range refs {
				if _, err := ref.WriteDigestInput(t.Context(), io.Discard); err != nil {
					t.Error(err)
				}
			}
		})
	}

	workers.Wait()
}

func testStage4VectorMutations(t *testing.T, test stage4Case, key crypto.PublicKey, opt xmldsig.SignatureOptions) {
	t.Helper()

	for _, raw := range []string{
		strings.Replace(test.XML, `PrefixList="ctx"`, `PrefixList="ds"`, 1),
		strings.Replace(test.XML, `urn:stage4:context`, `urn:modified-context`, 1),
	} {
		doc := coreParse(t, raw)
		if result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), doc, xmldsig.Signatures(doc)[0], key, opt); result != nil || err == nil {
			t.Fatal("parameter/namespace mutation accepted")
		}
	}

	if test.Kind == stage4KindManifest {
		original := test.Resources[uriUrnAttachment]
		test.Resources[uriUrnAttachment] = []byte("changed independent payload")
		doc := coreParse(t, test.XML)
		result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), doc, xmldsig.Signatures(doc)[0], key, opt)
		test.Resources[uriUrnAttachment] = original

		if result != nil || !errors.Is(err, xmldsig.ErrDigest) || report.References[0].Status != xmldsig.Valid || report.ManifestValidation == xmldsig.Valid {
			t.Fatal("independent nested-content mutation", report, err)
		}
	} else {
		doc := coreParse(t, strings.Replace(test.XML, "independent signed payload", "changed signed payload", 1))
		if result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), doc, xmldsig.Signatures(doc)[0], key, opt); result != nil || !errors.Is(err, xmldsig.ErrDigest) {
			t.Fatal("independent payload mutation", err)
		}
	}
}

func TestXMLDSigStage4IndependentURIContexts(t *testing.T) {
	vectors, _ := loadStage4Vectors(t)
	key := coreEC(t)

	resource, err := keyinfo.Build(t.Context(), keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: key.Public()}}})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := resource.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range vectors.Contexts {
		t.Run(test.Name, func(t *testing.T) {
			resolver := xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
				if uri != test.Resolved {
					return nil, xmldsig.ErrPolicy
				}

				return io.NopCloser(bytes.NewReader(raw)), ctx.Err()
			})

			linked, err := keyinfo.Build(t.Context(), keyinfo.Template{KeyInfoReferences: []string{test.Relative}})
			if err != nil {
				t.Fatal(err)
			}

			input := coreParse(t, test.XML)
			parent := input.Root().Children()[0].Children()[0]

			draft, selected, err := xmldsig.BuildTemplate(t.Context(), input, parent, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, KeyInfo: linked, References: []xmldsig.ReferenceTemplate{{URI: test.Relative}}})
			if err != nil {
				t.Fatal(err)
			}

			opt := xmldsig.SignatureOptions{ExpectedURIs: []string{test.Relative}, External: &xmldsig.ExternalReferences{BaseURI: test.BaseURI, AllowedURIs: []string{test.Resolved}, Resolver: resolver}}

			signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: opt})
			if err != nil {
				t.Fatal(err)
			}

			result, err := xmldsig.VerifySignatureWithKeyInfo(t.Context(), signed, xmldsig.Signatures(signed)[0], xmldsig.KeyInfoVerifyOptions{Signature: opt, KeyInfo: keyinfo.Options{External: &keyinfo.ExternalResources{BaseURI: test.BaseURI, AllowedURIs: []string{test.Resolved}, Resolver: resolver}}, SelectTrustedKey: keySelector(t, key.Public())})
			if err != nil || result.References()[0].ResourceURI() != test.Resolved {
				t.Fatal("URI differs from libxml2/Python fixture", err)
			}
		})
	}
}

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
			*p.(*ecdsa.PublicKey) = ecdsa.PublicKey{}

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

	ki, e := keyinfo.Build(ctx, keyinfo.Template{KeyInfoReferences: []string{uriUrnKey}})
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

	for _, retrieval := range []bool{false, true} {
		input := signed
		resource := remoteBytes

		if retrieval {
			linked, err := keyinfo.Build(ctx, keyinfo.Template{RetrievalMethods: []keyinfo.RetrievalMethod{{URI: uriUrnKey, Transforms: []reference.Transform{{Algorithm: reference.Base64}}}}})
			if err != nil {
				t.Fatal(err)
			}

			draft, selected, err := xmldsig.BuildTemplate(ctx, nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, KeyInfo: linked, References: []xmldsig.ReferenceTemplate{{URI: uriUrnPayload}}})
			if err != nil {
				t.Fatal(err)
			}

			input, err = xmldsig.SignTemplate(ctx, draft, selected, k, xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{External: ext}})
			if err != nil {
				t.Fatal(err)
			}

			resource = []byte(base64.StdEncoding.EncodeToString(remoteBytes))
		}

		for _, name := range []string{"success", "reject-trust", "invalid-signature", nameUnknownAlgorithm} {
			t.Run(fmt.Sprintf("retrieval=%t/%s", retrieval, name), func(t *testing.T) {
				testKeyInfoResourceOrderAndInvalidPreflightCase(t, &input, &name, &payload, &resource, &k, &ctx, retrieval)
			})
		}
	}
}

func testKeyInfoResourceOrderAndInvalidPreflightCase(t *testing.T, signed **document.Document, name *string, payload *[]byte, remoteBytes *[]byte, k **ecdsa.PrivateKey, ctx *context.Context, retrieval bool) {
	var sequence []string

	local := *signed

	xml := coreXML(t, *signed)
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
		return io.NopCloser(bytes.NewReader(*payload)), nil
	})
	keyResolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		sequence = append(sequence, "key")
		return io.NopCloser(bytes.NewReader(*remoteBytes)), nil
	})
	o := xmldsig.KeyInfoVerifyOptions{Signature: xmldsig.SignatureOptions{ExpectedURIs: []string{uriUrnPayload}, External: &xmldsig.ExternalReferences{AllowedURIs: []string{uriUrnPayload}, Resolver: payloadResolver}}, KeyInfo: keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: keyResolver}}, SelectTrustedKey: func(ctx context.Context, info *keyinfo.Result) (int, error) {
		sequence = append(sequence, "trust")

		if (*name) == "reject-trust" {
			return -1, errors.New("untrusted")
		}

		return keySelector(t, &(*k).PublicKey)(ctx, info)
	}}

	if retrieval {
		processing := reference.DefaultOptions()
		o.KeyInfo.RetrievalProcessing = &processing
	}

	r, e := xmldsig.VerifySignatureWithKeyInfo(*ctx, local, xmldsig.Signatures(local)[0], o)

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
	ki, e := keyinfo.Build(ctx, keyinfo.Template{X509Data: []keyinfo.X509Data{{
		Certificates: [][]byte{caDER, leafDER}, SubjectNames: []string{leaf.Subject.String()},
		IssuerSerials: []keyinfo.IssuerSerial{{Issuer: issuer.Subject.String(), Serial: leaf.SerialNumber.String()}},
	}}})
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

func TestTemplateKeyInfoRoot(t *testing.T) {
	for _, tt := range []struct {
		name string
		info *document.Document
		bad  bool
	}{
		{"absent", nil, false},
		{"zero", &document.Document{}, true},
		{"wrong", coreParse(t, `<KeyInfo/>`), true},
		{"valid", coreParse(t, `<ds:KeyInfo xmlns:ds="`+xmldsig.Namespace+`"><ds:KeyName>hint</ds:KeyName></ds:KeyInfo>`), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if value := recover(); value != nil {
					t.Errorf("BuildTemplate panicked: %v", value)
				}
			}()

			doc, _, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{
				SignatureMethod: xmldsig.ECDSASHA256,
				References:      []xmldsig.ReferenceTemplate{{URI: uriUrnData}}, KeyInfo: tt.info,
			})
			if tt.bad {
				if doc != nil || !errors.Is(err, xmldsig.ErrStructure) {
					t.Fatalf("got %v, %v; want ErrStructure", doc, err)
				}
				return
			} else if err != nil {
				t.Fatal(err)
			}
			assertTemplateKeyInfoCount(t, doc, tt.info != nil)
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
	vectors, independentKey := loadStage4Vectors(f)
	independentSelector := keySelector(f, independentKey)

	independentOptions := make([]xmldsig.SignatureOptions, len(vectors.Cases))
	for i, test := range vectors.Cases {
		independentOptions[i] = stage4Options(f, test)
		if test.Kind != stage4KindManifest {
			f.Add(append([]byte{byte(i)}, []byte(test.XML)...))
		}
	}

	f.Add(raw)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}

		options := xmldsig.KeyInfoVerifyOptions{Signature: xmldsig.SignatureOptions{ExpectedURIs: []string{nameData}}, SelectTrustedKey: selectKey}
		if len(b) > 0 && int(b[0]) < len(vectors.Cases) {
			options.Signature = independentOptions[int(b[0])]
			options.SelectTrustedKey = independentSelector

			options.KeyInfo.RetrievalProcessing = &options.Signature.Processing
			if external := options.Signature.External; external != nil {
				options.KeyInfo.External = &keyinfo.ExternalResources{AllowedURIs: external.AllowedURIs, Resolver: external.Resolver}
			}

			b = b[1:]
		}

		d, e := document.Parse(t.Context(), b, document.DefaultLimits())
		if e != nil {
			return
		}

		sigs := xmldsig.Signatures(d)
		if len(sigs) != 1 {
			return
		}

		r, e := xmldsig.VerifySignatureWithKeyInfo(context.Background(), d, sigs[0], options)
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

func assertTemplateKeyInfoCount(t testing.TB, doc *document.Document, present bool) {
	t.Helper()

	count := 0

	for _, child := range doc.Root().Children() {
		if child.Name() == (document.Name{Space: xmldsig.Namespace, Local: "KeyInfo"}) {
			count++
		}
	}

	want := 0
	if present {
		want = 1
	}

	if count != want {
		t.Fatalf("KeyInfo count %d, want %d", count, want)
	}
}

func TestTemplateCertificateEncodingConsistency(t *testing.T) {
	chain := testcert.New(t)
	for _, test := range testcert.CertificateEncodings(t, chain) {
		t.Run(test.Name, func(t *testing.T) {
			before := bytes.Clone(test.DER)
			draft, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#data"}}, Certificates: [][]byte{test.DER}})
			if !test.Valid {
				if draft != nil || selected.Valid() || !errors.Is(err, xmldsig.ErrStructure) {
					t.Fatal("template accepted invalid certificate DER", err)
				}
				return
			}
			if err != nil || draft == nil || !selected.Valid() {
				t.Fatal(err)
			}
			wire, err := draft.XML(t.Context())
			if err != nil || !bytes.Contains(wire, []byte(base64.StdEncoding.EncodeToString(test.DER))) || !bytes.Equal(before, test.DER) {
				t.Fatal("template changed original certificate bytes", err)
			}
		})
	}
}
