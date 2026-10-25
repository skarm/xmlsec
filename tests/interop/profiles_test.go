//go:build interop

package interop_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

const nameFresh = "fresh"

const uriAttachment = "urn:attachment"

const uriManifest = "urn:manifest"

func TestXMLSecExternalManifestURIContext(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	key := generateKey(t, fixture.work, nameRsaSha256)
	_, privateArg := nativeKeyArgs(nameRsa, "")

	const resourceURI = "urn:external#manifest"

	payload := []byte("external fragment payload")
	digest := sha256.Sum256(payload)
	manifestXML := `<ds:Manifest xmlns:ds="` + ds + `" Id="manifest"><ds:Reference URI="urn:attachment"><ds:DigestMethod Algorithm="` + xmldsig.SHA256 + `"/><ds:DigestValue>` + base64.StdEncoding.EncodeToString(digest[:]) + `</ds:DigestValue></ds:Reference></ds:Manifest>`
	manifest := xmlDoc(t, []byte(manifestXML))

	var selectedXML bytes.Buffer
	if err := c14n.WriteElement(t.Context(), &selectedXML, manifest.Root(), c14n.Options{Algorithm: c14n.Canonical10}); err != nil {
		t.Fatal(err)
	}

	// The native engine receives the original XML resource and performs its own
	// fragment selection. The Go resolver supplies the identified subresource
	// as octets, as required by the external-URI processing contract.
	nativeManifest := write(t, filepath.Join(fixture.work, "fragment-manifest.xml"), []byte(`<!DOCTYPE ds:Manifest [<!ATTLIST ds:Manifest Id ID #REQUIRED>]>`+manifestXML))
	payloadPath := write(t, filepath.Join(fixture.work, "fragment-payload.bin"), payload)
	opt := xmldsig.SignatureOptions{
		ExpectedURIs: []string{resourceURI},
		Manifests:    xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, AllowExternal: true},
		External: &xmldsig.ExternalReferences{AllowedURIs: []string{resourceURI, uriAttachment}, Resolver: xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
			switch uri {
			case resourceURI:
				return io.NopCloser(bytes.NewReader(selectedXML.Bytes())), ctx.Err()
			case uriAttachment:
				return os.Open(payloadPath)
			default:
				return nil, xmldsig.ErrPolicy
			}
		})},
	}

	draft, selectedSignature, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{
		SignatureMethod: key.method,
		References:      []xmldsig.ReferenceTemplate{{URI: resourceURI, Type: xmldsig.ManifestType, Transforms: []reference.Transform{{Algorithm: c14n.Canonical10}}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	template := write(t, filepath.Join(fixture.work, "fragment-template.xml"), xmlBytes(t, draft))

	signed, err := xmldsig.SignTemplate(t.Context(), draft, selectedSignature, key.signer, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		t.Fatal(err)
	}

	ours := write(t, filepath.Join(fixture.work, "fragment-go.xml"), xmlBytes(t, signed))
	nativeArgs := []string{"--url-map:urn:external", nativeManifest, "--url-map:urn:attachment", payloadPath}
	native(t, fixture, true, nameVerify, append(append([]string{flagPubkeyPem, key.public}, nativeArgs...), ours)...)
	theirs := filepath.Join(fixture.work, "fragment-native.xml")
	native(t, fixture, true, nameSign, append(append([]string{privateArg, key.private, flagNativeOutput, theirs}, nativeArgs...), template)...)
	nativeDoc := xmlDoc(t, read(t, theirs))

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), nativeDoc, nativeDoc.Root(), key.signer.Public(), opt)
	if err != nil || result == nil || len(result.Manifests()) != 1 || report.ManifestValidation != xmldsig.Valid {
		t.Fatal(result, report, err)
	}

	write(t, payloadPath, []byte("changed fragment payload"))

	result, report, err = xmldsig.VerifySignatureDetailed(t.Context(), nativeDoc, nativeDoc.Root(), key.signer.Public(), opt)
	if !errors.Is(err, xmldsig.ErrDigest) || result != nil || report.References[0].Status != xmldsig.Valid {
		t.Fatal(result, report, err)
	}

	// xmlsec1 validates this external Manifest's incoming Reference, but does
	// not recursively discover its children. Record that boundary explicitly.
	native(t, fixture, true, nameVerify, append(append([]string{flagPubkeyPem, key.public}, nativeArgs...), ours)...)

	changedDigest := sha256.Sum256([]byte("different nested digest"))
	changedManifest := strings.Replace(manifestXML, base64.StdEncoding.EncodeToString(digest[:]), base64.StdEncoding.EncodeToString(changedDigest[:]), 1)
	write(t, nativeManifest, []byte(`<!DOCTYPE ds:Manifest [<!ATTLIST ds:Manifest Id ID #REQUIRED>]>`+changedManifest))
	native(t, fixture, false, nameVerify, append(append([]string{flagPubkeyPem, key.public}, nativeArgs...), ours)...)
}

func TestXMLSecRelativeURIContext(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	key := generateKey(t, fixture.work, nameRsaSha256)
	_, privateArg := nativeKeyArgs(nameRsa, "")

	const resolved = "https://example.test/payload.bin?version=1"

	payload := write(t, filepath.Join(fixture.work, "relative-payload.bin"), []byte("relative resource"))
	input := xmlDoc(t, []byte(`<message xml:base="https://example.test/packages/"/>`))

	draft, selectedSignature, err := xmldsig.BuildTemplate(t.Context(), input, input.Root(), xmldsig.SignatureTemplate{SignatureMethod: key.method, References: []xmldsig.ReferenceTemplate{{URI: "../payload.bin?version=1"}}})
	if err != nil {
		t.Fatal(err)
	}

	opt := xmldsig.SignatureOptions{ExpectedURIs: []string{"../payload.bin?version=1"}, External: &xmldsig.ExternalReferences{BaseURI: "https://example.test/messages/signature.xml", AllowedURIs: []string{resolved}, Resolver: xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if uri != resolved {
			return nil, xmldsig.ErrPolicy
		}

		return os.Open(payload)
	})}}

	signed, err := xmldsig.SignTemplate(t.Context(), draft, selectedSignature, key.signer, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		t.Fatal(err)
	}

	ours := write(t, filepath.Join(fixture.work, "relative-go.xml"), xmlBytes(t, signed))
	args := []string{"--url-map:" + resolved, payload}
	// xmlsec1's CLI opens the literal relative URI in this profile instead of
	// applying inherited xml:base. Keep that difference visible, then exchange
	// identical octets through an explicit literal mapping in the native adapter.
	native(t, fixture, false, nameVerify, append(append([]string{flagPubkeyPem, key.public}, args...), ours)...)
	args = []string{"--url-map:../payload.bin?version=1", payload}
	native(t, fixture, true, nameVerify, append(append([]string{flagPubkeyPem, key.public}, args...), ours)...)
	template := write(t, filepath.Join(fixture.work, "relative-template.xml"), xmlBytes(t, draft))
	theirs := filepath.Join(fixture.work, "relative-native.xml")
	native(t, fixture, true, nameSign, append(append([]string{privateArg, key.private, flagNativeOutput, theirs}, args...), template)...)

	nativeDoc := xmlDoc(t, read(t, theirs))
	if result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), nativeDoc, xmldsig.Signatures(nativeDoc)[0], key.signer.Public(), opt); err != nil || result == nil || result.References()[0].ResourceURI() != resolved {
		t.Fatal(result, err)
	}

	write(t, payload, []byte("changed relative resource"))
	native(t, fixture, false, nameVerify, append(append([]string{flagPubkeyPem, key.public}, args...), ours)...)

	if result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), nativeDoc, xmldsig.Signatures(nativeDoc)[0], key.signer.Public(), opt); !errors.Is(err, xmldsig.ErrDigest) || result != nil {
		t.Fatal(result, err)
	}
}

func TestExternalManifestInterop(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "portable")
	key := generateKey(t, fixture.work, nameRsaSha256)
	theirs := filepath.Join(fixture.work, "jdk-external.xml")
	manifest := filepath.Join(fixture.work, "external-manifest.xml")
	payload := write(t, filepath.Join(fixture.work, "external-payload.bin"), []byte("external Manifest payload\x00\xff"))
	java(t, fixture, "ManifestOracle", "sign-external", key.private, theirs, manifest, payload, key.method)
	verifyJava(t, java(t, fixture, "ManifestOracle", "verify-external", key.public, theirs, manifest, payload), true)
	paths := map[string]string{uriManifest: manifest, uriAttachment: payload}
	options := xmldsig.SignatureOptions{
		Manifests: xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, AllowExternal: true}, ExpectedURIs: []string{uriManifest},
		External: &xmldsig.ExternalReferences{AllowedURIs: []string{uriManifest, uriAttachment}, Resolver: xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			path, ok := paths[uri]
			if !ok {
				return nil, xmldsig.ErrPolicy
			}

			return os.Open(path)
		})},
	}

	doc, err := document.Parse(t.Context(), read(t, theirs), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), doc, doc.Root(), key.signer.Public(), options)
	if err != nil || result == nil || len(result.Manifests()) != 1 || len(result.Manifests()[0].References()) != 1 || report.ManifestValidation != xmldsig.Valid {
		t.Fatal(result, report, err)
	}

	resources := write(t, filepath.Join(fixture.work, "resources.json"), []byte(`[{"uri":"urn:manifest","path":"external-manifest.xml"},{"uri":"urn:attachment","path":"external-payload.bin"}]`))
	cli := binary(t, fixture, "xmlsec")
	cliReport, _ := command(t, fixture, true, nil, cli, "verify-core", "-in", theirs, "-key", key.public, "-signature-index", "0", "-manifests", "recursive-external", "-resources", resources, "-expect-uri", uriManifest)
	verifyReport(t, cliReport, true)

	draft := xmlDoc(t, read(t, theirs))
	for _, value := range append(nodes(tree.Root(draft), ds, "SignatureValue"), nodes(tree.Root(draft), ds, "DigestValue")...) {
		value.Children = nil
	}

	template, err := document.Parse(t.Context(), xmlBytes(t, draft), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	signed, err := xmldsig.SignTemplate(t.Context(), template, template.Root(), key.signer, xmldsig.TemplateSignOptions{Validation: options})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := signed.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	ours := write(t, filepath.Join(fixture.work, "go-external.xml"), raw)
	verifyJava(t, java(t, fixture, "ManifestOracle", "verify-external", key.public, ours, manifest, payload), true)
	write(t, payload, []byte("changed external payload"))

	result, report, err = xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.signer.Public(), options)
	if !errors.Is(err, xmldsig.ErrDigest) || result != nil || report.SignatureValue != xmldsig.Valid || report.References[0].Status != xmldsig.Valid {
		t.Fatal(result, report, err)
	}

	verifyJava(t, java(t, fixture, "ManifestOracle", "verify-external", key.public, ours, manifest, payload), false)
}

func TestManifestProfiles(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	cli := binary(t, fixture, "xmlsec")
	attachment := write(t, filepath.Join(dir, "attachment.bin"), []byte("external bytes\x00\xff"))

	resources := write(t, filepath.Join(dir, "resources.json"), []byte(`[{"uri":"urn:attachment","path":"attachment.bin"}]`))
	for _, name := range []string{nameRsaSha256, nameRsaSha384, nameRsaSha512, nameEcdsaSha256} {
		key := generateKey(t, dir, name)
		if strings.HasPrefix(name, nameRsa) {
			key.method = pssURI + strings.TrimPrefix(name, "rsa-") + "-rsa-MGF1"
		}

		theirs, ours, bad := filepath.Join(dir, "jdk.xml"), filepath.Join(dir, "go.xml"), filepath.Join(dir, "bad.xml")
		java(t, fixture, "ManifestOracle", nameSign, key.private, theirs, attachment, key.method)

		draft := xmlDoc(t, read(t, theirs))
		for _, value := range append(nodes(tree.Root(draft), ds, "SignatureValue"), nodes(tree.Root(draft), ds, "DigestValue")...) {
			value.Children = nil
		}

		template := write(t, filepath.Join(dir, "manifest-template.xml"), xmlBytes(t, draft))
		opts := []string{"-signature-index", "0", "-modern-algorithms", "-manifests", "recursive", "-resources", resources, "-expect-uri", "#top"}
		raw, _ := command(t, fixture, true, nil, cli, append([]string{"sign-template", flagIn, template, flagOut, ours, flagKey, key.private}, opts...)...)
		_ = raw

		verifyJava(t, java(t, fixture, "ManifestOracle", nameVerify, key.public, ours, attachment), true)
		raw, _ = command(t, fixture, true, nil, cli, append([]string{"verify-core", flagIn, theirs, flagKey, key.public}, opts...)...)
		verifyReport(t, raw, true)
		java(t, fixture, "ManifestOracle", "sign-bad", key.private, bad, attachment, key.method)

		v := verifyJava(t, java(t, fixture, "ManifestOracle", nameVerify, key.public, bad, attachment), false)
		for _, r := range v.References {
			if !r {
				t.Fatal("direct Reference invalid in nested control")
			}
		}

		raw, _ = command(t, fixture, false, nil, cli, append([]string{"verify-core", flagIn, bad, flagKey, key.public}, opts...)...)

		r := verifyReport(t, raw, false)
		if r.References[0].Status != nameValid {
			t.Fatal("nested failure leaked into direct reference status")
		}
	}
	// Independently signed EdDSA and nested controls also run in the public
	// corpus without an external runtime.
	command(t, fixture, true, nil, "go", "test", "-count=1", "./tests/integration/xmldsig")
}

func TestSAMLProfiles(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	at := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)

	p := binary(t, fixture, "samlprobe")
	for _, name := range []string{nameRsaSha256, nameEcdsaSha256} {
		key := generateKey(t, dir, name)

		cert := write(t, filepath.Join(dir, "cert.der"), key.cert.Raw)
		for _, kind := range []string{"metadata", "request", "response"} {
			path := filepath.Join(dir, "signed.xml")
			command(t, fixture, true, nil, p, "-mode", "sign-"+kind, flagKey, key.private, flagCert, cert, "-at", at, flagOut, path)

			d := xmlDoc(t, read(t, path))
			for _, sig := range nodes(tree.Root(d), ds, "Signature") {
				verifySignatureValue(t, fixture, d, sig, key.public)

				if !checkReferences(t, fixture, d, sig) {
					t.Fatal("Go SAML Reference differs from independent canonicalization")
				}
			}
		}
	}

	base := filepath.Join(fixture.root, "testdata/saml-interop")

	var cases []struct {
		Name, Kind, Certificate, At string
		Valid                       bool
	}
	decode(t, read(t, filepath.Join(base, "manifest.json")), &cases)

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			certificate := filepath.Join(base, tc.Certificate)

			cert, err := x509.ParseCertificate(read(t, certificate))
			if err != nil {
				t.Fatal(err)
			}

			spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				t.Fatal(err)
			}

			public := write(t, filepath.Join(dir, "fixture-public.pem"), pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: spki}))
			path := filepath.Join(base, tc.Name+".xml")

			d := xmlDoc(t, read(t, path))
			for _, sig := range nodes(tree.Root(d), ds, "Signature") {
				verifySignatureValue(t, fixture, d, sig, public)

				if !checkReferences(t, fixture, d, sig) {
					t.Fatal("semantic negative must retain valid XML signature")
				}
			}

			command(t, fixture, tc.Valid, nil, p, "-mode", "verify-"+tc.Kind, flagIn, path, flagCert, certificate, "-at", tc.At)
		})
	}

	t.Logf("6 generated SAML documents and %d independently signed public fixtures, including semantic negatives", len(cases))
}

func TestKeyInfoFixtures(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	base := filepath.Join(fixture.root, "testdata/keyinfo")

	var manifest struct {
		Cases []struct{ Name, Signature, SPKI string }
	}
	decode(t, read(t, filepath.Join(base, "manifest.json")), &manifest)

	if len(manifest.Cases) == 0 {
		t.Fatal("missing KeyInfo corpus")
	}

	for _, tc := range manifest.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			d := xmlDoc(t, read(t, filepath.Join(base, tc.Signature)))
			public := write(t, filepath.Join(dir, "public.pem"), pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: read(t, filepath.Join(base, tc.SPKI))}))
			sig := one(t, tree.Root(d), ds, "Signature")
			verifySignatureValue(t, fixture, d, sig, public)

			if !checkReferences(t, fixture, d, sig) {
				t.Fatal("KeyInfo fixture reference differs")
			}
		})
	}
}

type redirectProfileCase struct{ name, hash string }

type redirectSignedQuery struct {
	parts     []string
	signature []byte
}

func TestRedirectProfiles(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	request := write(t, filepath.Join(dir, "request.xml"), []byte(`<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="request-1" Version="2.0" IssueInstant="2026-10-07T12:00:00Z"/>`))
	relay := "state/ü?x=1&y=two"

	cases := []redirectProfileCase{
		{nameRsaSha256, nameSha256},
		{nameRsaSha384, "sha384"},
		{nameRsaSha512, "sha512"},
		{nameEcdsaSha256, nameSha256},
		{nameEd25519, nameSha256},
	}
	for _, scenario := range cases {
		key := generateKey(t, dir, scenario.name)
		checkRedirectExchange(t, fixture, dir, request, relay, scenario, key)
	}
}

func checkRedirectExchange(t *testing.T, fixture *interopFixture, dir, request, relay string, scenario redirectProfileCase, key testKey) {
	t.Helper()

	task := map[string]any{nameMode: "redirect-sign", nameKey: key.private, nameInput: request, nameMethod: key.method, "Relay": relay}
	result := probe(t, fixture, "nextprobe", task, true)

	var query string
	decode(t, result[nameText], &query)

	signed := decodeRedirectSignedQuery(t, fixture, query, request)
	message := write(t, filepath.Join(dir, "query-message"), []byte(strings.Join(signed.parts, "&")))
	signature := write(t, filepath.Join(dir, "query-signature"), signed.signature)
	checkRedirectOpenSSL(t, fixture, scenario, key, message, signature, signed.signature)

	value := read(t, signature)
	if strings.HasPrefix(scenario.name, "ecdsa") {
		value = ecdsaRaw(t, value, 32)
	}

	reverse := strings.Join(signed.parts, "&") + "&Signature=" + url.QueryEscape(base64String(value))
	path := write(t, filepath.Join(dir, "query.txt"), []byte(reverse))
	verify := map[string]any{nameMode: "redirect-verify", nameKey: key.public, nameInput: path}
	probe(t, fixture, "nextprobe", verify, true)
	write(t, path, []byte(reverse+"&"+signed.parts[0]))
	probe(t, fixture, "nextprobe", verify, false)
}

func decodeRedirectSignedQuery(t *testing.T, fixture *interopFixture, query, request string) redirectSignedQuery {
	t.Helper()

	var signed redirectSignedQuery

	for _, part := range strings.Split(query, "&") {
		key, value, _ := strings.Cut(part, "=")
		if key == "Signature" {
			raw, err := url.QueryUnescape(value)
			if err != nil {
				t.Fatal(err)
			}

			signed.signature = decode64(t, raw)
		} else {
			signed.parts = append(signed.parts, part)

			if key == "SAMLRequest" {
				checkRedirectRequest(t, fixture, value, request)
			}
		}
	}

	return signed
}

func checkRedirectRequest(t *testing.T, fixture *interopFixture, value, request string) {
	t.Helper()

	raw, err := url.QueryUnescape(value)
	if err != nil {
		t.Fatal(err)
	}

	compressed := decode64(t, raw)
	r := flate.NewReader(bytes.NewReader(compressed))

	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	r.Close()
	equalXML(t, fixture, body, read(t, request))
}

func checkRedirectOpenSSL(t *testing.T, fixture *interopFixture, scenario redirectProfileCase, key testKey, message, signature string, value []byte) {
	t.Helper()

	if scenario.name == nameEd25519 {
		command(t, fixture, true, nil, "openssl", "pkeyutl", flagVerify, "-pubin", flagInkey, key.public, "-rawin", flagIn, message, "-sigfile", signature)
		command(t, fixture, true, nil, "openssl", "pkeyutl", "-sign", flagInkey, key.private, "-rawin", flagIn, message, flagOut, signature)

		return
	}

	if strings.HasPrefix(scenario.name, "ecdsa") {
		write(t, signature, ecdsaDER(t, value))
	}

	command(t, fixture, true, nil, "openssl", "dgst", "-"+scenario.hash, flagVerify, key.public, "-signature", signature, message)
	command(t, fixture, true, nil, "openssl", "dgst", "-"+scenario.hash, "-sign", key.private, flagOut, signature, message)
}

func TestCRLFixtures(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	base := filepath.Join(fixture.root, "testdata/next")
	leaf := filepath.Join(base, "pki-leaf.der")
	rootDER := filepath.Join(base, "pki-root.der")
	rootPEM := write(t, filepath.Join(dir, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: nameCERTIFICATE, Bytes: read(t, rootDER)}))

	leafPEM := write(t, filepath.Join(dir, "leaf.pem"), pem.EncodeToMemory(&pem.Block{Type: nameCERTIFICATE, Bytes: read(t, leaf)}))
	for _, mode := range []string{nameFresh, "revoked", "stale"} {
		crl := filepath.Join(base, "pki-"+mode+".crl.der")
		probe(t, fixture, "nextprobe", map[string]any{nameMode: "pki-verify", nameInput: leaf, "Root": rootDER, "CRL": crl, "At": "2026-10-07T12:00:00Z"}, mode == nameFresh)
		crlPEM := write(t, filepath.Join(dir, "crl.pem"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: read(t, crl)}))
		command(t, fixture, mode == nameFresh, nil, "openssl", nameVerify, "-CAfile", rootPEM, "-CRLfile", crlPEM, "-crl_check", "-attime", "1791374400", leafPEM)
	}
}

func referenceInput(t *testing.T, fixture *interopFixture, d *tree.Document, sig, ref *tree.Node, attachment []byte) []byte {
	t.Helper()

	uri := attr(ref, "URI")

	var (
		target *tree.Node
		octets []byte
	)
	if uri == uriAttachment {
		octets = bytes.Clone(attachment)
	} else if uri == "" {
		target = tree.Root(d)
	} else if strings.HasPrefix(uri, "#") {
		ident := strings.TrimPrefix(uri, "#")

		var walk func(*tree.Node)

		walk = func(n *tree.Node) { testreferenceInputCase(n, &ident, &target, &t, &walk) }
		walk(tree.Root(d))

		if target == nil {
			t.Fatalf("unresolved ID %s", uri)
		}
	} else {
		t.Fatalf("unallowlisted test URI %s", uri)
	}

	var canonical string

	enveloped := false

	for _, tr := range nodes(ref, ds, "Transform") {
		alg := attr(tr, "Algorithm")
		if alg == ds+"enveloped-signature" {
			enveloped = true
		} else if alg == ds+"base64" {
			if target != nil {
				octets = []byte(text(target))
				target = nil
			}

			octets = decode64(t, string(octets))
		} else if strings.HasPrefix(alg, exc) || strings.HasPrefix(alg, c10) || strings.HasPrefix(alg, c11) {
			canonical = alg
		} else {
			t.Fatalf("unsupported fixed profile transform %s", alg)
		}
	}

	if target == nil {
		if canonical != "" {
			doc := xmlDoc(t, octets)
			return externalCanonical(t, fixture, doc, nil, canonical)
		}

		return octets
	}

	if canonical == "" {
		canonical = c10
	}
	// Bare ID references strip comments before transforms, even WithComments.
	removed := make(map[*tree.Node][]*tree.Node)

	var prune func(*tree.Node)

	prune = func(n *tree.Node) { testreferenceInputCase2(n, &sig, &enveloped, &prune, &removed) }
	prune(target)

	defer func() {
		for n, children := range removed {
			n.Children = children
		}
	}()

	return externalCanonical(t, fixture, d, target, canonical)
}

func checkReferences(t *testing.T, fixture *interopFixture, d *tree.Document, sig *tree.Node) bool {
	t.Helper()

	valid := true

	for _, ref := range nodes(sig, ds, "Reference") {
		alg := attr(one(t, ref, ds, "DigestMethod"), "Algorithm")

		bits := 256
		if strings.HasSuffix(alg, "384") {
			bits = 384
		} else if strings.HasSuffix(alg, "512") {
			bits = 512
		}

		input := referenceInput(t, fixture, d, sig, ref, nil)

		digest := hashBytes(bits, input)
		if !bytes.Equal(digest, decode64(t, text(one(t, ref, ds, "DigestValue")))) {
			valid = false
		}
	}

	return valid
}

func testreferenceInputCase(n *tree.Node, ident *string, target **tree.Node, t **testing.T, walk *func(*tree.Node)) {
	if attr(n, "Id") == (*ident) || attr(n, "ID") == (*ident) {
		if (*target) != nil {
			(*t).Fatal("duplicate ID")
		}

		(*target) = n
	}

	for _, c := range n.Children {
		(*walk)(c)
	}
}

func testreferenceInputCase2(n *tree.Node, sig **tree.Node, enveloped *bool, prune *func(*tree.Node), removed *map[*tree.Node][]*tree.Node) {
	original := n.Children

	var kept []*tree.Node

	for _, c := range original {
		if c == (*sig) && (*enveloped) || c.Kind == tree.CommentNode {
			continue
		}

		kept = append(kept, c)
		(*prune)(c)
	}

	(*removed)[n] = original
	n.Children = kept
}
