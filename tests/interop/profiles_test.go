//go:build interop

package interop_test

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/keys"
	"github.com/skarm/xmlsec/pki"
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
		Name        string
		Kind        string
		Certificate string
		At          string
		Valid       bool
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
		Cases []struct {
			Name      string
			Signature string
			SPKI      string
		}
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

type redirectProfileCase struct {
	name string
	hash string
}

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

func TestCRLCompositionsOpenSSL(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "portable")
	c := testcert.New(t)
	at := testcert.Now()
	point := func(uri string) []byte { return der.Ctx(0, der.Wrap(2, 0, true, der.Wrap(2, 6, false, []byte(uri)))) }
	freshest := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 46}, Value: der.Seq(der.Seq(point("urn:offline:delta")))}
	list := func(number int64, this, next time.Time, base int64, scope []byte, entries []x509.RevocationListEntry, extras ...pkix.Extension) []byte {
		template := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: this, NextUpdate: next, RevokedCertificateEntries: entries, ExtraExtensions: extras}
		if base >= 0 {
			value, _ := asn1.Marshal(big.NewInt(base))
			template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: value})
		}
		if scope != nil {
			template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: scope})
		}
		raw, err := x509.CreateRevocationList(rand.Reader, template, c.Root, c.RootKey)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	entry := func(reason int) []x509.RevocationListEntry {
		return []x509.RevocationListEntry{{SerialNumber: c.Leaf.SerialNumber, RevocationTime: at.Add(-time.Hour), ReasonCode: reason}}
	}
	base := list(1, at.Add(-2*time.Minute), at.Add(time.Hour), -1, nil, nil, freshest)
	held := list(1, at.Add(-2*time.Minute), at.Add(time.Hour), -1, nil, entry(6), freshest)
	delta := func(entries []x509.RevocationListEntry) []byte {
		return list(2, at.Add(-time.Minute), at.Add(time.Hour), 1, nil, entries)
	}
	expired := list(1, at.Add(-2*time.Hour), at.Add(-time.Hour), -1, nil, nil, freshest)
	leafDP := func(encoded []byte) *x509.Certificate {
		template := *c.Leaf
		template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: encoded}}
		raw, err := x509.CreateCertificate(rand.Reader, &template, c.Root, c.LeafKey.Public(), c.RootKey)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := keys.ParseCertificate(raw, keys.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	scope := func(mask byte) []byte {
		return der.Seq(point("urn:offline:partition"), der.Wrap(2, 3, false, []byte{0, mask}))
	}
	scopedLeaf := leafDP(der.Seq(der.Seq(point("urn:offline:partition"))))
	relative := func(value string) []byte {
		return der.Ctx(0, der.Wrap(2, 1, true, der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 4, 3}), der.Wrap(0, asn1.TagUTF8String, false, []byte(value)))))
	}
	relativeLeaf := leafDP(der.Seq(der.Seq(relative("partition"))))
	type composition struct {
		name  string
		leaf  *x509.Certificate
		lists [][]byte
		want  error
	}
	tests := make([]composition, 0, 13)
	tests = append(tests, []composition{
		{"complete v1 good", c.Leaf, [][]byte{testcert.CRLV1(t, c)}, nil},
		{"complete v1 revoked", c.Leaf, [][]byte{testcert.CRLV1(t, c, c.Leaf)}, pki.ErrRevoked},
		{"complete v2 good", c.Leaf, [][]byte{testcert.CRL(t, c)}, nil},
		{"complete v2 revoked", c.Leaf, [][]byte{testcert.CRL(t, c, c.Leaf)}, pki.ErrRevoked},
		{"expired complete", c.Leaf, [][]byte{list(1, at.Add(-2*time.Hour), at.Add(-time.Hour), -1, nil, nil)}, pki.ErrUnavailable},
		{"delta adds revocation", c.Leaf, [][]byte{base, delta(entry(1))}, pki.ErrRevoked},
		{"delta releases hold", c.Leaf, [][]byte{held, delta(entry(8))}, nil},
		{"expired base current delta", c.Leaf, [][]byte{expired, delta(nil)}, nil},
		{"scoped all reasons", scopedLeaf, [][]byte{list(1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope(0x78), nil), list(1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope(0x07), nil), list(1, at.Add(-time.Minute), at.Add(time.Hour), -1, der.Seq(point("urn:offline:partition"), der.Wrap(2, 3, false, []byte{7, 0, 128})), nil)}, nil},
		{"scoped incomplete reasons", scopedLeaf, [][]byte{list(1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope(0x78), nil)}, pki.ErrUnavailable},
		{"relative distribution point", relativeLeaf, [][]byte{list(1, at.Add(-time.Minute), at.Add(time.Hour), -1, der.Seq(relative("PARTITION")), nil)}, nil},
	}...)

	delegateKey := testcert.Key(t)
	delegate := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(17), Subject: pkix.Name{CommonName: "non-CA CRL delegate"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageCRLSign, SubjectKeyId: []byte{9, 7, 5}}, c.Root, delegateKey.Public(), c.RootKey)
	indirectLeaf := leafDP(der.Seq(der.Seq(point("urn:offline:indirect"), der.Wrap(2, 2, true, der.Ctx(4, delegate.RawSubject)))))
	indirectScope := der.Seq(point("urn:offline:indirect"), der.Wrap(2, 4, false, []byte{255}))
	for _, revoked := range []bool{false, true} {
		template := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: indirectScope}}}
		name := "indirect non-CA good"
		var want error
		if revoked {
			name = "indirect non-CA revoked"
			want = pki.ErrRevoked
			template.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: indirectLeaf.SerialNumber, RevocationTime: at.Add(-time.Hour), ReasonCode: 1, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 29}, Critical: true, Value: der.Seq(der.Ctx(4, c.Root.RawSubject))}}}}
		}
		raw, err := x509.CreateRevocationList(rand.Reader, template, delegate, delegateKey)
		if err != nil {
			t.Fatal(err)
		}
		tests = append(tests, composition{name, indirectLeaf, [][]byte{raw}, want})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL})
			if err != nil {
				t.Fatal(err)
			}
			input := pki.Evidence{CRLs: test.lists}
			if strings.HasPrefix(test.name, "indirect ") {
				input.Intermediates = [][]byte{delegate.Raw}
			}
			result, _, err := verifier.Verify(t.Context(), test.leaf.Raw, at, input)
			if test.want == nil {
				if err != nil || result == nil {
					t.Fatal(result != nil, err)
				}
			} else if result != nil || !errors.Is(err, test.want) {
				t.Fatal(result != nil, err)
			}
			directory := t.TempDir()
			root := write(t, filepath.Join(directory, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Root.Raw}))
			leaf := write(t, filepath.Join(directory, "leaf.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: test.leaf.Raw}))
			var bundle bytes.Buffer
			for _, raw := range test.lists {
				if err := pem.Encode(&bundle, &pem.Block{Type: "X509 CRL", Bytes: raw}); err != nil {
					t.Fatal(err)
				}
			}
			crls := write(t, filepath.Join(directory, "crls.pem"), bundle.Bytes())

			args := []string{"verify", "-CAfile", root, "-CRLfile", crls, "-crl_check", "-extended_crl", "-use_deltas", "-attime", strconv.FormatInt(at.Unix(), 10)}
			if strings.HasPrefix(test.name, "indirect ") {
				untrusted := write(t, filepath.Join(directory, "delegate.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: delegate.Raw}))
				args = append(args, "-untrusted", untrusted)
			}
			args = append(args, leaf)
			output, diagnostic := command(t, fixture, test.want == nil, nil, "openssl", args...)
			if test.want == nil && !bytes.Contains(output, []byte(": OK")) {
				t.Fatal(string(output), string(diagnostic))
			}
			if test.want != nil {
				expected := "unable to get certificate CRL"
				if errors.Is(test.want, pki.ErrRevoked) {
					expected = "certificate revoked"
				}
				if test.name == "expired complete" {
					expected = "CRL has expired"
				}
				if !bytes.Contains(diagnostic, []byte(expected)) {
					t.Fatal(string(output), string(diagnostic))
				}
			}
		})
	}
}

// DSS is a separately started, offline demonstration runtime. Only its loopback
// REST service receives these locally generated test documents. The manifest is
// generated with the native historical fixtures, not downloaded test verdicts.
type dssHistoricalManifest struct {
	Version           string              `json:"version"`
	ValidationTime    time.Time           `json:"validation_time"`
	TrustAnchorSHA256 string              `json:"trust_anchor_sha256"`
	Policy            string              `json:"policy"`
	Pairs             []dssHistoricalPair `json:"pairs"`
}

type dssHistoricalPair struct {
	Name             string         `json:"name"`
	Sufficient       string         `json:"sufficient"`
	Insufficient     string         `json:"insufficient"`
	WantSufficient   dssExpectation `json:"want_sufficient"`
	WantInsufficient dssExpectation `json:"want_insufficient"`
}

type dssExpectation struct {
	Indication        string    `json:"indication"`
	SubIndication     string    `json:"sub_indication"`
	BestSignatureTime time.Time `json:"best_signature_time"`
}

type dssRemoteDocument struct {
	Bytes []byte `json:"bytes"`
	Name  string `json:"name"`
}

type dssValidationRequest struct {
	SignedDocument dssRemoteDocument  `json:"signedDocument"`
	Policy         *dssRemoteDocument `json:"policy,omitempty"`
	ValidationTime time.Time          `json:"validationTime"`
}

type dssSignatureSummary struct {
	ID                string    `json:"Id"`
	Indication        string    `json:"Indication"`
	SubIndication     string    `json:"SubIndication"`
	BestSignatureTime time.Time `json:"BestSignatureTime"`
	CertificateChain  struct {
		Certificates []struct {
			ID      string `json:"Id"`
			Trusted *bool  `json:"trusted"`
		} `json:"Certificate"`
	} `json:"CertificateChain"`
}

type dssBasicSignature struct {
	Intact *bool `json:"SignatureIntact"`
	Valid  *bool `json:"SignatureValid"`
}

type dssDigestMatcher struct {
	Found  *bool `json:"DataFound"`
	Intact *bool `json:"DataIntact"`
}

type dssProcess struct {
	Conclusion struct {
		Indication    string `json:"Indication"`
		SubIndication string `json:"SubIndication"`
	} `json:"Conclusion"`
}

type dssDetailedSignature struct {
	ID         string     `json:"Id"`
	Basic      dssProcess `json:"ValidationProcessBasicSignature"`
	LongTerm   dssProcess `json:"ValidationProcessLongTermData"`
	Archival   dssProcess `json:"ValidationProcessArchivalData"`
	Timestamps []struct {
		ID string `json:"Id"`
		dssProcess
	} `json:"Timestamp"`
}

type dssReports struct {
	DiagnosticData struct {
		ValidationDate time.Time `json:"ValidationDate"`
		Signatures     []struct {
			ID                   string `json:"Id"`
			StructuralValidation struct {
				Valid *bool `json:"valid"`
			} `json:"StructuralValidation"`
			BasicSignature dssBasicSignature  `json:"BasicSignature"`
			DigestMatchers []dssDigestMatcher `json:"DigestMatcher"`
		} `json:"Signature"`
		Timestamps []struct {
			ID             string             `json:"Id"`
			Type           string             `json:"Type"`
			BasicSignature dssBasicSignature  `json:"BasicSignature"`
			DigestMatchers []dssDigestMatcher `json:"DigestMatcher"`
		} `json:"Timestamp"`
	} `json:"DiagnosticData"`
	SimpleReport struct {
		ValidationTime time.Time `json:"ValidationTime"`
		Count          int       `json:"SignaturesCount"`
		ValidCount     int       `json:"ValidSignaturesCount"`
		Tokens         []struct {
			Signature *dssSignatureSummary `json:"Signature"`
		} `json:"signatureOrTimestampOrEvidenceRecord"`
	} `json:"SimpleReport"`
	DetailedReport *struct {
		ValidationTime time.Time `json:"ValidationTime"`
		Tokens         []struct {
			Signature *dssDetailedSignature `json:"Signature"`
		} `json:"signatureOrTimestampOrEvidenceRecord"`
	} `json:"DetailedReport"`
}

func TestDSSHistoricalValidation(t *testing.T) {
	selected(t, "portable")

	manifestPath := os.Getenv("XMLSEC_DSS_FIXTURES")
	endpoint := os.Getenv("XMLSEC_DSS_URL")
	runtimeJar := os.Getenv("XMLSEC_DSS_RUNTIME_JAR")
	if manifestPath == "" || endpoint == "" || runtimeJar == "" {
		if os.Getenv("XMLSEC_REQUIRE_P7_PROOFS") == "1" {
			t.Fatal("XMLSEC_DSS_FIXTURES, XMLSEC_DSS_URL and XMLSEC_DSS_RUNTIME_JAR are required")
		}

		t.Skip("optional local DSS historical compatibility fixtures/runtime")
	}

	base, err := dssLoopbackURL(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	var manifest dssHistoricalManifest
	decoder := json.NewDecoder(bytes.NewReader(dssReadFile(t, filepath.Dir(manifestPath), filepath.Base(manifestPath), 256<<10)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatal("trailing DSS manifest data:", err)
	}

	if manifest.Version != "6.5.1" || manifest.ValidationTime.IsZero() || len(manifest.Pairs) == 0 || len(manifest.Pairs) > 16 {
		t.Fatal("invalid DSS fixture version, explicit validation time or bounded pair count")
	}
	anchor, err := hex.DecodeString(manifest.TrustAnchorSHA256)
	if err != nil || len(anchor) != sha256.Size {
		t.Fatal("missing exact DSS trust-anchor certificate SHA-256")
	}
	anchorID := "C-" + strings.ToUpper(manifest.TrustAnchorSHA256)

	client := &http.Client{Timeout: time.Minute, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(client.CloseIdleConnections)
	dssCheckRuntime(t, client, base, runtimeJar, manifest.Version)

	directory := filepath.Dir(manifestPath)
	var policy *dssRemoteDocument
	if manifest.Policy != "" {
		policy = &dssRemoteDocument{Bytes: dssReadFile(t, directory, manifest.Policy, 1<<20), Name: filepath.Base(manifest.Policy)}
	}

	seen := map[string]struct{}{}
	for _, pair := range manifest.Pairs {
		if _, exists := seen[pair.Name]; pair.Name == "" || exists {
			t.Fatal("empty or duplicate historical pair name")
		}

		seen[pair.Name] = struct{}{}
		t.Run(pair.Name, func(t *testing.T) {
			sufficient := dssReadFile(t, directory, pair.Sufficient, 16<<20)
			insufficient := dssReadFile(t, directory, pair.Insufficient, 16<<20)
			dssCheckSameSignature(t, sufficient, insufficient)
			if pair.WantSufficient.Indication != "TOTAL_PASSED" || pair.WantSufficient.SubIndication != "" || pair.WantInsufficient.Indication != "INDETERMINATE" || pair.WantInsufficient.SubIndication == "" {
				t.Fatal("pair must specify total success and one exact indeterminate reason")
			}

			for _, item := range []struct {
				name string
				raw  []byte
				want dssExpectation
			}{{"sufficient", sufficient, pair.WantSufficient}, {"insufficient", insufficient, pair.WantInsufficient}} {
				t.Run(item.name, func(t *testing.T) {
					raw := dssPostValidation(t, client, base, dssValidationRequest{SignedDocument: dssRemoteDocument{Bytes: item.raw, Name: pair.Name + ".xml"}, Policy: policy, ValidationTime: manifest.ValidationTime})
					dssSaveReport(t, item.raw, raw)
					var report dssReports
					if err := json.Unmarshal(raw, &report); err != nil {
						t.Fatal(err)
					}

					if err := report.check(manifest.ValidationTime, item.want, anchorID); err != nil {
						t.Fatalf("DSS verdict: %v; summary=%+v\n%.4096s", err, report.SimpleReport, raw)
					}
					if err := report.checkArchiveRecovery(item.want.Indication == "TOTAL_PASSED"); err != nil {
						t.Fatal("DSS archive workflow:", err)
					}

					t.Logf("DSS %s %s/%s input-sha256=%x best-signature-time=%s", manifest.Version, item.want.Indication, item.want.SubIndication, sha256.Sum256(item.raw), item.want.BestSignatureTime.Format(time.RFC3339Nano))
				})
			}
		})
	}
}

func dssSaveReport(t *testing.T, input, report []byte) {
	t.Helper()
	directory := os.Getenv("XMLSEC_DSS_REPORT_DIR")
	if directory == "" {
		return
	}

	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	if err := os.WriteFile(filepath.Join(directory, hex.EncodeToString(digest[:])+".json"), report, 0o600); err != nil {
		t.Fatal(err)
	}
}

func dssReadFile(t *testing.T, directory, name string, limit int64) []byte {
	t.Helper()
	if !filepath.IsLocal(name) {
		t.Fatal("DSS fixture path must stay relative:", name)
	}

	path := filepath.Join(directory, name)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		t.Fatal("DSS fixture must be a bounded regular file:", name)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	raw, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	if err = errors.Join(readErr, file.Close()); err != nil {
		t.Fatal(err)
	}

	if int64(len(raw)) > limit {
		t.Fatal("DSS fixture exceeds byte limit:", name)
	}

	return raw
}

func dssLoopbackURL(endpoint string) (*url.URL, error) {
	base, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(base.Hostname())
	if base.Scheme != "http" || ip == nil || !ip.IsLoopback() || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("DSS compatibility service must use an explicit HTTP loopback IP URL")
	}

	base.Path = strings.TrimRight(base.Path, "/") + "/"

	return base, nil
}

func dssCheckRuntime(t *testing.T, client *http.Client, base *url.URL, jarPath, version string) {
	t.Helper()
	jar, err := zip.OpenReader(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := jar.Close(); err != nil {
			t.Error(err)
		}
	}()

	found := false
	for _, file := range jar.File {
		if !strings.HasSuffix(file.Name, "/dss-validation/pom.properties") {
			continue
		}

		stream, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}

		raw, readErr := io.ReadAll(io.LimitReader(stream, 4097))
		if err := errors.Join(readErr, stream.Close()); err != nil || len(raw) > 4096 {
			t.Fatal("DSS runtime version metadata:", err)
		}

		found = dssPinnedMetadata(raw, version)
	}

	if !found {
		t.Fatal("DSS runtime JAR has no exact pinned implementation version")
	}

	raw := dssHTTP(t, client, http.MethodGet, base.String(), nil)
	pageText := html.UnescapeString(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(string(raw), " "))
	if !regexp.MustCompile(`(?s)DSS Demonstration WebApp[^0-9]{0,160}` + regexp.QuoteMeta(version) + `(?:[^0-9.]|$)`).MatchString(pageText) {
		t.Fatal("DSS endpoint does not advertise the pinned runtime version")
	}
}

func dssPinnedMetadata(raw []byte, version string) bool {
	var artifact, implementation bool
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		artifact = artifact || bytes.Equal(line, []byte("artifactId=dss-validation"))
		implementation = implementation || bytes.Equal(line, []byte("version="+version))
	}

	return artifact && implementation
}

func dssPostValidation(t *testing.T, client *http.Client, base *url.URL, value dssValidationRequest) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return dssHTTP(t, client, http.MethodPost, base.ResolveReference(&url.URL{Path: "services/rest/validation/validateSignature"}).String(), raw)
}

func dssHTTP(t *testing.T, client *http.Client, method, endpoint string, raw []byte) []byte {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, endpoint, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if method == http.MethodGet {
		request.Header.Set("Accept", "text/html")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	body, readErr := io.ReadAll(io.LimitReader(response.Body, (32<<20)+1))
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		t.Fatal(err)
	}

	if len(body) > 32<<20 || response.StatusCode != http.StatusOK {
		t.Fatalf("DSS HTTP status=%d, bounded response bytes=%d: %.1024s", response.StatusCode, len(body), body)
	}

	return body
}

func dssCheckSameSignature(t *testing.T, left, right []byte) {
	t.Helper()
	if bytes.Equal(left, right) {
		t.Fatal("historical counterfactual did not change evidence")
	}

	var previousInfo, previousValue []byte
	for _, raw := range [][]byte{left, right} {
		doc := xmlDoc(t, raw)
		signature := one(t, tree.Root(doc), ds, "Signature")
		info := one(t, signature, ds, "SignedInfo")
		algorithm := attr(one(t, info, ds, "CanonicalizationMethod"), "Algorithm")
		var canonical bytes.Buffer
		if err := c14n.WriteElement(t.Context(), &canonical, tree.Wrap(doc, info), c14n.Options{Algorithm: algorithm}); err != nil {
			t.Fatal(err)
		}

		value := decode64(t, text(one(t, signature, ds, "SignatureValue")))
		if previousInfo != nil && (!bytes.Equal(previousInfo, canonical.Bytes()) || !bytes.Equal(previousValue, value)) {
			t.Fatal("historical pair changed SignedInfo or SignatureValue")
		}

		previousInfo = bytes.Clone(canonical.Bytes())
		previousValue = value
	}
}

func (r *dssReports) check(at time.Time, want dssExpectation, anchorID string) error {
	if want.BestSignatureTime.IsZero() || !r.DiagnosticData.ValidationDate.Equal(at) || !r.SimpleReport.ValidationTime.Equal(at) {
		return errors.New("missing/mismatched explicit validation or best-signature time")
	}

	if r.SimpleReport.Count != 1 || len(r.SimpleReport.Tokens) != 1 || len(r.DiagnosticData.Signatures) != 1 || r.DetailedReport == nil || len(r.DetailedReport.Tokens) != 1 {
		return errors.New("expected one signature in all three reports")
	}

	summary := r.SimpleReport.Tokens[0].Signature
	diagnostic := r.DiagnosticData.Signatures[0]
	if summary == nil || summary.ID == "" || summary.ID != diagnostic.ID || summary.Indication != want.Indication || summary.SubIndication != want.SubIndication || !summary.BestSignatureTime.Equal(want.BestSignatureTime) {
		return errors.New("signature identity, exact indication/reason or best-signature-time mismatch")
	}
	detailed := r.DetailedReport.Tokens[0].Signature
	if detailed == nil || detailed.ID != summary.ID || !r.DetailedReport.ValidationTime.Equal(at) {
		return errors.New("detailed report belongs to a different signature or validation time")
	}
	trustedAnchor := false
	for _, certificate := range summary.CertificateChain.Certificates {
		if certificate.ID == anchorID && dssTrue(certificate.Trusted) {
			trustedAnchor = true
		}
	}
	if !trustedAnchor {
		return errors.New("DSS report does not bind the configured trust-anchor certificate")
	}

	wantValid := 0
	if want.Indication == "TOTAL_PASSED" {
		wantValid = 1
	}

	if r.SimpleReport.ValidCount != wantValid || !dssTrue(diagnostic.StructuralValidation.Valid) || !dssTrue(diagnostic.BasicSignature.Intact) || !dssTrue(diagnostic.BasicSignature.Valid) || len(diagnostic.DigestMatchers) < 2 {
		return errors.New("pair does not retain an intact, structurally valid XAdES signature")
	}

	for _, matcher := range diagnostic.DigestMatchers {
		if !dssTrue(matcher.Found) || !dssTrue(matcher.Intact) {
			return errors.New("missing or damaged signed Reference in historical pair")
		}
	}

	return nil
}

func dssTrue(value *bool) bool { return value != nil && *value }

// These pairs exercise archive recovery after both basic and LT processing
// remain indeterminate. A currently valid signature is a different control.
func (r *dssReports) checkArchiveRecovery(success bool) error {
	if r.DetailedReport == nil || len(r.DetailedReport.Tokens) != 1 || r.DetailedReport.Tokens[0].Signature == nil {
		return errors.New("missing detailed signature recovery report")
	}
	detail := r.DetailedReport.Tokens[0].Signature
	if detail.Basic.Conclusion.Indication != "INDETERMINATE" || detail.LongTerm.Conclusion.Indication != "INDETERMINATE" {
		return errors.New("fixture did not require historical archive recovery")
	}
	archive := detail.Archival.Conclusion.Indication
	if success && archive != "PASSED" || !success && archive != "INDETERMINATE" {
		return errors.New("unexpected archive validation process result")
	}

	var signatureTime, archiveTime bool
	for _, stamp := range r.DiagnosticData.Timestamps {
		signatureTime = signatureTime || stamp.Type == "SIGNATURE_TIMESTAMP"
		archiveTime = archiveTime || stamp.Type == "ARCHIVE_TIMESTAMP"
		if !dssTrue(stamp.BasicSignature.Intact) || !dssTrue(stamp.BasicSignature.Valid) || len(stamp.DigestMatchers) == 0 {
			return errors.New("invalid timestamp cryptographic diagnostic")
		}
		for _, match := range stamp.DigestMatchers {
			if !dssTrue(match.Found) || !dssTrue(match.Intact) {
				return errors.New("timestamp imprint does not match its covered objects")
			}
		}
	}
	if !signatureTime || success && !archiveTime {
		return errors.New("required historical timestamps are absent")
	}
	if success {
		accepted := make(map[string]struct{}, len(detail.Timestamps))
		for _, stamp := range detail.Timestamps {
			if _, exists := accepted[stamp.ID]; stamp.ID == "" || exists || stamp.Conclusion.Indication != "PASSED" {
				return errors.New("an old timestamp was ignored instead of historically validated")
			}
			accepted[stamp.ID] = struct{}{}
		}
		if len(accepted) != len(r.DiagnosticData.Timestamps) {
			return errors.New("missing detailed timestamp trust results")
		}
		for _, stamp := range r.DiagnosticData.Timestamps {
			if _, exists := accepted[stamp.ID]; !exists {
				return errors.New("detailed timestamp result has a different token identity")
			}
		}
	}
	return nil
}

func TestDSSHistoricalReportContracts(t *testing.T) {
	at := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	proof := at.AddDate(-1, 0, 0)
	const raw = `{"DiagnosticData":{"ValidationDate":"2026-10-25T00:00:00Z","Signature":[{"Id":"s","StructuralValidation":{"valid":true},"BasicSignature":{"SignatureIntact":true,"SignatureValid":true},"DigestMatcher":[{"DataFound":true,"DataIntact":true},{"DataFound":true,"DataIntact":true}]}]},"SimpleReport":{"ValidationTime":"2026-10-25T00:00:00Z","SignaturesCount":1,"ValidSignaturesCount":1,"signatureOrTimestampOrEvidenceRecord":[{"Signature":{"Id":"s","Indication":"TOTAL_PASSED","SubIndication":null,"BestSignatureTime":"2025-10-25T00:00:00Z","CertificateChain":{"Certificate":[{"Id":"C-ROOT","trusted":true}]}}}]},"DetailedReport":{"ValidationTime":"2026-10-25T00:00:00Z","signatureOrTimestampOrEvidenceRecord":[{"Signature":{"Id":"s"}}]}}`
	want := dssExpectation{Indication: "TOTAL_PASSED", BestSignatureTime: proof}
	for _, test := range []struct {
		name string
		from string
		to   string
	}{
		{"complete report", "", ""},
		{"missing diagnostic", `"DiagnosticData"`, `"OtherData"`},
		{"wrong signature identity", `"Id":"s","Indication"`, `"Id":"other","Indication"`},
		{"unrelated indeterminate reason", `"TOTAL_PASSED"`, `"INDETERMINATE"`},
		{"missing proof time", `"2025-10-25T00:00:00Z"`, `null`},
		{"wrong proof time", `"2025-10-25T00:00:00Z"`, `"2025-10-24T00:00:00Z"`},
		{"wrong trusted anchor", `"Id":"C-ROOT"`, `"Id":"C-OTHER"`},
		{"untrusted anchor", `"trusted":true`, `"trusted":false`},
		{"signature invalid", `"SignatureValid":true`, `"SignatureValid":false`},
		{"missing signature validity", `"SignatureValid":true`, `"SignatureValid":null`},
		{"damaged reference", `"DataIntact":true`, `"DataIntact":false`},
		{"wrong explicit validation time", `"ValidationDate":"2026-10-25T00:00:00Z"`, `"ValidationDate":"2026-10-24T00:00:00Z"`},
		{"detailed report signature mismatch", `"Signature":{"Id":"s"}`, `"Signature":{"Id":"other"}`},
		{"detailed report time mismatch", `"DetailedReport":{"ValidationTime":"2026-10-25T00:00:00Z"`, `"DetailedReport":{"ValidationTime":"2026-10-24T00:00:00Z"`},
		{"no detailed report", `"DetailedReport":{"ValidationTime":"2026-10-25T00:00:00Z","signatureOrTimestampOrEvidenceRecord":[{"Signature":{"Id":"s"}}]}`, `"DetailedReport":null`},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := raw
			if test.from != "" {
				value = strings.Replace(value, test.from, test.to, 1)
				if value == raw {
					t.Fatal("test mutation missed")
				}
			}

			var report dssReports
			if err := json.Unmarshal([]byte(value), &report); err != nil {
				t.Fatal(err)
			}

			err := report.check(at, want, "C-ROOT")
			if (err == nil) != (test.from == "") {
				t.Fatal(err)
			}
		})
	}

	for _, endpoint := range []string{"https://127.0.0.1:8080/", "http://example.test/", "http://localhost/", "http://127.0.0.1/?query=1", "http://user@127.0.0.1/"} {
		if _, err := dssLoopbackURL(endpoint); err == nil {
			t.Fatal("nonlocal or ambiguous endpoint accepted:", endpoint)
		}
	}

	if _, err := dssLoopbackURL("http://127.0.0.1:8080/"); err != nil {
		t.Fatal(err)
	}

	t.Run("exact indeterminate cause with intact signature", func(t *testing.T) {
		value := strings.NewReplacer(`"TOTAL_PASSED"`, `"INDETERMINATE"`, `"ValidSignaturesCount":1`, `"ValidSignaturesCount":0`, `"SubIndication":null`, `"SubIndication":"OUT_OF_BOUNDS_NO_POE"`, `"2025-10-25T00:00:00Z"`, `"2026-10-25T00:00:00Z"`).Replace(raw)
		var report dssReports
		if err := json.Unmarshal([]byte(value), &report); err != nil {
			t.Fatal(err)
		}

		want := dssExpectation{Indication: "INDETERMINATE", SubIndication: "OUT_OF_BOUNDS_NO_POE", BestSignatureTime: at}
		if err := report.check(at, want, "C-ROOT"); err != nil {
			t.Fatal(err)
		}

		want.SubIndication = "NO_CERTIFICATE_CHAIN_FOUND"
		if err := report.check(at, want, "C-ROOT"); err == nil {
			t.Fatal("unrelated missing trust cause accepted as missing historical proof")
		}
	})

	for _, metadata := range []string{"artifactId=dss-validation\nversion=6.5.1", "# generated\nversion=6.5.1\nartifactId=dss-validation\n", "artifactId=dss-validation\r\nversion=6.5.1\r\n"} {
		if !dssPinnedMetadata([]byte(metadata), "6.5.1") {
			t.Fatal("valid Maven runtime version metadata rejected")
		}
	}
	for _, metadata := range []string{"artifactId=other\nversion=6.5.1\n", "artifactId=dss-validation\nversion=6.5.10\n", "artifactId=dss-validation\nversion=6.5\n"} {
		if dssPinnedMetadata([]byte(metadata), "6.5.1") {
			t.Fatal("different DSS implementation version accepted")
		}
	}
}

func TestDSSArchiveRecoveryReportContracts(t *testing.T) {
	const raw = `{"DetailedReport":{"signatureOrTimestampOrEvidenceRecord":[{"Signature":{"ValidationProcessBasicSignature":{"Conclusion":{"Indication":"INDETERMINATE"}},"ValidationProcessLongTermData":{"Conclusion":{"Indication":"INDETERMINATE"}},"ValidationProcessArchivalData":{"Conclusion":{"Indication":"PASSED"}},"Timestamp":[{"Id":"st","Conclusion":{"Indication":"PASSED"}},{"Id":"at","Conclusion":{"Indication":"PASSED"}}]}}]},"DiagnosticData":{"Timestamp":[{"Id":"st","Type":"SIGNATURE_TIMESTAMP","BasicSignature":{"SignatureIntact":true,"SignatureValid":true},"DigestMatcher":[{"DataFound":true,"DataIntact":true}]},{"Id":"at","Type":"ARCHIVE_TIMESTAMP","BasicSignature":{"SignatureIntact":true,"SignatureValid":true},"DigestMatcher":[{"DataFound":true,"DataIntact":true}]}]}}`
	for _, test := range []struct {
		name string
		from string
		to   string
	}{
		{"archive required and verified", "", ""},
		{"current signature passed instead", `"ValidationProcessBasicSignature":{"Conclusion":{"Indication":"INDETERMINATE"}}`, `"ValidationProcessBasicSignature":{"Conclusion":{"Indication":"PASSED"}}`},
		{"LT passed instead", `"ValidationProcessLongTermData":{"Conclusion":{"Indication":"INDETERMINATE"}}`, `"ValidationProcessLongTermData":{"Conclusion":{"Indication":"PASSED"}}`},
		{"archive process did not pass", `"ValidationProcessArchivalData":{"Conclusion":{"Indication":"PASSED"}}`, `"ValidationProcessArchivalData":{"Conclusion":{"Indication":"INDETERMINATE"}}`},
		{"missing archive timestamp", `"ARCHIVE_TIMESTAMP"`, `"OTHER_TIMESTAMP"`},
		{"timestamp signature invalid", `"SignatureValid":true`, `"SignatureValid":false`},
		{"timestamp imprint invalid", `"DataIntact":true`, `"DataIntact":false`},
		{"missing detailed report", `"DetailedReport"`, `"OtherReport"`},
		{"old timestamp ignored", `"Id":"st","Conclusion":{"Indication":"PASSED"}`, `"Id":"st","Conclusion":{"Indication":"INDETERMINATE"}`},
		{"missing old timestamp trust result", `{"Id":"st","Conclusion":{"Indication":"PASSED"}},`, ``},
		{"duplicate timestamp trust identity", `"Id":"at","Conclusion"`, `"Id":"st","Conclusion"`},
		{"different timestamp trust identity", `"Id":"at","Conclusion"`, `"Id":"other","Conclusion"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := raw
			if test.from != "" {
				value = strings.Replace(value, test.from, test.to, 1)
				if value == raw {
					t.Fatal("test mutation missed")
				}
			}
			var report dssReports
			if err := json.Unmarshal([]byte(value), &report); err != nil {
				t.Fatal(err)
			}
			if err := report.checkArchiveRecovery(true); (err == nil) != (test.from == "") {
				t.Fatal(err)
			}
		})
	}
}
