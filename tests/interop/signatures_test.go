//go:build interop

package interop_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/transform"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	flagInsecure   = "--insecure"
	stage4Manifest = "manifest"
	stage4Payload  = "payload"
)

const (
	uriSignedPayload         = "#payload"
	uriSharedKeyInfo         = "#shared"
	nameEnveloping           = "enveloping"
	nameMulti                = "multi"
	uriRetrievalKey          = "urn:key"
	flagMixedCaseIDAttribute = "--id-attr:Id"
)

func TestXMLSecX509DataGroups(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	key, crl := x509DataIdentity(t, fixture)
	digest256, digest384, digest512 := sha256.Sum256(key.cert.Raw), sha512.Sum384(key.cert.Raw), sha512.Sum512(key.cert.Raw)
	issuer := keyinfo.IssuerSerial{Issuer: key.cert.Issuer.String(), Serial: key.cert.SerialNumber.String()}

	all := keyinfo.X509Data{
		Certificates: [][]byte{key.cert.Raw}, CRLs: [][]byte{crl},
		IssuerSerials: []keyinfo.IssuerSerial{issuer}, SubjectNames: []string{key.cert.Subject.String()},
		SubjectKeyIdentifiers: [][]byte{key.cert.SubjectKeyId},
		CertificateDigests:    []keyinfo.CertificateDigest{{Algorithm: xmldsig.SHA256, Value: digest256[:]}},
	}
	for _, test := range []struct {
		name   string
		groups []keyinfo.X509Data
	}{
		{"certificate", []keyinfo.X509Data{{Certificates: all.Certificates}}},
		{"issuer-serial", []keyinfo.X509Data{{IssuerSerials: all.IssuerSerials}}},
		{"subject", []keyinfo.X509Data{{SubjectNames: all.SubjectNames}}},
		{"SKI", []keyinfo.X509Data{{SubjectKeyIdentifiers: all.SubjectKeyIdentifiers}}},
		{"digest-SHA256", []keyinfo.X509Data{{CertificateDigests: all.CertificateDigests}}},
		{"digest-SHA384", []keyinfo.X509Data{{CertificateDigests: []keyinfo.CertificateDigest{{Algorithm: xmldsig.SHA384, Value: digest384[:]}}}}},
		{"digest-SHA512", []keyinfo.X509Data{{CertificateDigests: []keyinfo.CertificateDigest{{Algorithm: xmldsig.SHA512, Value: digest512[:]}}}}},
		{"certificate-CRL", []keyinfo.X509Data{{Certificates: all.Certificates, CRLs: all.CRLs}}},
		{"combined", []keyinfo.X509Data{all}},
	} {
		t.Run(test.name, func(t *testing.T) { x509DataExchange(t, fixture, key, test.groups) })
	}

	t.Run("native-generation", func(t *testing.T) { x509DataNativeGeneration(t, fixture, key, all) })
}

// OpenSSL supplies the original certificate, SKI and CRL bytes, independently
// of the Go XML builder. Scratch CA files and generated XML stay in TempDir.
func x509DataIdentity(t *testing.T, fixture *interopFixture) (testKey, []byte) {
	t.Helper()
	key := generateKey(t, fixture.work, nameRsaSha256)
	dir := t.TempDir()
	certificate := filepath.Join(dir, "certificate.pem")
	command(t, fixture, true, nil, "openssl", "req", "-new", "-x509", "-key", key.private, "-out", certificate, "-subj", "/CN=X509Data interop", "-days", "1", "-set_serial", "123456789012345678901234567890", "-addext", "subjectKeyIdentifier=hash", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign")

	block, _ := pem.Decode(read(t, certificate))
	if block == nil {
		t.Fatal("OpenSSL certificate missing")
	}

	var err error

	key.cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil || len(key.cert.SubjectKeyId) == 0 {
		t.Fatal("OpenSSL certificate/SKI", err)
	}

	key.certificate = certificate
	index := write(t, filepath.Join(dir, "index"), nil)
	number := write(t, filepath.Join(dir, "crlnumber"), []byte("01\n"))
	config := write(t, filepath.Join(dir, "ca.cnf"), []byte("[ca]\ndefault_ca=CA\n[CA]\ndatabase="+index+"\ncrlnumber="+number+"\ncertificate="+certificate+"\nprivate_key="+key.private+"\ndefault_md=sha256\ndefault_crl_days=1\n"))
	crlPath := filepath.Join(dir, "crl.pem")
	command(t, fixture, true, nil, "openssl", "ca", "-gencrl", "-batch", "-config", config, "-out", crlPath)

	block, _ = pem.Decode(read(t, crlPath))
	if block == nil {
		t.Fatal("OpenSSL CRL missing")
	}

	return key, block.Bytes
}

func x509DataExchange(t *testing.T, fixture *interopFixture, key testKey, groups []keyinfo.X509Data) {
	t.Helper()
	dir := t.TempDir()

	info, err := keyinfo.Build(t.Context(), keyinfo.Template{ID: "x509-info", Names: []string{"signer"}, X509Data: groups})
	if err != nil {
		t.Fatal(err)
	}

	input := xmlDoc(t, []byte(`<root><payload ID="payload">X509Data payload</payload></root>`))

	draft, selected, err := xmldsig.BuildTemplate(t.Context(), input, input.Root(), xmldsig.SignatureTemplate{SignatureMethod: xmldsig.RSASHA256, KeyInfo: info, References: []xmldsig.ReferenceTemplate{
		{URI: uriSignedPayload, Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}},
		{URI: "#x509-info", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key.signer, xmldsig.TemplateSignOptions{})
	if err != nil {
		t.Fatal(err)
	}

	ours := xmlBytes(t, signed)
	source := write(t, filepath.Join(dir, "template.xml"), xmlBytes(t, draft))
	oursPath := write(t, filepath.Join(dir, "go.xml"), ours)

	args := append([]string{flagInsecure, "--untrusted-pem", key.certificate, flagMixedCaseIDAttribute, ds + ":KeyInfo"}, idArgs()...)
	// Strict key discovery uses X509Data and the explicit certificate store. No
	// lax key search or separately supplied public-key fallback is enabled.
	verify := func(path string, success bool) {
		all := append([]string{nameVerify}, args...)
		command(t, fixture, success, nil, xmlsecExecutable(), append(all, path)...)
	}
	verify(oursPath, true)

	theirPath := filepath.Join(dir, "native.xml")
	native(t, fixture, true, nameSign, append(args, "--privkey-pem:signer", key.private+","+key.certificate, "--output", theirPath, source)...)

	options := xmldsig.SignatureOptions{ExpectedURIs: []string{uriSignedPayload, "#x509-info"}}

	for _, raw := range [][]byte{ours, read(t, theirPath)} {
		doc := xmlDoc(t, raw)

		result, err := xmldsig.VerifySignature(t.Context(), doc, xmldsig.Signatures(doc)[0], key.signer.Public(), options)
		if err != nil || !result.CoversElement(tree.Wrap(doc, one(t, tree.Root(doc), ds, "KeyInfo"))) {
			t.Fatal("signature did not authenticate X509Data", err)
		}

		bad := xmlDoc(t, bytes.Replace(raw, []byte("X509Data payload"), []byte("changed payload"), 1))
		if result, err := xmldsig.VerifySignature(t.Context(), bad, xmldsig.Signatures(bad)[0], key.signer.Public(), options); result != nil || err == nil {
			t.Fatal("changed content accepted", err)
		}
	}

	changed := bytes.Replace(ours, []byte("</ds:X509Data>"), []byte("<ds:X509SubjectName>CN=changed</ds:X509SubjectName></ds:X509Data>"), 1)

	bad := xmlDoc(t, changed)
	if result, err := xmldsig.VerifySignature(t.Context(), bad, xmldsig.Signatures(bad)[0], key.signer.Public(), options); result != nil || err == nil {
		t.Fatal("changed authenticated selectors accepted", err)
	}

	verify(write(t, filepath.Join(dir, "changed.xml"), changed), false)
	verify(write(t, filepath.Join(dir, "changed-payload.xml"), bytes.Replace(ours, []byte("X509Data payload"), []byte("changed payload"), 1)), false)
}

func x509DataNativeGeneration(t *testing.T, fixture *interopFixture, key testKey, expected keyinfo.X509Data) {
	t.Helper()
	dir := t.TempDir()
	// xmlsec1 itself populates the selectors and base64 certificate. No Go
	// builder or adapter determines the independent expected XML values.
	raw := `<root><payload ID="payload">native X509Data</payload><ds:Signature xmlns:ds="` + ds + `" xmlns:dsig11="` + keyinfo.Namespace11 + `"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="` + c14n.Exclusive + `"/><ds:SignatureMethod Algorithm="` + xmldsig.RSASHA256 + `"/><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="` + c14n.Exclusive + `"/></ds:Transforms><ds:DigestMethod Algorithm="` + xmldsig.SHA256 + `"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509IssuerSerial/><ds:X509SubjectName/><ds:X509SKI/><ds:X509Certificate/><dsig11:X509Digest Algorithm="` + xmldsig.SHA256 + `"/></ds:X509Data></ds:KeyInfo></ds:Signature></root>`
	input := write(t, filepath.Join(dir, "native-template.xml"), []byte(raw))
	output := filepath.Join(dir, "native-generated.xml")
	native(t, fixture, true, nameSign, append(idArgs(), "--privkey-pem", key.private+","+key.certificate, "--output", output, input)...)
	doc := xmlDoc(t, read(t, output))

	info, err := keyinfo.Parse(t.Context(), doc, tree.Wrap(doc, one(t, tree.Root(doc), ds, "KeyInfo")), keyinfo.Options{})
	if err != nil || len(info.X509Groups()) != 1 || len(info.Candidates()) != 1 || !bytes.Equal(info.Candidates()[0].SPKI(), key.cert.RawSubjectPublicKeyInfo) {
		t.Fatal("native X509Data did not preserve original key", err)
	}

	group := info.X509Groups()[0]
	if !slices.Equal(group.IssuerSerials(), expected.IssuerSerials) || !slices.Equal(group.SubjectNames(), expected.SubjectNames) || !bytes.Equal(group.SubjectKeyIdentifiers()[0], key.cert.SubjectKeyId) || !bytes.Equal(group.CertificatesDER()[0], key.cert.Raw) || !bytes.Equal(group.CertificateDigests()[0].Value, expected.CertificateDigests[0].Value) {
		t.Fatal("native selectors/certificate differ from OpenSSL identity")
	}

	options := xmldsig.KeyInfoVerifyOptions{Signature: xmldsig.SignatureOptions{ExpectedURIs: []string{uriSignedPayload}}, SelectTrustedKey: func(_ context.Context, info *keyinfo.Result) (int, error) {
		if len(info.Candidates()) != 1 || !bytes.Equal(info.Candidates()[0].SPKI(), key.cert.RawSubjectPublicKeyInfo) {
			return -1, errors.New("unexpected native certificate")
		}

		return 0, nil
	}}
	if _, err := xmldsig.VerifySignatureWithKeyInfo(t.Context(), doc, xmldsig.Signatures(doc)[0], options); err != nil {
		t.Fatal(err)
	}
}

func TestLegacySignatureFixtures(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "portable")

	dir := filepath.Join(fixture.root, "testdata", "legacy-dsig")
	for _, kind := range []string{"dsa", "rsa"} {
		verifyJava(t, java(t, fixture, "CoreOracle", "verify-legacy", filepath.Join(dir, kind+"-public.pem"), filepath.Join(dir, kind+"-sha1.xml"), "0"), true)
	}

	hmacPath := filepath.Join(dir, "hmac-sha1.xml")
	verifyJava(t, java(t, fixture, "CoreOracle", "verify-legacy-hmac", "-", hmacPath, "0"), true)
	// Use the JDK-created structure as a template with empty placeholders.
	placeholders := regexp.MustCompile(`(<ds:(?:DigestValue|SignatureValue)>)[^<]*(</ds:(?:DigestValue|SignatureValue)>)`)
	raw := placeholders.ReplaceAll(read(t, hmacPath), []byte("${1}${2}"))

	d, err := document.Parse(t.Context(), raw, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	signed, err := xmldsig.SignHMACTemplate(t.Context(), d, xmldsig.Signatures(d)[0], bytes.Repeat([]byte{0xaa}, 80), xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{Policy: xmldsig.LegacyHMACPolicy()}})
	if err != nil {
		t.Fatal(err)
	}

	output, err := signed.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	ours := write(t, filepath.Join(fixture.work, "go-hmac-sha1.xml"), output)
	verifyJava(t, java(t, fixture, "CoreOracle", "verify-legacy-hmac", "-", ours, "0"), true)
	bad := write(t, filepath.Join(fixture.work, "changed-hmac-sha1.xml"), bytes.Replace(output, []byte("legacy fixture"), []byte("changed fixture"), 1))
	verifyJava(t, java(t, fixture, "CoreOracle", "verify-legacy-hmac", "-", bad, "0"), false)
	key := generateKey(t, fixture.work, nameRsaSha256)

	input, err := document.Parse(t.Context(), []byte(`<root ID="root">SHA-1 reference</root>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	publicSigned, err := xmldsig.SignEnveloped(t.Context(), input, key.signer, xmldsig.SignOptions{DigestMethod: xmldsig.SHA1, Policy: xmldsig.LegacyVerificationPolicy()})
	if err != nil {
		t.Fatal(err)
	}

	output, err = publicSigned.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	ours = write(t, filepath.Join(fixture.work, "go-sha1-reference.xml"), output)
	verifyJava(t, java(t, fixture, "CoreOracle", "verify-legacy", key.public, ours, "0"), true)
}

func TestCoreSignatures(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "portable")
	coreSignatures(t, fixture, false)
}

func TestXMLSecSignatures(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "xmlsec")
	checkXMLSec(t, fixture)
	coreSignatures(t, fixture, true)
}

func checkXMLSec(t *testing.T, fixture *interopFixture) {
	t.Helper()
	version, _ := command(t, fixture, true, nil, xmlsecExecutable(), "--version")
	t.Log(strings.TrimSpace(string(version)))

	transforms, _ := command(t, fixture, true, nil, xmlsecExecutable(), "--list-transforms")
	for _, name := range []string{"eddsa-ed25519", "rsa-pss-sha256", "aes128-gcm", "kw-aes256", "xpath2"} {
		if !bytes.Contains(transforms, []byte(`"`+name+`"`)) {
			t.Fatalf("xmlsec1 lacks %s", name)
		}
	}
}

type retrievalRecipe struct {
	name     string
	uri      string
	typ      string
	resource []byte
	chain    []reference.Transform
}

type stage4InteropCase struct {
	Name            string
	Kind            string
	XML             string
	Template        string
	Resources       map[string][]byte
	NativeResources map[string][]byte `json:"native_resources"`
	Programs        []reference.Transform
	DigestInputs    [][]byte `json:"digest_inputs"`
}

func TestXMLSecStage4Vectors(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")

	var corpus struct {
		PublicKey   string `json:"public_key_pem"`
		Certificate []byte `json:"certificate_der"`
		Cases       []stage4InteropCase
		Contexts    []struct {
			Name         string
			XML          string
			Relative     string
			Resolved     string
			ExpectedBase string `json:"expected_base"`
		} `json:"uri_contexts"`
	}
	decode(t, read(t, filepath.Join(fixture.root, "testdata", "next", "dsig-stage4-vectors.json")), &corpus)
	public := write(t, filepath.Join(fixture.work, "stage4-public.pem"), []byte(corpus.PublicKey))

	key := generateKey(t, fixture.work, nameRsaSha256)
	for _, test := range corpus.Cases {
		t.Run(test.Name, func(t *testing.T) { stage4InteropExchange(t, fixture, test, public, key, corpus.Certificate) })
	}

	for _, test := range corpus.Contexts {
		t.Run("xml-base/"+test.Name, func(t *testing.T) {
			path := write(t, filepath.Join(t.TempDir(), "context.xml"), []byte(test.XML))

			out, _ := command(t, fixture, true, []byte("cd /root/inner/item\nbase\nbye\n"), "xmllint", "--shell", path)
			if !bytes.Contains(out, []byte(test.ExpectedBase+"\n")) {
				t.Fatal("libxml2 base changed", string(out))
			}
		})
	}
}

func stage4NativeResources(t *testing.T, resources map[string][]byte) []string {
	t.Helper()
	dir := t.TempDir()

	args := make([]string, 0, 2*len(resources))
	for uri, data := range resources {
		path := write(t, filepath.Join(dir, strconv.Itoa(len(args))+".bin"), data)
		args = append(args, "--url-map:"+uri, path)
	}

	return args
}

func stage4InteropExchange(t *testing.T, fixture *interopFixture, test stage4InteropCase, public string, key testKey, originalCertificate []byte) {
	t.Helper()
	dir := t.TempDir()

	nativeResources := test.Resources
	if test.NativeResources != nil {
		nativeResources = test.NativeResources
	}

	args := append([]string{nameVerify, flagInsecure, "--verbose", "--print-debug", "--store-references", flagIDAttrID, stage4Payload, flagMixedCaseIDAttribute, ds + ":KeyInfo"}, stage4NativeResources(t, nativeResources)...)
	if test.Kind == stage4Manifest {
		args = append(args, "--lax-key-search", flagPubkeyPem, public)
	}

	path := write(t, filepath.Join(dir, "independent.xml"), []byte(test.XML))
	out, stderr := command(t, fixture, true, nil, xmlsecExecutable(), append(args, path)...)

	buffers := regexp.MustCompile(`(?s)== PreDigest data - start buffer:\n(.*?)\n== PreDigest data - end buffer`).FindAllSubmatch(append(out, stderr...), -1)
	if len(buffers) != 1 || !bytes.Equal(buffers[0][1], test.DigestInputs[0]) {
		t.Fatal("fixed independent digest bytes changed")
	}

	// Re-sign the stored template with a fresh Go identity. Replace only the
	// unsigned certificate hints/resources, retaining all transform parameters.
	oldCert, newCert := []byte(base64String(originalCertificate)), []byte(base64String(key.cert.Raw))
	for uri, data := range test.Resources {
		test.Resources[uri] = bytes.ReplaceAll(data, oldCert, newCert)
	}

	if test.NativeResources != nil {
		for uri, data := range test.NativeResources {
			test.NativeResources[uri] = bytes.ReplaceAll(data, oldCert, newCert)
		}
	}

	input := xmlDoc(t, bytes.ReplaceAll([]byte(test.Template), oldCert, newCert))

	options := xmldsig.SignatureOptions{ExpectedURIs: []string{uriSignedPayload}, Processing: reference.DefaultOptions()}
	if test.Kind == stage4Manifest {
		options.ExpectedURIs = []string{uriManifest}
		options.Manifests = xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, AllowExternal: true, AllowTransformed: true}
	}

	if len(test.Programs) != 0 {
		engine, err := transform.NewEngine(transform.Config{AllowedPrograms: test.Programs})
		if err != nil {
			t.Fatal(err)
		}

		options.Processing.Extension = engine
		for _, program := range test.Programs {
			options.Processing.AllowedTransforms = append(options.Processing.AllowedTransforms, program.Algorithm)
		}
	}

	if len(test.Resources) != 0 {
		options.External = &xmldsig.ExternalReferences{Resolver: xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
			data, ok := test.Resources[uri]
			if !ok {
				return nil, xmldsig.ErrPolicy
			}

			return io.NopCloser(bytes.NewReader(data)), ctx.Err()
		})}
		for uri := range test.Resources {
			options.External.AllowedURIs = append(options.External.AllowedURIs, uri)
		}
	}

	signed, err := xmldsig.SignTemplate(t.Context(), input, xmldsig.Signatures(input)[0], key.signer, xmldsig.TemplateSignOptions{Validation: options})
	if err != nil {
		t.Fatal(err)
	}

	ours := xmlBytes(t, signed)
	goPath := write(t, filepath.Join(dir, "go.xml"), ours)

	nativeResources = test.Resources
	if test.NativeResources != nil {
		nativeResources = test.NativeResources
	}

	verify := append([]string{nameVerify, flagInsecure, flagIDAttrID, stage4Payload, flagMixedCaseIDAttribute, ds + ":KeyInfo"}, stage4NativeResources(t, nativeResources)...)
	if test.Kind == stage4Manifest {
		verify = append(verify, "--lax-key-search", flagPubkeyPem, key.public)
	}

	command(t, fixture, true, nil, xmlsecExecutable(), append(verify, goPath)...)
	bad := write(t, filepath.Join(dir, "changed-context.xml"), bytes.Replace(ours, []byte("urn:stage4:context"), []byte("urn:changed-context"), 1))
	command(t, fixture, false, nil, xmlsecExecutable(), append(verify, bad)...)

	if test.Kind != stage4Manifest {
		bad = write(t, filepath.Join(dir, "changed-content.xml"), bytes.Replace(ours, []byte("independent signed payload"), []byte("changed signed payload"), 1))
		command(t, fixture, false, nil, xmlsecExecutable(), append(verify, bad)...)
	}
}

func TestXMLSecRetrievalMethods(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	key := generateKey(t, fixture.work, nameRsaSha256)

	publicInfo, err := keyinfo.Build(t.Context(), keyinfo.Template{ID: "shared", Certificates: [][]byte{key.cert.Raw}})
	if err != nil {
		t.Fatal(err)
	}

	bare := tree.ImportSubtree(tree.Root(publicInfo).Children[0])
	bareDoc := tree.FromNodes([]*tree.Node{bare}, document.DefaultLimits())
	bareXML := xmlBytes(t, bareDoc)
	namespaces := map[string]string{"ds": ds, "dsig11": keyinfo.Namespace11}
	xpath := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: `ancestor-or-self::ds:X509Data`, Namespaces: namespaces}}}
	filter := reference.Transform{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{{Expression: `//ds:X509Data`, Filter: "intersect", Namespaces: map[string]string{"ds": ds, "dsig11": keyinfo.Namespace11, "xf": reference.XPathFilter2}}}}
	xslt := reference.Transform{Algorithm: reference.XSLT, Stylesheet: []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ds="` + ds + `" xmlns:dsig11="` + keyinfo.Namespace11 + `" version="1.0"><xsl:template match="/"><xsl:copy-of select="//ds:X509Data"/></xsl:template></xsl:stylesheet>`)}

	recipes := make([]retrievalRecipe, 0, 15)
	for i, algorithm := range canonicalizations() {
		recipes = append(recipes, retrievalRecipe{"canonical-" + strconv.Itoa(i), uriRetrievalKey, ds + "X509Data", bareXML, []reference.Transform{{Algorithm: algorithm}}})
	}

	recipes = append(recipes,
		retrievalRecipe{"base64-XML", uriRetrievalKey, ds + "X509Data", []byte(base64String(bareXML)), []reference.Transform{{Algorithm: reference.Base64}, {Algorithm: c14n.Exclusive}}},
		retrievalRecipe{"XPath", uriSharedKeyInfo, ds + "X509Data", nil, []reference.Transform{xpath, {Algorithm: c14n.Exclusive}}},
		retrievalRecipe{"enveloped-XPath", uriSharedKeyInfo, ds + "X509Data", nil, []reference.Transform{{Algorithm: reference.EnvelopedSignature}, xpath, {Algorithm: c14n.Exclusive}}},
		retrievalRecipe{"Filter2", uriSharedKeyInfo, ds + "X509Data", nil, []reference.Transform{filter, {Algorithm: c14n.Exclusive}}},
		retrievalRecipe{"XSLT", uriRetrievalKey, ds + "X509Data", xmlBytes(t, publicInfo), []reference.Transform{xslt, {Algorithm: c14n.Exclusive}}},
		retrievalRecipe{"raw-certificate", uriRetrievalKey, keyinfo.RawX509Certificate, key.cert.Raw, nil},
		retrievalRecipe{"two-base64-certificate", uriRetrievalKey, keyinfo.RawX509Certificate, []byte(base64String([]byte(base64String(key.cert.Raw)))), []reference.Transform{{Algorithm: reference.Base64}, {Algorithm: reference.Base64}}},
	)
	for _, format := range []keyinfo.KeyFormat{keyinfo.XMLKeyValue, keyinfo.DERKeyValue} {
		recipes = append(recipes, keyRetrievalRecipe(t, key, "RSA-", format))
	}

	for _, test := range recipes {
		t.Run(test.name, func(t *testing.T) { retrievalExchange{fixture, key, publicInfo, test}.run(t) })
	}

	ecKey := generateKey(t, fixture.work, nameEcdsaSha256)
	for _, format := range []keyinfo.KeyFormat{keyinfo.XMLKeyValue, keyinfo.DERKeyValue} {
		test := keyRetrievalRecipe(t, ecKey, "EC-", format)
		t.Run(test.name, func(t *testing.T) { retrievalExchange{fixture, ecKey, publicInfo, test}.run(t) })
	}

	t.Logf("%d native RetrievalMethod exchanges and four native key-form boundary controls", len(recipes)-2)
}

func keyRetrievalRecipe(t *testing.T, key testKey, name string, format keyinfo.KeyFormat) retrievalRecipe {
	t.Helper()

	description, err := keyinfo.Build(t.Context(), keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: key.signer.Public(), Format: format}}})
	if err != nil {
		t.Fatal(err)
	}

	node := tree.Root(description).Children[0]
	if format == keyinfo.XMLKeyValue {
		node = node.Children[0]
	}

	resource := tree.FromNodes([]*tree.Node{tree.ImportSubtree(node)}, document.DefaultLimits())

	return retrievalRecipe{name + string(format), uriRetrievalKey, node.Name.Space + node.Name.Local, xmlBytes(t, resource), nil}
}

type retrievalExchange struct {
	fixture    *interopFixture
	key        testKey
	publicInfo *document.Document
	recipe     retrievalRecipe
}

func (exchange retrievalExchange) run(t *testing.T) {
	t.Helper()

	fixture, key, publicInfo, test := exchange.fixture, exchange.key, exchange.publicInfo, exchange.recipe
	dir := t.TempDir()

	info, err := keyinfo.Build(t.Context(), keyinfo.Template{Names: []string{"signer"}, RetrievalMethods: []keyinfo.RetrievalMethod{{URI: test.uri, Type: test.typ, Transforms: test.chain}}})
	if err != nil {
		t.Fatal(err)
	}

	input := xmlDoc(t, []byte(`<root><payload ID="payload">retrieved key</payload>`+string(xmlBytes(t, publicInfo))+`</root>`))

	draft, selected, err := xmldsig.BuildTemplate(t.Context(), input, input.Root(), xmldsig.SignatureTemplate{SignatureMethod: key.method, KeyInfo: info, References: []xmldsig.ReferenceTemplate{{URI: uriSignedPayload, Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}}})
	if err != nil {
		t.Fatal(err)
	}

	ours, err := xmldsig.SignTemplate(t.Context(), draft, selected, key.signer, xmldsig.TemplateSignOptions{})
	if err != nil {
		t.Fatal(err)
	}

	source := write(t, filepath.Join(dir, "template.xml"), xmlBytes(t, draft))
	goPath := write(t, filepath.Join(dir, "go.xml"), xmlBytes(t, ours))
	resource := write(t, filepath.Join(dir, "resource.bin"), test.resource)
	args := append([]string{"--verbose", "--enabled-retrieval-method-uris", "same-doc,remote", "--url-map:urn:key", resource, flagInsecure, flagMixedCaseIDAttribute, ds + ":KeyInfo"}, idArgs()...)
	// This xmlsec1 CLI retrieves X509Data/raw certificates, but does not
	// discover the selected bare KeyValue/DER key roots. Record the boundary,
	// then verify core cryptography with an explicit key; Go checks retrieval.
	if test.typ != ds+"X509Data" && test.typ != keyinfo.RawX509Certificate {
		native(t, fixture, false, nameVerify, append(append([]string(nil), args...), goPath)...)
		args = append(args, flagPubkeyPem, key.public)
	}

	native(t, fixture, true, nameVerify, append(append([]string(nil), args...), goPath)...)

	theirPath := filepath.Join(dir, "xmlsec.xml")
	signArgs := append(append([]string(nil), args...), "--privkey-pem:signer", key.private, "--output", theirPath, source)
	native(t, fixture, true, nameSign, signArgs...)

	processing := reference.DefaultOptions()

	var programs []reference.Transform

	for _, step := range test.chain {
		if reference.IsExtension(step.Algorithm) {
			programs = append(programs, step)
			processing.AllowedTransforms = append(processing.AllowedTransforms, step.Algorithm)
		}
	}

	if len(programs) != 0 {
		processing.Extension, err = transform.NewEngine(transform.Config{AllowedPrograms: programs})
		if err != nil {
			t.Fatal(err)
		}
	}

	pin := sha256.Sum256(key.cert.RawSubjectPublicKeyInfo)
	options := xmldsig.KeyInfoVerifyOptions{Signature: xmldsig.SignatureOptions{ExpectedURIs: []string{uriSignedPayload}}, KeyInfo: keyinfo.Options{RetrievalProcessing: &processing, External: &keyinfo.ExternalResources{AllowedURIs: []string{uriRetrievalKey}, Resolver: xmldsig.ResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
		if uri != uriRetrievalKey {
			t.Fatal("unexpected resource", uri)
		}

		return io.NopCloser(bytes.NewReader(test.resource)), nil
	})}}, SelectTrustedKey: func(_ context.Context, result *keyinfo.Result) (int, error) {
		if len(result.Candidates()) != 1 || sha256.Sum256(result.Candidates()[0].SPKI()) != pin {
			return -1, errors.New("unexpected retrieved key")
		}

		return 0, nil
	}}

	for _, raw := range [][]byte{xmlBytes(t, ours), read(t, theirPath)} {
		doc := xmlDoc(t, raw)
		if _, err := xmldsig.VerifySignatureWithKeyInfo(t.Context(), doc, xmldsig.Signatures(doc)[0], options); err != nil {
			t.Fatal(err)
		}

		bad := xmlDoc(t, bytes.Replace(raw, []byte("retrieved key"), []byte("changed key"), 1))
		if result, err := xmldsig.VerifySignatureWithKeyInfo(t.Context(), bad, xmldsig.Signatures(bad)[0], options); result != nil || err == nil {
			t.Fatal("changed signed data accepted", err)
		}
	}

	badPath := write(t, filepath.Join(dir, "bad.xml"), bytes.Replace(xmlBytes(t, ours), []byte("retrieved key"), []byte("changed key"), 1))
	native(t, fixture, false, nameVerify, append(append([]string(nil), args...), badPath)...)
}

func TestDetachedSignatures(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	cli := binary(t, fixture, "xmlsec")
	// Reuse immutable public resources; signing keys are fresh for every run.
	resourceDir := filepath.Join(fixture.root, "testdata/detached")
	manifest := filepath.Join(resourceDir, "resources.json")

	var entries []struct {
		URI        string `json:"uri"`
		Path       string `json:"path"`
		Digest     string `json:"digest_method"`
		Transforms []struct {
			Algorithm string `json:"algorithm"`
		} `json:"transforms"`
	}
	decode(t, read(t, manifest), &entries)

	signResources := make([]string, 0, 4*len(entries))
	verifyResources := make([]string, 0, 4*len(entries))
	allowlist := make([]map[string]string, 0, len(entries))

	for _, e := range entries {
		path := filepath.Join(resourceDir, e.Path)

		var transforms []string
		for _, tr := range e.Transforms {
			transforms = append(transforms, tr.Algorithm)
		}

		chain := strings.Join(transforms, "|")
		if chain == "" {
			chain = "-"
		}

		signResources = append(signResources, e.URI, path, e.Digest, chain)
		verifyResources = append(verifyResources, e.URI, path)
		allowlist = append(allowlist, map[string]string{"uri": e.URI, "path": path})
	}

	encoded, err := json.Marshal(allowlist)
	if err != nil {
		t.Fatal(err)
	}

	verificationManifest := write(t, filepath.Join(dir, "verify-resources.json"), encoded)
	count := 0

	for _, name := range []string{nameRsaSha256, nameRsaSha384, nameRsaSha512, nameEcdsaSha256, nameEcdsaSha384, nameEcdsaSha512} {
		key := generateKey(t, dir, name)
		for _, cm := range canonicalizations() {
			ours, theirs := filepath.Join(dir, "go.xml"), filepath.Join(dir, "jdk.xml")
			command(t, fixture, true, nil, cli, "sign-detached", flagKey, key.private, "-method", key.method, "-resources", manifest, "-c14n", cm, flagOut, ours)
			java(t, fixture, "DetachedOracle", append([]string{nameSign, key.private, theirs, cm, key.method}, signResources...)...)
			verifyJava(t, java(t, fixture, "DetachedOracle", append([]string{nameVerify, key.public, ours}, verifyResources...)...), true)
			raw, _ := command(t, fixture, true, nil, cli, "verify-detached", flagKey, key.public, "-resources", verificationManifest, "-c14n", cm, flagIn, theirs)

			var r struct {
				Version   int    `json:"schema_version"`
				Operation string `json:"operation"`
				Status    string `json:"status"`
				Details   struct {
					References []json.RawMessage `json:"references"`
				} `json:"details"`
			}
			decode(t, raw, &r)

			if r.Version != 1 || r.Operation != "signature verify-detached" || r.Status != nameValid || len(r.Details.References) != len(entries) {
				t.Fatalf("detached: %s", raw)
			}

			count++
		}

		bad := filepath.Join(dir, "bad.xml")
		java(t, fixture, "DetachedOracle", append([]string{"sign-bad-second", key.private, bad, exc, key.method}, signResources...)...)

		v := verifyJava(t, java(t, fixture, "DetachedOracle", append([]string{nameVerify, key.public, bad}, verifyResources...)...), false)
		if !v.References[0] || v.References[1] {
			t.Fatal(v)
		}

		_, errout := command(t, fixture, false, nil, cli, "verify-detached", flagKey, key.public, "-resources", verificationManifest, flagIn, bad)
		if !bytes.Contains(errout, []byte("reference 1")) || !bytes.Contains(errout, []byte("digest mismatch")) {
			t.Fatalf("negative stage: %s", errout)
		}
	}

	t.Logf("%d detached exchanges each direction, %d references per signature, 6 bad-second controls", count, len(entries))
}

type javaVerdict struct {
	Core           bool   `json:"core"`
	Valid          bool   `json:"valid"`
	SignatureValue bool   `json:"signature_value"`
	References     []bool `json:"references"`
}

func verifyJava(t *testing.T, raw []byte, valid bool) javaVerdict {
	t.Helper()

	var r javaVerdict
	decode(t, raw, &r)

	if (r.Core || r.Valid) != valid || !r.SignatureValue {
		t.Fatalf("JDK verdict: %s", raw)
	}

	if valid {
		for _, ref := range r.References {
			if !ref {
				t.Fatalf("JDK reference: %s", raw)
			}
		}
	}

	return r
}

func coreSignatures(t *testing.T, fixture *interopFixture, externalXMLSec bool) {
	t.Helper()
	cli := binary(t, fixture, "xmlsec")

	names := []string{nameRsaSha256, nameRsaSha384, nameRsaSha512, nameEcdsaSha256, nameEcdsaSha384, nameEcdsaSha512}
	if externalXMLSec {
		names = append(names, "rsa-pss256", "rsa-pss384", "rsa-pss512", nameEd25519)
	}

	suite := coreSignatureSuite{fixture: fixture, cli: cli, externalXMLSec: externalXMLSec}

	for number, name := range names {
		t.Run(name, func(t *testing.T) { suite.algorithm(t, name, number) })
	}

	t.Logf("%d generated signature exchanges in each direction", suite.count)
}

type coreSignatureRecipe struct {
	form string
	cm   string
}

type coreSignatureSuite struct {
	fixture        *interopFixture
	cli            string
	externalXMLSec bool
	count          int
}

func (suite *coreSignatureSuite) algorithm(t *testing.T, name string, number int) {
	t.Helper()
	dir := t.TempDir()

	keyName := name
	if strings.HasPrefix(name, "rsa-pss") {
		keyName = nameRsaSha256
	}

	key := generateKey(t, dir, keyName)
	if strings.HasPrefix(name, "rsa-pss") {
		key.method = "http://www.w3.org/2007/05/xmldsig-more#sha" + strings.TrimPrefix(name, "rsa-pss") + "-rsa-MGF1"
	}

	scenario := coreSignatureCase{suite: suite, dir: dir, key: key, digest: digests()[number%3]}

	for _, recipe := range coreSignatureRecipes() {
		t.Run(recipe.form+"/"+strconv.Itoa(slices.Index(canonicalizations(), recipe.cm)), func(t *testing.T) {
			scenario.exchange(t, recipe)
		})
	}

	if !suite.externalXMLSec {
		scenario.rejectBadSecond(t)
	}
}

func coreSignatureRecipes() []coreSignatureRecipe {
	recipes := make([]coreSignatureRecipe, 0, 2*len(canonicalizations()))
	for _, cm := range canonicalizations() {
		for _, form := range []string{nameEnveloping, "whole"} {
			recipes = append(recipes, coreSignatureRecipe{form, cm})
		}
	}

	for _, form := range []string{"sibling", "xpointer", nameMulti} {
		recipes = append(recipes, coreSignatureRecipe{form, exc})
	}

	return recipes
}

type verification struct {
	Status         string `json:"status"`
	SignatureValue string `json:"signature_value"`
	References     []struct {
		Status string `json:"status"`
	} `json:"references"`
}

type coreSignatureExchange struct {
	recipe coreSignatureRecipe
	source string
	ours   string
	theirs string
	total  int
}

type coreSignatureCase struct {
	suite  *coreSignatureSuite
	dir    string
	key    testKey
	digest string
}

func (scenario coreSignatureCase) exchange(t *testing.T, recipe coreSignatureRecipe) {
	t.Helper()
	source := write(t, filepath.Join(scenario.dir, "template.xml"), []byte(strings.ReplaceAll(coreTemplate(recipe.form, scenario.key.method, recipe.cm), digests()[0], scenario.digest)))

	exchange := coreSignatureExchange{
		recipe: recipe,
		source: source,
		ours:   filepath.Join(scenario.dir, "go.xml"),
		theirs: filepath.Join(scenario.dir, "reference.xml"),
		total:  1,
	}
	if recipe.form == nameMulti {
		exchange.total = 2
	}

	scenario.signExchange(t, exchange)
	scenario.verifyExchange(t, exchange)

	if scenario.suite.externalXMLSec {
		scenario.rejectTamper(t, exchange)
	}
}

func (scenario coreSignatureCase) signExchange(t *testing.T, exchange coreSignatureExchange) {
	t.Helper()

	for index := range exchange.total {
		input := exchange.source
		if index > 0 {
			input = exchange.ours
		}

		args := []string{"sign-template", flagKey, scenario.key.private, "-signature-index", strconv.Itoa(index), "-c14n", exchange.recipe.cm, "-modern-algorithms", flagIn, input, flagOut, exchange.ours}
		if index > 0 {
			args = append(args, "-preserve", "0="+scenario.key.public)
		}

		command(t, scenario.suite.fixture, true, nil, scenario.suite.cli, args...)

		if scenario.suite.externalXMLSec {
			input = exchange.source
			if index > 0 {
				input = exchange.theirs
			}

			args = append([]string{"--privkey-pem", scenario.key.private, flagEnabledReferenceUris, nameEmptySameDoc}, idArgs()...)
			args = append(args, "--node-id", "s"+strconv.Itoa(index), "--output", exchange.theirs, input)
			native(t, scenario.suite.fixture, true, nameSign, args...)
		}
	}

	if !scenario.suite.externalXMLSec {
		java(t, scenario.suite.fixture, "CoreOracle", nameSign, scenario.key.private, exchange.theirs, exchange.recipe.cm, scenario.key.method, exchange.recipe.form)
	}
}

func (scenario coreSignatureCase) verifyExchange(t *testing.T, exchange coreSignatureExchange) {
	t.Helper()

	for index := range exchange.total {
		if scenario.suite.externalXMLSec {
			args := append([]string{flagPubkeyPem, scenario.key.public, flagEnabledReferenceUris, nameEmptySameDoc}, idArgs()...)
			native(t, scenario.suite.fixture, true, nameVerify, append(args, "--node-id", "s"+strconv.Itoa(index), exchange.ours)...)
		} else {
			verifyJava(t, java(t, scenario.suite.fixture, "CoreOracle", nameVerify, scenario.key.public, exchange.ours, strconv.Itoa(index)), true)
		}

		raw, _ := command(t, scenario.suite.fixture, true, nil, scenario.suite.cli, "verify-core", flagKey, scenario.key.public, "-signature-index", strconv.Itoa(index), "-modern-algorithms", "-c14n", exchange.recipe.cm, flagIn, exchange.theirs)
		verifyReport(t, raw, true)

		scenario.suite.count++
	}
}

func (scenario coreSignatureCase) rejectTamper(t *testing.T, exchange coreSignatureExchange) {
	t.Helper()
	original := read(t, exchange.theirs)

	changed := bytes.Replace(original, []byte(">one<"), []byte(">changed<"), 1)
	if bytes.Equal(original, changed) {
		t.Fatal("negative control did not alter input")
	}

	bad := write(t, filepath.Join(scenario.dir, "bad.xml"), changed)
	args := append([]string{flagPubkeyPem, scenario.key.public, flagEnabledReferenceUris, nameEmptySameDoc}, idArgs()...)
	native(t, scenario.suite.fixture, false, nameVerify, append(args, "--node-id", "s0", bad)...)
	raw, _ := command(t, scenario.suite.fixture, false, nil, scenario.suite.cli, "verify-core", flagKey, scenario.key.public, "-signature-index", "0", "-modern-algorithms", "-c14n", exchange.recipe.cm, flagIn, bad)
	verifyReport(t, raw, false)

	if exchange.recipe.form == nameEnveloping && exchange.recipe.cm == exc {
		write(t, bad, bytes.Replace(original, []byte("aGVsbG8="), []byte("aGVsbG8h"), 1))
		native(t, scenario.suite.fixture, false, nameVerify, append(args, bad)...)
		raw, _ = command(t, scenario.suite.fixture, false, nil, scenario.suite.cli, "verify-core", flagKey, scenario.key.public, "-signature-index", "0", "-modern-algorithms", flagIn, bad)
		badSecond(t, verifyReport(t, raw, false))
	}
}

func (scenario coreSignatureCase) rejectBadSecond(t *testing.T) {
	t.Helper()

	bad := filepath.Join(scenario.dir, "bad-second.xml")
	java(t, scenario.suite.fixture, "CoreOracle", "sign-bad-second", scenario.key.private, bad, exc, scenario.key.method, nameEnveloping)

	oracle := verifyJava(t, java(t, scenario.suite.fixture, "CoreOracle", nameVerify, scenario.key.public, bad, "0"), false)
	if !slices.Equal(oracle.References, []bool{true, false, true}) {
		t.Fatal(oracle)
	}

	raw, _ := command(t, scenario.suite.fixture, false, nil, scenario.suite.cli, "verify-core", flagKey, scenario.key.public, "-signature-index", "0", flagIn, bad)
	badSecond(t, verifyReport(t, raw, false))
}

func referenceTemplate(uri string, transforms ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<ds:Reference URI="%s">`, strings.ReplaceAll(uri, `"`, "&quot;"))

	if len(transforms) > 0 {
		b.WriteString("<ds:Transforms>")

		for _, alg := range transforms {
			fmt.Fprintf(&b, `<ds:Transform Algorithm="%s"/>`, alg)
		}

		b.WriteString("</ds:Transforms>")
	}

	fmt.Fprintf(&b, `<ds:DigestMethod Algorithm="%s"/><ds:DigestValue/></ds:Reference>`, digests()[0])

	return b.String()
}

func signatureTemplate(index int, method, cm, refs, objects string) string {
	return fmt.Sprintf(`<ds:Signature xmlns:ds="%s" Id="s%d"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="%s"/><ds:SignatureMethod Algorithm="%s"/>%s</ds:SignedInfo><ds:SignatureValue/>%s</ds:Signature>`, ds, index, cm, method, refs, objects)
}

func coreTemplate(form, method, cm string) string {
	if form == nameEnveloping {
		refs := referenceTemplate("#data", cm) + referenceTemplate("#bin", ds+"base64") + referenceTemplate("#data", exc)
		return signatureTemplate(0, method, cm, refs, `<ds:Object Id="data" MimeType="text/xml"><p:item xmlns:p="urn:payload">one<!--comment--></p:item></ds:Object><ds:Object Id="bin">aGVsbG8=</ds:Object>`)
	}

	var refs string

	switch form {
	case "whole":
		refs = referenceTemplate("", ds+"enveloped-signature", cm) + referenceTemplate("#root", ds+"enveloped-signature", exc)
	case "xpointer":
		refs = referenceTemplate("#xpointer(id('data'))", exc+"WithComments") + referenceTemplate("#data", exc+"WithComments")
	default:
		refs = referenceTemplate("#data", cm) + referenceTemplate("#other", c11)
	}

	sigs := signatureTemplate(0, method, cm, refs, "")
	if form == nameMulti {
		sigs += signatureTemplate(1, method, cm, refs, "")
	}

	return `<root xmlns:z="urn:unused" ID="root"><item ID="data">one<!--comment--></item><item ID="other">two<!--comment--></item>` + sigs + `</root>`
}

func verifyReport(t *testing.T, raw []byte, valid bool) verification {
	t.Helper()

	var envelope struct {
		Version   int    `json:"schema_version"`
		Operation string `json:"operation"`
		Status    string `json:"status"`
		Details   struct {
			Checks verification `json:"checks"`
		} `json:"details"`
	}
	decode(t, raw, &envelope)

	r := envelope.Details.Checks
	if envelope.Version != 1 || envelope.Operation != "signature verify-core" || envelope.Status != r.Status || len(r.References) == 0 {
		t.Fatalf("verification report schema: %s", raw)
	}

	if (r.Status == nameValid) != valid || r.SignatureValue != nameValid {
		t.Fatalf("verification: %s", raw)
	}

	if valid {
		for _, ref := range r.References {
			if ref.Status != nameValid {
				t.Fatalf("reference: %s", raw)
			}
		}
	}

	return r
}

func badSecond(t *testing.T, r verification) {
	t.Helper()

	statuses := make([]string, 0, len(r.References))
	for _, ref := range r.References {
		statuses = append(statuses, ref.Status)
	}

	if !slices.Equal(statuses, []string{nameValid, "invalid", "not-checked"}) {
		t.Fatalf("bad second reference: %v", statuses)
	}
}

func idArgs() []string {
	return []string{flagIDAttrID, nameRoot, flagIDAttrID, "item", flagIDAttrID, "payload", flagMixedCaseIDAttribute, ds + ":Object", flagMixedCaseIDAttribute, ds + ":Signature"}
}

func native(t *testing.T, fixture *interopFixture, success bool, mode string, args ...string) []byte {
	t.Helper()

	all := append([]string{mode, "--lax-key-search"}, args...)
	out, _ := command(t, fixture, success, nil, xmlsecExecutable(), all...)

	return out
}

func TestXAdESBaselineFormats(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	schema := xadesPublishedSchema(t)
	key := generateKey(t, fixture.work, nameEcdsaSha256)
	extra := generateKey(t, t.TempDir(), nameEcdsaSha384)
	for _, method := range canonicalizations() {
		for _, form := range []string{"nested-enveloped", "sibling", "enveloping", "external"} {
			t.Run(method+"/"+form, func(t *testing.T) {
				options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{ID: "baseline", SignatureMethod: key.method, Canonicalization: reference.Transform{Algorithm: method}, Certificates: [][]byte{key.cert.Raw, extra.cert.Raw}}, SignedPropertiesID: "properties", Properties: xades.BaselineProperties{SigningTime: time.Now().UTC(), SigningCertificateDigest: xmldsig.SHA512, AdditionalCertificates: []xades.CertificateIdentifier{{DER: extra.cert.Raw, DigestMethod: xmldsig.SHA384, IncludeIssuerSerial: true}}, ProductionPlace: &xades.ProductionPlace{City: "Perm", StreetAddress: "Main", CountryName: "RU"}, ClaimedRoles: []xades.PropertyValue{{Text: "author"}}, Commitments: []xades.CommitmentType{{Identifier: xades.ObjectIdentifier{Identifier: "urn:commitment:origin"}, All: true}}, Policy: &xades.SignaturePolicy{Identifier: xades.ObjectIdentifier{Identifier: "urn:policy:1"}, DigestMethod: xmldsig.SHA384, Qualifiers: []xades.PolicyQualifier{{URI: "https://example.test/policy"}, {Notice: &xades.PolicyNotice{Organization: "Example", NoticeNumbers: []string{"1", "-9999999999999999999999999999"}, ExplicitText: "terms"}}, {Specification: &xades.ObjectIdentifier{Identifier: "urn:oid:1.2.3", Qualifier: "OIDAsURN"}}}}}, Validation: xades.BaselineVerifyOptions{PolicyDocument: []byte("independent policy bytes")}}
				var doc *document.Document
				var parent document.Element
				switch form {
				case "nested-enveloped":
					doc = xmlDoc(t, []byte(`<Envelope><payload ID="payload">123</payload></Envelope>`))
					parent = doc.Root().Children()[0]
					options.Template.References = []xmldsig.ReferenceTemplate{{ID: "data", URI: "#payload", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}, {Algorithm: method}}}}
				case "sibling":
					doc = xmlDoc(t, []byte(`<Envelope><payload ID="payload">123</payload><slot/></Envelope>`))
					parent = doc.Root().Children()[1]
					options.Template.References = []xmldsig.ReferenceTemplate{{ID: "data", URI: "#payload", Transforms: []reference.Transform{{Algorithm: method}}}}
				case "enveloping":
					value := "123"
					options.Template.Objects = []xmldsig.ObjectTemplate{{ID: "payload", Text: &value}}
					options.Template.References = []xmldsig.ReferenceTemplate{{ID: "data", URI: "#payload", Transforms: []reference.Transform{{Algorithm: method}}}}
				case "external":
					path := write(t, filepath.Join(t.TempDir(), "payload.bin"), []byte("123"))
					uri := (&url.URL{Scheme: "file", Path: path}).String()
					options.Template.References = []xmldsig.ReferenceTemplate{{ID: "data", URI: uri}}
					options.Validation.Signature.External = &xmldsig.ExternalReferences{AllowedURIs: []string{uri}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
						return io.NopCloser(strings.NewReader("123")), nil
					})}
				}
				options.Properties.DataObjects = []xades.DataObjectFormat{{ObjectReference: "#data", Description: "data", MIMEType: "application/octet-stream", ObjectIdentifier: &xades.ObjectIdentifier{Identifier: "urn:oid:1.2.840.113549", Qualifier: "OIDAsURN", Documentation: []string{"https://example.test/format"}}}}
				signed, result, err := xades.SignBaseline(t.Context(), doc, parent, key.signer, key.cert.Raw, options)
				if err != nil {
					t.Fatal(err)
				}
				path := write(t, filepath.Join(t.TempDir(), "baseline.xml"), xmlBytes(t, signed))
				arguments := []string{flagPubkeyPem, key.public, flagIDAttrID, "payload", flagMixedCaseIDAttribute, xades.Namespace + ":SignedProperties", flagMixedCaseIDAttribute, ds + ":Signature", flagMixedCaseIDAttribute, ds + ":Object", "--node-id", "baseline", flagEnabledReferenceUris, "same-doc,local", path}
				native(t, fixture, true, nameVerify, arguments...)
				xadesSchemaFragment(t, fixture, schema, result.Basic().Signature().Signature(), true)
				for _, reference := range result.CertificateReferences() {
					hash := "-sha512"
					if reference.DigestMethod() == xmldsig.SHA384 {
						hash = "-sha384"
					}
					expected, _ := command(t, fixture, true, reference.CertificateDER(), "openssl", "dgst", hash, flagBinary)
					if !bytes.Equal(reference.Digest(), expected) {
						t.Fatal("OpenSSL certificate digest")
					}
				}
				expected, _ := command(t, fixture, true, options.Validation.PolicyDocument, "openssl", "dgst", "-sha384", flagBinary)
				if !bytes.Equal(result.SignaturePolicy().Digest, expected) {
					t.Fatal("OpenSSL policy digest")
				}
				// The ready XMLSec engine independently signs the same property-bearing
				// template; native validation then checks the exact policy/certificate binding.
				draft, err := tree.Clone(t.Context(), signed)
				if err != nil {
					t.Fatal(err)
				}
				selectedSignature := xmldsig.Signatures(draft)[0]
				_, sv := tree.Unwrap(selectedSignature.Children()[1])
				sv.Children = nil
				for _, ref := range selectedSignature.Children()[0].Children()[2:] {
					fields := ref.Children()
					_, value := tree.Unwrap(fields[len(fields)-1])
					value.Children = nil
				}
				template := write(t, filepath.Join(t.TempDir(), "template.xml"), xmlBytes(t, draft))
				theirs := filepath.Join(t.TempDir(), "xmlsec.xml")
				signArgs := []string{"--privkey-pem", key.private, flagIDAttrID, "payload", flagMixedCaseIDAttribute, xades.Namespace + ":SignedProperties", flagMixedCaseIDAttribute, ds + ":Signature", flagMixedCaseIDAttribute, ds + ":Object", "--node-id", "baseline", flagEnabledReferenceUris, "same-doc,local", flagNativeOutput, theirs, template}
				native(t, fixture, true, nameSign, signArgs...)
				parsed := xmlDoc(t, read(t, theirs))
				if _, err := xades.VerifyBaseline(t.Context(), parsed, xmldsig.Signatures(parsed)[0], key.cert.Raw, options.Validation); err != nil {
					t.Fatal(err)
				}
				if method == exc && form == "sibling" {
					xadesPublishedSchemaRejects(t, fixture, schema, signed)
				}
				t.Log("P7_ORACLE xmlsec1 baseline topology/core; pinned ETSI XSD properties; OpenSSL certificate and policy digests")
			})
		}
	}
}

func xadesPublishedSchema(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("XADES_SCHEMA_DIR")
	if dir == "" {
		if os.Getenv("XMLSEC_REQUIRE_P7_PROOFS") == "1" {
			t.Fatal("XADES_SCHEMA_DIR is required")
		}
		t.Skip("set XADES_SCHEMA_DIR to exact ETSI v1.3.1 schemas and their W3C2008 XMLDSig import")
	}
	pins := map[string]string{"1913201-XAdES01903v132.xsd": "457745286eaa292ae1aaa6e976e0f30eeceb0a37cc2301151576175e0ae1986c", "1913201-XAdES01903v141.xsd": "286bd63f122aafb907c03724c5959455d114020e523631cc22e90c5f5aa667e2", "xmldsig-core-schema-2008.xsd": "35cf8197da812c85e40d57891b35c94187569ed474a2dac813ce5090dafcd35c"}
	local := t.TempDir()
	for name, pin := range pins {
		raw := read(t, filepath.Join(dir, name))
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != pin {
			t.Fatal("published XAdES schema pin mismatch", name)
		}
		write(t, filepath.Join(local, name), raw)
	}
	uri := func(name string) string { return (&url.URL{Scheme: "file", Path: filepath.Join(local, name)}).String() }
	catalog := `<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog"><uri name="http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/xmldsig-core-schema.xsd" uri="` + uri("xmldsig-core-schema-2008.xsd") + `"/><uri name="https://forge.etsi.org/rep/esi/x19_13201_XAdES/raw/v1.3.1/1913201-XAdES01903v132.xsd" uri="` + uri("1913201-XAdES01903v132.xsd") + `"/></catalog>`
	t.Setenv("XML_CATALOG_FILES", write(t, filepath.Join(local, "catalog.xml"), []byte(catalog)))
	entry := `<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:import namespace="` + ds + `" schemaLocation="` + uri("xmldsig-core-schema-2008.xsd") + `"/><xs:import namespace="` + xades.Namespace + `" schemaLocation="` + uri("1913201-XAdES01903v132.xsd") + `"/><xs:import namespace="` + xades.Namespace141 + `" schemaLocation="` + uri("1913201-XAdES01903v141.xsd") + `"/></xs:schema>`
	return write(t, filepath.Join(local, "xades-schema.xsd"), []byte(entry))
}

func xadesSchemaFragment(t *testing.T, fixture *interopFixture, schema string, selected document.Element, success bool) {
	t.Helper()
	owner, node := tree.Unwrap(selected)
	fragment := tree.FromNodes([]*tree.Node{tree.ImportSubtree(node)}, tree.Policy(owner))
	path := write(t, filepath.Join(t.TempDir(), "signature.xml"), xmlBytes(t, fragment))
	command(t, fixture, success, nil, "xmllint", "--nonet", "--noout", "--schema", schema, path)
}

func xadesPublishedSchemaRejects(t *testing.T, fixture *interopFixture, schema string, signed *document.Document) {
	t.Helper()
	for _, tc := range []struct {
		name   string
		change func(*tree.Node)
	}{
		{"duplicate signing time", func(root *tree.Node) {
			ssp := one(t, root, xades.Namespace, "SignedSignatureProperties")
			duplicate := tree.ImportSubtree(ssp.Children[0])
			duplicate.Parent = ssp
			ssp.Children = append([]*tree.Node{duplicate}, ssp.Children...)
		}},
		{"missing format reference", func(root *tree.Node) { node := one(t, root, xades.Namespace, "DataObjectFormat"); node.Attrs = nil }},
		{"production place order", func(root *tree.Node) {
			node := one(t, root, xades.Namespace, "SignatureProductionPlaceV2")
			node.Children[0], node.Children[1] = node.Children[1], node.Children[0]
		}},
		{"both signature policy alternatives", func(root *tree.Node) {
			node := one(t, root, xades.Namespace, "SignaturePolicyIdentifier")
			node.Children = append(node.Children, &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: xades.Namespace, Local: "SignaturePolicyImplied"}, Prefix: "xades", Parent: node})
		}},
		{"duplicate claimed role container", func(root *tree.Node) {
			node := one(t, root, xades.Namespace, "SignerRoleV2")
			duplicate := tree.ImportSubtree(node.Children[0])
			duplicate.Parent = node
			node.Children = append(node.Children, duplicate)
		}},
	} {
		t.Run("published grammar rejects/"+tc.name, func(t *testing.T) {
			draft, err := tree.Clone(t.Context(), signed)
			if err != nil {
				t.Fatal(err)
			}
			tc.change(tree.Root(draft))
			xadesSchemaFragment(t, fixture, schema, xmldsig.Signatures(draft)[0], false)
		})
	}
}

func TestXAdESBaselineDataTimestampInputs(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	schema := xadesPublishedSchema(t)
	key := generateKey(t, fixture.work, nameEcdsaSha256)
	chain := testcert.New(t)
	rootPEM := write(t, filepath.Join(fixture.work, "timestamp-root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.Root.Raw}))
	for _, method := range canonicalizations() {
		for _, individual := range []bool{false, true} {
			t.Run(method+"/"+strconv.FormatBool(individual), func(t *testing.T) {
				source := xmlDoc(t, []byte(`<Message xmlns:u="urn:unused"><payload ID="payload">content<!--retained by XPointer--></payload><slot/></Message>`))
				uri := `#xpointer(id('payload'))`
				oracle, _, err := xmldsig.BuildTemplate(t.Context(), source, source.Root().Children()[1], xmldsig.SignatureTemplate{SignatureMethod: key.method, References: []xmldsig.ReferenceTemplate{{URI: uri, Transforms: []reference.Transform{{Algorithm: method}}}}})
				if err != nil {
					t.Fatal(err)
				}
				template := write(t, filepath.Join(t.TempDir(), "oracle.xml"), xmlBytes(t, oracle))
				signedOracle := filepath.Join(t.TempDir(), "signed-oracle.xml")
				command(t, fixture, true, nil, xmlsecExecutable(), nameSign, "--lax-key-search", "--privkey-pem", key.private, flagIDAttrID, "payload", flagNativeOutput, signedOracle, template)
				output, stderr := command(t, fixture, true, nil, xmlsecExecutable(), nameVerify, "--lax-key-search", "--verbose", "--print-debug", "--store-references", flagPubkeyPem, key.public, flagIDAttrID, "payload", signedOracle)
				buffers := regexp.MustCompile(`(?s)== PreDigest data - start buffer:\n(.*?)\n== PreDigest data - end buffer`).FindAllSubmatch(append(output, stderr...), -1)
				if len(buffers) != 1 {
					t.Fatalf("XMLSec exact canonical reference input missing: stdout=%s stderr=%s", output, stderr)
				}
				expected := buffers[0][1]
				request, err := timestamp.CreateRequest(t.Context(), expected, timestamp.RequestOptions{Hash: crypto.SHA384})
				if err != nil {
					t.Fatal(err)
				}
				response, err := timestamp.IssueResponse(t.Context(), request.DER(), chain.TSAKey, chain.TSA.Raw, timestamp.IssueOptions{Policy: []int{1, 2, 3, 4}, SerialNumber: big.NewInt(1), GenTime: testcert.Now(), ExtraCertificates: [][]byte{chain.Root.Raw}})
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := timestamp.ParseResponse(t.Context(), response)
				if err != nil {
					t.Fatal(err)
				}
				data := write(t, filepath.Join(t.TempDir(), "content.bin"), expected)
				reply := write(t, filepath.Join(t.TempDir(), "response.tsr"), response)
				command(t, fixture, true, nil, "openssl", "ts", flagVerify, flagIn, reply, "-data", data, "-CAfile", rootPEM, "-attime", strconv.FormatInt(testcert.Now().Unix(), 10))
				property := xades.DataTimestampProperty{Individual: individual, Canonicalization: reference.Transform{Algorithm: method}, TokenDER: parsed.TokenDER()}
				if individual {
					property.ObjectReferences = []string{"#data"}
				}
				doc, result, err := xades.SignBaseline(t.Context(), source, source.Root().Children()[1], key.signer, key.cert.Raw, xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: key.method, References: []xmldsig.ReferenceTemplate{{ID: "data", URI: uri}}}, Properties: xades.BaselineProperties{SigningTime: time.Now().UTC(), DataTimestamps: []xades.DataTimestampProperty{property}}})
				if err != nil {
					t.Fatal(err)
				}
				var actual bytes.Buffer
				if _, err := result.DataTimestamps()[0].WriteImprintInput(t.Context(), &actual); err != nil || !bytes.Equal(actual.Bytes(), expected) {
					t.Fatal("timestamp bytes disagree with ready XMLSec canonicalization", actual.String(), string(expected), err)
				}
				xadesSchemaFragment(t, fixture, schema, result.Basic().Signature().Signature(), true)
				path := write(t, filepath.Join(t.TempDir(), "baseline.xml"), xmlBytes(t, doc))
				native(t, fixture, true, nameVerify, flagPubkeyPem, key.public, flagIDAttrID, "payload", flagMixedCaseIDAttribute, xades.Namespace+":SignedProperties", path)
				t.Log("P7_ORACLE XMLSec exact final-node-set canonicalization; OpenSSL RFC3161 SHA384 token; published XAdES Include/encapsulation schema")
			})
		}
	}
}
