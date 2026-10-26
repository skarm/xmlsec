package keyinfo_test

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/x509name"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
)

const (
	uriUrnKey    = "urn:key"
	prefixDSig11 = "dsig11"
	uriChanged   = "urn:changed"
)

func TestKeyInfoURIContexts(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(strconv.FormatBool(explicit), func(t *testing.T) { testKeyInfoURIContext(t, explicit) })
	}
}

func testKeyInfoURIContext(t *testing.T, explicit bool) {
	t.Helper()

	const (
		base  = "https://example.test/messages/signature.xml"
		outer = "https://example.test/keys/bundle.xml#key"
		leaf  = "https://example.test/keys/nested.xml?version=1#leaf"
	)

	key := ec(t, elliptic.P256())

	remote := wrap(derXML(t, &key.PublicKey))
	options := keyinfo.Options{}

	if explicit {
		processing := reference.DefaultOptions()
		options.RetrievalProcessing = &processing
	}

	resources := map[string]string{outer: wrap(`<k:KeyInfoReference URI="nested.xml?version=1#leaf"/>`), leaf: remote}
	calls := map[string]int{}

	var readers []*reader

	options.External = &keyinfo.ExternalResources{BaseURI: base, AllowedURIs: []string{outer, leaf}, Resolver: resolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
		calls[uri]++

		value, ok := resources[uri]
		if !ok {
			t.Fatal("unexpected URI", uri)
		}
		// Configuration belongs to the operation after entry, even when a
		// callback mutates every caller-owned URI setting.
		options.External.BaseURI = "https://changed.test/"
		options.External.AllowedURIs[1] = uriChanged
		stream := &reader{read: strings.NewReader(value).Read}
		readers = append(readers, stream)

		return stream, nil
	})}

	info, err := keyinfo.Build(t.Context(), keyinfo.Template{KeyInfoReferences: []string{"bundle.xml#key"}, RetrievalMethods: []keyinfo.RetrievalMethod{{URI: "./bundle.xml#key"}}})
	if err != nil {
		t.Fatal(err)
	}

	doc := parseXML(t, `<message xml:base="../keys/">`+asXML(t, info)+`</message>`)

	result, err := keyinfo.Parse(t.Context(), doc, doc.Root().Children()[0], options)
	if err != nil || len(result.Candidates()) != 2 || calls[outer] != 1 || calls[leaf] != 1 || len(calls) != 2 {
		t.Fatal("nested URI context/cache", err, calls)
	}

	for _, candidate := range result.Candidates() {
		if candidate.ResourceURI() != leaf || !bytes.Equal(candidate.SPKI(), mustSPKI(t, &key.PublicKey)) {
			t.Fatal("resolved key identity changed")
		}
	}

	for _, stream := range readers {
		if !stream.closed {
			t.Fatal("resource was not closed")
		}
	}

	// Resolved aliases must identify the same graph node, including when
	// transformed snapshots are used by the explicit processing profile.
	resources[leaf] = wrap(`<k:KeyInfoReference URI="./bundle.xml#key"/>`)
	options.External.BaseURI = base
	options.External.AllowedURIs = []string{outer, leaf}

	clear(calls)

	if result, err := keyinfo.Parse(t.Context(), doc, doc.Root().Children()[0], options); result != nil || !errors.Is(err, keyinfo.ErrCycle) || calls[outer] != 1 || calls[leaf] != 1 {
		t.Fatal("resolved cycle", err, calls)
	}
}

func TestKeyInfoURIContextPolicy(t *testing.T) {
	const (
		base    = "https://example.test/messages/signature.xml"
		allowed = "https://example.test/messages/key.xml#selected"
	)

	noRead := resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		t.Fatal("I/O preceded URI preflight")
		return nil, nil
	})
	for _, value := range []string{"relative", "urn:opaque", base + "#fragment", "https://user:secret@example.test/key", "https://example.test/%xy", strings.Repeat("x", 8193)} {
		options := keyinfo.Options{External: &keyinfo.ExternalResources{BaseURI: value, AllowedURIs: []string{allowed}, Resolver: noRead}}
		requireErr(t, wrap(`<ds:KeyName>hint</ds:KeyName>`), options, keyinfo.ErrPolicy)
	}

	options := keyinfo.Options{External: &keyinfo.ExternalResources{BaseURI: base, AllowedURIs: []string{allowed}, Resolver: noRead}}
	for _, body := range []string{
		`<k:KeyInfoReference URI="key.xml#selected"/><k:KeyInfoReference URI="denied.xml"/>`,
		`<k:KeyInfoReference URI="key.xml#selected"/><ds:RetrievalMethod URI="denied.xml"/>`,
	} {
		requireErr(t, wrap(body), options, keyinfo.ErrPolicy)
	}

	for _, uri := range []string{"bad%xx", "key.xml#one#two", `key\file`, "key file"} {
		requireErr(t, wrap(`<k:KeyInfoReference URI="`+uri+`"/>`), options, keyinfo.ErrInput)
	}

	options.External.BaseURI = ""
	requireErr(t, wrap(`<k:KeyInfoReference URI="key.xml#selected"/>`), options, keyinfo.ErrPolicy)

	key := ec(t, elliptic.P256())
	doc := parseXML(t, `<message xml:base="https://elsewhere.test/"><ds:KeyInfo xmlns:ds="`+ns+`" xmlns:k="`+ns11+`"><k:KeyInfoReference URI="#local"/></ds:KeyInfo><ds:KeyInfo xmlns:ds="`+ns+`" xmlns:k="`+ns11+`" Id="local">`+derXML(t, &key.PublicKey)+`</ds:KeyInfo></message>`)
	options.External.BaseURI = base

	result, err := keyinfo.Parse(t.Context(), doc, doc.Root().Children()[0], options)
	if err != nil || len(result.Candidates()) != 1 || result.Candidates()[0].ResourceURI() != "" || len(result.ExternalURIs()) != 0 {
		t.Fatal("same-document scope changed under xml:base", err)
	}

	// Complete fragment identities reach the resolver, also for binary keys.
	der := cert(t, key)
	options.External.Resolver = resolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
		if uri != allowed {
			t.Fatal("fragment was discarded", uri)
		}

		return io.NopCloser(bytes.NewReader(der)), nil
	})
	doc = parseXML(t, wrap(`<ds:RetrievalMethod URI="key.xml#selected" Type="`+keyinfo.RawX509Certificate+`"/>`))

	result, err = keyinfo.Parse(t.Context(), doc, doc.Root(), options)
	if err != nil || len(result.Candidates()) != 1 || result.Candidates()[0].ResourceURI() != allowed {
		t.Fatal("raw-certificate URI context", err)
	}
}

func TestRetrievalTypesAndPreflight(t *testing.T) {
	k := ec(t, elliptic.P256())
	full := parseXML(t, wrap(derXML(t, &k.PublicKey)))
	xml := asXML(t, full)
	// Pull a DEREncodedKeyValue out with a root namespace declaration, not a KeyInfo wrapper.
	remote := `<k:DEREncodedKeyValue xmlns:k="` + ns11 + `">` + enc(mustSPKI(t, &k.PublicKey)) + `</k:DEREncodedKeyValue>`
	for _, test := range []struct {
		name string
		typ  string
		err  error
	}{{"typed", ns11 + "DEREncodedKeyValue", nil}, {"inferred", "", nil}, {"mismatch", ns + "X509Data", keyinfo.ErrInput}} {
		t.Run(test.name, func(t *testing.T) {
			d := parseXML(t, wrap(`<ds:RetrievalMethod URI="urn:key" Type="`+test.typ+`"/>`))
			o := keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(remote)), nil
			})}}

			r, e := keyinfo.Parse(t.Context(), d, d.Root(), o)
			if test.err != nil {
				if r != nil || !errors.Is(e, test.err) {
					t.Fatal(e)
				}

				return
			}

			if e != nil || len(r.Candidates()) != 1 {
				t.Fatal(e)
			}
		})
	}

	calls := 0
	o := keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return io.NopCloser(strings.NewReader(xml)), nil
	})}}
	requireErr(t, wrap(`<ds:RetrievalMethod URI="urn:key"><ds:Transforms><ds:Transform Algorithm="urn:unsupported"/></ds:Transforms></ds:RetrievalMethod>`), o, keyinfo.ErrUnsupported)

	if calls != 0 {
		t.Fatal("resource fetched before transform preflight")
	}
}

func mustSPKI(t testing.TB, k any) []byte {
	t.Helper()

	b, e := x509.MarshalPKIXPublicKey(k)
	if e != nil {
		t.Fatal(e)
	}

	return b
}

func TestDirectCRLRetainedWithoutTrust(t *testing.T) {
	key := ec(t, elliptic.P256())
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	ca := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "test"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}

	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}

	issuer, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}

	crl, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour)}, issuer, key)
	if e != nil {
		t.Fatal(e)
	}

	r := parseInfo(t, wrap(`<ds:X509Data><ds:X509CRL>`+enc(crl)+`</ds:X509CRL></ds:X509Data>`))

	g := r.X509Groups()[0]
	if len(r.Candidates()) != 0 || !g.Source().Valid() {
		t.Fatal("CRL became key")
	}

	g.CRLsDER()[0][0] ^= 255
	if !bytes.Equal(g.CRLsDER()[0], crl) {
		t.Fatal("CRL not owned")
	}
}

func TestLocalAndRemoteBudgets(t *testing.T) {
	requireErr(t, wrap(`<ds:KeyName>12345</ds:KeyName>`), keyinfo.Options{Limits: keyinfo.Limits{MaxBlobBytes: 4}}, keyinfo.ErrLimit)
	requireErr(t, wrap(`<ds:KeyName>x</ds:KeyName><ds:KeyName>x</ds:KeyName>`), keyinfo.Options{Limits: keyinfo.Limits{MaxElements: 2}}, keyinfo.ErrLimit)
	requireErr(t, wrap(`<k:DEREncodedKeyValue>`+strings.Repeat("A", 80)+`</k:DEREncodedKeyValue>`), keyinfo.Options{Limits: keyinfo.Limits{MaxBlobBytes: 4}}, keyinfo.ErrLimit)

	ctx, cancel := context.WithCancel(t.Context())
	r := &reader{read: func([]byte) (int, error) { cancel(); return 0, nil }}
	d := parseXML(t, wrap(`<k:KeyInfoReference URI="urn:key"/>`))

	result, e := keyinfo.Parse(ctx, d, d.Root(), keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) { return r, nil })}})
	if result != nil || !errors.Is(e, context.Canceled) || !r.closed {
		t.Fatal("cancellation/close", e)
	}
}

func TestRawCertificateRetainsFinalReadError(t *testing.T) {
	key := ec(t, elliptic.P256())
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}

	certificate, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	input := bytes.NewReader(certificate)
	failure := errors.New("final read failed")
	source := &reader{read: func(dst []byte) (int, error) {
		n, err := input.Read(dst)
		if n > 0 && input.Len() == 0 {
			err = failure
		}

		return n, err
	}}
	doc := parseXML(t, wrap(`<ds:RetrievalMethod URI="urn:key" Type="`+keyinfo.RawX509Certificate+`"/>`))

	options := keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) { return source, nil })}}
	if result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), options); result != nil || !errors.Is(err, failure) || !source.closed {
		t.Fatal("resource failure yielded key candidates", result, err, source.closed)
	}
}

func TestRetrievalTransformChains(t *testing.T) {
	key := ec(t, elliptic.P256())
	keyXML := `<k:DEREncodedKeyValue xmlns:k="` + ns11 + `" Id="shared">` + enc(mustSPKI(t, &key.PublicKey)) + `</k:DEREncodedKeyValue>`

	certificate := cert(t, key)
	for _, test := range []struct {
		name  string
		uri   string
		typ   string
		local string
		input []byte
		chain []reference.Transform
	}{
		{"base64-XML", uriUrnKey, ns11 + "DEREncodedKeyValue", "", []byte(enc([]byte(keyXML))), []reference.Transform{{Algorithm: reference.Base64}}},
		{"two-base64-certificate", uriUrnKey, keyinfo.RawX509Certificate, "", []byte(enc([]byte(enc(certificate)))), []reference.Transform{{Algorithm: reference.Base64}, {Algorithm: reference.Base64}}},
		{"local-certificate", "#encoded", keyinfo.RawX509Certificate, `<encoded Id="encoded">` + enc(certificate) + `</encoded>`, nil, []reference.Transform{{Algorithm: reference.Base64}}},
		{"exclusive-prefix-list", uriUrnKey, ns11 + "DEREncodedKeyValue", "", []byte(keyXML), []reference.Transform{{Algorithm: c14n.Exclusive, InclusivePrefixes: []string{"k", "#default"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			info, err := keyinfo.Build(t.Context(), keyinfo.Template{RetrievalMethods: []keyinfo.RetrievalMethod{{URI: test.uri, Type: test.typ, Transforms: test.chain}}})
			if err != nil {
				t.Fatal(err)
			}

			doc := parseXML(t, `<root>`+asXML(t, info)+test.local+`</root>`)
			calls := 0
			options := retrievalOptions(test.chain)
			options.AdditionalIDRules = []reference.IDAttributeRule{{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{{Local: "encoded"}}}}
			options.External = &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				calls++
				return io.NopCloser(bytes.NewReader(test.input)), nil
			})}

			result, err := keyinfo.Parse(t.Context(), doc, doc.Root().Children()[0], options)
			if err != nil || len(result.Candidates()) != 1 || !bytes.Equal(result.Candidates()[0].SPKI(), mustSPKI(t, &key.PublicKey)) {
				t.Fatal(result, err)
			}

			wantURI := ""
			if test.uri == uriUrnKey {
				wantURI = uriUrnKey
			}

			if result.Candidates()[0].ResourceURI() != wantURI || calls != len(result.ExternalURIs()) {
				t.Fatal("resource provenance", result.ExternalURIs(), calls)
			}

			if test.typ == keyinfo.RawX509Certificate && !bytes.Equal(result.Candidates()[0].CertificateDER(), certificate) {
				t.Fatal("certificate bytes changed")
			}
		})
	}

	for _, algorithm := range []string{c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments, c14n.Exclusive, c14n.ExclusiveWithComments} {
		t.Run(algorithm, func(t *testing.T) {
			doc := parseXML(t, `<root>`+wrap(`<ds:RetrievalMethod URI="#shared" Type="`+ns11+`DEREncodedKeyValue"><ds:Transforms><ds:Transform Algorithm="`+algorithm+`"/></ds:Transforms></ds:RetrievalMethod>`)+keyXML+`</root>`)
			options := retrievalOptions(nil)

			result, err := keyinfo.Parse(t.Context(), doc, doc.Root().Children()[0], options)
			if err != nil || len(result.Candidates()) != 1 || result.Candidates()[0].Source().Node().Document() == doc {
				t.Fatal("canonical result was not parsed as a new bounded snapshot", err)
			}
		})
	}

	t.Run("enveloped-containing-signature", func(t *testing.T) {
		info := wrap(`<ds:RetrievalMethod URI="#shared" Type="` + ns11 + `DEREncodedKeyValue"><ds:Transforms><ds:Transform Algorithm="` + reference.EnvelopedSignature + `"/><ds:Transform Algorithm="` + c14n.Exclusive + `"/></ds:Transforms></ds:RetrievalMethod>`)
		doc := parseXML(t, `<root><ds:Signature xmlns:ds="`+ns+`">`+info+`</ds:Signature>`+keyXML+`</root>`)

		result, err := keyinfo.Parse(t.Context(), doc, doc.Root().Children()[0].Children()[0], retrievalOptions(nil))
		if err != nil || len(result.Candidates()) != 1 || !bytes.Equal(result.Candidates()[0].SPKI(), mustSPKI(t, &key.PublicKey)) {
			t.Fatal("containing signature context was lost", err)
		}
	})
}

func retrievalOptions(programs []reference.Transform) keyinfo.Options {
	processing := reference.DefaultOptions()

	for _, program := range programs {
		if reference.IsExtension(program.Algorithm) {
			processing.AllowedTransforms = append(processing.AllowedTransforms, program.Algorithm)
		}
	}

	return keyinfo.Options{RetrievalProcessing: &processing}
}

func TestRetrievalApprovedPrograms(t *testing.T) {
	key := ec(t, elliptic.P256())

	target := `<ds:KeyInfo xmlns:ds="` + ns + `" xmlns:dsig11="` + ns11 + `" Id="shared"><dsig11:DEREncodedKeyValue>` + enc(mustSPKI(t, &key.PublicKey)) + `</dsig11:DEREncodedKeyValue></ds:KeyInfo>`
	for _, test := range []struct {
		name    string
		program reference.Transform
	}{
		{"XPath", reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: `ancestor-or-self::dsig11:DEREncodedKeyValue`, Namespaces: map[string]string{"ds": ns, prefixDSig11: ns11}}}}},
		{"Filter2", reference.Transform{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{{Expression: `//dsig11:DEREncodedKeyValue`, Filter: "intersect", Namespaces: map[string]string{"ds": ns, prefixDSig11: ns11, "xf": reference.XPathFilter2}}}}},
		{"here", reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: `count(here()/ancestor::ds:RetrievalMethod)=1 and ancestor-or-self::dsig11:DEREncodedKeyValue`, Namespaces: map[string]string{"ds": ns, prefixDSig11: ns11}}}}},
		{"XSLT", reference.Transform{Algorithm: reference.XSLT, Stylesheet: []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ds="` + ns + `" xmlns:dsig11="` + ns11 + `" version="1.0"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:copy-of select="//dsig11:DEREncodedKeyValue"/></xsl:template></xsl:stylesheet>`)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{test.program}})
			if err != nil {
				t.Fatal(err)
			}

			info, err := keyinfo.Build(t.Context(), keyinfo.Template{RetrievalMethods: []keyinfo.RetrievalMethod{{URI: "#shared", Type: ns11 + "DEREncodedKeyValue", Transforms: []reference.Transform{test.program, {Algorithm: c14n.Exclusive}}}}})
			if err != nil {
				t.Fatal(err)
			}

			doc := parseXML(t, `<root>`+asXML(t, info)+target+`</root>`)
			options := retrievalOptions([]reference.Transform{test.program})
			options.RetrievalProcessing.Extension = engine

			result, err := keyinfo.Parse(t.Context(), doc, doc.Root().Children()[0], options)
			if err != nil || len(result.Candidates()) != 1 || !bytes.Equal(result.Candidates()[0].SPKI(), mustSPKI(t, &key.PublicKey)) {
				t.Fatal(result, err)
			}

			options.RetrievalProcessing.Extension = nil
			if result, err := keyinfo.Parse(t.Context(), doc, doc.Root().Children()[0], options); result != nil || !errors.Is(err, keyinfo.ErrPolicy) {
				t.Fatal("program ran without approval", err)
			}
		})
	}
}

func TestRetrievalTransformPreflight(t *testing.T) {
	const (
		start = `<ds:RetrievalMethod URI="urn:key"><ds:Transforms>`
		end   = `</ds:Transforms></ds:RetrievalMethod>`
	)

	for _, test := range []struct {
		name string
		body string
		want error
	}{
		{"unknown", `<ds:Transform Algorithm="urn:unknown"/>`, keyinfo.ErrUnsupported},
		{"no-extension", `<ds:Transform Algorithm="` + reference.XPath + `"><ds:XPath>true()</ds:XPath></ds:Transform>`, keyinfo.ErrPolicy},
		{"foreign-base64-parameter", `<ds:Transform Algorithm="` + reference.Base64 + `"><ds:XPath>true()</ds:XPath></ds:Transform>`, keyinfo.ErrInput},
		{"inclusive-on-C14N10", `<ds:Transform Algorithm="` + c14n.Canonical10 + `"><ec:InclusiveNamespaces xmlns:ec="` + c14n.Exclusive + `" PrefixList="ds"/></ds:Transform>`, keyinfo.ErrInput},
		{"missing-prefix-list", `<ds:Transform Algorithm="` + c14n.Exclusive + `"><ec:InclusiveNamespaces xmlns:ec="` + c14n.Exclusive + `"/></ds:Transform>`, keyinfo.ErrInput},
		{"empty-transforms", "", keyinfo.ErrInput},
		{"no-containing-signature", `<ds:Transform Algorithm="` + reference.EnvelopedSignature + `"/>`, keyinfo.ErrInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			options := retrievalOptions(nil)
			options.RetrievalProcessing.AllowedTransforms = append(options.RetrievalProcessing.AllowedTransforms, reference.XPath)
			options.External = &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				calls++
				return nil, errors.New("unexpected read")
			})}
			// A malformed later sibling is rejected before the first link is read.
			requireErr(t, wrap(`<ds:RetrievalMethod URI="urn:key"/>`+start+test.body+end), options, test.want)

			if calls != 0 {
				t.Fatal("read before complete preflight", calls)
			}
		})
	}

	requireErr(t, wrap(start+`<ds:Transform Algorithm="`+c14n.Exclusive+`"/>`+end), keyinfo.Options{}, keyinfo.ErrUnsupported)
}

func TestRetrievalTransformGraphAndBudgets(t *testing.T) {
	key := ec(t, elliptic.P256())
	target := `<k:DEREncodedKeyValue xmlns:k="` + ns11 + `">` + enc(mustSPKI(t, &key.PublicKey)) + `</k:DEREncodedKeyValue>`

	link := `<ds:RetrievalMethod URI="urn:key"><ds:Transforms><ds:Transform Algorithm="` + c14n.Exclusive + `"/></ds:Transforms></ds:RetrievalMethod>`
	for _, test := range []struct {
		name   string
		xml    string
		input  string
		limits keyinfo.Limits
		want   error
	}{
		{"cycle", wrap(link), wrap(link), keyinfo.Limits{}, keyinfo.ErrCycle},
		{"total-output", wrap(link + link), target, keyinfo.Limits{MaxTransformBytes: len(target) + 16}, keyinfo.ErrLimit},
		{"node-budget", wrap(link), target, keyinfo.Limits{MaxTransformNodes: 4}, keyinfo.ErrLimit},
		{"wrong-result-type", wrap(strings.Replace(link, `URI="urn:key"`, `URI="urn:key" Type="`+ns+`X509Data"`, 1)), target, keyinfo.Limits{}, keyinfo.ErrInput},
		{"multiple-elements", wrap(link), target + target, keyinfo.Limits{}, keyinfo.ErrInput},
		{"empty-result", wrap(link), "", keyinfo.Limits{}, keyinfo.ErrInput},
		{"external-bytes", wrap(link), target, keyinfo.Limits{MaxExternalBytes: len(target) - 1}, keyinfo.ErrLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			options := retrievalOptions(nil)
			options.Limits = test.limits
			options.External = &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				calls++
				return io.NopCloser(strings.NewReader(test.input)), nil
			})}
			requireErr(t, test.xml, options, test.want)

			if calls != 1 {
				t.Fatal("resource was not immutable within one parse", calls)
			}
		})
	}
}

func TestRetrievalResourceSnapshot(t *testing.T) {
	key := ec(t, elliptic.P256())
	remote := wrap(derXML(t, &key.PublicKey))
	link := `<ds:RetrievalMethod URI="urn:key"><ds:Transforms><ds:Transform Algorithm="` + c14n.Exclusive + `"/></ds:Transforms></ds:RetrievalMethod>`
	doc := parseXML(t, wrap(link+`<k:KeyInfoReference URI="urn:key"/>`+link))
	calls := 0
	options := retrievalOptions(nil)
	options.Limits.MaxExternalResources = 1
	options.External = &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		// A resource callback cannot change the already frozen policy.
		options.RetrievalProcessing.AllowedTransforms[0] = "urn:changed"
		options.RetrievalProcessing.MaxOutputBytes = 1
		options.External.AllowedURIs[0] = "urn:changed"

		return io.NopCloser(strings.NewReader(remote)), nil
	})}

	result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), options)
	if err != nil || len(result.Candidates()) != 3 || calls != 1 || len(result.ExternalURIs()) != 1 {
		t.Fatal(result, err, calls)
	}

	for _, candidate := range result.Candidates() {
		if candidate.ResourceURI() != uriUrnKey || !bytes.Equal(candidate.SPKI(), mustSPKI(t, &key.PublicKey)) {
			t.Fatal("resource interpretation changed")
		}
	}
}

func TestRetrievalInputLimitPrecedesBuffering(t *testing.T) {
	reads := 0
	source := &reader{read: func(dst []byte) (int, error) {
		for i := range dst {
			dst[i] = 'A'
		}

		reads += len(dst)

		return len(dst), nil
	}}
	options := retrievalOptions(nil)
	options.RetrievalProcessing.MaxInputBytes = 32
	options.External = &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) { return source, nil })}
	requireErr(t, wrap(`<ds:RetrievalMethod URI="urn:key" Type="`+keyinfo.RawX509Certificate+`"/>`), options, keyinfo.ErrLimit)

	if reads != 33 || !source.closed {
		t.Fatal("input budget failed to bound reading", reads, source.closed)
	}
}

func TestRetrievalProcessingPolicy(t *testing.T) {
	doc := parseXML(t, wrap(`<ds:KeyName>untrusted</ds:KeyName>`))
	for _, processing := range []reference.Options{
		{MaxInputBytes: -1},
		{XMLLimits: document.Limits{MaxBytes: 1}},
		{Signature: doc.Root()},
		{IDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "id"}}}},
	} {
		result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{RetrievalProcessing: &processing})
		if result != nil || !errors.Is(err, keyinfo.ErrPolicy) {
			t.Fatal("invalid processing policy accepted", err)
		}
	}
}

func TestRetrievalRejectsUnapprovedOrEmptyPrograms(t *testing.T) {
	program := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: "false()", Namespaces: map[string]string{"ds": ns, "k": ns11}}}}

	engine, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{program}})
	if err != nil {
		t.Fatal(err)
	}

	link := `<ds:RetrievalMethod URI="urn:key"><ds:Transforms><ds:Transform Algorithm="` + reference.XPath + `"><ds:XPath>false()</ds:XPath></ds:Transform></ds:Transforms></ds:RetrievalMethod>`
	options := retrievalOptions([]reference.Transform{program})
	options.RetrievalProcessing.Extension = engine
	calls := 0
	options.External = &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return io.NopCloser(strings.NewReader(wrap(`<ds:KeyName>untrusted</ds:KeyName>`))), nil
	})}
	requireErr(t, wrap(strings.Replace(link, "false()", "true()", 1)), options, keyinfo.ErrPolicy)

	if calls != 0 {
		t.Fatal("unapproved program triggered I/O")
	}

	requireErr(t, wrap(link), options, keyinfo.ErrInput)

	if calls != 1 {
		t.Fatal(calls)
	}
}

func TestRetrievalTransformReaderFailures(t *testing.T) {
	key := ec(t, elliptic.P256())

	certificate := cert(t, key)

	const stepCancel = "cancel"
	for _, stage := range []string{"final-read", "close", stepCancel} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			failure := errors.New("resource failure")
			input := strings.NewReader(enc(certificate))
			source := &reader{read: func(dst []byte) (int, error) {
				n, err := input.Read(dst)
				if input.Len() == 0 {
					if stage == "final-read" {
						err = failure
					}

					if stage == stepCancel {
						cancel()
					}
				}

				return n, err
			}}

			var stream io.ReadCloser = source
			if stage == "close" {
				stream = &retrievalCloseFailure{source: source, err: failure}
			}

			doc := parseXML(t, wrap(`<ds:RetrievalMethod URI="urn:key" Type="`+keyinfo.RawX509Certificate+`"><ds:Transforms><ds:Transform Algorithm="`+reference.Base64+`"/></ds:Transforms></ds:RetrievalMethod>`))
			options := retrievalOptions(nil)
			options.External = &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) { return stream, nil })}
			result, err := keyinfo.Parse(ctx, doc, doc.Root(), options)

			want := failure
			if stage == stepCancel {
				want = context.Canceled
			}

			if result != nil || !errors.Is(err, want) || !source.closed {
				t.Fatal("failed stream produced a candidate", err, source.closed)
			}
		})
	}
}

type retrievalCloseFailure struct {
	source *reader
	err    error
}

func (r *retrievalCloseFailure) Read(dst []byte) (int, error) { return r.source.Read(dst) }
func (r *retrievalCloseFailure) Close() error                 { _ = r.source.Close(); return r.err }

func distinguishedAVA(oid asn1.ObjectIdentifier, tag int, text string) []byte {
	return der.Seq(der.OID(oid), der.Wrap(0, tag, false, []byte(text)))
}

func distinguishedCN(tag int, text string) []byte {
	return der.Seq(der.Set(distinguishedAVA(asn1.ObjectIdentifier{2, 5, 4, 3}, tag, text)))
}

func TestDistinguishedNameStringPreparation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		a     string
		b     string
		equal bool
	}{
		{"case and insignificant spaces", " Alice  SMITH ", "alice smith", true},
		{"sharp s fold", "Straße", "STRASSE", true},
		{"compatibility", "ＡK", "ak", true},
		{"normalization", "A\u0308", "ä", true},
		{"mapped nothing", "a\u00ad\u1806\u034f\u180b\ufe00\ufffc\x00\u200b\u2060\U000e0001b", "ab", true},
		{"mapped spaces", "a\t\u0085\u00a0\u1680\u2028b", "a b", true},
		{"direction controls removed", "a\u200fb", "AB", true},
		{"bidi is ignored", "aא", "Aא", true},
		{"protected space before mark", "a \u0308  b", " A \u0308 b ", true},
		{"protected space is significant", "a \u0308 b", "ä b", false},
		{"all spaces", " \t\u00a0 ", "", true},
		{"distinct value", "alice", "bob", false},
		{"Unicode32 Georgian still assigned", "\u10a0", "\u10a0", true},
		{"Unicode32 correction", "\uf951", "\u964b", true},
		{"correction32 old value differs", "\uf951", "\u96fb", false},
		{"pre40 correction1", "\U0002f868", "\U0002136a", true},
		{"pre40 correction2", "\U0002f874", "\u5f33", true},
		{"pre40 correction3", "\U0002f91f", "\u43ab", true},
		{"pre40 correction4", "\U0002f95f", "\u7aae", true},
		{"pre40 correction5", "\U0002f9bf", "\u4d57", true},
		{"current correction not substituted", "\U0002f868", "\u36fc", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := distinguishedCN(asn1.TagUTF8String, tc.a), distinguishedCN(asn1.TagUTF8String, tc.b)
			beforeA, beforeB := bytes.Clone(a), bytes.Clone(b)
			got, err := x509name.Equal(t.Context(), a, b)
			if err != nil || got != tc.equal {
				t.Fatal(got, tc.equal, err)
			}
			if !bytes.Equal(a, beforeA) || !bytes.Equal(b, beforeB) {
				t.Fatal("DER changed")
			}
		})
	}
	t.Run("Printable and UTF8 match", func(t *testing.T) {
		got, err := x509name.Equal(t.Context(), distinguishedCN(asn1.TagPrintableString, " ALICE "), distinguishedCN(asn1.TagUTF8String, "alice"))
		if err != nil || !got {
			t.Fatal(got, err)
		}
	})
	// RFC4518 section2.6.1 publishes this precise stored-value preparation.
	k, err := x509name.Key(t.Context(), distinguishedCN(asn1.TagUTF8String, "foo bar  "))
	if err != nil || !strings.HasSuffix(k, " foo  bar ") {
		t.Fatal("published stored-space example", k, err)
	}
}

func TestDistinguishedNameStructureAndFailure(t *testing.T) {
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	org := asn1.ObjectIdentifier{2, 5, 4, 10}
	a := distinguishedAVA(cn, asn1.TagUTF8String, "alice")
	b := distinguishedAVA(org, asn1.TagPrintableString, "EXAMPLE")
	first := der.Seq(der.Set(a, b))
	other := der.Seq(der.Set(distinguishedAVA(org, asn1.TagUTF8String, "example"), distinguishedAVA(cn, asn1.TagPrintableString, "ALICE")))
	if got, err := x509name.Equal(t.Context(), first, other); err != nil || !got {
		t.Fatal("unordered AVAs", got, err)
	}
	for _, pair := range [][2][]byte{{der.Seq(der.Set(a), der.Set(b)), der.Seq(der.Set(b), der.Set(a))}, {der.Seq(der.Set(a)), der.Seq(der.Set(a, a))}, {der.Seq(der.Set(a)), der.Seq(der.Set(b))}} {
		if got, err := x509name.Equal(t.Context(), pair[0], pair[1]); err != nil || got {
			t.Fatal("sequence/cardinality/OID mismatch", got, err)
		}
	}
	dc := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	if got, err := x509name.Equal(t.Context(), der.Seq(der.Set(distinguishedAVA(dc, asn1.TagIA5String, "XN--EXAMPLE"))), der.Seq(der.Set(distinguishedAVA(dc, asn1.TagIA5String, "xn--example")))); err != nil || !got {
		t.Fatal("domainComponent ASCII rule", got, err)
	}
	for _, text := range []string{"\u0221", "\u1e9e", "\ue000", "\U000f0000", "\ufdd0", "\uffff", "\ufffd"} {
		if k, err := x509name.Key(t.Context(), distinguishedCN(asn1.TagUTF8String, text)); k != "" || !errors.Is(err, x509name.ErrInvalid) {
			t.Fatal("prohibited/unassigned stored value", k, err)
		}
	}
	for _, raw := range [][]byte{nil, der.Set(a), der.Seq(der.Set()), der.Seq(der.Set(der.Seq(der.OID(cn)))), append(bytes.Clone(first), 0), distinguishedCN(asn1.TagUTF8String, "\xff"), distinguishedCN(asn1.TagPrintableString, "a@b"), distinguishedCN(asn1.TagPrintableString, "a_b")} {
		if k, err := x509name.Key(t.Context(), raw); k != "" || !errors.Is(err, x509name.ErrInvalid) {
			t.Fatal("malformed DER/name", k, err)
		}
	}
	if k, err := x509name.Key(t.Context(), distinguishedCN(asn1.TagBMPString, "\x00A")); k != "" || !errors.Is(err, x509name.ErrUnsupported) {
		t.Fatal("optional encoding not explicit", k, err)
	}
	if got, err := x509name.Equal(t.Context(), der.Seq(), der.Seq()); err != nil || !got {
		t.Fatal("empty RDNSequence", got, err)
	}
}

func TestDistinguishedNameBoundsAndCache(t *testing.T) {
	t.Parallel()
	raw := distinguishedCN(asn1.TagUTF8String, "Cached Name")
	before := bytes.Clone(raw)
	want, err := x509name.Key(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := x509name.Key(canceled, raw); got != "" || !errors.Is(err, context.Canceled) {
		t.Fatal("cache bypassed cancellation", got, err)
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("cached input changed")
	}
	for i := range 200 {
		n := distinguishedCN(asn1.TagUTF8String, "cache "+strconv.Itoa(i))
		if _, err := x509name.Key(t.Context(), n); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := x509name.Key(t.Context(), raw); err != nil || got != want {
		t.Fatal("bounded eviction changed value", got, err)
	}
	for _, raw := range [][]byte{make([]byte, (64<<10)+1), der.Seq(bytes.Repeat(der.Set(distinguishedAVA(asn1.ObjectIdentifier{2, 5, 4, 3}, asn1.TagUTF8String, "a")), 257)), der.Seq(der.Set(bytes.Repeat(distinguishedAVA(asn1.ObjectIdentifier{2, 5, 4, 3}, asn1.TagUTF8String, "a"), 1025)))} {
		if k, err := x509name.Key(t.Context(), raw); k != "" || !errors.Is(err, x509name.ErrLimit) {
			t.Fatal("name budget", k, err)
		}
	}
	for i := range 16 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			for range 20 {
				got, err := x509name.Equal(t.Context(), raw, distinguishedCN(asn1.TagPrintableString, "cached name"))
				if err != nil || !got {
					t.Fatal(got, err)
				}
			}
		})
	}
}

func TestDistinguishedNameExactFallback(t *testing.T) {
	t61 := distinguishedCN(asn1.TagT61String, "Alice")
	if got, err := x509name.Equal(t.Context(), t61, t61); got || !errors.Is(err, x509name.ErrUnsupported) {
		t.Fatal("strict optional encoding", got, err)
	}
	if got, err := x509name.EqualOrExact(t.Context(), t61, t61); err != nil || !got {
		t.Fatal("exact optional encoding", got, err)
	}
	if got, err := x509name.EqualOrExact(t.Context(), t61, distinguishedCN(asn1.TagT61String, "alice")); got || !errors.Is(err, x509name.ErrUnsupported) {
		t.Fatal("optional semantic claim", got, err)
	}
	badSupported := der.Seq(der.Set(distinguishedAVA(asn1.ObjectIdentifier{2, 5, 4, 3}, asn1.TagT61String, "a"), distinguishedAVA(asn1.ObjectIdentifier{2, 5, 4, 3}, asn1.TagUTF8String, "\ue000")))
	badStructure := der.Seq(der.Set(distinguishedAVA(asn1.ObjectIdentifier{2, 5, 4, 3}, asn1.TagT61String, "a")), der.Set())
	for _, bad := range [][]byte{badSupported, badStructure, append(bytes.Clone(t61), 0)} {
		if got, err := x509name.EqualOrExact(t.Context(), bad, bad); got || !errors.Is(err, x509name.ErrInvalid) {
			t.Fatal("unsupported masked invalid remainder", got, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := x509name.EqualOrExact(ctx, t61, t61); got || !errors.Is(err, context.Canceled) {
		t.Fatal("fallback ignored cancellation", got, err)
	}
}

func TestCRLVersionsAndOriginalDER(t *testing.T) {
	chain := testcert.New(t)
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			raw := testcert.CRL(t, chain)
			if version == "v1" {
				raw = testcert.CRLV1(t, chain)
			}
			expected := bytes.Clone(raw)
			built, err := keyinfo.Build(t.Context(), keyinfo.Template{X509Data: []keyinfo.X509Data{{CRLs: [][]byte{raw}}}})
			if err != nil {
				t.Fatal("valid CRL builder rejected", err)
			}
			parsed, err := keyinfo.Parse(t.Context(), built, built.Root(), keyinfo.Options{})
			if err != nil || len(parsed.Candidates()) != 0 || len(parsed.X509Groups()) != 1 {
				t.Fatal("CRL syntax became a key/trust decision", err)
			}
			clear(raw)
			group := parsed.X509Groups()[0]
			values := group.CRLsDER()
			if len(values) != 1 || !bytes.Equal(values[0], expected) {
				t.Fatal("original CRL DER was replaced")
			}
			clear(values[0])
			if !bytes.Equal(group.CRLsDER()[0], expected) {
				t.Fatal("CRL result borrowed caller state")
			}
			if result, err := keyinfo.Parse(t.Context(), built, built.Root(), keyinfo.Options{Limits: keyinfo.Limits{MaxBlobBytes: len(expected) - 1}}); result != nil || !errors.Is(err, keyinfo.ErrLimit) {
				t.Fatal("existing CRL byte cap weakened", err)
			}
			bad := append(bytes.Clone(expected), 0)
			if result, err := keyinfo.Build(t.Context(), keyinfo.Template{X509Data: []keyinfo.X509Data{{CRLs: [][]byte{bad}}}}); result != nil || !errors.Is(err, keyinfo.ErrInput) {
				t.Fatal("trailing CRL data accepted", err)
			}
		})
	}
}

func TestCRLConfiguredBlobBudget(t *testing.T) {
	chain := testcert.New(t)
	raw, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: testcert.Now(), NextUpdate: testcert.Now().Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: bytes.Repeat([]byte{42}, (1<<20)+(1<<18))}}}, chain.Root, chain.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	doc := parseXML(t, wrap(`<ds:X509Data><ds:X509CRL>`+enc(raw)+`</ds:X509CRL></ds:X509Data>`))
	if result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{}); result != nil || !errors.Is(err, keyinfo.ErrLimit) {
		t.Fatal("default blob cap changed", err)
	}
	result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{Limits: keyinfo.Limits{MaxBlobBytes: 2 << 20}})
	if err != nil || result == nil || !bytes.Equal(result.X509Groups()[0].CRLsDER()[0], raw) {
		t.Fatal("configured larger CRL cap narrowed", err)
	}
}
