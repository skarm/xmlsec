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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	uriExternalManifest  = "urn:manifest"
	uriLeafManifest      = "urn:leaf-manifest"
	uriSignatureBase     = "https://example.test/messages/signature.xml"
	xmlMessage           = `<message/>`
	uriRelativeResource  = "https://example.test/messages/g"
	uriInheritedResource = "https://example.test/a/b/x/g"
)

func TestTransformedManifestSnapshots(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(strconv.FormatBool(local), func(t *testing.T) { testTransformedManifestSnapshot(t, local) })
	}
}

func testTransformedManifestSnapshot(t *testing.T, local bool) {
	t.Helper()
	resources := externalManifestResources(t)
	encoded := base64.StdEncoding.EncodeToString(resources[uriExternalManifest])
	options, calls, closed := externalManifestOptions(resources)
	options.Manifests.AllowTransformed = true
	uri := uriExternalManifest

	var (
		input  *document.Document
		parent document.Element
	)

	if local {
		uri = "#encoded"
		input = graphDoc(t, `<message><blob ID="encoded">`+encoded+`</blob></message>`)
		parent = input.Root()
	} else {
		resources[uriExternalManifest] = []byte(encoded)
	}

	options.ExpectedURIs = []string{uri}

	draft, selected, err := xmldsig.BuildTemplate(t.Context(), input, parent, xmldsig.SignatureTemplate{
		SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: uri, Type: xmldsig.ManifestType, Transforms: []reference.Transform{{Algorithm: reference.Base64}, {Algorithm: c14n.Exclusive}}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	key := graphKey(t)

	signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: options})
	if err != nil {
		t.Fatal(err)
	}

	clear(calls)

	*closed = 0

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, xmldsig.Signatures(signed)[0], key.Public(), options)
	if err != nil || len(result.Manifests()) != 2 || report.ManifestValidation != xmldsig.Valid || !result.Manifests()[0].Transformed() || !report.Manifests[0].Transformed {
		t.Fatal("derived snapshot graph", report, err)
	}

	root := result.Manifests()[0]
	if root.Target().Name().Local != "Manifest" || result.CoversElement(root.Target()) || result.References()[0].CoversElement(root.Target()) {
		t.Fatal("derived and original coverage were conflated")
	}

	if local && (root.ResourceURI() != "" || result.References()[0].CoversElement(signed.Root().Children()[0])) {
		t.Fatal("decoded XML claimed original-node coverage")
	}

	if len(root.References()) != 3 || !root.References()[1].CoversElement(root.References()[1].Target()) {
		t.Fatal("derived same-document ID scope lost")
	}

	if calls[uriLeafManifest] != 1 || calls[uriUrnAttachment] != 1 || *closed != len(calls) {
		t.Fatal("graph resources", calls, *closed)
	}

	var replay bytes.Buffer
	if _, err := result.References()[0].WriteDigestInput(t.Context(), &replay); err != nil || replay.Len() == 0 {
		t.Fatal("derived reference replay", err)
	}
	// Child content mutation does not alter the incoming Manifest digest.
	resources[uriUrnAttachment] = []byte("modified nested payload")

	if result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, xmldsig.Signatures(signed)[0], key.Public(), options); result != nil || !errors.Is(err, xmldsig.ErrDigest) || report.References[0].Status != xmldsig.Valid || report.ManifestValidation == xmldsig.Valid {
		t.Fatal("nested mutation", report, err)
	}
}

func TestTransformedManifestProgramsAndIdentity(t *testing.T) {
	payload := []byte("program-selected payload")
	manifest := `<ds:Manifest xmlns:ds="` + xmldsig.Namespace + `" Id="selected">` + externalManifestReference(uriUrnAttachment, "", payload) + `</ds:Manifest>`
	xpath := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: `ancestor-or-self::ds:Manifest`, Namespaces: map[string]string{"ds": xmldsig.Namespace}}}}
	filter := reference.Transform{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{{Expression: `//ds:Manifest`, Filter: "intersect", Namespaces: map[string]string{"ds": xmldsig.Namespace, "xf": reference.XPathFilter2}}}}

	xslt := reference.Transform{Algorithm: reference.XSLT, Stylesheet: []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ds="` + xmldsig.Namespace + `" version="1.0"><xsl:template match="/"><xsl:copy-of select="//ds:Manifest"/></xsl:template></xsl:stylesheet>`)}
	for _, program := range []reference.Transform{xpath, filter, xslt} {
		t.Run(program.Algorithm, func(t *testing.T) {
			resources := map[string][]byte{uriExternalManifest: []byte(`<wrapper>` + manifest + `</wrapper>`), uriUrnAttachment: payload}
			options, _, _ := externalManifestOptions(resources)
			options.Manifests.AllowTransformed = true
			processing := reference.DefaultOptions()
			processing.AllowedTransforms = append(processing.AllowedTransforms, program.Algorithm)

			engine, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{program}})
			if err != nil {
				t.Fatal(err)
			}

			processing.Extension = engine
			options.Processing = processing
			refs := []xmldsig.ReferenceTemplate{{URI: uriExternalManifest, Type: xmldsig.ManifestType, Transforms: []reference.Transform{program, {Algorithm: c14n.Exclusive}}}}

			draft, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: refs})
			if err != nil {
				t.Fatal(err)
			}

			key := graphKey(t)

			signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: options})
			if err != nil {
				t.Fatal(err)
			}

			result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), options)
			if err != nil || len(result.Manifests()) != 1 || !result.Manifests()[0].Transformed() || report.Manifests[0].Status != xmldsig.Valid {
				t.Fatal(report, err)
			}
			// Type is applied to the authenticated transform result. Changing
			// program parameters is a SignedInfo mutation, not another lookup.
			raw := coreXML(t, signed)

			bad := graphDoc(t, strings.Replace(raw, c14n.Exclusive, c14n.Canonical10, 1))
			if result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), bad, bad.Root(), key.Public(), options); result != nil || err == nil {
				t.Fatal("changed transform context accepted")
			}
		})
	}
}

func TestTransformedManifestAuthenticationAndLimits(t *testing.T) {
	resources := externalManifestResources(t)
	resources[uriExternalManifest] = []byte(base64.StdEncoding.EncodeToString(resources[uriExternalManifest]))
	options, calls, _ := externalManifestOptions(resources)
	options.Manifests.AllowTransformed = true

	draft, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: uriExternalManifest, Type: xmldsig.ManifestType, Transforms: []reference.Transform{{Algorithm: reference.Base64}}}}})
	if err != nil {
		t.Fatal(err)
	}

	key := &countSigner{Signer: graphKey(t)}

	signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: options})
	if err != nil {
		t.Fatal(err)
	}

	for _, policy := range []xmldsig.ManifestPolicy{
		{Mode: xmldsig.ManifestRecursive, AllowExternal: true},
		{Mode: xmldsig.ManifestRecursive, AllowExternal: true, AllowTransformed: true, MaxManifests: 1},
		{Mode: xmldsig.ManifestRecursive, AllowExternal: true, AllowTransformed: true, MaxReferences: 1},
		{Mode: xmldsig.ManifestRecursive, AllowExternal: true, AllowTransformed: true, MaxDepth: 1},
	} {
		opt := options

		opt.Manifests = policy
		if result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), opt); result != nil || err == nil {
			t.Fatal("transformed policy/graph budget ignored")
		}
	}

	for _, processing := range []reference.Options{
		{MaxInputBytes: 16}, {MaxOutputBytes: 16}, {MaxProducedBytes: 16}, {MaxNodeVisits: 4},
	} {
		opt := options

		opt.Processing = processing
		if result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), opt); result != nil || (!errors.Is(err, xmldsig.ErrPolicy) && !errors.Is(err, document.ErrLimit) && !errors.Is(err, reference.ErrLimit)) {
			t.Fatal("derived byte/node budget ignored", err)
		}

		key.calls = 0
		if result, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: opt}); result != nil || (!errors.Is(err, xmldsig.ErrPolicy) && !errors.Is(err, document.ErrLimit) && !errors.Is(err, reference.ErrLimit)) || key.calls != 0 {
			t.Fatal("private signer preceded budget checks", err, key.calls)
		}
	}

	// Failed parent authentication must not discover or read its children.
	clear(calls)

	resources[uriExternalManifest] = []byte(base64.StdEncoding.EncodeToString([]byte(`<not-a-manifest/>`)))

	if result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), options); result != nil || !errors.Is(err, xmldsig.ErrDigest) || len(calls) != 1 || len(report.Manifests) != 0 {
		t.Fatal("discovery before parent digest", report, err, calls)
	}
	// A newly signed malformed result has no private-key side effect.
	key.calls = 0
	if result, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: options}); result != nil || err == nil || key.calls != 0 {
		t.Fatal("private signer preceded derived graph checks", err, key.calls)
	}
}

func TestTransformedManifestResultIdentity(t *testing.T) {
	const secondID = "second"

	first, second := []byte("first result"), []byte("second result")
	resources := map[string][]byte{
		"urn:first-result": first, "urn:second-result": second,
		uriExternalManifest: []byte(`<wrapper><ds:Manifest xmlns:ds="` + xmldsig.Namespace + `" Id="first">` + externalManifestReference("urn:first-result", "", first) + `</ds:Manifest><ds:Manifest xmlns:ds="` + xmldsig.Namespace + `" Id="second">` + externalManifestReference("urn:second-result", "", second) + `</ds:Manifest></wrapper>`),
	}
	options, _, _ := externalManifestOptions(resources)
	options.Manifests.AllowTransformed = true
	options.ExpectedURIs = []string{uriExternalManifest, uriExternalManifest}
	options.External.AllowedURIs = []string{uriExternalManifest, "urn:first-result", "urn:second-result"}
	programs := make([]reference.Transform, 0, 2)
	refs := make([]xmldsig.ReferenceTemplate, 0, 2)

	for _, id := range []string{"first", secondID} {
		program := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: `ancestor-or-self::ds:Manifest[@Id='` + id + `']`, Namespaces: map[string]string{"ds": xmldsig.Namespace}}}}
		programs = append(programs, program)
		refs = append(refs, xmldsig.ReferenceTemplate{URI: uriExternalManifest, Type: xmldsig.ManifestType, Transforms: []reference.Transform{program, {Algorithm: c14n.Exclusive}}})
	}

	engine, err := transform.NewEngine(transform.Config{AllowedPrograms: programs})
	if err != nil {
		t.Fatal(err)
	}

	options.Processing = reference.DefaultOptions()
	options.Processing.AllowedTransforms = append(options.Processing.AllowedTransforms, reference.XPath)
	options.Processing.Extension = engine

	draft, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: refs})
	if err != nil {
		t.Fatal(err)
	}

	key := graphKey(t)

	signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: options})
	if err != nil {
		t.Fatal(err)
	}

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), options)
	if err != nil || len(result.Manifests()) != 2 || report.Manifests[0].ID != "first" || report.Manifests[1].ID != secondID {
		t.Fatal("same URI merged different authenticated outputs", report, err)
	}

	resources["urn:second-result"] = []byte("modified second result")

	if result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), options); result != nil || !errors.Is(err, xmldsig.ErrDigest) || report.References[0].Status != xmldsig.Valid || report.References[1].Status != xmldsig.Valid || report.Manifests[1].References[0].Status != xmldsig.Invalid {
		t.Fatal("second transform result was not traversed", report, err)
	}
}

func TestExternalManifestURIContext(t *testing.T) {
	const (
		outer      = "https://example.test/packages/outer.xml#root"
		wireURI    = "outer.xml#root"
		inner      = "https://example.test/packages/child.xml#leaf"
		payloadURI = "https://example.test/payload.bin?version=1#data"
	)

	payload := []byte("identified payload subresource")
	leaf := []byte(`<ds:Manifest xmlns:ds="` + xmldsig.Namespace + `" Id="leaf">` + externalManifestReference("../payload.bin?version=1#data", "", payload) + `</ds:Manifest>`)
	root := []byte(`<ds:Manifest xmlns:ds="` + xmldsig.Namespace + `" Id="root">` + externalManifestReference("child.xml#leaf", xmldsig.ManifestType, leaf) + externalManifestReference("./child.xml#leaf", xmldsig.ManifestType, leaf) + `</ds:Manifest>`)
	resources := map[string][]byte{outer: root, inner: leaf, payloadURI: payload}
	opt, calls, closed := externalManifestOptions(resources)
	opt.External.BaseURI = uriSignatureBase
	opt.External.AllowedURIs = []string{outer, inner, payloadURI}
	opt.ExpectedURIs = []string{wireURI}
	input := graphDoc(t, `<message xml:base="../packages/"/>`)

	draft, selected, err := xmldsig.BuildTemplate(t.Context(), input, input.Root(), xmldsig.SignatureTemplate{
		SignatureMethod: xmldsig.ECDSASHA256,
		References:      []xmldsig.ReferenceTemplate{{URI: wireURI, Type: xmldsig.ManifestType}},
	})
	if err != nil {
		t.Fatal(err)
	}

	key := graphKey(t)

	signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		t.Fatal(err)
	}

	clear(calls)

	*closed = 0

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, xmldsig.Signatures(signed)[0], key.Public(), opt)
	if err != nil || result == nil || report.ManifestValidation != xmldsig.Valid || len(result.Manifests()) != 2 {
		t.Fatal(result, report, err)
	}

	if calls[outer] != 1 || calls[inner] != 1 || calls[payloadURI] != 1 || *closed != 3 || len(calls) != 3 {
		t.Fatal("resolved identities were not reused", calls, *closed)
	}

	if result.References()[0].URI() != wireURI || result.References()[0].ResourceURI() != outer || report.References[0].ResourceURI != outer || result.Manifests()[0].ResourceURI() != outer || result.Manifests()[1].ResourceURI() != inner {
		t.Fatal("signed and resolved URI identities", report)
	}

	refs := result.Manifests()[0].References()
	if len(refs) != 2 || refs[0].URI() == refs[1].URI() || refs[0].ResourceURI() != inner || refs[1].ResourceURI() != inner {
		t.Fatal("shared resolved URI lost original spelling", refs)
	}

	var replay bytes.Buffer
	if _, err := result.Manifests()[1].References()[0].WriteDigestInput(t.Context(), &replay); err != nil || !bytes.Equal(replay.Bytes(), payload) {
		t.Fatal("resolved subresource replay", err)
	}

	// The parent digest authenticates the resolver's identified subresource;
	// changing it must not discover another resource from its altered content.
	resources[outer] = bytes.Replace(root, []byte("child.xml#leaf"), []byte("other.xml#leaf"), 1)

	clear(calls)

	result, report, err = xmldsig.VerifySignatureDetailed(t.Context(), signed, xmldsig.Signatures(signed)[0], key.Public(), opt)
	if !errors.Is(err, xmldsig.ErrDigest) || result != nil || len(calls) != 1 || calls[outer] != 1 || len(report.Manifests) != 0 {
		t.Fatal("nested discovery preceded parent authentication", result, report, err, calls)
	}
}

func TestExternalReferenceBaseURI(t *testing.T) {
	const base = "https://example.test/a/b/c/d;p?q"
	for _, tc := range []struct {
		name, base, xml, uri, resolved string
	}{
		{"literal default", "", `<message xml:base="ignored/"/>`, "g", "g"},
		{"retrieval directory", base, xmlMessage, "g", "https://example.test/a/b/c/g"},
		{"parent segments", base, xmlMessage, "../../g", "https://example.test/a/g"},
		{"query", base, xmlMessage, "?y", "https://example.test/a/b/c/d;p?y"},
		{"authority", base, xmlMessage, "//other.test/g", "https://other.test/g"},
		{"escaped fragment", base, xmlMessage, "g#part%23one", "https://example.test/a/b/c/g#part%23one"},
		{"empty fragment", base, xmlMessage, "g#", "https://example.test/a/b/c/g#"},
		{"inherited base", base, `<message xml:base="../x/"/>`, "g", uriInheritedResource},
		{"empty base inherits", base, `<message xml:base="../x/"><container xml:base=""/></message>`, "g", uriInheritedResource},
		{"fragment base inherits", base, `<message xml:base="../x/"><container xml:base="#unused"/></message>`, "g", uriInheritedResource},
		{"nested override", base, `<message xml:base="../x/"><container xml:base="https://other.test/y/"/></message>`, "g", "https://other.test/y/g"},
		{"absolute spelling", base, `<message xml:base="ignored/"/>`, "https://other.test/a/../g?x=%2f#part", "https://other.test/a/../g?x=%2f#part"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := graphDoc(t, tc.xml)

			parent := input.Root()
			if children := parent.Children(); len(children) != 0 {
				parent = children[0]
			}

			draft, selected, err := xmldsig.BuildTemplate(t.Context(), input, parent, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: tc.uri}}})
			if err != nil {
				t.Fatal(err)
			}

			calls := 0
			external := &xmldsig.ExternalReferences{BaseURI: tc.base, AllowedURIs: []string{tc.resolved}}
			external.Resolver = xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
				calls++

				if uri != tc.resolved {
					t.Fatal("unexpected resolver URI", uri)
				}

				// Mutating the caller's option must not change this operation's
				// self-verification or the URI retained for subsequent replay.
				external.BaseURI = "https://changed.test/"

				return io.NopCloser(strings.NewReader("payload")), ctx.Err()
			})
			key := graphKey(t)

			signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{External: external, ExpectedURIs: []string{tc.uri}}})
			if err != nil || signed == nil || calls != 1 {
				t.Fatal(signed, err, calls)
			}

			external.BaseURI = tc.base

			result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, xmldsig.Signatures(signed)[0], key.Public(), xmldsig.SignatureOptions{External: external})
			if err != nil || result == nil || result.References()[0].URI() != tc.uri || result.References()[0].ResourceURI() != tc.resolved {
				t.Fatal(result, err)
			}

			if _, err := result.References()[0].WriteDigestInput(t.Context(), io.Discard); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExternalManifestResolvedCycle(t *testing.T) {
	const resolved = "https://example.test/messages/manifest.xml#root"

	root := []byte(`<ds:Manifest xmlns:ds="` + xmldsig.Namespace + `" Id="root">` + externalManifestReference("./manifest.xml#root", xmldsig.ManifestType, []byte("unneeded cycle digest")) + `</ds:Manifest>`)
	opt, calls, _ := externalManifestOptions(map[string][]byte{resolved: root})
	opt.External.BaseURI = uriSignatureBase
	opt.External.AllowedURIs = []string{resolved}
	opt.ExpectedURIs = []string{"manifest.xml#root"}
	// Core-only signing authenticates the parent without walking this cycle.
	opt.Manifests = xmldsig.ManifestPolicy{}

	draft, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "manifest.xml#root", Type: xmldsig.ManifestType}}})
	if err != nil {
		t.Fatal(err)
	}

	key := graphKey(t)

	signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		t.Fatal(err)
	}

	clear(calls)

	opt.Manifests = xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, AllowExternal: true}

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), opt)
	if !errors.Is(err, xmldsig.ErrReference) || result != nil || report.References[0].Status != xmldsig.Valid || calls[resolved] != 1 || len(calls) != 1 {
		t.Fatal("resolved cycle was reread or misclassified", result, report, err, calls)
	}
}

func TestExternalManifestFragmentScopes(t *testing.T) {
	const (
		first  = "urn:bundle#first"
		second = "urn:bundle#second"
	)

	resources := make(map[string][]byte)

	for uri, payload := range map[string]string{first: "first payload", second: "second payload"} {
		// The same local ID is valid in independently resolved subresources.
		ref := strings.Replace(externalManifestReference(uriUrnAttachment, "", []byte("shared payload")), `<ds:Reference `, `<ds:Reference Id="local" `, 1)
		fragment := graphDoc(t, `<ds:Manifest xmlns:ds="`+xmldsig.Namespace+`" Id="same">`+ref+`</ds:Manifest>`)

		var canonical bytes.Buffer
		if err := c14n.WriteElement(t.Context(), &canonical, fragment.Root().Children()[0], c14n.Options{Algorithm: c14n.Exclusive}); err != nil {
			t.Fatal(err)
		}

		resources[uri] = []byte(`<ds:Manifest xmlns:ds="` + xmldsig.Namespace + `" Id="same">` + ref + externalManifestReference("#local", "", canonical.Bytes(), c14n.Exclusive) + `<!--` + payload + `--></ds:Manifest>`)
	}

	resources[uriUrnAttachment] = []byte("shared payload")
	opt, calls, closed := externalManifestOptions(resources)
	opt.External.AllowedURIs = []string{first, second, uriUrnAttachment}
	opt.ExpectedURIs = []string{first, second}

	draft, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: first, Type: xmldsig.ManifestType}, {URI: second, Type: xmldsig.ManifestType}}})
	if err != nil {
		t.Fatal(err)
	}

	key := graphKey(t)

	signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		t.Fatal(err)
	}

	clear(calls)

	*closed = 0

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), opt)
	if err != nil || result == nil || len(result.Manifests()) != 2 || calls[first] != 1 || calls[second] != 1 || calls[uriUrnAttachment] != 1 || *closed != 3 {
		t.Fatal(result, report, err, calls, *closed)
	}

	left := result.Manifests()[0].References()[1]

	right := result.Manifests()[1].References()[1]
	if left.Target() == right.Target() || !left.CoversElement(left.Target()) || left.CoversElement(right.Target()) || right.CoversElement(left.Target()) {
		t.Fatal("fragment scopes or coverage were conflated")
	}

	for _, limit := range []xmldsig.ManifestPolicy{
		{Mode: xmldsig.ManifestRecursive, AllowExternal: true, MaxManifests: 1},
		{Mode: xmldsig.ManifestRecursive, AllowExternal: true, MaxReferences: 3},
	} {
		limited := opt

		limited.Manifests = limit
		if result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), limited); !errors.Is(err, xmldsig.ErrPolicy) || result != nil {
			t.Fatal("fragment graph limit bypassed", result, err)
		}
	}
}

func TestExternalReferenceURIRejections(t *testing.T) {
	for _, tc := range []struct {
		name, base, xml, uri, allowed string
	}{
		{"relative base", "relative.xml", xmlMessage, "g", "g"},
		{"opaque base", "urn:message", xmlMessage, "g", "urn:g"},
		{"fragment base", uriSignatureBase + "#part", xmlMessage, "g", uriRelativeResource},
		{"unresolved allowlist", uriSignatureBase, xmlMessage, "g", "g"},
		{"base target denied", uriSignatureBase, `<message xml:base="https://other.test/"/>`, "g", uriRelativeResource},
		{"malformed xml base", uriSignatureBase, `<message xml:base="%zz"/>`, "g", uriRelativeResource},
		{"whitespace xml base", uriSignatureBase, `<message xml:base="#bad value"/>`, "g", uriRelativeResource},
		{"opaque xml base", uriSignatureBase, `<message xml:base="urn:opaque"/>`, "g", uriRelativeResource},
		{"fragment not authorized by parent URI", "", xmlMessage, "urn:manifest#entry", "urn:manifest"},
		{"bad query escape", uriSignatureBase, `<message xml:base="?q=%zz"/>`, "g", uriRelativeResource},
		{"multiple base fragments", uriSignatureBase, `<message xml:base="#one#two"/>`, "g", uriRelativeResource},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := graphDoc(t, tc.xml)

			draft, selected, err := xmldsig.BuildTemplate(t.Context(), input, input.Root(), xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: tc.uri}}})
			if err != nil {
				t.Fatal(err)
			}

			calls := 0
			opt := xmldsig.SignatureOptions{External: &xmldsig.ExternalReferences{BaseURI: tc.base, AllowedURIs: []string{tc.allowed}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				calls++
				return io.NopCloser(strings.NewReader("payload")), nil
			})}}

			key := &countSigner{Signer: graphKey(t)}
			if result, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: opt}); err == nil || result != nil || calls != 0 || key.calls != 0 {
				t.Fatal("invalid URI context reached a resource or signer", result, err, calls, key.calls)
			}
		})
	}
}

func TestExternalURIContextKeepsSameDocumentReferences(t *testing.T) {
	for _, uri := range []string{"#payload", ""} {
		t.Run(uri, func(t *testing.T) {
			input := graphDoc(t, `<message xml:base="https://other.test/"><payload ID="payload">value</payload></message>`)

			transforms := graphC14N()
			if uri == "" {
				transforms = append([]reference.Transform{{Algorithm: xmldsig.EnvelopedSignature}}, transforms...)
			}

			draft, selected, err := xmldsig.BuildTemplate(t.Context(), input, input.Root(), xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: uri, Transforms: transforms}}})
			if err != nil {
				t.Fatal(err)
			}

			opt := xmldsig.SignatureOptions{External: &xmldsig.ExternalReferences{BaseURI: uriSignatureBase, AllowedURIs: []string{uriSignatureBase}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				t.Fatal("same-document reference invoked an external resolver")
				return nil, xmldsig.ErrReference
			})}}
			key := graphKey(t)

			signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: opt})
			if err != nil {
				t.Fatal(err)
			}

			result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, xmldsig.Signatures(signed)[0], key.Public(), opt)
			if err != nil || result == nil || result.References()[0].ResourceURI() != "" || report.References[0].ResourceURI != "" {
				t.Fatal(result, report, err)
			}
		})
	}
}

func TestExternalManifestIndependentVector(t *testing.T) {
	raw, err := os.ReadFile("../testdata/next/external-manifest-vector.json")
	if err != nil {
		t.Fatal(err)
	}

	var vector struct {
		Signature string            `json:"signature"`
		PublicKey string            `json:"public_key"`
		Resources map[string]string `json:"resources"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(vector.PublicKey))
	if block == nil {
		t.Fatal("independent public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	resources := make(map[string][]byte, len(vector.Resources))
	for uri, value := range vector.Resources {
		resources[uri] = []byte(value)
	}

	options, _, _ := externalManifestOptions(resources)
	doc := graphDoc(t, vector.Signature)

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), doc, doc.Root(), key, options)
	if err != nil || result == nil || len(result.Manifests()) != 1 || len(result.Manifests()[0].References()) != 1 || report.ManifestValidation != xmldsig.Valid {
		t.Fatal(result, report, err)
	}

	resources[uriUrnAttachment] = []byte("changed independent vector")

	result, report, err = xmldsig.VerifySignatureDetailed(t.Context(), doc, doc.Root(), key, options)
	if !errors.Is(err, xmldsig.ErrDigest) || result != nil || report.SignatureValue != xmldsig.Valid || report.References[0].Status != xmldsig.Valid {
		t.Fatal(result, report, err)
	}
}

func TestExternalManifestConcurrentReplay(t *testing.T) {
	resources := externalManifestResources(t)
	options, _, _ := externalManifestOptions(resources)
	options.External.Resolver = xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		value, ok := resources[uri]
		if !ok {
			return nil, xmldsig.ErrPolicy
		}

		return io.NopCloser(bytes.NewReader(value)), nil
	})
	key := graphKey(t)
	signed := signExternalManifest(t, key, options, true)

	result, err := xmldsig.VerifySignature(t.Context(), signed, signed.Root(), key.Public(), options)
	if err != nil {
		t.Fatal(err)
	}

	refs := []xmldsig.ReferenceResult{result.References()[0], result.Manifests()[0].References()[1]}

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

func TestExternalManifestGraph(t *testing.T) {
	for _, canonical := range []bool{false, true} {
		t.Run(strconv.FormatBool(canonical), func(t *testing.T) { testExternalManifestGraph(t, canonical) })
	}
}

func testExternalManifestGraph(t *testing.T, canonical bool) {
	t.Helper()
	resources := externalManifestResources(t)
	options, calls, closed := externalManifestOptions(resources)
	key := graphKey(t)
	signed := signExternalManifest(t, key, options, canonical)

	clear(calls)

	*closed = 0

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), options)
	if err != nil || result == nil {
		t.Fatal(result, report, err)
	}

	if len(result.Manifests()) != 2 || report.ManifestValidation != xmldsig.Valid {
		t.Fatal("incomplete graph", report)
	}

	for _, uri := range []string{uriExternalManifest, uriLeafManifest, uriUrnAttachment} {
		if calls[uri] != 1 {
			t.Fatalf("%s fetched %d times", uri, calls[uri])
		}
	}

	if *closed != 3 {
		t.Fatal("resource readers not closed", *closed)
	}

	root := result.Manifests()[0]
	if root.ResourceURI() != uriExternalManifest || report.Manifests[0].ResourceURI != uriExternalManifest || len(root.References()) != 3 {
		t.Fatal(root, report)
	}

	local := root.References()[1]
	if local.Target().Name().Local != "Reference" || !local.CoversElement(local.Target()) || result.CoversElement(local.Target()) {
		t.Fatal("external/local scope or coverage was confused")
	}

	if result.Manifests()[1].ResourceURI() != uriLeafManifest || len(result.Manifests()[1].References()) != 1 {
		t.Fatal("leaf result missing")
	}

	var replay bytes.Buffer
	if _, err := local.WriteDigestInput(t.Context(), &replay); err != nil || replay.Len() == 0 {
		t.Fatal("remote-scope replay", err)
	}

	for range 2 {
		if _, err := result.References()[0].WriteDigestInput(t.Context(), io.Discard); err != nil {
			t.Fatal("external replay", err)
		}
	}
}

func externalManifestResources(t *testing.T) map[string][]byte {
	t.Helper()

	payload := []byte("external payload")
	leaf := []byte(`<ds:Manifest xmlns:ds="` + xmldsig.Namespace + `" Id="leaf">` + externalManifestReference(uriUrnAttachment, "", payload) + `</ds:Manifest>`)
	first := strings.Replace(externalManifestReference(uriLeafManifest, xmldsig.ManifestType, leaf), `<ds:Reference `, `<ds:Reference Id="scoped" `, 1)
	doc := graphDoc(t, `<ds:Manifest xmlns:ds="`+xmldsig.Namespace+`" Id="remote">`+first+`</ds:Manifest>`)

	var canonical bytes.Buffer
	if err := c14n.WriteElement(t.Context(), &canonical, doc.Root().Children()[0], c14n.Options{Algorithm: c14n.Exclusive}); err != nil {
		t.Fatal(err)
	}

	second := externalManifestReference("#scoped", "", canonical.Bytes(), c14n.Exclusive)
	third := externalManifestReference(uriLeafManifest, xmldsig.ManifestType, leaf)
	root := []byte(`<ds:Manifest xmlns:ds="` + xmldsig.Namespace + `" Id="remote">` + first + second + third + `</ds:Manifest>`)

	return map[string][]byte{uriExternalManifest: root, uriLeafManifest: leaf, uriUrnAttachment: payload}
}

func externalManifestReference(uri, typ string, input []byte, transforms ...string) string {
	digest := sha256.Sum256(input)

	ref := coreRef(uri, transforms...)
	if typ != "" {
		ref = strings.Replace(ref, `<ds:Reference `, `<ds:Reference Type="`+typ+`" `, 1)
	}

	return strings.Replace(ref, `<ds:DigestValue/>`, `<ds:DigestValue>`+base64.StdEncoding.EncodeToString(digest[:])+`</ds:DigestValue>`, 1)
}

func externalManifestOptions(resources map[string][]byte) (xmldsig.SignatureOptions, map[string]int, *int) {
	calls := make(map[string]int)
	closed := new(int)
	opt := xmldsig.SignatureOptions{Manifests: xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, AllowExternal: true}, ExpectedURIs: []string{uriExternalManifest}}
	opt.External = &xmldsig.ExternalReferences{AllowedURIs: []string{uriExternalManifest, uriLeafManifest, uriUrnAttachment}, Resolver: xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		calls[uri]++

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		value, ok := resources[uri]
		if !ok {
			return nil, xmldsig.ErrReference
		}

		return &countClose{Reader: bytes.NewReader(value), n: closed}, nil
	})}

	return opt, calls, closed
}

func signExternalManifest(t *testing.T, key crypto.Signer, options xmldsig.SignatureOptions, canonical bool) *document.Document {
	t.Helper()

	var transforms []reference.Transform
	if canonical {
		transforms = graphC14N()
	}

	shadow := "signature document scope"

	doc, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{
		SignatureMethod: xmldsig.ECDSASHA256,
		References:      []xmldsig.ReferenceTemplate{{URI: uriExternalManifest, Type: xmldsig.ManifestType, Transforms: transforms}},
		Objects:         []xmldsig.ObjectTemplate{{ID: "scoped", Text: &shadow}},
	})
	if err != nil {
		t.Fatal(err)
	}

	signed, err := xmldsig.SignTemplate(t.Context(), doc, selected, key, xmldsig.TemplateSignOptions{Validation: options})
	if err != nil {
		t.Fatal(err)
	}

	return signed
}

func TestExternalManifestAuthenticationOrder(t *testing.T) {
	resources := externalManifestResources(t)
	opt, calls, _ := externalManifestOptions(resources)
	key := graphKey(t)
	signed := signExternalManifest(t, key, opt, true)
	raw := coreXML(t, signed)
	// An invalid SignatureValue must fail before every resource callback.
	value := signed.Root().Children()[1].Text()

	sig, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}

	sig[0] ^= 1
	bad := graphDoc(t, strings.Replace(raw, value, base64.StdEncoding.EncodeToString(sig), 1))

	clear(calls)

	if result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), bad, bad.Root(), key.Public(), opt); !errors.Is(err, xmldsig.ErrSignature) || result != nil || len(calls) != 0 {
		t.Fatal(result, err, calls)
	}
	// A corrupted authenticated-parent digest must not trigger nested loads.
	resources[uriExternalManifest] = bytes.Replace(resources[uriExternalManifest], []byte(`Id="remote"`), []byte(`Id="changed"`), 1)

	clear(calls)

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), opt)
	if !errors.Is(err, xmldsig.ErrDigest) || result != nil || calls[uriExternalManifest] != 1 || len(calls) != 1 || len(report.Manifests) != 0 {
		t.Fatal(result, report, err, calls)
	}
}

func TestExternalManifestBeforePrivateSigner(t *testing.T) {
	resources := externalManifestResources(t)
	resources[uriUrnAttachment] = []byte("wrong nested payload")
	options, _, _ := externalManifestOptions(resources)

	doc, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{
		SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: uriExternalManifest, Type: xmldsig.ManifestType}},
	})
	if err != nil {
		t.Fatal(err)
	}

	key := &countSigner{Signer: graphKey(t)}

	result, err := xmldsig.SignTemplate(t.Context(), doc, selected, key, xmldsig.TemplateSignOptions{Validation: options})
	if !errors.Is(err, xmldsig.ErrDigest) || result != nil || key.calls != 0 {
		t.Fatal("invalid external graph reached signer", result, err, key.calls)
	}
}

func TestExternalManifestPolicyAndFailures(t *testing.T) {
	resources := externalManifestResources(t)
	opt, _, _ := externalManifestOptions(resources)
	key := graphKey(t)
	signed := signExternalManifest(t, key, opt, false)

	for _, edit := range []func(*xmldsig.SignatureOptions){
		func(o *xmldsig.SignatureOptions) { o.Manifests.AllowExternal = false },
		func(o *xmldsig.SignatureOptions) { o.Manifests.Mode = xmldsig.ManifestNone },
		func(o *xmldsig.SignatureOptions) { o.Manifests.MaxDepth = 1 },
		func(o *xmldsig.SignatureOptions) { o.Manifests.MaxManifests = 1 },
		func(o *xmldsig.SignatureOptions) { o.Manifests.MaxReferences = 2 },
		func(o *xmldsig.SignatureOptions) { o.External.Limits.MaxResourceBytes = 16 },
		func(o *xmldsig.SignatureOptions) {
			o.External.Limits.MaxTotalResourceBytes = len(resources[uriExternalManifest]) + 4
		},
		func(o *xmldsig.SignatureOptions) { o.External.AllowedURIs = []string{uriExternalManifest} },
	} {
		options, calls, closed := externalManifestOptions(resources)
		edit(&options)

		result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), options)
		if err == nil || result != nil {
			t.Fatal("unsafe graph accepted", result, err)
		}

		count := 0
		for _, n := range calls {
			count += n
		}

		if *closed != count {
			t.Fatal("reader leak", calls, *closed)
		}
	}
	// Core-only success authenticates the Manifest bytes, not their contents.
	resources[uriUrnAttachment] = []byte("changed payload")
	options, calls, _ := externalManifestOptions(resources)
	options.Manifests = xmldsig.ManifestPolicy{}

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), options)
	if err != nil || result == nil || len(result.Manifests()) != 0 || report.ManifestValidation != xmldsig.NotChecked || len(calls) != 1 {
		t.Fatal(result, report, err, calls)
	}

	options.Manifests = opt.Manifests

	result, report, err = xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), options)
	if !errors.Is(err, xmldsig.ErrDigest) || result != nil || report.SignatureValue != xmldsig.Valid || report.References[0].Status != xmldsig.Valid {
		t.Fatal(result, report, err)
	}
}

func TestExternalManifestMalformedAndCyclic(t *testing.T) {
	key := graphKey(t)
	for _, test := range []struct {
		name, source string
		want         error
	}{
		{"malformed XML", `<ds:Manifest`, xmldsig.ErrReference},
		{"wrong root", `<root/>`, xmldsig.ErrStructure},
		{"wrong child", `<ds:Manifest xmlns:ds="` + xmldsig.Namespace + `"><root/></ds:Manifest>`, xmldsig.ErrStructure},
		{"cycle", `<ds:Manifest xmlns:ds="` + xmldsig.Namespace + `">` + externalManifestReference(uriExternalManifest, xmldsig.ManifestType, []byte("irrelevant cycle digest")) + `</ds:Manifest>`, xmldsig.ErrReference},
	} {
		t.Run(test.name, func(t *testing.T) {
			resources := map[string][]byte{uriExternalManifest: []byte(test.source)}
			opt, calls, closed := externalManifestOptions(resources)
			opt.Manifests = xmldsig.ManifestPolicy{}
			signed := signExternalManifest(t, key, opt, false)
			opt.Manifests = xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, AllowExternal: true}

			clear(calls)

			*closed = 0

			result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), opt)
			if !errors.Is(err, test.want) || result != nil || report.SignatureValue != xmldsig.Valid || report.References[0].Status != xmldsig.Valid {
				t.Fatal(result, report, err)
			}

			if calls[uriExternalManifest] != 1 || len(calls) != 1 || *closed != 1 {
				t.Fatal("unexpected recursive I/O", calls, *closed)
			}
		})
	}
}

func TestExternalManifestProvenancePreflight(t *testing.T) {
	resources := externalManifestResources(t)
	resources[uriExternalManifest] = []byte(base64.StdEncoding.EncodeToString(resources[uriExternalManifest]))
	opt, calls, _ := externalManifestOptions(resources)
	opt.Manifests = xmldsig.ManifestPolicy{}
	key := graphKey(t)

	doc, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{
		SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: uriExternalManifest, Type: xmldsig.ManifestType, Transforms: []reference.Transform{{Algorithm: reference.Base64}}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	signed, err := xmldsig.SignTemplate(t.Context(), doc, selected, key, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		t.Fatal(err)
	}

	opt.Manifests = xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, AllowExternal: true}

	clear(calls)

	if result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.Public(), opt); !errors.Is(err, xmldsig.ErrPolicy) || result != nil || len(calls) != 0 {
		t.Fatal("unsafe provenance", result, err, calls)
	}
}

func TestManifestGraphAndMixedReferences(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(strconv.FormatBool(external), func(t *testing.T) { testManifestGraphAndMixedReferencesCase(t, &external) })
	}
}

func testManifestGraphAndMixedReferencesCase(t *testing.T, external *bool) {
	ctx := context.Background()
	k := graphKey(t)
	d, s := makeGraph(t, (*external))
	before, _ := d.XML(ctx)
	opt := graphOptions()
	calls := 0
	closed := 0

	if *external {
		opt.External = &xmldsig.ExternalReferences{AllowedURIs: []string{uriUrnAttachment}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			calls++
			return &countClose{Reader: bytes.NewBufferString("external bytes"), n: &closed}, nil
		})}
	}

	out, e := xmldsig.SignTemplate(ctx, d, s, k, xmldsig.TemplateSignOptions{Validation: opt})
	if e != nil {
		t.Fatal(e)
	}

	if (*external) && (calls != 1 || closed != 1) {
		t.Fatalf("generation + selfcheck fetches=%d closes=%d", calls, closed)
	}

	after, _ := d.XML(ctx)
	if !bytes.Equal(before, after) {
		t.Fatal("input changed")
	}

	result, report, e := xmldsig.VerifySignatureDetailed(ctx, out, out.Root(), k.Public(), opt)
	if e != nil {
		t.Fatal(e)
	}

	if len(result.Manifests()) != 2 || report.ManifestValidation != xmldsig.Valid {
		t.Fatalf("report: %+v", report)
	}

	if len(result.Manifests()[0].References()) != 2 {
		t.Fatal("duplicate incoming Manifest references lost")
	}

	payload := result.Manifests()[1].References()[0].Target()
	if !result.CoversElement(payload) {
		t.Fatal("nested payload not covered")
	}

	refs := result.Manifests()[1].References()
	refs[0] = xmldsig.ReferenceResult{}

	if !result.CoversElement(payload) {
		t.Fatal("mutable result")
	}

	if (*external) && calls != 2 {
		t.Fatalf("shared Manifest fetched twice: %d", calls)
	}
}

func TestManifestDisabledAndBadNestedDigest(t *testing.T) {
	ctx := context.Background()
	k := graphKey(t)
	d, _ := makeGraph(t, false)
	raw, _ := d.XML(ctx)
	// Fill nested digest placeholders with deliberately wrong values, then sign
	// the Manifest itself using core-only mode. SignatureValue remains correct.
	marker := []byte("<ds:Manifest")
	pos := bytes.Index(raw, marker)
	head, tail := raw[:pos], raw[pos:]
	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	tail = bytes.ReplaceAll(tail, []byte("<ds:DigestValue></ds:DigestValue>"), []byte("<ds:DigestValue>"+zero+"</ds:DigestValue>"))
	prepared := graphDoc(t, string(append(append([]byte{}, head...), tail...)))

	signed, e := xmldsig.SignTemplate(ctx, prepared, prepared.Root(), k, xmldsig.TemplateSignOptions{})
	if e != nil {
		t.Fatal(e)
	}

	r, report, e := xmldsig.VerifySignatureDetailed(ctx, signed, signed.Root(), k.Public(), xmldsig.SignatureOptions{})
	if e != nil || r == nil || report.ManifestValidation != xmldsig.NotChecked || len(r.Manifests()) != 0 {
		t.Fatalf("core mode: %v %+v", e, report)
	}

	r, report, e = xmldsig.VerifySignatureDetailed(ctx, signed, signed.Root(), k.Public(), graphOptions())

	var me *xmldsig.ManifestReferenceError
	if r != nil || !errors.Is(e, xmldsig.ErrDigest) || !errors.As(e, &me) {
		t.Fatalf("nested mismatch not diagnosed: %v", e)
	}

	if report.SignatureValue != xmldsig.Valid || report.References[0].Status != xmldsig.Valid || report.Manifests[0].References[0].Status != xmldsig.Invalid || report.Manifests[0].References[1].Status != xmldsig.NotChecked {
		t.Fatalf("report: %+v", report)
	}
}

func TestManifestPolicyAndCycles(t *testing.T) {
	tests := []struct {
		name   string
		edit   func(*xmldsig.SignatureOptions)
		mutate func(string) string
	}{
		{name: "depth", edit: func(o *xmldsig.SignatureOptions) { o.Manifests.MaxDepth = 1 }},
		{name: "nodes", edit: func(o *xmldsig.SignatureOptions) { o.Manifests.MaxManifests = 1 }},
		{name: "references", edit: func(o *xmldsig.SignatureOptions) { o.Manifests.MaxReferences = 3 }},
		{name: "cycle", mutate: func(s string) string { return strings.ReplaceAll(s, `URI="#a"`, `URI="#top"`) }},
		{name: "wrong type target", mutate: func(s string) string { return strings.Replace(s, `URI="#top"`, `URI="#a"`, 1) }},
		{name: "external disabled", mutate: func(s string) string { return strings.ReplaceAll(s, `URI="#a"`, `URI="urn:unlisted"`) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, s := makeGraph(t, false)

			o := graphOptions()
			if tc.edit != nil {
				tc.edit(&o)
			}

			if tc.mutate != nil {
				raw, _ := d.XML(t.Context())
				d = graphDoc(t, tc.mutate(string(raw)))
				s = d.Root()
			}

			k := &countSigner{Signer: graphKey(t)}

			out, e := xmldsig.SignTemplate(context.Background(), d, s, k, xmldsig.TemplateSignOptions{Validation: o})
			if e == nil || out != nil || k.calls != 0 {
				t.Fatalf("not rejected before signing: %v calls=%d", e, k.calls)
			}
		})
	}
}

func TestMixedAuthBeforeIOAndBudgets(t *testing.T) {
	ctx := context.Background()
	k := graphKey(t)
	d, s := makeGraph(t, true)
	calls := 0
	o := graphOptions()
	o.External = &xmldsig.ExternalReferences{AllowedURIs: []string{uriUrnAttachment}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return io.NopCloser(strings.NewReader("bytes")), nil
	})}

	signed, e := xmldsig.SignTemplate(ctx, d, s, k, xmldsig.TemplateSignOptions{Validation: o})
	if e != nil {
		t.Fatal(e)
	}

	calls = 0
	wrong := graphKey(t)

	r, _, e := xmldsig.VerifySignatureDetailed(ctx, signed, signed.Root(), wrong.Public(), o)
	if r != nil || e == nil || calls != 0 {
		t.Fatal("resolver invoked before authentication")
	}

	o.External.Limits.MaxResourceBytes = 2

	r, _, e = xmldsig.VerifySignatureDetailed(ctx, signed, signed.Root(), k.Public(), o)
	if r != nil || e == nil {
		t.Fatal("resource budget bypassed")
	}

	o.External.Limits = xmldsig.ResourceLimits{}

	o.Policy.MaxCanonicalBytes = 200
	if r, _, e = xmldsig.VerifySignatureDetailed(ctx, signed, signed.Root(), k.Public(), o); r != nil || e == nil {
		t.Fatal("processing budget bypassed")
	}
}

func TestBuilderAppendAndDuplicateIDs(t *testing.T) {
	ctx := context.Background()
	d := graphDoc(t, `<r ID="r"><data ID="data">v</data></r>`)
	raw, _ := d.XML(ctx)
	spec := xmldsig.SignatureTemplate{ID: "s", SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: nameData, Transforms: graphC14N()}}}

	draft, s, e := xmldsig.BuildTemplate(ctx, d, d.Root(), spec)
	if e != nil {
		t.Fatal(e)
	}

	after, _ := d.XML(ctx)
	if !bytes.Equal(raw, after) || len(xmldsig.Signatures(draft)) != 1 {
		t.Fatal("builder mutated source")
	}

	if _, e = xmldsig.SignTemplate(ctx, draft, s, graphKey(t), xmldsig.TemplateSignOptions{}); e != nil {
		t.Fatal(e)
	}

	spec.ID = "r"
	if _, _, e = xmldsig.BuildTemplate(ctx, d, d.Root(), spec); e == nil {
		t.Fatal("duplicate ID allowed")
	}
}

func FuzzVerifyManifest(f *testing.F) {
	b, e := os.ReadFile("../testdata/next/ec256.python.xml")
	if e != nil {
		f.Fatal(e)
	}

	p, e := os.ReadFile("../testdata/next/ec256.pub.pem")
	if e != nil {
		f.Fatal(e)
	}

	block, _ := pem.Decode(p)

	public, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		f.Fatal(e)
	}

	payload, e := os.ReadFile("../testdata/next/attachment.bin")
	if e != nil {
		f.Fatal(e)
	}

	vectors, independentKey := loadStage4Vectors(f)

	independentOptions := make([]xmldsig.SignatureOptions, len(vectors.Cases))
	for i, test := range vectors.Cases {
		independentOptions[i] = stage4Options(f, test)
		if test.Kind == stage4KindManifest {
			f.Add(append([]byte{byte(i)}, []byte(test.XML)...))
		}
	}

	f.Add(b)
	f.Add(bytes.Replace(b, []byte(uriUrnAttachment), []byte("list.xml#part"), 1))
	f.Add(append(append([]byte(`<scope xml:base="../resources/">`), b...), []byte(`</scope>`)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			return
		}

		selected := -1
		if len(b) > 0 && int(b[0]) < len(vectors.Cases) {
			selected, b = int(b[0]), b[1:]
		}

		d, e := document.Parse(t.Context(), b, document.DefaultLimits())
		if e != nil {
			return
		}

		s := xmldsig.Signatures(d)
		if len(s) != 1 {
			return
		}

		if selected >= 0 {
			result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), d, s[0], independentKey, independentOptions[selected])
			if err != nil && result != nil {
				t.Fatal("partial success")
			}

			return
		}

		opt := xmldsig.SignatureOptions{Policy: xmldsig.ModernPolicy(), Manifests: xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, AllowExternal: true, MaxDepth: 4, MaxManifests: 8, MaxReferences: 32}, External: &xmldsig.ExternalReferences{AllowedURIs: []string{uriUrnAttachment, "https://example.test/messages/list.xml#part"}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		})}}
		for _, base := range []string{"", uriSignatureBase} {
			opt.External.BaseURI = base
			_, _, _ = xmldsig.VerifySignatureDetailed(t.Context(), d, s[0], public, opt)
		}
	})
}

func graphKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	return k
}

func graphDoc(t *testing.T, raw string) *document.Document {
	t.Helper()

	d, e := document.Parse(t.Context(), []byte(raw), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	return d
}

func graphC14N() []reference.Transform { return []reference.Transform{{Algorithm: c14n.Exclusive}} }

func makeGraph(t *testing.T, ext bool) (*document.Document, document.Element) {
	t.Helper()

	a := "payload"
	b := "second"

	leaves := []xmldsig.ReferenceTemplate{{URI: "#a", Transforms: graphC14N()}, {URI: "#b", Transforms: graphC14N()}}
	if ext {
		leaves = append(leaves, xmldsig.ReferenceTemplate{URI: uriUrnAttachment})
	}

	spec := xmldsig.SignatureTemplate{
		ID: "sig", SignatureMethod: xmldsig.ECDSASHA256,
		References: []xmldsig.ReferenceTemplate{{URI: "#top", Type: xmldsig.ManifestType, Transforms: graphC14N()}},
		Objects: []xmldsig.ObjectTemplate{
			{Manifest: &xmldsig.ManifestTemplate{ID: "top", References: []xmldsig.ReferenceTemplate{{URI: "#leaf", Type: xmldsig.ManifestType, Transforms: graphC14N()}, {URI: "#leaf", Transforms: graphC14N()}}}},
			{Manifest: &xmldsig.ManifestTemplate{ID: "leaf", References: leaves}},
			{ID: "a", Text: &a},
			{ID: "b", Text: &b},
		},
	}

	d, s, e := xmldsig.BuildTemplate(context.Background(), nil, document.Element{}, spec)
	if e != nil {
		t.Fatal(e)
	}

	return d, s
}

func graphOptions() xmldsig.SignatureOptions {
	return xmldsig.SignatureOptions{Manifests: xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive}, ExpectedURIs: []string{"#top"}}
}

type countClose struct {
	io.Reader
	n *int
}

func (c *countClose) Close() error { *c.n++; return nil }

type countSigner struct {
	crypto.Signer
	calls int
}

func (s *countSigner) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.Signer.Sign(r, d, o)
}
