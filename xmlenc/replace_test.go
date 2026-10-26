package xmlenc_test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
	"github.com/skarm/xmlsec/xmlenc"
)

func TestSelectedElementAllSuites(t *testing.T) {
	ctx := t.Context()
	recipient := key(t)

	for _, data := range []string{xmlenc.AES128GCM, xmlenc.AES192GCM, xmlenc.AES256GCM} {
		for _, wrap := range []string{"", xmlenc.AES128KeyWrap, xmlenc.AES192KeyWrap, xmlenc.AES256KeyWrap} {
			t.Run(data+"/"+wrap, func(t *testing.T) { testSelectedElementAllSuitesCase(t, &data, &wrap, &ctx, &recipient) })
		}
	}
}

func testSelectedElementAllSuitesCase(t *testing.T, data *string, wrap *string, ctx *context.Context, recipient **rsa.PrivateKey) {
	source := parse(t, []byte(`<?before ok?><!--outside--><r xmlns="urn:outer" xmlns:p="urn:p" xmlns:q="urn:unused" xmlns:ds="urn:shadow-ds" xml:lang="ru" xml:base="https://example.test/"><before>visible</before><box xmlns:p="urn:shadow-p"><p:secret xmlns="" p:flag="é">before<bare/>й 😀<!--inside--><?inside ok?></p:secret><after/></box></r><!--after-->`))
	before := xmlBytes(t, source)
	selected := source.Root().Children()[1].Children()[0]
	options := xmlenc.Options{DataAlgorithm: *data}

	var (
		encrypted, restored *document.Document
		err                 error
	)
	if (*wrap) == "" {
		encrypted, _, err = xmlenc.EncryptElement(*ctx, source, selected, &(*recipient).PublicKey, options)
	} else {
		sizes := map[string]int{xmlenc.AES128KeyWrap: 16, xmlenc.AES192KeyWrap: 24, xmlenc.AES256KeyWrap: 32}
		kek := bytes.Repeat([]byte{7}, sizes[(*wrap)])
		kw := xmlenc.KeyWrapOptions{Data: options, KeyAlgorithm: *wrap}

		encrypted, _, err = xmlenc.EncryptElementWithKeyWrap(*ctx, source, selected, kek, kw)
		if err == nil {
			restored, _, err = xmlenc.DecryptElementWithKeyWrap(*ctx, encrypted, encrypted.Root().Children()[1].Children()[0], kek, kw)
		}
	}

	if err != nil {
		t.Fatal(err)
	}

	if (*wrap) == "" {
		restored, _, err = xmlenc.DecryptElement(*ctx, encrypted, encrypted.Root().Children()[1].Children()[0], *recipient, options)
	}

	if err != nil {
		t.Fatal(err)
	}

	wire := xmlBytes(t, encrypted)
	if bytes.Contains(wire, []byte("й")) || !bytes.Contains(wire, []byte("visible")) || !bytes.Contains(wire, []byte("<!--outside-->")) {
		t.Fatal("selection or surrounding document changed", string(wire))
	}

	sameXML(t, source, restored)

	if !bytes.Equal(before, xmlBytes(t, source)) || !bytes.Equal(wire, xmlBytes(t, encrypted)) {
		t.Fatal("source snapshot mutated")
	}
}

func TestSelectedElementRootAndExactSelection(t *testing.T) {
	ctx, kek := t.Context(), make([]byte, 32)
	source := parse(t, []byte(`<!--before--><?outside ok?><r><secret>one</secret><secret>two</secret></r><!--after-->`))

	root, encryptedRoot, err := xmlenc.EncryptElementWithKeyWrap(ctx, source, source.Root(), kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !encryptedRoot.Same(root.Root()) {
		t.Fatal("returned encrypted handle belongs to another snapshot")
	}

	plain, plainRoot, err := xmlenc.DecryptElementWithKeyWrap(ctx, root, encryptedRoot, kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !plainRoot.Same(plain.Root()) {
		t.Fatal("returned plaintext handle belongs to another snapshot")
	}

	sameXML(t, source, plain)

	first, encryptedFirst, err := xmlenc.EncryptElementWithKeyWrap(ctx, source, source.Root().Children()[0], kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !encryptedFirst.Same(first.Root().Children()[0]) {
		t.Fatal("returned encrypted handle changed selection")
	}

	otherKey := bytes.Repeat([]byte{1}, 32)

	both, _, err := xmlenc.EncryptElementWithKeyWrap(ctx, first, first.Root().Children()[1], otherKey, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	partial, _, err := xmlenc.DecryptElementWithKeyWrap(ctx, both, both.Root().Children()[0], kek, xmlenc.KeyWrapOptions{})
	if err != nil || partial.Root().Children()[0].Text() != nameOne || partial.Root().Children()[1].Name().Local != "EncryptedData" {
		t.Fatal("not an exact selection", err)
	}

	full, _, err := xmlenc.DecryptElementWithKeyWrap(ctx, partial, partial.Root().Children()[1], otherKey, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	sameXML(t, source, full)
}

func TestSelectedElementPreservesEmbeddedSignatures(t *testing.T) {
	ctx, signer := t.Context(), key(t)
	for _, method := range []string{c14n.Exclusive, c14n.ExclusiveWithComments, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments} {
		t.Run(method, func(t *testing.T) {
			source := parse(t, []byte(`<r xmlns="urn:outer" xmlns:p="urn:p" xmlns:u="urn:unused" xml:lang="ru" xml:base="https://example.test/"><box><p:secret ID="payload" xmlns=""><v>protected</v><!--inside--></p:secret></box></r>`))
			selected := source.Root().Children()[0].Children()[0]
			template := xmldsig.SignatureTemplate{
				SignatureMethod:  xmldsig.RSASHA256,
				Canonicalization: reference.Transform{Algorithm: method},
				References:       []xmldsig.ReferenceTemplate{{URI: namePayload, Transforms: []reference.Transform{{Algorithm: xmldsig.EnvelopedSignature}, {Algorithm: method}}}},
			}

			draft, signature, err := xmldsig.BuildTemplate(ctx, source, selected, template)
			if err != nil {
				t.Fatal(err)
			}

			options := xmldsig.SignatureOptions{ExpectedURIs: []string{namePayload}, AllowedCanonicalizationMethods: []string{method}}

			signed, err := xmldsig.SignTemplate(ctx, draft, signature, signer, xmldsig.TemplateSignOptions{Validation: options})
			if err != nil {
				t.Fatal(err)
			}

			kek := make([]byte, 32)

			encrypted, _, err := xmlenc.EncryptElementWithKeyWrap(ctx, signed, signed.Root().Children()[0].Children()[0], kek, xmlenc.KeyWrapOptions{})
			if err != nil {
				t.Fatal(err)
			}

			restored, _, err := xmlenc.DecryptElementWithKeyWrap(ctx, encrypted, encrypted.Root().Children()[0].Children()[0], kek, xmlenc.KeyWrapOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if _, err := xmldsig.VerifySignature(ctx, restored, xmldsig.Signatures(restored)[0], signer.Public(), options); err != nil {
				t.Fatal("restored signature changed", err)
			}

			sameXML(t, signed, restored)
		})
	}
}

func TestSelectedElementSuperEncryption(t *testing.T) {
	ctx, kek := t.Context(), make([]byte, 32)
	source := parse(t, []byte(`<r><secret>protected</secret><tail>visible</tail></r>`))

	inner, innerHandle, err := xmlenc.EncryptElementWithKeyWrap(ctx, source, source.Root().Children()[0], kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Replacing a descendant would corrupt an XMLENC structure. The entire
	// EncryptedData, including its inline EncryptedKey, remains a valid selection.
	for _, selected := range []document.Element{innerHandle.Children()[0], innerHandle.Children()[1].Children()[0]} {
		before := xmlBytes(t, inner)

		result, handle, err := xmlenc.EncryptElementWithKeyWrap(ctx, inner, selected, kek, xmlenc.KeyWrapOptions{})
		if result != nil || handle.Valid() || !errors.Is(err, xmlenc.ErrFormat) || !bytes.Equal(before, xmlBytes(t, inner)) {
			t.Fatal("partial super-encryption accepted or source changed", err)
		}
	}

	outerKey := bytes.Repeat([]byte{1}, 32)

	outer, outerHandle, err := xmlenc.EncryptElementWithKeyWrap(ctx, inner, innerHandle, outerKey, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	partial, restoredInner, err := xmlenc.DecryptElementWithKeyWrap(ctx, outer, outerHandle, outerKey, xmlenc.KeyWrapOptions{})
	if err != nil || restoredInner.Name() != innerHandle.Name() {
		t.Fatal("super-encryption did not restore exact inner EncryptedData", err)
	}

	sameXML(t, inner, partial)

	full, _, err := xmlenc.DecryptElementWithKeyWrap(ctx, partial, restoredInner, kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	sameXML(t, source, full)
}

func TestSelectedElementAuthenticatedXMLAndLimits(t *testing.T) {
	ctx, kek := t.Context(), make([]byte, 32)
	parent := `<r xmlns="urn:outer" xmlns:p="urn:p" xmlns:q="urn:q">`
	valid := authenticatedElement(t, `<p:secret xmlns="" p:flag="é"><bare/>й<q:v>ok</q:v></p:secret>`, parent, document.DefaultLimits())

	restored, _, err := xmlenc.DecryptElementWithKeyWrap(ctx, valid, valid.Root().Children()[0], kek, xmlenc.KeyWrapOptions{})
	if err != nil || restored.Root().Children()[0].Name().Space != "urn:p" || restored.Root().Children()[0].Children()[0].Name().Space != "" || restored.Root().Children()[0].Children()[1].Name().Space != "urn:q" {
		t.Fatal("parent context or default reset lost", err)
	}
	// Inherited bindings are context, not local attributes or extra nodes of
	// the decrypted element. Wrapper overhead must not consume those budgets.
	leaf := authenticatedElement(t, `<p:secret a="1"/>`, parent, document.DefaultLimits())
	leafLimits := document.DefaultLimits()
	leafLimits.MaxBytes = len(`<p:secret a="1"/>`)

	leafLimits.MaxNodes, leafLimits.MaxDepth, leafLimits.MaxAttributesPerElement = 1, 1, 1
	if result, handle, err := xmlenc.DecryptElementWithKeyWrap(ctx, leaf, leaf.Root().Children()[0], kek, xmlenc.KeyWrapOptions{Data: xmlenc.Options{XMLLimits: leafLimits}}); err != nil || !handle.Same(result.Root().Children()[0]) || handle.Name().Space != "urn:p" {
		t.Fatal("namespace wrapper charged against plaintext budgets", err)
	}

	for _, raw := range []string{
		`<p:secret/><p:secret/>`, `<!--before--><p:secret/>`, `<p:secret/><?after ok?>`,
		`</xmlsec-context><p:secret/><xmlsec-context>`, `<p:secret xmlns:p="urn:changed" p:a="1" p:a="2"/>`,
		`<!DOCTYPE p:secret><p:secret/>`, `<?xml version="1.0"?><p:secret/>`,
		"<p:secret>e\u0301</p:secret>", `<ds:secret/>`, `<p:secret Type="Content">`,
	} {
		t.Run(fmt.Sprintf("invalid/%q", raw), func(t *testing.T) {
			encrypted := authenticatedElement(t, raw, parent, document.DefaultLimits())
			before := xmlBytes(t, encrypted)

			result, _, err := xmlenc.DecryptElementWithKeyWrap(ctx, encrypted, encrypted.Root().Children()[0], kek, xmlenc.KeyWrapOptions{})
			if result != nil || !errors.Is(err, xmlenc.ErrDecrypt) || !bytes.Equal(before, xmlBytes(t, encrypted)) {
				t.Fatal("authenticated invalid XML leaked or changed source", err)
			}
		})
	}

	for _, field := range []string{nameBytes, nameNodes, nameDepth, nameAttributes, nameNamespaces} {
		t.Run("limit/"+field, func(t *testing.T) {
			limits := document.DefaultLimits()

			switch field {
			case nameBytes:
				limits.MaxBytes = 16
			case nameNodes:
				limits.MaxNodes = 1
			case nameDepth:
				limits.MaxDepth = 1
			case nameAttributes:
				limits.MaxAttributesPerElement = 1
			case nameNamespaces:
				limits.MaxInScopeNamespaces = 1
			}

			encrypted := authenticatedElement(t, `<p:secret a="1" b="2"><q:v/></p:secret>`, parent, document.DefaultLimits())

			options := xmlenc.KeyWrapOptions{Data: xmlenc.Options{XMLLimits: limits}}
			if result, _, err := xmlenc.DecryptElementWithKeyWrap(ctx, encrypted, encrypted.Root().Children()[0], kek, options); result != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
				t.Fatal("plaintext budget bypassed", err)
			}
		})
	}
	// Plaintext is within its own limits, but grows beyond the full source's
	// depth budget after insertion; no partially restored result is returned.
	limits := document.DefaultLimits()
	limits.MaxDepth = 9

	encrypted := authenticatedElement(t, `<secret>`+strings.Repeat(`<n>`, 10)+strings.Repeat(`</n>`, 10)+`</secret>`, parent, limits)
	if result, _, err := xmlenc.DecryptElementWithKeyWrap(ctx, encrypted, encrypted.Root().Children()[0], kek, xmlenc.KeyWrapOptions{}); result != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
		t.Fatal("complete document depth bypassed", err)
	}
	// Escaping plaintext can make the restored document larger than its source.
	// The full output byte limit must be checked independently of raw plaintext.
	expanding := authenticatedElement(t, `<secret>`+strings.Repeat(`>`, 1024)+`</secret>`, parent, document.DefaultLimits())
	wire := xmlBytes(t, expanding)
	limits = document.DefaultLimits()
	limits.MaxBytes = len(wire)

	bounded, err := document.Parse(ctx, wire, limits)
	if err != nil {
		t.Fatal(err)
	}

	if result, handle, err := xmlenc.DecryptElementWithKeyWrap(ctx, bounded, bounded.Root().Children()[0], kek, xmlenc.KeyWrapOptions{}); result != nil || handle.Valid() || !errors.Is(err, xmlenc.ErrDecrypt) || !bytes.Equal(wire, xmlBytes(t, bounded)) {
		t.Fatal("complete document byte budget bypassed or source changed", err)
	}
}

// Use an authenticated plaintext produced through the opaque bytes API. Merely
// changing Type does not change the GCM tag, so failures test XML processing.
func authenticatedElement(t *testing.T, raw, parent string, limits document.Limits) *document.Document {
	t.Helper()

	encrypted, err := xmlenc.EncryptBytesWithKeyWrap(t.Context(), []byte(raw), make([]byte, 32), xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	wire := bytes.Replace(xmlBytes(t, encrypted), []byte("<xenc:EncryptedData "), []byte(`<xenc:EncryptedData Type="`+xmlenc.ElementType+`" `), 1)

	wrapped := io.MultiReader(strings.NewReader(parent), bytes.NewReader(wire), strings.NewReader("</r>"))

	doc, err := document.ParseReader(t.Context(), wrapped, limits)
	if err != nil {
		t.Fatal(err)
	}

	return doc
}

func TestSelectedElementRejectsHandlesTamperingAndCancellation(t *testing.T) {
	ctx, kek := t.Context(), make([]byte, 32)
	source := parse(t, []byte(`<r><secret>private</secret><tail/></r>`))

	foreign := parse(t, []byte(`<r><secret>foreign</secret></r>`))
	for _, selected := range []document.Element{{}, foreign.Root(), foreign.Root().Children()[0]} {
		if result, handle, err := xmlenc.EncryptElementWithKeyWrap(ctx, source, selected, kek, xmlenc.KeyWrapOptions{}); result != nil || handle.Valid() || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatal("foreign selection accepted", err)
		}

		if result, handle, err := xmlenc.DecryptElementWithKeyWrap(ctx, source, selected, kek, xmlenc.KeyWrapOptions{}); result != nil || handle.Valid() || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatal("foreign decryption selection accepted", err)
		}
	}

	encrypted, _, err := xmlenc.EncryptElementWithKeyWrap(ctx, source, source.Root().Children()[0], kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if result, _, err := xmlenc.DecryptElementWithKeyWrap(ctx, encrypted, source.Root().Children()[0], kek, xmlenc.KeyWrapOptions{}); result != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("stale source handle accepted", err)
	}

	value := encrypted.Root().Children()[0].Children()[2].Children()[0].Text()
	tag, _ := base64.StdEncoding.DecodeString(value)
	tag[len(tag)-1] ^= 1
	bad := parse(t, bytes.Replace(xmlBytes(t, encrypted), []byte(value), []byte(base64.StdEncoding.EncodeToString(tag)), 1))

	before := xmlBytes(t, bad)
	if result, _, err := xmlenc.DecryptElementWithKeyWrap(ctx, bad, bad.Root().Children()[0], kek, xmlenc.KeyWrapOptions{}); result != nil || !errors.Is(err, xmlenc.ErrDecrypt) || !bytes.Equal(before, xmlBytes(t, bad)) {
		t.Fatal("tamper leaked plaintext or changed source", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	if result, _, err := xmlenc.EncryptElementWithKeyWrap(canceled, source, source.Root().Children()[0], kek, xmlenc.KeyWrapOptions{}); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}

	if result, _, err := xmlenc.DecryptElementWithKeyWrap(canceled, encrypted, encrypted.Root().Children()[0], kek, xmlenc.KeyWrapOptions{}); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}

	if result, _, err := xmlenc.EncryptElementWithKeyWrap(ctx, source, source.Root().Children()[0], kek, xmlenc.KeyWrapOptions{Data: xmlenc.Options{MaxPlaintextBytes: 4}}); result != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal("plaintext budget bypassed", err)
	}

	limits := document.DefaultLimits()
	limits.MaxBytes = 128

	tight, err := document.Parse(ctx, xmlBytes(t, source), limits)
	if err != nil {
		t.Fatal(err)
	}

	if result, _, err := xmlenc.EncryptElementWithKeyWrap(ctx, tight, tight.Root().Children()[0], kek, xmlenc.KeyWrapOptions{}); result != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal("ciphertext output budget bypassed", err)
	}
}

func FuzzSelectedElementPlaintext(f *testing.F) {
	for _, raw := range []string{
		`<p:secret/>`, `<p:secret xmlns=""><bare/>й<!--ok--></p:secret>`,
		`<p:secret p:a="1"><p:v>q́</p:v></p:secret>`, `<p:secret/><p:secret/>`,
		`</xmlsec-context><p:secret/><xmlsec-context>`, "<p:secret>e\u0301</p:secret>",
	} {
		f.Add([]byte(raw))
	}

	kek := bytes.Repeat([]byte{0x37}, 32) // public TEST key; not a stored private fixture

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			return
		}

		ctx := t.Context()

		encrypted, err := xmlenc.EncryptBytesWithKeyWrap(ctx, raw, kek, xmlenc.KeyWrapOptions{})
		if err != nil {
			t.Fatal(err)
		}

		wire := bytes.Replace(xmlBytes(t, encrypted), []byte("<xenc:EncryptedData "), []byte(`<xenc:EncryptedData Type="`+xmlenc.ElementType+`" `), 1)
		wrapped := io.MultiReader(strings.NewReader(`<r xmlns="urn:outer" xmlns:p="urn:p" xml:lang="ru">`), bytes.NewReader(wire), strings.NewReader(`<tail>visible</tail></r>`))

		source, err := document.ParseReader(ctx, wrapped, document.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}

		before := xmlBytes(t, source)
		limits := document.DefaultLimits()
		limits.MaxBytes, limits.MaxNodes, limits.MaxDepth, limits.MaxAttributesPerElement = 4096, 64, 8, 8
		options := xmlenc.KeyWrapOptions{Data: xmlenc.Options{XMLLimits: limits}}

		result, handle, err := xmlenc.DecryptElementWithKeyWrap(ctx, source, source.Root().Children()[0], kek, options)
		if !bytes.Equal(before, xmlBytes(t, source)) {
			t.Fatal("source mutated")
		}

		if err != nil {
			if result != nil || handle.Valid() || !errors.Is(err, xmlenc.ErrDecrypt) {
				t.Fatal("error exposed a partial result", err)
			}

			return
		}

		if !handle.Same(result.Root().Children()[0]) || result.Root().Children()[1].Text() != "visible" || result.Root().Name() != source.Root().Name() {
			t.Fatal("restored selection or surrounding document changed")
		}
	})
}

func xmlBytes(t testing.TB, doc *document.Document) []byte {
	t.Helper()

	raw, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

func sameXML(t testing.TB, before, after *document.Document) {
	t.Helper()

	for _, method := range []string{c14n.Exclusive, c14n.ExclusiveWithComments, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments} {
		var a, b bytes.Buffer

		options := c14n.Options{Algorithm: method}
		if err := c14n.WriteDocument(t.Context(), &a, before, options); err != nil {
			t.Fatal(err)
		}

		if err := c14n.WriteDocument(t.Context(), &b, after, options); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(a.Bytes(), b.Bytes()) {
			t.Fatalf("changed %s\nbefore %s\nafter  %s", method, a.Bytes(), b.Bytes())
		}
	}
}
