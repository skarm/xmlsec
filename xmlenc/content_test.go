package xmlenc_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rsa"
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

func TestContentAllSuites(t *testing.T) {
	ctx, recipient := context.Background(), key(t)

	for _, data := range []string{xmlenc.AES128GCM, xmlenc.AES192GCM, xmlenc.AES256GCM} {
		for _, wrap := range []string{"", xmlenc.AES128KeyWrap, xmlenc.AES192KeyWrap, xmlenc.AES256KeyWrap} {
			for _, content := range []string{"", "й 😀 &amp; text", `before<p:v xmlns:p="urn:shadow">one</p:v><!--inside--><?inside ok?><bare xmlns="">two</bare>after`} {
				t.Run(fmt.Sprintf("%s/%s/%q", data, wrap, content), func(t *testing.T) { testContentAllSuitesCase(t, &content, &data, &wrap, &ctx, &recipient) })
			}
		}
	}
}

func testContentAllSuitesCase(t *testing.T, content *string, data *string, wrap *string, ctx *context.Context, recipient **rsa.PrivateKey) {
	source := parse(t, []byte(`<?outside ok?><!--before--><r xmlns="urn:r" xmlns:p="urn:p" xmlns:q="urn:unused" xml:lang="ru" xml:base="https://example.test/"><head>visible</head><box flag="public">`+(*content)+`</box><tail/></r><!--after-->`))
	parent := source.Root().Children()[1]
	before := xmlBytes(t, source)
	options := xmlenc.Options{DataAlgorithm: *data}

	var (
		encrypted, restored           *document.Document
		cipherElement, restoredParent document.Element
		err                           error
	)
	if (*wrap) == "" {
		encrypted, cipherElement, err = xmlenc.EncryptContent(*ctx, source, parent, &(*recipient).PublicKey, options)
		if err == nil {
			restored, restoredParent, err = xmlenc.DecryptContent(*ctx, encrypted, cipherElement, *recipient, options)
		}
	} else {
		sizes := map[string]int{xmlenc.AES128KeyWrap: 16, xmlenc.AES192KeyWrap: 24, xmlenc.AES256KeyWrap: 32}
		kek := bytes.Repeat([]byte{7}, sizes[(*wrap)])
		kw := xmlenc.KeyWrapOptions{Data: options, KeyAlgorithm: *wrap}

		encrypted, cipherElement, err = xmlenc.EncryptContentWithKeyWrap(*ctx, source, parent, kek, kw)
		if err == nil {
			restored, restoredParent, err = xmlenc.DecryptContentWithKeyWrap(*ctx, encrypted, cipherElement, kek, kw)
		}
	}

	if err != nil {
		t.Fatal(err)
	}

	if !cipherElement.Same(encrypted.Root().Children()[1].Children()[0]) || !restoredParent.Same(restored.Root().Children()[1]) {
		t.Fatal("returned handles lost exact selection")
	}

	if flag, _ := encrypted.Root().Children()[1].Attribute(document.Name{Local: "flag"}); flag != "public" || bytes.Contains(xmlBytes(t, encrypted), []byte("й")) {
		t.Fatal("parent attributes encrypted or content visible")
	}

	if !bytes.Equal(before, xmlBytes(t, source)) {
		t.Fatal("source snapshot mutated")
	}

	sameXML(t, source, restored)
}

func TestContentEmbeddedSignatures(t *testing.T) {
	ctx, signer, kek := context.Background(), key(t), make([]byte, 32)
	for _, method := range []string{c14n.Exclusive, c14n.ExclusiveWithComments, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments} {
		t.Run(method, func(t *testing.T) {
			source := parse(t, []byte(`<r xmlns="urn:r" xmlns:p="urn:p" xmlns:q="urn:unused" xml:lang="ru"><box>text<p:v ID="payload" xmlns=""><bare>signed</bare></p:v>after</box></r>`))
			payload := source.Root().Children()[0].Children()[0]

			draft, signature, err := xmldsig.BuildTemplate(ctx, source, payload, xmldsig.SignatureTemplate{
				SignatureMethod: xmldsig.RSASHA256, Canonicalization: reference.Transform{Algorithm: method},
				References: []xmldsig.ReferenceTemplate{{URI: namePayload, Transforms: []reference.Transform{{Algorithm: xmldsig.EnvelopedSignature}, {Algorithm: method}}}},
			},
			)
			if err != nil {
				t.Fatal(err)
			}

			options := xmldsig.SignatureOptions{ExpectedURIs: []string{namePayload}, AllowedCanonicalizationMethods: []string{method}}

			signed, err := xmldsig.SignTemplate(ctx, draft, signature, signer, xmldsig.TemplateSignOptions{Validation: options})
			if err != nil {
				t.Fatal(err)
			}

			encrypted, encryptedContent, err := xmlenc.EncryptContentWithKeyWrap(ctx, signed, signed.Root().Children()[0], kek, xmlenc.KeyWrapOptions{})
			if err != nil {
				t.Fatal(err)
			}

			restored, _, err := xmlenc.DecryptContentWithKeyWrap(ctx, encrypted, encryptedContent, kek, xmlenc.KeyWrapOptions{})
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

func TestContentAuthenticatedXMLAndLimits(t *testing.T) {
	ctx, kek := context.Background(), make([]byte, 32)
	prefix, suffix := `<r xmlns="urn:r" xmlns:p="urn:p" xmlns:q="urn:unused">before`, `after</r>`

	for _, raw := range []string{"", "text&amp;й", `<!--only comment--><?only pi?>`, `<p:v/>middle<bare xmlns=""/>`, `<![CDATA[<valid text>]]>`} {
		t.Run("valid/"+raw, func(t *testing.T) {
			encrypted := authenticatedContent(t, []byte(raw), prefix, suffix)

			restored, parent, err := xmlenc.DecryptContentWithKeyWrap(ctx, encrypted, encrypted.Root().Children()[0], kek, xmlenc.KeyWrapOptions{})
			if err != nil || !parent.Same(restored.Root()) {
				t.Fatal(err)
			}

			want := parse(t, []byte(prefix+raw+suffix))
			sameXML(t, want, restored)
		})
	}

	for _, raw := range []string{`</xmlsec-context><evil/><xmlsec-context>`, `<?xml version="1.0"?>`, `<!DOCTYPE r>`, `<p:v>`, `<ds:v/>`, `&unknown;`, "e\u0301", "\xff", `<p:v a="1" a="2"/>`} {
		t.Run("invalid/"+raw, func(t *testing.T) {
			encrypted := authenticatedContent(t, []byte(raw), prefix, suffix)
			before := xmlBytes(t, encrypted)

			result, handle, err := xmlenc.DecryptContentWithKeyWrap(ctx, encrypted, encrypted.Root().Children()[0], kek, xmlenc.KeyWrapOptions{})
			if result != nil || handle.Valid() || !errors.Is(err, xmlenc.ErrDecrypt) || !bytes.Equal(before, xmlBytes(t, encrypted)) {
				t.Fatal("invalid content leaked a result or mutated source", err)
			}
		})
	}

	for _, field := range []string{nameBytes, nameNodes, nameDepth, nameAttributes, nameNamespaces} {
		t.Run("limit/"+field, func(t *testing.T) {
			limits := document.DefaultLimits()

			switch field {
			case nameBytes:
				limits.MaxBytes = 4
			case nameNodes:
				limits.MaxNodes = 1
			case nameDepth:
				limits.MaxDepth = 1
			case nameAttributes:
				limits.MaxAttributesPerElement = 1
			case nameNamespaces:
				limits.MaxInScopeNamespaces = 1
			}

			encrypted := authenticatedContent(t, []byte(`<p:v a="1" b="2"><p:c/></p:v><p:v/>`), prefix, suffix)

			result, handle, err := xmlenc.DecryptContentWithKeyWrap(ctx, encrypted, encrypted.Root().Children()[0], kek, xmlenc.KeyWrapOptions{Data: xmlenc.Options{XMLLimits: limits}})
			if result != nil || handle.Valid() || !errors.Is(err, xmlenc.ErrDecrypt) {
				t.Fatal("plaintext limit bypassed", err)
			}
		})
	}
}

func TestContentSelectionAndSuperEncryption(t *testing.T) {
	ctx, kek := context.Background(), make([]byte, 32)
	source := parse(t, []byte(`<!--before--><r ID="root">before<secret>protected</secret>after</r><!--after-->`))

	inner, cipherElement, err := xmlenc.EncryptElementWithKeyWrap(ctx, source, source.Root().Children()[0], kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if result, handle, err := xmlenc.EncryptContentWithKeyWrap(ctx, inner, cipherElement, kek, xmlenc.KeyWrapOptions{}); result != nil || handle.Valid() || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("partial super-encryption accepted", err)
	}

	outer, contentElement, err := xmlenc.EncryptContentWithKeyWrap(ctx, inner, inner.Root(), kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if result, _, err := xmlenc.DecryptElementWithKeyWrap(ctx, outer, contentElement, kek, xmlenc.KeyWrapOptions{}); result != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("Content accepted by Element API", err)
	}

	if result, _, err := xmlenc.DecryptContentWithKeyWrap(ctx, inner, cipherElement, kek, xmlenc.KeyWrapOptions{}); result != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("Element accepted by Content API", err)
	}

	partial, parent, err := xmlenc.DecryptContentWithKeyWrap(ctx, outer, contentElement, kek, xmlenc.KeyWrapOptions{})
	if err != nil || !parent.Same(partial.Root()) {
		t.Fatal(err)
	}

	sameXML(t, inner, partial) // inner EncryptedData is retained, not decrypted

	full, _, err := xmlenc.DecryptElementWithKeyWrap(ctx, partial, partial.Root().Children()[0], kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	sameXML(t, source, full)

	for _, foreign := range []document.Element{source.Root(), {}} {
		if result, handle, err := xmlenc.DecryptContentWithKeyWrap(ctx, outer, foreign, kek, xmlenc.KeyWrapOptions{}); result != nil || handle.Valid() || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatal("foreign/empty handle accepted", err)
		}
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	if result, _, err := xmlenc.DecryptContentWithKeyWrap(canceled, outer, contentElement, kek, xmlenc.KeyWrapOptions{}); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}

	if result, _, err := xmlenc.EncryptContentWithKeyWrap(ctx, source, source.Root(), kek, xmlenc.KeyWrapOptions{Data: xmlenc.Options{MaxPlaintextBytes: 4}}); result != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal("serialization budget bypassed", err)
	}
}

func FuzzContentPlaintext(f *testing.F) {
	for _, raw := range []string{"", "text&amp;й", `<p:v/>middle<bare xmlns=""/>`, `<!--only--><?only pi?>`, `</xmlsec-context><evil/><xmlsec-context>`, "e\u0301"} {
		f.Add([]byte(raw))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			return
		}

		prefix, suffix := `<r xmlns="urn:r" xmlns:p="urn:p"><head>visible</head><box flag="public">`, `</box><tail/></r>`
		encrypted := authenticatedContent(t, raw, prefix, suffix)
		before := xmlBytes(t, encrypted)
		limits := document.DefaultLimits()
		limits.MaxBytes, limits.MaxNodes, limits.MaxDepth, limits.MaxAttributesPerElement = 4096, 64, 8, 8

		result, parent, err := xmlenc.DecryptContentWithKeyWrap(context.Background(), encrypted, encrypted.Root().Children()[1].Children()[0], make([]byte, 32), xmlenc.KeyWrapOptions{Data: xmlenc.Options{XMLLimits: limits}})
		if !bytes.Equal(before, xmlBytes(t, encrypted)) {
			t.Fatal("source snapshot mutated")
		}

		if err != nil {
			if result != nil || parent.Valid() || !errors.Is(err, xmlenc.ErrDecrypt) {
				t.Fatal("failure exposed a result", err)
			}

			return
		}

		want, err := document.Parse(t.Context(), []byte(prefix+string(raw)+suffix), document.DefaultLimits())
		if err != nil || !parent.Same(result.Root().Children()[1]) {
			t.Fatal("plaintext escaped its parent context", err)
		}

		sameXML(t, want, result)
	})
}

// Correctly authenticated bytes force XML processing, independently of tags.
func authenticatedContent(t testing.TB, raw []byte, prefix, suffix string) *document.Document {
	t.Helper()

	encrypted, err := xmlenc.EncryptBytesWithKeyWrap(context.Background(), raw, make([]byte, 32), xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	wire := bytes.Replace(xmlBytes(t, encrypted), []byte("<xenc:EncryptedData "), []byte(`<xenc:EncryptedData Type="`+xmlenc.ContentType+`" `), 1)

	wrapped := io.MultiReader(strings.NewReader(prefix), bytes.NewReader(wire), strings.NewReader(suffix))

	doc, err := document.ParseReader(t.Context(), wrapped, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	return doc
}

func TestECDHContent(t *testing.T) {
	for _, curve := range []ecdh.Curve{ecdh.P256(), ecdh.P384(), ecdh.P521()} {
		recipient := agreementKey(t, curve)
		for _, content := range []string{"", "й 😀 &amp; text", `before<p:v xmlns:p="urn:shadow">one</p:v><!--inside--><?inside ok?><bare xmlns=""/>after`} {
			t.Run(agreementCurveLabel(curve)+"/"+content, func(t *testing.T) {
				source := parse(t, []byte(`<?outside ok?><r xmlns="urn:r" xmlns:p="urn:p" xml:lang="ru"><head>visible</head><box flag="public">`+content+`</box><tail/></r><!--after-->`))
				before := xmlBytes(t, source)
				parent := source.Root().Children()[1]
				encrypted, handle, err := xmlenc.EncryptContentWithECDH(t.Context(), source, parent, recipient.PublicKey(), xmlenc.ECDHOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if !handle.Same(encrypted.Root().Children()[1].Children()[0]) {
					t.Fatal("wrong encrypted handle")
				}
				restored, restoredParent, err := xmlenc.DecryptContentWithECDH(t.Context(), encrypted, handle, recipient, xmlenc.ECDHOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if !restoredParent.Same(restored.Root().Children()[1]) {
					t.Fatal("wrong restored parent")
				}
				sameXML(t, source, restored)
				if !bytes.Equal(before, xmlBytes(t, source)) {
					t.Fatal("source mutated")
				}
				if out, handle, err := xmlenc.DecryptContentWithECDH(t.Context(), encrypted, encrypted.Root(), recipient, xmlenc.ECDHOptions{}); out != nil || handle.Valid() || err == nil {
					t.Fatal(out, handle, err)
				}
			})
		}
	}
}
