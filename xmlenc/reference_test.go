package xmlenc_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

const (
	nameCancel = "cancel"
	nameRsa    = "rsa"
)

type cipherReferenceProfile struct {
	mode   string
	rsaKey *rsa.PrivateKey
	secret []byte
}

func (p cipherReferenceProfile) encrypt(ctx context.Context, plain []byte) (*document.Document, error) {
	switch p.mode {
	case nameRsa:
		return xmlenc.EncryptBytes(ctx, plain, &p.rsaKey.PublicKey, xmlenc.Options{})
	case nameWrap:
		return xmlenc.EncryptBytesWithKeyWrap(ctx, plain, p.secret, xmlenc.KeyWrapOptions{})
	default:
		return xmlenc.EncryptBytesWithKey(ctx, plain, p.secret, xmlenc.SymmetricOptions{})
	}
}

func (p cipherReferenceProfile) decrypt(ctx context.Context, input *document.Document, options xmlenc.Options) ([]byte, error) {
	switch p.mode {
	case nameRsa:
		return xmlenc.DecryptBytes(ctx, input, p.rsaKey, options)
	case nameWrap:
		return xmlenc.DecryptBytesWithKeyWrap(ctx, input, p.secret, xmlenc.KeyWrapOptions{Data: options})
	default:
		return xmlenc.DecryptBytesWithKey(ctx, input, p.secret, xmlenc.SymmetricOptions{Data: options})
	}
}

type cipherReferenceFixture struct {
	profile  cipherReferenceProfile
	uri      string
	external *document.Document
	wire     []byte
	body     []byte
	plain    []byte
}

type resourceReader struct {
	io.Reader
	closed   bool
	closeErr error
}

func (r *resourceReader) Close() error { r.closed = true; return r.closeErr }

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type cipherReaderFunc func([]byte) (int, error)

func (f cipherReaderFunc) Read(p []byte) (int, error) { return f(p) }

type sizedCipherReader struct {
	io.ReadCloser
	size int64
}

func (r sizedCipherReader) Size() int64 { return r.size }

func TestCipherReferenceProfiles(t *testing.T) {
	ctx := t.Context()
	secret := bytes.Repeat([]byte{0x44}, 32)

	rsaKey := key(t)
	uri := "urn:example:ciphertext:1"

	for _, mode := range []string{nameRsa, nameWrap, "direct"} {
		profile := cipherReferenceProfile{mode: mode, rsaKey: rsaKey, secret: secret}
		for _, xml := range []bool{false, true} {
			checkCipherReferenceProfile(t, ctx, profile, uri, xml)
		}
	}
}

func TestCipherReferenceRejectsConcatenatedBase64Values(t *testing.T) {
	ctx := t.Context()
	secret := make([]byte, 32)
	const uri = "urn:example:base64-padding"
	encrypted, err := xmlenc.EncryptBytesWithKey(ctx, []byte("protected"), secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}
	external, _, body, err := xmlenc.ExternalizeCiphertext(ctx, encrypted, encrypted.Root(), uri)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := external.XML(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ref := `<xenc:CipherReference URI="` + uri + `"></xenc:CipherReference>`
	transformed := `<xenc:CipherReference URI="` + uri + `"><xenc:Transforms><ds:Transform Algorithm="` + xmlenc.SignatureNamespace + `base64"/></xenc:Transforms></xenc:CipherReference>`
	if !bytes.Contains(wire, []byte(ref)) {
		t.Fatal("missing reference")
	}
	external = parse(t, bytes.Replace(wire, []byte(ref), []byte(transformed), 1))
	options := xmlenc.SymmetricOptions{Data: xmlenc.Options{External: &xmlenc.ExternalCipherReference{
		URI: uri,
		Resolver: xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(io.MultiReader(
				strings.NewReader(base64.StdEncoding.EncodeToString(body[:1])),
				strings.NewReader(base64.StdEncoding.EncodeToString(body[1:])),
			)), nil
		}),
	}}}
	if out, err := xmlenc.DecryptBytesWithKey(ctx, external, secret, options); out != nil || err == nil {
		t.Fatalf("invalid Base64 framing accepted: plaintext=%q err=%v", out, err)
	}
}

func checkCipherReferenceProfile(t *testing.T, ctx context.Context, profile cipherReferenceProfile, uri string, xml bool) {
	t.Helper()

	plain := []byte("opaque\x00\xff")
	if xml {
		plain = []byte(`<r xmlns="urn:r"><v>é</v></r>`)
	}

	encrypted, err := profile.encrypt(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}

	before, _ := encrypted.XML(ctx)

	external, selected, body, err := xmlenc.ExternalizeCiphertext(ctx, encrypted, encrypted.Root(), uri)
	if err != nil || !selected.Same(external.Root()) {
		t.Fatal(err)
	}

	unchanged, _ := encrypted.XML(ctx)
	if !bytes.Equal(before, unchanged) {
		t.Fatal("source changed")
	}

	wire, _ := external.XML(ctx)
	fixture := cipherReferenceFixture{profile: profile, uri: uri, external: external, wire: wire, body: body, plain: plain}

	for _, transform := range []bool{false, true} {
		checkCipherReferenceTransform(t, ctx, fixture, transform)
	}
}

func checkCipherReferenceTransform(t *testing.T, ctx context.Context, fixture cipherReferenceFixture, transform bool) {
	t.Helper()

	input, resource := fixture.external, bytes.Clone(fixture.body)
	if transform {
		resource = []byte(" \n" + base64.StdEncoding.EncodeToString(fixture.body) + "\t\r")
		reference := `<xenc:CipherReference URI="` + fixture.uri + `"></xenc:CipherReference>`
		withTransform := `<xenc:CipherReference URI="` + fixture.uri + `"><xenc:Transforms><ds:Transform Algorithm="` + xmlenc.SignatureNamespace + `base64"/></xenc:Transforms></xenc:CipherReference>`

		if !bytes.Contains(fixture.wire, []byte(reference)) {
			t.Fatal("missing generated reference")
		}

		input = parse(t, bytes.Replace(fixture.wire, []byte(reference), []byte(withTransform), 1))
	}

	options := externalOptions(fixture.uri, resource)
	if out, err := fixture.profile.decrypt(ctx, input, options); err != nil || !bytes.Equal(out, fixture.plain) {
		t.Fatal(fixture.profile.mode, err)
	}

	if out, err := fixture.profile.decrypt(ctx, input, xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal("default external access enabled", err)
	}

	resource[len(resource)/2] ^= 1
	if out, err := fixture.profile.decrypt(ctx, input, externalOptions(fixture.uri, resource)); out != nil || err == nil {
		t.Fatal("changed resource accepted")
	}
}

func TestCipherReferenceSelectedSnapshots(t *testing.T) {
	ctx := t.Context()
	secret := bytes.Repeat([]byte{0x51}, 32)
	uri := "https://example.invalid/encrypted/1"
	source := parse(t, []byte(`<?before ok?><r xmlns="urn:r" xmlns:p="urn:p"><box>text<p:v>é</p:v><!--inside--></box><tail/></r>`))
	before, _ := source.XML(ctx)

	for _, content := range []bool{false, true} {
		var (
			encrypted, restored *document.Document
			node                document.Element
			err                 error
		)
		if content {
			encrypted, node, err = xmlenc.EncryptContentWithKey(ctx, source, source.Root().Children()[0], secret, xmlenc.SymmetricOptions{})
		} else {
			encrypted, node, err = xmlenc.EncryptElementWithKey(ctx, source, source.Root().Children()[0], secret, xmlenc.SymmetricOptions{})
		}

		if err != nil {
			t.Fatal(err)
		}

		external, handle, body, err := xmlenc.ExternalizeCiphertext(ctx, encrypted, node, uri)
		if err != nil {
			t.Fatal(err)
		}

		options := xmlenc.SymmetricOptions{Data: externalOptions(uri, body)}
		if content {
			restored, _, err = xmlenc.DecryptContentWithKey(ctx, external, handle, secret, options)
		} else {
			restored, _, err = xmlenc.DecryptElementWithKey(ctx, external, handle, secret, options)
		}

		if err != nil {
			t.Fatal(err)
		}

		got, _ := restored.XML(ctx)
		if !bytes.Equal(before, got) {
			t.Fatal("context changed", string(got))
		}

		if d, h, b, err := xmlenc.ExternalizeCiphertext(ctx, encrypted, source.Root(), uri); d != nil || h.Valid() || b != nil || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatal("foreign handle accepted", err)
		}

		if d, h, b, err := xmlenc.ExternalizeCiphertext(ctx, external, handle, uri); d != nil || h.Valid() || b != nil || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatal("external reference externalized again", err)
		}
	}
}

func TestCipherReferenceRejectsBeforeIO(t *testing.T) {
	ctx := t.Context()
	secret := make([]byte, 32)
	uri := "urn:example:1"

	d, err := xmlenc.EncryptBytesWithKey(ctx, []byte("protected"), secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}

	d, _, _, err = xmlenc.ExternalizeCiphertext(ctx, d, d.Root(), uri)
	if err != nil {
		t.Fatal(err)
	}

	wire, _ := d.XML(ctx)
	ref := `<xenc:CipherReference URI="urn:example:1"></xenc:CipherReference>`
	calls := 0
	options := xmlenc.SymmetricOptions{Data: xmlenc.Options{External: &xmlenc.ExternalCipherReference{URI: uri, Resolver: xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return nil, errors.New("unexpected resolver call")
	})}}}

	for _, replacement := range []string{
		`<xenc:CipherReference URI="urn:example:2"/>`,
		`<xenc:CipherReference URI="urn:example:1" bad="1"/>`,
		`<xenc:CipherReference URI="urn:example:1">bad</xenc:CipherReference>`,
		`<xenc:CipherReference URI="urn:example:1"><ds:Transforms/></xenc:CipherReference>`,
		`<xenc:CipherReference URI="urn:example:1"><xenc:Transforms/></xenc:CipherReference>`,
		`<xenc:CipherReference URI="urn:example:1"><xenc:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"/></xenc:Transforms></xenc:CipherReference>`,
		`<xenc:CipherReference URI="urn:example:1"><xenc:Transforms><ds:Transform Algorithm="` + xmlenc.SignatureNamespace + `base64"><bad/></ds:Transform></xenc:Transforms></xenc:CipherReference>`,
		`<xenc:CipherReference URI="urn:example:1"><xenc:Transforms><ds:Transform Algorithm="` + xmlenc.SignatureNamespace + `base64"/><ds:Transform Algorithm="` + xmlenc.SignatureNamespace + `base64"/></xenc:Transforms></xenc:CipherReference>`,
	} {
		if !bytes.Contains(wire, []byte(ref)) {
			t.Fatal("ineffective control")
		}

		bad := parse(t, bytes.Replace(wire, []byte(ref), []byte(replacement), 1))
		if out, err := xmlenc.DecryptBytesWithKey(ctx, bad, secret, options); out != nil || err == nil {
			t.Fatal("malformed reference accepted")
		}
	}

	if calls != 0 {
		t.Fatal("resolver invoked before format/policy validation")
	}

	for _, uri := range []string{"", "relative", "#id", "https://user:password@example.invalid/a", "urn:a#", "urn:a\n", "urn:a\\b", strings.Repeat("a", 4097)} {
		opts := options

		opts.Data.External = &xmlenc.ExternalCipherReference{URI: uri, Resolver: options.Data.External.Resolver}
		if out, err := xmlenc.DecryptBytesWithKey(ctx, d, secret, opts); out != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("invalid URI accepted", err)
		}
	}

	var nilResolver xmlenc.CipherResolverFunc
	for _, p := range []*xmlenc.ExternalCipherReference{{URI: uri}, {URI: uri, Resolver: nilResolver}, {URI: uri, Resolver: options.Data.External.Resolver, MaxBytes: -1}, {URI: uri, Resolver: options.Data.External.Resolver, MaxBytes: (64 << 20) + 1}} {
		if out, err := xmlenc.DecryptBytesWithKey(ctx, d, secret, xmlenc.SymmetricOptions{Data: xmlenc.Options{External: p}}); out != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("invalid resolver options accepted", err)
		}
	}
}

func TestCipherReferenceReaderLifecycle(t *testing.T) {
	ctx := t.Context()
	secret := make([]byte, 32)
	uri := "urn:example:1"

	d, err := xmlenc.EncryptBytesWithKey(ctx, []byte("protected"), secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}

	d, _, body, err := xmlenc.ExternalizeCiphertext(ctx, d, d.Root(), uri)
	if err != nil {
		t.Fatal(err)
	}

	failure := errors.New("reader failure")

	for _, kind := range []string{"ok", "resolve", nameNil, "read", "close", nameLimit, nameCancel} {
		t.Run(kind, func(t *testing.T) {
			testCipherReferenceReaderLifecycleCase(t, ctx, body, kind, failure, uri, d, secret)
		})
	}
}

func testCipherReferenceReaderLifecycleCase(t *testing.T, ctx context.Context, body []byte, kind string, failure error, uri string, d *document.Document, secret []byte) {
	t.Helper()

	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	r := &resourceReader{Reader: bytes.NewReader(body)}
	limit := len(body)

	if kind == "read" {
		r.Reader = errorReader{failure}
	}

	if kind == "close" {
		r.closeErr = failure
	}

	if kind == nameLimit {
		limit--
	}

	options := xmlenc.SymmetricOptions{Data: xmlenc.Options{External: &xmlenc.ExternalCipherReference{URI: uri, MaxBytes: limit, Resolver: xmlenc.CipherResolverFunc(func(got context.Context, gotURI string) (io.ReadCloser, error) {
		if got != callCtx || gotURI != uri {
			t.Fatal("resolver arguments changed")
		}

		if kind == nameCancel {
			cancel()
		}

		if kind == "resolve" {
			return r, failure
		}

		if kind == nameNil {
			var absent *resourceReader
			return absent, nil
		}

		return r, nil
	})}}}

	out, err := xmlenc.DecryptBytesWithKey(callCtx, d, secret, options)
	if kind == "ok" {
		if err != nil || string(out) != "protected" {
			t.Fatal(err)
		}
	} else {
		if out != nil || err == nil {
			t.Fatal("failed resource returned plaintext")
		}

		expected := xmlenc.ErrResource
		if kind == nameLimit {
			expected = xmlenc.ErrPolicy
		}

		if kind == nameCancel {
			expected = context.Canceled
		}

		if !errors.Is(err, expected) {
			t.Fatal(err)
		}
	}

	if kind != nameNil && !r.closed {
		t.Fatal("reader leaked")
	}
}

func TestCipherReferenceRejectsNonProgressingReader(t *testing.T) {
	reads := 0
	exhausted := errors.New("reader exceeded test bound")
	source := &resourceReader{Reader: cipherReaderFunc(func([]byte) (int, error) {
		reads++
		if reads > 200 {
			return 0, exhausted
		}

		return 0, nil
	})}

	plain, err := decryptReader(t, source)
	if plain != nil || !errors.Is(err, io.ErrNoProgress) || !source.closed || reads > 100 {
		t.Fatalf("plaintext=%x err=%v closed=%v reads=%d", plain, err, source.closed, reads)
	}
}

func TestCipherReferenceRejectsInvalidReaderCount(t *testing.T) {
	source := &resourceReader{Reader: cipherReaderFunc(func(p []byte) (int, error) { return len(p) + 1, nil })}

	defer func() {
		if value := recover(); value != nil {
			t.Errorf("reader caused panic: %v", value)
		}
	}()

	plain, err := decryptReader(t, source)
	if plain != nil || !errors.Is(err, io.ErrShortBuffer) || !source.closed {
		t.Fatalf("plaintext=%x err=%v closed=%v", plain, err, source.closed)
	}
}

func TestCipherReferencePreservesReadAndCloseErrors(t *testing.T) {
	readErr, closeErr := errors.New("read failed"), errors.New("close failed")
	source := &resourceReader{Reader: cipherReaderFunc(func([]byte) (int, error) { return 0, readErr }), closeErr: closeErr}

	plain, err := decryptReader(t, source)
	if plain != nil || !errors.Is(err, xmlenc.ErrResource) || !errors.Is(err, readErr) || !errors.Is(err, closeErr) || !source.closed {
		t.Fatalf("plaintext=%x err=%v closed=%v", plain, err, source.closed)
	}
}

func TestCipherReferenceRetainsErrorOnFullChunk(t *testing.T) {
	secret := make([]byte, 32)
	plaintext := bytes.Repeat([]byte("x"), (32<<10)-28) // Ciphertext fills one collection chunk exactly.

	encrypted, err := xmlenc.EncryptBytesWithKey(t.Context(), plaintext, secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}

	const uri = "urn:review:full-chunk"

	external, _, ciphertext, err := xmlenc.ExternalizeCiphertext(t.Context(), encrypted, encrypted.Root(), uri)
	if err != nil {
		t.Fatal(err)
	}

	failure := errors.New("final read failed")
	input := bytes.NewReader(ciphertext)
	source := &resourceReader{Reader: cipherReaderFunc(func(dst []byte) (int, error) {
		n, err := input.Read(dst)
		if input.Len() == 0 && n > 0 {
			err = failure
		}

		return n, err
	})}

	options := xmlenc.SymmetricOptions{Data: xmlenc.Options{External: &xmlenc.ExternalCipherReference{URI: uri, Resolver: xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) { return source, nil })}}}
	if got, err := xmlenc.DecryptBytesWithKey(t.Context(), external, secret, options); got != nil || !errors.Is(err, failure) || !source.closed {
		t.Fatal("resource failure yielded plaintext", len(got), err, source.closed)
	}
}

func externalOptions(uri string, body []byte) xmlenc.Options {
	return xmlenc.Options{External: &xmlenc.ExternalCipherReference{
		URI: uri,
		Resolver: xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}),
	}}
}

func decryptReader(t *testing.T, source io.ReadCloser) ([]byte, error) {
	t.Helper()

	key := make([]byte, 32)

	encrypted, err := xmlenc.EncryptBytesWithKey(t.Context(), []byte("secret"), key, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}

	const uri = "urn:review:ciphertext"

	external, _, _, err := xmlenc.ExternalizeCiphertext(t.Context(), encrypted, encrypted.Root(), uri)
	if err != nil {
		t.Fatal(err)
	}

	return xmlenc.DecryptBytesWithKey(t.Context(), external, key, xmlenc.SymmetricOptions{Data: xmlenc.Options{External: &xmlenc.ExternalCipherReference{URI: uri, Resolver: xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) { return source, nil })}}})
}

func graphXML(t *testing.T, doc *document.Document) string {
	t.Helper()
	wire, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return string(wire)
}

func graphData(t *testing.T, secret []byte, info string) *document.Document {
	t.Helper()
	doc, err := xmlenc.EncryptBytesWithKey(t.Context(), []byte("graph payload\x00\xff"), secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wire := strings.Replace(graphXML(t, doc), "<xenc:EncryptedData ", `<xenc:EncryptedData Id="data" `, 1)
	if info != "" {
		wire = strings.Replace(wire, "<xenc:CipherData>", `<ds:KeyInfo xmlns:ds="`+xmlenc.SignatureNamespace+`">`+info+`</ds:KeyInfo><xenc:CipherData>`, 1)
	}
	return parse(t, []byte(wire))
}

func graphWrap(t *testing.T, secret, kek []byte, name, carried, id string, refs []xmlenc.KeyGraphReference) *document.Document {
	t.Helper()
	doc, err := xmlenc.EncryptKey(t.Context(), secret, xmlenc.KeyGraphKey{Name: name, Algorithm: xmlenc.AES256KeyWrap, Secret: kek}, xmlenc.EncryptedKeyOptions{Algorithm: xmlenc.AES256KeyWrap, ID: id, CarriedKeyName: carried, References: refs})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func graphAssert(t *testing.T, doc *document.Document, selected document.Element, options xmlenc.KeyGraphOptions) {
	t.Helper()
	before := graphXML(t, doc)
	got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), doc, selected, options)
	if err != nil || string(got) != "graph payload\x00\xff" {
		t.Fatalf("graph plaintext %q: %v", got, err)
	}
	if graphXML(t, doc) != before {
		t.Fatal("graph changed source snapshot")
	}
}

func TestKeyGraphRelationships(t *testing.T) {
	secret, kek := bytes.Repeat([]byte{0x52}, 32), bytes.Repeat([]byte{0x93}, 32)
	options := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}}
	wrapped := graphWrap(t, secret, kek, "master", "session", "key", nil)
	for _, kind := range []string{"inline", "retrieval", "carried", "data-reference", "standalone"} {
		t.Run(kind, func(t *testing.T) {
			info := graphXML(t, wrapped)
			sibling := ""
			opts := options
			switch kind {
			case "retrieval":
				info = `<ds:RetrievalMethod URI="#key" Type="` + xmlenc.Namespace + `EncryptedKey"/>`
				sibling = graphXML(t, wrapped)
			case "carried":
				info = `<ds:KeyName>session</ds:KeyName>`
				sibling = graphXML(t, wrapped)
			case "data-reference":
				info = ""
				sibling = graphXML(t, graphWrap(t, secret, kek, "master", "", "key", []xmlenc.KeyGraphReference{{URI: "#data"}}))
			case "standalone":
				info = ""
				sibling = graphXML(t, wrapped)
				opts.KeyURIs = []string{"#key"}
			}
			data := graphData(t, secret, info)
			if sibling == "" {
				graphAssert(t, data, data.Root(), opts)
				return
			}
			envelope := parse(t, []byte("<r>"+graphXML(t, data)+sibling+"</r>"))
			graphAssert(t, envelope, envelope.Root().Children()[0], opts)
		})
	}
	t.Run("nested wrapping via KeyReference", func(t *testing.T) {
		intermediate := bytes.Repeat([]byte{0x71}, 32)
		outer := graphWrap(t, intermediate, kek, "master", "", "outer", []xmlenc.KeyGraphReference{{URI: "#inner", Key: true}})
		inner := graphWrap(t, secret, intermediate, "", "", "inner", nil)
		data := graphData(t, secret, `<ds:RetrievalMethod URI="#inner"/>`)
		doc := parse(t, []byte("<r>"+graphXML(t, data)+graphXML(t, inner)+graphXML(t, outer)+"</r>"))
		graphAssert(t, doc, doc.Root().Children()[0], options)
	})
	t.Run("consistent paths", func(t *testing.T) {
		info := `<ds:KeyName>direct</ds:KeyName>` + graphXML(t, wrapped)
		data := graphData(t, secret, info)
		opts := options
		opts.Keys = append(append([]xmlenc.KeyGraphKey(nil), options.Keys...), xmlenc.KeyGraphKey{Name: "direct", Algorithm: xmlenc.AES256GCM, Secret: secret})
		graphAssert(t, data, data.Root(), opts)
		opts.Keys[1].Secret = bytes.Repeat([]byte{0x11}, 32)
		if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), data, data.Root(), opts); got != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
			t.Fatal("conflicting authorized paths accepted", err)
		}
	})
}

func TestKeyGraphOmittedEncryptionMethod(t *testing.T) {
	secret, kek := bytes.Repeat([]byte{0x52}, 32), bytes.Repeat([]byte{0x93}, 32)
	for _, tc := range []struct {
		name, keyName string
		keys          []xmlenc.KeyGraphKey
		algorithms    []string
		want          error
	}{
		{"named binding", "master", []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}, nil, nil},
		{"name selects between algorithms", "master", []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}, {Name: "other", Algorithm: xmlenc.AES128KeyWrap, Secret: kek[:16]}}, nil, nil},
		{"unnamed binding", "", []xmlenc.KeyGraphKey{{Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}, nil, nil},
		{"same name ambiguous algorithms", "master", []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}, {Name: "master", Algorithm: xmlenc.AES128KeyWrap, Secret: kek[:16]}}, nil, xmlenc.ErrPolicy},
		{"policy fallback needs matching key", "missing", []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}, nil, xmlenc.ErrPolicy},
		{"ambiguous policy fallback", "master", nil, []string{xmlenc.AES128KeyWrap, xmlenc.AES256KeyWrap}, xmlenc.ErrPolicy},
		{"KDF is not a wrapping algorithm", "master", nil, []string{xmlenc.ConcatKDF}, xmlenc.ErrPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := graphWrap(t, secret, kek, tc.keyName, "", "key", nil)
			wire := graphXML(t, wrapped)
			start := strings.Index(wire, "<xenc:EncryptionMethod")
			const endTag = "</xenc:EncryptionMethod>"
			end := strings.Index(wire, endTag)
			if start < 0 || end < start {
				t.Fatal("generated fixture lacks EncryptionMethod")
			}
			wire = wire[:start] + wire[end+len(endTag):]
			data := graphData(t, secret, wire)
			options := xmlenc.KeyGraphOptions{Keys: tc.keys, KeyAlgorithms: tc.algorithms}
			if tc.want == nil {
				graphAssert(t, data, data.Root(), options)
				return
			}
			before := graphXML(t, data)
			if plain, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), data, data.Root(), options); plain != nil || !errors.Is(err, tc.want) {
				t.Fatalf("omitted method: %x, %v; want %v", plain, err, tc.want)
			}
			if graphXML(t, data) != before {
				t.Fatal("failed key resolution changed input")
			}
		})
	}
}

func TestKeyGraphDerivedKey(t *testing.T) {
	t.Run("OpenSSL aligned known vector", func(t *testing.T) {
		master := []byte("secret")
		parameters := xmlenc.ConcatKDFParameters{AlgorithmID: append([]byte{0}, []byte("algorithm")...), PartyUInfo: append([]byte{0}, []byte("party-u")...), PartyVInfo: append([]byte{0}, []byte("party-v")...)}
		// OpenSSL SSKDF/SHA256 counter1 output, independent of this implementation.
		secret, err := hex.DecodeString("decd092d8d48598e451375077940a69c91f27e53faa451bfd3eef6d0dec2a780")
		if err != nil {
			t.Fatal(err)
		}
		derived, err := xmlenc.BuildDerivedKey(t.Context(), xmlenc.DerivedKeyOptions{Parameters: parameters, MasterKeyName: "master"})
		if err != nil {
			t.Fatal(err)
		}
		data := graphData(t, secret, graphXML(t, derived))
		graphAssert(t, data, data.Root(), xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.ConcatKDF, Secret: master}}, ConcatKDF: &parameters})
	})
	master := bytes.Repeat([]byte{0x18}, 32)
	parameters := xmlenc.ConcatKDFParameters{AlgorithmID: append([]byte{0}, []byte(xmlenc.AES256GCM)...), PartyUInfo: []byte{3, 0xd8}, PartyVInfo: []byte{0, 0x71}}
	if fips140.Enabled() {
		if got, err := xmlenc.DeriveConcatKey(t.Context(), master, 256, parameters); got != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("non-octet KDF escaped FIPS policy", err)
		}
		parameters.PartyUInfo = []byte{0, 0xd8}
	}
	secret, err := xmlenc.DeriveConcatKey(t.Context(), master, 256, parameters)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := xmlenc.BuildDerivedKey(t.Context(), xmlenc.DerivedKeyOptions{Parameters: parameters, ID: "derived", MasterKeyName: "master", DerivedKeyName: "session"})
	if err != nil {
		t.Fatal(err)
	}
	data := graphData(t, secret, graphXML(t, derived))
	opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.ConcatKDF, Secret: master}}, ConcatKDF: &parameters}
	graphAssert(t, data, data.Root(), opts)
	t.Run("expected context binding", func(t *testing.T) {
		bad := parameters
		bad.PartyVInfo = []byte{0, 0x72}
		opts.ConcatKDF = &bad
		if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), data, data.Root(), opts); got != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("unbound KDF context accepted", err)
		}
	})
	t.Run("encrypted master", func(t *testing.T) {
		kek := bytes.Repeat([]byte{0x67}, 32)
		wrapped := graphWrap(t, master, kek, "kek", "master", "wrapped-master", nil)
		doc := parse(t, []byte("<r>"+graphXML(t, data)+graphXML(t, wrapped)+"</r>"))
		opts.Keys = []xmlenc.KeyGraphKey{{Name: "kek", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}
		opts.KeyAlgorithms = []string{xmlenc.ConcatKDF}
		opts.ConcatKDF = &parameters
		graphAssert(t, doc, doc.Root().Children()[0], opts)
	})
}

func TestKeyGraphCipherReferences(t *testing.T) {
	secret := bytes.Repeat([]byte{0x31}, 32)
	opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Algorithm: xmlenc.AES256GCM, Secret: secret}}}
	data := graphData(t, secret, "")
	value := data.Root().Children()[1].Children()[0].Text()
	wire := strings.Replace(graphXML(t, data), `<xenc:CipherValue>`+value+`</xenc:CipherValue>`, `<xenc:CipherReference URI="#blob"><xenc:Transforms><ds:Transform xmlns:ds="`+xmlenc.SignatureNamespace+`" Algorithm="`+xmlenc.SignatureNamespace+`base64"/></xenc:Transforms></xenc:CipherReference>`, 1)
	doc := parse(t, []byte(`<r><blob xml:id="blob">`+value+`</blob>`+wire+`</r>`))
	graphAssert(t, doc, doc.Root().Children()[1], opts)
	t.Run("empty same-document URI", func(t *testing.T) {
		whole := parse(t, []byte(strings.Replace(graphXML(t, doc), `URI="#blob"`, `URI=""`, 1)))
		graphAssert(t, whole, whole.Root().Children()[1], opts)
	})
	t.Run("duplicate IDs", func(t *testing.T) {
		duplicate := parse(t, []byte(strings.Replace(graphXML(t, doc), "</r>", `<other xml:id="blob"/></r>`, 1)))
		if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), duplicate, duplicate.Root().Children()[1], opts); got != nil || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatal("duplicate ID accepted", err)
		}
	})
	t.Run("unsafe transform", func(t *testing.T) {
		unsafe := parse(t, []byte(strings.Replace(graphXML(t, doc), xmlenc.SignatureNamespace+"base64", xmlenc.SignatureNamespace+"enveloped-signature", 1)))
		if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), unsafe, unsafe.Root().Children()[1], opts); got != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("unexpected transform accepted", err)
		}
	})
}

func TestKeyGraphExternalResources(t *testing.T) {
	secret, kek := bytes.Repeat([]byte{0x40}, 32), bytes.Repeat([]byte{0x41}, 32)
	data := graphData(t, secret, `<ds:RetrievalMethod URI="keys.xml#key"/>`)
	keydoc := graphWrap(t, secret, kek, "kek", "", "key", nil)
	calls := 0
	reader := &resourceReader{Reader: strings.NewReader(graphXML(t, keydoc))}
	options := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "kek", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}, External: &xmlenc.KeyGraphResources{BaseURI: "https://example.test/data.xml", AllowedURIs: []string{"https://example.test/keys.xml"}, Resolver: xmlenc.CipherResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		calls++
		if uri != "https://example.test/keys.xml" {
			t.Fatal(uri)
		}
		return reader, nil
	})}}
	graphAssert(t, data, data.Root(), options)
	if calls != 1 || !reader.closed {
		t.Fatal("external key lifecycle", calls, reader.closed)
	}
	options.External.AllowedURIs = nil
	calls = 0
	if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), data, data.Root(), options); got != nil || !errors.Is(err, xmlenc.ErrPolicy) || calls != 0 {
		t.Fatal("unapproved key I/O", err, calls)
	}
}

func TestKeyGraphSharesExternalResourceBudget(t *testing.T) {
	secret, kek := bytes.Repeat([]byte{0x61}, 32), bytes.Repeat([]byte{0x62}, 32)
	const keyURI = "https://example.test/graph/key.xml"
	const cipherURI = "https://example.test/graph/data.bin"
	wrapped := graphWrap(t, secret, kek, "master", "session", "key", nil)
	data := graphData(t, secret, `<ds:RetrievalMethod URI="`+keyURI+`#key"/>`)
	external, selected, ciphertext, err := xmlenc.ExternalizeCiphertext(t.Context(), data, data.Root(), cipherURI)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		maximum    int
		standalone bool
		pass       bool
	}{
		{"two resources fit exact quota", 2, false, true},
		{"key and cipher cannot each claim a separate quota", 1, false, false},
		{"cached key reference consumes no second resource", 2, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyReads, cipherReads := 0, 0
			keyBody := &resourceReader{Reader: strings.NewReader(graphXML(t, wrapped))}
			cipherBody := &resourceReader{Reader: bytes.NewReader(ciphertext)}
			options := xmlenc.KeyGraphOptions{
				Keys:   []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}},
				Limits: xmlenc.KeyGraphLimits{MaxResources: tc.maximum},
				External: &xmlenc.KeyGraphResources{AllowedURIs: []string{keyURI}, Resolver: xmlenc.CipherResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
					keyReads++
					if uri != keyURI {
						t.Fatal("unexpected key resource", uri)
					}
					return keyBody, nil
				})},
				Data: xmlenc.Options{External: &xmlenc.ExternalCipherReference{URI: cipherURI, Resolver: xmlenc.CipherResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
					cipherReads++
					if uri != cipherURI {
						t.Fatal("unexpected ciphertext resource", uri)
					}
					return cipherBody, nil
				})}},
			}
			if tc.standalone {
				options.KeyURIs = []string{keyURI + "#key"}
			}
			before := graphXML(t, external)
			plain, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), external, selected, options)
			if tc.pass {
				if err != nil || string(plain) != "graph payload\x00\xff" || cipherReads != 1 || !cipherBody.closed {
					t.Fatal("exact shared resource quota failed", cipherReads, cipherBody.closed, err)
				}
			} else if plain != nil || !errors.Is(err, document.ErrLimit) || !errors.Is(err, xmlenc.ErrPolicy) || cipherReads != 0 || cipherBody.closed {
				t.Fatal("resource quota returned partial plaintext or performed forbidden I/O", plain, cipherReads, cipherBody.closed, err)
			}
			if keyReads != 1 || !keyBody.closed || graphXML(t, external) != before {
				t.Fatal("key resource was reloaded, leaked, or mutated the source", keyReads, keyBody.closed)
			}
		})
	}
}

func TestKeyGraphMetadataAndGuards(t *testing.T) {
	secret := bytes.Repeat([]byte{0x19}, 32)
	opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Algorithm: xmlenc.AES256GCM, Secret: secret}}}
	data := graphData(t, secret, "")
	wire := graphXML(t, data)
	method := `<xenc:EncryptionMethod Algorithm="` + xmlenc.AES256GCM + `"></xenc:EncryptionMethod>`
	for _, kind := range []string{"method omitted", "opaque type", "properties"} {
		t.Run(kind, func(t *testing.T) {
			variant := wire
			switch kind {
			case "method omitted":
				variant = strings.Replace(variant, method, "", 1)
				if variant == wire {
					t.Fatal("method removal did not change fixture")
				}
			case "opaque type":
				variant = strings.Replace(variant, `Id="data"`, `Id="data" Type="urn:custom" MimeType="application/gzip" Encoding="urn:opaque"`, 1)
			case "properties":
				variant = strings.Replace(variant, "</xenc:EncryptedData>", `<xenc:EncryptionProperties Id="props"><xenc:EncryptionProperty Target="#data"><app:note xmlns:app="urn:app">hint</app:note></xenc:EncryptionProperty></xenc:EncryptionProperties></xenc:EncryptedData>`, 1)
			}
			doc := parse(t, []byte(variant))
			graphAssert(t, doc, doc.Root(), opts)
			if got, err := xmlenc.DecryptDocumentWithKeyGraph(t.Context(), doc, doc.Root(), opts); got != nil || !errors.Is(err, xmlenc.ErrFormat) {
				t.Fatal("opaque bytes entered XML API", err)
			}
		})
	}
	for _, kind := range []string{"duplicate bindings", "typed nil", "nodes", "bytes", "cancel", "foreign selected"} {
		t.Run(kind, func(t *testing.T) {
			options := opts
			ctx := t.Context()
			selected := data.Root()
			want := xmlenc.ErrPolicy
			switch kind {
			case "duplicate bindings":
				options.Keys = append(append([]xmlenc.KeyGraphKey(nil), opts.Keys...), opts.Keys...)
			case "typed nil":
				var provider *rsa.PrivateKey
				options.Keys = []xmlenc.KeyGraphKey{{Algorithm: xmlenc.AES256GCM, Secret: secret, Decrypter: provider}}
			case "nodes":
				options.Limits.MaxNodes = 1
			case "bytes":
				options.Limits.MaxBytes = 1
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "foreign selected":
				selected = graphData(t, secret, "").Root()
				want = xmlenc.ErrFormat
			}
			if got, err := xmlenc.DecryptBytesWithKeyGraph(ctx, data, selected, options); got != nil || !errors.Is(err, want) {
				t.Fatal("graph guard", kind, err)
			}
		})
	}
}

func TestKeyGraphDependencyGuards(t *testing.T) {
	secret, kek := bytes.Repeat([]byte{0x40}, 32), bytes.Repeat([]byte{0x41}, 32)
	keydoc := graphWrap(t, secret, kek, "master", "loop", "key", nil)
	wire := strings.Replace(graphXML(t, keydoc), "<ds:KeyName>master</ds:KeyName>", "<ds:KeyName>loop</ds:KeyName>", 1)
	data := graphData(t, secret, wire)
	options := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}}
	if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), data, data.Root(), options); got != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("cycle accepted", err)
	}
	t.Run("depth", func(t *testing.T) {
		options.Limits.MaxDepth = 1
		outer := graphWrap(t, kek, kek, "master", "intermediate", "outer", nil)
		inner := graphWrap(t, secret, kek, "intermediate", "session", "inner", nil)
		data := graphData(t, secret, `<ds:KeyName>session</ds:KeyName>`)
		doc := parse(t, []byte("<r>"+graphXML(t, data)+graphXML(t, inner)+graphXML(t, outer)+"</r>"))
		if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), doc, doc.Root().Children()[0], options); got != nil || !errors.Is(err, document.ErrLimit) {
			t.Fatal("dependency depth accepted", err)
		}
	})
}

func TestKeyGraphXMLRestoration(t *testing.T) {
	secret := bytes.Repeat([]byte{0x33}, 32)
	source := parse(t, []byte(`<r xmlns:p="urn:p"><p:a>value</p:a><tail/></r>`))
	options := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Algorithm: xmlenc.AES256GCM, Secret: secret}}}
	encrypted, selected, err := xmlenc.EncryptElementWithKey(t.Context(), source, source.Root().Children()[0], secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}
	restored, element, err := xmlenc.DecryptElementWithKeyGraph(t.Context(), encrypted, selected, options)
	if err != nil || element.Name() != (document.Name{Space: "urn:p", Local: "a"}) || len(restored.Root().Children()) != 2 {
		t.Fatal("element restoration", err)
	}
	content, selected, err := xmlenc.EncryptContentWithKey(t.Context(), source, source.Root(), secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}
	restored, parent, err := xmlenc.DecryptContentWithKeyGraph(t.Context(), content, selected, options)
	if err != nil || !parent.Same(restored.Root()) || len(parent.Children()) != 2 {
		t.Fatal("content restoration", err)
	}
	if got, _, err := xmlenc.DecryptElementWithKeyGraph(t.Context(), content, selected, options); got != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("content accepted as element", err)
	}
	standalone, err := xmlenc.EncryptDocumentWithKey(t.Context(), source, secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := xmlenc.DecryptDocumentWithKeyGraph(t.Context(), standalone, standalone.Root(), options)
	if err != nil || plain.Root().Name() != source.Root().Name() {
		t.Fatal("document restoration", err)
	}
}

func TestKeyGraphAuthenticatedPlaintextGrammar(t *testing.T) {
	secret := bytes.Repeat([]byte{0x72}, 32)
	for _, tc := range []struct {
		name             string
		plain            []byte
		element, content bool
		maximumDepth     int
	}{
		{"single element", []byte(`<a>value</a>`), true, true, 0},
		{"multiple elements are content", []byte(`<a/><b/>`), false, true, 0},
		{"mixed content", []byte(`before<a/>after`), false, true, 0},
		{"empty content", []byte{}, false, true, 0},
		{"comment and element are content", []byte(`<!--note--><a/>`), false, true, 0},
		{"invalid UTF8", []byte{'<', 'a', '>', 0xff, '<', '/', 'a', '>'}, false, false, 0},
		{"non NFC text", []byte("<a>e\u0301</a>"), false, false, 0},
		{"broken XML", []byte(`<a>`), false, false, 0},
		{"unbound namespace prefix", []byte(`<p:a/>`), false, false, 0},
		{"document declaration", []byte(`<?xml version="1.0"?><a/>`), false, false, 0},
		{"DTD declaration", []byte(`<!DOCTYPE a><a/>`), false, false, 0},
		{"nested XML at depth limit", []byte(`<a><b/></a>`), true, true, 2},
		{"decrypted XML exceeds depth", []byte(`<a><b/></a>`), false, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := xmlenc.EncryptBytesWithKey(t.Context(), tc.plain, secret, xmlenc.SymmetricOptions{})
			if err != nil {
				t.Fatal(err)
			}
			wire := graphXML(t, encrypted)
			typed := func(typ string) string {
				changed := strings.Replace(wire, "<xenc:EncryptedData ", `<xenc:EncryptedData Type="`+typ+`" `, 1)
				if changed == wire {
					t.Fatal("missing EncryptedData type mutation")
				}
				return changed
			}
			options := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Algorithm: xmlenc.AES256GCM, Secret: secret}}}
			if tc.maximumDepth > 0 {
				options.Data.XMLLimits = document.DefaultLimits()
				options.Data.XMLLimits.MaxDepth = tc.maximumDepth
			}
			elementEnvelope := parse(t, []byte(typed(xmlenc.ElementType)))
			// GCM authentication and exact byte recovery succeed even when XML parsing
			// must fail. Type metadata does not transcode or normalize byte results.
			if raw, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), elementEnvelope, elementEnvelope.Root(), options); err != nil || !bytes.Equal(raw, tc.plain) {
				t.Fatal("authenticated plaintext control failed", err)
			}
			standalone, err := xmlenc.DecryptDocumentWithKeyGraph(t.Context(), elementEnvelope, elementEnvelope.Root(), options)
			if tc.element {
				if standalone == nil || err != nil {
					t.Fatal("valid standalone element rejected", err)
				}
				sameXML(t, parse(t, tc.plain), standalone)
			} else if standalone != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
				t.Fatal("invalid XML entered standalone graph API", standalone != nil, err)
			}
			for _, content := range []bool{false, true} {
				typ, valid := xmlenc.ElementType, tc.element
				if content {
					typ, valid = xmlenc.ContentType, tc.content
				}
				container := parse(t, []byte(`<r><before/>`+typed(typ)+`<after/></r>`))
				before := graphXML(t, container)
				selected := container.Root().Children()[1]
				var restored *document.Document
				var handle document.Element
				if content {
					restored, handle, err = xmlenc.DecryptContentWithKeyGraph(t.Context(), container, selected, options)
				} else {
					restored, handle, err = xmlenc.DecryptElementWithKeyGraph(t.Context(), container, selected, options)
				}
				if valid {
					if restored == nil || err != nil || !handle.Valid() {
						t.Fatal("valid XML restoration rejected", content, err)
					}
					sameXML(t, parse(t, append(append([]byte(`<r><before/>`), tc.plain...), []byte(`<after/></r>`)...)), restored)
					if content && !handle.Same(restored.Root()) || !content && !handle.Same(restored.Root().Children()[1]) {
						t.Fatal("returned handle lost the restored snapshot")
					}
				} else if restored != nil || handle.Valid() || !errors.Is(err, xmlenc.ErrDecrypt) {
					t.Fatal("invalid decrypted XML returned a partial snapshot", content, restored != nil, handle.Valid(), err)
				}
				if graphXML(t, container) != before {
					t.Fatal("XML restoration mutated the encrypted input")
				}
			}
		})
	}
}

func TestKeyGraphExternalFailureGuards(t *testing.T) {
	secret, kek := bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x43}, 32)
	keydoc := graphWrap(t, secret, kek, "kek", "", "key", nil)
	data := graphData(t, secret, `<ds:RetrievalMethod URI="https://example.test/key.xml#key"/>`)
	failure := errors.New("key resolver failure")
	for _, kind := range []string{"resolver error", "close error", "nil reader", "typed nil reader", "stalled reader", "cancelled reader", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			source := &resourceReader{Reader: strings.NewReader(graphXML(t, keydoc))}
			ctx := t.Context()
			var cancel context.CancelFunc
			if kind == "cancelled reader" {
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
			}
			resolver := xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				switch kind {
				case "resolver error":
					return source, failure
				case "close error":
					source.closeErr = failure
				case "nil reader":
					return nil, nil
				case "typed nil reader":
					var reader *resourceReader
					return reader, nil
				case "stalled reader":
					source.Reader = cipherReaderFunc(func([]byte) (int, error) { return 0, nil })
				case "cancelled reader":
					cancel()
				}
				return source, nil
			})
			opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "kek", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}, External: &xmlenc.KeyGraphResources{AllowedURIs: []string{"https://example.test/key.xml"}, Resolver: resolver}}
			if kind == "bytes" {
				opts.Limits.MaxBytes = 900
			}
			got, err := xmlenc.DecryptBytesWithKeyGraph(ctx, data, data.Root(), opts)
			if got != nil || err == nil {
				t.Fatal("key resource failure returned plaintext", kind, err)
			}
			if kind != "nil reader" && kind != "typed nil reader" && !source.closed {
				t.Fatal("key reader not closed", kind)
			}
			if kind == "resolver error" || kind == "close error" {
				if !errors.Is(err, failure) {
					t.Fatal("lost resource cause", err)
				}
			}
			if kind == "cancelled reader" && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancellation", err)
			}
		})
	}
	t.Run("resource count", func(t *testing.T) {
		intermediate := graphWrap(t, kek, kek, "kek", "middle", "inner", nil)
		outer := graphWrap(t, secret, kek, "middle", "", "key", nil)
		outerwire := strings.Replace(graphXML(t, outer), `<ds:KeyName>middle</ds:KeyName>`, `<ds:RetrievalMethod URI="https://example.test/inner.xml#inner"/>`, 1)
		calls := 0
		opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "kek", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}, Limits: xmlenc.KeyGraphLimits{MaxResources: 1}, External: &xmlenc.KeyGraphResources{AllowedURIs: []string{"https://example.test/key.xml", "https://example.test/inner.xml"}, Resolver: xmlenc.CipherResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
			calls++
			wire := outerwire
			if uri == "https://example.test/inner.xml" {
				wire = graphXML(t, intermediate)
			}
			return io.NopCloser(strings.NewReader(wire)), nil
		})}}
		if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), data, data.Root(), opts); got != nil || !errors.Is(err, document.ErrLimit) || calls != 1 {
			t.Fatal("resource budget", err, calls)
		}
	})
}

func TestKeyGraphCipherPolicySeparation(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5b}, 32)
	data := graphData(t, secret, "")
	external, selected, ciphertext, err := xmlenc.ExternalizeCiphertext(t.Context(), data, data.Root(), "https://example.test/cipher.bin")
	if err != nil {
		t.Fatal(err)
	}
	opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Algorithm: xmlenc.AES256GCM, Secret: secret}}, Data: externalOptions("https://example.test/cipher.bin", ciphertext)}
	graphAssert(t, external, selected, opts)
	calls := 0
	opts.Data.External = nil
	opts.External = &xmlenc.KeyGraphResources{AllowedURIs: []string{"https://example.test/cipher.bin"}, Resolver: xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return io.NopCloser(bytes.NewReader(ciphertext)), nil
	})}
	if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), external, selected, opts); got != nil || !errors.Is(err, xmlenc.ErrPolicy) || calls != 0 {
		t.Fatal("key permission authorized cipher resource", err, calls)
	}
}

func TestKeyGraphECDHComposition(t *testing.T) {
	recipient, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x56}, 32)
	wrapped, err := xmlenc.EncryptKey(t.Context(), secret, xmlenc.KeyGraphKey{Name: "recipient", Algorithm: xmlenc.AES256KeyWrap, ECDHPublicKey: recipient.PublicKey()}, xmlenc.EncryptedKeyOptions{Algorithm: xmlenc.AES256KeyWrap, ID: "agreement", CarriedKeyName: "session"})
	if err != nil {
		t.Fatal(err)
	}
	opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "recipient", Algorithm: xmlenc.AES256KeyWrap, ECDHRecipient: recipient}}}
	for _, kind := range []string{"inline", "retrieval", "carried", "external", "nested"} {
		t.Run(kind, func(t *testing.T) {
			info := graphXML(t, wrapped)
			sibling := ""
			options := opts
			switch kind {
			case "retrieval":
				info = `<ds:RetrievalMethod URI="#agreement"/>`
				sibling = graphXML(t, wrapped)
			case "carried":
				info = `<ds:KeyName>session</ds:KeyName>`
				sibling = graphXML(t, wrapped)
			case "external":
				info = `<ds:RetrievalMethod URI="https://example.test/agreement.xml"/>`
				options.External = &xmlenc.KeyGraphResources{AllowedURIs: []string{"https://example.test/agreement.xml"}, Resolver: xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(graphXML(t, wrapped))), nil
				})}
			case "nested":
				kek := bytes.Repeat([]byte{0x47}, 16)
				outer, err := xmlenc.EncryptKey(t.Context(), kek, xmlenc.KeyGraphKey{Name: "recipient", Algorithm: xmlenc.AES256KeyWrap, ECDHPublicKey: recipient.PublicKey()}, xmlenc.EncryptedKeyOptions{Algorithm: xmlenc.AES256KeyWrap, ID: "outer", CarriedKeyName: "kek"})
				if err != nil {
					t.Fatal(err)
				}
				inner, err := xmlenc.EncryptKey(t.Context(), secret, xmlenc.KeyGraphKey{Name: "kek", Algorithm: xmlenc.AES128KeyWrap, Secret: kek}, xmlenc.EncryptedKeyOptions{Algorithm: xmlenc.AES128KeyWrap, ID: "inner"})
				if err != nil {
					t.Fatal(err)
				}
				options.KeyAlgorithms = []string{xmlenc.AES128KeyWrap}
				info = graphXML(t, inner)
				sibling = graphXML(t, outer)
			}
			data := graphData(t, secret, info)
			if sibling == "" {
				graphAssert(t, data, data.Root(), options)
				return
			}
			doc := parse(t, []byte("<r>"+graphXML(t, data)+sibling+"</r>"))
			graphAssert(t, doc, doc.Root().Children()[0], options)
		})
	}
	t.Run("provider validation and cancellation", func(t *testing.T) {
		data := graphData(t, secret, graphXML(t, wrapped))
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		provider := &agreementProvider{key: recipient, want: ctx, cancel: cancel}
		adapter, err := xmlenc.AdaptContextECDHRecipient(provider)
		if err != nil {
			t.Fatal(err)
		}
		options := opts
		options.Keys = []xmlenc.KeyGraphKey{{Name: "recipient", Algorithm: xmlenc.AES256KeyWrap, ECDHRecipient: adapter}}
		wire := strings.Replace(graphXML(t, data), `Algorithm="`+xmlenc.ConcatKDF+`"`, `Algorithm="urn:other-kdf"`, 1)
		malformed := parse(t, []byte(wire))
		if got, err := xmlenc.DecryptBytesWithKeyGraph(ctx, malformed, malformed.Root(), options); got != nil || err == nil || provider.calls != 0 {
			t.Fatal("bad KDF invoked ECDH provider", err, provider.calls)
		}
		if got, err := xmlenc.DecryptBytesWithKeyGraph(ctx, data, data.Root(), options); got != nil || !errors.Is(err, context.Canceled) || provider.calls != 1 {
			t.Fatal("ECDH graph cancellation", err, provider.calls)
		}
	})
}

func TestKeyGraphPropertyGrammar(t *testing.T) {
	secret := bytes.Repeat([]byte{0x69}, 32)
	data := graphData(t, secret, "")
	opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Algorithm: xmlenc.AES256GCM, Secret: secret}}}
	for _, body := range []string{"", "text", `<same xmlns="` + xmlenc.Namespace + `"/>`, `<no-namespace/>`} {
		t.Run(body, func(t *testing.T) {
			wire := strings.Replace(graphXML(t, data), "</xenc:EncryptedData>", `<xenc:EncryptionProperties><xenc:EncryptionProperty>`+body+`</xenc:EncryptionProperty></xenc:EncryptionProperties></xenc:EncryptedData>`, 1)
			doc := parse(t, []byte(wire))
			if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), doc, doc.Root(), opts); got != nil || !errors.Is(err, xmlenc.ErrFormat) {
				t.Fatal("invalid property content accepted", err)
			}
		})
	}
}

// RFC3394 section4.6 supplies all three octet strings independently of this API.
func TestKeyGraphGenerationVector(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	secret, _ := hex.DecodeString("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f")
	expected, _ := hex.DecodeString("28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21")
	wrapped := graphWrap(t, secret, kek, "master", "session", "key", nil)
	ciphertext, err := base64.StdEncoding.DecodeString(wrapped.Root().Children()[2].Children()[0].Text())
	if err != nil || !bytes.Equal(ciphertext, expected) {
		t.Fatal("standalone EncryptKey RFC3394 vector", err)
	}
	data := graphData(t, secret, graphXML(t, wrapped))
	graphAssert(t, data, data.Root(), xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}})
}

func TestKeyGraphECDHKeyInfoIDs(t *testing.T) {
	recipient, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x56}, 32)
	wrapped, err := xmlenc.EncryptKey(t.Context(), secret, xmlenc.KeyGraphKey{Name: "recipient", Algorithm: xmlenc.AES256KeyWrap, ECDHPublicKey: recipient.PublicKey()}, xmlenc.EncryptedKeyOptions{Algorithm: xmlenc.AES256KeyWrap})
	if err != nil {
		t.Fatal(err)
	}
	wire := graphXML(t, wrapped)
	for _, name := range []string{"ds:KeyInfo", "xenc:OriginatorKeyInfo", "xenc:RecipientKeyInfo"} {
		wire = strings.Replace(wire, "<"+name+">", "<"+name+` Id="`+strings.ReplaceAll(name, ":", "-")+`">`, 1)
	}
	data := graphData(t, secret, wire)
	opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "recipient", Algorithm: xmlenc.AES256KeyWrap, ECDHRecipient: recipient}}}
	graphAssert(t, data, data.Root(), opts)
	duplicate := parse(t, []byte(strings.Replace(graphXML(t, data), `Id="xenc-RecipientKeyInfo"`, `Id="xenc-OriginatorKeyInfo"`, 1)))
	if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), duplicate, duplicate.Root(), opts); got != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("agreement IDs bypassed index", err)
	}
}

func TestKeyGraphURIContext(t *testing.T) {
	secret, kek := bytes.Repeat([]byte{0x21}, 32), bytes.Repeat([]byte{0x22}, 32)
	wrapped := graphWrap(t, secret, kek, "master", "", "key", nil)
	data := graphData(t, secret, `<ds:RetrievalMethod URI="key.xml#key"/>`)
	base := "https://example.test/messages/data.xml"
	doc := parse(t, []byte(`<message xml:base="../keys/">`+graphXML(t, data)+`</message>`))
	calls := 0
	targetURI := "https://example.test/keys/key.xml"
	opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}, External: &xmlenc.KeyGraphResources{BaseURI: base, AllowedURIs: []string{targetURI}, Resolver: xmlenc.CipherResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
		calls++
		if uri != targetURI {
			t.Fatal(uri)
		}
		return io.NopCloser(strings.NewReader(graphXML(t, wrapped))), nil
	})}}
	graphAssert(t, doc, doc.Root().Children()[0], opts)
	if calls != 1 {
		t.Fatal("XML base resolution", calls)
	}
	for _, kind := range []string{"no opt in", "denied resolved URI", "malformed base", "base fragment", "base credentials"} {
		t.Run(kind, func(t *testing.T) {
			variant := doc
			options := opts
			policy := *opts.External
			policy.AllowedURIs = append([]string(nil), policy.AllowedURIs...)
			options.External = &policy
			calls = 0
			switch kind {
			case "no opt in":
				policy.BaseURI = ""
			case "denied resolved URI":
				policy.AllowedURIs = []string{"https://example.test/messages/key.xml"}
			case "malformed base":
				variant = parse(t, []byte(strings.Replace(graphXML(t, doc), `../keys/`, `bad%xx`, 1)))
			case "base fragment":
				variant = parse(t, []byte(strings.Replace(graphXML(t, doc), `../keys/`, `../keys/#x`, 1)))
			case "base credentials":
				variant = parse(t, []byte(strings.Replace(graphXML(t, doc), `../keys/`, `https://user:password@example.test/`, 1)))
			}
			if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), variant, variant.Root().Children()[0], options); got != nil || err == nil || calls != 0 {
				t.Fatal("URI policy bypass", kind, err, calls)
			}
		})
	}
	t.Run("same-document reference ignores external XML base", func(t *testing.T) {
		local := graphData(t, secret, `<ds:RetrievalMethod URI="#key"/>`)
		variant := parse(t, []byte(`<message xml:base="https://denied.test/">`+graphXML(t, local)+graphXML(t, wrapped)+`</message>`))
		calls = 0
		graphAssert(t, variant, variant.Root().Children()[0], opts)
		if calls != 0 {
			t.Fatal("fragment caused external read")
		}
	})
}

func TestExternalKeyBacklinksRespectPrincipalURI(t *testing.T) {
	secret, kek := bytes.Repeat([]byte{0x21}, 32), bytes.Repeat([]byte{0x22}, 32)
	const principalURI = "https://example.test/messages/data.xml"
	const keyURI = "https://example.test/keys/key.xml"
	for _, tc := range []struct {
		name, reference string
		want            error
	}{
		{"absolute reference", principalURI + "#data", xmlenc.ErrDecrypt},
		{"relative reference", "../messages/data.xml#data", xmlenc.ErrDecrypt},
		{"whole principal document", principalURI, xmlenc.ErrDecrypt},
		{"other document", "https://other.test/messages/data.xml#data", nil},
		{"fragment belongs to key document", "#data", nil},
		{"malformed reference", "bad%xx", xmlenc.ErrFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The explicit standalone key is authorized independently of backlinks.
			// A second key must participate, and conflict, only when its reference
			// resolves to this principal document. Unrelated backlinks are ignored.
			discovery := graphWrap(t, secret, kek, "master", "", "discovery", nil)
			wrapped := graphWrap(t, bytes.Repeat([]byte{0x99}, 32), kek, "master", "", "key", []xmlenc.KeyGraphReference{{URI: tc.reference}})
			external := "<keys>" + graphXML(t, discovery) + graphXML(t, wrapped) + "</keys>"
			data := graphData(t, secret, "")
			calls := 0
			options := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}, KeyURIs: []string{keyURI + "#discovery"}, External: &xmlenc.KeyGraphResources{BaseURI: principalURI, AllowedURIs: []string{keyURI}, Resolver: xmlenc.CipherResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
				calls++
				if uri != keyURI {
					t.Fatalf("backlink triggered unauthorized retrieval: %s", uri)
				}
				return io.NopCloser(strings.NewReader(external)), nil
			})}}
			if tc.want == nil {
				graphAssert(t, data, data.Root(), options)
			} else {
				before := graphXML(t, data)
				if plain, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), data, data.Root(), options); plain != nil || !errors.Is(err, tc.want) || graphXML(t, data) != before {
					t.Fatal("backlink conflict or policy error lost", plain, err)
				}
			}
			if calls != 1 {
				t.Fatal("unexpected external reads", calls)
			}
		})
	}
}

func TestKeyGraphCountsActualCipherResourceBytes(t *testing.T) {
	secret, kek := bytes.Repeat([]byte{0x62}, 32), bytes.Repeat([]byte{0x63}, 32)
	wrapped := graphWrap(t, secret, kek, "master", "", "", nil)
	encoded := wrapped.Root().Children()[2].Children()[0].Text()
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, transform := range []bool{false, true} {
		t.Run(strconv.FormatBool(transform), func(t *testing.T) {
			uri := "https://example.test/wrapped-key.bin"
			ref := `<xenc:CipherReference URI="` + uri + `"/>`
			body := ciphertext
			if transform {
				ref = `<xenc:CipherReference URI="` + uri + `"><xenc:Transforms><ds:Transform Algorithm="` + xmlenc.SignatureNamespace + `base64"/></xenc:Transforms></xenc:CipherReference>`
				body = []byte(strings.Repeat(" ", 4000) + encoded)
			}
			keywire := strings.Replace(graphXML(t, wrapped), "<xenc:CipherValue>"+encoded+"</xenc:CipherValue>", ref, 1)
			if !strings.Contains(keywire, "CipherReference") {
				t.Fatal("cipher reference fixture failed")
			}
			data := graphData(t, secret, keywire+keywire)
			for _, ceiling := range []int{len(body), 65536} {
				calls := 0
				opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}, Limits: xmlenc.KeyGraphLimits{MaxBytes: 32768}, Data: xmlenc.Options{External: &xmlenc.ExternalCipherReference{URI: uri, MaxBytes: ceiling, Resolver: xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
					calls++
					return io.NopCloser(bytes.NewReader(body)), nil
				})}}}
				graphAssert(t, data, data.Root(), opts)
				if calls != 2 {
					t.Fatal("expected both authorized paths", calls)
				}
				if transform {
					opts.Limits.MaxBytes = 8192
					calls = 0
					if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), data, data.Root(), opts); got != nil || !errors.Is(err, xmlenc.ErrPolicy) {
						t.Fatal("encoded whitespace escaped aggregate raw-byte budget", err, calls)
					}
				}
			}
		})
	}
}

func TestSizedCiphertextVerifiesActualStream(t *testing.T) {
	profile := cipherReferenceProfile{secret: make([]byte, 32)}
	encrypted, err := profile.encrypt(t.Context(), []byte("protected"))
	if err != nil {
		t.Fatal(err)
	}
	const uri = "urn:test:sized-ciphertext"
	external, _, body, err := xmlenc.ExternalizeCiphertext(t.Context(), encrypted, encrypted.Root(), uri)
	if err != nil {
		t.Fatal(err)
	}
	late := errors.New("late read")
	for _, name := range []string{"exact", "unknown", "short", "long", "limit", "late", "joined EOF", "no progress", "close", "cancel", "tampered"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			size := int64(len(body))
			source := &resourceReader{Reader: bytes.NewReader(body)}
			var want error
			switch name {
			case "unknown":
				size = -1
			case "short":
				size--
				want = xmlenc.ErrPolicy
			case "long":
				size++
				want = io.ErrUnexpectedEOF
			case "limit":
				size = 64 << 20
				want = xmlenc.ErrPolicy
			case "close":
				source.closeErr = late
				want = late
			case "no progress":
				source.Reader = cipherReaderFunc(func([]byte) (int, error) { return 0, nil })
				want = io.ErrNoProgress
			case "late", "joined EOF", "cancel":
				reader := bytes.NewReader(body)
				source.Reader = cipherReaderFunc(func(p []byte) (int, error) {
					n, err := reader.Read(p)
					if reader.Len() == 0 && n > 0 {
						switch name {
						case "cancel":
							cancel()
							err = context.Canceled
						case "joined EOF":
							err = errors.Join(io.EOF, late)
						default:
							err = late
						}
					}
					return n, err
				})
				want = late
				if name == "cancel" {
					want = context.Canceled
				}
			case "tampered":
				changed := bytes.Clone(body)
				changed[len(changed)-1] ^= 1
				source.Reader = bytes.NewReader(changed)
				want = xmlenc.ErrDecrypt
			}
			options := xmlenc.Options{External: &xmlenc.ExternalCipherReference{URI: uri, Resolver: xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) { return sizedCipherReader{source, size}, nil })}}
			out, err := profile.decrypt(ctx, external, options)
			if !source.closed {
				t.Fatal("source not closed")
			}
			if want != nil {
				if out != nil || !errors.Is(err, want) {
					t.Fatalf("plaintext %q error %v, want %v", out, err, want)
				}
			} else if err != nil || string(out) != "protected" {
				t.Fatal(string(out), err)
			}
		})
	}
}

func FuzzCipherReference(f *testing.F) {
	secret := bytes.Repeat([]byte{0x71}, 32) // Public test key.
	ctx := f.Context()
	uri := "urn:example:fuzz-ciphertext"

	d, err := xmlenc.EncryptBytesWithKey(ctx, []byte("positive"), secret, xmlenc.SymmetricOptions{})
	if err != nil {
		f.Fatal(err)
	}

	d, _, body, err := xmlenc.ExternalizeCiphertext(ctx, d, d.Root(), uri)
	if err != nil {
		f.Fatal(err)
	}

	raw, _ := d.XML(ctx)
	f.Add(raw, body)

	ref := `<xenc:CipherReference URI="` + uri + `"></xenc:CipherReference>`
	transformed := `<xenc:CipherReference URI="` + uri + `"><xenc:Transforms><ds:Transform Algorithm="` + xmlenc.SignatureNamespace + `base64"/></xenc:Transforms></xenc:CipherReference>`
	f.Add(bytes.Replace(raw, []byte(ref), []byte(transformed), 1), []byte(base64.StdEncoding.EncodeToString(body)))
	f.Fuzz(func(t *testing.T, raw, resource []byte) {
		if len(raw) > 64<<10 || len(resource) > 2048 {
			return
		}

		d, err := document.Parse(ctx, raw, document.DefaultLimits())
		if err != nil {
			return
		}

		options := externalOptions(uri, resource)
		options.MaxPlaintextBytes = 1024
		options.External.MaxBytes = 2048
		_, _ = xmlenc.DecryptBytesWithKey(ctx, d, secret, xmlenc.SymmetricOptions{Data: options})
	})
}

func BenchmarkExternalCiphertext(b *testing.B) {
	for _, size := range []int{256, 16 << 10, 8 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			profile := cipherReferenceProfile{secret: make([]byte, 32)}
			plain := bytes.Repeat([]byte("x"), size)
			encrypted, err := profile.encrypt(b.Context(), plain)
			if err != nil {
				b.Fatal(err)
			}
			const uri = "urn:benchmark:ciphertext"
			external, _, body, err := xmlenc.ExternalizeCiphertext(b.Context(), encrypted, encrypted.Root(), uri)
			if err != nil {
				b.Fatal(err)
			}
			for _, known := range []bool{false, true} {
				b.Run(strconv.FormatBool(known), func(b *testing.B) {
					options := xmlenc.Options{External: &xmlenc.ExternalCipherReference{URI: uri, Resolver: xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
						r := io.NopCloser(bytes.NewReader(body))
						if known {
							return sizedCipherReader{r, int64(len(body))}, nil
						}
						return r, nil
					})}}
					b.ReportAllocs()
					b.SetBytes(int64(size))
					for b.Loop() {
						out, err := profile.decrypt(b.Context(), external, options)
						if err != nil || !bytes.Equal(out, plain) {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}
