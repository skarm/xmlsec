package xmlenc_test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

const (
	nameCancel = "cancel"
	nameRsa    = "rsa"
)

type cipherReferenceFixture struct {
	profile    cipherReferenceProfile
	uri        string
	external   *document.Document
	wire, body []byte
	plain      []byte
}

func TestCipherReferenceProfiles(t *testing.T) {
	ctx := context.Background()
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
	ctx := context.Background()
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
	ctx := context.Background()
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
	ctx := context.Background()
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

func FuzzCipherReference(f *testing.F) {
	secret := bytes.Repeat([]byte{0x71}, 32) // Public test key.
	ctx := context.Background()
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

type resourceReader struct {
	io.Reader
	closed   bool
	closeErr error
}

func (r *resourceReader) Close() error { r.closed = true; return r.closeErr }

func externalOptions(uri string, body []byte) xmlenc.Options {
	return xmlenc.Options{External: &xmlenc.ExternalCipherReference{
		URI: uri,
		Resolver: xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}),
	}}
}

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

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

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

type cipherReaderFunc func([]byte) (int, error)

func (f cipherReaderFunc) Read(p []byte) (int, error) { return f(p) }
