package xmlenc_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

func TestRSADataAlgorithms(t *testing.T) {
	k := key(t)
	for _, algorithm := range gcmAlgorithms() {
		t.Run(algorithm.uri, func(t *testing.T) { testRSADataAlgorithmsCase(t, &algorithm, &k) })
	}
}

func testRSADataAlgorithmsCase(t *testing.T, algorithm *algorithmSpec, k **rsa.PrivateKey) {
	options := xmlenc.Options{DataAlgorithm: algorithm.uri}

	doc, err := xmlenc.EncryptBytes(context.Background(), []byte("payload"), &(*k).PublicKey, options)
	if err != nil {
		t.Fatal(err)
	}

	wrapped, _ := base64.StdEncoding.DecodeString(doc.Root().Children()[1].Children()[0].Children()[1].Children()[0].Text())

	symmetric, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, (*k), wrapped, nil)
	if err != nil || len(symmetric) != algorithm.keyBytes {
		t.Fatalf("wrong data-key size %d: %v", len(symmetric), err)
	}

	out, err := xmlenc.DecryptBytes(context.Background(), doc, (*k), options)
	if err != nil || string(out) != "payload" {
		t.Fatal(err)
	}

	for _, other := range gcmAlgorithms() {
		if other.uri == algorithm.uri {
			continue
		}

		if out, err := xmlenc.DecryptBytes(context.Background(), doc, (*k), xmlenc.Options{DataAlgorithm: other.uri}); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatalf("accepted different algorithm %s: %v", other.uri, err)
		}
	}

	if algorithm.uri != xmlenc.AES256GCM {
		if out, err := xmlenc.DecryptBytes(context.Background(), doc, (*k), xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatal("default policy weakened", err)
		}
	}
}

func TestKeyWrapSuites(t *testing.T) {
	ctx := context.Background()
	source := parse(t, []byte(`<?outside ok?><r xmlns="urn:test"><v>Текст &amp; 😀</v><!--inside--></r><!--outside-->`))
	before, _ := source.XML(ctx)

	for _, dataAlgorithm := range gcmAlgorithms() {
		for _, keyAlgorithm := range wrapAlgorithms() {
			t.Run(dataAlgorithm.uri+"/"+keyAlgorithm.uri, func(t *testing.T) { testKeyWrapSuitesCase(t, &keyAlgorithm, &dataAlgorithm, &ctx, &source, &before) })
		}
	}
}

func wrapAlgorithms() []algorithmSpec {
	return []algorithmSpec{{xmlenc.AES128KeyWrap, 16}, {xmlenc.AES192KeyWrap, 24}, {xmlenc.AES256KeyWrap, 32}}
}

func testKeyWrapSuitesCase(t *testing.T, keyAlgorithm *algorithmSpec, dataAlgorithm *algorithmSpec, ctx *context.Context, source **document.Document, before *[]byte) {
	kek := bytes.Repeat([]byte{0x27}, keyAlgorithm.keyBytes)
	originalKEK := bytes.Clone(kek)

	options := xmlenc.KeyWrapOptions{Data: xmlenc.Options{DataAlgorithm: dataAlgorithm.uri}, KeyAlgorithm: keyAlgorithm.uri}
	for _, plaintext := range [][]byte{{}, []byte("binary\x00\xff"), bytes.Repeat([]byte{1, 2, 3}, 1000)} {
		doc, err := xmlenc.EncryptBytesWithKeyWrap((*ctx), plaintext, kek, options)
		if err != nil {
			t.Fatal(err)
		}

		wire, _ := doc.XML(t.Context())
		doc = parse(t, wire)

		out, err := xmlenc.DecryptBytesWithKeyWrap((*ctx), doc, kek, options)
		if err != nil || !bytes.Equal(out, plaintext) {
			t.Fatalf("roundtrip: %v", err)
		}

		wrapped, _ := base64.StdEncoding.DecodeString(doc.Root().Children()[1].Children()[0].Children()[1].Children()[0].Text())
		if len(wrapped) != dataAlgorithm.keyBytes+8 {
			t.Fatal("wrong wrapped length")
		}
	}

	doc, err := xmlenc.EncryptDocumentWithKeyWrap((*ctx), (*source), kek, options)
	if err != nil {
		t.Fatal(err)
	}

	out, err := xmlenc.DecryptDocumentWithKeyWrap((*ctx), doc, kek, options)
	if err != nil {
		t.Fatal(err)
	}

	wire, _ := out.XML(t.Context())
	if strings.Contains(string(wire), "outside") || !strings.Contains(string(wire), "<!--inside-->") {
		t.Fatalf("element scope: %s", wire)
	}

	if out, err := xmlenc.DecryptBytesWithKeyWrap((*ctx), doc, kek, options); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("type confusion", err)
	}

	after, _ := (*source).XML(t.Context())
	if !bytes.Equal((*before), after) || !bytes.Equal(kek, originalKEK) {
		t.Fatal("source document or KEK mutated")
	}
}

func TestKeyWrapRejectsTamperingAndConfusion(t *testing.T) {
	ctx := context.Background()
	kek := bytes.Repeat([]byte{0x42}, 32)

	doc, err := xmlenc.EncryptBytesWithKeyWrap(ctx, []byte("secret"), kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	raw, _ := doc.XML(ctx)
	text := string(raw)

	replace := func(from, to string) *document.Document {
		t.Helper()
		return parse(t, []byte(strings.Replace(text, from, to, 1)))
	}
	for _, tc := range []struct{ name, from, to string }{
		{"data-algorithm", xmlenc.AES256GCM, xmlenc.AES128GCM},
		{"key-algorithm", xmlenc.AES256KeyWrap, xmlenc.AES128KeyWrap},
		{"key-transport", xmlenc.AES256KeyWrap, xmlenc.RSAOAEP},
		{"wrong-namespace", `<xenc:EncryptedKey>`, `<xenc:EncryptedKey xmlns:xenc="urn:evil">`},
		{"extra-key", `</ds:KeyInfo>`, `<xenc:EncryptedKey/></ds:KeyInfo>`},
		{
			"oaep-parameters",
			`Algorithm="` + xmlenc.AES256KeyWrap + `"></xenc:EncryptionMethod>`,
			`Algorithm="` + xmlenc.AES256KeyWrap + `"><ds:DigestMethod Algorithm="` + xmlenc.SHA256 + `"/></xenc:EncryptionMethod>`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(text, tc.from) {
				t.Fatal("negative control does not change input")
			}

			if out, err := xmlenc.DecryptBytesWithKeyWrap(ctx, replace(tc.from, tc.to), kek, xmlenc.KeyWrapOptions{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
				t.Fatal("accepted bad structure/algorithm", err)
			}
		})
	}

	for _, value := range []document.Element{doc.Root().Children()[1].Children()[0].Children()[1].Children()[0], doc.Root().Children()[2].Children()[0]} {
		data, _ := base64.StdEncoding.DecodeString(value.Text())
		data[len(data)-1] ^= 1

		bad := replace(value.Text(), base64.StdEncoding.EncodeToString(data))
		if out, err := xmlenc.DecryptBytesWithKeyWrap(ctx, bad, kek, xmlenc.KeyWrapOptions{}); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
			t.Fatal("accepted tampering", err)
		}
	}

	wrapped := doc.Root().Children()[1].Children()[0].Children()[1].Children()[0]
	for _, size := range []int{0, 24, 32, 39, 41, 48, 2048} {
		bad := replace(wrapped.Text(), base64.StdEncoding.EncodeToString(make([]byte, size)))
		if out, err := xmlenc.DecryptBytesWithKeyWrap(ctx, bad, kek, xmlenc.KeyWrapOptions{}); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
			t.Fatalf("wrapped length %d: %v", size, err)
		}
	}

	wrong := bytes.Clone(kek)

	wrong[0] ^= 1
	if out, err := xmlenc.DecryptBytesWithKeyWrap(ctx, doc, wrong, xmlenc.KeyWrapOptions{}); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
		t.Fatal("wrong KEK", err)
	}
	// A caller with an RSA key cannot accidentally enter the symmetric path.
	if out, err := xmlenc.DecryptBytes(ctx, doc, key(t), xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("key transport confusion", err)
	}
}

func TestEncryptionPolicyAndLimits(t *testing.T) {
	ctx := context.Background()

	kek := make([]byte, 32)
	for _, options := range []xmlenc.KeyWrapOptions{
		{Data: xmlenc.Options{DataAlgorithm: xmlenc.Namespace + "aes256-cbc"}},
		{Data: xmlenc.Options{DataAlgorithm: "urn:unknown"}},
		{KeyAlgorithm: "urn:unknown"},
		{KeyAlgorithm: xmlenc.AES128KeyWrap},
		{Data: xmlenc.Options{MaxPlaintextBytes: -1}},
		{Data: xmlenc.Options{MaxPlaintextBytes: 32<<20 + 1}},
	} {
		if doc, err := xmlenc.EncryptBytesWithKeyWrap(ctx, nil, kek, options); doc != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("invalid caller policy", err)
		}
	}

	for _, wrong := range [][]byte{nil, make([]byte, 16), make([]byte, 24), make([]byte, 31), make([]byte, 33)} {
		if doc, err := xmlenc.EncryptBytesWithKeyWrap(ctx, nil, wrong, xmlenc.KeyWrapOptions{}); doc != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("KEK length inferred", err)
		}
	}

	limited := xmlenc.KeyWrapOptions{Data: xmlenc.Options{MaxPlaintextBytes: 4}}
	if doc, err := xmlenc.EncryptBytesWithKeyWrap(ctx, []byte("12345"), kek, limited); doc != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal("plaintext limit", err)
	}

	if doc, err := xmlenc.EncryptDocumentWithKeyWrap(ctx, parse(t, []byte("<r/>")), kek, limited); doc != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal("serialized XML limit", err)
	}

	doc, err := xmlenc.EncryptBytesWithKeyWrap(ctx, []byte("12345"), kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if out, err := xmlenc.DecryptBytesWithKeyWrap(ctx, doc, kek, limited); out != nil || err == nil {
		t.Fatal("decryption limit")
	}

	raw, _ := doc.XML(ctx)

	typed := parse(t, bytes.Replace(raw, []byte("<xenc:EncryptedData "), []byte(`<xenc:EncryptedData Type="`+xmlenc.ElementType+`" `), 1))
	if out, err := xmlenc.DecryptDocumentWithKeyWrap(ctx, typed, kek, xmlenc.KeyWrapOptions{}); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
		t.Fatal("non-XML authenticated plaintext", err)
	}

	realXML, err := xmlenc.EncryptDocumentWithKeyWrap(ctx, parse(t, []byte("<r><v/></r>")), kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	limits := document.DefaultLimits()

	limits.MaxDepth = 1
	if out, err := xmlenc.DecryptDocumentWithKeyWrap(ctx, realXML, kek, xmlenc.KeyWrapOptions{Data: xmlenc.Options{XMLLimits: limits}}); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
		t.Fatal("decrypted XML depth limit", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	if doc, err := xmlenc.EncryptBytesWithKeyWrap(canceled, nil, kek, xmlenc.KeyWrapOptions{}); doc != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("encryption cancellation", err)
	}

	if out, err := xmlenc.DecryptBytesWithKeyWrap(canceled, doc, kek, xmlenc.KeyWrapOptions{}); out != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("decryption cancellation", err)
	}

	if out, err := xmlenc.DecryptBytesWithKeyWrap(nil, doc, kek, xmlenc.KeyWrapOptions{}); out != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal("nil context", err)
	}
}

func TestProviderFailureNeverReturnsPlaintext(t *testing.T) {
	k := key(t)

	doc, err := xmlenc.EncryptBytes(context.Background(), []byte("secret"), &k.PublicKey, xmlenc.Options{})
	if err != nil {
		t.Fatal(err)
	}

	for _, size := range []int{0, 16, 24, 31, 32, 33} {
		for _, failed := range []bool{false, true} {
			result := bytes.Repeat([]byte{0x42}, size)

			p := &failingProvider{public: &k.PublicKey, result: result}
			if failed {
				p.err = errors.New("private provider detail")
			}

			if out, err := xmlenc.DecryptBytes(context.Background(), doc, p, xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
				t.Fatalf("provider length %d error %t: %v", size, failed, err)
			}

			if !bytes.Equal(result, make([]byte, size)) {
				t.Fatal("temporary provider result not cleared")
			}
		}
	}
}

func TestConcurrentKeyWrapReads(t *testing.T) {
	t.Parallel()

	kek := bytes.Repeat([]byte{0x71}, 32)

	doc, err := xmlenc.EncryptBytesWithKeyWrap(context.Background(), []byte("parallel"), kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for range 16 {
		t.Run("reader", func(t *testing.T) {
			t.Parallel()

			out, err := xmlenc.DecryptBytesWithKeyWrap(context.Background(), doc, kek, xmlenc.KeyWrapOptions{})
			if err != nil || string(out) != "parallel" {
				t.Fatal(err)
			}
		})
	}
}

func FuzzDecryptWithKeyWrap(f *testing.F) {
	kek := bytes.Repeat([]byte{0x37}, 32) // fixed public TEST secret in every worker
	for _, plaintext := range [][]byte{{}, []byte("seed")} {
		doc, err := xmlenc.EncryptBytesWithKeyWrap(context.Background(), plaintext, kek, xmlenc.KeyWrapOptions{})
		if err != nil {
			f.Fatal(err)
		}

		raw, _ := doc.XML(context.Background())
		f.Add(raw)
	}

	f.Add([]byte("<EncryptedData/>"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}

		doc, err := document.Parse(t.Context(), raw, document.DefaultLimits())
		if err != nil {
			return
		}

		_, _ = xmlenc.DecryptBytesWithKeyWrap(context.Background(), doc, kek, xmlenc.KeyWrapOptions{Data: xmlenc.Options{MaxPlaintextBytes: 1024}})
	})
}

type algorithmSpec struct {
	uri      string
	keyBytes int
}

func gcmAlgorithms() []algorithmSpec {
	return []algorithmSpec{{xmlenc.AES128GCM, 16}, {xmlenc.AES192GCM, 24}, {xmlenc.AES256GCM, 32}}
}

type failingProvider struct {
	public *rsa.PublicKey
	result []byte
	err    error
}

func (p *failingProvider) Public() crypto.PublicKey { return p.public }

func (p *failingProvider) Decrypt(_ io.Reader, _ []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return p.result, p.err
}
