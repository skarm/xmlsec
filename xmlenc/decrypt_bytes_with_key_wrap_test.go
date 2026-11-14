package xmlenc_test

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/fips140"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

func TestKeyWrapSuites(t *testing.T) {
	ctx := t.Context()
	source := parse(t, []byte(`<?outside ok?><r xmlns="urn:test"><v>Текст &amp; 😀</v><!--inside--></r><!--outside-->`))
	before, _ := source.XML(ctx)

	for _, dataAlgorithm := range gcmAlgorithms() {
		for _, keyAlgorithm := range wrapAlgorithms() {
			t.Run(dataAlgorithm.uri+"/"+keyAlgorithm.uri, func(t *testing.T) { testKeyWrapSuitesCase(t, &keyAlgorithm, &dataAlgorithm, &ctx, &source, &before) })
		}
	}
}

func TestKeyWrapRejectsTamperingAndConfusion(t *testing.T) {
	ctx := t.Context()
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
	for _, tc := range []struct {
		name string
		from string
		to   string
	}{
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

			if out, err := xmlenc.DecryptBytesWithKeyWrap(ctx, replace(tc.from, tc.to), kek, xmlenc.KeyWrapOptions{}, xmlenc.DecryptOptions{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
				t.Fatal("accepted bad structure/algorithm", err)
			}
		})
	}

	for _, value := range []document.Element{doc.Root().Children()[1].Children()[0].Children()[1].Children()[0], doc.Root().Children()[2].Children()[0]} {
		data, _ := base64.StdEncoding.DecodeString(value.Text())
		data[len(data)-1] ^= 1

		bad := replace(value.Text(), base64.StdEncoding.EncodeToString(data))
		if out, err := xmlenc.DecryptBytesWithKeyWrap(ctx, bad, kek, xmlenc.KeyWrapOptions{}, xmlenc.DecryptOptions{}); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
			t.Fatal("accepted tampering", err)
		}
	}

	wrapped := doc.Root().Children()[1].Children()[0].Children()[1].Children()[0]
	for _, size := range []int{0, 24, 32, 39, 41, 48, 2048} {
		bad := replace(wrapped.Text(), base64.StdEncoding.EncodeToString(make([]byte, size)))
		if out, err := xmlenc.DecryptBytesWithKeyWrap(ctx, bad, kek, xmlenc.KeyWrapOptions{}, xmlenc.DecryptOptions{}); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
			t.Fatalf("wrapped length %d: %v", size, err)
		}
	}

	wrong := bytes.Clone(kek)

	wrong[0] ^= 1
	if out, err := xmlenc.DecryptBytesWithKeyWrap(ctx, doc, wrong, xmlenc.KeyWrapOptions{}, xmlenc.DecryptOptions{}); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
		t.Fatal("wrong KEK", err)
	}
	// A caller with an RSA key cannot accidentally enter the symmetric path.
	if out, err := xmlenc.DecryptBytes(ctx, doc, key(t), xmlenc.RSAOptions{}, xmlenc.DecryptOptions{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("key transport confusion", err)
	}
}

func TestConcurrentKeyWrapReads(t *testing.T) {
	t.Parallel()

	kek := bytes.Repeat([]byte{0x71}, 32)

	doc, err := xmlenc.EncryptBytesWithKeyWrap(t.Context(), []byte("parallel"), kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for range 16 {
		t.Run("reader", func(t *testing.T) {
			t.Parallel()

			out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), doc, kek, xmlenc.KeyWrapOptions{}, xmlenc.DecryptOptions{})
			if err != nil || string(out) != "parallel" {
				t.Fatal(err)
			}
		})
	}
}

func FuzzDecryptWithKeyWrap(f *testing.F) {
	kek := bytes.Repeat([]byte{0x37}, 32) // fixed public TEST secret in every worker
	for _, plaintext := range [][]byte{{}, []byte("seed")} {
		doc, err := xmlenc.EncryptBytesWithKeyWrap(f.Context(), plaintext, kek, xmlenc.KeyWrapOptions{})
		if err != nil {
			f.Fatal(err)
		}

		raw, _ := doc.XML(f.Context())
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

		_, _ = xmlenc.DecryptBytesWithKeyWrap(t.Context(), doc, kek, xmlenc.KeyWrapOptions{Data: xmlenc.CipherOptions{MaxPlaintextBytes: 1024}}, xmlenc.DecryptOptions{})
	})
}

func TestTripleDESKeyWrapPublishedVector(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy TripleDES wrap is forbidden in FIPS mode")
	}
	// RFC3217§3.4 gives these CEK, KEK and complete wrapped-key octets.
	cek, _ := hex.DecodeString("2923bf85e06dd6ae529149f1f1bae9eab3a7da3d860d3e98")
	kek, _ := hex.DecodeString("255e0d1c07b646dfb3134cc843ba8aa71f025b7c0838251f")
	wrapped, _ := hex.DecodeString("690107618ef092b3b48ca1796b234ae9fa33ebb4159604037db5d6a84eb3aac2768c632775a467d4")
	data := make([]byte, 16)
	padded := []byte{'a', 'b', 'c', 0xa1, 0xb2, 0xc3, 0xd4, 5}
	cipher.NewCBCEncrypter(legacyBlock(t, xmlenc.TripleDESCBC, cek), data[:8]).CryptBlocks(data[8:], padded)
	body := `<EncryptedData xmlns="` + xmlenc.Namespace + `" xmlns:ds="` + xmlenc.SignatureNamespace + `"><EncryptionMethod Algorithm="` + xmlenc.TripleDESCBC + `"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="` + xmlenc.TripleDESKeyWrap + `"/><CipherData><CipherValue>` + base64.StdEncoding.EncodeToString(wrapped) + `</CipherValue></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue>` + base64.StdEncoding.EncodeToString(data) + `</CipherValue></CipherData></EncryptedData>`
	options := xmlenc.KeyWrapOptions{Data: xmlenc.CipherOptions{DataAlgorithm: xmlenc.TripleDESCBC, AllowLegacy: true}, KeyAlgorithm: xmlenc.TripleDESKeyWrap}
	envelope := parse(t, []byte(body))
	out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), envelope, kek, options, xmlenc.DecryptOptions{})
	if err != nil || string(out) != "abc" {
		t.Fatal(out, err)
	}
	for _, plain := range [][]byte{nil, []byte("fresh key wrap")} {
		encrypted, err := xmlenc.EncryptBytesWithKeyWrap(t.Context(), plain, kek, options)
		if err != nil {
			t.Fatal(err)
		}
		out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), encrypted, kek, options, xmlenc.DecryptOptions{})
		if err != nil || !bytes.Equal(out, plain) {
			t.Fatal(out, err)
		}
	}
	for _, size := range []int{0, 39, 40} {
		bad := bytes.Clone(wrapped)
		if size == 40 {
			bad[0] ^= 1
		} else {
			bad = bad[:size]
		}
		mutated := parse(t, []byte(strings.Replace(body, base64.StdEncoding.EncodeToString(wrapped), base64.StdEncoding.EncodeToString(bad), 1)))
		if out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), mutated, kek, options, xmlenc.DecryptOptions{}); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
			t.Fatal(size, out, err)
		}
	}
	denied := options
	denied.Data.AllowLegacy = false
	if out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), envelope, kek, denied, xmlenc.DecryptOptions{}); out != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal(out, err)
	}
	other := options
	other.Data.DataAlgorithm = xmlenc.AES192GCM
	if envelope, err := xmlenc.EncryptBytesWithKeyWrap(t.Context(), nil, kek, other); envelope != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal("RFC3217 only supports TripleDES CEKs", envelope, err)
	}
}

func wrapAlgorithms() []algorithmSpec {
	return []algorithmSpec{{xmlenc.AES128KeyWrap, 16}, {xmlenc.AES192KeyWrap, 24}, {xmlenc.AES256KeyWrap, 32}}
}

func testKeyWrapSuitesCase(t *testing.T, keyAlgorithm *algorithmSpec, dataAlgorithm *algorithmSpec, ctx *context.Context, source **document.Document, before *[]byte) {
	kek := bytes.Repeat([]byte{0x27}, keyAlgorithm.keyBytes)
	originalKEK := bytes.Clone(kek)

	options := xmlenc.KeyWrapOptions{Data: xmlenc.CipherOptions{DataAlgorithm: dataAlgorithm.uri}, KeyAlgorithm: keyAlgorithm.uri}
	for _, plaintext := range [][]byte{{}, []byte("binary\x00\xff"), bytes.Repeat([]byte{1, 2, 3}, 1000)} {
		doc, err := xmlenc.EncryptBytesWithKeyWrap(*ctx, plaintext, kek, options)
		if err != nil {
			t.Fatal(err)
		}

		wire, _ := doc.XML(t.Context())
		doc = parse(t, wire)

		out, err := xmlenc.DecryptBytesWithKeyWrap(*ctx, doc, kek, options, xmlenc.DecryptOptions{})
		if err != nil || !bytes.Equal(out, plaintext) {
			t.Fatalf("roundtrip: %v", err)
		}

		wrapped, _ := base64.StdEncoding.DecodeString(doc.Root().Children()[1].Children()[0].Children()[1].Children()[0].Text())
		if len(wrapped) != dataAlgorithm.keyBytes+8 {
			t.Fatal("wrong wrapped length")
		}
	}

	doc, err := xmlenc.EncryptDocumentWithKeyWrap(*ctx, *source, kek, options)
	if err != nil {
		t.Fatal(err)
	}

	out, err := xmlenc.DecryptDocumentWithKeyWrap(*ctx, doc, kek, options, xmlenc.DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}

	wire, _ := out.XML(t.Context())
	if bytes.Contains(wire, []byte("outside")) || !bytes.Contains(wire, []byte("<!--inside-->")) {
		t.Fatalf("element scope: %s", wire)
	}

	if out, err := xmlenc.DecryptBytesWithKeyWrap(*ctx, doc, kek, options, xmlenc.DecryptOptions{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("type confusion", err)
	}

	after, _ := (*source).XML(t.Context())
	if !bytes.Equal(*before, after) || !bytes.Equal(kek, originalKEK) {
		t.Fatal("source document or KEK mutated")
	}
}
