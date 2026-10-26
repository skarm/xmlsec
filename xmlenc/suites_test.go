package xmlenc_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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

func TestRSADataAlgorithms(t *testing.T) {
	k := key(t)
	for _, algorithm := range gcmAlgorithms() {
		t.Run(algorithm.uri, func(t *testing.T) { testRSADataAlgorithmsCase(t, &algorithm, &k) })
	}
}

func testRSADataAlgorithmsCase(t *testing.T, algorithm *algorithmSpec, k **rsa.PrivateKey) {
	options := xmlenc.Options{DataAlgorithm: algorithm.uri}

	doc, err := xmlenc.EncryptBytes(t.Context(), []byte("payload"), &(*k).PublicKey, options)
	if err != nil {
		t.Fatal(err)
	}

	wrapped, _ := base64.StdEncoding.DecodeString(doc.Root().Children()[1].Children()[0].Children()[1].Children()[0].Text())

	symmetric, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, *k, wrapped, nil)
	if err != nil || len(symmetric) != algorithm.keyBytes {
		t.Fatalf("wrong data-key size %d: %v", len(symmetric), err)
	}

	out, err := xmlenc.DecryptBytes(t.Context(), doc, *k, options)
	if err != nil || string(out) != "payload" {
		t.Fatal(err)
	}

	for _, other := range gcmAlgorithms() {
		if other.uri == algorithm.uri {
			continue
		}

		if out, err := xmlenc.DecryptBytes(t.Context(), doc, *k, xmlenc.Options{DataAlgorithm: other.uri}); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatalf("accepted different algorithm %s: %v", other.uri, err)
		}
	}

	if algorithm.uri != xmlenc.AES256GCM {
		if out, err := xmlenc.DecryptBytes(t.Context(), doc, *k, xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatal("default policy weakened", err)
		}
	}
}

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

func wrapAlgorithms() []algorithmSpec {
	return []algorithmSpec{{xmlenc.AES128KeyWrap, 16}, {xmlenc.AES192KeyWrap, 24}, {xmlenc.AES256KeyWrap, 32}}
}

func testKeyWrapSuitesCase(t *testing.T, keyAlgorithm *algorithmSpec, dataAlgorithm *algorithmSpec, ctx *context.Context, source **document.Document, before *[]byte) {
	kek := bytes.Repeat([]byte{0x27}, keyAlgorithm.keyBytes)
	originalKEK := bytes.Clone(kek)

	options := xmlenc.KeyWrapOptions{Data: xmlenc.Options{DataAlgorithm: dataAlgorithm.uri}, KeyAlgorithm: keyAlgorithm.uri}
	for _, plaintext := range [][]byte{{}, []byte("binary\x00\xff"), bytes.Repeat([]byte{1, 2, 3}, 1000)} {
		doc, err := xmlenc.EncryptBytesWithKeyWrap(*ctx, plaintext, kek, options)
		if err != nil {
			t.Fatal(err)
		}

		wire, _ := doc.XML(t.Context())
		doc = parse(t, wire)

		out, err := xmlenc.DecryptBytesWithKeyWrap(*ctx, doc, kek, options)
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

	out, err := xmlenc.DecryptDocumentWithKeyWrap(*ctx, doc, kek, options)
	if err != nil {
		t.Fatal(err)
	}

	wire, _ := out.XML(t.Context())
	if bytes.Contains(wire, []byte("outside")) || !bytes.Contains(wire, []byte("<!--inside-->")) {
		t.Fatalf("element scope: %s", wire)
	}

	if out, err := xmlenc.DecryptBytesWithKeyWrap(*ctx, doc, kek, options); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("type confusion", err)
	}

	after, _ := (*source).XML(t.Context())
	if !bytes.Equal(*before, after) || !bytes.Equal(kek, originalKEK) {
		t.Fatal("source document or KEK mutated")
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
	ctx := t.Context()

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

	doc, err := xmlenc.EncryptBytes(t.Context(), []byte("secret"), &k.PublicKey, xmlenc.Options{})
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

			if out, err := xmlenc.DecryptBytes(t.Context(), doc, p, xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
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

	doc, err := xmlenc.EncryptBytesWithKeyWrap(t.Context(), []byte("parallel"), kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for range 16 {
		t.Run("reader", func(t *testing.T) {
			t.Parallel()

			out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), doc, kek, xmlenc.KeyWrapOptions{})
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

		_, _ = xmlenc.DecryptBytesWithKeyWrap(t.Context(), doc, kek, xmlenc.KeyWrapOptions{Data: xmlenc.Options{MaxPlaintextBytes: 1024}})
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

func TestLegacyCBCKeyTransports(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy CBC is forbidden in FIPS mode")
	}
	k := key(t)
	for _, algorithm := range cbcAlgorithms() {
		t.Run(algorithm.uri, func(t *testing.T) {
			for _, oaep := range []*xmlenc.OAEPParameters{nil, {Algorithm: xmlenc.RSAOAEP10, Hash: crypto.SHA1, AllowLegacy: true}} {
				opts := xmlenc.Options{DataAlgorithm: algorithm.uri, AllowLegacy: true, OAEP: oaep}
				envelope, err := xmlenc.EncryptBytes(t.Context(), []byte("legacy transport"), &k.PublicKey, opts)
				if err != nil {
					t.Fatal(err)
				}
				out, err := xmlenc.DecryptBytes(t.Context(), envelope, k, opts)
				if err != nil || string(out) != "legacy transport" {
					t.Fatal(out, err)
				}
			}
			for _, wrap := range wrapAlgorithms() {
				kek := bytes.Repeat([]byte{0x46}, wrap.keyBytes)
				opts := xmlenc.KeyWrapOptions{Data: xmlenc.Options{DataAlgorithm: algorithm.uri, AllowLegacy: true}, KeyAlgorithm: wrap.uri}
				envelope, err := xmlenc.EncryptBytesWithKeyWrap(t.Context(), []byte("wrapped CBC"), kek, opts)
				if err != nil {
					t.Fatal(err)
				}
				out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), envelope, kek, opts)
				if err != nil || string(out) != "wrapped CBC" {
					t.Fatal(out, err)
				}
			}
		})
	}
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
	options := xmlenc.KeyWrapOptions{Data: xmlenc.Options{DataAlgorithm: xmlenc.TripleDESCBC, AllowLegacy: true}, KeyAlgorithm: xmlenc.TripleDESKeyWrap}
	envelope := parse(t, []byte(body))
	out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), envelope, kek, options)
	if err != nil || string(out) != "abc" {
		t.Fatal(out, err)
	}
	for _, plain := range [][]byte{nil, []byte("fresh key wrap")} {
		encrypted, err := xmlenc.EncryptBytesWithKeyWrap(t.Context(), plain, kek, options)
		if err != nil {
			t.Fatal(err)
		}
		out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), encrypted, kek, options)
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
		if out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), mutated, kek, options); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
			t.Fatal(size, out, err)
		}
	}
	denied := options
	denied.Data.AllowLegacy = false
	if out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), envelope, kek, denied); out != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal(out, err)
	}
	other := options
	other.Data.DataAlgorithm = xmlenc.AES192GCM
	if envelope, err := xmlenc.EncryptBytesWithKeyWrap(t.Context(), nil, kek, other); envelope != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal("RFC3217 only supports TripleDES CEKs", envelope, err)
	}
}

func TestLegacyCBCProviderAndPlaintextLimits(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy CBC is forbidden in FIPS mode")
	}
	k := key(t)
	for _, algorithm := range cbcAlgorithms() {
		t.Run(algorithm.uri, func(t *testing.T) {
			opts := xmlenc.Options{DataAlgorithm: algorithm.uri, AllowLegacy: true}
			envelope, err := xmlenc.EncryptBytes(t.Context(), bytes.Repeat([]byte{'x'}, 33), &k.PublicKey, opts)
			if err != nil {
				t.Fatal(err)
			}
			for _, size := range []int{0, 16, 24, 32, 33} {
				actual := bytes.Repeat([]byte{0x42}, size)
				provider := &failingProvider{public: &k.PublicKey, result: actual, err: errors.New("private unwrap failure")}
				if out, err := xmlenc.DecryptBytes(t.Context(), envelope, provider, opts); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
					t.Fatal(size, out, err)
				}
				if !bytes.Equal(actual, make([]byte, size)) {
					t.Fatal("provider key was not cleared")
				}
			}
			b := 16
			if algorithm.uri == xmlenc.TripleDESCBC {
				b = 8
			}
			envelope, err = xmlenc.EncryptBytes(t.Context(), bytes.Repeat([]byte{'x'}, b+1), &k.PublicKey, opts)
			if err != nil {
				t.Fatal(err)
			}
			opts.MaxPlaintextBytes = b // Wire fits max+IV+onepadblock; only unpadded length exceeds max.
			if out, err := xmlenc.DecryptBytes(t.Context(), envelope, k, opts); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
				t.Fatal("post-decrypt plaintext bound", out, err)
			}
		})
	}
}

func methodKeySizeFixture(t *testing.T, raw []byte, algorithm, content string, last bool) []byte {
	t.Helper()
	start := []byte(`<xenc:EncryptionMethod Algorithm="` + algorithm + `">`)
	i := bytes.Index(raw, start)
	if i < 0 {
		t.Fatal("missing EncryptionMethod fixture", algorithm)
	}
	position := i + len(start)
	if last {
		end := bytes.Index(raw[position:], []byte(`</xenc:EncryptionMethod>`))
		if end < 0 {
			t.Fatal("missing method close")
		}
		position += end
	}
	out := append(bytes.Clone(raw[:position]), []byte(content)...)
	return append(out, raw[position:]...)
}

func TestEncryptionMethodKeySize(t *testing.T) {
	algorithms := gcmAlgorithms()
	if !fips140.Enabled() {
		algorithms = append(algorithms, cbcAlgorithms()...)
	}
	for _, algorithm := range algorithms {
		t.Run(algorithm.uri, func(t *testing.T) {
			secret := bytes.Repeat([]byte{0x38}, algorithm.keyBytes)
			opts := xmlenc.SymmetricOptions{Data: xmlenc.Options{DataAlgorithm: algorithm.uri, AllowLegacy: true}}
			doc, err := xmlenc.EncryptBytesWithKey(t.Context(), []byte("size"), secret, opts)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := doc.XML(t.Context())
			for _, size := range []string{strconv.Itoa(algorithm.keyBytes * 8), "\t+000" + strconv.Itoa(algorithm.keyBytes*8) + "\r\n"} {
				valid := parse(t, methodKeySizeFixture(t, raw, algorithm.uri, `<xenc:KeySize>`+size+`</xenc:KeySize>`, false))
				out, err := xmlenc.DecryptBytesWithKey(t.Context(), valid, secret, opts)
				if err != nil || string(out) != "size" {
					t.Fatal(size, out, err)
				}
			}
			for _, size := range []string{"", "0", "-1", "1.0", "1e2", "1 28", "++128", "\u00a0128", strconv.Itoa(algorithm.keyBytes*8 + 1)} {
				bad := parse(t, methodKeySizeFixture(t, raw, algorithm.uri, `<xenc:KeySize>`+size+`</xenc:KeySize>`, false))
				if out, err := xmlenc.DecryptBytesWithKey(t.Context(), bad, secret, opts); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
					t.Fatal(size, out, err)
				}
			}
		})
	}
	wrappers := wrapAlgorithms()
	if !fips140.Enabled() {
		wrappers = append(wrappers, algorithmSpec{xmlenc.TripleDESKeyWrap, 24})
	}
	for _, algorithm := range wrappers {
		t.Run(algorithm.uri, func(t *testing.T) {
			kek := bytes.Repeat([]byte{0x37}, algorithm.keyBytes)
			opts := xmlenc.KeyWrapOptions{KeyAlgorithm: algorithm.uri}
			if algorithm.uri == xmlenc.TripleDESKeyWrap {
				opts.Data = xmlenc.Options{DataAlgorithm: xmlenc.TripleDESCBC, AllowLegacy: true}
			}
			doc, err := xmlenc.EncryptBytesWithKeyWrap(t.Context(), []byte("key size"), kek, opts)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := doc.XML(t.Context())
			valid := parse(t, methodKeySizeFixture(t, raw, algorithm.uri, `<xenc:KeySize>`+strconv.Itoa(algorithm.keyBytes*8)+`</xenc:KeySize>`, false))
			out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), valid, kek, opts)
			if err != nil || string(out) != "key size" {
				t.Fatal(out, err)
			}
			bad := parse(t, methodKeySizeFixture(t, raw, algorithm.uri, `<xenc:KeySize>1</xenc:KeySize>`, false))
			if out, err := xmlenc.DecryptBytesWithKeyWrap(t.Context(), bad, kek, opts); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
				t.Fatal(out, err)
			}
		})
	}
}

func TestRSAEncryptionMethodKeySizeBeforeProvider(t *testing.T) {
	ctx := t.Context()
	k := key(t)
	doc, err := xmlenc.EncryptBytes(ctx, []byte("RSA size"), &k.PublicKey, xmlenc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := doc.XML(ctx)
	valid := parse(t, methodKeySizeFixture(t, raw, xmlenc.RSAOAEP, `<xenc:KeySize>`+strconv.Itoa(k.N.BitLen())+`</xenc:KeySize>`, false))
	out, err := xmlenc.DecryptBytes(ctx, valid, k, xmlenc.Options{})
	if err != nil || string(out) != "RSA size" {
		t.Fatal(out, err)
	}
	for _, algorithm := range []string{xmlenc.AES256GCM, xmlenc.RSAOAEP} {
		for _, content := range []string{`<xenc:KeySize>1</xenc:KeySize>`, `<xenc:KeySize bad="1">256</xenc:KeySize>`, `<xenc:KeySize><xenc:KeySize>256</xenc:KeySize></xenc:KeySize>`, `<xenc:KeySize>256</xenc:KeySize><xenc:KeySize>256</xenc:KeySize>`} {
			p := &provider{k: k, want: ctx}
			adapted, err := xmlenc.AdaptContextDecrypter(p)
			if err != nil {
				t.Fatal(err)
			}
			bad := parse(t, methodKeySizeFixture(t, raw, algorithm, content, false))
			if out, err := xmlenc.DecryptBytes(ctx, bad, adapted, xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) || p.calls != 0 {
				t.Fatal(algorithm, content, out, err, p.calls)
			}
		}
	}
	misplaced := parse(t, methodKeySizeFixture(t, raw, xmlenc.RSAOAEP, `<xenc:KeySize>`+strconv.Itoa(k.N.BitLen())+`</xenc:KeySize>`, true))
	p := &provider{k: k, want: ctx}
	adapted, err := xmlenc.AdaptContextDecrypter(p)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := xmlenc.DecryptBytes(ctx, misplaced, adapted, xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) || p.calls != 0 {
		t.Fatal(out, err, p.calls)
	}
}

func TestEncryptionNamespaces(t *testing.T) {
	k := key(t)
	doc, err := xmlenc.EncryptBytes(t.Context(), []byte("namespace-bound octets"), &k.PublicKey, xmlenc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	aliases := strings.NewReplacer("xmlns:xenc11=", "xmlns:new11=", "xenc11:", "new11:", "xmlns:xenc=", "xmlns:new=", "xenc:", "new:", "xmlns:ds=", "xmlns:sig=", "ds:", "sig:")
	for name, input := range map[string]string{
		"renamed prefixes":         aliases.Replace(string(wire)),
		"default XMLENC namespace": strings.NewReplacer("xmlns:xenc=", "xmlns=", "xenc:", "").Replace(string(wire)),
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := xmlenc.DecryptBytes(t.Context(), parse(t, []byte(input)), k, xmlenc.Options{}); err != nil || string(out) != "namespace-bound octets" {
				t.Fatal(out, err)
			}
		})
	}
	for _, namespace := range []string{xmlenc.Namespace, xmlenc.Namespace11, xmlenc.SignatureNamespace} {
		t.Run("wrong URI/"+namespace, func(t *testing.T) {
			bad := bytes.Replace(wire, []byte(`="`+namespace+`"`), []byte(`="urn:wrong-namespace"`), 1)
			p := &provider{k: k, want: t.Context()}
			adapted, err := xmlenc.AdaptContextDecrypter(p)
			if err != nil {
				t.Fatal(err)
			}
			if out, err := xmlenc.DecryptBytes(t.Context(), parse(t, bad), adapted, xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) || p.calls != 0 {
				t.Fatal("wrong expanded name reached provider", err, p.calls)
			}
		})
	}
}

func TestCipherDataChoiceBeforeProvider(t *testing.T) {
	k := key(t)
	doc, err := xmlenc.EncryptBytes(t.Context(), []byte("choice octets"), &k.PublicKey, xmlenc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	value := `<xenc:CipherValue>` + doc.Root().Children()[2].Children()[0].Text() + `</xenc:CipherValue>`
	data := `<xenc:CipherData>` + value + `</xenc:CipherData>`
	if !bytes.Contains(wire, []byte(data)) {
		t.Fatal("ineffective choice fixture")
	}
	for name, replacement := range map[string]string{
		"neither":           `<xenc:CipherData/>`,
		"both":              `<xenc:CipherData>` + value + `<xenc:CipherReference URI="urn:unused"/></xenc:CipherData>`,
		"duplicate value":   `<xenc:CipherData>` + value + value + `</xenc:CipherData>`,
		"character data":    `<xenc:CipherData>unexpected` + value + `</xenc:CipherData>`,
		"unknown attribute": `<xenc:CipherData other="1">` + value + `</xenc:CipherData>`,
		"value child":       `<xenc:CipherData><xenc:CipherValue><xenc:CipherValue/></xenc:CipherValue></xenc:CipherData>`,
		"malformed base64":  `<xenc:CipherData><xenc:CipherValue>!</xenc:CipherValue></xenc:CipherData>`,
	} {
		t.Run(name, func(t *testing.T) {
			bad := parse(t, bytes.Replace(wire, []byte(data), []byte(replacement), 1))
			p := &provider{k: k, want: t.Context()}
			adapted, err := xmlenc.AdaptContextDecrypter(p)
			if err != nil {
				t.Fatal(err)
			}
			if out, err := xmlenc.DecryptBytes(t.Context(), bad, adapted, xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) || p.calls != 0 {
				t.Fatal("invalid CipherData reached provider", err, p.calls)
			}
		})
	}
}

// TestPublishedOAEPDecryptionVectors uses exact C2SP/Wycheproof data at
// ee7b4f7e6119/testvectors_v1/rsa_oaep_2048_sha256_mgf1sha256_test.json.
// Source: https://github.com/C2SP/wycheproof/blob/ee7b4f7e6119/testvectors_v1/rsa_oaep_2048_sha256_mgf1sha256_test.json
// The source SHA-256 is 83dce701e3d8640ac56e6d7bf37a5a8f9bd6a336e1e932a1e9bfe4ba9c5ea3a9.
// Exact primitive outcomes are observed at the explicit provider boundary, so
// an invalid 6-byte OAEP result cannot pass merely by failing the 32-byte CEK check.
func TestPublishedOAEPDecryptionVectors(t *testing.T) {
	der, err := hex.DecodeString("308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d502030100010282010024cdc62317f5d72a6f6ba6cc9632899b01d1ff28867d72f61688995bc855a4e420a8405250089bdb13cf8e09543827b748b9d27fbb2b4d9e20af8c5a6a862796d1a4cc18ad16ea678bc1bd4a83bbbe9c5e57453b5ce7388e41a3ba4ce2b77b4438a229e954f720dae0353dc088ac8a76b26dc276f8e1b7851ddd6398ad16ff2e78195123b9b036e945c38c9d12434f6df76fe22359eb3e1ac9c011678fc926fad3ae475a4fffff55feb2d147e9c894f4c0e29a599e762462482d968bf42780945fc0d2c31c573c4431b8f4fe8b8c67bec815abd44f7a86edca1c2308737358d2c2ae5e2e0e2dadf730980262377e58b13b7d9992060a0bc870ccfdb4a9319ee102818100dc431050f782e894fb5248247d98cb7d58b8d1e24f3b55d041c56e4de086b0d5bb028bda42eeb5d234d5681e5809d415e6a289ad4cfbf78f978f6c35814f50eebff1c5b80a69f788e81e6bab5ddaa78369d659d143ec6f17e79813a575cfad9c569156b90113e2e9110ad9e7b48a1c9348a6e653321191290ea36cfb3a5b18f102818100bd1a81e7977f9898122273ae3222b598ea5fb19eb4eabc38308a5e32196603b2e500ffb79f5b886816611debc472fac45544070beb057c941378a6868af3b7a03d3f9880ec47d5e089b94fbde542aba9ae8d72c57088d7abf5b131f39098f7bc160f90536abc9492fd4e06f3ed7299d4b97bb03677207d95669f140cfbc20f2502818100a94b528b28f291599121d91952ffd1c7f21d7c1479d99d478885fb161870ee1218bf08472612dbe5497e8d9c650688e09c786961ae3e2c354dc48ae34514759c4c23c4588488961dc06b414e61c0e1e7fbbd2923d31532fe289f96da220711e58c14019808e00414276933bb07e4efb9b4a9b37656917205209f33f09515d7c10281803af0e72a933aef09ff2503df78bafed531c02ff1a2bc437c540cdcbd4ad35435cf511763596543480629b114ca7f780ff7efa32ea0cb6e000d6d9ea1f2ef71fd9cf9948422a165557e37e755edfe70d90b920502eb478bc98a63f788ce3a0f856d6ede7251a383bfa8fa480a81a925af7b3cc538c4bab8c9f7597ffb68011d8d0281802640fbfbcfefb163ee7a87b6483a66ee41f956d90fa8a7939bfc042ee0924b1b7993d0445f758d51933e85179c0320b0c968b48a91c38b5be923e1097c0c562f88d42294b6a2759bafa5428a74f1270874e45f6fcc60f21602de5eccd143cf31241f5921b5ad3983fb54ef17be3b285367e50c999c67247b552fe4bfce945f7b")
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	k, ok := private.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("publisher key is not RSA")
	}
	for _, tc := range []struct {
		id         int
		message    string
		ciphertext string
		label      string
		valid      bool
	}{
		// tc1: valid message
		{1, "", "6e62bf24d95aff6868afec2a92a445b6458f16f688c19fe1212f66a63137831653cedd359d8cff4dd485d77dfd55812c181373201f54aafd65730d2a304e623455d51125d891e65d97fce52341cae45fb64c38a384a1c621e2713ee6794633f029a9fd4d774f56551eac2176162e162640f25eab873a3451c475570f19228bcede4c67c370a75ed7fabccd538c9819eff182481b10d42f1a9f6a05373b8cf9b71818d467bd3b8ebacb619e8ad42916e600c043effceb3855bc48a629e60ae886f51b2a7876b0e623fb2ce68af4b039242f963adb0e4240aed0ed07f65f1ee7c0cc77d210d0c2d1dc10c81b881aa0c9c9e9499665cf2970d2ccfeeb3191531765", "", true},
		// tc7: valid message
		{7, "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "096958786ee7972050d67a9e4b69d6c6af7db7cc674386df725770dd29129b826e39552330104c8d71e6cc3a3014dd2f61b54153af51b0438d447ee939f9e3c13bb8b00a37dea6a068f6c9d27e848b1be7a1eeeb3ee50b78036fba95ae46948ca5b13f356ea24db10f60dc09e4b8bad8f766b668ef72524432080a0ce00ed676d6d5e354984b1078520412525848156d06f0652469f95791baa3d9a798ae537094f76f976faecd5c9ce0c930a75910c63dacf63485cb4b5e7bdbcf4d80e74037eaa1a8fe4b52930bec6be99cf6ac88cf5878dbf6859d456a95dbc34654eec425de84ca2a535d517403a9aada827e7d0093ecfc97ed056a7652825e9a45cb2dcb", "", true},
		// tc11: Longest valid message size
		{11, "78787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878", "7efb69f1137d6a6e813b7ab75bf0400b3d07a442b88ab048675dc06b0215fc1a2e033263ec31a6c1d2eac56cb0470d69022a48131d1f000bbed70586b80cf6356465c8834daced7ea2a5ff8ef9c44d5ab828ffbf0556a6394752a4a28a70cae20084e1236f042f6c29de5cb34ef73acba5abcc7ccb3a26342701df3b9daa945d9fa5bf0b9b10306655e56370183f50fb8321f8f0cd1c72114791fca5df2166296b509b01a0b291c46110787cebe69d41b3b1e89590bc2f5e5d49ea24ae0f1207eef1aee54b9760553e80c5506a8a8a75732e92875025f0bfd5ead71e4340c8a9fa16dcd5a7dc96d8c4a7dc4e91f47a69366445c4695c8bad578ffe52bb672f65", "", true},
		// tc12: first byte of l_hash modified
		{12, "313233343030", "287d7108a1c6e7a18acb0045b20c57cdf2ac03456b44942764a7a9e9fdf3db481d7e202e4c8d733b56b9c1e93d71e791af8325c9363df789b252a5ed0eddc79e76fa41c2cb0a35618398217a390a5e6d99eed905d5554d19c1cf4e30bdf1c2fcc5148b641d71b3f1977b63d232648ddd935ec9499a53ac2fbcac55f462e91065adaa018a39c453ba759bd68b454074153421e2ce75cf149f748b5b84758df8a423d1c50c880af863f2a6df3cd465ca36aa2152b5771f3d507f4a4dd9f8006d80eca23537092287976f218a90df1e16d889fe31e79f7309f3224f613e9b52479fe73b7aad915319a3b62a5936649f7d015d7b09f7fa9f454f78a7c3dd4bf791e0", "", false},
		// tc13: last byte of l_hash modified
		{13, "313233343030", "8b65065af82770625d24917d13fd97ae13247cad97910a2651f95800165b76cc34bfe06cbf8c31a7d7ab4f41e05c45a25b90c606378c8e49c95a15ca11ae37e797a00f1b2680a6958c54396be4e1ceedcabc58d9f136b36867a2fefe648a9758f49634bfbcaa48717a116cba58c27539be10c56911aabe013e0329645e8308423c3aa42e0c9b1f4b5f546ddd9f90bf4d007dab52ac3879db755e4f2b96db5cf01950f39076f261f50b1bae137be500b03ceff6ea1bbd80b33424f7faba5cc6b86670fcb7db1a9b3c58bdfd7b75ba9f3ebd34ae32d320c757020a7324df7d3985bccfe0e81bb7f61bd98cb37219312299b4f274b2c90c52a8e1790f52e8fdd768", "", false},
		// tc14: l_hash changed to all 0
		{14, "313233343030", "356e91db9bd932c7b5726da288e2620cd79667c2e1d7aca562331ceaa6e4ab47665213ed75579abb147728bcff60787c95107f5be787c42e714d51627fcc8b4ea71c232c0c80ce6163cd0fbfa9dd7e8c1990176abc2705f4ffcf1d5c62393eab1c0ec8a653a90f27a968df8f4af622e96f663fceead8b0bf5dff65cd657a72b9c33265c5c2a8f7f9c614b9c2f8a95246970e6a778aca4b12552da47c274282ad9205ecd2264ae3c649597beaa35c141910e84233776d419448f55019a84e199a4867d68bf213f47b0316d50079dab77299fbbe7fe8929906461c1103a97c2b3f1633c8ef03e820ec675e331cd1fda8ebfedf541d0f2b571f4eaf292ce0ab14c1", "", false},
		// tc15: l_hash changed to all 1
		{15, "313233343030", "5a6efdd2d211d50366885e177190ce1621ba110ee46530bd083ba76ed48992d85efd8f9ba964eb33e596e0c0bcb545f89e2c9592ed18495e8e5df1866fe30b27522a3ad9cf7124c4aa23f7c925900613c50b7c18872b4537a750419ae128e913e9a2d87c219e2cd01132972298028e54fe394ef9779d04543c72eec4c5732cadff0b954964706bc4085722b0c595162d11793ab29754837bf5d324e21814ea24b12fed441f20d22148ba5a987b6aa7c7d4ab5a33af8e6c9096c29777cb0d5cfe938a6ed5d30936a5a8f5fc435df14d1c439d1b9d274254e7b248bd20d21dc4652c1605d5a2929db018bd45794a523b217fe0a9a6b0704197ba8126fc8311556f", "", false},
		// tc16: first byte of ps modified
		{16, "313233343030", "52582e10264630e1584155f5e970b8eda9108a87370861cda12ee773411cf556db328c8a2a165d10f6f969ac61b170a75975fbdf9319d13c9535f30d621db19e41da3a04fe40874caf779c8f03bd5d1892e52925b183c118446ed9a335e9c1dc4519fb1253215e5f8d8ee6d49c0167af9d5ca5b1ace067af573e0be9a61beeccdac37b0e54f6b0f70576cb8a400d01136357a8576e81c119d3dd91c7b5cb343692a810362e1e6dc06c1746e071a903a2856b4446f10f78c670d617e5e24dc5c0e45caafbf8ffc4af6b3ef998fe1bfb59aacb16d98d7e389679939861a6722c4e29af731da99d17058d7a12ead0d3d576de796ad2ad596feada4c091f10748536", "", false},
		// tc17: all bits in ps flipped
		{17, "313233343030", "4b4546460b54697beb899b54f474079169b4f7e79d0299586d821bd9091e9c5d2603b96c1aeb2924e887b15b211b07a657a85629932f97f18acd5a9f15684c9959fa41a6d1c10eeca68b7b95179492e80927860b7fadce3eb4e1e8610adc709e25580d8c7ad95af1de3a94b4a09e3078b86e88ae9630388711d20e28c801131cd1f924dfeddd85a9d404ef5db9e6a887845b5aa4763fbb72f259985ccf7ee6fc8329bf1ded74e5112f8c16df81e8038443df4bacb2eae1b06a48f178cdf2257941ca5887db4dc5135f0a2d050f56ac94ad9ffd4a13925c85501976937e723979cc31fd48c4d68d06e4c9cee53517dcb18da61fe4347658df495508d6ea9d7282", "", false},
		// tc18: ps terminated by 0xff
		{18, "313233343030", "3f5e00347c36ceb79f400effcae92d331aa9f52539041c50dbbc6fd071912912692a16353378276a2c1596358c46f6232434a95a99c573d0b83e4a6e970a73e99ca13d734506e2a2a56744b1872bffd501a80ba7cf5494df6ff9b421cb10247e11d19ac9e60afe0dda87cb351c21ba554ea50b70f6eee4ffa949ae38694ef831020d4e599c6ff4493d07c7b6be06453b84143813a68dfe0fada2317a9f4040a3cf6308090b6bfaca36067312f41bc0c4c01ac00fdb5aee4395b04cdff82cb433b01cd3e70daafc7807b2f770226699e7535124a453f7ad2653bfb7cfe71e120dc37ba88a5be347ad134351c11ff1019b7e42d24b7a3890a8424fae53a10c0e11", "", false},
		// tc19: ps is all zero
		{19, "313233343030", "a166bf7b5c2cf1896c0b924a69233a0a585bd47ed7f2330654aa68806deb0ff68c6475050ab45c691bbbcc58dbc2f5c817729e8e195ebd39d48bd5e14977abae0829636831655917fb5a758fb43a8e505d6ce595f625970685f7ec81cb5592210f5d68c6e2e1ef26b4ef8c92bf44f077e1d5099f379cb8120ad185bf07877979ca81f251fb81be0ad3c14f4d7885fcec496f80033fd4279b6830a20cbdead27c0967e28d1e06ef4bd7ba89210ec0d696274a187dc2f13212f5adf06e9450eca398325cfda73431036ac21b087d373c9f575c941f8cb078961176e31859a61c49baf8ff4f817a11010448d6a0e40dcede1a5ac3befa4c6e9d9d67d8e8fd8b6de3", "", false},
		// tc20: ps replaced by 0xff's
		{20, "313233343030", "75829ac4d97848dfba21c1688e936cfc736f53fde5b91d5330b63a9968dd4f51c2f529fd8d8f84e4a908196fcc5deba21b5c7300d7381e07c4e0ea2184965169cc9464933ef5a840d86b1dbcc945c7547d9eab245ba64d24946a75961161c2b8f417daf11b163b1e5a5b02d45341384f37755248fa871e6a82f948ad6292f11445bf30596dcccec73a441cea5e5dc470016309a83b6c8f158536687ad2734d3ea1562d46e23bfe8cab498d19b0b104d97182aacf852b6db3c4670109b81af1bd99b483d92b3e4bd813edfa4d0513214dcc5bb4da768e86007c22f11e5fe6f4cb60b909958fb94dea660d3fff0b99db15c2d2e6c8df7478330dade8c517b90975", "", false},
		// tc21: seed is all 0
		{21, "313233343030", "8e5f01ff0c1775870715fd0366a8748531f8b00803df35e0e2308db63bbec4eca4e093351876b794213b904e5dde284a82d74abfcbfff94bc9a8300bea99edd07fe97d6e0b11219f85ac15acc404d37d3da16819a14a438f3f72f8178b312526232386e918a8a7e11fc38f4668c499a00480cf9d2d75aabc0198d3ba9ba345fba9105c6564df5f6ce796f14100d186abffe4d83d57969c1caddc7c7aa340b4d1bab23d9b3982278328ddebe648f5c52588738f3c56a88b3f34c890c03fafc27f485a17677a53e974dc1dd86f463a927f4328ac51bbc61705ae8abd7f45628957489e2defd8e043b955b118fb2a1c407d45893004aae0f945f06add1e45b41a03", "", true},
		// tc22: seed is all 1
		{22, "313233343030", "50c23e2ad6e3f3b10a5716cbf60efcc9f66d2c6f17bf050ba0153b877ba2755e8a0d54060034562266155744ef80547b8af777b0ff764fbb12baae49d02b4f6d65b6cd8f0a397839101d32ae163ff2e6072748d6b8017e5e73e332d53f4e91fe6233a82dbf54f3146b489803575c5ea37ab55a9ea7eae47ad4f1727d45822b569cd6e5d4b6ab759850948186616b5da2a9a316f57d899f91934bbb27edcdfa19532ba1c01f3724738daffdd88c9a18562ebcbc49185b0a817407903476d442c424c81b63aeb8f9d1b184756e0cc0a381eaba45a85c8bbc6770fd047ff1a6404a384599fbbd6a40b212a066e23f6a15cf13e42c0ea88c710e4d70c612074968e5", "", true},
		// tc23: First byte is 1
		{23, "313233343030", "3f92a694661cae336cac7a3c5a6f67e0655d10218a64459739ab9664f2cec58978939512df621e6b92fe3429bb22c08b5103da648a7719e7e95a04e6b61601546955825d60f4c517619f851780ad17f1b8a955cf8c7f1a5e26ca4a0cc19cca751d0790d56e1140a4705e19274f638b7c16d9d3e423a7f787d02699235e3e9e4d543a954f9b1bce5411c8ebdcae86a4bb86c66818a0bab51a2b00383b318e53d95508bab1b19e388cd5a03cdceba0f7176c1782e19ef62cff69352d444b1ce0e1f339e96d8a65c07aa37f5f2cf33867f6c496e0da6cd79b3e2183b57064ce21a1b92072702e555a82cad75107fdfd8bd5e7ea5f119cfbbc1770e962fd0b781aff", "", false},
		// tc24: m is 0
		{24, "313233343030", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "", false},
		// tc25: m is 1
		{25, "313233343030", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "", false},
		// tc26: m is n-1
		{26, "313233343030", "a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d4", "", false},
		// tc27: added n to c
		{27, "313233343030", "b056e2513c7c470d897032d406e97b5946dcad52df1c1650d61a1d7b0af59e8cfaec4d9e834d06d819b92a7d440d277e5039ab8aeff25043e98b281ae6ce0a91f8dfbbd1b4998fe5481671381b6a3952448b617ae606f06a0143561a040edaf3c972e611bd7cb814aa4761d38e4a007ca65af8fde6eb25d919d8bd9273cca7622984aa27994d049612424547775c5df75483962143522d075b8c55ea61b04583eb4c0358f9fbb902dedff30b7d8592b57094df4f6345668af53d1aea86fb36dd69b4434bacf8fc12c13802f5b03551ba8f207d4060a9f56e6b7e18c766eb82b6ce6ee0747fbe785c3c1c25fe7fb87de50032b172129fa41a69c3ce0e777ef10f", "", false},
		// tc28: ciphertext not reduced
		{28, "313233343030", "6ea4320bc5bcae709d0e4b9d67e7f0c248a65c5bc0762910e220ea96bdea088e20ce7ffb726a8fd87fa363249dc0ace75fdbe025b270dd72490cb164c468388117bd95624bddfb70c1f07f98a6b9ccf9cee3d2b5f5b3e79a6664568a788b3f1002fc9546d6b3a0fb5f3cfb14f70785dc542dbbbaffbb3b791f0a5906ace090a3c29d123db768ecce56f0dbf99956f070ce2ebe8209c2ff6de6064ac6247f81c4064960c516f684f9e740b00f361844d9c1bcb1553bed9b297462e8badd3d431a09b62c773b0071a8d734aae4de04bac45b7bf8555471e937b0a36f0c1bce595ec9b3d366c9109319a3501156a08c21393e31fcffa2c51b242dac9f813c8f968600", "", false},
		// tc29: ciphertext is empty
		{29, "313233343030", "", "", false},
		// tc30: prepended bytes to ciphertext
		{30, "313233343030", "00000da290b0bf71a1141b2adc62b5b42b07fc52520cb05d1f39ccca7b7c22d379a6c2f2d93143d057050140527a1e5638243938b531ec3de7014b0151301e49b9fa433482a02abdfd94193dc9c70157e557776a69ded01ecbeac405133595c61165a428b6284729a4746b47d2bbaca9d7432c3b5693591cfee488eb3c68ddb6cde0dd61cfc6952423f994abecee34f5683732b29934a2c498ad48cdd30c149177189f48eefd9cc7232df18be11ff5f7e3af7319e3115997c599e2d8f7f4f663dcc40032d403436d3058a5ea66473660f0e195281ec6eba997d2a951ca6ca5f3c112715c89da1d3dfb20a21940594ed10ade90ed7452b753757d7241cb8a803c373a", "", false},
		// tc31: appended bytes to ciphertext
		{31, "313233343030", "0da290b0bf71a1141b2adc62b5b42b07fc52520cb05d1f39ccca7b7c22d379a6c2f2d93143d057050140527a1e5638243938b531ec3de7014b0151301e49b9fa433482a02abdfd94193dc9c70157e557776a69ded01ecbeac405133595c61165a428b6284729a4746b47d2bbaca9d7432c3b5693591cfee488eb3c68ddb6cde0dd61cfc6952423f994abecee34f5683732b29934a2c498ad48cdd30c149177189f48eefd9cc7232df18be11ff5f7e3af7319e3115997c599e2d8f7f4f663dcc40032d403436d3058a5ea66473660f0e195281ec6eba997d2a951ca6ca5f3c112715c89da1d3dfb20a21940594ed10ade90ed7452b753757d7241cb8a803c373a0000", "", false},
		// tc32: truncated ciphertext
		{32, "313233343030", "a290b0bf71a1141b2adc62b5b42b07fc52520cb05d1f39ccca7b7c22d379a6c2f2d93143d057050140527a1e5638243938b531ec3de7014b0151301e49b9fa433482a02abdfd94193dc9c70157e557776a69ded01ecbeac405133595c61165a428b6284729a4746b47d2bbaca9d7432c3b5693591cfee488eb3c68ddb6cde0dd61cfc6952423f994abecee34f5683732b29934a2c498ad48cdd30c149177189f48eefd9cc7232df18be11ff5f7e3af7319e3115997c599e2d8f7f4f663dcc40032d403436d3058a5ea66473660f0e195281ec6eba997d2a951ca6ca5f3c112715c89da1d3dfb20a21940594ed10ade90ed7452b753757d7241cb8a803c373a", "", false},
		// tc33: em represents a small integer
		{33, "c4fc4b065f4595751c7ff8bb99681d505b7d0f1730d404617940f4b5c3b01979ffcffd19e86f69450e5fc14d9bc27a1f39734fd5f8f663d2d87c444e3e15da8764709909679aaa553d98ddbb1ad7dcc8be04bb8751570b4e6cdc7a8f56b09a4af43053a393bd8f947d7625137e6d84f9b9c727475a98ea22efcf679ee0aa5258da88a08afc53bd8bfa19b0131d6f676fe198a9c6a1f84174fc69ccf8e34e3617f8ff6c4192075cd6668392523fbecedb27578e591dead78c80a89be589a1", "18416ff48c3a78bc85e1f483d546052d84deac02ce86fcd197215f227b6dad58bc19394f46551111f858b08879bc37c620b1e81ebac4c75fdd71713ce75c24293fa39caf46294d28bf87a46da9a769a304157ea1fc71afc3bfb790da32e84d812a8946d1b3d211fb6972b3fe6674496b2d8056c1503d02fd4c2e607bfb1e6b26b35636b8b823757ee9ba3795d3af2dd8710b0a6da4dbb430bc69dc089f1563d34f0d79431d63e7b8d94c8234649b64223d1e0be17463401184a096feb9c81e226eec26c7e9f3f4357536633029ebc0349bc136d1206c6064fc51b6d2e79578f2b26439c5b3f6ffe1b515740b3c4b94a49430631292968eb50983251bbc7f0f89", "5a3564e9482a072bd99d0306d69a7f4595c49fb9c06b72250eed2b50ceddcc4700000000", true},
	} {
		t.Run(strconv.Itoa(tc.id), func(t *testing.T) {
			ciphertext, err := hex.DecodeString(tc.ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			message, err := hex.DecodeString(tc.message)
			if err != nil {
				t.Fatal(err)
			}
			label, err := hex.DecodeString(tc.label)
			if err != nil {
				t.Fatal(err)
			}
			p := &oaepVectorProvider{key: k}
			doc := publishedOAEPEnvelope(t, ciphertext, label)
			out, err := xmlenc.DecryptBytes(t.Context(), doc, p, xmlenc.Options{OAEP: &xmlenc.OAEPParameters{Label: label}})
			accepted := tc.valid && len(message) == 32
			if accepted {
				if err != nil || string(out) != "published OAEP CEK" {
					t.Fatal(out, err)
				}
			} else if out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
				t.Fatal("invalid OAEP or CEK length accepted", out, err)
			}
			if len(ciphertext) != k.Size() {
				if p.calls != 0 {
					t.Fatal("invalid ciphertext length reached provider", p.calls)
				}
				return
			}
			if p.calls != 1 || (p.failure == nil) != tc.valid {
				t.Fatal("published primitive result disagrees", p.calls, p.failure, tc.valid)
			}
			if tc.valid && p.length != len(message) || !tc.valid && p.length != 0 {
				t.Fatal("published primitive length", p.length, len(message))
			}
		})
	}
}

type oaepVectorProvider struct {
	key     *rsa.PrivateKey
	calls   int
	length  int
	failure error
}

func (p *oaepVectorProvider) Public() crypto.PublicKey { return &p.key.PublicKey }
func (p *oaepVectorProvider) Decrypt(random io.Reader, ciphertext []byte, options crypto.DecrypterOpts) ([]byte, error) {
	p.calls++
	out, err := p.key.Decrypt(random, ciphertext, options)
	p.failure, p.length = err, len(out)
	return out, err
}

func publishedOAEPEnvelope(t *testing.T, wrapped, label []byte) *document.Document {
	t.Helper()
	// tc7's exact published plaintext is a 32-octet AES key. Standard AEAD
	// constructs the independent data frame for this fixed test key/IV only.
	cek, err := hex.DecodeString("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 12)
	ciphertext := gcm.Seal(bytes.Clone(iv), iv, []byte("published OAEP CEK"), nil)
	oaepLabel := ""
	if len(label) > 0 {
		oaepLabel = `<xenc:OAEPparams>` + base64.StdEncoding.EncodeToString(label) + `</xenc:OAEPparams>`
	}
	wire := `<xenc:EncryptedData xmlns:xenc="` + xmlenc.Namespace + `" xmlns:ds="` + xmlenc.SignatureNamespace + `" xmlns:xenc11="` + xmlenc.Namespace11 + `"><xenc:EncryptionMethod Algorithm="` + xmlenc.AES256GCM + `"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="` + xmlenc.RSAOAEP + `">` + oaepLabel + `<ds:DigestMethod Algorithm="` + xmlenc.SHA256 + `"/><xenc11:MGF Algorithm="` + xmlenc.MGF1SHA256 + `"/></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(wrapped) + `</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(ciphertext) + `</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>`
	return parse(t, []byte(wire))
}

func TestKeyGraphImplicitCanonicalization(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("the fixed independent ciphertext fixture uses explicitly permitted CBC")
	}
	// The canonical frame is <b a="a" z="z" xml:id="c">AAAAAAAAAAAAAAAAAA</b>.
	// Its first16 octets are the IV; the remaining32 are CBC ciphertext.
	// OpenSSL3 enc -d -aes-128-cbc -nopad independently returns the literal
	// plaintext below followed by01. XMLENC5.9.1 requires implicit C14N1.0
	// when a CipherReference node set must be converted to ciphertext octets.
	want, err := hex.DecodeString("cea85e37d6cbce0572990f541088335ab8d6e8d01f385d6d19ad35c8d0fa0a")
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x0e}, 16)
	options := xmlenc.KeyGraphOptions{Data: xmlenc.Options{DataAlgorithm: xmlenc.AES128CBC, AllowLegacy: true, MaxPlaintextBytes: 64}, Keys: []xmlenc.KeyGraphKey{{Algorithm: xmlenc.AES128CBC, Secret: secret}}}
	for name, node := range map[string]string{
		"canonical input":               `<b a="a" z="z" xml:id="c">AAAAAAAAAAAAAAAAAA</b>`,
		"reordered and commented input": `<b z='z' xml:id='c' a='a'>AAAAAAAAA<!--omitted by canonicalization-->AAAAAAAAA</b>`,
	} {
		t.Run(name, func(t *testing.T) {
			wire := `<r>` + node + `<xenc:EncryptedData xmlns:xenc="` + xmlenc.Namespace + `"><xenc:EncryptionMethod Algorithm="` + xmlenc.AES128CBC + `"/><xenc:CipherData><xenc:CipherReference URI="#c"/></xenc:CipherData></xenc:EncryptedData></r>`
			doc := parse(t, []byte(wire))
			if out, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), doc, doc.Root().Children()[1], options); err != nil || !bytes.Equal(out, want) {
				t.Fatal("implicit canonicalization changed ciphertext octets", out, err)
			}
			limited := options
			limited.Data.MaxPlaintextBytes = len(want) - 1
			if out, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), doc, doc.Root().Children()[1], limited); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
				t.Fatal("post-canonicalization plaintext bound", out, err)
			}
		})
	}
}
