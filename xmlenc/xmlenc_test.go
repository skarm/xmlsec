package xmlenc_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
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

const (
	namePayload    = "#payload"
	nameAttributes = "attributes"
	nameOne        = "one"
	nameWrap       = "wrap"
	nameBytes      = "bytes"
	nameLimit      = "limit"
	nameDepth      = "depth"
	nameNil        = "nil"
	nameNamespaces = "namespaces"
	nameNodes      = "nodes"
)

func TestRoundTripAndPrimitives(t *testing.T) {
	k := key(t)

	ctx := context.Background()
	for _, b := range [][]byte{{}, []byte("payload\x00\xff"), bytes.Repeat([]byte{1, 2, 3}, 2048)} {
		d, e := xmlenc.EncryptBytes(ctx, b, &k.PublicKey, xmlenc.Options{})
		if e != nil {
			t.Fatal(e)
		}

		raw, _ := d.XML(ctx)
		d = parse(t, raw)

		plain, e := xmlenc.DecryptBytes(ctx, d, k, xmlenc.Options{})
		if e != nil || !bytes.Equal(b, plain) {
			t.Fatalf("roundtrip %v", e)
		}
		// Decrypt the wire layout directly with standard primitives, bypassing xmlenc.
		a := d.Root().Children()
		keyValue := a[1].Children()[0].Children()[1].Children()[0].Text()
		wrapped, _ := base64.StdEncoding.DecodeString(keyValue)

		symmetric, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, k, wrapped, nil)
		if e != nil {
			t.Fatal(e)
		}

		data, _ := base64.StdEncoding.DecodeString(a[2].Children()[0].Text())
		block, _ := aes.NewCipher(symmetric)
		gcm, _ := cipher.NewGCM(block)

		direct, e := gcm.Open(nil, data[:12], data[12:], nil)
		if e != nil || !bytes.Equal(b, direct) {
			t.Fatal("wire format", e)
		}
	}
}

func TestXMLDocument(t *testing.T) {
	k := key(t)
	d := parse(t, []byte(`<?outside ok?><r xmlns="urn:test" xml:lang="ru"><v>Текст &amp; 😀</v><!--inside--></r><!--outside-->`))
	raw, _ := d.XML(t.Context())

	encrypted, e := xmlenc.EncryptDocument(context.Background(), d, &k.PublicKey, xmlenc.Options{})
	if e != nil {
		t.Fatal(e)
	}

	out, e := xmlenc.DecryptDocument(context.Background(), encrypted, k, xmlenc.Options{})
	if e != nil {
		t.Fatal(e)
	}

	b, _ := out.XML(t.Context())
	if strings.Contains(string(b), "outside") || !strings.Contains(string(b), "<!--inside-->") {
		t.Fatal(string(b))
	}

	before, _ := d.XML(t.Context())
	if !bytes.Equal(raw, before) {
		t.Fatal("mutation")
	}

	if _, e := xmlenc.DecryptBytes(context.Background(), encrypted, k, xmlenc.Options{}); !errors.Is(e, xmlenc.ErrFormat) {
		t.Fatal("type confusion", e)
	}
}

func TestRejectsTamperingAndDowngrade(t *testing.T) {
	k := key(t)

	d, e := xmlenc.EncryptBytes(context.Background(), []byte("hello"), &k.PublicKey, xmlenc.Options{})
	if e != nil {
		t.Fatal(e)
	}

	raw, _ := d.XML(t.Context())
	text := string(raw)

	for _, tc := range []struct{ name, from, to string }{{"gcm", xmlenc.AES256GCM, xmlenc.Namespace + "aes256-cbc"}, {"oaep", xmlenc.RSAOAEP, xmlenc.Namespace + "rsa-1_5"}, {"hash", xmlenc.SHA256, "urn:sha1"}, {"mgf", xmlenc.MGF1SHA256, xmlenc.Namespace11 + "mgf1sha1"}, {"extra-key", `</ds:KeyInfo>`, `<xenc:EncryptedKey/></ds:KeyInfo>`}} {
		t.Run(tc.name, func(t *testing.T) {
			bad := parse(t, []byte(strings.Replace(text, tc.from, tc.to, 1)))
			if p, e := xmlenc.DecryptBytes(context.Background(), bad, k, xmlenc.Options{}); p != nil || !errors.Is(e, xmlenc.ErrFormat) {
				t.Fatal(e)
			}
		})
	}

	for i, v := range []document.Element{d.Root().Children()[1].Children()[0].Children()[1].Children()[0], d.Root().Children()[2].Children()[0]} {
		b, _ := base64.StdEncoding.DecodeString(v.Text())
		b[len(b)-1] ^= 1

		bad := parse(t, []byte(strings.Replace(text, v.Text(), base64.StdEncoding.EncodeToString(b), 1)))
		if p, e := xmlenc.DecryptBytes(context.Background(), bad, k, xmlenc.Options{}); p != nil || !errors.Is(e, xmlenc.ErrDecrypt) {
			t.Fatalf("%d %v", i, e)
		}
	}

	wrong := key(t)
	if p, e := xmlenc.DecryptBytes(context.Background(), d, wrong, xmlenc.Options{}); p != nil || !errors.Is(e, xmlenc.ErrDecrypt) {
		t.Fatal(e)
	}

	if _, e := xmlenc.EncryptBytes(context.Background(), []byte("12345"), &k.PublicKey, xmlenc.Options{MaxPlaintextBytes: 4}); !errors.Is(e, xmlenc.ErrPolicy) {
		t.Fatal(e)
	}

	if p, e := xmlenc.DecryptBytes(context.Background(), d, k, xmlenc.Options{MaxPlaintextBytes: 1}); p != nil || e == nil {
		t.Fatal(nameLimit)
	}
}

func TestProviderAndCancellation(t *testing.T) {
	k := key(t)

	d, e := xmlenc.EncryptBytes(context.Background(), []byte("hello"), &k.PublicKey, xmlenc.Options{})
	if e != nil {
		t.Fatal(e)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &provider{k: k, want: ctx}

	a, e := xmlenc.AdaptContextDecrypter(p)
	if e != nil {
		t.Fatal(e)
	}

	if _, e := xmlenc.DecryptBytes(ctx, d, a, xmlenc.Options{}); e != nil || p.calls != 1 {
		t.Fatal(e)
	}

	p.cancel = cancel

	if out, e := xmlenc.DecryptBytes(ctx, d, a, xmlenc.Options{}); out != nil || !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}

	var nilProvider *provider
	if _, e := xmlenc.AdaptContextDecrypter(nilProvider); e == nil {
		t.Fatal(nameNil)
	}
}

func FuzzDecrypt(f *testing.F) {
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		f.Fatal(e)
	}

	f.Add([]byte(`<EncryptedData/>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			return
		}

		d, e := document.Parse(t.Context(), b, document.DefaultLimits())
		if e != nil {
			return
		}

		_, _ = xmlenc.DecryptBytes(context.Background(), d, k, xmlenc.Options{MaxPlaintextBytes: 1024})
	})
}

func BenchmarkKeyWrap(b *testing.B) {
	kek := make([]byte, 32)
	ctx := context.Background()
	opt := xmlenc.KeyWrapOptions{}

	benchmarkByteEncryption(b,
		func(plain []byte) (*document.Document, error) {
			return xmlenc.EncryptBytesWithKeyWrap(ctx, plain, kek, opt)
		},
		func(encrypted *document.Document) ([]byte, error) {
			return xmlenc.DecryptBytesWithKeyWrap(ctx, encrypted, kek, opt)
		},
	)
}

func BenchmarkDirectKey(b *testing.B) {
	secret := make([]byte, 32)
	ctx := context.Background()
	opt := xmlenc.SymmetricOptions{}

	benchmarkByteEncryption(b,
		func(plain []byte) (*document.Document, error) {
			return xmlenc.EncryptBytesWithKey(ctx, plain, secret, opt)
		},
		func(encrypted *document.Document) ([]byte, error) {
			return xmlenc.DecryptBytesWithKey(ctx, encrypted, secret, opt)
		},
	)
}

func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}

	return k
}

func parse(t *testing.T, b []byte) *document.Document {
	t.Helper()

	d, e := document.Parse(t.Context(), b, document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	return d
}

type provider struct {
	k      *rsa.PrivateKey
	want   context.Context
	calls  int
	cancel context.CancelFunc
}

func (p *provider) Public() crypto.PublicKey { return &p.k.PublicKey }

func (p *provider) Decrypt(ctx context.Context, r io.Reader, c []byte, o crypto.DecrypterOpts) ([]byte, error) {
	if ctx != p.want {
		return nil, errors.New("context not passed")
	}

	p.calls++
	if p.cancel != nil {
		p.cancel()
	}

	return p.k.Decrypt(r, c, o)
}

func benchmarkByteEncryption(b *testing.B, encrypt func([]byte) (*document.Document, error), decrypt func(*document.Document) ([]byte, error)) {
	b.Helper()

	plain := make([]byte, 4096)

	encrypted, err := encrypt(plain)
	if err != nil {
		b.Fatal(err)
	}

	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{"Encrypt", func() error { _, err := encrypt(plain); return err }},
		{"Decrypt", func() error { _, err := decrypt(encrypted); return err }},
	} {
		b.Run(operation.name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				if err := operation.run(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
