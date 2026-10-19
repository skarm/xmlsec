package xmlenc_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

func TestDirectDataKeys(t *testing.T) {
	ctx := context.Background()

	for _, algorithm := range gcmAlgorithms() {
		for _, name := range []string{"", "explicit-key"} {
			secret := bytes.Repeat([]byte{0x31}, algorithm.keyBytes)
			original := bytes.Clone(secret)

			opts := xmlenc.SymmetricOptions{Data: xmlenc.Options{DataAlgorithm: algorithm.uri}, KeyName: name}
			for _, plain := range [][]byte{nil, {}, []byte("binary\x00\xff"), bytes.Repeat([]byte{0x41}, 4096)} {
				checkDirectDataKey(t, ctx, plain, secret, opts)
			}

			if !bytes.Equal(secret, original) {
				t.Fatal("data key changed")
			}
		}
	}
}

func checkDirectDataKey(t *testing.T, ctx context.Context, plain, secret []byte, opts xmlenc.SymmetricOptions) {
	t.Helper()

	d, err := xmlenc.EncryptBytesWithKey(ctx, plain, secret, opts)
	if err != nil {
		t.Fatal(err)
	}

	wire, _ := d.XML(ctx)
	if strings.Contains(string(wire), "EncryptedKey") {
		t.Fatal("direct key unexpectedly wrapped")
	}

	cv := d.Root().Children()[len(d.Root().Children())-1].Children()[0]
	data, _ := base64.StdEncoding.DecodeString(cv.Text())
	block, _ := aes.NewCipher(secret)
	aead, _ := cipher.NewGCM(block)

	out, err := aead.Open(nil, data[:12], data[12:], nil)
	if err != nil || !bytes.Equal(out, plain) {
		t.Fatal("standard GCM disagrees", err)
	}

	out, err = xmlenc.DecryptBytesWithKey(ctx, parse(t, wire), secret, opts)
	if err != nil || !bytes.Equal(out, plain) {
		t.Fatal(err)
	}

	data[len(data)-1] ^= 1

	bad := parse(t, bytes.Replace(wire, []byte(cv.Text()), []byte(base64.StdEncoding.EncodeToString(data)), 1))
	if out, err := xmlenc.DecryptBytesWithKey(ctx, bad, secret, opts); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
		t.Fatal("bad tag returned plaintext", err)
	}

	wrong := bytes.Clone(secret)

	wrong[0] ^= 1
	if out, err := xmlenc.DecryptBytesWithKey(ctx, d, wrong, opts); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
		t.Fatal("wrong key accepted", err)
	}
}

func TestDirectKeyElementAndContent(t *testing.T) {
	ctx := context.Background()
	secret := bytes.Repeat([]byte{0x42}, 32)
	opts := xmlenc.SymmetricOptions{KeyName: "expected"}

	for _, raw := range []string{
		`<?before ok?><r xmlns="urn:r" xmlns:p="urn:p"><box><p:item z="2" a="1">é</p:item><!--comment-->text</box><tail/></r><!--after-->`,
		`<r xmlns="urn:r"><box/></r>`,
		`<r xmlns="urn:r"><box>text only</box></r>`,
	} {
		source := parse(t, []byte(raw))
		before, _ := source.XML(ctx)
		selected := source.Root().Children()[0]

		for _, content := range []bool{false, true} {
			var (
				encrypted, decrypted *document.Document
				node                 document.Element
				err                  error
			)
			if content {
				encrypted, node, err = xmlenc.EncryptContentWithKey(ctx, source, selected, secret, opts)
			} else {
				encrypted, node, err = xmlenc.EncryptElementWithKey(ctx, source, selected, secret, opts)
			}

			if err != nil {
				t.Fatal(err)
			}

			if content {
				decrypted, _, err = xmlenc.DecryptContentWithKey(ctx, encrypted, node, secret, opts)
			} else {
				decrypted, _, err = xmlenc.DecryptElementWithKey(ctx, encrypted, node, secret, opts)
			}

			if err != nil {
				t.Fatal(err)
			}

			after, _ := decrypted.XML(ctx)
			if !bytes.Equal(before, after) {
				t.Fatalf("namespace/context changed: %s", after)
			}

			unchanged, _ := source.XML(ctx)
			if !bytes.Equal(before, unchanged) {
				t.Fatal("source mutated")
			}
		}

		d, err := xmlenc.EncryptDocumentWithKey(ctx, source, secret, opts)
		if err != nil {
			t.Fatal(err)
		}

		out, err := xmlenc.DecryptDocumentWithKey(ctx, d, secret, opts)
		if err != nil || out.Root().Name() != source.Root().Name() {
			t.Fatal(err)
		}
	}
}

func TestDirectKeyPolicyAndNonce(t *testing.T) {
	ctx := context.Background()

	secret := make([]byte, 32)
	for _, bad := range []xmlenc.SymmetricOptions{{Data: xmlenc.Options{DataAlgorithm: xmlenc.AES128GCM}}, {Data: xmlenc.Options{OAEP: &xmlenc.OAEPParameters{}}}, {KeyName: " bad "}, {KeyName: "\x00"}, {KeyName: strings.Repeat("a", 1025)}} {
		if d, err := xmlenc.EncryptBytesWithKey(ctx, nil, secret, bad); d != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("invalid policy", err)
		}
	}

	d, err := xmlenc.EncryptBytesWithKey(ctx, []byte("protected"), secret, xmlenc.SymmetricOptions{KeyName: nameOne})
	if err != nil {
		t.Fatal(err)
	}

	for _, opts := range []xmlenc.SymmetricOptions{{}, {KeyName: "two"}, {Data: xmlenc.Options{DataAlgorithm: xmlenc.AES128GCM}, KeyName: nameOne}} {
		if out, err := xmlenc.DecryptBytesWithKey(ctx, d, secret, opts); out != nil || err == nil {
			t.Fatal("name/algorithm inferred from XML")
		}
	}

	seen := map[string]bool{}

	for range 32 {
		d, err := xmlenc.EncryptBytesWithKey(ctx, nil, secret, xmlenc.SymmetricOptions{})
		if err != nil {
			t.Fatal(err)
		}

		data, _ := base64.StdEncoding.DecodeString(d.Root().Children()[1].Children()[0].Text())

		nonce := string(data[:12])
		if seen[nonce] {
			t.Fatal("nonce reused")
		}

		seen[nonce] = true
	}

	limited := xmlenc.SymmetricOptions{Data: xmlenc.Options{MaxPlaintextBytes: 1}, KeyName: nameOne}
	if d, err := xmlenc.EncryptBytesWithKey(ctx, []byte("12"), secret, limited); d != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal(err)
	}

	if out, err := xmlenc.DecryptBytesWithKey(ctx, d, secret, limited); out != nil || err == nil {
		t.Fatal("plaintext limit not checked")
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	if d, err := xmlenc.EncryptBytesWithKey(canceled, nil, secret, xmlenc.SymmetricOptions{}); d != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzDecryptWithKey(f *testing.F) {
	secret := bytes.Repeat([]byte{0x57}, 32) // Public test key, never a production secret.
	for _, plain := range [][]byte{nil, []byte("positive")} {
		d, err := xmlenc.EncryptBytesWithKey(context.Background(), plain, secret, xmlenc.SymmetricOptions{})
		if err != nil {
			f.Fatal(err)
		}

		raw, _ := d.XML(context.Background())
		f.Add(raw)
	}

	f.Add([]byte(`<bad/>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}

		d, err := document.Parse(t.Context(), raw, document.DefaultLimits())
		if err != nil {
			return
		}

		_, _ = xmlenc.DecryptBytesWithKey(context.Background(), d, secret, xmlenc.SymmetricOptions{Data: xmlenc.Options{MaxPlaintextBytes: 1024}})
	})
}
