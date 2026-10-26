package xmlenc_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/fips140"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

func TestDirectDataKeys(t *testing.T) {
	ctx := t.Context()

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
	if bytes.Contains(wire, []byte("EncryptedKey")) {
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
	ctx := t.Context()
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
	ctx := t.Context()

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

	seen := map[string]struct{}{}

	for range 32 {
		d, err := xmlenc.EncryptBytesWithKey(ctx, nil, secret, xmlenc.SymmetricOptions{})
		if err != nil {
			t.Fatal(err)
		}

		data, _ := base64.StdEncoding.DecodeString(d.Root().Children()[1].Children()[0].Text())

		nonce := string(data[:12])
		if _, exists := seen[nonce]; exists {
			t.Fatal("nonce reused")
		}

		seen[nonce] = struct{}{}
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
		d, err := xmlenc.EncryptBytesWithKey(f.Context(), plain, secret, xmlenc.SymmetricOptions{})
		if err != nil {
			f.Fatal(err)
		}

		raw, _ := d.XML(f.Context())
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

		_, _ = xmlenc.DecryptBytesWithKey(t.Context(), d, secret, xmlenc.SymmetricOptions{Data: xmlenc.Options{MaxPlaintextBytes: 1024}})
	})
}

func cbcAlgorithms() []algorithmSpec {
	return []algorithmSpec{{xmlenc.AES128CBC, 16}, {xmlenc.AES192CBC, 24}, {xmlenc.AES256CBC, 32}, {xmlenc.TripleDESCBC, 24}}
}

func legacyBlock(t *testing.T, algorithm string, secret []byte) cipher.Block {
	t.Helper()
	var block cipher.Block
	var err error
	if algorithm == xmlenc.TripleDESCBC {
		block, err = des.NewTripleDESCipher(secret)
	} else {
		block, err = aes.NewCipher(secret)
	}
	if err != nil {
		t.Fatal(err)
	}
	return block
}

func TestLegacyCBCDataAlgorithms(t *testing.T) {
	for _, algorithm := range cbcAlgorithms() {
		t.Run(algorithm.uri, func(t *testing.T) {
			secret := bytes.Repeat([]byte{0x32}, algorithm.keyBytes)
			options := xmlenc.SymmetricOptions{Data: xmlenc.Options{DataAlgorithm: algorithm.uri, AllowLegacy: true}}
			if result, err := xmlenc.EncryptBytesWithKey(t.Context(), nil, secret, xmlenc.SymmetricOptions{Data: xmlenc.Options{DataAlgorithm: algorithm.uri}}); result != nil || !errors.Is(err, xmlenc.ErrPolicy) {
				t.Fatal("legacy default changed", result, err)
			}
			if fips140.Enabled() {
				if result, err := xmlenc.EncryptBytesWithKey(t.Context(), nil, secret, options); result != nil || !errors.Is(err, xmlenc.ErrPolicy) {
					t.Fatal(result, err)
				}
				return
			}
			block := legacyBlock(t, algorithm.uri, secret)
			for _, size := range []int{0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 4096} {
				plain := bytes.Repeat([]byte{0x42}, size)
				before := bytes.Clone(plain)
				envelope, err := xmlenc.EncryptBytesWithKey(t.Context(), plain, secret, options)
				if err != nil {
					t.Fatal(size, err)
				}
				cv := envelope.Root().Children()[1].Children()[0]
				encoded, err := base64.StdEncoding.DecodeString(cv.Text())
				b := block.BlockSize()
				if err != nil || len(encoded) != b+(size/b+1)*b {
					t.Fatal(size, len(encoded), err)
				}
				decoded := make([]byte, len(encoded)-b)
				cipher.NewCBCDecrypter(block, encoded[:b]).CryptBlocks(decoded, encoded[b:])
				if !bytes.Equal(decoded[:size], plain) || int(decoded[len(decoded)-1]) != b-size%b {
					t.Fatal("wire padding", size, decoded)
				}
				out, err := xmlenc.DecryptBytesWithKey(t.Context(), envelope, secret, options)
				if err != nil || !bytes.Equal(out, plain) || !bytes.Equal(plain, before) {
					t.Fatal(size, out, err)
				}
			}
		})
	}
}

func TestXMLENCCBCPaddingAndUnauthenticatedOutput(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy CBC is forbidden in FIPS mode")
	}
	for _, algorithm := range cbcAlgorithms() {
		t.Run(algorithm.uri, func(t *testing.T) {
			secret := bytes.Repeat([]byte{0x41}, algorithm.keyBytes)
			block := legacyBlock(t, algorithm.uri, secret)
			b := block.BlockSize()
			options := xmlenc.SymmetricOptions{Data: xmlenc.Options{DataAlgorithm: algorithm.uri, AllowLegacy: true}}
			for _, n := range []int{0, 1, b, b + 1} {
				padded := bytes.Repeat([]byte{0xa5}, b)
				padded[b-1] = byte(n)
				wire := make([]byte, 2*b)
				cipher.NewCBCEncrypter(block, wire[:b]).CryptBlocks(wire[b:], padded)
				xml := `<EncryptedData xmlns="` + xmlenc.Namespace + `"><EncryptionMethod Algorithm="` + algorithm.uri + `"/><CipherData><CipherValue>` + base64.StdEncoding.EncodeToString(wire) + `</CipherValue></CipherData></EncryptedData>`
				out, err := xmlenc.DecryptBytesWithKey(t.Context(), parse(t, []byte(xml)), secret, options)
				if n == 0 || n > b {
					if out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
						t.Fatal(n, out, err)
					}
				} else if err != nil || !bytes.Equal(out, padded[:b-n]) {
					t.Fatal("arbitrary pad octets rejected", n, out, err)
				}
			}
			plain := bytes.Repeat([]byte{'x'}, 2*b)
			envelope, err := xmlenc.EncryptBytesWithKey(t.Context(), plain, secret, options)
			if err != nil {
				t.Fatal(err)
			}
			cv := envelope.Root().Children()[1].Children()[0]
			wire, _ := base64.StdEncoding.DecodeString(cv.Text())
			wire[0] ^= 1 // IV malleability: padding stays valid; CBC has no authentication.
			raw, _ := envelope.XML(t.Context())
			changed := parse(t, bytes.Replace(raw, []byte(cv.Text()), []byte(base64.StdEncoding.EncodeToString(wire)), 1))
			out, err := xmlenc.DecryptBytesWithKey(t.Context(), changed, secret, options)
			if err != nil || len(out) != len(plain) || out[0] != plain[0]^1 {
				t.Fatal("CBC was presented as authenticated", out, err)
			}
			for _, length := range []int{0, b - 1, b, 2*b - 1} {
				bad := parse(t, bytes.Replace(raw, []byte(cv.Text()), []byte(base64.StdEncoding.EncodeToString(wire[:length])), 1))
				if out, err := xmlenc.DecryptBytesWithKey(t.Context(), bad, secret, options); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
					t.Fatal(length, out, err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if out, err := xmlenc.DecryptBytesWithKey(ctx, envelope, secret, options); out != nil || !errors.Is(err, context.Canceled) {
				t.Fatal(out, err)
			}
			limited := options
			limited.Data.MaxPlaintextBytes = len(plain) - 1
			if out, err := xmlenc.DecryptBytesWithKey(t.Context(), envelope, secret, limited); out != nil || err == nil {
				t.Fatal("plaintext limit", out, err)
			}
		})
	}
}

func TestLegacyCBCElementContentAndReferences(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy CBC is forbidden in FIPS mode")
	}
	for _, algorithm := range cbcAlgorithms() {
		t.Run(algorithm.uri, func(t *testing.T) {
			secret := bytes.Repeat([]byte{0x36}, algorithm.keyBytes)
			opts := xmlenc.SymmetricOptions{Data: xmlenc.Options{DataAlgorithm: algorithm.uri, AllowLegacy: true, MaxPlaintextBytes: 16}}
			source := parse(t, []byte(`<r xmlns="urn:r"><v/></r>`))
			before, _ := source.XML(t.Context())
			encrypted, selected, err := xmlenc.EncryptElementWithKey(t.Context(), source, source.Root().Children()[0], secret, opts)
			if err != nil {
				t.Fatal(err)
			}
			restored, _, err := xmlenc.DecryptElementWithKey(t.Context(), encrypted, selected, secret, opts)
			if err != nil {
				t.Fatal(err)
			}
			after, _ := restored.XML(t.Context())
			if !bytes.Equal(before, after) {
				t.Fatal(string(after))
			}
			encrypted, selected, err = xmlenc.EncryptContentWithKey(t.Context(), source, source.Root(), secret, opts)
			if err != nil {
				t.Fatal(err)
			}
			restored, _, err = xmlenc.DecryptContentWithKey(t.Context(), encrypted, selected, secret, opts)
			if err != nil {
				t.Fatal(err)
			}
			after, _ = restored.XML(t.Context())
			if !bytes.Equal(before, after) {
				t.Fatal(string(after))
			}
			plain := bytes.Repeat([]byte{0x42}, 16)
			envelope, err := xmlenc.EncryptBytesWithKey(t.Context(), plain, secret, opts)
			if err != nil {
				t.Fatal(err)
			}
			external, _, data, err := xmlenc.ExternalizeCiphertext(t.Context(), envelope, envelope.Root(), "urn:cbc:cipher")
			if err != nil {
				t.Fatal(err)
			}
			opts.Data.External = &xmlenc.ExternalCipherReference{URI: "urn:cbc:cipher", Resolver: xmlenc.CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil })}
			out, err := xmlenc.DecryptBytesWithKey(t.Context(), external, secret, opts)
			if err != nil || !bytes.Equal(out, plain) {
				t.Fatal(string(out), err)
			}
		})
	}
}
