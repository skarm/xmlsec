package xmlenc_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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

	ctx := t.Context()
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

	encrypted, e := xmlenc.EncryptDocument(t.Context(), d, &k.PublicKey, xmlenc.Options{})
	if e != nil {
		t.Fatal(e)
	}

	out, e := xmlenc.DecryptDocument(t.Context(), encrypted, k, xmlenc.Options{})
	if e != nil {
		t.Fatal(e)
	}

	b, _ := out.XML(t.Context())
	if bytes.Contains(b, []byte("outside")) || !bytes.Contains(b, []byte("<!--inside-->")) {
		t.Fatal(string(b))
	}

	before, _ := d.XML(t.Context())
	if !bytes.Equal(raw, before) {
		t.Fatal("mutation")
	}

	if _, e := xmlenc.DecryptBytes(t.Context(), encrypted, k, xmlenc.Options{}); !errors.Is(e, xmlenc.ErrFormat) {
		t.Fatal("type confusion", e)
	}
}

func TestRejectsTamperingAndDowngrade(t *testing.T) {
	k := key(t)

	d, e := xmlenc.EncryptBytes(t.Context(), []byte("hello"), &k.PublicKey, xmlenc.Options{})
	if e != nil {
		t.Fatal(e)
	}

	raw, _ := d.XML(t.Context())
	text := string(raw)

	for _, tc := range []struct {
		name string
		from string
		to   string
	}{{"gcm", xmlenc.AES256GCM, xmlenc.Namespace + "aes256-cbc"}, {"oaep", xmlenc.RSAOAEP, xmlenc.Namespace + "rsa-1_5"}, {"hash", xmlenc.SHA256, "urn:sha1"}, {"mgf", xmlenc.MGF1SHA256, xmlenc.Namespace11 + "mgf1sha1"}, {"extra-key", `</ds:KeyInfo>`, `<xenc:EncryptedKey/></ds:KeyInfo>`}} {
		t.Run(tc.name, func(t *testing.T) {
			bad := parse(t, []byte(strings.Replace(text, tc.from, tc.to, 1)))
			if p, e := xmlenc.DecryptBytes(t.Context(), bad, k, xmlenc.Options{}); p != nil || !errors.Is(e, xmlenc.ErrFormat) {
				t.Fatal(e)
			}
		})
	}

	for i, v := range []document.Element{d.Root().Children()[1].Children()[0].Children()[1].Children()[0], d.Root().Children()[2].Children()[0]} {
		b, _ := base64.StdEncoding.DecodeString(v.Text())
		b[len(b)-1] ^= 1

		bad := parse(t, []byte(strings.Replace(text, v.Text(), base64.StdEncoding.EncodeToString(b), 1)))
		if p, e := xmlenc.DecryptBytes(t.Context(), bad, k, xmlenc.Options{}); p != nil || !errors.Is(e, xmlenc.ErrDecrypt) {
			t.Fatalf("%d %v", i, e)
		}
	}

	wrong := key(t)
	if p, e := xmlenc.DecryptBytes(t.Context(), d, wrong, xmlenc.Options{}); p != nil || !errors.Is(e, xmlenc.ErrDecrypt) {
		t.Fatal(e)
	}

	if _, e := xmlenc.EncryptBytes(t.Context(), []byte("12345"), &k.PublicKey, xmlenc.Options{MaxPlaintextBytes: 4}); !errors.Is(e, xmlenc.ErrPolicy) {
		t.Fatal(e)
	}

	if p, e := xmlenc.DecryptBytes(t.Context(), d, k, xmlenc.Options{MaxPlaintextBytes: 1}); p != nil || e == nil {
		t.Fatal(nameLimit)
	}
}

func TestProviderAndCancellation(t *testing.T) {
	k := key(t)

	d, e := xmlenc.EncryptBytes(t.Context(), []byte("hello"), &k.PublicKey, xmlenc.Options{})
	if e != nil {
		t.Fatal(e)
	}

	ctx, cancel := context.WithCancel(t.Context())
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

		_, _ = xmlenc.DecryptBytes(t.Context(), d, k, xmlenc.Options{MaxPlaintextBytes: 1024})
	})
}

func BenchmarkKeyWrap(b *testing.B) {
	kek := make([]byte, 32)
	ctx := b.Context()
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
	ctx := b.Context()
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

func agreementChild(t testing.TB, parent document.Element, namespace, local string) document.Element {
	t.Helper()
	var result document.Element
	for _, child := range parent.Children() {
		if child.Name() == (document.Name{Space: namespace, Local: local}) {
			if result.Valid() {
				t.Fatal("duplicate", local)
			}
			result = child
		}
	}
	if !result.Valid() {
		t.Fatal("missing", local)
	}
	return result
}

func agreementMethod(t testing.TB, doc *document.Document) document.Element {
	t.Helper()
	info := agreementChild(t, doc.Root(), xmlenc.SignatureNamespace, "KeyInfo")
	wrapped := agreementChild(t, info, xmlenc.Namespace, "EncryptedKey")
	info = agreementChild(t, wrapped, xmlenc.SignatureNamespace, "KeyInfo")
	return agreementChild(t, info, xmlenc.Namespace, "AgreementMethod")
}

func agreementPoint(t testing.TB, info document.Element) document.Element {
	t.Helper()
	value := agreementChild(t, info, xmlenc.SignatureNamespace, "KeyValue")
	value = agreementChild(t, value, xmlenc.SignatureNamespace11, "ECKeyValue")
	return agreementChild(t, value, xmlenc.SignatureNamespace11, "PublicKey")
}

func agreementKey(t testing.TB, curve ecdh.Curve) *ecdh.PrivateKey {
	t.Helper()
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestECDHRoundTripAndWire(t *testing.T) {
	for _, curve := range []ecdh.Curve{ecdh.P256(), ecdh.P384(), ecdh.P521()} {
		recipient := agreementKey(t, curve)
		for _, data := range []string{xmlenc.AES128GCM, xmlenc.AES192GCM, xmlenc.AES256GCM} {
			for _, wrap := range []string{xmlenc.AES128KeyWrap, xmlenc.AES192KeyWrap, xmlenc.AES256KeyWrap} {
				for _, hash := range []crypto.Hash{0, crypto.SHA256, crypto.SHA1} {
					t.Run(fmt.Sprintf("%s/%s/%s/%d", curve, data, wrap, hash), func(t *testing.T) {
						options := xmlenc.ECDHOptions{Data: xmlenc.Options{DataAlgorithm: data}, KeyAlgorithm: wrap}
						if hash != 0 {
							options.KDF = &xmlenc.ConcatKDFParameters{Hash: hash, AllowLegacy: hash == crypto.SHA1, AlgorithmID: []byte{0, 'a', 'l', 'g'}, PartyUInfo: []byte{0, 'u'}, PartyVInfo: []byte{0, 'v'}, SuppPubInfo: []byte{0, 0, 0, 1, 0}}
						}
						plain := []byte("payload\x00\xff")
						doc, err := xmlenc.EncryptBytesWithECDH(t.Context(), plain, recipient.PublicKey(), options)
						if hash == crypto.SHA1 && fips140.Enabled() {
							if doc != nil || !errors.Is(err, xmlenc.ErrPolicy) {
								t.Fatal(doc, err)
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						wire, err := doc.XML(t.Context())
						if err != nil {
							t.Fatal(err)
						}
						doc = parse(t, wire)
						out, err := xmlenc.DecryptBytesWithECDH(t.Context(), doc, recipient, options)
						if err != nil || !bytes.Equal(out, plain) {
							t.Fatal(out, err)
						}
						method := agreementMethod(t, doc)
						algorithm, _ := method.Attribute(document.Name{Local: "Algorithm"})
						if algorithm != xmlenc.ECDHES {
							t.Fatal(algorithm)
						}
						sender := agreementChild(t, method, xmlenc.Namespace, "OriginatorKeyInfo")
						point := agreementPoint(t, sender)
						encoded, err := base64.StdEncoding.DecodeString(point.Text())
						if err != nil {
							t.Fatal(err)
						}
						if _, err := curve.NewPublicKey(encoded); err != nil {
							t.Fatal("wire point", err)
						}
						receiver := agreementChild(t, method, xmlenc.Namespace, "RecipientKeyInfo")
						if agreementPoint(t, receiver).Text() != base64.StdEncoding.EncodeToString(recipient.PublicKey().Bytes()) {
							t.Fatal("recipient binding")
						}
						second, err := xmlenc.EncryptBytesWithECDH(t.Context(), plain, recipient.PublicKey(), options)
						if err != nil {
							t.Fatal(err)
						}
						if agreementPoint(t, agreementChild(t, agreementMethod(t, second), xmlenc.Namespace, "OriginatorKeyInfo")).Text() == point.Text() {
							t.Fatal("ephemeral key reused")
						}
						if hash == 0 {
							params := agreementChild(t, agreementChild(t, method, xmlenc.Namespace11, "KeyDerivationMethod"), xmlenc.Namespace11, "ConcatKDFParams")
							algorithm, _ := params.Attribute(document.Name{Local: "AlgorithmID"})
							partyU, _ := params.Attribute(document.Name{Local: "PartyUInfo"})
							partyV, _ := params.Attribute(document.Name{Local: "PartyVInfo"})
							digest := sha256.Sum256(recipient.PublicKey().Bytes())
							if algorithm != "00"+hex.EncodeToString([]byte(wrap)) || partyU != "00" || partyV != "00"+hex.EncodeToString(digest[:]) {
								t.Fatal("default KDF binding", algorithm, partyU, partyV)
							}
						}
					})
				}
			}
		}
	}
}

func TestECDHRejectsMetadataBeforeProvider(t *testing.T) {
	recipient := agreementKey(t, ecdh.P256())
	options := xmlenc.ECDHOptions{RecipientKeyName: "static-recipient"}
	doc, err := xmlenc.EncryptBytesWithECDH(t.Context(), []byte("secret"), recipient.PublicKey(), options)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	method := agreementMethod(t, doc)
	point := agreementPoint(t, agreementChild(t, method, xmlenc.Namespace, "OriginatorKeyInfo")).Text()
	params := agreementChild(t, agreementChild(t, method, xmlenc.Namespace11, "KeyDerivationMethod"), xmlenc.Namespace11, "ConcatKDFParams")
	partyV, _ := params.Attribute(document.Name{Local: "PartyVInfo"})
	invalidPoint := append([]byte{4}, make([]byte, 64)...)
	for _, test := range []struct {
		name string
		from string
		to   string
	}{
		{"agreement algorithm", xmlenc.ECDHES, "urn:wrong"},
		{"key algorithm", xmlenc.AES256KeyWrap, xmlenc.AES128KeyWrap},
		{"data algorithm", xmlenc.AES256GCM, xmlenc.AES128GCM},
		{"curve", "urn:oid:1.2.840.10045.3.1.7", "urn:oid:1.3.132.0.34"},
		{"off curve", point, base64.StdEncoding.EncodeToString(invalidPoint)},
		{"compressed", point, base64.StdEncoding.EncodeToString(append([]byte{2}, make([]byte, 32)...))},
		{"infinity", point, "AA=="},
		{"hybrid", point, base64.StdEncoding.EncodeToString(append([]byte{6}, make([]byte, 64)...))},
		{"oversized point", point, base64.StdEncoding.EncodeToString(make([]byte, 66))},
		{"KDF parameters", partyV, "00" + strings.Repeat("00", 32)},
		{"KDF algorithm", xmlenc.ConcatKDF, "urn:wrong-kdf"},
		{"digest downgrade", xmlenc.SHA256, xmlenc.SHA1},
		{"name", "static-recipient", "other-recipient"},
		{"unknown child", "</xenc:AgreementMethod>", "<xenc:Unknown/></xenc:AgreementMethod>"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := bytes.Replace(raw, []byte(test.from), []byte(test.to), 1)
			if bytes.Equal(changed, raw) {
				t.Fatal("mutation absent")
			}
			provider := &agreementProvider{key: recipient, want: t.Context()}
			adapter, err := xmlenc.AdaptContextECDHRecipient(provider)
			if err != nil {
				t.Fatal(err)
			}
			if out, err := xmlenc.DecryptBytesWithECDH(t.Context(), parse(t, changed), adapter, options); out != nil || err == nil || provider.calls != 0 {
				t.Fatal(out, err, provider.calls)
			}
		})
	}
}

type agreementProvider struct {
	key    *ecdh.PrivateKey
	want   context.Context
	calls  int
	cancel context.CancelFunc
	trim   bool
}

func (p *agreementProvider) PublicKey() *ecdh.PublicKey { return p.key.PublicKey() }
func (p *agreementProvider) ECDH(ctx context.Context, peer *ecdh.PublicKey) ([]byte, error) {
	if ctx != p.want {
		return nil, errors.New("context not passed")
	}
	p.calls++
	if p.cancel != nil {
		p.cancel()
	}
	secret, err := p.key.ECDH(peer)
	if p.trim && len(secret) > 0 {
		secret = secret[1:]
	}
	return secret, err
}

func TestECDHPolicyAndContext(t *testing.T) {
	recipient := agreementKey(t, ecdh.P256())
	doc, err := xmlenc.EncryptBytesWithECDH(t.Context(), []byte("secret"), recipient.PublicKey(), xmlenc.ECDHOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	provider := &agreementProvider{key: recipient, want: ctx}
	adapter, err := xmlenc.AdaptContextECDHRecipient(provider)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := xmlenc.DecryptBytesWithECDH(ctx, doc, adapter, xmlenc.ECDHOptions{}); err != nil || string(out) != "secret" || provider.calls != 1 {
		t.Fatal(out, err, provider.calls)
	}
	provider.cancel = cancel
	if out, err := xmlenc.DecryptBytesWithECDH(ctx, doc, adapter, xmlenc.ECDHOptions{}); out != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(out, err)
	}
	var nilProvider *agreementProvider
	if _, err := xmlenc.AdaptContextECDHRecipient(nilProvider); !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal(err)
	}
	for _, options := range []xmlenc.ECDHOptions{{Data: xmlenc.Options{OAEP: &xmlenc.OAEPParameters{}}}, {KeyAlgorithm: xmlenc.TripleDESKeyWrap}, {KDF: &xmlenc.ConcatKDFParameters{Hash: crypto.SHA1}}, {KDF: &xmlenc.ConcatKDFParameters{Hash: crypto.SHA512}}, {KDF: &xmlenc.ConcatKDFParameters{PartyUInfo: []byte{8, 0}}}, {RecipientKeyName: " leading"}, {RecipientKeyName: string([]byte{0xff})}, {RecipientKeyName: strings.Repeat("x", 1025)}} {
		if out, err := xmlenc.EncryptBytesWithECDH(t.Context(), []byte("x"), recipient.PublicKey(), options); out != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal(options, out, err)
		}
	}
	if out, err := xmlenc.DecryptBytesWithECDH(t.Context(), doc, nil, xmlenc.ECDHOptions{}); out != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal(out, err)
	}
	if out, err := xmlenc.EncryptBytesWithECDH(nil, []byte("x"), recipient.PublicKey(), xmlenc.ECDHOptions{}); out != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal(out, err)
	}
	unsupported := agreementKey(t, ecdh.X25519())
	if out, err := xmlenc.EncryptBytesWithECDH(t.Context(), []byte("x"), unsupported.PublicKey(), xmlenc.ECDHOptions{}); out != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal(out, err)
	}
}

func agreementCurveLabel(curve ecdh.Curve) string { return fmt.Sprint(curve) }

func agreementRecipientXML(t testing.TB, raw []byte, replacement string) []byte {
	t.Helper()
	start := bytes.Index(raw, []byte("<xenc:RecipientKeyInfo"))
	if start < 0 {
		t.Fatal("recipient info absent")
	}
	end := bytes.Index(raw[start:], []byte("</xenc:RecipientKeyInfo>"))
	if end < 0 {
		t.Fatal("recipient close absent")
	}
	end += start + len("</xenc:RecipientKeyInfo>")
	return append(append(append([]byte{}, raw[:start]...), []byte(replacement)...), raw[end:]...)
}

func TestECDHLeadingZeroSecret(t *testing.T) {
	scalar := make([]byte, 32)
	scalar[31] = 1
	recipient, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	scalar[30], scalar[31] = 1, 123 // 379G has a leading-zero x-coordinate.
	originator, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := recipient.ECDH(originator.PublicKey())
	if err != nil || len(secret) != 32 || secret[0] != 0 {
		t.Fatal(secret, err)
	}
	defer clear(secret)
	params := &xmlenc.ConcatKDFParameters{AlgorithmID: []byte{0}}
	kek, err := xmlenc.DeriveConcatKey(t.Context(), secret, 256, *params)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(kek)
	plain := []byte("fixed leading-zero agreement")
	wrapped, err := xmlenc.EncryptBytesWithKeyWrap(t.Context(), plain, kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw := xmlBytes(t, wrapped)
	info := `<ds:KeyInfo xmlns:ds="` + xmlenc.SignatureNamespace + `" xmlns:xenc="` + xmlenc.Namespace + `" xmlns:xenc11="` + xmlenc.Namespace11 + `" xmlns:dsig11="` + xmlenc.SignatureNamespace11 + `"><xenc:AgreementMethod Algorithm="` + xmlenc.ECDHES + `"><xenc11:KeyDerivationMethod Algorithm="` + xmlenc.ConcatKDF + `"><xenc11:ConcatKDFParams AlgorithmID="00" PartyUInfo="" PartyVInfo=""><ds:DigestMethod Algorithm="` + xmlenc.SHA256 + `"/></xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>`
	keyValue := func(public *ecdh.PublicKey) string {
		return `<ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>` + base64.StdEncoding.EncodeToString(public.Bytes()) + `</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue>`
	}
	info += `<xenc:OriginatorKeyInfo>` + keyValue(originator.PublicKey()) + `</xenc:OriginatorKeyInfo><xenc:RecipientKeyInfo>` + keyValue(recipient.PublicKey()) + `</xenc:RecipientKeyInfo></xenc:AgreementMethod></ds:KeyInfo>`
	wire := bytes.Replace(raw, []byte("<xenc:CipherData>"), []byte(info+"<xenc:CipherData>"), 1)
	if bytes.Equal(wire, raw) {
		t.Fatal("insertion absent")
	}
	options := xmlenc.ECDHOptions{KDF: params}
	for _, omit := range []bool{false, true} {
		input := wire
		if omit {
			input = agreementRecipientXML(t, input, "")
		}
		if out, err := xmlenc.DecryptBytesWithECDH(t.Context(), parse(t, input), recipient, options); err != nil || !bytes.Equal(out, plain) {
			t.Fatal(out, err)
		}
	}
	provider := &agreementProvider{key: recipient, want: t.Context(), trim: true}
	adapter, err := xmlenc.AdaptContextECDHRecipient(provider)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := xmlenc.DecryptBytesWithECDH(t.Context(), parse(t, wire), adapter, options); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
		t.Fatal(out, err)
	}
	wrong := agreementKey(t, ecdh.P256())
	if out, err := xmlenc.DecryptBytesWithECDH(t.Context(), parse(t, agreementRecipientXML(t, wire, "")), wrong, options); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
		t.Fatal(out, err)
	}
}

func TestECDHOptionalRecipientAndLimits(t *testing.T) {
	recipient := agreementKey(t, ecdh.P256())
	for _, name := range []string{"", "recipient"} {
		options := xmlenc.ECDHOptions{RecipientKeyName: name}
		doc, err := xmlenc.EncryptBytesWithECDH(t.Context(), []byte("x"), recipient.PublicKey(), options)
		if err != nil {
			t.Fatal(err)
		}
		raw := xmlBytes(t, doc)
		absent := parse(t, agreementRecipientXML(t, raw, ""))
		out, err := xmlenc.DecryptBytesWithECDH(t.Context(), absent, recipient, options)
		if name == "" {
			if err != nil || string(out) != "x" {
				t.Fatal(out, err)
			}
		} else {
			if out != nil || !errors.Is(err, xmlenc.ErrFormat) {
				t.Fatal(out, err)
			}
		}
		if name != "" {
			named := parse(t, agreementRecipientXML(t, raw, `<xenc:RecipientKeyInfo><ds:KeyName>recipient</ds:KeyName></xenc:RecipientKeyInfo>`))
			if out, err := xmlenc.DecryptBytesWithECDH(t.Context(), named, recipient, options); err != nil || string(out) != "x" {
				t.Fatal(out, err)
			}
		}
	}
	field := make([]byte, 4097)
	for index := 1; index < len(field); index++ {
		field[index] = byte(index)
	}
	parameters := &xmlenc.ConcatKDFParameters{AlgorithmID: field, PartyUInfo: field, PartyVInfo: field, SuppPubInfo: field, SuppPrivInfo: field}
	options := xmlenc.ECDHOptions{Data: xmlenc.Options{MaxPlaintextBytes: 1}, KDF: parameters}
	doc, err := xmlenc.EncryptBytesWithECDH(t.Context(), []byte("x"), recipient.PublicKey(), options)
	if err != nil {
		t.Fatal("bounded large metadata", err)
	}
	if out, err := xmlenc.DecryptBytesWithECDH(t.Context(), doc, recipient, options); err != nil || string(out) != "x" {
		t.Fatal(out, err)
	}
	if out, err := xmlenc.EncryptBytesWithECDH(t.Context(), []byte("xx"), recipient.PublicKey(), options); out != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal(out, err)
	}
	if fips140.Enabled() {
		return
	}
	legacy := xmlenc.ECDHOptions{Data: xmlenc.Options{DataAlgorithm: xmlenc.AES128CBC, AllowLegacy: true}, KeyAlgorithm: xmlenc.AES128KeyWrap, KDF: &xmlenc.ConcatKDFParameters{Hash: crypto.SHA1, AllowLegacy: true}}
	doc, err = xmlenc.EncryptBytesWithECDH(t.Context(), []byte("legacy"), recipient.PublicKey(), legacy)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := xmlenc.DecryptBytesWithECDH(t.Context(), doc, recipient, legacy); err != nil || string(out) != "legacy" {
		t.Fatal(out, err)
	}
}

func TestECDHOriginatorHints(t *testing.T) {
	recipient := agreementKey(t, ecdh.P256())
	doc, err := xmlenc.EncryptBytesWithECDH(t.Context(), []byte("hint is not trust"), recipient.PublicKey(), xmlenc.ECDHOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw := xmlBytes(t, doc)
	for _, test := range []struct {
		name  string
		hint  string
		valid bool
	}{
		{"ignored name", `<ds:KeyName>untrusted sender name</ds:KeyName>`, true},
		{"empty name", `<ds:KeyName/>`, true},
		{"duplicate name", `<ds:KeyName>a</ds:KeyName><ds:KeyName>b</ds:KeyName>`, false},
		{"oversized name", `<ds:KeyName>` + strings.Repeat("x", 1025) + `</ds:KeyName>`, false},
		{"name attributes", `<ds:KeyName extra="x">a</ds:KeyName>`, false},
		{"name child", `<ds:KeyName><ds:KeyName/></ds:KeyName>`, false},
		{"name control", `<ds:KeyName>&#9;a</ds:KeyName>`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := bytes.Replace(raw, []byte(`<xenc:OriginatorKeyInfo>`), []byte(`<xenc:OriginatorKeyInfo>`+test.hint), 1)
			provider := &agreementProvider{key: recipient, want: t.Context()}
			adapter, err := xmlenc.AdaptContextECDHRecipient(provider)
			if err != nil {
				t.Fatal(err)
			}
			result, err := xmlenc.DecryptBytesWithECDH(t.Context(), parse(t, changed), adapter, xmlenc.ECDHOptions{})
			if test.valid {
				if err != nil || string(result) != "hint is not trust" || provider.calls != 1 {
					t.Fatal(result, err, provider.calls)
				}
			} else if result != nil || err == nil || provider.calls != 0 {
				t.Fatal(result, err, provider.calls)
			}
		})
	}
}

func TestECDHLegacyDataPolicy(t *testing.T) {
	recipient := agreementKey(t, ecdh.P256())
	for _, algorithm := range []string{xmlenc.AES128CBC, xmlenc.AES192CBC, xmlenc.AES256CBC, xmlenc.TripleDESCBC} {
		t.Run(algorithm, func(t *testing.T) {
			options := xmlenc.ECDHOptions{Data: xmlenc.Options{DataAlgorithm: algorithm}}
			if doc, err := xmlenc.EncryptBytesWithECDH(t.Context(), []byte("legacy"), recipient.PublicKey(), options); doc != nil || !errors.Is(err, xmlenc.ErrPolicy) {
				t.Fatal(doc, err)
			}
			options.Data.AllowLegacy = true
			doc, err := xmlenc.EncryptBytesWithECDH(t.Context(), []byte("legacy"), recipient.PublicKey(), options)
			if fips140.Enabled() {
				if doc != nil || !errors.Is(err, xmlenc.ErrPolicy) {
					t.Fatal(doc, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := xmlenc.DecryptBytesWithECDH(t.Context(), doc, recipient, options); err != nil || string(got) != "legacy" {
				t.Fatal(got, err)
			}
			options.Data.AllowLegacy = false
			provider := &agreementProvider{key: recipient, want: t.Context()}
			adapter, err := xmlenc.AdaptContextECDHRecipient(provider)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := xmlenc.DecryptBytesWithECDH(t.Context(), doc, adapter, options); got != nil || !errors.Is(err, xmlenc.ErrPolicy) || provider.calls != 0 {
				t.Fatal(got, err, provider.calls)
			}
		})
	}
}
