package xmlenc_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil"
	"github.com/skarm/xmlsec/xmlenc"
)

const nameOAEPPayload = "OAEP payload"

func TestOAEPParameters(t *testing.T) {
	k := key(t)

	for _, hash := range []crypto.Hash{crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		for _, label := range [][]byte{nil, {}, []byte("application\x00label\xff"), bytes.Repeat([]byte{0x42}, 1024)} {
			checkOAEPParameterCase(t, k, hash, label)
		}
	}
}

func TestOAEPMaskAndLegacyParameters(t *testing.T) {
	k := key(t)

	hashes := []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512}
	for _, hash := range hashes {
		for _, mgf := range hashes {
			for _, algorithm := range []string{xmlenc.RSAOAEP, xmlenc.RSAOAEP10} {
				if algorithm == xmlenc.RSAOAEP10 && mgf != crypto.SHA1 {
					continue
				}

				legacy := algorithm == xmlenc.RSAOAEP10 || hash == crypto.SHA1 || mgf == crypto.SHA1
				t.Run(fmt.Sprintf("%s/%s/%s", algorithm, hash, mgf), func(t *testing.T) {
					p := xmlenc.OAEPParameters{Algorithm: algorithm, Hash: hash, MGFHash: mgf, AllowLegacy: legacy, Label: []byte("bound\x00label\xff")}
					if fips140.Enabled() && legacy {
						if d, err := xmlenc.EncryptBytes(t.Context(), nil, &k.PublicKey, xmlenc.Options{OAEP: &p}); d != nil || !errors.Is(err, xmlenc.ErrPolicy) {
							t.Fatal("legacy OAEP escaped FIPS policy", err)
						}

						return
					}

					checkOAEPMask(t, k, p)
				})
			}
		}
	}
}

func checkOAEPMask(t *testing.T, k *rsa.PrivateKey, p xmlenc.OAEPParameters) {
	t.Helper()

	opts := xmlenc.Options{OAEP: &p}

	d, err := xmlenc.EncryptBytes(t.Context(), []byte(nameOAEPPayload), &k.PublicKey, opts)
	if err != nil {
		t.Fatal(err)
	}

	wrapped, err := base64.StdEncoding.DecodeString(d.Root().Children()[1].Children()[0].Children()[1].Children()[0].Text())
	if err != nil {
		t.Fatal(err)
	}

	actual, err := k.Decrypt(rand.Reader, wrapped, &rsa.OAEPOptions{Hash: p.Hash, MGFHash: p.MGFHash, Label: p.Label})
	if err != nil || len(actual) != 32 {
		t.Fatal("standard OAEP parameters disagree", err)
	}

	clear(actual)

	out, err := xmlenc.DecryptBytes(t.Context(), d, k, opts)
	if err != nil || string(out) != nameOAEPPayload {
		t.Fatal("OAEP round trip", err)
	}
	// Application choices, not wire metadata, decide the accepted parameter set.
	provider := &provider{k: k, want: t.Context()}

	adapted, err := xmlenc.AdaptContextDecrypter(provider)
	if err != nil {
		t.Fatal(err)
	}

	wrong := p

	wrong.MGFHash = crypto.SHA256
	if wrong.MGFHash == p.MGFHash {
		wrong.MGFHash = crypto.SHA512
	}

	if out, err := xmlenc.DecryptBytes(t.Context(), d, adapted, xmlenc.Options{OAEP: &wrong}); out != nil || err == nil || provider.calls != 0 {
		t.Fatal("wrong MGF accepted or invoked provider", err, provider.calls)
	}

	if p.AllowLegacy {
		denied := p

		denied.AllowLegacy = false
		if d, err := xmlenc.EncryptBytes(t.Context(), nil, &k.PublicKey, xmlenc.Options{OAEP: &denied}); d != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("legacy encryption without opt-in", err)
		}

		if out, err := xmlenc.DecryptBytes(t.Context(), d, adapted, xmlenc.Options{OAEP: &denied}); out != nil || !errors.Is(err, xmlenc.ErrPolicy) || provider.calls != 0 {
			t.Fatal("legacy decryption without opt-in", err, provider.calls)
		}
	}

	checkOAEPXMLDefaults(t, k, p, d)

	wire, err := d.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	badWrapped := bytes.Clone(wrapped)
	badWrapped[0] ^= 0x80

	bad := parse(t, bytes.Replace(wire, []byte(base64.StdEncoding.EncodeToString(wrapped)), []byte(base64.StdEncoding.EncodeToString(badWrapped)), 1))
	if out, err := xmlenc.DecryptBytes(t.Context(), bad, k, opts); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
		t.Fatal("bad transported key returned plaintext", err)
	}
}

func checkOAEPXMLDefaults(t *testing.T, k *rsa.PrivateKey, p xmlenc.OAEPParameters, d *document.Document) {
	t.Helper()

	opts := xmlenc.Options{OAEP: &p}

	wire, err := d.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if p.Algorithm == xmlenc.RSAOAEP10 && bytes.Contains(wire, []byte("<xenc11:MGF")) {
		t.Fatal("fixed-MGF algorithm emitted forbidden MGF")
	}
	// Omitted XML parameters have SHA-1 defaults, independently for digest/MGF.
	for _, field := range []struct {
		prefix string
		uri    string
		hash   crypto.Hash
	}{
		{"ds:DigestMethod", hashURI(p.Hash), p.Hash},
		{"xenc11:MGF", mgfURI(p.MGFHash), p.MGFHash},
	} {
		if p.Algorithm == xmlenc.RSAOAEP10 && field.prefix == "xenc11:MGF" {
			continue
		}

		tag := `<` + field.prefix + ` Algorithm="` + field.uri + `"></` + field.prefix + `>`
		if !bytes.Contains(wire, []byte(tag)) {
			t.Fatal("missing explicit OAEP field", field.prefix)
		}

		omitted := parse(t, bytes.Replace(wire, []byte(tag), nil, 1))

		out, err := xmlenc.DecryptBytes(t.Context(), omitted, k, opts)
		if field.hash == crypto.SHA1 {
			if err != nil || string(out) != nameOAEPPayload {
				t.Fatal("SHA-1 XML default rejected", err)
			}
		} else if out != nil || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatal("omitted parameter changed expected hash", err)
		}
	}
}

func hashURI(h crypto.Hash) string {
	return map[crypto.Hash]string{crypto.SHA1: xmlenc.SHA1, crypto.SHA224: xmlenc.SHA224, crypto.SHA256: xmlenc.SHA256, crypto.SHA384: xmlenc.SHA384, crypto.SHA512: xmlenc.SHA512}[h]
}

func mgfURI(h crypto.Hash) string {
	return map[crypto.Hash]string{crypto.SHA1: xmlenc.MGF1SHA1, crypto.SHA224: xmlenc.MGF1SHA224, crypto.SHA256: xmlenc.MGF1SHA256, crypto.SHA384: xmlenc.MGF1SHA384, crypto.SHA512: xmlenc.MGF1SHA512}[h]
}

func TestOAEPLegacyXMLDefaultsAndPolicy(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy OAEP is forbidden with FIPS enabled; covered by parameter matrix")
	}

	k := key(t)

	for _, algorithm := range []string{xmlenc.RSAOAEP, xmlenc.RSAOAEP10} {
		p := xmlenc.OAEPParameters{Algorithm: algorithm, Hash: crypto.SHA1, MGFHash: crypto.SHA1, AllowLegacy: true}

		d, err := xmlenc.EncryptBytes(t.Context(), []byte("legacy"), &k.PublicKey, xmlenc.Options{OAEP: &p})
		if err != nil {
			t.Fatal(err)
		}

		wire, _ := d.XML(t.Context())
		for _, field := range []string{
			`<ds:DigestMethod Algorithm="` + xmlenc.SHA1 + `"></ds:DigestMethod>`,
			`<xenc11:MGF Algorithm="` + xmlenc.MGF1SHA1 + `"></xenc11:MGF>`,
		} {
			wire = bytes.Replace(wire, []byte(field), nil, 1)
		}

		if out, err := xmlenc.DecryptBytes(t.Context(), parse(t, wire), k, xmlenc.Options{OAEP: &p}); err != nil || string(out) != "legacy" {
			t.Fatal("standard omitted SHA-1 defaults rejected", err)
		}
		// Enabling compatibility alone never changes SHA-256 application defaults.
		if out, err := xmlenc.DecryptBytes(t.Context(), d, k, xmlenc.Options{OAEP: &xmlenc.OAEPParameters{AllowLegacy: true}}); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatal("compatibility flag widened exact expectations", err)
		}

		if algorithm == xmlenc.RSAOAEP10 {
			bad := bytes.Replace(wire, []byte(`Algorithm="`+algorithm+`">`), []byte(`Algorithm="`+algorithm+`"><xenc11:MGF Algorithm="`+xmlenc.MGF1SHA1+`"/>`), 1)
			provider := &provider{k: k, want: t.Context()}

			adapted, err := xmlenc.AdaptContextDecrypter(provider)
			if err != nil {
				t.Fatal(err)
			}

			if out, err := xmlenc.DecryptBytes(t.Context(), parse(t, bad), adapted, xmlenc.Options{OAEP: &p}); out != nil || !errors.Is(err, xmlenc.ErrFormat) || provider.calls != 0 {
				t.Fatal("forbidden MGF parameter reached provider", err, provider.calls)
			}
		}
	}
}

func TestOAEPLegacyFIPSPolicy(t *testing.T) {
	if !testutil.RunFIPSTest(t) {
		return
	}

	k := key(t)
	provider := &provider{k: k, want: t.Context()}

	adapted, err := xmlenc.AdaptContextDecrypter(provider)
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range []xmlenc.OAEPParameters{
		{Hash: crypto.SHA1, AllowLegacy: true},
		{MGFHash: crypto.SHA1, AllowLegacy: true},
		{Algorithm: xmlenc.RSAOAEP10, AllowLegacy: true},
	} {
		opts := xmlenc.Options{OAEP: &p}
		if d, err := xmlenc.EncryptBytes(t.Context(), nil, &k.PublicKey, opts); d != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("legacy encryption reached FIPS primitives", err)
		}

		if out, err := xmlenc.DecryptBytes(t.Context(), nil, adapted, opts); out != nil || !errors.Is(err, xmlenc.ErrPolicy) || provider.calls != 0 {
			t.Fatal("legacy decryption reached FIPS provider", err, provider.calls)
		}
	}
}

func checkOAEPParameterCase(t *testing.T, k *rsa.PrivateKey, hash crypto.Hash, label []byte) {
	t.Helper()

	opts := xmlenc.Options{OAEP: &xmlenc.OAEPParameters{Hash: hash, Label: label}}

	d, err := xmlenc.EncryptBytes(t.Context(), []byte("secret"), &k.PublicKey, opts)
	if err != nil {
		t.Fatal(err)
	}

	method := d.Root().Children()[1].Children()[0].Children()[0]
	wrapped, _ := base64.StdEncoding.DecodeString(d.Root().Children()[1].Children()[0].Children()[1].Children()[0].Text())

	actual, err := rsa.DecryptOAEP(hash.New(), rand.Reader, k, wrapped, label)
	if err != nil || len(actual) != 32 {
		t.Fatalf("standard OAEP disagrees: %v", err)
	}

	clear(actual)

	wire, _ := d.XML(t.Context())

	out, err := xmlenc.DecryptBytes(t.Context(), parse(t, wire), k, opts)
	if err != nil || string(out) != "secret" {
		t.Fatal(err)
	}
	checkOAEPParameterOrder(t, k, method, wire, opts)

	wrong := xmlenc.Options{OAEP: &xmlenc.OAEPParameters{Hash: hash, Label: []byte("wrong")}}
	if out, err := xmlenc.DecryptBytes(t.Context(), d, k, wrong); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("unexpected label accepted", err)
	}

	if hash != crypto.SHA256 || len(label) != 0 {
		if out, err := xmlenc.DecryptBytes(t.Context(), d, k, xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatal("default policy broadened", err)
		}
	}
}

func checkOAEPParameterOrder(t *testing.T, k *rsa.PrivateKey, method document.Element, wire []byte, opts xmlenc.Options) {
	t.Helper()
	// Foreign DigestMethod/MGF children may be reordered, while OAEPparams
	// must remain before them in the EncryptionMethod schema sequence.
	reordered := reverseOAEPParameterOrder(method, wire, true)
	if out, err := xmlenc.DecryptBytes(t.Context(), parse(t, reordered), k, opts); err != nil || string(out) != "secret" {
		t.Fatal("foreign parameter order rejected", err)
	}
	if len(opts.OAEP.Label) == 0 {
		return
	}
	provider := &provider{k: k, want: t.Context()}
	adapted, err := xmlenc.AdaptContextDecrypter(provider)
	if err != nil {
		t.Fatal(err)
	}
	misplaced := reverseOAEPParameterOrder(method, wire, false)
	if out, err := xmlenc.DecryptBytes(t.Context(), parse(t, misplaced), adapted, opts); out != nil || !errors.Is(err, xmlenc.ErrFormat) || provider.calls != 0 {
		t.Fatal("misplaced OAEPparams accepted or reached provider", err, provider.calls)
	}
}

func reverseOAEPParameterOrder(method document.Element, wire []byte, labelFirst bool) []byte {
	var reversed bytes.Buffer

	ordered := method.Children()
	first := 0
	if labelFirst && len(ordered) > 0 && ordered[0].Name() == (document.Name{Space: xmlenc.Namespace, Local: "OAEPparams"}) {
		first = 1
	}
	slices.Reverse(ordered[first:])
	for _, v := range ordered {
		name := v.Prefix() + ":" + v.Name().Local
		reversed.WriteString("<" + name)

		if len(v.Attributes()) > 0 {
			reversed.WriteString(` Algorithm="` + v.Attributes()[0].Value + `"`)
		}

		reversed.WriteString(">" + v.Text() + "</" + name + ">")
	}

	start := bytes.Index(wire, []byte(`<xenc:EncryptionMethod Algorithm="`+xmlenc.RSAOAEP+`">`))
	start += len(`<xenc:EncryptionMethod Algorithm="` + xmlenc.RSAOAEP + `">`)
	end := start + bytes.Index(wire[start:], []byte("</xenc:EncryptionMethod>"))
	reordered := append(bytes.Clone(wire[:start]), reversed.Bytes()...)

	reordered = append(reordered, wire[end:]...)

	return reordered
}

func TestOAEPRejectsMalformedParametersBeforeProvider(t *testing.T) {
	k := key(t)
	opts := xmlenc.Options{OAEP: &xmlenc.OAEPParameters{Hash: crypto.SHA384, Label: []byte("expected")}}

	d, err := xmlenc.EncryptBytes(t.Context(), []byte("secret"), &k.PublicKey, opts)
	if err != nil {
		t.Fatal(err)
	}

	wire, _ := d.XML(t.Context())
	for _, pair := range [][2]string{
		{xmlenc.MGF1SHA384, xmlenc.MGF1SHA256},
		{xmlenc.SHA384, xmlenc.SHA256},
		{`<xenc:OAEPparams>ZXhwZWN0ZWQ=</xenc:OAEPparams>`, `<xenc:OAEPparams/>`},
		{`</xenc:OAEPparams>`, `</xenc:OAEPparams><xenc:OAEPparams>ZXhwZWN0ZWQ=</xenc:OAEPparams>`},
		{`<xenc:OAEPparams>`, `<xenc:OAEPparams bad="1">`},
		{`<xenc:OAEPparams>ZXhwZWN0ZWQ=`, `<xenc:OAEPparams>!!!`},
	} {
		if !bytes.Contains(wire, []byte(pair[0])) {
			t.Fatal("ineffective negative control")
		}

		bad := parse(t, bytes.Replace(wire, []byte(pair[0]), []byte(pair[1]), 1))

		provider := &failingProvider{public: &k.PublicKey, result: bytes.Repeat([]byte{1}, 32)}
		if out, err := xmlenc.DecryptBytes(t.Context(), bad, provider, opts); out != nil || err == nil {
			t.Fatal("malformed parameters accepted")
		}

		if !bytes.Equal(provider.result, bytes.Repeat([]byte{1}, 32)) {
			t.Fatal("provider invoked before parameter validation")
		}
	}

	for _, parameters := range []*xmlenc.OAEPParameters{
		{Hash: crypto.SHA1},
		{Hash: crypto.MD5},
		{MGFHash: crypto.MD5},
		{MGFHash: crypto.SHA1},
		{Algorithm: xmlenc.RSAOAEP10},
		{Algorithm: "urn:oaep:unsupported", AllowLegacy: true},
		{Algorithm: xmlenc.RSAOAEP10, MGFHash: crypto.SHA256, AllowLegacy: true},
		{Label: make([]byte, 1025)},
	} {
		if d, err := xmlenc.EncryptBytes(t.Context(), nil, &k.PublicKey, xmlenc.Options{OAEP: parameters}); d != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("invalid OAEP options accepted", err)
		}
	}
}

func TestRSARecipientPolicy(t *testing.T) {
	k := key(t)
	ctx := t.Context()

	d, err := xmlenc.EncryptBytes(ctx, []byte("protected"), &k.PublicKey, xmlenc.Options{})
	if err != nil {
		t.Fatal(err)
	}

	oversizedExponent := int64(0x80000001)
	for _, public := range []*rsa.PublicKey{
		nil,
		{},
		{N: new(big.Int).Neg(k.N), E: k.E},
		{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: k.E},
		{N: k.N, E: 2},
		{N: k.N, E: int(oversizedExponent)},
		{N: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 16385), big.NewInt(1)), E: k.E},
	} {
		if d, err := xmlenc.EncryptBytes(ctx, nil, public, xmlenc.Options{}); d != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("invalid RSA public key accepted", err)
		}

		provider := &failingProvider{public: public, result: bytes.Repeat([]byte{1}, 32)}
		if out, err := xmlenc.DecryptBytes(ctx, d, provider, xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("invalid RSA provider accepted", err)
		}
	}
}

func TestKeyGraphRSA(t *testing.T) {
	k := key(t)
	secret := bytes.Repeat([]byte{0x5a}, 32)
	private := &provider{k: k, want: t.Context()}
	adapted, err := xmlenc.AdaptContextDecrypter(private)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := xmlenc.EncryptKey(t.Context(), secret, xmlenc.KeyGraphKey{Name: "recipient", Algorithm: xmlenc.RSAOAEP, PublicKey: &k.PublicKey}, xmlenc.EncryptedKeyOptions{Algorithm: xmlenc.RSAOAEP, ID: "rsa-key"})
	if err != nil {
		t.Fatal(err)
	}
	data := graphData(t, secret, graphXML(t, wrapped))
	opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "recipient", Algorithm: xmlenc.RSAOAEP, Decrypter: adapted}}}
	graphAssert(t, data, data.Root(), opts)
	if private.calls != 1 {
		t.Fatal("private operation count", private.calls)
	}
	rawWrapped, err := base64.StdEncoding.DecodeString(wrapped.Root().Children()[2].Children()[0].Text())
	if err != nil {
		t.Fatal(err)
	}
	standard, err := k.Decrypt(rand.Reader, rawWrapped, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256})
	if err != nil || !bytes.Equal(standard, secret) {
		t.Fatal("independent RSA-OAEP disagrees", err)
	}
	wire := graphXML(t, data)
	for _, kind := range []string{"duplicate ID", "key size", "bad metadata", "bad key info text", "bad transform", "unknown algorithm"} {
		t.Run(kind, func(t *testing.T) {
			variant := wire
			switch kind {
			case "duplicate ID":
				variant = strings.Replace(variant, `Id="rsa-key"`, `Id="data"`, 1)
			case "key size":
				variant = strings.Replace(variant, `Algorithm="`+xmlenc.RSAOAEP+`">`, `Algorithm="`+xmlenc.RSAOAEP+`"><xenc:KeySize>1024</xenc:KeySize>`, 1)
			case "bad metadata":
				variant = strings.Replace(variant, `Id="rsa-key"`, `Id="rsa-key" unknown="x"`, 1)
			case "bad key info text":
				variant = strings.Replace(variant, `<ds:KeyName>recipient`, `illegal<ds:KeyName>recipient`, 1)
			case "bad transform":
				start := strings.Index(variant, "<xenc:CipherData")
				end := strings.Index(variant[start:], "</xenc:CipherData>") + start + len("</xenc:CipherData>")
				variant = variant[:start] + `<xenc:CipherData><xenc:CipherReference URI="urn:denied"><xenc:Transforms><ds:Transform Algorithm="urn:program"/></xenc:Transforms></xenc:CipherReference></xenc:CipherData>` + variant[end:]
			case "unknown algorithm":
				variant = strings.Replace(variant, xmlenc.RSAOAEP, xmlenc.RSAOAEP+"-unknown", 1)
			}

			doc := parse(t, []byte(variant))
			private.calls = 0
			private.want = t.Context()
			if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), doc, doc.Root(), opts); got != nil || err == nil || private.calls != 0 {
				t.Fatal("malformed graph invoked private provider", kind, err, private.calls)
			}
		})
	}
	t.Run("unwrap error does not select alternate path", func(t *testing.T) {
		variant := strings.Replace(wire, `<ds:KeyInfo xmlns:ds="`+xmlenc.SignatureNamespace+`">`, `<ds:KeyInfo xmlns:ds="`+xmlenc.SignatureNamespace+`"><ds:KeyName>direct</ds:KeyName>`, 1)
		if variant == wire {
			t.Fatal("fixture insertion failed")
		}
		encoded := base64.StdEncoding.EncodeToString(rawWrapped)
		mutated := "A" + encoded[1:]
		if encoded[0] == 'A' {
			mutated = "B" + encoded[1:]
		}
		variant = strings.Replace(variant, encoded, mutated, 1)
		if !strings.Contains(variant, mutated) {
			t.Fatal("ciphertext mutation failed")
		}
		doc := parse(t, []byte(variant))
		options := opts
		options.Keys = append(append([]xmlenc.KeyGraphKey(nil), opts.Keys...), xmlenc.KeyGraphKey{Name: "direct", Algorithm: xmlenc.AES256GCM, Secret: secret})
		private.calls = 0
		private.want = t.Context()
		if got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), doc, doc.Root(), options); got != nil || !errors.Is(err, xmlenc.ErrDecrypt) || private.calls != 1 {
			t.Fatal("failed path ignored", err, private.calls)
		}
	})
	t.Run("provider cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		private.want = ctx
		private.cancel = cancel
		private.calls = 0
		if got, err := xmlenc.DecryptBytesWithKeyGraph(ctx, data, data.Root(), opts); got != nil || !errors.Is(err, context.Canceled) || private.calls != 1 {
			t.Fatal("provider cancellation", err, private.calls)
		}
	})
}
