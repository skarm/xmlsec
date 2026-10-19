package xmlenc_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

func TestOAEPParameters(t *testing.T) {
	k := key(t)

	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		for _, label := range [][]byte{nil, {}, []byte("application\x00label\xff"), bytes.Repeat([]byte{0x42}, 1024)} {
			checkOAEPParameterCase(t, k, hash, label)
		}
	}
}

func checkOAEPParameterCase(t *testing.T, k *rsa.PrivateKey, hash crypto.Hash, label []byte) {
	t.Helper()

	opts := xmlenc.Options{OAEP: &xmlenc.OAEPParameters{Hash: hash, Label: label}}

	d, err := xmlenc.EncryptBytes(context.Background(), []byte("secret"), &k.PublicKey, opts)
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

	out, err := xmlenc.DecryptBytes(context.Background(), parse(t, wire), k, opts)
	if err != nil || string(out) != "secret" {
		t.Fatal(err)
	}
	// Reversing the XML children must preserve algorithm semantics.
	reordered := reverseOAEPParameterOrder(method, wire)

	if out, err := xmlenc.DecryptBytes(context.Background(), parse(t, reordered), k, opts); err != nil || string(out) != "secret" {
		t.Fatal("parameter order rejected", err)
	}

	wrong := xmlenc.Options{OAEP: &xmlenc.OAEPParameters{Hash: hash, Label: []byte("wrong")}}
	if out, err := xmlenc.DecryptBytes(context.Background(), d, k, wrong); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
		t.Fatal("unexpected label accepted", err)
	}

	if hash != crypto.SHA256 || len(label) != 0 {
		if out, err := xmlenc.DecryptBytes(context.Background(), d, k, xmlenc.Options{}); out != nil || !errors.Is(err, xmlenc.ErrFormat) {
			t.Fatal("default policy broadened", err)
		}
	}
}

func reverseOAEPParameterOrder(method document.Element, wire []byte) []byte {
	var reversed strings.Builder

	m := method.Children()
	for _, v := range slices.Backward(m) {
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
	reordered := append(bytes.Clone(wire[:start]), []byte(reversed.String())...)

	reordered = append(reordered, wire[end:]...)

	return reordered
}

func TestOAEPRejectsMalformedParametersBeforeProvider(t *testing.T) {
	k := key(t)
	opts := xmlenc.Options{OAEP: &xmlenc.OAEPParameters{Hash: crypto.SHA384, Label: []byte("expected")}}

	d, err := xmlenc.EncryptBytes(context.Background(), []byte("secret"), &k.PublicKey, opts)
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
		if out, err := xmlenc.DecryptBytes(context.Background(), bad, provider, opts); out != nil || err == nil {
			t.Fatal("malformed parameters accepted")
		}

		if !bytes.Equal(provider.result, bytes.Repeat([]byte{1}, 32)) {
			t.Fatal("provider invoked before parameter validation")
		}
	}

	for _, parameters := range []*xmlenc.OAEPParameters{{Hash: crypto.SHA1}, {Hash: crypto.MD5}, {Label: make([]byte, 1025)}} {
		if d, err := xmlenc.EncryptBytes(context.Background(), nil, &k.PublicKey, xmlenc.Options{OAEP: parameters}); d != nil || !errors.Is(err, xmlenc.ErrPolicy) {
			t.Fatal("invalid OAEP options accepted", err)
		}
	}
}

func TestRSARecipientPolicy(t *testing.T) {
	k := key(t)
	ctx := context.Background()

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
