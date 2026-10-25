package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"

	"github.com/skarm/xmlsec/xmldsig"
)

func TestSignatureParameterProjection(t *testing.T) {
	for _, test := range []struct {
		bits int
		want crypto.Hash
	}{{0, 0}, {256, crypto.SHA256}, {384, crypto.SHA384}, {512, crypto.SHA512}, {224, 0}} {
		if got := hashFromBits(test.bits); got != test.want {
			t.Fatalf("hash %d=%v", test.bits, got)
		}
	}
	defaults := signatureParameters(task{Method: xmldsig.RSAPSS, DefaultParams: true, Hash: 512, Salt: 99})
	if defaults.PSS != nil || defaults.HMACOutputLength != 0 {
		t.Fatalf("default params are no longer omitted: %+v", defaults)
	}
	explicit := signatureParameters(task{Method: xmldsig.RSAPSS, Hash: 384, MGF: 256, Salt: 0})
	want := xmldsig.PSSParameters{Hash: crypto.SHA384, MGFHash: crypto.SHA256, SaltLength: 0, TrailerField: 1}
	if explicit.PSS == nil || *explicit.PSS != want {
		t.Fatalf("explicit zero-salt params: %+v", explicit)
	}
	mac := signatureParameters(task{Method: xmldsig.HMACSHA256, Bits: 129})
	if mac.PSS != nil || mac.HMACOutputLength != 129 {
		t.Fatalf("MAC projection: %+v", mac)
	}
}

func TestPreparedSignerBindsDigestParametersAndOwnership(t *testing.T) {
	parameters := xmldsig.PSSParameters{Hash: crypto.SHA384, MGFHash: crypto.SHA256, SaltLength: 0, TrailerField: 1}
	signer := &preparedSigner{signature: []byte{1, 2, 3}, digest: []byte("expected digest"), expected: parameters}
	signature, err := signer.SignPSS(t.Context(), nil, []byte("expected digest"), parameters)
	if err != nil || !bytes.Equal(signature, []byte{1, 2, 3}) || signer.calls != 1 {
		t.Fatalf("signature/calls: %x %v %d", signature, err, signer.calls)
	}
	signature[0] = 99
	if signer.signature[0] != 1 {
		t.Fatal("provider released its owned signature")
	}
	for _, mutate := range []func([]byte, *xmldsig.PSSParameters){func(d []byte, _ *xmldsig.PSSParameters) { d[0] ^= 1 }, func(_ []byte, p *xmldsig.PSSParameters) { p.Hash = crypto.SHA512 }, func(_ []byte, p *xmldsig.PSSParameters) { p.TrailerField = 2 }, func(_ []byte, p *xmldsig.PSSParameters) { p.SaltLength++ }, func(_ []byte, p *xmldsig.PSSParameters) { p.MGFHash = crypto.SHA512 }} {
		digest := bytes.Clone(signer.digest)
		actual := parameters
		mutate(digest, &actual)
		if value, err := signer.SignPSS(t.Context(), nil, digest, actual); value != nil || err == nil {
			t.Fatal("mismatched precomputed input accepted")
		}
	}
	calls := signer.calls
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := signer.SignPSS(ctx, nil, signer.digest, parameters); !errors.Is(err, context.Canceled) || signer.calls != calls {
		t.Fatal("cancellation invoked provider", err, signer.calls)
	}
	if value, err := signer.Sign(nil, nil, crypto.SHA256); value != nil || err == nil {
		t.Fatal("standard signer route unexpectedly accepted")
	}
}

func TestHMACSignVerifyAndTampering(t *testing.T) {
	secret := bytes.Repeat([]byte{0x53}, 32)
	signed, err := run(task{Mode: "sign", Method: xmldsig.HMACSHA256, Secret: secret, Bits: 128})
	if err != nil || !signed.Valid || !bytes.Contains(signed.Data, []byte("HMACOutputLength>128")) {
		t.Fatalf("sign: %+v %v", signed, err)
	}
	verified, err := run(task{Mode: "verify", Method: xmldsig.HMACSHA256, Secret: secret, Input: signed.Data})
	if err != nil || !verified.Valid || verified.Report == nil {
		t.Fatalf("verify: %+v %v", verified, err)
	}
	tampered := bytes.Replace(signed.Data, []byte("independent payload"), []byte("changed payload"), 1)
	verified, err = run(task{Mode: "verify", Method: xmldsig.HMACSHA256, Secret: secret, Input: tampered})
	if err == nil || verified.Valid {
		t.Fatal("tampered signed object accepted")
	}
}

func TestProviderDefaultParametersDoNotPanic(t *testing.T) {
	want := xmldsig.PSSParameters{Hash: crypto.SHA256, MGFHash: crypto.SHA256, SaltLength: 32, TrailerField: 1}
	if got := providerParameters(task{Method: xmldsig.RSAPSS, DefaultParams: true, Salt: 99}); got != want {
		t.Fatalf("omitted parameters=%+v", got)
	}
	explicit := providerParameters(task{Method: xmldsig.RSAPSS, Hash: 384, Salt: 0})
	if explicit.Hash != crypto.SHA384 || explicit.MGFHash != crypto.SHA384 || explicit.SaltLength != 0 || explicit.TrailerField != 1 {
		t.Fatalf("explicit normalized parameters=%+v", explicit)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	first, second := "first", "second"
	draft, _, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{ID: "s", SignatureMethod: xmldsig.RSAPSS, References: []xmldsig.ReferenceTemplate{{URI: "#a", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}, {URI: "#b", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}}, Objects: []xmldsig.ObjectTemplate{{ID: "a", Text: &first}, {ID: "b", Text: &second}}})
	if err != nil {
		t.Fatal(err)
	}
	input, err := draft.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []task{{Mode: "provider-sign", Method: xmldsig.RSAPSS, Input: input, SPKI: spki, Hash: 224}, {Mode: "provider-sign", Method: xmldsig.RSAPSS, Input: input, SPKI: spki, Hash: 256, MGF: 1}} {
		result, err := run(invalid)
		if !errors.Is(err, xmldsig.ErrAlgorithm) || result.Valid || result.ProviderCalls != 0 || len(result.Data) != 0 {
			t.Fatalf("invalid hash downgraded to default: %+v %v", result, err)
		}
	}
	answer, err := run(task{Mode: "provider-sign", Method: xmldsig.RSAPSS, DefaultParams: true, Input: input, SPKI: spki})
	if err == nil || answer.Valid || answer.ProviderCalls != 1 || !strings.Contains(err.Error(), "independent precomputed signature input differs") {
		t.Fatalf("default provider did not reach its input guard: %+v %v", answer, err)
	}
}
