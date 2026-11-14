package signature_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		key  crypto.Signer
		pss  bool
	}{
		{"ECDSA", testcert.Key(t), false}, {"RSA", rsaKey, false}, {"RSA-PSS", rsaKey, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			algorithm, err := signature.Select(tc.key.Public(), crypto.SHA256, tc.pss)
			if err != nil {
				t.Fatal(err)
			}

			value, err := signature.Sign(t.Context(), tc.key, algorithm, []byte("signed message"))
			if err != nil {
				t.Fatal(err)
			}

			if err := signature.Verify(tc.key.Public(), algorithm, []byte("signed message"), value); err != nil {
				t.Fatal(err)
			}

			if err := signature.Verify(tc.key.Public(), algorithm, []byte("modified message"), value); err == nil {
				t.Fatal("modified message accepted")
			}
		})
	}
}

func TestSignRejectsProviderOutputAndCancellation(t *testing.T) {
	t.Parallel()

	provider := &invalidSigner{Signer: testcert.Key(t)}

	algorithm, err := signature.Select(provider.Public(), crypto.SHA256, false)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if value, err := signature.Sign(ctx, provider, algorithm, []byte("message")); !errors.Is(err, context.Canceled) || value != nil || provider.calls != 0 {
		t.Fatalf("canceled signing = %x, %v, calls=%d", value, err, provider.calls)
	}

	if value, err := signature.Sign(t.Context(), provider, algorithm, []byte("message")); !errors.Is(err, signature.Err) || value != nil || provider.calls != 1 {
		t.Fatalf("invalid provider output = %x, %v, calls=%d", value, err, provider.calls)
	}
}

func TestHashRequiresExplicitLegacyPolicy(t *testing.T) {
	t.Parallel()

	aid, err := signature.DigestAlgorithm(crypto.SHA1)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := signature.Hash(aid, false); !errors.Is(err, signature.Err) {
		t.Fatalf("SHA-1 enabled implicitly: %v", err)
	}

	if got, err := signature.Hash(aid, true); err != nil || got != crypto.SHA1 {
		t.Fatalf("explicit identifier policy: %v, %v", got, err)
	}

	aid.Parameters = asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte("invalid parameters")}
	if _, err := signature.Hash(aid, true); !errors.Is(err, signature.Err) {
		t.Fatalf("unexpected digest parameters accepted: %v", err)
	}
}

func TestHashRejectsUnknownDigestOID(t *testing.T) {
	t.Parallel()

	algorithm := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}}
	if got, err := signature.Hash(algorithm, true); got != 0 || !errors.Is(err, signature.Err) {
		t.Errorf("Hash(%v) = (%v, %v), want (0, %v)", algorithm.Algorithm, got, err, signature.Err)
	}
}

func TestDigestAlgorithmRejectsUnsupportedHash(t *testing.T) {
	t.Parallel()

	if got, err := signature.DigestAlgorithm(crypto.SHA3_256); got.Algorithm != nil || !errors.Is(err, signature.Err) {
		t.Errorf("DigestAlgorithm(SHA3-256) = (%v, %v), want no OID and %v", got.Algorithm, err, signature.Err)
	}
}

func TestSumRejectsUnavailableHash(t *testing.T) {
	t.Parallel()

	if got, err := signature.Sum(0, []byte("message")); got != nil || !errors.Is(err, signature.Err) {
		t.Errorf("Sum(0) = (%x, %v), want (nil, %v)", got, err, signature.Err)
	}
}

func TestAlgorithmPreservesOptionalParameters(t *testing.T) {
	t.Parallel()

	oid := asn1.ObjectIdentifier{1, 2, 3}
	for _, tc := range []struct {
		name       string
		parameters asn1.RawValue
		wantDER    []byte
		wantParams []byte
	}{
		{"absent", asn1.RawValue{}, []byte{0x30, 4, 6, 2, 0x2a, 3}, nil},
		{"null", asn1.NullRawValue, []byte{0x30, 6, 6, 2, 0x2a, 3, 5, 0}, []byte{5, 0}},
		{"raw_octets", asn1.RawValue{FullBytes: []byte{4, 1, 0x61}}, []byte{0x30, 7, 6, 2, 0x2a, 3, 4, 1, 0x61}, []byte{4, 1, 0x61}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := signature.EncAlgorithm(pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: tc.parameters})
			if !bytes.Equal(got, tc.wantDER) {
				t.Errorf("EncAlgorithm = % x, want % x", got, tc.wantDER)
			}

			value, err := der.Read(tc.wantDER, len(tc.wantDER))
			if err != nil {
				t.Fatalf("read reference encoding: %v", err)
			}
			decoded, err := signature.Algorithm(value)
			if err != nil || !decoded.Algorithm.Equal(oid) || !bytes.Equal(decoded.Parameters.FullBytes, tc.wantParams) {
				t.Errorf("Algorithm = (OID %v, parameters % x, %v), want (%v, % x, nil)", decoded.Algorithm, decoded.Parameters.FullBytes, err, oid, tc.wantParams)
			}
		})
	}
}

func TestAlgorithmRejectsInvalidSequence(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		encoded []byte
		wantErr error
	}{
		{"empty_sequence", []byte{0x30, 0}, der.ErrInvalidDER},
		{"integer_in_place_of_oid", []byte{0x30, 3, 2, 1, 1}, signature.Err},
		{"extra_parameter", []byte{0x30, 8, 6, 2, 0x2a, 3, 5, 0, 5, 0}, der.ErrInvalidDER},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			value, err := der.Read(tc.encoded, len(tc.encoded))
			if err != nil {
				t.Fatalf("read reference encoding: %v", err)
			}
			got, err := signature.Algorithm(value)
			if got.Algorithm != nil || !errors.Is(err, tc.wantErr) {
				t.Errorf("Algorithm(% x) = (%v, %v), want no OID and %v", tc.encoded, got.Algorithm, err, tc.wantErr)
			}
		})
	}
}

func TestSelectRejectsUnsupportedKeyAndHash(t *testing.T) {
	t.Parallel()

	edKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	ecKey := testcert.Key(t)
	for _, tc := range []struct {
		name string
		key  crypto.PublicKey
		hash crypto.Hash
	}{
		{"missing_key", nil, crypto.SHA256},
		{"legacy_digest", ecKey.Public(), crypto.SHA1},
		{"key_without_digest_signature", edKey.Public(), crypto.SHA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := signature.Select(tc.key, tc.hash, false)
			if got.Algorithm != nil || !errors.Is(err, signature.Err) {
				t.Errorf("Select(%T, %v) = (%v, %v), want no OID and %v", tc.key, tc.hash, got.Algorithm, err, signature.Err)
			}
		})
	}
}

func TestSignRejectsInvalidSetupBeforeCallingProvider(t *testing.T) {
	t.Parallel()

	provider := &invalidSigner{Signer: testcert.Key(t)}
	unknown := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}}
	if got, err := signature.Sign(t.Context(), provider, unknown, nil); got != nil || !errors.Is(err, signature.Err) || provider.calls != 0 {
		t.Errorf("Sign with unknown algorithm = (%x, %v), provider calls = %d, want nil, %v and zero calls", got, err, provider.calls, signature.Err)
	}

	valid, err := signature.Select(provider.Public(), crypto.SHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	provider.Signer = publicSigner{public: ed25519.PublicKey{1}}
	if got, err := signature.Sign(t.Context(), provider, valid, nil); got != nil || !errors.Is(err, signature.Err) || provider.calls != 0 {
		t.Errorf("Sign with malformed key = (%x, %v), provider calls = %d, want nil, %v and zero calls", got, err, provider.calls, signature.Err)
	}
}

func TestSignDigestPassesMessageToEd25519(t *testing.T) {
	t.Parallel()

	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	message := []byte("Ed25519 signs the supplied message directly")
	for _, tc := range []struct {
		name string
		key  crypto.Signer
	}{
		{"value", key},
		{"pointer", &key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := signature.SignDigest(t.Context(), tc.key, nil, message, crypto.Hash(0))
			if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), message, got) {
				t.Errorf("SignDigest(%T) returned an invalid signature, error = %v", tc.key, err)
			}
		})
	}
}

func TestVerifyRejectsUnsupportedInputs(t *testing.T) {
	t.Parallel()

	ecKey := testcert.Key(t).Public()
	edKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public()
	ecdsaSHA256 := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
	unknown := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}}
	digest := sha256.Sum256([]byte("message"))
	for _, tc := range []struct {
		name      string
		key       crypto.PublicKey
		algorithm pkix.AlgorithmIdentifier
	}{
		{"missing_public_key", nil, ecdsaSHA256},
		{"unknown_algorithm", ecKey, unknown},
		{"ed25519_does_not_verify_prehashed_ecdsa", edKey, ecdsaSHA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := signature.Verify(tc.key, tc.algorithm, []byte("message"), nil); !errors.Is(err, signature.Err) {
				t.Errorf("Verify = %v, want %v", err, signature.Err)
			}
			if err := signature.VerifyDigest(tc.key, tc.algorithm, digest[:], nil); !errors.Is(err, signature.Err) {
				t.Errorf("VerifyDigest = %v, want %v", err, signature.Err)
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	c := testcert.New(b)

	a, err := signature.Select(c.LeafKey.Public(), crypto.SHA256, false)
	if err != nil {
		b.Fatal(err)
	}

	m := make([]byte, 4096)

	s, err := signature.Sign(b.Context(), c.LeafKey, a, m)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if err := signature.Verify(c.LeafKey.Public(), a, m, s); err != nil {
			b.Fatal(err)
		}
	}
}

type invalidSigner struct {
	crypto.Signer
	calls int
}

func (s *invalidSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return []byte("invalid provider output"), nil
}

func TestPSSRequiresMatchingHashMGFAndExactSaltProfile(t *testing.T) {
	t.Parallel()

	digest := der.Seq(der.OID(signature.SHA256()), []byte{5, 0})
	otherDigest := der.Seq(der.OID(signature.SHA384()), []byte{5, 0})
	field := func(tag int, content []byte) []byte { return der.Ctx(tag, content) }
	mgf := der.Seq(der.OID(signature.MGF1()), digest)
	validFields := [][]byte{field(0, digest), field(1, mgf), field(2, der.Int(32))}
	for _, test := range []struct {
		name   string
		fields [][]byte
		want   bool
	}{
		{"supported explicit profile", validFields, true},
		{"missing salt", validFields[:2], false},
		{"extra trailer parameter", append(append([][]byte{}, validFields...), field(3, der.Int(1))), false},
		{"wrong hash context tag", [][]byte{field(1, digest), validFields[1], validFields[2]}, false},
		{"malformed hash identifier", [][]byte{field(0, der.Int(1)), validFields[1], validFields[2]}, false},
		{"legacy hash refused", [][]byte{field(0, der.Seq(der.OID(signature.SHA1()))), validFields[1], validFields[2]}, false},
		{"wrong MGF context tag", [][]byte{validFields[0], field(2, mgf), validFields[2]}, false},
		{"wrong MGF algorithm", [][]byte{validFields[0], field(1, der.Seq(der.OID(signature.RSA()), digest)), validFields[2]}, false},
		{"missing MGF hash", [][]byte{validFields[0], field(1, der.Seq(der.OID(signature.MGF1()))), validFields[2]}, false},
		{"different MGF hash", [][]byte{validFields[0], field(1, der.Seq(der.OID(signature.MGF1()), otherDigest)), validFields[2]}, false},
		{"short salt", [][]byte{validFields[0], validFields[1], field(2, der.Int(31))}, false},
		{"long salt", [][]byte{validFields[0], validFields[1], field(2, der.Int(33))}, false},
		{"salt wrong tag", [][]byte{validFields[0], validFields[1], field(2, der.Octets([]byte{32}))}, false},
		{"salt wrong context tag", [][]byte{validFields[0], validFields[1], field(3, der.Int(32))}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			algorithm := pkix.AlgorithmIdentifier{Algorithm: signature.PSS(), Parameters: asn1.RawValue{FullBytes: der.Seq(test.fields...)}}
			hash, mode, err := signature.Details(algorithm)
			if test.want {
				if err != nil || hash != crypto.SHA256 || mode != "pss" {
					t.Fatal("valid PSS profile refused", hash, mode, err)
				}
			} else if !errors.Is(err, signature.Err) || hash != 0 || mode != "" {
				t.Fatal("unsupported PSS profile accepted", hash, mode, err)
			}
		})
	}
	if _, _, err := signature.Details(pkix.AlgorithmIdentifier{Algorithm: signature.PSS(), Parameters: asn1.RawValue{FullBytes: []byte{48, 128}}}); !errors.Is(err, signature.Err) {
		t.Fatal("malformed DER parameters accepted", err)
	}
}

func TestVerifyDigestAgainstStandardCryptoImplementations(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey := testcert.Key(t)
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		message := []byte("independently signed digest")
		h := hash.New()
		_, _ = h.Write(message)
		digest := h.Sum(nil)
		for _, mode := range []string{"ecdsa", "rsa", "pss"} {
			t.Run(hash.String()+"/"+mode, func(t *testing.T) {
				t.Parallel()

				public := ecKey.Public()
				var value []byte
				var err error
				if mode == "ecdsa" {
					value, err = ecdsa.SignASN1(rand.Reader, ecKey, digest)
				} else {
					public = rsaKey.Public()
					if mode == "rsa" {
						value, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, hash, digest)
					} else {
						value, err = rsa.SignPSS(rand.Reader, rsaKey, hash, digest, &rsa.PSSOptions{Hash: hash, SaltLength: hash.Size()})
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				algorithm, err := signature.Select(public, hash, mode == "pss")
				if err != nil {
					t.Fatal(err)
				}
				if err := signature.VerifyDigest(public, algorithm, digest, value); err != nil {
					t.Fatal("independent valid signature rejected", err)
				}
				changed := bytes.Clone(digest)
				changed[0] ^= 1
				if err := signature.VerifyDigest(public, algorithm, changed, value); err == nil {
					t.Fatal("changed digest accepted")
				}
				if err := signature.VerifyDigest(public, algorithm, digest[:len(digest)-1], value); !errors.Is(err, signature.Err) {
					t.Fatal("short digest accepted", err)
				}
				other := ecKey.Public()
				if mode == "ecdsa" {
					other = rsaKey.Public()
				}
				if err := signature.VerifyDigest(other, algorithm, digest, value); !errors.Is(err, signature.Err) {
					t.Fatal("wrong key family accepted", err)
				}
			})
		}
	}
	algorithm, err := signature.Select(rsaKey.Public(), crypto.SHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("fixed-length salt profile"))
	value, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 31})
	if err != nil {
		t.Fatal(err)
	}
	if err := signature.VerifyDigest(rsaKey.Public(), algorithm, digest[:], value); !errors.Is(err, signature.Err) {
		t.Fatal("non-profile PSS salt accepted", err)
	}
}

type recordingProvider struct {
	key      crypto.Signer
	ctx      context.Context
	reader   io.Reader
	options  crypto.SignerOpts
	input    []byte
	output   []byte
	err      error
	calls    int
	complete func()
}

func (p *recordingProvider) Public() crypto.PublicKey { return p.key.Public() }

func (p *recordingProvider) Sign(ctx context.Context, reader io.Reader, input []byte, options crypto.SignerOpts) ([]byte, error) {
	p.calls++
	p.ctx, p.reader, p.options = ctx, reader, options
	p.input = input
	if p.err != nil {
		return nil, p.err
	}
	value, err := p.key.Sign(reader, input, options)
	p.output = value
	if p.complete != nil {
		p.complete()
	}
	return value, err
}

func TestSignerAdapterPreservesContextAndOwnedProviderBuffers(t *testing.T) {
	t.Parallel()

	key := testcert.Key(t)
	provider := &recordingProvider{key: key}
	adapter := signature.SignerAdapter{Provider: provider}
	algorithm, err := signature.Select(key.Public(), crypto.SHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	type contextKey struct{}
	ctx := context.WithValue(t.Context(), contextKey{}, "operation marker")
	message := []byte("exact message")
	value, err := signature.Sign(ctx, adapter, algorithm, message)
	if err != nil || provider.calls != 1 || provider.ctx.Value(contextKey{}) != "operation marker" || provider.options.HashFunc() != crypto.SHA256 {
		t.Fatal("context-aware signing failed", provider.calls, provider.ctx, err)
	}
	wantDigest := sha256.Sum256(message)
	if !bytes.Equal(provider.input, wantDigest[:]) || adapter.Public() != key.Public() {
		t.Fatal("provider received wrong digest or public key")
	}
	clear(provider.output)
	if err := signature.Verify(key.Public(), algorithm, message, value); err != nil {
		t.Fatal("caller signature aliased provider output", err)
	}

	digest := bytes.Clone(wantDigest[:])
	reader := bytes.NewReader([]byte("unused entropy for failing provider"))
	sentinel := errors.New("provider refused")
	provider.err = sentinel
	if result, err := signature.SignDigest(ctx, adapter, reader, digest, crypto.SHA256); result != nil || !errors.Is(err, sentinel) || provider.reader != reader || provider.ctx.Value(contextKey{}) != "operation marker" {
		t.Fatal("SignDigest replaced provider arguments or error", result, err)
	}
	clear(provider.input)
	if !bytes.Equal(digest, wantDigest[:]) {
		t.Fatal("provider received caller-owned digest storage")
	}
	if _, err := adapter.Sign(reader, digest, crypto.SHA256); !errors.Is(err, sentinel) || provider.ctx == nil || provider.ctx.Err() != nil || provider.ctx.Value(contextKey{}) != nil {
		t.Fatal("plain crypto.Signer adapter did not provide independent background context", err)
	}
}

func TestSignRejectsCancellationDuringProviderAndPreservesCause(t *testing.T) {
	t.Parallel()

	key := testcert.Key(t)
	algorithm, err := signature.Select(key.Public(), crypto.SHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	provider := &recordingProvider{key: key, complete: cancel}
	if value, err := signature.Sign(ctx, signature.SignerAdapter{Provider: provider}, algorithm, []byte("message")); value != nil || !errors.Is(err, context.Canceled) || provider.calls != 1 || len(provider.output) == 0 {
		t.Fatal("cancellation after successful provider call returned signature", value, err)
	}
	sentinel := errors.New("hardware failed")
	provider.complete, provider.err = nil, sentinel
	if value, err := signature.Sign(t.Context(), signature.SignerAdapter{Provider: provider}, algorithm, []byte("message")); value != nil || !errors.Is(err, sentinel) || provider.calls != 2 {
		t.Fatal("provider failure lost", value, err)
	}
	if value, err := signature.Sign(nil, key, algorithm, nil); value != nil || !errors.Is(err, signature.Err) {
		t.Fatal("nil context accepted", value, err)
	}
	var absent *ecdsa.PrivateKey
	if value, err := signature.Sign(t.Context(), absent, algorithm, nil); value != nil || !errors.Is(err, signature.Err) {
		t.Fatal("nil signer accepted", value, err)
	}
}

func TestKeyChecksStrengthAndMalformedPublicRepresentations(t *testing.T) {
	t.Parallel()

	rsaPublic := func(bits, exponent int) *rsa.PublicKey {
		return &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), big.NewInt(1)), E: exponent}
	}
	for _, test := range []struct {
		name string
		key  crypto.PublicKey
		want bool
	}{
		{"nil", nil, false},
		{"typed RSA nil", (*rsa.PublicKey)(nil), false},
		{"RSA missing modulus", &rsa.PublicKey{E: 65537}, false},
		{"RSA below minimum", rsaPublic(2047, 65537), false},
		{"RSA exact minimum", rsaPublic(2048, 3), true},
		{"RSA exact maximum", rsaPublic(16384, 65537), true},
		{"RSA over maximum", rsaPublic(16385, 65537), false},
		{"RSA negative modulus", &rsa.PublicKey{N: new(big.Int).Neg(rsaPublic(2048, 3).N), E: 3}, false},
		{"RSA even exponent", rsaPublic(2048, 4), false},
		{"RSA small exponent", rsaPublic(2048, 1), false},
		{"typed EC nil", (*ecdsa.PublicKey)(nil), false},
		{"EC missing curve", &ecdsa.PublicKey{}, false},
		{"EC missing coordinates", &ecdsa.PublicKey{Curve: elliptic.P256()}, false},
		{"EC off curve", &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, false}, //nolint:staticcheck // Intentionally constructs an invalid legacy public representation.
		{"Ed25519 exact length", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public(), true},
		{"Ed25519 short", make(ed25519.PublicKey, 31), false},
		{"Ed25519 long", make(ed25519.PublicKey, 33), false},
		{"unknown key", struct{}{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := signature.Key(test.key); test.want && err != nil || !test.want && !errors.Is(err, signature.Err) {
				t.Fatal("public key profile", err)
			}
		})
	}
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		err = signature.Key(key.Public())
		if curve == elliptic.P224() && !errors.Is(err, signature.Err) || curve != elliptic.P224() && err != nil {
			t.Fatal("curve profile", curve.Params().Name, err)
		}
	}
}

func TestMatchCertificateBindsExactSignerSPKI(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	if err := signature.MatchCertificate(chain.LeafKey, chain.Leaf); err != nil {
		t.Fatal("matching certificate rejected", err)
	}
	for _, test := range []struct {
		name string
		key  crypto.Signer
		cert *x509.Certificate
	}{
		{"nil signer", nil, chain.Leaf},
		{"typed nil signer", (*ecdsa.PrivateKey)(nil), chain.Leaf},
		{"nil certificate", chain.LeafKey, nil},
		{"different signer", chain.TSAKey, chain.Leaf},
		{"empty certificate", chain.LeafKey, &x509.Certificate{}},
		{"invalid public key", publicSigner{public: &ecdsa.PublicKey{}}, chain.Leaf},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := signature.MatchCertificate(test.key, test.cert); !errors.Is(err, signature.Err) {
				t.Fatal("unbound certificate or malformed signer accepted", err)
			}
		})
	}
}

type publicSigner struct{ public crypto.PublicKey }

func (s publicSigner) Public() crypto.PublicKey { return s.public }

func (publicSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("public-only fixture must not sign")
}
