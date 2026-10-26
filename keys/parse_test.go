package keys_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/keys"
)

const (
	textENCRYPTEDPRIVATEKEY = "ENCRYPTED PRIVATE KEY"
	privateKeyPEMType       = "PRIVATE KEY"
)

type keyFormatCase struct {
	name    string
	label   string
	raw     []byte
	private bool
}

func multiPrimeRSA(t testing.TB) *rsa.PrivateKey {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "rsa-three-prime.pem"))
	if err != nil {
		t.Fatal(err)
	}

	block, rest := pem.Decode(raw)
	if block == nil || block.Type != privateKeyPEMType || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("invalid multi-prime RSA fixture")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() != 2048 || len(key.Primes) != 3 {
		t.Fatal("fixture must contain a 2048-bit three-prime RSA key")
	}

	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}

	return key
}

func TestPrivateAndPublicFormats(t *testing.T) {
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	c := testcert.New(t)

	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for name, signer := range map[string]crypto.Signer{"rsa": r, "ec": c.LeafKey, "ed25519": ed} {
		private, err := x509.MarshalPKCS8PrivateKey(signer)
		if err != nil {
			t.Fatal(err)
		}

		public, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil {
			t.Fatal(err)
		}

		cases := []keyFormatCase{
			{"pkcs8", privateKeyPEMType, private, true}, {"spki", "PUBLIC KEY", public, false},
		}
		if name == "rsa" {
			cases = append(cases,
				keyFormatCase{"pkcs1-private", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(r), true},
				keyFormatCase{"pkcs1-public", "RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(&r.PublicKey), false})
		}

		if name == "ec" {
			raw, err := x509.MarshalECPrivateKey(c.LeafKey)
			if err != nil {
				t.Fatal(err)
			}

			cases = append(cases, keyFormatCase{"sec1", "EC PRIVATE KEY", raw, true})
		}

		for _, tc := range cases {
			for _, pemEncoding := range []bool{false, true} {
				t.Run(name+"/"+tc.name+"/"+map[bool]string{true: "pem", false: "der"}[pemEncoding], func(t *testing.T) { testPrivateAndPublicFormatsCase(t, &tc, &pemEncoding, &private, &public) })
			}
		}
	}
}

func testPrivateAndPublicFormatsCase(t *testing.T, tc *keyFormatCase, pemEncoding *bool, private *[]byte, public *[]byte) {
	input := bytes.Clone(tc.raw)
	if *pemEncoding {
		input = pem.EncodeToMemory(&pem.Block{Type: tc.label, Bytes: input})
	}

	original := bytes.Clone(input)

	var key crypto.PublicKey

	if tc.private {
		parsed, err := keys.ParsePrivate(input, keys.Limits{})
		if err != nil {
			t.Fatal(err)
		}

		key = parsed.Public()

		if !bytes.Equal(input, original) {
			t.Fatal("input changed")
		}

		clear(input)

		encoded, err := x509.MarshalPKCS8PrivateKey(parsed)
		if err != nil || !bytes.Equal(encoded, *private) {
			t.Fatalf("private key aliases input or differs: %v", err)
		}
	} else {
		var err error

		key, err = keys.ParsePublic(input, keys.Limits{})
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(input, original) {
			t.Fatal("input changed")
		}

		clear(input)
	}

	got, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(got, *public) {
		t.Fatalf("key aliases input or differs: %v", err)
	}
}

func TestCertificateAndCRLOwnership(t *testing.T) {
	c := testcert.New(t)

	crlDER := testcert.CRL(t, c)
	for _, pemEncoding := range []bool{false, true} {
		certInput, crlInput := bytes.Clone(c.Leaf.Raw), bytes.Clone(crlDER)
		if pemEncoding {
			certInput = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certInput})
			crlInput = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlInput})
		}

		cert, err := keys.ParseCertificate(certInput, keys.Limits{})
		if err != nil {
			t.Fatal(err)
		}

		pin, err := keys.ParsePublic(certInput, keys.Limits{})
		if err != nil {
			t.Fatal(err)
		}

		crl, err := keys.ParseCRL(crlInput, keys.Limits{})
		if err != nil {
			t.Fatal(err)
		}

		clear(certInput)
		clear(crlInput)

		if !bytes.Equal(cert.Raw, c.Leaf.Raw) || !bytes.Equal(crl.Raw, crlDER) {
			t.Fatal("parsed evidence aliases input")
		}

		if err := cert.CheckSignatureFrom(c.Root); err != nil {
			t.Fatal(err)
		}

		if err := crl.CheckSignatureFrom(c.Root); err != nil {
			t.Fatal(err)
		}

		a, _ := x509.MarshalPKIXPublicKey(pin)

		b, _ := x509.MarshalPKIXPublicKey(c.LeafKey.Public())
		if !bytes.Equal(a, b) {
			t.Fatal("wrong certificate key")
		}
	}
}

func TestRejectAmbiguousAndOversizedMaterial(t *testing.T) {
	c := testcert.New(t)
	private, _ := x509.MarshalPKCS8PrivateKey(c.LeafKey)

	p := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: private})
	for _, bad := range [][]byte{
		nil, append(bytes.Clone(private), 0), append(bytes.Clone(private), private...),
		append(bytes.Clone(p), p...), append([]byte("preamble"), p...), append(bytes.Clone(p), []byte("trailing")...),
		pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: private, Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}}),
		pem.EncodeToMemory(&pem.Block{Type: textENCRYPTEDPRIVATEKEY, Bytes: private}),
		bytes.Repeat([]byte{0}, keys.DefaultLimits().MaxInputBytes+1),
	} {
		if key, err := keys.ParsePrivate(bad, keys.Limits{}); key != nil || err == nil {
			t.Fatal("accepted ambiguous private material")
		}

		if key, err := keys.ParsePublic(bad, keys.Limits{}); key != nil || err == nil {
			t.Fatal("accepted ambiguous public material")
		}

		if cert, err := keys.ParseCertificate(bad, keys.Limits{}); cert != nil || err == nil {
			t.Fatal("accepted ambiguous certificate")
		}

		if crl, err := keys.ParseCRL(bad, keys.Limits{}); crl != nil || err == nil {
			t.Fatal("accepted ambiguous CRL")
		}
	}

	if key, err := keys.ParsePrivate(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: private}), keys.Limits{}); key != nil || !errors.Is(err, keys.ErrFormat) {
		t.Fatal("PEM label ignored", err)
	}

	oversized, err := asn1.Marshal(struct {
		Version int
		N       *big.Int
		E       int
		D       *big.Int
		P       *big.Int
		Q       *big.Int
		DP      *big.Int
		DQ      *big.Int
		QI      *big.Int
	}{0, new(big.Int).Lsh(big.NewInt(1), 16384), 65537, big.NewInt(3), big.NewInt(3), big.NewInt(3), big.NewInt(1), big.NewInt(1), big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}

	if key, err := keys.ParsePrivate(oversized, keys.Limits{}); key != nil || !errors.Is(err, keys.ErrLimit) {
		t.Fatal("oversized RSA component reached validation", err)
	}
}

func FuzzParseMaterial(f *testing.F) {
	c := testcert.New(f)
	crlDER := testcert.CRL(f, c)
	private, _ := x509.MarshalPKCS8PrivateKey(c.LeafKey)

	public, _ := x509.MarshalPKIXPublicKey(c.LeafKey.Public())
	for _, raw := range [][]byte{private, public, c.Leaf.Raw, crlDER, pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: private})} {
		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}

		_, _ = keys.ParsePrivate(raw, keys.Limits{})
		_, _ = keys.ParsePublic(raw, keys.Limits{})
		_, _ = keys.ParseCertificate(raw, keys.Limits{})
		_, _ = keys.ParseCRL(raw, keys.Limits{})
	})
}

func BenchmarkParse(b *testing.B) {
	c := testcert.New(b)

	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	rsaDER, err := x509.MarshalPKCS8PrivateKey(r)
	if err != nil {
		b.Fatal(err)
	}

	edDER, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		b.Fatal(err)
	}

	for name, raw := range map[string][]byte{"RSA-PKCS8-DER": rsaDER, "RSA-PKCS8-PEM": pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: rsaDER}), "Ed25519-PKCS8-DER": edDER} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				if _, err := keys.ParsePrivate(raw, keys.Limits{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	b.Run("Certificate", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			if _, err := keys.ParseCertificate(c.Leaf.Raw, keys.Limits{}); err != nil {
				b.Fatal(err)
			}
		}
	})
	crl := testcert.CRL(b, c)
	b.Run("CRL", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			if _, err := keys.ParseCRL(crl, keys.Limits{}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkPasswordProtection(b *testing.B) {
	c := testcert.New(b)
	ctx := b.Context()
	password := []byte("public benchmark password")
	identity := keys.PKCS12Identity{PrivateKey: c.LeafKey, Certificate: c.Leaf, ExtraCertificates: []*x509.Certificate{c.Root}}
	// Compare a cheap test count and the actual export default. No production
	// options or limits are reduced by these benchmark-only fixtures.
	for _, iterations := range []int{1000, 600000} {
		b.Run(strconv.Itoa(iterations), func(b *testing.B) {
			options := keys.EncryptionOptions{Iterations: iterations}

			pkcs8, err := keys.MarshalEncryptedPrivate(ctx, c.LeafKey, password, options, keys.Limits{})
			if err != nil {
				b.Fatal(err)
			}

			pfxOptions := keys.PKCS12Options{Encryption: options}

			pfx, err := keys.MarshalPKCS12(ctx, identity, password, pfxOptions, keys.Limits{})
			if err != nil {
				b.Fatal(err)
			}

			for name, operation := range map[string]func() error{
				"PKCS8-Parse": func() error {
					_, err := keys.ParseEncryptedPrivate(ctx, pkcs8, password, keys.Limits{})
					return err
				},
				"PKCS8-Marshal": func() error {
					_, err := keys.MarshalEncryptedPrivate(ctx, c.LeafKey, password, options, keys.Limits{})
					return err
				},
				"PKCS12-Parse": func() error { _, err := keys.ParsePKCS12(ctx, pfx, password, keys.Limits{}); return err },
				"PKCS12-Marshal": func() error {
					_, err := keys.MarshalPKCS12(ctx, identity, password, pfxOptions, keys.Limits{})
					return err
				},
			} {
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()

					for b.Loop() {
						if err := operation(); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func TestLargeCRLResourceLimits(t *testing.T) {
	t.Parallel()

	c := testcert.New(t)

	const entries = 60000

	template := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: testcert.Now(), NextUpdate: testcert.Now().Add(time.Hour)}
	for i := range entries {
		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: big.NewInt(int64(i + 1)), RevocationTime: testcert.Now()})
	}

	raw, err := x509.CreateRevocationList(rand.Reader, template, c.Root, c.RootKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(raw) <= 1<<20 {
		t.Fatal("fixture does not exercise the former 1 MiB ceiling")
	}

	limits := keys.Limits{MaxInputBytes: len(raw), MaxCRLBytes: len(raw), MaxCRLEntries: entries}

	parsed, err := keys.ParseCRL(raw, limits)
	if err != nil {
		t.Fatal(err)
	}

	if len(parsed.RevokedCertificateEntries) != entries {
		t.Fatalf("parsed %d entries, want %d", len(parsed.RevokedCertificateEntries), entries)
	}

	for _, small := range []keys.Limits{
		{MaxCRLBytes: len(raw) - 1}, {MaxInputBytes: len(raw) - 1}, {MaxCRLEntries: entries - 1}, {MaxASN1Nodes: 100000},
	} {
		if crl, err := keys.ParseCRL(raw, small); crl != nil || !errors.Is(err, keys.ErrLimit) {
			t.Fatalf("CRL limits %+v: %v", small, err)
		}
	}
}

func TestParseV1CRLOriginalOwnership(t *testing.T) {
	chain := testcert.New(t)
	for _, revoked := range []bool{false, true} {
		var targets []*x509.Certificate
		if revoked {
			targets = []*x509.Certificate{chain.Leaf}
		}
		source := testcert.CRLV1(t, chain, targets...)
		for _, asPEM := range []bool{false, true} {
			input := bytes.Clone(source)
			if asPEM {
				input = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: input})
			}
			parsed, err := keys.ParseCRL(input, keys.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			clear(input)
			if !bytes.Equal(parsed.Raw, source) || parsed.Number != nil || len(parsed.Extensions) != 0 {
				t.Fatal("v1 source fields were synthesized")
			}
			if err := parsed.CheckSignatureFrom(chain.Root); err != nil {
				t.Fatal("original signed bytes not retained", err)
			}
			want := 0
			if revoked {
				want = 1
			}
			if len(parsed.RevokedCertificateEntries) != want {
				t.Fatal("entry omitted")
			}
		}
	}
}
