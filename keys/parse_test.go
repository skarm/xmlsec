package keys_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/der"
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

func TestPrivateParserRejectsAgreementOnlyKeys(t *testing.T) {
	agreement, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		if fips140.Enabled() {
			t.Skip("X25519 is unavailable in FIPS mode")
		}
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(agreement)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(private); err != nil {
		t.Fatal("control PKCS#8 must parse", err)
	} else if _, signer := parsed.(crypto.Signer); signer {
		t.Fatal("control agreement key unexpectedly implements signing")
	}
	public, err := x509.MarshalPKIXPublicKey(agreement.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, encodedPEM := range []bool{false, true} {
		input := bytes.Clone(private)
		if encodedPEM {
			input = pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: input})
		}
		before := bytes.Clone(input)
		if signer, err := keys.ParsePrivate(input, keys.Limits{}); signer != nil || !errors.Is(err, keys.ErrFormat) || !bytes.Equal(input, before) {
			t.Fatal("agreement-only private key accepted as a signer", signer != nil, err)
		}
	}
	for _, maximum := range []int{len(public) - 1, len(public)} {
		input := bytes.Clone(public)
		parsed, err := keys.ParsePublic(input, keys.Limits{MaxKeyBytes: maximum})
		if maximum < len(public) {
			if parsed != nil || !errors.Is(err, keys.ErrLimit) {
				t.Fatal("public SPKI key budget ignored", err)
			}
			continue
		}
		clear(input)
		roundtrip, marshalErr := x509.MarshalPKIXPublicKey(parsed)
		if err != nil || marshalErr != nil || !bytes.Equal(roundtrip, public) {
			t.Fatal("public agreement key lost ownership or exact bytes", err, marshalErr)
		}
	}
}

func TestPEMFramingAndDecodedBudget(t *testing.T) {
	chain := testcert.New(t)
	raw, err := x509.MarshalPKCS8PrivateKey(chain.LeafKey)
	if err != nil {
		t.Fatal(err)
	}
	body := base64.StdEncoding.EncodeToString(raw)
	frame := func(label, content, ending string) []byte {
		return []byte("-----BEGIN " + label + "-----\n" + content + "\n-----END " + ending + "-----\n")
	}
	for _, tc := range []struct {
		name    string
		input   []byte
		maximum int
		want    error
	}{
		{"whitespace preserves decoded bytes", frame(privateKeyPEMType, body[:8]+" \t\r\n"+body[8:], privateKeyPEMType), len(raw), nil},
		{"exact decoded budget", frame(privateKeyPEMType, body, privateKeyPEMType), len(raw), nil},
		{"decoded budget one byte too small", frame(privateKeyPEMType, body, privateKeyPEMType), len(raw) - 1, keys.ErrLimit},
		{"empty body", frame(privateKeyPEMType, "", privateKeyPEMType), len(raw), keys.ErrFormat},
		{"incomplete base64 quartet", frame(privateKeyPEMType, body[:len(body)-1], privateKeyPEMType), len(raw), keys.ErrFormat},
		{"excessive padding", frame(privateKeyPEMType, "A===", privateKeyPEMType), len(raw), keys.ErrFormat},
		{"data after padding", frame(privateKeyPEMType, "AA=="+body, privateKeyPEMType), len(raw), keys.ErrFormat},
		{"overlong label", frame(strings.Repeat("K", 65), body, strings.Repeat("K", 65)), len(raw), keys.ErrFormat},
		{"missing end marker", []byte("-----BEGIN PRIVATE KEY-----\n" + body + "\n"), len(raw), keys.ErrFormat},
		{"mismatched end label", frame(privateKeyPEMType, body, "PUBLIC KEY"), len(raw), keys.ErrFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := bytes.Clone(tc.input)
			parsed, err := keys.ParsePrivate(tc.input, keys.Limits{MaxKeyBytes: tc.maximum})
			if tc.want != nil {
				if parsed != nil || !errors.Is(err, tc.want) {
					t.Fatal("invalid PEM framing or budget accepted", parsed != nil, err)
				}
			} else {
				if parsed == nil || err != nil {
					t.Fatal("valid framed material rejected", err)
				}
				encoded, err := x509.MarshalPKCS8PrivateKey(parsed)
				if err != nil || !bytes.Equal(encoded, raw) {
					t.Fatal("PEM parser changed the original key", err)
				}
			}
			if !bytes.Equal(before, tc.input) {
				t.Fatal("PEM processing modified caller bytes")
			}
		})
	}
}

func TestRSAStructureAndCertificateBudgets(t *testing.T) {
	key := multiPrimeRSA(t)
	chain := testcert.New(t)
	certificate := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(87), Subject: pkix.Name{CommonName: "RSA parser budget"}, NotBefore: testcert.Now().Add(-time.Hour), NotAfter: testcert.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}, chain.Root, key.Public(), chain.RootKey)
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, encodedPEM := range []bool{false, true} {
		input := bytes.Clone(certificate.Raw)
		if encodedPEM {
			input = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: input})
		}
		for _, tc := range []struct {
			name   string
			limits keys.Limits
			want   error
		}{
			{"certificate is not charged as standalone key", keys.Limits{MaxKeyBytes: 1, MaxCertificateBytes: len(certificate.Raw), MaxRSABits: 2048}, nil},
			{"large key budget cannot waive certificate budget", keys.Limits{MaxKeyBytes: len(certificate.Raw) + 1, MaxCertificateBytes: len(certificate.Raw) - 1}, keys.ErrLimit},
			{"certificate public modulus is bounded", keys.Limits{MaxRSABits: 2047}, keys.ErrLimit},
		} {
			t.Run(tc.name+"/pem="+strconv.FormatBool(encodedPEM), func(t *testing.T) {
				before := bytes.Clone(input)
				parsed, err := keys.ParsePublic(input, tc.limits)
				if tc.want != nil {
					if parsed != nil || !errors.Is(err, tc.want) {
						t.Fatal("certificate extraction bypassed independent budget", parsed != nil, err)
					}
				} else {
					if parsed == nil || err != nil {
						t.Fatal(err)
					}
					encoded, err := x509.MarshalPKIXPublicKey(parsed)
					if err != nil || !bytes.Equal(encoded, public) {
						t.Fatal("bounded extraction changed RSA public key", err)
					}
				}
				if !bytes.Equal(input, before) {
					t.Fatal("certificate parser modified source bytes")
				}
			})
		}
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(key)
	value, err := der.Read(pkcs1, len(pkcs1))
	if err != nil {
		t.Fatal(err)
	}
	fields, err := der.Sequence(value, 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	parts := make([][]byte, len(fields)+1)
	for index, field := range fields {
		parts[index] = field.FullBytes
	}
	parts[len(fields)] = der.Int(99)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	value, err = der.Read(pkcs8, len(pkcs8))
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := der.Sequence(value, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	malformedInner := der.Seq(wrapper[0].FullBytes, wrapper[1].FullBytes, der.Octets(der.Seq(der.Int(0))))
	for _, tc := range []struct {
		name   string
		raw    []byte
		limits keys.Limits
		want   error
	}{
		{"extra PKCS1 component", der.Seq(parts...), keys.Limits{}, keys.ErrFormat},
		{"malformed nested PKCS8 private sequence", malformedInner, keys.Limits{}, keys.ErrFormat},
		{"modulus exceeds small integer budget", pkcs1, keys.Limits{MaxRSABits: 64}, keys.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := bytes.Clone(tc.raw)
			if parsed, err := keys.ParsePrivate(tc.raw, tc.limits); parsed != nil || !errors.Is(err, tc.want) || !bytes.Equal(tc.raw, before) {
				t.Fatal("invalid RSA structure or resource budget accepted", parsed != nil, err)
			}
		})
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
