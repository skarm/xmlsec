package keys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"runtime"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestPasswordDerivation(t *testing.T) {
	salt := []byte("independent salt")

	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		for _, size := range []int{16, 24, 32, 48, 64} {
			s := testState(context.Background(), t)
			got, err := s.derive(h, salt, 1000, size)

			want, oracleErr := pbkdf2.Key(h.New, "public password", salt, 1000, size)
			if err != nil || oracleErr != nil || !bytes.Equal(got, want) {
				t.Fatal("PBKDF2 differs from the standard library", h, size, err, oracleErr)
			}

			if s.remaining != 3000000-1000*((size+h.Size()-1)/h.Size()) {
				t.Fatal("output blocks did not consume aggregate work")
			}

			clear(got)
			clear(want)
		}
	}

	for _, classic := range []bool{false, true} {
		ctx := cancelAt(3)
		s := testState(ctx, t)

		var (
			out []byte
			err error
		)
		if classic {
			out, err = classicMACKey(s, crypto.SHA256, salt, 4096)
		} else {
			out, err = s.derive(crypto.SHA256, salt, 4096, 32)
		}

		if out != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("KDF did not cancel without partial output", err)
		}
	}
}

func TestPKCS12AuthenticatedStructure(t *testing.T) {
	c := testcert.New(t)

	private, err := x509.MarshalPKCS8PrivateKey(c.LeafKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)

	keyBag := safeBag(oidKeyBag(), private, nil)
	certValue := der.Seq(der.OID(oidX509Cert()), der.Ctx(0, der.Octets(c.Leaf.Raw)))
	certBag := safeBag(oidCertBag(), certValue, nil)
	good := authenticatedPFX(t, der.Seq(keyBag, certBag))

	identity, err := ParsePKCS12(context.Background(), good, []byte("public password"), Limits{})
	if err != nil || identity == nil || !bytes.Equal(identity.Certificate.Raw, c.Leaf.Raw) {
		t.Fatal("MAC-protected plaintext bags rejected", err)
	}

	unknown := asn1.ObjectIdentifier{1, 2, 3, 4}

	id := func(b byte) []byte { return der.Set(der.Seq(der.OID(oidLocalKeyID()), der.Set(der.Octets([]byte{b})))) }
	for name, contents := range map[string][]byte{
		"duplicate key":                  der.Seq(keyBag, keyBag, certBag),
		"duplicate certificate":          der.Seq(keyBag, certBag, certBag),
		"no certificate":                 der.Seq(keyBag),
		"unknown bag":                    der.Seq(keyBag, certBag, safeBag(unknown, der.Int(0), nil)),
		"unknown attribute":              der.Seq(keyBag, safeBag(oidCertBag(), certValue, der.Set(der.Seq(der.OID(unknown), der.Set(der.Int(0)))))),
		"conflicting identifiers":        der.Seq(safeBag(oidKeyBag(), private, id(1)), safeBag(oidCertBag(), certValue, id(2))),
		"ambiguous matching certificate": der.Seq(keyBag, certBag, safeBag(oidCertBag(), der.Seq(der.OID(oidX509Cert()), der.Ctx(0, der.Octets(testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(99)}, c.Root, c.Leaf.PublicKey, c.RootKey).Raw))), nil)),
		"too many bags":                  der.Seq(bytes.Repeat(keyBag, 33)),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := ParsePKCS12(context.Background(), authenticatedPFX(t, contents), []byte("public password"), Limits{})
			if out != nil || err == nil {
				t.Fatal("invalid authenticated structure accepted")
			}
		})
	}

	f := sequence(t, good)
	mac := sequence(t, f[2].FullBytes)

	digest := sequence(t, mac[0].FullBytes)
	for name, bad := range map[string][]byte{
		"absent MAC":         der.Seq(f[0].FullBytes, f[1].FullBytes),
		"empty MAC":          der.Seq(f[0].FullBytes, f[1].FullBytes, der.Seq(der.Seq(digest[0].FullBytes, der.Octets(nil)), mac[1].FullBytes, mac[2].FullBytes)),
		"changed safe bytes": der.Seq(f[0].FullBytes, dataInfo(der.Seq(dataInfo(der.Seq(certBag)))), f[2].FullBytes),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := ParsePKCS12(context.Background(), bad, []byte("public password"), Limits{})
			if out != nil || err == nil {
				t.Fatal("unauthenticated structure accepted")
			}
		})
	}
	// RFC 9879 requires ignoring outer salt/iterations, even if the INTEGER
	// cannot fit a machine int. Only the PBMAC1 parameters drive the KDF.
	huge, _ := asn1.Marshal(new(big.Int).Lsh(big.NewInt(1), 200))

	ignored := der.Seq(f[0].FullBytes, f[1].FullBytes, der.Seq(mac[0].FullBytes, der.Octets(nil), huge))
	if out, err := ParsePKCS12(context.Background(), ignored, []byte("public password"), Limits{}); out == nil || err != nil {
		t.Fatal("PBMAC1 placeholder was interpreted as a KDF parameter", err)
	}
}

func authenticatedPFX(t testing.TB, contents []byte) []byte {
	t.Helper()

	authSafe := der.Seq(dataInfo(contents))
	s := testState(context.Background(), t)

	mac, err := encodePKCS12MAC(s, authSafe, PKCS12Options{Encryption: EncryptionOptions{Hash: crypto.SHA256, Iterations: 1000}})
	if err != nil {
		t.Fatal(err)
	}

	return der.Seq(der.Int(3), dataInfo(authSafe), mac)
}

func TestProtectionParameterPolicy(t *testing.T) {
	salt, iv := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)

	prf := der.Seq(der.OID(oidHMAC256()), []byte{5, 0})
	for name, kdf := range map[string][]byte{
		"omitted default SHA1": der.Seq(der.OID(oidPBKDF2()), der.Seq(der.Octets(salt), der.Int(1000))),
		"wrong key size":       kdfEncoding(salt, 1000, 16, crypto.SHA256),
		"zero iterations":      kdfEncoding(salt, 0, 32, crypto.SHA256),
		"excessive iterations": kdfEncoding(salt, 1000001, 32, crypto.SHA256),
		"tiny salt":            kdfEncoding([]byte{1}, 1000, 32, crypto.SHA256),
		"duplicate parameters": der.Seq(der.OID(oidPBKDF2()), der.Seq(der.Octets(salt), der.Int(1000), der.Int(32), prf, prf)),
	} {
		t.Run(name, func(t *testing.T) {
			want := map[string]error{"omitted default SHA1": ErrFormat, "wrong key size": ErrPolicy, "zero iterations": ErrLimit, "excessive iterations": ErrLimit, "tiny salt": ErrPolicy, "duplicate parameters": ErrFormat}[name]
			alg := der.Seq(der.OID(oidPBES2()), der.Seq(kdf, der.Seq(der.OID(oidAES256CBC()), der.Octets(iv))))

			out, err := decryptPBES2(testState(context.Background(), t), rawValue(t, alg), make([]byte, 16), DefaultLimits().MaxContainerBytes)
			if out != nil || !errors.Is(err, want) {
				t.Fatal("unsupported protection parameter reached decryption", name, err)
			}
		})
	}

	message := []byte("PBMAC1 independently keyed message")

	want, err := pbkdf2.Key(crypto.SHA256.New, "public password", salt, 1000, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(want)

	h := hmac.New(crypto.SHA512.New, want)
	h.Write(message)

	makeMAC := func(kdf []byte) asn1.RawValue {
		alg := der.Seq(der.OID(oidPBMAC1()), der.Seq(kdf, der.Seq(der.OID(oidHMAC512()))))
		return rawValue(t, der.Seq(der.Seq(alg, der.Octets(h.Sum(nil))), der.Octets(nil), der.Int(0)))
	}

	s := testState(context.Background(), t)
	if err := verifyPKCS12MAC(s, makeMAC(kdfEncoding(salt, 1000, 64, crypto.SHA256)), message); err != nil || s.remaining != 2998000 {
		t.Fatal("PBKDF2 PRF and MAC hash were incorrectly coupled", err)
	}

	noLength := der.Seq(der.OID(oidPBKDF2()), der.Seq(der.Octets(salt), der.Int(1000), prf))
	if err := verifyPKCS12MAC(testState(context.Background(), t), makeMAC(noLength), message); err == nil {
		t.Fatal("PBMAC1 without mandatory keyLength accepted")
	}
}

func TestDecryptedPKCS8Schema(t *testing.T) {
	c := testcert.New(t)

	raw, err := x509.MarshalPKCS8PrivateKey(c.LeafKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)

	f := sequence(t, raw)
	attr := der.Seq(der.OID(oidFriendlyName()), der.Set(der.Wrap(0, asn1.TagUTF8String, false, []byte("example"))))

	valid := der.Seq(f[0].FullBytes, f[1].FullBytes, f[2].FullBytes, der.Ctx(0, attr))
	if key, err := parseDecryptedPrivate(testState(context.Background(), t), valid); key == nil || err != nil {
		t.Fatal("valid version-zero PrivateKeyInfo attributes rejected", err)
	}

	for _, bad := range [][]byte{
		der.Seq(der.Int(1), f[1].FullBytes, f[2].FullBytes),
		der.Seq(f[0].FullBytes, f[1].FullBytes, f[2].FullBytes, der.Int(0)),
		der.Seq(f[0].FullBytes, f[1].FullBytes, f[2].FullBytes, der.Ctx(0, der.Int(0))),
		der.Seq(f[0].FullBytes, f[1].FullBytes, f[2].FullBytes, der.Ctx(0, der.Seq(der.OID(oidFriendlyName()), der.Set()))),
	} {
		if key, err := parseDecryptedPrivate(testState(context.Background(), t), bad); key != nil || !errors.Is(err, ErrDecrypt) {
			t.Fatal("invalid PrivateKeyInfo schema accepted", err)
		}
	}
}

func TestProtectionCancellationCheckpoints(t *testing.T) {
	c := testcert.New(t)

	for at := 1; at <= 16; at++ {
		for _, pfx := range []bool{false, true} {
			ctx := cancelAt(at)
			options := EncryptionOptions{Hash: crypto.SHA256, KeyBits: 256, Iterations: 1000}

			var (
				out []byte
				err error
			)
			if pfx {
				out, err = MarshalPKCS12(ctx, PKCS12Identity{PrivateKey: c.LeafKey, Certificate: c.Leaf}, []byte("public password"), PKCS12Options{Encryption: options}, Limits{})
			} else {
				out, err = MarshalEncryptedPrivate(ctx, c.LeafKey, []byte("public password"), options, Limits{})
			}

			ctx.cancel()

			if err != nil && (!errors.Is(err, context.Canceled) || out != nil) {
				t.Fatal("cancellation exposed partial output", at, pfx, err)
			}
		}
	}
	// Invalid structures must fail without dereferencing missing key components.
	for _, key := range []crypto.Signer{&rsa.PrivateKey{}, &rsa.PrivateKey{N: big.NewInt(5), D: big.NewInt(1), Primes: []*big.Int{nil, nil}}} {
		if out, err := MarshalEncryptedPrivate(context.Background(), key, []byte("password"), EncryptionOptions{Iterations: 1000}, Limits{}); out != nil || err == nil {
			t.Fatal("invalid RSA key exported")
		}
	}
}

func TestPrivateRSACollectionBudget(t *testing.T) {
	// Resource rejection precedes expensive mathematical validation; the
	// intentionally inconsistent small integers are not a valid private key.
	triplet := der.Seq(der.Int(3), der.Int(1), der.Int(1))
	private := der.Seq(der.Int(1), der.Int(17), der.Int(3), der.Int(1), der.Int(3), der.Int(5), der.Int(1), der.Int(1), der.Int(1), der.Seq(bytes.Repeat(triplet, 7)))

	pkcs8 := der.Seq(der.Int(0), der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}), []byte{5, 0}), der.Octets(private))
	for _, raw := range [][]byte{private, pkcs8} {
		if key, err := ParsePrivate(raw, Limits{}); key != nil || !errors.Is(err, ErrLimit) {
			t.Fatal("RSA additional primes reached crypto validation", err)
		}
	}
}

func TestDecryptedPrivateWorkingStorage(t *testing.T) {
	c := testcert.New(t)

	raw, err := x509.MarshalPKCS8PrivateKey(c.LeafKey)
	if err != nil {
		t.Fatal(err)
	}

	fields := sequence(t, raw)
	attribute := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 3, 4}), der.Set(der.Octets(bytes.Repeat([]byte{7}, 512<<10))))
	plain := der.Seq(fields[0].FullBytes, fields[1].FullBytes, fields[2].FullBytes, der.Ctx(0, attribute))
	limits := Limits{MaxKeyBytes: len(plain)}

	allocated := keyAllocated(t, func() error { _, err := ParsePrivate(plain, limits); return err })
	if allocated > 128<<10 {
		t.Fatal("private DER parsing copied ignored attributes", allocated)
	}

	state := testState(t.Context(), t)
	options := EncryptionOptions{Hash: crypto.SHA256, KeyBits: 256, Iterations: 1000}

	algorithm, ciphertext, err := encryptPBES2(state, plain, options)
	if err != nil {
		t.Fatal(err)
	}

	encrypted := der.Seq(algorithm, der.Octets(ciphertext))
	original := bytes.Clone(encrypted)

	var key crypto.Signer

	allocated = keyAllocated(t, func() error {
		var err error

		key, err = ParseEncryptedPrivate(t.Context(), encrypted, []byte("public password"), limits)

		return err
	})
	t.Logf("encrypted PKCS8: %d plaintext bytes, %d allocated", len(plain), allocated)

	if allocated > uint64(len(plain))+(128<<10) {
		t.Fatal("encrypted private parsing copied container/plaintext", allocated)
	}

	if !bytes.Equal(encrypted, original) {
		t.Fatal("encrypted input changed")
	}

	clear(encrypted)

	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || !bytes.Equal(public, c.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("private key aliases temporary plaintext", err)
	}
}

func TestPBES2WorkingStorage(t *testing.T) {
	plain := bytes.Repeat([]byte{7}, 8<<20)
	options := EncryptionOptions{Hash: crypto.SHA256, KeyBits: 256, Iterations: 1000}

	var algorithm, ciphertext []byte

	allocated := keyAllocated(t, func() error {
		state, err := newPasswordState(t.Context(), []byte("public password"), Limits{})
		if err != nil {
			return err
		}
		defer state.close()

		algorithm, ciphertext, err = encryptPBES2(state, plain, options)

		return err
	})
	t.Logf("PBES2 encryption: %d plaintext bytes, %d allocated", len(plain), allocated)

	if allocated > uint64(len(plain))+(128<<10) {
		t.Fatal("CBC encryption retained a second padded message", allocated)
	}

	parameters := rawValue(t, algorithm)

	allocated = keyAllocated(t, func() error {
		state, err := newPasswordState(t.Context(), []byte("public password"), Limits{})
		if err != nil {
			return err
		}
		defer state.close()

		decoded, err := decryptPBES2(state, parameters, ciphertext, len(plain))
		if err == nil && !bytes.Equal(decoded, plain) {
			return errors.New("CBC plaintext changed")
		}

		clear(decoded[:cap(decoded)])

		return err
	})
	if allocated > uint64(len(ciphertext))+(128<<10) {
		t.Fatal("CBC decryption duplicated ciphertext", allocated)
	}

	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	want, got := make([]byte, len(plain)), make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(want, plain)

	if err := cryptCBC(t.Context(), cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)), got, plain); err != nil || !bytes.Equal(got, want) {
		t.Fatal("chunked CBC differs from standard CBC", err)
	}

	clear(got)

	ctx := cancelAt(3)
	defer ctx.cancel()

	if err := cryptCBC(ctx, cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)), got, want); !errors.Is(err, context.Canceled) || !bytes.Equal(got[:64<<10], plain[:64<<10]) || !bytes.Equal(got[64<<10:], make([]byte, len(got)-(64<<10))) {
		t.Fatal("CBC did not stop between chunks", err)
	}
}

func FuzzPEMDecoding(f *testing.F) {
	raw := der.Seq(der.Int(0), der.Octets([]byte("PEM decoder fixture")))

	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	for _, input := range [][]byte{encoded, bytes.ReplaceAll(encoded, []byte{'\n'}, []byte{' ', '\t', '\r', '\n'}), bytes.TrimSpace(encoded), append(bytes.Clone(encoded), encoded...), []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")} {
		f.Add(input)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 16<<10 {
			return
		}

		trimmed := bytes.TrimSpace(input)

		block, rest := pem.Decode(trimmed)
		if block != nil && block.Type != "PRIVATE KEY" {
			return
		}

		valid := block != nil && len(block.Headers) == 0 && len(bytes.TrimSpace(rest)) == 0 && bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) && bytes.Count(trimmed, []byte("-----BEGIN ")) == 1
		if valid {
			_, err := readDER(block.Bytes, 64<<10, DefaultLimits())
			valid = err == nil
		}

		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
			return
		}

		original := bytes.Clone(input)

		decoded, err := material(t.Context(), input, 64<<10, DefaultLimits())
		defer decoded.clear()

		if valid && (err != nil || decoded.label != block.Type || !bytes.Equal(decoded.der, block.Bytes)) {
			t.Fatal("PEM decoding differs from encoding/pem", err)
		}

		if !valid && err == nil {
			t.Fatal("ambiguous/malformed PEM accepted")
		}

		if !bytes.Equal(input, original) {
			t.Fatal("PEM input changed")
		}
	})
}

func rawValue(t testing.TB, b []byte) asn1.RawValue {
	t.Helper()

	v, err := der.Read(b, len(b))
	if err != nil {
		t.Fatal(err)
	}

	return v
}

func sequence(t testing.TB, b []byte) []asn1.RawValue {
	t.Helper()
	v := rawValue(t, b)

	f, err := der.Sequence(v, 0, 32)
	if err != nil {
		t.Fatal(err)
	}

	return f
}

func testState(ctx context.Context, t testing.TB) *passwordState {
	t.Helper()

	s, err := newPasswordState(ctx, []byte("public password"), Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(s.close)

	return s
}

// cancelOnCheck cancels at a deterministic checkpoint, avoiding timing races.
type cancelOnCheck struct {
	context.Context
	cancel     context.CancelFunc
	at, checks int
}

func (c *cancelOnCheck) Err() error {
	c.checks++
	if c.checks >= c.at {
		c.cancel()
	}

	return c.Context.Err()
}

func cancelAt(n int) *cancelOnCheck {
	ctx, cancel := context.WithCancel(context.Background())
	return &cancelOnCheck{Context: ctx, cancel: cancel, at: n}
}

func keyAllocated(t *testing.T, run func() error) uint64 {
	t.Helper()

	allocated := ^uint64(0)

	for range 3 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)

		if err := run(); err != nil {
			t.Fatal(err)
		}

		runtime.ReadMemStats(&after)
		allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)
	}

	return allocated
}
