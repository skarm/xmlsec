package keys_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/keys"
)

func pkcs12FormOID(last int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, last}
}

func pkcs12FormData(input []byte) []byte {
	return der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}), der.Ctx(0, der.Octets(input)))
}

func pkcs12FormIndefinite(tag byte, parts ...[]byte) []byte {
	return append(append([]byte{tag, 0x80}, bytes.Join(parts, nil)...), 0, 0)
}

// Build the MAC with the independent standard-library PBKDF2 implementation.
// The authenticated octets deliberately need not be a canonical DER encoding.
func pkcs12FormPFX(t *testing.T, authenticated, macInput []byte, outerBER bool) []byte {
	t.Helper()
	salt := []byte("published form test salt")
	key, err := pbkdf2.Key(sha256.New, "forms password", salt, 1000, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write(macInput)
	prf := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}), []byte{5, 0})
	kdf := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}), der.Seq(der.Octets(salt), der.Int(1000), der.Int(32), prf))
	algorithm := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}), der.Seq(kdf, prf))
	macData := der.Seq(der.Seq(algorithm, der.Octets(mac.Sum(nil))), der.Octets(nil))
	if outerBER {
		mid := len(authenticated) / 2
		octets := pkcs12FormIndefinite(0x24, der.Octets(authenticated[:mid]), pkcs12FormIndefinite(0x24, der.Octets(authenticated[mid:])))
		info := pkcs12FormIndefinite(0x30, der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}), pkcs12FormIndefinite(0xa0, octets))
		return pkcs12FormIndefinite(0x30, der.Int(3), info, macData)
	}
	return der.Seq(der.Int(3), pkcs12FormData(authenticated), macData)
}

func pkcs12FormBags(t *testing.T, key crypto.Signer, certificate *x509.Certificate, encrypted bool) []byte {
	t.Helper()
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { clear(private) }()
	bagType := 1
	if encrypted {
		clear(private)
		private, err = keys.MarshalEncryptedPrivate(t.Context(), key, []byte("forms password"), protection(crypto.SHA256, 256), keys.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		bagType = 2
	}
	id := sha256.Sum256(certificate.Raw)
	attributes := der.Set(der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}), der.Set(der.Octets(id[:]))))
	keyBag := der.Seq(der.OID(pkcs12FormOID(bagType)), der.Ctx(0, private), attributes)
	certBag := der.Seq(der.OID(pkcs12FormOID(3)), der.Ctx(0, der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}), der.Ctx(0, der.Octets(certificate.Raw)))), attributes)
	return bytes.Join([][]byte{keyBag, certBag}, nil)
}

func TestPKCS12ExplicitIdentitiesAndSelection(t *testing.T) {
	t.Parallel()

	a, b := testcert.New(t), testcert.New(t)
	bags := bytes.Join([][]byte{pkcs12FormBags(t, a.LeafKey, a.Leaf, false), pkcs12FormBags(t, b.LeafKey, b.Leaf, false)}, nil)
	authenticated := der.Seq(pkcs12FormData(der.Seq(bags)))
	raw := pkcs12FormPFX(t, authenticated, authenticated, false)
	items, err := keys.ParsePKCS12Identities(t.Context(), raw, []byte("forms password"), keys.PKCS12ParseOptions{}, keys.Limits{})
	if err != nil || len(items) != 2 {
		t.Fatal(items, err)
	}
	for i, cert := range []*x509.Certificate{a.Leaf, b.Leaf} {
		if !bytes.Equal(items[i].Certificate.Raw, cert.Raw) {
			t.Fatal("identity order or certificate binding changed")
		}
		selected, err := keys.ParsePKCS12WithOptions(t.Context(), raw, []byte("forms password"), keys.PKCS12ParseOptions{CertificateSHA256: sha256.Sum256(cert.Raw)}, keys.Limits{})
		if err != nil || !bytes.Equal(selected.Certificate.Raw, cert.Raw) {
			t.Fatal(selected, err)
		}
	}
	if item, err := keys.ParsePKCS12(t.Context(), raw, []byte("forms password"), keys.Limits{}); item != nil || !errors.Is(err, keys.ErrFormat) {
		t.Fatal(item, err)
	}
	if item, err := keys.ParsePKCS12WithOptions(t.Context(), raw, []byte("forms password"), keys.PKCS12ParseOptions{CertificateSHA256: sha256.Sum256([]byte("absent"))}, keys.Limits{}); item != nil || !errors.Is(err, keys.ErrFormat) {
		t.Fatal(item, err)
	}
	clear(raw)
	if !bytes.Equal(items[0].Certificate.Raw, a.Leaf.Raw) || !bytes.Equal(items[1].Certificate.Raw, b.Leaf.Raw) {
		t.Fatal("identities borrowed the source encoding")
	}
	if items, err := keys.ParsePKCS12Identities(t.Context(), pkcs12FormPFX(t, authenticated, authenticated, false), []byte("wrong"), keys.PKCS12ParseOptions{}, keys.Limits{}); items != nil || !errors.Is(err, keys.ErrDecrypt) {
		t.Fatal(items, err)
	}
}

func TestPKCS12BERAndNestedSafeContents(t *testing.T) {
	t.Parallel()

	c := testcert.New(t)
	contents := der.Seq(pkcs12FormBags(t, c.LeafKey, c.Leaf, false))
	bags := privateFields(t, contents)
	mid := len(c.Leaf.Raw) / 2
	certificate := pkcs12FormIndefinite(0x30, der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}), pkcs12FormIndefinite(0xa0, pkcs12FormIndefinite(0x24, der.Octets(c.Leaf.Raw[:mid]), der.Octets(c.Leaf.Raw[mid:]))))
	certBag := pkcs12FormIndefinite(0x30, der.OID(pkcs12FormOID(3)), pkcs12FormIndefinite(0xa0, certificate))
	contents = pkcs12FormIndefinite(0x30, bags[0], certBag)
	nestedBag := pkcs12FormIndefinite(0x30, der.OID(pkcs12FormOID(6)), pkcs12FormIndefinite(0xa0, contents))
	nested := pkcs12FormIndefinite(0x30, nestedBag)
	authenticated := pkcs12FormIndefinite(0x30, pkcs12FormData(nested))
	raw := pkcs12FormPFX(t, authenticated, authenticated, true)
	options := keys.PKCS12ParseOptions{AllowBER: true, AllowNestedSafeContents: true}
	if item, err := keys.ParsePKCS12WithOptions(t.Context(), raw, []byte("forms password"), options, keys.Limits{}); item == nil || err != nil || !bytes.Equal(item.Certificate.Raw, c.Leaf.Raw) {
		t.Fatal(item, err)
	}
	for _, disabled := range []keys.PKCS12ParseOptions{{}, {AllowBER: true}, {AllowNestedSafeContents: true}} {
		if item, err := keys.ParsePKCS12WithOptions(t.Context(), raw, []byte("forms password"), disabled, keys.Limits{}); item != nil || err == nil {
			t.Fatal(item, err)
		}
	}
	for _, limits := range []keys.Limits{{MaxBags: 2}, {MaxASN1Depth: 4}, {MaxASN1Nodes: 4}, {MaxContainerBytes: len(raw) - 1}, {MaxKDFWork: 999}} {
		if item, err := keys.ParsePKCS12WithOptions(t.Context(), raw, []byte("forms password"), options, limits); item != nil || !errors.Is(err, keys.ErrLimit) {
			t.Fatal(item, err, limits)
		}
	}
	if item, err := keys.ParsePKCS12WithOptions(t.Context(), raw, []byte("forms password"), options, keys.Limits{MaxBags: 3}); item == nil || err != nil {
		t.Fatal(item, err)
	}
	canonical := der.Seq(pkcs12FormData(nested))
	wrongMAC := pkcs12FormPFX(t, authenticated, canonical, true)
	if item, err := keys.ParsePKCS12WithOptions(t.Context(), wrongMAC, []byte("forms password"), options, keys.Limits{}); item != nil || !errors.Is(err, keys.ErrDecrypt) {
		t.Fatal("MAC used repaired ASN.1 instead of original octets", item, err)
	}
	for _, malformed := range [][]byte{raw[:len(raw)-1], append(bytes.Clone(raw), 0, 0), append(bytes.Clone(raw), raw...), {0x30, 0x80, 0, 0, 0, 0}, {4, 0x80, 0, 0}} {
		if item, err := keys.ParsePKCS12WithOptions(t.Context(), malformed, []byte("forms password"), options, keys.Limits{}); item != nil || !errors.Is(err, keys.ErrFormat) {
			t.Fatal(item, err)
		}
	}
}

func TestPKCS12MultipleIdentityWorkAndFailures(t *testing.T) {
	t.Parallel()

	a, b := testcert.New(t), testcert.New(t)
	bags := bytes.Join([][]byte{pkcs12FormBags(t, a.LeafKey, a.Leaf, true), pkcs12FormBags(t, b.LeafKey, b.Leaf, true)}, nil)
	authenticated := der.Seq(pkcs12FormData(der.Seq(bags)))
	raw := pkcs12FormPFX(t, authenticated, authenticated, false)
	if items, err := keys.ParsePKCS12Identities(t.Context(), raw, []byte("forms password"), keys.PKCS12ParseOptions{}, keys.Limits{MaxKDFWork: 3000}); len(items) != 2 || err != nil {
		t.Fatal(items, err)
	}
	if items, err := keys.ParsePKCS12Identities(t.Context(), raw, []byte("forms password"), keys.PKCS12ParseOptions{}, keys.Limits{MaxKDFWork: 2999}); items != nil || !errors.Is(err, keys.ErrLimit) {
		t.Fatal(items, err)
	}
	// A valid selected key cannot hide an unmatched or corrupt later identity.
	badBags := bytes.Join([][]byte{pkcs12FormBags(t, a.LeafKey, a.Leaf, false), pkcs12FormBags(t, b.LeafKey, a.Root, false)}, nil)
	badSafe := der.Seq(pkcs12FormData(der.Seq(badBags)))
	if item, err := keys.ParsePKCS12WithOptions(t.Context(), pkcs12FormPFX(t, badSafe, badSafe, false), []byte("forms password"), keys.PKCS12ParseOptions{CertificateSHA256: sha256.Sum256(a.Leaf.Raw)}, keys.Limits{}); item != nil || !errors.Is(err, keys.ErrFormat) {
		t.Fatal(item, err)
	}
}

func TestPKCS12BEREncryptedContentAndStrictOpaqueFields(t *testing.T) {
	t.Parallel()

	c := testcert.New(t)
	raw, err := keys.MarshalPKCS12(t.Context(), keys.PKCS12Identity{PrivateKey: c.LeafKey, Certificate: c.Leaf}, []byte("forms password"), keys.PKCS12Options{Encryption: protection(crypto.SHA256, 256)}, keys.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	outer := privateFields(t, raw)
	authInfo := privateFields(t, outer[1])
	var explicit, octets asn1.RawValue
	if _, err := asn1.Unmarshal(authInfo[1], &explicit); err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(explicit.Bytes, &octets); err != nil {
		t.Fatal(err)
	}
	infos := privateFields(t, octets.Bytes)
	certInfo := privateFields(t, infos[0])
	if _, err := asn1.Unmarshal(certInfo[1], &explicit); err != nil {
		t.Fatal(err)
	}
	encrypted := privateFields(t, explicit.Bytes)
	fields := privateFields(t, encrypted[1])
	var ciphertext asn1.RawValue
	if _, err := asn1.Unmarshal(fields[2], &ciphertext); err != nil {
		t.Fatal(err)
	}
	mid := len(ciphertext.Bytes) / 2
	chunks := pkcs12FormIndefinite(0xa0, der.Octets(ciphertext.Bytes[:mid]), pkcs12FormIndefinite(0x24, der.Octets(ciphertext.Bytes[mid:])))
	makeSafe := func(algorithm []byte) []byte {
		info := pkcs12FormIndefinite(0x30, fields[0], algorithm, chunks)
		content := pkcs12FormIndefinite(0x30, encrypted[0], info)
		return pkcs12FormIndefinite(0x30, pkcs12FormIndefinite(0x30, certInfo[0], pkcs12FormIndefinite(0xa0, content)), infos[1])
	}
	valid := makeSafe(fields[1])
	options := keys.PKCS12ParseOptions{AllowBER: true}
	if item, err := keys.ParsePKCS12WithOptions(t.Context(), pkcs12FormPFX(t, valid, valid, true), []byte("forms password"), options, keys.Limits{}); item == nil || err != nil {
		t.Fatal(item, err)
	}
	// AlgorithmIdentifier remains DER even under explicit container BER support.
	algorithmFields := privateFields(t, fields[1])
	bad := makeSafe(pkcs12FormIndefinite(0x30, algorithmFields...))
	if item, err := keys.ParsePKCS12WithOptions(t.Context(), pkcs12FormPFX(t, bad, bad, true), []byte("forms password"), options, keys.Limits{}); item != nil || !errors.Is(err, keys.ErrFormat) {
		t.Fatal(item, err)
	}
}

func TestPrivateExportOwnership(t *testing.T) {
	t.Parallel()

	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	r.Precomputed = rsa.PrecomputedValues{}
	options := protection(crypto.SHA256, 256)

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			raw, err := keys.MarshalEncryptedPrivate(t.Context(), r, []byte("password"), options, keys.Limits{})
			if err != nil || len(raw) == 0 {
				t.Error("parallel export failed", err)
			}
		})
	}

	wg.Wait()

	if r.Precomputed.Dp != nil || r.Precomputed.Dq != nil || r.Precomputed.Qinv != nil {
		t.Fatal("export mutated caller RSA CRT state")
	}

	c := testcert.New(t)
	badEC := *c.LeafKey
	badEC.PublicKey = c.RootKey.PublicKey

	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ed[len(ed)-1] ^= 1
	for _, invalid := range []crypto.Signer{&ecdsa.PrivateKey{}, &ecdsa.PrivateKey{Curve: elliptic.P256()}, &badEC, ed25519.PrivateKey{1}, ed} {
		if raw, err := keys.MarshalEncryptedPrivate(t.Context(), invalid, []byte("password"), options, keys.Limits{}); raw != nil || !errors.Is(err, keys.ErrFormat) && !errors.Is(err, keys.ErrPolicy) {
			t.Fatal("invalid exportable key accepted", err)
		}
	}
}

func TestEncryptedPrivateKey(t *testing.T) {
	t.Parallel()

	c := testcert.New(t)

	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ctx := t.Context()
	password := []byte("explicit\x00binary password")
	beforePassword := bytes.Clone(password)

	t.Cleanup(func() {
		if !bytes.Equal(password, beforePassword) {
			t.Fatal("password changed")
		}
	})

	for name, key := range map[string]crypto.Signer{"rsa": r, "ec": c.LeafKey, "ed25519": ed} {
		for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			for _, bits := range []int{128, 192, 256} {
				t.Run(fmt.Sprintf("%s/%s/AES-%d", name, hash, bits), func(t *testing.T) {
					t.Parallel()
					checkEncryptedPrivateKeyCase(t, ctx, key, password, hash, bits)
				})
			}
		}
	}
}

func checkEncryptedPrivateKeyCase(t *testing.T, ctx context.Context, key crypto.Signer, password []byte, hash crypto.Hash, bits int) {
	t.Helper()

	raw, err := keys.MarshalEncryptedPrivate(ctx, key, password, protection(hash, bits), keys.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	other, err := keys.MarshalEncryptedPrivate(ctx, key, password, protection(hash, bits), keys.Limits{})
	if err != nil || bytes.Equal(raw, other) {
		t.Fatal("salt/IV reused", err)
	}

	for _, pemInput := range []bool{false, true} {
		input := bytes.Clone(raw)
		if pemInput {
			input = pem.EncodeToMemory(&pem.Block{Type: textENCRYPTEDPRIVATEKEY, Bytes: input})
		}

		before := bytes.Clone(input)

		parsed, err := keys.ParseEncryptedPrivate(ctx, input, password, keys.Limits{})
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(input, before) {
			t.Fatal("input changed")
		}

		clear(input)
		samePrivate(t, key, parsed)
	}

	if parsed, err := keys.ParseEncryptedPrivate(ctx, raw, []byte("wrong"), keys.Limits{}); parsed != nil || !errors.Is(err, keys.ErrDecrypt) {
		t.Fatal("wrong password accepted", err)
	}

	bad := bytes.Clone(raw)

	bad[len(bad)-1] ^= 1
	if parsed, err := keys.ParseEncryptedPrivate(ctx, bad, password, keys.Limits{}); parsed != nil || !errors.Is(err, keys.ErrDecrypt) {
		t.Fatal("corrupt private key accepted", err)
	}
}

func TestPKCS12Identity(t *testing.T) {
	t.Parallel()

	c := testcert.New(t)
	identity := keys.PKCS12Identity{PrivateKey: c.LeafKey, Certificate: c.Leaf, ExtraCertificates: []*x509.Certificate{c.Root}}
	ctx := t.Context()

	for _, classic := range []bool{false, true} {
		for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			for _, bits := range []int{128, 192, 256} {
				t.Run(fmt.Sprintf("classic=%t/%s/AES-%d", classic, hash, bits), func(t *testing.T) {
					t.Parallel()
					checkPKCS12IdentityCase(t, ctx, identity, classic, hash, bits)
				})
			}
		}
	}

	password := []byte("emoji 😀 password")

	raw, err := keys.MarshalPKCS12(ctx, identity, password, keys.PKCS12Options{Encryption: protection(crypto.SHA256, 256)}, keys.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	if parsed, err := keys.ParsePKCS12(ctx, raw, password, keys.Limits{}); parsed == nil || err != nil {
		t.Fatal("UTF-8 PBMAC1 password rejected", err)
	}

	if raw, err := keys.MarshalPKCS12(ctx, identity, password, keys.PKCS12Options{Encryption: protection(crypto.SHA256, 256), ClassicMAC: true}, keys.Limits{}); raw != nil || !errors.Is(err, keys.ErrPolicy) {
		t.Fatal("non-BMP classic password accepted", err)
	}
}

func checkPKCS12IdentityCase(t *testing.T, ctx context.Context, identity keys.PKCS12Identity, classic bool, hash crypto.Hash, bits int) {
	t.Helper()

	password := []byte("пароль ü")
	options := keys.PKCS12Options{Encryption: protection(hash, bits), ClassicMAC: classic}

	raw, err := keys.MarshalPKCS12(ctx, identity, password, options, keys.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	before := bytes.Clone(raw)

	parsed, err := keys.ParsePKCS12(ctx, raw, password, keys.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(raw, before) {
		t.Fatal("input changed")
	}

	clear(raw)
	samePrivate(t, identity.PrivateKey, parsed.PrivateKey)

	if !bytes.Equal(parsed.Certificate.Raw, identity.Certificate.Raw) || len(parsed.ExtraCertificates) != 1 || !bytes.Equal(parsed.ExtraCertificates[0].Raw, identity.ExtraCertificates[0].Raw) {
		t.Fatal("certificate binding/ownership changed")
	}

	if parsed, err := keys.ParsePKCS12(ctx, before, []byte("wrong"), keys.Limits{}); parsed != nil || !errors.Is(err, keys.ErrDecrypt) {
		t.Fatal("wrong password accepted", err)
	}

	before[len(before)-1] ^= 1 // MAC iteration parameter or PBMAC1 placeholder.
	if classic {
		if parsed, err := keys.ParsePKCS12(ctx, before, password, keys.Limits{}); parsed != nil || err == nil {
			t.Fatal("changed classic MAC parameter accepted")
		}
	}
}

func TestPasswordProtectionPolicy(t *testing.T) {
	t.Parallel()

	c := testcert.New(t)
	ctx := t.Context()
	password := []byte("public test password")

	identity := keys.PKCS12Identity{PrivateKey: c.LeafKey, Certificate: c.Leaf}
	for _, limits := range []keys.Limits{{MinIterations: -1}, {MaxIterations: -1}, {MaxKDFWork: -1}, {MinIterations: 2000, MaxIterations: 1000}} {
		if raw, err := keys.MarshalEncryptedPrivate(ctx, c.LeafKey, password, keys.EncryptionOptions{}, limits); raw != nil || !errors.Is(err, keys.ErrPolicy) {
			t.Fatal("invalid limits accepted", err)
		}
	}

	for _, options := range []keys.EncryptionOptions{{Hash: crypto.SHA1}, {KeyBits: 64}, {Iterations: -1}, {Iterations: 999}, {Iterations: 1000001}} {
		if raw, err := keys.MarshalEncryptedPrivate(ctx, c.LeafKey, password, options, keys.Limits{}); raw != nil || err == nil {
			t.Fatal("unsupported/budgeted encryption accepted")
		}
	}

	var absent *rsa.PrivateKey
	if raw, err := keys.MarshalEncryptedPrivate(ctx, absent, password, protection(crypto.SHA256, 256), keys.Limits{}); raw != nil || !errors.Is(err, keys.ErrPolicy) {
		t.Fatal("typed nil key accepted", err)
	}

	if raw, err := keys.MarshalEncryptedPrivate(ctx, c.LeafKey, nil, keys.EncryptionOptions{}, keys.Limits{}); raw != nil || !errors.Is(err, keys.ErrPolicy) {
		t.Fatal("empty export password accepted", err)
	}

	if raw, err := keys.MarshalPKCS12(ctx, keys.PKCS12Identity{PrivateKey: c.LeafKey, Certificate: c.Root}, password, keys.PKCS12Options{}, keys.Limits{}); raw != nil || !errors.Is(err, keys.ErrFormat) {
		t.Fatal("unmatched certificate accepted", err)
	}

	if raw, err := keys.MarshalPKCS12(ctx, keys.PKCS12Identity{PrivateKey: c.LeafKey, Certificate: c.Leaf, ExtraCertificates: []*x509.Certificate{c.Leaf}}, password, keys.PKCS12Options{}, keys.Limits{}); raw != nil || !errors.Is(err, keys.ErrFormat) {
		t.Fatal("duplicate certificate accepted", err)
	}

	options := keys.PKCS12Options{Encryption: protection(crypto.SHA256, 256)}

	limits := keys.Limits{MaxKDFWork: 2999}
	if raw, err := keys.MarshalPKCS12(ctx, identity, password, options, limits); raw != nil || !errors.Is(err, keys.ErrLimit) {
		t.Fatal("aggregate KDF limit not checked", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	if raw, err := keys.MarshalPKCS12(canceled, identity, password, keys.PKCS12Options{}, keys.Limits{}); raw != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	if key, err := keys.ParseEncryptedPrivate(nil, nil, password, keys.Limits{}); key != nil || !errors.Is(err, keys.ErrPolicy) {
		t.Fatal(err)
	}
}

func TestPrivateExportRejectsNilKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  crypto.Signer
		want error
	}{
		{"nil interface", nil, keys.ErrPolicy},
		{"nil RSA", (*rsa.PrivateKey)(nil), keys.ErrPolicy},
		{"nil ECDSA", (*ecdsa.PrivateKey)(nil), keys.ErrPolicy},
		{"nil Ed25519", ed25519.PrivateKey(nil), keys.ErrPolicy},
		{"empty Ed25519", ed25519.PrivateKey{}, keys.ErrFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := keys.MarshalEncryptedPrivate(t.Context(), tc.key, []byte("password"), protection(crypto.SHA256, 256), keys.Limits{})
			if data != nil || !errors.Is(err, tc.want) {
				t.Fatalf("private export: %d bytes, %v", len(data), err)
			}
		})
	}
}

func FuzzPasswordContainers(f *testing.F) {
	c := testcert.New(f)
	ctx := f.Context()
	password := []byte("public test password")
	options := protection(crypto.SHA256, 256)

	a, err := keys.MarshalEncryptedPrivate(ctx, c.LeafKey, password, options, keys.Limits{})
	if err != nil {
		f.Fatal(err)
	}

	b, err := keys.MarshalPKCS12(ctx, keys.PKCS12Identity{PrivateKey: c.LeafKey, Certificate: c.Leaf}, password, keys.PKCS12Options{Encryption: options}, keys.Limits{})
	if err != nil {
		f.Fatal(err)
	}

	for _, raw := range [][]byte{a, b, pem.EncodeToMemory(&pem.Block{Type: textENCRYPTEDPRIVATEKEY, Bytes: a})} {
		f.Add(raw, password)
	}

	f.Fuzz(func(t *testing.T, raw, password []byte) {
		if len(raw) > 64<<10 || len(password) > 128 {
			return
		}

		limits := keys.Limits{MaxIterations: 1000, MaxKDFWork: 3000}
		_, _ = keys.ParseEncryptedPrivate(ctx, raw, password, limits)
		_, _ = keys.ParsePKCS12(ctx, raw, password, limits)
	})
}

func TestPKCS8VersionAndAttributes(t *testing.T) {
	c := testcert.New(t)

	raw, err := x509.MarshalPKCS8PrivateKey(c.LeafKey)
	if err != nil {
		t.Fatal(err)
	}

	f := privateFields(t, raw)
	for _, version := range []int{-1, 1, 2} {
		rejectPrivate(t, der.Seq(der.Int(version), f[1], f[2]))
	}

	for _, extra := range [][]byte{der.Int(1), der.Ctx(1), der.Ctx(0, der.Seq()), der.Ctx(0, der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 3}), der.Set()))} {
		rejectPrivate(t, der.Seq(f[0], f[1], f[2], extra))
	}

	for _, value := range [][]byte{
		{12, 1, 255},
		{19, 1, '@'},
		{22, 1, 255},
		{30, 2, 0xd8, 0},
		der.Wrap(0, asn1.TagGeneralizedTime, false, []byte("20261019010203.10Z")),
	} {
		attribute := der.Ctx(0, der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 3}), der.Set(value)))
		rejectPrivate(t, der.Seq(f[0], f[1], f[2], attribute))
	}

	validAttr := der.Ctx(0, der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 3}), der.Set(der.Octets([]byte("application attribute")))))

	key, err := keys.ParsePrivate(der.Seq(f[0], f[1], f[2], validAttr), keys.Limits{})
	if err != nil || !key.Public().(*ecdsa.PublicKey).Equal(c.LeafKey.Public()) {
		t.Fatal("valid PKCS#8 attributes rejected", err)
	}
}

func TestPKCS1VersionAndComponentStructure(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	f := privateFields(t, x509.MarshalPKCS1PrivateKey(key))
	for _, version := range []int{-1, 1} {
		parts := append([][]byte{der.Int(version)}, f[1:]...)
		rejectPrivate(t, der.Seq(parts...))
	}

	rejectPrivate(t, der.Seq(append(append([][]byte(nil), f...), der.Seq())...))
	rejectPrivate(t, der.Seq(f[:8]...))
}

func TestMultiPrimeRSAEncodingConsistency(t *testing.T) {
	key := multiPrimeRSA(t)

	raw := x509.MarshalPKCS1PrivateKey(key)

	parsed, err := keys.ParsePrivate(raw, keys.Limits{})
	if err != nil || !parsed.Public().(*rsa.PublicKey).Equal(key.Public()) {
		t.Fatal("valid multi-prime key rejected", err)
	}

	f := privateFields(t, raw)

	other, err := der.Read(f[9], len(f[9]))
	if err != nil {
		t.Fatal(err)
	}

	primes, err := der.Sequence(other, 1, 1)
	if err != nil {
		t.Fatal(err)
	}

	info := privateFields(t, primes[0].FullBytes)
	for _, field := range []int{1, 2} {
		changed := append([][]byte(nil), info...)
		changed[field] = der.Int(0)

		parts := append([][]byte(nil), f...)
		parts[9] = der.Seq(der.Seq(changed...))
		rejectPrivate(t, der.Seq(parts...))
	}
}

func TestECPrivateEncodingConsistency(t *testing.T) {
	scalar := make([]byte, 32)
	scalar[len(scalar)-1] = 1

	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	f := privateFields(t, raw)
	for _, encoded := range [][]byte{scalar[1:], append([]byte{0}, scalar...)} {
		rejectPrivate(t, der.Seq(f[0], der.Octets(encoded), f[2], f[3]))
	}

	other := testcert.Key(t)

	public, err := other.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	bits, err := asn1.Marshal(asn1.BitString{Bytes: public, BitLength: len(public) * 8})
	if err != nil {
		t.Fatal(err)
	}

	rejectPrivate(t, der.Seq(f[0], f[1], f[2], der.Ctx(1, bits)))
	rejectPrivate(t, der.Seq(f[0], f[1], f[2], f[3], der.Ctx(2, der.Int(1))))

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	outer := privateFields(t, pkcs8)
	wrongCurve := der.Ctx(0, der.OID(asn1.ObjectIdentifier{1, 3, 132, 0, 34}))
	rejectPrivate(t, der.Seq(outer[0], outer[1], der.Octets(der.Seq(f[0], f[1], wrongCurve, f[3]))))

	parsed, err := keys.ParsePrivate(raw, keys.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	got, err := x509.MarshalPKCS8PrivateKey(parsed)
	if err != nil || !bytes.Equal(got, pkcs8) {
		t.Fatal("valid EC private key changed", err)
	}
}

func TestLargePKCS12ResourceLimits(t *testing.T) {
	c := testcert.New(t)

	const certificates = 20

	identity := keys.PKCS12Identity{PrivateKey: c.LeafKey, Certificate: c.Leaf}
	padding := make([]byte, 64<<10)

	for i := range certificates - 1 {
		template := *c.Root
		template.SerialNumber = big.NewInt(int64(i + 10))
		template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: padding}}
		identity.ExtraCertificates = append(identity.ExtraCertificates, testcert.Issue(t, &template, c.Root, c.RootKey.Public(), c.RootKey))
	}

	password := []byte("large container")
	options := keys.PKCS12Options{Encryption: protection(crypto.SHA256, 256)}
	limits := keys.Limits{MaxCertificates: certificates, MaxBags: certificates + 1, MaxKDFWork: 3000}

	raw, err := keys.MarshalPKCS12(t.Context(), identity, password, options, limits)
	if err != nil {
		t.Fatal(err)
	}

	if len(raw) <= 1<<20 {
		t.Fatal("fixture does not exercise the former container ceiling")
	}

	limits.MaxInputBytes = len(raw)
	limits.MaxContainerBytes = len(raw)

	parsed, err := keys.ParsePKCS12(t.Context(), raw, password, limits)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(parsed.Certificate.Raw, c.Leaf.Raw) || len(parsed.ExtraCertificates) != certificates-1 {
		t.Fatal("container identity or certificate collection changed")
	}

	for _, tc := range []struct {
		name   string
		change func(*keys.Limits)
	}{
		{"container", func(l *keys.Limits) { l.MaxContainerBytes-- }},
		{"certificate bytes", func(l *keys.Limits) { l.MaxCertificateBytes = 1 }},
		{"certificate count", func(l *keys.Limits) { l.MaxCertificates-- }},
		{"bags across safes", func(l *keys.Limits) { l.MaxBags-- }},
		{"content infos", func(l *keys.Limits) { l.MaxContentInfos = 1 }},
		{"aggregate KDF work", func(l *keys.Limits) { l.MaxKDFWork-- }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			small := limits
			tc.change(&small)

			if parsed, err := keys.ParsePKCS12(t.Context(), raw, password, small); parsed != nil || !errors.Is(err, keys.ErrLimit) {
				t.Fatalf("parse exposed partial identity: %v", err)
			}

			if data, err := keys.MarshalPKCS12(t.Context(), identity, password, options, small); data != nil || !errors.Is(err, keys.ErrLimit) {
				t.Fatalf("export exposed partial output: %v", err)
			}
		})
	}
}

func protection(hash crypto.Hash, bits int) keys.EncryptionOptions {
	return keys.EncryptionOptions{Hash: hash, KeyBits: bits, Iterations: 1000}
}

func samePrivate(t testing.TB, want, got crypto.Signer) {
	t.Helper()

	a, err := x509.MarshalPKCS8PrivateKey(want)
	if err != nil {
		t.Fatal(err)
	}

	b, err := x509.MarshalPKCS8PrivateKey(got)
	if err != nil {
		t.Fatal(err)
	}

	defer clear(a)
	defer clear(b)

	if !bytes.Equal(a, b) {
		t.Fatal("different private key")
	}
}

func privateFields(t *testing.T, raw []byte) [][]byte {
	t.Helper()

	v, err := der.Read(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}

	f, err := der.Sequence(v, 2, 16)
	if err != nil {
		t.Fatal(err)
	}

	parts := make([][]byte, len(f))
	for i := range f {
		parts[i] = f[i].FullBytes
	}

	return parts
}

func rejectPrivate(t *testing.T, raw []byte) {
	t.Helper()

	if key, err := keys.ParsePrivate(raw, keys.Limits{}); key != nil || !errors.Is(err, keys.ErrFormat) {
		t.Fatalf("invalid private-key structure accepted: key=%v, error=%v", key != nil, err)
	}
}
