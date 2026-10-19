//go:build interop

package interop_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/skarm/xmlsec/keys"
)

const (
	protectedKeyIterations = "2048"
	passwordFilePrefix     = "file:"
	flagPasswordOut        = "-passout"
	flagKDFIterations      = "-iter"
	pkcs8PEM               = "pkcs8-pem"
	flagCertificatePBE     = "-certpbe"
	flagKeyPBE             = "-keypbe"
	flagMACAlgorithm       = "-macalg"
	flagExportPKCS12       = "-export"
	flagPBMAC1             = "-pbmac1_pbkdf2"
	flagPBMAC1Digest       = "-pbmac1_pbkdf2_md"
	pkcs12Classic          = "pkcs12-classic"
	flagCertificateFile    = "-certfile"
	pemFormat              = "PEM"
)

const (
	namePkcs12Pbmac1 = "pkcs12-pbmac1"
	namePassword     = "Password"
	namePkcs12       = "pkcs12"
)

func TestXMLSecKeyFormats(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "xmlsec")
	dir := t.TempDir()
	cli := binary(t, fixture, "xmlsec")
	count := 0

	for _, name := range []string{nameRsaSha256, nameEcdsaSha256, nameEd25519} {
		key := generateKey(t, dir, name)

		pkcs8, err := x509.MarshalPKCS8PrivateKey(key.signer)
		if err != nil {
			t.Fatal(err)
		}

		formats := [][]byte{pkcs8}
		// Traditional private formats are supplied by the standard x509 encoder.
		block, _ := pem.Decode(read(t, key.private))
		if block == nil {
			t.Fatal("private key PEM")
		}

		if name == nameRsaSha256 {
			k, err := keys.ParsePrivate(read(t, key.private), keys.Limits{})
			if err != nil {
				t.Fatal(err)
			}

			formats = append(formats, traditionalRSA(t, k))
		}

		if name == nameEcdsaSha256 {
			k, err := keys.ParsePrivate(read(t, key.private), keys.Limits{})
			if err != nil {
				t.Fatal(err)
			}

			formats = append(formats, traditionalEC(t, k))
		}

		spki, err := x509.MarshalPKIXPublicKey(key.signer.Public())
		if err != nil {
			t.Fatal(err)
		}

		for _, privateDER := range formats {
			private := write(t, filepath.Join(dir, "private.der"), privateDER)
			source := write(t, filepath.Join(dir, "template.xml"), []byte(coreTemplate("whole", key.method, exc)))
			ours, theirs := filepath.Join(dir, "go.xml"), filepath.Join(dir, "ref.xml")
			command(t, fixture, true, nil, cli, "sign-template", flagKey, private, "-modern-algorithms", "-signature-index", "0", flagIn, source, flagOut, ours)
			args := append([]string{"--privkey-der", private, flagEnabledReferenceUris, nameEmptySameDoc}, idArgs()...)
			native(t, fixture, true, nameSign, append(args, "--output", theirs, source)...)

			for i, publicDER := range [][]byte{spki, key.cert.Raw} {
				public := write(t, filepath.Join(dir, "public.der"), publicDER)

				arg := "--pubkey-der"
				if i == 1 {
					arg = "--pubkey-cert-der"
				}

				args := append([]string{arg, public, flagEnabledReferenceUris, nameEmptySameDoc}, idArgs()...)
				native(t, fixture, true, nameVerify, append(args, ours)...)
				raw, _ := command(t, fixture, true, nil, cli, "verify-core", flagKey, public, "-modern-algorithms", "-signature-index", "0", flagIn, theirs)
				verifyReport(t, raw, true)

				count++
				bad := write(t, filepath.Join(dir, "trailing.der"), append(bytes.Clone(publicDER), 0))
				command(t, fixture, false, nil, cli, "verify-core", flagKey, bad, "-modern-algorithms", "-signature-index", "0", flagIn, theirs)
			}
		}
	}

	t.Logf("%d DER key/certificate exchanges each direction; trailing DER rejected", count)
}

func traditionalRSA(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	return x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))
}

func traditionalEC(t *testing.T, key crypto.Signer) []byte {
	t.Helper()

	b, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func TestXMLSecProtectedKeys(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "xmlsec")
	dir := t.TempDir()
	cli := binary(t, fixture, "xmlsec")
	chain := generateKey(t, dir, nameEcdsaSha384)
	count, macControls := 0, 0
	openssl, _ := command(t, fixture, true, nil, "openssl", "version")
	t.Log(string(openssl))

	for _, name := range []string{nameRsaSha256, nameEcdsaSha256, nameEd25519} {
		key := generateKey(t, dir, name)

		expectedDER, err := x509.MarshalPKIXPublicKey(key.signer.Public())
		if err != nil {
			t.Fatal(err)
		}

		expected := sha256.Sum256(expectedDER)
		certificateHash := sha256.Sum256(key.cert.Raw)
		source := write(t, filepath.Join(dir, "template.xml"), []byte(coreTemplate("whole", key.method, exc)))

		for _, pair := range [][2]int{{128, 256}, {192, 384}, {256, 512}} {
			bits, digest := pair[0], pair[1]
			for _, form := range []string{"pkcs8-der", pkcs8PEM, pkcs12Classic, namePkcs12Pbmac1} {
				t.Run(name+"/"+strconv.Itoa(bits)+"/"+form, func(t *testing.T) {
					testXMLSecProtectedKeysCase(t, &form, &dir, &fixture, &key, &digest, &bits, &chain, &expectedDER, &expected, &certificateHash, &source, &cli, &macControls, &count)
				})
			}
		}

		for _, modern := range []bool{false, true} {
			container := filepath.Join(dir, "empty.p12")
			passwordFile := write(t, filepath.Join(dir, "empty-password"), []byte{'\n'})

			args := []string{namePkcs12, flagExportPKCS12, flagInkey, key.private, flagIn, key.certificate, flagCertificateFile, chain.certificate, flagOut, container, flagPasswordOut, passwordFilePrefix + passwordFile, flagKeyPBE, "AES-256-CBC", flagCertificatePBE, "AES-256-CBC", flagMACAlgorithm, nameSha256, flagKDFIterations, protectedKeyIterations}
			if modern {
				args = append(args, flagPBMAC1, flagPBMAC1Digest, nameSha256)
			}

			command(t, fixture, true, nil, "openssl", args...)

			parse := map[string]any{nameMode: "parse-pkcs12", nameInput: container, namePassword: []byte{}}
			r := probe(t, fixture, "keyprobe", parse, true)
			assertJSON(t, r, "fingerprint", hex.EncodeToString(expected[:]))
			assertJSON(t, r, "extras", 1)

			parse[namePassword] = []byte("wrong password")
			probe(t, fixture, "keyprobe", parse, false)
		}
	}

	t.Logf("%d protected containers each direction with OpenSSL and xmlsec1; %d MAC and missing-MAC controls; 6 empty-password imports", count, macControls)
}

func assertJSON(t *testing.T, r map[string]json.RawMessage, name string, expected any) {
	t.Helper()

	want, _ := json.Marshal(expected)
	if !bytes.Equal(r[name], want) {
		t.Fatalf("%s=%s; want %s", name, r[name], want)
	}
}

func noOutput(t *testing.T, path string) {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	if len(b) != 0 {
		t.Fatalf("plaintext/output exposed after rejection: %s", path)
	}
}

func alterPFX(t *testing.T, data []byte, remove bool) []byte {
	t.Helper()

	var pfx struct {
		Version  int
		AuthSafe asn1.RawValue
		MAC      asn1.RawValue `asn1:"optional"`
	}

	rest, err := asn1.Unmarshal(data, &pfx)
	if err != nil || len(rest) != 0 {
		t.Fatal("PFX", err)
	}

	if remove {
		pfx.MAC = asn1.RawValue{}
	} else {
		var mac struct {
			Info struct {
				Algorithm asn1.RawValue
				Digest    []byte
			}
			Salt       []byte
			Iterations int `asn1:"optional,default:1"`
		}

		rest, err = asn1.Unmarshal(pfx.MAC.FullBytes, &mac)
		if err != nil || len(rest) != 0 || len(mac.Info.Digest) == 0 {
			t.Fatal("MAC", err)
		}

		mac.Info.Digest[0] ^= 1

		raw, err := asn1.Marshal(mac)
		if err != nil {
			t.Fatal(err)
		}

		pfx.MAC = asn1.RawValue{FullBytes: raw}
	}

	raw, err := asn1.Marshal(pfx)
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

func testXMLSecProtectedKeysCase(t *testing.T, form *string, dir *string, fixture **interopFixture, key *testKey, digest *int, bits *int, chain *testKey, expectedDER *[]byte, expected *[32]byte, certificateHash *[32]byte, source *string, cli *string, macControls *int, count *int) {
	pfx := (*form) == pkcs12Classic || (*form) == namePkcs12Pbmac1
	modern := (*form) == namePkcs12Pbmac1

	password := "public пароль ü"
	if modern {
		password += " 😀"
	}

	passwordFile := write(t, filepath.Join((*dir), "password"), []byte(password+"\n"))
	ours, theirs, restored, signed := filepath.Join((*dir), "container-go"), filepath.Join((*dir), "container-ref"), filepath.Join((*dir), "restored.pem"), filepath.Join((*dir), "signed.xml")
	mode := "marshal-pkcs8"
	nativeArg := "--pkcs8-der"
	format := nameDER

	if pfx {
		mode = "marshal-pkcs12"
		nativeArg = "--pkcs12"
	}

	if (*form) == pkcs8PEM {
		nativeArg = "--pkcs8-pem"
		format = pemFormat
	}

	encoded := probeData(t, (*fixture), "keyprobe", map[string]any{nameMode: mode, nameKey: key.private, namePassword: []byte(password), "Hash": (*digest), "KeyBits": (*bits), "Iterations": 2048, "Certificate": key.certificate, "Extras": []string{chain.certificate}, "ClassicMAC": !modern})
	if format == pemFormat {
		encoded = pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encoded})
	}

	write(t, ours, encoded)

	if pfx {
		command(t, (*fixture), true, nil, "openssl", namePkcs12, flagIn, ours, "-passin", passwordFilePrefix+passwordFile, "-noenc", flagOut, restored)

		args := []string{namePkcs12, flagExportPKCS12, flagInkey, key.private, flagIn, key.certificate, flagCertificateFile, chain.certificate, "-name", "test identity", flagOut, theirs, flagPasswordOut, passwordFilePrefix + passwordFile, flagKeyPBE, fmt.Sprintf("AES-%d-CBC", (*bits)), flagCertificatePBE, fmt.Sprintf("AES-%d-CBC", (*bits)), flagKDFIterations, protectedKeyIterations, flagMACAlgorithm, fmt.Sprintf("sha%d", (*digest))}
		if modern {
			args = append(args, flagPBMAC1, flagPBMAC1Digest, fmt.Sprintf("sha%d", (*digest)))
		}

		command(t, (*fixture), true, nil, "openssl", args...)
		checkCertificates(t, read(t, restored), key.cert.Raw, chain.cert.Raw)
	} else {
		command(t, (*fixture), true, nil, "openssl", "pkcs8", flagIn, ours, "-inform", format, "-passin", passwordFilePrefix+passwordFile, flagOut, restored)
		command(t, (*fixture), true, nil, "openssl", "pkcs8", "-topk8", flagIn, key.private, flagOut, theirs, "-outform", format, "-v2", fmt.Sprintf("aes-%d-cbc", (*bits)), "-v2prf", fmt.Sprintf("hmacWithSHA%d", (*digest)), flagKDFIterations, protectedKeyIterations, flagPasswordOut, passwordFilePrefix+passwordFile)
	}

	restoredKey := privatePEM(t, read(t, restored))

	spki, err := x509.MarshalPKIXPublicKey(restoredKey.Public())
	if err != nil || !bytes.Equal(spki, (*expectedDER)) {
		t.Fatalf("OpenSSL restored key differs: %v", err)
	}

	mode = "parse-pkcs8"
	if pfx {
		mode = "parse-pkcs12"
	}

	parse := map[string]any{nameMode: mode, nameInput: theirs, namePassword: []byte(password)}
	r := probe(t, (*fixture), "keyprobe", parse, true)
	assertJSON(t, r, "fingerprint", hex.EncodeToString((*expected)[:]))

	if pfx {
		assertJSON(t, r, "certificate", hex.EncodeToString((*certificateHash)[:]))
		assertJSON(t, r, "extras", 1)
	}

	args := append([]string{nativeArg, ours, "--pwd", password, flagEnabledReferenceUris, nameEmptySameDoc}, idArgs()...)
	native(t, (*fixture), true, nameSign, append(args, "--output", signed, (*source))...)
	raw, _ := command(t, (*fixture), true, nil, (*cli), "verify-core", flagKey, key.public, "-signature-index", "0", "-modern-algorithms", flagIn, signed)
	verifyReport(t, raw, true)

	keyFormat := "pkcs8"
	if pfx {
		keyFormat = namePkcs12
	}

	command(t, (*fixture), true, nil, (*cli), "sign-template", flagKey, theirs, "-key-format", keyFormat, "-password-file", passwordFile, "-signature-index", "0", "-modern-algorithms", flagIn, (*source), flagOut, signed)

	args = append([]string{flagPubkeyPem, key.public, flagEnabledReferenceUris, nameEmptySameDoc}, idArgs()...)
	native(t, (*fixture), true, nameVerify, append(args, signed)...)

	parse[namePassword] = []byte("wrong test password")

	r = probe(t, (*fixture), "keyprobe", parse, false)
	if len(r["fingerprint"]) != 0 {
		t.Fatal("key exposed after failure")
	}

	wrong := write(t, filepath.Join((*dir), "wrong-password"), []byte("wrong test password\n"))
	if pfx {
		command(t, (*fixture), false, nil, "openssl", namePkcs12, flagIn, theirs, "-passin", passwordFilePrefix+wrong, "-noout")
	} else {
		command(t, (*fixture), false, nil, "openssl", "pkcs8", flagIn, theirs, "-inform", format, "-passin", passwordFilePrefix+wrong, flagOut, restored)
	}

	if pfx {
		bad := filepath.Join((*dir), "bad.p12")
		write(t, bad, alterPFX(t, read(t, theirs), false))

		parse[namePassword] = []byte(password)
		parse[nameInput] = bad
		probe(t, (*fixture), "keyprobe", parse, false)
		command(t, (*fixture), false, nil, "openssl", namePkcs12, flagIn, bad, "-passin", passwordFilePrefix+passwordFile, "-noout")
		os.Remove(signed)

		args = append([]string{"--pkcs12", bad, "--pwd", password, flagEnabledReferenceUris, nameEmptySameDoc}, idArgs()...)
		native(t, (*fixture), false, nameSign, append(args, "--output", signed, (*source))...)
		noOutput(t, signed)
		write(t, bad, alterPFX(t, read(t, theirs), true))
		probe(t, (*fixture), "keyprobe", parse, false)

		(*macControls)++
	}

	(*count)++
}

func TestOpenSSLProtectedKeys(t *testing.T) {
	fixture := newInteropFixture(t)
	dir := t.TempDir()

	chain := generateKey(t, dir, nameEcdsaSha384)
	for _, name := range []string{nameRsaSha256, nameEcdsaSha256, nameEd25519} {
		key := generateKey(t, dir, name)

		for _, pair := range []struct {
			bits int
			hash crypto.Hash
		}{{128, crypto.SHA256}, {192, crypto.SHA384}, {256, crypto.SHA512}} {
			for _, form := range []string{"pkcs8-der", pkcs8PEM, pkcs12Classic, namePkcs12Pbmac1} {
				t.Run(name+"/"+strconv.Itoa(pair.bits)+"/"+form, func(t *testing.T) {
					testOpenSSLProtectedKey(t, fixture, key, chain, form, keys.EncryptionOptions{Hash: pair.hash, KeyBits: pair.bits, Iterations: 2048})
				})
			}
		}
	}
}

func testOpenSSLProtectedKey(t *testing.T, fixture *interopFixture, key, chain testKey, form string, options keys.EncryptionOptions) {
	t.Helper()
	dir := t.TempDir()
	password := []byte("public пароль ü")
	passwordFile := write(t, filepath.Join(dir, "password"), append(bytes.Clone(password), '\n'))
	ours, theirs, restored := filepath.Join(dir, "ours"), filepath.Join(dir, "theirs"), filepath.Join(dir, "restored.pem")
	pfx := form == pkcs12Classic || form == namePkcs12Pbmac1

	var (
		output bytes.Buffer
		n      int64
		err    error
	)
	if pfx {
		n, err = keys.WritePKCS12(t.Context(), &output, keys.PKCS12Identity{PrivateKey: key.signer, Certificate: key.cert, ExtraCertificates: []*x509.Certificate{chain.cert}}, password, keys.PKCS12Options{Encryption: options, ClassicMAC: form == pkcs12Classic}, keys.Limits{})
	} else {
		n, err = keys.WriteEncryptedPrivate(t.Context(), &output, key.signer, password, options, keys.Limits{})
	}

	if err != nil || n != int64(output.Len()) {
		t.Fatal(n, err)
	}

	encoded := output.Bytes()
	format := nameDER

	if form == pkcs8PEM {
		encoded = pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encoded})
		format = pemFormat
	}

	write(t, ours, encoded)

	digest := options.Hash.Size() * 8

	if pfx {
		command(t, fixture, true, nil, "openssl", namePkcs12, flagIn, ours, "-passin", passwordFilePrefix+passwordFile, "-noenc", flagOut, restored)

		args := []string{namePkcs12, flagExportPKCS12, flagInkey, key.private, flagIn, key.certificate, flagCertificateFile, chain.certificate, flagOut, theirs, flagPasswordOut, passwordFilePrefix + passwordFile, flagKeyPBE, fmt.Sprintf("AES-%d-CBC", options.KeyBits), flagCertificatePBE, fmt.Sprintf("AES-%d-CBC", options.KeyBits), flagKDFIterations, protectedKeyIterations, flagMACAlgorithm, fmt.Sprintf("sha%d", digest)}
		if form == namePkcs12Pbmac1 {
			args = append(args, flagPBMAC1, flagPBMAC1Digest, fmt.Sprintf("sha%d", digest))
		}

		command(t, fixture, true, nil, "openssl", args...)
		checkCertificates(t, read(t, restored), key.cert.Raw, chain.cert.Raw)
	} else {
		command(t, fixture, true, nil, "openssl", "pkcs8", flagIn, ours, "-inform", format, "-passin", passwordFilePrefix+passwordFile, flagOut, restored)
		command(t, fixture, true, nil, "openssl", "pkcs8", "-topk8", flagIn, key.private, flagOut, theirs, "-outform", format, "-v2", fmt.Sprintf("aes-%d-cbc", options.KeyBits), "-v2prf", fmt.Sprintf("hmacWithSHA%d", digest), flagKDFIterations, protectedKeyIterations, flagPasswordOut, passwordFilePrefix+passwordFile)
	}

	restoredKey := privatePEM(t, read(t, restored))

	got, err := x509.MarshalPKIXPublicKey(restoredKey.Public())
	if err != nil || !bytes.Equal(got, key.cert.RawSubjectPublicKeyInfo) {
		t.Fatal("OpenSSL restored a different key", err)
	}

	parse := func(data, password []byte) (crypto.Signer, error) {
		if !pfx {
			return keys.ParseEncryptedPrivate(t.Context(), data, password, keys.Limits{})
		}

		identity, err := keys.ParsePKCS12(t.Context(), data, password, keys.Limits{})
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(identity.Certificate.Raw, key.cert.Raw) || len(identity.ExtraCertificates) != 1 || !bytes.Equal(identity.ExtraCertificates[0].Raw, chain.cert.Raw) {
			return nil, errors.New("OpenSSL certificate bags changed")
		}

		return identity.PrivateKey, nil
	}

	parsed, err := parse(read(t, theirs), password)
	if err != nil {
		t.Fatal(err)
	}

	got, err = x509.MarshalPKIXPublicKey(parsed.Public())
	if err != nil || !bytes.Equal(got, key.cert.RawSubjectPublicKeyInfo) {
		t.Fatal("imported OpenSSL key differs", err)
	}

	if parsed, err := parse(read(t, theirs), []byte("wrong password")); parsed != nil || err == nil {
		t.Fatal("wrong password accepted")
	}
}

func checkCertificates(t *testing.T, data []byte, expected ...[]byte) {
	t.Helper()

	found := make(map[string]bool)

	for len(data) > 0 {
		p, rest := pem.Decode(data)
		if p == nil {
			break
		}

		data = rest

		if p.Type == nameCERTIFICATE {
			found[string(p.Bytes)] = true
		}
	}

	if len(found) != len(expected) {
		t.Fatalf("certificate count: %d", len(found))
	}

	for _, der := range expected {
		if !found[string(der)] {
			t.Fatal("certificate missing")
		}
	}
}

func privatePEM(t *testing.T, data []byte) crypto.Signer {
	t.Helper()

	for len(data) > 0 {
		p, rest := pem.Decode(data)
		if p == nil {
			break
		}

		data = rest

		if p.Type == "PRIVATE KEY" || p.Type == "RSA PRIVATE KEY" || p.Type == "EC PRIVATE KEY" {
			key, err := keys.ParsePrivate(pem.EncodeToMemory(p), keys.Limits{})
			if err != nil {
				t.Fatal(err)
			}

			return key
		}
	}

	t.Fatal("private key missing")

	return nil
}
