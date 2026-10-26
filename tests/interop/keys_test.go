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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
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

func pkcs12InteropFields(t *testing.T, raw []byte) []asn1.RawValue {
	t.Helper()
	v, err := der.Read(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}
	parts, err := der.Sequence(v, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	return parts
}

func pkcs12InteropSafe(t *testing.T, raw []byte) []asn1.RawValue {
	t.Helper()
	outer := pkcs12InteropFields(t, raw)
	info := pkcs12InteropFields(t, outer[1].FullBytes)
	wrapped, err := der.Explicit(info[1], 0)
	if err != nil || !der.Is(wrapped, 0, asn1.TagOctetString, false) {
		t.Fatal(err)
	}
	return pkcs12InteropFields(t, wrapped.Bytes)
}

func pkcs12InteropPFX(t *testing.T, fixture *interopFixture, authenticated []byte) []byte {
	t.Helper()
	salt := []byte("OpenSSL independent multi-identity salt")
	key, _ := command(t, fixture, true, nil, "openssl", "kdf", "-keylen", "32", "-kdfopt", "digest:SHA256", "-kdfopt", "pass:forms password", "-kdfopt", "hexsalt:"+hex.EncodeToString(salt), "-kdfopt", "iter:1000", "-binary", "PBKDF2")
	defer clear(key)
	mac, _ := command(t, fixture, true, authenticated, "openssl", "mac", "-digest", "SHA256", "-macopt", "hexkey:"+hex.EncodeToString(key), "-binary", "HMAC")
	prf := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}), []byte{5, 0})
	kdf := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}), der.Seq(der.Octets(salt), der.Int(1000), der.Int(32), prf))
	algorithm := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}), der.Seq(kdf, prf))
	macData := der.Seq(der.Seq(algorithm, der.Octets(mac)), der.Octets(nil))
	return der.Seq(der.Int(3), der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}), der.Ctx(0, der.Octets(authenticated))), macData)
}

func TestXMLSecPKCS12Forms(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	dir := t.TempDir()
	passwordFile := write(t, filepath.Join(dir, "password"), []byte("forms password\n"))
	var infos [][]byte
	certs := make([][]byte, 0, 2)
	for i, name := range []string{nameEcdsaSha256, nameEd25519} {
		key := generateKey(t, dir, name)
		path := filepath.Join(dir, strconv.Itoa(i)+".p12")
		command(t, fixture, true, nil, "openssl", "pkcs12", "-export", "-inkey", key.private, "-in", key.certificate, "-out", path, "-passout", passwordFilePrefix+passwordFile, "-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC", "-iter", "1000", "-macalg", "SHA256", "-pbmac1_pbkdf2", "-pbmac1_pbkdf2_md", "SHA256")
		for _, info := range pkcs12InteropSafe(t, read(t, path)) {
			infos = append(infos, info.FullBytes)
		}
		certs = append(certs, key.cert.Raw)
	}
	for _, nested := range []bool{false, true} {
		selectedInfos := infos
		if nested {
			selectedInfos = pkcs12InteropNested(t, infos)
		}
		for _, indefinite := range []bool{false, true} {
			authenticated := der.Seq(selectedInfos...)
			if indefinite {
				authenticated = append(append([]byte{0x30, 0x80}, bytes.Join(selectedInfos, nil)...), 0, 0)
			}
			raw := pkcs12InteropPFX(t, fixture, authenticated)
			path := write(t, filepath.Join(dir, "multi.p12"), raw)
			out, _ := command(t, fixture, true, nil, "openssl", "pkcs12", "-in", path, "-passin", passwordFilePrefix+passwordFile, "-noenc")
			checkCertificates(t, out, certs...)
			if bytes.Count(out, []byte("-----BEGIN PRIVATE KEY-----")) != 2 {
				t.Fatal("independent reader did not recover both keys")
			}
			options := keys.PKCS12ParseOptions{AllowBER: indefinite, AllowNestedSafeContents: nested}
			items, err := keys.ParsePKCS12Identities(t.Context(), raw, []byte("forms password"), options, keys.Limits{})
			if err != nil || len(items) != 2 {
				t.Fatal(items, err)
			}
			for _, certificate := range certs {
				options.CertificateSHA256 = sha256.Sum256(certificate)
				item, err := keys.ParsePKCS12WithOptions(t.Context(), raw, []byte("forms password"), options, keys.Limits{})
				if err != nil || !bytes.Equal(item.Certificate.Raw, certificate) {
					t.Fatal(item, err)
				}
			}
			if item, err := keys.ParsePKCS12(t.Context(), raw, []byte("forms password"), keys.Limits{}); item != nil || err == nil {
				t.Fatal(item, err)
			}
			bad := alterPFX(t, raw, false)
			badPath := write(t, filepath.Join(dir, "corrupt-mac.p12"), bad)
			command(t, fixture, false, nil, "openssl", "pkcs12", "-in", badPath, "-passin", passwordFilePrefix+passwordFile, "-noout")
			options.CertificateSHA256 = [32]byte{}
			if items, err := keys.ParsePKCS12Identities(t.Context(), bad, []byte("forms password"), options, keys.Limits{}); items != nil || !errors.Is(err, keys.ErrDecrypt) {
				t.Fatal(items, err)
			}
		}
	}
	t.Log("P6_PROOF_PKCS12_FORMS: OpenSSL-generated encrypted bags; OpenSSL PBKDF2/HMAC and reader agree on DER/BER flat/nested multi-identity contents; exact certificate selection, default and corrupt-MAC rejection")
}

func pkcs12InteropNested(t *testing.T, infos [][]byte) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(infos))
	for _, raw := range infos {
		fields := pkcs12InteropFields(t, raw)
		if !der.OIDEqual(fields[0], asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}) {
			out = append(out, raw)
			continue
		}
		content, err := der.Explicit(fields[1], 0)
		if err != nil || !der.Is(content, 0, asn1.TagOctetString, false) {
			t.Fatal(err)
		}
		nested := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}), der.Ctx(0, content.Bytes))
		out = append(out, der.Seq(fields[0].FullBytes, der.Ctx(0, der.Octets(der.Seq(nested)))))
	}
	return out
}

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

	found := make(map[string]struct{})

	for len(data) > 0 {
		p, rest := pem.Decode(data)
		if p == nil {
			break
		}

		data = rest

		if p.Type == nameCERTIFICATE {
			found[string(p.Bytes)] = struct{}{}
		}
	}

	if len(found) != len(expected) {
		t.Fatalf("certificate count: %d", len(found))
	}

	for _, der := range expected {
		if _, exists := found[string(der)]; !exists {
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

// Compatibility is explicit: independent PKCS#8 SHA-1/default-PRF readers do
// not widen the package's SHA-2 export or strict DER import defaults.
func TestXMLSecPKCS8Compatibility(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	dir := t.TempDir()
	key := generateKey(t, dir, nameEcdsaSha256)
	password := []byte("compatibility password")
	passwordFile := write(t, filepath.Join(dir, "password"), append(bytes.Clone(password), '\n'))
	for _, bits := range []int{128, 192, 256} {
		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			path := filepath.Join(dir, "legacy.der")
			command(t, fixture, true, nil, "openssl", "pkcs8", "-topk8", "-in", key.private, "-out", path, "-outform", "DER", "-v2", fmt.Sprintf("aes-%d-cbc", bits), "-v2prf", "hmacWithSHA1", "-iter", "1000", "-passout", passwordFilePrefix+passwordFile)
			raw := read(t, path)
			if got, err := keys.ParseEncryptedPrivate(t.Context(), raw, password, keys.Limits{}); got != nil || !errors.Is(err, keys.ErrPolicy) {
				t.Fatal("default accepted SHA1", err)
			}
			checkPKCS8CompatibilityKey(t, key.signer, raw, password)
			if got, err := keys.ParseEncryptedPrivateWithOptions(t.Context(), raw, []byte("wrong"), keys.EncryptedPrivateParseOptions{AllowLegacy: true}, keys.Limits{}); got != nil || !errors.Is(err, keys.ErrDecrypt) {
				t.Fatal("wrong password accepted", err)
			}
			// An explicit HMAC-SHA1 identifier denotes the same compatibility
			// algorithm as the omitted DEFAULT. The independent reader verifies it.
			outer := pkcs12InteropFields(t, raw)
			alg := pkcs12InteropFields(t, outer[0].FullBytes)
			params := pkcs12InteropFields(t, alg[1].FullBytes)
			kdf := pkcs12InteropFields(t, params[0].FullBytes)
			kdfParams := pkcs12InteropFields(t, kdf[1].FullBytes)
			if len(kdfParams) != 2 {
				t.Fatal("OpenSSL did not produce omitted default PRF")
			}
			sha1 := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}), []byte{5, 0})
			explicit := der.Seq(der.Seq(alg[0].FullBytes, der.Seq(der.Seq(kdf[0].FullBytes, der.Seq(kdfParams[0].FullBytes, kdfParams[1].FullBytes, sha1)), params[1].FullBytes)), outer[1].FullBytes)
			write(t, path, explicit)
			command(t, fixture, true, nil, "openssl", "pkcs8", "-in", path, "-inform", "DER", "-passin", passwordFilePrefix+passwordFile, "-out", filepath.Join(dir, "restored.pem"))
			checkPKCS8CompatibilityKey(t, key.signer, explicit, password)
			checkPKCS8BERCompatibility(t, fixture, key.signer, raw, password, passwordFile, dir)
		})
	}
	checkPKCS8BinaryPasswordCompatibility(t, fixture, key.signer)
	checkPKCS12SHA1Compatibility(t, fixture, key, dir, password, passwordFile)
	t.Log("P6_PROOF_PKCS8_COMPATIBILITY: ready OpenSSL PBES2 default/explicit SHA1, all AES sizes, selected BER, binary/empty password primitives, classic SHA1 MAC and non-default PBMAC1 key length")
}

func checkPKCS8CompatibilityKey(t *testing.T, expected crypto.Signer, raw, password []byte) {
	t.Helper()
	got, err := keys.ParseEncryptedPrivateWithOptions(t.Context(), raw, password, keys.EncryptedPrivateParseOptions{AllowLegacy: true, AllowBER: true}, keys.Limits{})
	if got == nil || err != nil {
		t.Fatal(got, err)
	}
	wantDER, _ := x509.MarshalPKIXPublicKey(expected.Public())
	gotDER, _ := x509.MarshalPKIXPublicKey(got.Public())
	if !bytes.Equal(wantDER, gotDER) {
		t.Fatal("independent encrypted private key changed public identity")
	}
}

func interopPKCS8BER(t *testing.T, raw []byte, encrypted bool) []byte {
	t.Helper()
	fields := pkcs12InteropFields(t, raw)
	at := 2
	if encrypted {
		at = 1
	}
	parts := make([][]byte, len(fields))
	for i, field := range fields {
		parts[i] = field.FullBytes
	}
	value := fields[at].Bytes
	middle := len(value) / 2
	chunks := bytes.Join([][]byte{der.Octets(value[:middle]), der.Octets(value[middle:])}, nil)
	parts[at] = append(append([]byte{0x24, 0x80}, chunks...), 0, 0)
	return append(append([]byte{0x30, 0x80}, bytes.Join(parts, nil)...), 0, 0)
}

func checkPKCS8BERCompatibility(t *testing.T, fixture *interopFixture, key crypto.Signer, raw, password []byte, passwordFile, dir string) {
	t.Helper()
	outer := interopPKCS8BER(t, raw, true)
	path := write(t, filepath.Join(dir, "wrapper.ber"), outer)
	command(t, fixture, true, nil, "openssl", "pkcs8", "-in", path, "-inform", "DER", "-passin", passwordFilePrefix+passwordFile, "-out", filepath.Join(dir, "restored.pem"))
	checkPKCS8CompatibilityKey(t, key, outer, password)
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	inner := interopPKCS8BER(t, plain, false)
	defer clear(inner)
	write(t, path, inner)
	command(t, fixture, true, nil, "openssl", "pkey", "-in", path, "-inform", "DER", "-noout")
	if got, err := keys.ParsePrivateWithOptions(t.Context(), inner, keys.PrivateParseOptions{AllowBER: true}, keys.Limits{}); got == nil || err != nil {
		t.Fatal(got, err)
	}
	if got, err := keys.ParsePrivate(inner, keys.Limits{}); got != nil || err == nil {
		t.Fatal("default imported BER", err)
	}
}

func checkPKCS8BinaryPasswordCompatibility(t *testing.T, fixture *interopFixture, key crypto.Signer) {
	t.Helper()
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	salt, iv := []byte("independent salt"), bytes.Repeat([]byte{0x42}, 16)
	for _, bits := range []int{128, 192, 256} {
		for _, password := range [][]byte{nil, {'p', 0, 'w', 0xff}} {
			derived, _ := command(t, fixture, true, nil, "openssl", "kdf", "-keylen", strconv.Itoa(bits/8), "-kdfopt", "digest:SHA256", "-kdfopt", "hexpass:"+hex.EncodeToString(password), "-kdfopt", "hexsalt:"+hex.EncodeToString(salt), "-kdfopt", "iter:1000", "-binary", "PBKDF2")
			ciphertext, _ := command(t, fixture, true, plain, "openssl", "enc", fmt.Sprintf("-aes-%d-cbc", bits), "-K", hex.EncodeToString(derived), "-iv", hex.EncodeToString(iv))
			clear(derived)
			prf := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}), []byte{5, 0})
			kdf := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}), der.Seq(der.Octets(salt), der.Int(1000), prf))
			cipherOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, map[int]int{128: 2, 192: 22, 256: 42}[bits]}
			algorithm := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}), der.Seq(kdf, der.Seq(der.OID(cipherOID), der.Octets(iv))))
			raw := der.Seq(algorithm, der.Octets(ciphertext))
			checkPKCS8CompatibilityKey(t, key, raw, password)
			inner := interopPKCS8BER(t, plain, false)
			derived = mustOpenSSLPBKDF2(t, fixture, password, salt, bits/8, 256)
			ciphertext, _ = command(t, fixture, true, inner, "openssl", "enc", fmt.Sprintf("-aes-%d-cbc", bits), "-K", hex.EncodeToString(derived), "-iv", hex.EncodeToString(iv))
			clear(derived)
			clear(inner)
			checkPKCS8CompatibilityKey(t, key, der.Seq(algorithm, der.Octets(ciphertext)), password)
			if len(password) == 0 {
				continue // Export deliberately requires a nonempty password.
			}
			for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
				exported, err := keys.MarshalEncryptedPrivate(t.Context(), key, password, keys.EncryptionOptions{KeyBits: bits, Hash: hash, Iterations: 1000}, keys.Limits{})
				if err != nil {
					t.Fatal(err)
				}
				checkPKCS8OpenSSLDecryption(t, fixture, exported, plain, password, bits, hash)
				clear(exported)
			}
		}
	}
}

func mustOpenSSLPBKDF2(t *testing.T, fixture *interopFixture, password, salt []byte, size, digest int) []byte {
	t.Helper()
	key, _ := command(t, fixture, true, nil, "openssl", "kdf", "-keylen", strconv.Itoa(size), "-kdfopt", "digest:SHA"+strconv.Itoa(digest), "-kdfopt", "hexpass:"+hex.EncodeToString(password), "-kdfopt", "hexsalt:"+hex.EncodeToString(salt), "-kdfopt", "iter:1000", "-binary", "PBKDF2")
	return key
}

func checkPKCS8OpenSSLDecryption(t *testing.T, fixture *interopFixture, raw, plain, password []byte, bits int, hash crypto.Hash) {
	t.Helper()
	outer := pkcs12InteropFields(t, raw)
	alg := pkcs12InteropFields(t, outer[0].FullBytes)
	params := pkcs12InteropFields(t, alg[1].FullBytes)
	kdf := pkcs12InteropFields(t, params[0].FullBytes)
	kdfParams := pkcs12InteropFields(t, kdf[1].FullBytes)
	cipher := pkcs12InteropFields(t, params[1].FullBytes)
	digest := map[crypto.Hash]int{crypto.SHA256: 256, crypto.SHA384: 384, crypto.SHA512: 512}[hash]
	derived := mustOpenSSLPBKDF2(t, fixture, password, kdfParams[0].Bytes, bits/8, digest)
	defer clear(derived)
	got, _ := command(t, fixture, true, outer[1].Bytes, "openssl", "enc", "-d", fmt.Sprintf("-aes-%d-cbc", bits), "-K", hex.EncodeToString(derived), "-iv", hex.EncodeToString(cipher[1].Bytes))
	defer clear(got)
	if !bytes.Equal(got, plain) {
		t.Fatal("OpenSSL decryption with exact binary password changed private bytes")
	}
}

func checkPKCS12SHA1Compatibility(t *testing.T, fixture *interopFixture, key testKey, dir string, password []byte, passwordFile string) {
	t.Helper()
	path := filepath.Join(dir, "classic-sha1.p12")
	command(t, fixture, true, nil, "openssl", "pkcs12", "-export", "-inkey", key.private, "-in", key.certificate, "-out", path, "-passout", passwordFilePrefix+passwordFile, "-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC", "-iter", "1000", "-macalg", "SHA1")
	raw := read(t, path)
	if got, err := keys.ParsePKCS12(t.Context(), raw, password, keys.Limits{}); got != nil || !errors.Is(err, keys.ErrPolicy) {
		t.Fatal("default imported classic SHA1", err)
	}
	options := keys.PKCS12ParseOptions{AllowLegacy: true}
	if got, err := keys.ParsePKCS12WithOptions(t.Context(), raw, password, options, keys.Limits{}); got == nil || err != nil || !bytes.Equal(got.Certificate.Raw, key.cert.Raw) {
		t.Fatal(got, err)
	}
	if got, err := keys.ParsePKCS12WithOptions(t.Context(), raw, []byte("wrong"), options, keys.Limits{}); got != nil || !errors.Is(err, keys.ErrDecrypt) {
		t.Fatal("wrong classic MAC password accepted", err)
	}
	outer := pkcs12InteropFields(t, raw)
	info := pkcs12InteropFields(t, outer[1].FullBytes)
	authenticated, err := der.Explicit(info[1], 0)
	if err != nil {
		t.Fatal(err)
	}
	checkPKCS12ClassicDefault(t, fixture, outer, authenticated.Bytes, key, dir, password, passwordFile)
	for _, size := range []int{1, 16, 20, 64} {
		salt := []byte("independent salt")
		derived := mustOpenSSLPBKDF2(t, fixture, password, salt, size, 256)
		mac, _ := command(t, fixture, true, authenticated.Bytes, "openssl", "mac", "-digest", "SHA256", "-macopt", "hexkey:"+hex.EncodeToString(derived), "-binary", "HMAC")
		clear(derived)
		prf := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}), []byte{5, 0})
		kdf := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}), der.Seq(der.Octets(salt), der.Int(1000), der.Int(size), prf))
		algorithm := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}), der.Seq(kdf, prf))
		macData := der.Seq(der.Seq(algorithm, der.Octets(mac)), der.Octets(nil), der.Int(1))
		candidate := der.Seq(outer[0].FullBytes, outer[1].FullBytes, macData)
		if got, err := keys.ParsePKCS12(t.Context(), candidate, password, keys.Limits{}); got != nil || !errors.Is(err, keys.ErrPolicy) {
			t.Fatal("default accepted non-default PBMAC1 key length", size, err)
		}
		options.AllowNonDefaultMACKeyLength = true
		got, err := keys.ParsePKCS12WithOptions(t.Context(), candidate, password, options, keys.Limits{})
		if size < 16 {
			if got != nil || !errors.Is(err, keys.ErrPolicy) {
				t.Fatal("weak MAC key bypassed compatibility policy", err)
			}
			continue
		}
		if got == nil || err != nil || !bytes.Equal(got.Certificate.Raw, key.cert.Raw) {
			t.Fatal(got, err)
		}
		write(t, path, candidate)
		if size == 16 {
			_, diagnostic := command(t, fixture, false, nil, "openssl", "pkcs12", "-in", path, "-passin", passwordFilePrefix+passwordFile, "-noout")
			if !bytes.Contains(diagnostic, []byte("Invalid Key length (16 is not in the range 20..64)")) {
				t.Fatalf("unexpected OpenSSL compatibility diagnostic: %s", diagnostic)
			}
			t.Log("P6_DIAGNOSTIC_PKCS12_MAC_KEY: OpenSSL PFX reader selects20..64; explicit16-byte native compatibility agrees with independent PBKDF2/HMAC primitives;20/64 reader controls pass")
		} else {
			command(t, fixture, true, nil, "openssl", "pkcs12", "-in", path, "-passin", passwordFilePrefix+passwordFile, "-noout")
		}
	}
}

// The published corpus remains external. Exact decoded hashes prevent a local
// replacement or generator from silently becoming the normative oracle.
func TestXMLSecPKCS12PublishedVectors(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	path := os.Getenv("RFC9879_FILE")
	if path == "" {
		if os.Getenv("XMLSEC_REQUIRE_P6_PROOFS") == "1" {
			t.Fatal("RFC9879_FILE is required for the published PKCS12 proof")
		}
		t.Skip("provide the external primary RFC9879 text through RFC9879_FILE")
	}
	text, err := os.ReadFile(path)
	if err != nil || len(text) > 1<<20 {
		t.Fatal("unavailable or oversized primary RFC9879 fixture", err)
	}
	hashes := []string{
		"a5aa952ca788f945834c9edb40f0b94b2d845b86d0c80856adc9578d05e9de43",
		"da385cc443abb3bb1872fda6c02a74c1f619c2e6f6abb9dce7793d56388e61d0",
		"c3e2845fcb7f78ea188286448669875474009dd29d299ab234bf6f14f1065a53",
		"cc6c9709db9a96e5e04dfd740d5a739decb4a9b6605694cda1c4958179d58b0f",
		"b03af0abd2075652ed4f17fb014a1b2f7d4f61f3071931dba45e43b13c9a7ffd",
		"2c95ab6c2dbd08d47c096a2dea1cbc59cb2effed1baa8b1059a8585d175e3d83",
	}
	dir := t.TempDir()
	passwordFile := write(t, filepath.Join(dir, "password"), []byte("1234\n"))
	for at, digest := range hashes {
		section := "A." + strconv.Itoa(at+1)
		t.Run(section, func(t *testing.T) {
			raw := publishedPKCS12Vector(t, text, section, digest)
			input := write(t, filepath.Join(dir, "published.p12"), raw)
			valid := at < 3
			command(t, fixture, valid, nil, "openssl", "pkcs12", "-in", input, "-passin", passwordFilePrefix+passwordFile, "-noout")
			got, err := keys.ParsePKCS12(t.Context(), raw, []byte("1234"), keys.Limits{})
			if valid {
				if err != nil || got == nil {
					t.Fatal("published valid PFX rejected", err)
				}
				if got, err := keys.ParsePKCS12(t.Context(), raw, []byte("wrong"), keys.Limits{}); got != nil || !errors.Is(err, keys.ErrDecrypt) {
					t.Fatal("wrong password accepted", err)
				}
			} else {
				want := keys.ErrDecrypt
				if at == 5 {
					want = keys.ErrFormat
				}
				if got != nil || !errors.Is(err, want) {
					t.Fatal("published invalid PFX not rejected for its stated cause", err)
				}
			}
		})
	}
	t.Log("P6_PROOF_RFC9879_APPENDIX_A: all six exact publisher vectors and ready OpenSSL agree; wrong PRF iteration/salt fail integrity, absent keyLength fails syntax")
}

func publishedPKCS12Vector(t *testing.T, text []byte, section, digest string) []byte {
	t.Helper()
	at := bytes.LastIndex(text, []byte(section+"."))
	if at < 0 {
		t.Fatal("missing published section", section)
	}
	var encoded strings.Builder
	for _, line := range bytes.Split(text[at:], []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) >= 20 && bytes.IndexFunc(line, func(r rune) bool {
			return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=')
		}) < 0 {
			encoded.Write(line)
		} else if encoded.Len() > 0 {
			break
		}
	}
	raw, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != digest {
		t.Fatal("published vector digest mismatch", section, err)
	}
	return raw
}

func checkPKCS12ClassicDefault(t *testing.T, fixture *interopFixture, outer []asn1.RawValue, authenticated []byte, key testKey, dir string, password []byte, passwordFile string) {
	t.Helper()
	salt := []byte("independent salt")
	bmp := make([]byte, 0, 2*len(password)+2)
	for _, r := range string(password) {
		bmp = append(bmp, byte(r>>8), byte(r))
	}
	bmp = append(bmp, 0, 0)
	derived, _ := command(t, fixture, true, nil, "openssl", "kdf", "-keylen", "20", "-kdfopt", "digest:SHA1", "-kdfopt", "hexpass:"+hex.EncodeToString(bmp), "-kdfopt", "hexsalt:"+hex.EncodeToString(salt), "-kdfopt", "iter:1", "-kdfopt", "id:3", "-binary", "PKCS12KDF")
	clear(bmp)
	mac, _ := command(t, fixture, true, authenticated, "openssl", "mac", "-digest", "SHA1", "-macopt", "hexkey:"+hex.EncodeToString(derived), "-binary", "HMAC")
	clear(derived)
	digest := der.Seq(der.OID(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}), []byte{5, 0})
	macData := der.Seq(der.Seq(digest, der.Octets(mac)), der.Octets(salt))
	raw := der.Seq(outer[0].FullBytes, outer[1].FullBytes, macData)
	options := keys.PKCS12ParseOptions{AllowLegacy: true}
	if got, err := keys.ParsePKCS12WithOptions(t.Context(), raw, password, options, keys.Limits{}); got != nil || !errors.Is(err, keys.ErrLimit) {
		t.Fatal("iteration default bypassed the minimum policy", err)
	}
	if got, err := keys.ParsePKCS12WithOptions(t.Context(), raw, password, options, keys.Limits{MinIterations: 1}); got == nil || err != nil || !bytes.Equal(got.Certificate.Raw, key.cert.Raw) {
		t.Fatal("classic omitted iteration default differs from OpenSSL", err)
	}
	path := write(t, filepath.Join(dir, "classic-default.p12"), raw)
	command(t, fixture, true, nil, "openssl", "pkcs12", "-in", path, "-passin", passwordFilePrefix+passwordFile, "-noout")
}
