//go:build interop

package interop_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

const pssURI = "http://www.w3.org/2007/05/xmldsig-more#"

const (
	namePss    = "pss"
	nameSecret = "Secret"
)

func TestParameters(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	key := generateKey(t, dir, nameRsaSha256)

	priv, err := x509.MarshalPKCS8PrivateKey(key.signer)
	if err != nil {
		t.Fatal(err)
	}

	spki, err := x509.MarshalPKIXPublicKey(key.signer.Public())
	if err != nil {
		t.Fatal(err)
	}

	secret := bytes.Repeat([]byte{0xa7}, 64)

	var configs []signatureParameterCase

	for _, h := range []int{256, 384, 512} {
		for _, mgf := range []int{256, 384, 512} {
			for _, salt := range []int{0, 20, h / 8} {
				configs = append(configs, signatureParameterCase{kind: namePss, hash: h, mgf: mgf, salt: salt})
			}
		}
	}

	configs = append(configs, signatureParameterCase{kind: namePss, hash: 256, mgf: 256, salt: 32, defaultParams: true})

	for _, h := range []int{256, 384, 512} {
		for _, bits := range []int{0, h / 2, h - 8} {
			configs = append(configs, signatureParameterCase{kind: "hmac", hash: h, bits: bits})
		}
	}

	providers := 0

	for i, cfg := range configs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			testParametersCase(t, cfg, priv, spki, secret, fixture, dir, key, &providers)
		})
	}

	t.Logf("%d parameterized exchanges; %d precomputed provider checks; one correctly signed bad-second control per exchange", len(configs), providers)
	// Independently produced wrong-salt and parser-negative fixtures remain in the
	// ordinary tests/integration/parameters suite; verify them on every portable run.
	command(t, fixture, true, nil, "go", "test", "-count=1", "./tests/integration/xmldsig")
}

func base64String(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func hashBytes(bits int, b []byte) []byte {
	switch bits {
	case 256:
		h := sha256.Sum256(b)
		return h[:]
	case 384:
		h := sha512.Sum384(b)
		return h[:]
	case 512:
		h := sha512.Sum512(b)
		return h[:]
	}

	panic("hash")
}

func digestURI(bits int) string {
	switch bits {
	case 256:
		return digests()[0]
	case 384:
		return digests()[1]
	case 512:
		return digests()[2]
	}

	panic("digest")
}

func testParametersCase(t *testing.T, cfg signatureParameterCase, priv, spki, secret []byte, fixture *interopFixture, dir string, key testKey, providers *int) {
	method := pssURI + "rsa-pss"
	if cfg.kind == "hmac" {
		method = more + fmt.Sprintf("hmac-sha%d", cfg.hash)
	}

	task := map[string]any{nameMode: nameSign, nameMethod: method, "Hash": cfg.hash, "MGF": cfg.hash, "Salt": cfg.salt, "Bits": cfg.bits, "DefaultParams": cfg.defaultParams, "Private": priv, "SPKI": spki, nameSecret: secret}
	if cfg.kind == namePss && cfg.salt == 0 {
		task["Salt"] = cfg.hash / 8
	}

	raw := probeData(t, fixture, "parametersprobe", task)
	d := xmlDoc(t, raw)
	sig := tree.Root(d)
	si := one(t, sig, ds, "SignedInfo")

	sv := one(t, sig, ds, "SignatureValue")
	if cfg.kind == namePss && cfg.salt == 0 {
		setText(one(t, sig, pssURI, "SaltLength"), "0")
	}

	if cfg.kind == namePss && cfg.mgf != cfg.hash {
		params := one(t, sig, pssURI, "MaskGenerationFunction")

		dm := one(t, params, ds, "DigestMethod")
		for i := range dm.Attrs {
			if dm.Attrs[i].Name.Local == "Algorithm" {
				dm.Attrs[i].Value = digestURI(cfg.mgf)
			}
		}
	}

	message := externalCanonical(t, fixture, d, si, exc)
	messagePath := write(t, filepath.Join(dir, "message"), message)
	valuePath := filepath.Join(dir, "signature.bin")
	exchange := parameterExchange{cfg: cfg, fixture: fixture, key: key, secret: secret, messagePath: messagePath, valuePath: valuePath}

	if cfg.kind == namePss && (cfg.mgf != cfg.hash || cfg.salt == 0) {
		value := exchange.sign(t, message)

		sv.Children = nil
		for _, dv := range nodes(si, ds, "DigestValue") {
			dv.Children = nil
		}

		task[nameMode] = "provider-sign"
		task[nameInput] = xmlBytes(t, d)
		task["MGF"] = cfg.mgf
		task["Salt"] = cfg.salt
		task["Value"] = value
		task["Digest"] = hashBytes(cfg.hash, message)
		result := probe(t, fixture, "parametersprobe", task, true)
		assertJSON(t, result, "provider_calls", 1)

		var produced []byte
		decode(t, result["data"], &produced)
		d = xmlDoc(t, produced)
		sig = tree.Root(d)
		sv = one(t, sig, ds, "SignatureValue")
		(*providers)++
	}

	exchange.verify(t, decode64(t, text(sv)), message)
	// OpenSSL supplies a fresh signature over independently canonicalized input.
	setText(sv, base64String(exchange.sign(t, message)))

	reverse := xmlBytes(t, d)
	verifyTask := map[string]any{nameMode: nameVerify, nameMethod: method, "SPKI": spki, nameSecret: secret, nameInput: reverse}
	result := probe(t, fixture, "parametersprobe", verifyTask, true)
	assertJSON(t, result, nameValid, true)

	if cfg.kind == namePss && cfg.hash != 256 && cfg.mgf == cfg.hash && cfg.salt == cfg.hash/8 {
		empty := xmlDoc(t, reverse)
		mgf := one(t, tree.Root(empty), pssURI, "MaskGenerationFunction")
		mgf.Attrs, mgf.Children = nil, nil
		emptyMessage := externalCanonical(t, fixture, empty, one(t, tree.Root(empty), ds, "SignedInfo"), exc)
		setText(one(t, tree.Root(empty), ds, "SignatureValue"), base64String(exchange.sign(t, emptyMessage)))
		verifyTask[nameInput] = xmlBytes(t, empty)
		result = probe(t, fixture, "parametersprobe", verifyTask, true)
		assertJSON(t, result, nameValid, true)
	}

	if cfg.kind == namePss && !cfg.defaultParams {
		wrong := xmlDoc(t, reverse)
		wrongSig := tree.Root(wrong)
		setText(one(t, wrongSig, pssURI, "SaltLength"), strconv.Itoa(cfg.salt+1))
		changed := externalCanonical(t, fixture, wrong, one(t, wrongSig, ds, "SignedInfo"), exc)
		setText(one(t, wrongSig, ds, "SignatureValue"), base64String(exchange.sign(t, changed)))
		verifyTask[nameInput] = xmlBytes(t, wrong)
		result = probe(t, fixture, "parametersprobe", verifyTask, false)

		var stage struct {
			FailureStage string `json:"failure_stage"`
		}
		decode(t, result["report"], &stage)

		if stage.FailureStage != "signature-value" {
			t.Fatalf("wrong-salt control: %s", result["report"])
		}
	}
	// Correctly signed bad second digest must fail only at Reference validation.
	si = one(t, sig, ds, "SignedInfo")
	refs := nodes(si, ds, "Reference")
	setText(one(t, refs[1], ds, "DigestValue"), base64String(make([]byte, 32)))
	message = externalCanonical(t, fixture, d, si, exc)
	setText(sv, base64String(exchange.sign(t, message)))

	verifyTask[nameInput] = xmlBytes(t, d)
	result = probe(t, fixture, "parametersprobe", verifyTask, false)

	var r verification
	decode(t, result["report"], &r)

	if r.SignatureValue != nameValid || len(r.References) != 2 || r.References[1].Status != "invalid" {
		t.Fatalf("wrong failure stage: %s", result["report"])
	}
}

func TestXMLSecHMAC(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "xmlsec")
	dir := t.TempDir()
	secret := randomBytes(t, 64)
	key := write(t, filepath.Join(dir, "hmac.bin"), secret)

	for _, bits := range []int{256, 384, 512} {
		for _, output := range []int{0, bits / 2} {
			method := more + fmt.Sprintf("hmac-sha%d", bits)
			ours := write(t, filepath.Join(dir, "ours.xml"), probeData(t, fixture, "parametersprobe", map[string]any{nameMode: nameSign, nameMethod: method, nameSecret: secret, "Bits": output}))
			theirs := filepath.Join(dir, "theirs.xml")

			native(t, fixture, true, nameVerify, "--hmackey", key, flagEnabledReferenceUris, "same-doc", ours)
			native(t, fixture, true, nameSign, "--hmackey", key, flagEnabledReferenceUris, "same-doc", "--output", theirs, ours)
			r := probe(t, fixture, "parametersprobe", map[string]any{nameMode: nameVerify, nameMethod: method, nameSecret: secret, nameInput: read(t, theirs)}, true)
			assertJSON(t, r, nameValid, true)
		}
	}
}

// verifySignatureValue uses external canonicalization and OpenSSL primitives.
// It deliberately does not use the toolkit's XMLDSig verification functions.
func verifySignatureValue(t *testing.T, fixture *interopFixture, d *tree.Document, sig *tree.Node, public string) {
	t.Helper()
	si := one(t, sig, ds, "SignedInfo")
	cm := one(t, si, ds, "CanonicalizationMethod")
	method := attr(one(t, si, ds, "SignatureMethod"), "Algorithm")
	message := externalCanonical(t, fixture, d, si, attr(cm, "Algorithm"))
	value := decode64(t, text(one(t, sig, ds, "SignatureValue")))
	dir := t.TempDir()
	messagePath := write(t, filepath.Join(dir, "message"), message)
	hash := nameSha256

	for _, bits := range []string{"384", "512"} {
		if strings.Contains(method, bits) {
			hash = "sha" + bits
		}
	}

	if strings.Contains(method, "ecdsa") {
		width := len(value) / 2
		if width == 0 || len(value)%2 != 0 {
			t.Fatal("ECDSA width")
		}

		der, err := asn1.Marshal(struct {
			R *big.Int
			S *big.Int
		}{new(big.Int).SetBytes(value[:width]), new(big.Int).SetBytes(value[width:])})
		if err != nil {
			t.Fatal(err)
		}

		value = der
	}

	signature := write(t, filepath.Join(dir, "signature"), value)
	if strings.Contains(method, "eddsa-ed25519") {
		command(t, fixture, true, nil, "openssl", "pkeyutl", flagVerify, "-pubin", flagInkey, public, "-rawin", flagIn, messagePath, "-sigfile", signature)
		return
	}

	args := []string{"dgst", "-" + hash, flagVerify, public, "-signature", signature}
	if strings.Contains(method, "MGF1") {
		args = append(args, "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:digest")
	}

	command(t, fixture, true, nil, "openssl", append(args, messagePath)...)
}

func ecdsaDER(t *testing.T, value []byte) []byte {
	t.Helper()

	if len(value)%2 != 0 || len(value) == 0 {
		t.Fatal("ECDSA raw width")
	}

	n := len(value) / 2

	der, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{new(big.Int).SetBytes(value[:n]), new(big.Int).SetBytes(value[n:])})
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func ecdsaRaw(t *testing.T, value []byte, width int) []byte {
	t.Helper()

	var pair struct {
		R *big.Int
		S *big.Int
	}

	rest, err := asn1.Unmarshal(value, &pair)
	if err != nil || len(rest) != 0 || pair.R == nil || pair.S == nil {
		t.Fatal("ECDSA DER", err)
	}

	out := make([]byte, 2*width)
	pair.R.FillBytes(out[:width])
	pair.S.FillBytes(out[width:])

	return out
}

type signatureParameterCase struct {
	kind          string
	hash          int
	mgf           int
	salt          int
	bits          int
	defaultParams bool
}

type parameterExchange struct {
	cfg         signatureParameterCase
	fixture     *interopFixture
	key         testKey
	secret      []byte
	messagePath string
	valuePath   string
}

func (x parameterExchange) sign(t *testing.T, message []byte) []byte {
	t.Helper()

	write(t, x.messagePath, message)

	if x.cfg.kind == namePss {
		command(t, x.fixture, true, nil, "openssl", "dgst", fmt.Sprintf("-sha%d", x.cfg.hash), "-sign", x.key.private, "-sigopt", "rsa_padding_mode:pss", "-sigopt", fmt.Sprintf("rsa_pss_saltlen:%d", x.cfg.salt), "-sigopt", fmt.Sprintf("rsa_mgf1_md:sha%d", x.cfg.mgf), flagOut, x.valuePath, x.messagePath)
		return read(t, x.valuePath)
	}

	value, _ := command(t, x.fixture, true, nil, "openssl", "dgst", fmt.Sprintf("-sha%d", x.cfg.hash), "-mac", "HMAC", "-macopt", "hexkey:"+hex.EncodeToString(x.secret), flagBinary, x.messagePath)

	n := x.cfg.bits / 8
	if n == 0 {
		n = x.cfg.hash / 8
	}

	return value[:n]
}

func (x parameterExchange) verify(t *testing.T, value, message []byte) {
	t.Helper()

	if x.cfg.kind == namePss {
		write(t, x.valuePath, value)
		command(t, x.fixture, true, nil, "openssl", "dgst", fmt.Sprintf("-sha%d", x.cfg.hash), flagVerify, x.key.public, "-signature", x.valuePath, "-sigopt", "rsa_padding_mode:pss", "-sigopt", fmt.Sprintf("rsa_pss_saltlen:%d", x.cfg.salt), "-sigopt", fmt.Sprintf("rsa_mgf1_md:sha%d", x.cfg.mgf), x.messagePath)
	} else if !bytes.Equal(value, x.sign(t, message)) {
		t.Fatal("OpenSSL HMAC differs")
	}
}
