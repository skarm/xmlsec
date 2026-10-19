//go:build interop

package interop_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/tree"
)

const (
	xadesNS   = "http://uri.etsi.org/01903/v1.3.2#"
	archiveNS = "http://uri.etsi.org/01903/v1.4.1#"
)

const (
	flagData = "-data"
	nameCms  = "cms"
)

func TestEvidenceExchange(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	at := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	epoch := strconv.FormatInt(at.Unix(), 10)
	p := binary(t, fixture, "evidenceprobe")
	goProbe := func(mode string, args ...string) {
		command(t, fixture, true, nil, p, append([]string{"-mode", mode, "-at", at.Format(time.RFC3339)}, args...)...)
	}
	rootKey := generateKey(t, dir, nameEcdsaSha384)
	rootTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "temporary evidence root"}, NotBefore: at.Add(-24 * time.Hour), NotAfter: at.Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	rootCert, rootDER, rootPEM := certificateFiles(t, dir, nameRoot, rootTpl, rootTpl, rootKey.signer, rootKey.signer)

	crlRaw, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: at.Add(-time.Hour), NextUpdate: at.Add(time.Hour)}, rootCert, rootKey.signer)
	if err != nil {
		t.Fatal(err)
	}

	crl := write(t, filepath.Join(dir, "crl.der"), crlRaw)

	data := write(t, filepath.Join(dir, nameContent), []byte("CMS and timestamp payload\x00\r\n"))
	for _, name := range []string{nameRsaSha256, nameEcdsaSha256} {
		key := generateKey(t, dir, name)
		issue := func(label string, serial int64, eku x509.ExtKeyUsage) (*x509.Certificate, string, string) {
			tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: label}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
			if eku == x509.ExtKeyUsageTimeStamping {
				tpl.ExtraExtensions = []pkix.Extension{{Id: []int{2, 5, 29, 37}, Critical: true, Value: []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08}}}
			}

			return certificateFiles(t, dir, label, tpl, rootCert, key.signer, rootKey.signer)
		}
		_, signerDER, signerPEM := issue("signer", 2, x509.ExtKeyUsageCodeSigning)

		for _, hash := range []int{256, 384, 512} {
			pssValues := []bool{false}
			if name == nameRsaSha256 {
				pssValues = append(pssValues, true)
			}

			for _, pss := range pssValues {
				for _, detached := range []bool{false, true} {
					t.Run(fmt.Sprintf("cms/%s/%d/pss=%v/detached=%v", name, hash, pss, detached), func(t *testing.T) {
						testEvidenceExchangeCase(t, &dir, &key, &signerDER, &data, &hash, &pss, &detached, &goProbe, &fixture, &signerPEM)
					})
				}
			}
		}

		_, leafDER, leafPEM := issue("leaf", 3, x509.ExtKeyUsageCodeSigning)
		_, responderDER, _ := issue("responder", 4, x509.ExtKeyUsageOCSPSigning)
		request, response := filepath.Join(dir, "request.ocsp"), filepath.Join(dir, "response.ocsp")
		goProbe("ocsp-request", flagCert, leafDER, "-issuer", rootDER, "-nonce", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", flagOut, request)

		args := []string{"-request", request, flagCert, responderDER, "-issuer", rootDER, flagData, leafDER, flagKey, key.private, flagOut, response}
		if name == nameRsaSha256 {
			args = append(args, "-pss")
		}

		goProbe("ocsp-issue", args...)
		command(t, fixture, true, nil, "openssl", "ocsp", "-respin", response, "-issuer", rootPEM, "-sha256", flagCert, leafPEM, "-CAfile", rootPEM, "-attime", epoch, "-no_nonce")

		_, tsaDER, tsaPEM := issue("tsa", 5, x509.ExtKeyUsageTimeStamping)
		serial := filepath.Join(dir, "serial")
		config := filepath.Join(dir, "tsa.cnf")

		configTSA := func(hash int) {
			write(t, serial, []byte("01\n"))
			write(t, config, []byte(fmt.Sprintf("[tsa]\ndefault_tsa=tsa_config\n[tsa_config]\ndir=%s\nserial=%s\ncrypto_device=builtin\nsigner_cert=%s\ncerts=%s\nsigner_key=%s\nsigner_digest=sha%d\ndefault_policy=1.2.3.4.1\nother_policies=1.2.3.4.2\ndigests=sha256,sha384,sha512\naccuracy=secs:1,millisecs:2,microsecs:3\nordering=yes\ntsa_name=yes\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n", dir, serial, tsaPEM, rootPEM, key.private, hash)))
		}
		for _, hash := range []int{256, 384, 512} {
			query, reply, ours := filepath.Join(dir, "query.tsq"), filepath.Join(dir, "reply.tsr"), filepath.Join(dir, "go.tsr")
			goProbe("ts-request", flagData, data, "-hash", strconv.Itoa(hash), flagOut, query)
			configTSA(hash)
			command(t, fixture, true, nil, "openssl", "ts", "-reply", "-config", config, "-queryfile", query, flagOut, reply)
			goProbe("ts-verify", flagIn, reply, "-request", query, flagCert, tsaDER, "-root", rootDER, "-crl", crl)
			goProbe("ts-issue", "-request", query, flagCert, tsaDER, "-root", rootDER, flagKey, key.private, "-hash", strconv.Itoa(hash), flagOut, ours)
			command(t, fixture, true, nil, "openssl", "ts", flagVerify, flagIn, ours, "-queryfile", query, "-CAfile", rootPEM, "-attime", epoch)
		}

		invoice := write(t, filepath.Join(dir, "invoice.xml"), []byte(`<Invoice xmlns="urn:test:invoice" ID="invoice"><Amount>123</Amount></Invoice>`))
		basic := filepath.Join(dir, "basic.xml")
		goProbe("xades-basic", flagData, invoice, flagKey, key.private, flagCert, signerDER, flagOut, basic)
		d := xmlDoc(t, read(t, basic))
		sig := one(t, tree.Root(d), ds, "Signature")
		verifySignatureValue(t, fixture, d, sig, key.public)

		if !checkReferences(t, fixture, d, sig) {
			t.Fatal("XAdES Reference mismatch")
		}

		value := externalCanonical(t, fixture, d, one(t, sig, ds, "SignatureValue"), exc)
		valuePath := write(t, filepath.Join(dir, "signature-value"), value)
		goValue := filepath.Join(dir, "go-value")
		goProbe("xades-value", flagIn, basic, flagOut, goValue)

		if !bytes.Equal(read(t, goValue), value) {
			t.Fatal("XAdES SignatureValue canonicalization")
		}

		query, reply, timed := filepath.Join(dir, "xades.tsq"), filepath.Join(dir, "xades.tsr"), filepath.Join(dir, "timed.xml")
		goProbe("ts-request", flagData, valuePath, flagOut, query)
		configTSA(256)
		command(t, fixture, true, nil, "openssl", "ts", "-reply", "-config", config, "-queryfile", query, flagOut, reply)
		goProbe("xades-attach", flagIn, basic, flagData, reply, flagCert, signerDER, "-root", rootDER, "-crl", crl, flagOut, timed)
		goProbe("xades-verify", flagIn, timed, flagCert, signerDER, "-root", rootDER, "-crl", crl)

		lt := filepath.Join(dir, "lt.xml")
		goProbe("xades-embed", flagIn, timed, flagCert, signerDER, "-root", rootDER, "-crl", crl, flagOut, lt)

		for _, algorithm := range []string{exc, c10} {
			archive := filepath.Join(dir, "archive.xml")
			goProbe("archive-add", flagIn, lt, flagCert, signerDER, "-issuer", tsaDER, flagKey, key.private, "-root", rootDER, "-crl", crl, "-alg", algorithm, flagOut, archive)
			d := xmlDoc(t, read(t, archive))
			stamp := one(t, tree.Root(d), archiveNS, "ArchiveTimeStamp")
			token := write(t, filepath.Join(dir, "archive-token.cms"), decode64(t, text(one(t, stamp, xadesNS, "EncapsulatedTimeStamp"))))
			input := write(t, filepath.Join(dir, "archive-input"), independentArchiveInput(t, fixture, d, stamp))
			command(t, fixture, true, nil, "openssl", "ts", flagVerify, "-token_in", flagIn, token, flagData, input, "-CAfile", rootPEM, "-attime", epoch)
			// OpenSSL produces the reverse timestamp from an independently recomputed
			// archive input; Go only embeds and verifies the received CMS token.
			d = xmlDoc(t, read(t, lt))
			write(t, input, archiveInput(t, fixture, d, nil, algorithm))
			goProbe("ts-request", flagData, input, flagOut, query)
			configTSA(256)
			command(t, fixture, true, nil, "openssl", "ts", "-reply", "-config", config, "-queryfile", query, flagOut, reply)
			command(t, fixture, true, nil, "openssl", "ts", "-reply", flagIn, reply, "-token_out", flagOut, token)
			goProbe("archive-attach", flagIn, lt, flagCert, signerDER, "-token", token, "-root", rootDER, "-crl", crl, "-alg", algorithm, flagOut, archive)
			goProbe("archive-verify", flagIn, archive, flagCert, signerDER, "-root", rootDER, "-crl", crl)
		}
	}

	t.Log("18 CMS, 6 RFC3161, 2 XAdES-T, 4 archive exchanges each direction; 2 Go OCSP responses verified by OpenSSL")
}

func certificateFiles(t *testing.T, dir, name string, tpl, parent *x509.Certificate, signer, issuer crypto.Signer) (*x509.Certificate, string, string) {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, signer.Public(), issuer)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert, write(t, filepath.Join(dir, name+".der"), der), write(t, filepath.Join(dir, name+".pem"), pem.EncodeToMemory(&pem.Block{Type: nameCERTIFICATE, Bytes: der}))
}

func testEvidenceExchangeCase(t *testing.T, dir *string, key *testKey, signerDER *string, data *string, hash *int, pss *bool, detached *bool, goProbe *func(mode string, args ...string), fixture **interopFixture, signerPEM *string) {
	ours, theirs, verified := filepath.Join((*dir), "go.cms"), filepath.Join((*dir), "ref.cms"), filepath.Join((*dir), "verified")

	args := []string{flagKey, key.private, flagCert, (*signerDER), flagData, (*data), flagOut, ours, "-hash", strconv.Itoa((*hash))}
	if *pss {
		args = append(args, "-pss")
	}

	if *detached {
		args = append(args, "-detached")
	}

	(*goProbe)("cms-sign", args...)

	args = []string{nameCms, flagVerify, flagBinary, "-inform", nameDER, flagIn, ours, "-noverify", flagOut, verified}
	if *detached {
		args = append(args, "-content", (*data))
	}

	command(t, (*fixture), true, nil, "openssl", args...)

	if !bytes.Equal(read(t, verified), read(t, (*data))) {
		t.Fatal("CMS content changed")
	}

	args = []string{nameCms, "-sign", flagBinary, flagIn, (*data), "-signer", (*signerPEM), flagInkey, key.private, "-md", fmt.Sprintf("sha%d", (*hash)), "-nosmimecap", "-cades", "-outform", nameDER, flagOut, theirs}
	if !(*detached) {
		args = append(args, "-nodetach")
	}

	if *pss {
		args = append(args, "-keyopt", "rsa_padding_mode:pss", "-keyopt", "rsa_pss_saltlen:digest")
	}

	command(t, (*fixture), true, nil, "openssl", args...)

	args = []string{flagIn, theirs, flagCert, (*signerDER), flagData, (*data), flagOut, verified}
	if *detached {
		args = append(args, "-detached")
	}

	(*goProbe)("cms-verify", args...)

	if !bytes.Equal(read(t, verified), read(t, (*data))) {
		t.Fatal("CMS content changed")
	}
}

func TestEvidenceFixtures(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")

	base := filepath.Join(fixture.root, "testdata/evidence")
	dir := t.TempDir()

	var cases []struct {
		Group, Name, At, Status string
		Detached                bool
	}
	decode(t, read(t, filepath.Join(base, "manifest.json")), &cases)

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) { testEvidenceFixturesCase(t, &base, &tc, &dir, &fixture) })
	}

	command(t, fixture, true, nil, "go", "test", "-count=1", "./tests/integration/evidence")
}

func testEvidenceFixturesCase(t *testing.T, base *string, tc *struct {
	Group    string
	Name     string
	At       string
	Status   string
	Detached bool
}, dir *string, fixture **interopFixture,
) {
	fixturePath := filepath.Join((*base), tc.Name)
	path := func(name string) string { return filepath.Join(fixturePath, name) }

	at, err := time.Parse(time.RFC3339, tc.At)
	if err != nil {
		t.Fatal(err)
	}

	epoch := strconv.FormatInt(at.Unix(), 10)
	asPEM := func(source, name string) string {
		return write(t, filepath.Join((*dir), name+".pem"), pem.EncodeToMemory(&pem.Block{Type: nameCERTIFICATE, Bytes: read(t, source)}))
	}

	switch tc.Group {
	case nameCms:
		output := filepath.Join((*dir), "cms-content")

		args := []string{nameCms, flagVerify, flagBinary, "-inform", nameDER, flagIn, path("signature.der"), "-noverify", flagOut, output}
		if tc.Detached {
			args = append(args, "-content", path("content.bin"))
		}

		command(t, (*fixture), true, nil, "openssl", args...)

		if !bytes.Equal(read(t, output), read(t, path("content.bin"))) {
			t.Fatal("fixture CMS content")
		}
	case "ocsp":
		issuer := asPEM(path("issuer.der"), "issuer")
		leaf := asPEM(path("leaf.der"), "leaf")

		hash := "-sha256"
		if bytes.Contains([]byte(tc.Name), []byte("-sha1-")) {
			hash = "-sha1"
		}

		out, stderr := command(t, (*fixture), true, nil, "openssl", "ocsp", "-respin", path("response.der"), "-issuer", issuer, hash, flagCert, leaf, "-CAfile", issuer, "-attime", epoch, "-no_nonce")
		if !bytes.Contains(stderr, []byte("Response verify OK")) {
			t.Fatalf("OCSP signature was not verified: %s", stderr)
		}

		statusFound := bytes.Contains(out, []byte(": "+tc.Status))
		for _, line := range bytes.Split(out, []byte{'\n'}) {
			if string(bytes.TrimSpace(line)) == tc.Status {
				statusFound = true
			}
		}

		if !statusFound {
			t.Fatalf("OCSP status mismatch: %s", out)
		}
		// OpenSSL's CLI checks response freshness against the real clock,
		// even with -attime. Only its signature/status checks are compared;
		// historical freshness is asserted by tests/integration/evidence at tc.At.
	case "timestamp":
		rootPEM := asPEM(path("root.der"), nameRoot)
		command(t, (*fixture), true, nil, "openssl", "ts", flagVerify, flagIn, path("response.der"), "-queryfile", path("request.der"), "-CAfile", rootPEM, "-attime", epoch)
	case "xades", "archive":
		d := xmlDoc(t, read(t, path("signed.xml")))
		sig := one(t, tree.Root(d), ds, "Signature")

		cert, err := x509.ParseCertificate(read(t, path("signer.der")))
		if err != nil {
			t.Fatal(err)
		}

		public, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		publicPath := write(t, filepath.Join((*dir), "signer-public.pem"), pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: public}))
		verifySignatureValue(t, (*fixture), d, sig, publicPath)

		if !checkReferences(t, (*fixture), d, sig) {
			t.Fatal("fixture XML Reference mismatch")
		}

		rootPEM := asPEM(path("root.der"), nameRoot)

		for _, stamp := range nodes(sig, xadesNS, "SignatureTimeStamp") {
			value := externalCanonical(t, (*fixture), d, one(t, sig, ds, "SignatureValue"), exc)
			token := write(t, filepath.Join((*dir), "token.cms"), decode64(t, text(one(t, stamp, xadesNS, "EncapsulatedTimeStamp"))))
			input := write(t, filepath.Join((*dir), "timestamp-input"), value)
			command(t, (*fixture), true, nil, "openssl", "ts", flagVerify, "-token_in", flagIn, token, flagData, input, "-CAfile", rootPEM, "-attime", epoch)
		}

		for _, stamp := range nodes(sig, archiveNS, "ArchiveTimeStamp") {
			token := write(t, filepath.Join((*dir), "token.cms"), decode64(t, text(one(t, stamp, xadesNS, "EncapsulatedTimeStamp"))))
			input := write(t, filepath.Join((*dir), "archive-input"), independentArchiveInput(t, (*fixture), d, stamp))
			command(t, (*fixture), true, nil, "openssl", "ts", flagVerify, "-token_in", flagIn, token, flagData, input, "-CAfile", rootPEM, "-attime", epoch)
		}
	default:
		t.Fatal("unknown evidence group", tc.Group)
	}
}

func independentArchiveInput(t *testing.T, fixture *interopFixture, d *tree.Document, stamp *tree.Node) []byte {
	t.Helper()
	return archiveInput(t, fixture, d, stamp, attr(one(t, stamp, ds, "CanonicalizationMethod"), "Algorithm"))
}

func archiveInput(t *testing.T, fixture *interopFixture, d *tree.Document, stamp *tree.Node, algorithm string) []byte {
	t.Helper()
	sig := one(t, tree.Root(d), ds, "Signature")
	si := one(t, sig, ds, "SignedInfo")

	var out []byte

	for _, ref := range si.Children {
		if ref.Name.Space == ds && ref.Name.Local == "Reference" {
			out = append(out, referenceInput(t, fixture, d, sig, ref, nil)...)
		}
	}

	out = append(out, externalCanonical(t, fixture, d, si, attr(one(t, si, ds, "CanonicalizationMethod"), "Algorithm"))...)
	for _, name := range []string{"SignatureValue", "KeyInfo"} {
		out = append(out, externalCanonical(t, fixture, d, one(t, sig, ds, name), algorithm)...)
	}

	unsigned := one(t, sig, xadesNS, "UnsignedSignatureProperties")
	for _, child := range unsigned.Children {
		if child == stamp {
			break
		}

		if child.Kind == tree.ElementNode {
			out = append(out, externalCanonical(t, fixture, d, child, algorithm)...)
		}
	}

	return out
}
