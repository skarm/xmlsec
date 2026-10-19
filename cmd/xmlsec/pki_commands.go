package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/skarm/xmlsec/pki"
)

func runPKI(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := args[0]
	fs := flag.NewFlagSet("pki "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)
	input := fs.String("in", "-", "OCSP request/response input")
	out := fs.String("out", "-", "output DER or verification JSON")
	certificate := fs.String("certificate", "", "leaf certificate PEM/DER")
	issuer := fs.String(fieldIssuer, "", "explicit issuer certificate PEM/DER")
	trustFile := fs.String("trust", "", "trusted local JSON trust/evidence configuration")
	atValue := fs.String("at", "", "explicit verification time, RFC3339")
	hashName := fs.String("hash", "sha256", "OCSP CertID hash")
	nonceFile := fs.String("nonce-file", "", "exact expected/request nonce file; request generates random nonce if omitted")
	responder := fs.String("responder", "", "OCSP responder certificate")
	keyFile := fs.String("key", "", "responder private key")
	config := fs.String("config", "", "trusted JSON pki.OCSPResponseTemplate for issuance")
	maxAge := fs.Duration("max-age", 0, "OCSP freshness maximum age; 0 uses library default")
	skew := fs.Duration("clock-skew", 0, "OCSP clock skew tolerance")
	flags := registerPrivateKeyFlags(fs)

	specific := "out certificate"

	switch cmd {
	case nameVerify:
		specific += " trust at"
	case "ocsp-request":
		specific += " issuer hash nonce-file"
	case "ocsp-verify":
		specific += " in issuer at nonce-file trust max-age clock-skew"
	case "ocsp-issue":
		specific += " in issuer responder key config" + privateKeyFlagNames
	}

	fs = commandFlags(fs, specific, false)

	done, err := parseFlags(fs, args[1:])
	if done || err != nil {
		return err
	}

	ctx, cancel, err := exec.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	cert, err := readCertificate(ctx, *certificate)
	if err != nil {
		return err
	}

	if cmd == nameVerify {
		return verifyCertificateCLI(ctx, cert.Raw, *trustFile, *atValue, *out, stdout)
	}

	issuerCert, err := readCertificate(ctx, *issuer)
	if err != nil {
		return err
	}

	var nonce []byte
	if *nonceFile != "" {
		nonce, err = readInputContext(ctx, *nonceFile, nil, 128)
		if err != nil {
			return err
		}
	}

	if cmd == "ocsp-request" {
		hash, err := parseHash(*hashName)
		if err != nil {
			return err
		}

		if nonce == nil {
			nonce = make([]byte, 32)
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
		}

		raw, err := pki.CreateOCSPRequest(cert.Raw, issuerCert.Raw, hash, nonce)
		if err != nil {
			return err
		}

		return writeOutputContext(ctx, *out, stdout, raw)
	}

	raw, err := readInputContext(ctx, *input, stdin, exec.xml.MaxBytes)
	if err != nil {
		return err
	}

	if cmd == "ocsp-verify" {
		return verifyOCSPCLI(ctx, raw, cert.Raw, issuerCert.Raw, nonce, *atValue, *trustFile, *out, *maxAge, *skew, stdout)
	}

	var spec pki.OCSPResponseTemplate
	if err := readJSONFile(ctx, *config, &spec); err != nil {
		return err
	}

	responderCert, err := readCertificate(ctx, *responder)
	if err != nil {
		return err
	}

	key, err := loadPrivateConfigured(ctx, *keyFile, flags)
	if err != nil {
		return err
	}

	response, err := pki.CreateOCSPResponse(ctx, raw, cert.Raw, issuerCert.Raw, responderCert.Raw, key, spec)
	if err != nil {
		return err
	}

	return writeOutputContext(ctx, *out, stdout, response)
}

func verifyCertificateCLI(ctx context.Context, certificate []byte, trustFile, atValue, output string, stdout io.Writer) error {
	at, err := parseTime(atValue)
	if err != nil {
		return err
	}

	opt, evidence, err := loadTrust(ctx, trustFile)
	if err != nil {
		return err
	}

	verifier, err := pki.NewVerifier(opt)
	if err != nil {
		return err
	}

	_, report, verifyErr := verifier.Verify(ctx, certificate, at, evidence)

	return errors.Join(verifyErr, jsonOutput(ctx, output, stdout, resultReport("pki verify", "explicit-pkix-roots", report, verifyErr)))
}

func verifyOCSPCLI(ctx context.Context, raw, certificate, issuer, nonce []byte, atValue, trustFile, output string, maxAge, skew time.Duration, stdout io.Writer) error {
	at, err := parseTime(atValue)
	if err != nil {
		return err
	}

	var crls [][]byte

	if trustFile != "" {
		_, evidence, err := loadTrust(ctx, trustFile)
		if err != nil {
			return err
		}

		crls = evidence.CRLs
	}

	_, report, verifyErr := pki.VerifyOCSP(ctx, raw, certificate, issuer, at, pki.OCSPOptions{ExpectedNonce: nonce, MaxAge: maxAge, ClockSkew: skew, MaxBytes: min(execution(ctx).xml.MaxBytes, 8<<20), ResponderCRLs: crls})

	return errors.Join(verifyErr, jsonOutput(ctx, output, stdout, resultReport("pki ocsp-verify", "explicit-issuer", report, verifyErr)))
}
