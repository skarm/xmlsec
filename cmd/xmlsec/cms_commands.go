package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"path/filepath"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/pki"
)

func runCMS(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := args[0]
	fs := flag.NewFlagSet("cms "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)
	input := fs.String("in", "-", "content input for sign, CMS DER for inspect/verify")
	out := fs.String("out", "-", "output DER or report JSON")
	keyFile := fs.String("key", "", "single signer private key")
	certFile := fs.String("certificate", "", "single signer certificate")
	config := fs.String("signers", "", "trusted JSON signer array for multiple signers; paths relative to JSON")
	hashName := fs.String("hash", "sha256", "signer digest hash")
	pss := fs.Bool("pss", false, "use fixed RSA-PSS for signing")
	ski := fs.Bool("subject-key-identifier", false, "identify signer by certificate SKI")
	detached := fs.Bool("detached", false, "create detached SignedData")
	contentFile := fs.String("content", "", "exact detached content file for verification")
	contentType := fs.String("content-type", "1.2.840.113549.1.7.1", "expected/created content type OID")
	extract := fs.String("extract", "", "write authenticated content to this local file after verification")
	omitCerts := fs.Bool("omit-certificates", false, "omit embedded certificates when signing")
	legacyESS := fs.Bool("allow-legacy-ess", false, "allow legacy ESS certificate binding when verifying")
	trustFile := fs.String("trust", "", "optional PKIX trust/evidence JSON for every pinned signer")
	atValue := fs.String("at", "", "explicit PKIX verification time, RFC3339")

	var certs, extra repeatedFlag
	fs.Var(&certs, "expect-certificate", "required signer certificate pin; repeat for every signer")
	fs.Var(&extra, "extra-certificate", "extra embedded certificate when signing; repeatable")
	flags := registerPrivateKeyFlags(fs)

	specific := ioFlagNames

	switch cmd {
	case nameSign:
		specific += " key certificate signers hash pss subject-key-identifier detached content-type omit-certificates extra-certificate" + privateKeyFlagNames
	case nameVerify:
		specific += " expect-certificate content content-type extract allow-legacy-ess trust at"
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

	options := cmsCommand{command: cmd, input: *input, output: *out, key: *keyFile, certificate: *certFile, signersFile: *config, hash: *hashName, pss: *pss, ski: *ski, detached: *detached, content: *contentFile, contentType: *contentType, extract: *extract, omitCertificates: *omitCerts, legacyESS: *legacyESS, trust: *trustFile, at: *atValue, certificates: certs, extra: extra, flags: flags}

	return options.run(ctx, stdin, stdout)
}

type cmsSignerFile struct {
	Key                  string          `json:"key"`
	Certificate          string          `json:"certificate"`
	KeyFormat            string          `json:"key_format,omitempty"`
	PasswordFile         string          `json:"password_file,omitempty"`
	Hash                 string          `json:"hash,omitempty"`
	PSS                  bool            `json:"pss,omitempty"`
	SubjectKeyIdentifier bool            `json:"subject_key_identifier,omitempty"`
	Attributes           []cms.Attribute `json:"attributes,omitempty"`
}

type cmsCommand struct {
	command, input, output, key, certificate, signersFile, hash, content, contentType, extract, trust, at string
	pss, ski, detached, omitCertificates, legacyESS                                                       bool
	certificates, extra                                                                                   []string
	flags                                                                                                 *privateKeyFlags
}

func (c cmsCommand) run(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	if c.command == nameVerify && len(c.certificates) == 0 {
		return usageError("-expect-certificate is required for every signer")
	}

	oid, err := parseOID(c.contentType)
	if err != nil {
		return err
	}

	limits := cms.Limits{MaxBytes: execution(ctx).xml.MaxBytes, MaxContentBytes: min(execution(ctx).xml.MaxBytes, execution(ctx).output)}
	if c.command == nameSign {
		return c.sign(ctx, stdin, stdout, cms.SignOptions{ContentType: oid, Detached: c.detached, OmitCertificates: c.omitCertificates, Limits: limits})
	}

	raw, err := readInputContext(ctx, c.input, stdin, execution(ctx).xml.MaxBytes)
	if err != nil {
		return err
	}

	container, err := cms.Parse(ctx, raw, limits)
	if err != nil {
		return err
	}

	if c.command == nameInspect {
		return jsonOutput(ctx, c.output, stdout, map[string]any{fieldStatus: statusUnverified, "content_type": container.ContentType().String(), "detached": container.Detached(), "signer_count": container.SignerCount(), "certificate_count": len(container.Certificates()), "content_bytes": len(container.UnverifiedContent())})
	}

	return c.verify(ctx, container, cms.VerifyOptions{ExpectedContentType: oid, RequireCertificateBinding: true, AllowLegacyESSCertID: c.legacyESS}, stdout)
}

func (c cmsCommand) sign(ctx context.Context, stdin io.Reader, stdout io.Writer, opt cms.SignOptions) error {
	signers, err := c.signers(ctx)
	if err != nil {
		return err
	}

	content, err := readInputContext(ctx, c.input, stdin, execution(ctx).xml.MaxBytes)
	if err != nil {
		return err
	}

	opt.ExtraCertificates, err = readCertificates(ctx, "", c.extra)
	if err != nil {
		return err
	}

	raw, err := cms.Sign(ctx, content, signers, opt)
	if err != nil {
		return err
	}

	return writeOutputContext(ctx, c.output, stdout, raw)
}

func (c cmsCommand) signers(ctx context.Context) ([]cms.Signer, error) {
	if c.signersFile == "" {
		signer, err := c.signer(ctx, "", cmsSignerFile{Key: c.key, Certificate: c.certificate, Hash: c.hash, PSS: c.pss, SubjectKeyIdentifier: c.ski, KeyFormat: c.flags.format, PasswordFile: c.flags.passwordFile})
		if err != nil {
			return nil, err
		}

		return []cms.Signer{signer}, nil
	}

	if c.key != "" || c.certificate != "" {
		return nil, usageError("choose -signers or -key/-certificate")
	}

	var specs []cmsSignerFile
	if err := readJSONFile(ctx, c.signersFile, &specs); err != nil {
		return nil, err
	}

	if len(specs) < 1 || len(specs) > 16 {
		return nil, usageError("require 1..16 signers")
	}

	signers := make([]cms.Signer, 0, len(specs))
	for _, spec := range specs {
		signer, err := c.signer(ctx, filepath.Dir(c.signersFile), spec)
		if err != nil {
			return nil, err
		}

		signers = append(signers, signer)
	}

	return signers, nil
}

func (c cmsCommand) signer(ctx context.Context, base string, spec cmsSignerFile) (cms.Signer, error) {
	keyFlags := *c.flags

	keyFlags.format = spec.KeyFormat
	if keyFlags.format == "" {
		keyFlags.format = namePlain
	}

	keyFlags.passwordFile = ""
	if spec.PasswordFile != "" {
		keyFlags.passwordFile = localPath(base, spec.PasswordFile)
	}

	key, err := loadPrivateConfigured(ctx, localPath(base, spec.Key), &keyFlags)
	if err != nil {
		return cms.Signer{}, err
	}

	cert, err := readCertificate(ctx, localPath(base, spec.Certificate))
	if err != nil {
		return cms.Signer{}, err
	}

	hash := spec.Hash
	if hash == "" {
		hash = c.hash
	}

	h, err := parseHash(hash)
	if err != nil {
		return cms.Signer{}, err
	}

	return cms.Signer{Key: key, CertificateDER: cert.Raw, Hash: h, RSAPSS: spec.PSS, SubjectKeyIdentifier: spec.SubjectKeyIdentifier, Attributes: spec.Attributes}, nil
}

func (c cmsCommand) verify(ctx context.Context, container *cms.SignedData, opt cms.VerifyOptions, stdout io.Writer) error {
	expected, err := readCertificates(ctx, "", c.certificates)
	if err != nil {
		return err
	}

	if c.content != "" {
		raw, err := readInputContext(ctx, c.content, nil, execution(ctx).xml.MaxBytes)
		if err != nil {
			return err
		}

		opt.DetachedContent = &raw
	}

	result, verifyErr := container.Verify(ctx, expected, opt)

	trust := "explicit-certificate-pins"
	if verifyErr == nil && c.trust != "" {
		trust = "explicit-pkix-roots"
		verifyErr = c.verifyTrust(ctx, expected)
	}

	var details any
	if verifyErr == nil {
		details = map[string]any{"content_type": result.ContentType().String(), "content_bytes": len(result.Content()), "signers": len(result.Signers())}

		if c.extract != "" {
			if err := separateOutput(c.extract, c.output, "extract"); err != nil {
				return err
			}

			if err := writeOutputContext(ctx, c.extract, stdout, result.Content()); err != nil {
				return err
			}
		}
	}

	return errors.Join(verifyErr, jsonOutput(ctx, c.output, stdout, resultReport("cms verify", trust, details, verifyErr)))
}

func (c cmsCommand) verifyTrust(ctx context.Context, certificates [][]byte) error {
	at, err := parseTime(c.at)
	if err != nil {
		return err
	}

	cfg, evidence, err := loadTrust(ctx, c.trust)
	if err != nil {
		return err
	}

	verifier, err := pki.NewVerifier(cfg)
	if err != nil {
		return err
	}

	for _, cert := range certificates {
		if _, _, err := verifier.Verify(ctx, cert, at, evidence); err != nil {
			return err
		}
	}

	return nil
}
