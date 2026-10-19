package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

type xadesConfig struct {
	SignerTrust                    trustConfig `json:"signer_trust"`
	TSAConfig                      string      `json:"tsa_config,omitempty"`
	Level                          xades.Level `json:"level"`
	AllowUncheckedSignerRevocation bool        `json:"allow_unchecked_signer_revocation,omitempty"`
	MaxTimestamps                  int         `json:"max_timestamps,omitempty"`
	MaxTokenBytes                  int         `json:"max_token_bytes,omitempty"`
	MaxArchiveTimestamps           int         `json:"max_archive_timestamps,omitempty"`
	MaxArchiveBytes                int         `json:"max_archive_bytes,omitempty"`
}

func runXAdES(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := args[0]
	fs := flag.NewFlagSet("xades "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)
	input := fs.String("in", "-", "input XML")
	out := fs.String("out", "-", "output XML, request DER or verification JSON")
	certFile := fs.String("certificate", "", "explicit document signer certificate pin")
	keyFile := fs.String("key", "", "private signing key")
	method := fs.String("method", "", "signature URI; selected from key if omitted")
	atValue := fs.String("at", "", "claimed signing time or trusted verification time, RFC3339")
	configFile := fs.String("trust", "", "trusted XAdES validator JSON with signer_trust, tsa_config and level")
	tsaFile := fs.String("tsa-trust", "", "TSA JSON for attaching/requesting a signature timestamp")
	tokenFile := fs.String(nameToken, "", "previously obtained timestamp token DER")
	idAttr := fs.String("id-attr", "ID", "application ID attribute local name")
	idNS := fs.String("id-ns", "", "application ID namespace")
	sigID := fs.String("signature-id", "signature", "signature ID when signing")
	propsID := fs.String("properties-id", "properties", "SignedProperties ID")
	refID := fs.String("reference-id", "data-reference", "data Reference ID")
	mimeType := fs.String("mime-type", "application/xml", "signed data MIME type")
	index := fs.Int("signature-index", -1, "explicit zero-based signature selection; omitted requires exactly one signature")
	canonical := fs.String(nameC14n, c14n.Exclusive, "timestamp canonicalization URI")
	profile := fs.String("validation-profile", "current-time", "validation: current-time or with-time")
	flags := registerPrivateKeyFlags(fs)

	specific := "in out certificate at id-attr id-ns signature-index"

	switch cmd {
	case nameSign:
		specific = "in out key certificate method at id-attr id-ns signature-id properties-id reference-id mime-type" + privateKeyFlagNames
	case "timestamp":
		specific += " tsa-trust token c14n"
	case nameTimestampRequest:
		specific += " tsa-trust c14n"
	case "archive":
		specific += " trust token c14n"
	case "archive-request":
		specific += " trust c14n"
	case "material":
		specific += " trust"
	case "validate":
		specific += " trust validation-profile"
	}

	fs = commandFlags(fs, specific, true)

	done, err := parseFlags(fs, args[1:])
	if done || err != nil {
		return err
	}

	ctx, cancel, err := exec.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	at, err := parseTime(*atValue)
	if err != nil {
		return err
	}

	cert, err := readCertificate(ctx, *certFile)
	if err != nil {
		return err
	}

	policy, err := exec.signaturePolicy(false)
	if err != nil {
		return err
	}

	basic := xades.VerifyOptions{IDAttribute: document.Name{Space: *idNS, Local: *idAttr}, Policy: policy}

	doc, err := readDocument(ctx, *input, stdin)
	if err != nil {
		return err
	}

	if cmd == nameSign {
		key, err := loadPrivateConfigured(ctx, *keyFile, flags)
		if err != nil {
			return err
		}

		if *method == "" {
			*method = signatureMethod(key.Public())
		}

		result, _, err := xades.SignBasicEnveloped(ctx, doc, key, cert.Raw, xades.SignOptions{SignatureID: *sigID, SignedPropertiesID: *propsID, DataReferenceID: *refID, SignatureMethod: *method, ClaimedSigningTime: at, MIMEType: *mimeType, IDAttribute: basic.IDAttribute, Policy: policy})
		if err != nil {
			return err
		}

		return documentOutput(ctx, *out, stdout, result)
	}

	if *index < -1 {
		return usageError("-signature-index must be nonnegative when supplied")
	}

	selected, err := selectElement(doc, document.Name{}, "", *index, document.Name{Space: xmldsig.Namespace, Local: "Signature"})
	if err != nil {
		return err
	}

	if cmd == nameVerify {
		return verifyBasicXAdESCLI(ctx, doc, selected, cert.Raw, basic, *out, stdout)
	}

	operation := xadesOperation{doc: doc, selected: selected, certificate: cert.Raw, basic: basic, at: at, output: *out}
	if cmd == "timestamp" || cmd == nameTimestampRequest {
		return operation.timestamp(ctx, cmd, *tsaFile, *canonical, *tokenFile, stdout)
	}

	var cfg xadesConfig
	if err := readJSONFile(ctx, *configFile, &cfg); err != nil {
		return err
	}

	base := filepath.Dir(*configFile)

	signerTrust, signerEvidence, err := cfg.SignerTrust.load(ctx, base)
	if err != nil {
		return err
	}

	var (
		tsa         *timestamp.Verifier
		tsaEvidence pki.Evidence
	)
	if cfg.TSAConfig != "" {
		tsa, tsaEvidence, err = loadTSA(ctx, localPath(base, cfg.TSAConfig))
		if err != nil {
			return err
		}
	}

	evidence := xades.ValidationEvidence{Signer: signerEvidence, TSA: tsaEvidence}

	if *profile == "with-time" {
		return operation.withTime(ctx, cmd, cfg, signerTrust, tsa, evidence, stdout)
	}

	if *profile != "current-time" {
		return usageError("-validation-profile must be current-time or with-time")
	}

	return runXAdESCurrent(ctx, operation, cmd, cfg, signerTrust, tsa, evidence, *canonical, *tokenFile, stdout)
}

type xadesOperation struct {
	doc         *document.Document
	selected    document.Element
	certificate []byte
	basic       xades.VerifyOptions
	at          time.Time
	output      string
}

func (o xadesOperation) timestamp(ctx context.Context, cmd, tsaFile, canonical, tokenFile string, stdout io.Writer) error {
	tsa, evidence, err := loadTSA(ctx, tsaFile)
	if err != nil {
		return err
	}

	opt := xades.AddTimestampOptions{Validation: xades.TimedOptions{Basic: o.basic, TSA: tsa, At: o.at, Evidence: evidence}, Canonicalization: canonical}

	if cmd == nameTimestampRequest {
		var request []byte

		sentinel := errors.New("request captured")

		_, _, err := xades.AddSignatureTimestamp(ctx, o.doc, o.selected, o.certificate, timestamp.TransportFunc(func(_ context.Context, b []byte) (io.ReadCloser, error) {
			request = append([]byte(nil), b...)
			return nil, sentinel
		}), opt)
		if !errors.Is(err, sentinel) {
			return err
		}

		return writeOutputContext(ctx, o.output, stdout, request)
	}

	token, err := readInputContext(ctx, tokenFile, nil, execution(ctx).xml.MaxBytes)
	if err != nil {
		return err
	}

	result, _, err := xades.AttachSignatureTimestamp(ctx, o.doc, o.selected, o.certificate, token, opt)
	if err != nil {
		return err
	}

	return documentOutput(ctx, o.output, stdout, result)
}

func (o xadesOperation) withTime(ctx context.Context, cmd string, cfg xadesConfig, signerTrust pki.Config, tsa *timestamp.Verifier, evidence xades.ValidationEvidence, stdout io.Writer) error {
	if cfg.Level != xades.LevelBT {
		return usageError("with-time profile requires level B-T; it cannot satisfy other configured levels")
	}

	if cmd != "validate" {
		return usageError("with-time profile is for validation only")
	}

	validator, err := xades.NewWithTimeValidator(xades.WithTimeConfig{SignerPKI: signerTrust, TSA: tsa, Basic: o.basic, MaxTimestamps: cfg.MaxTimestamps, MaxTokenBytes: cfg.MaxTokenBytes})
	if err != nil {
		return err
	}

	result, report, verifyErr := validator.ValidateEnveloped(ctx, o.doc, o.selected, o.certificate, o.at, evidence)

	detail := map[string]any{"profile": report.Profile(), "indication": report.Indication(), "proof_time": report.ProofTime(), "verification_time": report.VerificationTime()}
	if verifyErr == nil {
		detail["signature"] = basicXAdESReport(result.Basic())
	}

	return errors.Join(verifyErr, jsonOutput(ctx, o.output, stdout, resultReport("xades validate", "explicit-pkix-and-tsa-policy", detail, verifyErr)))
}

func basicXAdESReport(r *xades.BasicResult) any {
	return map[string]any{"signature_method": r.Signature().SignatureMethod(), "key_fingerprint_sha256": r.Signature().KeyFingerprintSHA256(), "claimed_signing_time": r.ClaimedSigningTime(), "reference_count": len(r.Signature().References())}
}

func runXAdESCurrent(ctx context.Context, o xadesOperation, cmd string, cfg xadesConfig, signerTrust pki.Config, tsa *timestamp.Verifier, evidence xades.ValidationEvidence, canonical, tokenFile string, stdout io.Writer) error {
	validator, err := xades.NewValidator(xades.ValidatorConfig{SignerPKI: signerTrust, TSA: tsa, MinimumLevel: cfg.Level, AllowUncheckedSignerRevocation: cfg.AllowUncheckedSignerRevocation, Basic: o.basic, MaxTimestamps: cfg.MaxTimestamps, MaxTokenBytes: cfg.MaxTokenBytes, MaxArchiveTimestamps: cfg.MaxArchiveTimestamps, MaxArchiveBytes: cfg.MaxArchiveBytes})
	if err != nil {
		return err
	}

	if cmd == "material" {
		result, _, err := validator.EmbedValidationMaterial(ctx, o.doc, o.selected, o.certificate, o.at, evidence)
		if err != nil {
			return err
		}

		return documentOutput(ctx, o.output, stdout, result)
	}

	if cmd == "archive-request" {
		var request []byte

		sentinel := errors.New("request captured")

		_, _, err := validator.AddArchiveTimestamp(ctx, o.doc, o.selected, o.certificate, o.at, timestamp.TransportFunc(func(_ context.Context, b []byte) (io.ReadCloser, error) {
			request = append([]byte(nil), b...)
			return nil, sentinel
		}), xades.AddArchiveOptions{Canonicalization: canonical})
		if !errors.Is(err, sentinel) {
			return err
		}

		return writeOutputContext(ctx, o.output, stdout, request)
	}

	if cmd == "archive" {
		token, err := readInputContext(ctx, tokenFile, nil, execution(ctx).xml.MaxBytes)
		if err != nil {
			return err
		}

		result, _, err := validator.AttachArchiveTimestamp(ctx, o.doc, o.selected, o.certificate, o.at, token, canonical)
		if err != nil {
			return err
		}

		return documentOutput(ctx, o.output, stdout, result)
	}

	result, verifyErr := validator.ValidateEnveloped(ctx, o.doc, o.selected, o.certificate, o.at, evidence)

	var detail any
	if verifyErr == nil {
		detail = map[string]any{"profile": result.Profile(), "level": result.Level(), "signature": basicXAdESReport(result.Basic()), "timestamps": len(result.Timestamps()), "archive_timestamps": len(result.ArchiveTimestamps())}
	}

	return errors.Join(verifyErr, jsonOutput(ctx, o.output, stdout, resultReport("xades validate", "explicit-pkix-and-tsa-policy", detail, verifyErr)))
}

func verifyBasicXAdESCLI(ctx context.Context, doc *document.Document, selected document.Element, certificate []byte, opt xades.VerifyOptions, output string, stdout io.Writer) error {
	result, verifyErr := xades.VerifyBasicEnveloped(ctx, doc, selected, certificate, opt)

	var detail any
	if verifyErr == nil {
		detail = basicXAdESReport(result)
	}

	return errors.Join(verifyErr, jsonOutput(ctx, output, stdout, resultReport("xades verify", "explicit-certificate-pin", detail, verifyErr)))
}
