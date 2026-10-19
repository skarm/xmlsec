package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/timestamp"
)

func runTimestamp(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := args[0]
	fs := flag.NewFlagSet("timestamp "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)
	input := fs.String("in", "-", "data for request, request DER for issue, response/token DER for verify/inspect")
	out := fs.String("out", "-", "output DER or diagnostic JSON")
	kind := fs.String(fieldKind, nameResponse, "inspect/verify: request (inspect only), response or token")
	hashName := fs.String("hash", "sha256", "imprint/signature hash")
	policy := fs.String("tsa-policy", "", "TSA policy OID for request/issue or expected token policy")
	nonceFile := fs.String("nonce-file", "", "exact nonce bytes; omitted requests generate a random nonce")
	omitNonce := fs.Bool("omit-nonce", false, "explicitly omit request nonce")
	omitCerts := fs.Bool("omit-certificates", false, "do not request TSA certificate inclusion")
	requestFile := fs.String(nameRequest, "", "original request DER required to verify a response")
	dataFile := fs.String("data", "", "original timestamped data required to verify a standalone token")
	config := fs.String("trust", "", "trusted TSA JSON configuration")
	atValue := fs.String("at", "", "explicit verification/issuance time, RFC3339")
	serialValue := fs.String("serial", "", "positive unique decimal serial for issuance")
	accuracy := fs.Duration("accuracy", 0, "declared issuance accuracy (0 omits accuracy)")
	ordering := fs.Bool("ordering", false, "assert TSA ordering; issuer must guarantee it")
	pss := fs.Bool("pss", false, "RSA-PSS signature for issuance")
	keyFile := fs.String("key", "", "TSA private key")
	certificate := fs.String("certificate", "", "TSA certificate PEM/DER")
	tokenOut := fs.String("token-out", "", "optional local token DER output after verification")
	flags := registerPrivateKeyFlags(fs)

	specific := ioFlagNames

	switch cmd {
	case nameRequest:
		specific += " hash tsa-policy nonce-file omit-nonce omit-certificates"
	case nameInspect:
		specific += " kind"
	case nameIssue:
		specific += " hash tsa-policy at serial accuracy ordering pss key certificate" + privateKeyFlagNames
	case nameVerify:
		specific += " kind hash tsa-policy nonce-file request data trust at token-out"
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

	options := timestampCommand{command: cmd, input: *input, output: *out, kind: *kind, hash: *hashName, policy: *policy, nonceFile: *nonceFile, omitNonce: *omitNonce, omitCertificates: *omitCerts, requestFile: *requestFile, dataFile: *dataFile, trust: *config, at: *atValue, serial: *serialValue, accuracy: *accuracy, ordering: *ordering, pss: *pss, key: *keyFile, certificate: *certificate, tokenOut: *tokenOut, flags: flags}

	return options.run(ctx, stdin, stdout)
}

type timestampCommand struct {
	command, input, output, kind, hash, policy, nonceFile, requestFile, dataFile, trust, at, serial, key, certificate, tokenOut string
	omitNonce, omitCertificates, ordering, pss                                                                                  bool
	accuracy                                                                                                                    time.Duration
	flags                                                                                                                       *privateKeyFlags
}

func (c timestampCommand) run(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	if err := c.validate(); err != nil {
		return err
	}

	opt, err := c.requestOptions(ctx)
	if err != nil {
		return err
	}

	raw, err := readInputContext(ctx, c.input, stdin, execution(ctx).xml.MaxBytes)
	if err != nil {
		return err
	}

	switch c.command {
	case nameRequest:
		q, err := timestamp.CreateRequest(ctx, raw, opt)
		if err != nil {
			return err
		}

		return writeOutputContext(ctx, c.output, stdout, q.DER())
	case nameInspect:
		value, err := inspectTimestamp(raw, c.kind)
		if err != nil {
			return err
		}

		return jsonOutput(ctx, c.output, stdout, value)
	case nameIssue:
		response, err := c.issue(ctx, raw, opt)
		if err != nil {
			return err
		}

		return writeOutputContext(ctx, c.output, stdout, response)
	default:
		return c.verify(ctx, raw, opt, stdout)
	}
}

func inspectTimestamp(raw []byte, kind string) (any, error) {
	switch kind {
	case nameRequest:
		q, err := timestamp.ParseRequest(raw)
		if err != nil {
			return nil, err
		}

		return map[string]any{fieldStatus: statusUnverified, "imprint": q.Imprint(), "nonce": q.Nonce(), "policy": q.Policy().String(), "certificates_requested": q.CertificatesRequested()}, nil
	case nameResponse:
		r, err := timestamp.ParseResponse(context.Background(), raw)
		if err != nil {
			return nil, err
		}

		info, err := timestamp.InspectToken(context.Background(), r.TokenDER())
		if err != nil {
			return nil, err
		}

		return map[string]any{fieldStatus: statusUnverified, "response_status": r.Status(), nameToken: timestampInfo(info)}, nil
	case nameToken:
		info, err := timestamp.InspectToken(context.Background(), raw)
		if err != nil {
			return nil, err
		}

		return map[string]any{fieldStatus: statusUnverified, nameToken: timestampInfo(info)}, nil
	default:
		return nil, usageError("-kind must be request, response or token")
	}
}

func (c timestampCommand) validate() error {
	switch c.command {
	case nameIssue:
		if _, err := parseTime(c.at); err != nil {
			return err
		}

		n, ok := new(big.Int).SetString(c.serial, 10)
		if !ok || n.Sign() <= 0 {
			return usageError("-serial must be a positive unique decimal integer")
		}

		if c.policy == "" || c.key == "" || c.certificate == "" {
			return usageError("issuance requires -tsa-policy, -key and -certificate")
		}

		if c.accuracy < 0 {
			return usageError("-accuracy must not be negative")
		}
	case nameVerify:
		if _, err := parseTime(c.at); err != nil {
			return err
		}

		if c.trust == "" {
			return usageError("-trust is required")
		}

		switch c.kind {
		case nameResponse:
			if c.requestFile == "" {
				return usageError("-request is required for response verification")
			}
		case nameToken:
			if c.dataFile == "" {
				return usageError("-data is required for token verification")
			}
		default:
			return usageError("verification -kind must be response or token")
		}
	}

	return nil
}

func (c timestampCommand) requestOptions(ctx context.Context) (timestamp.RequestOptions, error) {
	h, err := parseHash(c.hash)
	if err != nil {
		return timestamp.RequestOptions{}, err
	}

	opt := timestamp.RequestOptions{Hash: h, OmitNonce: c.omitNonce, OmitCertificates: c.omitCertificates}
	if c.policy != "" {
		opt.Policy, err = parseOID(c.policy)
		if err != nil {
			return opt, err
		}
	}

	if c.nonceFile != "" {
		if c.omitNonce {
			return opt, usageError("choose -nonce-file or -omit-nonce")
		}

		opt.Nonce, err = readInputContext(ctx, c.nonceFile, nil, 128)
	}

	return opt, err
}

func (c timestampCommand) issue(ctx context.Context, request []byte, opt timestamp.RequestOptions) ([]byte, error) {
	at, err := parseTime(c.at)
	if err != nil {
		return nil, err
	}

	serial, _ := new(big.Int).SetString(c.serial, 10)

	key, err := loadPrivateConfigured(ctx, c.key, c.flags)
	if err != nil {
		return nil, err
	}

	cert, err := readCertificate(ctx, c.certificate)
	if err != nil {
		return nil, err
	}

	spec := timestamp.IssueOptions{GenTime: at, SerialNumber: serial, Policy: opt.Policy, Hash: opt.Hash, Ordering: c.ordering, RSAPSS: c.pss}
	if c.accuracy > 0 {
		spec.Accuracy = &c.accuracy
	}

	return timestamp.IssueResponse(ctx, request, key, cert.Raw, spec)
}

func (c timestampCommand) verify(ctx context.Context, raw []byte, opt timestamp.RequestOptions, stdout io.Writer) error {
	at, err := parseTime(c.at)
	if err != nil {
		return err
	}

	verifier, evidence, err := loadTSA(ctx, c.trust)
	if err != nil {
		return err
	}

	var (
		result    *timestamp.Result
		verifyErr error
	)

	if c.kind == nameResponse {
		b, err := readInputContext(ctx, c.requestFile, nil, execution(ctx).xml.MaxBytes)
		if err != nil {
			return err
		}

		q, err := timestamp.ParseRequest(b)
		if err != nil {
			return err
		}

		result, verifyErr = verifier.VerifyResponse(ctx, raw, q, at, evidence)
	} else {
		data, err := readInputContext(ctx, c.dataFile, nil, execution(ctx).xml.MaxBytes)
		if err != nil {
			return err
		}

		imprint, err := timestamp.ImprintFor(ctx, data, opt.Hash)
		if err != nil {
			return err
		}

		want := timestamp.Expectation{Imprint: imprint, Policy: opt.Policy}
		if len(opt.Nonce) > 0 {
			want.Nonce = new(big.Int).SetBytes(opt.Nonce)
		}

		result, verifyErr = verifier.VerifyToken(ctx, raw, want, at, evidence)
	}

	var details any
	if verifyErr == nil {
		details = timestampInfo(result.Info())

		if c.tokenOut != "" {
			if err := separateOutput(c.tokenOut, c.output, "token-out"); err != nil {
				return err
			}

			if err := writeOutputContext(ctx, c.tokenOut, stdout, result.TokenDER()); err != nil {
				return err
			}
		}
	}

	return errors.Join(verifyErr, jsonOutput(ctx, c.output, stdout, resultReport("timestamp verify", "explicit-tsa-pkix-policy", details, verifyErr)))
}

func timestampInfo(info timestamp.Info) map[string]any {
	accuracy, present := info.Accuracy()
	return map[string]any{"policy": info.Policy().String(), "imprint": info.Imprint(), "serial": info.SerialNumber(), "nonce": info.Nonce(), "gen_time": info.GenTime(), "accuracy": accuracy.String(), "accuracy_present": present, "ordering": info.Ordering()}
}
