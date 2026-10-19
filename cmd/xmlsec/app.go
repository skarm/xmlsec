package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
)

type (
	commandHandler func(context.Context, []string, io.Reader, io.Writer, io.Writer) error
	commandSpec    struct {
		name, summary string
		handler       commandHandler
	}
)

func commands() []commandSpec {
	return []commandSpec{
		{"signature sign", "Sign a root-enveloped XML document", runXML},
		{"signature verify", "Verify a root-enveloped signature with an explicit key pin", runXML},
		{"signature build", "Build an unsigned XMLDSig template from trusted JSON", runSignatureBuild},
		{"signature sign-template", "Sign a selected template, preserving explicitly trusted signatures", runCore},
		{"signature verify-keyinfo", "Verify a selected KeyInfo candidate against an explicit external key pin", runCore},
		{"signature verify-core", "Verify a selected signature, references, coverage and Manifests", runCore},
		{"signature sign-detached", "Sign exact external resources from a local manifest", runDetached},
		{"signature verify-detached", "Verify the exact resource set in a local manifest", runDetached},
		{"signature inspect", "List untrusted signatures, algorithms, references and IDs", runInspect},
		{nameC14n, "Canonicalize XML, an element or an XPath node set", runXML},
		{"encryption encrypt", "Encrypt bytes, a document, an element or element content", runEncryption},
		{"encryption decrypt", "Authenticate and decrypt explicitly selected XML ciphertext", runEncryption},
		{"encryption externalize", "Extract selected ciphertext into a CipherReference", runEncryption},
		{"key generate", "Generate RSA, ECDSA, Ed25519 or a random symmetric key", runKey},
		{"key public", "Export a public key from a private key or certificate", runKey},
		{"key convert", "Export plain/encrypted PKCS#8 or PKCS#12", runKey},
		{"key inspect", "Inspect public metadata without printing private material", runKey},
		{"keyinfo build", "Build untrusted XML KeyInfo descriptions", runKeyInfo},
		{"keyinfo inspect", "Inspect bounded KeyInfo candidates and references", runKeyInfo},
		{"transform xpath", "Evaluate XPath 1.0, 2.0, 3.0 or 3.1", runTransform},
		{"transform xslt", "Run XSLT 1.0 or Basic XSLT 2.0/3.0", runTransform},
		{"pki verify", "Verify a certificate with explicit offline trust and time", runPKI},
		{"pki ocsp-request", "Build an OCSP request for a certificate and issuer", runPKI},
		{"pki ocsp-verify", "Verify an offline OCSP response", runPKI},
		{"pki ocsp-issue", "Issue an OCSP response from explicit trusted configuration", runPKI},
		{"cms sign", "Create CMS SignedData with explicit signers", runCMS},
		{"cms verify", "Verify all CMS signers against explicit certificate pins", runCMS},
		{"cms inspect", "Inspect unauthenticated CMS container metadata", runCMS},
		{"timestamp request", "Create an RFC 3161 request with a random nonce", runTimestamp},
		{"timestamp inspect", "Inspect an unauthenticated RFC 3161 request, response or token", runTimestamp},
		{"timestamp issue", "Issue a response with explicit time, serial and policy", runTimestamp},
		{"timestamp verify", "Verify a response or token with explicit TSA trust", runTimestamp},
		{"xades sign", "Create a basic enveloped XAdES signature", runXAdES},
		{"xades verify", "Verify basic XAdES with a certificate pin", runXAdES},
		{"xades timestamp-request", "Create an offline TSA request for SignatureValue", runXAdES},
		{"xades archive-request", "Create an offline TSA request for an archive timestamp", runXAdES},
		{"xades timestamp", "Attach and verify a supplied signature timestamp token", runXAdES},
		{"xades material", "Attach validation material to a verified signature", runXAdES},
		{"xades archive", "Attach and verify an archive timestamp", runXAdES},
		{"xades validate", "Validate B-B/B-T/B-LT/B-LTA or the with-time profile", runXAdES},
		{"saml post-encode", "Encode a SAML POST form (no authentication)", runSAML},
		{"saml post-decode", "Decode an unauthenticated SAML POST form", runSAML},
		{"saml redirect-sign", "Sign a SAML Redirect query", runSAML},
		{"saml redirect-verify", "Authenticate a SAML Redirect query before inflation", runSAML},
		{"saml metadata-build", "Build SP or IdP metadata from trusted JSON", runSAML},
		{"saml metadata-verify", "Read metadata with explicit signature trust or document pin", runSAML},
		{"saml request-build", "Build a SAML AuthnRequest", runSAML},
		{"saml redirect-request-verify", "Validate an authenticated Redirect AuthnRequest offline", runSAML},
		{"saml request-verify", "Validate an AuthnRequest against explicit expectations", runSAML},
		{"saml response-build", "Create a signed solicited WebSSO response", runSAML},
		{"saml response-verify", "Validate a solicited WebSSO response offline", runSAML},
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == jsonErrorsFlag {
		args = args[1:]
	}

	if ctx == nil {
		return usageError("nil context")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if len(args) == 0 {
		return showHelp(ctx, nil, stdin, stdout, stderr)
	}

	switch args[0] {
	case "-h", "--help", nameHelp:
		return showHelp(ctx, args[1:], stdin, stdout, stderr)
	case "version", "--version":
		if len(args) != 1 {
			return usageError("version takes no arguments")
		}

		return writeJSON(stdout, versionInfo())
	case "algorithms":
		if len(args) != 1 {
			return usageError("algorithms takes no arguments")
		}

		return writeJSON(stdout, algorithmInfo())
	}

	args = expandAlias(args)
	if command, tail, ok := findCommand(args); ok {
		return command.handler(ctx, append([]string{lastWord(command.name)}, tail...), stdin, stdout, stderr)
	}

	if isGroupHelp(args) {
		return showHelp(ctx, args[:1], stdin, stdout, stderr)
	}

	return usageError("unknown command %q; use xmlsec --help", strings.Join(args, " "))
}

func showHelp(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	path := strings.Join(args, " ")
	for _, command := range commands() {
		if command.name == path {
			return command.handler(ctx, []string{lastWord(path), "-h"}, stdin, stdout, stderr)
		}
	}

	found := path == ""
	for _, command := range commands() {
		if path != "" && !strings.HasPrefix(command.name, path+" ") {
			continue
		}

		found = true

		if _, err := fmt.Fprintf(stdout, "  %-30s %s\n", command.name, command.summary); err != nil {
			return err
		}
	}

	if !found {
		return usageError("unknown help topic %q", path)
	}

	_, err := fmt.Fprintln(stdout, "\nRoot options: --json-errors (before command).\nUse xmlsec help COMMAND or xmlsec GROUP COMMAND -h. Flags follow the command.\nFiles use - for stdin/stdout where supported. Trust and resource access are explicit.\nExit codes: 0 success/help, 1 operation or verification failed, 2 usage, 130 canceled, 124 timeout.")

	return err
}

func expandAlias(args []string) []string {
	aliases := map[string]string{nameSign: "signature sign", nameVerify: "signature verify", nameSignTemplate: "signature sign-template", nameVerifyCore: "signature verify-core", nameSignDetached: "signature sign-detached", nameVerifyDetached: "signature verify-detached", nameInspect: "signature inspect", nameEncrypt: "encryption encrypt", nameDecrypt: "encryption decrypt", nameXPath: "transform xpath", nameXSLT: "transform xslt"}
	if path, ok := aliases[args[0]]; ok {
		return append(strings.Fields(path), args[1:]...)
	}

	return args
}

func findCommand(args []string) (commandSpec, []string, bool) {
	for _, command := range commands() {
		parts := strings.Fields(command.name)
		if len(args) < len(parts) {
			continue
		}

		matches := true

		for i := range parts {
			if parts[i] != args[i] {
				matches = false
				break
			}
		}

		if matches {
			return command, args[len(parts):], true
		}
	}

	return commandSpec{}, nil, false
}

func isGroupHelp(args []string) bool {
	if len(args) != 1 && (len(args) != 2 || (args[1] != "-h" && args[1] != "--help")) {
		return false
	}

	for _, command := range commands() {
		if strings.HasPrefix(command.name, args[0]+" ") {
			return true
		}
	}

	return false
}

func lastWord(s string) string { fields := strings.Fields(s); return fields[len(fields)-1] }

type usageFailure struct{ error }

func usageError(format string, args ...any) error { return usageFailure{fmt.Errorf(format, args...)} }

func exitCode(err error) int {
	if err == nil {
		return 0
	}

	if errors.Is(err, context.Canceled) {
		return 130
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return 124
	}

	if _, ok := errors.AsType[usageFailure](err); ok {
		return 2
	}

	return 1
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(v)
}

func versionInfo() any {
	version, revision, modified := "devel", "", false

	if b, ok := debug.ReadBuildInfo(); ok {
		if b.Main.Version != "" {
			version = b.Main.Version
		}

		for _, s := range b.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				modified = s.Value == valueTrue
			}
		}
	}

	return map[string]any{"name": "xmlsec", "version": version, "revision": revision, "modified": modified}
}
