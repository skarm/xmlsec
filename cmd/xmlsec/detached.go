package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

// This file is a TRUSTED local manifest, not a resource list from a signature.
// Paths are resolved relative to the manifest's directory; network is never used.
type resourceEntry struct {
	URI           string                `json:"uri"`
	Path          string                `json:"path"`
	Type          string                `json:"type,omitempty"`
	DigestMethod  string                `json:"digest_method,omitempty"`
	Transforms    []reference.Transform `json:"transforms,omitempty"`
	signingFields bool
}

func (e *resourceEntry) UnmarshalJSON(raw []byte) error {
	type plain resourceEntry

	var value plain
	if err := decodeJSON(raw, &value); err != nil {
		return err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}

	*e = resourceEntry(value)

	for key := range fields {
		switch strings.ToLower(key) {
		case fieldType, "digest_method", "transforms":
			e.signingFields = true
		}
	}

	return nil
}

func loadResourcesContext(ctx context.Context, path string) ([]resourceEntry, xmldsig.Resolver, error) {
	var entries []resourceEntry
	if err := readJSONFile(ctx, path, &entries); err != nil {
		return nil, nil, fmt.Errorf("resource manifest: %w", err)
	}

	if len(entries) == 0 || len(entries) > 64 {
		return nil, nil, errors.New("resource manifest requires 1..64 entries")
	}

	paths := make(map[string]string, len(entries))
	for _, e := range entries {
		if e.URI == "" || e.Path == "" {
			return nil, nil, errors.New("resource URI and path are required")
		}

		if _, ok := paths[e.URI]; ok {
			return nil, nil, errors.New("duplicate manifest URI")
		}

		resource := e.Path
		if !filepath.IsAbs(resource) {
			resource = filepath.Join(filepath.Dir(path), resource)
		}

		paths[e.URI] = resource
	}

	resolver := xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		p, ok := paths[uri]
		if !ok {
			return nil, errors.New("URI is not allowed by the local manifest")
		}
		// Do not open named pipes/devices as though they were finite payload files.
		stat, err := os.Stat(p)
		if err != nil {
			return nil, err
		}

		if !stat.Mode().IsRegular() {
			return nil, errors.New("resource must be a regular file")
		}

		f, err := os.Open(p) // #nosec G304 -- Only paths in the operator-supplied manifest are opened.
		if err != nil {
			return nil, err
		}

		stat, err = f.Stat()
		if err != nil {
			return nil, errors.Join(err, f.Close())
		}

		if !stat.Mode().IsRegular() {
			return nil, errors.Join(errors.New("resource must be a regular file"), f.Close())
		}

		return &cancelReadCloser{ReadCloser: f, stop: interruptIO(ctx, f)}, nil
	})

	return entries, resolver, nil
}

func runDetached(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)

	var keyFlags *privateKeyFlags
	if cmd == nameSignDetached {
		keyFlags = registerPrivateKeyFlags(fs)
	}

	modern := fs.Bool("modern-algorithms", false, "also permit fixed RSA-PSS, Ed25519 and Ed25519ph")
	manifest := fs.String("resources", "", "trusted local JSON resource manifest")
	keyPath := fs.String("key", "", "private key file (sign) or externally trusted public key/certificate PEM/DER (verify)")
	output := fs.String("out", "-", "output path; - writes stdout")
	canonical := fs.String(nameC14n, c14n.Exclusive, "SignedInfo C14N URI; verification permits exactly this method")
	resourceLimit := fs.Int("max-resource-bytes", 8<<20, "maximum bytes per external resource")
	totalLimit := fs.Int("max-total-resource-bytes", 32<<20, "maximum source bytes per operation")
	allowedTransforms := fs.String("allowed-transforms", "", "comma-separated permitted reference transform URIs; empty uses implemented defaults")

	var input, method, inclusive string
	if cmd == nameVerifyDetached {
		fs.StringVar(&input, "in", "-", "standalone signature XML; - reads stdin")
	} else {
		fs.StringVar(&method, "method", "", "signature method URI; default selected from key")
		fs.StringVar(&inclusive, "inclusive-prefixes", "", "SignedInfo Exclusive C14N inclusive prefix list")
	}

	if done, err := parseFlags(fs, args[1:]); done || err != nil {
		return err
	}

	if err := validateDetachedArgs(fs, *manifest, *keyPath); err != nil {
		return err
	}

	ctx, cancel, err := exec.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	entries, resolver, err := loadResourcesContext(ctx, *manifest)
	if err != nil {
		return err
	}

	processing, err := exec.processing(ctx, *resourceLimit, *allowedTransforms)
	if err != nil {
		return err
	}

	limits := xmldsig.ResourceLimits{MaxResourceBytes: *resourceLimit, MaxTotalResourceBytes: *totalLimit}
	if limits.MaxResourceBytes < 1 || limits.MaxResourceBytes > 64<<20 || limits.MaxTotalResourceBytes < 1 || limits.MaxTotalResourceBytes > 64<<20 {
		return usageError("resource byte limits must be 1..67108864")
	}

	policy, err := exec.signaturePolicy(*modern)
	if err != nil {
		return err
	}

	if exec.policy == nameHMAC {
		return usageError("HMAC uses signature sign-template/verify-core with -secret-file")
	}

	if cmd == nameSignDetached {
		return signDetachedCLI(ctx, stdout, *output, *keyPath, keyFlags, entries, resolver, xmldsig.DetachedSignOptions{Policy: policy, SignatureMethod: method, Canonicalization: reference.Transform{Algorithm: *canonical, InclusivePrefixes: strings.Fields(inclusive)}, Limits: limits, Processing: processing, XMLLimits: exec.xml})
	}

	return verifyDetachedCLI(ctx, stdin, stdout, input, *output, *keyPath, entries, resolver, xmldsig.DetachedVerifyOptions{Policy: policy, ExpectedURIs: detachedResourceURIs(entries), AllowedCanonicalizationMethods: []string{*canonical}, Processing: processing, Limits: limits})
}

func signDetachedCLI(ctx context.Context, stdout io.Writer, output, keyPath string, keyFlags *privateKeyFlags, entries []resourceEntry, resolver xmldsig.Resolver, opt xmldsig.DetachedSignOptions) error {
	key, err := loadPrivateConfigured(ctx, keyPath, keyFlags)
	if err != nil {
		return err
	}

	doc, err := xmldsig.SignDetached(ctx, detachedReferenceSpecs(entries), key, resolver, opt)
	if err != nil {
		return err
	}

	return documentOutput(ctx, output, stdout, doc)
}

func verifyDetachedCLI(ctx context.Context, stdin io.Reader, stdout io.Writer, input, output, keyPath string, entries []resourceEntry, resolver xmldsig.Resolver, opt xmldsig.DetachedVerifyOptions) error {
	if err := validateResourceAllowlist(entries); err != nil {
		return err
	}

	key, err := loadPublicContext(ctx, keyPath)
	if err != nil {
		return err
	}

	doc, err := readDocument(ctx, input, stdin)
	if err != nil {
		return err
	}

	result, verifyErr := xmldsig.VerifyDetached(ctx, doc, key, resolver, opt)
	if verifyErr != nil {
		return errors.Join(verifyErr, jsonOutput(ctx, output, stdout, resultReport("signature verify-detached", "externally-supplied-key", nil, verifyErr)))
	}

	raw, err := detachedVerificationReport(result)
	if err != nil {
		return err
	}

	return writeOutputContext(ctx, output, stdout, raw)
}

func validateDetachedArgs(fs *flag.FlagSet, manifest, keyPath string) error {
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}

	if manifest == "" || manifest == "-" || keyPath == "" {
		return errors.New("-resources file and -key are required")
	}

	return nil
}

func detachedVerificationReport(result *xmldsig.DetachedResult) ([]byte, error) {
	type checkedReference struct {
		URI              string           `json:"uri"`
		Type             string           `json:"type,omitempty"`
		DigestMethod     string           `json:"digest_method"`
		DigestInputBytes int              `json:"digest_input_bytes"`
		Canonicalization string           `json:"canonicalization,omitempty"`
		Steps            []reference.Step `json:"steps"`
	}

	report := struct {
		Status          string             `json:"status"`
		Profile         string             `json:"profile"`
		Trust           string             `json:"trust"`
		SignatureMethod string             `json:"signature_method"`
		KeyFingerprint  string             `json:"key_fingerprint_sha256"`
		References      []checkedReference `json:"references"`
	}{
		Status:          statusValid,
		Profile:         "external-detached-v0",
		Trust:           "externally-supplied-key",
		SignatureMethod: result.SignatureMethod(),
		KeyFingerprint:  result.KeyFingerprintSHA256(),
	}

	for _, r := range result.References() {
		report.References = append(report.References, checkedReference{r.URI(), r.Type(), r.DigestMethod(), r.Size(), r.CanonicalizationMethod(), r.Steps()})
	}

	out, err := json.MarshalIndent(resultReport("signature verify-detached", "externally-supplied-key", report, nil), "", "  ")
	if err != nil {
		return nil, err
	}

	return append(out, '\n'), nil
}

func detachedReferenceSpecs(entries []resourceEntry) []xmldsig.DetachedReference {
	refs := make([]xmldsig.DetachedReference, len(entries))
	for i, e := range entries {
		refs[i] = xmldsig.DetachedReference{URI: e.URI, Type: e.Type, DigestMethod: e.DigestMethod, Transforms: e.Transforms}
	}

	return refs
}

func detachedResourceURIs(entries []resourceEntry) []string {
	uris := make([]string, len(entries))
	for i, e := range entries {
		uris[i] = e.URI
	}

	return uris
}

// Verification manifests authorize URI/path only; recipes are never silently treated as policy.
func validateResourceAllowlist(entries []resourceEntry) error {
	for _, e := range entries {
		if e.signingFields || e.Type != "" || e.DigestMethod != "" || e.Transforms != nil {
			return usageError("verification resource manifest accepts only uri/path; use -allowed-transforms and -allowed-digests for policy")
		}
	}

	return nil
}

type cancelReadCloser struct {
	io.ReadCloser
	stop func()
}

func (c *cancelReadCloser) Close() error { c.stop(); return c.ReadCloser.Close() }
