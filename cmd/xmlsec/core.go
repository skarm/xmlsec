package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

const nameRecursiveExternal = "recursive-external"

type repeatedFlag []string

func (v *repeatedFlag) String() string { return strings.Join(*v, ",") }

func (v *repeatedFlag) Set(s string) error { *v = append(*v, s); return nil }

func runCore(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)

	keyInfoConfig, keyInfoResources, keyInfoBase := "", "", ""
	if cmd == nameVerifyKeyInfo {
		fs.StringVar(&keyInfoConfig, "keyinfo-config", "", "trusted JSON KeyInfo parsing policy")
		fs.StringVar(&keyInfoResources, "keyinfo-resources", "", "separate trusted URI/path allowlist for KeyInfo retrieval")
		fs.StringVar(&keyInfoBase, "keyinfo-base-uri", "", "explicit KeyInfo base URI; requires -keyinfo-resources")
	}

	var keyFlags *privateKeyFlags
	if cmd == nameSignTemplate {
		keyFlags = registerPrivateKeyFlags(fs)
	}

	input := fs.String("in", "-", "input XML; - reads stdin")
	output := fs.String("out", "-", "output signed XML or diagnostic JSON")
	keyFile := fs.String("key", "", "private key for sign-template; trusted public key for verify-core")
	index := fs.Int("signature-index", -1, "REQUIRED zero-based Signature index (explicit selection, not trust)")
	idAttr := fs.String("id-attr", "ID", "application ID attribute local name")
	idNS := fs.String("id-ns", "", "application ID namespace URI")
	methods := fs.String(nameC14n, c14n.Exclusive, "comma-separated allowed SignedInfo canonicalization URIs")
	modern := fs.Bool("modern-algorithms", false, "also permit fixed RSA-PSS, Ed25519 and Ed25519ph")
	manifests := fs.String("manifests", "none", "Manifest validation: none, recursive or recursive-external")
	manifestTransforms := fs.Bool("manifest-transforms", false, "follow authenticated Manifest transform results; requires recursive mode")
	depth := fs.Int("manifest-max-depth", 8, "recursive Manifest depth limit")
	nodes := fs.Int("manifest-max-nodes", 64, "maximum unique Manifest elements")
	refs := fs.Int("manifest-max-references", 256, "maximum total direct and nested Reference elements")
	resources := fs.String("resources", "", "optional trusted JSON URI/path allowlist for external references")
	baseURI := fs.String("base-uri", "", "explicit absolute signature document URI for relative external references; requires -resources")
	resourceLimit := fs.Int("max-resource-bytes", 8<<20, "maximum bytes per external resource")
	totalLimit := fs.Int("max-total-resource-bytes", 32<<20, "maximum fetched source bytes per operation")
	allowedTransforms := fs.String("allowed-transforms", "", "comma-separated permitted Reference transform URIs")
	maxSignatures := fs.Int("max-signatures", 16, "maximum Signature elements (1..64)")
	idRules := fs.String("id-rules", "", "trusted JSON array of additional IDAttributeRule values")
	secretFile := fs.String("secret-file", "", "HMAC shared-secret file, instead of -key; requires -policy hmac")

	var requiredIDs repeatedFlag
	fs.Var(&requiredIDs, "require-id", "require coverage of this exact application ID; repeatable")
	rootRequired := fs.Bool("require-root", false, "require original root element coverage")

	var expected, preserve repeatedFlag
	fs.Var(&expected, "expect-uri", "exact expected Reference URI; repeat for every reference (empty URI allowed)")

	if cmd == nameSignTemplate {
		fs.Var(&preserve, "preserve", "existing signature INDEX=PUBLIC_KEY_FILE; repeat as needed")
	}

	if done, err := parseFlags(fs, args[1:]); done || err != nil {
		return err
	}

	invocation := coreInvocation{command: cmd, key: *keyFile, secret: *secretFile, index: *index, maxSignatures: *maxSignatures, resourceLimit: *resourceLimit, totalLimit: *totalLimit}
	if err := invocation.validate(); err != nil {
		return err
	}

	ctx, cancel, err := exec.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	data, err := readInputContext(ctx, *input, stdin, exec.xml.MaxBytes)
	if err != nil {
		return err
	}

	doc, err := document.Parse(ctx, data, exec.xml)
	if err != nil {
		return err
	}

	signatures := xmldsig.Signatures(doc)
	if *index >= len(signatures) {
		return errors.New("signature index out of range")
	}

	opt := xmldsig.SignatureOptions{IDAttribute: document.Name{Space: *idNS, Local: *idAttr}, AllowedCanonicalizationMethods: strings.Split(*methods, ","), ExpectedURIs: expected}

	cfg := coreValidationFlags{modern: *modern, resourceLimit: *resourceLimit, totalLimit: *totalLimit, allowedTransforms: *allowedTransforms, maxSignatures: *maxSignatures, idRules: *idRules, requiredIDs: requiredIDs, manifests: *manifests, depth: *depth, nodes: *nodes, references: *refs, resources: *resources, baseURI: *baseURI, rootRequired: *rootRequired, manifestTransforms: *manifestTransforms}

	opt, err = cfg.options(ctx, doc, exec, opt)
	if err != nil {
		return err
	}

	if *secretFile != "" {
		return runCoreHMAC(ctx, cmd, doc, signatures[*index], *secretFile, preserve, opt, *output, stdout)
	}

	if exec.policy == nameHMAC {
		return usageError("-policy hmac requires -secret-file")
	}

	if cmd == nameSignTemplate {
		key, err := loadPrivateConfigured(ctx, *keyFile, keyFlags)
		if err != nil {
			return err
		}

		signing := xmldsig.TemplateSignOptions{Validation: opt}

		if err := runCorePreserve(ctx, preserve, signatures, &opt, &signing); err != nil {
			return err
		}

		signed, err := xmldsig.SignTemplate(ctx, doc, signatures[*index], key, signing)
		if err != nil {
			return err
		}

		raw, err := signed.XML(ctx)
		if err != nil {
			return err
		}

		return writeOutputContext(ctx, *output, stdout, raw)
	}

	key, err := loadPublicContext(ctx, *keyFile)
	if err != nil {
		return err
	}

	if cmd == nameVerifyKeyInfo {
		return verifyWithKeyInfoCLI(ctx, doc, signatures[*index], key, opt, keyInfoConfig, keyInfoResources, keyInfoBase, *output, stdout)
	}

	result, report, verifyErr := xmldsig.VerifySignatureDetailed(ctx, doc, signatures[*index], key, opt)

	details := map[string]any{"checks": report, "signature_index": *index, "root_coverage_required": *rootRequired, "required_ids": requiredIDs}
	if verifyErr == nil {
		details["key_fingerprint_sha256"] = result.KeyFingerprintSHA256()
		details["root_covered"] = result.CoversElement(doc.Root())
	}

	return errors.Join(verifyErr, jsonOutput(ctx, *output, stdout, resultReport("signature verify-core", "externally-supplied-key", details, verifyErr)))
}

func runCorePreserve(ctx context.Context, preserve repeatedFlag, signatures []document.Element, opt *xmldsig.SignatureOptions, signing *xmldsig.TemplateSignOptions) error {
	for _, s := range preserve {
		fields := strings.SplitN(s, "=", 2)
		if len(fields) != 2 {
			return errors.New("-preserve requires INDEX=PUBLIC_KEY_FILE")
		}

		i, err := strconv.Atoi(fields[0])
		if err != nil || i < 0 || i >= len(signatures) {
			return errors.New("preserved signature index out of range")
		}

		public, err := loadPublicContext(ctx, fields[1])
		if err != nil {
			return err
		}
		// The old signature may have different references/coverage; do not
		// copy the NEW signature's ExpectedURIs/RequiredElements onto it.
		oldOpt := *opt
		oldOpt.ExpectedURIs = nil
		oldOpt.RequiredElements = nil
		signing.Preserve = append(signing.Preserve, xmldsig.SignatureRequirement{Signature: signatures[i], PublicKey: public, Options: oldOpt})
	}

	return nil
}

type coreValidationFlags struct {
	modern, rootRequired, manifestTransforms                           bool
	resourceLimit, totalLimit, maxSignatures, depth, nodes, references int
	allowedTransforms, idRules, manifests, resources, baseURI          string
	requiredIDs                                                        []string
}

func (c coreValidationFlags) options(ctx context.Context, doc *document.Document, exec *executionFlags, opt xmldsig.SignatureOptions) (xmldsig.SignatureOptions, error) {
	var err error

	if c.baseURI != "" && c.resources == "" {
		return opt, usageError("-base-uri requires -resources")
	}

	opt.Policy, err = exec.signaturePolicy(c.modern)
	if err != nil {
		return opt, err
	}

	resourceInput := 0
	if c.resources != "" {
		resourceInput = c.resourceLimit
	}

	opt.Processing, err = exec.processing(ctx, resourceInput, c.allowedTransforms)
	if err != nil {
		return opt, err
	}

	opt.MaxSignatures = c.maxSignatures
	if c.idRules != "" {
		if err := readJSONFile(ctx, c.idRules, &opt.AdditionalIDRules); err != nil {
			return opt, err
		}
	}

	if len(c.requiredIDs) > 0 {
		opt.RequiredElements, err = requiredIDElements(ctx, doc, opt, c.requiredIDs)
		if err != nil {
			return opt, err
		}
	}

	switch c.manifests {
	case "none":
	case "recursive", nameRecursiveExternal:
		if c.manifests == nameRecursiveExternal && c.resources == "" {
			return opt, errors.New("external Manifest validation requires -resources")
		}

		opt.Manifests = xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, AllowExternal: c.manifests == nameRecursiveExternal, MaxDepth: c.depth, MaxManifests: c.nodes, MaxReferences: c.references}
	default:
		return opt, errors.New("-manifests must be none, recursive or recursive-external")
	}

	if c.manifestTransforms {
		if opt.Manifests.Mode != xmldsig.ManifestRecursive {
			return opt, usageError("-manifest-transforms requires recursive Manifest mode")
		}

		opt.Manifests.AllowTransformed = true
	}

	if c.resources != "" {
		opt.External, err = coreExternalReferencesContext(ctx, c.resources, c.resourceLimit, c.totalLimit)
		if err != nil {
			return opt, err
		}

		opt.External.BaseURI = c.baseURI
	}

	if c.rootRequired {
		opt.RequiredElements = append(opt.RequiredElements, doc.Root())
	}

	return opt, nil
}

func runCoreEntries(entries []resourceEntry, allowed []string) error {
	for i, e := range entries {
		if e.signingFields || e.Type != "" || e.DigestMethod != "" || e.Transforms != nil {
			return errors.New("core resource allowlist accepts only uri/path, not detached signing options")
		}

		allowed[i] = e.URI
	}

	return nil
}

func coreExternalReferencesContext(ctx context.Context, path string, resourceLimit, totalLimit int) (*xmldsig.ExternalReferences, error) {
	if path == "-" {
		return nil, errors.New("-resources must be a trusted local JSON file")
	}

	entries, resolver, err := loadResourcesContext(ctx, path)
	if err != nil {
		return nil, err
	}

	allowed := make([]string, len(entries))
	if err := runCoreEntries(entries, allowed); err != nil {
		return nil, err
	}

	return &xmldsig.ExternalReferences{Resolver: resolver, AllowedURIs: allowed, Limits: xmldsig.ResourceLimits{MaxResourceBytes: resourceLimit, MaxTotalResourceBytes: totalLimit}}, nil
}

func requiredIDElements(ctx context.Context, doc *document.Document, opt xmldsig.SignatureOptions, ids []string) ([]document.Element, error) {
	attribute := opt.IDAttribute
	if attribute == (document.Name{}) {
		attribute.Local = "ID"
	}

	rules := append([]reference.IDAttributeRule{{Attribute: attribute}}, opt.AdditionalIDRules...)
	rules = append(rules, reference.IDAttributeRule{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{{Space: xmldsig.Namespace, Local: "Object"}, {Space: xmldsig.Namespace, Local: "Manifest"}, {Space: xmldsig.Namespace, Local: "Signature"}, {Space: xmldsig.Namespace, Local: "SignedInfo"}, {Space: xmldsig.Namespace, Local: "Reference"}, {Space: xmldsig.Namespace, Local: "KeyInfo"}, {Space: xmldsig.Namespace, Local: "SignatureValue"}}})

	resolver, err := reference.NewSameDocumentResolverWithRules(ctx, doc, rules)
	if err != nil {
		return nil, err
	}

	out := make([]document.Element, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			return nil, usageError("-require-id must not be empty")
		}

		element, whole, err := resolver.Target(ctx, "#"+id)
		if err != nil {
			return nil, err
		}

		if whole {
			return nil, usageError("-require-id requires an element ID")
		}

		out = append(out, element)
	}

	return out, nil
}

type coreInvocation struct {
	command, key, secret                            string
	index, maxSignatures, resourceLimit, totalLimit int
}

func (c coreInvocation) validate() error {
	if c.key != "" && c.secret != "" {
		return usageError("choose -key or -secret-file")
	}

	if c.command == nameVerifyKeyInfo && c.secret != "" {
		return usageError("KeyInfo verification requires an external public key pin")
	}

	if (c.key == "" && c.secret == "") || c.index < 0 {
		return usageError("an explicit nonnegative -signature-index and -key or -secret-file are required")
	}

	if c.maxSignatures < 1 || c.maxSignatures > 64 {
		return usageError("-max-signatures must be 1..64")
	}

	if c.resourceLimit < 1 || c.resourceLimit > 64<<20 || c.totalLimit < 1 || c.totalLimit > 64<<20 {
		return usageError("resource byte limits must be 1..67108864")
	}

	return nil
}
