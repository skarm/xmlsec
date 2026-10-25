package main

import (
	"context"
	"flag"
	"io"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/keyinfo"
)

func runKeyInfo(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := args[0]
	fs := flag.NewFlagSet("keyinfo "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)
	input := fs.String("in", "-", "XML input for inspect")
	output := fs.String("out", "-", "output XML or diagnostic JSON")
	id := fs.String("id", "", "KeyInfo Id (build) or exact selection ID (inspect)")
	index := fs.Int("index", -1, "explicit zero-based KeyInfo index")
	format := fs.String("format", "der", "public key representation: der or xml")
	resources := fs.String("resources", "", "separate trusted URI/path allowlist for external KeyInfo retrieval")
	configFile := fs.String("config", "", "trusted JSON keyinfo.Options for inspection limits, ID rules and allowed representations")
	baseURI := fs.String("base-uri", "", "explicit KeyInfo document base URI; requires -resources")

	var names, keys, certs, refs repeatedFlag
	fs.Var(&names, "name", "KeyName hint; repeatable")
	fs.Var(&keys, "key", "public key file; repeatable")
	fs.Var(&certs, "certificate", "certificate file; repeatable")
	fs.Var(&refs, "reference", "KeyInfoReference URI; repeatable")

	specific := "in out id index resources config base-uri"
	if cmd == "build" {
		specific = "out id format name key certificate reference"
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

	if cmd == "build" {
		return buildKeyInfoCLI(ctx, stdout, *output, keyinfo.Template{ID: *id, Names: names, KeyInfoReferences: refs}, keys, certs, *format)
	}

	if *index < -1 {
		return usageError("-index must be nonnegative when supplied")
	}

	doc, err := readDocument(ctx, *input, stdin)
	if err != nil {
		return err
	}

	selected, err := selectElement(doc, document.Name{Local: "Id"}, *id, *index, document.Name{Space: keyinfo.Namespace, Local: "KeyInfo"})
	if err != nil {
		return err
	}

	opt, err := inspectionKeyInfoOptions(ctx, exec, *configFile, *resources, *baseURI)
	if err != nil {
		return err
	}

	result, err := keyinfo.Parse(ctx, doc, selected, opt)
	if err != nil {
		return err
	}

	type candidate struct {
		Index       int           `json:"index"`
		Kind        document.Name `json:"kind"`
		Fingerprint string        `json:"spki_sha256"`
		Resource    string        `json:"resource_uri,omitempty"`
		Certificate any           `json:"certificate,omitempty"`
	}

	var candidates []candidate

	for i, c := range result.Candidates() {
		v := candidate{Index: i, Kind: c.Kind(), Fingerprint: c.FingerprintSHA256(), Resource: c.ResourceURI()}
		if len(c.CertificateDER()) > 0 {
			cert, err := c.Certificate()
			if err != nil {
				return err
			}

			v.Certificate = certificateDescription(cert)
		}

		candidates = append(candidates, v)
	}

	return jsonOutput(ctx, *output, stdout, map[string]any{fieldStatus: statusUnverified, "key_names": result.KeyNames(), "candidates": candidates, "x509_groups": len(result.X509Groups()), "external_uris": result.ExternalURIs()})
}

func inspectionKeyInfoOptions(ctx context.Context, exec *executionFlags, configFile, resources, baseURI string) (keyinfo.Options, error) {
	opt := keyinfo.Options{}
	if baseURI != "" && resources == "" {
		return opt, usageError("-base-uri requires -resources")
	}

	if configFile != "" {
		if err := readJSONFile(ctx, configFile, &opt); err != nil {
			return opt, err
		}

		if opt.External != nil {
			return opt, usageError("external KeyInfo access must use -resources")
		}
	}

	if resources != "" {
		entries, resolver, err := loadResourcesContext(ctx, resources)
		if err != nil {
			return opt, err
		}

		if err := validateResourceAllowlist(entries); err != nil {
			return opt, err
		}

		opt.External = &keyinfo.ExternalResources{AllowedURIs: detachedResourceURIs(entries), Resolver: resolver, BaseURI: baseURI}
	}

	if opt.RetrievalProcessing != nil && exec.programs != "" {
		processing, err := exec.processing(ctx, 0, "")
		if err != nil {
			return opt, err
		}

		opt.RetrievalProcessing.Extension = processing.Extension
	}

	return opt, nil
}

func buildKeyInfoCLI(ctx context.Context, stdout io.Writer, output string, spec keyinfo.Template, keys, certs []string, format string) error {
	if format != "der" && format != "xml" {
		return usageError("-format must be der or xml")
	}

	for _, path := range keys {
		key, err := loadPublicContext(ctx, path)
		if err != nil {
			return err
		}

		spec.Keys = append(spec.Keys, keyinfo.PublicKeyValue{Key: key, Format: keyinfo.KeyFormat(format)})
	}

	var err error

	spec.Certificates, err = readCertificates(ctx, "", certs)
	if err != nil {
		return err
	}

	doc, err := keyinfo.Build(ctx, spec)
	if err != nil {
		return err
	}

	return documentOutput(ctx, output, stdout, doc)
}
