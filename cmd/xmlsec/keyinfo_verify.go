package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"io"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/xmldsig"
)

func verifyWithKeyInfoCLI(ctx context.Context, doc *document.Document, selected document.Element, key crypto.PublicKey, opt xmldsig.SignatureOptions, configFile, resourcesFile, baseURI, output string, stdout io.Writer) error {
	if baseURI != "" && resourcesFile == "" {
		return usageError("-keyinfo-base-uri requires -keyinfo-resources")
	}

	pin, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}

	keyOptions := keyinfo.Options{}
	if configFile != "" {
		if err := readJSONFile(ctx, configFile, &keyOptions); err != nil {
			return err
		}

		if keyOptions.External != nil {
			return usageError("external KeyInfo access must use -keyinfo-resources")
		}
	}

	if resourcesFile != "" {
		entries, resolver, err := loadResourcesContext(ctx, resourcesFile)
		if err != nil {
			return err
		}

		if err := validateResourceAllowlist(entries); err != nil {
			return err
		}

		keyOptions.External = &keyinfo.ExternalResources{Resolver: resolver, AllowedURIs: detachedResourceURIs(entries), BaseURI: baseURI}
	}

	if keyOptions.RetrievalProcessing != nil {
		// Retrieval remains a separate explicit opt-in and transform allowlist.
		// Approved programs come only from the trusted global CLI configuration.
		keyOptions.RetrievalProcessing.Extension = opt.Processing.Extension
	}

	selector := func(ctx context.Context, result *keyinfo.Result) (int, error) {
		if err := ctx.Err(); err != nil {
			return -1, err
		}

		for i, candidate := range result.Candidates() {
			if bytes.Equal(pin, candidate.SPKI()) {
				return i, nil
			}
		}

		return -1, xmldsig.ErrKeyInfoTrust
	}
	result, verifyErr := xmldsig.VerifySignatureWithKeyInfo(ctx, doc, selected, xmldsig.KeyInfoVerifyOptions{Signature: opt, KeyInfo: keyOptions, SelectTrustedKey: selector})

	var details any
	if verifyErr == nil {
		details = map[string]any{"key_fingerprint_sha256": result.KeyFingerprintSHA256(), "reference_count": len(result.References()), "root_covered": result.CoversElement(doc.Root()), "keyinfo_declarations_checked": true}
	}

	return errors.Join(verifyErr, jsonOutput(ctx, output, stdout, resultReport("signature verify-keyinfo", "externally-pinned-keyinfo-candidate", details, verifyErr)))
}
