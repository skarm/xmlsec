package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"path/filepath"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
	"github.com/skarm/xmlsec/xmlenc"
)

func selectElement(doc *document.Document, idName document.Name, id string, index int, name document.Name) (document.Element, error) {
	if idName.Local == "" {
		idName.Local = "ID"
	}

	var (
		found []document.Element
		walk  func(document.Element)
	)

	walk = func(e document.Element) {
		matches := name == (document.Name{}) || e.Name() == name
		if id != "" {
			v, ok := e.Attribute(idName)
			matches = matches && ok && v == id
		}

		if matches {
			found = append(found, e)
		}

		for _, c := range e.Children() {
			walk(c)
		}
	}
	walk(doc.Root())

	if index >= 0 {
		if id != "" {
			return document.Element{}, usageError("choose -id or -index")
		}

		if index >= len(found) {
			return document.Element{}, usageError("element index %d out of range (%d matches)", index, len(found))
		}

		return found[index], nil
	}

	if len(found) != 1 {
		return document.Element{}, usageError("selection must match exactly one element; found %d (use an ID or explicit index)", len(found))
	}

	return found[0], nil
}

func runCoreHMAC(ctx context.Context, cmd string, doc *document.Document, selected document.Element, secretFile string, preserve repeatedFlag, opt xmldsig.SignatureOptions, output string, stdout io.Writer) error {
	if execution(ctx).policy != nameHMAC {
		return usageError("-secret-file requires -policy hmac")
	}

	if len(preserve) != 0 {
		return usageError("HMAC preservation entries use a separate trust model and are not accepted by -preserve")
	}

	secret, err := readInputContext(ctx, secretFile, nil, 1<<20)
	if err != nil {
		return err
	}
	defer clear(secret)

	if cmd == nameSignTemplate {
		signed, err := xmldsig.SignHMACTemplate(ctx, doc, selected, secret, xmldsig.TemplateSignOptions{Validation: opt})
		if err != nil {
			return err
		}

		return documentOutput(ctx, output, stdout, signed)
	}

	_, report, verifyErr := xmldsig.VerifyHMACSignatureDetailed(ctx, doc, selected, secret, opt)

	return errors.Join(verifyErr, jsonOutput(ctx, output, stdout, resultReport("signature verify-core", "shared-secret", report, verifyErr)))
}

type templateObject struct {
	ID         string                    `json:"id"`
	MIMEType   string                    `json:"mime_type,omitempty"`
	XMLFile    string                    `json:"xml_file,omitempty"`
	BinaryFile string                    `json:"binary_file,omitempty"`
	Text       *string                   `json:"text,omitempty"`
	Manifest   *xmldsig.ManifestTemplate `json:"manifest,omitempty"`
}

type templateConfig struct {
	ID               string                      `json:"id,omitempty"`
	Method           string                      `json:"method"`
	Canonicalization reference.Transform         `json:"canonicalization"`
	Parameters       templateParameters          `json:"parameters"`
	References       []xmldsig.ReferenceTemplate `json:"references"`
	Objects          []templateObject            `json:"objects,omitempty"`
	Certificates     []string                    `json:"certificates,omitempty"`
	KeyInfoFile      string                      `json:"keyinfo_file,omitempty"`
}

func runSignatureBuild(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("signature build", flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)
	config := fs.String("config", "", "trusted JSON template specification (paths relative to its directory)")
	input := fs.String("in", "", "existing XML document; empty creates a standalone Signature")
	out := fs.String("out", "-", "output template XML")
	parentID := fs.String("parent-id", "", "explicit parent ID; empty selects root")
	idAttr := fs.String("id-attr", "ID", "application ID attribute local name")
	idNS := fs.String("id-ns", "", "application ID namespace")

	fs = commandFlags(fs, "config in out parent-id id-attr id-ns", false)

	done, err := parseFlags(fs, args[1:])
	if done || err != nil {
		return err
	}

	ctx, cancel, err := exec.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	var cfg templateConfig
	if err := readJSONFile(ctx, *config, &cfg); err != nil {
		return err
	}

	base := filepath.Dir(*config)

	parameters, err := cfg.Parameters.library()
	if err != nil {
		return err
	}

	spec := xmldsig.SignatureTemplate{ID: cfg.ID, SignatureMethod: cfg.Method, SignatureParameters: parameters, Canonicalization: cfg.Canonicalization, References: cfg.References, XMLLimits: exec.xml}
	for _, o := range cfg.Objects {
		obj := xmldsig.ObjectTemplate{ID: o.ID, MIMEType: o.MIMEType, Text: o.Text, Manifest: o.Manifest}
		if o.XMLFile != "" {
			obj.XML, err = readDocument(ctx, localPath(base, o.XMLFile), nil)
		}

		if err != nil {
			return err
		}

		if o.BinaryFile != "" {
			obj.Binary, err = readInputContext(ctx, localPath(base, o.BinaryFile), nil, exec.xml.MaxBytes)
		}

		if err != nil {
			return err
		}

		spec.Objects = append(spec.Objects, obj)
	}

	spec.Certificates, err = readCertificates(ctx, base, cfg.Certificates)
	if err != nil {
		return err
	}

	if cfg.KeyInfoFile != "" {
		spec.KeyInfo, err = readDocument(ctx, localPath(base, cfg.KeyInfoFile), nil)
		if err != nil {
			return err
		}
	}

	var (
		doc    *document.Document
		parent document.Element
	)

	if *input != "" {
		doc, err = readDocument(ctx, *input, stdin)
		if err != nil {
			return err
		}

		parent = doc.Root()
		if *parentID != "" {
			parent, err = selectElement(doc, document.Name{Space: *idNS, Local: *idAttr}, *parentID, -1, document.Name{})
			if err != nil {
				return err
			}
		}
	} else if *parentID != "" {
		return usageError("-parent-id requires -in")
	}

	if doc != nil {
		spec.XMLLimits = document.Limits{}
	}

	result, _, err := xmldsig.BuildTemplate(ctx, doc, parent, spec)
	if err != nil {
		return err
	}

	return documentOutput(ctx, *out, stdout, result)
}

func localPath(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}

	return filepath.Join(base, path)
}

func runInspect(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("signature inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)
	input := fs.String("in", "-", "input XML")
	out := fs.String("out", "-", "diagnostic JSON")

	fs = commandFlags(fs, "in out", false)

	done, err := parseFlags(fs, args[1:])
	if done || err != nil {
		return err
	}

	ctx, cancel, err := exec.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	doc, err := readDocument(ctx, *input, stdin)
	if err != nil {
		return err
	}

	type signature struct {
		Index            int      `json:"index"`
		ID               string   `json:"id,omitempty"`
		Method           string   `json:"method,omitempty"`
		Canonicalization string   `json:"canonicalization,omitempty"`
		References       []string `json:"references"`
	}

	var signatures []signature

	for i, sig := range xmldsig.Signatures(doc) {
		v := signature{Index: i, References: []string{}}

		v.ID, _ = sig.Attribute(document.Name{Local: "Id"})
		for _, si := range sig.Children() {
			if si.Name() != (document.Name{Space: xmldsig.Namespace, Local: "SignedInfo"}) {
				continue
			}

			for _, n := range si.Children() {
				switch n.Name().Local {
				case "SignatureMethod":
					v.Method, _ = n.Attribute(document.Name{Local: "Algorithm"})
				case "CanonicalizationMethod":
					v.Canonicalization, _ = n.Attribute(document.Name{Local: "Algorithm"})
				case "Reference":
					u, _ := n.Attribute(document.Name{Local: "URI"})
					v.References = append(v.References, u)
				}
			}
		}

		signatures = append(signatures, v)
	}

	return jsonOutput(ctx, *out, stdout, map[string]any{fieldStatus: statusUnverified, "root": doc.Root().Name(), "signatures": signatures})
}

func algorithmInfo() any {
	return map[string]any{"signature_policies": map[string]any{nameDefault: xmldsig.DefaultPolicy().AllowedSignatureMethods, "modern": xmldsig.ModernPolicy().AllowedSignatureMethods, "pss": xmldsig.ParameterizedPolicy().AllowedSignatureMethods, nameHMAC: xmldsig.HMACPolicy().AllowedSignatureMethods}, "digests": xmldsig.DefaultPolicy().AllowedDigestMethods, "canonicalization": []string{c14n.Exclusive, c14n.ExclusiveWithComments, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments}, "transforms": append(reference.DefaultOptions().AllowedTransforms, reference.XPath, reference.XPathFilter2, reference.XSLT), nameEncryption: []string{xmlenc.AES128GCM, xmlenc.AES192GCM, xmlenc.AES256GCM, xmlenc.RSAOAEP, xmlenc.AES128KeyWrap, xmlenc.AES192KeyWrap, xmlenc.AES256KeyWrap}, nameXPath: []string{version10, version20, version30, version31}, nameXSLT: []string{version10, "2.0-basic", "3.0-basic"}}
}

func fingerprint(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func resultReport(operation, trust string, detail any, err error) map[string]any {
	status := statusValid
	if err != nil {
		status = "invalid"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			status = "indeterminate"
		}
	}

	v := map[string]any{"schema_version": 1, fieldStatus: status, "operation": operation, "trust": trust}
	if detail != nil {
		v["details"] = detail
	}

	if err != nil {
		v["error"] = err.Error()
	}

	return v
}

func requiredFlag(name, value string) error {
	if value == "" {
		return usageError("-%s is required", name)
	}

	return nil
}

func separateOutput(path, report, flagName string) error {
	if path == "-" || report != "-" && samePath(path, report) {
		return usageError("-%s requires a local file distinct from report output", flagName)
	}

	return nil
}

type templatePSS struct {
	Hash       string `json:"hash"`
	MGFHash    string `json:"mgf_hash"`
	SaltLength int    `json:"salt_length"`
}

type templateParameters struct {
	PSS              *templatePSS `json:"pss,omitempty"`
	HMACOutputLength int          `json:"hmac_output_bits,omitempty"`
}

func (p templateParameters) library() (xmldsig.SignatureParameters, error) {
	opt := xmldsig.SignatureParameters{HMACOutputLength: p.HMACOutputLength}
	if p.PSS != nil {
		hash, err := parseHash(p.PSS.Hash)
		if err != nil {
			return opt, err
		}

		mgf, err := parseHash(p.PSS.MGFHash)
		if err != nil {
			return opt, err
		}

		opt.PSS = &xmldsig.PSSParameters{Hash: hash, MGFHash: mgf, SaltLength: p.PSS.SaltLength}
	}

	return opt, nil
}
