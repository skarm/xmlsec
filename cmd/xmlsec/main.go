package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmldsig"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() { <-ctx.Done(); stop() }() // A second signal regains its terminating behavior.

	jsonErrors := len(os.Args) > 1 && os.Args[1] == jsonErrorsFlag

	var diagnostics bytes.Buffer

	stderr := io.Writer(os.Stderr)
	if jsonErrors {
		stderr = &diagnostics
	}

	err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, stderr)

	stop()

	if err != nil {
		if jsonErrors {
			report := map[string]any{"schema_version": 1, fieldStatus: "error", "error": err.Error(), "exit_code": exitCode(err)}
			if diagnostics.Len() > 0 {
				report["diagnostics"] = diagnostics.String()
			}

			_ = writeJSON(os.Stderr, report)
		} else {
			_, _ = fmt.Fprintln(os.Stderr, "xmlsec:", err)
		}

		os.Exit(exitCode(err))
	}

	if jsonErrors && diagnostics.Len() > 0 {
		_, _ = os.Stderr.Write(diagnostics.Bytes())
	}
}

func runXML(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := args[0]

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)
	input := fs.String("in", "-", "input XML file; - reads stdin")
	output := fs.String("out", "-", "output file; - writes stdout")
	idAttr := fs.String("id-attr", "ID", "ID attribute local name (not guessed)")
	idNS := fs.String("id-ns", "", "ID attribute namespace URI")
	modern := fs.Bool("modern-algorithms", false, "also permit fixed RSA-PSS, Ed25519 and Ed25519ph")

	var (
		xpathExpression                        string
		xpathNamespaces                        repeatedFlag
		keyFile, method, digest, refs          string
		inclusive, selectID, rootLocal, rootNS string
		comments                               bool
		canonicalAlgorithm                     string
		keyFlags                               *privateKeyFlags
	)

	switch cmd {
	case nameSign:
		keyFlags = registerPrivateKeyFlags(fs)
		fs.StringVar(&keyFile, "key", "", "private key file; -key-format selects plain, encrypted PKCS#8 or PKCS#12")
		fs.StringVar(&method, "method", "", "signature method URI; default selected from key type")
		fs.StringVar(&digest, "digest", xmldsig.SHA256, "reference digest method URI")
		fs.StringVar(&refs, "refs", "", "comma-separated reference IDs; default root ID")
		fs.StringVar(&inclusive, "inclusive-prefixes", "", "space-separated inclusive namespace prefixes")
	case nameVerify:
		fs.StringVar(&keyFile, "key", "", "externally trusted public key or pinned certificate, PEM/DER")
		fs.StringVar(&rootLocal, "root-local", "", "expected root local name")
		fs.StringVar(&rootNS, "root-ns", "", "expected root namespace URI")
	case nameC14n:
		fs.StringVar(&xpathExpression, nameXPath, "", "XPath 1.0 node-set filter (evaluated for each node)")
		fs.Var(&xpathNamespaces, "namespace", "PREFIX=URI for -xpath; repeatable")
		fs.StringVar(&canonicalAlgorithm, "algorithm", c14n.Exclusive, "canonicalization URI: Exclusive, C14N 1.0 or C14N 1.1")
		fs.BoolVar(&comments, "comments", false, "include comments")
		fs.StringVar(&inclusive, "inclusive-prefixes", "", "space-separated inclusive namespace prefixes")
		fs.StringVar(&selectID, "id", "", "canonicalize the unique element with this ID; default whole document")
	}

	if cmd == nameC14n {
		fs = commandFlags(fs, "in out id-attr id-ns algorithm comments inclusive-prefixes id xpath namespace max-node-visits", false)
	} else {
		fs = withoutFlags(fs, "allowed-programs max-node-visits max-transforms")
	}

	if done, err := parseFlags(fs, args[1:]); done || err != nil {
		return err
	}

	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}

	if cmd != nameC14n && keyFile == "" {
		return usageError("-key is required")
	}

	ctx, cancel, err := exec.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	var (
		signer crypto.Signer
		public crypto.PublicKey
	)

	switch cmd {
	case nameSign:
		signer, err = loadPrivateConfigured(ctx, keyFile, keyFlags)
	case nameVerify:
		public, err = loadPublicContext(ctx, keyFile)
	}

	if err != nil {
		return err
	}

	doc, err := readDocument(ctx, *input, stdin)
	if err != nil {
		return err
	}

	idName := document.Name{Space: *idNS, Local: *idAttr}

	var out []byte

	switch cmd {
	case nameC14n:
		opt := c14n.Options{MaxOutputBytes: exec.output, Algorithm: canonicalAlgorithm, WithComments: comments, InclusivePrefixes: strings.Fields(inclusive)}

		return produceOutput(ctx, *output, stdout, func(w io.Writer) error {
			return canonicalizeSelection(ctx, w, doc, idName, selectID, xpathExpression, xpathNamespaces, opt)
		})

	case nameSign:
		opt := xmldsig.SignOptions{IDAttribute: idName, SignatureMethod: method, DigestMethod: digest, InclusivePrefixes: strings.Fields(inclusive)}

		opt.Policy, err = exec.signaturePolicy(*modern)
		if err != nil {
			return err
		}

		if refs != "" {
			opt.ReferenceIDs = strings.Split(refs, ",")
		}

		signed, err := xmldsig.SignEnveloped(ctx, doc, signer, opt)
		if err != nil {
			return err
		}

		return documentOutput(ctx, *output, stdout, signed)

	case nameVerify:
		out, err = verifyCLI(ctx, doc, public, idName, document.Name{Space: rootNS, Local: rootLocal}, *modern)
		if err != nil {
			if len(out) == 0 {
				return err
			}

			return errors.Join(err, writeOutputContext(ctx, *output, stdout, out))
		}
	}

	return writeOutputContext(ctx, *output, stdout, out)
}

func writeAtomicOutput(ctx context.Context, path string, w io.Writer, b []byte) error {
	return writeAtomicOutputFunc(ctx, path, w, func(target io.Writer) error {
		n, err := target.Write(b)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}

		return err
	})
}

func writeAtomicOutputFunc(ctx context.Context, path string, w io.Writer, produce func(io.Writer) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if path == "-" {
		return produce(w)
	}
	// Same-directory temporary output; rename atomicity depends on the OS.
	parent, _ := filepath.Split(path)
	if parent == "" {
		parent = "."
	}

	f, err := os.CreateTemp(parent, ".xmlsec-*") // #nosec G703 -- The operator selects the CLI output directory.
	if err != nil {
		return err
	}

	temp := f.Name()
	defer func() { _ = os.Remove(temp) }() // #nosec G703 -- Remove only the uncommitted file created by CreateTemp.

	stopWrite := interruptIO(ctx, f)
	defer stopWrite()

	if err := errors.Join(produce(f), f.Close()); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return os.Rename(temp, path) // #nosec G703 -- The operator selects the CLI output path.
}

func canonicalizeCLI(ctx context.Context, w io.Writer, doc *document.Document, idName document.Name, selectID string, opt c14n.Options) error {
	var err error

	if selectID == "" {
		err = c14n.WriteDocument(ctx, w, doc, opt)
	} else {
		var target document.Element

		count := 0

		var walk func(document.Element)

		walk = func(e document.Element) {
			if v, ok := e.Attribute(idName); ok && v == selectID {
				target = e
				count++
			}

			for _, child := range e.Children() {
				walk(child)
			}
		}
		walk(doc.Root())

		if count != 1 {
			return fmt.Errorf("ID must match exactly one element; found %d", count)
		}

		err = c14n.WriteElement(ctx, w, target, opt)
	}

	return err
}

func verifyCLI(ctx context.Context, doc *document.Document, key crypto.PublicKey, idName, expectedRoot document.Name, modern bool) ([]byte, error) {
	rootNS, rootLocal := expectedRoot.Space, expectedRoot.Local

	if rootNS != "" && rootLocal == "" {
		return nil, errors.New("-root-ns requires -root-local")
	}

	policy, err := execution(ctx).signaturePolicy(modern)
	if err != nil {
		return nil, err
	}

	result, err := xmldsig.Verify(ctx, doc, key, xmldsig.VerifyOptions{Policy: policy, IDAttribute: idName, ExpectedRoot: document.Name{Space: rootNS, Local: rootLocal}})
	if err != nil {
		raw, marshalErr := json.MarshalIndent(resultReport("signature verify", "externally-supplied-key", nil, err), "", "  ")
		if marshalErr != nil {
			return nil, errors.Join(err, marshalErr)
		}

		return append(raw, '\n'), err
	}

	uris := make([]string, 0, len(result.References()))
	for _, r := range result.References() {
		uris = append(uris, r.URI())
	}

	report := struct {
		Status          string   `json:"status"`
		Profile         string   `json:"profile"`
		Trust           string   `json:"trust"`
		SignatureMethod string   `json:"signature_method"`
		KeyFingerprint  string   `json:"key_fingerprint_sha256"`
		References      []string `json:"references"`
	}{statusValid, "root-enveloped-v0", "externally-supplied-key", result.SignatureMethod(), result.KeyFingerprintSHA256(), uris}

	out, err := json.MarshalIndent(resultReport("signature verify", "externally-supplied-key", report, nil), "", "  ")
	if err != nil {
		return nil, err
	}

	return append(out, '\n'), nil
}

func canonicalizeSelection(ctx context.Context, w io.Writer, doc *document.Document, idName document.Name, selectID, xpathExpression string, xpathNamespaces repeatedFlag, opt c14n.Options) error {
	if xpathExpression == "" {
		return canonicalizeCLI(ctx, w, doc, idName, selectID, opt)
	}

	if selectID != "" {
		return usageError("choose -xpath or -id")
	}

	ns, err := namespaces(xpathNamespaces)
	if err != nil {
		return err
	}

	if opt.WithComments {
		switch opt.Algorithm {
		case c14n.Exclusive:
			opt.Algorithm = c14n.ExclusiveWithComments
		case c14n.Canonical10:
			opt.Algorithm = c14n.Canonical10WithComments
		case c14n.Canonical11:
			opt.Algorithm = c14n.Canonical11WithComments
		}
	}

	return canonicalizeXPath(ctx, w, doc, xpathExpression, ns, opt)
}
