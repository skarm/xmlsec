package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
	"github.com/skarm/xmlsec/xmldsig"
)

type executionFlags struct {
	xml                 document.Limits
	output              int
	references          int
	canonical           int
	nodeVisits          int
	transforms          int
	timeout             time.Duration
	policy              string
	methods             string
	digests             string
	programs            string
	minRSABits          int
	maxRSABits          int
	minPSSSalt          int
	maxPSSSalt          int
	minHMACKey          int
	maxHMACKey          int
	minHMACBits         int
	allowHMACTruncation bool
}

func (e *executionFlags) start(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if err := e.xml.Validate(); err != nil {
		return ctx, func() {}, usageError("%v", err)
	}

	if e.output < 1 || e.output > 64<<20 || e.xml.MaxBytes > 64<<20 || e.timeout < 0 || e.references < 1 || e.references > 64 || e.canonical < 1 || e.canonical > 64<<20 || e.nodeVisits < 1 || e.transforms < 1 || e.transforms > 64 {
		return ctx, func() {}, usageError("invalid execution limits (byte limits cannot exceed 64 MiB)")
	}

	if err := e.validateCryptoLimits(); err != nil {
		return ctx, func() {}, err
	}

	if _, err := e.signaturePolicy(false); err != nil {
		return ctx, func() {}, err
	}

	ctx = context.WithValue(ctx, executionKey{}, e)
	if e.timeout > 0 {
		c, cancel := context.WithTimeout(ctx, e.timeout)
		return c, cancel, nil
	}

	return ctx, func() {}, ctx.Err()
}

func (e *executionFlags) signaturePolicy(modern bool) (xmldsig.Policy, error) {
	var p xmldsig.Policy

	switch e.policy {
	case nameDefault:
		p = xmldsig.DefaultPolicy()
		if modern {
			p = xmldsig.ModernPolicy()
		}
	case "modern":
		p = xmldsig.ModernPolicy()
	case "pss":
		p = xmldsig.ParameterizedPolicy()
	case nameHMAC:
		p = xmldsig.HMACPolicy()
	default:
		return p, usageError("-policy must be default, modern, pss or hmac")
	}

	if e.methods != "" {
		p.AllowedSignatureMethods = splitList(e.methods)
	}

	if e.digests != "" {
		p.AllowedDigestMethods = splitList(e.digests)
	}

	p.MinRSABits = e.minRSABits
	p.MaxRSABits = e.maxRSABits
	p.MinPSSSaltBytes = e.minPSSSalt
	p.MaxPSSSaltBytes = e.maxPSSSalt
	p.MinHMACKeyBytes = e.minHMACKey
	p.MaxHMACKeyBytes = e.maxHMACKey
	p.MinHMACOutputBits = e.minHMACBits
	p.AllowHMACTruncation = e.allowHMACTruncation
	p.MaxReferences = e.references
	p.MaxCanonicalBytes = e.canonical

	return p, nil
}

func (e *executionFlags) processing(ctx context.Context, maxResource int, allowed string) (reference.Options, error) {
	opt := reference.Options{MaxInputBytes: max(e.xml.MaxBytes, maxResource), MaxOutputBytes: e.output, MaxProducedBytes: e.output, MaxNodeVisits: e.nodeVisits, MaxTransforms: e.transforms, XMLLimits: e.xml}

	opt.XMLLimits.MaxBytes = opt.MaxInputBytes
	if allowed != "" {
		opt.AllowedTransforms = splitList(allowed)
	}

	if e.programs != "" {
		var programs []reference.Transform
		if err := readJSONFile(ctx, e.programs, &programs); err != nil {
			return opt, err
		}

		if len(programs) == 0 {
			return opt, usageError("-allowed-programs requires 1..64 explicit programs")
		}

		engine, err := transform.NewEngine(transform.Config{AllowedPrograms: programs, Limits: transform.Limits{MaxInputBytes: opt.MaxInputBytes, MaxOutputBytes: e.output, MaxNodes: e.xml.MaxNodes, MaxDepth: e.xml.MaxDepth, MaxOperations: e.nodeVisits}})
		if err != nil {
			return opt, err
		}

		opt.Extension = engine
		if allowed == "" {
			opt.AllowedTransforms = reference.DefaultOptions().AllowedTransforms
			for _, p := range programs {
				opt.AllowedTransforms = append(opt.AllowedTransforms, p.Algorithm)
			}
		}
	}

	return opt, reference.ValidateTransforms(nil, opt)
}

func readInputContext(ctx context.Context, path string, stdin io.Reader, maximum int) (data []byte, err error) {
	err = consumeInput(ctx, path, stdin, maximum, func(r io.Reader) error {
		var readErr error

		data, readErr = io.ReadAll(r)

		return readErr
	})
	if err != nil {
		return nil, err
	}

	return data, nil
}

// consumeInput owns local descriptors through parsing and completion. Consumers
// must read to EOF on success so terminal errors and byte-limit probes are seen.
func consumeInput(ctx context.Context, path string, stdin io.Reader, maximum int, consume func(io.Reader) error) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}

	if maximum < 1 || maximum > 64<<20 {
		return usageError("input byte limit must be 1..67108864")
	}

	r := stdin

	if path != "-" {
		f, err := openRegular(path)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, f.Close()) }()

		r = f
	}

	if r == nil {
		return usageError("stdin is unavailable")
	}
	// Enroll inherited streams in the runtime poller before installing cancellation.
	if file, ok := r.(*os.File); ok {
		stream, cleanup, err := prepareFileIO(file)
		if err != nil {
			return err
		}
		defer cleanup()

		r = stream
	}
	// Cancel the actual descriptor/pipe, never leave a goroutine blocked in Read.
	stop := interruptIO(ctx, r)
	defer stop()

	reader := &streamio.Reader{Context: ctx, Source: r, Limit: int64(maximum), LimitError: fmt.Errorf("input exceeds %d bytes", maximum)}
	err := consume(reader)

	if ce := ctx.Err(); ce != nil {
		return ce
	}

	return err
}

func openRegular(path string) (*os.File, error) {
	stat, err := os.Stat(path) // #nosec G703 -- Only an explicit operator-selected local input is opened.
	if err != nil {
		return nil, err
	}

	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: input must be a regular file; use stdin for streams", path)
	}

	f, err := os.Open(path) // #nosec G304 G703 -- Only an explicit operator-selected local input is opened.
	if err != nil {
		return nil, err
	}

	stat, err = f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		_ = f.Close()

		if err == nil {
			err = errors.New("input must be a regular file")
		}

		return nil, err
	}

	return f, nil
}

func interruptIO(ctx context.Context, v any) func() {
	c, ok := v.(io.Closer)
	if !ok {
		return func() {}
	}

	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = c.Close(); close(done) })

	return func() {
		if !stop() {
			<-done
		}
	}
}

func readJSONFile(ctx context.Context, path string, target any) error {
	if path == "" || path == "-" {
		return usageError("configuration must be a trusted local JSON file")
	}

	raw, err := readInputContext(ctx, path, nil, 4<<20)
	if err != nil {
		return err
	}

	return decodeJSON(raw, target)
}

func decodeJSON(raw []byte, target any) error {
	// encoding/json otherwise accepts duplicate policy keys. Reject them before decoding.
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueJSON(d, 0); err != nil {
		return err
	}

	if _, err := d.Token(); err != io.EOF {
		return errors.New("configuration must contain exactly one JSON value")
	}

	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()

	return d.Decode(target)
}

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 256 {
		return errors.New("JSON nesting exceeds 256")
	}

	t, err := d.Token()
	if err != nil {
		return err
	}

	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := map[string]struct{}{}

		for d.More() {
			t, err := d.Token()
			if err != nil {
				return err
			}

			key, ok := t.(string)
			if !ok {
				return errors.New("invalid JSON key")
			}

			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}

			seen[key] = struct{}{}

			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}

	_, err = d.Token()

	return err
}

func (e *executionFlags) validateCryptoLimits() error {
	if e.minRSABits < 2048 || e.maxRSABits < e.minRSABits || e.maxRSABits > 16384 {
		return usageError("RSA bounds require 2048 <= min <= max <= 16384")
	}

	if e.minPSSSalt < 0 || e.maxPSSSalt < e.minPSSSalt || e.maxPSSSalt > 2048 {
		return usageError("invalid PSS salt limits")
	}

	if e.minHMACKey < 32 || e.maxHMACKey < e.minHMACKey || e.maxHMACKey > 1<<20 {
		return usageError("invalid HMAC key bounds")
	}

	if e.minHMACBits < 128 || e.minHMACBits > 512 || e.minHMACBits%8 != 0 {
		return usageError("HMAC output floor must be 128..512 bits in multiples of 8")
	}

	return nil
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	return parts
}

type executionKey struct{}

func registerExecutionFlags(fs *flag.FlagSet) *executionFlags {
	e := &executionFlags{xml: document.DefaultLimits()}
	fs.IntVar(&e.xml.MaxBytes, "max-input-bytes", e.xml.MaxBytes, "maximum main input and transform input bytes")
	fs.IntVar(&e.xml.MaxDepth, "max-depth", e.xml.MaxDepth, "maximum XML nesting depth (1..512)")
	fs.IntVar(&e.xml.MaxNodes, "max-nodes", e.xml.MaxNodes, "maximum parsed XML nodes")
	fs.IntVar(&e.xml.MaxAttributesPerElement, "max-attributes", e.xml.MaxAttributesPerElement, "maximum attributes/namespaces per XML element")
	fs.IntVar(&e.xml.MaxNodeSetNodes, "max-nodeset-nodes", e.xml.MaxNodeSetNodes, "maximum expanded node-set nodes")
	fs.IntVar(&e.xml.MaxInScopeNamespaces, "max-namespaces", e.xml.MaxInScopeNamespaces, "maximum in-scope namespaces")
	fs.IntVar(&e.output, "max-output-bytes", 32<<20, "maximum output and transform output bytes")
	fs.IntVar(&e.references, "max-references", 16, "maximum direct signature references (1..64)")
	fs.IntVar(&e.canonical, "max-canonical-bytes", 32<<20, "aggregate signature digest/canonical byte budget")
	fs.IntVar(&e.nodeVisits, "max-node-visits", 2_000_000, "aggregate signature transform node visits")
	fs.IntVar(&e.transforms, "max-transforms", 8, "maximum transforms per reference (1..64)")
	fs.DurationVar(&e.timeout, "timeout", 0, "operation deadline, e.g. 30s; 0 has no deadline")
	fs.StringVar(&e.policy, "policy", nameDefault, "signature policy: default, modern, pss or hmac (explicit shared secret)")
	fs.StringVar(&e.methods, "allowed-methods", "", "comma-separated signature method allowlist; overrides selected policy")
	fs.StringVar(&e.digests, "allowed-digests", "", "comma-separated digest method allowlist")
	fs.StringVar(&e.programs, "allowed-programs", "", "trusted local JSON array of exact approved XPath/Filter2/XSLT transforms")
	fs.IntVar(&e.minRSABits, "min-rsa-bits", 2048, "minimum RSA modulus size")
	fs.IntVar(&e.maxRSABits, "max-rsa-bits", 8192, "maximum RSA modulus size (up to 16384)")
	fs.IntVar(&e.minPSSSalt, "min-pss-salt-bytes", 0, "minimum generic RSA-PSS salt length")
	fs.IntVar(&e.maxPSSSalt, "max-pss-salt-bytes", 1024, "maximum generic RSA-PSS salt length")
	fs.IntVar(&e.minHMACKey, "min-hmac-key-bytes", 32, "minimum HMAC key bytes")
	fs.IntVar(&e.maxHMACKey, "max-hmac-key-bytes", 4096, "maximum HMAC key bytes")
	fs.IntVar(&e.minHMACBits, "min-hmac-output-bits", 128, "minimum explicitly permitted HMAC tag size")
	fs.BoolVar(&e.allowHMACTruncation, "allow-hmac-truncation", false, "explicitly allow bounded truncated HMAC tags")

	return e
}

func execution(ctx context.Context) *executionFlags {
	if e, ok := ctx.Value(executionKey{}).(*executionFlags); ok {
		return e
	}

	return &executionFlags{xml: document.DefaultLimits(), output: 32 << 20, references: 16, canonical: 32 << 20, nodeVisits: 2_000_000, transforms: 8, policy: nameDefault}
}

func writeOutputContext(ctx context.Context, path string, w io.Writer, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if len(b) > execution(ctx).output {
		return fmt.Errorf("output exceeds %d bytes", execution(ctx).output)
	}

	if path == "-" {
		if file, ok := w.(*os.File); ok {
			stream, cleanup, err := prepareFileIO(file)
			if err != nil {
				return err
			}
			defer cleanup()

			w = stream
		}

		stop := interruptIO(ctx, w)
		defer stop()
	}

	err := writeAtomicOutput(ctx, path, w, b)
	if ce := ctx.Err(); ce != nil {
		return ce
	}

	return err
}

func parseFlags(fs *flag.FlagSet, args []string) (bool, error) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return true, nil
		}

		return false, usageError("%v", err)
	}

	if fs.NArg() != 0 {
		return false, usageError("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	return false, nil
}

func parseHash(s string) (crypto.Hash, error) {
	switch strings.ToLower(s) {
	case "sha256", "sha-256":
		return crypto.SHA256, nil
	case "sha384", "sha-384":
		return crypto.SHA384, nil
	case "sha512", "sha-512":
		return crypto.SHA512, nil
	}

	return 0, usageError("hash must be sha256, sha384 or sha512")
}

func jsonOutput(ctx context.Context, path string, w io.Writer, v any) error {
	if path == "-" {
		return produceOutput(ctx, path, w, func(dst io.Writer) error { return writeJSON(dst, v) })
	}

	// encoding/json already stages one complete value. Another disk buffer
	// adds fixed storage without combining any of its writes.
	limit := execution(ctx).output

	err := writeAtomicOutputFunc(ctx, path, w, func(dst io.Writer) error {
		return writeJSON(&streamio.Writer{Context: ctx, Target: dst, Limit: int64(limit), LimitError: fmt.Errorf("output exceeds %d bytes", limit)}, v)
	})
	if ce := ctx.Err(); ce != nil {
		return ce
	}

	return err
}

func readDocument(ctx context.Context, path string, stdin io.Reader) (doc *document.Document, err error) {
	err = consumeInput(ctx, path, stdin, execution(ctx).xml.MaxBytes, func(r io.Reader) error {
		var parseErr error

		doc, parseErr = document.ParseReader(ctx, r, execution(ctx).xml)

		return parseErr
	})
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// produceOutput streams local output to the same-directory temporary file.
// Stdout is collected first so serialization errors cannot publish a prefix.
func produceOutput(ctx context.Context, path string, w io.Writer, produce func(io.Writer) error) error {
	limit := execution(ctx).output
	limitErr := fmt.Errorf("output exceeds %d bytes", limit)

	if path == "-" {
		var output bytes.Buffer
		if err := produce(&streamio.Writer{Context: ctx, Target: &output, Limit: int64(limit), LimitError: limitErr}); err != nil {
			return err
		}

		return writeOutputContext(ctx, path, w, output.Bytes())
	}

	err := writeAtomicOutputFunc(ctx, path, w, func(target io.Writer) error {
		// Serializers emit short markup and 4 KiB escaped text fragments. Batch
		// disk writes without collecting the complete serialized document.
		buffered := bufio.NewWriterSize(target, 32<<10)
		if err := produce(&streamio.Writer{Context: ctx, Target: buffered, Limit: int64(limit), LimitError: limitErr}); err != nil {
			return err
		}

		return buffered.Flush()
	})
	if ce := ctx.Err(); ce != nil {
		return ce
	}

	return err
}

func documentOutput(ctx context.Context, path string, w io.Writer, doc *document.Document) error {
	return produceOutput(ctx, path, w, func(target io.Writer) error {
		_, err := doc.WriteXML(ctx, target, execution(ctx).output)
		return err
	})
}
