package xdm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/skarm/xmlsec/internal/tree"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
)

// ParseOptions configures XML-to-XDM construction through internal/tree.
// DTD resources can only use the explicitly supplied invocation opener.
type ParseOptions struct {
	// Limits bounds the XML tree and parser work. A zero MaxBytes selects the complete
	// default limits.
	Limits tree.Limits
	// BaseURI supplies the retrieval base retained by the resulting document view.
	BaseURI string
	// AllowSingleByteEncodings permits supported ASCII-compatible single-byte XML byte
	// encodings.
	AllowSingleByteEncodings bool
	// AllowRelativeNamespaces permits deprecated relative namespace names and preserves
	// their literal spelling.
	AllowRelativeNamespaces bool
	// AllowDTD enables bounded nonvalidating DTD processing. False retains the DTD-free
	// security profile.
	AllowDTD bool
	// DTDOpen opens explicitly authorized external DTD or entity URIs. Nil supplies no
	// external entity resolver.
	DTDOpen func(context.Context, string) (io.ReadCloser, error)
}

// WithByteLimit intersects a resource byte cap with the XML input limit.
func (o ParseOptions) WithByteLimit(maxBytes int64) ParseOptions {
	limits := o.limits()
	if maxBytes > 0 && maxBytes < int64(limits.MaxBytes) {
		limits.MaxBytes = int(maxBytes)
	}

	o.Limits = limits

	return o
}

// Parse creates XDM nodes over the project parser's document storage.
func (o ParseOptions) Parse(ctx context.Context, data []byte) (*Document, error) {
	return o.ParseReader(ctx, bytes.NewReader(data))
}

// ParseText parses already decoded XML characters; the declaration's encoding
// does not reinterpret them. The parser still checks the declaration grammar.
func (o ParseOptions) ParseText(ctx context.Context, text string) (*Document, error) {
	d, err := o.parserOptions().ParseText(ctx, text)
	if err != nil {
		return nil, err
	}

	return o.wrapDocument(ctx, d)
}

// ParseReader incrementally constructs XDM nodes without buffering source XML.
func (o ParseOptions) ParseReader(ctx context.Context, r io.Reader) (*Document, error) {
	d, err := o.parserOptions().ParseReader(ctx, r)
	if err != nil {
		return nil, err
	}

	return o.wrapDocument(ctx, d)
}

// CheckXMLProlog checks bytes through the first complete element start tag.
func (o ParseOptions) CheckXMLProlog(ctx context.Context, r io.Reader) error {
	return o.parserOptions().CheckXMLProlog(ctx, r)
}

// ParseFragment builds a document from a sequence of XML content nodes.
func (o ParseOptions) ParseFragment(ctx context.Context, fragment string) (*Document, error) {
	d, err := o.parserOptions().ParseFragment(ctx, fragment)
	if err != nil {
		return nil, err
	}

	return o.wrapDocument(ctx, d)
}

// ReadRecords uses the same language input policy for independent records.
func (o ParseOptions) ReadRecords(ctx context.Context, r io.Reader, options tree.RecordOptions, emit func(*tree.Document) error) error {
	return o.parserOptions().ReadRecords(ctx, r, options, emit)
}

func (o ParseOptions) wrapDocument(ctx context.Context, doc *tree.Document) (*Document, error) {
	view, err := WrapDocument(ctx, doc)
	if err != nil {
		return nil, err
	}

	view.url = o.BaseURI

	return view, nil
}

func (o ParseOptions) parserOptions() tree.ParseOptions {
	options := tree.ParseOptions{Limits: o.limits(), AllowSingleByteEncodings: o.AllowSingleByteEncodings, AllowRelativeNamespaces: o.AllowRelativeNamespaces, AllowDTD: o.AllowDTD, BaseURI: o.BaseURI}
	// XSLT's resolver also accepts portable absolute file paths. Entity bases
	// are absolute URIs, independently of that resolver's path spelling.
	if uripath.IsWindowsAbsolute(options.BaseURI) {
		options.BaseURI = uripath.WindowsToFileURI(options.BaseURI)
	} else if strings.HasPrefix(options.BaseURI, "/") {
		options.BaseURI = "file://" + options.BaseURI
	}

	if o.DTDOpen != nil {
		options.DTDResolver = func(ctx context.Context, systemID, base string) (io.ReadCloser, string, error) {
			if strings.Contains(systemID, "#") {
				return nil, "", fmt.Errorf("%w: fragment in external entity identifier", tree.ErrMalformed)
			}

			uri, err := uripath.ResolveIRIReference(systemID, base)
			if err != nil {
				return nil, "", err
			}

			if uripath.URIScheme(uri) == "" {
				return nil, "", fmt.Errorf("%w: external entity %q against %q has no absolute URI", tree.ErrMalformed, systemID, base)
			}

			reader, err := o.DTDOpen(ctx, uri)

			return reader, uri, err
		}
	}

	return options
}

func (o ParseOptions) limits() tree.Limits {
	if o.Limits.MaxBytes == 0 {
		return tree.DefaultLimits()
	}

	return o.Limits
}
