package xdm

import (
	"bytes"
	"context"
	"io"

	"github.com/skarm/xmlsec/internal/tree"
)

// ParseOptions configures XML-to-XDM construction. XML parsing, including DTD
// rejection and namespace validation, is always performed by internal/tree.
// Resource retrieval belongs to the evaluator; parsing performs no I/O.
type ParseOptions struct {
	Limits                   tree.Limits
	BaseURI                  string
	AllowSingleByteEncodings bool
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
	d, err := tree.ParseText(ctx, text, o.limits())
	if err != nil {
		return nil, err
	}

	view, err := WrapDocument(ctx, d)
	if err != nil {
		return nil, err
	}

	view.url = o.BaseURI

	return view, nil
}

// ParseReader incrementally constructs XDM nodes without buffering source XML.
func (o ParseOptions) ParseReader(ctx context.Context, r io.Reader) (*Document, error) {
	parse := tree.ParseReader
	if o.AllowSingleByteEncodings {
		parse = tree.ParseReaderWithSingleByteEncodings
	}

	d, err := parse(ctx, r, o.limits())
	if err != nil {
		return nil, err
	}

	view, err := WrapDocument(ctx, d)
	if err != nil {
		return nil, err
	}

	view.url = o.BaseURI

	return view, nil
}

// ParseFragment builds a document from a sequence of XML content nodes.
func (o ParseOptions) ParseFragment(ctx context.Context, fragment string) (*Document, error) {
	d, err := tree.ParseFragmentText(ctx, fragment, o.limits())
	if err != nil {
		return nil, err
	}

	view, err := WrapDocument(ctx, d)
	if err != nil {
		return nil, err
	}

	view.url = o.BaseURI

	return view, nil
}

func (o ParseOptions) limits() tree.Limits {
	if o.Limits.MaxBytes == 0 {
		return tree.DefaultLimits()
	}

	return o.Limits
}
