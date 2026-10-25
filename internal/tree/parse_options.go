package tree

import (
	"context"
	"io"
	"strings"
)

// ParseOptions separates XML language input from the default security parser.
// The security parser remains DTD-free. Language callers can explicitly enable
// bounded nonvalidating DTD processing with an optional authorized resolver.
type ParseOptions struct {
	Limits                   Limits
	AllowSingleByteEncodings bool
	AllowDTD                 bool
	BaseURI                  string
	DTDResolver              DTDEntityResolver
	// Namespaces 1.0 permits deprecated relative namespace names. Keep their
	// literal values; they are never resolved against an XML base URI.
	AllowRelativeNamespaces bool
}

func (o ParseOptions) ParseReader(ctx context.Context, src io.Reader) (*Document, error) {
	if o.AllowDTD {
		return o.parseDTDReader(ctx, src)
	}

	return parseXMLReader(ctx, src, o.Limits, false, o.AllowSingleByteEncodings, o.AllowRelativeNamespaces)
}

func (o ParseOptions) ParseText(ctx context.Context, text string) (*Document, error) {
	if o.AllowDTD && strings.Contains(text, "<!DOCTYPE") {
		return o.parseDTDText(ctx, text)
	}

	return parseXMLReader(ctx, strings.NewReader(text), o.Limits, true, false, o.AllowRelativeNamespaces)
}

func (o ParseOptions) ParseFragment(ctx context.Context, text string) (*Document, error) {
	return parseFragmentText(ctx, text, o.Limits, o.AllowRelativeNamespaces)
}

func (o ParseOptions) CheckXMLProlog(ctx context.Context, src io.Reader) error {
	parser, err := newDocumentReader(ctx, src, o.Limits, false, o.AllowSingleByteEncodings, o.AllowRelativeNamespaces)
	if err != nil {
		return err
	}

	parser.stopAtRoot = true
	_, err = parser.parse(ctx)

	return err
}
