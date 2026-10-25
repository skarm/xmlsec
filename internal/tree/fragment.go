package tree

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
)

// ParseFragment uses the same XML parser and policy as Parse. The synthetic
// element is removed before publication and does not consume the caller's node,
// depth or byte budget.
func ParseFragment(ctx context.Context, data []byte, limits Limits) (*Document, error) {
	if len(data) > limits.MaxBytes {
		return nil, fmt.Errorf("%w: XML fragment", ErrLimit)
	}

	return ParseFragmentReader(ctx, bytes.NewReader(data), limits)
}

// ParseFragmentText accepts an already decoded external parsed entity. Its
// optional TextDecl selects no byte decoder, but must satisfy XML 1.0 [77].
func ParseFragmentText(ctx context.Context, text string, limits Limits) (*Document, error) {
	return parseFragmentText(ctx, text, limits, false)
}

func parseFragmentText(ctx context.Context, text string, limits Limits, relativeNamespaces bool) (*Document, error) {
	if ctx == nil {
		return nil, ErrMalformed
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := limits.Validate(); err != nil {
		return nil, err
	}

	if len(text) > limits.MaxBytes {
		return nil, fmt.Errorf("%w: XML fragment", ErrLimit)
	}

	content, err := stripTextDeclaration(text)
	if err != nil {
		return nil, err
	}

	doc, err := parseFragmentReader(ctx, strings.NewReader(content), limits, relativeNamespaces)
	if err != nil {
		return nil, err
	}

	doc.inputBytes = len(text)

	return doc, nil
}

func stripTextDeclaration(text string) (string, error) {
	if !strings.HasPrefix(text, "<?xml") || len(text) < 6 || !spaceByte(text[5]) {
		return text, nil
	}

	end := strings.Index(text, "?>")
	if end < 0 {
		return "", fmt.Errorf("%w: unterminated text declaration", ErrMalformed)
	}

	attrs, err := declarationAttributes([]byte(text[5:end]))
	if err != nil {
		return "", err
	}

	if attrs[0].Name == (xml.Name{Local: nameXMLVersion}) {
		if attrs[0].Value != "1.0" {
			return "", fmt.Errorf("%w: XML 1.0 is required", ErrUnsupported)
		}

		attrs = attrs[1:]
	}

	if len(attrs) != 1 || attrs[0].Name != (xml.Name{Local: "encoding"}) || !validEncodingName(attrs[0].Value) {
		return "", fmt.Errorf("%w: text declaration attributes", ErrMalformed)
	}

	return text[end+2:], nil
}

// ParseFragmentReader constructs a fragment without copying a complete source
// into a synthetic XML wrapper. The source remains caller-owned.
func ParseFragmentReader(ctx context.Context, src io.Reader, limits Limits) (*Document, error) {
	return parseFragmentReader(ctx, src, limits, false)
}

func parseFragmentReader(ctx context.Context, src io.Reader, limits Limits, relativeNamespaces bool) (*Document, error) {
	if ctx == nil || nilcheck.IsNil(src) {
		return nil, ErrMalformed
	}

	if err := limits.Validate(); err != nil {
		return nil, err
	}

	const (
		start   = "<xmlsec-fragment>"
		end     = "</xmlsec-fragment>"
		wrapper = len(start) + len(end)
	)

	maximum := int(^uint(0) >> 1)
	if limits.MaxBytes > maximum-wrapper || limits.MaxNodes == maximum || limits.MaxDepth == maximum {
		return nil, fmt.Errorf("%w: XML fragment", ErrLimit)
	}

	source := &streamio.Reader{Context: ctx, Source: src, Limit: int64(limits.MaxBytes), LimitError: ErrLimit}
	wrapped := limits
	wrapped.MaxBytes += wrapper
	wrapped.MaxDepth++
	wrapped.MaxNodes++

	input, err := newXMLInput(ctx, io.MultiReader(strings.NewReader(start), source, strings.NewReader(end)), int64(wrapped.MaxBytes), wrapped.MaxBytes)
	if err != nil {
		return nil, err
	}

	parser := readerParser(input, wrapped)
	parser.relativeNamespaces = relativeNamespaces

	d, err := parser.parse(ctx)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	children := d.root.Children
	for _, n := range children {
		n.Parent = nil
	}

	out := FromNodes(children, limits)
	out.inputBytes = int(source.ReadBytes)

	return out, nil
}
