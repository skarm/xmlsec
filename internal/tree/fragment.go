package tree

import (
	"bytes"
	"context"
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

// ParseFragmentReader constructs a fragment without copying a complete source
// into a synthetic XML wrapper. The source remains caller-owned.
func ParseFragmentReader(ctx context.Context, src io.Reader, limits Limits) (*Document, error) {
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
