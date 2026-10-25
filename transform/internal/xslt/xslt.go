// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"io"
	"math"

	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// CompileStylesheet compiles a parsed stylesheet through NewCompiler().Compile. The
// result can be reused concurrently under the Stylesheet ownership contract.
func CompileStylesheet(ctx context.Context, doc *xdm.Document) (*Stylesheet, error) {
	return NewCompiler().Compile(ctx, doc)
}

// Transform applies ss to a borrowed read-only source through
// ss.Transform(source).Do(ctx). The compiled stylesheet can be reused concurrently;
// shared host callbacks must support concurrent calls.
func Transform(ctx context.Context, source *xdm.Document, ss *Stylesheet) (*xdm.Document, error) {
	if ss == nil {
		return nil, errNilStylesheet
	}

	return ss.Transform(source).Do(ctx)
}

// TransformString applies ss to a borrowed read-only source and serializes the
// principal result through ss.Transform(source).Serialize(ctx). It shares the
// Stylesheet concurrency contract.
func TransformString(ctx context.Context, source *xdm.Document, ss *Stylesheet) (string, error) {
	if ss == nil {
		return "", errNilStylesheet
	}

	return ss.Transform(source).Serialize(ctx)
}

// TransformToWriter applies the compiled stylesheet and writes the result to w.
// This is a convenience wrapper over ss.Transform(source).WriteTo(ctx, w).
func TransformToWriter(ctx context.Context, source *xdm.Document, ss *Stylesheet, w io.Writer) error {
	if ss == nil {
		return errNilStylesheet
	}

	return ss.Transform(source).WriteTo(ctx, w)
}

// parseXMLResource consumes and closes an explicitly opened XML resource.
func parseXMLResource(ctx context.Context, configured *xdm.ParseOptions, reader io.ReadCloser, baseURI string, maxBytes int64) (*xdm.Document, error) {
	options := xdm.ParseOptions{}
	if configured != nil {
		options = *configured
	}

	if baseURI != "" {
		options.BaseURI = baseURI
	}

	limit := resolveResourceLimit(maxBytes)
	if limit < 0 {
		limit = math.MaxInt64
	}

	input := &streamio.Reader{Context: ctx, Source: reader, Limit: limit, LimitError: ErrResourceTooLarge}
	doc, err := options.WithByteLimit(limit).ParseReader(ctx, input)

	err = errors.Join(err, reader.Close(), ctx.Err())
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// clampInt64ToInt preserves the sign of resource limits on 32-bit platforms.
func clampInt64ToInt(n int64) int {
	if n > int64(math.MaxInt) {
		return math.MaxInt
	}

	if n < int64(math.MinInt) {
		return math.MinInt
	}

	return int(n)
}
