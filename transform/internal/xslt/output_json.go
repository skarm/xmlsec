// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"io"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// serializeJSONItems serializes a sequence of items as JSON output.
// Per XSLT 3.0 §26: the sequence is serialized as a single JSON value.
func serializeJSONItems(ctx context.Context, w io.Writer, items xdm.Sequence, _ *xdm.Document, outDef *OutputDef) error {
	return writeJSONItems(ctx, w, items, outDef, 0)
}
