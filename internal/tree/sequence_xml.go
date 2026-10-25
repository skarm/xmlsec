package tree

import (
	"context"
	"errors"
	"io"
	"iter"
	"maps"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
)

type XMLCharacterMode uint8

const (
	XMLTextContent XMLCharacterMode = iota
	XMLAttributeValue
	XMLCDATAContent
)

// WriteXMLCharacters shares XML escaping, normalization and CDATA splitting
// with the tree writer, without adding surrounding markup.
func WriteXMLCharacters(ctx context.Context, dst io.Writer, text string, mode XMLCharacterMode, maximum int, options XMLWriteOptions) (int64, error) {
	if ctx == nil || nilcheck.IsNil(dst) || maximum <= 0 {
		return 0, ErrMalformed
	}

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	w := xmlStream{ctx: ctx, output: streamio.Writer{Context: ctx, Target: dst, Limit: int64(maximum), LimitError: ErrLimit}, options: options}

	switch mode {
	case XMLTextContent:
		w.escaped(text, false)
	case XMLAttributeValue:
		w.escaped(text, true)
	case XMLCDATAContent:
		w.cdata(text)
	default:
		return 0, ErrMalformed
	}

	return w.output.Written, errors.Join(w.err, ctx.Err())
}

// WriteXMLSequence writes independent nodes without constructing a result tree.
// Each top-level element preserves its original in-scope namespace bindings.
func WriteXMLSequence(ctx context.Context, dst io.Writer, nodes iter.Seq2[*Node, error], maximum int, options XMLWriteOptions) (int64, error) {
	if ctx == nil || dst == nil || maximum <= 0 {
		return 0, ErrMalformed
	}

	bindings := maps.Clone(options.InheritedNamespaces)
	if bindings == nil {
		bindings = make(map[string]string)
	}

	w := xmlStream{ctx: ctx, output: streamio.Writer{Context: ctx, Target: dst, Limit: int64(maximum), LimitError: ErrLimit}, options: options, ns: namespaceContext{bindings: bindings}}

	doe := false

	for node, err := range nodes {
		if err != nil {
			return w.output.Written, err
		}

		if node == nil {
			return w.output.Written, ErrMalformed
		}

		if node.Kind == ElementNode && node.Parent != nil {
			detached := *node
			detached.NS = inheritedRecordNamespaces(node)
			detached.Parent = nil
			w.sibling(&detached, &doe, false)
		} else {
			w.sibling(node, &doe, false)
		}

		if w.err != nil {
			return w.output.Written, w.err
		}
	}

	return w.output.Written, nil
}
