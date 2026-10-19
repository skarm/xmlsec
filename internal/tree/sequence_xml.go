package tree

import (
	"context"
	"io"
	"iter"
	"maps"

	"github.com/skarm/xmlsec/internal/streamio"
)

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
			w.node(&detached)
		} else {
			w.node(node)
		}

		if w.err != nil {
			return w.output.Written, w.err
		}
	}

	return w.output.Written, nil
}
