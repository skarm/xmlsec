package xmlenc

import (
	"bytes"
	"context"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// The wrapper carries only the actual parent's namespace context. EncryptedData
// declarations and synthetic namespace prefixes must not leak into plaintext:
// even an unused added prefix can invalidate an inclusive XML signature.
func namespaceContext(ctx context.Context, node *tree.Node) ([]tree.Namespace, error) {
	bindings := map[string]string{"": ""}
	seen := make(map[string]struct{})

	for ; node != nil; node = node.Parent {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		for _, ns := range node.NS {
			if _, exists := seen[ns.Prefix]; ns.Prefix != "xml" && !exists {
				bindings[ns.Prefix] = ns.URI
				seen[ns.Prefix] = struct{}{}
			}
		}
	}

	prefixes := make([]string, 0, len(bindings))
	for prefix := range bindings {
		prefixes = append(prefixes, prefix)
	}

	sort.Strings(prefixes)

	namespaces := make([]tree.Namespace, 0, len(prefixes))
	for _, prefix := range prefixes {
		namespaces = append(namespaces, tree.Namespace{Prefix: prefix, URI: bindings[prefix]})
	}

	return namespaces, ctx.Err()
}

func parseSelectedPlaintext(ctx context.Context, raw []byte, parent *tree.Node, limits document.Limits, contextBytes int) (*tree.Node, error) {
	if err := elementEncoding(ctx, raw); err != nil {
		return nil, err
	}

	if parent == nil {
		parsed, err := document.Parse(ctx, raw, limits)
		if err != nil || !singleElement(parsed) {
			return nil, ErrDecrypt
		}

		return tree.Root(parsed), nil
	}

	nodes, err := parseContentPlaintext(ctx, raw, parent, limits, contextBytes)
	if err != nil || len(nodes) != 1 || nodes[0].Kind != tree.ElementNode {
		return nil, ErrDecrypt
	}

	return nodes[0], nil
}

func parseContentPlaintext(ctx context.Context, raw []byte, parent *tree.Node, limits document.Limits, contextBytes int) ([]*tree.Node, error) {
	if err := contentEncoding(ctx, raw); err != nil {
		return nil, err
	}

	if parent == nil || len(raw) > limits.MaxBytes {
		return nil, ErrDecrypt
	}
	// XMLENC 1.1 section 4.5.4: wrap in parent context, parse, remove wrapper.
	// DTD/entities remain disabled. The wrapper has no additional namespace.
	var wrapped bytes.Buffer
	defer func() { clear(wrapped.Bytes()) }()

	namespaces, err := namespaceContext(ctx, parent)
	if err != nil {
		return nil, err
	}

	frame := &tree.Node{Kind: tree.ElementNode, Name: document.Name{Local: "xmlsec-context"}, NS: namespaces}
	frameDoc := tree.FromNodes([]*tree.Node{frame}, limits)
	// Stream escaping of inherited namespace values under the complete source
	// byte budget; a small plaintext budget must not hide unbounded wrapper I/O.
	if _, err := frameDoc.WriteXML(ctx, &wrapped, contextBytes); err != nil {
		return nil, err
	}

	const closing = "</xmlsec-context>"
	wrapped.Truncate(wrapped.Len() - len(closing))

	parseLimits := limits

	parseLimits.MaxBytes += wrapped.Len() + len(closing)
	if parseLimits.MaxDepth < 512 {
		parseLimits.MaxDepth++
	}

	if parseLimits.MaxNodes < math.MaxInt {
		parseLimits.MaxNodes++
	}
	// Inherited namespace declarations are wrapper overhead; the original
	// attribute/depth budgets are checked on the plaintext subtree below.
	parseLimits.MaxAttributesPerElement = max(parseLimits.MaxAttributesPerElement, len(namespaces))

	parsed, err := document.ParseReader(ctx, io.MultiReader(bytes.NewReader(wrapped.Bytes()), bytes.NewReader(raw), strings.NewReader(closing)), parseLimits)
	if err != nil {
		return nil, ErrDecrypt
	}

	plain := tree.Root(parsed).Children
	if err := validatePlaintextNodes(ctx, plain, limits); err != nil {
		return nil, err
	}

	return plain, nil
}

func validatePlaintextNodes(ctx context.Context, nodes []*tree.Node, limits document.Limits) error {
	count := 0

	var walk func(*tree.Node, int) error

	walk = func(n *tree.Node, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		count++
		if count > limits.MaxNodes || n.Kind == tree.ElementNode && (depth > limits.MaxDepth || len(n.NS)+len(n.Attrs) > limits.MaxAttributesPerElement) {
			return ErrDecrypt
		}

		for _, child := range n.Children {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}

		return nil
	}

	for _, node := range nodes {
		if err := walk(node, 1); err != nil {
			return err
		}
	}

	return ctx.Err()
}
