package transform

import (
	"context"
	"io"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// Document is an immutable XML snapshot shared by XPath and XSLT.
// Mutating input bytes after Parse does not change it.
type Document struct{ native *xdm.Document }

// Root returns the document node as an XPath context item.
func (d *Document) Root() Value {
	if d == nil || d.native == nil {
		return Value{}
	}

	return Value{item: xdm.NodeItem{Node: d.native}}
}

// Node is an immutable handle retaining its owner snapshot, including nodes
// outside a selected subtree. No mutable engine nodes escape this API.
type Node struct{ native xdm.Node }

// Reference returns this node's immutable handle for document, c14n and other
// library packages. A zero Node returns an invalid handle.
func (n Node) Reference() document.Node {
	if n.native == nil {
		return document.Node{}
	}

	return n.native.Reference()
}

// Document returns the immutable owner snapshot, or nil for a zero Node.
func (n Node) Document() *Document {
	if n.native == nil || n.native.OwnerDocument() == nil {
		return nil
	}

	return &Document{native: n.native.OwnerDocument()}
}

// Name returns the expanded name; text and document nodes have no name.
func (n Node) Name() Name {
	switch node := n.native.(type) {
	case *xdm.Element:
		return Name{Space: node.URI(), Local: node.LocalName()}
	case *xdm.Attribute:
		return Name{Space: node.URI(), Local: node.LocalName()}
	case *xdm.ProcessingInstruction, *xdm.NamespaceNodeWrapper:
		return Name{Local: node.Name()}
	default:
		return Name{}
	}
}

// StringValue returns the XPath string value, including descendant text.
func (n Node) StringValue() string {
	if n.native == nil {
		return ""
	}

	value, err := xpath.AtomizeItem(xdm.NodeItem{Node: n.native})
	if err != nil {
		return ""
	}

	text, _ := lexical(value)

	return text
}

// Kind reports the node kind using XPath's standard names.
func (n Node) Kind() string {
	if n.native == nil {
		return ""
	}

	switch n.native.Type() {
	case xdm.DocumentNode:
		return "document"
	case xdm.ElementNode:
		return "element"
	case xdm.AttributeNode:
		return "attribute"
	case xdm.TextNode, xdm.CDATASectionNode:
		return "text"
	case xdm.CommentNode:
		return "comment"
	case xdm.ProcessingInstructionNode:
		return "processing-instruction"
	default:
		return strings.ToLower(n.native.Type().String())
	}
}

type inputLimitsKey struct{}

// Parse validates XML, rejects DTDs and applies the engine's input limits.
func (e *Engine) Parse(ctx context.Context, xml []byte) (*Document, error) {
	ctx, cancel, err := e.invocation(ctx)
	if err != nil {
		return nil, wrap("parse", err)
	}
	defer cancel()

	d, err := e.parse(ctx, xml, "")
	if err == nil {
		d.native.Freeze()
	}

	return d, err
}

// ParseReader reads XML incrementally using the engine policy and publishes an
// immutable snapshot. It retains the complete tree and current lexical token;
// it does not close the caller-owned reader or interrupt arbitrary blocked reads.
func (e *Engine) ParseReader(ctx context.Context, src io.Reader) (*Document, error) {
	ctx, cancel, err := e.invocation(ctx)
	if err != nil {
		return nil, wrap("parse", err)
	}
	defer cancel()

	if nilcheck.IsNil(src) {
		return nil, wrap("parse", ErrInput)
	}

	d, err := e.parseOptions().ParseReader(ctx, src)
	if err != nil {
		return nil, wrap("parse", err)
	}

	d.Freeze()

	return &Document{native: d}, nil
}

// Import creates a read-only XPath/XSLT view of the existing snapshot. It
// preserves the project's node storage and never serializes or reparses XML.
func (e *Engine) Import(ctx context.Context, d *document.Document) (*Document, error) {
	ctx, cancel, err := e.invocation(ctx)
	if err != nil {
		return nil, wrap("import", err)
	}
	defer cancel()

	if d == nil {
		return nil, wrap("import", ErrInput)
	}

	limits := document.DefaultLimits()
	limits.MaxBytes = e.limits.MaxInputBytes
	limits.MaxDepth = e.limits.MaxDepth

	limits.MaxNodes = e.limits.MaxNodes
	if err = tree.CheckSnapshotLimits(ctx, d, limits); err != nil {
		return nil, wrap("import", err)
	}

	native, err := xdm.FromDocument(ctx, d)
	if err != nil {
		return nil, wrap("import", err)
	}

	return &Document{native: native}, nil
}

// Export returns the same immutable snapshot for use by other library packages.
// Only complete XML documents can be exported; fragments and atomic sequences
// must be handled as values. No XML is serialized or reparsed.
func (e *Engine) Export(ctx context.Context, d *Document) (*document.Document, error) {
	ctx, cancel, err := e.invocation(ctx)
	if err != nil {
		return nil, wrap("export", err)
	}
	defer cancel()

	if d == nil || d.native == nil {
		return nil, wrap("export", ErrInput)
	}

	if err := checkInputDocument(ctx, d.native, e.limits); err != nil {
		return nil, wrap("export", err)
	}

	count := 0

	for child := d.native.FirstChild(); child != nil; child = child.NextSibling() {
		switch child.Type() {
		case xdm.ElementNode:
			count++
		case xdm.CommentNode, xdm.ProcessingInstructionNode:
		case xdm.TextNode:
			if !tree.IsXMLSpace(xdm.CharacterData(child)) {
				return nil, wrap("export", ErrInput)
			}
		default:
			return nil, wrap("export", ErrInput)
		}
	}

	if count != 1 {
		return nil, wrap("export", ErrInput)
	}

	return d.native.Snapshot(), nil
}

// Node values can cross engine boundaries, so the consuming policy must be
// checked even when the producing engine already parsed the snapshot. Cache
// one successful policy on frozen snapshots to keep repeated evaluations cheap.
// Different consuming engines must not grow a per-document policy cache.
func checkInputDocument(ctx context.Context, native *xdm.Document, limits Limits) error {
	native.Freeze()

	policy := document.DefaultLimits()
	policy.MaxBytes = limits.MaxInputBytes
	policy.MaxNodes = limits.MaxNodes
	policy.MaxDepth = limits.MaxDepth
	snapshot := native.Snapshot()

	key := inputLimitsKey{}
	if value, ok := tree.LoadView(snapshot, key); ok {
		if checked, ok := value.(document.Limits); ok && policy.MaxBytes >= checked.MaxBytes && policy.MaxNodes >= checked.MaxNodes && policy.MaxDepth >= checked.MaxDepth {
			return ctx.Err()
		}
	}

	if err := tree.CheckSnapshotLimits(ctx, snapshot, policy); err != nil {
		return err
	}

	tree.StoreView(snapshot, key, policy)

	return ctx.Err()
}

// ImportNode returns an XPath value for an original immutable document handle.
// Attributes and namespaces retain their owner-bound identities.
func (e *Engine) ImportNode(ctx context.Context, n document.Node) (Value, error) {
	if !n.Valid() {
		return Value{}, wrap("import node", ErrInput)
	}

	d, err := e.Import(ctx, n.Document())
	if err != nil {
		return Value{}, err
	}

	node := d.native.NodeView(n)
	if node == nil {
		return Value{}, wrap("import node", ErrInput)
	}

	return Value{item: xdm.NodeItem{Node: node}}, nil
}

func (e *Engine) parse(ctx context.Context, xml []byte, baseURI string) (*Document, error) {
	if len(xml) > e.limits.MaxInputBytes {
		return nil, wrap("parse", ErrLimit)
	}

	options := e.parseOptions()
	options.BaseURI = baseURI

	d, err := options.Parse(ctx, xml)
	if err != nil {
		return nil, wrap("parse", err)
	}

	return &Document{native: d}, nil
}
