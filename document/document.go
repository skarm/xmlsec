package document

import (
	"context"
	"io"

	"github.com/skarm/xmlsec/internal/tree"
)

const (
	// ElementNode identifies an element node.
	ElementNode = tree.ElementNode
	// TextNode identifies a text node.
	TextNode = tree.TextNode
	// CommentNode identifies a comment node.
	CommentNode = tree.CommentNode
	// ProcessingInstructionNode identifies a processing instruction.
	ProcessingInstructionNode = tree.PINode
	// DocumentNode identifies the XPath document node.
	DocumentNode = tree.DocumentNode
	// AttributeNode identifies an attribute node.
	AttributeNode = tree.AttributeNode
	// NamespaceNode identifies a namespace node.
	NamespaceNode = tree.NamespaceNode
	// InvalidNode identifies an invalid node handle.
	InvalidNode = tree.InvalidNode
	// XMLNamespace is the predefined XML namespace URI.
	XMLNamespace = tree.XMLNamespace
)

var (
	// ErrMalformed reports malformed XML.
	ErrMalformed = tree.ErrMalformed
	// ErrLimit reports an XML resource limit exceeded.
	ErrLimit = tree.ErrLimit
	// ErrUnsupported reports an unsupported XML feature.
	ErrUnsupported = tree.ErrUnsupported
)

type (
	// Document is an immutable, namespace-aware XML 1.0 snapshot. It owns its data and
	// supports concurrent reads.
	Document = tree.Document
	// Element is an immutable element handle tied to one Document. Its zero value is invalid.
	Element = tree.Element
	// Name is an expanded XML name; Space is a namespace URI and Local is the local name.
	Name = tree.Name
	// Attribute is an owned copy of a non-namespace attribute.
	Attribute = tree.Attribute
	// Limits bounds XML parsing and expanded node sets. Use DefaultLimits for a complete
	// policy.
	Limits = tree.Limits
	// Node is an immutable handle to an individual XPath node in one Document.
	Node = tree.NodeRef
	// NodeKind identifies an XPath node kind.
	NodeKind = tree.Kind
	// NodeSet is an immutable set of individual nodes from one Document. Selecting an element
	// does not select its subtree.
	NodeSet = tree.NodeSet
	// RecordOptions selects independent XML subtrees and their resource limits.
	RecordOptions = tree.RecordOptions
)

// NewNodeSet selects individual nodes, not their subtrees. Nodes from different
// snapshots are rejected. An empty selection is valid; a zero NodeSet is not.
func NewNodeSet(d *Document, nodes ...Node) (NodeSet, error) {
	return tree.NewNodeSet(d, nodes...)
}

// DefaultLimits returns a fresh value containing the default resource budgets.
func DefaultLimits() Limits { return tree.DefaultLimits() }

// Parse parses an owned immutable XML snapshot with cancellation and explicit
// limits. DTDs and external entities are rejected.
func Parse(ctx context.Context, data []byte, limits Limits) (*Document, error) {
	return tree.Parse(ctx, data, limits)
}

// ParseReader incrementally constructs a complete immutable snapshot. It retains
// the tree and current lexical token, which can span a large text node or start
// tag, but no separate complete source buffer. The caller owns src; blocking
// reads must support cancellation themselves. Use ReadRecords for independent
// subtrees without retaining the enclosing tree.
func ParseReader(ctx context.Context, src io.Reader, limits Limits) (*Document, error) {
	return tree.ParseReader(ctx, src, limits)
}

// ReadRecords incrementally validates XML and calls emit for each selected
// subtree. Working storage includes one record, the current lexical token and
// enclosing namespace/xml:* context, subject to options.Limits. Retaining records
// in emit also retains their storage; this is not a fixed heap-size guarantee.
// Callbacks may run before the enclosing input is fully validated; later errors
// do not roll back prior callbacks. The caller owns src.
func ReadRecords(ctx context.Context, src io.Reader, options RecordOptions, emit func(*Document) error) error {
	return tree.ReadRecords(ctx, src, options, emit)
}
