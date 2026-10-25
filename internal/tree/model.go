package tree

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
)

const (
	// XMLNamespace is the predefined XML namespace URI.
	XMLNamespace = lexicon.NamespaceXML
	// XMLNSNamespace is the reserved namespace-declaration URI.
	XMLNSNamespace = lexicon.NamespaceXMLNS
)

const xmlSpaceName = "space"

var (
	// ErrMalformed reports malformed XML.
	ErrMalformed   = errors.New("malformed XML")
	ErrUnencodable = errors.New("XML markup is not representable in the output encoding")
	// ErrLimit reports XML resource limit exceeded.
	ErrLimit = errors.New("XML resource limit exceeded")
	// ErrUnsupported reports unsupported XML feature.
	ErrUnsupported = errors.New("unsupported XML feature")
)

// Name is an expanded XML name, independent of its lexical prefix.
type Name struct {
	// Space is the namespace URI; empty denotes no namespace.
	Space string
	// Local is the local name without a prefix or colon.
	Local string
}

// Attribute is a copy of a non-namespace attribute.
type Attribute struct {
	// Name is the expanded attribute name. Unprefixed attributes have no namespace.
	Name Name
	// Prefix is the lexical namespace prefix, or empty for an unprefixed attribute.
	Prefix string
	// Value is the XML-normalized attribute value after character and entity reference expansion.
	Value string
}

// Namespace is one lexical namespace declaration.
type Namespace struct {
	Prefix string
	URI    string
}

// Kind identifies an XML or XPath node kind.
type Kind uint8

const (
	// ElementNode identifies an element node.
	ElementNode Kind = iota
	// TextNode identifies a text node.
	TextNode
	// CommentNode identifies a comment node.
	CommentNode
	// PINode identifies a processing instruction.
	PINode
	// DocumentNode identifies the XPath document node.
	DocumentNode
	// AttributeNode identifies an attribute node.
	AttributeNode
	// NamespaceNode identifies a namespace node.
	NamespaceNode
	// InvalidNode identifies an invalid node handle.
	InvalidNode Kind = 255
)

// Node is mutable only inside this module. Public Documents never expose it.
type Node struct {
	Kind       Kind
	SourceLine uint32 // 1-based start-tag line; zero when unavailable
	Name       Name
	Prefix     string
	Attrs      []Attribute
	NS         []Namespace
	Data       string
	Parent     *Node
	Children   []*Node
	textBuffer *strings.Builder
}

// Root returns the private root node for module-internal draft operations.
func Root(d *Document) *Node {
	if d == nil {
		return nil
	}

	return d.root
}

// Limits bounds XML parsing and expanded node sets. MaxBytes, MaxDepth,
// MaxNodes and MaxAttributesPerElement must be positive. Use DefaultLimits
// for a complete policy.
type Limits struct {
	// MaxBytes bounds XML input bytes before and after decoding.
	MaxBytes int
	// MaxDepth bounds element nesting and cannot exceed 512.
	MaxDepth int
	// MaxNodes bounds parsed content nodes, excluding expanded namespace and attribute axes.
	MaxNodes int
	// MaxAttributesPerElement bounds attributes and namespace declarations on each start tag.
	MaxAttributesPerElement int
	// MaxInScopeNamespaces bounds namespace bindings visible on each element,
	// including the implicit xml binding; zero selects 256.
	MaxInScopeNamespaces int
	// MaxNodeSetNodes bounds expanded XPath selections; zero uses 250000.
	MaxNodeSetNodes int
}

// DefaultLimits returns a fresh value; there is no mutable global policy.
func DefaultLimits() Limits {
	return Limits{MaxBytes: 8 << 20, MaxDepth: 128, MaxNodes: 100_000, MaxAttributesPerElement: 128, MaxInScopeNamespaces: 256, MaxNodeSetNodes: 250_000}
}

// Policy returns the snapshot resource policy.
func Policy(d *Document) Limits { return d.limits }

// Validate checks this value against the supported resource policy.
func (l Limits) Validate() error {
	if l.MaxBytes <= 0 || l.MaxDepth <= 0 || l.MaxNodes <= 0 || l.MaxAttributesPerElement <= 0 {
		return fmt.Errorf("%w: all limits must be positive", ErrLimit)
	}

	if l.MaxInScopeNamespaces < 0 || l.MaxNodeSetNodes < 0 {
		return fmt.Errorf("%w: negative namespace/node-set budget", ErrLimit)
	}
	// The recursive canonicalizer must never be handed an unbounded tree.
	if l.MaxDepth > 512 {
		return fmt.Errorf("%w: MaxDepth must be <= 512", ErrLimit)
	}

	return nil
}

func (l Limits) namespaceLimit() int {
	if l.MaxInScopeNamespaces == 0 {
		return 256
	}

	return l.MaxInScopeNamespaces
}

func (l Limits) nodeSetLimit() int {
	if l.MaxNodeSetNodes == 0 {
		return 250_000
	}

	return l.MaxNodeSetNodes
}

// DTDAttributeType records the DTD classifications needed for ID and IDREF lookup.
type DTDAttributeType uint8

const (
	DTDNoType DTDAttributeType = iota
	DTDID
	DTDIDRef
	DTDIDRefs
)

type dtdAttributeKey struct {
	owner *Node
	name  Name
}

// UnparsedEntity preserves an XML declaration's identifiers without fetching it.
type UnparsedEntity struct {
	// SystemID is the declared system identifier, without retrieving its resource.
	SystemID string
	// PublicID is the optional declared public identifier.
	PublicID string
	// BaseURI is the retrieval base used to resolve the system identifier.
	BaseURI string
}

// Document is an immutable, namespace-aware XML 1.0 snapshot.
// It owns its data and may be read concurrently.
// This type is aliased by the public document package. Internal draft operations
// must be package functions so they cannot enter the public method set.
type Document struct {
	children         []*Node
	root             *Node
	limits           Limits
	inputBytes       int
	unparsedEntities map[string]UnparsedEntity
	nodeBases        map[*Node]string
	dtdTypes         map[dtdAttributeKey]DTDAttributeType
	views            sync.Map
}

// Unwrap returns the private snapshot and node represented by an immutable handle.
func Unwrap(e Element) (*Document, *Node) { return e.doc, e.node }

// FromNodes creates a private draft without copying nodes or changing parents.
// Borrowed snapshot nodes must only be read through the draft. Reparse produces
// an independently owned, validated snapshot.
func FromNodes(nodes []*Node, limits Limits) *Document {
	d := &Document{children: nodes, limits: limits}
	for _, n := range nodes {
		if n.Kind == ElementNode {
			d.root = n
		}
	}

	return d
}

// Clone copies a private draft, checking cancellation at each node.
// It never returns a partial snapshot.
func Clone(ctx context.Context, d *Document) (*Document, error) {
	if ctx == nil || d == nil {
		return nil, ErrMalformed
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	out := &Document{limits: d.limits, inputBytes: d.inputBytes, unparsedEntities: d.unparsedEntities, children: make([]*Node, len(d.children))}

	var cp func(*Node, *Node) (*Node, error)

	cp = func(n, p *Node) (*Node, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		x := &Node{
			Kind: n.Kind, Name: n.Name, Prefix: n.Prefix, Data: n.Data, Parent: p,
			Attrs: append([]Attribute(nil), n.Attrs...), NS: append([]Namespace(nil), n.NS...),
			SourceLine: n.SourceLine,
		}

		if base := d.nodeBases[n]; base != "" {
			if out.nodeBases == nil {
				out.nodeBases = make(map[*Node]string)
			}

			out.nodeBases[x] = base
		}

		for _, attribute := range n.Attrs {
			if kind := AttributeDTDType(d, n, attribute.Name); kind != DTDNoType {
				SetAttributeDTDType(out, x, attribute.Name, kind)
			}
		}

		if len(n.Children) != 0 {
			x.Children = make([]*Node, len(n.Children))
		}

		for i, c := range n.Children {
			child, err := cp(c, x)
			if err != nil {
				return nil, err
			}

			x.Children[i] = child
		}

		return x, nil
	}
	for i, n := range d.children {
		c, err := cp(n, nil)
		if err != nil {
			return nil, err
		}

		out.children[i] = c
		if c.Kind == ElementNode {
			out.root = c
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

// Root returns the immutable root handle, or an invalid handle for a nil document.
func (d *Document) Root() Element {
	if d == nil {
		return Element{}
	}

	return Element{d, d.root}
}

// Element is an immutable handle tied to one Document snapshot.
// Its zero value is invalid. Handles remain comparable by Same.
type Element struct {
	doc  *Document
	node *Node
}

// Wrap creates an immutable handle for a node owned by the supplied snapshot.
func Wrap(d *Document, n *Node) Element { return Element{d, n} }

// Valid returns whether this value is initialized.
func (e Element) Valid() bool { return e.doc != nil && e.node != nil }

// Name returns the expanded XML name.
func (e Element) Name() Name {
	if !e.Valid() {
		return Name{}
	}

	return e.node.Name
}

// Prefix returns the original lexical namespace prefix.
func (e Element) Prefix() string {
	if !e.Valid() {
		return ""
	}

	return e.node.Prefix
}

// Same returns whether both handles identify the same node in the same snapshot.
func (e Element) Same(other Element) bool {
	return e.Valid() && e.doc == other.doc && e.node == other.node
}

// Attribute returns the attribute value and whether the expanded attribute name exists.
func (e Element) Attribute(name Name) (string, bool) {
	if e.Valid() {
		for _, a := range e.node.Attrs {
			if a.Name == name {
				return a.Value, true
			}
		}
	}

	return "", false
}

// Attributes returns an owned copy of the non-namespace attributes.
func (e Element) Attributes() []Attribute {
	if !e.Valid() {
		return nil
	}

	return append([]Attribute(nil), e.node.Attrs...)
}

// Children returns an owned slice of immutable handles to direct child elements
// in document order. Text, comments and processing instructions are excluded;
// use the Node child axis to include other content kinds.
func (e Element) Children() []Element {
	if !e.Valid() {
		return nil
	}

	count := 0

	for _, n := range e.node.Children {
		if n.Kind == ElementNode {
			count++
		}
	}

	if count == 0 {
		return nil
	}

	out := make([]Element, 0, count)

	for _, n := range e.node.Children {
		if n.Kind == ElementNode {
			out = append(out, Element{e.doc, n})
		}
	}

	return out
}

// Text returns concatenated descendant text, without comments or PI data.
// This is a convenience, not schema or application-level validation.
func (e Element) Text() string {
	if !e.Valid() {
		return ""
	}

	return StringValue(e.node)
}

// Namespace resolves a prefix in the original snapshot. Unused namespace
// bindings are not necessarily protected by Exclusive C14N.
func (e Element) Namespace(prefix string) (string, bool) {
	if !e.Valid() {
		return "", false
	}

	return ResolvePrefix(e.node, prefix)
}

// Children returns private document children; callers must not mutate a published
// snapshot.
func Children(d *Document) []*Node { return d.children }

// QName joins a prefix and local name into a lexical QName.
func QName(prefix, local string) string {
	if prefix == "" {
		return local
	}

	return prefix + ":" + local
}

// ResolvePrefix resolves a namespace prefix by walking the original ancestors.
func ResolvePrefix(n *Node, prefix string) (string, bool) {
	if prefix == lexicon.PrefixXML {
		return XMLNamespace, true
	}

	for ; n != nil; n = n.Parent {
		for _, ns := range n.NS {
			if ns.Prefix == prefix {
				return ns.URI, true
			}
		}
	}

	if prefix == "" {
		return "", true
	}

	return "", false
}

// IsXMLSpace reports whether s contains only XML whitespace characters.
func IsXMLSpace(s string) bool { return xmlchar.IsAllSpace(s) }

// NCName reports whether s is an XML 1.0 NCName.
func NCName(s string) bool { return xmlchar.IsValidNCName(s) }

// SetDraftChildren updates an unpublished internal draft. Published Documents
// must remain immutable; only the transform result builder uses this operation.
func SetDraftChildren(d *Document, nodes []*Node) {
	d.children = nodes
	d.root = nil

	for _, n := range nodes {
		if n.Kind == ElementNode {
			d.root = n
			break
		}
	}
}

// LoadView and StoreView cache read-only module views by private key. The cache
// owns no alternative node storage and is collected with its Document.
func LoadView(d *Document, key any) (any, bool) { return d.views.Load(key) }

// StoreView atomically installs a module view, returning the existing one if set.
func StoreView(d *Document, key, value any) any {
	actual, _ := d.views.LoadOrStore(key, value)
	return actual
}

// StringValue returns concatenated descendant text from existing node storage.
func StringValue(n *Node) string {
	if n == nil {
		return ""
	}

	var first string

	size, count := 0, 0

	var measure func(*Node)

	measure = func(node *Node) {
		if node.Kind == TextNode && node.Data != "" {
			first = node.Data
			size += len(node.Data)
			count++
		}

		for _, child := range node.Children {
			measure(child)
		}
	}
	measure(n)

	if count <= 1 {
		return first
	}

	var output strings.Builder
	output.Grow(size)

	var appendText func(*Node)

	appendText = func(node *Node) {
		if node.Kind == TextNode {
			output.WriteString(node.Data)
		}

		for _, child := range node.Children {
			appendText(child)
		}
	}
	appendText(n)

	return output.String()
}

// AppendTextData grows a private draft's content without repeatedly copying the
// accumulated prefix. The published string remains valid after later appends.
func AppendTextData(n *Node, text string) {
	if n.textBuffer == nil || n.textBuffer.String() != n.Data {
		n.textBuffer = &strings.Builder{}
		n.textBuffer.Grow(len(n.Data) + len(text))
		_, _ = n.textBuffer.WriteString(n.Data)
	}

	_, _ = n.textBuffer.WriteString(text)
	n.Data = n.textBuffer.String()
}
