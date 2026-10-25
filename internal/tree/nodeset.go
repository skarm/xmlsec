package tree

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/skarm/xmlsec/internal/lexicon"
)

// NodeRef is an immutable XPath 1.0 node handle. Attribute and namespace nodes
// belong to their owning element, including namespace bindings inherited from
// ancestors. A namespace node on two different elements is NOT the same node.
// The zero value is invalid. Handles are comparable and snapshot-bound.
type NodeRef struct {
	doc    *Document
	node   *Node // Content node, or owner for an attribute / namespace.
	kind   Kind
	index  int // Attribute index; namespace identity uses prefix instead.
	prefix string
}

// WrapNode creates a reference to an existing project content node.
func WrapNode(d *Document, n *Node) NodeRef { return ref(d, n) }

// Valid returns whether this value is initialized.
func (n NodeRef) Valid() bool { return n.doc != nil && (n.node != nil || n.kind == DocumentNode) }

// Kind returns the data or node kind.
func (n NodeRef) Kind() Kind {
	if !n.Valid() {
		return InvalidNode
	}

	return n.kind
}

// Same returns whether both handles identify the same node in the same snapshot.
func (n NodeRef) Same(other NodeRef) bool { return n.Valid() && n == other }

// Document returns the immutable document snapshot.
func (n NodeRef) Document() *Document { return n.doc }

// Element returns the element handle and whether this node is an element.
func (n NodeRef) Element() (Element, bool) {
	if !n.Valid() || n.kind != ElementNode {
		return Element{}, false
	}

	return Element{n.doc, n.node}, true
}

// Name returns the expanded XML name.
func (n NodeRef) Name() Name {
	if !n.Valid() {
		return Name{}
	}

	switch n.kind {
	case ElementNode, PINode:
		return n.node.Name
	case AttributeNode:
		return n.node.Attrs[n.index].Name
	case NamespaceNode:
		return Name{Local: n.prefix}
	default:
		return Name{}
	}
}

// Prefix returns the original lexical namespace prefix.
func (n NodeRef) Prefix() string {
	if !n.Valid() {
		return ""
	}

	if n.kind == ElementNode {
		return n.node.Prefix
	}

	if n.kind == AttributeNode {
		return n.node.Attrs[n.index].Prefix
	}

	return ""
}

// Value returns the XPath string-value. For an element/document it concatenates
// descendant text, without comments and PI data; for a namespace it is its URI.
func (n NodeRef) Value() string {
	if !n.Valid() {
		return ""
	}

	switch n.kind {
	case ElementNode:
		return (Element{n.doc, n.node}).Text()
	case DocumentNode:
		return n.doc.Root().Text()
	case AttributeNode:
		return n.node.Attrs[n.index].Value
	case NamespaceNode:
		value, _ := ResolvePrefix(n.node, n.prefix)
		return value
	default:
		return n.node.Data
	}
}

// Parent returns the immutable XPath parent handle, invalid for the document node.
func (n NodeRef) Parent() NodeRef {
	if !n.Valid() || n.kind == DocumentNode {
		return NodeRef{}
	}

	if n.kind == AttributeNode || n.kind == NamespaceNode {
		return ref(n.doc, n.node)
	}

	if n.node.Parent == nil {
		return n.doc.Node()
	}

	return ref(n.doc, n.node.Parent)
}

// Children follows the XPath child axis. Attributes/namespaces are separate.
func (n NodeRef) Children() []NodeRef {
	if !n.Valid() {
		return nil
	}

	var children []*Node

	switch n.kind {
	case DocumentNode:
		children = n.doc.children
	case ElementNode:
		children = n.node.Children
	default:
		return nil
	}

	out := make([]NodeRef, len(children))
	for i, child := range children {
		out[i] = ref(n.doc, child)
	}

	return out
}

// NodeSet is an immutable mathematical set of individual XPath nodes from ONE
// document snapshot. Selecting an element never implicitly selects its axes or
// descendants. Use Element.Subtree / Document.AllNodes for complete selections.
// A valid empty set is distinct from the invalid zero value.
type NodeSet struct {
	doc     *Document
	members map[NodeRef]struct{}
}

// NewNodeSet selects individual nodes from one snapshot without selecting their
// descendants.
func NewNodeSet(d *Document, nodes ...NodeRef) (NodeSet, error) {
	if d == nil || d.root == nil {
		return NodeSet{}, fmt.Errorf("%w: node-set document", ErrMalformed)
	}

	s := NodeSet{doc: d, members: make(map[NodeRef]struct{})}
	for _, n := range nodes {
		if err := s.add(n); err != nil {
			return NodeSet{}, err
		}
	}

	return s, nil
}

// Valid returns whether this value is initialized.
func (s NodeSet) Valid() bool { return s.doc != nil && s.members != nil }

// Document returns the immutable document snapshot.
func (s NodeSet) Document() *Document { return s.doc }

// Len returns the number of selected nodes.
func (s NodeSet) Len() int { return len(s.members) }

// Contains returns whether this exact node handle belongs to the selection.
func (s NodeSet) Contains(n NodeRef) bool {
	if !s.Valid() || !n.Valid() || n.doc != s.doc {
		return false
	}

	_, ok := s.members[n]

	return ok
}

// Nodes returns a copy in document order; namespace nodes precede attributes,
// sorted by prefix / expanded attribute name. No caller slice aliases the set.
func (s NodeSet) Nodes() []NodeRef {
	if !s.Valid() {
		return nil
	}

	out := make([]NodeRef, 0, len(s.members))
	axes := make(map[*Node][]NodeRef)

	for n := range s.members {
		if n.kind == AttributeNode || n.kind == NamespaceNode {
			axes[n.node] = append(axes[n.node], n)
		}
	}

	if s.Contains(s.doc.Node()) {
		out = append(out, s.doc.Node())
	}

	var walk func(*Node)

	walk = func(n *Node) {
		r := ref(s.doc, n)
		if s.Contains(r) {
			out = append(out, r)
		}

		list := axes[n]
		sort.Slice(list, func(i, j int) bool {
			a, b := list[i], list[j]
			if a.kind != b.kind {
				return a.kind == NamespaceNode
			}

			if a.kind == NamespaceNode {
				return a.prefix < b.prefix
			}

			return compareNames(a.Name(), b.Name()) < 0
		})
		out = append(out, list...)

		for _, child := range n.Children {
			walk(child)
		}
	}
	for _, n := range s.doc.children {
		walk(n)
	}

	return out
}

// With returns a new immutable set with the supplied nodes added.
func (s NodeSet) With(nodes ...NodeRef) (NodeSet, error) {
	if !s.Valid() {
		return NodeSet{}, fmt.Errorf("%w: invalid node-set", ErrMalformed)
	}

	out, _ := NewNodeSet(s.doc)
	for n := range s.members {
		out.members[n] = struct{}{}
	}

	for _, n := range nodes {
		if err := out.add(n); err != nil {
			return NodeSet{}, err
		}
	}

	return out, nil
}

// Without returns a new immutable set with the supplied nodes removed.
func (s NodeSet) Without(nodes ...NodeRef) (NodeSet, error) {
	out, err := s.With()
	if err != nil {
		return NodeSet{}, err
	}

	for _, n := range nodes {
		if !n.Valid() || n.doc != s.doc {
			return NodeSet{}, fmt.Errorf("%w: invalid or foreign node", ErrMalformed)
		}

		delete(out.members, n)
	}

	return out, nil
}

// Union returns a new union of selections from the same snapshot.
func (s NodeSet) Union(other NodeSet) (NodeSet, error) { return s.combine(other, 'u') }

// Intersect returns a new intersection of selections from the same snapshot.
func (s NodeSet) Intersect(other NodeSet) (NodeSet, error) { return s.combine(other, 'i') }

// Difference returns a new selection excluding nodes in the other selection.
func (s NodeSet) Difference(other NodeSet) (NodeSet, error) { return s.combine(other, 'd') }

func (s NodeSet) add(n NodeRef) error {
	if !n.Valid() || n.doc != s.doc {
		return fmt.Errorf("%w: node-set contains an invalid or foreign node", ErrMalformed)
	}

	if _, exists := s.members[n]; exists {
		return nil
	}

	if len(s.members) >= s.doc.limits.nodeSetLimit() {
		return fmt.Errorf("%w: expanded node-set size", ErrLimit)
	}

	s.members[n] = struct{}{}

	return nil
}

func (s NodeSet) combine(other NodeSet, op byte) (NodeSet, error) {
	if !s.Valid() || !other.Valid() || s.doc != other.doc {
		return NodeSet{}, fmt.Errorf("%w: node-sets must belong to one snapshot", ErrMalformed)
	}

	out, _ := NewNodeSet(s.doc)
	for n := range s.members {
		in := other.Contains(n)
		if op == 'u' || op == 'i' && in || op == 'd' && !in {
			out.members[n] = struct{}{}
		}
	}

	if op == 'u' {
		for n := range other.members {
			if err := out.add(n); err != nil {
				return NodeSet{}, err
			}
		}
	}

	return out, nil
}

// UnwrapNode returns module-owned storage; attributes and namespaces use their
// owner element. It is used by the XPath view adapter, never by public callers.
func UnwrapNode(n NodeRef) (*Document, *Node) { return n.doc, n.node }

// Node returns the immutable XPath node handle.
func (d *Document) Node() NodeRef {
	if d == nil || d.root == nil {
		return NodeRef{}
	}

	return NodeRef{doc: d, kind: DocumentNode}
}

// AllNodes selects all XPath nodes with cancellation and the snapshot node-set
// budget.
func (d *Document) AllNodes(ctx context.Context) (NodeSet, error) {
	return collectNodes(ctx, d, nil)
}

// Node returns the immutable XPath node handle.
func (e Element) Node() NodeRef {
	if !e.Valid() {
		return NodeRef{}
	}

	return ref(e.doc, e.node)
}

// AttributeNodes returns an owned slice of immutable attribute handles.
func (e Element) AttributeNodes() []NodeRef {
	if !e.Valid() {
		return nil
	}

	out := make([]NodeRef, len(e.node.Attrs))
	for i := range out {
		out[i] = attributeRef(e.doc, e.node, i)
	}

	slices.SortFunc(out, func(a, b NodeRef) int { return compareNames(a.Name(), b.Name()) })

	return out
}

// NamespaceNodes returns the in-scope XPath namespace axis, ordered by prefix.
// The xml binding is included. An empty default binding is ABSENT (not a node).
func (e Element) NamespaceNodes() []NodeRef {
	if !e.Valid() {
		return nil
	}

	scope := namespaceScope(e.node)

	prefixes := make([]string, 0, len(scope))
	for p, uri := range scope {
		if uri != "" {
			prefixes = append(prefixes, p)
		}
	}

	sort.Strings(prefixes)

	out := make([]NodeRef, len(prefixes))
	for i, p := range prefixes {
		out[i] = namespaceRef(e.doc, e.node, p)
	}

	return out
}

func namespaceScope(n *Node) map[string]string {
	scope := map[string]string{lexicon.PrefixXML: XMLNamespace}

	for ; n != nil; n = n.Parent {
		for _, ns := range n.NS {
			if _, exists := scope[ns.Prefix]; !exists {
				scope[ns.Prefix] = ns.URI
			}
		}
	}

	return scope
}

// Subtree selects this element, descendants and axes with cancellation and the
// snapshot node-set budget.
func (e Element) Subtree(ctx context.Context) (NodeSet, error) {
	if !e.Valid() {
		return NodeSet{}, fmt.Errorf("%w: invalid subtree", ErrMalformed)
	}

	return collectNodes(ctx, e.doc, e.node)
}

// String names the node kind, not XML markup or its potentially sensitive data.
func (k Kind) String() string {
	switch k {
	case ElementNode:
		return "element"
	case TextNode:
		return "text"
	case CommentNode:
		return "comment"
	case PINode:
		return "processing-instruction"
	case DocumentNode:
		return "document"
	case AttributeNode:
		return "attribute"
	case NamespaceNode:
		return "namespace"
	default:
		return "invalid"
	}
}

func ref(d *Document, n *Node) NodeRef {
	if d == nil || n == nil {
		return NodeRef{}
	}

	return NodeRef{doc: d, node: n, kind: n.Kind}
}

func attributeRef(d *Document, n *Node, i int) NodeRef {
	return NodeRef{doc: d, node: n, kind: AttributeNode, index: i}
}

func namespaceRef(d *Document, n *Node, prefix string) NodeRef {
	return NodeRef{doc: d, node: n, kind: NamespaceNode, prefix: prefix}
}

func compareNames(a, b Name) int {
	if order := cmp.Compare(a.Space, b.Space); order != 0 {
		return order
	}

	return cmp.Compare(a.Local, b.Local)
}

func collectNodes(ctx context.Context, d *Document, start *Node) (NodeSet, error) {
	if ctx == nil {
		return NodeSet{}, fmt.Errorf("%w: nil context", ErrMalformed)
	}

	if err := ctx.Err(); err != nil {
		return NodeSet{}, err
	}

	out, err := NewNodeSet(d)
	if err != nil {
		return NodeSet{}, err
	}

	var parent *Node
	if start != nil {
		parent = start.Parent
	}

	scope := newNamespaceContext(parent)

	if start == nil {
		if err := out.add(d.Node()); err != nil {
			return NodeSet{}, err
		}

		for _, n := range d.children {
			if err := collectNodeSubtree(ctx, d, n, &scope, &out); err != nil {
				return NodeSet{}, err
			}
		}
	} else if err := collectNodeSubtree(ctx, d, start, &scope, &out); err != nil {
		return NodeSet{}, err
	}

	return out, nil
}

func collectNodeSubtree(ctx context.Context, d *Document, n *Node, scope *namespaceContext, out *NodeSet) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := out.add(ref(d, n)); err != nil {
		return err
	}

	if n.Kind == ElementNode {
		mark := scope.push(n.NS)
		defer scope.pop(mark)

		for prefix, uri := range scope.bindings {
			if uri == "" {
				continue
			}

			if err := out.add(namespaceRef(d, n, prefix)); err != nil {
				return err
			}
		}

		for i := range n.Attrs {
			if err := out.add(attributeRef(d, n, i)); err != nil {
				return err
			}
		}
	}

	for _, child := range n.Children {
		if err := collectNodeSubtree(ctx, d, child, scope, out); err != nil {
			return err
		}
	}

	return nil
}
