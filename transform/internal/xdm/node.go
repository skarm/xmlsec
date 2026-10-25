package xdm

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/xmlchar"
)

// ElementType identifies a node kind in the XDM view, including internal CDATA
// identity.
type ElementType int

const (
	ElementNode ElementType = iota + 1
	AttributeNode
	TextNode
	CDATASectionNode

	ProcessingInstructionNode
	CommentNode
	DocumentNode

	NamespaceNode
)

// String returns a diagnostic node-kind name, falling back to the numeric value for
// unknown kinds.
func (t ElementType) String() string {
	switch t {
	case ElementNode:
		return "ElementNode"
	case AttributeNode:
		return "AttributeNode"
	case TextNode:
		return "TextNode"
	case DocumentNode:
		return "DocumentNode"
	case CommentNode:
		return "CommentNode"
	case ProcessingInstructionNode:
		return "ProcessingInstructionNode"
	case NamespaceNode:
		return "NamespaceNode"
	}

	return fmt.Sprintf("NodeKind(%d)", t)
}

// Node provides XDM identity and navigation over the project XML tree.
// Original XML content and child/attribute storage live in internal/tree.
// Node views can cache derived values; parsed documents are shared without serialization.
type Node interface {
	// view returns the package-private navigation state and restricts Node
	// implementations to this package.
	view() *nodeView
	// FirstChild returns the first child, or nil when the node has no children.
	FirstChild() Node
	// LastChild returns the last child, or nil when the node has no children.
	LastChild() Node
	// Line returns retained source line information, or zero when unavailable.
	Line() int
	// Name returns the node's lexical name as defined by its kind.
	Name() string
	// NextSibling returns the following sibling, or nil when absent.
	NextSibling() Node
	// PrevSibling returns the preceding sibling, or nil when absent.
	PrevSibling() Node
	// OwnerDocument returns the document retaining this node's storage and identity.
	OwnerDocument() *Document
	// Parent returns the logical parent, or nil for a document root or detached node.
	Parent() Node
	// Type identifies the node kind used by navigation and serialization.
	Type() ElementType
	// Reference returns the underlying project-tree handle when the view can represent
	// one.
	Reference() tree.NodeRef
}

// CopyNode copies src into d without attaching it to a parent. It preserves ID
// classification and source namespace context for copied element subtrees.
func CopyNode(src Node, d *Document) (Node, error) {
	if a, ok := src.(*Attribute); ok {
		copied, err := d.CreateAttribute(a.LocalName(), a.Value(), a.Namespace())
		if err == nil {
			copied.SetIDType(a.IDType())
		}

		return copied, err
	}

	root := src.view().raw
	if root.Kind == tree.ElementNode {
		root = tree.ImportSubtree(root)
	}

	draft := tree.FromNodes([]*tree.Node{root}, tree.DefaultLimits())

	cp, err := tree.Clone(context.Background(), draft)
	if err != nil {
		return nil, err
	}

	r := tree.Children(cp)[0]
	if err = d.wrap(context.Background(), r, -1); err != nil {
		return nil, err
	}

	copyIDProperties(src, d.nodes[r])

	return d.nodes[r], nil
}

// MutableNode provides internal draft construction and editing. Callers must not
// mutate a frozen source view or concurrently edit a draft.
type MutableNode interface {
	Node
	// AddChild appends a child to the mutable draft and updates ownership and sibling
	// positions.
	AddChild(Node) error
	// AddSibling inserts a sibling next to this draft node.
	AddSibling(Node) error
	// AppendText adds character data to the mutable draft.
	AppendText(string) error
	// Replace substitutes the supplied nodes at this draft node's position.
	Replace(...Node) error
	// SetLine sets retained source line metadata for internal construction.
	SetLine(int)
	// SetOwnerDocument updates the view's owner during internal draft adoption.
	SetOwnerDocument(*Document)
	// SetTreeDoc updates the document association used by internal tree construction.
	SetTreeDoc(*Document)
}

// NodeWalkerFunc adapts a function to the visitor contract used by Walk.
type NodeWalkerFunc func(Node) error

// Visit calls the underlying function for n.
func (f NodeWalkerFunc) Visit(n Node) error { return f(n) }

// DocumentStandaloneType records XML declaration presence and standalone metadata.
type DocumentStandaloneType int

const (
	StandaloneImplicitNo DocumentStandaloneType = iota
	StandaloneExplicitYes
	StandaloneExplicitNo
	StandaloneNoXMLDecl
)

// DocProperties is a bit set of internal document construction flags.
type DocProperties int

const (
	DocInternal DocProperties = 1 << iota
)

// Document stores an XDM view and construction metadata over a project XML tree. New
// drafts are mutable. Freeze marks a view for shared read-only use; callers must not
// alter its metadata after publication.
type Document struct {
	nodeView
	// native retains the project tree backing this document view.
	native *tree.Document
	// nodes preserves one view per underlying tree node within this document.
	nodes map[*tree.Node]Node
	// attrs caches attribute views by owning tree node and expanded attribute name.
	attrs map[attrKey]*Attribute
	// readOnly marks a published view whose tree must no longer be edited.
	readOnly atomic.Bool
	// url is the document retrieval URI used as the base for relative references.
	url string
	// encoding retains the XML encoding label for declaration output.
	encoding string
	// version retains the XML version used by construction and serialization.
	version string
	// standalone retains XML declaration and standalone metadata.
	standalone DocumentStandaloneType
	// properties records internal construction flags separately from the tree.
	properties DocProperties
	// ids indexes declared ID values to their owning elements.
	ids map[string]*Element
	// Doctype retains optional output declaration metadata separately from the node tree.
	Doctype *Doctype
}

type sharedViewKey struct{}

// NewDocument creates an empty mutable draft with explicit XML declaration metadata.
func NewDocument(version, encoding string, standalone DocumentStandaloneType) *Document {
	d := &Document{nodes: map[*tree.Node]Node{}, attrs: map[attrKey]*Attribute{}, ids: map[string]*Element{}, version: version, encoding: encoding, standalone: standalone}
	d.nodeView = nodeView{raw: &tree.Node{Kind: tree.DocumentNode}, doc: d, slot: -1, kind: DocumentNode, self: d}
	d.native = tree.FromNodes(nil, tree.DefaultLimits())

	return d
}

// WrapDocument builds an unfrozen view over borrowed tree storage. Callers must not
// mutate a borrowed published snapshot; FromDocument supplies the shared frozen view
// for read-only use.
func WrapDocument(ctx context.Context, d *tree.Document) (*Document, error) {
	if d == nil {
		return nil, tree.ErrMalformed
	}

	out := NewDefaultDocument()
	out.native = d

	out.raw.Children = tree.Children(d)
	for i, r := range out.raw.Children {
		if err := out.wrap(ctx, r, i); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// NewDefaultDocument creates an empty mutable XML 1.0 UTF-8 draft with implicit
// standalone=no metadata.
func NewDefaultDocument() *Document { return NewDocument("1.0", "UTF-8", StandaloneImplicitNo) }

// CopyDoc clones tree storage and document metadata into a mutable independent
// document.
func CopyDoc(src *Document) (*Document, error) {
	cp, err := tree.Clone(context.Background(), src.native)
	if err != nil {
		return nil, err
	}

	d, err := WrapDocument(context.Background(), cp)
	if err == nil {
		d.url = src.url
		d.encoding = src.encoding
		d.version = src.version
		d.standalone = src.standalone
		d.properties = src.properties
		copyDocumentBases(src, d)
		CopyDoctype(src, d)
	}

	return d, err
}

// CopyTree clones a snapshot tree, retaining its root kind and construction
// bases without attaching the root to a new parent.
func CopyTree(src Node) (Node, error) {
	if doc, ok := src.(*Document); ok {
		return CopyDoc(doc)
	}

	if namespace, ok := src.(*NamespaceNodeWrapper); ok {
		return NewNamespaceNodeWrapper(NewNamespace(namespace.Name(), CharacterData(namespace)), nil), nil
	}

	doc := NewDefaultDocument()
	if owner := src.OwnerDocument(); owner != nil {
		doc.url, doc.encoding, doc.version = owner.url, owner.encoding, owner.version
		doc.standalone, doc.properties = owner.standalone, owner.properties
		CopyDoctype(owner, doc)
	}

	copied, err := CopyNode(src, doc)
	if err != nil {
		return nil, err
	}

	copyDocumentBases(src, copied)

	return copied, nil
}

func copyIDProperties(source, destination Node) {
	first, ok := source.(*Element)
	if ok {
		if second, ok := destination.(*Element); ok {
			for _, attribute := range first.Attributes() {
				if kind := attribute.IDType(); kind != UntypedAttribute {
					if target := second.GetAttributeNodeNS(attribute.LocalName(), attribute.URI()); target != nil {
						target.SetIDType(kind)
					}
				}
			}
		}
	}

	a, b := source.FirstChild(), destination.FirstChild()
	for a != nil && b != nil {
		copyIDProperties(a, b)
		a, b = a.NextSibling(), b.NextSibling()
	}
}

// Snapshot cloning preserves construction bases stored outside XML attributes.
// Language copies into new parents apply their own inheritance rules separately.
func copyDocumentBases(source, destination Node) {
	destination.view().baseURI = source.view().baseURI
	destination.OwnerDocument().native.SetNodeBase(destination.view().raw, source.view().baseURI)

	first, second := source.FirstChild(), destination.FirstChild()
	for first != nil && second != nil {
		copyDocumentBases(first, second)
		first, second = first.NextSibling(), second.NextSibling()
	}
}

// FromDocument returns a stable read-only view, so repeated imports of the
// same snapshot preserve XPath document/node identity across engines.
func FromDocument(ctx context.Context, d *tree.Document) (*Document, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if v, ok := tree.LoadView(d, sharedViewKey{}); ok {
		return checkedDocumentView(v), nil
	}

	v, err := WrapDocument(ctx, d)
	if err != nil {
		return nil, err
	}

	v.Freeze()

	return checkedDocumentView(tree.StoreView(d, sharedViewKey{}, v)), nil
}

func checkedDocumentView(v any) *Document {
	d, ok := v.(*Document)
	if !ok || d == nil {
		panic("invalid internal snapshot view")
	}

	return d
}

// Snapshot returns the underlying tree document without copying it. A mutable draft's
// storage must not be published before construction finishes.
func (d *Document) Snapshot() *tree.Document { return d.native }

// Freeze marks the view as read-only for checked tree mutations. Internal callers
// must also leave document metadata unchanged after publication.
func (d *Document) Freeze() { d.readOnly.Store(true) }

// DocumentElement returns the first document child element, or nil when absent.
func (d *Document) DocumentElement() *Element {
	for _, r := range d.raw.Children {
		if r.Kind == tree.ElementNode {
			e := mustNode[*Element](d.nodes[r])
			return e
		}
	}

	return nil
}

// SetDocumentElement replaces the existing root element with e in an internal mutable
// draft.
func (d *Document) SetDocumentElement(e MutableNode) error {
	if old := d.DocumentElement(); old != nil {
		UnlinkNode(old)
	}

	return d.AddChild(e)
}

// CreateElement creates a detached element view after validating its lexical QName
// components.
func (d *Document) CreateElement(name string) (*Element, error) {
	prefix, local := splitName(name)
	if !tree.NCName(local) || prefix != "" && !tree.NCName(prefix) {
		return nil, tree.ErrMalformed
	}

	r := &tree.Node{Kind: tree.ElementNode, Name: tree.Name{Local: local}, Prefix: prefix}
	_ = d.wrap(context.Background(), r, -1)

	return mustNode[*Element](d.nodes[r]), nil
}

// CreateElementNS creates a detached element and applies the supplied namespace
// binding when non-nil.
func (d *Document) CreateElementNS(local string, ns *Namespace) (*Element, error) {
	e, err := d.CreateElement(local)
	if err == nil && ns != nil {
		e.SetNamespace(ns)
	}

	return e, err
}

// CreateAttribute creates a detached attribute view with the supplied value and
// namespace binding.
func (d *Document) CreateAttribute(name, value string, ns *Namespace) (*Attribute, error) {
	e, _ := d.CreateElement("attribute-owner")

	if ns == nil {
		prefix, local := splitName(name)
		ns = NewNamespace(prefix, "")
		name = local
	}

	if err := e.SetAttributeNS(name, value, ns); err != nil {
		return nil, err
	}

	a := e.Attributes()[0]
	a.detached = true

	return a, nil
}

// CreateNamespace validates the optional prefix and creates a namespace binding.
func (d *Document) CreateNamespace(prefix, uri string) (*Namespace, error) {
	if prefix != "" && !tree.NCName(prefix) {
		return nil, tree.ErrMalformed
	}

	return NewNamespace(prefix, uri), nil
}

// CreateText stores immutable text without copying its bytes.
func (d *Document) CreateText(value string) *Text {
	r := &tree.Node{Kind: tree.TextNode, Data: value}
	_ = d.wrap(context.Background(), r, -1)

	return mustNode[*Text](d.nodes[r])
}

// CreateComment stores immutable text; serialization checks XML comment syntax.
func (d *Document) CreateComment(value string) *Comment {
	r := &tree.Node{Kind: tree.CommentNode, Data: value}
	_ = d.wrap(context.Background(), r, -1)

	return mustNode[*Comment](d.nodes[r])
}

// CreatePI creates a detached processing instruction. Serialization validates its
// target and data syntax.
func (d *Document) CreatePI(name, data string) *ProcessingInstruction {
	r := &tree.Node{Kind: tree.PINode, Name: tree.Name{Local: name}, Data: data}
	_ = d.wrap(context.Background(), r, -1)

	return mustNode[*ProcessingInstruction](d.nodes[r])
}

// CreateCDATASection retains immutable text with a CDATA node identity.
func (d *Document) CreateCDATASection(value string) *CDATASection {
	r := &tree.Node{Kind: tree.TextNode, Data: value}
	n := &CDATASection{raw: r, doc: d, slot: -1, kind: CDATASectionNode}
	n.self = n
	d.nodes[r] = n

	return n
}

// URL returns the document retrieval URI or construction base.
func (d *Document) URL() string { return d.url }

// SetURL sets retrieval metadata on an internal draft. Callers must not change
// published views.
func (d *Document) SetURL(s string) { d.url = s }

// Encoding returns the encoding metadata, defaulting to UTF-8 when empty.
func (d *Document) Encoding() string {
	if d.encoding == "" {
		return "UTF-8"
	}

	return d.encoding
}

// RawEncoding returns the stored encoding metadata without applying a default.
func (d *Document) RawEncoding() string { return d.encoding }

// SetEncoding updates encoding metadata on an internal draft.
func (d *Document) SetEncoding(s string) { d.encoding = s }

// Version returns the stored XML version metadata.
func (d *Document) Version() string { return d.version }

// SetVersion updates XML version metadata on an internal draft.
func (d *Document) SetVersion(s string) { d.version = s }

// Standalone returns XML declaration and standalone metadata.
func (d *Document) Standalone() DocumentStandaloneType { return d.standalone }

// Properties returns the internal document flags.
func (d *Document) Properties() DocProperties { return d.properties }

// SetProperties replaces the internal flags on a draft document.
func (d *Document) SetProperties(p DocProperties) { d.properties = p }

// HasProperty reports whether any bit in p is set.
func (d *Document) HasProperty(p DocProperties) bool { return d.properties&p != 0 }

// RegisterID records the element for an ID value in the draft's lookup index. It does
// not authenticate or validate the element.
func (d *Document) RegisterID(id string, e *Element) { d.ids[id] = e }

// UnparsedEntity returns retained unparsed entity identifiers without retrieving the
// resource.
func (d *Document) UnparsedEntity(name string) (tree.UnparsedEntity, bool) {
	return d.native.UnparsedEntity(name)
}

// GetElementByID returns the indexed element, or nil when no ID mapping exists.
func (d *Document) GetElementByID(id string) *Element { return d.ids[id] }

func (d *Document) wrap(ctx context.Context, r *tree.Node, slot int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if _, ok := d.nodes[r]; ok {
		return nil
	}

	var (
		n    Node
		kind ElementType
	)

	switch r.Kind {
	case tree.ElementNode:
		kind, n = ElementNode, &Element{}
	case tree.TextNode:
		kind, n = TextNode, &Text{}
	case tree.CommentNode:
		kind, n = CommentNode, &Comment{}
	case tree.PINode:
		kind, n = ProcessingInstructionNode, &ProcessingInstruction{}
	default:
		return tree.ErrUnsupported
	}

	*n.view() = nodeView{raw: r, doc: d, slot: slot, line: int(r.SourceLine), baseURI: d.native.NodeBase(r), kind: kind, self: n}

	d.nodes[r] = n
	if e, ok := n.(*Element); ok {
		for i, a := range r.Attrs {
			d.attribute(e, a.Name, i)

			if d.native.AttributeDTDType(r, a.Name) == tree.DTDID || a.Name == (tree.Name{Space: tree.XMLNamespace, Local: "id"}) {
				d.ids[d.attrs[attrKey{r, a.Name}].Value()] = e
			}
		}
	}

	for i, c := range r.Children {
		if err := d.wrap(ctx, c, i); err != nil {
			return err
		}
	}

	return nil
}

func (d *Document) sync() {
	if !d.readOnly.Load() {
		tree.SetDraftChildren(d.native, d.raw.Children)
	}
}

func (d *Document) adopt(n Node) {
	old := n.OwnerDocument()
	d.native.SetNodeBase(n.view().raw, n.view().baseURI)
	n.view().doc = d

	d.nodes[n.view().raw] = n
	if e, ok := n.(*Element); ok {
		for i, entry := range e.raw.Attrs {
			if entry.Name == (tree.Name{Space: tree.XMLNamespace, Local: "id"}) {
				d.ids[xmlchar.CollapseSpace(entry.Value)] = e
			}

			key := attrKey{e.raw, entry.Name}
			if a := old.attrs[key]; a != nil {
				kind := a.IDType()
				a.doc = d
				a.owner = e
				a.parent = e
				a.attributeIndex = i
				d.attrs[key] = a
				a.SetIDType(kind)
			} else {
				d.attribute(e, entry.Name, i)
			}
		}
	}

	for _, r := range n.view().raw.Children {
		if child := old.nodes[r]; child != nil {
			d.adopt(child)
		}
	}
}

func (d *Document) attribute(e *Element, name tree.Name, index int) {
	key := attrKey{e.raw, name}
	if a := d.attrs[key]; a != nil {
		a.detached = false
		a.attributeIndex = index
		a.refreshXMLID()

		return
	}

	a := &Attribute{raw: e.raw, doc: d, kind: AttributeNode, slot: -1, parent: e, key: name, owner: e, attributeIndex: index}
	a.self = a
	a.refreshXMLID()
	d.attrs[key] = a
}

type (
	// Element is an XDM element view over project-tree storage.
	Element struct{ nodeView }
	// Text is an XDM text view over project-tree character data.
	Text struct{ nodeView }
	// Comment is an XDM comment view over project-tree character data.
	Comment struct{ nodeView }
	// ProcessingInstruction is an XDM view of a processing instruction target and data.
	ProcessingInstruction struct{ nodeView }
	// CDATASection retains internal CDATA construction identity over text-node storage.
	CDATASection struct{ nodeView }
)

// Prefix returns the element's lexical namespace prefix.
func (e *Element) Prefix() string { return e.raw.Prefix }

// URI returns the element's expanded namespace URI.
func (e *Element) URI() string { return e.raw.Name.Space }

// Namespace returns a copy of the element's active namespace binding, or nil for an
// unprefixed name without a namespace.
func (e *Element) Namespace() *Namespace {
	if e.Prefix() == "" && e.URI() == "" {
		return nil
	}

	return NewNamespace(e.Prefix(), e.URI())
}

// Namespaces returns copies of declarations written on this element, excluding
// inherited bindings.
func (e *Element) Namespaces() []*Namespace {
	out := make([]*Namespace, len(e.raw.NS))
	for i, ns := range e.raw.NS {
		out[i] = NewNamespace(ns.Prefix, ns.URI)
	}

	return out
}

// SetNamespace changes the draft element's active name binding. Nil clears it. It
// panics when the view is frozen.
func (e *Element) SetNamespace(ns *Namespace) {
	if err := e.mutable(); err != nil {
		panic(err)
	}

	if ns == nil {
		e.raw.Prefix = ""
		e.raw.Name.Space = ""
	} else {
		e.raw.Prefix = ns.Prefix()
		e.raw.Name.Space = ns.URI()
	}
}

// SetActiveNamespace changes the draft element's active prefix and URI without adding
// a declaration.
func (e *Element) SetActiveNamespace(prefix, uri string) error {
	e.SetNamespace(NewNamespace(prefix, uri))
	return nil
}

// DeclareNamespace adds or replaces a lexical declaration on a mutable element.
func (e *Element) DeclareNamespace(prefix, uri string) error {
	if err := e.mutable(); err != nil {
		return err
	}

	for i, ns := range e.raw.NS {
		if ns.Prefix == prefix {
			e.raw.NS[i].URI = uri
			return nil
		}
	}

	e.raw.NS = append(e.raw.NS, tree.Namespace{Prefix: prefix, URI: uri})

	return nil
}

// AddNamespaceDecl copies the supplied binding into the element's declarations.
func (e *Element) AddNamespaceDecl(ns *Namespace) error {
	return e.DeclareNamespace(ns.Prefix(), ns.URI())
}

// RemoveNamespaceByPrefix removes a lexical declaration and reports whether it
// existed. It panics when the view is frozen.
func (e *Element) RemoveNamespaceByPrefix(prefix string) bool {
	if err := e.mutable(); err != nil {
		panic(err)
	}

	for i, ns := range e.raw.NS {
		if ns.Prefix == prefix {
			e.raw.NS = slices.Delete(e.raw.NS, i, i+1)
			return true
		}
	}

	return false
}

// SetAttribute sets a draft attribute by lexical QName, using the element's in-scope
// prefix binding when available.
func (e *Element) SetAttribute(name, value string) error {
	prefix, local := splitName(name)
	uri := ""

	if prefix != "" {
		ns := LookupNSByPrefix(e, prefix)
		if ns != nil {
			uri = ns.URI()
		}
	}

	return e.SetAttributeNS(local, value, NewNamespace(prefix, uri))
}

// SetAttributeNS sets a draft attribute by expanded name and normalizes xml:id values
// for XDM lookup.
func (e *Element) SetAttributeNS(local, value string, ns *Namespace) error {
	if err := e.mutable(); err != nil {
		return err
	}

	prefix, uri := "", ""
	if ns != nil {
		prefix, uri = ns.Prefix(), ns.URI()
	}

	name := tree.Name{Space: uri, Local: local}
	if uri == tree.XMLNamespace && local == "id" {
		value = xmlchar.CollapseSpace(value)
	}

	for i, a := range e.raw.Attrs {
		if a.Name == name {
			view := e.doc.attrs[attrKey{e.raw, name}]
			isID := view.IDType() == IDAttribute
			e.raw.Attrs[i].Value = value

			e.raw.Attrs[i].Prefix = prefix
			if isID {
				if oldID := xmlchar.CollapseSpace(a.Value); e.doc.ids[oldID] == e {
					delete(e.doc.ids, oldID)
				}

				e.doc.RegisterID(value, e)

				if uri == tree.XMLNamespace && local == "id" {
					view.xmlIDValue = value
				}
			}

			return nil
		}
	}

	e.raw.Attrs = append(e.raw.Attrs, tree.Attribute{Name: name, Prefix: prefix, Value: value})
	e.doc.attribute(e, name, len(e.raw.Attrs)-1)

	if uri == tree.XMLNamespace && local == "id" {
		e.doc.RegisterID(value, e)
	}

	return nil
}

// SetParsedAttribute stores an already parsed attribute through SetAttribute.
func (e *Element) SetParsedAttribute(n, v string) error { return e.SetAttribute(n, v) }

// SetParsedAttributeNS stores an already parsed attribute through SetAttributeNS.
func (e *Element) SetParsedAttributeNS(n, v string, ns *Namespace) error {
	return e.SetAttributeNS(n, v, ns)
}

// SetBooleanAttribute creates or replaces an attribute with an empty value.
func (e *Element) SetBooleanAttribute(n string) error { return e.SetAttribute(n, "") }

// GetAttribute returns an attribute value by lexical prefix and local name, with a
// presence flag.
func (e *Element) GetAttribute(n string) (string, bool) {
	prefix, local := splitName(n)
	for _, a := range e.raw.Attrs {
		if a.Name.Local == local && a.Prefix == prefix {
			return e.attributeValue(a), true
		}
	}

	return "", false
}

// HasAttribute reports whether an attribute with the lexical name exists.
func (e *Element) HasAttribute(n string) bool { _, ok := e.GetAttribute(n); return ok }

// GetAttributeNS returns an attribute value by expanded name, with a presence flag.
func (e *Element) GetAttributeNS(local, uri string) (string, bool) {
	for _, a := range e.raw.Attrs {
		if a.Name == (tree.Name{Space: uri, Local: local}) {
			return e.attributeValue(a), true
		}
	}

	return "", false
}

// GetAttributeNodeNS returns the attribute view for an expanded name, or nil when
// absent.
func (e *Element) GetAttributeNodeNS(local, uri string) *Attribute {
	if _, ok := e.GetAttributeNS(local, uri); !ok {
		return nil
	}

	return e.doc.attrs[attrKey{e.raw, tree.Name{Space: uri, Local: local}}]
}

// Attributes returns an independent slice of shared attribute views in stored order.
func (e *Element) Attributes() []*Attribute {
	out := make([]*Attribute, len(e.raw.Attrs))
	for i, a := range e.raw.Attrs {
		out[i] = e.doc.attrs[attrKey{e.raw, a.Name}]
	}

	return out
}

// AttributeCount returns the number of attributes without constructing views.
func (e *Element) AttributeCount() int { return len(e.raw.Attrs) }

// ForEachAttributeValue visits expanded names and XDM-normalized values in stored
// order without constructing attribute views or a slice. It stops when fn returns
// false. The callback must not mutate the element during iteration.
func (e *Element) ForEachAttributeValue(fn func(local, uri, value string) bool) {
	for _, a := range e.raw.Attrs {
		if !fn(a.Name.Local, a.Name.Space, e.attributeValue(a)) {
			return
		}
	}
}

// ForEachAttribute visits attributes in stored order until fn returns false.
func (e *Element) ForEachAttribute(fn func(*Attribute) bool) {
	for _, a := range e.Attributes() {
		if !fn(a) {
			break
		}
	}
}

// RemoveAttribute removes a draft attribute by lexical QName and reports whether it
// existed.
func (e *Element) RemoveAttribute(name string) bool {
	for _, a := range e.raw.Attrs {
		if tree.QName(a.Prefix, a.Name.Local) == name {
			return e.RemoveAttributeNS(a.Name.Local, a.Name.Space)
		}
	}

	return false
}

// RemoveAttributeNS removes a draft attribute and its ID metadata by expanded name.
// It panics when the view is frozen.
func (e *Element) RemoveAttributeNS(local, uri string) bool {
	if err := e.mutable(); err != nil {
		panic(err)
	}

	for i, a := range e.raw.Attrs {
		if a.Name == (tree.Name{Space: uri, Local: local}) {
			view := e.doc.attrs[attrKey{e.raw, a.Name}]

			e.raw.Attrs = slices.Delete(e.raw.Attrs, i, i+1)
			for index := i; index < len(e.raw.Attrs); index++ {
				if shifted := e.doc.attrs[attrKey{e.raw, e.raw.Attrs[index].Name}]; shifted != nil {
					shifted.attributeIndex = index
				}
			}

			if view != nil && view.IDType() == IDAttribute {
				if id := xmlchar.CollapseSpace(a.Value); e.doc.ids[id] == e {
					delete(e.doc.ids, id)
				}
			}

			if view != nil {
				view.detached = true
				view.attributeIndex = -1
			}

			e.doc.native.SetAttributeDTDType(e.raw, a.Name, tree.DTDNoType)
			delete(e.doc.attrs, attrKey{e.raw, a.Name})

			return true
		}
	}

	return false
}

// FindAttribute returns the first attribute accepted by p and reports whether one was
// found.
func (e *Element) FindAttribute(p AttributePredicate) (*Attribute, bool) {
	for _, a := range e.Attributes() {
		if p.Match(a) {
			return a, true
		}
	}

	return nil, false
}

// Attribute views a non-namespace attribute and its XDM ID metadata. It retains its
// owning element even when logically detached.
type Attribute struct {
	nodeView
	// key identifies the attribute by expanded namespace URI and local name.
	key tree.Name
	// owner retains the element supplying attribute storage, including while detached.
	owner *Element
	// attributeIndex identifies the raw entry. Draft mutations update shifted
	// views; read-only access never changes this index.
	attributeIndex int
	// Cache the derived value so repeated reads do not rescan or allocate for
	// an immutable input attribute. Private mutations refresh it before publishing.
	xmlIDValue string
	// atype retains the attribute's ID or IDREF classification.
	atype AttributeIDType
	// detached hides the logical parent while retaining storage ownership.
	detached bool
}

// Name returns the attribute's lexical QName.
func (a *Attribute) Name() string { return tree.QName(a.Prefix(), a.LocalName()) }

// LocalName returns the attribute's expanded local name.
func (a *Attribute) LocalName() string { return a.key.Local }

// Prefix returns the stored lexical namespace prefix.
func (a *Attribute) Prefix() string { return a.entry().Prefix }

// URI returns the attribute's namespace URI.
func (a *Attribute) URI() string { return a.key.Space }

// Value exposes the XDM-normalized xml:id while retaining the original snapshot
// for references and export. Other attributes keep the XML parser's value.
func (a *Attribute) Value() string {
	if a.key == (tree.Name{Space: tree.XMLNamespace, Local: "id"}) {
		return a.xmlIDValue
	}

	return a.entry().Value
}

func (a *Attribute) refreshXMLID() {
	if a.key == (tree.Name{Space: tree.XMLNamespace, Local: "id"}) {
		a.xmlIDValue = xmlchar.CollapseSpace(a.entry().Value)
	}
}

func (e *Element) attributeValue(a tree.Attribute) string {
	if a.Name == (tree.Name{Space: tree.XMLNamespace, Local: "id"}) {
		return e.doc.attrs[attrKey{e.raw, a.Name}].Value()
	}

	return a.Value
}

// Namespace returns a copy of the attribute's active binding, or nil when no prefix
// or URI is present.
func (a *Attribute) Namespace() *Namespace {
	if a.URI() == "" && a.Prefix() == "" {
		return nil
	}

	return NewNamespace(a.Prefix(), a.URI())
}

// Parent returns the owning element, or nil when the attribute is detached.
func (a *Attribute) Parent() Node {
	if a.detached {
		return nil
	}

	return a.owner
}

// NextAttribute returns the next attribute in its owner's stored order, or nil when
// absent.
func (a *Attribute) NextAttribute() *Attribute {
	attrs := a.owner.Attributes()
	for i, v := range attrs {
		if v == a && i+1 < len(attrs) {
			return attrs[i+1]
		}
	}

	return nil
}

// FirstChild returns nil because XDM attributes have no child nodes.
func (a *Attribute) FirstChild() Node { return nil }

// LastChild returns nil because XDM attributes have no child nodes.
func (a *Attribute) LastChild() Node { return nil }

// IDType returns the retained ID or IDREF classification, recognizing xml:id
// independently of DTD metadata.
func (a *Attribute) IDType() AttributeIDType {
	if a.key == (tree.Name{Space: tree.XMLNamespace, Local: "id"}) {
		return IDAttribute
	}

	if a.atype != 0 {
		return a.atype
	}

	switch a.doc.native.AttributeDTDType(a.owner.raw, a.key) {
	case tree.DTDID:
		return IDAttribute
	case tree.DTDIDRef:
		return IDRefAttribute
	case tree.DTDIDRefs:
		return IDRefsAttribute
	}

	return a.atype
}

// SetIDType changes draft ID classification and updates the document's ID lookup
// metadata.
func (a *Attribute) SetIDType(t AttributeIDType) {
	if a.IDType() == IDAttribute && a.doc.ids[a.Value()] == a.owner {
		delete(a.doc.ids, a.Value())
	}

	a.atype = t
	kind := tree.DTDNoType

	switch t {
	case IDAttribute:
		kind = tree.DTDID
	case IDRefAttribute:
		kind = tree.DTDIDRef
	case IDRefsAttribute:
		kind = tree.DTDIDRefs
	}

	a.doc.native.SetAttributeDTDType(a.owner.raw, a.key, kind)

	if t == IDAttribute {
		a.doc.RegisterID(a.Value(), a.owner)
	}
}

func (a *Attribute) entry() tree.Attribute {
	if i := a.attributeIndex; i >= 0 && i < len(a.owner.raw.Attrs) && a.owner.raw.Attrs[i].Name == a.key {
		return a.owner.raw.Attrs[i]
	}

	// Retain detached/stale-view behavior without writing a cache during reads.
	for _, v := range a.owner.raw.Attrs {
		if v.Name == a.key {
			return v
		}
	}

	return tree.Attribute{Name: a.key}
}

type (
	// AttributePredicate selects attributes for FindAttribute.
	AttributePredicate interface {
		// Match reports whether the attribute satisfies the predicate.
		Match(*Attribute) bool
	}
	// QNamePredicate matches an attribute's lexical QName, including its prefix.
	QNamePredicate string
)

// Match compares the attribute's lexical QName with p.
func (p QNamePredicate) Match(a *Attribute) bool { return a.Name() == string(p) }

// LocalNamePredicate matches attribute local names without restricting their
// namespaces.
type LocalNamePredicate string

// Match compares the attribute's local name with p.
func (p LocalNamePredicate) Match(a *Attribute) bool { return a.LocalName() == string(p) }

// NSPredicate matches an attribute's expanded namespace URI and local name.
type NSPredicate struct {
	// LocalName is the exact attribute local name to match.
	LocalName string
	// URI is the exact attribute namespace URI to match.
	URI string
}

// Match reports whether both expanded-name components match.
func (p NSPredicate) Match(a *Attribute) bool {
	return a.LocalName() == p.LocalName && a.URI() == p.URI
}

// Namespace holds a lexical prefix and namespace URI binding.
type Namespace struct {
	// binding retains the lexical prefix and namespace URI.
	binding tree.Namespace
}

// NewNamespace creates a binding without validating its prefix or URI.
func NewNamespace(prefix, uri string) *Namespace {
	return &Namespace{tree.Namespace{Prefix: prefix, URI: uri}}
}

// LookupNSByPrefix searches the node and its ancestors for a prefix binding. The xml
// prefix always has its predefined binding.
func LookupNSByPrefix(n Node, prefix string) *Namespace {
	if prefix == "xml" {
		return NewNamespace("xml", tree.XMLNamespace)
	}

	for ; n != nil; n = n.Parent() {
		if e, ok := n.(*Element); ok {
			for _, ns := range e.raw.NS {
				if ns.Prefix == prefix {
					return NewNamespace(prefix, ns.URI)
				}
			}

			if e.Prefix() == prefix && e.URI() != "" {
				return e.Namespace()
			}
		}
	}

	return nil
}

// LookupNSByHref searches the node and its ancestors for a lexical declaration with
// the given namespace URI.
func LookupNSByHref(n Node, uri string) *Namespace {
	for ; n != nil; n = n.Parent() {
		if e, ok := n.(*Element); ok {
			for _, ns := range e.Namespaces() {
				if ns.URI() == uri {
					return ns
				}
			}
		}
	}

	return nil
}

// NamespaceDeclarationAt reads one lexical binding without copying the list.
func NamespaceDeclarationAt(e *Element, index int) (*Namespace, bool) {
	if index < 0 || index >= len(e.raw.NS) {
		return nil, false
	}

	v := e.raw.NS[index]

	return NewNamespace(v.Prefix, v.URI), true
}

// Prefix returns the lexical namespace prefix.
func (n *Namespace) Prefix() string { return n.binding.Prefix }

// URI returns the namespace URI.
func (n *Namespace) URI() string { return n.binding.URI }

type (
	// NamespaceContainer exposes an element's lexical namespace declarations.
	NamespaceContainer interface {
		// Namespaces returns the lexical namespace declarations carried by the node.
		Namespaces() []*Namespace
	}
	// Namespacer exposes expanded-name components and lexical namespace bindings.
	Namespacer interface {
		// Namespace returns the active name binding when present.
		Namespace() *Namespace
		// Namespaces returns lexical declarations carried by the node.
		Namespaces() []*Namespace
		// Prefix returns the lexical name prefix.
		Prefix() string
		// URI returns the expanded namespace URI.
		URI() string
		// LocalName returns the name without its prefix.
		LocalName() string
	}
)

// NamespaceNodeWrapper gives an in-scope binding a logical owner and XDM
// namespace-node identity.
type NamespaceNodeWrapper struct {
	nodeView
	// ns supplies the binding represented by this virtual namespace node.
	ns *Namespace
}

// NewNamespaceNodeWrapper creates a namespace node for ns and owner. A nil owner
// produces a detached wrapper.
func NewNamespaceNodeWrapper(ns *Namespace, owner Node) *NamespaceNodeWrapper {
	var doc *Document
	if !IsNilNode(owner) {
		doc = owner.OwnerDocument()
	}

	n := &NamespaceNodeWrapper{doc: doc, kind: NamespaceNode, parent: owner, slot: -1, ns: ns}
	n.self = n

	return n
}

// Name returns the namespace node's prefix, including empty for the default
// namespace.
func (n *NamespaceNodeWrapper) Name() string { return n.ns.Prefix() }

// UnlinkNode detaches a child from its mutable parent and updates sibling positions.
// It panics when the parent view is frozen.
func UnlinkNode(n MutableNode) {
	v := n.view()

	p := v.Parent()
	if p == nil {
		return
	}

	if err := p.view().mutable(); err != nil {
		panic(err)
	}

	p.view().raw.Children = slices.Delete(p.view().raw.Children, v.slot, v.slot+1)
	v.slot = -1
	v.raw.Parent = nil
	v.parent = nil

	reindex(p)
}

// AsNode reports whether n has concrete node type T and excludes typed nil values.
func AsNode[T Node](n Node) (T, bool) {
	v, ok := n.(T)
	if ok && IsNilNode(v) {
		var zero T
		return zero, false
	}

	return v, ok
}

// Children iterates direct children in order. It saves the next sibling before
// yielding, permitting draft edits by the caller.
func Children(n Node) iter.Seq[Node] {
	return func(yield func(Node) bool) {
		if n == nil {
			return
		}

		for c := n.FirstChild(); c != nil; {
			next := c.NextSibling()
			if !yield(c) {
				return
			}

			c = next
		}
	}
}

// ChildElements iterates direct element children in order.
func ChildElements(n Node) iter.Seq[*Element] {
	return func(yield func(*Element) bool) {
		for c := range Children(n) {
			if e, ok := c.(*Element); ok && !yield(e) {
				return
			}
		}
	}
}

// Walk visits n and its descendants in preorder, stopping at the first visitor error.
func Walk(n Node, w interface{ Visit(Node) error }) error {
	if n == nil {
		return nil
	}

	if err := w.Visit(n); err != nil {
		return err
	}

	for c := range Children(n) {
		if err := Walk(c, w); err != nil {
			return err
		}
	}

	return nil
}

// CharacterData returns the XDM string value for elements and documents, attribute
// values, namespace URIs or other nodes' stored character data.
func CharacterData(n Node) string {
	if n == nil {
		return ""
	}

	if a, ok := n.(*Attribute); ok {
		return a.Value()
	}

	if ns, ok := n.(*NamespaceNodeWrapper); ok {
		return ns.ns.URI()
	}

	v := n.view()
	if v.raw == nil {
		return ""
	}

	if n.Type() != DocumentNode && n.Type() != ElementNode {
		return v.raw.Data
	}

	return tree.StringValue(v.raw)
}

// ClarkName joins uri and local in the expanded-name form {uri}local.
func ClarkName(uri, local string) string { return "{" + uri + "}" + local }

// NodeGetBase resolves inherited xml:base and retained construction bases against the
// document URL.
func NodeGetBase(doc *Document, n Node) string {
	var chain []Node
	for p := n; p != nil; p = p.Parent() {
		chain = append(chain, p)
	}

	base := ""
	if doc != nil {
		base = doc.URL()
	}

	for _, p := range slices.Backward(chain) {
		if p.view().baseURI != "" {
			base = p.view().baseURI
		}

		if e, ok := p.(*Element); ok {
			if s, ok := e.GetAttributeNS("base", tree.XMLNamespace); ok {
				base = BuildURI(s, base)
			}
		}
	}

	return base
}

// NodeGetBaseBeforeXMLBase returns the base against which this node's own
// xml:base is resolved. It includes inherited and construction bases, allowing
// a selected stylesheet root to be compiled without resolving xml:base twice.
func NodeGetBaseBeforeXMLBase(doc *Document, node Node) string {
	if node == nil {
		return NodeGetBase(doc, nil)
	}

	base := NodeGetBase(doc, node.Parent())
	if node.view().baseURI != "" {
		base = node.view().baseURI
	}

	return base
}

// SetNodeBaseURI records a construction base on an internal node view without
// changing xml:base attributes.
func SetNodeBaseURI(n Node, uri string) { n.view().baseURI = uri }

// NodeBaseOverride returns the parser/construction base before xml:base.
func NodeBaseOverride(n Node) string { return n.view().baseURI }

// FilterChildren edits a private result/draft in one pass; source views are frozen.
func FilterChildren(n Node, keep func(Node) bool) {
	if err := n.view().mutable(); err != nil {
		panic(err)
	}

	v := n.view()

	out := v.raw.Children[:0]
	for _, r := range v.raw.Children {
		child := v.doc.nodes[r]
		if keep(child) {
			out = append(out, r)
		} else {
			child.view().slot = -1
			r.Parent = nil
		}
	}

	clear(v.raw.Children[len(out):])
	v.raw.Children = out

	reindex(n)
}

// Views are initialized in place; an assigned identity stays with its node.
type nodeView struct {
	// identity lazily assigns a process-unique node number without retaining other nodes.
	identity atomic.Uint64
	// raw borrows the underlying project-tree node when this node kind has one.
	raw *tree.Node
	// doc retains the document that owns this view's storage.
	doc *Document
	// self retains the concrete wrapper used when returning navigation results.
	self Node
	// kind selects XDM navigation behavior for the concrete node.
	kind ElementType
	// slot caches the node's sibling or attribute position; detached nodes can use a
	// negative value.
	slot int
	// line retains source line information when available.
	line int
	// baseURI retains an explicit base override for this view.
	baseURI string
	// parent retains the logical parent independently of underlying storage ownership.
	parent Node
}

var nextNodeIdentity atomic.Uint64 //nolint:gochecknoglobals // Process-unique, non-retaining identities must survive node collection.

// NodeIdentity returns a non-recycled number without retaining the node. Lazy
// assignment is safe for shared immutable snapshots and survives node adoption.
func NodeIdentity(n Node) uint64 {
	nv := n.view()
	if id := nv.identity.Load(); id != 0 {
		return id
	}

	id := nextNodeIdentity.Add(1)
	if nv.identity.CompareAndSwap(0, id) {
		return id
	}

	return nv.identity.Load()
}

func (nv *nodeView) Type() ElementType { return nv.kind }

func (nv *nodeView) Line() int { return nv.line }

func (nv *nodeView) SetLine(v int) { nv.line = v }

func (nv *nodeView) OwnerDocument() *Document { return nv.doc }

func (nv *nodeView) SetOwnerDocument(d *Document) { nv.doc = d }

func (nv *nodeView) SetTreeDoc(d *Document) {
	nv.doc = d
	for c := range Children(nv.self) {
		mustNode[MutableNode](c).SetTreeDoc(d)
	}
}

func (nv *nodeView) Name() string {
	if nv.raw == nil {
		return ""
	}

	return tree.QName(nv.raw.Prefix, nv.raw.Name.Local)
}

func (nv *nodeView) LocalName() string {
	if nv.raw == nil {
		return ""
	}

	return nv.raw.Name.Local
}

func (nv *nodeView) Parent() Node {
	if nv.parent != nil {
		return nv.parent
	}

	if nv.raw == nil || nv.doc == nil || nv.kind == DocumentNode {
		return nil
	}

	if nv.raw.Parent != nil {
		return nv.doc.nodes[nv.raw.Parent]
	}

	if nv.slot >= 0 && nv.slot < len(nv.doc.raw.Children) && nv.doc.raw.Children[nv.slot] == nv.raw {
		return nv.doc
	}

	return nil
}

func (nv *nodeView) FirstChild() Node {
	if nv.raw == nil || len(nv.raw.Children) == 0 {
		return nil
	}

	return nv.doc.nodes[nv.raw.Children[0]]
}

func (nv *nodeView) LastChild() Node {
	if nv.raw == nil || len(nv.raw.Children) == 0 {
		return nil
	}

	return nv.doc.nodes[nv.raw.Children[len(nv.raw.Children)-1]]
}

func (nv *nodeView) NextSibling() Node { return nv.sibling(1) }

func (nv *nodeView) PrevSibling() Node { return nv.sibling(-1) }

func (nv *nodeView) AddChild(child Node) error {
	if err := nv.mutable(); err != nil {
		return err
	}

	if child == nil || child.view().raw == nil {
		return errors.New("invalid XML child")
	}

	if nv.kind != ElementNode && nv.kind != DocumentNode {
		return errors.New("node cannot have children")
	}

	for p := nv.self; p != nil; p = p.Parent() {
		if p == child {
			return errors.New("XML tree cycle")
		}
	}

	if a, ok := child.(*Attribute); ok {
		if e, ok := nv.self.(*Element); ok {
			if err := e.SetAttributeNS(a.LocalName(), a.Value(), a.Namespace()); err != nil {
				return err
			}

			e.GetAttributeNodeNS(a.LocalName(), a.URI()).SetIDType(a.IDType())

			return nil
		}

		return errors.New("attribute parent must be an element")
	}

	if child.Type() == DocumentNode {
		for c := child.FirstChild(); c != nil; {
			next := c.NextSibling()
			if err := nv.AddChild(c); err != nil {
				return err
			}

			c = next
		}

		return nil
	}

	v := child.view()
	if v.doc != nil && v.doc.readOnly.Load() {
		var err error

		child, err = CopyNode(child, nv.doc)
		if err != nil {
			return err
		}

		v = child.view()
	} else {
		UnlinkNode(mustNode[MutableNode](child))
	}

	if v.doc != nv.doc {
		nv.doc.adopt(child)
	}

	if last := nv.LastChild(); last != nil && last.Type() == TextNode && child.Type() == TextNode {
		tree.AppendTextData(last.view().raw, v.raw.Data)
		return nil
	}

	v.raw.Parent = nv.raw
	if nv.kind == DocumentNode {
		v.raw.Parent = nil
	}

	v.parent = nil
	v.slot = len(nv.raw.Children)
	nv.raw.Children = append(nv.raw.Children, v.raw)
	nv.doc.sync()

	return nil
}

func (nv *nodeView) AddSibling(child Node) error {
	p := nv.Parent()
	if p == nil {
		return errors.New("detached sibling")
	}

	if err := p.view().mutable(); err != nil {
		return err
	}

	if child == nil || child == nv.self || child.view().raw == nil || child.Type() == AttributeNode || child.Type() == DocumentNode {
		return errors.New("invalid XML sibling")
	}

	for a := p; a != nil; a = a.Parent() {
		if a == child {
			return errors.New("XML tree cycle")
		}
	}

	if child.OwnerDocument().readOnly.Load() {
		var err error

		child, err = CopyNode(child, p.OwnerDocument())
		if err != nil {
			return err
		}
	} else {
		UnlinkNode(mustNode[MutableNode](child))
	}

	if child.OwnerDocument() != p.OwnerDocument() {
		p.OwnerDocument().adopt(child)
	}

	if nv.kind == TextNode && child.Type() == TextNode {
		tree.AppendTextData(nv.raw, child.view().raw.Data)
		return nil
	}

	v := child.view()
	v.parent = nil

	v.raw.Parent = p.view().raw
	if p.Type() == DocumentNode {
		v.raw.Parent = nil
	}

	p.view().raw.Children = slices.Insert(p.view().raw.Children, nv.slot+1, v.raw)
	reindex(p)

	return nil
}

func (nv *nodeView) AppendText(b string) error {
	if err := nv.mutable(); err != nil {
		return err
	}

	if nv.kind == TextNode || nv.kind == CDATASectionNode || nv.kind == CommentNode || nv.kind == ProcessingInstructionNode {
		tree.AppendTextData(nv.raw, b)
		return nil
	}

	return nv.AddChild(nv.doc.CreateText(b))
}

func (nv *nodeView) Replace(nodes ...Node) error {
	p := nv.Parent()
	if p == nil || nv.kind == AttributeNode || nv.kind == NamespaceNode || len(nodes) == 0 {
		return errors.New("cannot replace detached node")
	}

	if err := p.view().mutable(); err != nil {
		return err
	}

	prepared := make([]Node, len(nodes))

	seen := make(map[Node]struct{}, len(nodes))
	for i, c := range nodes {
		if c == nil || c.view().raw == nil || c.Type() == AttributeNode || c.Type() == DocumentNode {
			return errors.New("invalid replacement node")
		}

		if _, duplicate := seen[c]; duplicate {
			return errors.New("invalid replacement node")
		}

		seen[c] = struct{}{}
		for a := p; a != nil; a = a.Parent() {
			if a == c {
				return errors.New("XML tree cycle")
			}
		}

		if c.OwnerDocument().readOnly.Load() {
			var err error

			c, err = CopyNode(c, p.OwnerDocument())
			if err != nil {
				return err
			}
		}

		prepared[i] = c
	}

	for _, c := range prepared {
		if c != nv.self {
			UnlinkNode(mustNode[MutableNode](c))
		}
	}

	at := nv.slot
	UnlinkNode(mustNode[MutableNode](nv.self))

	insert := make([]*tree.Node, len(prepared))
	for i, c := range prepared {
		if c.OwnerDocument() != p.OwnerDocument() {
			p.OwnerDocument().adopt(c)
		}

		v := c.view()

		v.raw.Parent = p.view().raw
		if p.Type() == DocumentNode {
			v.raw.Parent = nil
		}

		v.parent = nil
		insert[i] = v.raw
	}
	// Splice without AddChild's append/coalescing behavior: XSLT uses temporary
	// placeholders and coalesces text after resolving them in document order.
	p.view().raw.Children = slices.Insert(p.view().raw.Children, at, insert...)
	reindex(p)

	return nil
}

func (nv *nodeView) view() *nodeView { return nv }

func (nv *nodeView) sibling(delta int) Node {
	p := nv.Parent()
	if p == nil || nv.kind == AttributeNode || nv.kind == NamespaceNode {
		return nil
	}

	children := p.view().raw.Children

	at := nv.slot + delta
	if at < 0 || at >= len(children) {
		return nil
	}

	return nv.doc.nodes[children[at]]
}

func (nv *nodeView) mutable() error {
	if nv.doc != nil && nv.doc.readOnly.Load() {
		return errors.New("immutable XML snapshot")
	}

	return nil
}

func reindex(p Node) {
	for i, r := range p.view().raw.Children {
		p.OwnerDocument().nodes[r].view().slot = i
	}

	p.OwnerDocument().sync()
}

type attrKey struct {
	node *tree.Node
	name tree.Name
}

func splitName(name string) (string, string) {
	if p, l, ok := strings.Cut(name, ":"); ok {
		return p, l
	}

	return "", name
}

// These assertions guard node-view invariants; all node implementations are sealed
// pointer views constructed in this package.
func mustNode[T Node](n Node) T {
	v, ok := AsNode[T](n)
	if !ok {
		panic("invalid internal node view")
	}

	return v
}
