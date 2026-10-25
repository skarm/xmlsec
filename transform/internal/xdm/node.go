// Node views implement XDM identity and navigation over the project XML tree.
// Original XML content and child/attribute storage live in internal/tree.
// Views can cache derived values; parsed documents are shared without serialization.
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

type Node interface {
	view() *nodeView
	FirstChild() Node
	LastChild() Node
	Line() int
	Name() string
	NextSibling() Node
	PrevSibling() Node
	OwnerDocument() *Document
	Parent() Node
	Type() ElementType
	Reference() tree.NodeRef
}

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

type MutableNode interface {
	Node
	AddChild(Node) error
	AddSibling(Node) error
	AppendText(string) error
	Replace(...Node) error
	SetLine(int)
	SetOwnerDocument(*Document)
	SetTreeDoc(*Document)
}

type NodeWalkerFunc func(Node) error

func (f NodeWalkerFunc) Visit(n Node) error { return f(n) }

type DocumentStandaloneType int

const (
	StandaloneImplicitNo DocumentStandaloneType = iota
	StandaloneExplicitYes
	StandaloneExplicitNo
	StandaloneNoXMLDecl
)

type DocProperties int

const (
	DocInternal DocProperties = 1 << iota
)

type Document struct {
	nodeView
	native                 *tree.Document
	nodes                  map[*tree.Node]Node
	attrs                  map[attrKey]*Attribute
	readOnly               atomic.Bool
	url, encoding, version string
	standalone             DocumentStandaloneType
	properties             DocProperties
	ids                    map[string]*Element
	Doctype                *Doctype
}

type sharedViewKey struct{}

func NewDocument(version, encoding string, standalone DocumentStandaloneType) *Document {
	d := &Document{nodes: map[*tree.Node]Node{}, attrs: map[attrKey]*Attribute{}, ids: map[string]*Element{}, version: version, encoding: encoding, standalone: standalone}
	d.nodeView = nodeView{raw: &tree.Node{Kind: tree.DocumentNode}, doc: d, slot: -1, kind: DocumentNode, self: d}
	d.native = tree.FromNodes(nil, tree.DefaultLimits())

	return d
}

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

func NewDefaultDocument() *Document { return NewDocument("1.0", "UTF-8", StandaloneImplicitNo) }

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

func (d *Document) Snapshot() *tree.Document { return d.native }

func (d *Document) Freeze() { d.readOnly.Store(true) }

func (d *Document) DocumentElement() *Element {
	for _, r := range d.raw.Children {
		if r.Kind == tree.ElementNode {
			e := mustNode[*Element](d.nodes[r])
			return e
		}
	}

	return nil
}

func (d *Document) SetDocumentElement(e MutableNode) error {
	if old := d.DocumentElement(); old != nil {
		UnlinkNode(old)
	}

	return d.AddChild(e)
}

func (d *Document) CreateElement(name string) (*Element, error) {
	prefix, local := splitName(name)
	if !tree.NCName(local) || prefix != "" && !tree.NCName(prefix) {
		return nil, tree.ErrMalformed
	}

	r := &tree.Node{Kind: tree.ElementNode, Name: tree.Name{Local: local}, Prefix: prefix}
	_ = d.wrap(context.Background(), r, -1)

	return mustNode[*Element](d.nodes[r]), nil
}

func (d *Document) CreateElementNS(local string, ns *Namespace) (*Element, error) {
	e, err := d.CreateElement(local)
	if err == nil && ns != nil {
		e.SetNamespace(ns)
	}

	return e, err
}

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

func (d *Document) URL() string { return d.url }

func (d *Document) SetURL(s string) { d.url = s }

func (d *Document) Encoding() string {
	if d.encoding == "" {
		return "UTF-8"
	}

	return d.encoding
}

func (d *Document) RawEncoding() string { return d.encoding }

func (d *Document) SetEncoding(s string) { d.encoding = s }

func (d *Document) Version() string { return d.version }

func (d *Document) SetVersion(s string) { d.version = s }

func (d *Document) Standalone() DocumentStandaloneType { return d.standalone }

func (d *Document) Properties() DocProperties { return d.properties }

func (d *Document) SetProperties(p DocProperties) { d.properties = p }

func (d *Document) HasProperty(p DocProperties) bool { return d.properties&p != 0 }

func (d *Document) RegisterID(id string, e *Element) { d.ids[id] = e }

func (d *Document) UnparsedEntity(name string) (tree.UnparsedEntity, bool) {
	return d.native.UnparsedEntity(name)
}

func (d *Document) GetElementByID(id string) *Element { return d.ids[id] }

func (d *Document) wrap(ctx context.Context, r *tree.Node, slot int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if _, ok := d.nodes[r]; ok {
		return nil
	}

	v := nodeView{raw: r, doc: d, slot: slot, line: int(r.SourceLine), baseURI: d.native.NodeBase(r)}

	var n Node

	switch r.Kind {
	case tree.ElementNode:
		v.kind = ElementNode
		n = &Element{nodeView: v}
	case tree.TextNode:
		v.kind = TextNode
		n = &Text{nodeView: v}
	case tree.CommentNode:
		v.kind = CommentNode
		n = &Comment{nodeView: v}
	case tree.PINode:
		v.kind = ProcessingInstructionNode
		n = &ProcessingInstruction{nodeView: v}
	default:
		return tree.ErrUnsupported
	}

	n.view().self = n

	d.nodes[r] = n
	if e, ok := n.(*Element); ok {
		for _, a := range r.Attrs {
			d.attribute(e, a.Name)

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
		for _, entry := range e.raw.Attrs {
			if entry.Name == (tree.Name{Space: tree.XMLNamespace, Local: "id"}) {
				d.ids[xmlchar.CollapseSpace(entry.Value)] = e
			}

			key := attrKey{e.raw, entry.Name}
			if a := old.attrs[key]; a != nil {
				kind := a.IDType()
				a.doc = d
				a.owner = e
				a.parent = e
				d.attrs[key] = a
				a.SetIDType(kind)
			} else {
				d.attribute(e, entry.Name)
			}
		}
	}

	for _, r := range n.view().raw.Children {
		if child := old.nodes[r]; child != nil {
			d.adopt(child)
		}
	}
}

func (d *Document) attribute(e *Element, name tree.Name) {
	key := attrKey{e.raw, name}
	if a := d.attrs[key]; a != nil {
		a.detached = false
		a.refreshXMLID()

		return
	}

	a := &Attribute{raw: e.raw, doc: d, kind: AttributeNode, slot: -1, parent: e, key: name, owner: e}
	a.self = a
	a.refreshXMLID()
	d.attrs[key] = a
}

type (
	Element               struct{ nodeView }
	Text                  struct{ nodeView }
	Comment               struct{ nodeView }
	ProcessingInstruction struct{ nodeView }
	CDATASection          struct{ nodeView }
)

func (e *Element) Prefix() string { return e.raw.Prefix }

func (e *Element) URI() string { return e.raw.Name.Space }

func (e *Element) Namespace() *Namespace {
	if e.Prefix() == "" && e.URI() == "" {
		return nil
	}

	return NewNamespace(e.Prefix(), e.URI())
}

func (e *Element) Namespaces() []*Namespace {
	out := make([]*Namespace, len(e.raw.NS))
	for i, ns := range e.raw.NS {
		out[i] = NewNamespace(ns.Prefix, ns.URI)
	}

	return out
}

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

func (e *Element) SetActiveNamespace(prefix, uri string) error {
	e.SetNamespace(NewNamespace(prefix, uri))
	return nil
}

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

func (e *Element) AddNamespaceDecl(ns *Namespace) error {
	return e.DeclareNamespace(ns.Prefix(), ns.URI())
}

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
	e.doc.attribute(e, name)

	if uri == tree.XMLNamespace && local == "id" {
		e.doc.RegisterID(value, e)
	}

	return nil
}

func (e *Element) SetParsedAttribute(n, v string) error { return e.SetAttribute(n, v) }

func (e *Element) SetParsedAttributeNS(n, v string, ns *Namespace) error {
	return e.SetAttributeNS(n, v, ns)
}

func (e *Element) SetBooleanAttribute(n string) error { return e.SetAttribute(n, "") }

func (e *Element) GetAttribute(n string) (string, bool) {
	prefix, local := splitName(n)
	for _, a := range e.raw.Attrs {
		if a.Name.Local == local && a.Prefix == prefix {
			return e.attributeValue(a), true
		}
	}

	return "", false
}

func (e *Element) HasAttribute(n string) bool { _, ok := e.GetAttribute(n); return ok }

func (e *Element) GetAttributeNS(local, uri string) (string, bool) {
	for _, a := range e.raw.Attrs {
		if a.Name == (tree.Name{Space: uri, Local: local}) {
			return e.attributeValue(a), true
		}
	}

	return "", false
}

func (e *Element) GetAttributeNodeNS(local, uri string) *Attribute {
	if _, ok := e.GetAttributeNS(local, uri); !ok {
		return nil
	}

	return e.doc.attrs[attrKey{e.raw, tree.Name{Space: uri, Local: local}}]
}

func (e *Element) Attributes() []*Attribute {
	out := make([]*Attribute, len(e.raw.Attrs))
	for i, a := range e.raw.Attrs {
		out[i] = e.doc.attrs[attrKey{e.raw, a.Name}]
	}

	return out
}

func (e *Element) ForEachAttribute(fn func(*Attribute) bool) {
	for _, a := range e.Attributes() {
		if !fn(a) {
			break
		}
	}
}

func (e *Element) RemoveAttribute(name string) bool {
	for _, a := range e.raw.Attrs {
		if tree.QName(a.Prefix, a.Name.Local) == name {
			return e.RemoveAttributeNS(a.Name.Local, a.Name.Space)
		}
	}

	return false
}

func (e *Element) RemoveAttributeNS(local, uri string) bool {
	if err := e.mutable(); err != nil {
		panic(err)
	}

	for i, a := range e.raw.Attrs {
		if a.Name == (tree.Name{Space: uri, Local: local}) {
			view := e.doc.attrs[attrKey{e.raw, a.Name}]

			e.raw.Attrs = slices.Delete(e.raw.Attrs, i, i+1)
			if view != nil && view.IDType() == IDAttribute {
				if id := xmlchar.CollapseSpace(a.Value); e.doc.ids[id] == e {
					delete(e.doc.ids, id)
				}
			}

			if view != nil {
				view.detached = true
			}

			e.doc.native.SetAttributeDTDType(e.raw, a.Name, tree.DTDNoType)
			delete(e.doc.attrs, attrKey{e.raw, a.Name})

			return true
		}
	}

	return false
}

func (e *Element) FindAttribute(p AttributePredicate) (*Attribute, bool) {
	for _, a := range e.Attributes() {
		if p.Match(a) {
			return a, true
		}
	}

	return nil, false
}

type Attribute struct {
	nodeView
	key   tree.Name
	owner *Element
	// Cache the derived value so repeated reads do not rescan or allocate for
	// an immutable input attribute. Private mutations refresh it before publishing.
	xmlIDValue string
	atype      AttributeIDType
	detached   bool
}

func (a *Attribute) Name() string { return tree.QName(a.Prefix(), a.LocalName()) }

func (a *Attribute) LocalName() string { return a.key.Local }

func (a *Attribute) Prefix() string { return a.entry().Prefix }

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

func (a *Attribute) Namespace() *Namespace {
	if a.URI() == "" && a.Prefix() == "" {
		return nil
	}

	return NewNamespace(a.Prefix(), a.URI())
}

func (a *Attribute) Parent() Node {
	if a.detached {
		return nil
	}

	return a.owner
}

func (a *Attribute) NextAttribute() *Attribute {
	attrs := a.owner.Attributes()
	for i, v := range attrs {
		if v == a && i+1 < len(attrs) {
			return attrs[i+1]
		}
	}

	return nil
}

func (a *Attribute) FirstChild() Node { return nil }

func (a *Attribute) LastChild() Node { return nil }

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
	for _, v := range a.owner.raw.Attrs {
		if v.Name == a.key {
			return v
		}
	}

	return tree.Attribute{Name: a.key}
}

type (
	AttributePredicate interface{ Match(*Attribute) bool }
	QNamePredicate     string
)

func (p QNamePredicate) Match(a *Attribute) bool { return a.Name() == string(p) }

type LocalNamePredicate string

func (p LocalNamePredicate) Match(a *Attribute) bool { return a.LocalName() == string(p) }

type NSPredicate struct{ LocalName, URI string }

func (p NSPredicate) Match(a *Attribute) bool {
	return a.LocalName() == p.LocalName && a.URI() == p.URI
}

type Namespace struct{ binding tree.Namespace }

func NewNamespace(prefix, uri string) *Namespace {
	return &Namespace{tree.Namespace{Prefix: prefix, URI: uri}}
}

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

func (n *Namespace) Prefix() string { return n.binding.Prefix }

func (n *Namespace) URI() string { return n.binding.URI }

type (
	NamespaceContainer interface{ Namespaces() []*Namespace }
	Namespacer         interface {
		Namespace() *Namespace
		Namespaces() []*Namespace
		Prefix() string
		URI() string
		LocalName() string
	}
)

type NamespaceNodeWrapper struct {
	nodeView
	ns *Namespace
}

func NewNamespaceNodeWrapper(ns *Namespace, owner Node) *NamespaceNodeWrapper {
	var doc *Document
	if !IsNilNode(owner) {
		doc = owner.OwnerDocument()
	}

	n := &NamespaceNodeWrapper{doc: doc, kind: NamespaceNode, parent: owner, slot: -1, ns: ns}
	n.self = n

	return n
}

func (n *NamespaceNodeWrapper) Name() string { return n.ns.Prefix() }

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

func AsNode[T Node](n Node) (T, bool) {
	v, ok := n.(T)
	if ok && IsNilNode(v) {
		var zero T
		return zero, false
	}

	return v, ok
}

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

func ChildElements(n Node) iter.Seq[*Element] {
	return func(yield func(*Element) bool) {
		for c := range Children(n) {
			if e, ok := c.(*Element); ok && !yield(e) {
				return
			}
		}
	}
}

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

func ClarkName(uri, local string) string { return "{" + uri + "}" + local }

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

type nodeView struct {
	raw     *tree.Node
	doc     *Document
	self    Node
	kind    ElementType
	slot    int
	line    int
	baseURI string
	parent  Node
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

	seen := make(map[Node]bool, len(nodes))
	for i, c := range nodes {
		if c == nil || c.view().raw == nil || c.Type() == AttributeNode || c.Type() == DocumentNode || seen[c] {
			return errors.New("invalid replacement node")
		}

		seen[c] = true
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
