package tree

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
)

const (
	// AlgorithmExclusive is the Exclusive C14N 1.0 algorithm URI.
	AlgorithmExclusive = "http://www.w3.org/2001/10/xml-exc-c14n#"
	// AlgorithmCanonical10 is the Canonical XML 1.0 algorithm URI.
	AlgorithmCanonical10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	// AlgorithmCanonical11 is the Canonical XML 1.1 algorithm URI.
	AlgorithmCanonical11 = "http://www.w3.org/2006/12/xml-c14n11"
)

// CanonicalOptions sets the private canonicalization algorithm, selection and output
// budget.
type CanonicalOptions struct {
	Algorithm         string
	Comments          bool
	InclusivePrefixes []string
	MaxBytes          int
	// Exclude removes a whole subtree for the restricted enveloped profile.
	// It is not an XPath filter and is not exposed as a general transform API.
	Exclude *Node
}

// ExclusiveOptions is retained for the existing signing implementation.
type ExclusiveOptions struct {
	Comments          bool
	InclusivePrefixes []string
	MaxBytes          int
	Exclude           *Node
}

// Exclusive writes Exclusive C14N using the private subtree selection options.
func Exclusive(ctx context.Context, w io.Writer, d *Document, start *Node, opt ExclusiveOptions) error {
	return Canonical(ctx, w, d, start, nil, CanonicalOptions{
		Algorithm: AlgorithmExclusive, Comments: opt.Comments,
		InclusivePrefixes: opt.InclusivePrefixes, MaxBytes: opt.MaxBytes, Exclude: opt.Exclude,
	})
}

// Canonical writes the selected nodes in original document order. For a nil set,
// start selects a full subtree (nil start = full document), without materializing
// expanded namespace nodes. Both paths use the same processing implementation.
func Canonical(ctx context.Context, w io.Writer, d *Document, start *Node, set *NodeSet, opt CanonicalOptions) error {
	if ctx == nil || nilcheck.IsNil(w) || d == nil || d.root == nil {
		return fmt.Errorf("%w: nil canonicalization input", ErrMalformed)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if set != nil && (!set.Valid() || set.doc != d || start != nil || opt.Exclude != nil) {
		return fmt.Errorf("%w: invalid node-set canonicalization input", ErrMalformed)
	}

	opt, err := normalizeCanonicalOptions(opt)
	if err != nil {
		return err
	}

	inclusive, err := canonicalInclusivePrefixes(opt.InclusivePrefixes)
	if err != nil {
		return err
	}

	var parent *Node
	if start != nil {
		parent = start.Parent
	}

	writer := canonicalWriter{
		ctx: ctx, opt: opt, inclusive: inclusive,
		sel:   canonicalSelection{doc: d, start: start, set: set},
		out:   streamio.Writer{Context: ctx, Target: w, Limit: int64(opt.MaxBytes), LimitError: fmt.Errorf("%w: output bytes", ErrLimit)},
		scope: newNamespaceContext(parent),
	}
	if start != nil {
		err = writer.visit(start, canonicalFrame{}, 0)
	} else {
		err = writer.writeDocument(d)
	}

	return errors.Join(err, ctx.Err())
}

func normalizeCanonicalOptions(opt CanonicalOptions) (CanonicalOptions, error) {
	if opt.Algorithm == "" {
		opt.Algorithm = AlgorithmExclusive
	}

	switch opt.Algorithm {
	case AlgorithmExclusive + "WithComments":
		opt.Algorithm = AlgorithmExclusive
		opt.Comments = true
	case AlgorithmCanonical10 + "#WithComments":
		opt.Algorithm = AlgorithmCanonical10
		opt.Comments = true
	case AlgorithmCanonical11 + "#WithComments":
		opt.Algorithm = AlgorithmCanonical11
		opt.Comments = true
	}

	if opt.Algorithm != AlgorithmExclusive && opt.Algorithm != AlgorithmCanonical10 && opt.Algorithm != AlgorithmCanonical11 {
		return opt, fmt.Errorf("%w: canonicalization algorithm", ErrUnsupported)
	}

	if opt.Algorithm != AlgorithmExclusive && len(opt.InclusivePrefixes) != 0 {
		return opt, fmt.Errorf("%w: InclusiveNamespaces only applies to Exclusive C14N", ErrUnsupported)
	}

	if opt.MaxBytes == 0 {
		opt.MaxBytes = 32 << 20
	}

	if opt.MaxBytes < 0 {
		return opt, fmt.Errorf("%w: output budget", ErrLimit)
	}

	if len(opt.InclusivePrefixes) > 128 {
		return opt, fmt.Errorf("%w: inclusive prefixes", ErrLimit)
	}

	return opt, nil
}

func canonicalInclusivePrefixes(prefixes []string) (map[string]bool, error) {
	inclusive := make(map[string]bool, len(prefixes))

	for _, prefix := range prefixes {
		if prefix == "#default" {
			prefix = ""
		} else if !NCName(prefix) || prefix == nameXmlns {
			return nil, fmt.Errorf("%w: inclusive namespace prefix", ErrMalformed)
		}

		inclusive[prefix] = true
	}

	return inclusive, nil
}

type canonicalSelection struct {
	doc   *Document
	start *Node
	set   *NodeSet
}

func (s canonicalSelection) has(n *Node) bool {
	if n == nil {
		return false
	}

	if s.set != nil {
		return s.set.Contains(ref(s.doc, n))
	}

	if s.start == nil {
		return true
	}

	for p := n; p != nil; p = p.Parent {
		if p == s.start {
			return true
		}
	}

	return false
}

func (s canonicalSelection) attribute(n *Node, i int) bool {
	return s.set == nil || s.set.Contains(attributeRef(s.doc, n, i))
}

func (s canonicalSelection) namespace(n *Node, p string) bool {
	return s.set == nil || s.set.Contains(namespaceRef(s.doc, n, p))
}

// canonicalFrame captures the *selected namespace axis* of the nearest output
// ancestor as well as Exclusive C14N's nearest visibly-utilizing ancestors.
// Using only a map of declarations already printed is incorrect for sparse
// node-sets which intentionally omit individual namespace nodes.
type canonicalFrame struct {
	selected map[string]string
	utilized map[string]string // empty value = no selected namespace at that use
	rendered map[string]string
}

type canonicalWriter struct {
	ctx       context.Context
	opt       CanonicalOptions
	sel       canonicalSelection
	out       streamio.Writer
	escaper   xmlEscaper
	scope     namespaceContext
	inclusive map[string]bool
	// Attributes are emitted before children, so one buffer serves the walk.
	attrs          []Attribute
	namespaceNames []string
	// Scratch maps are private to a recursion depth and reused across siblings.
	frames []canonicalFrame
	// Namespace work sets are consumed before descending into children too.
	prefixes     map[string]bool
	declarations map[string]string
	err          error
}

func (w *canonicalWriter) put(s string) {
	if w.err == nil {
		_, w.err = io.WriteString(&w.out, s)
	}
}

func (w *canonicalWriter) escape(value string, attribute bool) {
	if w.err == nil {
		w.err = w.escaper.write(&w.out, value, func(c byte) string { return xmlEscape(c, attribute) })
	}
}

func (w *canonicalWriter) carriage(value string) {
	if w.err == nil {
		w.err = w.escaper.write(&w.out, value, func(c byte) string {
			if c == '\r' {
				return "&#xD;"
			}

			return ""
		})
	}
}

func (w *canonicalWriter) putNamespace(prefix, uri string) {
	w.put(" xmlns")

	if prefix != "" {
		w.put(":")
		w.put(prefix)
	}

	w.put("=\"")
	w.escape(uri, true)
	w.put("\"")
}

func (w *canonicalWriter) writeDocument(d *Document) error {
	before := true

	for _, n := range d.children {
		if n.Kind == ElementNode {
			if err := w.visit(n, canonicalFrame{}, 0); err != nil {
				return err
			}

			before = false

			continue
		}

		if !w.sel.has(n) || !(n.Kind == PINode || n.Kind == CommentNode && w.opt.Comments) {
			continue
		}

		if !before {
			w.put("\n")
		}

		if err := w.visit(n, canonicalFrame{}, 0); err != nil {
			return err
		}

		if before {
			w.put("\n")
		}
	}

	return w.err
}

func (w *canonicalWriter) visit(n *Node, frame canonicalFrame, depth int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}

	if n == w.opt.Exclude {
		return nil
	}

	visible := w.sel.set == nil || w.sel.has(n)
	if n.Kind == ElementNode {
		return w.visitElement(n, frame, visible, depth)
	}

	if visible {
		w.writeLeaf(n)
	}

	return w.err
}

func (w *canonicalWriter) writeLeaf(n *Node) {
	switch n.Kind {
	case TextNode:
		w.escape(n.Data, false)
	case CommentNode:
		if w.opt.Comments {
			w.put("<!--")
			w.carriage(n.Data)
			w.put("-->")
		}
	case PINode:
		w.put("<?")
		w.put(n.Name.Local)

		if n.Data != "" {
			w.put(" ")
			w.carriage(n.Data)
		}

		w.put("?>")
	}
}

func (w *canonicalWriter) visitElement(n *Node, frame canonicalFrame, visible bool, depth int) error {
	mark := w.scope.push(n.NS)
	defer w.scope.pop(mark)

	if depth == len(w.frames) {
		w.frames = append(w.frames, canonicalFrame{})
	}

	scratch := &w.frames[depth]
	selected := frame.selected
	// Full selections have the same namespace axis until a declaration changes.
	// Sparse selections may choose different namespace nodes on every element.
	if w.sel.set != nil || len(n.NS) != 0 || selected == nil {
		scratch.selected = w.selectedNamespaces(n, scratch.selected)
		selected = scratch.selected
	}

	utilized := w.utilizedPrefixes(n, visible)
	toRender := w.namespaceDeclarations(selected, utilized, frame, visible)

	if err := w.writeElementStart(n, visible, toRender); err != nil {
		return err
	}

	next := nextCanonicalFrame(frame, selected, utilized, toRender, visible, scratch)
	for _, child := range n.Children {
		if err := w.visit(child, next, depth+1); err != nil {
			return err
		}
	}

	if visible {
		w.put("</")
		w.put(QName(n.Prefix, n.Name.Local))
		w.put(">")
	}

	return w.err
}

func copyBindings(dst, src map[string]string) map[string]string {
	if dst == nil {
		dst = make(map[string]string, len(src))
	} else {
		clear(dst)
	}

	maps.Copy(dst, src)

	return dst
}

func nextCanonicalFrame(frame canonicalFrame, selected map[string]string, utilized map[string]bool, toRender map[string]string, visible bool, scratch *canonicalFrame) canonicalFrame {
	if !visible {
		return frame
	}

	next := canonicalFrame{selected: selected, utilized: frame.utilized, rendered: frame.rendered}
	copied := false

	for prefix := range utilized {
		uri := selected[prefix]
		if previous, ok := next.utilized[prefix]; ok && previous == uri {
			continue
		}

		if !copied {
			scratch.utilized = copyBindings(scratch.utilized, frame.utilized)
			next.utilized = scratch.utilized
			copied = true
		}

		next.utilized[prefix] = uri
	}

	if len(toRender) != 0 {
		scratch.rendered = copyBindings(scratch.rendered, frame.rendered)
		next.rendered = scratch.rendered
		maps.Copy(next.rendered, toRender)
	}

	return next
}

func (w *canonicalWriter) selectedNamespaces(n *Node, selected map[string]string) map[string]string {
	if selected == nil {
		selected = make(map[string]string)
	} else {
		clear(selected)
	}

	for prefix, uri := range w.scope.bindings {
		if uri != "" && w.sel.namespace(n, prefix) {
			selected[prefix] = uri
		}
	}

	return selected
}

func (w *canonicalWriter) utilizedPrefixes(n *Node, visible bool) map[string]bool {
	if w.prefixes == nil {
		w.prefixes = make(map[string]bool)
	}

	clear(w.prefixes)

	utilized := w.prefixes
	if !visible {
		return utilized
	}

	utilized[n.Prefix] = true

	for i, attribute := range n.Attrs {
		if attribute.Prefix != "" && w.sel.attribute(n, i) {
			utilized[attribute.Prefix] = true
		}
	}

	return utilized
}

func (w *canonicalWriter) namespaceDeclarations(selected map[string]string, utilized map[string]bool, frame canonicalFrame, visible bool) map[string]string {
	if w.declarations == nil {
		w.declarations = make(map[string]string)
	}

	clear(w.declarations)
	toRender := w.declarations

	for prefix, uri := range selected {
		if prefix == nameXML {
			continue
		}

		if w.opt.Algorithm != AlgorithmExclusive || w.inclusive[prefix] {
			if frame.selected[prefix] != uri {
				toRender[prefix] = uri
			}

			continue
		}

		if visible && utilized[prefix] {
			_, rendered := frame.rendered[prefix]
			if !rendered || frame.utilized[prefix] != uri {
				toRender[prefix] = uri
			}
		}
	}

	if !visible || selected[""] != "" {
		return toRender
	}

	if w.opt.Algorithm != AlgorithmExclusive || w.inclusive[""] {
		if frame.selected[""] != "" {
			toRender[""] = ""
		}
	} else if utilized[""] && frame.utilized[""] != "" {
		toRender[""] = ""
	}

	return toRender
}

func (w *canonicalWriter) writeElementStart(n *Node, visible bool, toRender map[string]string) error {
	if visible {
		w.put("<")
		w.put(QName(n.Prefix, n.Name.Local))
	}

	prefixes := w.namespaceNames[:0]
	for prefix := range toRender {
		prefixes = append(prefixes, prefix)
	}

	w.namespaceNames = prefixes
	sort.Strings(prefixes)

	for _, prefix := range prefixes {
		w.putNamespace(prefix, toRender[prefix])
	}

	if cap(w.attrs) < len(n.Attrs) {
		w.attrs = make([]Attribute, 0, len(n.Attrs))
	}

	var err error

	w.attrs, err = canonicalAttributes(w.attrs[:0], n, visible, w.sel, w.opt.Algorithm)
	if err != nil {
		return err
	}

	slices.SortFunc(w.attrs, func(a, b Attribute) int { return compareNames(a.Name, b.Name) })

	for _, attribute := range w.attrs {
		w.put(" ")
		w.put(QName(attribute.Prefix, attribute.Name.Local))
		w.put("=\"")
		w.escape(attribute.Value, true)
		w.put("\"")
	}

	if visible {
		w.put(">")
	}

	return w.err
}

func canonicalAttributes(attrs []Attribute, n *Node, visible bool, sel canonicalSelection, algorithm string) ([]Attribute, error) {
	for i, attribute := range n.Attrs {
		if sel.attribute(n, i) {
			attrs = append(attrs, attribute)
		}
	}
	// Inclusive inheritance applies to orphan ELEMENTS only, not loose attrs.
	if !visible || algorithm == AlgorithmExclusive || n.Parent == nil || sel.has(n.Parent) {
		return attrs, nil
	}

	attrs = inheritedXMLAttributes(attrs, n, algorithm)
	if algorithm != AlgorithmCanonical11 {
		return attrs, nil
	}

	value, omittedBase, err := canonicalBase(n, sel)
	if err != nil {
		return nil, err
	}

	if !omittedBase {
		return attrs, nil
	}

	filtered := attrs[:0]
	for _, attribute := range attrs {
		if attribute.Name.Space != XMLNamespace || attribute.Name.Local != nameBase {
			filtered = append(filtered, attribute)
		}
	}

	if value != "" {
		filtered = append(filtered, Attribute{Name: Name{Space: XMLNamespace, Local: nameBase}, Prefix: nameXML, Value: value})
	}

	return filtered, nil
}

func inheritedXMLAttributes(attrs []Attribute, n *Node, algorithm string) []Attribute {
	have := make(map[string]bool)

	for _, attribute := range n.Attrs {
		if attribute.Name.Space == XMLNamespace {
			have[attribute.Name.Local] = true
		}
	}

	for parent := n.Parent; parent != nil; parent = parent.Parent {
		for _, attribute := range parent.Attrs {
			if attribute.Name.Space != XMLNamespace || have[attribute.Name.Local] {
				continue
			}

			if algorithm == AlgorithmCanonical11 && attribute.Name.Local != "lang" && attribute.Name.Local != "space" {
				continue
			}

			have[attribute.Name.Local] = true
			attrs = append(attrs, attribute)
		}
	}

	return attrs
}

func canonicalBase(n *Node, sel canonicalSelection) (string, bool, error) {
	// Only contiguous omitted ancestors contribute xml:base, not every ancestor.
	// E11-01 corrects the example in C14N 1.1 section 3.8 accordingly.
	value, hasValue := xmlAttribute(n, nameBase)
	omittedBase := false

	for parent := n.Parent; parent != nil && !sel.has(parent); parent = parent.Parent {
		base, ok := xmlAttribute(parent, nameBase)
		if !ok {
			continue
		}

		omittedBase = true

		if !hasValue {
			value = base
			hasValue = true

			continue
		}

		joined, err := joinURIReferences(base, value)
		if err != nil {
			return "", false, err
		}

		value = joined
	}

	return value, omittedBase, nil
}

func xmlAttribute(n *Node, name string) (string, bool) {
	for _, a := range n.Attrs {
		if a.Name.Space == XMLNamespace && a.Name.Local == name {
			return a.Value, true
		}
	}

	return "", false
}
