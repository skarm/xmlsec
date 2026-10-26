// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"fmt"
	"maps"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func copyFunctionInput(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) != 0 {
		return args[0], nil
	}

	item, err := xpath.FnContextItem(ctx)
	if err != nil {
		return nil, err
	}

	return xdm.ItemSlice{item}, nil
}

func (ec *execContext) fnCopyOf(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	input, err := copyFunctionInput(ctx, args)
	if err != nil {
		return nil, err
	}

	var result xdm.ItemSlice

	for item := range xdm.SequenceItems(input) {
		if err := xpath.Charge(ctx, 1); err != nil {
			return nil, err
		}

		if node, isNode := item.(xdm.NodeItem); isNode {
			copied, err := ec.copyFunctionNode(ctx, node.Node)
			if err != nil {
				return nil, err
			}

			item = xdm.NodeItem{Node: copied}
		}

		result = append(result, item)
	}

	return result, nil
}

func (ec *execContext) copyFunctionNode(ctx context.Context, node xdm.Node) (xdm.Node, error) {
	if node.Type() == xdm.AttributeNode && ec.nodeHasNamespaceSensitiveContent(node) {
		return nil, dynamicError(errCodeXTTE0950, "copy-of(): cannot copy attribute with namespace-sensitive content")
	}

	var (
		copied xdm.Node
		err    error
	)
	if node.Type() == xdm.DocumentNode {
		copied, err = ec.copyDocumentNode(node)
	} else {
		if err := xpath.ChargeTree(ctx, node); err != nil {
			return nil, err
		}

		if node.Type() == xdm.NamespaceNode {
			copied, err = xdm.CopyTree(node)
		} else {
			copied, err = xdm.CopyNode(node, ec.resultDoc)
		}
	}

	if err != nil {
		return nil, err
	}

	if source, isElement := node.(*xdm.Element); isElement {
		if target, isElement := copied.(*xdm.Element); isElement {
			addInScopeNamespaces(source, target)
		}
	}

	if ec.typeAnnotations != nil {
		ec.deepTransferAnnotations(node, copied)
	}

	ec.transferNilledStatus(node, copied)

	if err := ec.copyAccumulatorState(ctx, node, copied); err != nil {
		return nil, err
	}

	return copied, nil
}

func (ec *execContext) copyAccumulatorState(ctx context.Context, original, copied xdm.Node) error {
	if len(ec.effectiveAccumulators()) == 0 {
		return nil
	}

	if err := ec.ensureAccumulatorStates(ctx, original); err != nil {
		return err
	}

	ec.transferAccumulatorStates(original, copied)

	if ec.accumulatorComputedDocs == nil {
		ec.accumulatorComputedDocs = make(map[xdm.Node]struct{})
	}

	ec.accumulatorComputedDocs[documentRoot(copied)] = struct{}{}

	return nil
}

// snapshot() copies each node with its ancestor shells and preserves non-nodes.
func (ec *execContext) fnSnapshot(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	input, err := copyFunctionInput(ctx, args)
	if err != nil {
		return nil, err
	}

	var result xdm.ItemSlice

	for item := range xdm.SequenceItems(input) {
		if err := xpath.Charge(ctx, 1); err != nil {
			return nil, err
		}

		if node, isNode := item.(xdm.NodeItem); isNode {
			copied, err := ec.snapshotNode(ctx, node.Node)
			if err != nil {
				return nil, err
			}

			ec.transferNilledStatus(node.Node, copied)

			if err := ec.copyAccumulatorState(ctx, node.Node, copied); err != nil {
				return nil, err
			}

			item = xdm.NodeItem{Node: copied}
		}

		result = append(result, item)
	}

	return result, nil
}

// snapshotNode creates a deep copy of node and wraps it in shallow copies
// of all its ancestors up to and including the document root.
func (ec *execContext) snapshotNode(ctx context.Context, node xdm.Node) (xdm.Node, error) {
	// For a document node, just do a full deep copy.
	if node.Type() == xdm.DocumentNode {
		doc, ok := node.(*xdm.Document)
		if !ok {
			return nil, fmt.Errorf("unexpected DocumentNode type %T", node)
		}

		copied, err := xdm.CopyDoc(doc)
		if err != nil {
			return nil, err
		}

		if ec.typeAnnotations != nil {
			ec.deepTransferAnnotations(doc, copied)
		}

		return copied, nil
	}

	// For namespace nodes, build the ancestor chain, declare the namespace
	// on the innermost shell element, and return a NamespaceNodeWrapper.
	if node.Type() == xdm.NamespaceNode {
		return ec.snapshotNamespaceNode(node)
	}

	// For attribute nodes, build the ancestor chain, attach the attribute
	// to the innermost shell element, and return the copied attribute.
	if node.Type() == xdm.AttributeNode {
		return ec.snapshotAttributeNode(node)
	}

	var (
		ancestors  []*xdm.Element
		hasDocRoot bool
		origDoc    *xdm.Document
	)

	for p := node.Parent(); p != nil; p = p.Parent() {
		if elem, ok := p.(*xdm.Element); ok {
			ancestors = append(ancestors, elem)
		}

		if p.Type() == xdm.DocumentNode {
			hasDocRoot = true
			origDoc, _ = p.(*xdm.Document)
		}
	}

	snapDoc := xdm.NewDefaultDocument()

	// Copy DTD info (entities, notations) from the original document so
	// that unparsed-entity-uri() / unparsed-entity-public-id() work on
	// the snapshot.
	if origDoc != nil {
		xdm.CopyDoctype(origDoc, snapDoc)
	}

	// Deep-copy the target node itself.
	copied, err := xdm.CopyNode(node, snapDoc)
	if err != nil {
		return nil, err
	}

	// Add all in-scope namespaces from the original element directly onto
	// the deep-copied element. This ensures that when the snapshot result
	// is later copied into the result tree (via CopyNode in xsl:sequence),
	// the inherited namespace bindings travel with the element itself,
	// relying on no ancestor shell chain alone.
	if srcElem, ok := node.(*xdm.Element); ok {
		if dstElem, ok2 := copied.(*xdm.Element); ok2 {
			addInScopeNamespaces(srcElem, dstElem)
		}
	}

	// Transfer type annotations from original to copy so that
	// nilled(), instance of, etc. work on the snapshot.
	if ec.typeAnnotations != nil {
		ec.deepTransferAnnotations(node, copied)
	}

	// For parentless (orphan) nodes that have no document root ancestor,
	// return just the deep copy without wrapping in a document node.
	// Per XSLT 3.0 spec, snapshot of a parentless node is a deep copy.
	if len(ancestors) == 0 && !hasDocRoot {
		return copied, nil
	}

	// Build the ancestor chain: for each ancestor (bottom-up), create a
	// shallow copy (name + attributes + namespace declarations) and attach
	// the previous level as its only child.
	current := copied

	for _, anc := range ancestors {
		shell, err := shallowCopyElement(anc, snapDoc)
		if err != nil {
			return nil, err
		}

		addInScopeNamespaces(anc, shell)

		if err := shell.AddChild(current); err != nil {
			return nil, err
		}

		current = shell
	}

	// Attach the top-level element (or the copied node itself if no
	// ancestors) to the snapshot document.
	if err := snapDoc.AddChild(current); err != nil {
		return nil, err
	}

	// Ensure accumulator states are computed for the original document
	// before transferring, since the snapshot may be created before any
	// accumulator-before()/accumulator-after() call triggers lazy computation.
	if err := ec.ensureAccumulatorStates(ctx, node); err != nil {
		return nil, err
	}

	// Transfer accumulator state from original subtree to snapshot copy.
	ec.transferAccumulatorStates(node, copied)
	// Transfer accumulator state for ancestor shells too.
	snapshotNodeAncestors(ancestors, copied, ec)

	// Mark the snapshot document as having computed accumulators so that
	// ensureAccumulatorStates does not re-walk and overwrite the transferred
	// values (the snapshot tree structure differs from the original).
	if ec.accumulatorComputedDocs == nil {
		ec.accumulatorComputedDocs = make(map[xdm.Node]struct{})
	}

	ec.accumulatorComputedDocs[snapDoc] = struct{}{}

	return copied, nil
}

// xsltFunctionsNS returns user-defined xsl:function definitions and
// XSLT built-in functions that need to be callable in the fn: namespace
// as xpath functions keyed by qualified name.

func snapshotNodeAncestors(ancestors []*xdm.Element, copied xdm.Node, ec *execContext) {
	for i, anc := range ancestors {
		// ancestors[0] is the immediate parent, ancestors[1] is grandparent, etc.
		// The ancestor chain was built bottom-up, so the corresponding shell
		// is: copied.Parent() for i=0, copied.Parent().Parent() for i=1, etc.
		shell := copied.Parent()
		for range i {
			if shell != nil {
				shell = shell.Parent()
			}
		}

		if shell != nil {
			ec.transferAccumulatorNode(anc, shell)
		}
	}
}

// transferAccumulatorStates copies accumulator before/after state from
// an original node subtree to a copied node subtree (parallel walk).
func (ec *execContext) transferAccumulatorStates(orig, dst xdm.Node) {
	ec.transferAccumulatorNode(orig, dst)
	oc := orig.FirstChild()

	cc := dst.FirstChild()
	for oc != nil && cc != nil {
		ec.transferAccumulatorStates(oc, cc)
		oc = oc.NextSibling()
		cc = cc.NextSibling()
	}
}

// transferAccumulatorNode copies the accumulator before/after maps for a
// single node from orig to dst.
func (ec *execContext) transferAccumulatorNode(orig, dst xdm.Node) {
	if ec.accumulatorBeforeByNode != nil {
		if vals, ok := ec.accumulatorBeforeByNode[orig]; ok {
			ec.accumulatorBeforeByNode[dst] = cloneAccumulatorSnapshot(vals)
		}
	}

	if ec.accumulatorAfterByNode != nil {
		if vals, ok := ec.accumulatorAfterByNode[orig]; ok {
			ec.accumulatorAfterByNode[dst] = cloneAccumulatorSnapshot(vals)
		}
	}

	if ec.accumulatorBeforeErrorByNode != nil {
		if errs, ok := ec.accumulatorBeforeErrorByNode[orig]; ok {
			cloned := make(map[string]error, len(errs))
			maps.Copy(cloned, errs)
			ec.accumulatorBeforeErrorByNode[dst] = cloned
		}
	}

	if ec.accumulatorAfterErrorByNode != nil {
		if errs, ok := ec.accumulatorAfterErrorByNode[orig]; ok {
			cloned := make(map[string]error, len(errs))
			maps.Copy(cloned, errs)
			ec.accumulatorAfterErrorByNode[dst] = cloned
		}
	}
}

// snapshotNamespaceNode creates a snapshot of a namespace node by building
// the ancestor chain and declaring the namespace on the innermost element.
func (ec *execContext) snapshotNamespaceNode(node xdm.Node) (xdm.Node, error) {
	prefix := node.Name()
	uri := xdm.CharacterData(node)

	_, innermostShell, err := snapshotAncestorShells(node)
	if err != nil {
		return nil, err
	}

	// Ensure the namespace is declared on the innermost element.
	if innermostShell != nil {
		// The shallowCopy already copied namespace declarations, so the
		// namespace should already be there. Return a wrapper pointing to
		// the innermost element.
		ns := xdm.NewNamespace(prefix, uri)
		return xdm.NewNamespaceNodeWrapper(ns, innermostShell), nil
	}

	// No parent element — return a standalone namespace wrapper.
	ns := xdm.NewNamespace(prefix, uri)

	return xdm.NewNamespaceNodeWrapper(ns, nil), nil
}

// snapshotAttributeNode creates a snapshot of an attribute node by building
// the ancestor chain and attaching the attribute to the innermost element.
func (ec *execContext) snapshotAttributeNode(node xdm.Node) (xdm.Node, error) {
	attr, ok := node.(*xdm.Attribute)
	if !ok {
		return nil, fmt.Errorf("unexpected AttributeNode type %T", node)
	}

	snapDoc, innermostShell, err := snapshotAncestorShells(node)
	if err != nil {
		return nil, err
	}

	if innermostShell != nil {
		// The shallowCopy already includes all attributes, so find the
		// matching attribute on the shell.
		for _, a := range innermostShell.Attributes() {
			if a.LocalName() == attr.LocalName() && a.URI() == attr.URI() {
				return a, nil
			}
		}
	}

	// Fallback: create a standalone copy.
	copied, err := xdm.CopyNode(node, snapDoc)
	if err != nil {
		return nil, err
	}

	return copied, nil
}

// regex-group(n) returns the nth captured group from the current regex match.
// Returns empty string if called outside xsl:matching-substring or if the
// group number is out of range.
func (ec *execContext) fnRegexGroup(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xpath.IsDynamicCall(ctx) || ec.inPatternMatch || len(args) == 0 || (args[0] == nil || xdm.SequenceLen(args[0]) == 0) {
		return xdm.SingleString(""), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return xdm.SingleString(""), nil //nolint:nilerr // regex-group returns "" on atomization failure
	}

	s, err := xpath.AtomicToString(av)
	if err != nil {
		return xdm.SingleString(""), nil //nolint:nilerr // regex-group returns "" on string conversion failure
	}

	idx, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return xdm.SingleString(""), nil //nolint:nilerr // regex-group returns "" for non-integer group number
	}

	if idx < 0 || idx >= len(ec.regexGroups) {
		return xdm.SingleString(""), nil
	}

	return xdm.SingleString(ec.regexGroups[idx]), nil
}

// snapshotAncestorShells copies the parent element and its ancestor chain.
func snapshotAncestorShells(node xdm.Node) (*xdm.Document, *xdm.Element, error) {
	var ancestors []*xdm.Element

	for p := node.Parent(); p != nil; p = p.Parent() {
		if elem, ok := p.(*xdm.Element); ok {
			ancestors = append(ancestors, elem)
		}
	}

	snapDoc := xdm.NewDefaultDocument()

	// Build the innermost shell first, then wrap it with outer ancestors.
	var (
		innermostShell *xdm.Element
		current        xdm.Node
	)

	for i, anc := range ancestors {
		shell, err := shallowCopyElement(anc, snapDoc)
		if err != nil {
			return nil, nil, err
		}

		if i == 0 {
			innermostShell = shell
		}

		if current != nil {
			if err := shell.AddChild(current); err != nil {
				return nil, nil, err
			}
		}

		current = shell
	}

	if current != nil {
		if err := snapDoc.AddChild(current); err != nil {
			return nil, nil, err
		}
	}

	return snapDoc, innermostShell, nil
}

// shallowCopyElement copies an element's name, namespace declarations, and
// attributes but none of its children.
func shallowCopyElement(src *xdm.Element, doc *xdm.Document) (*xdm.Element, error) {
	elem, err := doc.CreateElement(src.LocalName())
	if err != nil {
		return nil, err
	}

	declaredPrefixes := make(map[string]struct{})

	if nc, ok := xdm.Node(src).(xdm.NamespaceContainer); ok {
		for _, ns := range nc.Namespaces() {
			if err := elem.DeclareNamespace(ns.Prefix(), ns.URI()); err != nil {
				return nil, err
			}

			declaredPrefixes[ns.Prefix()] = struct{}{}
		}
	}

	if nsr, ok := xdm.Node(src).(xdm.Namespacer); ok {
		if ns := nsr.Namespace(); ns != nil {
			_, alreadyDeclared := declaredPrefixes[ns.Prefix()]
			if ns.Prefix() != "" && !alreadyDeclared {
				if err := elem.DeclareNamespace(ns.Prefix(), ns.URI()); err != nil {
					return nil, err
				}
			}

			if err := elem.SetActiveNamespace(ns.Prefix(), ns.URI()); err != nil {
				return nil, err
			}
		}
	}

	for _, a := range src.Attributes() {
		if a.URI() != "" {
			ns := xdm.NewNamespace(a.Prefix(), a.URI())
			_ = elem.SetAttributeNS(a.LocalName(), a.Value(), ns)

			_, prefixDeclared := declaredPrefixes[a.Prefix()]
			if a.Prefix() != "" && !prefixDeclared {
				_ = elem.DeclareNamespace(a.Prefix(), a.URI())
				declaredPrefixes[a.Prefix()] = struct{}{}
			}
		} else {
			_ = elem.SetAttribute(a.Name(), a.Value())
		}
	}

	return elem, nil
}

// addInScopeNamespaces copies all in-scope namespaces from src to dst that
// are not already declared on dst.  This ensures that inherited namespace
// bindings visible on the source element are preserved on the copy.
func addInScopeNamespaces(src, dst *xdm.Element) {
	declared := make(map[string]struct{})
	for _, ns := range dst.Namespaces() {
		declared[ns.Prefix()] = struct{}{}
	}

	for _, ns := range collectInScopeNamespaces(src) {
		if _, exists := declared[ns.Prefix()]; !exists {
			_ = dst.DeclareNamespace(ns.Prefix(), ns.URI())
			declared[ns.Prefix()] = struct{}{}
		}
	}
}
