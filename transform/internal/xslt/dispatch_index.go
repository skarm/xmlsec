// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// templateIndexThreshold is the minimum mode-list length a templateIndex is
// built for. Shorter lists keep the plain linear scan: the merge cursor's
// fixed overhead is not worth paying for a handful of templates, and small
// stylesheets are the common case in tests.
const templateIndexThreshold = 16

// nodeKind groups nodes by the terminal match conditions used by template dispatch.
// Text and CDATA share a group because text() matches both. The groups need not mirror
// every storage node kind.
type nodeKind uint8

const (
	kindElement nodeKind = iota
	kindAttribute
	kindText
	kindComment
	kindPI
	kindDocument
	kindNamespace
	numKinds
)

// kindSet is a bitmask over nodeKind, used only while deriving a pattern's
// signature. It is never stored in the built index — every admitted
// sigEntry names exactly one nodeKind.
type kindSet uint16

// kindSetAll is every kind a TypeTest{node()} test can conceivably admit,
// before the axis-based gates in nodeMatchesStep narrow it.
const kindSetAll = kindSet(1)<<numKinds - 1

func kindBit(k nodeKind) kindSet { return kindSet(1) << k }

// singleBit reports the one nodeKind set in ks, when ks has exactly one bit
// set.
func singleBit(ks kindSet) (nodeKind, bool) {
	if ks == 0 || ks&(ks-1) != 0 {
		return 0, false
	}

	for k := range numKinds {
		if ks == kindBit(k) {
			return k, true
		}
	}

	return 0, false
}

// nameKey identifies a bucket of templates whose terminal step requires a
// specific expanded name on a specific node kind (only kindElement or
// kindAttribute ever appear here — see stepSignature).
type nameKey struct {
	kind  nodeKind
	uri   string
	local string
}

// sigEntry is one admitted (necessary-condition) entry in a pattern's
// signature: a node can be admitted by this entry only if its kind is kind,
// and — when named is true — its expanded name is exactly (uri, local).
type sigEntry struct {
	kind  nodeKind
	named bool
	uri   string
	local string
}

// signature is the result of extracting a necessary matching condition from
// one pattern alternative (or the union of several): a node can satisfy the
// alternative only if it satisfies at least one entry. unindexed means no
// safe necessary condition could be derived at all — entries is meaningless
// and the owning template must be probed for every node.
type signature struct {
	entries   []sigEntry
	unindexed bool
}

// templateIndex buckets a sorted mode-template list by the node kind and
// expanded name a template's terminal step requires. Every bucket slice holds
// POSITIONS into that same sorted list, in ascending order (a subsequence of
// the original scan order) — see dispatch_index.go's package-level doc
// comment in execute_templates.go (findFirstMatch) for why positions, not
// templates, are stored: the list's sort order (compile_toplevel.go
// sortTemplates) is derived from live slice indices and cannot be
// re-computed, only inherited.
type templateIndex struct {
	byName    map[nameKey][]int32
	byKind    [numKinds][]int32
	unindexed []int32
}

// buildTemplateIndex derives a templateIndex from an already-sorted mode
// template list, or returns nil when the list is below templateIndexThreshold
// (the caller falls back to a plain linear scan).
func buildTemplateIndex(templates []*template) *templateIndex {
	if len(templates) < templateIndexThreshold {
		return nil
	}

	idx := &templateIndex{byName: make(map[nameKey][]int32)}

	for i, tmpl := range templates {
		pos := int32(i)
		if tmpl.Match == nil {
			idx.unindexed = append(idx.unindexed, pos)
			continue
		}

		sig := patternSignature(tmpl.Match)
		if sig.unindexed {
			idx.unindexed = append(idx.unindexed, pos)
			continue
		}

		addTemplateToBuckets(idx, pos, sig.entries)
	}

	return idx
}

// addTemplateToBuckets registers position pos into every bucket named by
// entries, skipping an entry that would duplicate a bucket already recorded
// for this position (a multi-alternative pattern can otherwise contribute the
// same kind twice, e.g. "foo | foo").
func addTemplateToBuckets(idx *templateIndex, pos int32, entries []sigEntry) {
	seenKind := kindSet(0)
	seenName := map[nameKey]struct{}(nil)

	for _, e := range entries {
		if e.named {
			key := nameKey{kind: e.kind, uri: e.uri, local: e.local}

			if seenName == nil {
				seenName = make(map[nameKey]struct{}, len(entries))
			}

			if _, dup := seenName[key]; dup {
				continue
			}

			seenName[key] = struct{}{}
			idx.byName[key] = append(idx.byName[key], pos)

			continue
		}

		if seenKind&kindBit(e.kind) != 0 {
			continue
		}

		seenKind |= kindBit(e.kind)
		idx.byKind[e.kind] = append(idx.byKind[e.kind], pos)
	}
}

// patternSignature extracts the necessary matching condition for pattern p:
// the union (OR) of every top-level alternative's own signature. A pattern
// normally holds one alternative — compile_templates.go splits an unprioritized
// union match="P1|P2" into separate templates, one per alternative — but an
// explicit @priority keeps a union pattern as one template with several
// Alternatives, so this still has to union across them. Any single
// unindexable alternative makes the whole pattern unindexed: matchPattern
// returns true if ANY alternative matches, so a signature that ignored an
// unindexable alternative could wrongly rule out a node it actually admits.
func patternSignature(p *pattern) signature {
	var entries []sigEntry

	for _, alt := range p.Alternatives {
		if alt.neverMatches {
			continue // contributes nothing: matchPatternAlt always returns false for it
		}

		s := altSignature(p, alt.expr)
		if s.unindexed {
			return signature{unindexed: true}
		}

		entries = append(entries, s.entries...)
	}

	return signature{entries: entries}
}

// altSignature extracts the signature of one pattern alternative's AST,
// mirroring matchPatternAlt's own dispatch (compile_patterns.go). Only the
// forms matchPatternAlt matches WITHOUT ever falling back to
// matchByEvaluation are safe to narrow: LocationPath, PathStepExpr (whose
// terminal condition is entirely its Right side — matchPathStepPattern opens
// with matchPatternAlt(e.Right, node) and returns false on failure), RootExpr,
// and UnionExpr (union of both sides). Everything else — ContextItemExpr
// (always true), FilterExpr, VariableExpr, IntersectExceptExpr, and critically
// PathExpr (matchPathExprPattern falls through to matchByEvaluation when its
// terminal step fails, so the terminal step is not a necessary condition —
// this single case also covers key(...)/foo, id(...)/foo, and (a|b)/c) — is
// unindexed.
func altSignature(p *pattern, expr xpath.Expr) signature {
	switch e := expr.(type) {
	case xpath.LocationPath:
		return locationPathSignature(p, e)
	case *xpath.LocationPath:
		return locationPathSignature(p, *e)
	case xpath.RootExpr, *xpath.RootExpr:
		return signature{entries: []sigEntry{{kind: kindDocument}}}
	case xpath.PathStepExpr:
		return altSignature(p, e.Right)
	case xpath.UnionExpr:
		return unionAltSignature(p, e)
	default:
		return signature{unindexed: true}
	}
}

// unionAltSignature computes the signature of a nested UnionExpr (e.g. inside
// "(a|b)/c"'s Right, or a bare "a|b" alternative that survived the
// compile-time union split): the union of both sides, or unindexed if either
// side is.
func unionAltSignature(p *pattern, e xpath.UnionExpr) signature {
	left := altSignature(p, e.Left)

	right := altSignature(p, e.Right)
	if left.unindexed || right.unindexed {
		return signature{unindexed: true}
	}

	entries := make([]sigEntry, 0, len(left.entries)+len(right.entries))
	entries = append(entries, left.entries...)
	entries = append(entries, right.entries...)

	return signature{entries: entries}
}

// locationPathSignature extracts the signature of a LocationPath: the
// terminal (last) step governs, per matchLocationPath's own bottom-up
// matching (compile_patterns.go). A zero-step absolute path ("/") requires a
// document node; a zero-step relative path never matches any node (an empty
// pattern), and contributes no entries.
func locationPathSignature(p *pattern, path xpath.LocationPath) signature {
	if len(path.Steps) == 0 {
		if path.Absolute {
			return signature{entries: []sigEntry{{kind: kindDocument}}}
		}

		return signature{}
	}

	return stepSignature(p, path.Steps[len(path.Steps)-1])
}

// stepSignature extracts the signature of a single Step, mirroring
// nodeMatchesStep's gates (compile_patterns.go) exactly: predicates are
// ignored (they can only reject, never widen a match), the axis restricts the
// node-test's own kind set (attribute:: to {attribute}, namespace:: to
// {namespace}, every other axis excludes attribute/namespace/document except
// where a DocumentTest or self::node() explicitly re-admits document), and a
// concrete NameTest on a kind set narrowed to exactly {element} or
// {attribute} additionally narrows to a name key.
func stepSignature(p *pattern, step xpath.Step) signature {
	tk := nodeTestKinds(step.NodeTest)

	var ks kindSet

	switch step.Axis {
	case xpath.AxisAttribute:
		ks = tk & kindBit(kindAttribute)
	case xpath.AxisNamespace:
		ks = tk & kindBit(kindNamespace)
	default:
		ks = tk &^ (kindBit(kindAttribute) | kindBit(kindNamespace) | kindBit(kindDocument))
		if isDocumentTest(step.NodeTest) || (step.Axis == xpath.AxisSelf && isNodeKindNodeTest(step.NodeTest)) {
			ks |= kindBit(kindDocument)
		}
	}

	if ks == 0 {
		return signature{} // this step can never match any node kind
	}

	if k, ok := singleBit(ks); ok && (k == kindElement || k == kindAttribute) {
		if nt, isName := step.NodeTest.(xdm.NameTest); isName && isConcreteName(nt) {
			uri := resolveStaticPatternName(nt, p.nsBindings, p.xpathDefaultNS, k == kindElement)
			return signature{entries: []sigEntry{{kind: k, named: true, uri: uri, local: nt.Local}}}
		}
	}

	entries := make([]sigEntry, 0, numKinds)
	for k := range numKinds {
		if ks&kindBit(k) != 0 {
			entries = append(entries, sigEntry{kind: k})
		}
	}

	return signature{entries: entries}
}

// nodeTestKinds returns the set of node kinds a NodeTest can match BEFORE the
// axis-based gates in nodeMatchesStep are applied, mirroring nodeMatchesTest
// (compile_patterns.go) exactly.
func nodeTestKinds(nt xdm.NodeTest) kindSet {
	switch t := nt.(type) {
	case xdm.TypeTest:
		switch t.Kind {
		case xdm.NodeKindNode:
			return kindSetAll
		case xdm.NodeKindText:
			return kindBit(kindText)
		case xdm.NodeKindComment:
			return kindBit(kindComment)
		case xdm.NodeKindProcessingInstruction:
			return kindBit(kindPI)
		default:
			return 0
		}
	case xdm.NameTest:
		return kindBit(kindElement) | kindBit(kindAttribute) | kindBit(kindNamespace)
	case xdm.PITest:
		return kindBit(kindPI)
	case xdm.ElementTest, xdm.SchemaElementTest:
		return kindBit(kindElement)
	case xdm.AttributeTest, xdm.SchemaAttributeTest:
		return kindBit(kindAttribute)
	case xdm.DocumentTest:
		return kindBit(kindDocument)
	case xdm.NamespaceNodeTest:
		return kindBit(kindNamespace)
	default:
		return 0
	}
}

func isDocumentTest(nt xdm.NodeTest) bool {
	_, ok := nt.(xdm.DocumentTest)
	return ok
}

func isNodeKindNodeTest(nt xdm.NodeTest) bool {
	tt, ok := nt.(xdm.TypeTest)
	return ok && tt.Kind == xdm.NodeKindNode
}

// isConcreteName reports whether a NameTest names a single expanded name —
// not a wildcard local ("*"), and not a wildcard namespace ("*:local").
func isConcreteName(nt xdm.NameTest) bool {
	return nt.Local != "*" && nt.Prefix != "*"
}

// resolveStaticPatternName resolves a concrete NameTest's expected namespace
// URI within a pattern's compile-time namespace context, mirroring
// matchNameTest's own resolution order (compile_patterns.go) literally: an
// explicit URI (Q{uri}local) wins, then a prefix resolved through the
// pattern's lexical namespace snapshot, then — for an element name only —
// xpath-default-namespace; an unprefixed attribute name is always in no
// namespace. matchNameTest calls this same helper (via
// ec.patternNamespaces/ec.xpathDefaultNS, which during pattern matching hold
// exactly p.nsBindings/p.xpathDefaultNS) so the two resolution paths cannot
// drift apart.
func resolveStaticPatternName(nt xdm.NameTest, nsBindings map[string]string, xpathDefaultNS string, isElem bool) string {
	if nt.URI != "" {
		return nt.URI
	}

	if nt.Prefix != "" {
		return resolvePatternPrefix(nsBindings, nt.Prefix)
	}

	if isElem {
		return xpathDefaultNS
	}

	return ""
}

// nodeKindOf classifies a dispatched node into the coarse nodeKind buckets
// the index uses, collapsing CDATA into the same bucket as text (text()
// matches both — see matchTypeTest). ok is false for a node type the index
// never buckets (e.g. a DOCTYPE or entity node, which no XSLT match pattern
// can select).
func nodeKindOf(node xdm.Node) (nodeKind, bool) {
	switch node.Type() {
	case xdm.ElementNode:
		return kindElement, true
	case xdm.AttributeNode:
		return kindAttribute, true
	case xdm.TextNode, xdm.CDATASectionNode:
		return kindText, true
	case xdm.CommentNode:
		return kindComment, true
	case xdm.ProcessingInstructionNode:
		return kindPI, true
	case xdm.DocumentNode:
		return kindDocument, true
	case xdm.NamespaceNode:
		return kindNamespace, true
	default:
		return 0, false
	}
}

// expandedName is a node's (namespace URI, local name) pair.
type expandedName struct {
	uri   string
	local string
}

// expandedNameOf returns a node's expanded name, for the node types a named
// bucket ever keys on (element, attribute).
func expandedNameOf(node xdm.Node) (expandedName, bool) {
	switch v := node.(type) {
	case *xdm.Element:
		return expandedName{uri: v.URI(), local: v.LocalName()}, true
	case *xdm.Attribute:
		return expandedName{uri: v.URI(), local: v.LocalName()}, true
	default:
		return expandedName{}, false
	}
}

// indexCursor is an allocation-free ascending merge over the (at most) three
// bucket slices a dispatch on one node consults: a name bucket, a kind
// bucket, and the unindexed bucket. Every source slice is itself ascending
// (built by buildTemplateIndex walking the sorted mode list front to back),
// so the merge recovers exactly the original scan order restricted to
// positions that cannot be ruled out — dedup-ing a position that a
// multi-alternative pattern registered into more than one bucket, or that the
// same source slice happens to repeat consecutively.
type indexCursor struct {
	lists [3][]int32
	pos   [3]int
}

// next returns the next candidate position in ascending order, or false once
// every source list is exhausted. A position present in more than one list —
// cross-list (the same template registered in two buckets) or, defensively,
// repeated within one list — is only ever returned once.
func (c *indexCursor) next() (int32, bool) {
	lowest := int32(0)
	found := false

	for i := range c.lists {
		if c.pos[i] >= len(c.lists[i]) {
			continue
		}

		v := c.lists[i][c.pos[i]]
		if !found || v < lowest {
			lowest = v
			found = true
		}
	}

	if !found {
		return 0, false
	}

	for i := range c.lists {
		for c.pos[i] < len(c.lists[i]) && c.lists[i][c.pos[i]] == lowest {
			c.pos[i]++
		}
	}

	return lowest, true
}

// candidates builds the merge cursor for dispatching node against idx. idx
// must be non-nil (the caller checks modeIndex[mode] != nil before falling
// into the index path at all).
func candidates(idx *templateIndex, node xdm.Node) indexCursor {
	var c indexCursor

	c.lists[2] = idx.unindexed

	kind, ok := nodeKindOf(node)
	if !ok {
		return c
	}

	c.lists[1] = idx.byKind[kind]
	if kind == kindElement || kind == kindAttribute {
		if name, ok := expandedNameOf(node); ok {
			c.lists[0] = idx.byName[nameKey{kind: kind, uri: name.uri, local: name.local}]
		}
	}

	return c
}
