// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
	xpathstream "github.com/skarm/xmlsec/transform/internal/xslt/internal/stream"
)

type predicateOutcome int

const (
	// predicatesNeedPosition: the predicates cannot be decided from the node
	// alone; the caller evaluates them with the node's position.
	predicatesNeedPosition predicateOutcome = iota
	// predicatesFail: a predicate is false for the node, at any position.
	predicatesFail
	// predicatesMatch: every predicate is true for the node, at any position.
	predicatesMatch
)

// pattern is a compiled XSLT match pattern.
type pattern struct {
	nsBindings map[string]string // prefix→URI bindings from compile context
	// predicates holds the compiled form of every step predicate in the
	// pattern's location paths, keyed by the predicate's address in the AST
	// (&step.Predicates[i]). It is built once by compilePattern and only read
	// while matching.
	predicates map[*xpath.Expr]*patternPredicate
	source     string
	// xpathDefaultNS is the effective xpath-default-namespace at the compile
	// site; hasXPathDefaultNS records whether one is in effect at all.
	// An explicit xpath-default-namespace="" sets hasXPathDefaultNS=true with an
	// empty xpathDefaultNS, which RESETS an inherited default to no-namespace —
	// distinct from no xpath-default-namespace ever being declared (false).
	xpathDefaultNS    string
	defaultCollation  string
	Alternatives      []*patternAlt
	hasXPathDefaultNS bool
	// compat is true when the pattern was compiled under backwards-compatible
	// processing (effective version < 2.0); its predicate expressions then
	// evaluate in XPath 1.0 compatibility mode (§3.10.1).
	compat bool
}

// matchPattern tests whether a node matches the pattern.
func (p *pattern) matchPattern(ctx context.Context, ec *execContext, node xdm.Node) bool {
	// Temporarily clear contextItem so predicates evaluate with the candidate
	// node as the context item (not an atomic value from an enclosing
	// instruction like xsl:analyze-string), and clear regexGroups. Per XSLT
	// spec, the set of captured substrings is empty when evaluating patterns:
	// regex-group() must return empty sequence inside a pattern, not groups
	// from an enclosing matching-substring. These fields, plus contextNode/
	// currentNode/inPatternMatch, depend only on node — never on which pattern
	// is being probed — so a caller that probes many patterns against the same
	// node (a dispatch scan) can set them once and call matchPatternProbe
	// directly instead of paying this save/restore on every probe.
	savedGroups := ec.regexGroups
	savedContext := ec.contextNode
	savedCurrent := ec.currentNode
	savedItem := ec.contextItem
	savedInPattern := ec.inPatternMatch
	ec.regexGroups = nil
	ec.contextNode = node
	ec.currentNode = node
	ec.contextItem = nil

	ec.inPatternMatch = true
	defer func() {
		ec.regexGroups = savedGroups
		ec.contextNode = savedContext
		ec.currentNode = savedCurrent
		ec.contextItem = savedItem
		ec.inPatternMatch = savedInPattern
	}()

	return p.matchPatternProbe(ctx, ec, node)
}

// matchPatternProbe tests whether node matches the pattern, assuming the
// caller has already set the node-scoped execContext fields (contextNode,
// currentNode, contextItem, inPatternMatch, regexGroups) for node — either via
// matchPattern itself, or once around a dispatch loop that probes many
// patterns against the same node (see findFirstMatch / hasConflictingMatch).
// It saves and restores only the fields that vary per pattern:
// xpath-default-namespace, the pattern's lexical namespace snapshot, its
// backwards-compatible-processing flag, and its compiled step predicates.
func (p *pattern) matchPatternProbe(ctx context.Context, ec *execContext, node xdm.Node) bool {
	saved := ec.xpathDefaultNS
	savedHas := ec.hasXPathDefaultNS
	savedPatternNS := ec.patternNamespaces
	savedPatternCompat := ec.patternCompat
	savedPatternPreds := ec.patternPredicates
	savedCollation := ec.defaultCollation
	ec.xpathDefaultNS = p.xpathDefaultNS
	ec.hasXPathDefaultNS = p.hasXPathDefaultNS
	ec.patternNamespaces = p.nsBindings
	ec.patternCompat = p.compat

	ec.patternPredicates = p.predicates

	ec.defaultCollation = p.defaultCollation
	defer func() {
		ec.xpathDefaultNS = saved
		ec.hasXPathDefaultNS = savedHas
		ec.patternNamespaces = savedPatternNS
		ec.patternCompat = savedPatternCompat
		ec.patternPredicates = savedPatternPreds
		ec.defaultCollation = savedCollation
	}()

	for _, alt := range p.Alternatives {
		if matchPatternAlt(ctx, ec, alt, node) {
			return true
		}
	}

	return false
}

// matchPatternAlt tests whether a node matches a single pattern alternative.
// XSLT patterns evaluate by checking if the node would be selected by the
// equivalent XPath expression when evaluated in the right context.
func matchPatternAlt(ctx context.Context, ec *execContext, alt *patternAlt, node xdm.Node) bool {
	if alt.neverMatches {
		return false
	}

	switch e := alt.expr.(type) {
	case xpath.LocationPath:
		return matchLocationPath(ctx, ec, e, node)
	case *xpath.LocationPath:
		return matchLocationPath(ctx, ec, *e, node)
	case xpath.RootExpr:
		return node.Type() == xdm.DocumentNode
	case *xpath.RootExpr:
		return node.Type() == xdm.DocumentNode
	case xpath.ContextItemExpr:
		// "." matches any node (equivalent to self::node()).
		return true
	case xpath.FilterExpr:
		// FilterExpr with root inner: (/)[pred] — matches document node
		// when predicate is true.
		if lp, ok := e.Expr.(xpath.LocationPath); ok && lp.Absolute && len(lp.Steps) == 0 {
			if node.Type() != xdm.DocumentNode {
				return false
			}

			return matchByEvaluation(ctx, ec, alt, node)
		}

		return matchByEvaluation(ctx, ec, alt, node)
	case xpath.UnionExpr:
		// Union pattern: (a|b) matches if node matches either operand.
		leftAlt := &patternAlt{expr: e.Left}
		rightAlt := &patternAlt{expr: e.Right}

		return matchPatternAlt(ctx, ec, leftAlt, node) || matchPatternAlt(ctx, ec, rightAlt, node)
	case xpath.IntersectExceptExpr:
		// intersect/except patterns require evaluation-based matching to
		// get correct set semantics. Both sides must be evaluated from the
		// same context; independent matching gives wrong results for cases
		// like "a//* intersect b//*" where a and b are nested.
		return matchByEvaluation(ctx, ec, alt, node)
	case xpath.PathStepExpr:
		// Path step pattern: E1/E2 or E1//E2 where E2 is a non-axis step.
		// Match bottom-up: check if the candidate matches the right part,
		// then verify the left part matches an ancestor.
		return matchPathStepPattern(ctx, ec, e, node)
	case xpath.PathExpr:
		// PathExpr: filter/steps. Try bottom-up matching first; fall back
		// to evaluation-based matching for complex cases (key()//union, etc.).
		if matchPathExprPattern(ctx, ec, e, node) {
			return true
		}

		return matchByEvaluation(ctx, ec, alt, node)
	case xpath.VariableExpr:
		// $var pattern: matches if node is in the variable's value.
		return matchByEvaluation(ctx, ec, alt, node)
	default:
		// For complex expressions, try evaluating from document root
		// and checking if node is in the result set.
		return matchByEvaluation(ctx, ec, alt, node)
	}
}

// matchPathExprPattern matches a PathExpr pattern (Filter/Path) bottom-up.
// First checks if the node matches the path's last step, then works upward
// through the remaining steps, and finally checks the filter against an ancestor.
func matchPathExprPattern(ctx context.Context, ec *execContext, e xpath.PathExpr, node xdm.Node) bool {
	if e.Path == nil || len(e.Path.Steps) == 0 {
		// No path steps: just check the filter
		filterAlt := &patternAlt{expr: e.Filter}
		return matchPatternAlt(ctx, ec, filterAlt, node)
	}

	// Match the path steps bottom-up (like matchLocationPath)
	lastStep := e.Path.Steps[len(e.Path.Steps)-1]
	if !nodeMatchesStep(ctx, ec, lastStep, node) {
		return false
	}

	// If there's only one step, check the filter against the parent
	if len(e.Path.Steps) == 1 {
		filterAlt := &patternAlt{expr: e.Filter}

		parent := node.Parent()
		if parent != nil && matchPatternAlt(ctx, ec, filterAlt, parent) {
			return true
		}

		return false
	}

	// Multiple steps: match remaining steps upward, then check filter
	remaining := e.Path.Steps[:len(e.Path.Steps)-1]

	parent := node.Parent()
	if parent == nil {
		return false
	}

	if !matchStepsUpward(ctx, ec, remaining, false, parent) {
		return false
	}
	// Walk up to find where the remaining steps matched, then check filter
	filterAlt := &patternAlt{expr: e.Filter}
	// The filter needs to match the ancestor above the remaining steps
	cur := parent
	for range slices.Backward(remaining) {
		cur = cur.Parent()
		if cur == nil {
			return false
		}
	}

	return matchPatternAlt(ctx, ec, filterAlt, cur)
}

// matchPathStepPattern matches a PathStepExpr pattern (E1/E2 or E1//E2) bottom-up.
// First checks if the candidate node matches the right part (E2), then verifies
// that an ancestor matches the left part (E1).
func matchPathStepPattern(ctx context.Context, ec *execContext, e xpath.PathStepExpr, node xdm.Node) bool {
	rightAlt := &patternAlt{expr: e.Right}
	if !matchPatternAlt(ctx, ec, rightAlt, node) {
		return false
	}
	// Determine if the right part uses descendant-axis steps.
	// When the right part (or any union branch) uses descendant::,
	// the left part may match ANY ancestor, not just the parent.
	checkAllAncestors := e.DescOrSelf || rightPartUsesDescendantAxis(e.Right)
	leftAlt := &patternAlt{expr: e.Left}

	if checkAllAncestors {
		for ancestor := node.Parent(); ancestor != nil; ancestor = ancestor.Parent() {
			if matchPatternAlt(ctx, ec, leftAlt, ancestor) {
				return true
			}
		}
	} else {
		// E1/E2 with child axis: check immediate parent.
		parent := node.Parent()
		if parent != nil && matchPatternAlt(ctx, ec, leftAlt, parent) {
			return true
		}
	}

	return false
}

// rightPartUsesDescendantAxis checks if an expression (typically the right
// side of a PathStepExpr) contains any descendant:: or descendant-or-self::
// axis steps. This determines whether ancestor matching should walk all the
// way up the tree.
func rightPartUsesDescendantAxis(expr xpath.Expr) bool {
	found := false

	xpathstream.WalkExpr(expr, func(e xpath.Expr) bool {
		if found {
			return false
		}

		switch lp := e.(type) {
		case xpath.LocationPath:
			for _, step := range lp.Steps {
				if step.Axis == xpath.AxisDescendant || step.Axis == xpath.AxisDescendantOrSelf {
					found = true
					return false
				}
			}
		}

		return true
	})

	return found
}

// matchLocationPath matches a LocationPath pattern against a node.
// Patterns match bottom-up: starting from the node, check if there's
// a path from the root that would select this node.
func matchLocationPath(ctx context.Context, ec *execContext, path xpath.LocationPath, node xdm.Node) bool {
	if len(path.Steps) == 0 {
		// "/" matches document nodes
		return path.Absolute && node.Type() == xdm.DocumentNode
	}

	// Check the last step against the node.
	// For a last step on the descendant axis with predicates, skip predicate
	// evaluation here — predicates will be evaluated with proper
	// descendant-set position relative to the ancestor later.
	lastStep := path.Steps[len(path.Steps)-1]
	descendantAxis := lastStep.Axis == xpath.AxisDescendant || lastStep.Axis == xpath.AxisDescendantOrSelf

	hasDescPreds := descendantAxis && len(lastStep.Predicates) > 0
	if hasDescPreds {
		stepNoPreds := lastStep

		stepNoPreds.Predicates = nil
		if !nodeMatchesStep(ctx, ec, stepNoPreds, node) {
			return false
		}
	} else if !nodeMatchesStep(ctx, ec, lastStep, node) {
		return false
	}

	// If there's only one step on the child axis and it's absolute, check
	// parent is document. A single descendant step reaches below the children
	// and goes through the descendant matching below.
	if len(path.Steps) == 1 && !descendantAxis {
		if path.Absolute {
			parent := node.Parent()
			return parent != nil && parent.Type() == xdm.DocumentNode
		}

		return true
	}

	// Match remaining steps upward.
	// The axis of the last step determines how to walk to the preceding step.
	remaining := path.Steps[:len(path.Steps)-1]

	if descendantAxis {
		if hasDescPreds {
			return matchDescendantStepPredicates(ctx, ec, path.Absolute, remaining, lastStep, node)
		}
		// descendant axis: any ancestor may match the preceding steps; for
		// descendant-or-self, the node itself may too.
		start := node.Parent()
		if lastStep.Axis == xpath.AxisDescendantOrSelf {
			start = node
		}
		// XSLT 3.0 §5.5.3 gives a descendant step no "-or-top" form, so a
		// parentless node never matches through the descendant axis.
		for cur := start; cur != nil; cur = cur.Parent() {
			if matchStepsUpward(ctx, ec, remaining, path.Absolute, cur) {
				return true
			}
		}

		return false
	}

	if matchStepsUpward(ctx, ec, remaining, path.Absolute, node.Parent()) {
		return true
	}

	return false
}

// matchDescendantStepPredicates matches the remaining steps and the
// predicates of the last step of a pattern whose last step, on the
// descendant or descendant-or-self axis, carries predicates. node has already
// passed the step's node test. A position in those predicates counts among
// all the nodes the step selects from the ancestor that matches the
// remaining steps, so the predicates are evaluated per candidate ancestor,
// unless they are focus-free and can be decided from node alone.
func matchDescendantStepPredicates(ctx context.Context, ec *execContext, absolute bool, remaining []xpath.Step, lastStep xpath.Step, node xdm.Node) bool {
	positional := true

	switch matchFocusFreePredicates(ctx, ec, lastStep.Predicates, node) {
	case predicatesFail:
		return false
	case predicatesMatch:
		positional = false
	}

	isSelfAxis := lastStep.Axis == xpath.AxisDescendantOrSelf
	// For descendant-or-self, start from the node itself (it IS a
	// descendant-or-self of itself) and walk upward through ancestors.
	// For descendant (without self), start from parent.
	startNode := node.Parent()
	if isSelfAxis {
		startNode = node
	}

	for cur := startNode; cur != nil; cur = cur.Parent() {
		if matchDescendantStepFrom(ctx, ec, absolute, remaining, lastStep, node, cur, isSelfAxis, positional) {
			return true
		}
	}

	return false
}

// matchDescendantStepFrom reports whether cur matches the remaining steps and,
// when positional is set, whether node passes lastStep's predicates at its
// position among the nodes the step selects from cur (cur itself included
// when includeSelf is set). With positional unset the caller has already
// decided the predicates from node alone.
func matchDescendantStepFrom(ctx context.Context, ec *execContext, absolute bool, remaining []xpath.Step, lastStep xpath.Step, node, cur xdm.Node, includeSelf, positional bool) bool {
	if !matchStepsUpward(ctx, ec, remaining, absolute, cur) {
		return false
	}

	if !positional {
		return true
	}
	// Collect all descendants of cur that match the name test.
	// For descendant-or-self, include cur itself if it matches.
	var descendants []xdm.Node
	if includeSelf && nodeMatchesTest(ctx, ec, lastStep.NodeTest, cur) {
		descendants = append(descendants, cur)
	}

	descendants = append(descendants, collectDescendants(ctx, ec, lastStep.NodeTest, cur)...)

	return passesChainedPredicates(ctx, ec, lastStep.Predicates, descendants, node)
}

// matchStepsUpward matches remaining pattern steps upward through ancestors.
func matchStepsUpward(ctx context.Context, ec *execContext, steps []xpath.Step, absolute bool, node xdm.Node) bool {
	if len(steps) == 0 {
		if absolute {
			return node != nil && node.Type() == xdm.DocumentNode
		}

		return true
	}

	if node == nil {
		return false
	}

	lastStep := steps[len(steps)-1]

	switch lastStep.Axis {
	case xpath.AxisChild:
		// child axis in pattern means "the parent must match"
		if !nodeMatchesStep(ctx, ec, lastStep, node) {
			return false
		}

		return matchStepsUpward(ctx, ec, steps[:len(steps)-1], absolute, node.Parent())
	case xpath.AxisDescendantOrSelf:
		// // in pattern means any ancestor may match
		// This step is the desc-or-self::node() inserted by //
		// Try matching from this node and any ancestor
		remaining := steps[:len(steps)-1]
		for cur := node; cur != nil; cur = cur.Parent() {
			if matchStepsUpward(ctx, ec, remaining, absolute, cur) {
				return true
			}
		}

		return false
	default:
		if !nodeMatchesStep(ctx, ec, lastStep, node) {
			return false
		}

		return matchStepsUpward(ctx, ec, steps[:len(steps)-1], absolute, node.Parent())
	}
}

// nodeMatchesStep checks if a node matches a single step's node test and predicates.
func nodeMatchesStep(ctx context.Context, ec *execContext, step xpath.Step, node xdm.Node) bool {
	nodeType := node.Type()

	// Document nodes are matched by document-node() patterns, or by node()
	// on the self axis (as in match=".").  On the child/descendant axes,
	// document nodes are never selected.
	if nodeType == xdm.DocumentNode {
		if _, isDocTest := step.NodeTest.(xdm.DocumentTest); !isDocTest {
			// Allow self::node() to match document nodes.
			if step.Axis != xpath.AxisSelf {
				return false
			}

			if tt, ok := step.NodeTest.(xdm.TypeTest); !ok || tt.Kind != xdm.NodeKindNode {
				return false
			}
		}
	}
	// Attribute nodes are only matched by the attribute axis (e.g., @*, attribute::node()).
	// The default child axis does not include attributes.
	// Conversely, the attribute axis only matches attribute nodes.
	isAttr := nodeType == xdm.AttributeNode
	if isAttr != (step.Axis == xpath.AxisAttribute) {
		return false
	}
	// Namespace nodes are only matched by the namespace axis or namespace-node() test.
	// matchesNamespaceNodes relies on this being the only way a namespace node
	// can match: widening it (e.g. letting self:: select one) requires updating
	// matchesNamespaceNodes too, or key table building will silently drop
	// namespace-node entries.
	isNS := nodeType == xdm.NamespaceNode
	if isNS != (step.Axis == xpath.AxisNamespace) {
		return false
	}

	if !nodeMatchesTest(ctx, ec, step.NodeTest, node) {
		return false
	}

	if len(step.Predicates) > 0 {
		return evaluateChainedPredicates(ctx, ec, step, node)
	}

	return true
}

// nodeMatchesTest checks if a node matches a node test.
func nodeMatchesTest(ctx context.Context, ec *execContext, test xdm.NodeTest, node xdm.Node) bool {
	switch nt := test.(type) {
	case xdm.TypeTest:
		return matchTypeTest(nt, node)
	case xdm.NameTest:
		return matchNameTest(ctx, ec, nt, node)
	case xdm.PITest:
		if node.Type() != xdm.ProcessingInstructionNode {
			return false
		}

		if nt.Target == "" {
			return true
		}

		pi, ok := node.(*xdm.ProcessingInstruction)

		return ok && pi.Name() == nt.Target
	case xdm.ElementTest:
		return matchElementTest(ctx, ec, nt, node)
	case xdm.AttributeTest:
		return matchAttributeTest(ctx, ec, nt, node)
	case xdm.DocumentTest:
		return matchDocumentTest(ctx, ec, nt, node)
	case xdm.NamespaceNodeTest:
		return node.Type() == xdm.NamespaceNode
	case xdm.SchemaElementTest:
		return matchSchemaElementTest(ctx, ec, nt, node)
	case xdm.SchemaAttributeTest:
		return matchSchemaAttributeTest(ctx, ec, nt, node)
	default:
		return false
	}
}

// matchSchemaElementTest checks if a node matches a schema-element(name) test.
func matchSchemaElementTest(_ context.Context, ec *execContext, t xdm.SchemaElementTest, node xdm.Node) bool {
	if node.Type() != xdm.ElementNode {
		return false
	}

	elem, _ := xdm.AsNode[*xdm.Element](node)
	// Resolve the schema element name through the shared pattern-name resolver so
	// the pattern's lexical namespace snapshot (and xpath-default-namespace)
	// governs prefix resolution, identical to NameTest/element().
	local, ns := resolvePatternKindTestName(ec, t.Name)
	nameMatch := elem.LocalName() == local && elem.URI() == ns

	if !nameMatch {
		return false
	}

	return false
}

// matchSchemaAttributeTest checks if a node matches a schema-attribute(name) test.
func matchSchemaAttributeTest(_ context.Context, ec *execContext, t xdm.SchemaAttributeTest, node xdm.Node) bool {
	if node.Type() != xdm.AttributeNode {
		return false
	}

	attr, _ := xdm.AsNode[*xdm.Attribute](node)
	// Resolve through the shared pattern-name resolver. Note: an unprefixed
	// schema-attribute() name is in no namespace (attributes are not governed by
	// xpath-default-namespace); resolvePatternKindTestName returns no namespace
	// for a bare name unless a default is in effect, but for attributes we never
	// apply the element default, so strip any default-namespace result here.
	local, ns := resolvePatternKindTestName(ec, t.Name)
	if !strings.HasPrefix(t.Name, "Q{") && !strings.Contains(t.Name, ":") {
		ns = ""
	}

	if attr.LocalName() != local || attr.URI() != ns {
		return false
	}

	return false
}

// resolvePatternKindTestName resolves a kind-test name string (used by
// element(), attribute(), schema-element(), schema-attribute()) to its expected
// local name and namespace URI within a pattern's namespace context. It is the
// single shared resolution path for every pattern-name site so compile-time and
// runtime resolution stay symmetric. The parse order is:
//
//  1. Q{uri}local — braced EQName/URIQualifiedName (checked FIRST so that a name
//     like Q{http://x}a is not mis-split on the ':' inside the URI).
//  2. prefix:local — lexical QName; the prefix resolves via the pattern's
//     namespace snapshot (ec.resolvePrefix during pattern matching).
//  3. bare local — unprefixed; resolves to xpath-default-namespace when one is
//     in effect (including an explicit "" reset → no namespace), else to no
//     namespace.
func resolvePatternKindTestName(ec *execContext, name string) (string, string) {
	if strings.HasPrefix(name, "Q{") {
		if closeIdx := strings.IndexByte(name, '}'); closeIdx >= 0 {
			return name[closeIdx+1:], name[2:closeIdx]
		}
		// Malformed Q{...} without a closing brace: treat the whole thing as a
		// local name in no namespace.
		return name, ""
	}

	if prefix, local, ok := strings.Cut(name, ":"); ok {
		uri := ""
		if ec != nil {
			uri = ec.resolvePrefix(prefix)
		}

		return local, uri
	}

	uri := ""
	if ec != nil && ec.hasXPathDefaultNS {
		uri = ec.xpathDefaultNS
	}

	return name, uri
}

func matchTypeTest(tt xdm.TypeTest, node xdm.Node) bool {
	switch tt.Kind {
	case xdm.NodeKindNode:
		return true
	case xdm.NodeKindText:
		return node.Type() == xdm.TextNode || node.Type() == xdm.CDATASectionNode
	case xdm.NodeKindComment:
		return node.Type() == xdm.CommentNode
	case xdm.NodeKindProcessingInstruction:
		return node.Type() == xdm.ProcessingInstructionNode
	}

	return false
}

func matchNameTest(_ context.Context, ec *execContext, nt xdm.NameTest, node xdm.Node) bool {
	var (
		nodeLocal, nodeURI string
		isElem             bool
	)

	switch v := node.(type) {
	case *xdm.Element:
		isElem = true
		nodeLocal = v.LocalName()
		nodeURI = v.URI()
	case *xdm.Attribute:
		nodeLocal = v.LocalName()
		nodeURI = v.URI()
	case *xdm.NamespaceNodeWrapper:
		nodeLocal = v.Name()
		nodeURI = ""
	default:
		return false
	}

	if nt.Local == "*" && nt.Prefix == "" && nt.URI == "" {
		// * matches all elements/attributes/namespace-nodes
		return true
	}

	if nt.Local == "*" {
		// prefix:* matches any local name in the given namespace
		uri := nt.URI
		if uri == "" && nt.Prefix != "" && ec != nil {
			uri = ec.resolvePrefix(nt.Prefix)
		}

		return nodeURI == uri
	}

	// Exact name match
	if nt.URI != "" {
		return nodeLocal == nt.Local && nodeURI == nt.URI
	}

	if nt.Prefix == "*" {
		// *:local matches any namespace
		return nodeLocal == nt.Local
	}
	// Resolve through the same shared helper the dispatch index's signature
	// extractor uses (resolveStaticPatternName in dispatch_index.go), so the
	// two resolution paths cannot drift apart. During pattern matching
	// ec.patternNamespaces and ec.xpathDefaultNS hold exactly the pattern's
	// own p.nsBindings/p.xpathDefaultNS (matchPattern/matchPatternProbe set
	// them), which is what ec.resolvePrefix already short-circuits to via
	// resolvePatternPrefix while ec.inPatternMatch is set.
	expectedURI := ""
	if ec != nil {
		expectedURI = resolveStaticPatternName(nt, ec.patternNamespaces, ec.xpathDefaultNS, isElem)
	}

	if nodeLocal != nt.Local || nodeURI != expectedURI {
		return false
	}
	// XSLT 3.0 §6.6: when the mode is typed (typed="strict" or typed="lax"), a
	// bare element name pattern whose name is a global element declaration is
	// treated as an implicit schema-element() — the element must have been
	// validated against that declaration for the pattern to match. strict and
	// lax differ in how an untyped / undeclared node is treated: strict rejects
	// it, lax falls back to a plain by-name match. A TYPED node whose type is
	// not derived from the declared type never matches in either (e.g. a
	// constructed element carrying xsl:type="xs:string" for a name declared with
	// a decimal type).
	if isElem && ec != nil && nt.Prefix != "*" {
		strict := isTypedStrictMode(ec)
		if strict || isTypedLaxMode(ec) {
			return !strict
		}
	}

	return true
}

// isTypedStrictMode returns true if the current mode has typed="strict" or typed="yes".
func isTypedStrictMode(ec *execContext) bool {
	if md := currentModeDef(ec); md != nil {
		return md.Typed == validationStrict || md.Typed == lexicon.ValueYes || md.Typed == lexicon.ValueTrue || md.Typed == "1"
	}

	return false
}

// isTypedLaxMode returns true if the current mode has typed="lax".
func isTypedLaxMode(ec *execContext) bool {
	if md := currentModeDef(ec); md != nil {
		return md.Typed == validationLax
	}

	return false
}

// currentModeDef returns the mode definition for the current mode, falling back
// to the default (unnamed) mode definition when the current mode is unnamed.
func currentModeDef(ec *execContext) *modeDef {
	return ec.lookupModeDef(ec.currentMode)
}

// matchElementTest checks if a node matches an element() test.
// isBuiltinXSDType returns true for type names that are built-in XSD types
// (e.g., lexicon.TypeString, "integer", "decimal", "untyped", "untypedAtomic").
func isBuiltinXSDType(name string) bool {
	switch name {
	case lexicon.TypeString, lexicon.TypeBoolean, lexicon.TypeDecimal, lexicon.TypeFloat, lexicon.TypeDouble,
		lexicon.TypeDuration, lexicon.TypeDateTime, lexicon.TypeTime, lexicon.TypeDate,
		"gYearMonth", "gYear", "gMonthDay", "gDay", "gMonth",
		"hexBinary", "base64Binary", lexicon.TypeAnyURI, "QName", "NOTATION",
		"normalizedString", "token", "language", "NMTOKEN", "NMTOKENS",
		"Name", "NCName", "ID", "IDREF", "IDREFS", "ENTITY", "ENTITIES",
		lexicon.TypeInteger, "nonPositiveInteger", "negativeInteger", "long", "int",
		"short", "byte", "nonNegativeInteger", "unsignedLong", "unsignedInt",
		"unsignedShort", "unsignedByte", "positiveInteger",
		lexicon.TypeYearMonthDuration, lexicon.TypeDayTimeDuration, "dateTimeStamp",
		"untyped", lexicon.TypeUntypedAtomic, "anyType", "anySimpleType", "anyAtomicType":
		return true
	}

	return false
}

func matchElementTest(ctx context.Context, ec *execContext, et xdm.ElementTest, node xdm.Node) bool {
	if node.Type() != xdm.ElementNode {
		return false
	}

	if et.Name == "" || et.Name == "*" {
		if et.TypeName != "" {
			return matchTypeAnnotation(ctx, ec, node, et.TypeName)
		}

		return true
	}

	elem, ok := node.(*xdm.Element)
	if !ok {
		return false
	}
	// Resolve the test name through the shared pattern-name resolver (Q{}-first
	// EQName parsing, lexical-snapshot prefix resolution, xpath-default-namespace
	// for bare names) so element() resolves identically to NameTest. Compare BOTH
	// local name and namespace URI.
	local, uri := resolvePatternKindTestName(ec, et.Name)
	if elem.LocalName() != local || elem.URI() != uri {
		return false
	}

	if et.TypeName != "" {
		if !matchTypeAnnotation(ctx, ec, node, et.TypeName) {
			return false
		}
		// element(name, type) without ? does not match nilled elements;
		// element(name, type?) with ? matches even when nilled.
		if !et.Nillable && ec != nil && ec.isNilled(elem) {
			return false
		}

		return true
	}

	return true
}

// matchAttributeTest checks if a node matches an attribute() test.
func matchAttributeTest(ctx context.Context, ec *execContext, at xdm.AttributeTest, node xdm.Node) bool {
	if node.Type() != xdm.AttributeNode {
		return false
	}

	if at.Name == "" || at.Name == "*" {
		if at.TypeName != "" {
			return matchTypeAnnotation(ctx, ec, node, at.TypeName)
		}

		return true
	}

	attr, ok := node.(*xdm.Attribute)
	if !ok {
		return false
	}

	attrLocal := attr.LocalName()
	if idx := strings.IndexByte(attrLocal, ':'); idx >= 0 {
		attrLocal = attrLocal[idx+1:]
	}
	// Resolve the test name through the shared pattern-name resolver (Q{}-first
	// EQName parsing, then prefix:local via the lexical snapshot). A bare,
	// unprefixed attribute name is always in no namespace — the
	// xpath-default-namespace governs element names, not attribute names — so
	// override the resolver's default for the bare case.
	local, uri := resolvePatternKindTestName(ec, at.Name)
	if !strings.HasPrefix(at.Name, "Q{") && !strings.Contains(at.Name, ":") {
		uri = ""
	}

	if attrLocal != local || attr.URI() != uri {
		return false
	}

	if at.TypeName != "" {
		return matchTypeAnnotation(ctx, ec, node, at.TypeName)
	}

	return true
}

// matchTypeAnnotation checks if a node's type annotation matches the given type name.
func matchTypeAnnotation(_ context.Context, ec *execContext, node xdm.Node, typeName string) bool {
	var ann string
	if ec != nil && ec.typeAnnotations != nil {
		ann = ec.typeAnnotations[node]
	}

	if ann == "" {
		switch node.Type() {
		case xdm.ElementNode:
			ann = "untyped"
		case xdm.AttributeNode:
			ann = lexicon.TypeUntypedAtomic
		default:
			return false
		}
	}

	// Try direct comparison after resolving prefixes
	resolvedAnn := resolvePatternTypeName(ec, ann)

	resolvedType := resolvePatternTypeName(ec, typeName)
	if resolvedAnn == resolvedType {
		return true
	}

	normAnn := normalizePatternTypeName(ann)

	normType := normalizePatternTypeName(typeName)
	if normAnn == normType {
		return true
	}

	fullAnn := ann
	if !strings.HasPrefix(fullAnn, "xs:") && !strings.HasPrefix(fullAnn, "Q{") {
		fullAnn = "xs:" + fullAnn
	}

	fullType := typeName
	if !strings.HasPrefix(fullType, "xs:") && !strings.HasPrefix(fullType, "Q{") {
		fullType = "xs:" + fullType
	}

	if xdm.BuiltinIsSubtypeOf(fullAnn, fullType) {
		return true
	}

	return false
}

func normalizePatternTypeName(name string) string {
	for _, prefix := range []string{"xs:", "xsd:", "http://www.w3.org/2001/XMLSchema:"} {
		if strings.HasPrefix(name, prefix) {
			return name[len(prefix):]
		}
	}

	return name
}

// resolvePatternTypeName expands type names using the pattern's lexical context.
func resolvePatternTypeName(ec *execContext, name string) string {
	if strings.HasPrefix(name, "Q{") {
		return name
	}

	if prefix, local, ok := strings.Cut(name, ":"); ok {
		if ec != nil {
			if uri := ec.resolvePrefix(prefix); uri != "" {
				return "Q{" + uri + "}" + local
			}
		}

		return name
	}

	if ec != nil && ec.xpathDefaultNS != "" {
		return "Q{" + ec.xpathDefaultNS + "}" + name
	}

	if !isBuiltinXSDType(name) {
		return "Q{}" + name
	}

	return name
}

// matchDocumentTest checks if a node matches a document-node() test.
func matchDocumentTest(ctx context.Context, ec *execContext, dt xdm.DocumentTest, node xdm.Node) bool {
	if node.Type() != xdm.DocumentNode {
		return false
	}

	if dt.Inner == nil {
		return true
	}
	// document-node(element(name)) — check that the document has a single
	// element child matching the inner test.
	doc, ok := node.(*xdm.Document)
	if !ok {
		return false
	}

	var docElem xdm.Node

	for child := range xdm.Children(doc) {
		if child.Type() == xdm.ElementNode {
			if docElem != nil {
				return false // more than one element child
			}

			docElem = child
		}
	}

	if docElem == nil {
		return false
	}

	return nodeMatchesTest(ctx, ec, dt.Inner, docElem)
}

// evaluateChainedPredicates evaluates a chain of predicates in a pattern step.
// For patterns with multiple predicates like x[P1][P2][P3], each predicate
// filters based on position among siblings matching the node test AND all
// previous predicates. This implements XSLT 3.0 Section 5.5.3.
//
// Focus-free predicates are decided from the node alone (see
// matchFocusFreePredicates); only the others pay for collecting the siblings.
func evaluateChainedPredicates(ctx context.Context, ec *execContext, step xpath.Step, node xdm.Node) bool {
	switch matchFocusFreePredicates(ctx, ec, step.Predicates, node) {
	case predicatesFail:
		return false
	case predicatesMatch:
		return true
	}

	siblings := collectMatchingSiblings(ctx, ec, step.NodeTest, node)

	return passesChainedPredicates(ctx, ec, step.Predicates, siblings, node)
}

// passesChainedPredicates reports whether node passes preds when they filter
// selected, the nodes a pattern step selects from one context node in
// document order, in turn (XSLT 3.0 §5.5.3): each predicate sees the node's
// position and the size of the list the previous predicates left.
func passesChainedPredicates(ctx context.Context, ec *execContext, preds []xpath.Expr, selected []xdm.Node, node xdm.Node) bool {
	for i := range preds {
		pred := ec.patternPredicate(&preds[i])
		if pred == nil {
			return false
		}

		pos := 0

		for j, n := range selected {
			if n == node {
				pos = j + 1
				break
			}
		}

		if pos == 0 {
			return false // node not in the filtered set
		}

		if !evaluatePredicateWithPosition(ctx, ec, pred.compiled, node, pos, len(selected)) {
			return false
		}

		// For subsequent predicates, filter the list
		if i < len(preds)-1 {
			var filtered []xdm.Node

			for j, n := range selected {
				if evaluatePredicateWithPosition(ctx, ec, pred.compiled, n, j+1, len(selected)) {
					filtered = append(filtered, n)
				}
			}

			selected = filtered
		}
	}

	return true
}

// collectDescendants collects the XDM descendants of root that match the
// given node test, in document order, as the descendant axis selects them: a
// DOCTYPE or an entity reference is not a descendant, and neither is anything
// beneath it. An attribute has no descendants. A cancelled context ends the
// collection with no nodes, so nothing matches.
func collectDescendants(ctx context.Context, ec *execContext, test xdm.NodeTest, root xdm.Node) []xdm.Node {
	if root.Type() == xdm.AttributeNode {
		return nil
	}

	stack, err := xdm.PushXDMChildren(ctx, nil, root)
	if err != nil {
		return nil
	}

	var result []xdm.Node

	for len(stack) > 0 {
		last := len(stack) - 1
		cur := stack[last]
		stack = stack[:last]

		if nodeMatchesTest(ctx, ec, test, cur) {
			result = append(result, cur)
		}

		stack, err = xdm.PushXDMChildren(ctx, stack, cur)
		if err != nil {
			return nil
		}
	}

	return result
}

// collectMatchingSiblings collects all siblings (including the node itself)
// that match the given node test, in document order.
func collectMatchingSiblings(ctx context.Context, ec *execContext, test xdm.NodeTest, node xdm.Node) []xdm.Node {
	var siblings []xdm.Node

	parent := node.Parent()
	if parent == nil {
		// No parent means we can only check the node itself
		return []xdm.Node{node}
	}

	if node.Type() == xdm.NamespaceNode {
		return collectMatchingNamespaceNodes(ctx, ec, test, node, parent)
	}

	// For attribute nodes, iterate the element's attributes instead of children
	if node.Type() == xdm.AttributeNode {
		if elem, ok := parent.(*xdm.Element); ok {
			for _, attr := range elem.Attributes() {
				if nodeMatchesTest(ctx, ec, test, attr) {
					siblings = append(siblings, attr)
				}
			}

			return siblings
		}
	}

	// Iterate through the XDM children of the parent: a DOCTYPE or an entity
	// reference is not a sibling, so it takes no position.
	for child := range xdm.Children(parent) {
		if xdm.IsXDMChild(child) && nodeMatchesTest(ctx, ec, test, child) {
			siblings = append(siblings, child)
		}
	}

	return siblings
}

// collectMatchingNamespaceNodes collects the namespace nodes of parent that
// match the given node test, in the order the xpath namespace axis returns
// them, so a positional predicate in a pattern counts the same positions as
// parent/namespace::*[...] in a select expression. The namespace axis builds
// fresh wrapper nodes on every traversal, so the wrapper with node's prefix is
// replaced by node itself: callers find node's position by pointer identity.
// A cancelled context ends the collection with no nodes, so nothing matches.
func collectMatchingNamespaceNodes(ctx context.Context, ec *execContext, test xdm.NodeTest, node, parent xdm.Node) []xdm.Node {
	nsNodes, err := xdm.TraverseAxisSimple(ctx, xdm.AxisNamespace, parent)
	if err != nil {
		return nil
	}

	matching := nsNodes[:0]
	for _, ns := range nsNodes {
		if ns.Name() == node.Name() {
			ns = node
		}

		if nodeMatchesTest(ctx, ec, test, ns) {
			matching = append(matching, ns)
		}
	}

	return matching
}

// matchFocusFreePredicates decides a step's predicates from node alone when
// that is possible. XSLT 3.0 §5.5.3 defines a pattern step's predicates by
// filtering the nodes the step selects, so a predicate can see the node's
// position among them; but a focus-free predicate (patternPredicate.focusFree)
// whose value is not a number has the same truth value at every position. Each
// predicate is evaluated in order with node as the context item; the first one
// that is not focus-free, or that yields a number (a position test), makes the
// outcome predicatesNeedPosition. A false predicate fails the match whatever
// the later ones are, because a node it rejects is not among the nodes the
// later predicates filter. An evaluation error fails the match, as it does on
// the positional path.
func matchFocusFreePredicates(ctx context.Context, ec *execContext, preds []xpath.Expr, node xdm.Node) predicateOutcome {
	for i := range preds {
		pred, ok := ec.patternPredicates[&preds[i]]
		if !ok || !pred.focusFree {
			return predicatesNeedPosition
		}

		result, err := evalStepPredicate(ctx, ec, pred.compiled, node, 1, 1)
		if err != nil {
			recordPatternPredicateError(ec, err)
			return predicatesFail
		}

		if _, isNum := result.IsNumber(); isNum {
			return predicatesNeedPosition
		}

		b, err := result.EBV()
		if err != nil || !b {
			return predicatesFail
		}
	}

	return predicatesMatch
}

// evalStepPredicate evaluates a pattern step predicate with node as the
// context item and the given context position and size, in XPath 1.0
// compatibility mode when the pattern is backwards-compatible.
func evalStepPredicate(ctx context.Context, ec *execContext, compiled *xpath.Expression, node xdm.Node, pos, size int) (*xpath.Result, error) {
	eval := ec.xpathEvaluator(ctx).
		Position(pos).
		Size(size)
	if ec.patternCompat {
		eval = eval.XPath10Compat()
	}

	return eval.Evaluate(ec.xpathContext(ctx), compiled, node)
}

// recordPatternPredicateError propagates the fatal errors among a predicate's
// evaluation errors (like XTDE0640 circular key or ErrCircularRef from
// variable/param evaluation) through the exec context so they can be raised
// after pattern matching. Every other error only makes the predicate false.
func recordPatternPredicateError(ec *execContext, err error) {
	if isXSLTError(err, errCodeXTDE0640) {
		ec.patternMatchErr = err
		return
	}

	if errors.Is(err, ErrCircularRef) {
		ec.patternMatchErr = dynamicError(errCodeXTDE0640, "%s", err.Error())
	}
}

// evaluatePredicateWithPosition evaluates a compiled pattern predicate with
// explicit position and size context.
func evaluatePredicateWithPosition(ctx context.Context, ec *execContext, compiled *xpath.Expression, node xdm.Node, pos, size int) bool {
	result, err := evalStepPredicate(ctx, ec, compiled, node, pos, size)
	if err != nil {
		recordPatternPredicateError(ec, err)
		return false
	}
	// Numeric predicates: compare to the provided position. Compare as float64:
	// converting f to int is undefined above the int range (2^31-1 where int is
	// 32 bits) and truncates a fraction, while position()=1.5 is never true.
	if f, ok := result.IsNumber(); ok {
		return f == float64(pos)
	}

	b, err := result.EBV()
	if err != nil {
		return false
	}

	return b
}

// matchByEvaluation matches complex patterns (e.g., id(), key(), doc()) by
// evaluating the pattern expression and checking whether the candidate node
// appears in the result sequence. It tries the candidate node as context first,
// then walks up the ancestor chain trying each ancestor as context.
func matchByEvaluation(ctx context.Context, ec *execContext, alt *patternAlt, node xdm.Node) bool {
	compiled := alt.compiled
	if compiled == nil {
		var compErr error

		compiled, compErr = xpath.NewCompiler().CompileExpr(alt.expr)
		if compErr != nil {
			return false
		}
	}

	// Try evaluating with the node itself as context first.
	// Needed for document-node patterns like (/)[doc].
	result, err := ec.evalPatternExpr(ctx, compiled, node)
	if err != nil {
		// Propagate fatal errors (like XTDE0640 circular key) through
		// the exec context so they can be raised after pattern matching.
		if isXSLTError(err, errCodeXTDE0640) {
			ec.patternMatchErr = err
			return false
		}
	}

	isNS := node.Type() == xdm.NamespaceNode
	if err == nil && sequenceHasNode(result.Sequence(), node, isNS) {
		return true
	}
	// Then try evaluating from each ancestor up to the document root.
	for ancestor := node.Parent(); ancestor != nil; ancestor = ancestor.Parent() {
		result, err := ec.evalPatternExpr(ctx, compiled, ancestor)
		if err != nil {
			if isXSLTError(err, errCodeXTDE0640) {
				ec.patternMatchErr = err
				return false
			}

			continue
		}

		if sequenceHasNode(result.Sequence(), node, isNS) {
			return true
		}
	}

	return false
}

// sequenceHasNode reports whether seq contains node. isNS tells whether node
// is a namespace node: the namespace axis builds a fresh wrapper on every
// traversal, so a namespace node in seq is a different Go value than node and
// is compared by its parent element and prefix (xdm.SameNode). Every other
// node is compared by pointer.
func sequenceHasNode(seq xdm.Sequence, node xdm.Node, isNS bool) bool {
	for item := range xdm.SequenceItems(seq) {
		ni, ok := item.(xdm.NodeItem)
		if !ok {
			continue
		}

		if ni.Node == node || (isNS && xdm.SameNode(ni.Node, node)) {
			return true
		}
	}

	return false
}

// matchPatternItem tests whether an arbitrary item (node or atomic value)
// matches the pattern. For node items it delegates to matchPattern; for atomic
// values it evaluates the pattern expression with the item as context and
// checks whether it produces a non-empty result. This is needed for
// group-starting-with / group-ending-with over non-node sequences (XSLT 3.0).
func (p *pattern) matchPatternItem(ctx context.Context, ec *execContext, item xdm.Item) bool {
	if ni, ok := item.(xdm.NodeItem); ok {
		// A positional predicate over the context item, e.g. ".[position()=3]",
		// must see the focus of the population being grouped (position/size set
		// by the caller in ec.position/ec.size), not the document-order focus
		// that matchPattern re-establishes for the node. This mirrors the atomic
		// branch below (ENG-005): evaluate each predicate directly with the node
		// as context item and the population focus already in scope.
		if p.matchNodeContextItemPositional(ctx, ec, ni.Node) {
			return true
		}

		return p.matchPattern(ctx, ec, ni.Node)
	}

	// Atomic item: evaluate each alternative's expression with the item as
	// context. A FilterExpr like .[pred] returns the item when pred is true.
	saved := ec.xpathDefaultNS
	savedHas := ec.hasXPathDefaultNS
	savedGroups := ec.regexGroups
	savedItem := ec.contextItem
	savedInPattern := ec.inPatternMatch
	savedPatternNS := ec.patternNamespaces
	savedPatternCompat := ec.patternCompat
	savedPatternPreds := ec.patternPredicates
	ec.xpathDefaultNS = p.xpathDefaultNS
	ec.hasXPathDefaultNS = p.hasXPathDefaultNS
	ec.regexGroups = nil
	ec.contextItem = item
	ec.inPatternMatch = true
	ec.patternNamespaces = p.nsBindings
	ec.patternCompat = p.compat

	ec.patternPredicates = p.predicates
	defer func() {
		ec.xpathDefaultNS = saved
		ec.hasXPathDefaultNS = savedHas
		ec.regexGroups = savedGroups
		ec.contextItem = savedItem
		ec.inPatternMatch = savedInPattern
		ec.patternNamespaces = savedPatternNS
		ec.patternCompat = savedPatternCompat
		ec.patternPredicates = savedPatternPreds
	}()

	for _, alt := range p.Alternatives {
		// variable reference patterns (e.g., match="$var") only match nodes,
		// never atomic items. Per XSLT 3.0 §5.5.3, the semantics require
		// root(N)//(V) which is undefined for non-node items.
		if _, isVar := alt.expr.(xpath.VariableExpr); isVar {
			continue
		}

		// A positional predicate over the context item, e.g. ".[position()=3]",
		// must see the focus of the population sequence (position/size set by
		// the caller in ec.position/ec.size), not a re-based filter focus.
		// Evaluating the whole FilterExpr would re-bind position() to 1 because
		// "." is a singleton; instead evaluate each predicate directly with the
		// item as context item and the population focus already in scope.
		if fe, ok := alt.expr.(xpath.FilterExpr); ok {
			if _, isCtxItem := fe.Expr.(xpath.ContextItemExpr); isCtxItem {
				if ec.matchContextItemPredicates(ctx, fe.Predicates) {
					return true
				}

				continue
			}
		}

		compiled, compErr := xpath.NewCompiler().CompileExpr(alt.expr)
		if compErr != nil {
			continue
		}

		result, err := ec.evalPatternExpr(ctx, compiled, nil)
		if err != nil {
			continue
		}

		seq := result.Sequence()
		if seq != nil && xdm.SequenceLen(seq) > 0 {
			return true
		}
	}

	return false
}

// matchNodeContextItemPositional handles ".[pred]" pattern alternatives for a
// node item during for-each-group boundary evaluation. It evaluates each such
// alternative's predicates with the node as the context item and the population
// focus (ec.position/ec.size) already in scope, so that positional predicates
// like position()=3 are tested against the node's position within the population
// being grouped, and never its document-order position. It returns true only
// when a ".[pred]" alternative matches; non-".[pred]" alternatives are left for
// the caller to handle via matchPattern.
func (p *pattern) matchNodeContextItemPositional(ctx context.Context, ec *execContext, node xdm.Node) bool {
	var ctxAlts []xpath.FilterExpr

	for _, alt := range p.Alternatives {
		fe, ok := alt.expr.(xpath.FilterExpr)
		if !ok {
			continue
		}

		if _, isCtxItem := fe.Expr.(xpath.ContextItemExpr); !isCtxItem {
			continue
		}

		ctxAlts = append(ctxAlts, fe)
	}

	if len(ctxAlts) == 0 {
		return false
	}

	saved := ec.xpathDefaultNS
	savedHas := ec.hasXPathDefaultNS
	savedGroups := ec.regexGroups
	savedContext := ec.contextNode
	savedCurrent := ec.currentNode
	savedItem := ec.contextItem
	savedInPattern := ec.inPatternMatch
	savedPatternNS := ec.patternNamespaces
	savedPatternCompat := ec.patternCompat
	savedPatternPreds := ec.patternPredicates
	ec.xpathDefaultNS = p.xpathDefaultNS
	ec.hasXPathDefaultNS = p.hasXPathDefaultNS
	ec.regexGroups = nil
	ec.contextNode = node
	ec.currentNode = node
	ec.contextItem = xdm.NodeItem{Node: node}
	ec.inPatternMatch = true
	ec.patternNamespaces = p.nsBindings
	ec.patternCompat = p.compat

	ec.patternPredicates = p.predicates
	defer func() {
		ec.xpathDefaultNS = saved
		ec.hasXPathDefaultNS = savedHas
		ec.regexGroups = savedGroups
		ec.contextNode = savedContext
		ec.currentNode = savedCurrent
		ec.contextItem = savedItem
		ec.inPatternMatch = savedInPattern
		ec.patternNamespaces = savedPatternNS
		ec.patternCompat = savedPatternCompat
		ec.patternPredicates = savedPatternPreds
	}()

	for _, fe := range ctxAlts {
		if ec.matchContextItemPredicates(ctx, fe.Predicates) {
			return true
		}
	}

	return false
}

// matchesAttributes returns true if the pattern source could potentially match
// attribute nodes. This is a conservative heuristic used by key table building
// to decide whether to visit attribute nodes during the document walk.
func (p *pattern) matchesAttributes() bool {
	return strings.Contains(p.source, "@") || strings.Contains(p.source, "attribute")
}

// matchesNamespaceNodes reports whether the pattern could match a namespace
// node. A namespace node is only ever selected structurally by a step on the
// namespace axis (nodeMatchesStep rejects it on every other axis), so a pattern
// whose alternatives are all paths ending on another axis can never match one.
// Every other alternative form — "." and ".[p]", a variable or function-call
// pattern matched by evaluating the expression — is treated as though it could.
// Key table building uses this to decide whether to enumerate in-scope
// namespace nodes during the document walk.
func (p *pattern) matchesNamespaceNodes() bool {
	for _, alt := range p.Alternatives {
		// Skipping a neverMatches alternative cannot lose a namespace node:
		// matchPatternAlt returns false for every node under that same flag,
		// and key table building matches only through that path. An
		// alternative skipped here therefore selects nothing anywhere, so this
		// skip is exactly the matcher's.
		if alt.neverMatches {
			continue
		}

		if exprMatchesNamespaceNodes(alt.expr) {
			return true
		}
	}

	return false
}

// exprMatchesNamespaceNodes is the structural half of matchesNamespaceNodes.
// It must stay in sync with nodeMatchesStep's namespace-axis check: see the
// comment there.
func exprMatchesNamespaceNodes(expr xpath.Expr) bool {
	switch e := expr.(type) {
	case xpath.LocationPath:
		return locationPathMatchesNamespaceNodes(e)
	case *xpath.LocationPath:
		return locationPathMatchesNamespaceNodes(*e)
	case xpath.RootExpr, *xpath.RootExpr:
		return false
	case xpath.UnionExpr:
		return exprMatchesNamespaceNodes(e.Left) || exprMatchesNamespaceNodes(e.Right)
	case xpath.PathStepExpr:
		// Only the right-hand part is tested against the candidate node; the
		// left part is matched against its ancestors.
		return exprMatchesNamespaceNodes(e.Right)
	default:
		return true
	}
}

func locationPathMatchesNamespaceNodes(path xpath.LocationPath) bool {
	if len(path.Steps) == 0 {
		// "/" matches the document node only.
		return false
	}

	return path.Steps[len(path.Steps)-1].Axis == xpath.AxisNamespace
}

// patternPredicate is one step predicate of a match pattern, compiled once
// when the pattern is compiled.
type patternPredicate struct {
	compiled *xpath.Expression
	// focusFree is true when the predicate calls none of fn:position, fn:last
	// and fn:function-lookup (matched by local name alone, in any namespace).
	// Its value for a node then does not depend on the node's position among
	// the nodes the step selects, so unless the value is a number (a position
	// test) the predicate can be decided from the node alone (XSLT 3.0
	// §5.5.3).
	focusFree bool
}

// patternPredicateCollector compiles the step predicates of a pattern's
// location paths for compilePattern.
type patternPredicateCollector struct {
	version    int
	nsBindings map[string]string
	predicates map[*xpath.Expr]*patternPredicate
}

// visit is the xpathstream.WalkExpr callback. It records the predicates of
// every step of a location path and does not descend into them: a path nested
// inside a predicate is evaluated as an expression, never matched step by
// step.
func (c *patternPredicateCollector) visit(expr xpath.Expr) bool {
	lp, ok := expr.(xpath.LocationPath)
	if !ok {
		return true
	}

	for i := range lp.Steps {
		for j := range lp.Steps[i].Predicates {
			c.add(&lp.Steps[i].Predicates[j])
		}
	}

	return false
}

func (c *patternPredicateCollector) add(pred *xpath.Expr) {
	compiled, err := xpath.NewCompiler().Language(c.version, c.nsBindings).CompileExpr(*pred)
	if err != nil {
		// Leave it out: matching compiles it on use and treats a failure as
		// a non-match, as it does for any predicate not found here.
		return
	}

	if c.predicates == nil {
		c.predicates = make(map[*xpath.Expr]*patternPredicate)
	}

	c.predicates[pred] = &patternPredicate{
		compiled:  compiled,
		focusFree: isFocusFreePredicate(compiled, c.nsBindings),
	}
}

// isFocusFreePredicate reports whether a predicate's value is independent of
// the context position and size. Only fn:position and fn:last read them, and
// fn:function-lookup can return either one as a function item bound to the
// current focus. The names are matched on their local part alone, so a
// same-named function in another namespace also counts as focus-dependent.
func isFocusFreePredicate(compiled *xpath.Expression, nsBindings map[string]string) bool {
	for _, fn := range compiled.StaticReferences(nsBindings).FunctionNames {
		switch fn.Name {
		case "position", "last", "function-lookup":
			return false
		}
	}

	return true
}

// patternAlt is one alternative in a union pattern (separated by |).
type patternAlt struct {
	expr         xpath.Expr        // the parsed XPath AST
	compiled     *xpath.Expression // cached compiled expression for runtime matching
	priority     float64
	neverMatches bool // true for syntactically valid but semantically empty patterns (e.g., child::document-node())
}

// compilePattern compiles an XSLT match pattern string.
// XSLT patterns are a restricted subset of XPath expressions.
//
// The pattern's namespace context is captured as a LEXICAL snapshot of the
// xmlns declarations in scope at elem's position (elem and its ancestors), not
// from the mutable compiler-global nsBindings map. The compiler-global map is
// polluted in document order by every top-level declaration's namespaces (see
// collectNamespaces), so an unrelated earlier xmlns:math="urn:custom" would
// otherwise leak into a later pattern that has no local xmlns:math. Snapshotting
// the element's own in-scope namespaces gives each pattern exactly its lexical
// context, so both compile-time validation and runtime matching resolve prefixes
// identically and the predeclared XPath namespaces (fn/math/map/...) apply as a
// fallback only when a prefix is not lexically bound.
//
// Patterns whose elements have the same in-scope namespaces share one
// namespace map (see internPatternNamespaces). The pattern is compiled under
// backwards-compatible processing when the compiler's effective version is
// below 2.0.
func (c *compiler) compilePattern(s string, elem *xdm.Element, xpathDefaultNS string, hasXPathDefaultNS bool) (*pattern, error) {
	nsBindings := c.internPatternNamespaces(inScopeNamespaces(elem))

	collation, err := c.declarationDefaultCollation(elem)
	if err != nil {
		return nil, err
	}

	compat := c.backwardsCompatible()
	decls := c.schemaDeclsForValidation()
	p := &pattern{source: s, xpathDefaultNS: xpathDefaultNS, hasXPathDefaultNS: hasXPathDefaultNS, nsBindings: nsBindings, compat: compat, defaultCollation: collation}

	version := c.stylesheet.xpathVersion()

	validateNS := patternValidateNamespaces(nsBindings, xpathDefaultNS, hasXPathDefaultNS)

	alts, err := xpath.SplitPatternUnion(s, version)
	if err != nil {
		return nil, patternCompilationError(c.invocation, s, err)
	}

	for _, alt := range alts {
		alt = strings.TrimSpace(alt)
		if alt == "" {
			return nil, staticError(errCodeXTSE0340, "empty pattern alternative in %q", s)
		}

		compiled, err := xpath.NewCompiler().Context(c.invocation).Language(version, nsBindings).HostFunctions(c.hostFunctionAvailable).Compile(alt)
		if err != nil {
			return nil, patternCompilationError(c.invocation, alt, err)
		}
		// Run static validation (prefix checks) against the stylesheet
		// namespace bindings. Use the same sanitized map the runtime evaluator
		// applies for pattern matching: a stylesheet xmlns="..." default
		// namespace (the "" key) must NOT become the XPath default element
		// namespace for unprefixed names unless xpath-default-namespace is set.
		// This keeps compile-time and runtime prefix resolution symmetric.
		if valErr := compiled.ValidateWithSchema(validateNS, decls); valErr != nil {
			return nil, patternCompilationError(c.invocation, alt, valErr)
		}

		if err := c.recordVariableReferences(compiled.StaticReferences(validateNS).FreeVariables, validateNS, elem, elem.LocalName() == lexicon.XSLTElementAccumulatorRule); err != nil {
			return nil, err
		}

		ast := compiled.AST()
		if err := validatePatternAlternative(compiled, alt, nsBindings, version); err != nil {
			return nil, err
		}

		if err := validatePatternExpr(ast, nsBindings); err != nil {
			return nil, staticError(errCodeXTSE0340, "invalid match pattern %q: %s", alt, err)
		}
		// XTSE3500: current-merge-key() must not be used within a pattern.
		if err := checkPatternForbiddenFunctions(ast, nsBindings); err != nil {
			return nil, err
		}

		compiledExpr, compErr := xpath.NewCompiler().CompileExpr(ast)
		if compErr != nil {
			return nil, patternCompilationError(c.invocation, alt, compErr)
		}

		pa := &patternAlt{
			expr:         ast,
			compiled:     compiledExpr,
			priority:     computeDefaultPriority(ast),
			neverMatches: isNeverMatchingPattern(alt),
		}
		p.Alternatives = append(p.Alternatives, pa)
	}

	collector := patternPredicateCollector{nsBindings: nsBindings, version: version}
	for _, pa := range p.Alternatives {
		xpathstream.WalkExpr(pa.expr, collector.visit)
	}

	p.predicates = collector.predicates
	// Union patterns (multiple alternatives separated by |) require each
	// alternative to be a PathPattern. PredicatePatterns (FilterExpr like
	// .[pred]) are only valid as standalone patterns, not in unions.
	// Note: FilterExpr wrapping a parenthesized node test with predicates
	// (e.g. (* except xsl:*)[@attr]) is valid in a union.
	if len(p.Alternatives) > 1 {
		for _, pa := range p.Alternatives {
			if isContextPredicatePattern(pa.expr) {
				return nil, staticError(errCodeXTSE0340,
					"invalid match pattern %q: predicate pattern not allowed in union", s)
			}
		}
	}

	return p, nil
}

func patternCompilationError(ctx context.Context, source string, cause error) error {
	if failure := preserveControlFailure(ctx, cause); failure != nil {
		return failure
	}

	return staticErrorCause(errCodeXTSE0340, cause, "invalid pattern %q: %v", source, cause)
}

// isNeverMatchingPattern detects patterns that are syntactically valid but
// semantically can never match any node. For example, child::document-node()
// never matches because document nodes cannot be children; similarly,
// child::attribute() never matches because attributes are not children.
func isNeverMatchingPattern(alt string) bool {
	// NOTE: this is a heuristic based on source text, not AST analysis.
	// It may miss patterns with unusual whitespace around "::" but is
	// safe in the false-negative direction (worst case: we compile a
	// pattern that never matches at runtime).
	s := strings.TrimSpace(alt)
	// child::document-node() — document nodes are never children
	if strings.HasPrefix(s, "child::document-node") || strings.Contains(s, "/child::document-node") {
		return true
	}
	// child::attribute() / child::schema-attribute() — attributes are never children
	if strings.HasPrefix(s, "child::attribute") || strings.Contains(s, "/child::attribute") ||
		strings.HasPrefix(s, "child::schema-attribute") || strings.Contains(s, "/child::schema-attribute") {
		return true
	}
	// child::namespace-node() — namespace nodes are never children
	if strings.HasPrefix(s, "child::namespace-node") || strings.Contains(s, "/child::namespace-node") {
		return true
	}

	return false
}

func validatePatternAlternative(compiled *xpath.Expression, alt string, nsBindings map[string]string, version int) error {
	ast := compiled.AST()
	if version == 20 {
		if err := checkPattern20(ast); err != nil {
			return err
		}
	}

	if version == 10 {
		if len(compiled.StaticReferences(nsBindings).FreeVariables) > 0 {
			return staticError("XTSE0340", "variables are unavailable in XSLT 1.0 patterns")
		}

		if err := checkPattern10(ast); err != nil {
			return err
		}
	}
	// Parenthesized predicate patterns are not allowed: (.[pred]).
	// XPath comments (:...:) start with "(" but are not parentheses.
	trimmedAlt := strings.TrimSpace(alt)
	if strings.HasPrefix(trimmedAlt, "(") && !strings.HasPrefix(trimmedAlt, "(:") &&
		strings.HasSuffix(trimmedAlt, ")") && isContextPredicatePattern(ast) {
		return staticError(errCodeXTSE0340, "invalid match pattern %q: parenthesized predicate pattern not allowed", alt)
	}

	return nil
}

func checkPattern20(expr xpath.Expr) error {
	switch e := expr.(type) {
	case *xpath.LocationPath:
		return checkPattern20(*e)
	case xpath.LocationPath, xpath.RootExpr, *xpath.RootExpr:
		return nil
	case xpath.PathExpr:
		if err := checkPattern20(e.Filter); err != nil {
			return err
		}

		if e.Path != nil {
			return checkPattern20(*e.Path)
		}

		return nil
	case *xpath.PathExpr:
		return checkPattern20(*e)
	case xpath.FunctionCall:
		return checkPatternFunction20(e)
	case *xpath.FunctionCall:
		return checkPatternFunction20(*e)
	}

	return staticError(errCodeXTSE0340, "invalid XSLT 2.0 match pattern")
}

func checkPatternFunction20(call xpath.FunctionCall) error {
	if call.Prefix != "" || call.Name != "id" && call.Name != nameKey2 {
		return staticError(errCodeXTSE0340, "only unprefixed id/key calls can start an XSLT 2.0 pattern")
	}

	argument := 0

	if call.Name == nameKey2 {
		if len(call.Args) != 2 {
			return staticError(errCodeXTSE0340, "key pattern requires two arguments")
		}

		literal, ok := call.Args[0].(xpath.LiteralExpr)
		if !ok {
			return staticError(errCodeXTSE0340, "key pattern name must be a string literal")
		}

		if _, ok := literal.Value.(string); !ok {
			return staticError(errCodeXTSE0340, "key pattern name must be a string literal")
		}

		argument = 1
	} else if len(call.Args) != 1 {
		return staticError(errCodeXTSE0340, "id pattern requires one argument")
	}

	switch value := call.Args[argument].(type) {
	case xpath.VariableExpr:
		return nil
	case xpath.LiteralExpr:
		if call.Name == nameKey2 {
			return nil
		}

		if _, ok := value.Value.(string); ok {
			return nil
		}
	}

	return staticError(errCodeXTSE0340, "id/key pattern value must be a literal or variable")
}

func isContextPredicatePattern(expr xpath.Expr) bool {
	fe, ok := expr.(xpath.FilterExpr)
	if !ok {
		return false
	}

	_, isCtx := fe.Expr.(xpath.ContextItemExpr)

	return isCtx
}

// patternValidateNamespaces builds the prefix→URI map used to statically
// validate a pattern. It mirrors the runtime evaluator overlay: only non-empty
// prefixes from the lexical snapshot are kept, and the "" (default element
// namespace) binding is applied only when xpath-default-namespace is declared.
// An XML default namespace (xmlns="...") must not govern unprefixed pattern
// names; they default to no-namespace.
func patternValidateNamespaces(nsBindings map[string]string, xpathDefaultNS string, hasXPathDefaultNS bool) map[string]string {
	ns := make(map[string]string, len(nsBindings)+1)
	for prefix, uri := range nsBindings {
		if prefix == "" {
			continue
		}

		ns[prefix] = uri
	}
	// Only an explicitly declared xpath-default-namespace governs unprefixed
	// names. A non-empty value sets the default element namespace; an explicit
	// "" (hasXPathDefaultNS true, empty value) resets to no-namespace, so no ""
	// binding is added.
	if hasXPathDefaultNS && xpathDefaultNS != "" {
		ns[""] = xpathDefaultNS
	}

	return ns
}

// validatePatternExpr validates that a parsed XPath expression is a valid
// XSLT match pattern. XSLT patterns are a restricted subset of XPath —
// certain constructs like variable references, arbitrary function calls,
// and parenthesized union expressions are not allowed.
func validatePatternExpr(expr xpath.Expr, nsBindings map[string]string) error {
	return validatePatternExprInner(expr, true, nsBindings)
}

func validatePatternExprInner(expr xpath.Expr, _ bool, nsBindings map[string]string) error {
	switch e := expr.(type) {
	case xpath.LocationPath, *xpath.LocationPath:
		// LocationPath patterns are valid (e.g., a/b/c, //x, /)
		return validateLocationPathPattern(expr)
	case xpath.RootExpr, *xpath.RootExpr:
		// "/" is valid
		return nil
	case xpath.ContextItemExpr:
		// "." is valid
		return nil
	case xpath.FilterExpr:
		// FilterExpr: a primary expression with predicates.
		// XSLT 3.0 allows various filter patterns:
		//   .[pred], (/)[pred], $var[pred], (union)[pred], etc.
		switch fexpr := e.Expr.(type) {
		case xpath.ContextItemExpr:
			return nil // .[pred]
		case xpath.RootExpr:
			return nil // (/)[pred]
		case xpath.VariableExpr:
			return nil // $var[pred]
		case xpath.UnionExpr:
			return nil // (a|b)[pred]
		case xpath.IntersectExceptExpr:
			return nil // (a except b)[pred]
		case xpath.FunctionCall:
			// fn()[pred] — e.g., root()[self::A]. Only the fn-namespace
			// pattern-start functions (key/id/idref/doc/element-with-id/root)
			// qualify; a custom-namespace call like c:key('x')[true()] or
			// Q{urn:custom}key('x')[true()] must be rejected, mirroring the
			// bare-FunctionCall and path-start checks routed through
			// isAllowedPatternFunction.
			if isAllowedPatternFunction(fexpr, nsBindings) {
				return nil
			}

			return fmt.Errorf("function call %s() not allowed in pattern", fexpr.Name)
		case xpath.LocationPath:
			return nil // (path)[pred]
		case *xpath.LocationPath:
			lp := e.Expr.(*xpath.LocationPath) //nolint:forcetypeassert
			if lp.Absolute && len(lp.Steps) == 0 {
				return nil // (/)[pred]
			}

			return nil // (path)[pred]
		}

		return fmt.Errorf("filter expression not allowed in pattern")
	case xpath.PathExpr:
		// PathExpr: filter/step. Check the filter part is valid.
		return validatePatternPathExpr(e, nsBindings)
	case xpath.PathStepExpr:
		// E1/E2 or E1//E2 where E2 is a non-axis expression
		return validatePatternPathStepExpr(e, nsBindings)
	case xpath.VariableExpr:
		// variable references are allowed in XSLT 3.0 patterns
		return nil
	case xpath.FunctionCall:
		// Function calls: key(), id(), doc() with literal args are allowed
		if isAllowedPatternFunction(e, nsBindings) {
			return nil
		}

		return fmt.Errorf("function call %s() not allowed in pattern", e.Name)
	case xpath.UnionExpr:
		// Union inside a pattern: valid in XSLT 3.0 as operands of
		// intersect/except or inside parenthesized path steps
		return nil
	case xpath.IntersectExceptExpr:
		// intersect/except are valid pattern operators in XSLT 3.0
		if err := validatePatternExprInner(e.Left, false, nsBindings); err != nil {
			return err
		}

		return validatePatternExprInner(e.Right, false, nsBindings)
	case xpath.BinaryExpr:
		// Binary expressions like "and union or" parse as operator expressions
		return fmt.Errorf("binary operator not allowed in pattern")
	default:
		return fmt.Errorf("expression type %T not allowed in pattern", expr)
	}
}

func validateLocationPathPattern(expr xpath.Expr) error {
	var steps []xpath.Step

	switch e := expr.(type) {
	case xpath.LocationPath:
		steps = e.Steps
	case *xpath.LocationPath:
		steps = e.Steps
	}

	for _, step := range steps {
		// XTSE0340: reverse axes (parent, ancestor, preceding,
		// preceding-sibling, ancestor-or-self) are not allowed in match
		// patterns. Forward axes are allowed in XSLT 3.0.
		switch step.Axis {
		case xpath.AxisParent, xpath.AxisAncestor, xpath.AxisAncestorOrSelf,
			xpath.AxisPreceding, xpath.AxisPrecedingSibling:
			return fmt.Errorf("axis %v not allowed in match pattern", step.Axis)
		}

		for _, pred := range step.Predicates {
			if err := validatePredicateExpr(pred); err != nil {
				return err
			}
		}
	}

	return nil
}

func validatePatternPathExpr(e xpath.PathExpr, nsBindings map[string]string) error {
	// The filter part: only ContextItemExpr, RootExpr, or FunctionCall (key/id/doc)
	switch f := e.Filter.(type) {
	case xpath.ContextItemExpr:
		// .[pred]/steps is valid
	case xpath.RootExpr, *xpath.RootExpr:
		// /steps is valid
	case xpath.FunctionCall:
		// Only certain functions at the start of a path pattern
		if !isAllowedPatternFunction(f, nsBindings) {
			return fmt.Errorf("function call %s() not allowed at start of path pattern", f.Name)
		}
	case xpath.FilterExpr:
		// FilterExpr at the start of a path
		return validatePatternExprInner(f, false, nsBindings)
	case xpath.VariableExpr:
		// variable references are allowed in XSLT 3.0 patterns
	case xpath.PathStepExpr:
		// Nested path step (e.g., x/(a|b)/text())
		return validatePatternPathStepExpr(f, nsBindings)
	case *xpath.PathStepExpr:
		return validatePatternPathStepExpr(*f, nsBindings)
	default:
		return fmt.Errorf("expression type %T not allowed at start of path pattern", e.Filter)
	}

	return nil
}

func validatePatternPathStepExpr(e xpath.PathStepExpr, nsBindings map[string]string) error {
	switch l := e.Left.(type) {
	case xpath.VariableExpr:
		// variable references are allowed in XSLT 3.0 patterns
	case xpath.FunctionCall:
		if !isAllowedPatternFunction(l, nsBindings) {
			return fmt.Errorf("function call %s() not allowed in pattern", l.Name)
		}
	case xpath.PathExpr:
		if err := validatePatternPathExpr(l, nsBindings); err != nil {
			return err
		}
	case xpath.PathStepExpr:
		if err := validatePatternPathStepExpr(l, nsBindings); err != nil {
			return err
		}
	}
	// Check right side: must be a valid step (axis step / node test), not
	// an arbitrary expression like a numeric literal.
	if !isValidPatternStep(e.Right) {
		return fmt.Errorf("expression %T not allowed as step in pattern", e.Right)
	}

	switch r := e.Right.(type) {
	case xpath.VariableExpr:
		// variable references are allowed in XSLT 3.0 patterns
	case xpath.FunctionCall:
		return fmt.Errorf("function call %s() not allowed in middle of pattern", r.Name)
	case xpath.FilterExpr:
		// A filtered primary as a non-leading step, e.g. a/key('x')[pred] or
		// a/c:key('x')[pred]. Pattern-start functions may appear only at the
		// START of a pattern, so a function-call primary here is rejected just
		// like the bare mid-pattern function call above — otherwise the
		// predicate wrapper would smuggle a forbidden/custom function past the
		// isAllowedPatternFunction gate. Other filtered primaries (a
		// parenthesized union/path with a predicate such as a/(b|c)[1]) remain
		// valid and need no further checking here.
		if fc, ok := r.Expr.(xpath.FunctionCall); ok {
			return fmt.Errorf("function call %s() not allowed in middle of pattern", fc.Name)
		}
	case xpath.ArrayConstructorExpr:
		return fmt.Errorf("array constructor not allowed in pattern")
	}

	return nil
}

// isValidPatternStep checks whether an expression is valid as a step in a
// match pattern (i.e., an axis step or node test, not a literal or arbitrary expr).
func isValidPatternStep(expr xpath.Expr) bool {
	switch expr.(type) {
	case xpath.LocationPath, *xpath.LocationPath:
		return true
	case xpath.FilterExpr:
		return true
	case xpath.ContextItemExpr:
		return true
	case xpath.VariableExpr:
		return true
	case xpath.FunctionCall:
		return true
	case xpath.UnionExpr:
		return true
	case xpath.IntersectExceptExpr:
		return true
	}

	return false
}

// isAllowedPatternFunction returns true if a function call is allowed at the
// start of a path pattern. In XSLT 3.0, key(), id(), and doc() are allowed
// with literal arguments. Only the built-in functions in the XPath functions
// namespace qualify: an allowlisted local name in any OTHER namespace (e.g. a
// user-declared Q{urn:custom}key()) is NOT an allowed pattern-start function,
// so the namespace URI must be the functions namespace before the local-name
// switch is consulted.
func isAllowedPatternFunction(fc xpath.FunctionCall, nsBindings map[string]string) bool {
	// Resolve the call's (namespace URI, local name) honoring the EQName braced
	// form, explicit xmlns bindings, and the predeclared fn: default. A function
	// outside the functions namespace can never be a built-in pattern function,
	// regardless of its local name.
	uri, local := patternFunctionIdentity(fc, nsBindings)
	if uri != lexicon.NamespaceFn {
		return false
	}

	switch local {
	case nameKey2, "id", "idref", nameDoc, "element-with-id", "root":
		for _, arg := range fc.Args {
			if !isPatternFunctionArg(arg) {
				return false
			}
		}

		return true
	}

	return false
}

// isPatternFunctionArg returns true if an expression is a valid argument
// to a function in a pattern (must be a literal or variable reference).
func isPatternFunctionArg(expr xpath.Expr) bool {
	switch expr.(type) {
	case xpath.LiteralExpr:
		return true
	case xpath.VariableExpr:
		return true
	}

	return false
}

// validatePredicateExpr validates expressions used inside predicates.
// Predicates in patterns can contain arbitrary XPath expressions.
func validatePredicateExpr(_ xpath.Expr) error {
	// Predicates can contain any valid XPath expression,
	// so no additional validation needed beyond function checks
	// (which are handled separately by validatePatternFunctions).
	return nil
}

// checkPatternForbiddenFunctions checks that a pattern AST does not
// contain calls to functions forbidden in patterns per XSLT 3.0.
// XTSE3500: current-merge-key() must not be used within a pattern.
// XTSE3470: current-merge-group() must not be used within a pattern.
// XTSE1060: current-group()/current-grouping-key() must not be used within a pattern.
func checkPatternForbiddenFunctions(ast xpath.Expr, nsBindings map[string]string) error {
	var walkErr error

	xpathstream.WalkExpr(ast, func(e xpath.Expr) bool {
		if walkErr != nil {
			return false
		}

		fc, ok := e.(xpath.FunctionCall)
		if !ok {
			return true
		}
		// The forbidden list applies only to the XSLT/XPath functions
		// namespace. Resolve identity the same way function existence is
		// resolved (braced EQName URI first, then explicit bindings, then
		// predeclared as fallback) so an explicit xmlns:fn override pointing
		// at a custom namespace makes fn:current-group() a user function, not
		// the forbidden builtin, and the EQName spelling
		// Q{http://www.w3.org/2005/xpath-functions}current-group() is caught.
		uri, local := patternFunctionIdentity(fc, nsBindings)
		if uri != lexicon.NamespaceFn {
			return true
		}

		switch local {
		case nameCurrentMergeKey:
			walkErr = staticError(errCodeXTSE3500, "current-merge-key() must not be used within a pattern")
			return false
		case nameCurrentMergeGroup:
			walkErr = staticError(errCodeXTSE3470, "current-merge-group() must not be used within a pattern")
			return false
		case lexicon.FnCurrentGroup:
			walkErr = staticError(errCodeXTSE1060, "current-group() must not be used within a pattern")
			return false
		case lexicon.FnCurrentGroupingKey:
			walkErr = staticError(errCodeXTSE1070, "current-grouping-key() must not be used within a pattern")
			return false
		}

		return true
	})

	return walkErr
}

// computeDefaultPriority computes the default priority for a pattern
// alternative per XSLT 3.0 Section 6.5.
func computeDefaultPriority(expr xpath.Expr) float64 {
	var steps []xpath.Step

	switch e := expr.(type) {
	case xpath.LocationPath:
		steps = e.Steps
	case *xpath.LocationPath:
		steps = e.Steps
	case xpath.RootExpr, *xpath.RootExpr:
		// "/" matches document nodes; default priority is -0.5
		return -0.5
	case xpath.ContextItemExpr:
		return -1
	case xpath.IntersectExceptExpr:
		return computeDefaultPriority(e.Left)
	case xpath.UnionExpr:
		// Union pattern (a|b): priority is max of operands' priorities.
		lp := computeDefaultPriority(e.Left)

		rp := computeDefaultPriority(e.Right)
		if lp > rp {
			return lp
		}

		return rp
	case xpath.FilterExpr:
		// PredicatePattern priority is one, independently of predicate count.
		if _, ok := e.Expr.(xpath.ContextItemExpr); ok {
			return 1
		}

		return 0.5
	default:
		return 0.5
	}

	if len(steps) == 0 {
		// Absolute path with no steps is "/" — document root, priority -0.5
		if isAbsolute(expr) {
			return -0.5
		}

		return 0.5
	}
	// Per XSLT 3.0 §6.5: path patterns with multiple steps get priority 0.5.
	// An absolute path like "/doc" counts as multi-step (root + step).
	if len(steps) > 1 || (len(steps) == 1 && isAbsolute(expr)) {
		return 0.5
	}

	lastStep := steps[0]
	// A step with predicates gets priority 0.5 (more specific)
	if len(lastStep.Predicates) > 0 {
		return 0.5
	}

	return stepPriority(lastStep)
}

func isAbsolute(expr xpath.Expr) bool {
	switch e := expr.(type) {
	case xpath.LocationPath:
		return e.Absolute
	case *xpath.LocationPath:
		return e.Absolute
	}

	return false
}

func stepPriority(step xpath.Step) float64 {
	switch nt := step.NodeTest.(type) {
	case xdm.TypeTest, xdm.NamespaceNodeTest:
		// node(), text(), comment(), processing-instruction()
		return -0.5
	case xdm.PITest:
		if nt.HasTarget {
			return 0
		}

		return -0.5
	case xdm.NameTest:
		if nt.Local == "*" && nt.Prefix == "" && nt.URI == "" {
			return -0.5
		}

		if nt.Local == "*" || nt.Prefix == "*" {
			// prefix:* or *:local — one component is wildcard
			return -0.25
		}

		return 0
	case xdm.ElementTest:
		if nt.TypeName != "" {
			if nt.Name == "" || nt.Name == "*" {
				return 0 // element(*, type) — type constraint, priority 0
			}

			return 0.25 // element(name, type)
		}

		if nt.Name == "" || nt.Name == "*" {
			return -0.5 // element() or element(*)
		}

		return 0 // element(specific-name)
	case xdm.AttributeTest:
		if nt.TypeName != "" {
			if nt.Name == "" || nt.Name == "*" {
				return 0 // attribute(*, type) — type constraint, priority 0
			}

			return 0.25 // attribute(name, type)
		}

		if nt.Name == "" || nt.Name == "*" {
			return -0.5 // attribute() or attribute(*)
		}

		return 0 // attribute(specific-name)
	case xdm.DocumentTest:
		if nt.Inner == nil {
			return -0.5
		}
		// Priority of document-node(test) derives from the inner test
		return stepPriority(xpath.Step{NodeTest: nt.Inner})
	case xdm.SchemaElementTest, xdm.SchemaAttributeTest:
		return 0.25
	default:
		return 0.5
	}
}

// internPatternNamespaces returns the compiler's shared map with the same
// bindings as ns, registering ns as that map when none exists yet. Every
// pattern keeps its map for the life of the stylesheet, and the runtime caches
// one base XPath evaluator per distinct map (baseEvalKey), so sharing the map
// lets patterns with the same in-scope namespaces share that evaluator. The
// returned map is never modified.
func (c *compiler) internPatternNamespaces(ns map[string]string) map[string]string {
	prefixes := slices.Sorted(maps.Keys(ns))

	var b strings.Builder
	for _, prefix := range prefixes {
		b.WriteString(prefix)
		b.WriteByte(0)
		b.WriteString(ns[prefix])
		b.WriteByte(0)
	}

	key := b.String()
	if shared, ok := c.patternNamespaceMaps[key]; ok {
		return shared
	}

	if c.patternNamespaceMaps == nil {
		c.patternNamespaceMaps = make(map[string]map[string]string)
	}

	c.patternNamespaceMaps[key] = ns

	return ns
}

// validatePatternFunctions checks that all function calls in a pattern
// reference known functions (built-in XPath or declared xsl:function).
// Unknown functions like f:special() raise XPST0017 at compile time.
func (c *compiler) validatePatternFunctions(ctx context.Context, p *pattern, source string) error {
	for _, alt := range p.Alternatives {
		var walkErr error

		xpathstream.WalkExpr(alt.expr, func(e xpath.Expr) bool {
			if walkErr != nil {
				return false
			}

			fc, ok := e.(xpath.FunctionCall)
			if !ok {
				return true
			}
			// An unprefixed function call names the XPath functions namespace,
			// the same as the prefixed path. Resolve identity (URI + local)
			// explicitly so it gets the identical existence/arity validation
			// below — a nonexistent no-such-function() or a wrong-arity key()
			// must be rejected, not silently allowed. patternFunctionIdentity
			// also normalizes the EQName spelling Q{uri}local so it is matched
			// against the same registries as the lexical form.
			nsURI, local := patternFunctionIdentity(fc, p.nsBindings)

			displayName := local
			if fc.Prefix != "" {
				displayName = fc.Prefix + ":" + local
			}
			// Resolving the prefix to a known function namespace is not enough:
			// the function must actually exist with an acceptable arity. Confirm
			// against xpath's built-in registry (covers fn:, math:, map:, array:,
			// err: and the xs: constructor functions). An invalid call such as
			// math:no-such-function() falls through to the declared-function
			// lookup below and is rejected as XPST0017.
			if xpath.BuiltinFunctionAcceptsArity(nsURI, local, len(fc.Args)) {
				return true
			}
			// XSLT defines additional functions in the fn: namespace (key,
			// current, document, generate-id, ...). These are not XPath
			// built-ins, so consult the XSLT function registry before
			// rejecting. Functions forbidden in patterns (current-group,
			// current-merge-key, ...) are caught separately by
			// checkPatternForbiddenFunctions.
			if nsURI == lexicon.NamespaceFn && xsltFunctionAcceptsVersionArity(c.stylesheet.processorLanguage(), local, len(fc.Args)) {
				return true
			}

			qn := xpath.QualifiedName{Name: local, URI: nsURI}
			if fn := xpath.FunctionsFromContext(ctx)[qn]; fn != nil && len(fc.Args) >= fn.MinArity() && len(fc.Args) <= fn.MaxArity() {
				return true
			}

			if c.stylesheet.functions[funcKey{Name: qn, Arity: len(fc.Args)}] != nil {
				return true
			}

			walkErr = staticError(lexicon.ErrXPST0017,
				"unknown function %s() in match pattern %q", displayName, source)

			return false
		})

		if walkErr != nil {
			return walkErr
		}
	}

	return nil
}

func resolvePatternFunctionNamespace(prefix string, nsBindings map[string]string) string {
	if prefix == "" {
		return lexicon.NamespaceFn
	}

	if uri, bound := nsBindings[prefix]; bound {
		return uri
	}

	if ns, ok := xpath.PredeclaredNamespace(prefix); ok {
		return ns
	}

	return ""
}

// patternFunctionIdentity resolves a function call's (namespace URI, local name)
// for pattern validation. The xpath parseOptions keeps an EQName function call's whole
// braced spelling in fc.Name (e.g. "Q{http://www.w3.org/2005/xpath-functions}current-group"),
// so the braced URI must be read directly from the name, and never resolved
// through fc.Prefix. For the lexical (unprefixed or prefixed) form it falls back
// to resolvePatternFunctionNamespace so explicit xmlns overrides are honored.
func patternFunctionIdentity(fc xpath.FunctionCall, nsBindings map[string]string) (uri, local string) {
	if strings.HasPrefix(fc.Name, "Q{") {
		if idx := strings.IndexByte(fc.Name, '}'); idx >= 0 {
			return fc.Name[2:idx], fc.Name[idx+1:]
		}
	}

	return resolvePatternFunctionNamespace(fc.Prefix, nsBindings), fc.Name
}

// resolvePatternFunctionNamespace resolves a function-call prefix to its
// namespace URI using the same precedence everywhere in pattern validation:
// an unprefixed call names the XPath functions namespace; a prefixed call
// resolves through the EXPLICIT in-scope xmlns bindings first, falling back to
// the XPath 3.0 predeclared bindings (fn:, math:, map:, array:, err:, xs:) only
// when the prefix is otherwise undeclared. An unresolved prefix returns "".
// resolvePatternPrefix resolves a non-empty namespace prefix used inside a
// match pattern against the pattern's lexical namespace snapshot, then the
// predeclared XPath prefixes (fn:, math:, map:, ...), then the universally
// predeclared xml prefix. It returns "" when the prefix is unbound. This is the
// single shared resolution path for pattern prefixes so that compile-time checks
// (e.g. the typed="strict" XTSE3105 NameTest check) and runtime pattern matching
// (execContext.resolvePrefix during pattern matching) cannot drift.
func resolvePatternPrefix(nsBindings map[string]string, prefix string) string {
	if uri, ok := nsBindings[prefix]; ok {
		return uri
	}

	if uri, ok := xpath.PredeclaredNamespace(prefix); ok {
		return uri
	}

	if prefix == lexicon.PrefixXML {
		return lexicon.NamespaceXML
	}

	return ""
}

// matchContextItemPredicates evaluates each predicate of a ".[pred]" pattern
// with the current context item (ec.contextItem) and the population focus
// (ec.position/ec.size) already in scope. A numeric predicate is treated as a
// position test against ec.position; any other predicate uses its effective
// boolean value. All predicates must hold for a match.
func (ec *execContext) matchContextItemPredicates(ctx context.Context, preds []xpath.Expr) bool {
	for _, pred := range preds {
		compiled, compErr := xpath.NewCompiler().CompileExpr(pred)
		if compErr != nil {
			return false
		}

		result, err := ec.evalPatternExpr(ctx, compiled, nil)
		if err != nil {
			return false
		}

		seq := result.Sequence()
		if seq == nil {
			return false
		}
		// Numeric predicate: position test against the population position.
		if xdm.SequenceLen(seq) == 1 {
			if a, ok := seq.Get(0).(xdm.AtomicValue); ok && a.IsNumeric() {
				// A positional predicate matches only when the numeric
				// value equals the integer position exactly: position()=2.7
				// is never true, so ".[2.7]" must not match position 2.
				if a.ToFloat64() != float64(ec.position) {
					return false
				}

				continue
			}
		}

		ebv, err := xpath.EBV(seq)
		if err != nil || !ebv {
			return false
		}
	}

	return true
}

// patternPredicate returns the compiled form of the step predicate at pred:
// the one compilePattern built for the pattern being matched, or else a fresh
// compilation, marked as not focus-free. It returns nil when the predicate
// does not compile.
func (ec *execContext) patternPredicate(pred *xpath.Expr) *patternPredicate {
	if compiled, ok := ec.patternPredicates[pred]; ok {
		return compiled
	}

	compiled, err := xpath.NewCompiler().CompileExpr(*pred)
	if err != nil {
		return nil
	}

	return &patternPredicate{compiled: compiled}
}
