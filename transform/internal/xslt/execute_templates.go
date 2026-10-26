// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// executeTemplate executes a template with the given node as context.
const maxRecursionDepth = 2000

// conflictCandidateResult classifies one candidate template probed by
// hasConflictingMatchIn against the current best match.
type conflictCandidateResult int

const (
	conflictCandidateNone  conflictCandidateResult = iota // not a conflict; keep scanning
	conflictCandidateFound                                // a genuine conflicting match
	// conflictCandidateStop means precedence/priority dropped below best's:
	// templates are sorted, so no later candidate can conflict either.
	conflictCandidateStop
)

func (ec *execContext) applyTemplates(ctx context.Context, node xdm.Node, mode string, paramValues ...map[string]xdm.Sequence) error {
	initialCall := ec.initialTemplateCall
	ec.initialTemplateCall = false

	if normalizeNode(node) == nil {
		return nil
	}
	// Strip whitespace-only text nodes per xsl:strip-space
	if ec.shouldStripWhitespace(node) {
		return nil
	}

	ec.depth++
	if ec.depth > xpath.DepthLimit(ctx, maxRecursionDepth) {
		ec.depth--
		return xpath.ErrRecursionLimit
	}
	defer func() { ec.depth-- }()

	mode, restoreMode := ec.pushMode(mode)
	defer restoreMode()

	// Collect param values if any
	var pv map[string]xdm.Sequence
	if len(paramValues) > 0 {
		pv = paramValues[0]
	}

	// XTTE3100: typed="yes" mode rejects untyped nodes
	// XTTE3110: typed="no" mode rejects typed nodes
	if md := ec.lookupModeDef(mode); md != nil {
		switch md.Typed {
		case lexicon.ValueYes, lexicon.ValueTrue, "1", validationStrict, validationLax:
			if !ec.nodeIsTyped(node) {
				return dynamicError(errCodeXTTE3100,
					"mode %q has typed=%q but node is untyped", mode, md.Typed)
			}
		case lexicon.ValueNo, lexicon.ValueFalse, "0":
			if ec.nodeIsTyped(node) {
				return dynamicError(errCodeXTTE3110,
					"mode %q has typed=%q but node is typed", mode, md.Typed)
			}
		}
	}

	tmpl, err := ec.findBestTemplate(ctx, node, mode)
	if err != nil {
		return err
	}

	if tmpl != nil {
		if initialCall {
			if err := ec.checkInitialTemplateParameters(tmpl); err != nil {
				return err
			}
		}

		return ec.executeTemplate(ctx, tmpl, node, mode, pv)
	}

	// Use built-in template rules
	return ec.applyBuiltinRules(ctx, node, mode, paramValues...)
}

// lookupModeDef returns the modeDef for the given mode name.
// Handles the mismatch where templates use "" for the unnamed mode
// but mode definitions are stored under "#default".
func (ec *execContext) lookupModeDef(mode string) *modeDef {
	modeDefs := ec.effectiveModeDefs()
	if md := modeDefs[mode]; md != nil {
		return md
	}

	if mode == "" {
		return modeDefs[modeDefault]
	}

	return nil
}

// nodeIsTyped returns true if the node has a schema type annotation,
// or if the node belongs to a document that was schema-validated (even if
// this specific node has a complex type without an individual annotation).
func (ec *execContext) nodeIsTyped(node xdm.Node) bool {
	if ec.typeAnnotations == nil {
		return false
	}

	if _, ok := ec.typeAnnotations[node]; ok {
		return true
	}
	// Check if the node belongs to a validated document. This covers
	// complex-type elements that don't have individual annotations but
	// are still considered typed per the XDM data model.
	if len(ec.validatedDocs) > 0 {
		for cur := node; cur != nil; cur = cur.Parent() {
			if doc, ok := cur.(*xdm.Document); ok {
				if _, validated := ec.validatedDocs[doc]; validated {
					return true
				}

				break
			}
		}
	}

	return false
}

// findBestTemplate finds the highest-priority matching template for a node.
// Returns XTDE0540 when on-multiple-match="fail" and two templates match
// with equal priority and import precedence.
func (ec *execContext) findBestTemplate(ctx context.Context, node xdm.Node, mode string) (*template, error) {
	// Set currentNode to the candidate so current() works in pattern predicates
	savedCurrent := ec.currentNode

	ec.currentNode = node
	defer func() { ec.currentNode = savedCurrent }()

	best := ec.findFirstMatch(ctx, ec.activeModePackage().modeTemplates[mode], ec.activeModePackage().modeIndex[mode], node)

	// Also check #all mode templates that might not be registered in this mode
	if best == nil && mode != modeAll {
		best = ec.findFirstMatch(ctx, ec.activeModePackage().modeTemplates[modeAll], ec.activeModePackage().modeIndex[modeAll], node)
	}

	if best == nil {
		return nil, nil //nolint:nilnil
	}

	if ec.onMultipleMatchFail(mode) {
		if ec.hasConflictingMatch(ctx, node, mode, best) {
			return nil, dynamicError(errCodeXTDE0540,
				"ambiguous rule match for node %v in mode %q (on-multiple-match=fail)",
				node, mode)
		}
	}

	return best, nil
}

// findFirstMatch returns the first template in the list that matches the
// node. idx is ec.activeModePackage().modeIndex for the same mode templates was drawn
// from; when non-nil the scan visits only the positions the dispatch index
// cannot rule out (dispatch_index.go candidates), in the same ascending order
// a plain scan would find them in. idx == nil (a mode list below
// templateIndexThreshold, or one Compile never indexed) falls back to
// scanning every template.
//
// Every probe in this scan targets the SAME node, so the node-scoped
// execContext fields that matchPattern would otherwise save and restore on
// every call (contextNode, currentNode, contextItem, inPatternMatch,
// regexGroups) are set once here instead, and each template is tested via
// matchPatternProbe, which only handles the fields that vary per pattern.
func (ec *execContext) findFirstMatch(ctx context.Context, templates []*template, idx *templateIndex, node xdm.Node) *template {
	if len(templates) == 0 {
		return nil
	}

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

	if idx != nil {
		cur := candidates(idx, node)
		for {
			pos, ok := cur.next()
			if !ok {
				return nil
			}

			tmpl := templates[pos]
			if ec.matchTemplatePattern(ctx, tmpl, node, true) {
				return tmpl
			}
		}
	}

	for _, tmpl := range templates {
		if ec.matchTemplatePattern(ctx, tmpl, node, true) {
			return tmpl
		}
	}

	return nil
}

// onMultipleMatchFail returns true when the effective on-multiple-match for
// the given mode is "fail".
func (ec *execContext) onMultipleMatchFail(mode string) bool {
	modeDefs := ec.effectiveModeDefs()
	if md := modeDefs[mode]; md != nil && md.OnMultipleMatch != "" {
		return md.OnMultipleMatch == onNoMatchFail
	}
	// The unnamed default mode is stored as "#default" but referenced as ""
	if mode == "" {
		if md := modeDefs[modeDefault]; md != nil && md.OnMultipleMatch != "" {
			return md.OnMultipleMatch == onNoMatchFail
		}
	}
	// Fall back to transform-time override (e.g. from W3C test dependency)
	if ec.transformConfig != nil && ec.transformConfig.onMultipleMatch != "" {
		return ec.transformConfig.onMultipleMatch == onNoMatchFail
	}

	return false
}

// hasConflictingMatch checks whether there is another template (besides best)
// that matches the same node with equal import precedence and priority.
func (ec *execContext) hasConflictingMatch(ctx context.Context, node xdm.Node, mode string, best *template) bool {
	if ec.hasConflictingMatchIn(ctx, ec.activeModePackage().modeTemplates[mode], ec.activeModePackage().modeIndex[mode], node, best) {
		return true
	}

	if mode != modeAll {
		return ec.hasConflictingMatchIn(ctx, ec.activeModePackage().modeTemplates[modeAll], ec.activeModePackage().modeIndex[modeAll], node, best)
	}

	return false
}

// hasConflictingMatchIn scans one mode-template list for a template
// conflicting with best. idx is that same mode's dispatch index (nil falls
// back to a plain scan). The index's candidate positions are a subsequence of
// the sorted list that preserves scan order, so classifyConflictCandidate's
// precedence/priority early-break stays sound over it: every position the
// index skips is one signatureAdmits ruled out, which — by
// TestDispatchIndexSignatureSoundness — cannot match the node at all, so it
// cannot be the conflict this check is looking for.
func (ec *execContext) hasConflictingMatchIn(ctx context.Context, templates []*template, idx *templateIndex, node xdm.Node, best *template) bool {
	if len(templates) == 0 {
		return false
	}

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

	if idx != nil {
		cur := candidates(idx, node)
		for {
			pos, ok := cur.next()
			if !ok {
				return false
			}

			switch classifyConflictCandidate(ctx, ec, templates[pos], best, node) {
			case conflictCandidateFound:
				return true
			case conflictCandidateStop:
				return false
			case conflictCandidateNone:
			}
		}
	}

	for _, tmpl := range templates {
		switch classifyConflictCandidate(ctx, ec, tmpl, best, node) {
		case conflictCandidateFound:
			return true
		case conflictCandidateStop:
			return false
		case conflictCandidateNone:
		}
	}

	return false
}

// findAtomicTemplate finds a template matching an atomic value.
// XSLT 3.0 patterns like ".[. instance of xs:integer]" can match atomic items.
func (ec *execContext) findAtomicTemplate(ctx context.Context, item xdm.Item, mode string) (*template, error) {
	var best *template

	templates := ec.activeModePackage().modeTemplates[mode]
	for _, tmpl := range templates {
		if tmpl.Match != nil && ec.matchAtomicTemplate(ctx, tmpl, item) {
			best = tmpl
			break
		}
	}

	if best == nil && mode != modeAll {
		for _, tmpl := range ec.activeModePackage().modeTemplates[modeAll] {
			if tmpl.Match != nil && ec.matchAtomicTemplate(ctx, tmpl, item) {
				best = tmpl
				break
			}
		}
	}

	if best == nil {
		return nil, nil //nolint:nilnil
	}

	if ec.onMultipleMatchFail(mode) {
		if ec.hasConflictingAtomicMatch(ctx, item, mode, best) {
			return nil, dynamicError(errCodeXTDE0540,
				"ambiguous rule match for atomic item in mode %q (on-multiple-match=fail)", mode)
		}
	}

	return best, nil
}

// hasConflictingAtomicMatch checks whether there is another template (besides best)
// that matches the same atomic item with equal import precedence and priority.
func (ec *execContext) hasConflictingAtomicMatch(ctx context.Context, item xdm.Item, mode string, best *template) bool {
	check := func(templates []*template) bool {
		for _, tmpl := range templates {
			if tmpl == best {
				continue
			}

			if tmpl.ImportPrec < best.ImportPrec {
				return false
			}

			if tmpl.ImportPrec == best.ImportPrec && tmpl.Priority < best.Priority {
				return false
			}
			// Split union pattern branches share a non-zero splitOriginID; they
			// originate from the same rule and must not self-conflict.
			if tmpl.splitOriginID != nil && tmpl.splitOriginID == best.splitOriginID {
				continue
			}

			if tmpl.Match != nil && ec.matchAtomicTemplate(ctx, tmpl, item) {
				return true
			}
		}

		return false
	}
	if check(ec.activeModePackage().modeTemplates[mode]) {
		return true
	}

	if mode != modeAll {
		return check(ec.activeModePackage().modeTemplates[modeAll])
	}

	return false
}

func (ec *execContext) matchTemplatePattern(ctx context.Context, tmpl *template, node xdm.Node, probe bool) bool {
	if tmpl.Match == nil {
		return false
	}

	defer ec.pushPackage(tmpl.OwnerPackage)()

	if probe {
		return tmpl.Match.matchPatternProbe(ctx, ec, node)
	}

	return tmpl.Match.matchPattern(ctx, ec, node)
}

func (ec *execContext) matchAtomicTemplate(ctx context.Context, tmpl *template, item xdm.Item) bool {
	defer ec.pushPackage(tmpl.OwnerPackage)()

	p := tmpl.Match
	savedNS, savedDefault, savedHasDefault, savedInPattern := ec.patternNamespaces, ec.xpathDefaultNS, ec.hasXPathDefaultNS, ec.inPatternMatch

	ec.patternNamespaces, ec.xpathDefaultNS, ec.hasXPathDefaultNS, ec.inPatternMatch = p.nsBindings, p.xpathDefaultNS, p.hasXPathDefaultNS, true
	defer func() {
		ec.patternNamespaces, ec.xpathDefaultNS, ec.hasXPathDefaultNS, ec.inPatternMatch = savedNS, savedDefault, savedHasDefault, savedInPattern
	}()

	for _, alt := range p.Alternatives {
		// variable reference patterns (e.g., match="$var") only match nodes,
		// never atomic items per XSLT 3.0 §5.5.3.
		if _, isVar := alt.expr.(xpath.VariableExpr); isVar {
			continue
		}

		compiled := alt.compiled
		if compiled == nil {
			var compErr error

			compiled, compErr = xpath.NewCompiler().CompileExpr(alt.expr)
			if compErr != nil {
				continue
			}
		}
		// Evaluate the pattern as a boolean predicate with the item as context.
		// A backwards-compatible pattern evaluates in XPath 1.0 compatibility mode.
		peval := ec.xpathEvaluator(ctx).ContextItem(item)
		if p.compat {
			peval = peval.XPath10Compat()
		}

		result, err := peval.Evaluate(ec.xpathContext(ctx), compiled, nil)
		if err != nil {
			continue
		}
		// The pattern ".[. instance of xs:integer]" evaluates to the item
		// itself when matched, or empty when not. Check non-empty.
		if result.Sequence() != nil && xdm.SequenceLen(result.Sequence()) > 0 {
			return true
		}
	}

	return false
}

func (ec *execContext) executeAtomicTemplate(ctx context.Context, tmpl *template, item xdm.Item, mode string, paramOverrides ...map[string]xdm.Sequence) error {
	defer ec.pushPackage(tmpl.OwnerPackage)()

	savedContext := ec.contextNode
	savedCurrent := ec.currentNode
	savedMode := ec.currentMode
	savedItem := ec.contextItem
	savedTemplate := ec.currentTemplate
	ec.contextItem = item
	ec.contextNode = nil
	ec.currentNode = nil
	ec.currentMode = mode

	ec.setCurrentTemplate(tmpl)
	defer func() {
		ec.contextNode = savedContext
		ec.currentNode = savedCurrent
		ec.currentMode = savedMode
		ec.contextItem = savedItem
		ec.setCurrentTemplate(savedTemplate)
	}()

	ec.pushVarScope()
	defer ec.popVarScope()

	// Collect param overrides supplied by the caller (via xsl:with-param).
	var po map[string]xdm.Sequence
	if len(paramOverrides) > 0 {
		po = paramOverrides[0]
	}

	if err := ec.bindTemplateParams(ctx, tmpl.Params, po, func(p *param) (xdm.Sequence, error) {
		return ec.atomicTemplateParamDefault(ctx, p, item)
	}); err != nil {
		return err
	}

	if tmpl.As != "" {
		return ec.executeTemplateBodyWithAs(ctx, tmpl)
	}

	return ec.executeSequenceConstructor(ctx, tmpl.Body)
}

func (ec *execContext) executeTemplate(ctx context.Context, tmpl *template, node xdm.Node, mode string, paramOverrides ...map[string]xdm.Sequence) error {
	if tmpl.Visibility == visAbstract {
		return dynamicError(errCodeXTDE3052, "abstract template %q was invoked without an implementation", tmpl.Name)
	}

	// If the template belongs to a package, switch function scope
	// so package-private functions are visible.
	savedFnsNS := ec.cachedFnsNS
	savedPackage := ec.currentPackage
	// Component bodies retain the scope of the package that declares them,
	// including overriding match rules without a named original.
	if tmpl.OwnerPackage != ec.currentPackage {
		ec.cachedFnsNS = nil
		ec.currentPackage = tmpl.OwnerPackage
	}

	defer func() {
		ec.cachedFnsNS = savedFnsNS
		ec.currentPackage = savedPackage
	}()

	// Save and restore context
	savedCurrent := ec.currentNode
	savedContext := ec.contextNode
	savedItem := ec.contextItem
	savedMode := ec.currentMode
	savedPos := ec.position
	savedSize := ec.size
	savedTemplate := ec.currentTemplate
	savedTunnel := ec.tunnelParams
	savedXPathDefaultNS := ec.xpathDefaultNS
	savedHasXPathDefaultNS := ec.hasXPathDefaultNS
	savedDefaultCollation := ec.defaultCollation
	ec.currentNode = node
	ec.contextNode = node
	ec.currentMode = mode
	ec.setCurrentTemplate(tmpl)
	ec.xpathDefaultNS = tmpl.XPathDefaultNS

	ec.hasXPathDefaultNS = tmpl.XPathDefaultNS != ""
	if tmpl.DefaultCollation != "" {
		ec.defaultCollation = tmpl.DefaultCollation
	}
	// When entering a template with a node context, clear the atomic context
	// item so that next-match and other instructions use the node context,
	// and never a stale atomic value (e.g., from xsl:analyze-string).
	if node != nil {
		ec.contextItem = nil
	}
	// xsl:context-item use="absent": make the context item absent within the template body
	if tmpl.ContextItemUse == ctxItemAbsent {
		ec.contextNode = nil
		ec.contextItem = nil
	}
	// XTTE0590: check context-item type constraint
	if err := ec.checkContextItemType(tmpl); err != nil {
		return err
	}
	// Track overriding template for xsl:original support
	savedOverridingTemplate := ec.overridingTemplate
	if tmpl.OriginalTemplate != nil {
		ec.overridingTemplate = tmpl
	}
	defer func() {
		ec.currentNode = savedCurrent
		ec.contextNode = savedContext
		ec.contextItem = savedItem
		ec.currentMode = savedMode
		ec.setCurrentTemplate(savedTemplate)
		ec.overridingTemplate = savedOverridingTemplate
		ec.xpathDefaultNS = savedXPathDefaultNS
		ec.hasXPathDefaultNS = savedHasXPathDefaultNS
		ec.defaultCollation = savedDefaultCollation
		ec.position = savedPos
		ec.size = savedSize
		ec.tunnelParams = savedTunnel
	}()

	ec.pushVarScope()
	defer ec.popVarScope()

	// Collect param overrides
	var po map[string]xdm.Sequence
	if len(paramOverrides) > 0 {
		po = paramOverrides[0]
	}

	if err := ec.bindTemplateParams(ctx, tmpl.Params, po, func(p *param) (xdm.Sequence, error) {
		return ec.nodeTemplateParamDefault(ctx, p, node)
	}); err != nil {
		return err
	}

	if tmpl.As != "" {
		// template has return type constraint — capture output and validate
		return ec.executeTemplateBodyWithAs(ctx, tmpl)
	}

	return ec.executeSequenceConstructor(ctx, tmpl.Body)
}

func (ec *execContext) bindTemplateParams(ctx context.Context, params []*param, overrides map[string]xdm.Sequence, defaultValue func(*param) (xdm.Sequence, error)) error {
	for _, p := range params {
		val, fromCaller := ec.callerTemplateParam(p, overrides)
		if !fromCaller {
			if err := ec.missingTemplateParam(p); err != nil {
				return err
			}

			var err error

			val, err = defaultValue(p)
			if err != nil {
				return err
			}
		}

		checked, err := ec.checkTemplateParam(ctx, p, val, fromCaller)
		if err != nil {
			return err
		}

		ec.setVar(p.Name, checked)
	}

	return nil
}

func (ec *execContext) callerTemplateParam(p *param, overrides map[string]xdm.Sequence) (xdm.Sequence, bool) {
	if p.Tunnel {
		value, ok := ec.tunnelParams[p.Name]
		return value, ok
	}

	value, ok := overrides[p.Name]

	return value, ok
}

func (ec *execContext) checkTemplateParam(ctx context.Context, p *param, val xdm.Sequence, fromCaller bool) (xdm.Sequence, error) {
	if p.As == "" {
		return val, nil
	}

	code := ec.parameterDefaultErrorCode()
	if fromCaller {
		code = errCodeXTTE0590
	}

	savedNS, savedDefault, savedHas := ec.nsOverride, ec.xpathDefaultNS, ec.hasXPathDefaultNS

	ec.nsOverride, ec.xpathDefaultNS, ec.hasXPathDefaultNS = p.TypeNamespaces, p.XPathDefaultNS, p.HasXPathDefaultNS
	defer func() { ec.nsOverride, ec.xpathDefaultNS, ec.hasXPathDefaultNS = savedNS, savedDefault, savedHas }()

	return checkSequenceType(ctx, val, parseSequenceType(p.As), code, "param $"+p.Name, ec)
}

func (ec *execContext) parameterDefaultErrorCode() string {
	if ec.stylesheet.processorLanguage() == 20 {
		return "XTTE0600"
	}

	return errCodeXTTE0590
}

func (ec *execContext) missingTemplateParam(p *param) error {
	if !p.Required && !p.implicitlyMandatory() {
		return nil
	}

	code := errCodeXTDE0700
	if !p.Required && ec.stylesheet.processorLanguage() == 20 {
		code = "XTDE0610"
	}

	return dynamicError(code, "required template parameter $%s was not supplied", p.Name)
}

func (ec *execContext) atomicTemplateParamDefault(ctx context.Context, p *param, item xdm.Item) (xdm.Sequence, error) {
	if p.Select != nil {
		result, err := ec.withCompat(ec.xpathEvaluator(ctx).ContextItem(item), p.Select).Evaluate(ec.xpathContext(ctx), p.Select, nil)
		if err != nil {
			return nil, err
		}

		return result.Sequence(), nil
	}

	return ec.templateParamBody(ctx, p)
}

func (ec *execContext) nodeTemplateParamDefault(ctx context.Context, p *param, node xdm.Node) (xdm.Sequence, error) {
	if p.Select != nil {
		result, err := ec.evalXPath(ctx, p.Select, node)
		if err != nil {
			return nil, err
		}

		return result.Sequence(), nil
	}

	return ec.templateParamBody(ctx, p)
}

func (ec *execContext) templateParamBody(ctx context.Context, p *param) (xdm.Sequence, error) {
	if len(p.Body) == 0 {
		if p.As == "" {
			return xdm.SingleString(""), nil
		}

		return xdm.EmptySequence(), nil
	}

	ec.temporaryOutputDepth++

	var (
		val xdm.Sequence
		err error
	)
	if p.As != "" {
		val, err = ec.evaluateBodyAsSequence(ctx, p.Body)
	} else {
		val, err = ec.evaluateBodyAsDocument(ctx, p.Body)
	}

	ec.temporaryOutputDepth--

	return val, err
}

// executeTemplateBodyWithAs runs the template body in capture mode,
// checks the result against the declared as type, then writes the
// validated items to the real output.
func (ec *execContext) executeTemplateBodyWithAs(ctx context.Context, tmpl *template) error {
	seq, err := ec.evaluateBodyAsSequence(ctx, tmpl.Body)
	if err != nil {
		return err
	}

	// Strip DOE marker PIs from the captured sequence before type checking.
	// DOE PIs are internal serialization markers that should be transparent
	// to the XSLT type system. Track which text node indices had DOE markers
	// so we can re-insert them when writing to the result tree.
	stripped, doeTextIndices := stripDOEMarkers(seq)

	st := parseSequenceType(tmpl.As)

	checked, err := checkSequenceType(ctx, stripped, st, errCodeXTTE0505, nameTemplate, ec)
	if err != nil {
		return err
	}

	// Capture the raw typed sequence when writing to the primary output
	// (outputStack depth == 1). This preserves atomic type information
	// that would otherwise be lost during serialization to text nodes.
	if len(ec.outputStack) == 1 {
		ec.rawResultSequence = checked
	}

	// Write the validated items to the real output.
	// When the output is in capture mode (e.g., inside key body or
	// variable evaluation), preserve atomic values directly so that
	// their XSD type is retained for typed comparisons.
	out := ec.currentOutput()

	// In a document-constructor frame at the document node, capture the whole
	// typed result as one ordered unit (behind a placeholder) so it keeps
	// document order with literal result elements; otherwise the nodes would
	// go to the DOM while atomics buffered to pendingItems, splitting the
	// stream and losing interleaving order.
	if out.captureItems && out.documentConstructor && out.current == out.doc {
		if xdm.SequenceLen(checked) > 0 {
			out.captureSequenceItems(xdm.Materialize(checked))
		}

		return nil
	}

	for i := range xdm.SequenceLen(checked) {
		item := checked.Get(i)
		switch v := item.(type) {
		case xdm.NodeItem:
			_, isDOE := doeTextIndices[i]
			if err := ec.writeTypedTemplateNode(v, out, isDOE); err != nil {
				return err
			}
		case xdm.AtomicValue:
			if err := ec.writeTypedTemplateAtomic(v, out); err != nil {
				return err
			}
		default:
			// Function items, maps, and arrays: capture when in
			// capture/sequence mode, otherwise error (they cannot
			// appear in the result tree).
			if out.captureItems || out.sequenceMode || ec.isItemOutputMethod() {
				out.pendingItems = append(out.pendingItems, item)
				out.noteOutput()
			} else {
				return dynamicError(errCodeXTDE0450,
					"cannot add a %T to the result tree", item)
			}
		}
	}

	return nil
}

func (ec *execContext) writeTypedTemplateNode(v xdm.NodeItem, out *outputFrame, isDOE bool) error {
	out.prevWasAtomic = false
	// Re-insert DOE markers when writing directly to the result tree
	// (not inside a variable/capture context). DOE is ignored when
	// writing to variables, attributes, or comments (XSLT 3.0 §20.1).
	// Re-insert DOE markers only when writing directly to the
	// final result tree. DOE is ignored in temporary output
	// states (variables, functions) and capture contexts
	// (comments, attributes, PIs) per XSLT 3.0 §20.1.
	emitDOE := isDOE && ec.temporaryOutputDepth == 0 && !out.captureItems && !out.sequenceMode
	if emitDOE {
		pi := ec.resultDoc.CreatePI(lexicon.OutputDisableEscaping, "")
		if err := ec.addNode(pi); err != nil {
			return err
		}
	}
	// Raw sequences retain identity; complex content copies the returned node
	// through the same namespace/attribute fixup path as xsl:sequence.
	if out.sequenceMode {
		if err := ec.addNode(v.Node); err != nil {
			return err
		}
	} else if !out.captureXSLSequence(xdm.ItemSlice{v}) {
		if _, err := ec.writeXSLSequenceNode(v.Node); err != nil {
			return err
		}
	}

	if emitDOE {
		piEnd := ec.resultDoc.CreatePI("enable-output-escaping", "")
		if err := ec.addNode(piEnd); err != nil {
			return err
		}
	}

	return nil
}

func (ec *execContext) writeTypedTemplateAtomic(v xdm.AtomicValue, out *outputFrame) error {
	if out.captureItems {
		out.pendingItems = append(out.pendingItems, v)
		out.noteOutput()
	} else {
		s, err := xpath.AtomicToString(v)
		if err != nil {
			return err
		}
		// Insert space separator between consecutive atomic values
		// (XSLT 3.0 §11.3: adjacent atomic values are separated by spaces)
		if out.prevWasAtomic {
			sep := ec.resultDoc.CreateText(" ")
			if err := ec.addNode(sep); err != nil {
				return err
			}
		}

		text := ec.resultDoc.CreateText(s)
		if err := ec.addNode(text); err != nil {
			return err
		}

		out.prevWasAtomic = true
	}

	return nil
}

// classifyConflictCandidate applies hasConflictingMatchIn's per-candidate
// rules: skip best itself, stop once precedence/priority drops below best's,
// skip a sibling split from the same union rule (spec bug 30402, tracked by
// splitOriginID), and otherwise probe the pattern.
func classifyConflictCandidate(ctx context.Context, ec *execContext, tmpl, best *template, node xdm.Node) conflictCandidateResult {
	if tmpl == best {
		return conflictCandidateNone
	}

	if tmpl.ImportPrec < best.ImportPrec {
		return conflictCandidateStop
	}

	if tmpl.ImportPrec == best.ImportPrec && tmpl.Priority < best.Priority {
		return conflictCandidateStop
	}
	// Split union pattern branches originate from the same template rule and
	// should not be treated as conflicting with each other (spec bug 30402).
	// They carry a shared non-zero splitOriginID.
	if tmpl.splitOriginID != nil && tmpl.splitOriginID == best.splitOriginID {
		return conflictCandidateNone
	}

	if ec.matchTemplatePattern(ctx, tmpl, node, true) {
		return conflictCandidateFound
	}

	return conflictCandidateNone
}

// stripDOEMarkers removes disable-output-escaping / enable-output-escaping
// marker PIs from a sequence, returning the cleaned sequence and a map of
// indices (in the cleaned sequence) that had DOE markers around them.
func stripDOEMarkers(seq xdm.Sequence) (xdm.Sequence, map[int]struct{}) {
	doeIndices := map[int]struct{}{}
	result := make(xdm.ItemSlice, 0, xdm.SequenceLen(seq))
	doeActive := false

	for item := range xdm.SequenceItems(seq) {
		if ni, ok := item.(xdm.NodeItem); ok && ni.Node.Type() == xdm.ProcessingInstructionNode {
			piName := ni.Node.Name()
			if piName == lexicon.OutputDisableEscaping {
				doeActive = true
				continue
			}

			if piName == "enable-output-escaping" {
				doeActive = false
				continue
			}
		}

		if doeActive {
			doeIndices[len(result)] = struct{}{}
		}

		result = append(result, item)
	}

	return result, doeIndices
}
