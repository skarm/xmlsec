// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"maps"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func (ec *execContext) evaluateTemplateArguments(ctx context.Context, params []*withParam) (map[string]xdm.Sequence, map[string]xdm.Sequence, error) {
	var regular, tunnel map[string]xdm.Sequence

	for _, param := range params {
		value, err := ec.evaluateWithParam(ctx, param)
		if err != nil {
			return nil, nil, err
		}

		if param.Tunnel {
			if tunnel == nil {
				tunnel = make(map[string]xdm.Sequence)
			}

			tunnel[param.Name] = value
		} else {
			if regular == nil {
				regular = make(map[string]xdm.Sequence)
			}

			regular[param.Name] = value
		}
	}

	return regular, tunnel, nil
}

func (ec *execContext) pushTunnelArguments(tunnel map[string]xdm.Sequence) func() {
	saved := ec.tunnelParams
	if tunnel != nil {
		merged := make(map[string]xdm.Sequence, len(saved)+len(tunnel))
		maps.Copy(merged, saved)
		maps.Copy(merged, tunnel)
		ec.tunnelParams = merged
	}

	return func() { ec.tunnelParams = saved }
}

func (ec *execContext) execApplyTemplates(ctx context.Context, inst *applyTemplatesInst) error {
	items, err := ec.selectApplyTemplateItems(ctx, inst)
	if err != nil {
		return err
	}

	if len(inst.Sort) > 0 {
		items, err = ec.sortApplyTemplateItems(ctx, items, inst.Sort)
		if err != nil {
			return err
		}
	}

	mode := inst.Mode
	// When mode is absent (empty), use the stylesheet's default-mode
	// (not the current mode — #current must be explicit)

	paramValues, newTunnelParams, err := ec.evaluateTemplateArguments(ctx, inst.Params)
	if err != nil {
		return err
	}

	restoreTunnel := ec.pushTunnelArguments(newTunnelParams)

	// Filter whitespace-only text nodes per xsl:strip-space before
	// setting position/size, so position()/last() reflect the filtered list.
	filtered := items[:0]
	for _, item := range items {
		if ni, ok := item.(xdm.NodeItem); ok && ec.shouldStripWhitespace(ni.Node) {
			continue
		}

		filtered = append(filtered, item)
	}

	items = filtered

	savedPos := ec.position
	savedSize := ec.size
	savedInMerge := ec.inMergeAction
	ec.size = len(items)

	ec.inMergeAction = false // XTDE3480: merge context not available across template boundaries
	defer func() {
		ec.position = savedPos
		ec.size = savedSize

		restoreTunnel()

		ec.inMergeAction = savedInMerge
	}()

	// Dispatch each selected item in sequence order. Node items go through
	// template matching for nodes; atomic values, arrays, and maps use the
	// XSLT 3.0 atomic dispatch rules.
	for i, item := range items {
		if err := ctx.Err(); err != nil {
			return err
		}

		ec.position = i + 1

		if ni, ok := item.(xdm.NodeItem); ok {
			if err := ec.applyTemplates(ctx, ni.Node, mode, paramValues); err != nil {
				return err
			}

			continue
		}

		if err := ec.dispatchApplyTemplatesItem(ctx, item, mode, paramValues); err != nil {
			return err
		}
	}

	return nil
}

// selectApplyTemplateItems preserves sequence order and array/map identity.
func (ec *execContext) selectApplyTemplateItems(ctx context.Context, inst *applyTemplatesInst) (xdm.ItemSlice, error) {
	var items xdm.ItemSlice

	if inst.Select != nil {
		result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
		if err != nil {
			return nil, err
		}
		// Do NOT flatten arrays here: XSLT 3.0 allows arrays (and maps) as
		// items in apply-templates, matched via pattern rules (e.g.,
		// match=".[. instance of array(*)]"). Flattening would destroy the
		// array before template matching can see it.
		items = xdm.Materialize(result.Sequence())
		if ec.stylesheet.processorLanguage() == 20 {
			if _, nodesOnly := xdm.NodesFrom(items); !nodesOnly {
				return nil, dynamicError("XTTE0520", "XSLT 2.0 apply-templates selection must contain only nodes")
			}
		}
	} else {
		// Default select is child::node() which requires a node context item.
		// If the context item is an atomic value (contextNode is nil), raise XTTE0510.
		if normalizeNode(ec.contextNode) == nil {
			return nil, dynamicError(errCodeXTTE0510, "apply-templates with default select requires a node context item")
		}

		for _, node := range selectDefaultNodes(ec.contextNode) {
			items = append(items, xdm.NodeItem{Node: node})
		}
	}

	return items, nil
}

// sortApplyTemplateItems uses the node path so current() in sort keys receives
// each node; mixed/atomic sorting still validates attributes for empty input.
func (ec *execContext) sortApplyTemplateItems(ctx context.Context, items xdm.ItemSlice, sortKeys []*sortKey) (xdm.ItemSlice, error) {
	if nodes, allNodes := xdm.NodesFrom(items); allNodes {
		sorted, err := sortNodes(ctx, ec, nodes, sortKeys)
		if err != nil {
			return nil, err
		}

		items = items[:0]
		for _, node := range sorted {
			items = append(items, xdm.NodeItem{Node: node})
		}
	} else {
		// Validate sort key attributes even when the selection is empty
		// (XTDE0030); sortNodes does this internally, sortItems does not.
		for _, sk := range sortKeys {
			if err := validateSortKeyAttrs(ctx, ec, sk); err != nil {
				return nil, err
			}
		}

		sorted, err := sortItems(ctx, ec, items, sortKeys)
		if err != nil {
			return nil, err
		}

		items = xdm.Materialize(sorted)
	}

	return items, nil
}

// dispatchApplyTemplatesItem matches a non-node item before using the current
// mode's built-in rule. Maps/functions are not implicitly traversed.
func (ec *execContext) dispatchApplyTemplatesItem(ctx context.Context, item xdm.Item, mode string, params map[string]xdm.Sequence) error {
	initialCall := ec.initialTemplateCall
	ec.initialTemplateCall = false

	ec.depth++
	if ec.depth > xpath.DepthLimit(ctx, maxRecursionDepth) {
		ec.depth--
		return xpath.ErrRecursionLimit
	}
	defer func() { ec.depth-- }()

	mode, restoreMode := ec.pushMode(mode)
	defer restoreMode()

	tmpl, err := ec.findAtomicTemplate(ctx, item, mode)
	if err != nil {
		return err
	}

	if tmpl != nil {
		if initialCall {
			if err := ec.checkInitialTemplateParameters(tmpl); err != nil {
				return err
			}
		}

		return ec.executeAtomicTemplate(ctx, tmpl, item, mode, params)
	}

	return ec.applyBuiltinTemplateItem(ctx, item, mode, params)
}

func (ec *execContext) applyBuiltinTemplateItem(ctx context.Context, item xdm.Item, mode string, params map[string]xdm.Sequence) error {
	defer ec.pushPackage(ec.activeModePackage())()

	if err := xpath.Charge(ctx, 1); err != nil {
		return err
	}

	switch ec.builtinTemplateBehavior(mode) {
	case onNoMatchDeepCopy, onNoMatchShallowCopy:
		return ec.outputSequence(xdm.ItemSlice{item})
	case onNoMatchDeepSkip:
		return nil
	case onNoMatchFail:
		return dynamicError(errCodeXTDE0555, "no matching template in mode %q (on-no-match=fail)", mode)
	case onNoMatchShallowSkip:
		if array, ok := item.(xdm.ArrayItem); ok {
			return ec.applyBuiltinArray(ctx, array, mode, params)
		}

		return nil
	default:
		if array, ok := item.(xdm.ArrayItem); ok {
			return ec.applyBuiltinArray(ctx, array, mode, params)
		}

		if atomic, ok := item.(xdm.AtomicValue); ok {
			value, err := xpath.AtomicToString(atomic)
			if err != nil {
				return err
			}

			return ec.addNode(ec.resultDoc.CreateText(value))
		}

		return nil
	}
}

// The implicit ?* selection concatenates members without recursively flattening
// nested arrays. Matching sees the whole selection's position and size.
func (ec *execContext) applyBuiltinArray(ctx context.Context, array xdm.ArrayItem, mode string, params map[string]xdm.Sequence) error {
	var items xdm.ItemSlice

	for _, member := range array.MembersView() {
		for item := range xdm.SequenceItems(member) {
			if err := xpath.Charge(ctx, 1); err != nil {
				return err
			}

			if len(items) >= xpath.NodeLimit(ctx, 1_000_000) {
				return xpath.ErrNodeSetLimit
			}

			items = append(items, item)
		}
	}

	return ec.applyTemplatesToSequence(ctx, items, mode, params)
}

func (ec *execContext) applyTemplatesToSequence(ctx context.Context, seq xdm.Sequence, mode string, params map[string]xdm.Sequence) error {
	items := xdm.Materialize(seq)

	filtered := items[:0]
	for _, item := range items {
		if node, ok := item.(xdm.NodeItem); ok && ec.shouldStripWhitespace(node.Node) {
			continue
		}

		filtered = append(filtered, item)
	}

	items = filtered
	savedPos, savedSize, savedMerge := ec.position, ec.size, ec.inMergeAction

	ec.inMergeAction = false
	defer func() { ec.position, ec.size, ec.inMergeAction = savedPos, savedSize, savedMerge }()

	ec.size = len(items)
	for i, item := range items {
		if err := xpath.Charge(ctx, 1); err != nil {
			return err
		}

		ec.position = i + 1
		if node, ok := item.(xdm.NodeItem); ok {
			if err := ec.applyTemplates(ctx, node.Node, mode, params); err != nil {
				return err
			}
		} else if err := ec.dispatchApplyTemplatesItem(ctx, item, mode, params); err != nil {
			return err
		}
	}

	return nil
}

func (ec *execContext) evaluateWithParam(ctx context.Context, wp *withParam) (xdm.Sequence, error) {
	var val xdm.Sequence

	if wp.Select != nil {
		result, err := ec.evalXPath(ctx, wp.Select, ec.contextNode)
		if err != nil {
			return nil, err
		}

		val = result.Sequence()
	} else if len(wp.Body) > 0 {
		ec.temporaryOutputDepth++

		var err error
		if wp.As != "" {
			// With as attribute: evaluate as sequence constructor,
			// keeping each node as a separate item
			val, err = ec.evaluateBodyAsSequence(ctx, wp.Body)
		} else {
			// No as: wrap in document node (temporary tree)
			val, err = ec.evaluateBodyAsDocument(ctx, wp.Body)
		}

		ec.temporaryOutputDepth--

		if err != nil {
			return nil, err
		}
	} else {
		if wp.As != "" {
			val = xdm.EmptySequence()
		} else {
			val = xdm.SingleAtomic(xdm.AtomicValue{
				TypeName: xdm.TypeString,
				Value:    "",
			})
		}
	}

	// Type check against the declared as type
	if wp.Type != nil {
		checked, err := ec.convertSequenceType(ctx, val, *wp.Type)
		if err != nil {
			if failure := preserveControlFailure(ctx, err); failure != nil {
				return nil, failure
			}

			return nil, dynamicError(errCodeXTTE0590, "with-param $%s: %s", wp.Name, err)
		}

		val = checked
	}

	return val, nil
}

// resolveNamedTemplate resolves from the calling package, whose component
// bindings include its accepted and overridden components.
func (ec *execContext) resolveNamedTemplate(name string) (*template, bool) {
	// Handle xsl:original — resolve to the original overridden template
	if name == xdm.ClarkName(lexicon.NamespaceXSLT, nameOriginal) {
		if ec.overridingTemplate != nil && ec.overridingTemplate.OriginalTemplate != nil {
			return ec.overridingTemplate.OriginalTemplate, true
		}

		return nil, false
	}

	if ec.currentPackage != nil {
		tmpl, ok := ec.currentPackage.namedTemplates[name]
		return tmpl, ok
	}

	tmpl, ok := ec.stylesheet.namedTemplates[name]

	return tmpl, ok
}

func (ec *execContext) execCallTemplate(ctx context.Context, inst *callTemplateInst) error {
	ec.depth++
	if ec.depth > xpath.DepthLimit(ctx, maxRecursionDepth) {
		ec.depth--
		return xpath.ErrRecursionLimit
	}
	defer func() { ec.depth-- }()

	// XTDE3480/XTDE3510: clear merge-action context across template boundaries.
	savedInMerge := ec.inMergeAction

	ec.inMergeAction = false
	defer func() { ec.inMergeAction = savedInMerge }()

	tmpl, ok := ec.resolveNamedTemplate(inst.Name)
	if !ok {
		return dynamicError(errCodeXTSE0650, "named template %q not found", inst.Name)
	}

	if tmpl.Visibility == visAbstract {
		return dynamicError(errCodeXTDE3052, "abstract template %q was invoked without an implementation", tmpl.Name)
	}

	// XTTE0590: check context-item type constraint
	if err := ec.checkContextItemType(tmpl); err != nil {
		return err
	}

	// Evaluate with-param values BEFORE clearing the context for use="absent",
	// because the with-param select expressions need the caller's context item.
	//
	// Two-phase param evaluation (mirrors xsl:apply-templates): evaluate ALL
	// with-param values into LOCAL maps first, THEN merge tunnel params into
	// ec.tunnelParams. This prevents a later with-param body that invokes
	// another template (e.g. via an error caught by xsl:try/xsl:catch) from
	// observing a tentative tunnel override before control has actually been
	// transferred to the called template.
	paramOverrides, newTunnelParams, err := ec.evaluateTemplateArguments(ctx, inst.Params)
	if err != nil {
		return err
	}

	defer ec.pushTunnelArguments(newTunnelParams)()

	// Switch package function scope if the template belongs to a different package.
	savedFnsNS, savedPackage := ec.cachedFnsNS, ec.currentPackage

	// Component bodies retain the scope of the package that declares them,
	// including overriding match rules without a named original.
	if tmpl.OwnerPackage != ec.currentPackage {
		ec.cachedFnsNS = nil
		ec.currentPackage = tmpl.OwnerPackage
	}

	// Do NOT set ec.currentTemplate here: xsl:call-template preserves the
	// current template rule for xsl:apply-imports/xsl:next-match.

	// Track overriding template for xsl:original support.
	savedOverridingTemplate := ec.overridingTemplate
	if tmpl.OriginalTemplate != nil {
		ec.overridingTemplate = tmpl
	}

	// xsl:context-item use="absent": make the context item absent within the
	// called template's body. This means xsl:next-match will fail with
	// XTDE0560 because there is no context node to match against.
	// The current group is independent of the focus and remains available
	// across ordinary template calls (XSLT 3.0 section 14.2).
	savedContextNode := ec.contextNode
	savedContextItem := ec.contextItem

	savedCurrentNode := ec.currentNode

	savedCurrentTemplate := ec.currentTemplate
	if tmpl.ContextItemUse == ctxItemAbsent {
		ec.contextNode = nil
		ec.contextItem = nil
		ec.currentNode = nil
		ec.setCurrentTemplate(nil)
	}
	defer func() {
		ec.cachedFnsNS = savedFnsNS
		ec.currentPackage = savedPackage

		ec.overridingTemplate = savedOverridingTemplate
		if tmpl.ContextItemUse == ctxItemAbsent {
			ec.contextNode = savedContextNode
			ec.contextItem = savedContextItem
			ec.currentNode = savedCurrentNode
			ec.setCurrentTemplate(savedCurrentTemplate)
		}
	}()

	ec.pushVarScope()
	defer ec.popVarScope()

	// Apply default-collation from the called template
	savedDefaultCollation := ec.defaultCollation
	if tmpl.DefaultCollation != "" {
		ec.defaultCollation = tmpl.DefaultCollation
	}
	defer func() { ec.defaultCollation = savedDefaultCollation }()

	if err := ec.bindCalledTemplateParams(ctx, tmpl.Params, paramOverrides); err != nil {
		return err
	}

	if tmpl.As != "" {
		return ec.executeTemplateBodyWithAs(ctx, tmpl)
	}

	return ec.executeSequenceConstructor(ctx, tmpl.Body)
}

func (ec *execContext) bindCalledTemplateParams(ctx context.Context, params []*param, overrides map[string]xdm.Sequence) error {
	return ec.bindTemplateParams(ctx, params, overrides, func(p *param) (xdm.Sequence, error) {
		if p.Select != nil {
			result, err := ec.evalXPath(ctx, p.Select, ec.contextNode)
			if err != nil {
				return nil, err
			}

			return result.Sequence(), nil
		}

		return ec.templateParamBody(ctx, p)
	})
}

func (ec *execContext) execNextMatch(ctx context.Context, inst *nextMatchInst) error {
	// XTDE0560: xsl:next-match when the current template rule is absent.
	if ec.currentTemplate == nil || ec.currentTemplate.Match == nil {
		return dynamicError(errCodeXTDE0560, "xsl:next-match: no current template rule")
	}
	// xsl:next-match: find the next matching template after the current one
	node := ec.currentNode
	mode := ec.currentMode

	// Process with-param (tunnel and regular).
	//
	// Two-phase param evaluation (mirrors xsl:apply-templates): evaluate ALL
	// with-param values into LOCAL maps first, THEN merge tunnel params into
	// ec.tunnelParams. This prevents a later with-param body that invokes
	// another template (e.g. via an error caught by xsl:try/xsl:catch) from
	// observing a tentative tunnel override before control has actually been
	// transferred to the next-match template.
	pv, newTunnelParams, err := ec.evaluateTemplateArguments(ctx, inst.Params)
	if err != nil {
		return err
	}

	defer ec.pushTunnelArguments(newTunnelParams)()

	if ec.contextItem != nil {
		return ec.execNextAtomicMatch(ctx, mode, pv)
	}

	templates := ec.activeModePackage().modeTemplates[mode]
	foundCurrent := false

	failOnMultiple := ec.onMultipleMatchFail(mode)
	for i, tmpl := range templates {
		if tmpl == ec.currentTemplate {
			foundCurrent = true
			continue
		}

		if !foundCurrent {
			continue
		}

		if !ec.matchTemplatePattern(ctx, tmpl, node, false) {
			continue
		}

		if failOnMultiple {
			if err := ec.checkNextMatchConflicts(ctx, templates[i+1:], tmpl, node, mode); err != nil {
				return err
			}
		}

		return ec.executeTemplate(ctx, tmpl, node, mode, pv)
	}

	// No next match found — apply built-in rules
	return ec.applyBuiltinRules(ctx, node, mode, pv)
}

func (ec *execContext) checkNextMatchConflicts(ctx context.Context, candidates []*template, tmpl *template, node xdm.Node, mode string) error {
	for _, other := range candidates {
		if other.ImportPrec < tmpl.ImportPrec || (other.ImportPrec == tmpl.ImportPrec && other.Priority < tmpl.Priority) {
			break
		}
		// A mode list can hold one template twice (a mode="#all"
		// template registered in the default mode); it never
		// conflicts with itself.
		if other == tmpl {
			continue
		}
		// Split union pattern branches originate from the same template
		// rule and never conflict with each other (spec bug 30402).
		if other.splitOriginID != nil && other.splitOriginID == tmpl.splitOriginID {
			continue
		}

		if ec.matchTemplatePattern(ctx, other, node, false) {
			return dynamicError(errCodeXTDE0540,
				"ambiguous rule match for node %v in mode %q (on-multiple-match=fail)",
				node, mode)
		}
	}

	return nil
}

func (ec *execContext) execNextAtomicMatch(ctx context.Context, mode string, pv map[string]xdm.Sequence) error {
	templates := ec.activeModePackage().modeTemplates[mode]
	foundCurrent := false

	for _, tmpl := range templates {
		if tmpl == ec.currentTemplate {
			foundCurrent = true
			continue
		}

		if foundCurrent && tmpl.Match != nil && ec.matchAtomicTemplate(ctx, tmpl, ec.contextItem) {
			return ec.executeAtomicTemplate(ctx, tmpl, ec.contextItem, mode, pv)
		}
	}

	return ec.applyBuiltinTemplateItem(ctx, ec.contextItem, mode, pv)
}

func (ec *execContext) execApplyImports(ctx context.Context, inst *applyImportsInst) error {
	// xsl:apply-imports: find a matching template with lower import precedence
	// than the currently executing template.
	// XTDE0560: xsl:apply-imports when the current template rule is absent.
	// A template rule is a template with a match pattern; named templates
	// invoked via call-template or initial-template don't count.
	if ec.currentTemplate == nil || ec.currentTemplate.Match == nil {
		return dynamicError(errCodeXTDE0560, "xsl:apply-imports: no current template rule")
	}

	node := ec.currentNode
	mode := ec.currentMode
	maxPrec := ec.currentTemplate.ImportPrec

	// Process with-param (tunnel and regular).
	//
	// Two-phase param evaluation (mirrors xsl:apply-templates): evaluate ALL
	// with-param values into LOCAL maps first, THEN merge tunnel params into
	// ec.tunnelParams. This prevents a later with-param body that invokes
	// another template (e.g. via an error caught by xsl:try/xsl:catch) from
	// observing a tentative tunnel override before control has actually been
	// transferred to the imported template.
	pv, newTunnelParams, err := ec.evaluateTemplateArguments(ctx, inst.Params)
	if err != nil {
		return err
	}

	defer ec.pushTunnelArguments(newTunnelParams)()

	// xsl:apply-imports searches only within the current module's import
	// tree. MinImportPrec marks the lowest precedence among the module's
	// (transitive) imports, so we restrict the search to [minPrec, maxPrec).
	minPrec := ec.currentTemplate.MinImportPrec

	// XSLT 3.0: when the context item is an atomic value (e.g. from
	// xsl:apply-templates select="1 to 5"), search for matching atomic
	// templates with lower import precedence, then use the current mode
	// for the built-in rule on the original item.
	if ec.contextItem != nil {
		templates := ec.activeModePackage().modeTemplates[mode]
		for _, tmpl := range templates {
			if tmpl.ImportPrec >= maxPrec || tmpl.ImportPrec < minPrec {
				continue
			}

			if tmpl.Match != nil && ec.matchAtomicTemplate(ctx, tmpl, ec.contextItem) {
				return ec.executeAtomicTemplate(ctx, tmpl, ec.contextItem, mode, pv)
			}
		}

		return ec.applyBuiltinTemplateItem(ctx, ec.contextItem, mode, pv)
	}

	templates := ec.activeModePackage().modeTemplates[mode]
	for _, tmpl := range templates {
		if tmpl.ImportPrec >= maxPrec || tmpl.ImportPrec < minPrec {
			continue
		}

		if ec.matchTemplatePattern(ctx, tmpl, node, false) {
			return ec.executeTemplate(ctx, tmpl, node, mode, pv)
		}
	}

	// No imported template found, use built-in rules
	return ec.applyBuiltinRules(ctx, node, mode, pv)
}

// checkContextItemType validates the context item against the template's
// xsl:context-item declaration. Returns XTTE0590 on type mismatch or
// XTTE3090 when the context item is absent but required.
func (ec *execContext) checkContextItemType(tmpl *template) error {
	if tmpl.ContextItemAs == "" && tmpl.ContextItemUse == "" {
		return nil
	}

	// Determine the current context item
	var contextSeq xdm.ItemSlice
	if ec.contextItem != nil {
		contextSeq = xdm.ItemSlice{ec.contextItem}
	} else if normalizeNode(ec.contextNode) != nil {
		contextSeq = xdm.ItemSlice{xdm.NodeItem{Node: ec.contextNode}}
	}

	use := tmpl.ContextItemUse
	if use == "" {
		use = ctxItemOptional
	}

	// XTTE3090: context item absent when use="required"
	if len(contextSeq) == 0 && use == ctxItemRequired {
		return dynamicError(errCodeXTTE3090, "context item is absent but xsl:context-item use=\"required\"")
	}

	// Type check: if as is specified and context item exists, check the type.
	// Context-item type checking uses "instance of" semantics (no atomization/casting).
	if tmpl.contextItemType != nil && len(contextSeq) > 0 {
		if !xpath.MatchesSequenceType(contextSeq, *tmpl.contextItemType) {
			return dynamicError(errCodeXTTE0590,
				"context item does not match required type %s", tmpl.ContextItemAs)
		}
	}

	return nil
}

// stripXPathComments removes XPath 2.0+ comments (: ... :) from a string
// and normalizes whitespace (collapses runs of whitespace into single spaces,
// removes spaces adjacent to parentheses).
func stripXPathComments(s string) string {
	// First pass: remove comments
	var buf strings.Builder

	depth := 0

	for i := 0; i < len(s); i++ {
		if i+1 < len(s) && s[i] == '(' && s[i+1] == ':' {
			depth++
			i++ // skip ':'

			continue
		}

		if i+1 < len(s) && s[i] == ':' && s[i+1] == ')' {
			if depth > 0 {
				depth--
			}

			i++ // skip ')'

			continue
		}

		if depth == 0 {
			buf.WriteByte(s[i])
		}
	}
	// Normalize whitespace: collapse runs into single space, trim
	result := strings.Join(strings.Fields(buf.String()), " ")
	result = strings.ReplaceAll(result, " (", "(")
	result = strings.ReplaceAll(result, "( ", "(")
	result = strings.ReplaceAll(result, " )", ")")
	result = strings.ReplaceAll(result, ") ", ")")
	result = strings.ReplaceAll(result, " ,", ",")
	result = strings.ReplaceAll(result, ", ", ",")

	return result
}
