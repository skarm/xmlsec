// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type iterateCompileState struct {
	inParams         bool
	seenOnCompletion bool
	paramNames       map[string]struct{}
	bodyChildren     []iterateBodyChild
}

type iterateBodyChild struct {
	elem *xdm.Element
	text string
	node xdm.Node
}

// Structural content models permit only named child elements after stylesheet
// preprocessing; retained character data is never a sequence constructor there.
func validateStructuralText(child xdm.Node, parent *xdm.Element) error {
	if isStylesheetTextNode(child) {
		return staticError(errCodeXTSE0010, "text is not allowed as a child of xsl:%s", parent.LocalName())
	}

	return nil
}

// compileSourceDocument compiles an xsl:source-document element.
func (c *compiler) compileSourceDocument(ctx context.Context, elem *xdm.Element) (instruction, error) {
	hrefAttr := getAttr(elem, lexicon.AttrHref)
	if hrefAttr == "" {
		return nil, staticError(errCodeXTSE0010, "xsl:source-document requires href attribute")
	}

	hrefAVT, err := c.compileAVT(hrefAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	inst := &sourceDocumentInst{
		Href:       hrefAVT,
		Streamable: xsdBoolTrue(getAttr(elem, nameStreamable)),
		BaseURI:    stylesheetBaseURI(elem, c.baseURI, c.moduleRoot),
		Validation: basicValidation(getAttr(elem, nameValidation)),
	}
	if typeName := getAttr(elem, lexicon.AttrType); typeName != "" {
		inst.TypeName = resolveQName(typeName, c.nsBindings)
	}

	if useAccumulators := getAttr(elem, nameUseAccumulators); useAccumulators != "" {
		for name := range strings.FieldsSeq(useAccumulators) {
			inst.UseAccumulators = append(inst.UseAccumulators, resolveQName(name, c.nsBindings))
		}
	}

	body, err := c.compileChildren(ctx, elem)
	if err != nil {
		return nil, err
	}

	inst.Body = body

	return inst, nil
}

// compileIterate compiles an xsl:iterate element.
func (c *compiler) compileIterate(ctx context.Context, elem *xdm.Element) (instruction, error) {
	selectAttr, hasSelect := elem.GetAttribute(xslAttrSelect)
	if !hasSelect {
		return nil, staticError(errCodeXTSE0010, "xsl:iterate requires select attribute")
	}

	expr, err := c.compileXPath(selectAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	inst := &iterateInst{Select: expr}

	// Save/restore iterate context.
	savedIterDepth := c.iterateDepth
	savedBreakAllowed := c.breakAllowed
	c.iterateDepth++
	// breakAllowed is set per-instruction below (only the tail instruction
	// is allowed to contain xsl:break / xsl:next-iteration).
	c.breakAllowed = false
	defer func() {
		c.iterateDepth = savedIterDepth
		c.breakAllowed = savedBreakAllowed
	}()

	state := &iterateCompileState{inParams: true, paramNames: make(map[string]struct{})}
	for child := range xdm.Children(elem) {
		if err := c.collectIterateChild(ctx, child, inst, state); err != nil {
			return nil, err
		}
	}

	if err := c.compileIterateBody(ctx, inst, state.bodyChildren); err != nil {
		return nil, err
	}

	c.breakAllowed = false

	if err := validateNextIterationParams(inst.Body, state.paramNames); err != nil {
		return nil, err
	}

	if err := validateIterateParamDefaults(inst.Params); err != nil {
		return nil, err
	}

	return inst, nil
}

func validateIterateParamDefaults(params []*iterateParam) error {
	for _, param := range params {
		if param.Select == nil && len(param.Body) == 0 && !allowsEmptySequence(param.As) {
			return staticError(errCodeXTSE3520, "xsl:iterate parameter %q with type %q requires a select attribute or default value", param.Name, param.As)
		}
	}

	return nil
}

// validateNextIterationParams walks the instruction tree checking that any
// nextIterationInst only references declared iterate parameter names.
func validateNextIterationParams(body []instruction, paramNames map[string]struct{}) error {
	for _, inst := range body {
		if ni, ok := inst.(*nextIterationInst); ok {
			for _, wp := range ni.Params {
				if _, exists := paramNames[wp.Name]; !exists {
					return staticError(errCodeXTSE3130, "xsl:next-iteration references undeclared parameter %q", wp.Name)
				}
			}
		}
		// Recurse into sub-instructions.
		for _, child := range instructionChildren(inst) {
			if err := validateNextIterationParams(child, paramNames); err != nil {
				return err
			}
		}
	}

	return nil
}

// instructionChildren returns the sub-instruction slices of an instruction
// for recursive walking.
func instructionChildren(inst instruction) [][]instruction {
	switch v := inst.(type) {
	case *ifInst:
		return [][]instruction{v.Body}
	case *chooseInst:
		var result [][]instruction
		for _, w := range v.When {
			result = append(result, w.Body)
		}

		if v.Otherwise != nil {
			result = append(result, v.Otherwise)
		}

		return result
	case *forEachInst:
		return [][]instruction{v.Body}
	case *tryCatchInst:
		result := [][]instruction{v.Try}
		for _, c := range v.Catches {
			result = append(result, c.Body)
		}

		return result
	case *sequenceInst:
		return [][]instruction{v.Body}
	case *variableInst:
		return [][]instruction{v.Body}
	case *literalResultElement:
		return [][]instruction{v.Body}
	case *elementInst:
		return [][]instruction{v.Body}
	case *copyInst:
		return [][]instruction{v.Body}
	case *copyOfInst:
		return nil
	case *collationScopeInst:
		if v.Inner != nil {
			return [][]instruction{{v.Inner}}
		}

		return nil
	default:
		return nil
	}
}

func (c *compiler) collectIterateChild(ctx context.Context, child xdm.Node, inst *iterateInst, state *iterateCompileState) error {
	elem, ok := child.(*xdm.Element)
	if !ok {
		if text, ok := child.(*xdm.Text); ok {
			value := xdm.CharacterData(text)
			if !c.shouldStripText(ctx, value) {
				state.inParams = false
				state.bodyChildren = append(state.bodyChildren, iterateBodyChild{text: value, node: child})
			}
		}

		return nil
	}

	if elem.URI() == lexicon.NamespaceXSLT {
		switch elem.LocalName() {
		case lexicon.XSLTElementParam:
			return c.collectIterateParam(ctx, elem, inst, state)
		case lexicon.XSLTElementOnCompletion:
			state.inParams = false
			if state.seenOnCompletion {
				return staticError(errCodeXTSE0010, "xsl:iterate must have at most one xsl:on-completion child")
			}

			state.seenOnCompletion = true

			body, err := c.compileIterateCompletion(ctx, elem)
			if err != nil {
				return err
			}

			inst.OnCompletion = body

			return nil
		}
	}

	state.inParams = false
	state.bodyChildren = append(state.bodyChildren, iterateBodyChild{elem: elem})

	return nil
}

func (c *compiler) collectIterateParam(ctx context.Context, elem *xdm.Element, inst *iterateInst, state *iterateCompileState) error {
	if !state.inParams {
		return staticError(errCodeXTSE0010, "xsl:param in xsl:iterate must precede all other children")
	}

	param, err := c.compileIterateParam(ctx, elem)
	if err != nil {
		return err
	}

	if _, duplicate := state.paramNames[param.Name]; duplicate {
		return staticError(errCodeXTSE0580, "duplicate parameter name %q in xsl:iterate", param.Name)
	}

	state.paramNames[param.Name] = struct{}{}
	inst.Params = append(inst.Params, param)

	return nil
}

// hasStreamingSequenceBody retains the streaming instruction rules: fallback
// children are ignored, and significant ordinary text or elements form a body.
func (c *compiler) hasStreamingSequenceBody(ctx context.Context, elem *xdm.Element) bool {
	for child := range xdm.Children(elem) {
		if element, ok := child.(*xdm.Element); ok {
			if element.URI() == lexicon.NamespaceXSLT && element.LocalName() == lexicon.XSLTElementFallback {
				continue
			}

			return true
		}

		if text, ok := child.(*xdm.Text); ok && !c.shouldStripText(ctx, xdm.CharacterData(text)) {
			return true
		}
	}

	return false
}

func (c *compiler) compileIterateCompletion(ctx context.Context, elem *xdm.Element) ([]instruction, error) {
	selectAttr, hasSelect := elem.GetAttribute(xslAttrSelect)
	hasBody := c.hasStreamingSequenceBody(ctx, elem)

	if hasSelect && hasBody {
		return nil, staticError(errCodeXTSE3125, "xsl:on-completion must not have both select attribute and sequence constructor")
	}

	if !hasSelect {
		return c.compileChildren(ctx, elem)
	}

	restoreVersion := c.pushElementVersion(elem)
	expression, err := c.compileXPath(selectAttr, c.nsBindings)

	restoreVersion()

	if err != nil {
		return nil, err
	}

	return []instruction{&xslSequenceInst{Select: expression}}, nil
}

func (c *compiler) compileIterateBody(ctx context.Context, inst *iterateInst, children []iterateBodyChild) error {
	last := lastIterateBodyChild(children)
	for i, child := range children {
		if child.elem == nil {
			text, err := c.compileLiteralTextAt(child.node, child.text)
			if err != nil {
				return err
			}

			inst.Body = append(inst.Body, text)

			continue
		}

		c.breakAllowed = i == last

		compiled, err := c.compileInstruction(ctx, child.elem)
		if err != nil {
			return err
		}

		if compiled != nil {
			inst.Body = append(inst.Body, compiled)
		}
	}

	return nil
}

func lastIterateBodyChild(children []iterateBodyChild) int {
	for i, child := range slices.Backward(children) {
		if child.elem != nil && child.elem.URI() == lexicon.NamespaceXSLT && child.elem.LocalName() == lexicon.XSLTElementFallback {
			continue
		}

		return i
	}

	return -1
}

// compileIterateParam compiles an xsl:param inside xsl:iterate.
func (c *compiler) compileIterateParam(ctx context.Context, elem *xdm.Element) (*iterateParam, error) {
	for _, attribute := range []string{ctxItemRequired, nameTunnel, nameStatic} {
		if xsdBoolTrue(getAttr(elem, attribute)) {
			return nil, staticError(errCodeXTSE0020, "xsl:iterate parameter must not specify %s=\"yes\"", attribute)
		}
	}

	definition, err := c.compileParamDef(ctx, elem)
	if err != nil {
		return nil, err
	}

	p := &iterateParam{Name: definition.Name, As: definition.As, Select: definition.Select, Body: definition.Body}
	if p.As != "" {
		st, err := xpath.ParseSequenceType(p.As)
		if err != nil {
			return nil, err
		}

		bound, err := xpath.BindSequenceType(ctx, st, definition.TypeNamespaces, definition.XPathDefaultNS)
		if err != nil {
			return nil, err
		}

		p.Type = &bound
	}

	return p, nil
}

// compileFork compiles an xsl:fork element.
func (c *compiler) compileFork(ctx context.Context, elem *xdm.Element) (instruction, error) {
	inst := &forkInst{}
	seenSequence, seenGroup := false, false

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			if err := validateStructuralText(child, elem); err != nil {
				return nil, err
			}

			continue
		}

		if childElem.URI() != lexicon.NamespaceXSLT {
			return nil, staticError(errCodeXTSE0010, "unexpected child element in xsl:fork: %s", childElem.Name())
		}

		switch childElem.LocalName() {
		case lexicon.XSLTElementFallback:
			continue
		case lexicon.XSLTElementSequence:
			if seenGroup {
				return nil, staticError(errCodeXTSE0010, "xsl:fork cannot mix xsl:sequence and xsl:for-each-group branches")
			}

			seenSequence = true
		case lexicon.XSLTElementForEachGroup:
			if seenSequence || seenGroup {
				return nil, staticError(errCodeXTSE0010, "xsl:fork permits only one xsl:for-each-group branch")
			}

			seenGroup = true
		default:
			return nil, staticError(errCodeXTSE0010, "unexpected child element xsl:%s in xsl:fork", childElem.LocalName())
		}

		branch, err := c.compileForkBranch(ctx, childElem)
		if err != nil {
			return nil, err
		}

		if branch != nil {
			inst.Branches = append(inst.Branches, branch)
		}
	}

	return inst, nil
}

// compileForkBranch compiles one child of xsl:fork into a branch (slice of instructions).
func (c *compiler) compileForkBranch(ctx context.Context, elem *xdm.Element) ([]instruction, error) {
	// Dispatch through the ordinary compiler so each branch retains its lexical
	// context and the same select/body validation as instructions outside a fork.
	inst, err := c.compileInstruction(ctx, elem)
	if err != nil {
		return nil, err
	}

	if inst == nil {
		return nil, nil
	}

	return []instruction{inst}, nil
}

// compileBreak compiles an xsl:break element.
func (c *compiler) compileBreak(ctx context.Context, elem *xdm.Element) (instruction, error) {
	// XTSE0010: xsl:break must be lexically within xsl:iterate.
	if c.iterateDepth == 0 {
		return nil, staticError(errCodeXTSE0010, "xsl:break must be within xsl:iterate")
	}
	// XTSE3120: xsl:break must not be inside an element constructor,
	// xsl:for-each, or other non-iterate-body position.
	if !c.breakAllowed {
		return nil, staticError(errCodeXTSE3120, "xsl:break is not allowed in this position within xsl:iterate")
	}

	// XTSE3125: xsl:break must not have both select and body.
	selectAttr, hasSelect := elem.GetAttribute(xslAttrSelect)
	hasBody := false

	for ch := elem.FirstChild(); ch != nil; ch = ch.NextSibling() {
		if chElem, ok := ch.(*xdm.Element); ok {
			if chElem.URI() == lexicon.NamespaceXSLT && chElem.LocalName() == lexicon.XSLTElementFallback {
				continue
			}

			hasBody = true

			break
		}

		if txt, ok := ch.(*xdm.Text); ok {
			t := xdm.CharacterData(txt)
			if !c.shouldStripText(ctx, t) {
				hasBody = true
				break
			}
		}
	}

	if hasSelect && hasBody {
		return nil, staticError(errCodeXTSE3125, "xsl:break must not have both select attribute and sequence constructor")
	}

	inst := &breakInst{}

	if hasSelect {
		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = expr
	} else {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}

		inst.Body = body
	}

	return inst, nil
}

// compileNextIteration compiles an xsl:next-iteration element.
func (c *compiler) compileNextIteration(ctx context.Context, elem *xdm.Element) (instruction, error) {
	// XTSE0010: xsl:next-iteration must be lexically within xsl:iterate.
	if c.iterateDepth == 0 {
		return nil, staticError(errCodeXTSE0010, "xsl:next-iteration must be within xsl:iterate")
	}
	// XTSE3120: xsl:next-iteration must not be inside an element constructor,
	// xsl:for-each, or other non-iterate-body position.
	if !c.breakAllowed {
		return nil, staticError(errCodeXTSE3120, "xsl:next-iteration is not allowed in this position within xsl:iterate")
	}

	inst := &nextIterationInst{}

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			if err := validateStructuralText(child, elem); err != nil {
				return nil, err
			}

			continue
		}

		if childElem.URI() != lexicon.NamespaceXSLT || childElem.LocalName() != lexicon.XSLTElementWithParam {
			return nil, staticError(errCodeXTSE0010, "unexpected child element in xsl:next-iteration: %s", childElem.Name())
		}

		wp, err := c.compileWithParam(ctx, childElem)
		if err != nil {
			return nil, err
		}

		if wp == nil {
			continue
		}

		if err := checkDuplicateWithParam(inst.Params, wp); err != nil {
			return nil, err
		}

		inst.Params = append(inst.Params, wp)
	}

	return inst, nil
}

// compileAccumulator compiles an xsl:accumulator top-level element.
func (c *compiler) compileAccumulator(ctx context.Context, elem *xdm.Element) error {
	defer c.pushElementVersion(elem)()

	savedNamespaces := c.pushElementNamespaces(ctx, elem)
	defer func() { c.nsBindings = savedNamespaces }()

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return staticError(errCodeXTSE0010, "xsl:accumulator requires name attribute")
	}

	expandedName := resolveQName(name, c.nsBindings)

	acc := &accumulatorDef{
		Name:       expandedName,
		As:         getAttr(elem, "as"),
		Streamable: xsdBoolTrue(getAttr(elem, nameStreamable)),
		ImportPrec: c.importPrec,
	}

	if acc.As != "" {
		typeName, err := xpath.ParseSequenceType(acc.As)
		if err != nil {
			return err
		}

		defaultNamespace, _ := c.declarationDefaultNamespace(elem)

		bound, err := xpath.BindSequenceType(ctx, typeName, inScopeNamespaces(elem), defaultNamespace)
		if err != nil {
			return err
		}

		acc.Type = &bound
	}

	// Read initial-value attribute (required per XSLT 3.0 §10.4)
	iv, hasInitial := elem.GetAttribute("initial-value")
	if !hasInitial {
		return staticError(errCodeXTSE0010, "xsl:accumulator %q requires initial-value attribute", expandedName)
	}

	initialExpr, err := c.compileXPath(iv, c.nsBindings)
	if err != nil {
		return err
	}

	acc.Initial = initialExpr

	// Scan children for accumulator-rule elements
	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			if err := validateStructuralText(child, elem); err != nil {
				return err
			}

			continue
		}

		if childElem.URI() != lexicon.NamespaceXSLT || childElem.LocalName() != lexicon.XSLTElementAccumulatorRule {
			return staticError(errCodeXTSE0010, "unexpected child element in xsl:accumulator: %s", childElem.Name())
		}

		if err := c.compileAccumulatorRule(ctx, acc, childElem); err != nil {
			return err
		}
	}

	// XTSE0010: an accumulator must have at least one rule
	if len(acc.Rules) == 0 {
		return staticError(errCodeXTSE0010, "xsl:accumulator %q must have at least one xsl:accumulator-rule", expandedName)
	}

	if existing, exists := c.stylesheet.accumulators[expandedName]; exists {
		// Accumulators in different packages may share the same name.
		// A local accumulator shadows a package-imported one.
		if existing.FromPackage {
			c.stylesheet.accumulators[expandedName] = acc
			return nil
		}
		// XTSE3350: duplicate accumulator name at the same import precedence.
		// Defer the error — a higher-precedence accumulator may resolve the
		// conflict later (e.g. imported file has duplicates but the importer
		// provides its own override).
		if acc.ImportPrec == existing.ImportPrec {
			existing.conflictDuplicate = true
			return nil
		}
		// Different import precedence: highest wins, lower is silently discarded.
		// A higher-precedence declaration also clears any deferred duplicate
		// conflict from a lower level.
		if acc.ImportPrec > existing.ImportPrec {
			c.stylesheet.accumulators[expandedName] = acc
		}

		return nil
	}

	c.stylesheet.accumulatorOrder = append(c.stylesheet.accumulatorOrder, expandedName)
	c.stylesheet.accumulators[expandedName] = acc

	return nil
}

// compileAccumulatorRule compiles an xsl:accumulator-rule element.
func (c *compiler) compileAccumulatorRule(ctx context.Context, parent *accumulatorDef, elem *xdm.Element) error {
	defer c.pushElementVersion(elem)()

	matchAttr, hasMatch := elem.GetAttribute(lexicon.AttrMatch)
	if !hasMatch {
		return staticError(errCodeXTSE0010, "xsl:accumulator-rule requires match attribute")
	}

	matchPat, err := c.compilePattern(matchAttr, elem, c.xpathDefaultNS, c.hasXPathDefaultNS)
	if err != nil {
		return err
	}

	rule := &accumulatorRule{
		Match: matchPat,
		Phase: getAttr(elem, "phase"),
		New:   getAttr(elem, "new-value") == lexicon.ValueYes,
	}

	// Default phase is "start" per XSLT 3.0 spec §14
	if rule.Phase == "" {
		rule.Phase = "start"
	}

	selectAttr, hasSelect := elem.GetAttribute(xslAttrSelect)
	if hasSelect {
		if err := c.validateEmptyElement(ctx, elem, "xsl:accumulator-rule"); err != nil {
			return err
		}

		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return err
		}

		rule.Select = expr
	} else {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return err
		}

		rule.Body = body
	}

	parent.Rules = append(parent.Rules, rule)

	return nil
}

// compileMerge compiles an xsl:merge element.
func (c *compiler) compileMerge(ctx context.Context, elem *xdm.Element) (instruction, error) {
	inst := &mergeInst{}

	actionCount := 0

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			if err := validateStructuralText(child, elem); err != nil {
				return nil, err
			}

			continue
		}

		if childElem.URI() != lexicon.NamespaceXSLT {
			return nil, staticError(errCodeXTSE0010, "unexpected child element in xsl:merge: %s", childElem.Name())
		}
		// Resolve shadow attributes on child XSLT elements (e.g.
		// _select="..." on xsl:merge-source) before compilation.
		if err := c.resolveShadowAttributes(ctx, childElem); err != nil {
			return nil, err
		}

		switch childElem.LocalName() {
		case lexicon.XSLTElementMergeSource:
			if actionCount != 0 {
				return nil, staticError(errCodeXTSE0010, "xsl:merge-source must precede xsl:merge-action")
			}

			src, err := c.compileMergeSource(ctx, childElem)
			if err != nil {
				return nil, err
			}

			inst.Sources = append(inst.Sources, src)
		case lexicon.XSLTElementMergeAction:
			actionCount++
			if actionCount > 1 {
				return nil, staticError(errCodeXTSE0010, "xsl:merge must have at most one xsl:merge-action child")
			}

			body, err := c.compileChildren(ctx, childElem)
			if err != nil {
				return nil, err
			}

			inst.Action = body
		case lexicon.XSLTElementFallback:
			// xsl:fallback is allowed only after xsl:merge-action (XTSE0010).
			if actionCount == 0 {
				return nil, staticError(errCodeXTSE0010, "xsl:fallback in xsl:merge must follow xsl:merge-action")
			}

			continue
		default:
			return nil, staticError(errCodeXTSE0010, "unexpected child element xsl:%s in xsl:merge", childElem.LocalName())
		}
	}

	if actionCount == 0 {
		return nil, staticError(errCodeXTSE0010, "xsl:merge requires an xsl:merge-action child")
	}

	if err := validateMergeComponents(inst); err != nil {
		return nil, err
	}

	return inst, nil
}

func validateMergeComponents(inst *mergeInst) error {
	if len(inst.Sources) == 0 {
		return staticError(errCodeXTSE0010, "xsl:merge requires at least one xsl:merge-source child")
	}

	// XTSE2200: all merge-sources must have the same number of merge-keys.
	if len(inst.Sources) > 1 {
		keyCount := len(inst.Sources[0].Keys)
		for i := 1; i < len(inst.Sources); i++ {
			if len(inst.Sources[i].Keys) != keyCount {
				return staticError(errCodeXTSE2200, "all xsl:merge-source children must have the same number of xsl:merge-key children")
			}
		}
	}

	// XTSE0020: merge-source name must be a valid xs:QName.
	for _, src := range inst.Sources {
		if src.Name != "" && !xmlchar.IsValidQName(src.Name) {
			return staticError(errCodeXTSE0020, "xsl:merge-source @name %q is not a valid xs:QName", src.Name)
		}
	}

	// XTSE3190: duplicate xsl:merge-source names.
	seenNames := make(map[string]struct{})

	for _, src := range inst.Sources {
		name := src.Name
		if name == "" {
			// Implicit name is the position, so no duplicate check needed for unnamed
			continue
		}

		if _, ok := seenNames[name]; ok {
			return staticError(errCodeXTSE3190, "duplicate xsl:merge-source name %q", name)
		}

		seenNames[name] = struct{}{}
	}

	// Streamability checks when any merge-source has streamable="yes".
	if err := mergeStreamCheck(inst); err != nil {
		return err
	}

	return nil
}

func mergeStreamCheck(inst *mergeInst) error {
	hasStreamable := false

	for _, src := range inst.Sources {
		if src.StreamableAttr {
			hasStreamable = true
			break
		}
	}

	if !hasStreamable {
		return nil
	}
	// XTSE3470: merge-key order/data-type must not be AVTs within
	// a streamable merge-source.
	for _, src := range inst.Sources {
		if !src.StreamableAttr {
			continue
		}

		for _, mk := range src.Keys {
			if mk.OrderAVT != nil && avtIsDynamic(mk.OrderAVT) {
				return staticError(errCodeXTSE3470, "xsl:merge-key @order must not be an AVT when xsl:merge-source is streamable")
			}

			if mk.DataTypeAVT != nil && avtIsDynamic(mk.DataTypeAVT) {
				return staticError(errCodeXTSE3470, "xsl:merge-key @data-type must not be an AVT when xsl:merge-source is streamable")
			}
		}
	}

	return nil
}

func avtIsDynamic(value *avt) bool {
	_, static := value.staticValue()
	return !static
}

func (c *compiler) compileMergeSource(ctx context.Context, elem *xdm.Element) (*mergeSource, error) {
	defer c.pushElementVersion(elem)()

	if err := c.validateXSLTAttrs(ctx, elem, mergeSourceAllowedAttrs); err != nil {
		return nil, err
	}

	src := &mergeSource{
		Name:       getAttr(elem, xslAttrName),
		BaseURI:    stylesheetBaseURI(elem, c.baseURI, c.moduleRoot),
		Validation: basicValidation(getAttr(elem, nameValidation)),
	}
	// The type attribute names a schema type against which each source
	// document is validated; the resulting PSVI type annotations flow onto
	// the selected merge items (mirroring xsl:source-document).
	if typeName := getAttr(elem, lexicon.AttrType); typeName != "" {
		src.TypeName = resolveQName(typeName, c.nsBindings)
	}

	if err := c.compileMergeSourceSelection(elem, src); err != nil {
		return nil, err
	}

	// Parse xsl:merge-key children — only xsl:merge-key is allowed
	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			if err := validateStructuralText(child, elem); err != nil {
				return nil, err
			}

			continue
		}

		if childElem.URI() == lexicon.NamespaceXSLT && childElem.LocalName() == lexicon.XSLTElementMergeKey {
			mk, err := c.compileMergeKey(ctx, childElem)
			if err != nil {
				return nil, err
			}

			src.Keys = append(src.Keys, mk)
		} else {
			// Any non-merge-key child is an error
			return nil, staticError(errCodeXTSE0010, "unexpected child element in xsl:merge-source: %s", childElem.Name())
		}
	}

	if len(src.Keys) == 0 {
		return nil, staticError(errCodeXTSE0010, "xsl:merge-source requires at least one xsl:merge-key child")
	}

	if src.Select == nil {
		return nil, staticError(errCodeXTSE0010, "xsl:merge-source requires a select attribute")
	}

	// XTSE3195: for-each-source and for-each-item are mutually exclusive.
	if src.ForEachSource != nil && src.ForEachItem != nil {
		return nil, staticError(errCodeXTSE3195, "xsl:merge-source must not have both for-each-source and for-each-item attributes")
	}

	// XTSE3430: sort-before-merge="yes" is incompatible with streamable="yes".
	// Fall back to non-streaming, raising no fatal error.
	if src.SortBeforeMerge && src.StreamableAttr {
		src.StreamableAttr = false
	}

	return src, nil
}

func (c *compiler) compileMergeSourceSelection(elem *xdm.Element, src *mergeSource) error {
	if streamRaw := getAttr(elem, nameStreamable); streamRaw != "" {
		streamVal := strings.TrimSpace(streamRaw)
		if v, ok := parseXSDBool(streamVal); ok {
			src.StreamableAttr = v
		} else {
			return staticError(errCodeXTSE0020, "%q is not a valid value for xsl:merge-source/@streamable", streamVal)
		}
	}

	if sortAttr, hasSBM := elem.GetAttribute("sort-before-merge"); hasSBM {
		sortVal := strings.TrimSpace(sortAttr)
		if v, ok := parseXSDBool(sortVal); ok {
			src.SortBeforeMerge = v
		} else {
			return staticError(errCodeXTSE0020, "%q is not a valid value for xsl:merge-source/@sort-before-merge", sortVal)
		}
	}

	// for-each-source: XPath expression evaluating to sequence of URI strings
	if fes, present := elem.GetAttribute("for-each-source"); present {
		expr, err := c.compileXPath(fes, c.nsBindings)
		if err != nil {
			return err
		}

		src.ForEachSource = expr
	}

	// for-each-item: XPath expression evaluating to sequence of items (nodes)
	if fei, present := elem.GetAttribute("for-each-item"); present {
		expr, err := c.compileXPath(fei, c.nsBindings)
		if err != nil {
			return err
		}

		src.ForEachItem = expr
	}

	// select: XPath expression for selecting items from each source
	if sel, present := elem.GetAttribute(xslAttrSelect); present {
		expr, err := c.compileXPath(sel, c.nsBindings)
		if err != nil {
			return err
		}

		src.Select = expr
	}

	if useAccumulators := getAttr(elem, nameUseAccumulators); useAccumulators != "" {
		for name := range strings.FieldsSeq(useAccumulators) {
			src.UseAccumulators = append(src.UseAccumulators, resolveQName(name, c.nsBindings))
		}
	}

	return nil
}

// compileMergeKey compiles an xsl:merge-key element.
func (c *compiler) compileMergeKey(ctx context.Context, elem *xdm.Element) (*mergeKey, error) {
	defer c.pushElementVersion(elem)()

	if err := validateMergeKeyAttrs(elem); err != nil {
		return nil, err
	}

	mk := &mergeKey{
		Order:   sortOrderAscending,
		BaseURI: stylesheetBaseURI(elem, c.baseURI, c.moduleRoot),
	}

	if err := c.compileMergeKeyCollation(elem, mk); err != nil {
		return nil, err
	}

	selAttr, hasSelect := elem.GetAttribute(xslAttrSelect)

	if hasSelect && c.hasStreamingSequenceBody(ctx, elem) {
		return nil, staticError(errCodeXTSE3200, "xsl:merge-key must not have both select attribute and sequence constructor")
	}

	if hasSelect {
		expr, err := c.compileXPath(selAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		mk.Select = expr
	} else {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}

		mk.Body = body
	}

	if err := c.compileMergeKeyOrdering(elem, mk); err != nil {
		return nil, err
	}

	return mk, nil
}

func validateMergeKeyAttrs(elem *xdm.Element) error {
	// XTSE0090: validate permitted attributes on xsl:merge-key.
	for _, attr := range elem.Attributes() {
		if attr.URI() != "" {
			continue // namespace-qualified attributes are allowed
		}

		switch attr.LocalName() {
		case xslAttrSelect, nameOrder, nameCollation, nameDataType, lexicon.AttrLang, nameCaseOrder:
			// permitted
		default:
			return staticError(errCodeXTSE0090, "attribute %q is not permitted on xsl:merge-key", attr.LocalName())
		}
	}

	return nil
}

func (c *compiler) compileMergeKeyCollation(elem *xdm.Element, key *mergeKey) error {
	for _, option := range []struct {
		name   string
		target **avt
		flag   uint8
	}{
		{nameCollation, &key.CollationAVT, mergeAttrCollation},
		{lexicon.AttrLang, &key.LangAVT, mergeAttrLang},
		{nameCaseOrder, &key.CaseOrderAVT, mergeAttrCaseOrder},
	} {
		if err := c.compileMergeKeyOption(elem, key, option.name, option.target, option.flag); err != nil {
			return err
		}
	}

	return nil
}

func (c *compiler) compileMergeKeyOrdering(elem *xdm.Element, key *mergeKey) error {
	for _, option := range []struct {
		name   string
		target **avt
		flag   uint8
	}{
		{nameOrder, &key.OrderAVT, mergeAttrOrder},
		{nameDataType, &key.DataTypeAVT, mergeAttrDataType},
	} {
		if err := c.compileMergeKeyOption(elem, key, option.name, option.target, option.flag); err != nil {
			return err
		}
	}

	return nil
}

func (c *compiler) compileMergeKeyOption(elem *xdm.Element, key *mergeKey, name string, target **avt, flag uint8) error {
	value, present := elem.GetAttribute(name)
	if !present {
		return nil
	}

	compiled, err := c.compileAVT(value, c.nsBindings)
	if err != nil {
		return err
	}

	if literal, static := compiled.staticValue(); static {
		if err := validateLiteralSortOption(name, literal); err != nil {
			return err
		}
	}

	key.specified |= flag
	*target = compiled

	return nil
}

// sortAccumulatorOrder topologically sorts the accumulator evaluation order
// so that accumulators that depend on others (via accumulator-before/after
// calls in their rule expressions) are evaluated after their dependencies.
// This ensures that when accumulator A calls accumulator-after('B'), B's
// value for the current node has already been computed.
// Cyclic dependencies (including self-references) are detected and the
// involved accumulators are marked with CyclicDeps=true for XTDE3400.
func sortAccumulatorOrder(ss *Stylesheet) {
	deps := accumulatorDependencies(ss)

	// Detect self-cycles: an accumulator that references itself.
	for name := range deps {
		if _, selfRef := deps[name][name]; selfRef {
			if acc, ok := ss.accumulators[name]; ok {
				acc.CyclicDeps = true
			}

			delete(deps[name], name)
		}
	}

	if len(ss.accumulatorOrder) <= 1 {
		return
	}

	// DFS-based topological sort with cycle detection.
	// States: 0=unvisited, 1=visiting (on stack), 2=done
	state := make(map[string]int)

	var (
		sorted []string
		visit  func(string) bool
	)

	visit = func(name string) bool {
		switch state[name] {
		case 2:
			return false // already processed
		case 1:
			return true // cycle detected
		}

		state[name] = 1
		for dep := range deps[name] {
			if visit(dep) {
				// Mark all accumulators in the cycle
				if acc, ok := ss.accumulators[name]; ok {
					acc.CyclicDeps = true
				}

				if acc, ok := ss.accumulators[dep]; ok {
					acc.CyclicDeps = true
				}
			}
		}

		state[name] = 2
		sorted = append(sorted, name)

		return false
	}
	for _, name := range ss.accumulatorOrder {
		visit(name)
	}

	ss.accumulatorOrder = sorted
}

func accumulatorDependencies(ss *Stylesheet) map[string]map[string]struct{} {
	// Build dependency graph by scanning rule select expressions for
	// accumulator-before('name') and accumulator-after('name') calls.
	deps := make(map[string]map[string]struct{})
	for name, acc := range ss.accumulators {
		deps[name] = make(map[string]struct{})

		for _, rule := range acc.Rules {
			var src string
			if rule.Select != nil {
				src = rule.Select.String()
			}

			if src == "" {
				continue
			}

			for _, ref := range extractAccumulatorRefs(src) {
				resolved := resolveQName(ref, ss.namespaces)
				if _, ok := ss.accumulators[resolved]; ok {
					deps[name][resolved] = struct{}{}
				}
			}
		}
	}

	return deps
}

// extractAccumulatorRefs extracts accumulator names referenced by
// accumulator-before('name') and accumulator-after('name') calls
// from an XPath expression source string.
func extractAccumulatorRefs(src string) []string {
	var refs []string

	for _, prefix := range []string{"accumulator-before(", "accumulator-after("} {
		s := src
		for {
			idx := strings.Index(s, prefix)
			if idx < 0 {
				break
			}

			s = s[idx+len(prefix):]

			s = strings.TrimSpace(s)
			if len(s) == 0 {
				break
			}
			// Expect a quote character
			q := s[0]
			if q != '\'' && q != '"' {
				break
			}

			s = s[1:]

			end := strings.IndexByte(s, q)
			if end < 0 {
				break
			}

			refs = append(refs, s[:end])
			s = s[end+1:]
		}
	}

	return refs
}

// mergeSourceAllowedAttrs reports attributes permitted on xsl:merge-source.
func mergeSourceAllowedAttrs(name string) bool {
	switch name {
	case xslAttrName, "for-each-item", "for-each-source", xslAttrSelect, nameStreamable, "sort-before-merge", nameUseAccumulators, nameValidation, lexicon.AttrType:
		return true
	default:
		return false
	}
}
