// Copyright (c) 2026 xmlsec contributors. MIT License.

package xslt

import (
	"context"
	"math"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// XPath10FunctionArity reports the shared XPath core or XSLT 1.0 host arity.
func XPath10FunctionArity(name string) ([2]int, bool) {
	if v, ok := xpath.XPath10FunctionArity(name); ok {
		return v, true
	}

	v, ok := lookupXSLT10FunctionArity(name)

	return v, ok
}

// XSLT10ElementAttributes shares the immutable grammar metadata with XMLDSig
// preflight; its resource policy is enforced independently of language syntax.
func XSLT10ElementAttributes(name string) (string, bool) {
	v, ok := lookupXSLT10Attribute(name)
	return v, ok
}

func lookupXSLT10Attribute(key string) (string, bool) {
	switch key {
	case nameStylesheet, fnNameTransform:
		return "version id extension-element-prefixes exclude-result-prefixes", true
	case nameImport, nameInclude:
		return lexicon.AttrHref, true
	case nameFallback, "apply-imports", "choose", "otherwise", "comment":
		return "", true
	case nameTemplate:
		return "match name priority mode", true
	case nameOutput:
		return "method version encoding omit-xml-declaration standalone doctype-public doctype-system cdata-section-elements indent media-type", true
	case nameStripSpace, namePreserveSpace:
		return nameElements, true
	case nameKey2:
		return "name match use", true
	case "decimal-format":
		return "name decimal-separator grouping-separator infinity minus-sign NaN percent per-mille zero-digit digit pattern-separator", true
	case "namespace-alias":
		return "stylesheet-prefix result-prefix", true
	case nameAttributeSet:
		return "name use-attribute-sets", true
	case nameVariable, nameParam, "with-param":
		return textNameSelect, true
	case "apply-templates":
		return "select mode", true
	case "call-template", "processing-instruction":
		return xslAttrName, true
	case "for-each", "copy-of":
		return xslAttrSelect, true
	case nameSort:
		return "select lang data-type order case-order", true
	case "if", "when":
		return lexicon.AttrTest, true
	case "value-of":
		return "select disable-output-escaping", true
	case lexicon.MethodText:
		return nameDisableOutputEscaping, true
	case "copy":
		return nameUseAttributeSets, true
	case "element":
		return "name namespace use-attribute-sets", true
	case "attribute":
		return "name namespace", true
	case lexicon.TypeNumber:
		return "level count from value format lang letter-value grouping-separator grouping-size", true
	case "message":
		return "terminate", true
	}

	var zero string

	return zero, false
}

func xslt10Attributes(key string) string { value, _ := lookupXSLT10Attribute(key); return value }

func forwards10(e *xdm.Element) bool {
	for n := xdm.Node(e); n != nil; n = n.Parent() {
		if elem, ok := n.(*xdm.Element); ok {
			version := ""
			if elem.URI() != lexicon.NamespaceXSLT {
				version, _ = elem.GetAttributeNS(lexicon.SerializationVersion, lexicon.NamespaceXSLT)
			} else if elem.LocalName() == nameStylesheet || elem.LocalName() == fnNameTransform {
				version = getAttr(elem, lexicon.SerializationVersion)
			}

			if version != "" {
				v, err := strconv.ParseFloat(version, 64)
				return err == nil && v > 1
			}
		}
	}

	return false
}

// Reuse the shared grammar's closed enumerations. A future value of an
// optional attribute is ignored by a 1.0 processor in forwards mode (§2.5).
// AVTs are validated after evaluation by their instruction's runtime handler.
func ignoredOptional10(e *xdm.Element, a *xdm.Attribute) bool {
	if e.URI() != lexicon.NamespaceXSLT || a.URI() != "" || !forwards10(e) {
		return false
	}

	def := elementXSLTDef(e.LocalName()).attrs[a.LocalName()]
	// Only these closed enumerations are AVTs in 1.0. In particular,
	// xsl:message/@terminate became an AVT in a later language version.
	avt10 := e.LocalName() == nameSort && contains10Word("order case-order", a.LocalName()) || e.LocalName() == lexicon.TypeNumber && a.LocalName() == nameLetterValue
	if e.LocalName() == nameOutput && a.LocalName() == lexicon.SerializationStandalone {
		def.values = []string{lexicon.ValueYes, "no"}
	}

	if e.LocalName() == nameOutput && a.LocalName() == lexicon.SerializationMethod && !strings.Contains(a.Value(), ":") {
		def.values = []string{lexicon.MethodXML, lexicon.MethodHTML, lexicon.MethodText}
	}

	if def.required || len(def.values) == 0 || avt10 && strings.ContainsAny(a.Value(), "{}") {
		return false
	}

	for _, value := range def.values {
		if strings.TrimSpace(a.Value()) == value {
			return false
		}
	}

	return true
}

// prepareModule privately normalizes stylesheet text, expands simplified modules
// and modern shadow attributes, or hides future attributes from older processors. The original
// source remains available to document(""); unchanged modules reuse their storage.
func prepareModule(ctx context.Context, doc *xdm.Document, processor int) (*xdm.Document, error) {
	root := doc.DocumentElement()

	ignored := unknownAttribute20
	if processor >= 30 {
		ignored = func(elem *xdm.Element, attr *xdm.Attribute) bool {
			return elem.URI() == lexicon.NamespaceXSLT && attr.URI() == "" && strings.HasPrefix(attr.LocalName(), "_")
		}
	}

	if processor == 10 {
		if err := validateModuleRoot10(root); err != nil {
			return nil, err
		}

		ignored = unknownAttribute10
	}

	needed, err := inspectModulePreparation(ctx, root, false, func(elem *xdm.Element, attr *xdm.Attribute) bool {
		conditional := attr.LocalName() == xslAttrUseWhen && (elem.URI() == lexicon.NamespaceXSLT && attr.URI() == "" || elem.URI() != lexicon.NamespaceXSLT && attr.URI() == lexicon.NamespaceXSLT)
		return ignored(elem, attr) || processor >= 20 && conditional
	})
	if err != nil {
		return nil, err
	}

	if root.URI() != lexicon.NamespaceXSLT {
		if _, simplified := root.GetAttributeNS(lexicon.SerializationVersion, lexicon.NamespaceXSLT); simplified {
			prepared, err := expandSimplifiedModule(ctx, doc, root)
			if err != nil {
				return nil, err
			}

			if processor < 30 {
				filterModuleAttributes(prepared.DocumentElement(), ignored)
			}

			return prepared, ctx.Err()
		}
	}

	if !needed {
		return doc, nil
	}

	clone, err := tree.Clone(ctx, doc.Reference().Document())
	if err != nil {
		return nil, err
	}

	if err := normalizeStylesheetDocument(ctx, clone); err != nil {
		return nil, err
	}

	prepared, err := xdm.WrapDocument(ctx, clone)
	if err != nil {
		return nil, err
	}

	prepared.SetURL(doc.URL())

	if processor < 30 {
		filterModuleAttributes(prepared.DocumentElement(), ignored)
	}

	return prepared, ctx.Err()
}

// unknownAttribute10 identifies attributes hidden from the shared compiler in
// forwards-compatible modules, including future optional enumeration values.
func unknownAttribute10(elem *xdm.Element, attr *xdm.Attribute) bool {
	if ignoredOptional10(elem, attr) {
		return true
	}

	if elem.URI() == lexicon.NamespaceXSLT {
		return attr.URI() == "" && !contains10Word(xslt10Attributes(elem.LocalName()), attr.LocalName())
	}

	return attr.URI() == lexicon.NamespaceXSLT && !contains10Word("version extension-element-prefixes exclude-result-prefixes use-attribute-sets", attr.LocalName())
}

func inspectModulePreparation(ctx context.Context, elem *xdm.Element, needed bool, ignored func(*xdm.Element, *xdm.Attribute) bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return needed, err
	}

	for _, attr := range elem.Attributes() {
		needed = needed || ignored(elem, attr)
	}

	for child := range xdm.Children(elem) {
		if err := xpath.Charge(ctx, 1); err != nil {
			return needed, err
		}

		if child.Type() == xdm.CommentNode || child.Type() == xdm.ProcessingInstructionNode ||
			(child.Type() == xdm.TextNode || child.Type() == xdm.CDATASectionNode) && isXMLWhitespaceOnly(xdm.CharacterData(child)) {
			needed = true
		}
	}

	for child := range xdm.ChildElements(elem) {
		var err error

		needed, err = inspectModulePreparation(ctx, child, needed, ignored)
		if err != nil {
			return needed, err
		}
	}

	return needed, nil
}

// normalizeStylesheetDocument applies XSLT §4.3 to a private draft before
// conditional/static processing. The original document remains available to
// document("") and callers that supplied a stylesheet node.
func normalizeStylesheetDocument(ctx context.Context, doc *tree.Document) error {
	root := &tree.Node{Kind: tree.DocumentNode, Children: tree.Children(doc)}
	if err := normalizeStylesheetChildren(ctx, root, false); err != nil {
		return err
	}

	tree.SetDraftChildren(doc, root.Children)

	return nil
}

func normalizeStylesheetChildren(ctx context.Context, parent *tree.Node, preserve bool) error {
	for _, attr := range parent.Attrs {
		if attr.Name.Space == lexicon.NamespaceXML && attr.Name.Local == lexicon.AttrSpace {
			switch attr.Value {
			case lexicon.SpacePreserve:
				preserve = true
			case lexicon.SpaceDefault:
				preserve = false
			}
		}
	}

	// Remove comments/PIs and coalesce text before deciding which whitespace
	// nodes to remove; a whitespace fragment can belong to significant text.
	children := parent.Children
	merged := children[:0]

	var text *tree.Node

	for _, child := range children {
		if err := xpath.Charge(ctx, 1); err != nil {
			return err
		}

		if child.Kind == tree.CommentNode || child.Kind == tree.PINode {
			continue
		}

		if child.Kind == tree.TextNode {
			if text != nil {
				tree.AppendTextData(text, child.Data)
				continue
			}

			text = child
		} else {
			text = nil
		}

		merged = append(merged, child)
	}

	clear(children[len(merged):])

	kept := merged[:0]
	for i, child := range merged {
		if stripStylesheetWhitespace(parent, merged, i, preserve) {
			continue
		}

		if child.Kind == tree.ElementNode {
			if err := normalizeStylesheetChildren(ctx, child, preserve); err != nil {
				return err
			}
		}

		kept = append(kept, child)
	}

	clear(merged[len(kept):])
	parent.Children = kept

	return nil
}

func stripStylesheetWhitespace(parent *tree.Node, siblings []*tree.Node, index int, preserve bool) bool {
	child := siblings[index]
	if child.Kind != tree.TextNode || !tree.IsXMLSpace(child.Data) {
		return false
	}

	if parent.Name.Space == lexicon.NamespaceXSLT && parent.Name.Local == lexicon.XSLTElementText {
		return false
	}

	if !preserve || stylesheetWhitespaceParent(parent) {
		return true
	}

	if index+1 < len(siblings) {
		next := siblings[index+1]
		if next.Name.Space == lexicon.NamespaceXSLT {
			switch next.Name.Local {
			case lexicon.XSLTElementParam, lexicon.XSLTElementSort, nameContextItem, lexicon.XSLTElementOnCompletion:
				return true
			}
		}
	}

	return index > 0 && siblings[index-1].Name.Space == lexicon.NamespaceXSLT && siblings[index-1].Name.Local == lexicon.XSLTElementCatch
}

func stylesheetWhitespaceParent(parent *tree.Node) bool {
	if parent.Name.Space != lexicon.NamespaceXSLT {
		return false
	}

	switch parent.Name.Local {
	case lexicon.XSLTElementAccumulator, lexicon.XSLTElementAnalyzeString, lexicon.XSLTElementApplyImports, lexicon.XSLTElementApplyTemplates, lexicon.XSLTElementAttributeSet, lexicon.XSLTElementCallTemplate, lexicon.XSLTElementCharacterMap, lexicon.XSLTElementChoose, lexicon.XSLTElementEvaluate, lexicon.XSLTElementFork, lexicon.XSLTElementMerge, lexicon.XSLTElementMergeSource, lexicon.XSLTElementMode, lexicon.XSLTElementNextIteration, lexicon.XSLTElementNextMatch, lexicon.XSLTElementOverride, lexicon.XSLTElementPackage, nameStylesheet, fnNameTransform, lexicon.XSLTElementUsePackage:
		return true
	}

	return false
}

func filterModuleAttributes(elem *xdm.Element, ignored func(*xdm.Element, *xdm.Attribute) bool) {
	for _, attr := range elem.Attributes() {
		if ignored(elem, attr) {
			elem.RemoveAttributeNS(attr.LocalName(), attr.URI())
		}
	}

	for child := range xdm.ChildElements(elem) {
		filterModuleAttributes(child, ignored)
	}
}

func (c *compiler) sourceModule(doc *xdm.Document) *xdm.Document {
	if original := c.moduleSources[doc]; original != nil {
		return original
	}

	return doc
}

func (c *compiler) checkFragment10(doc *xdm.Document, fragment string) error {
	if fragment == "" || c.stylesheet.processorLanguage() != 10 {
		return nil
	}

	root := findElementByID(c.sourceModule(doc), fragment)
	if root == nil {
		return staticError("XTSE0010", "no embedded stylesheet with id=%q", fragment)
	}

	return checkLanguage10(root)
}

func checkLanguage10(root *xdm.Element) error {
	return checkElementLanguage10(root, root, 1)
}

func checkElementLanguage10(root, elem *xdm.Element, inherited float64) error {
	effective, err := elementLanguageVersion10(root, elem, inherited)
	if err != nil {
		return err
	}

	if elem.URI() == lexicon.NamespaceXSLT {
		if err := checkXSLTElement10(elem, effective); err != nil {
			return err
		}
	} else if err := checkLiteralResultAttributes10(elem, effective); err != nil {
		return err
	}

	for child := range xdm.ChildElements(elem) {
		if err := checkElementLanguage10(root, child, effective); err != nil {
			return err
		}
	}

	return nil
}

func elementLanguageVersion10(root, elem *xdm.Element, inherited float64) (float64, error) {
	effective := inherited

	if version, ok := elem.GetAttributeNS(lexicon.SerializationVersion, lexicon.NamespaceXSLT); ok {
		n, err := strconv.ParseFloat(version, 64)
		if err != nil || !(n > 0) || math.IsInf(n, 0) {
			return 0, staticError("XTSE0110", "invalid XSLT version")
		}

		effective = n
	}

	if elem == root && elem.URI() == lexicon.NamespaceXSLT {
		effective, _ = strconv.ParseFloat(getAttr(root, lexicon.SerializationVersion), 64)
	}

	return effective, nil
}

func checkXSLTElement10(elem *xdm.Element, effective float64) error {
	allowed, known := lookupXSLT10Attribute(elem.LocalName())
	if !known && effective <= 1 {
		return staticError("XTSE0010", "xsl:%s is unavailable in XSLT 1.0", elem.LocalName())
	}

	for _, attr := range elem.Attributes() {
		if attr.URI() == lexicon.NamespaceXML {
			continue
		}

		if attr.URI() == lexicon.NamespaceXSLT {
			return staticError("XTSE0090", "XSLT attributes on XSLT elements")
		}

		if attr.URI() == "" && effective <= 1 && !contains10Word(allowed, attr.LocalName()) {
			return staticError("XTSE0090", "%s on xsl:%s is unavailable in XSLT 1.0", attr.LocalName(), elem.LocalName())
		}
	}

	return nil
}

func checkLiteralResultAttributes10(elem *xdm.Element, effective float64) error {
	for _, attr := range elem.Attributes() {
		if attr.URI() == lexicon.NamespaceXSLT && effective <= 1 && !contains10Word("version extension-element-prefixes exclude-result-prefixes use-attribute-sets", attr.LocalName()) {
			return staticError("XTSE0090", "unknown XSLT 1.0 literal-result attribute %s", attr.LocalName())
		}
	}

	return nil
}

func contains10Word(words, word string) bool {
	for v := range strings.FieldsSeq(words) {
		if v == word {
			return true
		}
	}

	return false
}

func (c *compiler) forwardsCompatible(version string) bool {
	comparison, valid := compareLanguageVersion(version, c.stylesheet.processorLanguage()/10)
	return valid && comparison > 0
}

func lookupXSLT10FunctionArity(key string) ([2]int, bool) {
	switch key {
	case "current":
		return [2]int{0, 0}, true
	case fnNameDocument:
		return [2]int{1, 2}, true
	case nameKey2:
		return [2]int{2, 2}, true
	case lexicon.FnFormatNumber:
		return [2]int{2, 3}, true
	case lexicon.FnGenerateID, nameUnparsedEntityURI, funcSystemProperty, "element-available", "function-available":
		return [2]int{1, 1}, true
	}

	var zero [2]int

	return zero, false
}

// A 1.0 stylesheet exposes only its host's 1.0 arities and conversions, while
// delegating execution to the same host functions used by newer stylesheets.
type function10 struct {
	name   string
	target xpath.Function
}

func (f function10) MinArity() int { return xslt10Functions(f.name)[0] }

func (f function10) MaxArity() int { return xslt10Functions(f.name)[1] }

func (f function10) Call(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	switch f.name {
	case fnNameDocument:
		if err := prepareDocumentArguments10(ctx, args); err != nil {
			return nil, err
		}
	case nameKey2:
		if err := prepareKeyArguments10(ctx, args); err != nil {
			return nil, err
		}
	case lexicon.FnGenerateID:
		if err := prepareGenerateIDArgument10(args); err != nil {
			return nil, err
		}
	case lexicon.FnFormatNumber:
		if err := prepareFormatNumberArguments10(ctx, args); err != nil {
			return nil, err
		}
	case funcSystemProperty, "element-available", "function-available", nameUnparsedEntityURI:
		if err := convertStringArgument10(ctx, args, 0); err != nil {
			return nil, err
		}
	}

	return f.target.Call(ctx, args)
}

func convertStringArgument10(ctx context.Context, args []xdm.Sequence, index int) error {
	value, err := xpath.XPath10String(args[index])
	if err != nil {
		return err
	}

	if err := xpath.ChargeString(ctx, len(value)); err != nil {
		return err
	}

	args[index] = xdm.SingleString(value)

	return nil
}

func isNodeSet10(seq xdm.Sequence) bool {
	_, ok := xdm.NodesFrom(seq)
	return ok
}

func prepareDocumentArguments10(ctx context.Context, args []xdm.Sequence) error {
	if !isNodeSet10(args[0]) {
		if err := convertStringArgument10(ctx, args, 0); err != nil {
			return err
		}
	}

	if len(args) > 1 && !isNodeSet10(args[1]) {
		return staticError(lexicon.ErrXPTY0004, "document() second argument must be a node-set")
	}

	return nil
}

func prepareKeyArguments10(ctx context.Context, args []xdm.Sequence) error {
	if err := convertStringArgument10(ctx, args, 0); err != nil {
		return err
	}

	if !isNodeSet10(args[1]) {
		return convertStringArgument10(ctx, args, 1)
	}

	var values xdm.ItemSlice

	for item := range xdm.SequenceItems(args[1]) {
		value, err := xpath.XPath10String(xdm.ItemSlice{item})
		if err != nil {
			return err
		}

		if err := xpath.ChargeString(ctx, len(value)); err != nil {
			return err
		}

		values = append(values, xdm.AtomicValue{TypeName: xdm.TypeString, Value: value})
	}

	args[1] = values

	return nil
}

func prepareGenerateIDArgument10(args []xdm.Sequence) error {
	if !isNodeSet10(args[0]) {
		return staticError(lexicon.ErrXPTY0004, "generate-id() requires a node-set")
	}

	if args[0] != nil && args[0].Len() > 1 {
		args[0] = xdm.ItemSlice{args[0].Get(0)}
	}

	return nil
}

func prepareFormatNumberArguments10(ctx context.Context, args []xdm.Sequence) error {
	number, err := xpath.XPath10Number(args[0])
	if err != nil {
		return err
	}

	args[0] = xdm.SingleAtomic(number)
	for index := 1; index < len(args); index++ {
		if err := convertStringArgument10(ctx, args, index); err != nil {
			return err
		}
	}

	return nil
}

func xslt10Functions(key string) [2]int { value, _ := lookupXSLT10FunctionArity(key); return value }

func checkPattern10(ast xpath.Expr) error {
	switch e := ast.(type) {
	case *xpath.LocationPath:
		return checkPattern10(*e)
	case *xpath.RootExpr:
		return nil
	case *xpath.PathExpr:
		return checkPattern10(*e)
	case *xpath.FunctionCall:
		return checkPattern10(*e)
	case xpath.RootExpr:
		return nil
	case xpath.LocationPath:
		for _, step := range e.Steps {
			if step.Axis != xpath.AxisChild && step.Axis != xpath.AxisAttribute && step.Axis != xpath.AxisDescendantOrSelf {
				return staticError("XTSE0340", "invalid XSLT 1.0 pattern axis")
			}
		}

		return nil
	case xpath.FunctionCall:
		return checkFunctionPattern10(e)
	case xpath.PathExpr:
		if err := checkPattern10(e.Filter); err != nil {
			return err
		}

		if e.Path != nil {
			return checkPattern10(*e.Path)
		}

		return nil
	}

	return staticError("XTSE0340", "invalid XSLT 1.0 match pattern")
}

func checkFunctionPattern10(e xpath.FunctionCall) error {
	if e.Prefix != "" || e.Name != "id" && e.Name != nameKey2 {
		return staticError("XTSE0340", "invalid XSLT 1.0 match pattern")
	}

	want := 1
	if e.Name == nameKey2 {
		want = 2
	}

	if len(e.Args) != want {
		return staticError("XTSE0340", "invalid XSLT 1.0 match pattern")
	}

	for _, arg := range e.Args {
		v, ok := arg.(xpath.LiteralExpr)
		if !ok {
			return staticError("XTSE0340", "id/key patterns require string literals")
		}

		if _, ok := v.Value.(string); !ok {
			return staticError("XTSE0340", "id/key patterns require string literals")
		}
	}

	return nil
}

func finalizeOutput10(s *Stylesheet) {
	if s.processorLanguage() != 10 {
		return
	}

	if s.outputs[""] == nil {
		s.outputs[""] = defaultOutputDef()
	}

	for _, out := range s.outputs {
		out.languageVersion = 10
		if out.HTMLVersion == "" {
			out.HTMLVersion = "4.0"
		}
	}
}

// validateModuleRoot10 leaves embedded modules for validation after their
// fragment root is selected, while checking ordinary and simplified modules now.
func validateModuleRoot10(root *xdm.Element) error {
	_, simplified := root.GetAttributeNS(lexicon.SerializationVersion, lexicon.NamespaceXSLT)
	if root.URI() == lexicon.NamespaceXSLT || simplified {
		return checkLanguage10(root)
	}

	return nil
}
