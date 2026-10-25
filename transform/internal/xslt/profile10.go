// Copyright (c) 2026 xmlsec contributors. MIT License.
package xslt

import (
	"context"
	"math"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// XPath10FunctionArity reports the shared XPath core or XSLT 1.0 host arity.
func XPath10FunctionArity(name string) ([2]int, bool) {
	if v, ok := xpath.XPath10FunctionArity(name); ok {
		return v, true
	}

	v, ok := lookupxslt10Functions(name)

	return v, ok
}

// XSLT10ElementAttributes shares the immutable grammar metadata with XMLDSig
// preflight; its resource policy is enforced independently of language syntax.
func XSLT10ElementAttributes(name string) (string, bool) {
	v, ok := lookupxslt10Attributes(name)
	return v, ok
}

func lookupxslt10Attributes(key string) (string, bool) {
	switch key {
	case nameStylesheet, fnNameTransform:
		return "version id extension-element-prefixes exclude-result-prefixes", true
	case nameImport, nameInclude:
		return nameHref, true
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
		return nameTest2, true
	case "value-of":
		return "select disable-output-escaping", true
	case methodText:
		return nameDisableOutputEscaping, true
	case "copy":
		return nameUseAttributeSets, true
	case "element":
		return "name namespace use-attribute-sets", true
	case "attribute":
		return "name namespace", true
	case nameNumber:
		return "level count from value format lang letter-value grouping-separator grouping-size", true
	case "message":
		return "terminate", true
	}

	var zero string

	return zero, false
}

func xslt10Attributes(key string) string { value, _ := lookupxslt10Attributes(key); return value }

func forwards10(e *xdm.Element) bool {
	for n := xdm.Node(e); n != nil; n = n.Parent() {
		if elem, ok := n.(*xdm.Element); ok {
			version := ""
			if elem.URI() != lexicon.NamespaceXSLT {
				version, _ = elem.GetAttributeNS(paramVersion, lexicon.NamespaceXSLT)
			} else if elem.LocalName() == nameStylesheet || elem.LocalName() == fnNameTransform {
				version = getAttr(elem, paramVersion)
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
	avt10 := e.LocalName() == nameSort && contains10Word("order case-order", a.LocalName()) || e.LocalName() == nameNumber && a.LocalName() == "letter-value"
	if e.LocalName() == nameOutput && a.LocalName() == paramStandalone {
		def.values = []string{nameYes, "no"}
	}

	if e.LocalName() == nameOutput && a.LocalName() == paramMethod && !strings.Contains(a.Value(), ":") {
		def.values = []string{methodXML, methodHTML, methodText}
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

// prepareModule10 hides future attributes from the shared compiler without
// changing the source document exposed by document(""). Ordinary 1.0 modules
// need no copy. The project tree remains the sole storage/clone implementation.
func prepareModule10(ctx context.Context, doc *xdm.Document) (*xdm.Document, error) {
	root := doc.DocumentElement()
	if err := validateModuleRoot10(root); err != nil {
		return nil, err
	}

	needed, err := inspectModuleAttributes10(ctx, root, false)
	if err != nil {
		return nil, err
	}

	if !needed {
		return doc, nil
	}

	clone, err := tree.Clone(ctx, doc.Reference().Document())
	if err != nil {
		return nil, err
	}

	prepared, err := xdm.WrapDocument(ctx, clone)
	if err != nil {
		return nil, err
	}

	prepared.SetURL(doc.URL())

	filterModuleAttributes10(prepared.DocumentElement())

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

func inspectModuleAttributes10(ctx context.Context, elem *xdm.Element, needed bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return needed, err
	}

	for _, attr := range elem.Attributes() {
		needed = needed || unknownAttribute10(elem, attr)
	}

	for child := range xdm.ChildElements(elem) {
		var err error

		needed, err = inspectModuleAttributes10(ctx, child, needed)
		if err != nil {
			return needed, err
		}
	}

	return needed, nil
}

func filterModuleAttributes10(elem *xdm.Element) {
	for _, attr := range elem.Attributes() {
		if unknownAttribute10(elem, attr) {
			elem.RemoveAttributeNS(attr.LocalName(), attr.URI())
		}
	}

	for child := range xdm.ChildElements(elem) {
		filterModuleAttributes10(child)
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

	if version, ok := elem.GetAttributeNS(paramVersion, lexicon.NamespaceXSLT); ok {
		n, err := strconv.ParseFloat(version, 64)
		if err != nil || !(n > 0) || math.IsInf(n, 0) {
			return 0, staticError("XTSE0110", "invalid XSLT version")
		}

		effective = n
	}

	if elem == root && elem.URI() == lexicon.NamespaceXSLT {
		effective, _ = strconv.ParseFloat(getAttr(root, paramVersion), 64)
	}

	return effective, nil
}

func checkXSLTElement10(elem *xdm.Element, effective float64) error {
	allowed, known := lookupxslt10Attributes(elem.LocalName())
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
	if c.stylesheet.processorLanguage() == 10 {
		v, err := strconv.ParseFloat(version, 64)
		return err == nil && v > 1
	}

	return isForwardsCompatible(version)
}

func lookupxslt10Functions(key string) ([2]int, bool) {
	switch key {
	case "current":
		return [2]int{0, 0}, true
	case fnNameDocument:
		return [2]int{1, 2}, true
	case nameKey2:
		return [2]int{2, 2}, true
	case "format-number":
		return [2]int{2, 3}, true
	case nameGenerateId, nameUnparsedEntityUri, funcSystemProperty, "element-available", "function-available":
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
	case nameGenerateId:
		if err := prepareGenerateIDArgument10(args); err != nil {
			return nil, err
		}
	case "format-number":
		if err := prepareFormatNumberArguments10(ctx, args); err != nil {
			return nil, err
		}
	case funcSystemProperty, "element-available", "function-available", nameUnparsedEntityUri:
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
		return staticError("XPTY0004", "document() second argument must be a node-set")
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
		return staticError("XPTY0004", "generate-id() requires a node-set")
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

func xslt10Functions(key string) [2]int { value, _ := lookupxslt10Functions(key); return value }

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
	_, simplified := root.GetAttributeNS(paramVersion, lexicon.NamespaceXSLT)
	if root.URI() == lexicon.NamespaceXSLT || simplified {
		return checkLanguage10(root)
	}

	return nil
}
