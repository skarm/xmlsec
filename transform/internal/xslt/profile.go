// Copyright (c) 2026 xmlsec contributors. MIT License.

package xslt

import (
	"errors"
	"math/big"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// ErrLanguageUnsupported identifies features outside the modern Basic profile.
var ErrLanguageUnsupported = errors.New("unsupported XSLT language profile")

// CheckLanguage checks the declared stylesheet version against the selected language
// profile and the compiler's syntax rules. Schema awareness is unavailable. Streaming
// declarations do not change the materialized-tree execution model or establish W3C
// streamability.
func CheckLanguage(d *xdm.Document, want int) (int, error) {
	return CheckProcessorLanguage(d, want, 0)
}

// CheckProcessorLanguage keeps the processor selection separate from the
// principal declaration and each element's effective compatibility version.
func CheckProcessorLanguage(d *xdm.Document, want, processor int) (int, error) {
	if d == nil || d.DocumentElement() == nil {
		return 0, ErrLanguageUnsupported
	}

	root := d.DocumentElement()

	declaration, hasDeclaration := elementXSLTVersionAttribute(root)
	if _, shadow := root.GetAttribute("_version"); shadow && root.URI() == lexicon.NamespaceXSLT && (processor == 0 || processor == 30) {
		declaration = lexicon.XSLTVersion30
		hasDeclaration = true
	}

	if !hasDeclaration {
		if root.URI() == lexicon.NamespaceXSLT {
			return 0, staticError("XTSE0010", "stylesheet requires a version attribute")
		}

		return 0, staticError("XTSE0150", "simplified stylesheet requires xsl:version")
	}

	version, valid := declaredLanguageProfile(declaration)
	if !valid {
		return 0, staticError("XTSE0110", "invalid XSLT version")
	}

	if want != 0 && want != version {
		return 0, ErrLanguageUnsupported
	}

	if processor == 0 {
		processor = version
	}

	if processor != 10 && processor != 20 && processor != 30 {
		return 0, ErrLanguageUnsupported
	}

	if processor == 20 && root.URI() == lexicon.NamespaceXSLT && root.LocalName() == namePackage {
		return 0, staticError("XTSE0010", "xsl:package requires an XSLT 3.0 processor")
	}

	if processor == 10 {
		return processor, checkLanguage10(root)
	}

	return processor, checkModernLanguage(root, declaration, processor)
}

func compareLanguageVersion(version string, boundary int) (int, bool) {
	version = strings.Trim(version, " \t\r\n")
	for number, text := range []string{lexicon.XSLTVersion10, lexicon.XSLTVersion20, lexicon.XSLTVersion30} {
		if version == text {
			return number + 1 - boundary, true
		}
	}

	if !isXSDecimal(version) {
		return 0, false
	}

	number, ok := new(big.Rat).SetString(version)
	if !ok {
		return 0, false
	}

	return number.Cmp(big.NewRat(int64(boundary), 1)), true
}

func declaredLanguageProfile(version string) (int, bool) {
	if comparison, valid := compareLanguageVersion(version, 2); !valid {
		return 0, false
	} else if comparison < 0 {
		return 10, true
	}

	if comparison, _ := compareLanguageVersion(version, 3); comparison < 0 {
		return 20, true
	}

	return 30, true
}

func languageVersionAttribute(elem *xdm.Element) string {
	return elementXSLTVersion(elem)
}

func checkModernLanguage(elem *xdm.Element, effective string, selected int) error {
	if isUserDefinedDataElement(elem) {
		return nil
	}

	// Conditional inclusion and shadow attributes are evaluated by the compiler
	// with the declaration's static scope. Validate this subtree after that pass.
	if hasConditionalAttributes(elem, selected) {
		return nil
	}

	own, hasOwn := elementXSLTVersionAttribute(elem)
	if _, shadow := elem.GetAttribute("_version"); shadow && elem.URI() == lexicon.NamespaceXSLT && selected >= 30 {
		own = lexicon.XSLTVersion30
		hasOwn = true
	}

	if hasOwn {
		if _, valid := declaredLanguageProfile(own); !valid {
			return staticError("XTSE0110", "invalid XSLT version")
		}

		effective = own
	}

	comparison, _ := compareLanguageVersion(effective, selected/10)

	forwards := comparison > 0
	if elem.URI() == lexicon.NamespaceXSLT && unavailableInstruction(elem.LocalName(), selected) && forwards {
		return checkFutureInstructionFallbacks(elem, effective, selected)
	}

	if err := checkExtensionNamespaceAttribute(elem, selected); err != nil {
		return err
	}

	if selected >= 20 {
		if err := checkExclusionNamespaceAttribute(elem); err != nil {
			return err
		}
	}

	if err := checkModernElementLanguage(elem, selected); err != nil {
		return err
	}

	for child := elem.FirstChild(); child != nil; child = child.NextSibling() {
		if element, ok := child.(*xdm.Element); ok {
			if err := checkModernLanguage(element, effective, selected); err != nil {
				return err
			}
		}
	}

	return nil
}

func checkFutureInstructionFallbacks(elem *xdm.Element, effective string, selected int) error {
	for child := range xdm.ChildElements(elem) {
		if child.URI() == lexicon.NamespaceXSLT && child.LocalName() == "fallback" {
			if err := checkModernLanguage(child, effective, selected); err != nil {
				return err
			}
		}
	}

	return nil
}

func checkExclusionNamespaceAttribute(elem *xdm.Element) error {
	value := getAttr(elem, nameExcludeResultPrefixes)
	if elem.URI() != lexicon.NamespaceXSLT {
		value, _ = elem.GetAttributeNS(nameExcludeResultPrefixes, lexicon.NamespaceXSLT)
	}

	if value == "" || value == lexicon.ModeAll {
		return nil
	}

	namespaces := inScopeNamespaces(elem)
	for prefix := range strings.FieldsSeq(value) {
		if prefix == lexicon.ModeDefault {
			if namespaces[""] == "" {
				return staticError(errCodeXTSE0809, "#default in exclude-result-prefixes but no default namespace is declared")
			}
		} else if namespaces[prefix] == "" {
			return staticError(errCodeXTSE0808, "undeclared namespace prefix %q in exclude-result-prefixes", prefix)
		}
	}

	return nil
}

func checkExtensionNamespaceAttribute(elem *xdm.Element, selected int) error {
	value := getAttr(elem, nameExtensionElementPrefixes)

	if elem.URI() != lexicon.NamespaceXSLT {
		value, _ = elem.GetAttributeNS(nameExtensionElementPrefixes, lexicon.NamespaceXSLT)
	}

	if value == "" {
		return nil
	}

	namespaces := inScopeNamespaces(elem)

	for prefix := range strings.FieldsSeq(value) {
		lookup := prefix
		if prefix == lexicon.ModeDefault {
			lookup = ""
		}

		uri := namespaces[lookup]
		if uri == "" {
			return staticError(errCodeXTSE1430, "undeclared extension namespace prefix %q", prefix)
		}

		if selected >= 30 && isReservedNamespace(uri) {
			return staticError("XTSE0085", "reserved namespace %q must not be used as an extension namespace", uri)
		}
	}

	return nil
}

func unavailableInstruction(name string, selected int) bool {
	def, known := lookupXSLTElement(name)
	minimum := minXSLTElementVersion(name)

	return !known || selected < 30 && (def.since30 || minimum == lexicon.XSLTVersion30) || selected < 20 && minimum == lexicon.XSLTVersion20
}

func checkModernElementLanguage(elem *xdm.Element, effective int) error {
	if elem.URI() != lexicon.NamespaceXSLT {
		return checkLiteralElementLanguage(elem, effective)
	}

	name := elem.LocalName()

	def, known := lookupXSLTElement(name)
	if known && (def.since30 || minXSLTElementVersion(name) == lexicon.XSLTVersion30) && effective < 30 {
		return staticError("XTSE0010", "xsl:%s requires XSLT 3.0", name)
	}

	if err := checkComponentNames(elem, effective); err != nil {
		return err
	}

	for _, attribute := range elem.Attributes() {
		if attribute.URI() != "" {
			continue
		}

		if effective < 30 && unknownAttribute20(elem, attribute) {
			continue
		}

		if _, shadow := elem.GetAttribute("_" + attribute.LocalName()); shadow && effective >= 30 {
			continue
		}

		if err := checkModernAttributeLanguage(attribute.LocalName(), xdm.CharacterData(attribute), name, def, effective); err != nil {
			return err
		}
	}

	if effective < 30 {
		for attribute, metadata := range def.attrs {
			if _, present := elem.GetAttribute(attribute); metadata.optional30 && !present {
				return staticError("XTSE0010", "xsl:%s requires %s in XSLT 2.0", name, attribute)
			}
		}
	}

	return checkStaticBindingPosition(elem, effective)
}

func checkStaticBindingPosition(elem *xdm.Element, processor int) error {
	name := elem.LocalName()
	if processor >= 30 && (name == nameVariable || name == nameParam) && xsdBoolTrue(getAttr(elem, nameStatic)) {
		parent, ok := elem.Parent().(*xdm.Element)
		if !ok || parent.URI() != lexicon.NamespaceXSLT || !isStaticBindingParent(parent.LocalName()) {
			return staticError(errCodeXTSE0020, "static=\"yes\" is permitted only on a top-level variable or parameter")
		}
	}

	return nil
}

// Stylesheet object names cannot use a reserved namespace. The 3.0
// namespace set is larger than the set reserved by an actual 2.0 processor.
func checkComponentNames(element *xdm.Element, processor int) error {
	if element.LocalName() == nameTemplate {
		for _, mode := range strings.FieldsFunc(getAttr(element, lexicon.AttrMode), xmlchar.IsSpace) {
			if err := checkReservedComponentName(element, mode, processor, false); err != nil {
				return err
			}
		}
	}

	switch element.LocalName() {
	case nameTemplate, lexicon.XSLTElementMode, nameAttributeSet, nameKey2, lexicon.XSLTElementDecimalFormat,
		nameVariable, nameParam, lexicon.XSLTElementFunction, nameOutput, lexicon.XSLTElementCharacterMap, lexicon.XSLTElementAccumulator:
	default:
		return nil
	}

	if _, shadow := element.GetAttribute("_name"); shadow && processor >= 30 {
		return nil
	}

	name, present := element.GetAttribute(xslAttrName)
	if !present {
		return nil // Required-attribute checks retain their own prescribed errors.
	}

	name = strings.TrimFunc(name, xmlchar.IsSpace)
	if element.LocalName() == lexicon.XSLTElementMode && name == modeUnnamed {
		return nil
	}

	if !xmlchar.IsValidQName(name) && !(processor >= 30 && isValidEQName(name)) {
		return staticError(errCodeXTSE0020, "invalid name %q on xsl:%s", name, element.LocalName())
	}

	return checkReservedComponentName(element, name, processor, element.LocalName() == nameTemplate)
}

func checkReservedComponentName(element *xdm.Element, name string, processor int, namedTemplate bool) error {
	expanded := resolveQName(name, inScopeNamespaces(element))
	if namedTemplate && processor >= 30 && expanded == xdm.ClarkName(lexicon.NamespaceXSLT, "initial-template") {
		return nil
	}

	if strings.HasPrefix(expanded, "{") {
		uri, _, _ := strings.Cut(expanded[1:], "}")
		if reservedNamespaceForProcessor(uri, processor) {
			return staticError(errCodeXTSE0080, "name %q on xsl:%s uses a reserved namespace", name, element.LocalName())
		}
	}

	return nil
}

func isStaticBindingParent(name string) bool {
	return name == lexicon.XSLTElementStylesheet || name == lexicon.XSLTElementTransform || name == lexicon.XSLTElementPackage || name == lexicon.XSLTElementOverride
}

func checkLiteralElementLanguage(elem *xdm.Element, effective int) error {
	for _, attribute := range elem.Attributes() {
		if unknownAttribute20(elem, attribute) {
			continue
		}

		if attribute.URI() != lexicon.NamespaceXSLT {
			continue
		}

		if requiresSchemaAttribute(attribute.LocalName(), xdm.CharacterData(attribute), effective) {
			return staticError("XTSE1660", "xsl:%s requires a schema-aware processor", attribute.LocalName())
		}

		if effective < 30 && attribute.LocalName() == nameExpandText {
			return staticError("XTSE0090", "expand-text requires XSLT 3.0")
		}

		if effective == 20 && attribute.LocalName() == nameInheritNamespaces {
			if err := checkBoolean20Attribute(nameInheritNamespaces, xdm.CharacterData(attribute), elementXSLTDef(lexicon.XSLTElementElement)); err != nil {
				return err
			}
		}
	}

	return nil
}

func elementForwardsCompatible(elem *xdm.Element, processor int) bool {
	for node := xdm.Node(elem); node != nil; node = node.Parent() {
		parent, ok := node.(*xdm.Element)
		if !ok {
			continue
		}

		if version := languageVersionAttribute(parent); version != "" {
			comparison, valid := compareLanguageVersion(version, processor/10)
			return valid && comparison > 0
		}
	}

	return false
}

// unknownAttribute20 identifies future vocabulary ignored by a 2.0 processor
// only when this element explicitly inherits forwards-compatible processing.
func unknownAttribute20(elem *xdm.Element, attr *xdm.Attribute) bool {
	if !elementForwardsCompatible(elem, 20) {
		return false
	}

	if elem.URI() == lexicon.NamespaceXSLT {
		if attr.URI() != "" {
			return attr.URI() == lexicon.NamespaceXSLT
		}
	} else if attr.URI() != lexicon.NamespaceXSLT {
		return false
	}

	name := attr.LocalName()
	if strings.HasPrefix(name, "_") || name == nameExpandText || name == nameDefaultMode || name == nameUseAccumulators {
		return true
	}

	if elem.URI() != lexicon.NamespaceXSLT {
		return !lreAllowedXSLTAttrs(name)
	}

	metadata, declared := elementXSLTDef(elem.LocalName()).attrs[name]

	return metadata.since30 || metadata.processor30 || !declared && !xsltStandardAttrs(name)
}

func checkModernAttributeLanguage(attribute, value, element string, def elementDef, effective int) error {
	if requiresSchemaAttribute(attribute, value, effective) {
		return staticError("XTSE1660", "%s on xsl:%s requires a schema-aware processor", attribute, element)
	}

	if effective < 30 && attribute == lexicon.SerializationMethod && (value == "json" || value == "adaptive") {
		return staticError("XTSE0020", "serialization method requires XSLT 3.0")
	}

	if strings.HasPrefix(attribute, "_") && effective < 30 {
		return staticError("XTSE0090", "shadow attributes require XSLT 3.0")
	}

	if effective < 30 {
		if metadata, ok := def.attrs[attribute]; ok && (metadata.since30 || metadata.processor30) {
			return staticError("XTSE0090", "%s on xsl:%s requires XSLT 3.0", attribute, element)
		}

		if attribute == nameExpandText || attribute == nameDefaultMode || attribute == nameUseAccumulators {
			return staticError("XTSE0090", "%s requires XSLT 3.0", attribute)
		}

		if err := checkBoolean20Attribute(attribute, value, def); err != nil {
			return err
		}
	}

	if attribute == "as" {
		sequenceType, err := xpath.ParseSequenceType(value)
		if element == nameContextItem || element == lexicon.XSLTElementGlobalContextItem {
			if err != nil || sequenceType.Void || sequenceType.Occurrence != xdm.OccurrenceExactlyOne {
				return staticError(errCodeXTSE0020, "xsl:%s/@as must be an ItemType: %q", element, value)
			}
		}

		if err != nil {
			return staticErrorCause(lexicon.ErrXPST0003, err, "invalid xsl:%s/@as: %v", element, err)
		}

		return xpath.CheckTypeLanguage(sequenceType, map[int]int{20: 20, 30: 31}[effective])
	}

	return nil
}

// XSLT 2.0 enumerates yes/no; XSLT 3.0 admits the four xs:boolean aliases,
// including when a 3.0 processor evaluates a version="2.0" stylesheet.
func parseXSLTBoolean(value string, processor int) (bool, bool) {
	if processor == 20 {
		switch strings.Trim(value, " \t\r\n") {
		case lexicon.ValueYes:
			return true, true
		case lexicon.ValueNo:
			return false, true
		default:
			return false, false
		}
	}

	return parseXSDBool(value)
}

func checkBoolean20Attribute(name, value string, def elementDef) error {
	metadata, known := def.attrs[name]
	if !known || !slices.Contains(metadata.values, lexicon.ValueYes) || !slices.Contains(metadata.values, lexicon.ValueNo) {
		return nil
	}

	if metadata.avt && strings.ContainsAny(value, "{}") {
		return nil // Computed values are checked after AVT evaluation.
	}

	value = strings.Trim(value, " \t\r\n")
	if value == lexicon.ValueOmit && slices.Contains(metadata.values, lexicon.ValueOmit) {
		return nil
	}

	if _, valid := parseXSLTBoolean(value, 20); !valid {
		return staticError(errCodeXTSE0020, "%q is not a valid XSLT 2.0 value for @%s", value, name)
	}

	return nil
}

func requiresSchemaAttribute(attribute, value string, processor int) bool {
	value = strings.TrimSpace(value)

	switch attribute {
	case nameValidation, nameDefaultValidation:
		return value == validationStrict || processor == 20 && (value == validationLax || value == validationPreserve)
	case lexicon.AttrType:
		return true
	case nameTyped:
		return value == validationStrict || value == lexicon.ValueYes || value == lexicon.ValueTrue || value == "1"
	default:
		return false
	}
}

// basicValidation applies the non-schema-aware rules in XSLT 3.0 §27.1.
// Preserve and lax have the same effect as strip without schema annotations.
func basicValidation(value string) string {
	switch value {
	case validationPreserve, validationLax:
		return validationStrip
	default:
		return value
	}
}
