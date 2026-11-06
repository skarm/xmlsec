// Derived from knroy/go-xml at eb327e4c08420169c271e94708b5c803d58e91f9.
// Copyright (c) 2026 Komol Nath Roy. MIT License; see licenses/MIT-knroy-go-xml.txt at the repository root.

package xslt

import "github.com/skarm/xmlsec/internal/lexicon"

// Numeric XML Schema boolean aliases shared by grammar validation and runtime parsing; each language profile still decides whether those aliases are admissible, and format pictures keep their independent spellings.
const (
	booleanDigitFalse = "0"
	booleanDigitTrue  = "1"
)

// elementDef describes XSLT element syntax from the normative XSLT 3.0
// summaries (§2.2): allowed attributes, required fields, AVTs and closed values.
// The table supports XTSE0010 (invalid element), XTSE0020 (invalid attribute
// value) and XTSE0090 (invalid attribute). Expression, QName and URI semantics
// require separate checks. Draft spellings marked removed30 remain explicit so
// current-version processing rejects them as unknown attributes.
type elementDef struct {
	// attrs maps an attribute name to what the summary says about it.
	attrs map[string]attrDef
	// since30 rejects a 3.0-only element in a 2.0 module with XTSE0010.
	// Forwards-compatible processing (§3.9) is handled before this check.
	since30 bool
}

type attrDef struct {
	required bool
	// values is the closed set of permitted values, or nil when the summary
	// does not give one.
	values []string
	// avt marks an attribute value template, whose value may be "{...}" and
	// therefore cannot be checked against the enumeration at compile time.
	avt bool
	// since30 rejects a 3.0-only attribute in a 2.0 module with XTSE0090.
	since30 bool
	// optional30 makes a required 2.0 attribute optional in 3.0, where a
	// sequence constructor can replace xsl:sequence/@select.
	optional30 bool
	// processor30 gates an attribute on the processor's version rather than
	// the module's @version.
	processor30 bool
	// eqnameOK permits a namespaced EQName in addition to enumerated tokens,
	// as in xsl:function/@streamability (REC H.1).
	eqnameOK bool
	// uri requires a syntactically valid URI reference, including relative URIs.
	uri bool
	// nmtoken checks the lexical form independently of processor support:
	// an unsupported normalization form fails later with SESU0011.
	nmtoken bool
	// removed30 marks withdrawn draft names; forwards-compatible processing
	// may ignore them like other unknown attributes.
	removed30 bool
}

// componentKinds is the closed REC H.1 vocabulary for xsl:expose and xsl:accept.
func componentKinds() []string {
	return []string{nameTemplate, lexicon.XSLTElementFunction, nameVariable, nameAttributeSet, lexicon.AttrMode, "*"}
}

// lookupXSLTElement constructs the requested element's grammar definition.
func lookupXSLTElement(name string) (elementDef, bool) {
	for _, lookup := range []func(string) (elementDef, bool){
		lookupRootXSLTElement,
		lookupPackageXSLTElement,
		lookupDeclarationXSLTElement,
		lookupConstructorXSLTElement,
		lookupTemplateControlXSLTElement,
		lookupSequenceControlXSLTElement,
		lookupDynamicXSLTElement,
		lookupSerializationXSLTElement,
	} {
		if definition, ok := lookup(name); ok {
			return definition, true
		}
	}

	return elementDef{}, false
}

func elementXSLTDef(name string) elementDef {
	definition, _ := lookupXSLTElement(name)
	return definition
}

func lookupRootXSLTElement(name string) (elementDef, bool) {
	switch name {
	case nameStylesheet:
		return elementDef{attrs: map[string]attrDef{
			lexicon.AttrID:               {},
			nameExtensionElementPrefixes: {},
			nameExcludeResultPrefixes:    {},
			xslAttrVersion:               {required: true},
			nameXPathDefaultNamespace:    {},
			nameDefaultValidation:        {values: []string{validationPreserve, validationStrip}},
			nameDefaultCollation:         {},
			nameInputTypeAnnotations:     {values: []string{validationPreserve, validationStrip, validationUnspecified}},
		}}, true
	case namePackage:
		return elementDef{since30: true, attrs: map[string]attrDef{
			lexicon.AttrID:               {},
			xslAttrName:                  {},
			namePackageVersion:           {},
			xslAttrVersion:               {required: true},
			nameDeclaredModes:            {values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse}},
			nameExtensionElementPrefixes: {},
			nameExcludeResultPrefixes:    {},
			nameXPathDefaultNamespace:    {},
			nameDefaultValidation:        {values: []string{validationPreserve, validationStrip}},
			nameDefaultCollation:         {},
			nameDefaultMode:              {},
			nameInputTypeAnnotations:     {values: []string{validationPreserve, validationStrip, validationUnspecified}},
			// Packages are composed through xsl:use-package, not this draft attribute.
			nameUsePackage: {removed30: true},
		}}, true
	case lexicon.XSLTElementTransform:
		return elementDef{attrs: map[string]attrDef{
			lexicon.AttrID:               {},
			nameExtensionElementPrefixes: {},
			nameExcludeResultPrefixes:    {},
			xslAttrVersion:               {required: true},
			nameXPathDefaultNamespace:    {},
			nameDefaultValidation:        {values: []string{validationPreserve, validationStrip}},
			nameDefaultCollation:         {},
			nameInputTypeAnnotations:     {values: []string{validationPreserve, validationStrip, validationUnspecified}},
		}}, true
	}

	return elementDef{}, false
}

func lookupPackageXSLTElement(name string) (elementDef, bool) {
	switch name {
	// Package composition is available only in XSLT 3.0 (§3.5).
	case nameUsePackage:
		return elementDef{since30: true, attrs: map[string]attrDef{
			xslAttrName:        {required: true},
			namePackageVersion: {},
		}}, true
	case lexicon.XSLTElementExpose:
		return elementDef{since30: true, attrs: map[string]attrDef{
			// REC H.1 restricts @component to the six component kinds.
			xslAttrComponent: {required: true, values: componentKinds()},
			xslAttrNames:     {required: true},
			// The summary (section 3.5.3.1) stops at "abstract"; unlike
			// xsl:accept's, it carries no "hidden".
			xslAttrVisibility: {required: true, values: []string{
				visPublic, visPrivate, visFinal, visAbstract,
			}},
		}}, true
	case lexicon.XSLTElementAccept:
		return elementDef{since30: true, attrs: map[string]attrDef{
			xslAttrComponent: {required: true, values: componentKinds()},
			xslAttrNames:     {required: true},
			xslAttrVisibility: {required: true, values: []string{
				visPublic, visPrivate, visFinal, visAbstract, visHidden,
			}},
		}}, true
	case xslElemOverride:
		return elementDef{since30: true, attrs: map[string]attrDef{}}, true
	case nameOriginal:
		return elementDef{since30: true, attrs: map[string]attrDef{}}, true
	}

	return elementDef{}, false
}

func lookupDeclarationXSLTElement(name string) (elementDef, bool) {
	const (
		nameAppliesTo      = "applies-to"
		nameExport         = "export"
		nameSchemaLocation = "schema-location"
		streamDeepDescent  = "deep-descent"
	)

	switch name {
	// The engine accepts xsl:mode in 2.0 modules as configuration whose
	// defaults already match 2.0. Attributes are still validated; streamable does
	// not enable W3C streaming execution.
	case lexicon.AttrMode:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:                {},
			nameStreamable:             {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			nameUseAccumulators:        {},
			nameOnNoMatch:              {values: []string{onNoMatchDeepCopy, onNoMatchShallowCopy, onNoMatchDeepSkip, onNoMatchShallowSkip, onNoMatchTextOnlyCopy, onNoMatchFail}},
			nameOnMultipleMatch:        {values: []string{onMultipleMatchUseLast, onNoMatchFail}},
			nameWarningOnNoMatch:       {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			nameWarningOnMultipleMatch: {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			// XSLT 3.0 section 6.6: @typed says whether the mode expects typed
			// input. "lax" and "strict" join the booleans, so the vocabulary is
			// not the plain yes/no one.
			nameTyped: {values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse, validationLax, validationStrict, validationUnspecified}},
			// Modes cannot declare abstract or hidden visibility (§6.6).
			// Hidden visibility is acquired through xsl:accept or xsl:expose.
			xslAttrVisibility: {values: []string{visPublic, visPrivate, visFinal}},
		}}, true
	case nameInclude:
		return elementDef{attrs: map[string]attrDef{
			lexicon.AttrHref: {required: true},
		}}, true
	case nameImport:
		return elementDef{attrs: map[string]attrDef{
			lexicon.AttrHref: {required: true},
		}}, true
	case lexicon.XSLTElementImportSchema:
		return elementDef{attrs: map[string]attrDef{
			nameNamespace:      {},
			nameSchemaLocation: {},
		}}, true
	case nameStripSpace:
		return elementDef{attrs: map[string]attrDef{
			nameElements: {required: true},
		}}, true
	case namePreserveSpace:
		return elementDef{attrs: map[string]attrDef{
			nameElements: {required: true},
		}}, true
	case lexicon.XSLTElementAccumulator:
		return elementDef{since30: true, attrs: map[string]attrDef{
			xslAttrName:      {required: true},
			nameInitialValue: {required: true},
			nameAs:           {},
			nameStreamable:   {values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse}},
			// Reject the draft attribute absent from the §18.2.1 summary.
			nameAppliesTo: {removed30: true},
		}}, true

	// An accumulator rule allows only match, phase and select (§18.2.1).
	case lexicon.XSLTElementAccumulatorRule:
		return elementDef{since30: true, attrs: map[string]attrDef{
			lexicon.AttrMatch: {required: true},
			namePhase:         {values: []string{accumulatorPhaseStart, accumulatorPhaseEnd}},
			xslAttrSelect:     {},
		}}, true
	case nameTemplate:
		return elementDef{attrs: map[string]attrDef{
			lexicon.AttrMatch: {},
			xslAttrName:       {},
			namePriority:      {},
			lexicon.AttrMode:  {},
			nameAs:            {},
			// Declared visibility excludes hidden, which is acquired through
			// xsl:accept or xsl:expose (§6.1).
			xslAttrVisibility: {since30: true, values: []string{visPublic, visPrivate, visFinal, visAbstract}},
		}}, true

	// static is valid only on top-level declarations (§9.5). Placement is
	// checked separately because the grammar table has no tree context.
	case nameVariable:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:   {required: true},
			xslAttrSelect: {},
			nameAs:        {},
			nameStatic:    {since30: true, values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse}},
			// Unlike xsl:param, xsl:variable declares visibility (§9.1).
			// Hidden visibility is acquired rather than declared.
			xslAttrVisibility: {since30: true, values: []string{visPublic, visPrivate, visFinal, visAbstract}},
		}}, true
	case nameParam:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:     {required: true},
			xslAttrSelect:   {},
			nameAs:          {},
			xslAttrRequired: {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			nameTunnel:      {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			// Reject the draft export attribute absent from §9.2.
			nameExport: {removed30: true},
			// Static parameters follow the processor's version, not the module's.
			nameStatic: {
				processor30: true,
				values:      []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse},
			},
		}}, true
	case nameAttributeSet:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:          {required: true},
			nameUseAttributeSets: {},
			// Both attributes are XSLT 3.0 additions (§10.2).
			xslAttrVisibility: {processor30: true, values: []string{
				visPublic, visPrivate, visFinal, visAbstract,
			}},
			nameStreamable: {processor30: true, values: []string{
				lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse,
			}},
		}}, true
	case lexicon.XSLTElementFunction:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName: {required: true},
			nameAs:      {},
			// A 2.0 attribute; a selected 3.0 processor also admits the four
			// boolean aliases, regardless of the module's version.
			xslElemOverride: {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			// A function cannot declare hidden visibility; xsl:expose may make it
			// hidden (REC H.1, xsl:visibility-not-hidden-type).
			xslAttrVisibility: {since30: true, values: []string{
				visPublic, visPrivate, visFinal, visAbstract,
			}},
			// REC H.1 permits a namespaced EQName as a processor-defined streamability
			// classification. This attribute is not an AVT; shadow attributes are expanded
			// before grammar validation.
			nameStreamability: {
				since30: true, eqnameOK: true,
				values: []string{
					lexicon.StreamUnclassified, lexicon.StreamAbsorbing, lexicon.StreamInspection,
					lexicon.StreamFilter, lexicon.StreamShallowDescent, streamDeepDescent, lexicon.StreamAscent,
				},
			},
			// Reject the draft identity-sensitive attribute absent from §10.3.
			nameIdentitySensitive: {removed30: true},
			// These attributes govern processor behavior, so their availability
			// follows the processor's version.
			nameOverrideExtensionFunction: {
				processor30: true,
				values:      []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse},
			},
			// The default "maybe" permits result reuse. This attribute is not an AVT.
			nameNewEachTime: {
				processor30: true,
				values:      []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse, nameMaybe},
			},
			// @cache is a boolean memoization hint, not a result-reuse guarantee (§10.3).
			nameCache: {
				processor30: true,
				values:      []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse},
			},
		}}, true
	case lexicon.XSLTElementNamespaceAlias:
		return elementDef{attrs: map[string]attrDef{
			nameStylesheetPrefix: {required: true},
			nameResultPrefix:     {required: true},
		}}, true

	// XSLT 3.0 section 3.10, a top-level declaration.
	case lexicon.XSLTElementGlobalContextItem:
		return elementDef{since30: true, attrs: map[string]attrDef{
			nameAs:          {},
			lexicon.AttrUse: {values: []string{ctxItemRequired, ctxItemOptional, ctxItemAbsent}},
			// Global context declarations are validated through the context-item entry.
		}}, true

	// XSLT 3.0 section 10.1.1, a child of xsl:template only.
	case nameContextItem:
		return elementDef{since30: true, attrs: map[string]attrDef{
			nameAs:          {},
			lexicon.AttrUse: {values: []string{ctxItemRequired, ctxItemOptional, ctxItemAbsent}},
		}}, true
	case keyLocalName:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:       {required: true},
			lexicon.AttrMatch: {required: true},
			lexicon.AttrUse:   {},
			nameCollation:     {},
			// composite selects one key for the entire use sequence instead of one
			// key per item (§6.3).
			nameComposite: {since30: true, values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse}},
		}}, true
	case lexicon.XSLTElementDecimalFormat:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:              {},
			nameDecimalSeparator:     {},
			nameGroupingSeparator:    {},
			nameInfinity:             {},
			nameMinusSign:            {},
			lexicon.DecimalFormatNaN: {},
			namePercent:              {},
			namePerMille:             {},
			nameZeroDigit:            {},
			nameDigit:                {},
			namePatternSeparator:     {},
			// exponent-separator follows the processor's version, not the module's.
			nameExponentSeparator: {processor30: true},
		}}, true
	}

	return elementDef{}, false
}

func lookupConstructorXSLTElement(name string) (elementDef, bool) {
	switch name {
	case lexicon.XSLTElementElement:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:           {required: true, avt: true},
			nameNamespace:         {avt: true},
			nameInheritNamespaces: {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			nameUseAttributeSets:  {},
			lexicon.AttrType:      {},
			nameValidation:        {values: []string{validationStrict, validationLax, validationPreserve, validationStrip}},
		}}, true
	case lexicon.XSLTElementAttribute:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:      {required: true, avt: true},
			nameNamespace:    {avt: true},
			xslAttrSelect:    {},
			nameSeparator:    {avt: true},
			lexicon.AttrType: {},
			nameValidation:   {values: []string{validationStrict, validationLax, validationPreserve, validationStrip}},
		}}, true
	case lexicon.MethodText:
		return elementDef{attrs: map[string]attrDef{
			nameDisableOutputEscaping: {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
		}}, true
	case lexicon.XSLTElementValueOf:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect:             {},
			nameSeparator:             {avt: true},
			nameDisableOutputEscaping: {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
		}}, true
	case fnNameDocument:
		return elementDef{attrs: map[string]attrDef{
			nameValidation:   {values: []string{validationStrict, validationLax, validationPreserve, validationStrip}},
			lexicon.AttrType: {},
		}}, true
	case lexicon.XSLTElementProcessingInstruction:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:   {required: true, avt: true},
			xslAttrSelect: {},
		}}, true
	case nameNamespace:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:   {required: true, avt: true},
			xslAttrSelect: {},
		}}, true
	case lexicon.XSLTElementComment:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect: {},
		}}, true
	case lexicon.XSLTElementCopy:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect:         {since30: true},
			nameCopyNamespaces:    {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			nameInheritNamespaces: {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			nameUseAttributeSets:  {},
			lexicon.AttrType:      {},
			nameValidation:        {values: []string{validationStrict, validationLax, validationPreserve, validationStrip}},
		}}, true
	case lexicon.XSLTElementCopyOf:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect:      {required: true},
			nameCopyNamespaces: {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			// XSLT 3.0 section 18.3: the copy carries the accumulator values of
			// the node it was copied from, which nothing else can supply — the
			// copy's own tree is all the document the rules would see.
			nameCopyAccumulators: {since30: true, values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			lexicon.AttrType:     {},
			nameValidation: {avt: true, values: []string{
				validationStrict, validationLax, validationPreserve, validationStrip,
			}},
		}}, true

	// The XSLT 3.0 conditional content instructions, section 8.4. Both
	// xsl:on-empty and xsl:on-non-empty share xsl:sequence's summary;
	// xsl:where-populated has no attributes at all.
	// The map constructor instructions of section 14. xsl:map takes no
	// attributes; on xsl:map-entry the key is required and select is the
	// alternative to a sequence constructor.
	case lexicon.XSLTElementMap:
		return elementDef{since30: true, attrs: map[string]attrDef{}}, true
	case lexicon.XSLTElementMapEntry:
		return elementDef{since30: true, attrs: map[string]attrDef{
			keyLocalName:  {required: true},
			xslAttrSelect: {},
		}}, true
	case lexicon.XSLTElementSequence:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect: {required: true, optional30: true},
		}}, true
	case lexicon.TypeNumber:
		return elementDef{attrs: map[string]attrDef{
			lexicon.AttrValue:     {},
			xslAttrSelect:         {},
			nameLevel:             {values: []string{nameSingle, numberMultiple, numberAny}},
			lexicon.AttrCount:     {},
			lexicon.AttrFrom:      {},
			nameFormat:            {avt: true},
			lexicon.AttrLang:      {avt: true},
			nameLetterValue:       {values: []string{numberAlphabetic, numberTraditional}, avt: true},
			nameOrdinal:           {avt: true},
			nameGroupingSeparator: {avt: true},
			nameGroupingSize:      {avt: true},
			nameStartAt:           {avt: true, since30: true},
		}}, true
	}

	return elementDef{}, false
}

func lookupTemplateControlXSLTElement(name string) (elementDef, bool) {
	switch name {
	case lexicon.XSLTElementApplyTemplates:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect:    {},
			lexicon.AttrMode: {},
		}}, true
	case lexicon.XSLTElementApplyImports:
		return elementDef{attrs: map[string]attrDef{}}, true
	case lexicon.XSLTElementNextMatch:
		return elementDef{attrs: map[string]attrDef{}}, true
	case lexicon.XSLTElementForEach:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect: {required: true},
		}}, true
	case lexicon.XSLTElementIf:
		return elementDef{attrs: map[string]attrDef{
			lexicon.AttrTest: {required: true},
		}}, true
	case lexicon.XSLTElementChoose:
		return elementDef{attrs: map[string]attrDef{}}, true
	case lexicon.XSLTElementWhen:
		return elementDef{attrs: map[string]attrDef{
			lexicon.AttrTest: {required: true},
		}}, true
	case lexicon.XSLTElementOtherwise:
		return elementDef{attrs: map[string]attrDef{}}, true
	case lexicon.XSLTElementCallTemplate:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName: {required: true},
		}}, true
	case lexicon.XSLTElementWithParam:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:   {required: true},
			xslAttrSelect: {},
			nameAs:        {},
			nameTunnel:    {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
		}}, true
	}

	return elementDef{}, false
}

func lookupSequenceControlXSLTElement(name string) (elementDef, bool) {
	const (
		nameBindGroup       = "bind-group"
		nameBindGroupingKey = "bind-grouping-key"
		nameForEachStream   = "for-each-stream"
	)

	switch name {
	// The engine also supports evaluate and iterate in 2.0 modules through
	// ordinary XPath evaluation and sequence execution.
	case lexicon.XSLTElementIterate:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect: {required: true},
		}}, true
	case lexicon.XSLTElementNextIteration:
		return elementDef{attrs: map[string]attrDef{}}, true
	case lexicon.XSLTElementBreak:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect: {},
		}}, true
	case lexicon.XSLTElementOnCompletion:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect: {},
		}}, true
	case lexicon.XSLTElementOnEmpty:
		return elementDef{since30: true, attrs: map[string]attrDef{
			xslAttrSelect: {},
		}}, true
	case lexicon.XSLTElementOnNonEmpty:
		return elementDef{since30: true, attrs: map[string]attrDef{
			xslAttrSelect: {},
		}}, true
	case lexicon.XSLTElementWherePopulated:
		return elementDef{since30: true, attrs: map[string]attrDef{}}, true

	// xsl:fork, section 16. It has no attributes; its content model is the
	// alternation in 16.1, which compileFork checks.
	case lexicon.XSLTElementFork:
		return elementDef{since30: true, attrs: map[string]attrDef{}}, true

	// Merge instructions require XSLT 3.0 (§15).
	case lexicon.XSLTElementMerge:
		return elementDef{since30: true, attrs: map[string]attrDef{}}, true
	case lexicon.XSLTElementMergeSource:
		return elementDef{since30: true, attrs: map[string]attrDef{
			xslAttrName:     {},
			nameForEachItem: {},
			// The Recommendation uses for-each-source. Reject the draft spelling
			// for-each-stream even under forwards-compatible processing.
			nameForEachSource:   {},
			nameForEachStream:   {removed30: true},
			xslAttrSelect:       {required: true},
			nameStreamable:      {values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse}},
			nameUseAccumulators: {},
			nameSortBeforeMerge: {
				values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse},
			},
			nameValidation:   {values: []string{validationStrict, validationLax, validationPreserve, validationStrip}},
			lexicon.AttrType: {},
		}}, true

	// Unlike xsl:sort, xsl:merge-key does not allow @stable (§15.5).
	case lexicon.XSLTElementMergeKey:
		return elementDef{since30: true, attrs: map[string]attrDef{
			xslAttrSelect:    {},
			lexicon.AttrLang: {avt: true},
			nameOrder:        {values: []string{sortOrderAscending, sortOrderDescending}, avt: true},
			nameCollation:    {avt: true},
			nameCaseOrder:    {values: []string{nameUpperFirst, nameLowerFirst}, avt: true},
			// { "text" | "number" | eqname }: a prefixed name selects an
			// implementation-defined type, so it passes as eqnameOK.
			nameDataType: {values: []string{lexicon.MethodText, lexicon.TypeNumber}, eqnameOK: true, avt: true},
		}}, true
	case lexicon.XSLTElementMergeAction:
		return elementDef{since30: true, attrs: map[string]attrDef{}}, true
	case nameSort:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect:    {},
			lexicon.AttrLang: {avt: true},
			nameOrder:        {values: []string{sortOrderAscending, sortOrderDescending}, avt: true},
			nameCollation:    {avt: true},
			nameStable:       {values: []string{lexicon.ValueYes, lexicon.ValueNo}, avt: true},
			nameCaseOrder:    {values: []string{nameUpperFirst, nameLowerFirst}, avt: true},
			// { "text" | "number" | eqname }: a prefixed name selects an
			// implementation-defined type, so it passes as eqnameOK.
			nameDataType: {values: []string{lexicon.MethodText, lexicon.TypeNumber}, eqnameOK: true, avt: true},
		}}, true
	case lexicon.XSLTElementPerformSort:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect: {},
		}}, true
	case lexicon.XSLTElementForEachGroup:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect:         {required: true},
			nameGroupBy:           {},
			nameGroupAdjacent:     {},
			nameGroupStartingWith: {},
			nameGroupEndingWith:   {},
			nameCollation:         {avt: true},
			// composite="yes" makes the whole key sequence one grouping key.
			// XSLT 3.0 only: a 2.0 stylesheet naming it must still be told so.
			nameComposite: {
				since30: true,
				values:  []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse},
			},
			// These withdrawn binding attributes are unknown in the published REC.
			nameBindGroup:       {removed30: true},
			nameBindGroupingKey: {removed30: true},
		}}, true
	case lexicon.XSLTElementAnalyzeString:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect: {required: true},
			nameRegex:     {required: true, avt: true},
			nameFlags:     {avt: true},
		}}, true
	case lexicon.XSLTElementMatchingSubstring:
		return elementDef{attrs: map[string]attrDef{}}, true
	case lexicon.XSLTElementNonMatchingSubstring:
		return elementDef{attrs: map[string]attrDef{}}, true
	}

	return elementDef{}, false
}

func lookupDynamicXSLTElement(name string) (elementDef, bool) {
	const (
		nameStream = "stream"
	)

	switch name {
	case lexicon.XSLTElementEvaluate:
		return elementDef{attrs: map[string]attrDef{
			nameXPath:            {required: true},
			nameAs:               {},
			nameBaseURI:          {avt: true},
			nameWithParams:       {},
			nameContextItem:      {},
			nameNamespaceContext: {},
			nameSchemaAware:      {avt: true},
		}}, true
	case lexicon.XSLTElementMessage:
		return elementDef{attrs: map[string]attrDef{
			xslAttrSelect: {},
			// Both editions support AVTs. The 2.0 vocabulary is yes/no; a
			// selected 3.0 processor also accepts the four boolean aliases.
			nameTerminate: {values: []string{lexicon.ValueYes, lexicon.ValueNo}, avt: true},
			// @error-code follows the processor's version, not the module's.
			nameErrorCode: {processor30: true, avt: true},
		}}, true

	// xsl:assert requires XSLT 3.0 (§22.2).
	case lexicon.XSLTElementAssert:
		return elementDef{since30: true, attrs: map[string]attrDef{
			lexicon.AttrTest: {required: true},
			xslAttrSelect:    {},
			// Written as {eqname} in the summary, so an attribute value template
			// exactly as it is on xsl:message.
			nameErrorCode: {avt: true},
		}}, true
	case nameFallback:
		return elementDef{attrs: map[string]attrDef{}}, true
	case lexicon.XSLTElementTry:
		return elementDef{since30: true, attrs: map[string]attrDef{
			xslAttrSelect:      {},
			nameRollbackOutput: {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
		}}, true
	case lexicon.XSLTElementCatch:
		return elementDef{since30: true, attrs: map[string]attrDef{
			nameErrors:    {},
			xslAttrSelect: {},
		}}, true

	// source-document evaluates its body with the loaded document as context.
	// streamable is accepted, but execution builds a tree (§18.1).
	// The draft xsl:stream spelling is also supported with its own attribute set;
	// it has no @streamable attribute.
	case nameStream:
		return elementDef{since30: true, attrs: map[string]attrDef{
			lexicon.AttrHref:    {required: true, avt: true},
			nameUseAccumulators: {},
			nameValidation:      {values: []string{validationStrict, validationLax, validationPreserve, validationStrip}},
			lexicon.AttrType:    {},
		}}, true
	case lexicon.XSLTElementSourceDocument:
		return elementDef{since30: true, attrs: map[string]attrDef{
			lexicon.AttrHref:    {required: true, avt: true},
			nameStreamable:      {values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse}},
			nameUseAccumulators: {},
			nameValidation:      {values: []string{validationStrict, validationLax, validationPreserve, validationStrip}},
			lexicon.AttrType:    {},
		}}, true
	}

	return elementDef{}, false
}

func lookupSerializationXSLTElement(name string) (elementDef, bool) {
	switch name {
	case lexicon.XSLTElementResultDocument:
		return elementDef{attrs: map[string]attrDef{
			// build-tree says whether the raw result is normalised into a final
			// result tree or serialised as the sequence it is; see 2.3.6. XSLT
			// 3.0 added it, along with the two JSON serialisation parameters.
			lexicon.SerializationBuildTree:           {processor30: true, avt: true, values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse}},
			lexicon.SerializationAllowDuplicateNames: {processor30: true, avt: true, values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse}},
			// Both enumerate as on xsl:output, plus braces: a literal outside
			// the set is XTSE0020 here, a computed one XTDE0030 in resultdoc.go.
			lexicon.SerializationJSONNodeOutputMethod: {
				processor30: true, avt: true, eqnameOK: true,
				values: []string{lexicon.MethodXML, lexicon.MethodHTML, lexicon.MethodXHTML, lexicon.MethodText},
			},
			lexicon.SerializationParameterDocument:   {processor30: true, avt: true},
			lexicon.SerializationItemSeparator:       {processor30: true, avt: true},
			lexicon.SerializationHTMLVersion:         {processor30: true, avt: true},
			lexicon.SerializationSuppressIndentation: {processor30: true, avt: true},
			nameFormat:                               {avt: true},
			lexicon.AttrHref:                         {avt: true},
			nameValidation:                           {values: []string{validationStrict, validationLax, validationPreserve, validationStrip}},
			lexicon.AttrType:                         {},
			lexicon.SerializationMethod: {avt: true, eqnameOK: true, values: []string{
				lexicon.MethodXML, lexicon.MethodHTML, lexicon.MethodXHTML, lexicon.MethodText, lexicon.MethodJSON, lexicon.MethodAdaptive,
			}},
			lexicon.SerializationByteOrderMark:        {values: []string{lexicon.ValueYes, lexicon.ValueNo}, avt: true},
			lexicon.SerializationCDATASectionElements: {avt: true},
			lexicon.SerializationDoctypePublic:        {avt: true},
			lexicon.SerializationDoctypeSystem:        {avt: true},
			lexicon.SerializationEncoding:             {avt: true},
			lexicon.SerializationEscapeURIAttributes:  {values: []string{lexicon.ValueYes, lexicon.ValueNo}, avt: true},
			lexicon.SerializationIncludeContentType:   {values: []string{lexicon.ValueYes, lexicon.ValueNo}, avt: true},
			lexicon.SerializationIndent:               {values: []string{lexicon.ValueYes, lexicon.ValueNo}, avt: true},
			lexicon.SerializationMediaType:            {avt: true},
			lexicon.SerializationNormalizationForm:    {avt: true, nmtoken: true},
			lexicon.SerializationOmitXMLDeclaration:   {values: []string{lexicon.ValueYes, lexicon.ValueNo}, avt: true},
			lexicon.SerializationStandalone:           {values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueOmit}, avt: true},
			lexicon.SerializationUndeclarePrefixes:    {values: []string{lexicon.ValueYes, lexicon.ValueNo}, avt: true},
			lexicon.SerializationUseCharacterMaps:     {},
			nameOutputVersion:                         {avt: true},
		}}, true
	case nameOutput:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:                 {},
			lexicon.SerializationMethod: {},
			// Output declarations use literal attributes, unlike result-document AVTs
			// (§26.1). json-node-output-method permits xml, html, xhtml, text or a namespaced
			// EQName; json and adaptive cannot serialize a node within JSON output.
			lexicon.SerializationJSONNodeOutputMethod: {
				processor30: true, eqnameOK: true,
				values: []string{lexicon.MethodXML, lexicon.MethodHTML, lexicon.MethodXHTML, lexicon.MethodText},
			},
			// parameter-document is a literal URI reference, not an AVT.
			lexicon.SerializationParameterDocument:   {processor30: true, uri: true},
			lexicon.SerializationAllowDuplicateNames: {processor30: true, values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse}},
			lexicon.SerializationBuildTree:           {processor30: true, values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueTrue, lexicon.ValueFalse, booleanDigitTrue, booleanDigitFalse}},
			lexicon.SerializationHTMLVersion:         {processor30: true},
			lexicon.SerializationSuppressIndentation: {processor30: true},
			// item-separator is applied during sequence normalization (§5.7.1), not
			// just serialization: inserted text nodes participate in result validation.
			lexicon.SerializationItemSeparator:        {processor30: true},
			lexicon.SerializationByteOrderMark:        {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			lexicon.SerializationCDATASectionElements: {},
			lexicon.SerializationDoctypePublic:        {},
			lexicon.SerializationDoctypeSystem:        {},
			lexicon.SerializationEncoding:             {},
			lexicon.SerializationEscapeURIAttributes:  {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			lexicon.SerializationIncludeContentType:   {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			lexicon.SerializationIndent:               {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			lexicon.SerializationMediaType:            {},
			lexicon.SerializationNormalizationForm:    {nmtoken: true},
			lexicon.SerializationOmitXMLDeclaration:   {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			// The enumeration retains the 2.0 vocabulary. A selected 3.0 processor
			// also admits the boolean synonyms in a 2.0 module.
			lexicon.SerializationStandalone:        {values: []string{lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueOmit}},
			lexicon.SerializationUndeclarePrefixes: {values: []string{lexicon.ValueYes, lexicon.ValueNo}},
			lexicon.SerializationUseCharacterMaps:  {},
			lexicon.SerializationVersion:           {},
		}}, true
	case lexicon.XSLTElementCharacterMap:
		return elementDef{attrs: map[string]attrDef{
			xslAttrName:                           {required: true},
			lexicon.SerializationUseCharacterMaps: {},
		}}, true
	case lexicon.XSLTElementOutputCharacter:
		return elementDef{attrs: map[string]attrDef{
			nameCharacter:             {required: true},
			nameOutputCharacterString: {required: true},
		}}, true
	}

	return elementDef{}, false
}
