package lexicon

const (
	// DecimalFormatDecimalSeparator names the "decimal-separator" property shared by XSLT declarations
	// and host decimal formats.
	DecimalFormatDecimalSeparator = "decimal-separator"
	// DecimalFormatDigit names the "digit" property shared by XSLT declarations and host decimal
	// formats.
	DecimalFormatDigit = "digit"
	// DecimalFormatExponentSeparator names the "exponent-separator" property shared by XSLT
	// declarations and host decimal formats.
	DecimalFormatExponentSeparator = "exponent-separator"
	// DecimalFormatGroupingSeparator names the "grouping-separator" property shared by XSLT
	// declarations and host decimal formats.
	DecimalFormatGroupingSeparator = "grouping-separator"
	// DecimalFormatInfinity names the "infinity" property shared by XSLT declarations and host decimal
	// formats.
	DecimalFormatInfinity = "infinity"
	// DecimalFormatMinusSign names the "minus-sign" property shared by XSLT declarations and host
	// decimal formats.
	DecimalFormatMinusSign = "minus-sign"
	// DecimalFormatPatternSeparator names the "pattern-separator" property shared by XSLT declarations
	// and host decimal formats.
	DecimalFormatPatternSeparator = "pattern-separator"
	// DecimalFormatPerMille names the "per-mille" property shared by XSLT declarations and host
	// decimal formats.
	DecimalFormatPerMille = "per-mille"
	// DecimalFormatPercent names the "percent" property shared by XSLT declarations and host decimal
	// formats.
	DecimalFormatPercent = "percent"
	// DecimalFormatZeroDigit names the "zero-digit" property shared by XSLT declarations and host
	// decimal formats.
	DecimalFormatZeroDigit = "zero-digit"
)

// XSLT element local names shared by compilation and language introspection.
// Consumers must also match NamespaceXSLT.
const (
	XSLTElementAccumulator           = "accumulator"
	XSLTElementAccumulatorRule       = "accumulator-rule"
	XSLTElementAnalyzeString         = "analyze-string"
	XSLTElementApplyImports          = "apply-imports"
	XSLTElementApplyTemplates        = "apply-templates"
	XSLTElementAssert                = "assert"
	XSLTElementAttribute             = "attribute"
	XSLTElementAttributeSet          = "attribute-set"
	XSLTElementBreak                 = "break"
	XSLTElementCallTemplate          = "call-template"
	XSLTElementCatch                 = "catch"
	XSLTElementCharacterMap          = "character-map"
	XSLTElementChoose                = "choose"
	XSLTElementComment               = "comment"
	XSLTElementContextItem           = "context-item"
	XSLTElementCopy                  = "copy"
	XSLTElementCopyOf                = "copy-of"
	XSLTElementDecimalFormat         = "decimal-format"
	XSLTElementDocument              = "document"
	XSLTElementElement               = "element"
	XSLTElementEvaluate              = "evaluate"
	XSLTElementExpose                = "expose"
	XSLTElementFallback              = "fallback"
	XSLTElementForEach               = "for-each"
	XSLTElementForEachGroup          = "for-each-group"
	XSLTElementFork                  = "fork"
	XSLTElementFunction              = "function"
	XSLTElementGlobalContextItem     = "global-context-item"
	XSLTElementIf                    = "if"
	XSLTElementImport                = "import"
	XSLTElementImportSchema          = "import-schema"
	XSLTElementInclude               = "include"
	XSLTElementIterate               = "iterate"
	XSLTElementKey                   = "key"
	XSLTElementMap                   = "map"
	XSLTElementMapEntry              = "map-entry"
	XSLTElementMatchingSubstring     = "matching-substring"
	XSLTElementMerge                 = "merge"
	XSLTElementMergeAction           = "merge-action"
	XSLTElementMergeKey              = "merge-key"
	XSLTElementMergeSource           = "merge-source"
	XSLTElementMessage               = "message"
	XSLTElementMode                  = "mode"
	XSLTElementNamespace             = "namespace"
	XSLTElementNamespaceAlias        = "namespace-alias"
	XSLTElementNextIteration         = "next-iteration"
	XSLTElementNextMatch             = "next-match"
	XSLTElementNonMatchingSubstring  = "non-matching-substring"
	XSLTElementNumber                = "number"
	XSLTElementOnCompletion          = "on-completion"
	XSLTElementOnEmpty               = "on-empty"
	XSLTElementOnNonEmpty            = "on-non-empty"
	XSLTElementOtherwise             = "otherwise"
	XSLTElementOutput                = "output"
	XSLTElementOutputCharacter       = "output-character"
	XSLTElementParam                 = "param"
	XSLTElementPerformSort           = "perform-sort"
	XSLTElementProcessingInstruction = "processing-instruction"
	XSLTElementPreserveSpace         = "preserve-space"
	XSLTElementResultDocument        = "result-document"
	XSLTElementSchema                = "schema"
	XSLTElementSequence              = "sequence"
	XSLTElementSort                  = "sort"
	XSLTElementSourceDocument        = "source-document"
	XSLTElementStripSpace            = "strip-space"
	XSLTElementTemplate              = "template"
	XSLTElementText                  = "text"
	XSLTElementTry                   = "try"
	XSLTElementUsePackage            = "use-package"
	XSLTElementValueOf               = "value-of"
	XSLTElementVariable              = "variable"
	XSLTElementWhen                  = "when"
	XSLTElementWherePopulated        = "where-populated"
	XSLTElementWithParam             = "with-param"

	// XSLTElementAccept names the xsl:accept declaration for package components.
	XSLTElementAccept     = "accept"
	XSLTElementArray      = "array"
	XSLTElementOverride   = "override"
	XSLTElementPackage    = "package"
	XSLTElementStylesheet = "stylesheet"
	XSLTElementTransform  = "transform"
)

// Names used in static streamability metadata. A category alone does not assert
// that a particular program executes with bounded streaming storage.
const (
	StreamAbsorbing      = "absorbing"
	StreamInspection     = "inspection"
	StreamFilter         = "filter"
	StreamAscent         = "ascent"
	StreamShallowDescent = "shallow-descent"
	StreamUnclassified   = "unclassified"
)

// XSLT grouping function names.
const (
	FnCurrentGroup       = "current-group"
	FnCurrentGroupingKey = "current-grouping-key"
)

// XSLT output constants.
const (
	// OutputDisableEscaping names the XSLT attribute; internal PI markers have separate names.
	OutputDisableEscaping = "disable-output-escaping"
	OutputDescending      = "descending"
	// OutputVersion10 is the serialization version token, distinct from XSLTVersion10.
	OutputVersion10 = "1.0"
	// OutputRaw selects delivery of an un-serialized result value.
	OutputRaw = "raw"
	// NormFullyNormalized names the fully-normalized request; support is checked by the serializer.
	NormFullyNormalized = "FULLY-NORMALIZED"
)

// XSLT XPath function names used in streamability analysis.
const (
	FnPosition = "position"
	FnLast     = "last"
	FnName     = "name"
)

// XSLT spec version strings used for MinVersion fields and version-attribute
// comparisons across compile/streamability/element-info tables.
const (
	XSLTVersion10 = "1.0"
	XSLTVersion20 = "2.0"
	XSLTVersion30 = "3.0"
)

// DecimalFormatNaN names the NaN property in a decimal-format declaration.
const DecimalFormatNaN = "NaN"
