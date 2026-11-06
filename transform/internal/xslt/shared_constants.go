package xslt

import "github.com/skarm/xmlsec/internal/lexicon"

// xslAttrRequired names the unqualified boolean attribute on parameter
// declarations. It is separate from the required value of context-item/@use.
const xslAttrRequired = "required"

// Draft identity-sensitive attribute spelling shared by legacy compiler checks and the grammar that rejects it in XSLT 3.0; this naming does not broaden support.
const (
	nameIdentitySensitive = "identity-sensitive"
)

// Reserved initial-template local name in the XSLT namespace; explicit invocation names still resolve through their namespace context.
const (
	initialTemplateLocalName = "initial-template"
)

// The XSLT language-version attribute (unqualified on instructions, XSLT-qualified on literal result elements); serialization version and system-property names retain their separate roles.
const (
	xslAttrVersion = "version"
)

// Unqualified xsl:output-character/@string supplies replacement text; it is independent of the xs:string atomic type.
const (
	nameOutputCharacterString = "string"
)

// strconv.ParseFloat result precision for binary64 host values; it is independent of operation-accounting granularity and index cardinality.
const (
	float64ParseBits = 64
)

// Unqualified XSLT attribute and closed selector names shared by grammar and compilation; namespace, version and allowed-value checks remain at their call sites.
const (
	nameAs                        = "as"
	nameBaseURI                   = "base-uri"
	nameCache                     = "cache"
	nameCharacter                 = "character"
	nameCopyAccumulators          = "copy-accumulators"
	nameCopyNamespaces            = "copy-namespaces"
	nameDeclaredModes             = "declared-modes"
	nameErrorCode                 = "error-code"
	nameErrors                    = "errors"
	nameFlags                     = "flags"
	nameForEachItem               = "for-each-item"
	nameForEachSource             = "for-each-source"
	nameGroupAdjacent             = "group-adjacent"
	nameGroupBy                   = "group-by"
	nameGroupEndingWith           = "group-ending-with"
	nameGroupStartingWith         = "group-starting-with"
	nameInitialValue              = "initial-value"
	nameLevel                     = "level"
	nameNamespaceContext          = "namespace-context"
	nameNewEachTime               = "new-each-time"
	nameOnMultipleMatch           = "on-multiple-match"
	nameOnNoMatch                 = "on-no-match"
	nameOrdinal                   = "ordinal"
	nameOutputVersion             = "output-version"
	nameOverrideExtensionFunction = "override-extension-function"
	namePhase                     = "phase"
	namePriority                  = "priority"
	nameRegex                     = "regex"
	nameResultPrefix              = "result-prefix"
	nameRollbackOutput            = "rollback-output"
	nameSchemaAware               = "schema-aware"
	nameSeparator                 = "separator"
	nameSortBeforeMerge           = "sort-before-merge"
	nameStable                    = "stable"
	nameStreamability             = "streamability"
	nameStylesheetPrefix          = "stylesheet-prefix"
	nameTerminate                 = "terminate"
	nameWarningOnMultipleMatch    = "warning-on-multiple-match"
	nameWarningOnNoMatch          = "warning-on-no-match"
	nameWithParams                = "with-params"
	nameXPath                     = "xpath"
)

const (
	nameFormat                         = "format"
	nameLetterValue                    = "letter-value"
	nameGroupingSize                   = "grouping-size"
	nameStartAt                        = "start-at"
	nameOriginal                       = "original"
	processorProductName               = "xmlsec"
	nameProductName                    = "product-name"
	nameAccumulatorAfter               = "accumulator-after"
	nameAccumulatorBefore              = "accumulator-before"
	nameAttributeSet                   = lexicon.XSLTElementAttributeSet
	nameCaseOrder                      = "case-order"
	nameCollation                      = "collation"
	nameComposite                      = "composite"
	nameContextItem                    = lexicon.XSLTElementContextItem
	nameCurrentMergeGroup              = "current-merge-group"
	nameCurrentMergeKey                = "current-merge-key"
	nameDataType                       = "data-type"
	nameDecimalSeparator               = lexicon.DecimalFormatDecimalSeparator
	nameDefaultCollation               = "default-collation"
	nameDefaultMode                    = "default-mode"
	nameDefaultValidation              = "default-validation"
	nameDigit                          = lexicon.DecimalFormatDigit
	nameDisableOutputEscaping          = "disable-output-escaping"
	nameDoc                            = "doc"
	nameElements                       = "elements"
	nameEmptySequence                  = "empty-sequence()"
	nameExcludeResultPrefixes          = "exclude-result-prefixes"
	nameExpandText                     = "expand-text"
	nameExponentSeparator              = lexicon.DecimalFormatExponentSeparator
	nameExtensionElementPrefixes       = "extension-element-prefixes"
	nameFallback                       = lexicon.XSLTElementFallback
	nameGroupingSeparator              = lexicon.DecimalFormatGroupingSeparator
	nameImport                         = lexicon.XSLTElementImport
	nameInclude                        = lexicon.XSLTElementInclude
	nameInfinity                       = lexicon.DecimalFormatInfinity
	nameInheritNamespaces              = "inherit-namespaces"
	nameInputTypeAnnotations           = "input-type-annotations"
	nameIsSchemaAware                  = "is-schema-aware"
	keyLocalName                       = lexicon.XSLTElementKey
	nameLowerFirst                     = "lower-first"
	nameMaybe                          = "maybe"
	nameMinusSign                      = lexicon.DecimalFormatMinusSign
	textNameSelect                     = xslAttrName + " " + xslAttrSelect
	nameNamespace                      = lexicon.XSLTElementNamespace
	nameOrder                          = "order"
	nameOutput                         = lexicon.XSLTElementOutput
	namePackage                        = lexicon.XSLTElementPackage
	namePackageVersion                 = "package-version"
	nameParam                          = lexicon.XSLTElementParam
	namePatternSeparator               = lexicon.DecimalFormatPatternSeparator
	namePerMille                       = lexicon.DecimalFormatPerMille
	namePercent                        = lexicon.DecimalFormatPercent
	namePreserveSpace                  = lexicon.XSLTElementPreserveSpace
	nameRegexGroup                     = "regex-group"
	nameSingle                         = "single"
	nameSort                           = lexicon.XSLTElementSort
	nameStatic                         = "static"
	nameStreamAvailable                = "stream-available"
	nameStreamable                     = "streamable"
	nameStripSpace                     = lexicon.XSLTElementStripSpace
	nameStylesheet                     = lexicon.XSLTElementStylesheet
	textSupportsBackwardsCompatibility = "supports-backwards-compatibility"
	nameSupportsDynamicEvaluation      = "supports-dynamic-evaluation"
	textSupportsHigherOrderFunctions   = "supports-higher-order-functions"
	nameSupportsNamespaceAxis          = "supports-namespace-axis"
	nameSupportsSerialization          = "supports-serialization"
	nameSupportsStreaming              = "supports-streaming"
	nameTemplate                       = lexicon.XSLTElementTemplate
	nameTunnel                         = "tunnel"
	nameTyped                          = "typed"
	nameUnparsedEntityPublicID         = "unparsed-entity-public-id"
	nameUnparsedEntityURI              = "unparsed-entity-uri"
	nameUpperFirst                     = "upper-first"
	nameUseAccumulators                = "use-accumulators"
	nameUseAttributeSets               = "use-attribute-sets"
	nameUsePackage                     = lexicon.XSLTElementUsePackage
	nameUTF16                          = "utf16"
	nameValidation                     = "validation"
	nameVariable                       = lexicon.XSLTElementVariable
	nameXPathDefaultNamespace          = "xpath-default-namespace"
	nameZeroDigit                      = lexicon.DecimalFormatZeroDigit
)
