// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type instruction interface {
	instructionTag()
}

// xpathNSHolder is implemented by instructions that may carry a
// per-instruction xpath-default-namespace override.
type xpathNSHolder interface {
	getXPathDefaultNS() string
	xpathNSIsSet() bool
}

// xpathNS is embedded in instructions that support xpath-default-namespace.
type xpathNS struct {
	XPathDefaultNS         string
	HasXPathDefaultNS      bool // true when xpath-default-namespace is set (explicit or inherited)
	HasLocalXPathDefaultNS bool // true only when xpath-default-namespace is declared on this element
}

func (x xpathNS) getXPathDefaultNS() string { return x.XPathDefaultNS }

func (x xpathNS) xpathNSIsSet() bool { return x.HasXPathDefaultNS }

// collationScopeInst wraps an instruction with a default-collation override.
// Emitted by the compiler when default-collation changes on an instruction element.
type collationScopeInst struct {
	DefaultCollation string
	Inner            instruction
}

func (*collationScopeInst) instructionTag() {}

// sourceInfo records the source location of an instruction in the stylesheet.
// Embedded in instruction types to report location for xsl:catch error variables.
type sourceInfo struct {
	SourceLine    int    // line number in the stylesheet
	SourceModule  string // stylesheet URI (module)
	StaticBaseURI string // effective static base URI from xml:base (non-empty when overridden)
}

func (s *sourceInfo) setSourceInfo(line int, module string) {
	s.SourceLine = line
	s.SourceModule = module
}

func (s *sourceInfo) getSourceLine() int { return s.SourceLine }

func (s *sourceInfo) getSourceModule() string { return s.SourceModule }

func (s *sourceInfo) getStaticBaseURI() string { return s.StaticBaseURI }

func (s *sourceInfo) setStaticBaseURI(v string) { s.StaticBaseURI = v }

type applyTemplatesInst struct {
	sourceInfo
	xpathNS
	Select *xpath.Expression // nil = "child::node()"
	Mode   string            // "" = current mode, "#default", "#current"
	Sort   []*sortKey
	Params []*withParam
}

func (*applyTemplatesInst) instructionTag() {}

type callTemplateInst struct {
	sourceInfo
	Name   string
	Params []*withParam
	// Compat is true when the xsl:call-template is processed with
	// backwards-compatible behavior (effective version < 2.0), which permits a
	// with-param that has no matching xsl:param in the target (§10.1.1).
	Compat bool
}

func (*callTemplateInst) instructionTag() {}

type withParam struct {
	Name   string
	Select *xpath.Expression
	Body   []instruction
	As     string
	Type   *xdm.SequenceType
	Tunnel bool
}

type valueOfInst struct {
	sourceInfo
	xpathNS
	Select                *xpath.Expression
	Separator             *avt // nil = absent; non-nil = present (even if empty)
	Body                  []instruction
	DisableOutputEscaping bool
}

func (*valueOfInst) instructionTag() {}

type textInst struct {
	sourceInfo
	Value                 string
	TVT                   *avt // text value template (non-nil when expand-text is active)
	DisableOutputEscaping bool
}

func (*textInst) instructionTag() {}

type literalTextInst struct {
	sourceInfo
	Value string
	TVT   *avt // text value template (non-nil when expand-text is active)
}

func (*literalTextInst) instructionTag() {}

type elementInst struct {
	sourceInfo
	Name              *avt
	Namespace         *avt
	NSBindings        map[string]string // compile-time in-scope namespace bindings
	Body              []instruction
	TypeName          string   // XSD type annotation (e.g., "xs:integer")
	Validation        string   // "strict", "lax", "preserve", "strip"
	UseAttrSets       []string // xsl:use-attribute-sets (resolved QNames)
	InheritNamespaces bool     // inherit-namespaces="yes" (default true)
}

func (*elementInst) instructionTag() {}

type attributeInst struct {
	sourceInfo
	Name       *avt
	Namespace  *avt
	Select     *xpath.Expression
	Body       []instruction
	Separator  *avt
	TypeName   string // XSD type annotation (e.g., "xs:ID")
	Validation string // "strict", "lax", "preserve", "strip"
}

func (*attributeInst) instructionTag() {}

type commentInst struct {
	sourceInfo
	Select *xpath.Expression
	Body   []instruction
}

func (*commentInst) instructionTag() {}

type piInst struct {
	sourceInfo
	Name   *avt
	Select *xpath.Expression
	Body   []instruction
}

func (*piInst) instructionTag() {}

type ifInst struct {
	sourceInfo
	xpathNS
	Test *xpath.Expression
	Body []instruction
}

func (*ifInst) instructionTag() {}

type whenClause struct {
	xpathNS
	Test             *xpath.Expression
	Body             []instruction
	Namespaces       map[string]string // per-clause namespace bindings (nil = use stylesheet default)
	DefaultCollation string            // per-clause default-collation (empty = inherit)
}

type chooseInst struct {
	sourceInfo
	xpathNS
	When             []*whenClause
	Otherwise        []instruction
	OtherwiseXPNS    string // xpath-default-namespace on xsl:otherwise
	HasOtherwiseXPNS bool
	DefaultCollation string // default-collation URI for XPath comparisons
}

func (*chooseInst) instructionTag() {}

type forEachInst struct {
	sourceInfo
	xpathNS
	Select *xpath.Expression
	Sort   []*sortKey
	Body   []instruction
}

func (*forEachInst) instructionTag() {}

type variableInst struct {
	sourceInfo
	xpathNS
	Name   string
	Select *xpath.Expression
	Body   []instruction
	As     string // type declaration (e.g., "item()*"); empty = wrap body in document node
}

func (*variableInst) instructionTag() {}

type paramInst struct {
	sourceInfo
	Name     string
	Select   *xpath.Expression
	Body     []instruction
	As       string // type declaration (e.g., "xs:integer")
	Required bool
	Tunnel   bool
}

func (*paramInst) instructionTag() {}

type copyInst struct {
	sourceInfo
	Select               *xpath.Expression
	Body                 []instruction
	Validation           string   // "strict", "lax", "preserve", "strip"
	TypeName             string   // type annotation (e.g., "Q{ns}typeName")
	UseAttributeSets     []string // xsl:use-attribute-sets (resolved QNames)
	UseAttrSets          []string // attribute set names (raw)
	CopyNamespaces       bool     // copy-namespaces="yes" (default true)
	InheritNamespaces    bool     // inherit-namespaces="yes" (default true)
	CopyNamespacesAVT    *avt     // shadow attr _copy-namespaces (overrides CopyNamespaces)
	InheritNamespacesAVT *avt     // shadow attr _inherit-namespaces (overrides InheritNamespaces)
}

func (*copyInst) instructionTag() {}

type copyOfInst struct {
	sourceInfo
	Select            *xpath.Expression
	Validation        string // "strict", "lax", "preserve", "strip"
	TypeName          string // type annotation (e.g., "Q{ns}typeName")
	CopyNamespaces    bool   // copy-namespaces="yes" (default true)
	CopyNamespacesAVT *avt   // shadow attr _copy-namespaces (overrides CopyNamespaces)
	CopyAccumulators  bool   // copy-accumulators="yes" (default false)
}

func (*copyOfInst) instructionTag() {}

// literalAttribute is a computed attribute on a literal result element.
type literalAttribute struct {
	Name      string // qualified name
	Namespace string
	Prefix    string
	LocalName string
	Value     *avt
}

type literalResultElement struct {
	sourceInfo
	xpathNS
	Name              string // qualified name (prefix:local)
	Namespace         string // namespace URI
	Prefix            string
	LocalName         string
	Attrs             []*literalAttribute
	Namespaces        map[string]string // prefix -> URI declarations to copy
	NamespacePrefixes []string          // sorted once at compilation for stable serialization
	Body              []instruction
	UseAttrSets       []string // xsl:use-attribute-sets (resolved QNames)
	Validation        string   // xsl:validation="strict"|"lax"|"preserve"|"strip"
	TypeName          string   // xsl:type annotation (e.g., "xs:integer")
	DefaultValidation string   // xsl:default-validation override for this LRE scope
	InheritNamespaces bool     // xsl:inherit-namespaces (default true)
}

func (*literalResultElement) instructionTag() {}

type numberInst struct {
	sourceInfo
	Level             string // "single", "multiple", "any"
	Count             *pattern
	From              *pattern
	Value             *xpath.Expression
	Format            *avt
	GroupingSeparator *avt
	GroupingSize      *avt
	Ordinal           *avt
	StartAt           *avt              // XSLT 3.0 start-at attribute
	Select            *xpath.Expression // XSLT 3.0 select attribute
	Lang              *avt              // language for word/ordinal numbering
	LetterValue       *avt              // "alphabetic" or "traditional"
	// memoizable is true when neither Count nor From reads a variable, so
	// whether a node matches them depends on the node alone and a count from an
	// earlier evaluation can be reused (see execContext.numberMemos).
	memoizable bool
}

func (*numberInst) instructionTag() {}

type messageInst struct {
	sourceInfo
	Select          *xpath.Expression
	Body            []instruction
	Terminate       *avt // defaults to "no"
	ErrorCode       *avt // defaults to "XTMM9000"
	ErrorNamespaces map[string]string
}

func (*messageInst) instructionTag() {}

type sequenceInst struct {
	sourceInfo
	Body              []instruction
	DefaultValidation string // xsl:default-validation override (from xsl:sequence)
}

func (*sequenceInst) instructionTag() {}

type namespaceInst struct {
	sourceInfo
	Name   *avt
	Select *xpath.Expression
	Body   []instruction
}

func (*namespaceInst) instructionTag() {}

// resultDocumentInst represents xsl:result-document.
// The body output goes to a secondary result, not the primary output.
type resultDocumentInst struct {
	sourceInfo
	Href             *avt
	Body             []instruction
	Format           string   // name of xsl:output to use (static format attribute)
	FormatAVT        *avt     // dynamic format attribute (when it contains {…})
	Method           string   // output method override (from method attribute)
	ItemSeparator    *avt     // item-separator override (avt); nil = not specified
	ItemSeparatorSet bool     // true when item-separator attribute is present (including #absent)
	Validation       string   // "strict", "lax", "preserve", "strip"
	TypeName         string   // type annotation (e.g., "Q{ns}typeName")
	UseCharacterMaps []string // names of character maps to use

	NSBindings map[string]string // compile-time namespace bindings for QName resolution
	// OutputVersion is the output version AVT, evaluated at runtime.
	OutputVersion           *avt
	Encoding                *avt
	Indent                  *avt
	OmitXMLDeclaration      *avt
	Standalone              *avt
	DoctypeSystem           *avt
	DoctypePublic           *avt
	CDATASectionElements    *avt
	ByteOrderMark           *avt
	MethodAVT               *avt // method as avt (overrides Method if non-nil)
	MediaType               *avt
	HTMLVersion             *avt
	IncludeContentType      *avt
	AllowDuplicateNames     *avt
	UndeclarePrefixes       *avt
	EscapeURIAttributes     *avt
	JSONNodeOutputMethodAVT *avt             // json-node-output-method avt
	NormalizationForm       *avt             // normalization-form avt
	SuppressIndentation     []string         // suppress-indentation element names
	ParameterDocAVT         *avt             // parameter-document avt
	ParameterDocOutputDef   *OutputDef       // resolved output def from parameter-document (compile-time)
	ParameterDocPresence    paramDocPresence // parameter-presence set for the compile-time parameter-document delta
	BuildTree               *avt             // build-tree avt: nil=default(true); evaluated as xs:boolean
}

func (*resultDocumentInst) instructionTag() {}

type xslSequenceInst struct {
	sourceInfo
	Select *xpath.Expression
}

func (*xslSequenceInst) instructionTag() {}

type mapInst struct {
	sourceInfo
	Body []instruction // child xsl:map-entry instructions
}

func (*mapInst) instructionTag() {}

type mapEntryInst struct {
	sourceInfo
	xpathNS
	Key    *xpath.Expression // key expression
	Select *xpath.Expression // optional select expression for value
	Body   []instruction     // optional body for value
}

func (*mapEntryInst) instructionTag() {}

type performSortInst struct {
	sourceInfo
	Select *xpath.Expression
	Sort   []*sortKey
	Body   []instruction
}

func (*performSortInst) instructionTag() {}

type nextMatchInst struct {
	sourceInfo
	Params []*withParam
}

func (*nextMatchInst) instructionTag() {}

type applyImportsInst struct {
	sourceInfo
	Params []*withParam
}

func (*applyImportsInst) instructionTag() {}

type wherePopulatedInst struct {
	sourceInfo
	Body []instruction
}

func (*wherePopulatedInst) instructionTag() {}

// onEmptyInst represents xsl:on-empty.
// Executes its body/select only if the current output container has no significant content.
type onEmptyInst struct {
	sourceInfo
	Body   []instruction
	Select *xpath.Expression
}

func (*onEmptyInst) instructionTag() {}

// onNonEmptyInst represents xsl:on-non-empty.
// Executes its body/select only if the current output container has significant content.
type onNonEmptyInst struct {
	sourceInfo
	Body   []instruction
	Select *xpath.Expression
}

func (*onNonEmptyInst) instructionTag() {}

type catchClause struct {
	Errors []string          // error codes to match (empty = "*")
	Select *xpath.Expression // xsl:catch select attribute
	Body   []instruction     // xsl:catch body
}

type tryCatchInst struct {
	sourceInfo
	Select         *xpath.Expression // xsl:try select attribute
	Try            []instruction
	Catches        []*catchClause // multiple catch clauses (matched in order)
	RollbackOutput bool           // rollback-output="yes" (default true)
}

func (*tryCatchInst) instructionTag() {}

type sourceDocumentInst struct {
	sourceInfo
	Href            *avt
	Streamable      bool
	UseAccumulators []string
	BaseURI         string // effective base URI for resolving href
	Validation      string // "strict", "lax", "preserve", "strip"
	TypeName        string // resolved QName for type attribute
	Body            []instruction
}

func (*sourceDocumentInst) instructionTag() {}

type iterateParam struct {
	Name   string
	Select *xpath.Expression
	Body   []instruction
	As     string // type declaration (e.g., "element()*")
	Type   *xdm.SequenceType
}

type iterateInst struct {
	sourceInfo
	Select       *xpath.Expression
	Params       []*iterateParam
	OnCompletion []instruction
	Body         []instruction
}

func (*iterateInst) instructionTag() {}

type breakInst struct {
	sourceInfo
	Select *xpath.Expression
	Body   []instruction
}

func (*breakInst) instructionTag() {}

type nextIterationInst struct {
	sourceInfo
	Params []*withParam
}

func (*nextIterationInst) instructionTag() {}

// forkInst represents xsl:fork.
// Each entry in Branches is a sequence of instructions from one child.
type forkInst struct {
	sourceInfo
	Branches [][]instruction
}

func (*forkInst) instructionTag() {}

type forEachGroupInst struct {
	sourceInfo
	Select            *xpath.Expression
	GroupBy           *xpath.Expression
	GroupAdjacent     *xpath.Expression
	GroupStartingWith *pattern
	GroupEndingWith   *pattern
	Collation         *avt
	DefaultCollation  string
	Composite         bool
	Sort              []*sortKey
	Body              []instruction
}

func (*forEachGroupInst) instructionTag() {}

type mergeSource struct {
	Name            string
	ForEachSource   *xpath.Expression // XPath expr evaluating to sequence of URIs
	ForEachItem     *xpath.Expression // XPath expr evaluating to sequence of items (nodes)
	Select          *xpath.Expression
	UseAccumulators []string
	StreamableAttr  bool
	SortBeforeMerge bool
	BaseURI         string // effective base URI for resolving for-each-source URIs
	Validation      string // validation mode (strict/lax/preserve/strip) for loaded sources
	TypeName        string // named schema type annotation (e.g., "Q{ns}typeName")
	Keys            []*mergeKey
}

type mergeKey struct {
	Select       *xpath.Expression
	OrderAVT     *avt // non-nil when order is an avt
	DataTypeAVT  *avt // non-nil when data-type is an avt
	CollationAVT *avt // non-nil when collation is an AVT
	LangAVT      *avt
	CaseOrderAVT *avt
	BaseURI      string
	Order        string        // "ascending" or "descending" (static)
	DataType     string        // "text" or "number" (static)
	Collation    string        // collation URI (for XTDE2210 mismatch detection)
	Lang         string        // effective lang attribute value
	CaseOrder    string        // effective case-order attribute value
	Body         []instruction // used when select is absent
	specified    uint8
	HasCollation bool // true when lang, collation, or case-order is specified
}

type mergeInst struct {
	sourceInfo
	Sources []*mergeSource
	Action  []instruction
}

func (*mergeInst) instructionTag() {}

// documentInst represents xsl:document.
// It creates a document node wrapping its content body.
type documentInst struct {
	sourceInfo
	Validation string // "strict", "lax", "preserve", "strip"
	TypeName   string // type annotation (e.g., "Q{ns}typeName")
	Body       []instruction
}

func (*documentInst) instructionTag() {}

type analyzeStringInst struct {
	sourceInfo
	Select          *xpath.Expression
	Regex           *avt
	Flags           *avt
	MatchingBody    []instruction
	NonMatchingBody []instruction
}

func (*analyzeStringInst) instructionTag() {}

// assertInst represents xsl:assert.
// When test evaluates to false, a dynamic error XTMM9001 is raised
// (or the error-code specified by the error-code attribute).
type assertInst struct {
	sourceInfo
	xpathNS
	Test            *xpath.Expression
	Select          *xpath.Expression
	ErrorCode       *avt // default "XTMM9001"
	ErrorNamespaces map[string]string
	Body            []instruction
}

func (*assertInst) instructionTag() {}

type evaluateInst struct {
	sourceInfo
	xpathNS
	XPath            *xpath.Expression // xpath attribute (expression producing the XPath string)
	ContextItem      *xpath.Expression // context-item attribute (optional)
	BaseURI          *avt              // base-uri attribute (optional)
	NamespaceContext *xpath.Expression // namespace-context attribute (optional, expression producing a node)
	WithParamsExpr   *xpath.Expression // with-params attribute (optional, map expression)
	As               string            // as attribute (optional sequence type)
	ResultType       *xdm.SequenceType
	Namespaces       map[string]string
	SchemaAwareAVT   *avt         // nil = absent; non-nil = schema-aware attribute present
	Params           []*withParam // child xsl:with-param elements
}

func (*evaluateInst) instructionTag() {}

// fallbackInst represents a forwards-compatible unknown XSLT instruction.
// At runtime, the Body (from xsl:fallback children) is executed.
// If no xsl:fallback was found, XTDE1450 is raised.
type fallbackInst struct {
	sourceInfo
	Body        []instruction // compiled xsl:fallback children
	Name        string        // original instruction name for error messages
	HasFallback bool          // true if at least one xsl:fallback was found
	ErrorCode   string        // disabled features use their prescribed error instead of XTDE1450
}

func (*fallbackInst) instructionTag() {}
