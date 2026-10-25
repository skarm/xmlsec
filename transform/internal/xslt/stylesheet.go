// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

const (
	// Mode sentinel values per the XSLT 3.0 specification.
	modeDefault = "#default" // the default (unnamed) mode, used as internal key
	modeUnnamed = "#unnamed" // explicit unnamed mode reference
	modeCurrent = "#current" // inherit current mode from caller
	modeAll     = "#all"     // template applies to all modes

	// on-no-match behavior values for xsl:mode.
	onNoMatchDeepCopy     = "deep-copy"
	onNoMatchDeepSkip     = "deep-skip"
	onNoMatchShallowCopy  = "shallow-copy"
	onNoMatchShallowSkip  = "shallow-skip"
	onNoMatchTextOnlyCopy = "text-only-copy"
	onNoMatchFail         = "fail"

	// Validation mode values for validation attribute on xsl:copy, xsl:element, etc.
	validationStrict      = "strict"
	validationLax         = "lax"
	validationPreserve    = "preserve"
	validationStrip       = "strip"
	validationUnspecified = "unspecified"

	// Context item use values for xsl:context-item/@use.
	ctxItemRequired = "required"
	ctxItemOptional = "optional"
	ctxItemAbsent   = "absent"

	// on-multiple-match values for xsl:mode.
	onMultipleMatchUseLast = "use-last"

	// XSLT attribute names used across compile/validation.
	xslAttrName    = "name"
	xslAttrSelect  = "select"
	xslAttrUseWhen = "use-when"

	// XSLT/XPath function names referenced in multiple places.
	funcSystemProperty            = "system-property"
	funcAvailableSystemProperties = "available-system-properties"
	funcSnapshot                  = "snapshot"
)

// Stylesheet retains compiled templates, expressions and static context. Compilation
// finishes its indexes before publication, so the stylesheet can be reused by
// concurrent invocations.
//
// Each invocation owns mutable execution state. Source documents are borrowed
// read-only; whitespace stripping uses a private copy. Host-supplied resolvers,
// handlers and writers can still be shared, so their concurrency safety remains the
// caller's responsibility. The public transform profiles do not support schema-aware
// processing.
type Stylesheet struct {
	packageResolver PackageResolver // resolver used at compile time (for fn:transform package-name)
	uriResolver     URIResolver     // resolver used at compile time (for fn:transform nested compiles)
	// compatExprs holds every compiled XPath expression that must evaluate in
	// XPath 1.0 compatibility mode (XSLT backwards-compatible processing, effective
	// version < 2.0), keyed by pointer identity. nil when the stylesheet has no
	// backwards-compatible subtree, so the common case costs a nil-map lookup.
	compatExprs map[*xpath.Expression]struct{}
	// namedTemplates indexes named template components by expanded QName.
	namedTemplates map[string]*template
	modeTemplates  map[string][]*template // mode -> templates sorted by import-precedence then priority
	// modeIndex holds, per mode, a templateIndex built from modeTemplates[mode]
	// once it is sorted (compiler.sortTemplates), keyed by node kind and
	// expanded name so findFirstMatch / hasConflictingMatch can skip templates
	// their pattern's terminal step provably cannot match. A nil entry (or a
	// missing key) means the mode's list is below templateIndexThreshold, or
	// has no entries at all — dispatch falls back to a plain linear scan.
	// Built once, eagerly, at the end of Compile; never mutated afterward, so
	// it is safe to read from concurrent Transform calls without locking.
	modeIndex map[string]*templateIndex
	// keys retains all key definitions contributing to each expanded key name.
	keys                map[string][]*keyDef
	outputs             map[string]*OutputDef                       // "" = default output
	functions           map[funcKey]*xslFunction                    // xsl:function defs (keyed by name+arity)
	namespaces          map[string]string                           // prefix -> URI from stylesheet
	decimalFormats      map[xpath.QualifiedName]xpath.DecimalFormat // named decimal formats
	decimalFmtPrec      map[xpath.QualifiedName]int                 // import precedence of each decimal format
	decimalFmtSet       map[xpath.QualifiedName]map[string]struct{} // explicitly set properties per format
	decimalFmtConflicts map[xpath.QualifiedName]int                 // pending XTSE1290 conflicts (value = precedence)
	modeDefs            map[string]*modeDef                         // mode name -> mode definition
	attributeSets       map[string]*attributeSetDef                 // xsl:attribute-set definitions
	accumulators        map[string]*accumulatorDef                  // accumulator name -> definition
	sourceDoc           *xdm.Document                               // the parsed stylesheet document (for document(""))
	moduleDocs          map[string]*xdm.Document                    // module base URI -> parsed stylesheet document
	// Visibility maps track per-component visibility for package system.
	// Keys are component names (expanded QNames for templates/variables,
	// QualifiedName.String() for functions with arity suffix).
	templateVisibility    map[string]string     // template name -> visibility
	functionVisibility    map[string]string     // "ns:local#arity" -> visibility
	variableVisibility    map[string]string     // variable name -> visibility
	attrSetVisibility     map[string]string     // attribute-set name -> visibility
	globalParamVisibility map[string]string     // global param name -> visibility
	globalContextItem     *globalContextItemDef // xsl:global-context-item declaration
	// globalContextModules retains module-specific global context declarations.
	globalContextModules map[string]*globalContextItemDef
	characterMaps        map[string]*characterMapDef // name -> character map definition
	parseOptions         *xdm.ParseOptions           // caller-injected base parseOptions from the compiler (forwarded to runtime + fn:transform nested compiles); nil = hardened default
	// version retains the principal module's declared stylesheet version.
	version string
	// defaultMode selects the mode used when invocation entry does not supply one.
	defaultMode          string
	baseURI              string // base URI for resolving relative document references
	defaultValidation    string // "strict", "lax", "preserve", "strip" (default-validation attr)
	inputTypeAnnotations string // "preserve", "strip", "unspecified" (input-type-annotations attr)
	defaultCollation     string // default-collation URI from stylesheet root
	packageName          string // xsl:package/@name
	packageVersion       string // xsl:package/@package-version
	// templates retains compiled template rules in declaration order before dispatch
	// indexing.
	templates  []*template
	globalVars []*variable // topologically sorted
	// globalParams retains top-level parameter declarations for invocation binding.
	globalParams []*param
	// stripSpace retains element-name tests requesting whitespace stripping on private
	// source copies.
	stripSpace []nameTest
	// preserveSpace retains element-name tests preserving whitespace against stripping
	// rules.
	preserveSpace []nameTest
	// accumulatorOrder retains the dependency order for accumulator initialization.
	accumulatorOrder []string
	namespaceAliases []namespaceAlias // xsl:namespace-alias declarations
	usedPackages     []*Stylesheet    // packages loaded via xsl:use-package
	// processorVersion selects the processor's supported language profile independently
	// of declared versions.
	processorVersion int
	maxResourceBytes int64 // per-resource read cap from compiler; 0 = MaxResourceBytes default, <0 = unbounded
	// dynamicEvaluationDisabled records whether the host disallows xsl:evaluate.
	dynamicEvaluationDisabled bool
	schemaAware               bool // true when xsl:import-schema was encountered
	isPackage                 bool // true when compiled from xsl:package root
	declaredModes             bool // xsl:package/@declared-modes (default true)
}

// funcKey identifies an xsl:function by its expanded QName and arity.
type funcKey struct {
	Name  xpath.QualifiedName
	Arity int
}

type globalContextItemDef struct {
	Use string // "required", "optional", "absent"
	As  string // sequence type (e.g., "document-node(element(codd))")
	// Namespaces captures the in-scope namespace bindings (prefix→URI) at the
	// declaration element, so the @as sequence type resolves prefixes exactly
	// as written at the declaration site, and never against the runtime
	// stylesheet-wide namespace map.
	Namespaces map[string]string
	// XPathDefaultNS is the in-scope xpath-default-namespace (default element
	// namespace) at the declaration element. Used to resolve unprefixed names
	// in the @as sequence type.
	XPathDefaultNS    string
	HasXPathDefaultNS bool
}

// namespaceAlias maps a stylesheet namespace URI to a result namespace URI.
type namespaceAlias struct {
	StylesheetURI string // namespace URI used in stylesheet
	ResultURI     string // namespace URI to use in output
	ResultPrefix  string // preferred prefix for the result namespace
	ImportPrec    int    // import precedence for conflict resolution
}

type modeDef struct {
	OwnerPackage        *Stylesheet // non-nil for a mode accepted from another package
	UseAccumulators     *string     // nil = attribute absent; non-nil = attribute present (space-separated names, "#all", or "")
	Name                string
	OnNoMatch           string // "shallow-copy", "deep-copy", "shallow-skip", "deep-skip", "text-only-copy", "fail"
	Typed               string // "strict", "lax", "unspecified", "yes", "no"
	Visibility          string // "public", "private", "final"
	OnMultipleMatch     string // "use-last", "fail"
	ImportPrec          int
	Implicit            bool // created from a template rule, with no matching xsl:expose
	Streamable          bool
	conflictStreamable  bool // deferred: conflicting streamable at same prec
	conflictOnNoMatch   bool
	conflictVisibility  bool
	conflictOnMultiple  bool
	conflictAccumulator bool
}

// attributeSetPart represents a single xsl:attribute-set declaration.
// Multiple same-named declarations are stored as separate parts.
type attributeSetPart struct {
	UseAttrSets   []string      // names of other attribute sets to include
	Attrs         []instruction // xsl:attribute instructions
	StaticBaseURI string        // effective static base URI from xml:base on this declaration
}

type attributeSetDef struct {
	Name            string
	UseAttrSets     []string           // flattened: all use-attribute-sets (legacy, used by streamability)
	Attrs           []instruction      // flattened: all xsl:attribute instructions (legacy, used by streamability)
	Parts           []attributeSetPart // ordered parts from same-named declarations
	Visibility      string             // "public", "private", "final", "abstract"
	Streamable      bool               // streamable="yes" on the attribute-set
	OriginalAttrSet *attributeSetDef   // original attribute-set being overridden (for xsl:original)
	OwnerPackage    *Stylesheet        // owning package (nil for locally declared)
}

type xslFunction struct {
	signatureTypeKey string

	Name          xpath.QualifiedName
	Params        []*param
	Body          []instruction
	As            string       // return type constraint (e.g., "xs:string?")
	Cache         bool         // cache="yes" encourages result memoization by argument values
	Streamability string       // "absorbing", "inspection", etc.; "" = unspecified
	Visibility    string       // "public", "private", "final", "abstract"
	NewEachTime   string       // "yes", "no", "maybe"; "" = unspecified (defaults to "maybe")
	OwnerPackage  *Stylesheet  // package that defined this function (nil = main stylesheet)
	AcceptedFrom  *Stylesheet  // use-package that accepted this function (for XTSE3050 detection)
	ImportPrec    int          // import precedence for XTSE0770 conflict detection
	OriginalFunc  *xslFunction // original function being overridden (for xsl:original calls)
	IsOverride    bool         // true if this function was defined in xsl:override

	// Call-time data that prepareCall derives once from the fields above.
	cacheAtomicSelf bool               // select-only arithmetic/self recursion, with no dynamic or external calls
	selectOnly      bool               // Body holds only select-form xsl:sequence instructions
	paramTypes      []xdm.SequenceType // declaration-bound parameter types for XPath function conversion
	returnType      *xdm.SequenceType  // declaration-bound return type; nil if As is empty
}

type template struct {
	Match            *pattern
	OwnerPackage     *Stylesheet // package that defined this template (nil = main stylesheet)
	OriginalTemplate *template   // original template being overridden (for xsl:original calls)
	// splitOriginID identifies the originating template rule when a union match
	// pattern (P1 | P2) is split into separate template entries. All split
	// branches of one rule share the same non-nil identity so the on-multiple-match
	// conflict checks can treat them as a single rule (spec bug 30402). Nil means
	// the template was not produced by a union split. The identity is allocated by
	// nextSplitOriginID so splits from independently
	// compiled packages merged via xsl:use-package never collide.
	splitOriginID     *splitOrigin
	signatureTypeKey  string
	contextTypeKey    string
	contextItemType   *xdm.SequenceType // bound in the xsl:context-item declaration's scope
	Name              string
	Mode              string // "" = default, "#all" = all modes
	As                string // return type constraint (e.g., "element()")
	ContextItemAs     string // xsl:context-item/@as type constraint
	ContextItemUse    string // xsl:context-item/@use: "required" (default), "optional", "absent"
	XPathDefaultNS    string // xpath-default-namespace (inherited or explicit)
	DefaultCollation  string // default-collation URI (inherited or explicit)
	BaseURI           string // base URI of the stylesheet module that defined this template
	Visibility        string // "public", "private", "final", "abstract"
	Version           string // effective version (from template or stylesheet)
	Params            []*param
	Body              []instruction
	Priority          float64
	ImportPrec        int
	MinImportPrec     int  // lowest import precedence among this module's imports (for apply-imports boundary)
	conflictDuplicate bool // deferred XTSE0660, discarded by a higher-precedence declaration
	// explicitPriority reports a priority attribute on the template. Without
	// one, a union match pattern is split into one rule per alternative
	// (templateRules).
	explicitPriority bool
}

type variable struct {
	signatureTypeKey  string
	TypeNamespaces    map[string]string
	HasXPathDefaultNS bool

	Name           string
	Select         *xpath.Expression
	Body           []instruction // used when select is absent
	As             string        // type declaration (e.g., "element()*")
	Visibility     string        // "public", "private", "final", "abstract"
	OwnerPackage   *Stylesheet   // package that defined this variable (nil = main stylesheet)
	Original       globalBinding // hidden original component bound to $xsl:original
	Declaration    *variable     // shared declaration identity of accepted copies
	ImportPrec     int           // import precedence for XTSE0630 duplicate detection
	StaticValue    xdm.Sequence  // pre-computed value for static="yes" variables
	XPathDefaultNS string        // xpath-default-namespace in scope at definition site
	StaticBaseURI  string        // declaration-site static base URI (module base + any xml:base override)
}

type param struct {
	StaticValue       xdm.Sequence
	Original          globalBinding
	TypeNamespaces    map[string]string
	OwnerPackage      *Stylesheet
	Declaration       *param
	Select            *xpath.Expression
	signatureTypeKey  string
	XPathDefaultNS    string
	Name              string
	As                string        // type declaration (e.g., "xs:integer")
	Visibility        string        // "public", "private", "final", "abstract" (for global params)
	StaticBaseURI     string        // declaration-site static base URI (module base + any xml:base override)
	Body              []instruction // used when select is absent
	ImportPrec        int           // import precedence for XTSE0630 duplicate detection
	HasXPathDefaultNS bool
	IsStatic          bool // xmlsec: static parameters retain their compile-time values.
	Required          bool
	Tunnel            bool
}

func (p *param) implicitlyMandatory() bool {
	return p.Select == nil && len(p.Body) == 0 && p.As != "" && !allowsEmptySequence(p.As)
}

// globalBinding identifies one declaration, independently of its symbolic name
// and of the accepted copies exposing it in other packages.
type globalBinding struct {
	variable *variable
	param    *param
}

func (v *variable) binding() globalBinding {
	if v.Declaration != nil {
		return globalBinding{variable: v.Declaration}
	}

	return globalBinding{variable: v}
}

func (p *param) binding() globalBinding {
	if p.Declaration != nil {
		return globalBinding{param: p.Declaration}
	}

	return globalBinding{param: p}
}

func (b globalBinding) typeKey() string {
	if b.variable != nil {
		return b.variable.signatureTypeKey
	}

	return b.param.signatureTypeKey
}

type keyDef struct {
	StaticBaseURI string
	Match         *pattern
	Use           *xpath.Expression
	Name          string
	Collation     string        // collation URI (explicit or default; empty = codepoint)
	Body          []instruction // content constructor (when use attribute is absent)
	Composite     bool          // composite="yes" on xsl:key
	Compat        bool          // backwards-compatible processing (effective version < 2.0)
}

type characterMapDef struct {
	Name             string          // expanded QName
	Mappings         map[rune]string // character -> replacement string
	UseCharacterMaps []string        // other character maps to include
}

type accumulatorDef struct {
	Initial           *xpath.Expression
	Name              string
	As                string            // type declaration
	Type              *xdm.SequenceType // type bound in the declaration static context
	InitialBody       []instruction
	Rules             []*accumulatorRule
	ImportPrec        int // import precedence for conflict resolution
	Streamable        bool
	FromPackage       bool // true if imported via xsl:use-package
	conflictDuplicate bool // deferred XTSE3350: same-precedence duplicate
	CyclicDeps        bool // XTDE3400: cyclic dependency detected
}

type accumulatorRule struct {
	Match  *pattern
	Phase  string // "start" or "end"
	Select *xpath.Expression
	Body   []instruction
	New    bool // new="yes" starts a fresh value
}

// nameTest is used for xsl:strip-space and xsl:preserve-space element names.
//
// The namespace URI for a prefixed or default-namespace name is resolved at
// compile time using the namespace context in scope at the declaration (the
// xsl:strip-space / xsl:preserve-space element). This is required because a
// stylesheet and the modules it imports may bind the same prefix to different
// URIs; relying on a single flat runtime binding map would mis-resolve such
// names. ImportPrec records the import precedence of the declaring module so
// that conflicting strip/preserve rules are resolved by precedence (XTSE0270
// is only raised for genuine same-precedence conflicts).
type nameTest struct {
	Prefix     string
	Local      string // "*" = wildcard
	URI        string // resolved namespace URI (set at compile time)
	HasURI     bool   // true when URI was explicitly resolved (distinguishes "" from unset)
	ImportPrec int    // import precedence of the declaring module
	SpaceOrder int    // declaration order for XSLT 2.0 whitespace conflict recovery
}

// DefaultOutputDef returns the default output definition for the stylesheet
// as declared at compile time. For the effective output definition that
// includes runtime overrides from xsl:result-document, use
// Invocation.ResolvedOutputDef after calling Do.
func (ss *Stylesheet) DefaultOutputDef() *OutputDef {
	if ss == nil {
		return nil
	}

	out := cloneOutputDef(ss.outputs[""])
	if out == nil && ss.processorLanguage() <= 20 {
		out = defaultOutputDef()
	}

	if out != nil {
		out.serializationVersion = ss.processorLanguage()
	}

	return out
}

// Transform creates an Invocation that applies templates to the source
// document using the default mode.
func (ss *Stylesheet) Transform(source *xdm.Document) Invocation {
	inv := newInvocation(ss, invocationTransform)
	inv.cfg.source = source

	return inv
}

// ApplyTemplates creates an Invocation that applies templates with
// explicit mode and selection control.
func (ss *Stylesheet) ApplyTemplates(source *xdm.Document) Invocation {
	inv := newInvocation(ss, invocationApplyTemplates)
	inv.cfg.source = source

	return inv
}

// CallTemplate creates an Invocation that calls a named template directly.
func (ss *Stylesheet) CallTemplate(name string) Invocation {
	inv := newInvocation(ss, invocationCallTemplate)
	inv.cfg.initialTemplate = name

	return inv
}

// CallFunction creates an Invocation that calls a named function directly.
func (ss *Stylesheet) CallFunction(name string, args ...xdm.Sequence) Invocation {
	inv := newInvocation(ss, invocationCallFunction)
	inv.cfg.initialFunction = name
	inv.cfg.initialArgs = args

	return inv
}

// defaultItemSeparator returns the item-separator from the default output
// definition, or nil if not set.
func (ss *Stylesheet) defaultItemSeparator() *string {
	if ss == nil {
		return nil
	}

	if outDef, ok := ss.outputs[""]; ok {
		return outDef.ItemSeparator
	}

	return nil
}

// OutputDef retains serialization settings for a compiled xsl:output definition. Nil
// means no explicit definition; Get methods accept a nil receiver.
//
// Fields ending in Explicit distinguish source settings from defaults. Fields ending
// in Raw retain source spelling for conflict checks. Optional pointers distinguish an
// omitted parameter from an explicit false or empty value.
//
// Execution resolves character maps into an invocation-local output definition. Treat
// values returned by Invocation.ResolvedOutputDef as read-only.
type OutputDef struct {
	// serializationVersion is the selected processor contract, independent of
	// source backwards-compatibility and the serialized HTML version.
	serializationVersion int
	canEncode            func(rune) bool // invocation-local repertoire check for character content
	IncludeContentType   *bool           // include-content-type: nil=default(yes), true/false
	ItemSeparator        *string         // item-separator serialization parameter; nil = not set
	EscapeURIAttributes  *bool           // escape-uri-attributes: nil=default(true), true/false
	ResolvedCharMap      map[rune]string // resolved character map (populated at runtime)
	BuildTree            *bool           // build-tree: nil=default(true), true/false
	// Name is the expanded QName of the output definition (empty for the
	// unnamed primary definition).
	Name string
	// Method is the output method: "xml", "html", "text", "xhtml", "json", or "adaptive".
	Method string
	// Encoding is the character encoding for the output.
	Encoding string
	// Standalone is the standalone document declaration: "yes", "no", or "omit".
	Standalone string
	// DoctypePublic is the PUBLIC identifier for the emitted DOCTYPE.
	DoctypePublic string
	// DoctypeSystem is the SYSTEM identifier for the emitted DOCTYPE.
	DoctypeSystem string
	// MediaType is the MIME media type of the output.
	MediaType string
	// Version selects the requested XML or HTML output version. HTMLVersion takes
	// precedence for HTML serialization when supplied.
	Version              string
	HTMLVersion          string // html-version: "5", "4.0", etc.
	NormalizationForm    string // "NFC", "NFD", "NFKC", "NFKD", "fully-normalized", "none"
	JSONNodeOutputMethod string // json-node-output-method: "xml", "html", "xhtml", "text"
	ParameterDocument    string // parameter-document URI
	// MethodRaw and the other Raw fields retain literal attribute values for
	// XTSE1560 conflict detection.
	MethodRaw string
	// IndentRaw retains the literal indent attribute for output-declaration conflict
	// checks.
	IndentRaw string
	// EncodingRaw retains the literal encoding attribute for output-declaration conflict
	// checks.
	EncodingRaw string
	// VersionRaw retains the literal version attribute for output-declaration conflict
	// checks.
	VersionRaw string
	// StandaloneRaw retains the literal standalone attribute for output-declaration
	// conflict checks.
	StandaloneRaw string
	// CDATASections lists element names whose text content is emitted as CDATA.
	CDATASections       []string
	UseCharacterMaps    []string // names of character maps to use
	SuppressIndentation []string // suppress-indentation element names
	// languageVersion preserves host-language serialization defaults.
	languageVersion int
	// An implicit result from a 1.0 principal module defaults to XML even
	// with an XHTML html element. Explicit result-document output is exempt.
	implicitXMLMethod bool
	ImportPrec        int // import precedence for XTSE1560 conflict detection
	// MethodExplicit is true when method was explicitly specified (not defaulted).
	MethodExplicit bool
	// Indent enables pretty-printing of the output.
	Indent bool
	// OmitDeclaration suppresses the XML declaration.
	OmitDeclaration bool
	// OmitDeclarationExplicit is true when omit-xml-declaration was explicitly set.
	OmitDeclarationExplicit bool
	// UndeclarePrefixes enables namespace-undeclaration in XML 1.1 output.
	UndeclarePrefixes   bool
	ItemSeparatorAbsent bool // true when item-separator="#absent" was explicitly set
	ByteOrderMark       bool // byte-order-mark: emit BOM at start of output
	AllowDuplicateNames bool // allow-duplicate-names for JSON output
}

// GetUseCharacterMaps returns the use-character-maps list, nil-safe.
func (o *OutputDef) GetUseCharacterMaps() []string {
	if o == nil {
		return nil
	}

	return o.UseCharacterMaps
}

// processorLanguage also covers internal zero-value stylesheet helpers.
func (ss *Stylesheet) processorLanguage() int {
	if ss.processorVersion == 0 {
		return 30
	}

	return ss.processorVersion
}

func (ss *Stylesheet) xpathVersion() int {
	switch ss.processorLanguage() {
	case 10:
		return 10
	case 20:
		return 20
	default:
		return 31
	}
}
