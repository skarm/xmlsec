// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	norm "github.com/skarm/xmlsec/internal/normalization"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/internal/xmloutput"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/encoding"
	"github.com/skarm/xmlsec/transform/internal/xdm/html"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexical"
)

const (
	errCodeSEPM0017 = "SEPM0017"
	errCodeSEPM0018 = "SEPM0018"
	errCodeSEPM0019 = "SEPM0019"
	errCodeSERE0020 = "SERE0020"
	errCodeSERE0021 = "SERE0021"
	errCodeSERE0023 = "SERE0023"
)

// Named types from the published serialization-parameter schemas.
const (
	serializeStringParamType          = "string-param-type"
	serializeTokenizedStringParamType = "tokenized-string-param-type"
	serializeQualifiedEQNameType      = "Qualified-EQName"
	serializeQNameOrEQNameType        = "QName-or-EQName"
	serializeJSONNodeMethodType       = "json-node-output-method-type"
	serializePrefixedQNameType        = "Prefixed-QName"
	serializeCharacterMapsParamType   = "use-character-maps-param-type"
)

func lookupFunctionsSerialize(name string) (*builtinFunc, bool) {
	switch name {
	case "serialize":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnSerialize}, true
	}

	return nil, false
}

func fnSerialize(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	opts, err := parseSerializeOptions(ctx, args)
	if err != nil {
		return nil, err
	}

	if err := opts.validate(); err != nil {
		return nil, err
	}

	var result string

	switch opts.method {
	case "":
		result, err = serializeXMLSequence(args[0], opts)
	case lexicon.MethodAdaptive:
		result, err = serializeAdaptiveSequence(args[0], opts)
	case lexicon.MethodJSON:
		result, err = serializeJSONSequence(args[0], opts)
	case lexicon.MethodHTML:
		validator := htmlSequenceValidator{ctx: ctx, html5: serializeHTMLIsVersion5(opts), separator: opts.itemSeparator}
		if err = validator.sequence(args[0], 0); err == nil {
			result, err = serializeHTMLSequence(args[0], opts)
		}
	case lexicon.MethodText:
		result, err = serializeTextSequence(args[0], opts)
	default:
		// XML and XHTML share sequence normalization and XML character rules.
		result, err = serializeXMLSequence(args[0], opts)
	}

	if err != nil {
		return nil, err
	}

	// Markup and JSON normalize content before escaping. Only text without
	// character maps still normalizes the concatenated string here. Mapped
	// text and adaptive values normalize unmapped runs at their write sites.

	switch opts.method {
	case lexicon.MethodText:
		if len(opts.charMap) == 0 {
			result, err = applySerializeNormalization(result, opts)
			if err != nil {
				return nil, err
			}
		}
	}

	return xdm.SingleString(result), nil
}

// serializeNormForm maps a supported normalization-form name (NFC/NFD/NFKC/NFKD)
// to its golang.org/x/text norm.Form. Any other value (none/"", or the
// unsupported "fully-normalized", which fnSerialize rejects up front as SESU0011)
// reports false.
func serializeNormForm(form string) (norm.Form, bool) {
	switch form {
	case nameNFC:
		return norm.NFC, true
	case nameNFD:
		return norm.NFD, true
	case nameNFKC:
		return norm.NFKC, true
	case nameNFKD:
		return norm.NFKD, true
	}

	return norm.NFC, false
}

// serializeCharMapNorm selects content normalization before escaping. JSON
// requires this even without a map: normalization can introduce quotes or
// backslashes that must then receive JSON escaping.
func serializeCharMapNorm(opts serializeOptions) (norm.Form, bool) {
	if len(opts.charMap) == 0 && opts.method != lexicon.MethodJSON || !opts.methodAppliesNormalization() || !serializeNormalizationActive(opts.normalizationForm) {
		return norm.NFC, false
	}

	return serializeNormForm(opts.normalizationForm)
}

// applySerializeNormalization applies the normalization-form parameter to a whole
// serialized string. It is used only by the text and json output methods (and
// only when no character map is in force — with one, the character-map
// application sites normalize each non-mapped run themselves), whose output is
// pure character data (text) or ASCII-delimited character data (json), so
// normalizing the whole string is equivalent to the node-scoped
// character-expansion phase (Serialization 3.1 §4); the markup methods
// (xml/xhtml/html) normalize inside their writer instead so element/attribute
// names and other markup are never touched. none/"" is a no-op;
// NFC/NFD/NFKC/NFKD are applied via golang.org/x/text/unicode/norm; the
// W3C-specific "fully-normalized" form is rejected up front (SESU0011).
func applySerializeNormalization(s string, opts serializeOptions) (string, error) {
	form := opts.normalizationForm
	if form == "" || form == nameNone || !opts.methodAppliesNormalization() {
		return s, nil
	}

	_, ok := serializeNormForm(form)
	if !ok {
		return "", &xdm.Error{Code: lexicon.ErrSESU0011, Message: fmt.Sprintf("normalization-form %q is not supported", form)}
	}

	return normalizeSerializedValue(s, opts)
}

type serializeOptions struct {
	ctx   context.Context
	depth int
	// edition is the serialization contract selected by the originating
	// XPath function context. Zero denotes the shared 3.1 host defaults.
	edition int
	// cdataElements / suppressIndent hold the exact expanded {uri}local element
	// names for the cdata-section-elements and suppress-indentation parameters.
	cdataElements  map[string]struct{}
	suppressIndent map[string]struct{}
	// charMap is the resolved character map (use-character-maps).
	charMap map[rune]string
	method  string
	// itemSeparator is the item-separator parameter value; itemSeparatorSet
	// records whether it was explicitly specified. Per Serialization 3.1 §2
	// (sequence normalization, step 3) an ABSENT item-separator inserts a single
	// space ONLY between two adjacent atomic-value-derived strings (never between
	// nodes, nor between a node and an atomic value); a PRESENT item-separator is
	// inserted between EVERY adjacent pair of items regardless of kind.
	itemSeparator string
	encoding      string
	// standalone is the resolved standalone pseudo-attribute request:
	// "yes"/"no" force it, "omit" forces omission. It defaults to "omit" (the
	// Serialization 3.1 default), so a source declaration's standalone is not
	// retained unless the parameter requests it.
	standalone string
	// xmlVersion is the requested output version parameter ("" = unspecified,
	// treated as "1.0").
	xmlVersion string
	// htmlVersion is the requested html-version ("" = default 5.0). doctypePublic
	// / doctypeSystem are the requested DOCTYPE identifiers.
	htmlVersion   string
	doctypePublic string
	doctypeSystem string
	// mediaType is the media-type parameter ("" = default "text/html"), used in
	// the html Content-Type meta element.
	mediaType string
	// normalizationForm is the requested Unicode normalization form ("" / "none"
	// = no normalization). NFC/NFD/NFKC/NFKD are applied to the serialized output
	// for the methods that support normalization — xml/xhtml/html/text, json, and
	// adaptive (§9.1.9); "fully-normalized" is the SESU0011 unsupported-
	// normalization serialization error.
	normalizationForm string
	// jsonNodeOutputMethod selects xml, html, xhtml or text output for nodes embedded in
	// JSON. Empty selects xml; unsupported extension methods are rejected when dispatched.
	jsonNodeOutputMethod string
	itemSeparatorSet     bool
	indent               bool
	omitXMLDeclaration   bool
	allowDuplicateNames  bool
	// undeclarePrefixes requests XML 1.1 namespace undeclarations (xmlns:pfx="").
	// It is honored only when the effective output version is 1.1; otherwise it
	// is a SEPM0010 static error.
	undeclarePrefixes bool
	// HTML output-method parameters.
	// includeContentType / escapeURIAttributes default to true.
	includeContentType  bool
	escapeURIAttributes bool
}

// effectiveSerializeVersion returns the effective output version, defaulting an
// unspecified version to "1.0".
func (opts serializeOptions) effectiveSerializeVersion() string {
	if opts.xmlVersion == "" {
		return lexicon.XMLVersion10
	}

	return opts.xmlVersion
}

// methodEmitsXMLDeclaration reports whether the output method produces an XML
// declaration (the xml and xhtml methods, and the unspecified default). The
// omit-xml-declaration / standalone / SEPM0009 rules apply only to these; for
// html/json/text/adaptive an XML declaration is never produced.
func (opts serializeOptions) methodEmitsXMLDeclaration() bool {
	switch opts.method {
	case "", lexicon.MethodXML, lexicon.MethodXHTML:
		return true
	}

	return false
}

// methodEmitsDoctype reports whether the output method emits a document type
// declaration from the doctype-system / doctype-public parameters (the xml,
// xhtml, and html methods, and the unspecified xml default). doctype-system is
// applicable to these methods (Serialization 3.1 §5.1.7 for xml/xhtml, §7.4.6 for
// html) and is ignored by the text/json/adaptive methods.
func (opts serializeOptions) methodEmitsDoctype() bool {
	switch opts.method {
	case "", lexicon.MethodXML, lexicon.MethodXHTML, lexicon.MethodHTML:
		return true
	}

	return false
}

// validate checks method-specific parameter constraints before output starts.
func (opts serializeOptions) validate() error {
	if opts.edition == 30 && (opts.method == lexicon.MethodJSON || opts.method == lexicon.MethodAdaptive) {
		return &xdm.Error{Code: lexicon.ErrSEPM0016, Message: fmt.Sprintf("output method %q is not defined by Serialization 3.0", opts.method)}
	}
	// An extension method (a prefixed QName) is a valid method-type value but
	// the serializer implements no extension output methods, so it is an unsupported
	// value (SEPM0016), with no silent fall-through to the xml method. The
	// built-in methods and the unspecified default ("") are supported.
	if opts.method != "" && !isBuiltinSerializeMethod(opts.method) {
		return &xdm.Error{Code: lexicon.ErrSEPM0016, Message: fmt.Sprintf("output method %q is not supported", opts.method)}
	}

	if opts.method == lexicon.MethodHTML {
		version := html.RequestedVersion(opts.htmlVersion, opts.xmlVersion)
		if !html.SupportedVersion(version) {
			return &xdm.Error{Code: lexicon.ErrSESU0013, Message: fmt.Sprintf("HTML output version %q is not supported", version)}
		}
	}

	// The version parameter, for the methods that emit an XML declaration, must
	// name an XML version the serializer supports (1.0 or 1.1); any other value
	// is the SESU0013 unsupported-version serialization error, and never a
	// bogus version pseudo-attribute. It also drives the XML 1.1 escaping /
	// undeclaration rules, so it must be validated even when the declaration is
	// omitted.
	if opts.methodEmitsXMLDeclaration() && opts.xmlVersion != "" && !isSupportedXMLOutputVersion(opts.xmlVersion) {
		return &xdm.Error{Code: lexicon.ErrSESU0013, Message: fmt.Sprintf("XML output version %q is not supported", opts.xmlVersion)}
	}

	// Parameter domains are checked before method-specific effects. In
	// particular, ignored metadata still has to be a valid parameter value.
	if !xmloutput.ValidPublicID(opts.doctypePublic) || !xmloutput.ValidSystemID(opts.doctypeSystem) {
		return &xdm.Error{Code: lexicon.ErrSEPM0016, Message: "invalid doctype identifier"}
	}

	// SEPM0009 (Serialization 3.1): when the omit-xml-declaration parameter is
	// yes, it is an error if (a) the standalone parameter has a value other than
	// omit, OR (b) the version parameter has a value other than 1.0 AND the
	// doctype-system parameter is specified. Both sub-conditions are gated on
	// omit-xml-declaration=yes. It applies only to methods that emit an XML
	// declaration (xml/xhtml/default); this uses the EFFECTIVE
	// omit-xml-declaration (the map-form default of true) and the RESOLVED
	// standalone value. A DOCTYPE without an XML declaration is well-formed in
	// XML 1.0, so omit + doctype-system at version 1.0 is NOT an error.
	if opts.methodEmitsXMLDeclaration() && opts.omitXMLDeclaration {
		if opts.standalone == lexicon.ValueYes || opts.standalone == lexicon.ValueNo {
			return &xdm.Error{Code: lexicon.ErrSEPM0009, Message: "omit-xml-declaration=yes conflicts with standalone=yes/no"}
		}

		if opts.effectiveSerializeVersion() != lexicon.XMLVersion10 && opts.doctypeSystem != "" {
			return &xdm.Error{Code: lexicon.ErrSEPM0009, Message: "omit-xml-declaration=yes conflicts with a doctype-system value at version other than 1.0"}
		}
	}

	// Namespace undeclarations require XML/XHTML 1.1; requesting them at an
	// effective output version of 1.0 is a static error (Serialization 3.1 §5.1.8
	// SEPM0010). undeclare-prefixes is applicable ONLY to the xml and xhtml output
	// methods (and the unspecified xml default) — for html/text/json/adaptive it is
	// silently ignored, no error — so SEPM0010 is gated to that method family
	// (methodEmitsXMLDeclaration covers exactly {"", xml, xhtml}).
	if opts.methodEmitsXMLDeclaration() && opts.undeclarePrefixes && opts.effectiveSerializeVersion() != lexicon.XMLVersion11 {
		return &xdm.Error{Code: lexicon.ErrSEPM0010, Message: "undeclare-prefixes requires output version 1.1"}
	}

	// Validate the normalization-form up front so an unsupported form
	// ("fully-normalized" → SESU0011) is reported for every method that applies
	// normalization, even when the serialized output has no text/attribute content
	// to normalize (e.g. an empty element under the xml method). NFC/NFD/NFKC/NFKD
	// are applied later — inside the writer for the markup methods (scoped to
	// text/attribute nodes), to the whole output for text/json (pure character
	// data), or while adaptive serializes its string-like atomics.
	if opts.methodAppliesNormalization() && serializeNormalizationActive(opts.normalizationForm) && !isSupportedSerializeNormForm(opts.normalizationForm) {
		return &xdm.Error{Code: lexicon.ErrSESU0011, Message: fmt.Sprintf("normalization-form %q is not supported", opts.normalizationForm)}
	}

	return nil
}

// methodAppliesNormalization reports whether the output method applies the
// normalization-form parameter. Per Serialization 3.1 it is a parameter of the
// xml/xhtml/html/text, json, AND adaptive (§9.1.9) output methods and the
// unspecified default.
func (opts serializeOptions) methodAppliesNormalization() bool {
	switch opts.method {
	case "", lexicon.MethodXML, lexicon.MethodXHTML, lexicon.MethodHTML, lexicon.MethodText, lexicon.MethodJSON, lexicon.MethodAdaptive:
		return true
	}

	return false
}

// booleanParam binds each boolean parameter to its option field. A recognized
// nil target requests lexical validation only: UTF-8 output emits no BOM.
func (opts *serializeOptions) booleanParam(name string) (*bool, bool) {
	switch name {
	case lexicon.SerializationIndent:
		return &opts.indent, true
	case lexicon.SerializationOmitXMLDeclaration:
		return &opts.omitXMLDeclaration, true
	case lexicon.SerializationAllowDuplicateNames:
		return &opts.allowDuplicateNames, true
	case lexicon.SerializationUndeclarePrefixes:
		return &opts.undeclarePrefixes, true
	case lexicon.SerializationEscapeURIAttributes:
		return &opts.escapeURIAttributes, true
	case lexicon.SerializationIncludeContentType:
		return &opts.includeContentType, true
	case lexicon.SerializationByteOrderMark:
		return nil, true
	default:
		return nil, false
	}
}

func (opts *serializeOptions) stringParam(name string) *string {
	switch name {
	case lexicon.SerializationMethod:
		return &opts.method
	case lexicon.SerializationItemSeparator:
		return &opts.itemSeparator
	case lexicon.SerializationEncoding:
		return &opts.encoding
	case lexicon.SerializationVersion:
		return &opts.xmlVersion
	case lexicon.SerializationHTMLVersion:
		return &opts.htmlVersion
	case lexicon.SerializationDoctypePublic:
		return &opts.doctypePublic
	case lexicon.SerializationDoctypeSystem:
		return &opts.doctypeSystem
	case lexicon.SerializationJSONNodeOutputMethod:
		return &opts.jsonNodeOutputMethod
	case lexicon.SerializationNormalizationForm:
		return &opts.normalizationForm
	case lexicon.SerializationMediaType:
		return &opts.mediaType
	case lexicon.SerializationStandalone:
		return &opts.standalone
	default:
		return nil
	}
}

// isSupportedSerializeNormForm reports the implemented Unicode forms. Other
// valid NMTOKEN values, including fully-normalized, raise SESU0011.
func isSupportedSerializeNormForm(form string) bool {
	switch form {
	case nameNFC, nameNFD, nameNFKC, nameNFKD:
		return true
	}

	return false
}

// serializeNormalizationActive reports whether the normalization-form parameter
// requests an actual Unicode normalization (anything other than none/"").
func serializeNormalizationActive(form string) bool {
	return form != "" && form != nameNone
}

// isSupportedXMLOutputVersion reports whether v selects XML 1.0 or XML 1.1 output.
// Parameter validation reports other values as unsupported versions.
func isSupportedXMLOutputVersion(v string) bool {
	return v == lexicon.XMLVersion10 || v == lexicon.XMLVersion11
}

// isBuiltinSerializeMethod reports whether v names a supported built-in
// output method.
func isBuiltinSerializeMethod(v string) bool {
	switch v {
	case lexicon.MethodXML, lexicon.MethodHTML, lexicon.MethodXHTML, lexicon.MethodText, lexicon.MethodJSON, lexicon.MethodAdaptive:
		return true
	}

	return false
}

func parseSerializeOptions(ctx context.Context, args []xdm.Sequence) (serializeOptions, error) {
	// The host defaults to XML without a declaration for both node and atomic
	// input. Adaptive output must be requested explicitly.
	opts := serializeOptions{
		ctx:                ctx,
		omitXMLDeclaration: true,
		method:             "",
		itemSeparator:      " ",
		// The Serialization 3.1 default for the standalone parameter is "omit".
		standalone: lexicon.ValueOmit,
		// include-content-type and escape-uri-attributes default to yes.
		includeContentType:  true,
		escapeURIAttributes: true,
	}
	if ec := getFnContext(ctx); ec != nil && ec.version == 30 {
		opts.edition = 30
	}

	if len(args) <= 1 || xdm.SequenceLen(args[1]) == 0 {
		return opts, nil
	}

	if xdm.SequenceLen(args[1]) != 1 {
		return opts, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize options must be a singleton"}
	}

	if m, ok := args[1].Get(0).(xdm.MapItem); ok {
		if opts.edition == 30 {
			return opts, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "XPath 3.0 serialization parameters must be an output:serialization-parameters element"}
		}

		return parseSerializeOptionsMap(ctx, opts, m)
	}

	node, ok := args[1].Get(0).(xdm.NodeItem)
	if !ok {
		return opts, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize options must be a parameter element or map"}
	}

	return parseSerializeOptionsNode(opts, node.Node)
}

func parseSerializeOptionsMap(ctx context.Context, opts serializeOptions, m xdm.MapItem) (serializeOptions, error) {
	// Map-form parameters default to UTF-8, including its XML declaration label.
	opts.encoding = lexicon.EncodingUTF8U
	// F&O 3.1 section 14.7.3 fixes this map-option default at 5.
	// It is supplied even when the separate version option is explicit.
	opts.htmlVersion = "5"

	var err error

	opts, err = parseSerializeMapOutputOptions(ctx, opts, m)
	if err != nil {
		return opts, err
	}

	opts, err = parseSerializeMapMarkupOptions(ctx, opts, m)
	if err != nil {
		return opts, err
	}

	return parseSerializeMapContentOptions(ctx, opts, m)
}

func parseSerializeMapOutputOptions(ctx context.Context, opts serializeOptions, m xdm.MapItem) (serializeOptions, error) {
	method, found, err := resolveSerializeMethodMap(ctx, m)
	if err != nil {
		return opts, err
	}

	if found {
		opts.method = method
	}

	sep, found, err := readSerializeStringOption(ctx, m, lexicon.SerializationItemSeparator)
	if err != nil {
		return opts, err
	}

	if found {
		opts.itemSeparator = sep
		opts.itemSeparatorSet = true
	}

	indent, found, err := readSerializeBooleanOption(ctx, m, lexicon.SerializationIndent)
	if err != nil {
		return opts, err
	}

	if found {
		opts.indent = indent
	}
	// The map form of fn:serialize defaults omit-xml-declaration to true:
	// supplying an empty map has the same effect as omitting the argument, and
	// the XML declaration is omitted unless the option requests otherwise
	// (F&O 3.1 §14.7.3; W3C serialize-xml-127a).
	opts.omitXMLDeclaration = true

	omit, found, err := readSerializeBooleanOption(ctx, m, lexicon.SerializationOmitXMLDeclaration)
	if err != nil {
		return opts, err
	}

	if found {
		opts.omitXMLDeclaration = omit
	}

	allow, found, err := readSerializeBooleanOption(ctx, m, lexicon.SerializationAllowDuplicateNames)
	if err != nil {
		return opts, err
	}

	if found {
		opts.allowDuplicateNames = allow
	}

	encoding, found, err := readSerializeStringOption(ctx, m, lexicon.SerializationEncoding)
	if err != nil {
		return opts, err
	}

	if found {
		if !xmlchar.IsValidEncName(encoding) {
			return opts, &xdm.Error{Code: lexicon.ErrSEPM0016, Message: "invalid serialization encoding name"}
		}

		opts.encoding = encoding
	}

	return opts, nil
}

func parseSerializeMapMarkupOptions(ctx context.Context, opts serializeOptions, m xdm.MapItem) (serializeOptions, error) {
	undeclare, found, err := readSerializeBooleanOption(ctx, m, lexicon.SerializationUndeclarePrefixes)
	if err != nil {
		return opts, err
	}

	if found {
		opts.undeclarePrefixes = undeclare
	}

	include, found, err := readSerializeBooleanOption(ctx, m, lexicon.SerializationIncludeContentType)
	if err != nil {
		return opts, err
	}

	if found {
		opts.includeContentType = include
	}

	escape, found, err := readSerializeBooleanOption(ctx, m, lexicon.SerializationEscapeURIAttributes)
	if err != nil {
		return opts, err
	}

	if found {
		opts.escapeURIAttributes = escape
	}

	version, found, err := readSerializeStringOption(ctx, m, lexicon.SerializationVersion)
	if err != nil {
		return opts, err
	}

	if found {
		opts.xmlVersion = version
	}

	hv, found, err := readSerializeNumberOption(ctx, m, lexicon.SerializationHTMLVersion)
	if err != nil {
		return opts, err
	}

	if found {
		opts.htmlVersion = hv
	}

	pub, found, err := readSerializeStringOption(ctx, m, lexicon.SerializationDoctypePublic)
	if err != nil {
		return opts, err
	}

	if found {
		opts.doctypePublic = pub
	}

	sys, found, err := readSerializeStringOption(ctx, m, lexicon.SerializationDoctypeSystem)
	if err != nil {
		return opts, err
	}

	if found {
		opts.doctypeSystem = sys
	}

	mt, found, err := readSerializeStringOption(ctx, m, lexicon.SerializationMediaType)
	if err != nil {
		return opts, err
	}

	if found {
		opts.mediaType = mt
	}
	// Validation parity with the element form for the recognized-but-unapplied
	// (or limitation) parameters, so an invalid value is rejected consistently.
	// Validate the boolean value; UTF-8 output does not emit a BOM.
	if _, _, err := readSerializeBooleanOption(ctx, m, lexicon.SerializationByteOrderMark); err != nil {
		return opts, err
	}

	return opts, nil
}

func parseSerializeMapContentOptions(ctx context.Context, opts serializeOptions, m xdm.MapItem) (serializeOptions, error) {
	jn, found, err := resolveSerializeJSONNodeMethodMap(ctx, m)
	if err != nil {
		return opts, err
	}

	if found {
		opts.jsonNodeOutputMethod = jn
	}

	nf, found, err := readSerializeStringOption(ctx, m, lexicon.SerializationNormalizationForm)
	if err != nil {
		return opts, err
	}

	if found {
		if !serializeNormalizationFormValid(nf) {
			return opts, &xdm.Error{Code: lexicon.ErrSEPM0016, Message: fmt.Sprintf("serialize option normalization-form has an invalid value %q", nf)}
		}

		opts.normalizationForm = nf
	}

	if v, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: lexicon.SerializationStandalone}); found {
		standalone, err := resolveSerializeStandaloneMap(ctx, v)
		if err != nil {
			return opts, err
		}

		opts.standalone = standalone
	}

	if v, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: lexicon.SerializationUseCharacterMaps}); found {
		charMap, err := resolveSerializeCharacterMaps(ctx, v)
		if err != nil {
			return opts, err
		}

		opts.charMap = charMap
	}

	if v, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: lexicon.SerializationCDATASectionElements}); found {
		names, err := resolveSerializeQNameNames(ctx, v, lexicon.SerializationCDATASectionElements)
		if err != nil {
			return opts, err
		}

		opts.cdataElements = names
	}

	if v, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: lexicon.SerializationSuppressIndentation}); found {
		names, err := resolveSerializeQNameNames(ctx, v, lexicon.SerializationSuppressIndentation)
		if err != nil {
			return opts, err
		}

		opts.suppressIndent = names
	}

	return opts, nil
}

// serializeOptionValue applies the map option's declared function conversion,
// independently of an enclosing XSLT backwards-compatibility mode.
func serializeOptionValue(ctx context.Context, value xdm.Sequence, target string, occurrence xdm.Occurrence, name string) (xdm.Sequence, error) {
	var strict evalContext
	if ec := getFnContext(ctx); ec != nil {
		strict = *ec
	}

	strict.xpath10Compat = false

	return coerceFuncallArg(ctx, value, stAtomic(target, occurrence), "serialize option "+name, 0, &strict)
}

func serializeOptionalAtomic(ctx context.Context, value xdm.Sequence, target, name string) (xdm.AtomicValue, bool, error) {
	converted, err := serializeOptionValue(ctx, value, target, xdm.OccurrenceZeroOrOne, name)
	if err != nil {
		return xdm.AtomicValue{}, false, err
	}

	if xdm.SequenceLen(converted) == 0 {
		return xdm.AtomicValue{}, false, nil
	}

	atom, ok := converted.Get(0).(xdm.AtomicValue)
	if !ok {
		return xdm.AtomicValue{}, false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialization option did not yield an atomic value"}
	}

	return atom, true, nil
}

func readSerializeBooleanOption(ctx context.Context, m xdm.MapItem, name string) (bool, bool, error) {
	value, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: name})
	if !found {
		return false, false, nil
	}

	atom, found, err := serializeOptionalAtomic(ctx, value, xdm.TypeBoolean, name)
	if err != nil || !found {
		return false, found, err
	}

	return atom.BooleanVal(), true, nil
}

// resolveSerializeQNameNames converts a serialization parameter whose value is a
// sequence of xs:QName items (cdata-section-elements, suppress-indentation) into
// the element-name key set the writer matches against: each QName contributes its
// exact expanded {uri}local name (Clark notation; an explicit empty namespace is
// "{}local"). Matching is by exact expanded name, so QName("","b") does not match
// a namespaced <p:b>.
func resolveSerializeQNameNames(ctx context.Context, value xdm.Sequence, name string) (map[string]struct{}, error) {
	converted, err := serializeOptionValue(ctx, value, xdm.TypeQName, xdm.OccurrenceZeroOrMore, name)
	if err != nil {
		return nil, err
	}

	names := make(map[string]struct{})

	for item := range xdm.SequenceItems(converted) {
		atom, ok := item.(xdm.AtomicValue)
		if !ok {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialization QName option did not yield atomic values"}
		}

		qname, ok := atom.Value.(xdm.QNameValue)
		if !ok {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialization QName option has an invalid value"}
		}

		names[xdm.ClarkName(qname.URI, qname.Local)] = struct{}{}
	}

	return names, nil
}

// html-version requires xs:decimal?: integers are subtypes, while floating
// values cannot be promoted down to decimal by function conversion.
func readSerializeNumberOption(ctx context.Context, m xdm.MapItem, name string) (string, bool, error) {
	return readSerializeAtomicStringOption(ctx, m, name, xdm.TypeDecimal)
}

func readSerializeStringOption(ctx context.Context, m xdm.MapItem, name string) (string, bool, error) {
	return readSerializeAtomicStringOption(ctx, m, name, xdm.TypeString)
}

func readSerializeAtomicStringOption(ctx context.Context, m xdm.MapItem, name, target string) (string, bool, error) {
	value, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: name})
	if !found {
		return "", false, nil
	}

	atom, found, err := serializeOptionalAtomic(ctx, value, target, name)
	if err != nil || !found {
		return "", found, err
	}

	text, err := atomicToString(atom)

	return text, true, err
}

// resolveSerializeMethodMap resolves a map-form method option while preserving a
// QName's namespace. Namespaced methods remain EQNames for unsupported-extension
// checks. Invalid values raise SEPM0016; found=false means the option is absent.
func resolveSerializeMethodMap(ctx context.Context, m xdm.MapItem) (string, bool, error) {
	return resolveSerializeMethodOption(ctx, m, lexicon.SerializationMethod, serializeMethodValid)
}

// resolveSerializeJSONNodeMethodMap uses the narrower xml/html/xhtml/text domain
// for nodes embedded in JSON, retaining extension QNames for later validation.
func resolveSerializeJSONNodeMethodMap(ctx context.Context, m xdm.MapItem) (string, bool, error) {
	return resolveSerializeMethodOption(ctx, m, lexicon.SerializationJSONNodeOutputMethod, serializeJSONNodeOutputMethodValid)
}

// resolveSerializeMethodOption preserves namespaced QName values as EQNames and
// applies the parameter's lexical domain to string values. Empty values request
// the default; built-in methods must be strings rather than no-namespace QNames.
func resolveSerializeMethodOption(ctx context.Context, m xdm.MapItem, name string, valid func(string) bool) (string, bool, error) {
	v, present := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: name})
	if !present {
		return "", false, nil
	}

	atoms, err := atomizeTypedValue(ctx, v)
	if err != nil {
		return "", true, err
	}

	if len(atoms) == 0 {
		return "", false, nil
	}

	if len(atoms) != 1 {
		return "", true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be a singleton", name)}
	}

	av := atoms[0]
	if av.TypeName == xdm.TypeQName {
		qn, ok := av.Value.(xdm.QNameValue)
		if !ok {
			return "", true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q is not a valid xs:QName", name)}
		}

		if qn.URI == "" {
			return "", true, &xdm.Error{Code: lexicon.ErrSEPM0016, Message: fmt.Sprintf("serialize option %s: an xs:QName value must have a non-absent namespace, got %q", name, qn.Local)}
		}

		return "Q{" + qn.URI + "}" + qn.Local, true, nil
	}

	// The expected type is a namespace-sensitive pure union. Unlike an
	// expected xs:string, it does not permit URI promotion or untyped casting.
	if av.TypeName == xdm.TypeUntypedAtomic {
		return "", true, &xdm.Error{Code: "XPTY0117", Message: "untypedAtomic cannot be converted to the serialization method union"}
	}

	if !atomicMatchesTargetType(av, xdm.TypeString, getFnContext(ctx)) {
		return "", true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialization method must be a string or QName"}
	}

	value := av.StringVal()

	if !valid(value) {
		return "", true, &xdm.Error{Code: lexicon.ErrSEPM0016, Message: fmt.Sprintf("serialize option %s has an invalid value %q", name, value)}
	}

	return value, true, nil
}

func parseSerializeOptionsNode(opts serializeOptions, n xdm.Node) (serializeOptions, error) {
	elem, err := readSerializeOptionsRoot(n, opts.edition)
	if err != nil {
		return opts, err
	}

	seen := make(map[string]struct{})

	for child := range xdm.Children(elem) {
		param, err := readSerializeOptionsChild(child, opts.edition)
		if err != nil {
			return opts, err
		}

		if param == nil {
			continue
		}

		key := param.URI() + "|" + param.LocalName()
		if _, exists := seen[key]; exists {
			return opts, &xdm.Error{Code: errCodeSEPM0019, Message: "serialize options parameter must not appear more than once"}
		}

		seen[key] = struct{}{}

		if param.URI() != lexicon.NamespaceSerialization {
			if opts.edition == 30 {
				return opts, &xdm.Error{Code: errCodeSEPM0017, Message: "Serialization 3.0 does not declare extension parameter elements"}
			}

			// No extension serialization parameters are implemented. The 3.1
			// schema permits foreign elements with arbitrary content.
			continue
		}

		opts, err = applySerializeNodeParam(opts, param)
		if err != nil {
			return opts, err
		}
	}

	return opts, nil
}

// SerializationParameters is a validated, presence-preserving view of a
// parameter document. It contains no fn:serialize defaults or Unicode-output
// overrides, so a byte serializer can apply its own host defaults afterwards.
type SerializationParameters struct {
	// Strings contains supplied string-valued serialization parameters by local name.
	Strings map[string]string
	// Booleans contains supplied boolean parameters, preserving explicit false values.
	Booleans map[string]bool
	// Names contains resolved expanded-name lists for name-valued parameters.
	Names map[string][]string
	// Characters maps input characters to verbatim character-map replacements.
	Characters map[rune]string
	// CharactersSet distinguishes an explicitly supplied character map from an absent
	// parameter.
	CharactersSet bool
}

// ReadSerializationParameters applies the selected published parameter schema
// and namespace-resolution rules without validating method-specific output
// restrictions. Those restrictions depend on the receiving host's final method.
func ReadSerializationParameters(ctx context.Context, root *xdm.Element, edition int) (SerializationParameters, error) {
	var result SerializationParameters

	opts, err := parseSerializeOptionsNode(serializeOptions{ctx: ctx, edition: edition}, root)
	if err != nil {
		return result, err
	}

	result.Strings = make(map[string]string)
	result.Booleans = make(map[string]bool)
	result.Names = make(map[string][]string)

	for child := range xdm.Children(root) {
		if err := Charge(ctx, 1); err != nil {
			return result, err
		}

		param, ok := child.(*xdm.Element)
		if !ok || param.URI() != lexicon.NamespaceSerialization || serializeParameterType(param.LocalName(), edition) == "" {
			continue
		}

		name := param.LocalName()
		if target, boolean := opts.booleanParam(name); boolean {
			if target != nil {
				result.Booleans[name] = *target
			} else {
				// fn:serialize ignores byte-order-mark for its string result,
				// but the byte host must retain its validated explicit value.
				value, err := readSerializeParamYesNo(param, edition)
				if err != nil {
					return result, err
				}

				result.Booleans[name] = value
			}

			continue
		}

		if target := opts.stringParam(name); target != nil {
			result.Strings[name] = *target
			continue
		}

		switch name {
		case lexicon.SerializationCDATASectionElements:
			result.Names[name] = slices.Sorted(maps.Keys(opts.cdataElements))
		case lexicon.SerializationSuppressIndentation:
			result.Names[name] = slices.Sorted(maps.Keys(opts.suppressIndent))
		case lexicon.SerializationUseCharacterMaps:
			result.Characters, result.CharactersSet = opts.charMap, true
		}
	}

	return result, nil
}

// SerializeNodeForJSON returns the inner node serialization before JSON string
// escaping. XPath and XSLT share the node-kind checks and XML/HTML/text rules.
func SerializeNodeForJSON(ctx context.Context, v xdm.NodeItem, method string) (string, error) {
	if method == "" {
		method = lexicon.MethodXML
	}
	// SER31 §9 supplies only the node output method and omit-xml-declaration.
	// JSON character maps and normalization apply to the resulting JSON string.
	nodeOpts := serializeOptions{
		ctx:    ctx,
		method: method, omitXMLDeclaration: true,
		standalone: lexicon.ValueOmit, includeContentType: true, escapeURIAttributes: true,
	}
	if err := nodeOpts.validate(); err != nil {
		return "", err
	}

	switch method {
	case lexicon.MethodText:
		return serializeTextSequence(xdm.ItemSlice{v}, nodeOpts)
	case lexicon.MethodHTML:
		return serializeHTMLSequence(xdm.ItemSlice{v}, nodeOpts)
	default:
		return serializeXMLSequence(xdm.ItemSlice{v}, nodeOpts)
	}
}

func readSerializeOptionsRoot(n xdm.Node, edition int) (*xdm.Element, error) {
	elem, ok := n.(*xdm.Element)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize options node must be an element"}
	}

	if elem.URI() != lexicon.NamespaceSerialization || elem.LocalName() != "serialization-parameters" {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize options root must be output:serialization-parameters"}
	}

	if edition == 30 {
		for _, attr := range elem.Attributes() {
			if attr.URI() != lexicon.NamespaceXSI || !serializeInstanceAttribute(attr.LocalName()) {
				return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "Serialization 3.0 options root must not have attributes"}
			}
		}

		if err := validateSerializeInstanceAttributes(elem, ""); err != nil {
			return nil, err
		}
	}

	return elem, nil
}

func serializeInstanceAttribute(name string) bool {
	switch name {
	case lexicon.AttrType, "nil", "schemaLocation", "noNamespaceSchemaLocation":
		return true
	}

	return false
}

// readSerializeOptionsChild skips comments, PIs and whitespace while enforcing
// the parameter element's required namespace.
func readSerializeOptionsChild(child xdm.Node, edition int) (*xdm.Element, error) {
	switch child.Type() {
	case xdm.TextNode, xdm.CDATASectionNode:
		if edition != 30 || isXSDWhitespaceOnly(xdm.CharacterData(child)) {
			return nil, nil
		}

		return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "serialize options root must not contain text"}
	case xdm.CommentNode, xdm.ProcessingInstructionNode:
		return nil, nil
	case xdm.ElementNode:
	default:
		return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "serialize options root has invalid child node"}
	}

	param, _ := xdm.AsNode[*xdm.Element](child)
	if edition == 30 && param.URI() == "" {
		return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "serialize options parameters must be namespace-qualified"}
	}

	return param, nil
}

func applySerializeNodeParam(opts serializeOptions, param *xdm.Element) (serializeOptions, error) {
	name := param.LocalName()
	if opts.edition == 30 && (name == lexicon.SerializationAllowDuplicateNames || name == lexicon.SerializationJSONNodeOutputMethod) {
		return opts, &xdm.Error{Code: errCodeSEPM0017, Message: fmt.Sprintf("serialization parameter %q is not defined by Serialization 3.0", name)}
	}

	parameterType := serializeParameterType(name, opts.edition)
	if opts.edition != 30 && parameterType == "" {
		// SER31 validates the selected standard parameters individually. A
		// child outside that finite set participates only in duplicate checks.
		return opts, nil
	}

	if err := validateSerializeInstanceAttributes(param, parameterType); err != nil {
		return opts, err
	}

	if target, recognized := opts.booleanParam(name); recognized {
		value, err := readSerializeParamYesNo(param, opts.edition)
		if err != nil {
			return opts, err
		}

		if target != nil {
			*target = value
		}

		return opts, nil
	}

	if target := opts.stringParam(name); target != nil {
		value, err := readSerializeNodeStringParam(param, opts.edition)
		if err != nil {
			return opts, err
		}

		*target = value

		if name == lexicon.SerializationItemSeparator {
			opts.itemSeparatorSet = true
		}

		return opts, nil
	}

	switch name {
	case lexicon.SerializationCDATASectionElements, lexicon.SerializationSuppressIndentation:
		names, err := readSerializeParamQNameNames(param, opts.edition)
		if err != nil {
			return opts, err
		}

		if name == lexicon.SerializationCDATASectionElements {
			opts.cdataElements = names
		} else {
			opts.suppressIndent = names
		}
	case lexicon.SerializationUseCharacterMaps:
		charMap, err := resolveSerializeCharacterMapsElement(opts, param, true)
		if err != nil {
			return opts, err
		}

		opts.charMap = charMap
	default:
		return opts, &xdm.Error{Code: errCodeSEPM0017, Message: fmt.Sprintf("unsupported serialize parameter %q", name)}
	}

	return opts, nil
}

// Serialization declares a finite set of complex parameter types, all direct
// siblings derived from base-param-type. No additional schema types are supplied
// by this host, so xsi:type must name the parameter's own declared type.
func serializeParameterType(name string, edition int) string {
	switch name {
	case lexicon.SerializationByteOrderMark, lexicon.SerializationEscapeURIAttributes, lexicon.SerializationIncludeContentType,
		lexicon.SerializationIndent, lexicon.SerializationOmitXMLDeclaration, lexicon.SerializationUndeclarePrefixes,
		lexicon.SerializationAllowDuplicateNames:
		return "yes-no-param-type"
	case lexicon.SerializationCDATASectionElements, lexicon.SerializationSuppressIndentation:
		return "QNames-param-type"
	case lexicon.SerializationHTMLVersion:
		return "decimal-param-type"
	case lexicon.SerializationItemSeparator:
		return serializeStringParamType
	case lexicon.SerializationMediaType, lexicon.SerializationVersion:
		if edition == 30 {
			return serializeStringParamType
		}

		return serializeTokenizedStringParamType
	case lexicon.SerializationNormalizationForm:
		return "NMTOKEN-param-type"
	case lexicon.SerializationStandalone:
		return "yes-no-omit-param-type"
	case lexicon.SerializationDoctypePublic, lexicon.SerializationDoctypeSystem, lexicon.SerializationEncoding,
		lexicon.SerializationMethod, lexicon.SerializationJSONNodeOutputMethod, lexicon.SerializationUseCharacterMaps:
		return name + "-param-type"
	}

	return ""
}

func validateSerializeInstanceAttributes(elem *xdm.Element, expectedType string) error {
	for _, attr := range elem.Attributes() {
		if attr.URI() != lexicon.NamespaceXSI {
			continue
		}

		switch attr.LocalName() {
		case "nil":
			// XSD Element Locally Valid (Element) forbids xsi:nil entirely
			// when the declaration is not nillable, even xsi:nil="false".
			return &xdm.Error{Code: errCodeSEPM0017, Message: "serialization parameter element is not nillable"}
		case lexicon.AttrType:
			name := strings.Trim(attr.Value(), lexicon.XMLWhitespace)
			if strings.HasPrefix(name, "Q{") {
				return &xdm.Error{Code: errCodeSEPM0017, Message: "xsi:type must be a lexical QName"}
			}

			resolved, err := resolveSerializeNameToken(elem, name)
			if err != nil {
				return err
			}

			if expectedType == "" || resolved != xdm.ClarkName(lexicon.NamespaceSerialization, expectedType) {
				return &xdm.Error{Code: errCodeSEPM0017, Message: "xsi:type is not derived from the declared serialization parameter type"}
			}
		}
	}

	return nil
}

// Lax assessment is confined to the finite published serialization schema and
// its XSD 1.0 builtins. No extension schemas are loaded. An undeclared foreign
// element still assesses declared descendants and an explicit xsi:type.
func validateSerializeLaxElement(opts serializeOptions, elem *xdm.Element) error {
	if err := Charge(opts.ctx, 1); err != nil {
		return err
	}

	if declared, err := validateSerializeDeclaredElement(opts, elem); declared {
		return err
	}

	for _, attr := range elem.Attributes() {
		if attr.URI() != lexicon.NamespaceXSI || attr.LocalName() != lexicon.AttrType {
			continue
		}

		name := strings.Trim(attr.Value(), lexicon.XMLWhitespace)
		if strings.HasPrefix(name, "Q{") {
			return serializeSchemaError("xsi:type must be a lexical QName")
		}

		resolved, err := resolveSerializeNameToken(elem, name)
		if err != nil {
			return err
		}

		if after, ok := strings.CutPrefix(resolved, "{"+lexicon.NamespaceSerialization+"}"); ok {
			return validateSerializeNamedType(opts, elem, after)
		}

		if after, ok := strings.CutPrefix(resolved, "{"+lexicon.NamespaceXSD+"}"); ok {
			return validateSerializeBuiltinType(opts, elem, after)
		}

		return serializeSchemaError("unknown serialization subtree xsi:type")
	}

	return validateSerializeLaxChildren(opts, elem)
}

func validateSerializeDeclaredElement(opts serializeOptions, elem *xdm.Element) (bool, error) {
	if elem.URI() != lexicon.NamespaceSerialization {
		return false, nil
	}

	name := elem.LocalName()
	if name == "serialization-parameters" {
		return true, validateSerializeLaxContainer(opts, elem)
	}

	if name == "serialization-parameter-element" {
		return true, serializeSchemaError("serialization-parameter-element is abstract")
	}

	if serializeParameterType(name, opts.edition) == "" || opts.edition == 30 && (name == lexicon.SerializationAllowDuplicateNames || name == lexicon.SerializationJSONNodeOutputMethod) {
		return false, nil
	}

	if name == lexicon.SerializationUseCharacterMaps {
		// Nested validation neither extracts mappings nor imposes SEPM0018 on
		// otherwise schema-valid duplicate entries.
		if err := validateSerializeInstanceAttributes(elem, serializeCharacterMapsParamType); err != nil {
			return true, err
		}

		_, err := resolveSerializeCharacterMapsElement(opts, elem, false)

		return true, err
	}

	_, err := applySerializeNodeParam(opts, elem)

	return true, err
}

func validateSerializeLaxChildren(opts serializeOptions, elem *xdm.Element) error {
	for child := range xdm.Children(elem) {
		if err := Charge(opts.ctx, 1); err != nil {
			return err
		}

		if element, ok := child.(*xdm.Element); ok {
			if err := validateSerializeLaxElement(opts, element); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateSerializeLaxContainer(opts serializeOptions, elem *xdm.Element) error {
	// The global schema declaration has no attributes in either edition; this
	// differs from the unvalidated outer container in the SER31 procedure.
	if _, err := readSerializeOptionsRoot(elem, 30); err != nil {
		return err
	}

	for child := range xdm.Children(elem) {
		if err := Charge(opts.ctx, 1); err != nil {
			return err
		}

		param, err := readSerializeOptionsChild(child, 30)
		if err != nil {
			return err
		}

		if param == nil {
			continue
		}

		if param.URI() == lexicon.NamespaceSerialization {
			if serializeParameterType(param.LocalName(), opts.edition) == "" || opts.edition == 30 && (param.LocalName() == lexicon.SerializationAllowDuplicateNames || param.LocalName() == lexicon.SerializationJSONNodeOutputMethod) {
				return serializeSchemaError("unknown child of serialization-parameters")
			}
		} else if opts.edition == 30 {
			return serializeSchemaError("Serialization 3.0 container has no foreign-element wildcard")
		}

		if err := validateSerializeLaxElement(opts, param); err != nil {
			return err
		}
	}

	return nil
}

func validateSerializeNamedType(opts serializeOptions, elem *xdm.Element, name string) error {
	if opts.edition == 30 && name == serializeQNameOrEQNameType {
		return serializeSchemaError("unknown Serialization 3.0 type")
	}

	if name == serializeCharacterMapsParamType {
		_, err := resolveSerializeCharacterMapsElement(opts, elem, false)
		return err
	}

	if name == "base-param-type" {
		if err := validateSerializeMapAttributes(elem); err != nil {
			return err
		}

		if hasNonWhitespaceContent(elem) {
			return serializeSchemaError("base-param-type must be empty")
		}

		return nil
	}

	domain := ""

	switch name {
	case serializeStringParamType, serializeTokenizedStringParamType, "decimal-param-type", "NMTOKEN-param-type":
		if name == serializeTokenizedStringParamType && opts.edition == 30 {
			return serializeSchemaError("unknown Serialization 3.0 type")
		}

		domain = strings.TrimSuffix(name, "-param-type")
	case "yes-no-param-type", "yes-no-omit-param-type", "QNames-param-type", "method-param-type":
		domain = strings.TrimSuffix(name, "-param-type") + "-type"
	case "doctype-public-param-type":
		domain = "pubid-char-string-type"
	case "doctype-system-param-type":
		domain = "system-id-string-type"
	case "encoding-param-type":
		domain = "encoding-string-type"
	case "json-node-output-method-param-type":
		if opts.edition == 30 {
			return serializeSchemaError("unknown Serialization 3.0 type")
		}

		domain = serializeJSONNodeMethodType
	}

	if domain != "" {
		value, err := readSerializeParamValue(elem)
		if err != nil {
			return err
		}

		return validateSerializeTypeValue(opts, elem, domain, value)
	}

	value, err := serializeSimpleContent(opts, elem)
	if err != nil {
		return err
	}

	return validateSerializeTypeValue(opts, elem, name, value)
}

func serializeSimpleContent(opts serializeOptions, elem *xdm.Element) (string, error) {
	for _, attr := range elem.Attributes() {
		if err := Charge(opts.ctx, 1); err != nil {
			return "", err
		}

		if attr.URI() != lexicon.NamespaceXSI || !serializeInstanceAttribute(attr.LocalName()) {
			return "", serializeSchemaError("simple xsi:type does not permit attributes")
		}
	}

	for child := range xdm.Children(elem) {
		if err := Charge(opts.ctx, 1); err != nil {
			return "", err
		}

		if child.Type() == xdm.ElementNode {
			return "", serializeSchemaError("simple xsi:type does not permit element children")
		}
	}

	value := xdm.StringValue(elem)
	if err := Charge(opts.ctx, len(value)); err != nil {
		return "", err
	}

	return value, nil
}

func validateSerializeBuiltinType(opts serializeOptions, elem *xdm.Element, name string) error {
	if !xdm.IsKnownXSDType("xs:" + name) {
		return serializeSchemaError("unknown XSD xsi:type")
	}

	switch name {
	case lexicon.TypeUntyped, lexicon.TypeUntypedAtomic, lexicon.TypeAnyAtomicType, lexicon.TypeNumeric, lexicon.TypeError, lexicon.TypeDateTimeStamp, lexicon.TypeDayTimeDuration, lexicon.TypeYearMonthDuration:
		return serializeSchemaError("xsi:type is not in the published XSD 1.0 schema context")
	case lexicon.TypeAnyType:
		return validateSerializeLaxChildren(opts, elem)
	}

	value, err := serializeSimpleContent(opts, elem)
	if err != nil {
		return err
	}

	if name == lexicon.TypeAnySimpleType {
		return nil
	}

	value = lexical.Normalize(value, name)
	if err := lexical.ValidateBuiltin(value, name, lexical.Version10); err != nil {
		return serializeSchemaError("invalid XSD-typed serialization subtree value")
	}

	if name == lexicon.TypeQName {
		if strings.HasPrefix(value, "Q{") {
			return serializeSchemaError("xs:QName requires a lexical QName")
		}

		_, err := resolveSerializeNameToken(elem, value)

		return err
	}

	if name == lexicon.TypeNotation {
		return serializeSchemaError("no NOTATION declarations in serialization schema")
	}

	if name == lexicon.TypeENTITY || name == lexicon.TypeENTITIES {
		doc, ok := xdm.DocumentRoot(elem).(*xdm.Document)
		for _, entity := range xsdListFields(value) {
			if !ok {
				return serializeSchemaError("ENTITY requires an unparsed entity declaration")
			}

			if _, found := doc.UnparsedEntity(entity); !found {
				return serializeSchemaError("unknown unparsed ENTITY")
			}
		}
	}

	return nil
}

func validateSerializeTypeValue(opts serializeOptions, elem *xdm.Element, name, value string) error {
	token := strings.Trim(value, lexicon.XMLWhitespace)
	valid := true

	switch name {
	case "string", "tokenized-string":
		return nil
	case lexicon.TypeDecimal:
		valid = isValidXSDecimal(token)
	case lexicon.TypeNMToken:
		valid = serializeNormalizationFormValid(token)
	case "yes-no-type", "yes-no-omit-type":
		_, valid = serializeEditionBooleanValue(token, opts.edition)
		valid = valid || name == "yes-no-omit-type" && token == lexicon.ValueOmit
	case "char-type":
		valid = utf8.RuneCountInString(value) == 1
	case "encoding-string-type":
		valid = xmlchar.IsValidEncName(token) && (opts.edition != 30 || value == token)
	case "pubid-char-string-type":
		valid = xmloutput.ValidPublicID(strings.ReplaceAll(value, "\t", " "))
	case "system-id-string-type":
		valid = xmloutput.ValidSystemID(value)
	case "method-type", serializeJSONNodeMethodType:
		if name == serializeJSONNodeMethodType && opts.edition == 30 {
			return serializeSchemaError("unknown Serialization 3.0 type")
		}

		_, err := readSerializeNodeMethodValue(elem, value, token, opts.edition, name == "method-type")

		return err
	case "QNames-type":
		for _, part := range xsdListFields(value) {
			if err := Charge(opts.ctx, 1); err != nil {
				return err
			}

			if err := validateSerializeTypeValue(opts, elem, serializeQNameOrEQNameType, part); err != nil {
				return err
			}
		}
	case serializeQNameOrEQNameType, "EQName", serializePrefixedQNameType, serializeQualifiedEQNameType:
		return validateSerializeQNameType(opts, elem, name, token)
	default:
		valid = false
	}

	if !valid {
		return serializeSchemaError("invalid or unknown published serialization type")
	}

	return nil
}

func validateSerializeQNameType(opts serializeOptions, elem *xdm.Element, name, token string) error {
	if opts.edition == 30 && name != serializeQNameOrEQNameType {
		return serializeSchemaError("unknown Serialization 3.0 type")
	}

	if uri, local, eqname := parseEQNameToken(token); eqname {
		if opts.edition == 30 || name == serializePrefixedQNameType || !xmlchar.IsValidNCName(local) || name == serializeQualifiedEQNameType && strings.Trim(uri, lexicon.XMLWhitespace) == "" {
			return serializeSchemaError("invalid published EQName type")
		}

		return nil
	}

	if name == "EQName" || name == serializeQualifiedEQNameType || name == serializePrefixedQNameType && !strings.Contains(token, ":") {
		return serializeSchemaError("invalid published QName type")
	}

	_, err := resolveSerializeNameToken(elem, token)

	return err
}

func serializeSchemaError(message string) error {
	return &xdm.Error{Code: errCodeSEPM0017, Message: message}
}

// readSerializeNodeStringParam preserves literal string parameters and trims
// XSD whitespace only for parameters with token or decimal lexical domains.
func readSerializeNodeStringParam(param *xdm.Element, edition int) (string, error) {
	name := param.LocalName()
	if name == lexicon.SerializationStandalone {
		return readSerializeParamStandalone(param, edition)
	}

	value, err := readSerializeParamValue(param)
	if err != nil {
		return "", err
	}

	token := strings.Trim(value, lexicon.XMLWhitespace)

	switch name {
	case lexicon.SerializationEncoding:
		if !xmlchar.IsValidEncName(token) || edition == 30 && value != token {
			return "", &xdm.Error{Code: errCodeSEPM0017, Message: "invalid serialization encoding name"}
		}
	case lexicon.SerializationMethod, lexicon.SerializationJSONNodeOutputMethod:
		return readSerializeNodeMethod(param, value, token, edition)
	case lexicon.SerializationNormalizationForm:
		if !serializeNormalizationFormValid(token) {
			return "", &xdm.Error{Code: errCodeSEPM0017, Message: fmt.Sprintf("serialize parameter normalization-form has an invalid value %q", value)}
		}
	case lexicon.SerializationHTMLVersion:
		if !isValidXSDecimal(token) {
			return "", &xdm.Error{Code: errCodeSEPM0017, Message: fmt.Sprintf("serialize parameter html-version must be an xs:decimal, got %q", value)}
		}
	case lexicon.SerializationDoctypePublic:
		if edition != 30 {
			value = xmlchar.CollapseSpace(value)
		}

		if !xmloutput.ValidPublicID(strings.ReplaceAll(value, "\t", " ")) {
			return "", &xdm.Error{Code: errCodeSEPM0017, Message: "invalid doctype-public parameter"}
		}

		return value, nil
	case lexicon.SerializationDoctypeSystem:
		if !xmloutput.ValidSystemID(value) {
			return "", &xdm.Error{Code: errCodeSEPM0017, Message: "invalid doctype-system parameter"}
		}

		return value, nil
	case lexicon.SerializationMediaType:
		if edition != 30 {
			return xmlchar.CollapseSpace(value), nil
		}

		return value, nil
	case lexicon.SerializationVersion:
		if edition == 30 {
			return value, nil // SER30 uses xs:string, SER31 uses xs:token.
		}
	default:
		return value, nil
	}

	return token, nil
}

func readSerializeNodeMethod(param *xdm.Element, value, token string, edition int) (string, error) {
	return readSerializeNodeMethodValue(param, value, token, edition, param.LocalName() == lexicon.SerializationMethod)
}

func readSerializeNodeMethodValue(param *xdm.Element, value, token string, edition int, method bool) (string, error) {
	if edition != 30 {
		// The published 3.1 union also admits Q{\s*}builtin. It denotes
		// the same absent-namespace method as the corresponding token.
		if uri, local, ok := parseEQNameToken(token); ok && strings.Trim(uri, lexicon.XMLWhitespace) == "" && isBuiltinSerializeMethod(local) {
			token = local
		}
	}

	valid := serializeJSONNodeOutputMethodValid(token)
	if method {
		valid = serializeMethodValid(token)
		if edition == 30 && (isBuiltinSerializeMethod(token) && value != token ||
			token == lexicon.MethodJSON || token == lexicon.MethodAdaptive || strings.HasPrefix(token, "Q{")) {
			valid = false
		}
	}

	if !valid {
		return "", &xdm.Error{Code: errCodeSEPM0017, Message: "invalid serialization method parameter"}
	}

	if isExtensionMethodName(token) {
		if _, err := resolveSerializeNameToken(param, token); err != nil {
			return "", err
		}
	}

	return token, nil
}

// isXSDWhitespaceOnly reports whether s is empty or consists only of XSD
// whitespace (#x20/#x9/#xA/#xD). NBSP and other Unicode whitespace are NOT
// whitespace, so content containing them is significant.
func isXSDWhitespaceOnly(s string) bool {
	return strings.Trim(s, lexicon.XMLWhitespace) == ""
}

// isValidXSDecimal reports whether s is a valid xs:decimal lexical form: an
// optional sign followed by digits with an optional fractional part (no
// exponent). Used to validate the html-version parameter.
func isValidXSDecimal(s string) bool {
	if s == "" {
		return false
	}

	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}

	intPart, fracPart, _ := strings.Cut(s, ".")
	// A second "." (e.g. "5.0.0") leaves a "." in fracPart — reject it. A lone
	// "." with no digits either side is invalid; "5." and ".5" are valid.
	if strings.IndexByte(fracPart, '.') >= 0 {
		return false
	}

	if intPart == "" && fracPart == "" {
		return false
	}

	return allASCIIDigits(intPart) && allASCIIDigits(fracPart)
}

func allASCIIDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}

// serializeNormalizationFormValid checks the NMTOKEN parameter domain. A
// syntactically valid but unsupported form is diagnosed later as SESU0011.
func serializeNormalizationFormValid(v string) bool {
	if v == "" {
		return false
	}

	for _, r := range v {
		if r != ':' && !xmlchar.IsNCNameChar(r) {
			return false
		}
	}

	return true
}

// isExtensionMethodName reports whether v is a syntactically valid extension
// method name: a lexical QName WITH a prefix (its expanded name has a non-null
// namespace), or an `Q{uri}local` EQName with a NON-EMPTY namespace URI. A bare
// NCName (null namespace) is NOT an extension method — per Serialization 3.1 the
// method-type restricts extension methods to prefixed QNames, so an unprefixed
// value must be one of the built-in tokens.
func isExtensionMethodName(v string) bool {
	if uri, local, ok := parseEQNameToken(v); ok {
		return strings.Trim(uri, lexicon.XMLWhitespace) != "" && xmlchar.IsValidNCName(local)
	}

	prefix, local, hasPrefix := strings.Cut(v, ":")
	if !hasPrefix {
		return false
	}

	return xmlchar.IsValidNCName(prefix) && xmlchar.IsValidNCName(local)
}

// serializeMethodValid reports whether v is a valid method-type value: a
// built-in output method, or a prefixed QName / non-null EQName naming an
// extension method. A bare non-built-in NCName (e.g. "bogus") is NOT valid.
// Note: passing validation does not imply the method is SUPPORTED — an extension
// method is valid but unimplemented, and fnSerialize rejects it at dispatch,
// with no silent fall-through to the xml method.
func serializeMethodValid(v string) bool {
	return isBuiltinSerializeMethod(v) || isExtensionMethodName(v)
}

// serializeJSONNodeOutputMethodValid reports whether v is a valid
// json-node-output-method value. Per Serialization 3.1 §9.1 its domain is the
// tokens xml|html|xhtml|text (NOT json or adaptive) or a prefixed extension
// QName — a SEPARATE, narrower domain than the method parameter.
func serializeJSONNodeOutputMethodValid(v string) bool {
	switch v {
	case lexicon.MethodXML, lexicon.MethodHTML, lexicon.MethodXHTML, lexicon.MethodText:
		return true
	}

	return isExtensionMethodName(v)
}

func readSerializeParamValue(elem *xdm.Element) (string, error) {
	if hasNonWhitespaceContent(elem) {
		return "", &xdm.Error{Code: errCodeSEPM0017, Message: "serialize parameter must not have child content"}
	}

	var (
		value string
		found bool
	)

	for _, attr := range elem.Attributes() {
		if attr.URI() != "" && attr.URI() != lexicon.NamespaceSerialization {
			continue // base-param-type permits foreign attributes.
		}

		if attr.URI() != "" || attr.LocalName() != "value" {
			return "", &xdm.Error{Code: errCodeSEPM0017, Message: "serialize parameter must use an unqualified value attribute"}
		}

		value, found = attr.Value(), true
	}

	if !found {
		return "", &xdm.Error{Code: errCodeSEPM0017, Message: "serialize parameter requires a value attribute"}
	}

	return value, nil
}

// serializeBooleanValue normalizes a Serialization 3.1 boolean lexical to
// "yes"/"no". The value space (after collapsing leading/trailing XSD whitespace)
// is the full xs:boolean lexical space plus the yes/no synonyms:
// {yes, no, true, false, 1, 0}. ok is false for any other value — including
// uppercase forms (xs:boolean is lowercase-only) and NBSP-padded values.
func serializeBooleanValue(value string) (string, bool) {
	switch strings.Trim(value, lexicon.XMLWhitespace) {
	case lexicon.ValueYes, lexicon.ValueTrue, "1":
		return lexicon.ValueYes, true
	case lexicon.ValueNo, lexicon.ValueFalse, "0":
		return lexicon.ValueNo, true
	}

	return "", false
}

// Serialization 3.0 parameter documents admit only yes/no; the boolean
// synonyms were added in the 3.1 schema.
func serializeEditionBooleanValue(value string, edition int) (string, bool) {
	if edition == 30 {
		value = strings.Trim(value, lexicon.XMLWhitespace)
		return value, value == lexicon.ValueYes || value == lexicon.ValueNo
	}

	return serializeBooleanValue(value)
}

func readSerializeParamYesNo(elem *xdm.Element, edition int) (bool, error) {
	value, err := readSerializeParamValue(elem)
	if err != nil {
		return false, err
	}

	bv, ok := serializeEditionBooleanValue(value, edition)
	if !ok {
		return false, &xdm.Error{Code: errCodeSEPM0017, Message: fmt.Sprintf("serialize parameter %q must be a boolean (yes/no/true/false/1/0)", elem.LocalName())}
	}

	return bv == lexicon.ValueYes, nil
}

// readSerializeParamStandalone reads and normalizes the element-form
// "standalone" parameter, whose schema type is yes-no-omit-type: the boolean
// lexical space {yes, no, true, false, 1, 0} plus "omit" (Serialization 3.1).
// The value is XSD-whitespace-collapsed, so " no " is the "no" value; it returns
// the normalized "yes"/"no"/"omit".
func readSerializeParamStandalone(elem *xdm.Element, edition int) (string, error) {
	value, err := readSerializeParamValue(elem)
	if err != nil {
		return "", err
	}

	if strings.Trim(value, lexicon.XMLWhitespace) == lexicon.ValueOmit {
		return lexicon.ValueOmit, nil
	}

	if bv, ok := serializeEditionBooleanValue(value, edition); ok {
		return bv, nil
	}

	return "", &xdm.Error{Code: errCodeSEPM0017, Message: `serialize parameter "standalone" must be yes/no/omit or a boolean (true/false/1/0)`}
}

// readSerializeParamQNameNames reads a cdata-section-elements or
// suppress-indentation element-form parameter whose value attribute is a
// whitespace-separated list of names, and returns the writer's exact expanded-
// name key set. Per the Serialization 3.1 schema each token is a QName OR an
// EQName: an `Q{uri}local` EQName supplies its namespace directly; a prefixed
// lexical QName resolves its prefix against the parameter element's in-scope
// namespaces; an UNPREFIXED lexical QName resolves through the in-scope DEFAULT
// namespace (these parameters use the default namespace for unprefixed QNames).
func readSerializeParamQNameNames(elem *xdm.Element, edition int) (map[string]struct{}, error) {
	value, err := readSerializeParamValue(elem)
	if err != nil {
		return nil, err
	}

	names := make(map[string]struct{})
	// QNames-type is an xs:list, so tokens split ONLY on XSD list whitespace
	// (#x20/#x9/#xA/#xD) — NBSP and other Unicode whitespace stay inside the token
	// and then fail NCName validation, and are never silently split.
	for _, token := range xsdListFields(value) {
		if edition == 30 && strings.HasPrefix(token, "Q{") {
			return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "Serialization 3.0 requires lexical QNames"}
		}

		key, err := resolveSerializeNameToken(elem, token)
		if err != nil {
			return nil, err
		}

		names[key] = struct{}{}
	}

	return names, nil
}

// resolveSerializeNameToken resolves one cdata-section-elements /
// suppress-indentation name token (a QName or an `Q{uri}local` EQName) to its
// exact expanded {uri}local key. NCName parts are validated before resolution.
func resolveSerializeNameToken(elem *xdm.Element, token string) (string, error) {
	badName := func() error {
		return &xdm.Error{Code: errCodeSEPM0017, Message: fmt.Sprintf("serialize parameter has an invalid name %q", token)}
	}

	if uri, local, ok := parseEQNameToken(token); ok {
		if !xmlchar.IsValidNCName(local) {
			return "", badName()
		}

		return xdm.ClarkName(uri, local), nil
	}

	prefix, local, hasPrefix := strings.Cut(token, ":")
	if !hasPrefix {
		// No colon: strings.Cut puts the whole token in prefix. Resolve through
		// the in-scope default namespace (absent → no namespace).
		if !xmlchar.IsValidNCName(prefix) {
			return "", badName()
		}

		uri, _ := lookupInScopeNamespace(elem, "")

		return xdm.ClarkName(uri, prefix), nil
	}

	if !xmlchar.IsValidNCName(prefix) || !xmlchar.IsValidNCName(local) {
		return "", badName()
	}

	uri, ok := lookupInScopeNamespace(elem, prefix)
	if !ok {
		return "", &xdm.Error{Code: errCodeSEPM0017, Message: fmt.Sprintf("serialize parameter uses unbound namespace prefix %q", prefix)}
	}

	return xdm.ClarkName(uri, local), nil
}

// parseEQNameToken recognizes an EQName of the form `Q{uri}local`, returning the
// namespace URI and local name. Per the grammar `Q\{[^{}]*\}...` the URI part
// admits neither "{" nor "}"; the first "}" after "Q{" ends it (so the URI never
// contains "}"), and a "{" inside the URI part means the token is not a
// well-formed EQName (the caller then rejects it as an invalid name).
func parseEQNameToken(token string) (string, string, bool) {
	if !strings.HasPrefix(token, "Q{") {
		return "", "", false
	}

	uri, local, ok := strings.Cut(token[2:], "}")
	if !ok || strings.ContainsRune(uri, '{') {
		return "", "", false
	}

	return uri, local, true
}

// lookupInScopeNamespace resolves prefix against the in-scope namespace
// declarations of elem, walking up its ancestors. The reserved "xml" prefix is
// always bound (no declaration required). For a non-default prefix, an empty URI
// is an UNDECLARATION (XML 1.1 namespace masking): the prefix becomes unbound and
// the masking hides any ancestor binding. The default prefix ("") may be bound to
// the empty URI (xmlns="" = no default namespace), which is a valid state.
func lookupInScopeNamespace(elem xdm.Node, prefix string) (string, bool) {
	if prefix == lexicon.PrefixXML {
		return lexicon.NamespaceXML, true
	}

	for node := elem; node != nil; node = node.Parent() {
		nser, ok := node.(xdm.Namespacer)
		if !ok {
			continue
		}

		for _, ns := range nser.Namespaces() {
			if ns.Prefix() != prefix {
				continue
			}

			uri := ns.URI()
			if prefix != "" && uri == "" {
				// Undeclaration: the prefix is unbound from here up (masking).
				return "", false
			}

			return uri, true
		}
	}

	return "", false
}

// The map-form standalone option is xs:boolean?, unlike the XML parameter's
// yes/no/omit lexical domain. An empty value selects the default, omit.
func resolveSerializeStandaloneMap(ctx context.Context, value xdm.Sequence) (string, error) {
	atom, found, err := serializeOptionalAtomic(ctx, value, xdm.TypeBoolean, lexicon.SerializationStandalone)
	if err != nil || !found {
		return "", err
	}

	if atom.BooleanVal() {
		return lexicon.ValueYes, nil
	}

	return lexicon.ValueNo, nil
}

// serializeNodeKindError reports err:SENR0001 when a bare attribute or namespace
// node is serialized under a markup output method (xml/xhtml/html/text or the
// unspecified default). Sequence normalization (Serialization 3.1 §2) rejects
// these node kinds before any of those output methods run. Under the adaptive and
// json methods these node kinds are serialized specially, so callers must not
// apply this guard for those methods.
func serializeNodeKindError(item xdm.NodeItem) error {
	if _, ok := item.Node.(*xdm.Attribute); ok {
		return &xdm.Error{Code: errCodeSENR0001, Message: "cannot serialize an attribute node under this output method"}
	}

	if item.Node != nil && item.Node.Type() == xdm.NamespaceNode {
		return &xdm.Error{Code: errCodeSENR0001, Message: "cannot serialize a namespace node under this output method"}
	}

	return nil
}

// serializeItemKindError reports err:SENR0001 for every item kind that sequence
// normalization (Serialization 3.1 §2) rejects under the markup output methods
// (xml/xhtml/html/text and the unspecified default): a bare attribute node, a
// namespace node, OR a function item — INCLUDING a map (a map is a function item),
// but NOT an array. Arrays are flattened into their members by
// SerializationItems before this guard runs, so an array is never a rejected
// kind. It returns nil for any other item. The adaptive and json methods serialize
// these kinds specially (json serializes maps/arrays; both handle function items
// their own way), so callers must not apply this guard for those methods.
func serializeItemKindError(item xdm.Item) error {
	switch v := item.(type) {
	case xdm.NodeItem:
		return serializeNodeKindError(v)
	case xdm.MapItem:
		return &xdm.Error{Code: errCodeSENR0001, Message: "cannot serialize a map under this output method"}
	case xdm.FunctionItem:
		return &xdm.Error{Code: errCodeSENR0001, Message: "cannot serialize a function item under this output method"}
	}

	return nil
}

// resolveSerializeCharacterMapsElement validates the element form of
// use-character-maps and builds the rune→replacement map from its
// output:character-map children.
func resolveSerializeCharacterMapsElement(opts serializeOptions, elem *xdm.Element, extract bool) (map[rune]string, error) {
	if err := validateSerializeMapAttributes(elem); err != nil {
		return nil, err
	}

	result := make(map[rune]string)
	foreignChild := false

	for child := range xdm.Children(elem) {
		switch child.Type() {
		case xdm.TextNode, xdm.CDATASectionNode:
			if isXSDWhitespaceOnly(xdm.CharacterData(child)) {
				continue
			}

			return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "use-character-maps must not contain text"}
		case xdm.CommentNode, xdm.ProcessingInstructionNode:
			continue
		case xdm.ElementNode:
		default:
			return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "use-character-maps has invalid child node"}
		}

		charMap, _ := xdm.AsNode[*xdm.Element](child)
		if charMap.URI() != "" && charMap.URI() != lexicon.NamespaceSerialization {
			if foreignChild {
				return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "use-character-maps permits one trailing foreign child"}
			}

			foreignChild = true

			if err := validateSerializeLaxElement(opts, charMap); err != nil {
				return nil, err
			}

			continue
		}

		if foreignChild || charMap.URI() != lexicon.NamespaceSerialization || charMap.LocalName() != "character-map" {
			return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "use-character-maps children must be output:character-map"}
		}

		character, mapString, hasCharacter, err := readSerializeCharacterMap(charMap)
		if err != nil {
			return nil, err
		}

		if !hasCharacter {
			continue
		}

		if !extract {
			continue // Schema validity does not extract nested character maps.
		}

		key := []rune(character)[0]
		if _, exists := result[key]; exists {
			return nil, &xdm.Error{Code: errCodeSEPM0018, Message: "character-map entries must be unique"}
		}

		result[key] = mapString
	}

	return result, nil
}

func validateSerializeMapAttributes(elem *xdm.Element) error {
	for _, attr := range elem.Attributes() {
		if attr.URI() == "" || attr.URI() == lexicon.NamespaceSerialization {
			return &xdm.Error{Code: errCodeSEPM0017, Message: "use-character-maps only permits foreign attributes"}
		}
	}

	return nil
}

// Both character-map attributes are optional in the schema. An absent character
// matches no input character; an absent map-string deletes the matching one.
func readSerializeCharacterMap(elem *xdm.Element) (character, replacement string, present bool, err error) {
	if hasNonWhitespaceContent(elem) {
		return "", "", false, &xdm.Error{Code: errCodeSEPM0017, Message: "character-map must not have child content"}
	}

	if err := validateSerializeInstanceAttributes(elem, ""); err != nil {
		return "", "", false, err
	}

	for _, attr := range elem.Attributes() {
		if attr.URI() != "" && attr.URI() != lexicon.NamespaceSerialization {
			continue
		}

		if attr.URI() != "" {
			return "", "", false, &xdm.Error{Code: errCodeSEPM0017, Message: "character-map attributes must be unqualified"}
		}

		switch attr.LocalName() {
		case "character":
			character, present = attr.Value(), true
		case "map-string":
			replacement = attr.Value()
		default:
			return "", "", false, &xdm.Error{Code: errCodeSEPM0017, Message: "character-map has unsupported attribute"}
		}
	}

	if present && utf8.RuneCountInString(character) != 1 {
		return "", "", false, &xdm.Error{Code: errCodeSEPM0017, Message: "character-map character must be a single character"}
	}

	return character, replacement, present, nil
}

func hasNonWhitespaceContent(elem *xdm.Element) bool {
	for child := range xdm.Children(elem) {
		switch child.Type() {
		case xdm.TextNode, xdm.CDATASectionNode:
			if !isXSDWhitespaceOnly(xdm.CharacterData(child)) {
				return true
			}
		case xdm.CommentNode, xdm.ProcessingInstructionNode:
			continue
		default:
			return true
		}
	}

	return false
}

// resolveSerializeCharacterMaps validates the map form of the use-character-maps
// option and builds the rune→replacement map. Keys must be single-character
// strings and values strings (option (function) conventions apply — a QName key
// is err:XPTY0004; W3C serialize-xml-139/139b).
func resolveSerializeCharacterMaps(ctx context.Context, v xdm.Sequence) (map[rune]string, error) {
	// A use-character-maps entry present with the empty sequence selects the
	// default (no character map); present-empty = use default, not an error. An
	// empty (non-nil) map disables the feature just like a nil one.
	if xdm.SequenceLen(v) == 0 {
		return map[rune]string{}, nil
	}

	if xdm.SequenceLen(v) != 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize option 'use-character-maps' must be a singleton map"}
	}

	m, ok := v.Get(0).(xdm.MapItem)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize option 'use-character-maps' must be a map"}
	}

	charMap := make(map[rune]string)

	err := m.ForEachView(func(key xdm.AtomicValue, value xdm.Sequence) error {
		if err := fnCountOp(ctx, getFnContext(ctx)); err != nil {
			return err
		}

		if !atomicMatchesTargetType(key, xdm.TypeString, getFnContext(ctx)) {
			return &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize use-character-maps keys must be strings"}
		}

		keyString, err := atomicToString(key)
		if err != nil || utf8.RuneCountInString(keyString) != 1 {
			return &xdm.Error{Code: lexicon.ErrSEPM0016, Message: "serialize use-character-maps keys must be single characters"}
		}

		if xdm.SequenceLen(value) != 1 {
			return &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize use-character-maps values must be singleton strings"}
		}

		av, ok := value.Get(0).(xdm.AtomicValue)
		if !ok || !atomicMatchesTargetType(av, xdm.TypeString, getFnContext(ctx)) {
			return &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize use-character-maps values must be strings"}
		}

		mapString, err := atomicToString(av)
		if err != nil {
			return err
		}

		if err := ChargeString(ctx, len(keyString)+len(mapString)); err != nil {
			return err
		}

		charMap[[]rune(keyString)[0]] = mapString

		return nil
	})
	if err != nil {
		return nil, err
	}

	return charMap, nil
}

func serializeAdaptiveSequence(seq xdm.Sequence, opts serializeOptions) (string, error) {
	xmlOptions := opts
	xmlOptions.method = lexicon.MethodXML

	writer := newSerializeXMLWriter(xmlOptions)
	if opts.doctypeSystem != "" {
		writer.Doctype = &xdm.Doctype{PublicID: opts.doctypePublic, SystemID: opts.doctypeSystem}
	}

	var buf serializationBuffer

	buf.ctx = opts.serializationContext()

	serializer := AdaptiveSerialization{XML: writer, ItemSeparator: opts.serializationSeparator()}
	if err := serializer.WriteTo(buf.ctx, &buf, seq); err != nil {
		return "", err
	}

	return buf.Result()
}

func serializeJSONSequence(seq xdm.Sequence, opts serializeOptions) (string, error) {
	if xdm.SequenceLen(seq) > 1 {
		return "", &xdm.Error{Code: errCodeSERE0023, Message: "json serialization requires at most one top-level item"}
	}

	if xdm.SequenceLen(seq) == 0 {
		return jsonKindNull, nil
	}

	return serializeJSONItem(seq.Get(0), opts)
}

func serializeJSONItem(item xdm.Item, opts serializeOptions) (string, error) {
	if err := opts.enterValue(); err != nil {
		return "", err
	}

	opts.depth++

	switch v := item.(type) {
	case xdm.AtomicValue:
		return serializeJSONAtomic(v, opts)
	case xdm.ArrayItem:
		return serializeJSONArray(v, opts)
	case xdm.MapItem:
		return serializeJSONMap(v, opts)
	case xdm.NodeItem:
		return serializeJSONNode(v, opts)
	case xdm.FunctionItem:
		return "", &xdm.Error{Code: errCodeSERE0021, Message: "cannot serialize function item as JSON"}
	default:
		return "", &xdm.Error{Code: errCodeSERE0021, Message: fmt.Sprintf("cannot serialize %T as JSON", item)}
	}
}

func serializeJSONArray(v xdm.ArrayItem, opts serializeOptions) (string, error) {
	parts := make([]string, 0, v.Size())
	for _, member := range v.MembersView() {
		text, err := serializeJSONSequence(member, opts)
		if err != nil {
			return "", err
		}

		parts = append(parts, text)
	}

	return opts.jsonComposite("[", "]", parts)
}

func serializeJSONMap(v xdm.MapItem, opts serializeOptions) (string, error) {
	seen := make(map[string]struct{}, v.Size())
	parts := make([]string, 0, v.Size())

	err := v.ForEachView(func(key xdm.AtomicValue, value xdm.Sequence) error {
		keyText, err := atomicToString(key)
		if err != nil {
			return &xdm.Error{Code: errCodeSERE0021, Message: "json serialization map keys must be stringifiable"}
		}

		if _, exists := seen[keyText]; exists && !opts.allowDuplicateNames {
			return &xdm.Error{Code: lexicon.ErrSERE0022, Message: fmt.Sprintf("json serialization duplicate key %q", keyText)}
		}

		seen[keyText] = struct{}{}

		if xdm.SequenceLen(value) > 1 {
			return &xdm.Error{Code: errCodeSERE0023, Message: "json serialization map values must be singleton or empty"}
		}

		valText := jsonKindNull
		if xdm.SequenceLen(value) == 1 {
			valText, err = serializeJSONItem(value.Get(0), opts)
			if err != nil {
				return err
			}
		}

		encoded, err := encodeJSONStringForSerialization(keyText, opts)
		if err != nil {
			return err
		}

		pair, err := opts.join(`"`, []string{encoded, valText}, `":`+valueSeparator(opts.indent), "")
		if err != nil {
			return err
		}

		parts = append(parts, pair)

		return nil
	})
	if err != nil {
		return "", err
	}

	return opts.jsonComposite("{", "}", parts)
}

func serializeJSONNode(v xdm.NodeItem, opts serializeOptions) (string, error) {
	var buf serializationBuffer

	buf.ctx = opts.serializationContext()
	if err := WriteJSONNode(buf.ctx, &buf, v, opts.jsonNodeOutputMethod, opts.charMap, opts.normalizationForm, serializeRepertoire(opts.encoding)); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func serializeJSONAtomic(v xdm.AtomicValue, opts serializeOptions) (string, error) {
	switch {
	case v.TypeName == xdm.TypeBoolean:
		if v.BooleanVal() {
			return lexicon.ValueTrue, nil
		}

		return lexicon.ValueFalse, nil
	case v.IsNumeric():
		s, err := atomicToString(v)
		if err != nil {
			return "", err
		}

		if s == lexicon.FloatNaN || s == "INF" || s == "-INF" {
			return "", &xdm.Error{Code: errCodeSERE0020, Message: "cannot serialize NaN or infinity as JSON"}
		}

		return s, nil
	default:
		s, err := atomicToString(v)
		if err != nil {
			return "", err
		}
		// use-character-maps (§9.1.11) and normalization-form (§9.1.9) ARE
		// applicable to the json output method (Serialization 3.1; matching Saxon,
		// e.g. a character map that maps "/"→"/" prevents JSON-escaping it as "\/").
		// A mapped character is replaced by its verbatim replacement instead of
		// being JSON-escaped; when normalization is also in force the encoder
		// splits the content at each mapped rune and normalizes only the
		// non-mapped runs, so a replacement is neither re-escaped nor normalized
		// (§11).
		encoded, err := encodeJSONStringForSerialization(s, opts)
		if err != nil {
			return "", err
		}

		return opts.join(`"`, []string{encoded}, "", `"`)
	}
}

// serializeTextSequence implements the text output method (Serialization 3.1
// §8): the concatenation of the string values of the items, with the
// item-separator between adjacent items and no markup. A node contributes its
// string value; an atomic its lexical form. Sequence normalization (Serialization
// 3.1 §2) applies to the text method too, so an attribute node, a namespace node,
// or a function item is a serialization error [err:SENR0001]. Character maps apply
// to the resulting text.
func serializeTextSequence(seq xdm.Sequence, opts serializeOptions) (string, error) {
	var buf serializationBuffer

	buf.ctx = opts.serializationContext()
	for item, err := range SerializationItems(buf.ctx, seq, opts.serializationSeparator(), false) {
		if err != nil {
			return "", err
		}

		value := item.Text
		if item.Node != nil && item.Node.Type() == xdm.ElementNode {
			value = xdm.StringValue(item.Node)
		}

		if _, err := buf.WriteString(value); err != nil {
			return "", err
		}
	}

	return applyCharMapToString(buf.String(), opts)
}

// applyCharMapToString substitutes each mapped rune in s with its replacement
// string (used by the text output method, where the whole output is text). When
// an active normalization-form accompanies the character map, the content is
// split at each mapped rune (matching decided on the pre-normalization content,
// Serialization 3.1 §4 rules c/d), each non-mapped run is normalized on its own,
// and each replacement is spliced in verbatim — never normalized (§11). A
// literal content rune that happens to equal no mapped key always passes through
// unchanged, whatever codepoint it is.
func applyCharMapToString(s string, opts serializeOptions) (string, error) {
	if len(opts.charMap) == 0 {
		return s, nil
	}

	var buf serializationBuffer

	buf.ctx = opts.serializationContext()
	err := opts.characterRuns(s, func(run string) error { _, err := buf.WriteString(run); return err }, func(replacement string) error { _, err := buf.WriteString(replacement); return err })

	return buf.String(), err
}

func serializeXMLSequence(seq xdm.Sequence, opts serializeOptions) (string, error) {
	var buf serializationBuffer

	buf.ctx = opts.serializationContext()
	if err := writeXMLSequence(seq, opts, &buf); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func writeXMLSequence(seq xdm.Sequence, opts serializeOptions, dst io.Writer) error {
	ctx := opts.serializationContext()

	separator := opts.serializationSeparator()
	if opts.doctypeSystem != "" || opts.standalone != lexicon.ValueOmit && opts.standalone != "" {
		if err := ValidateSerializationDocument(ctx, seq, separator); err != nil {
			return err
		}
	}

	if opts.method == lexicon.MethodXHTML {
		doc, err := NormalizeSerialization(ctx, seq, separator, "")
		if err != nil {
			return err
		}

		text, err := serializeXHTMLDocument(doc, opts)
		if err != nil {
			return err
		}

		return writeSerializationString(dst, text)
	}

	writer := newSerializeXMLWriter(opts)
	if opts.doctypeSystem != "" {
		writer.Doctype = &xdm.Doctype{PublicID: opts.doctypePublic, SystemID: opts.doctypeSystem}
	}

	if err := writer.WriteTo(dst, xdm.NewDefaultDocument()); err != nil {
		return err
	}

	_, coalesce := serializeNormForm(opts.normalizationForm)
	if err := writer.WriteSequence(ctx, dst, SerializationItems(ctx, seq, separator, coalesce)); err != nil {
		return err
	}

	return nil
}

// newSerializeXMLWriter builds a xdm.XMLSerialization configured from the serialization
// options for the xml output method: version, encoding, omit-xml-declaration,
// indent, standalone, undeclare-prefixes, cdata-section-elements,
// suppress-indentation, and character maps.
func newSerializeXMLWriter(opts serializeOptions) xdm.XMLSerialization {
	writer := xdm.XMLSerialization{
		// The effective output version (version param, default "1.0") drives the XML
		// declaration text AND the XML 1.1 escaping/undeclaration behavior, so they
		// stay consistent regardless of the source document's own version.
		Version: opts.effectiveSerializeVersion(),
		// F&O 3.1 section 14.7.3 skips only the final octet-encoding phase.
		// The declaration and earlier character-reference decisions still use
		// the requested encoding; the returned Go string itself remains UTF-8.
		Encoding: opts.encoding,
		// Source DTD metadata is outside XDM. Only explicit output parameters
		// (or XHTML5 automatic detection) can supply a new declaration.
		OmitDoctype: !(opts.doctypeSystem != "" && opts.methodEmitsDoctype()),

		CompactDeclaration: !opts.indent,
		CanEncode:          serializeRepertoire(opts.encoding),
		EscapeControlChars: true,
	}

	if opts.omitXMLDeclaration {
		writer.OmitDeclaration = true
	}

	if opts.indent {
		writer.Indent = true
	}

	switch opts.standalone {
	case lexicon.ValueYes:
		writer.Standalone = "yes"
	case lexicon.ValueNo:
		writer.Standalone = "no"
	default:
		// "omit" (the default) or an empty-sequence value: force omission of the
		// standalone pseudo-attribute, overriding the source declaration.
		writer.Standalone = ""
	}
	// undeclare-prefixes is honored only at output version 1.1 (fnSerialize has
	// already rejected the 1.0 case with SEPM0010).
	if opts.undeclarePrefixes && opts.effectiveSerializeVersion() == lexicon.XMLVersion11 {
		writer.PrefixUndeclarations = true
	}

	if len(opts.cdataElements) > 0 {
		writer.CDATA = opts.cdataElements
	}

	if len(opts.suppressIndent) > 0 {
		writer.SuppressIndent = opts.suppressIndent
	}

	if len(opts.charMap) > 0 {
		writer.CharacterMap = opts.charMap
	}
	// Normalize character content inside the writer, preserving markup names,
	// comments, PIs and character-map replacements.

	if opts.methodAppliesNormalization() {
		writer.Normalization = opts.normalizationForm
	}

	return writer
}

// serializeHTMLSequence serializes a sequence under the html output method.
// Sequence normalization (Serialization 3.1 §2) wraps the WHOLE sequence in a
// single document node, so the html method emits at most ONE DOCTYPE for the
// entire sequence — immediately before the first element (§7.4.6). An html-rooted
// document contributes the default <!DOCTYPE html> (or an explicit doctype) plus a
// <meta http-equiv="Content-Type"> injected into <head>; a non-html-rooted
// document or a bare element contributes a DOCTYPE only when doctype-public/
// doctype-system is specified; any node with no element (or once a prior item has
// emitted the DOCTYPE) is a plain HTML fragment. The doctypeEmitted flag threads
// that "at most once" rule across the item loop. Character maps (use-character-
// maps) are applied to text and attribute content.
func serializeHTMLSequence(seq xdm.Sequence, opts serializeOptions) (string, error) {
	ctx := opts.serializationContext()

	hw := serializeHTMLWriter(opts)
	if opts.includeContentType {
		encoding, media := opts.encoding, opts.mediaType
		if encoding == "" {
			encoding = lexicon.EncodingUTF8U
		}

		if media == "" {
			media = "text/html"
		}

		hw = hw.ContentType(media + "; charset=" + encoding)
	}

	var buf serializationBuffer

	buf.ctx = ctx

	prolog := htmlSerializationProlog{opts: opts, buf: &buf, automatic: serializeHTMLIsVersion5(opts)}

	_, coalesce := serializeNormForm(opts.normalizationForm)

	items := func(yield func(xdm.XMLItem, error) bool) {
		for item, err := range SerializationItems(ctx, seq, opts.serializationSeparator(), coalesce) {
			if err != nil {
				yield(xdm.XMLItem{}, err)
				return
			}

			if err = ValidateHTMLItem(ctx, item, serializeHTMLIsVersion5(opts)); err != nil {
				yield(xdm.XMLItem{}, err)
				return
			}

			if err = prolog.before(item); err != nil {
				yield(xdm.XMLItem{}, err)
				return
			}

			if !yield(item, nil) {
				return
			}
		}
	}
	if err := hw.WriteSequence(ctx, &buf, items); err != nil {
		return "", err
	}

	if prolog.explicit() && !prolog.emitted {
		if _, err := buf.WriteString(htmlDoctype(opts)); err != nil {
			return "", err
		}
	}

	return buf.String(), nil
}

type htmlSerializationProlog struct {
	opts        serializeOptions
	buf         *serializationBuffer
	seenElement bool
	emitted     bool
	automatic   bool
}

func (p *htmlSerializationProlog) explicit() bool {
	return p.opts.doctypeSystem != "" || p.opts.doctypePublic != ""
}

func (p *htmlSerializationProlog) before(item xdm.XMLItem) error {
	if p.seenElement {
		return nil
	}

	if item.Node == nil && !isXSDWhitespaceOnly(item.Text) {
		p.automatic = false
	}

	element, ok := item.Node.(*xdm.Element)
	if !ok {
		return nil
	}

	p.seenElement = true
	if p.explicit() || p.automatic && strings.EqualFold(element.LocalName(), "html") && html.IsHTMLNamespace(element.URI(), true) {
		_, err := p.buf.WriteString(htmlDoctype(p.opts))
		p.emitted = err == nil

		return err
	}

	return nil
}

// ValidateHTMLItem checks the actual normalized item before HTML serialization.
// It is shared with XSLT's streaming writer, which need not have a result DOM.
func ValidateHTMLItem(ctx context.Context, item xdm.XMLItem, html5 bool) error {
	if item.Node == nil {
		return checkHTMLCharacters(ctx, item.Text, html5)
	}

	return validateHTMLNode(ctx, item.Node, html5, 0)
}

func serializeHTMLWriter(opts serializeOptions) html.Writer {
	return html.NewWriter().DefaultDTD(false).Format(false).PreserveCase(true).
		SerializationVersion(opts.edition).
		EscapeURIAttributes(opts.escapeURIAttributes).CharacterMap(opts.charMap).
		Repertoire(serializeRepertoire(opts.encoding)).CDATAElements(opts.cdataElements).
		Normalization(opts.normalizationForm).EscapeControlChars(serializeHTMLIsVersion5(opts)).
		NullNamespaceHTMLOnly(!serializeHTMLIsVersion5(opts)).ForeignNamespaces(serializeHTMLIsVersion5(opts))
}

// Unsupported encoding labels recover using UTF-8, as permitted by SER31
// section 5.1.3. Known encodings retain their character repertoire even though
// fn:serialize returns a string rather than encoded octets.
func serializeRepertoire(name string) func(rune) bool {
	if name == "" || strings.EqualFold(name, "UTF-8") || strings.EqualFold(name, "UTF8") {
		return nil
	}

	if encoding.IsASCII(name) {
		return func(r rune) bool { return r < utf8.RuneSelf }
	}

	codec := encoding.Load(name)
	if codec == nil {
		return nil
	}

	return encoding.Repertoire(codec.NewEncoder())
}

func htmlDoctype(opts serializeOptions) string {
	if opts.doctypePublic != "" || opts.doctypeSystem != "" {
		// The html output method's DOCTYPE name is the fixed token "html" (per the
		// Serialization 3.1 html output method / HTML5 doctype rule — the name is
		// always html/HTML), NOT the document element's own (possibly mixed-case)
		// name. So a source root <HtMl> still emits `<!DOCTYPE html ...>`.
		rootName := lexicon.MethodHTML

		var b strings.Builder
		b.WriteString("<!DOCTYPE ")
		b.WriteString(rootName)

		if opts.doctypePublic != "" {
			// A PubidLiteral (XML SystemLiteral's public-id sibling) can never
			// contain a double quote (it is not a PubidChar), so double-quoting the
			// public id is always well-formed.
			b.WriteString(` PUBLIC "`)
			b.WriteString(opts.doctypePublic)
			b.WriteString(`"`)

			if opts.doctypeSystem != "" {
				b.WriteByte(' ')
				writeDoctypeSystemLiteral(&b, opts.doctypeSystem)
			}
		} else {
			b.WriteString(` SYSTEM `)
			writeDoctypeSystemLiteral(&b, opts.doctypeSystem)
		}

		b.WriteString(">\n")

		return b.String()
	}

	if serializeHTMLIsVersion5(opts) {
		return "<!DOCTYPE html>\n"
	}

	return `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.Doctype">` + "\n"
}

// writeDoctypeSystemLiteral encloses a validated system identifier in double quotes,
// or apostrophes when the value contains a double quote. Parameter validation must
// reject values containing both quote characters.
func writeDoctypeSystemLiteral(b *strings.Builder, sys string) {
	quote := xmloutput.Quote(sys, '"')
	b.WriteByte(quote)
	b.WriteString(sys)
	b.WriteByte(quote)
}

// serializeHTMLIsVersion5 reports whether the effective html-version selects
// HTML5 serialization (version ≥ 5). The default (unspecified) html-version is
// 5.0. Parameter validation rejects unsupported values.
func serializeHTMLIsVersion5(opts serializeOptions) bool {
	version := html.RequestedVersion(opts.htmlVersion, opts.xmlVersion)
	value, err := strconv.ParseFloat(version, 64)

	return err == nil && value >= 5
}

// The document is already owned by NormalizeSerialization. Prefix/metadata
// changes need no additional complete copies of the result tree.
func serializeXHTMLDocument(doc *xdm.Document, opts serializeOptions) (string, error) {
	ctx := opts.serializationContext()
	writer := newSerializeXMLWriter(opts)
	html5 := isSerializeXHTML5(opts)
	contentType := ""

	if opts.includeContentType {
		name, media := opts.encoding, opts.mediaType
		if name == "" {
			name = lexicon.EncodingUTF8U
		}

		if media == "" {
			media = "text/html"
		}

		contentType = media + "; charset=" + name
	}

	if err := html.PrepareXHTML(ctx, doc, html5, contentType); err != nil {
		return "", err
	}

	if opts.doctypeSystem != "" {
		writer.Doctype = &xdm.Doctype{PublicID: opts.doctypePublic, SystemID: opts.doctypeSystem}
	} else if html5 && xhtmlAutomaticDoctype(doc) {
		doc.SetDoctype(doc.DocumentElement().LocalName(), "", "")

		writer.OmitDoctype = false
	}

	html.ConfigureXHTML(&writer.XMLWriteOptions, html5, opts.escapeURIAttributes, opts.edition)

	var buf serializationBuffer

	buf.ctx = ctx
	if err := writer.WriteTo(&buf, doc); err != nil {
		return "", err
	}

	return buf.Result()
}

func isSerializeXHTML5(opts serializeOptions) bool {
	value, err := strconv.ParseFloat(opts.htmlVersion, 64)
	return err == nil && value >= 5
}

func xhtmlAutomaticDoctype(doc *xdm.Document) bool {
	for child := range xdm.Children(doc) {
		if element, ok := child.(*xdm.Element); ok {
			return html.XHTMLIsElement(element.URI(), element.LocalName(), true) && strings.EqualFold(element.LocalName(), "html")
		}

		if child.Type() == xdm.TextNode && strings.Trim(xdm.CharacterData(child), " \t\r\n") != "" {
			return false
		}
	}

	return false
}

// elementWithInScopeNamespaces returns elem unchanged when it inherits no
// in-scope namespace declarations from ancestors outside itself, otherwise a
// deep copy carrying those inherited declarations so the serialized element is
// namespace-complete (fn:serialize serializes an element as if it were the root
// of a tree; the element's in-scope namespaces become namespace declarations on
// it). Only PREFIXED namespaces with a non-empty URI are added: a prefixed
// declaration never rebinds the element's own name, so adding one is always
// safe, while the default (empty-prefix) namespace and namespace undeclarations
// are handled by the deep copy's own active-namespace binding and are not
// force-added here (adding an inherited default could rebind a no-namespace
// element). Declarations that already appear on the element are left to the copy.
func elementWithInScopeNamespaces(elem *xdm.Element) (xdm.Node, error) {
	inherited := inheritedInScopeNamespaces(elem)
	if len(inherited) == 0 {
		return elem, nil
	}

	dst := xdm.NewDocument(lexicon.XMLVersion10, "", xdm.StandaloneImplicitNo)

	copied, err := xdm.CopyNode(elem, dst)
	if err != nil {
		return nil, err
	}

	copyElem, ok := copied.(*xdm.Element)
	if !ok {
		return elem, nil
	}
	// The over-declaring deep copy already re-declares the element's active
	// namespace and its literal declarations; add only the inherited prefixes it
	// does not already carry.
	declared := map[string]struct{}{}
	for _, ns := range copyElem.Namespaces() {
		declared[ns.Prefix()] = struct{}{}
	}

	for _, ns := range inherited {
		if _, dup := declared[ns.Prefix()]; dup {
			continue
		}

		if err := copyElem.DeclareNamespace(ns.Prefix(), ns.URI()); err != nil {
			return nil, err
		}

		declared[ns.Prefix()] = struct{}{}
	}
	// xdm.CopyNode over-declares: every namespaced element re-declares its own
	// active namespace, so a descendant repeats a prefix its serialized-subtree
	// ancestor already binds. The XML output method emits a namespace declaration
	// for an element only when its namespace node differs from its parent's (no
	// redundant xmlns), so drop descendant declarations already in scope from an
	// ancestor within the copy. The root keeps every declaration (it is the top of
	// the serialized tree and must be namespace-complete).
	pruneRedundantNamespaceDecls(copyElem, map[string]string{})

	return copyElem, nil
}

// pruneRedundantNamespaceDecls removes, from every element BELOW root, the
// namespace declarations whose prefix is already bound to the same URI by an
// ancestor within root's subtree — the redundant declarations xdm.CopyNode's
// over-declaring copy leaves behind. inScope maps prefix -> URI for the bindings
// visible from elem's ancestors (empty at root, so root's own declarations are
// never pruned). A declaration that establishes a new prefix or rebinds one to a
// different URI is kept and extends the scope for elem's descendants.
func pruneRedundantNamespaceDecls(elem *xdm.Element, inScope map[string]string) {
	childScope := inScope
	cloned := false

	for _, ns := range elem.Namespaces() {
		prefix := ns.Prefix()
		if uri, ok := inScope[prefix]; ok && uri == ns.URI() {
			elem.RemoveNamespaceByPrefix(prefix)
			continue
		}
		// This declaration establishes or rebinds prefix; extend the scope for
		// elem's descendants without mutating the ancestor-owned inScope map.
		if !cloned {
			childScope = maps.Clone(inScope)
			cloned = true
		}

		childScope[prefix] = ns.URI()
	}

	for child := range xdm.ChildElements(elem) {
		pruneRedundantNamespaceDecls(child, childScope)
	}
}

// inheritedInScopeNamespaces returns the namespace declarations that are in
// scope on elem by virtue of an ANCESTOR declaration (i.e. not declared on elem
// itself), with a non-empty prefix, closest-ancestor wins per prefix. A prefix
// declared on elem itself shadows any ancestor declaration and is omitted (the
// copy already reproduces elem's own declarations). The NEAREST ancestor
// declaration for a prefix decides it: if that declaration is an XML 1.1
// undeclaration (empty URI, xmlns:p="") the prefix is NOT in scope, so it is
// recorded as decided and NOT added — and a further-out ancestor binding for the
// same prefix cannot resurrect it (marking "seen" happens BEFORE the empty-URI
// skip).
func inheritedInScopeNamespaces(elem *xdm.Element) []*xdm.Namespace {
	seen := map[string]struct{}{}
	// elem's own declarations shadow ancestors and are reproduced by the copy, so
	// seed the seen set with them (they are never re-added as "inherited").
	for _, ns := range elem.Namespaces() {
		seen[ns.Prefix()] = struct{}{}
	}

	var result []*xdm.Namespace

	for cur := elem.Parent(); cur != nil; cur = cur.Parent() {
		e, ok := cur.(*xdm.Element)
		if !ok {
			continue
		}

		for _, ns := range e.Namespaces() {
			prefix := ns.Prefix()
			// The default (empty-prefix) namespace is left to the copy's active-
			// namespace binding, never force-added here.
			if prefix == "" {
				continue
			}

			if _, dup := seen[prefix]; dup {
				continue
			}
			// This is the nearest ancestor declaration for prefix: it decides
			// whether prefix is in scope, so mark it decided BEFORE the
			// undeclaration skip so an outer binding cannot revive it.
			seen[prefix] = struct{}{}

			if ns.URI() == "" {
				continue
			}

			result = append(result, ns)
		}
	}

	return result
}

// encodeJSONStringForSerialization escapes s as JSON string content for the json
// output method, honoring the encoding parameter (a non-UTF-8 encoding escapes
// non-ASCII as \u sequences) and the use-character-maps parameter: a mapped
// character is replaced by its replacement string INSTEAD of being JSON-escaped,
// and the replacement is emitted verbatim (not re-escaped), per Serialization 3.1
// §9.1.11 (use-character-maps applies to the JSON output method) / §11. A
// nil/empty opts.charMap disables mapping. When an active normalization-form
// accompanies the character map, the content is split at each mapped rune
// (matching decided on the pre-normalization content), each non-mapped run is
// normalized before escaping, and each replacement is spliced in verbatim —
// never normalized (§11). A literal content rune that equals no mapped key
// always encodes as ordinary content, whatever codepoint it is.
func encodeJSONStringForSerialization(s string, opts serializeOptions) (string, error) {
	canEncode := serializeRepertoire(opts.encoding)

	var buf serializationBuffer

	buf.ctx = opts.serializationContext()
	err := opts.characterRuns(s, func(run string) error {
		return writeSerializedJSONRun(opts.serializationContext(), &buf, run, canEncode)
	}, func(replacement string) error { _, err := buf.WriteString(replacement); return err })

	return buf.String(), err
}

func utf16SurrogatePair(r rune) (uint16, uint16) {
	cp := uint32(r - 0x10000)
	hi := uint16(0xD800 + (cp >> 10))
	lo := uint16(0xDC00 + (cp & 0x3FF))

	return hi, lo
}

func validateHTMLNode(ctx context.Context, node xdm.Node, html5 bool, depth int) error {
	if depth > DepthLimit(ctx, 512) {
		return ErrBudget
	}

	if err := Charge(ctx, 1); err != nil {
		return err
	}

	if node == nil {
		return nil
	}

	if node.Type() == xdm.ProcessingInstructionNode && !htmlXMLIslandNode(node, html5) {
		content := xdm.CharacterData(node)
		if err := Charge(ctx, 1+len(content)/64); err != nil {
			return err
		}

		if strings.Contains(content, ">") {
			return &xdm.Error{Code: "SERE0015", Message: "HTML processing instruction contains '>'"}
		}
	}

	switch value := node.(type) {
	case *xdm.Document:
	case *xdm.Element:
		for _, attribute := range value.Attributes() {
			if htmlXMLIslandNode(value, html5) || attribute.URI() != "" {
				continue
			}

			if err := checkHTMLCharacters(ctx, attribute.Value(), html5); err != nil {
				return err
			}
		}
	default:
		if !htmlXMLIslandNode(node, html5) {
			if err := checkHTMLCharacters(ctx, xdm.CharacterData(node), html5); err != nil {
				return err
			}
		}
	}

	for child := node.FirstChild(); child != nil; child = child.NextSibling() {
		if err := validateHTMLNode(ctx, child, html5, depth+1); err != nil {
			return err
		}
	}

	return nil
}

func htmlXMLIslandNode(node xdm.Node, html5 bool) bool {
	element, ok := node.(*xdm.Element)
	if !ok {
		element, ok = node.Parent().(*xdm.Element)
	}

	return ok && !html.IsHTMLNamespace(element.URI(), html5)
}

func checkHTMLCharacters(ctx context.Context, value string, html5 bool) error {
	if html5 {
		return ctx.Err()
	}

	if err := Charge(ctx, 1+len(value)/64); err != nil {
		return err
	}

	for _, r := range value {
		if r >= 0x7f && r <= 0x9f || r >= 1 && r <= 8 || r == 0xb || r == 0xc || r >= 0xe && r <= 0x1f {
			return &xdm.Error{Code: "SERE0014", Message: fmt.Sprintf("character U+%04X is not permitted in HTML before version 5", r)}
		}
	}

	return nil
}

type htmlSequenceValidator struct {
	ctx       context.Context
	separator string
	html5     bool
	seen      bool
}

func (v *htmlSequenceValidator) sequence(seq xdm.Sequence, depth int) error {
	if depth > DepthLimit(v.ctx, 512) {
		return ErrBudget
	}

	for item := range xdm.SequenceItems(seq) {
		if err := Charge(v.ctx, 1); err != nil {
			return err
		}

		if array, ok := item.(xdm.ArrayItem); ok {
			for _, member := range array.MembersView() {
				if err := v.sequence(member, depth+1); err != nil {
					return err
				}
			}

			continue
		}

		if v.seen && v.separator != "" {
			if err := checkHTMLCharacters(v.ctx, v.separator, v.html5); err != nil {
				return err
			}
		}

		v.seen = true
		if err := v.item(item); err != nil {
			return err
		}
	}

	return nil
}

func (v *htmlSequenceValidator) item(item xdm.Item) error {
	if err := serializeItemKindError(item); err != nil {
		return err
	}

	if node, ok := item.(xdm.NodeItem); ok {
		return ValidateHTMLItem(v.ctx, xdm.XMLItem{Node: node.Node}, v.html5)
	}

	atomic, err := AtomizeItem(item)
	if err != nil {
		return err
	}

	value, err := AtomicToString(atomic)
	if err != nil {
		return err
	}

	return checkHTMLCharacters(v.ctx, value, v.html5)
}
