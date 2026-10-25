// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/transform/internal/xdm"

	norm "github.com/skarm/xmlsec/internal/normalization"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/internal/xmloutput"
	htmlpkg "github.com/skarm/xmlsec/transform/internal/xdm/html"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

const (
	serializeMethodXML                 = "xml"
	serializeMethodXHTML               = "xhtml"
	serializeMethodHTML                = "html"
	serializeMethodText                = "text"
	serializeMethodJSON                = "json"
	serializeMethodAdaptive            = "adaptive"
	serializeStandaloneOmit            = "omit"
	serializeParamCDATASectionElements = "cdata-section-elements"
	serializeParamVersion              = "version"
)

const (
	errCodeSEPM0009 = "SEPM0009"
	errCodeSEPM0010 = "SEPM0010"
	errCodeSEPM0016 = "SEPM0016"
	errCodeSEPM0017 = "SEPM0017"
	errCodeSEPM0018 = "SEPM0018"
	errCodeSEPM0019 = "SEPM0019"
	errCodeSERE0020 = "SERE0020"
	errCodeSERE0021 = "SERE0021"
	errCodeSERE0022 = "SERE0022"
	errCodeSERE0023 = "SERE0023"
	errCodeSESU0011 = "SESU0011"
	errCodeSESU0013 = "SESU0013"
)

// xsdWhitespaceCutset is the XSD list / whiteSpace-collapse whitespace set
// (#x20, #x9, #xA, #xD). Element-form enumeration/boolean/QNames values are
// token-derived, so leading/trailing runs of these characters are stripped —
// but NBSP and other Unicode whitespace are NOT whitespace and must remain in
// the value (where they then fail lexical validation).
const xsdWhitespaceCutset = " \t\r\n"

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
		// The unspecified default is the xml family: sequence normalization
		// (Serialization 3.1 §2) flattens array inputs into their members. It
		// otherwise reuses the adaptive machinery, whose node-kind guard treats the
		// default method as a markup method (SENR0001 for attribute/namespace/map/
		// function items).
		result, err = serializeAdaptiveSequence(flattenSerializeArrays(args[0]), opts)
	case serializeMethodAdaptive:
		result, err = serializeAdaptiveSequence(args[0], opts)
	case serializeMethodJSON:
		result, err = serializeJSONSequence(args[0], opts)
	case serializeMethodHTML:
		validator := htmlSequenceValidator{ctx: ctx, html5: serializeHTMLIsVersion5(opts), separator: opts.itemSeparator}
		if err = validator.sequence(args[0], 0); err == nil {
			result, err = serializeHTMLSequence(args[0], opts)
		}
	case serializeMethodText:
		result, err = serializeTextSequence(args[0], opts)
	default:
		// The xml method (and xhtml, serialized as XML — a defensible
		// approximation, since helium implements no XHTML-specific rules).
		result, err = serializeXMLSequence(args[0], opts)
	}

	if err != nil {
		return nil, err
	}

	// Unicode normalization (normalization-form). The markup methods
	// (xml/xhtml/html and the unspecified default) apply it INSIDE the writer,
	// scoped to text-node and attribute-value character content (Serialization 3.1
	// §4 character-expansion phase) so element/attribute names, comments, PIs, the
	// DOCTYPE, and the XML declaration are never normalized. The text and json
	// methods emit pure character data (no element/attribute names; the json
	// structure is ASCII), so normalizing the whole output is equivalent to
	// node-scoped normalization and is applied here — EXCEPT when a character map
	// is in force: then the character-map application sites (applyCharMapToString
	// for text, encodeJSONStringForSerialization for json) apply the normalization
	// themselves, segmented around mapped runes, so a replacement string passes
	// through un-normalized (Serialization 3.1 §11) and a literal content rune is
	// never rewritten. Adaptive applies character mapping and normalization while
	// serializing its string-like atomics.
	switch opts.method {
	case serializeMethodText, serializeMethodJSON:
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

// serializeCharMapNorm returns the norm.Form the text/json/adaptive character-map
// application sites apply to each non-mapped content run, and whether that
// inline normalization is active. It is active exactly when a character map is
// in force AND the method applies an active, supported normalization-form —
// the same condition under which fnSerialize skips its whole-output
// normalization pass, so normalization runs exactly once. Splitting the content
// at each mapped rune and normalizing only the non-mapped runs keeps a
// replacement string un-normalized (Serialization 3.1 §11) without rewriting
// any literal content rune.
func serializeCharMapNorm(opts serializeOptions) (norm.Form, bool) {
	if len(opts.charMap) == 0 || !opts.methodAppliesNormalization() || !serializeNormalizationActive(opts.normalizationForm) {
		return norm.NFC, false
	}

	return serializeNormForm(opts.normalizationForm)
}

// normalizeSerializeRun returns one non-mapped content run normalized by form
// when inline normalization is active, unchanged otherwise.
func normalizeSerializeRun(run string, normalize bool, form norm.Form) string {
	if !normalize {
		return run
	}

	return form.String(run)
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

	f, ok := serializeNormForm(form)
	if !ok {
		return "", &xdm.Error{Code: errCodeSESU0011, Message: fmt.Sprintf("normalization-form %q is not supported", form)}
	}

	return f.String(s), nil
}

type serializeOptions struct {
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
	// jsonNodeOutputMethod is the requested json-node-output-method value ("" =
	// the default xml). helium serializes a node embedded in JSON only with the
	// xml method, so any other value that would change node serialization is an
	// unsupported-feature error when a node is actually serialized under json.
	jsonNodeOutputMethod string
	itemSeparatorSet     bool
	indent               bool
	omitXMLDeclaration   bool
	allowDuplicateNames  bool
	// undeclarePrefixes requests XML 1.1 namespace undeclarations (xmlns:pfx="").
	// It is honored only when the effective output version is 1.1; otherwise it
	// is a SEPM0010 static error.
	undeclarePrefixes bool
	// HTML output-method parameters (applied by serializeHTMLNode).
	// includeContentType / escapeURIAttributes default to true.
	includeContentType  bool
	escapeURIAttributes bool
}

// effectiveSerializeVersion returns the effective output version, defaulting an
// unspecified version to "1.0".
func (so serializeOptions) effectiveSerializeVersion() string {
	if so.xmlVersion == "" {
		return version10
	}

	return so.xmlVersion
}

// methodEmitsXMLDeclaration reports whether the output method produces an XML
// declaration (the xml and xhtml methods, and the unspecified default). The
// omit-xml-declaration / standalone / SEPM0009 rules apply only to these; for
// html/json/text/adaptive an XML declaration is never produced.
func (so serializeOptions) methodEmitsXMLDeclaration() bool {
	switch so.method {
	case "", serializeMethodXML, serializeMethodXHTML:
		return true
	}

	return false
}

// methodEmitsDoctype reports whether the output method emits a document type
// declaration from the doctype-system / doctype-public parameters (the xml,
// xhtml, and html methods, and the unspecified xml default). doctype-system is
// applicable to these methods (Serialization 3.1 §5.1.7 for xml/xhtml, §7.4.6 for
// html) and is ignored by the text/json/adaptive methods.
func (so serializeOptions) methodEmitsDoctype() bool {
	switch so.method {
	case "", serializeMethodXML, serializeMethodXHTML, serializeMethodHTML:
		return true
	}

	return false
}

// validate checks method-specific parameter constraints before output starts.
func (so serializeOptions) validate() error {
	// An extension method (a prefixed QName) is a valid method-type value but
	// helium implements no extension output methods, so it is an unsupported
	// value (SEPM0016), with no silent fall-through to the xml method. The
	// built-in methods and the unspecified default ("") are supported.
	if so.method != "" && !isBuiltinSerializeMethod(so.method) {
		return &xdm.Error{Code: errCodeSEPM0016, Message: fmt.Sprintf("output method %q is not supported", so.method)}
	}

	// The version parameter, for the methods that emit an XML declaration, must
	// name an XML version the serializer supports (1.0 or 1.1); any other value
	// is the SESU0013 unsupported-version serialization error, and never a
	// bogus version pseudo-attribute. It also drives the XML 1.1 escaping /
	// undeclaration rules, so it must be validated even when the declaration is
	// omitted.
	if so.methodEmitsXMLDeclaration() && so.xmlVersion != "" && !isSupportedXMLOutputVersion(so.xmlVersion) {
		return &xdm.Error{Code: errCodeSESU0013, Message: fmt.Sprintf("XML output version %q is not supported", so.xmlVersion)}
	}

	// A doctype-system value MUST NOT contain BOTH an apostrophe (#x27) and a
	// quotation mark (#x22) — it could not be written as an XML SystemLiteral. Per
	// Serialization 3.1 §3 that is an invalid parameter value (SEPM0016), rather
	// than silently emitting a malformed DOCTYPE. doctype-system is applicable only
	// to the xml, xhtml, and html output methods (§5.1.7 / §7.4.6) — text/json/
	// adaptive ignore it — so the SystemLiteral check is gated to the methods that
	// actually emit a DOCTYPE.
	if so.methodEmitsDoctype() && strings.ContainsRune(so.doctypeSystem, '"') && strings.ContainsRune(so.doctypeSystem, '\'') {
		return &xdm.Error{Code: errCodeSEPM0016, Message: "doctype-system must not contain both a quotation mark and an apostrophe"}
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
	if so.methodEmitsXMLDeclaration() && so.omitXMLDeclaration {
		if so.standalone == lexicon.ValueYes || so.standalone == lexicon.ValueNo {
			return &xdm.Error{Code: errCodeSEPM0009, Message: "omit-xml-declaration=yes conflicts with standalone=yes/no"}
		}

		if so.effectiveSerializeVersion() != version10 && so.doctypeSystem != "" {
			return &xdm.Error{Code: errCodeSEPM0009, Message: "omit-xml-declaration=yes conflicts with a doctype-system value at version other than 1.0"}
		}
	}

	// Namespace undeclarations require XML/XHTML 1.1; requesting them at an
	// effective output version of 1.0 is a static error (Serialization 3.1 §5.1.8
	// SEPM0010). undeclare-prefixes is applicable ONLY to the xml and xhtml output
	// methods (and the unspecified xml default) — for html/text/json/adaptive it is
	// silently ignored, no error — so SEPM0010 is gated to that method family
	// (methodEmitsXMLDeclaration covers exactly {"", xml, xhtml}).
	if so.methodEmitsXMLDeclaration() && so.undeclarePrefixes && so.effectiveSerializeVersion() != version11 {
		return &xdm.Error{Code: errCodeSEPM0010, Message: "undeclare-prefixes requires output version 1.1"}
	}

	// Validate the normalization-form up front so an unsupported form
	// ("fully-normalized" → SESU0011) is reported for every method that applies
	// normalization, even when the serialized output has no text/attribute content
	// to normalize (e.g. an empty element under the xml method). NFC/NFD/NFKC/NFKD
	// are applied later — inside the writer for the markup methods (scoped to
	// text/attribute nodes), to the whole output for text/json (pure character
	// data), or while adaptive serializes its string-like atomics.
	if so.methodAppliesNormalization() && serializeNormalizationActive(so.normalizationForm) && !isSupportedSerializeNormForm(so.normalizationForm) {
		return &xdm.Error{Code: errCodeSESU0011, Message: fmt.Sprintf("normalization-form %q is not supported", so.normalizationForm)}
	}

	return nil
}

// isSupportedSerializeNormForm reports whether form names a Unicode normalization
// form helium applies. A valid, active normalization-form (serialize parameter
// values are validated at parse time by serializeNormalizationFormValid) is one of
// NFC/NFD/NFKC/NFKD or "fully-normalized"; of these only "fully-normalized" is
// unsupported — it is not provided by golang.org/x/text/unicode/norm and is the
// SESU0011 unsupported-normalization serialization error. "none"/"" request no
// normalization (serializeNormalizationActive is false).
func isSupportedSerializeNormForm(form string) bool {
	return serializeNormalizationActive(form) && form != "fully-normalized"
}

// serializeNormalizationActive reports whether the normalization-form parameter
// requests an actual Unicode normalization (anything other than none/"").
func serializeNormalizationActive(form string) bool {
	return form != "" && form != nameNone
}

// isSupportedXMLOutputVersion reports whether v is an XML output version the
// serializer supports. helium serializes XML 1.0 and 1.1; any other value
// (including a malformed one or an unsupported version such as "1.2") is the
// SESU0013 unsupported-version error.
func isSupportedXMLOutputVersion(v string) bool {
	return v == version10 || v == version11
}

// isBuiltinSerializeMethod reports whether v names a supported built-in
// output method.
func isBuiltinSerializeMethod(v string) bool {
	switch v {
	case serializeMethodXML, serializeMethodHTML, serializeMethodXHTML, serializeMethodText, serializeMethodJSON, serializeMethodAdaptive:
		return true
	}

	return false
}

// methodAppliesNormalization reports whether the output method applies the
// normalization-form parameter. Per Serialization 3.1 it is a parameter of the
// xml/xhtml/html/text, json, AND adaptive (§9.1.9) output methods and the
// unspecified default.
func (so serializeOptions) methodAppliesNormalization() bool {
	switch so.method {
	case "", serializeMethodXML, serializeMethodXHTML, serializeMethodHTML, serializeMethodText, serializeMethodJSON, serializeMethodAdaptive:
		return true
	}

	return false
}

// booleanParam binds each boolean parameter to its option field. A recognized
// nil target requests lexical validation only: UTF-8 output emits no BOM.
func (so *serializeOptions) booleanParam(name string) (*bool, bool) {
	switch name {
	case "indent":
		return &so.indent, true
	case "omit-xml-declaration":
		return &so.omitXMLDeclaration, true
	case "allow-duplicate-names":
		return &so.allowDuplicateNames, true
	case "undeclare-prefixes":
		return &so.undeclarePrefixes, true
	case "escape-uri-attributes":
		return &so.escapeURIAttributes, true
	case "include-content-type":
		return &so.includeContentType, true
	case "byte-order-mark":
		return nil, true
	default:
		return nil, false
	}
}

func (so *serializeOptions) stringParam(name string) *string {
	switch name {
	case "method":
		return &so.method
	case "item-separator":
		return &so.itemSeparator
	case "encoding":
		return &so.encoding
	case serializeParamVersion:
		return &so.xmlVersion
	case "html-version":
		return &so.htmlVersion
	case "doctype-public":
		return &so.doctypePublic
	case "doctype-system":
		return &so.doctypeSystem
	case "json-node-output-method":
		return &so.jsonNodeOutputMethod
	case "normalization-form":
		return &so.normalizationForm
	case "media-type":
		return &so.mediaType
	case nameStandalone:
		return &so.standalone
	default:
		return nil
	}
}

func parseSerializeOptions(ctx context.Context, args []xdm.Sequence) (serializeOptions, error) {
	// The default output method is xml (Serialization 3.1 §2 / F&O 3.1
	// §18.9.1); adaptive is opt-in and must be requested explicitly. An empty
	// method means "unspecified default (xml family)", which the dispatch
	// treats like adaptive for atomic/map/array output but which the node-kind
	// guard distinguishes from an explicit "adaptive" so serializing an
	// attribute or namespace node under the default method raises SENR0001.
	opts := serializeOptions{
		method:        "",
		itemSeparator: " ",
		// The Serialization 3.1 default for the standalone parameter is "omit".
		standalone: serializeStandaloneOmit,
		// include-content-type and escape-uri-attributes default to yes.
		includeContentType:  true,
		escapeURIAttributes: true,
	}
	if len(args) <= 1 || xdm.SequenceLen(args[1]) == 0 {
		return opts, nil
	}

	if xdm.SequenceLen(args[1]) != 1 {
		return opts, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize options must be a singleton"}
	}

	if m, ok := args[1].Get(0).(xdm.MapItem); ok {
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

	sep, found, err := readSerializeStringOption(ctx, m, "item-separator")
	if err != nil {
		return opts, err
	}

	if found {
		opts.itemSeparator = sep
		opts.itemSeparatorSet = true
	}

	indent, found, err := readSerializeBooleanOption(m, "indent")
	if err != nil {
		return opts, err
	}

	if found {
		opts.indent = indent
	}
	// The map form of fn:serialize defaults omit-xml-declaration to true:
	// supplying an empty map has the same effect as omitting the argument, and
	// the XML declaration is omitted unless the option requests otherwise
	// (F&O 3.1 §18.9.1; W3C serialize-xml-127a).
	opts.omitXMLDeclaration = true

	omit, found, err := readSerializeBooleanOption(m, "omit-xml-declaration")
	if err != nil {
		return opts, err
	}

	if found {
		opts.omitXMLDeclaration = omit
	}

	allow, found, err := readSerializeBooleanOption(m, "allow-duplicate-names")
	if err != nil {
		return opts, err
	}

	if found {
		opts.allowDuplicateNames = allow
	}

	encoding, found, err := readSerializeStringOption(ctx, m, "encoding")
	if err != nil {
		return opts, err
	}

	if found {
		opts.encoding = encoding
	}

	return opts, nil
}

func parseSerializeMapMarkupOptions(ctx context.Context, opts serializeOptions, m xdm.MapItem) (serializeOptions, error) {
	undeclare, found, err := readSerializeBooleanOption(m, "undeclare-prefixes")
	if err != nil {
		return opts, err
	}

	if found {
		opts.undeclarePrefixes = undeclare
	}

	include, found, err := readSerializeBooleanOption(m, "include-content-type")
	if err != nil {
		return opts, err
	}

	if found {
		opts.includeContentType = include
	}

	escape, found, err := readSerializeBooleanOption(m, "escape-uri-attributes")
	if err != nil {
		return opts, err
	}

	if found {
		opts.escapeURIAttributes = escape
	}

	version, found, err := readSerializeStringOption(ctx, m, serializeParamVersion)
	if err != nil {
		return opts, err
	}

	if found {
		opts.xmlVersion = version
	}

	hv, found, err := readSerializeNumberOption(m, "html-version")
	if err != nil {
		return opts, err
	}

	if found {
		opts.htmlVersion = hv
	}

	pub, found, err := readSerializeStringOption(ctx, m, "doctype-public")
	if err != nil {
		return opts, err
	}

	if found {
		opts.doctypePublic = pub
	}

	sys, found, err := readSerializeStringOption(ctx, m, "doctype-system")
	if err != nil {
		return opts, err
	}

	if found {
		opts.doctypeSystem = sys
	}

	mt, found, err := readSerializeStringOption(ctx, m, "media-type")
	if err != nil {
		return opts, err
	}

	if found {
		opts.mediaType = mt
	}
	// Validation parity with the element form for the recognized-but-unapplied
	// (or limitation) parameters, so an invalid value is rejected consistently.
	// Validate the boolean value; UTF-8 output does not emit a BOM.
	if _, _, err := readSerializeBooleanOption(m, "byte-order-mark"); err != nil {
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

	nf, found, err := readSerializeStringOption(ctx, m, "normalization-form")
	if err != nil {
		return opts, err
	}

	if found {
		if !serializeNormalizationFormValid(nf) {
			return opts, &xdm.Error{Code: errCodeSEPM0016, Message: fmt.Sprintf("serialize option normalization-form has an invalid value %q", nf)}
		}

		opts.normalizationForm = nf
	}

	if v, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: nameStandalone}); found {
		standalone, err := resolveSerializeStandaloneMap(ctx, v)
		if err != nil {
			return opts, err
		}

		opts.standalone = standalone
	}

	if v, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: "use-character-maps"}); found {
		charMap, err := resolveSerializeCharacterMaps(v)
		if err != nil {
			return opts, err
		}

		opts.charMap = charMap
	}

	if v, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: serializeParamCDATASectionElements}); found {
		names, err := resolveSerializeQNameNames(ctx, v, serializeParamCDATASectionElements)
		if err != nil {
			return opts, err
		}

		opts.cdataElements = names
	}

	if v, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: "suppress-indentation"}); found {
		names, err := resolveSerializeQNameNames(ctx, v, "suppress-indentation")
		if err != nil {
			return opts, err
		}

		opts.suppressIndent = names
	}

	return opts, nil
}

func readSerializeBooleanOption(m xdm.MapItem, name string) (bool, bool, error) {
	v, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: name})
	if !found {
		return false, false, nil
	}
	// A map entry present with the empty sequence selects the parameter's
	// DEFAULT (F&O 3.1 fn:serialize: present-empty = use default, not an
	// error), so report it as not-found and let the caller keep its default.
	if xdm.SequenceLen(v) == 0 {
		return false, false, nil
	}

	if xdm.SequenceLen(v) != 1 {
		return false, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be a single xs:boolean", name)}
	}

	av, ok := v.Get(0).(xdm.AtomicValue)
	if !ok {
		return false, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be xs:boolean", name)}
	}

	switch av.TypeName {
	case xdm.TypeBoolean:
		return av.BooleanVal(), true, nil
	case xdm.TypeUntypedAtomic:
		s, err := atomicToString(av)
		if err != nil {
			return false, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be xs:boolean", name)}
		}

		switch s {
		case lexicon.ValueTrue, "1":
			return true, true, nil
		case lexicon.ValueFalse, "0":
			return false, true, nil
		default:
			return false, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be xs:boolean", name)}
		}
	default:
		return false, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be xs:boolean", name)}
	}
}

// resolveSerializeQNameNames converts a serialization parameter whose value is a
// sequence of xs:QName items (cdata-section-elements, suppress-indentation) into
// the element-name key set the writer matches against: each QName contributes its
// exact expanded {uri}local name (Clark notation; an explicit empty namespace is
// "{}local"). Matching is by exact expanded name, so QName("","b") does not match
// a namespaced <p:b>.
func resolveSerializeQNameNames(ctx context.Context, v xdm.Sequence, name string) (map[string]struct{}, error) {
	// Option (function) conversion (F&O 3.1 §2.5): atomize FIRST so an array
	// value (W3C serialize-xml-106a supplies [QName(...), ...]) flattens to its
	// members and each member atomizes to its xs:QName, THEN require every atom to
	// be an xs:QName.
	atoms, err := atomizeTypedValue(ctx, v)
	if err != nil {
		return nil, err
	}

	names := make(map[string]struct{})

	for _, av := range atoms {
		if av.TypeName != xdm.TypeQName {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be a sequence of xs:QName", name)}
		}

		qn, ok := av.Value.(xdm.QNameValue)
		if !ok {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be a sequence of xs:QName", name)}
		}

		names[xdm.ClarkName(qn.URI, qn.Local)] = struct{}{}
	}

	return names, nil
}

// readSerializeNumberOption extracts a numeric-valued serialize option
// (html-version, an xs:decimal) from the option map as its canonical string
// form. A non-numeric value is err:XPTY0004. found is false only when the key is
// absent.
func readSerializeNumberOption(m xdm.MapItem, name string) (string, bool, error) {
	v, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: name})
	if !found {
		return "", false, nil
	}
	// A map entry present with the empty sequence selects the parameter's DEFAULT
	// (present-empty = use default, not an error); report it as not-found.
	if xdm.SequenceLen(v) == 0 {
		return "", false, nil
	}

	if xdm.SequenceLen(v) != 1 {
		return "", true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be a single number", name)}
	}

	av, ok := v.Get(0).(xdm.AtomicValue)
	if !ok || !av.IsNumeric() {
		return "", true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be numeric", name)}
	}

	s, err := atomicToString(av)
	if err != nil {
		return "", true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be numeric", name)}
	}

	return s, true, nil
}

// readSerializeStringOption extracts a string-valued serialize option from the
// option map, applying F&O 3.1 §2.5 option (function) conversion: it atomizes
// the value FIRST — through the ctx-aware typed-value atomization, so an
// element-only-typed node (which has no typed value) raises err:FOTY0012 and an
// array (e.g. an empty-array member) flattens to its members — THEN enforces the
// singleton cardinality. atomizeTypedValue keeps the atom's type (e.g. an
// xs:QName "method" value), so atomicToString handles it unchanged; a raw
// pre-atomization seqLen gate would wrongly reject map{"method": ([], "xml")}.
// found is false only when the option key is absent.
func readSerializeStringOption(ctx context.Context, m xdm.MapItem, name string) (string, bool, error) {
	v, found := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: name})
	if !found {
		return "", false, nil
	}

	atoms, err := atomizeTypedValue(ctx, v)
	if err != nil {
		return "", true, err
	}
	// A map entry present with the empty sequence selects the parameter's DEFAULT
	// (present-empty = use default, not an error); report it as not-found.
	if len(atoms) == 0 {
		return "", false, nil
	}

	if len(atoms) != 1 {
		return "", true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be a singleton", name)}
	}

	s, err := atomicToString(atoms[0])
	if err != nil {
		return "", true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %q must be string-like", name)}
	}

	return s, true, nil
}

// resolveSerializeMethodMap resolves the map-form "method" option, whose value is
// an xs:string OR xs:QName (F&O 3.1 §18.9.1). It inspects the ATOM so a
// namespaced QName keeps its namespace instead of being stringified to its local
// part: a no-namespace value must be a built-in method token (else err:XPTY0004),
// and a value with a non-null namespace (a namespaced QName, or a prefixed-QName
// string) names an EXTENSION method — a valid value helium does not implement,
// which the SEPM0016 dispatch check reports as unsupported (the extension name is
// carried as an EQName so it is never mistaken for a built-in token). found is
// false only when the "method" key is absent.
func resolveSerializeMethodMap(ctx context.Context, m xdm.MapItem) (string, bool, error) {
	return resolveSerializeMethodOption(ctx, m, "method", serializeMethodValid)
}

// resolveSerializeJSONNodeMethodMap uses the narrower xml/html/xhtml/text domain
// for nodes embedded in JSON, retaining extension QNames for later validation.
func resolveSerializeJSONNodeMethodMap(ctx context.Context, m xdm.MapItem) (string, bool, error) {
	return resolveSerializeMethodOption(ctx, m, "json-node-output-method", serializeJSONNodeOutputMethodValid)
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
			return "", true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %s: an xs:QName value must have a non-absent namespace, got %q", name, qn.Local)}
		}

		return "Q{" + qn.URI + "}" + qn.Local, true, nil
	}

	value, err := atomicToString(av)
	if err != nil {
		return "", true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %s has an invalid value", name)}
	}

	if !valid(value) {
		return "", true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("serialize option %s has an invalid value %q", name, value)}
	}

	return value, true, nil
}

func parseSerializeOptionsNode(opts serializeOptions, n xdm.Node) (serializeOptions, error) {
	elem, err := readSerializeOptionsRoot(n)
	if err != nil {
		return opts, err
	}

	seen := make(map[string]struct{})

	for child := range xdm.Children(elem) {
		param, err := readSerializeOptionsChild(child)
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
			if _, err := readSerializeParamValue(param); err != nil {
				return opts, err
			}

			continue
		}

		opts, err = applySerializeNodeParam(opts, param)
		if err != nil {
			return opts, err
		}
	}

	return opts, nil
}

func readSerializeOptionsRoot(n xdm.Node) (*xdm.Element, error) {
	elem, ok := n.(*xdm.Element)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize options node must be an element"}
	}

	if elem.URI() != lexicon.NamespaceSerialization || elem.LocalName() != "serialization-parameters" {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize options root must be output:serialization-parameters"}
	}

	if len(elem.Attributes()) != 0 {
		return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "serialize options root must not have attributes"}
	}

	return elem, nil
}

// readSerializeOptionsChild skips comments, PIs and whitespace while enforcing
// the parameter element's required namespace.
func readSerializeOptionsChild(child xdm.Node) (*xdm.Element, error) {
	switch child.Type() {
	case xdm.TextNode, xdm.CDATASectionNode:
		if isXSDWhitespaceOnly(xdm.CharacterData(child)) {
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
	if param.URI() == "" {
		return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "serialize options parameters must be namespace-qualified"}
	}

	return param, nil
}

func applySerializeNodeParam(opts serializeOptions, param *xdm.Element) (serializeOptions, error) {
	name := param.LocalName()
	if target, recognized := opts.booleanParam(name); recognized {
		value, err := readSerializeParamYesNo(param)
		if err != nil {
			return opts, err
		}

		if target != nil {
			*target = value
		}

		return opts, nil
	}

	if target := opts.stringParam(name); target != nil {
		value, err := readSerializeNodeStringParam(param)
		if err != nil {
			return opts, err
		}

		*target = value

		if name == "item-separator" {
			opts.itemSeparatorSet = true
		}

		return opts, nil
	}

	switch name {
	case serializeParamCDATASectionElements, "suppress-indentation":
		names, err := readSerializeParamQNameNames(param)
		if err != nil {
			return opts, err
		}

		if name == serializeParamCDATASectionElements {
			opts.cdataElements = names
		} else {
			opts.suppressIndent = names
		}
	case "use-character-maps":
		charMap, err := resolveSerializeCharacterMapsElement(param)
		if err != nil {
			return opts, err
		}

		opts.charMap = charMap
	default:
		return opts, &xdm.Error{Code: errCodeSEPM0017, Message: fmt.Sprintf("unsupported serialize parameter %q", name)}
	}

	return opts, nil
}

// readSerializeNodeStringParam preserves literal string parameters and trims
// XSD whitespace only for parameters with token or decimal lexical domains.
func readSerializeNodeStringParam(param *xdm.Element) (string, error) {
	name := param.LocalName()
	if name == nameStandalone {
		return readSerializeParamStandalone(param)
	}

	value, err := readSerializeParamValue(param)
	if err != nil {
		return "", err
	}

	token := strings.Trim(value, xsdWhitespaceCutset)

	switch name {
	case "method":
		if !serializeMethodValid(token) {
			return "", &xdm.Error{Code: errCodeSEPM0017, Message: fmt.Sprintf("serialize parameter method has an invalid value %q", value)}
		}
	case "json-node-output-method":
		if !serializeJSONNodeOutputMethodValid(token) {
			return "", &xdm.Error{Code: errCodeSEPM0017, Message: fmt.Sprintf("serialize parameter json-node-output-method has an invalid value %q", value)}
		}
	case "normalization-form":
		if !serializeNormalizationFormValid(token) {
			return "", &xdm.Error{Code: errCodeSEPM0017, Message: fmt.Sprintf("serialize parameter normalization-form has an invalid value %q", value)}
		}
	case "html-version":
		if !isValidXSDecimal(token) {
			return "", &xdm.Error{Code: errCodeSEPM0017, Message: fmt.Sprintf("serialize parameter html-version must be an xs:decimal, got %q", value)}
		}
	case serializeParamVersion:
	default:
		return value, nil
	}

	return token, nil
}

// isXSDWhitespaceOnly reports whether s is empty or consists only of XSD
// whitespace (#x20/#x9/#xA/#xD). NBSP and other Unicode whitespace are NOT
// whitespace, so content containing them is significant.
func isXSDWhitespaceOnly(s string) bool {
	return strings.Trim(s, xsdWhitespaceCutset) == ""
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

// serializeNormalizationFormValid reports whether v is a valid normalization-form
// value: one of the Unicode normalization forms, "none", or empty.
func serializeNormalizationFormValid(v string) bool {
	switch v {
	case "", nameNone, nameNFC, nameNFD, nameNFKC, nameNFKD, "fully-normalized":
		return true
	}

	return false
}

// isExtensionMethodName reports whether v is a syntactically valid extension
// method name: a lexical QName WITH a prefix (its expanded name has a non-null
// namespace), or an `Q{uri}local` EQName with a NON-EMPTY namespace URI. A bare
// NCName (null namespace) is NOT an extension method — per Serialization 3.1 the
// method-type restricts extension methods to prefixed QNames, so an unprefixed
// value must be one of the built-in tokens.
func isExtensionMethodName(v string) bool {
	if uri, local, ok := parseEQNameToken(v); ok {
		return uri != "" && xmlchar.IsValidNCName(local)
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
	case serializeMethodXML, serializeMethodHTML, serializeMethodXHTML, serializeMethodText:
		return true
	}

	return isExtensionMethodName(v)
}

func readSerializeParamValue(elem *xdm.Element) (string, error) {
	if hasNonWhitespaceContent(elem) {
		return "", &xdm.Error{Code: errCodeSEPM0017, Message: "serialize parameter must not have child content"}
	}

	attrs := elem.Attributes()
	if len(attrs) != 1 {
		return "", &xdm.Error{Code: errCodeSEPM0017, Message: "serialize parameter must have exactly one value attribute"}
	}

	attr := attrs[0]
	if attr.URI() != "" || attr.LocalName() != "value" {
		return "", &xdm.Error{Code: errCodeSEPM0017, Message: "serialize parameter must use an unqualified value attribute"}
	}

	return attr.Value(), nil
}

// serializeBooleanValue normalizes a Serialization 3.1 boolean lexical to
// "yes"/"no". The value space (after collapsing leading/trailing XSD whitespace)
// is the full xs:boolean lexical space plus the yes/no synonyms:
// {yes, no, true, false, 1, 0}. ok is false for any other value — including
// uppercase forms (xs:boolean is lowercase-only) and NBSP-padded values.
func serializeBooleanValue(value string) (string, bool) {
	switch strings.Trim(value, xsdWhitespaceCutset) {
	case lexicon.ValueYes, lexicon.ValueTrue, "1":
		return lexicon.ValueYes, true
	case lexicon.ValueNo, lexicon.ValueFalse, "0":
		return lexicon.ValueNo, true
	}

	return "", false
}

func readSerializeParamYesNo(elem *xdm.Element) (bool, error) {
	value, err := readSerializeParamValue(elem)
	if err != nil {
		return false, err
	}

	bv, ok := serializeBooleanValue(value)
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
func readSerializeParamStandalone(elem *xdm.Element) (string, error) {
	value, err := readSerializeParamValue(elem)
	if err != nil {
		return "", err
	}

	if strings.Trim(value, xsdWhitespaceCutset) == serializeStandaloneOmit {
		return serializeStandaloneOmit, nil
	}

	if bv, ok := serializeBooleanValue(value); ok {
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
func readSerializeParamQNameNames(elem *xdm.Element) (map[string]struct{}, error) {
	value, err := readSerializeParamValue(elem)
	if err != nil {
		return nil, err
	}

	names := make(map[string]struct{})
	// QNames-type is an xs:list, so tokens split ONLY on XSD list whitespace
	// (#x20/#x9/#xA/#xD) — NBSP and other Unicode whitespace stay inside the token
	// and then fail NCName validation, and are never silently split.
	for _, token := range xsdListFields(value) {
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

// resolveSerializeStandaloneMap validates and resolves the "standalone" option
// value in the map form of fn:serialize. Its value space is
// union(xs:boolean, enum("omit")) (F&O 3.1 §18.9.1). The map form does NOT
// whitespace-collapse the value, so a string such as " omit " (with surrounding
// spaces) is not the "omit" enum value and is a type error [err:XPTY0004]. It
// returns "yes"/"no"/"omit", or "" to select the parameter default (omit).
func resolveSerializeStandaloneMap(ctx context.Context, v xdm.Sequence) (string, error) {
	xerr := &xdm.Error{Code: lexicon.ErrXPTY0004, Message: `serialize option "standalone" must be xs:boolean or "omit"`}
	// Option (function) conversion (F&O 3.1 §2.5): atomize FIRST so an array
	// (e.g. an empty-array member) flattens to its members, THEN apply the
	// singleton cardinality. An empty atomized value selects the parameter
	// default (omit); it is not a bad value (QT3 serialize-xml-131 supplies
	// map{"standalone":()}). Atomization is ctx-aware: an element-only-typed node
	// has no typed value, so it surfaces err:FOTY0012, masked as no
	// XPTY0004 bad-value error.
	atoms, err := atomizeTypedValue(ctx, v)
	if err != nil {
		if isNoTypedValueError(err) {
			return "", err
		}

		return "", xerr
	}

	if len(atoms) == 0 {
		return "", nil
	}

	if len(atoms) > 1 {
		return "", xerr
	}

	av := atoms[0]
	switch av.TypeName {
	case xdm.TypeBoolean:
		if av.BooleanVal() {
			return lexicon.ValueYes, nil
		}

		return lexicon.ValueNo, nil
	case xdm.TypeString, xdm.TypeUntypedAtomic:
		s, err := atomicToString(av)
		if err != nil {
			return "", xerr
		}

		if s == serializeStandaloneOmit {
			return serializeStandaloneOmit, nil
		}
		// An untypedAtomic may carry an xs:boolean lexical; accept the same
		// value space the other boolean map options do (readBool): true/false/1/0.
		// A TYPED xs:string is not an xs:boolean member of the union, and yes/no
		// are not xs:boolean lexicals — both stay rejected.
		if av.TypeName == xdm.TypeUntypedAtomic {
			switch s {
			case lexicon.ValueTrue, "1":
				return lexicon.ValueYes, nil
			case lexicon.ValueFalse, "0":
				return lexicon.ValueNo, nil
			}
		}

		return "", xerr
	default:
		return "", xerr
	}
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
// flattenSerializeArrays before this guard runs, so an array is never a rejected
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

// flattenSerializeArrays implements the array-flattening step of sequence
// normalization (Serialization 3.1 §2): an array supplied to a markup output
// method (xml/xhtml/html/text and the unspecified default) is replaced by its
// member items, RECURSIVELY (nested arrays flatten too), and those members are
// serialized as if they had been supplied directly. A map is NOT flattened (it is
// a function item, rejected by serializeItemKindError). The json and adaptive
// methods keep their native array handling and must NOT call this. When the
// sequence contains no array the input is returned unchanged.
func flattenSerializeArrays(seq xdm.Sequence) xdm.Sequence {
	hasArray := false

	for item := range xdm.SequenceItems(seq) {
		if _, ok := item.(xdm.ArrayItem); ok {
			hasArray = true
			break
		}
	}

	if !hasArray {
		return seq
	}

	out := make(xdm.ItemSlice, 0, xdm.SequenceLen(seq))
	for item := range xdm.SequenceItems(seq) {
		if arr, ok := item.(xdm.ArrayItem); ok {
			out = append(out, arr.Flatten().Materialize()...)
			continue
		}

		out = append(out, item)
	}

	return out
}

// resolveSerializeCharacterMapsElement validates the element form of
// use-character-maps and builds the rune→replacement map from its
// output:character-map children.
func resolveSerializeCharacterMapsElement(elem *xdm.Element) (map[rune]string, error) {
	if len(elem.Attributes()) != 0 {
		return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "serialize parameter use-character-maps must not have attributes"}
	}

	result := make(map[rune]string)

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
		if charMap.URI() != lexicon.NamespaceSerialization || charMap.LocalName() != "character-map" {
			return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "use-character-maps children must be output:character-map"}
		}

		if hasNonWhitespaceContent(charMap) {
			return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "character-map must not have child content"}
		}

		// map-string is an xs:string: an absent OR empty value maps the character
		// to the EMPTY replacement (deletion), so presence is tracked separately
		// from value and an empty value is not rejected. Only the character
		// attribute is required (and must be a single character).
		var (
			character, mapString string
			hasCharacter         bool
		)

		for _, attr := range charMap.Attributes() {
			if attr.URI() != "" {
				return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "character-map attributes must be unqualified"}
			}

			switch attr.LocalName() {
			case "character":
				character = attr.Value()
				hasCharacter = true
			case "map-string":
				mapString = attr.Value()
			default:
				return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "character-map has unsupported attribute"}
			}
		}

		if !hasCharacter || utf8.RuneCountInString(character) != 1 {
			return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "character-map character must be a single character"}
		}

		key := []rune(character)[0]
		if _, exists := result[key]; exists {
			return nil, &xdm.Error{Code: errCodeSEPM0018, Message: "character-map entries must be unique"}
		}

		result[key] = mapString
	}

	return result, nil
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
func resolveSerializeCharacterMaps(v xdm.Sequence) (map[rune]string, error) {
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
		if key.TypeName != xdm.TypeString && key.TypeName != xdm.TypeUntypedAtomic {
			return &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize use-character-maps keys must be strings"}
		}

		keyString, err := atomicToString(key)
		if err != nil || utf8.RuneCountInString(keyString) != 1 {
			return &xdm.Error{Code: errCodeSEPM0016, Message: "serialize use-character-maps keys must be single characters"}
		}

		if xdm.SequenceLen(value) != 1 {
			return &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize use-character-maps values must be singleton strings"}
		}

		av, ok := value.Get(0).(xdm.AtomicValue)
		if !ok || (av.TypeName != xdm.TypeString && av.TypeName != xdm.TypeUntypedAtomic) {
			return &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "serialize use-character-maps values must be strings"}
		}

		mapString, err := atomicToString(av)
		if err != nil {
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
	parts := make([]string, 0, xdm.SequenceLen(seq))

	atomic := make([]bool, 0, xdm.SequenceLen(seq))
	for item := range xdm.SequenceItems(seq) {
		s, err := serializeAdaptiveItem(item, opts)
		if err != nil {
			return "", err
		}

		parts = append(parts, s)
		_, isAtomic := item.(xdm.AtomicValue)
		atomic = append(atomic, isAtomic)
	}
	// The unspecified default method ("") is the xml family and obeys sequence
	// normalization (Serialization 3.1 §2): an absent item-separator separates
	// only adjacent atomic-value strings, not adjacent nodes. The explicit
	// adaptive method (and nested map/array serialization) is exempt and joins
	// every item with the item-separator.
	if opts.method == "" {
		return joinSerializedItems(parts, atomic, opts), nil
	}

	return strings.Join(parts, opts.itemSeparator), nil
}

func serializeAdaptiveItem(item xdm.Item, opts serializeOptions) (string, error) {
	// serializeAdaptiveItem serves BOTH the explicit adaptive method and the
	// unspecified default method (the xml family). Under the default method
	// sequence normalization (Serialization 3.1 §2) rejects a bare attribute node,
	// a namespace node, or a function item — which in XDM includes maps and arrays
	// — with SENR0001. The explicit adaptive method (and the nested map/array
	// serialization, which passes method="adaptive") serializes all of these its
	// own way, so this guard applies only when the method is not adaptive.
	if opts.method != serializeMethodAdaptive {
		if err := serializeItemKindError(item); err != nil {
			return "", err
		}
	}

	switch v := item.(type) {
	case xdm.AtomicValue:
		if opts.method != serializeMethodAdaptive {
			value, err := atomicToString(v)
			if err != nil {
				return "", err
			}

			doc := xdm.NewDefaultDocument()

			return serializeNodeItem(xdm.NodeItem{Node: doc.CreateText(value)}, opts)
		}

		if v.TypeName == xdm.TypeBoolean {
			if v.BooleanVal() {
				return "true()", nil
			}

			return "false()", nil
		}

		s, err := atomicToString(v)
		if err != nil {
			return "", err
		}
		// Per XPath 3.1 §12.2 (Adaptive): string, anyURI, and untypedAtomic
		// values are serialized enclosed in double quotes, with internal quotes
		// escaped as "".
		if v.TypeName == xdm.TypeString || v.TypeName == xdm.TypeAnyURI || v.TypeName == xdm.TypeUntypedAtomic {
			if opts.method == serializeMethodAdaptive {
				s, err = serializeAdaptiveStringContent(s, opts)
				if err != nil {
					return "", err
				}
			}

			escaped := strings.ReplaceAll(s, `"`, `""`)

			return `"` + escaped + `"`, nil
		}

		return s, nil
	case xdm.NodeItem:
		return serializeNodeItem(v, opts)
	case xdm.MapItem:
		return serializeAdaptiveMap(v, opts)
	case xdm.ArrayItem:
		return serializeAdaptiveArray(v, opts)
	case xdm.FunctionItem:
		// Only reachable under the explicit adaptive method (the default method is
		// rejected above). helium emits no adaptive function representation.
		return "", &xdm.Error{Code: errCodeFOER0000, Message: "cannot serialize function item"}
	default:
		return "", &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("cannot serialize %T", item)}
	}
}

// serializeAdaptiveStringContent applies the character-expansion phase to
// string-like atomic values before adaptive quoting. A character-map replacement
// is emitted verbatim, while each non-mapped content run is normalized on its
// own. Without a map, the whole string is normalized.
func serializeAdaptiveStringContent(s string, opts serializeOptions) (string, error) {
	if len(opts.charMap) > 0 {
		return applyCharMapToString(s, opts), nil
	}

	return applySerializeNormalization(s, opts)
}

func serializeAdaptiveMap(m xdm.MapItem, opts serializeOptions) (string, error) {
	parts := make([]string, 0, m.Size())

	err := m.ForEachView(func(key xdm.AtomicValue, value xdm.Sequence) error {
		keyText, err := serializeAdaptiveItem(key, opts)
		if err != nil {
			return err
		}

		nestedOpts := opts
		nestedOpts.method = serializeMethodAdaptive
		nestedOpts.itemSeparator = ","

		valText, err := serializeAdaptiveSequence(value, nestedOpts)
		if err != nil {
			return err
		}

		parts = append(parts, keyText+":"+valText)

		return nil
	})
	if err != nil {
		return "", err
	}

	return "map{" + strings.Join(parts, ",") + "}", nil
}

func serializeAdaptiveArray(a xdm.ArrayItem, opts serializeOptions) (string, error) {
	parts := make([]string, 0, a.Size())
	for _, member := range a.MembersView() {
		nestedOpts := opts
		nestedOpts.method = serializeMethodAdaptive
		nestedOpts.itemSeparator = ","

		text, err := serializeAdaptiveSequence(member, nestedOpts)
		if err != nil {
			return "", err
		}

		parts = append(parts, text)
	}

	return "[" + strings.Join(parts, ",") + "]", nil
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

	return formatJSONComposite("[", "]", parts, 0, opts.indent), nil
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
			return &xdm.Error{Code: errCodeSERE0022, Message: fmt.Sprintf("json serialization duplicate key %q", keyText)}
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

		parts = append(parts, `"`+encodeJSONStringForSerialization(keyText, opts)+`":`+valueSeparator(opts.indent)+valText)

		return nil
	})
	if err != nil {
		return "", err
	}

	return formatJSONComposite("{", "}", parts, 0, opts.indent), nil
}

func serializeJSONNode(v xdm.NodeItem, opts serializeOptions) (string, error) {
	text, err := SerializeNodeForJSON(v, opts.jsonNodeOutputMethod)
	if err != nil {
		return "", err
	}

	return `"` + encodeJSONStringForSerialization(text, opts) + `"`, nil
}

// SerializeNodeForJSON returns the inner node serialization before JSON string
// escaping. XPath and XSLT share the node-kind checks and XML/HTML/text rules.
func SerializeNodeForJSON(v xdm.NodeItem, method string) (string, error) {
	if method == "" {
		method = serializeMethodXML
	}
	// SER31 §9 supplies only the node output method and omit-xml-declaration.
	// JSON character maps and normalization apply to the resulting JSON string.
	nodeOpts := serializeOptions{
		method: method, omitXMLDeclaration: true,
		standalone: serializeStandaloneOmit, includeContentType: true, escapeURIAttributes: true,
	}
	if err := nodeOpts.validate(); err != nil {
		return "", err
	}

	switch method {
	case serializeMethodText:
		return serializeTextSequence(xdm.ItemSlice{v}, nodeOpts)
	case serializeMethodHTML:
		return serializeHTMLSequence(xdm.ItemSlice{v}, nodeOpts)
	default:
		return serializeXMLSequence(xdm.ItemSlice{v}, nodeOpts)
	}
}

func serializeJSONAtomic(v xdm.AtomicValue, opts serializeOptions) (string, error) {
	switch {
	case v.TypeName == xdm.TypeBoolean:
		if v.BooleanVal() {
			return nameTrue, nil
		}

		return nameFalse, nil
	case v.IsNumeric():
		s, err := atomicToString(v)
		if err != nil {
			return "", err
		}

		if s == valueNaN || s == "INF" || s == "-INF" {
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
		return `"` + encodeJSONStringForSerialization(s, opts) + `"`, nil
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
	// Sequence normalization (Serialization 3.1 §2) flattens array inputs into
	// their members before serialization.
	seq = flattenSerializeArrays(seq)
	parts := make([]string, 0, xdm.SequenceLen(seq))

	atomic := make([]bool, 0, xdm.SequenceLen(seq))
	for item := range xdm.SequenceItems(seq) {
		s, err := serializeTextItem(item)
		if err != nil {
			return "", err
		}

		parts = append(parts, s)
		_, isAtomic := item.(xdm.AtomicValue)
		atomic = append(atomic, isAtomic)
	}

	return applyCharMapToString(joinSerializedItems(parts, atomic, opts), opts), nil
}

func serializeTextItem(item xdm.Item) (string, error) {
	// Sequence normalization (Serialization 3.1 §2) rejects a bare attribute node,
	// a namespace node, or a function item with SENR0001 before the text output
	// method runs.
	if err := serializeItemKindError(item); err != nil {
		return "", err
	}

	switch v := item.(type) {
	case xdm.AtomicValue:
		return atomicToString(v)
	case xdm.NodeItem:
		return xdm.StringValue(v.Node), nil
	default:
		// A map or array has no string value; it can only be serialized with the
		// json or adaptive method.
		return "", &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("cannot serialize %T using the text output method", item)}
	}
}

// applyCharMapToString substitutes each mapped rune in s with its replacement
// string (used by the text output method, where the whole output is text). When
// an active normalization-form accompanies the character map, the content is
// split at each mapped rune (matching decided on the pre-normalization content,
// Serialization 3.1 §4 rules c/d), each non-mapped run is normalized on its own,
// and each replacement is spliced in verbatim — never normalized (§11). A
// literal content rune that happens to equal no mapped key always passes through
// unchanged, whatever codepoint it is.
func applyCharMapToString(s string, opts serializeOptions) string {
	charMap := opts.charMap
	if len(charMap) == 0 {
		return s
	}

	normForm, normalize := serializeCharMapNorm(opts)

	var b strings.Builder
	b.Grow(len(s))

	seg := 0

	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])

		repl, mapped := charMap[r]
		if !mapped {
			i += width
			continue
		}

		if i > seg {
			b.WriteString(normalizeSerializeRun(s[seg:i], normalize, normForm))
		}

		b.WriteString(repl)

		i += width
		seg = i
	}

	if seg == 0 {
		// No mapped rune in the content: normalize (or return) it whole.
		return normalizeSerializeRun(s, normalize, normForm)
	}

	if seg < len(s) {
		b.WriteString(normalizeSerializeRun(s[seg:], normalize, normForm))
	}

	return b.String()
}

// joinSerializedItems joins the serialized item strings under sequence
// normalization (Serialization 3.1 §2, step 3). When the item-separator
// parameter is explicitly specified, it is inserted between EVERY adjacent pair
// of items regardless of kind. Otherwise a single space is inserted ONLY between
// two adjacent atomic-value-derived strings — never between two nodes, nor
// between a node and an atomic value (atomic[i] reports whether parts[i] came
// from an atomic value). This preserves serialize((1,2,3)) → "1 2 3" while
// producing serialize((<a/>,<b/>)) → "<a/><b/>" with no spurious separator.
func joinSerializedItems(parts []string, atomic []bool, opts serializeOptions) string {
	if opts.itemSeparatorSet {
		return strings.Join(parts, opts.itemSeparator)
	}

	var b strings.Builder

	for i, p := range parts {
		if i > 0 && atomic[i-1] && atomic[i] {
			b.WriteByte(' ')
		}

		b.WriteString(p)
	}

	return b.String()
}

func serializeXMLSequence(seq xdm.Sequence, opts serializeOptions) (string, error) {
	// Sequence normalization (Serialization 3.1 §2) flattens array inputs into
	// their members before serialization.
	seq = flattenSerializeArrays(seq)
	parts := make([]string, 0, xdm.SequenceLen(seq))

	atomic := make([]bool, 0, xdm.SequenceLen(seq))
	for item := range xdm.SequenceItems(seq) {
		// Sequence normalization (Serialization 3.1 §2) rejects a bare attribute
		// node, a namespace node, or a function item under the xml/xhtml methods
		// [err:SENR0001] before serialization.
		if err := serializeItemKindError(item); err != nil {
			return "", err
		}

		switch v := item.(type) {
		case xdm.NodeItem:
			text, err := serializeNodeItem(v, opts)
			if err != nil {
				return "", err
			}

			parts = append(parts, text)
			atomic = append(atomic, false)
		default:
			s, err := serializeAdaptiveItem(item, opts)
			if err != nil {
				return "", err
			}

			parts = append(parts, s)
			atomic = append(atomic, true)
		}
	}

	return joinSerializedItems(parts, atomic, opts), nil
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
		// The encoding param drives the encoding pseudo-attribute of the XML
		// declaration (Serialization 3.1 §5.1.6: the declaration includes an encoding
		// declaration). When the param is unset it is empty, and the writer keeps the
		// document's own encoding, leaving default output byte-identical.
		//
		// fn:serialize returns a string, so the encoding parameter is DECLARATION-ONLY
		// (W3C Serialization): the declaration carries the label but the octets are not
		// transcoded — a non-representable character becomes a character reference. The
		// writer's declaration-only mode (an internal mode with no public method,
		// reached through internal/writerctl) sets the label from the effective
		// encoding while leaving octets UTF-8 with char-reference escaping, so a
		// Document node serializes to a UTF-8 Go string regardless of the encoding
		// parameter.
		Encoding: opts.encoding,
		// The DTD / internal subset of a source document node is NOT part of the XDM
		// data model (an XDM document node's children are element/PI/comment/text
		// nodes only), so fn:serialize must never reproduce it. A document type
		// declaration is emitted ONLY when the doctype-system parameter is specified
		// (Serialization 3.1 §5.1.7: the XML output method MUST output a document type
		// declaration immediately before the first element; the internal subset MUST be
		// empty). When doctype-system is set, serializeNodeItem/applyDoctype inject a
		// fresh empty-internal-subset DTD carrying the requested identifiers, and the
		// writer must emit that; otherwise any DTD present on the source tree is
		// dropped. The gate mirrors serializeNodeItem's applyDoctype gate: the
		// adaptive and json methods, whose node items also serialize through this
		// writer, ignore doctype-system entirely — no fresh DTD is injected for them,
		// so IncludeDTD(true) would leak the SOURCE document's own DTD.
		OmitDoctype: !(opts.doctypeSystem != "" && opts.methodEmitsDoctype()),
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
	if opts.undeclarePrefixes && opts.effectiveSerializeVersion() == version11 {
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
	// normalization-form is applied inside the writer, scoped to text-node and
	// attribute-value character content (Serialization 3.1 §4), so element/attribute
	// names, comments, PIs, the DOCTYPE, and the XML declaration are never
	// normalized. An unsupported form (fully-normalized) is rejected up front, so
	// the writer only ever sees NFC/NFD/NFKC/NFKD (or none/"" = disabled). Gated to
	// methods that apply normalization: serializeNodeItem uses this writer for the
	// xml/xhtml and unspecified-default methods, the adaptive method, and
	// json-embedded nodes.
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
	// Sequence normalization (Serialization 3.1 §2) flattens array inputs into
	// their members before serialization.
	seq = flattenSerializeArrays(seq)
	parts := make([]string, 0, xdm.SequenceLen(seq))
	atomic := make([]bool, 0, xdm.SequenceLen(seq))
	doctypeEmitted := false

	for item := range xdm.SequenceItems(seq) {
		// Sequence normalization (Serialization 3.1 §2) rejects a bare attribute
		// node, a namespace node, or a function item under the html method
		// [err:SENR0001] — a function item must NOT fall through to adaptive
		// serialization.
		if err := serializeItemKindError(item); err != nil {
			return "", err
		}

		node, ok := item.(xdm.NodeItem)
		if !ok {
			s, err := serializeAdaptiveItem(item, opts)
			if err != nil {
				return "", err
			}

			parts = append(parts, s)
			atomic = append(atomic, true)

			continue
		}

		text, emitted, err := serializeHTMLNode(node.Node, opts, !doctypeEmitted)
		if err != nil {
			return "", err
		}

		if emitted {
			doctypeEmitted = true
		}

		parts = append(parts, text)
		atomic = append(atomic, false)
	}

	return joinSerializedItems(parts, atomic, opts), nil
}

// serializeHTMLNode normalizes one node into a private document when metadata
// must be inserted. Every applicable head element participates, including a
// selected head or html element; the caller's tree is never modified.
func serializeHTMLNode(node xdm.Node, opts serializeOptions, allowDoctype bool) (string, bool, error) {
	hw := htmlpkg.NewWriter().DefaultDTD(false).Format(false).PreserveCase(true).
		EscapeURIAttributes(opts.escapeURIAttributes).CharacterMap(opts.charMap).
		Normalization(opts.normalizationForm)

	htmlRooted := false

	switch value := node.(type) {
	case *xdm.Document:
		htmlRooted = htmlDocumentElementIsHTML(value)
	case *xdm.Element:
		htmlRooted = strings.EqualFold(value.LocalName(), serializeMethodHTML)
	}

	emitDoctype := allowDoctype && (htmlRooted || opts.doctypePublic != "" || opts.doctypeSystem != "")
	if !opts.includeContentType {
		return writeHTMLNodeTree(hw, node, opts, emitDoctype)
	}

	doc, err := copyHTMLNodeDocument(node)
	if err != nil {
		return "", false, err
	}

	for root := range xdm.ChildElements(doc) {
		pruneRedundantNamespaceDecls(root, map[string]string{"": ""})
	}

	insertHTMLContentTypeMeta(doc, opts.encoding, opts.mediaType, serializeHTMLIsVersion5(opts))

	return writeHTMLNodeTree(hw, doc, opts, emitDoctype)
}

func copyHTMLNodeDocument(node xdm.Node) (*xdm.Document, error) {
	if doc, ok := node.(*xdm.Document); ok {
		return xdm.CopyDoc(doc)
	}

	if element, ok := node.(*xdm.Element); ok {
		var err error

		node, err = elementWithInScopeNamespaces(element)
		if err != nil {
			return nil, err
		}
	}

	doc := xdm.NewDefaultDocument()

	copied, err := xdm.CopyNode(node, doc)
	if err != nil {
		return nil, err
	}

	if err := doc.AddChild(copied); err != nil {
		return nil, err
	}

	return doc, nil
}

// writeHTMLNodeTree serializes node under the html writer, reporting whether it
// emitted a DOCTYPE. When emitDoctype is true it writes the computed DOCTYPE
// (htmlDoctype) immediately before the first element (Serialization 3.1 §7.4.6);
// otherwise no DOCTYPE is written. A document node's children are written in order
// (its DTD node skipped, the DOCTYPE inserted before the first element child); a
// bare element is written after the DOCTYPE; any other single node (text/comment/
// PI) has no first element, so no DOCTYPE is written even when emitDoctype is true
// (and it reports false so a later item in the sequence can still emit one).
func writeHTMLNodeTree(hw htmlpkg.Writer, node xdm.Node, opts serializeOptions, emitDoctype bool) (string, bool, error) {
	var doctype string
	if emitDoctype {
		doctype = htmlDoctype(opts)
	}

	var buf strings.Builder

	emitted := false

	switch n := node.(type) {
	case *xdm.Document:
		for child := range xdm.Children(n) {
			if emitDoctype && !emitted && child.Type() == xdm.ElementNode {
				buf.WriteString(doctype)

				emitted = true
			}

			if err := hw.WriteTo(&buf, child); err != nil {
				return "", false, err
			}
		}
	case *xdm.Element:
		if emitDoctype {
			buf.WriteString(doctype)

			emitted = true
		}

		if err := hw.WriteTo(&buf, n); err != nil {
			return "", false, err
		}
	default:
		if err := hw.WriteTo(&buf, node); err != nil {
			return "", false, err
		}
	}

	return strings.TrimSuffix(buf.String(), "\n"), emitted, nil
}

// htmlDoctype computes the DOCTYPE declaration (with trailing newline) for the
// html output method: an explicit doctype-public/doctype-system produces a
// PUBLIC/SYSTEM declaration; otherwise HTML5 (html-version ≥ 5, the default)
// produces `<!DOCTYPE html>` and HTML 4 produces the HTML 4.01 declaration.
func htmlDoctype(opts serializeOptions) string {
	if opts.doctypePublic != "" || opts.doctypeSystem != "" {
		// The html output method's DOCTYPE name is the fixed token "html" (per the
		// Serialization 3.1 html output method / HTML5 doctype rule — the name is
		// always html/HTML), NOT the document element's own (possibly mixed-case)
		// name. So a source root <HtMl> still emits `<!DOCTYPE html ...>`.
		rootName := serializeMethodHTML

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

// writeDoctypeSystemLiteral writes a doctype-system value as a well-formed XML
// SystemLiteral, choosing the enclosing quote character by content: apostrophes
// when the value contains a double quote, else double quotes. Serialization 3.1
// §7.4.6 requires the system identifier be enclosed in quotation marks (#x22) OR
// apostrophes (#x27) — it does not mandate double quotes — and SEPM0016 rejects
// only a value containing BOTH, so a value with just a `"` (e.g. `a"b`) must be
// single-quoted (`'a"b'`), and never emitted as malformed `"a"b"`. This mirrors
// helium's dtdQuoteChar used by the xml output method's DOCTYPE path (writer_dtd.go).
func writeDoctypeSystemLiteral(b *strings.Builder, sys string) {
	quote := xmloutput.Quote(sys, '"')
	b.WriteByte(quote)
	b.WriteString(sys)
	b.WriteByte(quote)
}

// serializeHTMLIsVersion5 reports whether the effective html-version selects
// HTML5 serialization (version ≥ 5). The default (unspecified) html-version is
// 5.0; an unparseable value is treated permissively as HTML5.
func serializeHTMLIsVersion5(opts serializeOptions) bool {
	version := opts.htmlVersion
	if version == "" {
		version = opts.xmlVersion
	}

	if version == "" {
		return true
	}

	v, err := strconv.ParseFloat(version, 64)
	if err != nil {
		return true
	}

	return v >= 5
}

// htmlDocumentElementIsHTML reports whether the document element's local name is
// "html" (case-insensitive) — the condition under which the html output method
// emits the HTML5 DOCTYPE and injects the Content-Type meta element.
func htmlDocumentElementIsHTML(doc *xdm.Document) bool {
	root := doc.DocumentElement()
	return root != nil && strings.EqualFold(root.LocalName(), "html")
}

// insertHTMLContentTypeMeta applies SER31 §7.4.13 to each HTML head element,
// discarding stale Content-Type declarations before inserting the computed meta.
// The document is a private copy. HTML 5 also recognizes the XHTML namespace.
func insertHTMLContentTypeMeta(doc *xdm.Document, encoding, mediaType string, html5 bool) {
	_ = xdm.Walk(doc, xdm.NodeWalkerFunc(func(node xdm.Node) error {
		head, ok := node.(*xdm.Element)
		if ok && strings.EqualFold(head.LocalName(), fnNameHead) &&
			(head.URI() == "" || html5 && head.URI() == lexicon.NamespaceXHTML) {
			insertHTMLHeadMeta(doc, head, encoding, mediaType)
		}

		return nil
	}))
}

func insertHTMLHeadMeta(doc *xdm.Document, head *xdm.Element, encoding, mediaType string) {
	enc := encoding
	if enc == "" {
		enc = lexicon.EncodingUTF8U
	}

	mt := mediaType
	if mt == "" {
		mt = "text/html"
	}

	contentValue := mt + "; charset=" + enc

	// Discard every stale Content-Type meta (matched case-insensitively and
	// whitespace-trimmed) so no conflicting declaration survives, regardless of
	// its position or how many exist.
	removeHTMLContentTypeMetas(head)

	meta, _ := doc.CreateElement("meta")
	if headURI := head.URI(); headURI != "" {
		_ = meta.SetActiveNamespace(head.Prefix(), headURI)
	}

	_ = meta.SetAttribute("http-equiv", "Content-Type")
	_ = meta.SetAttribute("content", contentValue)

	// Detach the current children, add meta first, then re-add them, so meta
	// becomes the head's first child.
	var children []xdm.Node

	for child := head.FirstChild(); child != nil; {
		next := child.NextSibling()

		mut, ok := child.(xdm.MutableNode)
		if ok {
			xdm.UnlinkNode(mut)

			children = append(children, child)
		}

		child = next
	}

	_ = head.AddChild(meta)
	for _, child := range children {
		_ = head.AddChild(child)
	}
}

// removeHTMLContentTypeMetas unlinks every <meta http-equiv="Content-Type"> child
// of head so a stale Content-Type declaration cannot survive the freshly-inserted
// one.
func removeHTMLContentTypeMetas(head *xdm.Element) {
	for child := head.FirstChild(); child != nil; {
		next := child.NextSibling()
		if isHTMLContentTypeMeta(child) {
			if mut, ok := child.(xdm.MutableNode); ok {
				xdm.UnlinkNode(mut)
			}
		}

		child = next
	}
}

// isHTMLContentTypeMeta reports whether n is a <meta> element whose http-equiv
// attribute is "Content-Type", compared case-insensitively after trimming
// surrounding whitespace so " Content-Type " and "CONTENT-TYPE" both match.
func isHTMLContentTypeMeta(n xdm.Node) bool {
	e, ok := n.(*xdm.Element)
	if !ok || !strings.EqualFold(e.LocalName(), "meta") {
		return false
	}

	for _, attr := range e.Attributes() {
		if attr.URI() != "" {
			continue
		}

		if strings.EqualFold(strings.TrimSpace(attr.LocalName()), "http-equiv") &&
			strings.EqualFold(strings.TrimSpace(attr.Value()), "Content-Type") {
			return true
		}
	}

	return false
}

func serializeNodeItem(item xdm.NodeItem, opts serializeOptions) (string, error) {
	if attr, ok := item.Node.(*xdm.Attribute); ok {
		return fmt.Sprintf(`%s="%s"`, attr.Name(), attr.Value()), nil
	}

	node := item.Node
	// fn:serialize serializes the node as if it were the root of a tree, so an
	// element selected from a larger document must carry the namespace
	// declarations for every namespace in scope on it — including those inherited
	// from ancestors that are NOT part of the serialized subtree. In XDM an
	// element node's namespace nodes comprise ALL its in-scope namespaces, and the
	// XML output method emits a namespace declaration for each. helium's DOM stores
	// only the declarations that appear literally on each element, so an isolated
	// element would otherwise drop its inherited (ancestor-declared) namespaces and
	// serialize with unbound prefixes. elementWithInScopeNamespaces returns the
	// element unchanged when it has no inherited in-scope namespaces (a document
	// root, or a standalone element — byte-identical), otherwise a namespace-
	// complete deep copy. This runs before the doctype handling so applyDoctype
	// copies the namespace-complete element.
	if elem, ok := node.(*xdm.Element); ok {
		aug, err := elementWithInScopeNamespaces(elem)
		if err != nil {
			return "", err
		}

		node = aug
	}
	// The xml method emits a document type declaration when doctype-system is
	// specified (Serialization 3.1 §5.1.7: "If the doctype-system parameter is
	// specified, the XML output method MUST output a document type declaration
	// immediately before the first element"). doctype-public is additive and MUST
	// be ignored unless doctype-system is present, so both are gated on
	// doctypeSystem alone. fn:serialize performs sequence normalization
	// (Serialization 3.1 §2), which wraps the node sequence in a document node, so
	// the DOCTYPE applies to an ELEMENT input too — not only a document node. The
	// node is copied into a fresh document (the caller's tree is never mutated) and
	// the DOCTYPE is injected as its internal subset, named after the document
	// element. A node with no document element (bare text/comment/PI) has no name
	// to declare, so no DOCTYPE is emitted and the node serializes unchanged.
	//
	// Only the DOCTYPE-emitting methods (xml/xhtml/html and the unspecified
	// default) inject the declaration — the adaptive method, which also reaches
	// this function, ignores doctype-system, matching the methodEmitsDoctype gate
	// on the SEPM0016 SystemLiteral check.
	if opts.doctypeSystem != "" && opts.methodEmitsDoctype() {
		withDT, err := applyDoctype(node, opts)
		if err != nil {
			return "", err
		}

		node = withDT
	}

	var buf strings.Builder
	if err := newSerializeXMLWriter(opts).WriteTo(&buf, node); err != nil {
		return "", err
	}

	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// applyDoctype returns the node that serializeNodeItem should serialize with the
// requested doctype-system / doctype-public applied. fn:serialize performs
// sequence normalization (Serialization 3.1 §2, step S7 "construct a new
// sequence … that consists of a single document node and copy all the items …
// as children of that document node"), so a DOCTYPE applies to a document node
// AND to a bare element input: the node is deep-copied into a fresh document
// (the caller's tree is never mutated) and an internal-subset DTD carrying the
// requested identifiers is injected, named after the document element. Per
// Serialization 3.1 §5.1.7 the internal subset MUST be empty, so any pre-existing
// internal subset on a copied document is replaced (its system/public identifiers
// and declarations do not leak through). A node with no document element (bare
// text/comment/PI, or a document without a root element) has no name to declare,
// so it is returned unchanged and no DOCTYPE is emitted.
func applyDoctype(node xdm.Node, opts serializeOptions) (xdm.Node, error) {
	var clone *xdm.Document

	switch n := node.(type) {
	case *xdm.Document:
		c, err := xdm.CopyDoc(n)
		if err != nil {
			return nil, err
		}

		clone = c
	case *xdm.Element:
		c, err := wrapElementInDocument(n)
		if err != nil {
			return nil, err
		}

		clone = c
	default:
		return node, nil
	}

	root := clone.DocumentElement()
	if root == nil {
		return node, nil
	}

	clone.Doctype = nil
	clone.SetDoctype(root.Name(), opts.doctypePublic, opts.doctypeSystem)

	return clone, nil
}

// wrapElementInDocument returns a fresh document node holding a deep COPY of elem
// as its document element (fn:serialize sequence normalization, Serialization 3.1
// §2), so a DOCTYPE can be injected without mutating the caller's tree.
func wrapElementInDocument(elem *xdm.Element) (*xdm.Document, error) {
	dst := xdm.NewDocument(version10, "", xdm.StandaloneImplicitNo)

	copied, err := xdm.CopyNode(elem, dst)
	if err != nil {
		return nil, err
	}

	if err := dst.AddChild(copied); err != nil {
		return nil, err
	}

	return dst, nil
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

	dst := xdm.NewDocument(version10, "", xdm.StandaloneImplicitNo)

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
func encodeJSONStringForSerialization(s string, opts serializeOptions) string {
	utf8Out := opts.encoding == "" || strings.EqualFold(opts.encoding, "utf-8") || strings.EqualFold(opts.encoding, "utf8")
	charMap := opts.charMap
	normForm, normalize := serializeCharMapNorm(opts)

	var b strings.Builder
	b.Grow(len(s))

	seg := 0

	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])

		repl, mapped := charMap[r]
		if !mapped {
			i += width
			continue
		}

		if i > seg {
			encodeJSONStringRun(&b, normalizeSerializeRun(s[seg:i], normalize, normForm), utf8Out)
		}

		b.WriteString(repl)

		i += width
		seg = i
	}

	if seg < len(s) {
		encodeJSONStringRun(&b, normalizeSerializeRun(s[seg:], normalize, normForm), utf8Out)
	}

	return b.String()
}

// encodeJSONStringRun escapes one run of non-mapped characters as JSON string
// content (utf8Out=false escapes non-ASCII as \u sequences).
func encodeJSONStringRun(b *strings.Builder, run string, utf8Out bool) {
	for _, r := range run {
		switch {
		case utf8Out || r <= 0x7F:
			appendSerializedJSONStringRune(b, r)
		case r <= 0xFFFF:
			appendJSONCodeUnit(b, uint16(r), jsonHexUpper)
		default:
			hi, lo := utf16SurrogatePair(r)
			appendJSONCodeUnit(b, hi, jsonHexUpper)
			appendJSONCodeUnit(b, lo, jsonHexUpper)
		}
	}
}

func utf16SurrogatePair(r rune) (uint16, uint16) {
	cp := uint32(r - 0x10000)
	hi := uint16(0xD800 + (cp >> 10))
	lo := uint16(0xDC00 + (cp & 0x3FF))

	return hi, lo
}

// ValidateHTMLItem checks the actual normalized item before HTML serialization.
// It is shared with XSLT's streaming writer, which need not have a result DOM.
func ValidateHTMLItem(ctx context.Context, item xdm.XMLItem, html5 bool) error {
	if item.Node == nil {
		return checkHTMLCharacters(ctx, item.Text, html5)
	}

	return validateHTMLNode(ctx, item.Node, html5, 0)
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

	if node.Type() == xdm.ProcessingInstructionNode {
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
			if err := checkHTMLCharacters(ctx, attribute.Value(), html5); err != nil {
				return err
			}
		}
	default:
		if err := checkHTMLCharacters(ctx, xdm.CharacterData(node), html5); err != nil {
			return err
		}
	}

	for child := node.FirstChild(); child != nil; child = child.NextSibling() {
		if err := validateHTMLNode(ctx, child, html5, depth+1); err != nil {
			return err
		}
	}

	return nil
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
