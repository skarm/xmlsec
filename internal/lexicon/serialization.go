package lexicon

// XML declaration versions and whitespace.
const (
	// XMLVersion10 selects XML 1.0 declaration and character rules.
	XMLVersion10 = "1.0"
	// XMLVersion11 selects XML 1.1 declaration and character rules.
	XMLVersion11 = "1.1"
	// XMLWhitespace is the set of XSD whitespace characters (#x20 space, #x9 tab,
	// #xD carriage return, #xA newline). Unlike Go's unicode.IsSpace this excludes
	// NBSP (U+00A0) and other Unicode whitespace, so an invalid value padded with
	// such characters stays invalid under subsequent lexical validation.
	// XSD list / whiteSpace-collapse and element-form serialization parameter
	// enumeration/boolean/QName values are token-derived: leading/trailing runs
	// of this set are stripped, but other Unicode whitespace remains in the value
	// (where it then fails lexical validation).
	XMLWhitespace = " \t\r\n"
)

// Explicit byte orders in encoding declarations.
const (
	EncodingUTF16BE = "UTF-16BE"
	EncodingUTF16LE = "UTF-16LE"
)

// Output method names per the XSLT 3.0 serialization specification.
const (
	MethodXML      = "xml"
	MethodHTML     = "html"
	MethodXHTML    = "xhtml"
	MethodText     = "text"
	MethodJSON     = "json"
	MethodAdaptive = "adaptive"
)

// Internal processing-instruction targets used to carry output-escaping state
// between result-tree construction and serialization. These marker names are
// distinct from the XSLT disable-output-escaping attribute.
const (
	// DisableOutputEscapingPITarget starts a span emitted without XML/HTML escaping.
	DisableOutputEscapingPITarget = "disable-output-escaping"
	// EnableOutputEscapingPITarget ends that span and restores normal escaping.
	EnableOutputEscapingPITarget = "enable-output-escaping"
)

// Serialization parameter names shared by xsl:output, xsl:result-document and
// fn:serialize. These are keys; accepted values and defaults depend on the method.
const (
	SerializationMethod = "method"
	// SerializationVersion identifies a method's output version, not the XSLT language version.
	SerializationVersion            = "version"
	SerializationEncoding           = "encoding"
	SerializationOmitXMLDeclaration = "omit-xml-declaration"
	SerializationStandalone         = "standalone"
	// SerializationDoctypePublic names emitted public-ID metadata; it performs no DTD retrieval.
	SerializationDoctypePublic = "doctype-public"
	// SerializationDoctypeSystem names emitted system-ID metadata; it grants no resource access.
	SerializationDoctypeSystem        = "doctype-system"
	SerializationCDATASectionElements = "cdata-section-elements"
	SerializationIndent               = "indent"
	// SerializationMediaType names declared output metadata, not an input trust decision.
	SerializationMediaType           = "media-type"
	SerializationByteOrderMark       = "byte-order-mark"
	SerializationEscapeURIAttributes = "escape-uri-attributes"
	SerializationIncludeContentType  = "include-content-type"
	// SerializationNormalizationForm selects Unicode normalization for eligible output content.
	SerializationNormalizationForm   = "normalization-form"
	SerializationUndeclarePrefixes   = "undeclare-prefixes"
	SerializationUseCharacterMaps    = "use-character-maps"
	SerializationSuppressIndentation = "suppress-indentation"
	// SerializationHTMLVersion selects the HTML edition independently of an XML declaration.
	SerializationHTMLVersion          = "html-version"
	SerializationItemSeparator        = "item-separator"
	SerializationJSONNodeOutputMethod = "json-node-output-method"
	SerializationParameterDocument    = "parameter-document"
	SerializationBuildTree            = "build-tree"
	SerializationAllowDuplicateNames  = "allow-duplicate-names"
)

// Unicode normalization names shared by string functions and serializers.
const (
	// NormalizationFormNFC selects canonical composition.
	NormalizationFormNFC = "NFC"
	// NormalizationFormNFD selects canonical decomposition.
	NormalizationFormNFD = "NFD"
	// NormalizationFormNFKC selects compatibility composition.
	NormalizationFormNFKC = "NFKC"
	// NormalizationFormNFKD selects compatibility decomposition.
	NormalizationFormNFKD = "NFKD"
)
