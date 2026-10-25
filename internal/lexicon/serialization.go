package lexicon

// XML declaration versions and whitespace.
const (
	XMLVersion10 = "1.0"
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

// Serialization parameter names (xsl:output / xsl:result-document attributes).
// Also shared by fn:serialize.
const (
	SerializationMethod               = "method"
	SerializationVersion              = "version"
	SerializationEncoding             = "encoding"
	SerializationOmitXMLDeclaration   = "omit-xml-declaration"
	SerializationStandalone           = "standalone"
	SerializationDoctypePublic        = "doctype-public"
	SerializationDoctypeSystem        = "doctype-system"
	SerializationCDATASectionElements = "cdata-section-elements"
	SerializationIndent               = "indent"
	SerializationMediaType            = "media-type"
	SerializationByteOrderMark        = "byte-order-mark"
	SerializationEscapeURIAttributes  = "escape-uri-attributes"
	SerializationIncludeContentType   = "include-content-type"
	SerializationNormalizationForm    = "normalization-form"
	SerializationUndeclarePrefixes    = "undeclare-prefixes"
	SerializationUseCharacterMaps     = "use-character-maps"
	SerializationSuppressIndentation  = "suppress-indentation"
	SerializationHTMLVersion          = "html-version"
	SerializationItemSeparator        = "item-separator"
	SerializationJSONNodeOutputMethod = "json-node-output-method"
	SerializationParameterDocument    = "parameter-document"
	SerializationBuildTree            = "build-tree"
	SerializationAllowDuplicateNames  = "allow-duplicate-names"
)
