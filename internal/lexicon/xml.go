package lexicon

// Byte-order marks and escaped XML spellings are exact bytes. Consumers select
// the permitted encoding and the text/attribute context before using them.
const (
	// BOMUTF16BE contains the original big-endian UTF-16 byte-order mark bytes for encoding detection.
	BOMUTF16BE = "\xfe\xff"
	// BOMUTF16LE contains the original little-endian UTF-16 byte-order mark bytes for encoding
	// detection.
	BOMUTF16LE = "\xff\xfe"
	// BOMUTF32BE contains the original big-endian UTF-32 byte-order mark bytes for encoding detection.
	BOMUTF32BE = "\x00\x00\xfe\xff"
	// BOMUTF32LE contains the original little-endian UTF-32 byte-order mark bytes for encoding
	// detection.
	BOMUTF32LE = "\xff\xfe\x00\x00"
	// BOMUTF8 contains the original UTF-8 byte-order mark bytes for encoding detection.
	BOMUTF8 = "\xef\xbb\xbf"
	// EscapeAmpersand is the XML reference emitted for a literal ampersand.
	EscapeAmpersand = "&amp;"
	// EscapeGreaterThan is the XML reference emitted when a literal greater-than sign must be escaped.
	EscapeGreaterThan = "&gt;"
	// EscapeLessThan is the XML reference emitted for a literal less-than sign.
	EscapeLessThan = "&lt;"
	// EscapeQuote is the XML reference emitted for a double quote in an attribute value.
	EscapeQuote = "&quot;"
)

// Reserved XML names, lexical attribute values and shared local names. A local
// name must be paired with the namespace required by its consuming vocabulary.
const (
	// PrefixXML names the predefined xml prefix bound to NamespaceXML.
	PrefixXML = "xml"
	// ReservedXMLPITarget cannot be used as a processing-instruction target,
	// compared without case sensitivity. It does not select an output method.
	ReservedXMLPITarget = "xml"
	// PrefixXMLNS names the reserved xmlns prefix used for namespace declarations.
	PrefixXMLNS = "xmlns"
	// PrefixErr is the conventional prefix for NamespaceErr, not the error namespace itself.
	PrefixErr = "err"

	AttrBase  = "base"
	AttrID    = "id"
	AttrLang  = "lang"
	AttrSpace = "space"

	// QNameXMLBase is the reserved prefixed spelling of the XML base attribute.
	QNameXMLBase  = "xml:base"
	QNameXMLID    = "xml:id"
	QNameXMLLang  = "xml:lang"
	QNameXMLSpace = "xml:space"

	// SpaceDefault selects ordinary whitespace handling through xml:space.
	SpaceDefault = "default"
	// SpacePreserve requests preservation through xml:space.
	SpacePreserve = "preserve"

	// ValueYes and ValueNo are lexical yes/no tokens; accepted forms depend on the attribute.
	ValueYes = "yes"
	ValueNo  = "no"

	// DeclVersion names the version pseudo-attribute of an XML declaration.
	DeclVersion = "version"
	// DeclEncoding names an XML declaration's encoding pseudo-attribute.
	DeclEncoding = "encoding"
	// DeclStandalone names an XML declaration's standalone pseudo-attribute.
	DeclStandalone = "standalone"

	// AttrValue names the value attribute shared by several XML vocabularies.
	// Note: AttrName is defined in catalog.go.
	AttrValue  = "value"
	AttrType   = "type"
	AttrClass  = "class"
	AttrStyle  = "style"
	AttrHref   = "href"
	AttrSrc    = "src"
	AttrAlt    = "alt"
	AttrTitle  = "title"
	AttrRef    = "ref"
	AttrSelect = "select"
	AttrMatch  = "match"
	AttrTest   = "test"
	AttrUse    = "use"
	AttrMode   = "mode"
	AttrCount  = "count"
	AttrFrom   = "from"
)

// Boolean and common attribute value string constants.
const (
	ValueTrue  = "true"
	ValueFalse = "false"
	ValueOmit  = "omit"
)

// URL scheme constants.
const (
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
	SchemeFile  = "file"
)

// Conventional xs:-prefixed spellings used in type displays and matching. Type
// resolution still depends on NamespaceXSD, regardless of the chosen prefix.
const (
	XSUntyped       = "xs:untyped"
	XSAnyType       = "xs:anyType"
	XSAnyAtomicType = "xs:anyAtomicType"
	XSUntypedAtomic = "xs:untypedAtomic"
	XSInteger       = "xs:integer"
	XSBoolean       = "xs:boolean"
	XSString        = "xs:string"
)

// XSD type local name constants (unprefixed).
const (
	TypeBoolean          = "boolean"
	TypeString           = "string"
	TypeNormalizedString = "normalizedString"
	TypeInteger          = "integer"
	TypeDecimal          = "decimal"
	TypeFloat            = "float"
	TypeDouble           = "double"
	TypeDate             = "date"
	TypeDateTime         = "dateTime"
	// TypeTime is the xs:time builtin local name, hoisted to a constant so the
	// several switch/comparison sites that reference it share one literal.
	TypeTime              = "time"
	TypeDuration          = "duration"
	TypeGYear             = "gYear"
	TypeGYearMonth        = "gYearMonth"
	TypeGMonth            = "gMonth"
	TypeGDay              = "gDay"
	TypeGMonthDay         = "gMonthDay"
	TypeDayTimeDuration   = "dayTimeDuration"
	TypeYearMonthDuration = "yearMonthDuration"
	TypeDateTimeStamp     = "dateTimeStamp"
	// TypeAnyType names the universal schema type used in node annotations.
	TypeAnyType = "anyType"
	// TypeUntyped is the XDM node annotation's local name in the XSD namespace.
	TypeUntyped            = "untyped"
	TypeAnyAtomicType      = "anyAtomicType"
	TypeError              = "error"
	TypeAnyURI             = "anyURI"
	TypeUntypedAtomic      = "untypedAtomic"
	TypePositiveInteger    = "positiveInteger"
	TypeNonNegativeInteger = "nonNegativeInteger"
	TypeNonPositiveInteger = "nonPositiveInteger"
	TypeNegativeInteger    = "negativeInteger"
	TypeLong               = "long"
	TypeInt                = "int"
	TypeShort              = "short"
	TypeByte               = "byte"
	TypeUnsignedLong       = "unsignedLong"
	TypeUnsignedInt        = "unsignedInt"
	TypeUnsignedShort      = "unsignedShort"
	TypeUnsignedByte       = "unsignedByte"
	TypeIDREF              = "IDREF"
	TypeIDREFS             = "IDREFS"
	TypeToken              = "token"
	TypeNumber             = "number"
	TypeQName              = "QName"
	TypeNotation           = "NOTATION"
	TypeAnySimpleType      = "anySimpleType"
	TypeHexBinary          = "hexBinary"
	TypeBase64Binary       = "base64Binary"
	TypeLanguage           = "language"
	TypeName               = "Name"
	TypeNCName             = "NCName"
	TypeID                 = "ID"
	TypeENTITY             = "ENTITY"
	TypeENTITIES           = "ENTITIES"
	TypeNMToken            = "NMTOKEN"
	TypeNMTokens           = "NMTOKENS"

	// TypeNumeric names the XPath 3.1 numeric union in the XSD namespace.
	TypeNumeric = "numeric"
)

// XPath node and item test spellings, including parentheses.
const (
	NodeTestNode         = "node()"
	NodeTestElement      = "element()"
	NodeTestAttribute    = "attribute()"
	NodeTestText         = "text()"
	NodeTestComment      = "comment()"
	NodeTestPI           = "processing-instruction()"
	NodeTestDocumentNode = "document-node()"
	NodeTestItem         = "item()"
)

// XPath kind test name constants (without parentheses).
const (
	KindNode            = "node"
	KindText            = "text"
	KindComment         = "comment"
	KindPI              = "processing-instruction"
	KindElement         = "element"
	KindAttribute       = "attribute"
	KindDocumentNode    = "document-node"
	KindSchemaElement   = "schema-element"
	KindSchemaAttribute = "schema-attribute"
	KindNamespaceNode   = "namespace-node"
	KindItem            = "item"
	KindEmptySequence   = "empty-sequence"
)

// Numeric special value string constants.
const (
	FloatINF    = "INF"
	FloatPosINF = "+INF"
	FloatNegINF = "-INF"
	FloatNaN    = "NaN"
)

// XSLT mode value constants.
const (
	ModeAll     = "#all"     // template applies to all modes
	ModeDefault = "#default" // the default (unnamed) mode, used as internal key
	ModeUnnamed = "#unnamed" // explicit unnamed mode reference
)

// XSD prefix constants.
const (
	// PrefixXS is the conventional prefix used for XML Schema type names.
	PrefixXS = "xs"
	// PrefixXSD is the alternate XML Schema prefix recognized by schema type resolution.
	PrefixXSD = "xsd"
)

// Encoding-label spellings shared by lookup and output. Keep their original
// case and punctuation when emitting a declaration; aliases are not new codecs.
const (
	EncodingUTF8    = "utf-8"
	EncodingUTF8U   = "UTF-8"
	EncodingUTF8Alt = "utf8"
	EncodingUTF16   = "utf-16"
)
