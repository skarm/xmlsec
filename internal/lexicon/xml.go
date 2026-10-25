package lexicon

const (
	PrefixXML   = "xml"
	PrefixXMLNS = "xmlns"
	PrefixErr   = "err"

	AttrBase  = "base"
	AttrID    = "id"
	AttrLang  = "lang"
	AttrSpace = "space"

	QNameXMLBase  = "xml:base"
	QNameXMLID    = "xml:id"
	QNameXMLLang  = "xml:lang"
	QNameXMLSpace = "xml:space"

	SpaceDefault  = "default"
	SpacePreserve = "preserve"

	ValueYes = "yes"
	ValueNo  = "no"

	// DeclVersion names the version pseudo-attribute of an XML declaration.
	DeclVersion    = "version"
	DeclEncoding   = "encoding"
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

// XSD prefixed type name constants (xs: prefix).
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

// XPath node test string constants (with parentheses).
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
	PrefixXS  = "xs"
	PrefixXSD = "xsd"
)

// Output encoding constants.
const (
	EncodingUTF8    = "utf-8"
	EncodingUTF8U   = "UTF-8"
	EncodingUTF8Alt = "utf8"
	EncodingUTF16   = "utf-16"
)
