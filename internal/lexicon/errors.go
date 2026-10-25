package lexicon

// Error codes shared by XPath, XSLT and serialization.
const (
	// ErrFOCH0001 is the W3C XPath/XQuery error code raised when a codepoint
	// is not a valid XML character (e.g. fn:codepoints-to-string with an
	// out-of-range value). Used by xpath and asserted by test fixtures.
	ErrFOCH0001 = "FOCH0001"
	ErrFOAY0001 = "FOAY0001"
	ErrFODC0002 = "FODC0002" // document() / xsl:source-document load or parse error
	// ErrFORX0002 is the XPath FORX0002 ("invalid regular expression") error code.
	ErrFORX0002 = "FORX0002"
	ErrFOTY0013 = "FOTY0013" // atomization of map/function items
	ErrSEPM0009 = "SEPM0009" // omit-xml-declaration conflicts with standalone/doctype
	ErrSEPM0010 = "SEPM0010" // undeclare-prefixes="yes" requires XML 1.1
	ErrSEPM0016 = "SEPM0016" // invalid serialization parameter value
	ErrSERE0006 = "SERE0006" // character invalid for the output XML version
	ErrSERE0022 = "SERE0022" // duplicate keys in JSON map
	ErrSESU0011 = "SESU0011" // unsupported normalization form
	ErrSESU0013 = "SESU0013" // unsupported encoding
	ErrXPDY0002 = "XPDY0002" // context item is absent
	ErrXPST0003 = "XPST0003" // invalid XPath/XSLT type expression
	ErrXPST0008 = "XPST0008" // undeclared variable / circular static param reference
	ErrXPST0017 = "XPST0017" // invalid function call in pattern/static context
	// ErrXPTY0004 is the W3C XPath/XQuery type-error code raised when an
	// operand's type is not appropriate for the operation. Used by xpath
	// internally and asserted by both xpath and xslt test fixtures.
	ErrXPTY0004 = "XPTY0004" // type mismatch
)
