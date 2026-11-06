// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

const (
	// XPath 3.1 reserved keywords. The lexer and token-string tables use
	// these; they also serve as the conventional default namespace prefixes
	// for the map/array function namespaces per the F&O spec.
	keywordMap   = "map"
	keywordArray = "array"

	// JSON kind labels used by fn:json-to-xml / fn:xml-to-json and the
	// JSON serializer. The string values match the local-element names
	// defined by the W3C XPath/XQuery 3.1 F&O spec for the
	// http://www.w3.org/2005/xpath-functions namespace. Kept separate from
	// keywordMap/keywordArray because the conceptual roles are unrelated
	// even though the string values coincide.
	jsonKindNull    = "null"
	jsonKindMap     = "map"
	jsonKindArray   = "array"
	jsonKindString  = "string"
	jsonKindNumber  = "number"
	jsonKindBoolean = "boolean"

	// Duplicate-key handling option values for JSON-related functions.
	duplicatesUseFirst = "use-first"
	duplicatesReject   = "reject"
)

// XPath 1.0 retains legacy errors; XPath 2.0 introduces the standard dynamic
// error-code vocabulary; 3.0 and 3.1 select later grammars and function libraries.
// These language codes are separate from schema and XSLT.
const (
	xpathVersionDefault = 0 // selects the engine default
	xpathVersion10      = 10
	xpathVersion20      = 20
	xpathVersion30      = 30
	xpathVersion31      = 31
)
