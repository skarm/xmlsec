// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

// xsltElementContext describes where an XSLT element is allowed.
type xsltElementContext int

const (
	elementTopLevel    xsltElementContext = 1 << iota // allowed as xsl:stylesheet child
	elementInstruction                                // allowed in sequence constructors
	elementChildOnly                                  // only valid as child of specific parent(s)
	elementRoot                                       // root wrapper (stylesheet/transform/package)
)

// xsltElementInfo describes an XSLT element's metadata.
type xsltElementInfo struct {
	minVersion  string             // "1.0", "2.0", "3.0"
	context     xsltElementContext // bitmask: where this element is allowed
	implemented bool               // false for recognized-but-unsupported elements
}

// isKnownXSLTElement reports whether an element is recognized.
func isKnownXSLTElement(name string) bool { _, ok := lookupXSLTElementInfo(name); return ok }

// isTopLevelXSLTElement reports whether an element is permitted at the top level.
func isTopLevelXSLTElement(name string) bool {
	info, ok := lookupXSLTElementInfo(name)
	return ok && info.context&elementTopLevel != 0
}

// isXSLTInstruction reports whether an element is permitted in a sequence constructor.
func isXSLTInstruction(name string) bool {
	info, ok := lookupXSLTElementInfo(name)
	return ok && info.context&elementInstruction != 0
}

// isImplementedXSLTElement reports whether a recognized element is implemented.
func isImplementedXSLTElement(name string) bool {
	info, ok := lookupXSLTElementInfo(name)
	return ok && info.implemented
}

// minXSLTElementVersion returns an element's minimum XSLT version, or an empty string.
func minXSLTElementVersion(name string) string {
	info, _ := lookupXSLTElementInfo(name)
	return info.minVersion
}
