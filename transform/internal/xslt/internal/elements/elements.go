// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package elements

import "slices"

// ElementContext describes where an XSLT element is allowed.
type ElementContext int

const (
	CtxTopLevel    ElementContext = 1 << iota // allowed as xsl:stylesheet child
	CtxInstruction                            // allowed in sequence constructors
	CtxChildOnly                              // only valid as child of specific parent(s)
	CtxRoot                                   // root wrapper (stylesheet/transform/package)
)

// ElementInfo describes an XSLT element's metadata.
type ElementInfo struct {
	MinVersion   string              // "1.0", "2.0", "3.0"
	Context      ElementContext      // bitmask: where this element is allowed
	Implemented  bool                // false for recognized-but-unsupported elements
	AllowedAttrs map[string]struct{} // element-specific unprefixed attrs (nil = unchecked)
	Parents      []string            // for CtxChildOnly: valid parent element names
}

// IsKnown reports whether an element is recognized.
func IsKnown(name string) bool { _, ok := Lookup(name); return ok }

// IsTopLevel reports whether an element is permitted at the top level.
func IsTopLevel(name string) bool {
	info, ok := Lookup(name)
	return ok && info.Context&CtxTopLevel != 0
}

// IsInstruction reports whether an element is permitted in a sequence constructor.
func IsInstruction(name string) bool {
	info, ok := Lookup(name)
	return ok && info.Context&CtxInstruction != 0
}

// IsImplemented reports whether a recognized element is implemented.
func IsImplemented(name string) bool { info, ok := Lookup(name); return ok && info.Implemented }

// MinVersion returns an element's minimum XSLT version, or an empty string.
func MinVersion(name string) string { info, _ := Lookup(name); return info.MinVersion }

// AllowedAttrs returns the allowed unprefixed attributes of a recognized element.
func AllowedAttrs(name string) (map[string]struct{}, bool) {
	info, ok := Lookup(name)
	return info.AllowedAttrs, ok
}

// ValidParents returns the valid parents of a child-only element.
func ValidParents(name string) []string {
	info, _ := Lookup(name)
	if info.Context&CtxChildOnly == 0 {
		return nil
	}

	return info.Parents
}

// IsValidChild reports whether a child-only element allows the given parent.
func IsValidChild(child, parent string) bool { return slices.Contains(ValidParents(child), parent) }
