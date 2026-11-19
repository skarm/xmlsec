// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/unparsedtext"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
)

// URI helper dispatch and the absent-static-base error retain F&O spellings.
const (
	fnNameEncodeForURI  = "encode-for-uri"
	fnNameIRIToURI      = "iri-to-uri"
	fnNameEscapeHTMLURI = "escape-html-uri"
	fnNameResolveURI    = "resolve-uri"
	errCodeFONS0005     = "FONS0005"
)

// Percent escapes encode each byte as two hexadecimal nibbles. URI escaping
// and IRI validation retain their distinct space/control boundary comparisons.
const (
	uriHexDigitBits      = 4
	uriHexDigitMask      = 0x0F
	uriEscapeHexDigits   = 2
	uriPrintableASCIIMin = 0x20
	uriPrintableASCIIMax = 0x7E
	iriC1ControlEnd      = 0xA0
)

// ResolveURIReference applies fn:resolve-uri's IRI rules to explicit strings.
// An absolute reference does not inspect the base. Hosts can share the standard
// URI semantics without invoking an XPath evaluator or rewriting IRI characters.
func ResolveURIReference(relative, base string) (string, error) {
	if err := validateIRI(relative); err != nil {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "invalid relative URI: " + relative}
	}

	parsed, err := uripath.ParseIRIReference(relative)
	if err != nil {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "invalid relative URI: " + relative}
	}

	if parsed.IsAbsolute() {
		return relative, nil
	}

	return resolveRelativeURIReference(parsed, base)
}

func lookupFunctionsURI(name string) (*builtinFunc, bool) {
	switch name {
	case fnNameEncodeForURI:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnEncodeForURI}, true
	case fnNameIRIToURI:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnIRIToURI}, true
	case fnNameEscapeHTMLURI:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnEscapeHTMLURI}, true
	case fnNameResolveURI:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityTwo, fn: fnResolveURI}, true
	}

	return nil, false
}

func fnEncodeForURI(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	return xdm.SingleString(encodeForURI(s)), nil
}

// encodeForURI percent-encodes all characters except unreserved characters
// as defined by RFC 3986: A-Z a-z 0-9 - _ . ~
func encodeForURI(s string) string {
	var b strings.Builder

	for i := range len(s) {
		c := s[i]
		if isUnreservedChar(c) {
			b.WriteByte(c)
		} else {
			writePercentEncodedByte(&b, c)
		}
	}

	return b.String()
}

func writePercentEncodedByte(b *strings.Builder, c byte) {
	const percentEscapeHexAlphabet = "0123456789ABCDEF"

	b.WriteByte('%')
	b.WriteByte(percentEscapeHexAlphabet[c>>uriHexDigitBits])
	b.WriteByte(percentEscapeHexAlphabet[c&uriHexDigitMask])
}

func isUnreservedChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == '~'
}

func fnIRIToURI(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}
	// Per XPath F&O 3.0 §7.4.5: escape characters that are not allowed in URIs.
	// Keep: unreserved, reserved, and already percent-encoded sequences.
	// Escape: space, <, >, ", {, }, |, \, ^, `, non-ASCII (>0x7E), and control chars (<0x20).
	var b strings.Builder

	for i := range len(s) {
		c := s[i]
		if c == '%' && i+uriEscapeHexDigits < len(s) && xmlchar.IsHexDigit(s[i+1]) && xmlchar.IsHexDigit(s[i+uriEscapeHexDigits]) {
			// Already percent-encoded: pass through
			b.WriteByte(c)
			continue
		}

		if c > uriPrintableASCIIMax || c <= uriPrintableASCIIMin || c == '"' || c == '<' || c == '>' ||
			c == '{' || c == '}' || c == '|' || c == '\\' || c == '^' || c == '`' {
			writePercentEncodedByte(&b, c)
		} else {
			b.WriteByte(c)
		}
	}

	return xdm.SingleString(b.String()), nil
}

func fnResolveURI(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// fn:resolve-uri returns the empty sequence when the relative argument is
	// empty. Detect emptiness AFTER atomization so an empty array or a
	// nilled/empty-content typed node (which atomizes to the empty sequence, not
	// to "") also yields (), resolving no empty relative reference.
	relative, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	if err := validateIRI(relative); err != nil {
		return nil, &xdm.Error{Code: errCodeFORG0002, Message: "invalid relative URI: " + relative}
	}

	parsedRelative, err := uripath.ParseIRIReference(relative)
	if err != nil {
		return nil, &xdm.Error{Code: errCodeFORG0002, Message: "invalid relative URI: " + relative}
	}

	// F&O section 6.1 orders this rule before inspecting the effective base.
	if parsedRelative.IsAbsolute() {
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: relative}), nil
	}

	base := ""
	if len(args) == builtinArityTwo {
		base, err = coerceArgToString(ctx, args[1])
		if err != nil {
			return nil, err
		}
	} else {
		base = baseURIFromContext(ctx)
		if base == "" {
			return nil, &xdm.Error{Code: errCodeFONS0005, Message: "static base URI is absent"}
		}
	}

	result, err := resolveRelativeURIReference(parsedRelative, base)
	if err != nil {
		return nil, err
	}

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: result}), nil
}

func resolveRelativeURIReference(relative uripath.IRIReference, base string) (string, error) {
	if err := validateIRI(base); err != nil {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "invalid base URI: " + base}
	}

	parsedBase, err := uripath.ParseIRIReference(base)
	if err != nil {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "invalid base URI: " + base}
	}

	if !parsedBase.IsAbsolute() || !parsedBase.IsHierarchical() {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "base URI is not absolute and hierarchical: " + base}
	}

	if strings.Contains(base, "#") {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "base URI must not contain a fragment: " + base}
	}

	return relative.ResolveAgainst(parsedBase), nil
}

// validateIRI checks that a string is a valid IRI reference.
// Rejects characters that are not allowed in IRIs (like raw spaces).
func validateIRI(s string) error {
	if err := unparsedtext.ValidatePercentEncoding(s); err != nil {
		return err
	}
	// RFC 3987 permits only one fragment separator and permits literal
	// private-use characters only in a query.
	beforeFragment, fragment, _ := strings.Cut(s, "#")
	if strings.ContainsRune(fragment, '#') {
		return fmt.Errorf("invalid IRI: multiple '#' characters")
	}

	beforeQuery, _, _ := strings.Cut(beforeFragment, "?")

	isPrivateUse := func(r rune) bool { return unicode.Is(unicode.Co, r) }
	if strings.ContainsFunc(beforeQuery, isPrivateUse) || strings.ContainsFunc(fragment, isPrivateUse) {
		return fmt.Errorf("invalid IRI: private-use character outside the query")
	}

	for _, r := range s {
		if r < uriPrintableASCIIMin || (r > uriPrintableASCIIMax && r < iriC1ControlEnd) {
			return fmt.Errorf("invalid IRI character U+%04X", r)
		}
	}

	return nil
}

func fnEscapeHTMLURI(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}
	// Per XPath F&O: escape non-ASCII and control characters, keep printable ASCII as-is
	var b strings.Builder

	for i := range len(s) {
		c := s[i]
		if c > uriPrintableASCIIMax || c < uriPrintableASCIIMin {
			writePercentEncodedByte(&b, c)
		} else {
			b.WriteByte(c)
		}
	}

	return xdm.SingleString(b.String()), nil
}
