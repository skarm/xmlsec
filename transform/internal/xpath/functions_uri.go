// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	unparsedtext "github.com/skarm/xmlsec/transform/internal/xpath/text"
)

// ResolveURIReference applies fn:resolve-uri's IRI rules to explicit strings.
// An absolute reference does not inspect the base. Hosts can share the standard
// URI semantics without invoking an XPath evaluator or rewriting IRI characters.
func ResolveURIReference(relative, base string) (string, error) {
	if err := validateIRI(relative); err != nil {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "invalid relative URI: " + relative}
	}

	parsed, err := parseURIReference(relative)
	if err != nil {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "invalid relative URI: " + relative}
	}

	if parsed.IsAbs() {
		return relative, nil
	}

	return resolveRelativeURIReference(relative, base)
}

func lookupFunctionsURI(name string) (*builtinFunc, bool) {
	switch name {
	case "encode-for-uri":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnEncodeForURI}, true
	case "iri-to-uri":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnIRIToURI}, true
	case "escape-html-uri":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnEscapeHTMLURI}, true
	case "resolve-uri":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnResolveURI}, true
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
	const hex = "0123456789ABCDEF"

	b.WriteByte('%')
	b.WriteByte(hex[c>>4])
	b.WriteByte(hex[c&0x0F])
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
		if c == '%' && i+2 < len(s) && xmlchar.IsHexDigit(s[i+1]) && xmlchar.IsHexDigit(s[i+2]) {
			// Already percent-encoded: pass through
			b.WriteByte(c)
			continue
		}

		if c > 0x7E || c <= 0x20 || c == '"' || c == '<' || c == '>' ||
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

	parsedRelative, err := parseURIReference(relative)
	if err != nil {
		return nil, &xdm.Error{Code: errCodeFORG0002, Message: "invalid relative URI: " + relative}
	}

	// F&O section 6.1 orders this rule before inspecting the effective base.
	if parsedRelative.IsAbs() {
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: relative}), nil
	}

	base := ""
	if len(args) == 2 {
		base, err = coerceArgToString(ctx, args[1])
		if err != nil {
			return nil, err
		}
	} else {
		base = baseURIFromContext(ctx)
		if base == "" {
			return nil, &xdm.Error{Code: "FONS0005", Message: "static base URI is absent"}
		}
	}

	result, err := resolveRelativeURIReference(relative, base)
	if err != nil {
		return nil, err
	}

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: result}), nil
}

func resolveRelativeURIReference(relative, base string) (string, error) {
	if err := validateIRI(base); err != nil {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "invalid base URI: " + base}
	}

	parsedBase, err := parseURIReference(base)
	if err != nil {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "invalid base URI: " + base}
	}

	if !parsedBase.IsAbs() || parsedBase.Opaque != "" {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "base URI is not absolute and hierarchical: " + base}
	}

	if strings.Contains(base, "#") {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "base URI must not contain a fragment: " + base}
	}

	result, err := resolveURIReference(base, relative)
	if err != nil {
		return "", &xdm.Error{Code: errCodeFORG0002, Message: "invalid relative URI: " + relative}
	}

	return result, nil
}

// validateIRI checks that a string is a valid IRI reference.
// Rejects characters that are not allowed in IRIs (like raw spaces).
func validateIRI(s string) error {
	if err := unparsedtext.ValidatePercentEncoding(s); err != nil {
		return err
	}
	// A URI reference may contain at most one '#' (fragment separator).
	if _, after, ok := strings.Cut(s, "#"); ok {
		if strings.IndexByte(after, '#') >= 0 {
			return fmt.Errorf("invalid IRI: multiple '#' characters")
		}
	}

	for _, r := range s {
		if r < 0x20 || (r > 0x7E && r < 0xA0) {
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
		if c > 0x7E || c < 0x20 {
			writePercentEncodedByte(&b, c)
		} else {
			b.WriteByte(c)
		}
	}

	return xdm.SingleString(b.String()), nil
}
