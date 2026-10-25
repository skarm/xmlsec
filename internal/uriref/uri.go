// Package uriref shares the bounded XML security URI-context contract.
package uriref

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/xmlchar"
)

// Err reports a malformed or unsupported URI context.
var Err = errors.New("invalid URI context")

// Validate checks URI-reference encoding without authorizing or rewriting it.
func Validate(value string) error {
	if strings.Contains(value, "\\") || !utf8.ValidString(value) {
		return fmt.Errorf("%w: URI encoding", Err)
	}

	if _, fragment, ok := strings.Cut(value, "#"); ok && strings.Contains(fragment, "#") {
		return fmt.Errorf("%w: multiple URI fragments", Err)
	}

	for i := 0; i < len(value); i++ {
		if value[i] == '%' {
			if i+2 >= len(value) || !xmlchar.IsHexDigit(value[i+1]) || !xmlchar.IsHexDigit(value[i+2]) {
				return fmt.Errorf("%w: malformed URI escape", Err)
			}

			i += 2
		}
	}

	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%w: unescaped URI whitespace/control", Err)
		}
	}

	if _, err := url.Parse(value); err != nil {
		return fmt.Errorf("%w: malformed URI: %w", Err, err)
	}

	return nil
}

// Base parses an optional absolute hierarchical, fragment-free document base.
func Base(value string) (*url.URL, error) {
	if value == "" {
		return nil, nil
	}

	if err := Validate(value); err != nil {
		return nil, err
	}

	base, err := url.Parse(value)
	if err != nil || !base.IsAbs() || base.Opaque != "" || strings.Contains(value, "#") {
		return nil, fmt.Errorf("%w: absolute hierarchical fragment-free base required", Err)
	}

	return base, nil
}

// Resolve derives the external URI without fetching or authorizing anything.
// Empty and fragment-only references must be handled in their document scope by
// the caller. A nil base preserves literal URI spelling. Absolute references are
// preserved exactly; relative references inherit the retrieval URI and xml:base.
func Resolve(value string, base *url.URL, resource string, source *tree.Node) (string, error) {
	if err := Validate(value); err != nil {
		return "", err
	}

	uri, _ := url.Parse(value) // validated above
	if base == nil || uri.IsAbs() {
		return value, nil
	}

	if resource != "" {
		var err error

		base, err = url.Parse(resource)
		if err != nil {
			return "", fmt.Errorf("%w: retrieval URI: %w", Err, err)
		}
	}

	var ancestors []*tree.Node
	for n := source; n != nil; n = n.Parent {
		ancestors = append(ancestors, n)
	}

	for _, n := range slices.Backward(ancestors) {
		for _, attr := range n.Attrs {
			if attr.Name != (document.Name{Space: document.XMLNamespace, Local: "base"}) {
				continue
			}

			if err := Validate(attr.Value); err != nil {
				return "", fmt.Errorf("%w: xml:base: %w", Err, err)
			}

			part, _ := url.Parse(attr.Value)
			base = base.ResolveReference(part)
		}
	}

	if !base.IsAbs() || base.Opaque != "" {
		return "", fmt.Errorf("%w: hierarchical resource base required", Err)
	}

	resolved := base.ResolveReference(uri).String()
	if strings.HasSuffix(value, "#") {
		resolved += "#" // net/url omits an explicitly empty fragment
	}

	return resolved, Validate(resolved)
}
