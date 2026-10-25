// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"

	xpathregex "github.com/skarm/xmlsec/transform/internal/xpath/regex"
)

// The XPath pattern translator lives in internal/xpathregex. These wrappers
// preserve XPath error code FORX0002; matching uses the shared Go pattern VM.

// Regex is a compiled XPath regular expression that can be used by external
// packages (e.g., xslt) for regex matching with XPath/XML Schema semantics.
type Regex struct {
	inner *compiledXPathRegex
}

// CompileRegex compiles an XPath regular expression with the given flags.
// Flags follow the XPath F&O specification: 'i' (case-insensitive),
// 'm' (multi-line), 's' (dot-all), 'x' (free-spacing), 'q' (literal).
func CompileRegex(pattern, flags string) (*Regex, error) {
	return CompileRegexContext(context.Background(), pattern, flags)
}

// CompileRegexContext applies the invocation's XML Schema edition and limits.
func CompileRegexContext(ctx context.Context, source, flags string) (*Regex, error) {
	re, err := compileXPathRegex(ctx, source, flags)
	if err != nil {
		return nil, err
	}

	return &Regex{inner: re}, nil
}

// MatchString reports whether the string s contains any match of the regex.
func (r *Regex) MatchString(ctx context.Context, s string) (bool, error) {
	return r.inner.MatchString(ctx, s)
}

// FindAllSubmatchIndex returns a slice of all successive matches of the
// regex in s, where each match is represented as a slice of index pairs
// (start, end) for the full match and each capture group.
// A return value of nil indicates no match.
// n limits the number of matches; -1 means no limit.
func (r *Regex) FindAllSubmatchIndex(ctx context.Context, s string, n int) ([][]int, error) {
	return r.inner.FindAllStringSubmatchIndex(ctx, s, n)
}

// EachSubmatchIndex streams the successive matches of the regex in s, calling
// fn once per match with the (start, end) byte-index pairs for the full match
// and each capture group (the same layout as a single FindAllSubmatchIndex
// entry; an unmatched group is reported as -1, -1). The slice handed to fn is
// only valid for the duration of the call — copy it to retain it. Iteration
// stops early, and EachSubmatchIndex returns nil, as soon as fn returns false.
//
// Matches are streamed with full input context, including multi-line anchors.
// limit caps the number of matches; a non-positive value selects no cap.
// Cancellation and work/storage limits are checked during enumeration.
func (r *Regex) EachSubmatchIndex(ctx context.Context, s string, limit int, fn func(m []int) bool) error {
	return r.inner.eachStringSubmatchIndex(ctx, s, limit, fn)
}

func xsdRegexError(err error) error {
	if err == nil {
		return nil
	}

	return &xdm.Error{Code: lexicon.ErrFORX0002, Message: err.Error(), Cause: err}
}

func translateXPathRegex(pattern string, dotAll, ignoreCase bool) (string, error) {
	out, err := xpathregex.Translate(pattern, dotAll, ignoreCase)
	if err != nil {
		return "", xsdRegexError(err)
	}

	return out, nil
}

func validateXPathRegex(pattern string, allowBackrefs bool) error {
	return xsdRegexError(xpathregex.Validate(pattern, allowBackrefs))
}

func rejectPerlSpecific(pattern string) error {
	return xsdRegexError(xpathregex.RejectPerlSpecific(pattern))
}

func hasXPathBackrefs(pattern string) bool { return xpathregex.HasBackrefs(pattern) }
