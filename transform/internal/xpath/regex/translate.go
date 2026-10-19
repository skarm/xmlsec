// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpathregex

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// errCodeFORX0002 mirrors the XPath FORX0002 ("invalid regular expression")
// error code. This package is layering-neutral (no xpath dependency); callers
// map regexError back to their own error type — xpath wraps it as XPathError.
const errCodeFORX0002 = "FORX0002"

// XML NameStartChar as a character class (for use outside [])
const (
	xmlNameStartCharClass    = `[a-zA-Z_:\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}]`
	xmlNameStartCharClassNeg = `[^a-zA-Z_:\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}]`
)

// XML NameStartChar range (for use inside [])
const xmlNameStartCharRange = `a-zA-Z_:\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}`

// Exact complement of xmlNameStartCharRange over U+0000–U+10FFFF.
const xmlNameStartCharRangeNeg = `\x{0}-\x{39}\x{3B}-\x{40}\x{5B}-\x{5E}\x{60}\x{7B}-\x{BF}\x{D7}\x{F7}\x{300}-\x{36F}\x{37E}\x{2000}-\x{200B}\x{200E}-\x{206F}\x{2190}-\x{2BFF}\x{2FF0}-\x{3000}\x{D800}-\x{F8FF}\x{FDD0}-\x{FDEF}\x{FFFE}-\x{FFFF}\x{F0000}-\x{10FFFF}`

// The XPath \c character class excludes U+0346. This applies only to pattern
// syntax; XML names use the shared internal/xmlchar predicates.
const (
	xpathRegexNameCharClass = `[a-zA-Z_:\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}\-.0-9\x{B7}\x{300}-\x{345}\x{347}-\x{36F}\x{203F}-\x{2040}]`
	xpathRegexNameCharRange = `a-zA-Z_:\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}\-.0-9\x{B7}\x{300}-\x{345}\x{347}-\x{36F}\x{203F}-\x{2040}`
)

const (
	xpathRegexNameCharClassNeg = `[^` + xpathRegexNameCharRange + `]`
	// The complement includes U+0346.
	xpathRegexNameCharRangeNeg = `\x{0}-\x{2C}\x{2F}\x{3B}-\x{40}\x{5B}-\x{5E}\x{60}\x{7B}-\x{B6}\x{B8}-\x{BF}\x{D7}\x{F7}\x{346}\x{37E}\x{2000}-\x{200B}\x{200E}-\x{203E}\x{2041}-\x{206F}\x{2190}-\x{2BFF}\x{2FF0}-\x{3000}\x{D800}-\x{F8FF}\x{FDD0}-\x{FDEF}\x{FFFE}-\x{FFFF}\x{F0000}-\x{10FFFF}`
)

// Translate converts an XPath/XQuery regex pattern (fn:matches/tokenize/replace)
// into the shared Go pattern grammar. In this flavor '^' and '$' are anchors and the pattern
// is not implicitly anchored.
func Translate(pattern string, dotAll, ignoreCase bool) (string, error) {
	return translateXPathRegex(pattern, dotAll, ignoreCase)
}

// translateXPathRegex translates an XPath/XML Schema regex pattern into a
// pattern with explicit XML Schema character semantics. Handles:
//   - \p{IsBlockName} / \P{IsBlockName} → (negated) Unicode block character range
//   - \p{Category} → Go-compatible \p{Category} (pass-through)
//   - \i / \I → XML NameStartChar / negated
//   - \c / \C → XML NameChar / negated
//   - \d \D \w \W \s \S → XSD-semantics equivalents
//   - '.' → [^\n\r] (or [\s\S] when dotAll)
//
// It does NOT expand character class subtraction ([a-z-[aeiou]]); that is passed
// through to the shared engine, which handles subtraction directly. It also does NOT reject
// Perl-specific constructs or validate back-references — call RejectPerlSpecific
// and Validate separately for those checks.
func translateXPathRegex(pattern string, dotAll, ignoreCase bool) (string, error) {
	var b strings.Builder

	runes := []rune(pattern)
	for i := 0; i < len(runes); {
		r := runes[i]
		if r == '\\' && i+1 < len(runes) {
			replacement, consumed, err := translateRegexEscape(runes, i, ignoreCase)
			if err != nil {
				return "", err
			}

			b.WriteString(replacement)

			i += consumed

			continue
		}

		if r == '[' {
			class, consumed, err := translateCharClass(runes, i)
			if err != nil {
				return "", err
			}

			b.WriteString(class)

			i += consumed

			continue
		}

		if r == '.' {
			// XPath's dot excludes both CR and LF unless dotAll is set.
			if dotAll {
				b.WriteString(`[\s\S]`)
			} else {
				b.WriteString(`[^\n\r]`)
			}
		} else {
			b.WriteRune(r)
		}

		i++
	}

	return b.String(), nil
}

func translateRegexEscape(runes []rune, start int, ignoreCase bool) (string, int, error) {
	next := runes[start+1]
	if (next == 'p' || next == 'P') && start+2 < len(runes) && runes[start+2] == '{' {
		end := findClosingBrace(runes, start+3)
		if end < 0 {
			return "", 0, fmt.Errorf("unterminated \\%c{ at position %d", next, start)
		}

		replacement, err := translateUnicodeProperty(string(runes[start+3:end]), next == 'P')
		if err != nil {
			return "", 0, err
		}

		if ignoreCase {
			replacement = "(?-i:" + replacement + ")"
		}

		return replacement, end - start + 1, nil
	}

	switch next {
	case 'i':
		return xmlNameStartCharClass, 2, nil
	case 'I':
		return xmlNameStartCharClassNeg, 2, nil
	case 'c':
		return xpathRegexNameCharClass, 2, nil
	case 'C':
		return xpathRegexNameCharClassNeg, 2, nil
	case 'd':
		return `\p{Nd}`, 2, nil
	case 'D':
		return `[^\p{Nd}]`, 2, nil
	case 'w':
		return `[^\p{P}\p{Z}\p{C}]`, 2, nil
	case 'W':
		return `[\p{P}\p{Z}\p{C}]`, 2, nil
	case 's':
		return `[\t\n\r ]`, 2, nil
	case 'S':
		return `[^\t\n\r ]`, 2, nil
	default:
		return string(runes[start : start+2]), 2, nil
	}
}

// translateCharClass translates a character class, handling subtraction.
// Returns the translated class and the number of runes consumed.
func translateCharClass(runes []rune, start int) (string, int, error) {
	// Find the matching close bracket, handling nesting
	depth := 0

	i := start
	for i < len(runes) {
		switch runes[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				// We have the full character class from start to i (inclusive)
				content := runes[start : i+1]

				result, err := processCharClass(content)
				if err != nil {
					return "", 0, err
				}

				return result, i + 1 - start, nil
			}
		case '\\':
			i++ // skip next character
		}

		i++
	}
	// No closing bracket found — pass through as-is
	return string(runes[start : start+1]), 1, nil
}

// processCharClass processes a character class, expanding subtraction and
// translating embedded \p{} and \i/\c escapes.
func processCharClass(runes []rune) (string, error) {
	s := string(runes)
	if err := validateXPathCharClassStructure(s); err != nil {
		return "", err
	}

	if err := validateXPathCharClassSubtraction(s); err != nil {
		return "", err
	}
	// Preserve character class subtraction for the shared engine.
	// Class structure is preserved through translation and parsed by the engine.
	result, err := translateClassContent(s)
	if err != nil {
		return "", err
	}

	return result, nil
}

func validateXPathCharClassStructure(class string) error {
	runes := []rune(class)
	if len(runes) < 2 || runes[0] != '[' || runes[len(runes)-1] != ']' {
		return nil
	}

	first := 1
	if first < len(runes)-1 && runes[first] == '^' {
		first++
	}

	if first >= len(runes)-1 {
		return &regexError{
			Code:    errCodeFORX0002,
			Message: fmt.Sprintf("invalid character class: %s", class),
		}
	}

	prevRaw := rune(0)

	for i := first; i < len(runes)-1; {
		if runes[i] == '\\' {
			if i+1 >= len(runes)-1 {
				return &regexError{
					Code:    errCodeFORX0002,
					Message: fmt.Sprintf("invalid character class: %s", class),
				}
			}

			i += 2

			continue
		}

		if i == first && (runes[i] == ']' || runes[i] == '[') {
			return &regexError{
				Code:    errCodeFORX0002,
				Message: fmt.Sprintf("invalid character class: %s", class),
			}
		}

		if runes[i] == '[' && prevRaw != '-' {
			return &regexError{
				Code:    errCodeFORX0002,
				Message: fmt.Sprintf("invalid character class: %s", class),
			}
		}
		// An interior raw '-' denotes a range operator whose endpoints must be
		// single characters, never another '-'. A '-' is literal (not a range
		// operator) at the start of the class (i == first) or immediately
		// before the closing ']' (runes[i+1] == ']'); a '-' immediately before
		// '[' is the operator of a '-[' character-class subtraction (validated
		// separately by validateXPathCharClassSubtraction), not a range. An
		// interior, non-subtraction '-' whose immediately-preceding or
		// immediately-following raw char is itself a literal '-' uses a '-' as
		// a range endpoint, which the XSD/XPath regex grammar forbids — except
		// when that adjacent '-' is itself the operator of a '-[' subtraction
		// (its own following char is '['), which is a literal dash abutting the
		// subtraction operator (e.g. the valid base group of '[a--[b]]'), not a
		// range endpoint.
		if runes[i] == '-' && i != first && runes[i+1] != ']' && runes[i+1] != '[' {
			precededByHyphen := prevRaw == '-'

			followedByHyphen := runes[i+1] == '-' && (i+2 >= len(runes) || runes[i+2] != '[')
			if precededByHyphen || followedByHyphen {
				return &regexError{
					Code:    errCodeFORX0002,
					Message: fmt.Sprintf("invalid character class: %s", class),
				}
			}
		}

		prevRaw = runes[i]
		i++
	}

	return nil
}

func validateXPathCharClassSubtraction(class string) error {
	if !strings.Contains(class, "-[") {
		return nil
	}

	runes := []rune(class)
	if len(runes) < 4 || runes[0] != '[' || runes[len(runes)-1] != ']' {
		return nil
	}

	for i := 1; i < len(runes)-2; i++ {
		if runes[i] == '\\' {
			i++
			continue
		}

		if runes[i] == '-' && runes[i+1] == '[' {
			if i == 1 || (i == 2 && runes[1] == '^') {
				return &regexError{
					Code:    errCodeFORX0002,
					Message: fmt.Sprintf("invalid character class subtraction: %s", class),
				}
			}
		}
	}

	return nil
}

// translateClassContent translates \p{}, \i, \c escapes inside a character class.
func translateClassContent(s string) (string, error) {
	var b strings.Builder

	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '\\' && i+1 < len(runes) {
			replacement, consumed, err := translateClassEscape(runes, i)
			if err != nil {
				return "", err
			}

			if consumed > 0 {
				b.WriteString(replacement)

				i += consumed - 1

				continue
			}
		}

		b.WriteRune(runes[i])
	}

	return b.String(), nil
}

func translateClassEscape(runes []rune, start int) (string, int, error) {
	next := runes[start+1]
	if (next == 'p' || next == 'P') && start+2 < len(runes) && runes[start+2] == '{' {
		if end := findClosingBrace(runes, start+3); end >= 0 {
			replacement, err := translateUnicodeProperty(string(runes[start+3:end]), next == 'P')
			return replacement, end - start + 1, err
		}
	}

	switch next {
	case 'i':
		return xmlNameStartCharRange, 2, nil
	case 'I':
		return xmlNameStartCharRangeNeg, 2, nil
	case 'c':
		return xpathRegexNameCharRange, 2, nil
	case 'C':
		return xpathRegexNameCharRangeNeg, 2, nil
	case 'd':
		return `\p{Nd}`, 2, nil
	case 'D':
		return `\P{Nd}`, 2, nil
	case 'w':
		return `\p{L}\p{M}\p{N}\p{S}`, 2, nil
	case 'W':
		return `\p{P}\p{Z}\p{C}`, 2, nil
	default:
		return "", 0, nil
	}
}

// Validate enforces the XPath/XSD pattern grammar before compilation.
func Validate(pattern string, allowBackrefs bool) error {
	return validateXPathRegex(pattern, allowBackrefs)
}

func validateXPathRegex(pattern string, allowBackrefs bool) error {
	state := regexValidation{runes: []rune(pattern), allowBackrefs: allowBackrefs}
	for i := 0; i < len(state.runes); i++ {
		r := state.runes[i]
		if r == '\\' && i+1 < len(state.runes) {
			end, err := state.validateEscape(i)
			if err != nil {
				return err
			}

			i = end

			continue
		}

		switch r {
		case '[':
			state.inCharClass++
			continue
		case ']':
			if state.inCharClass == 0 {
				return &regexError{
					Code:    errCodeFORX0002,
					Message: "unescaped ']' outside character class is not allowed in XPath regex",
				}
			}

			state.inCharClass--

			continue
		}

		if state.inCharClass == 0 {
			if err := state.validateOutsideClass(i); err != nil {
				return err
			}
		}
	}

	if state.inCharClass > 0 {
		return &regexError{Code: errCodeFORX0002, Message: "unterminated character class in XPath regex"}
	}

	return nil
}

// HasBackrefs reports whether the pattern contains a back-reference.
func HasBackrefs(pattern string) bool { return hasXPathBackrefs(pattern) }

func hasXPathBackrefs(pattern string) bool {
	runes := []rune(pattern)
	inCharClass := 0

	for i := 0; i < len(runes)-1; i++ {
		switch runes[i] {
		case '[':
			inCharClass++
		case ']':
			if inCharClass > 0 {
				inCharClass--
			}
		case '\\':
			if inCharClass == 0 && runes[i+1] >= '1' && runes[i+1] <= '9' {
				return true
			}

			i++
		}
	}

	return false
}

// RejectPerlSpecific rejects Perl-only constructs not allowed in XPath regex.
func RejectPerlSpecific(pattern string) error { return rejectPerlSpecific(pattern) }

func rejectPerlSpecific(pattern string) error {
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '\\' && i+1 < len(runes) {
			switch runes[i+1] {
			case 'b', 'B', 'A', 'Z', 'z', 'x', 'u', 'U':
				return &regexError{
					Code:    errCodeFORX0002,
					Message: fmt.Sprintf("Perl-specific escape \\%c is not allowed in XPath regex", runes[i+1]),
				}
			}

			i++ // skip escaped character

			continue
		}
		// Reject inline flags (?...) — XPath uses flags parameter instead
		if runes[i] == '(' && i+1 < len(runes) && runes[i+1] == '?' {
			// Allow (?:...) for non-capturing groups
			if i+2 < len(runes) && runes[i+2] == ':' {
				continue
			}

			return &regexError{
				Code:    errCodeFORX0002,
				Message: "inline flag groups (?...) are not allowed in XPath regex",
			}
		}
	}

	return nil
}

type classRange struct {
	low  int64
	high int64
}

// ResolveProperty preserves Unicode block escapes as predicates, so the i flag
// cannot accidentally case-fold them after expansion into character ranges.
func ResolveProperty(name string) *unicode.RangeTable {
	if !strings.HasPrefix(name, "Is") {
		return nil
	}

	spec, ok := lookupUnicodeBlockRange(name[2:])
	if !ok {
		return nil
	}

	ranges, err := parseClassRanges(spec)
	if err != nil {
		return nil
	}

	table := &unicode.RangeTable{}

	for _, r := range ranges {
		if r.low <= 0xFFFF {
			table.R16 = append(table.R16, unicode.Range16{Lo: uint16(r.low), Hi: uint16(min(r.high, 0xFFFF)), Stride: 1})
		}

		if r.high > 0xFFFF {
			table.R32 = append(table.R32, unicode.Range32{Lo: uint32(max(r.low, 0x10000)), Hi: uint32(r.high), Stride: 1})
		}
	}

	return table
}

func parseClassRanges(spec string) ([]classRange, error) {
	runes := []rune(spec)

	var ranges []classRange

	for i := 0; i < len(runes); {
		low, next, err := parseClassRune(runes, i)
		if err != nil {
			return nil, err
		}

		i = next

		high := low
		if i < len(runes)-1 && runes[i] == '-' {
			high, i, err = parseClassRune(runes, i+1)
			if err != nil {
				return nil, err
			}
		}

		ranges = append(ranges, classRange{low: low, high: high})
	}

	return ranges, nil
}

func parseClassRune(runes []rune, start int) (int64, int, error) {
	if start >= len(runes) {
		return 0, start, fmt.Errorf("unexpected end of character class range")
	}

	if runes[start] != '\\' {
		return int64(runes[start]), start + 1, nil
	}

	if start+1 >= len(runes) {
		return 0, start, fmt.Errorf("dangling escape in character class range")
	}

	if runes[start+1] != 'x' {
		return int64(runes[start+1]), start + 2, nil
	}

	if start+2 >= len(runes) || runes[start+2] != '{' {
		return 0, start, fmt.Errorf("invalid hex escape in character class range")
	}

	end := -1

	for i := start + 3; i < len(runes); i++ {
		if runes[i] == '}' {
			end = i
			break
		}
	}

	if end < 0 {
		return 0, start, fmt.Errorf("unterminated hex escape in character class range")
	}

	value, err := strconv.ParseInt(string(runes[start+3:end]), 16, 64)
	if err != nil {
		return 0, start, err
	}

	return value, end + 1, nil
}

type regexError struct {
	Code    string
	Message string
	Cause   error
}

func (e *regexError) Error() string { return e.Message }

func (e *regexError) Unwrap() error { return e.Cause }

func findClosingBrace(runes []rune, start int) int {
	for i := start; i < len(runes); i++ {
		if runes[i] == '}' {
			return i
		}
	}

	return -1
}

func translateUnicodeProperty(name string, neg bool) (string, error) {
	prefix := `\p`
	if neg {
		prefix = `\P`
	}

	if strings.HasPrefix(name, "Is") {
		blockName := name[2:]
		if _, ok := lookupUnicodeBlockRange(blockName); ok {
			return prefix + "{" + name + "}", nil
		}

		return "", &regexError{Code: errCodeFORX0002, Message: fmt.Sprintf("unknown Unicode block: Is%s", blockName)}
	}

	if isGoSupportedProperty(name) {
		return prefix + "{" + name + "}", nil
	}

	return "", &regexError{Code: errCodeFORX0002, Message: fmt.Sprintf("unknown Unicode property: %s", name)}
}

func lookupUnicodeBlockRange(blockName string) (string, bool) {
	// Block names are ASCII. These are the two non-ASCII members of ASCII
	// Unicode simple-fold classes: long s folds to s, Kelvin sign to k.
	name := strings.ToLower(strings.ReplaceAll(blockName, "ſ", "s"))
	if name == "" {
		return "", false
	}

	return lookupUnicodeBlock(name)
}

// goSupportedScripts lists script names supported by Go's Unicode tables.
func goSupportedScripts(key string) bool {
	switch key {
	case "Arabic", "Armenian", "Bengali", "Bopomofo", "Braille", "Buhid", "Canadian_Aboriginal", "Cherokee", "Common", "Cyrillic", "Devanagari", "Ethiopic", "Georgian", "Greek", "Gujarati", "Gurmukhi", "Han", "Hangul", "Hanunoo", "Hebrew", "Hiragana", "Inherited", "Kannada", "Katakana", "Khmer", "Lao", "Latin", "Limbu", "Malayalam", "Mongolian", "Myanmar", "Ogham", "Oriya", "Runic", "Sinhala", "Syriac", "Tagalog", "Tagbanwa", "Tamil", "Telugu", "Thaana", "Thai", "Tibetan", "Yi":
		return true
	}

	return false
}

func isGoSupportedProperty(name string) bool {
	// Single-letter categories
	if len(name) == 1 || len(name) == 2 {
		return true // L, Lu, Ll, M, Mn, N, Nd, P, S, Z, C, etc.
	}

	ok := goSupportedScripts(name)

	return ok
}

// lookupUnicodeBlock preserves the Unicode 6.0 blocks used by XML Schema
// regexes. Name groups make the immutable lookup table easy to inspect.
func lookupUnicodeBlock(name string) (string, bool) {
	switch name[0] {
	case 'a':
		return lookupUnicodeBlockA(name)
	case 'b':
		return lookupUnicodeBlockB(name)
	case 'c':
		return lookupUnicodeBlockC(name)
	case 'd':
		return lookupUnicodeBlockD(name)
	case 'e':
		return lookupUnicodeBlockE(name)
	case 'g':
		return lookupUnicodeBlockG(name)
	case 'h':
		return lookupUnicodeBlockH(name)
	case 'i':
		return lookupUnicodeBlockI(name)
	case 'k':
		return lookupUnicodeBlockK(name)
	case 'l':
		return lookupUnicodeBlockL(name)
	case 'm':
		return lookupUnicodeBlockM(name)
	case 'n':
		return lookupUnicodeBlockN(name)
	case 'o':
		return lookupUnicodeBlockO(name)
	case 'p':
		return lookupUnicodeBlockP(name)
	case 'r':
		return lookupUnicodeBlockR(name)
	case 's':
		return lookupUnicodeBlockS(name)
	case 't':
		return lookupUnicodeBlockT(name)
	case 'u':
		return lookupUnicodeBlockU(name)
	case 'v':
		return lookupUnicodeBlockV(name)
	case 'y':
		return lookupUnicodeBlockY(name)
	default:
		return "", false
	}
}

func lookupUnicodeBlockA(name string) (string, bool) {
	switch name {
	case "armenian":
		return `\x{0530}-\x{058F}`, true
	case "arabic":
		return `\x{0600}-\x{06FF}`, true
	case "arabicsupplement":
		return `\x{0750}-\x{077F}`, true
	case "arrows":
		return `\x{2190}-\x{21FF}`, true
	case "alphabeticpresentationforms":
		return `\x{FB00}-\x{FB4F}`, true
	case "arabicpresentationforms-a":
		return `\x{FB50}-\x{FDFF}`, true
	case "arabicpresentationforms-b":
		return `\x{FE70}-\x{FEFF}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockB(name string) (string, bool) {
	switch name {
	case "basiclatin":
		return `\x{0000}-\x{007F}`, true
	case "bengali":
		return `\x{0980}-\x{09FF}`, true
	case "buhid":
		return `\x{1740}-\x{175F}`, true
	case "buginese":
		return `\x{1A00}-\x{1A1F}`, true
	case "boxdrawing":
		return `\x{2500}-\x{257F}`, true
	case "blockelements":
		return `\x{2580}-\x{259F}`, true
	case "braillepatterns":
		return `\x{2800}-\x{28FF}`, true
	case "bopomofo":
		return `\x{3100}-\x{312F}`, true
	case "bopomofoextended":
		return `\x{31A0}-\x{31BF}`, true
	case "byzantinemusicalsymbols":
		return `\x{1D000}-\x{1D0FF}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockC(name string) (string, bool) {
	switch name {
	case "combiningdiacriticalmarks":
		return `\x{0300}-\x{036F}`, true
	case "cyrillic":
		return `\x{0400}-\x{04FF}`, true
	case "cyrillicsupplement":
		return `\x{0500}-\x{052F}`, true
	case "cherokee":
		return `\x{13A0}-\x{13FF}`, true
	case "combiningdiacriticalmarkssupplement":
		return `\x{1DC0}-\x{1DFF}`, true
	case "currencysymbols":
		return `\x{20A0}-\x{20CF}`, true
	case "combiningdiacriticalmarksforsymbols":
		return `\x{20D0}-\x{20FF}`, true
	case "combiningmarksforsymbols":
		return `\x{20D0}-\x{20FF}`, true
	case "controlpictures":
		return `\x{2400}-\x{243F}`, true
	case "cjkradicalssupplement":
		return `\x{2E80}-\x{2EFF}`, true
	case "cjksymbolsandpunctuation":
		return `\x{3000}-\x{303F}`, true
	case "cjkcompatibility":
		return `\x{3300}-\x{33FF}`, true
	case "cjkunifiedideographsextensiona":
		return `\x{3400}-\x{4DBF}`, true
	case "cjkunifiedideographs":
		return `\x{4E00}-\x{9FFF}`, true
	case "cjkcompatibilityideographs":
		return `\x{F900}-\x{FAFF}`, true
	case "combininghalfmarks":
		return `\x{FE20}-\x{FE2F}`, true
	case "cjkcompatibilityforms":
		return `\x{FE30}-\x{FE4F}`, true
	case "cjkunifiedideographsextensionb":
		return `\x{20000}-\x{2A6DF}`, true
	case "cjkcompatibilityideographssupplement":
		return `\x{2F800}-\x{2FA1F}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockD(name string) (string, bool) {
	switch name {
	case "devanagari":
		return `\x{0900}-\x{097F}`, true
	case "dingbats":
		return `\x{2700}-\x{27BF}`, true
	case "deseret":
		return `\x{10400}-\x{1044F}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockE(name string) (string, bool) {
	switch name {
	case "ethiopic":
		return `\x{1200}-\x{137F}`, true
	case "ethiopicsupplement":
		return `\x{1380}-\x{139F}`, true
	case "enclosedalphanumerics":
		return `\x{2460}-\x{24FF}`, true
	case "enclosedcjklettersandmonths":
		return `\x{3200}-\x{32FF}`, true
	case "emoticons":
		return `\x{1F600}-\x{1F64F}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockG(name string) (string, bool) {
	switch name {
	case "greek":
		return `\x{0370}-\x{03FF}`, true
	case "greekandcoptic":
		return `\x{0370}-\x{03FF}`, true
	case "gurmukhi":
		return `\x{0A00}-\x{0A7F}`, true
	case "gujarati":
		return `\x{0A80}-\x{0AFF}`, true
	case "georgian":
		return `\x{10A0}-\x{10FF}`, true
	case "greekextended":
		return `\x{1F00}-\x{1FFF}`, true
	case "generalpunctuation":
		return `\x{2000}-\x{206F}`, true
	case "geometricshapes":
		return `\x{25A0}-\x{25FF}`, true
	case "gothic":
		return `\x{10330}-\x{1034F}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockH(name string) (string, bool) {
	switch name {
	case "hebrew":
		return `\x{0590}-\x{05FF}`, true
	case "hanguljamo":
		return `\x{1100}-\x{11FF}`, true
	case "hanunoo":
		return `\x{1720}-\x{173F}`, true
	case "hiragana":
		return `\x{3040}-\x{309F}`, true
	case "hangulcompatibilityjamo":
		return `\x{3130}-\x{318F}`, true
	case "hangulsyllables":
		return `\x{AC00}-\x{D7AF}`, true
	case "highsurrogates":
		return `\x{D800}-\x{DB7F}`, true
	case "highprivateusesurrogates":
		return `\x{DB80}-\x{DBFF}`, true
	case "halfwidthandfullwidthforms":
		return `\x{FF00}-\x{FFEF}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockI(name string) (string, bool) {
	switch name {
	case "ipaextensions":
		return `\x{0250}-\x{02AF}`, true
	case "ideographicdescriptioncharacters":
		return `\x{2FF0}-\x{2FFF}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockK(name string) (string, bool) {
	switch name {
	case "kannada":
		return `\x{0C80}-\x{0CFF}`, true
	case "khmer":
		return `\x{1780}-\x{17FF}`, true
	case "khmersymbols":
		return `\x{19E0}-\x{19FF}`, true
	case "kangxiradicals":
		return `\x{2F00}-\x{2FDF}`, true
	case "katakana":
		return `\x{30A0}-\x{30FF}`, true
	case "kanbun":
		return `\x{3190}-\x{319F}`, true
	case "katakanaphoneticextensions":
		return `\x{31F0}-\x{31FF}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockL(name string) (string, bool) {
	switch name {
	case "latin-1supplement":
		return `\x{0080}-\x{00FF}`, true
	case "latinextended-a":
		return `\x{0100}-\x{017F}`, true
	case "latinextended-b":
		return `\x{0180}-\x{024F}`, true
	case "lao":
		return `\x{0E80}-\x{0EFF}`, true
	case "limbu":
		return `\x{1900}-\x{194F}`, true
	case "latinextendedadditional":
		return `\x{1E00}-\x{1EFF}`, true
	case "letterlikesymbols":
		return `\x{2100}-\x{214F}`, true
	case "lowsurrogates":
		return `\x{DC00}-\x{DFFF}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockM(name string) (string, bool) {
	switch name {
	case "malayalam":
		return `\x{0D00}-\x{0D7F}`, true
	case "myanmar":
		return `\x{1000}-\x{109F}`, true
	case "mongolian":
		return `\x{1800}-\x{18AF}`, true
	case "mathematicaloperators":
		return `\x{2200}-\x{22FF}`, true
	case "miscellaneoustechnical":
		return `\x{2300}-\x{23FF}`, true
	case "miscellaneoussymbols":
		return `\x{2600}-\x{26FF}`, true
	case "miscellaneousmathematicalsymbols-a":
		return `\x{27C0}-\x{27EF}`, true
	case "miscellaneousmathematicalsymbols-b":
		return `\x{2980}-\x{29FF}`, true
	case "miscellaneoussymbolsandarrows":
		return `\x{2B00}-\x{2BFF}`, true
	case "musicalsymbols":
		return `\x{1D100}-\x{1D1FF}`, true
	case "mathematicalalphanumericsymbols":
		return `\x{1D400}-\x{1D7FF}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockN(name string) (string, bool) {
	switch name {
	case "nko":
		return `\x{07C0}-\x{07FF}`, true
	case "newtailue":
		return `\x{1980}-\x{19DF}`, true
	case "numberforms":
		return `\x{2150}-\x{218F}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockO(name string) (string, bool) {
	switch name {
	case "oriya":
		return `\x{0B00}-\x{0B7F}`, true
	case "ogham":
		return `\x{1680}-\x{169F}`, true
	case "opticalcharacterrecognition":
		return `\x{2440}-\x{245F}`, true
	case "olditalic":
		return `\x{10300}-\x{1032F}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockP(name string) (string, bool) {
	switch name {
	case "phoneticextensions":
		return `\x{1D00}-\x{1D7F}`, true
	case "phoneticextensionssupplement":
		return `\x{1D80}-\x{1DBF}`, true
	case "privateusearea":
		return `\x{E000}-\x{F8FF}`, true
	case "privateuse":
		return `\x{E000}-\x{F8FF}\x{F0000}-\x{FFFFD}\x{100000}-\x{10FFFD}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockR(name string) (string, bool) {
	switch name {
	case "runic":
		return `\x{16A0}-\x{16FF}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockS(name string) (string, bool) {
	switch name {
	case "spacingmodifierletters":
		return `\x{02B0}-\x{02FF}`, true
	case "syriac":
		return `\x{0700}-\x{074F}`, true
	case "sinhala":
		return `\x{0D80}-\x{0DFF}`, true
	case "superscriptsandsubscripts":
		return `\x{2070}-\x{209F}`, true
	case "supplementalarrows-a":
		return `\x{27F0}-\x{27FF}`, true
	case "supplementalarrows-b":
		return `\x{2900}-\x{297F}`, true
	case "supplementalmathematicaloperators":
		return `\x{2A00}-\x{2AFF}`, true
	case "smallformvariants":
		return `\x{FE50}-\x{FE6F}`, true
	case "specials":
		return `\x{FFF0}-\x{FFFF}`, true
	case "supplementaryprivateusearea-a":
		return `\x{F0000}-\x{FFFFD}`, true
	case "supplementaryprivateusearea-b":
		return `\x{100000}-\x{10FFFD}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockT(name string) (string, bool) {
	switch name {
	case "thaana":
		return `\x{0780}-\x{07BF}`, true
	case "tamil":
		return `\x{0B80}-\x{0BFF}`, true
	case "telugu":
		return `\x{0C00}-\x{0C7F}`, true
	case "thai":
		return `\x{0E00}-\x{0E7F}`, true
	case "tibetan":
		return `\x{0F00}-\x{0FFF}`, true
	case "tagalog":
		return `\x{1700}-\x{171F}`, true
	case "tagbanwa":
		return `\x{1760}-\x{177F}`, true
	case "taile":
		return `\x{1950}-\x{197F}`, true
	case "tags":
		return `\x{E0000}-\x{E007F}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockU(name string) (string, bool) {
	switch name {
	case "unifiedcanadianaboriginalsyllabics":
		return `\x{1400}-\x{167F}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockV(name string) (string, bool) {
	switch name {
	case "variationselectors":
		return `\x{FE00}-\x{FE0F}`, true
	default:
		return "", false
	}
}

func lookupUnicodeBlockY(name string) (string, bool) {
	switch name {
	case "yijinghexagramsymbols":
		return `\x{4DC0}-\x{4DFF}`, true
	case "yisyllables":
		return `\x{A000}-\x{A48F}`, true
	case "yiradicals":
		return `\x{A490}-\x{A4CF}`, true
	default:
		return "", false
	}
}

// validateXPathRegex checks for patterns that Go's regexp accepts but
// the XPath/XML Schema regex spec forbids. This must be called before
// compilation to reject invalid patterns with FORX0002.
type regexValidation struct {
	runes         []rune
	groupStack    []int
	inCharClass   int
	captureCount  int
	inQuantifier  bool
	allowBackrefs bool
}

// validateEscape returns the final consumed rune's index.
func (v *regexValidation) validateEscape(start int) (int, error) {
	next := v.runes[start+1]
	if next == '0' {
		return 0, &regexError{Code: errCodeFORX0002, Message: "back-reference \\0 is not allowed in XPath regex"}
	}

	if v.inCharClass == 0 && next >= '1' && next <= '9' {
		return v.validateBackreference(start)
	}

	if (next == 'p' || next == 'P') && start+2 < len(v.runes) && v.runes[start+2] == '{' {
		end := findClosingBrace(v.runes, start+3)
		if end < 0 {
			return 0, &regexError{
				Code:    errCodeFORX0002,
				Message: fmt.Sprintf("unterminated \\%c{ in regex", next),
			}
		}

		_, err := translateUnicodeProperty(string(v.runes[start+3:end]), next == 'P')

		return end, err
	}

	return start + 1, nil
}

func (v *regexValidation) validateBackreference(start int) (int, error) {
	ref, validEnd, end, invalid := resolveXPathBackref(v.runes, start+1, v.captureCount, v.groupStack)
	if !v.allowBackrefs {
		return 0, &regexError{
			Code:    errCodeFORX0002,
			Message: fmt.Sprintf("back-reference \\%d is not allowed in XPath regex", ref),
		}
	}

	if invalid || validEnd < 0 {
		return 0, &regexError{
			Code:    errCodeFORX0002,
			Message: fmt.Sprintf("invalid back-reference \\%s in XPath regex", string(v.runes[start+1:end])),
		}
	}

	return end - 1, nil
}

func isOpenCaptureGroup(groupStack []int, ref int) bool {
	return slices.Contains(groupStack, ref)
}

func resolveXPathBackref(runes []rune, start, captureCount int, groupStack []int) (int, int, int, bool) {
	ref := 0
	validEnd := -1
	end := start

	value := 0
	for end < len(runes) && runes[end] >= '0' && runes[end] <= '9' {
		// Stop accumulating once value exceeds captureCount: more digits only
		// grow it, and a long digit run would wrap int (past 2^31-1 where int
		// is 32 bits) back into the capture range.
		if value <= captureCount {
			value = value*10 + int(runes[end]-'0')
		}

		end++
	}

	if value > 0 && value <= captureCount {
		if isOpenCaptureGroup(groupStack, value) {
			return 0, -1, end, true
		}

		return value, end, end, false
	}

	value = 0
	for i := start; i < end; i++ {
		if value > captureCount {
			break
		}

		value = value*10 + int(runes[i]-'0')
		if value > 0 && value <= captureCount && !isOpenCaptureGroup(groupStack, value) {
			ref = value
			validEnd = i + 1
		}
	}

	return ref, validEnd, end, false
}

func (v *regexValidation) validateOutsideClass(index int) error {
	switch v.runes[index] {
	case '(':
		if index+2 < len(v.runes) && v.runes[index+1] == '?' && v.runes[index+2] == ':' {
			v.groupStack = append(v.groupStack, 0)
			return nil
		}

		v.captureCount++
		v.groupStack = append(v.groupStack, v.captureCount)
	case ')':
		if len(v.groupStack) > 0 {
			v.groupStack = v.groupStack[:len(v.groupStack)-1]
		}
	case '{':
		if !isValidQuantifierBrace(v.runes, index) {
			return &regexError{
				Code:    errCodeFORX0002,
				Message: "unescaped '{' outside quantifier is not allowed in XPath regex",
			}
		}

		v.inQuantifier = true
	case '}':
		if !v.inQuantifier {
			return &regexError{
				Code:    errCodeFORX0002,
				Message: "unescaped '}' outside quantifier is not allowed in XPath regex",
			}
		}

		v.inQuantifier = false
	}

	return nil
}

// validQuantifierContent recognizes digits [ "," [ digits ] ].
func validQuantifierContent(s string) bool {
	left, right, comma := strings.Cut(s, ",")
	if left == "" {
		return false
	}

	for i := range len(left) {
		if left[i] < '0' || left[i] > '9' {
			return false
		}
	}

	if comma {
		for i := range len(right) {
			if right[i] < '0' || right[i] > '9' {
				return false
			}
		}
	}

	return true
}

// isValidQuantifierBrace checks whether '{' at position i is part of a
// valid quantifier {n}, {n,}, or {n,m}. The '{' must be preceded by a
// quantifiable atom (not at the start) and its content must match the
// quantifier pattern.
func isValidQuantifierBrace(runes []rune, i int) bool {
	// Must have a preceding quantifiable atom
	if i == 0 {
		return false
	}

	prev := runes[i-1]
	// Valid preceding chars for a quantifier: ), ], or any non-meta char,
	// or an escape sequence. We check broadly.
	if prev == '|' || prev == '(' || prev == '{' {
		return false
	}

	end := -1

	for j := i + 1; j < len(runes); j++ {
		if runes[j] == '}' {
			end = j
			break
		}
	}

	if end < 0 {
		return false
	}

	content := string(runes[i+1 : end])

	return validQuantifierContent(content)
}
