// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/xmlsec/transform/internal/xdm"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"

	"github.com/skarm/xmlsec/internal/lexicon"
)

const (
	collationOptionNumeric    = "numeric"
	collationAlternateShifted = "shifted"
	maxIdleCollators          = 2
	maxPooledCollationInput   = 4096
)

// caseblindCollationURI is the QT3 test suite's case-blind collation URI.
const caseblindCollationURI = "http://www.w3.org/2010/09/qt-fots-catalog/collation/caseblind"

// IsCollationSupported reports whether the given collation URI is recognized
// by the evaluator.  This is useful for XSLT default-collation resolution
// where the first supported URI from a list should be selected.
func IsCollationSupported(uri string) bool {
	_, err := resolveCollation(uri, "")
	return err == nil
}

// ResolveCollationKeyFunc resolves a collation URI and returns a function that
// maps strings to their collation sort keys (as strings). Two strings that are
// equal under the collation will produce identical keys.
// This is intended for use by xslt for-each-group collation-based grouping.
func ResolveCollationKeyFunc(uri string) (func(string) string, error) {
	coll, err := resolveCollation(uri, "")
	if err != nil {
		return nil, err
	}

	return func(s string) string {
		return string(coll.key(s))
	}, nil
}

// ResolveCollationCompareFunc returns a comparison function for the given
// collation URI. Returns an error for unrecognized collation URIs.
func ResolveCollationCompareFunc(uri string) (func(a, b string) int, error) {
	coll, err := resolveCollation(uri, "")
	if err != nil {
		return nil, err
	}

	return coll.compare, nil
}

// CollationHasUnsupportedOptions returns true if the UCA collation URI
// contains options that are not fully supported (e.g., alternate=shifted).
// Returns false for non-UCA collation URIs.
func CollationHasUnsupportedOptions(uri string) bool {
	if !strings.HasPrefix(uri, lexicon.CollationUCA) {
		return false
	}

	_, query, found := strings.Cut(uri, "?")
	if !found {
		return false
	}

	params, err := parseUCAParams(query)
	if err != nil {
		return true // parse error = unsupported
	}

	return params.alternate == collationAlternateShifted || params.alternate == nameBlanked ||
		params.caseLevel || params.backwards
}

// collatorPool bounds idle objects independently of GC and concurrency. Large
// comparisons can grow unexported collate buffers, so those objects are dropped.
type collatorPool struct {
	idle [maxIdleCollators]atomic.Pointer[collate.Collator]
	new  func() *collate.Collator
}

func newCollatorPool(tag language.Tag, options []collate.Option) *collatorPool {
	return &collatorPool{
		new: func() *collate.Collator { return collate.New(tag, options...) },
	}
}

func (p *collatorPool) get() *collate.Collator {
	for i := range p.idle {
		if p.idle[i].Load() != nil {
			if c := p.idle[i].Swap(nil); c != nil {
				return c
			}
		}
	}

	return p.new()
}

func (p *collatorPool) put(c *collate.Collator, inputBytes int) {
	if inputBytes > maxPooledCollationInput {
		return
	}
	// CompareString resets both iterators, releasing even short substrings
	// backed by large caller buffers. It does not shrink grown element arrays.
	c.CompareString("", "")

	for i := range p.idle {
		if p.idle[i].CompareAndSwap(nil, c) {
			return
		}
	}
}

type collationImpl struct {
	codepoint bool
	compare   func(a, b string) int
	indexOf   func(s, substr string) (pos, matchLen int)
	hasPrefix func(s, prefix string) (bool, int)
	hasSuffix func(s, suffix string) (bool, int)
	key       func(s string) []byte
}

// newCodepointCollation constructs the default XPath byte-level collation.
func newCodepointCollation() *collationImpl {
	return &collationImpl{
		codepoint: true,
		compare:   strings.Compare,
		indexOf: func(s, substr string) (int, int) {
			idx := strings.Index(s, substr)
			if idx < 0 {
				return -1, 0
			}

			return idx, len(substr)
		},
		hasPrefix: func(s, prefix string) (bool, int) {
			if strings.HasPrefix(s, prefix) {
				return true, len(prefix)
			}

			return false, 0
		},
		hasSuffix: func(s, suffix string) (bool, int) {
			if strings.HasSuffix(s, suffix) {
				return true, len(suffix)
			}

			return false, 0
		},
		key: func(s string) []byte {
			return []byte(s)
		},
	}
}

// newHTMLASCIICaseInsensitiveCollation compares ASCII letters case-insensitively,
// all other characters by codepoint.
func newHTMLASCIICaseInsensitiveCollation() *collationImpl {
	return &collationImpl{
		compare: func(a, b string) int {
			return strings.Compare(foldASCIIString(a), foldASCIIString(b))
		},
		indexOf: func(s, substr string) (int, int) {
			ls := foldASCIIString(s)
			lsub := foldASCIIString(substr)

			idx := strings.Index(ls, lsub)
			if idx < 0 {
				return -1, 0
			}

			return idx, len(substr)
		},
		hasPrefix: func(s, prefix string) (bool, int) {
			if len(s) < len(prefix) {
				return false, 0
			}

			if foldASCIIString(s[:len(prefix)]) == foldASCIIString(prefix) {
				return true, len(prefix)
			}

			return false, 0
		},
		hasSuffix: func(s, suffix string) (bool, int) {
			if len(s) < len(suffix) {
				return false, 0
			}

			if foldASCIIString(s[len(s)-len(suffix):]) == foldASCIIString(suffix) {
				return true, len(suffix)
			}

			return false, 0
		},
		key: func(s string) []byte {
			return []byte(foldASCIIString(s))
		},
	}
}

func (c *collationImpl) isCodepoint() bool { return c != nil && c.codepoint }

func foldASCIIString(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}

		b.WriteByte(c)
	}

	return b.String()
}

// makeUCACollation creates a collation based on the Unicode Collation Algorithm
// with optional parameters parsed from the URI query string.
// Its collator pools support concurrent use by the owning evaluation runtime.
func makeUCACollation(params string) (*collationImpl, error) {
	opts, err := parseUCAParams(params)
	if err != nil {
		return nil, err
	}

	if opts.caseLevel || opts.backwards {
		tagParts := []string{"und-u"}
		if opts.backwards {
			tagParts = append(tagParts, "kb-true")
		}

		if opts.caseLevel {
			tagParts = append(tagParts, "kc-true")
		}

		if extraTag, err := language.Parse(strings.Join(tagParts, "-")); err == nil {
			opts.collateOpts = append(opts.collateOpts, collate.OptionsFromTag(extraTag))
		}
	}

	mainPool := newCollatorPool(opts.tag, opts.collateOpts)

	numeric := opts.numeric
	ignoreVariables := opts.ignoreVariableRunes()
	normalize := func(s string) string {
		if !ignoreVariables {
			return s
		}

		return projectVariableRunes(s).value
	}
	cmp := func(a, b string) int {
		cl := mainPool.get()
		r := cl.CompareString(normalize(a), normalize(b))
		mainPool.put(cl, max(len(a), len(b)))

		return r
	}
	key := func(s string) []byte {
		cl := mainPool.get()
		buf := &collate.Buffer{}
		k := append([]byte(nil), cl.KeyFromString(buf, normalize(s))...)
		mainPool.put(cl, len(s))

		return k
	}

	if opts.caseFirst != "" && (!opts.ignoreCase || opts.caseLevel) {
		caseBlindOpts := append([]collate.Option(nil), opts.collateOpts...)
		caseBlindOpts = append(caseBlindOpts, collate.IgnoreCase)
		caseBlindPool := newCollatorPool(opts.tag, caseBlindOpts)
		caseFirst := opts.caseFirst
		key = func(s string) []byte {
			s = normalize(s)
			cl := caseBlindPool.get()
			buf := &collate.Buffer{}
			base := append([]byte(nil), cl.KeyFromString(buf, s)...)
			caseBlindPool.put(cl, len(s))

			caseKey := buildCaseFirstKey(s, caseFirst)
			if len(caseKey) == 0 {
				return base
			}

			base = append(base, 0)

			return append(base, caseKey...)
		}
		cmp = func(a, b string) int {
			return bytes.Compare(key(a), key(b))
		}
	}

	return &collationImpl{
		compare: cmp,
		indexOf: func(s, substr string) (int, int) {
			if ignoreVariables {
				return ucaVariableIndexOf(cmp, s, substr, numeric)
			}

			return ucaIndexOf(cmp, s, substr, numeric)
		},
		hasPrefix: func(s, prefix string) (bool, int) {
			if ignoreVariables {
				return ucaVariableHasPrefix(cmp, s, prefix, numeric)
			}

			return ucaHasPrefix(cmp, s, prefix, numeric)
		},
		hasSuffix: func(s, suffix string) (bool, int) {
			if ignoreVariables {
				return ucaVariableHasSuffix(cmp, s, suffix, numeric)
			}

			return ucaHasSuffix(cmp, s, suffix, numeric)
		},
		key: key,
	}, nil
}

type ucaParams struct {
	tag         language.Tag
	collateOpts []collate.Option
	numeric     bool
	ignoreCase  bool
	caseFirst   string
	strength    string
	alternate   string
	caseLevel   bool
	backwards   bool
	fallbackNo  bool
}

func (p ucaParams) ignoreVariableRunes() bool {
	switch p.alternate {
	case nameBlanked:
		return p.strength != "identical"
	case collationAlternateShifted:
		switch p.strength {
		case "primary", "secondary", nameTertiary:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func parseUCAParams(query string) (ucaParams, error) {
	parser := ucaParamParser{params: ucaParams{tag: language.Und, strength: nameTertiary}}
	if query == "" {
		return parser.params, nil
	}

	for parameter := range strings.SplitSeq(query, ";") {
		if parameter == "" {
			continue
		}

		key, value, ok := strings.Cut(parameter, "=")
		if !ok {
			parser.invalid = true

			continue
		}

		parser.apply(key, value)
	}

	if parser.params.fallbackNo && (parser.invalid || parser.unsupported || parser.hasRegionalLang) {
		return ucaParams{}, &xdm.Error{Code: errCodeFOCH0002, Message: "unsupported collation"}
	}

	return parser.params, nil
}

type ucaParamParser struct {
	params          ucaParams
	unsupported     bool
	invalid         bool
	hasRegionalLang bool
}

func (p *ucaParamParser) apply(key, value string) {
	switch key {
	case nameFallback:
		p.applyFallback(value)
	case lexicon.AttrLang:
		p.applyLanguage(value)
	case "strength":
		p.applyStrength(value)
	case "alternate":
		p.applyAlternate(value)
	case "caseFirst":
		if value == nameUpper2 || value == nameLower {
			p.params.caseFirst = value
		} else {
			p.invalid = true
		}
	case "caseLevel", "backwards", collationOptionNumeric, "normalization":
		p.applyBoolean(key, value)
	case "reorder", "maxVariable", "version", "keyword", "hiraganaQuaternary":
		p.unsupported = true
	default:
		p.invalid = true
	}
}

func (p *ucaParamParser) applyFallback(value string) {
	switch value {
	case lexicon.ValueNo:
		p.params.fallbackNo = true
	case lexicon.ValueYes, "unknown":
		// Unknown values are implementation-defined unless fallback=no
		// explicitly requests strict rejection.
	default:
		p.invalid = true
	}
}

func (p *ucaParamParser) applyLanguage(value string) {
	tag, err := language.Parse(value)
	if err != nil {
		p.invalid = true

		return
	}

	p.params.tag = tag
	if _, confidence := tag.Region(); confidence != language.No {
		p.hasRegionalLang = true
	}
}

func (p *ucaParamParser) applyStrength(value string) {
	p.params.strength = value

	switch value {
	case "primary":
		p.params.collateOpts = append(p.params.collateOpts, collate.IgnoreCase, collate.IgnoreDiacritics)
		p.params.ignoreCase = true
	case "secondary":
		p.params.collateOpts = append(p.params.collateOpts, collate.IgnoreCase)
		p.params.ignoreCase = true
	case nameTertiary:
		// Default strength needs no additional collator options.
	default:
		p.unsupported = true
	}
}

func (p *ucaParamParser) applyAlternate(value string) {
	switch value {
	case "non-ignorable":
		p.params.alternate = ""
	case nameBlanked, collationAlternateShifted:
		p.params.alternate = value
		p.unsupported = true
	default:
		p.invalid = true
	}
}

func (p *ucaParamParser) applyBoolean(key, value string) {
	if value != lexicon.ValueYes && value != lexicon.ValueNo {
		p.invalid = true

		return
	}

	enabled := value == lexicon.ValueYes

	switch key {
	case "caseLevel":
		p.params.caseLevel = enabled
		if enabled {
			p.unsupported = true
		}
	case "backwards":
		p.params.backwards = enabled
	case collationOptionNumeric:
		if enabled {
			p.params.collateOpts = append(p.params.collateOpts, collate.Numeric)
		}

		p.params.numeric = enabled
	case "normalization":
		if enabled {
			p.unsupported = true
		}
	}
}

func isUCAVariableRune(r rune) bool {
	return unicode.IsSpace(r) || unicode.IsPunct(r) || unicode.IsSymbol(r)
}

type projectedString struct {
	value  string
	starts []int
	ends   []int
}

func projectVariableRunes(s string) projectedString {
	var (
		b      strings.Builder
		starts []int
		ends   []int
	)

	for i, r := range s {
		if isUCAVariableRune(r) {
			continue
		}

		b.WriteRune(r)

		starts = append(starts, i)
		ends = append(ends, i+utf8.RuneLen(r))
	}

	return projectedString{
		value:  b.String(),
		starts: starts,
		ends:   ends,
	}
}

// ucaIndexOf finds substr in s using UCA collation, scanning rune by rune.
// Tries varying match lengths to handle numeric collation (e.g., "001" == "1").
func ucaIndexOf(cmp func(a, b string) int, s, substr string, numeric bool) (int, int) {
	start, end := ucaIndexOfRange(cmp, s, substr, numeric)
	if start < 0 {
		return -1, 0
	}

	sRunes := []rune(s)
	bytePos := len(string(sRunes[:start]))
	byteLen := len(string(sRunes[start:end]))

	return bytePos, byteLen
}

func ucaIndexOfRange(cmp func(a, b string) int, s, substr string, numeric bool) (int, int) {
	if substr == "" {
		return 0, 0
	}

	subRuneLen := len([]rune(substr))
	sRunes := []rune(s)

	for i := range sRunes {
		// Try match lengths from subRuneLen to end of string
		minLen := min(subRuneLen, len(sRunes)-i)

		maxLen := len(sRunes) - i
		for matchLen := minLen; matchLen <= maxLen; matchLen++ {
			candidate := string(sRunes[i : i+matchLen])
			if cmp(candidate, substr) == 0 {
				if numeric && splitsDigitRun(sRunes, i, i+matchLen) {
					continue
				}

				return i, i + matchLen
			}
		}
		// Also try shorter matches (for cases where collation compresses)
		for matchLen := minLen - 1; matchLen > 0; matchLen-- {
			candidate := string(sRunes[i : i+matchLen])
			if cmp(candidate, substr) == 0 {
				if numeric && splitsDigitRun(sRunes, i, i+matchLen) {
					continue
				}

				return i, i + matchLen
			}
		}
	}

	return -1, -1
}

// splitsDigitRun returns true if the match boundary [start, end) in runes
// would split a contiguous run of digits. This is used with numeric collation
// to avoid matching "10" inside "100".
func splitsDigitRun(runes []rune, start, end int) bool {
	// Check if start splits a digit run (digit before and at start)
	if start > 0 && isDigit(runes[start-1]) && isDigit(runes[start]) {
		return true
	}
	// Check if end splits a digit run (digit at end-1 and at end)
	if end > 0 && end < len(runes) && isDigit(runes[end-1]) && isDigit(runes[end]) {
		return true
	}

	return false
}

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

func ucaHasPrefix(cmp func(a, b string) int, s, prefix string, numeric bool) (bool, int) {
	matchEnd, ok := ucaHasPrefixRange(cmp, s, prefix, numeric)
	if !ok {
		return false, 0
	}

	sRunes := []rune(s)

	return true, len(string(sRunes[:matchEnd]))
}

func ucaHasPrefixRange(cmp func(a, b string) int, s, prefix string, numeric bool) (int, bool) {
	prefixRunes := []rune(prefix)

	sRunes := []rune(s)
	if len(sRunes) < len(prefixRunes) {
		return 0, false
	}
	// Try match lengths from len(prefixRunes) upward to handle numeric expansion
	for matchLen := len(prefixRunes); matchLen <= len(sRunes); matchLen++ {
		candidate := string(sRunes[:matchLen])
		if cmp(candidate, prefix) == 0 {
			if numeric && splitsDigitRun(sRunes, 0, matchLen) {
				continue
			}

			return matchLen, true
		}
	}
	// Also try shorter matches
	for matchLen := len(prefixRunes) - 1; matchLen > 0; matchLen-- {
		candidate := string(sRunes[:matchLen])
		if cmp(candidate, prefix) == 0 {
			if numeric && splitsDigitRun(sRunes, 0, matchLen) {
				continue
			}

			return matchLen, true
		}
	}

	return 0, false
}

func ucaHasSuffix(cmp func(a, b string) int, s, suffix string, numeric bool) (bool, int) {
	matchStart, ok := ucaHasSuffixRange(cmp, s, suffix, numeric)
	if !ok {
		return false, 0
	}

	sRunes := []rune(s)

	return true, len(string(sRunes[matchStart:]))
}

func ucaHasSuffixRange(cmp func(a, b string) int, s, suffix string, numeric bool) (int, bool) {
	suffixRunes := []rune(suffix)

	sRunes := []rune(s)
	if len(sRunes) < len(suffixRunes) {
		return 0, false
	}
	// Try match lengths from len(suffixRunes) upward
	for matchLen := len(suffixRunes); matchLen <= len(sRunes); matchLen++ {
		start := len(sRunes) - matchLen

		candidate := string(sRunes[start:])
		if cmp(candidate, suffix) == 0 {
			if numeric && splitsDigitRun(sRunes, start, len(sRunes)) {
				continue
			}

			return start, true
		}
	}
	// Also try shorter matches
	for matchLen := len(suffixRunes) - 1; matchLen > 0; matchLen-- {
		start := len(sRunes) - matchLen

		candidate := string(sRunes[start:])
		if cmp(candidate, suffix) == 0 {
			if numeric && splitsDigitRun(sRunes, start, len(sRunes)) {
				continue
			}

			return start, true
		}
	}

	return 0, false
}

func ucaVariableIndexOf(cmp func(a, b string) int, s, substr string, numeric bool) (int, int) {
	projectedS := projectVariableRunes(s)

	projectedSub := projectVariableRunes(substr)
	if projectedSub.value == "" {
		return 0, 0
	}

	start, end := ucaIndexOfRange(cmp, projectedS.value, projectedSub.value, numeric)
	if start < 0 {
		return -1, 0
	}

	byteStart := projectedS.starts[start]
	byteEnd := projectedS.ends[end-1]

	return byteStart, byteEnd - byteStart
}

func ucaVariableHasPrefix(cmp func(a, b string) int, s, prefix string, numeric bool) (bool, int) {
	projectedS := projectVariableRunes(s)

	projectedPrefix := projectVariableRunes(prefix)
	if projectedPrefix.value == "" {
		return true, 0
	}

	matchEnd, ok := ucaHasPrefixRange(cmp, projectedS.value, projectedPrefix.value, numeric)
	if !ok {
		return false, 0
	}

	return true, projectedS.ends[matchEnd-1]
}

func ucaVariableHasSuffix(cmp func(a, b string) int, s, suffix string, numeric bool) (bool, int) {
	projectedS := projectVariableRunes(s)

	projectedSuffix := projectVariableRunes(suffix)
	if projectedSuffix.value == "" {
		return true, 0
	}

	matchStart, ok := ucaHasSuffixRange(cmp, projectedS.value, projectedSuffix.value, numeric)
	if !ok {
		return false, 0
	}

	return true, len(s) - projectedS.starts[matchStart]
}

func buildCaseFirstKey(s, caseFirst string) []byte {
	var key []byte

	for _, r := range s {
		lower := unicode.ToLower(r)

		upper := unicode.ToUpper(r)
		if lower == upper {
			continue
		}

		switch caseFirst {
		case nameLower:
			if unicode.IsLower(r) {
				key = append(key, 0x01)
			} else {
				key = append(key, 0x02)
			}
		case nameUpper2:
			if unicode.IsUpper(r) {
				key = append(key, 0x01)
			} else {
				key = append(key, 0x02)
			}
		}
	}

	return key
}

// resolveCollation resolves a collation URI string to a collation implementation.
// If baseURI is non-empty, relative URIs are resolved against it.
func resolveCollation(uri, baseURI string) (*collationImpl, error) {
	// Resolve relative URI if baseURI is provided
	if baseURI != "" && !strings.Contains(uri, "://") {
		base, err := url.Parse(baseURI)
		if err == nil {
			ref, err := url.Parse(uri)
			if err == nil {
				uri = base.ResolveReference(ref).String()
			}
		}
	}

	switch {
	case uri == lexicon.CollationCodepoint:
		return newCodepointCollation(), nil
	case uri == lexicon.CollationHTMLASCII:
		return newHTMLASCIICaseInsensitiveCollation(), nil
	case uri == caseblindCollationURI:
		return newHTMLASCIICaseInsensitiveCollation(), nil
	case strings.HasPrefix(uri, lexicon.CollationUCA):
		params := ""
		if _, after, ok := strings.Cut(uri, "?"); ok {
			params = after
		}

		cl, err := makeUCACollation(params)
		if err != nil {
			return nil, err
		}

		return cl, nil
	default:
		return nil, &xdm.Error{Code: errCodeFOCH0002, Message: fmt.Sprintf("unsupported collation: %s", uri)}
	}
}
