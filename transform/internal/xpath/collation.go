// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"bytes"
	"context"
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
	"github.com/skarm/xmlsec/internal/tree"
)

// UCA query selectors keep their defined case; locale extensions enable the
// matching x/text options without changing query fallback semantics.
const (
	collationOptionNumeric    = "numeric"
	collationAlternateShifted = "shifted"
)

const (
	collationOptionStrength           = "strength"
	collationOptionAlternate          = "alternate"
	collationOptionCaseFirst          = "caseFirst"
	collationOptionCaseLevel          = "caseLevel"
	collationOptionBackwards          = "backwards"
	collationOptionNormalization      = "normalization"
	collationOptionReorder            = "reorder"
	collationOptionMaxVariable        = "maxVariable"
	collationOptionVersion            = "version"
	collationOptionKeyword            = "keyword"
	collationOptionHiraganaQuaternary = "hiraganaQuaternary"
	collationStrengthIdentical        = "identical"
	collationStrengthPrimary          = "primary"
	collationStrengthSecondary        = "secondary"
	collationAlternateNonIgnorable    = "non-ignorable"
	collationFallbackUnknown          = "unknown"
	collationExtensionRootTag         = "und-u"
	collationBackwardsExtension       = "kb-true"
	collationCaseLevelExtension       = "kc-true"
)

// Idle retention is bounded by two collator objects. Inputs above 4096 bytes
// drop their collator to avoid retaining enlarged internal element buffers.
const (
	maxIdleCollators        = 2
	maxPooledCollationInput = 4096
)

// Case tie-break keys sort the preferred case before the other case after a
// zero separator from the base key. Missing substring boundaries use -1.
const (
	collationCaseKeySeparator    = 0
	collationPreferredCaseWeight = 0x01
	collationOtherCaseWeight     = 0x02
	collationMatchNotFound       = -1
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
	indexOf   func(ctx context.Context, s, substr string) (pos, matchLen int, err error)
	hasPrefix func(ctx context.Context, s, prefix string) (bool, int, error)
	hasSuffix func(ctx context.Context, s, suffix string) (bool, int, error)
	key       func(s string) []byte
}

// newCodepointCollation constructs the default XPath byte-level collation.
func newCodepointCollation() *collationImpl {
	return &collationImpl{
		codepoint: true,
		compare:   strings.Compare,
		indexOf: func(_ context.Context, s, substr string) (int, int, error) {
			idx := strings.Index(s, substr)
			if idx < 0 {
				return collationMatchNotFound, 0, nil
			}

			return idx, len(substr), nil
		},
		hasPrefix: func(_ context.Context, s, prefix string) (bool, int, error) {
			if strings.HasPrefix(s, prefix) {
				return true, len(prefix), nil
			}

			return false, 0, nil
		},
		hasSuffix: func(_ context.Context, s, suffix string) (bool, int, error) {
			if strings.HasSuffix(s, suffix) {
				return true, len(suffix), nil
			}

			return false, 0, nil
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
		indexOf: func(_ context.Context, s, substr string) (int, int, error) {
			ls := foldASCIIString(s)
			lsub := foldASCIIString(substr)

			idx := strings.Index(ls, lsub)
			if idx < 0 {
				return collationMatchNotFound, 0, nil
			}

			return idx, len(substr), nil
		},
		hasPrefix: func(_ context.Context, s, prefix string) (bool, int, error) {
			if len(s) < len(prefix) {
				return false, 0, nil
			}

			if foldASCIIString(s[:len(prefix)]) == foldASCIIString(prefix) {
				return true, len(prefix), nil
			}

			return false, 0, nil
		},
		hasSuffix: func(_ context.Context, s, suffix string) (bool, int, error) {
			if len(s) < len(suffix) {
				return false, 0, nil
			}

			if foldASCIIString(s[len(s)-len(suffix):]) == foldASCIIString(suffix) {
				return true, len(suffix), nil
			}

			return false, 0, nil
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
		tagParts := []string{collationExtensionRootTag}
		if opts.backwards {
			tagParts = append(tagParts, collationBackwardsExtension)
		}

		if opts.caseLevel {
			tagParts = append(tagParts, collationCaseLevelExtension)
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

			base = append(base, collationCaseKeySeparator)

			return append(base, caseKey...)
		}
		cmp = func(a, b string) int {
			return bytes.Compare(key(a), key(b))
		}
	}

	return &collationImpl{
		compare: cmp,
		indexOf: func(ctx context.Context, s, substr string) (int, int, error) {
			if err := chargeCollationWork(ctx, s, substr); err != nil {
				return collationMatchNotFound, 0, err
			}

			compare := boundedCollationCompare(ctx, cmp)
			if ignoreVariables {
				return ucaVariableIndexOf(compare, s, substr, numeric)
			}

			return ucaIndexOf(compare, s, substr, numeric)
		},
		hasPrefix: func(ctx context.Context, s, prefix string) (bool, int, error) {
			if err := chargeCollationWork(ctx, s, prefix); err != nil {
				return false, 0, err
			}

			compare := boundedCollationCompare(ctx, cmp)
			if ignoreVariables {
				return ucaVariableHasPrefix(compare, s, prefix, numeric)
			}

			return ucaHasPrefix(compare, s, prefix, numeric)
		},
		hasSuffix: func(ctx context.Context, s, suffix string) (bool, int, error) {
			if err := chargeCollationWork(ctx, s, suffix); err != nil {
				return false, 0, err
			}

			compare := boundedCollationCompare(ctx, cmp)
			if ignoreVariables {
				return ucaVariableHasSuffix(compare, s, suffix, numeric)
			}

			return ucaHasSuffix(compare, s, suffix, numeric)
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
		return p.strength != collationStrengthIdentical
	case collationAlternateShifted:
		switch p.strength {
		case collationStrengthPrimary, collationStrengthSecondary, nameTertiary:
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

	parameters := make(map[string]string)

	for parameter := range strings.SplitSeq(query, ";") {
		if parameter == "" {
			continue
		}

		key, value, ok := strings.Cut(parameter, "=")
		if !ok {
			parser.invalid = true

			continue
		}

		parameters[key] = value
	}
	// F&O 3.1 requires the final value of a repeated keyword to take effect.
	// Apply only those values so superseded flags and options cannot accumulate.
	for key, value := range parameters {
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
	case collationOptionStrength:
		p.applyStrength(value)
	case collationOptionAlternate:
		p.applyAlternate(value)
	case collationOptionCaseFirst:
		if value == nameUpperCase || value == nameLower {
			p.params.caseFirst = value
		} else {
			p.invalid = true
		}
	case collationOptionCaseLevel, collationOptionBackwards, collationOptionNumeric, collationOptionNormalization:
		p.applyBoolean(key, value)
	case collationOptionReorder, collationOptionMaxVariable, collationOptionVersion, collationOptionKeyword, collationOptionHiraganaQuaternary:
		p.unsupported = true
	default:
		p.invalid = true
	}
}

func (p *ucaParamParser) applyFallback(value string) {
	switch value {
	case lexicon.ValueNo:
		p.params.fallbackNo = true
	case lexicon.ValueYes, collationFallbackUnknown:
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
	switch value {
	case "1":
		value = collationStrengthPrimary
	case "2":
		value = collationStrengthSecondary
	case "3":
		value = nameTertiary
	case "4":
		value = "quaternary"
	case "5":
		value = collationStrengthIdentical
	}

	p.params.strength = value

	switch value {
	case collationStrengthPrimary:
		p.params.collateOpts = append(p.params.collateOpts, collate.IgnoreCase, collate.IgnoreDiacritics)
		p.params.ignoreCase = true
	case collationStrengthSecondary:
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
	case collationAlternateNonIgnorable:
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
	case collationOptionCaseLevel:
		p.params.caseLevel = enabled
		if enabled {
			p.unsupported = true
		}
	case collationOptionBackwards:
		p.params.backwards = enabled
	case collationOptionNumeric:
		if enabled {
			p.params.collateOpts = append(p.params.collateOpts, collate.Numeric)
		}

		p.params.numeric = enabled
	case collationOptionNormalization:
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

type collationCompare func(a, b string) (int, error)

func chargeCollationWork(ctx context.Context, a, b string) error {
	// Charge each comparison and additional work for longer inputs. The same
	// charge precedes preprocessing, which scans both strings before matching.
	const bytesPerOperation = 64
	return Charge(ctx, 1+len(a)/bytesPerOperation+len(b)/bytesPerOperation)
}

func boundedCollationCompare(ctx context.Context, compare func(a, b string) int) collationCompare {
	return func(a, b string) (int, error) {
		if err := chargeCollationWork(ctx, a, b); err != nil {
			return 0, err
		}

		return compare(a, b), nil
	}
}

// ucaIndexOf finds substr in s using UCA collation, scanning rune by rune.
// Tries varying match lengths to handle numeric collation (e.g., "001" == "1").
func ucaIndexOf(cmp collationCompare, s, substr string, numeric bool) (int, int, error) {
	start, end, err := ucaIndexOfRange(cmp, s, substr, numeric)
	if err != nil {
		return collationMatchNotFound, 0, err
	}

	if start < 0 {
		return collationMatchNotFound, 0, nil
	}

	bytePos := ucaRuneByteOffset(s, start)
	byteLen := ucaRuneByteOffset(s, end) - bytePos

	return bytePos, byteLen, nil
}

// ucaRuneByteOffset maps a decoded rune boundary to the original byte offset.
// A malformed UTF-8 byte occupies one source byte, even though its rune is
// RuneError. The caller supplies a boundary between zero and the rune count.
func ucaRuneByteOffset(s string, index int) int {
	for offset := range s {
		if index == 0 {
			return offset
		}

		index--
	}

	return len(s)
}

func ucaCandidateBoundaries(s, needle string, runeCount int) []int {
	if !utf8.ValidString(needle) || !utf8.ValidString(s) {
		return nil
	}

	if runeCount == len(s) {
		return []int{} // A non-nil empty slice marks ASCII byte boundaries.
	}

	boundaries := make([]int, runeCount+1)

	index := 0
	for offset := range s {
		boundaries[index] = offset
		index++
	}

	boundaries[index] = len(s)

	return boundaries
}

func ucaCandidateString(s string, runes []rune, boundaries []int, start, end int) string {
	if boundaries == nil {
		return string(runes[start:end])
	}

	if len(boundaries) == 0 {
		return s[start:end]
	}

	return s[boundaries[start]:boundaries[end]]
}

func ucaIndexOfRange(cmp collationCompare, s, substr string, numeric bool) (int, int, error) {
	if substr == "" {
		return 0, 0, nil
	}

	emptyOrder, err := cmp("", substr)
	if err != nil {
		return collationMatchNotFound, collationMatchNotFound, err
	}

	if emptyOrder == 0 {
		return 0, 0, nil
	}

	subRuneLen := len([]rune(substr))
	sRunes := []rune(s)
	boundaries := ucaCandidateBoundaries(s, substr, len(sRunes))

	for i := range sRunes {
		// Try match lengths from subRuneLen to end of string
		minLen := min(subRuneLen, len(sRunes)-i)

		maxLen := len(sRunes) - i
		for matchLen := minLen; matchLen <= maxLen; matchLen++ {
			candidate := ucaCandidateString(s, sRunes, boundaries, i, i+matchLen)

			order, err := cmp(candidate, substr)
			if err != nil {
				return collationMatchNotFound, collationMatchNotFound, err
			}

			if order == 0 {
				if numeric && splitsDigitRun(sRunes, i, i+matchLen) {
					continue
				}

				return i, i + matchLen, nil
			}
		}
		// Also try shorter matches (for cases where collation compresses)
		for matchLen := minLen - 1; matchLen > 0; matchLen-- {
			candidate := ucaCandidateString(s, sRunes, boundaries, i, i+matchLen)

			order, err := cmp(candidate, substr)
			if err != nil {
				return collationMatchNotFound, collationMatchNotFound, err
			}

			if order == 0 {
				if numeric && splitsDigitRun(sRunes, i, i+matchLen) {
					continue
				}

				return i, i + matchLen, nil
			}
		}
	}

	return collationMatchNotFound, collationMatchNotFound, nil
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

func ucaHasPrefix(cmp collationCompare, s, prefix string, numeric bool) (bool, int, error) {
	matchEnd, ok, err := ucaHasPrefixRange(cmp, s, prefix, numeric)
	if err != nil {
		return false, 0, err
	}

	if !ok {
		return false, 0, nil
	}

	return true, ucaRuneByteOffset(s, matchEnd), nil
}

func ucaHasPrefixRange(cmp collationCompare, s, prefix string, numeric bool) (int, bool, error) {
	if prefix == "" {
		return 0, true, nil
	}

	emptyOrder, err := cmp("", prefix)
	if err != nil {
		return 0, false, err
	}

	if emptyOrder == 0 {
		return 0, true, nil
	}

	prefixRunes := []rune(prefix)

	sRunes := []rune(s)
	boundaries := ucaCandidateBoundaries(s, prefix, len(sRunes))
	initialLength := min(len(prefixRunes), len(sRunes))
	// Try match lengths from len(prefixRunes) upward to handle numeric expansion
	for matchLen := initialLength; matchLen <= len(sRunes); matchLen++ {
		candidate := ucaCandidateString(s, sRunes, boundaries, 0, matchLen)

		order, err := cmp(candidate, prefix)
		if err != nil {
			return 0, false, err
		}

		if order == 0 {
			if numeric && splitsDigitRun(sRunes, 0, matchLen) {
				continue
			}

			return matchLen, true, nil
		}
	}
	// Also try shorter matches
	for matchLen := initialLength - 1; matchLen > 0; matchLen-- {
		candidate := ucaCandidateString(s, sRunes, boundaries, 0, matchLen)

		order, err := cmp(candidate, prefix)
		if err != nil {
			return 0, false, err
		}

		if order == 0 {
			if numeric && splitsDigitRun(sRunes, 0, matchLen) {
				continue
			}

			return matchLen, true, nil
		}
	}

	return 0, false, nil
}

func ucaHasSuffix(cmp collationCompare, s, suffix string, numeric bool) (bool, int, error) {
	matchStart, ok, err := ucaHasSuffixRange(cmp, s, suffix, numeric)
	if err != nil {
		return false, 0, err
	}

	if !ok {
		return false, 0, nil
	}

	return true, len(s) - ucaRuneByteOffset(s, matchStart), nil
}

func ucaHasSuffixRange(cmp collationCompare, s, suffix string, numeric bool) (int, bool, error) {
	if suffix == "" {
		return utf8.RuneCountInString(s), true, nil
	}

	emptyOrder, err := cmp("", suffix)
	if err != nil {
		return 0, false, err
	}

	if emptyOrder == 0 {
		return utf8.RuneCountInString(s), true, nil
	}

	suffixRunes := []rune(suffix)

	sRunes := []rune(s)
	boundaries := ucaCandidateBoundaries(s, suffix, len(sRunes))
	initialLength := min(len(suffixRunes), len(sRunes))
	// Try match lengths from len(suffixRunes) upward
	for matchLen := initialLength; matchLen <= len(sRunes); matchLen++ {
		start := len(sRunes) - matchLen

		candidate := ucaCandidateString(s, sRunes, boundaries, start, len(sRunes))

		order, err := cmp(candidate, suffix)
		if err != nil {
			return 0, false, err
		}

		if order == 0 {
			if numeric && splitsDigitRun(sRunes, start, len(sRunes)) {
				continue
			}

			return start, true, nil
		}
	}
	// Also try shorter matches
	for matchLen := initialLength - 1; matchLen > 0; matchLen-- {
		start := len(sRunes) - matchLen

		candidate := ucaCandidateString(s, sRunes, boundaries, start, len(sRunes))

		order, err := cmp(candidate, suffix)
		if err != nil {
			return 0, false, err
		}

		if order == 0 {
			if numeric && splitsDigitRun(sRunes, start, len(sRunes)) {
				continue
			}

			return start, true, nil
		}
	}

	return 0, false, nil
}

func ucaVariableIndexOf(cmp collationCompare, s, substr string, numeric bool) (int, int, error) {
	projectedS := projectVariableRunes(s)

	projectedSub := projectVariableRunes(substr)
	if projectedSub.value == "" {
		return 0, 0, nil
	}

	start, end, err := ucaIndexOfRange(cmp, projectedS.value, projectedSub.value, numeric)
	if err != nil {
		return collationMatchNotFound, 0, err
	}

	if start < 0 {
		return collationMatchNotFound, 0, nil
	}

	if start == end {
		return 0, 0, nil
	}

	byteStart := projectedS.starts[start]
	byteEnd := projectedS.ends[end-1]

	return byteStart, byteEnd - byteStart, nil
}

func ucaVariableHasPrefix(cmp collationCompare, s, prefix string, numeric bool) (bool, int, error) {
	projectedS := projectVariableRunes(s)

	projectedPrefix := projectVariableRunes(prefix)
	if projectedPrefix.value == "" {
		return true, 0, nil
	}

	matchEnd, ok, err := ucaHasPrefixRange(cmp, projectedS.value, projectedPrefix.value, numeric)
	if err != nil {
		return false, 0, err
	}

	if !ok {
		return false, 0, nil
	}

	if matchEnd == 0 {
		return true, 0, nil
	}

	return true, projectedS.ends[matchEnd-1], nil
}

func ucaVariableHasSuffix(cmp collationCompare, s, suffix string, numeric bool) (bool, int, error) {
	projectedS := projectVariableRunes(s)

	projectedSuffix := projectVariableRunes(suffix)
	if projectedSuffix.value == "" {
		return true, 0, nil
	}

	matchStart, ok, err := ucaHasSuffixRange(cmp, projectedS.value, projectedSuffix.value, numeric)
	if err != nil {
		return false, 0, err
	}

	if !ok {
		return false, 0, nil
	}

	if matchStart == len(projectedS.starts) {
		return true, 0, nil
	}

	return true, len(s) - projectedS.starts[matchStart], nil
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
				key = append(key, collationPreferredCaseWeight)
			} else {
				key = append(key, collationOtherCaseWeight)
			}
		case nameUpperCase:
			if unicode.IsUpper(r) {
				key = append(key, collationPreferredCaseWeight)
			} else {
				key = append(key, collationOtherCaseWeight)
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
				uri = tree.ResolveURIReference(base, ref).String()
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
