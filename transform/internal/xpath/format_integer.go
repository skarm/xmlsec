// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// Alphabetic and sequential-symbol numbering preserve these ordered Unicode
// alphabets/ranges. Symbol count is per block; the Roman ceiling and CJK myriad
// unit have different roles although their numeric values coincide.
const (
	greekAlphabetLower       = "αβγδεζηθικλμνξοπρστυφχψω"
	greekAlphabetUpper       = "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ"
	greekLowerFirst          = 0x03B1
	greekLowerLast           = 0x03C9
	greekUpperFirst          = 0x0391
	greekUpperLast           = 0x03A9
	circledSymbolFirst       = 0x2460
	circledSymbolLast        = 0x2473
	parenthesizedSymbolFirst = 0x2474
	parenthesizedSymbolLast  = 0x2487
	fullstopSymbolFirst      = 0x2488
	fullstopSymbolLast       = 0x249B
	sequentialSymbolCount    = 20
	latinAlphabetSize        = 26
	cjkMyriadUnit            = 10000
	romanMaximumValue        = 10000
)

// Word-formatting control thresholds count numeric values, not string lengths.
// The vocabulary tables below remain language data. German zero is a word,
// separate from the identical JSON null element-name spelling.
const (
	wordGermanZero       = "null"
	wordSmallNumberLimit = 20
	wordHundred          = 100
	wordThousand         = 1000
	wordMillion          = 1000000
	wordBillion          = 1000000000
	wordTrillion         = 1000000000000
)

// Ordinal selectors and suffixes are implementation-supported F&O language
// hints. English teen exceptions inspect the last two decimal digits; French
// composite tens and Italian vowel elision are independent language rules.
const (
	ordinalSpellout             = "%spellout-ordinal"
	ordinalSpelloutMasculine    = "%spellout-ordinal-masculine"
	ordinalSpelloutFeminine     = "%spellout-ordinal-feminine"
	ordinalMasculineSuffix      = "-o"
	ordinalFeminineSuffix       = "-a"
	ordinalLastTwoDigitsModulus = 100
	ordinalTeenFirst            = 11
	ordinalTeenLast             = 13
	ordinalFirstLastDigit       = 1
	ordinalSecondLastDigit      = 2
	ordinalThirdLastDigit       = 3
	ordinalEnglishGeneralSuffix = "th"
	ordinalEnglishFirstSuffix   = "st"
	ordinalEnglishSecondSuffix  = "nd"
	ordinalEnglishThirdSuffix   = "rd"
	frenchCompositeSeventy      = 7
	frenchCompositeEighty       = 8
	frenchCompositeNinety       = 9
	frenchElevenUnit            = 11
	italianElidedOne            = 1
	italianElidedEight          = 8
	frenchConjunctionOne        = 1     // units digit receiving et outside composite80/90
	ordinalMasculine            = false // masculine vocabulary in italianOrdinalWord
	ordinalFeminine             = true  // feminine vocabulary in italianOrdinalWord
	italianOrdinalDecimalFormat = "%d°"
	integerRepeatingGroupPair   = 2 // one separator between two groups repeats
	integerMinimumDecimalDigits = 1
)

const wordGermanSeven = "sieben"

// FormatGreekAlphabetic uses the 24-letter Greek alphabet, excluding the
// unassigned capital U+03A2 and the context-specific lowercase final sigma.
// It is shared with XSLT numbering so both execution paths use the same digits.
func FormatGreekAlphabetic(n *big.Int, upper bool) string {
	if n.Sign() <= 0 {
		return n.String()
	}

	alphabet := []rune(greekAlphabetLower)
	if upper {
		alphabet = []rune(greekAlphabetUpper)
	}

	value, one, size := new(big.Int).Set(n), big.NewInt(1), big.NewInt(int64(len(alphabet)))

	var (
		digits    []rune
		remainder big.Int
	)

	for value.Sign() > 0 {
		value.Sub(value, one)
		value.DivMod(value, size, &remainder)
		digits = append(digits, alphabet[remainder.Int64()])
	}

	slices.Reverse(digits)

	return string(digits)
}

func fnFormatInteger(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// format-integer($value, $picture [, $lang])
	valSeq := args[0]

	// $picture is a required, exactly-one xs:string. Validate it before the
	// empty-$value short-circuit so an empty or oversized picture raises
	// XPTY0004 and never panics on picSeq.Get(0).
	picture, err := coerceArgToStringRequired(ctx, args[1])
	if err != nil {
		return nil, err
	}

	// Empty $value → empty string (per F&O), once $picture is known valid.
	if xdm.SequenceLen(valSeq) == 0 {
		return xdm.SingleString(""), nil
	}

	valAtom, err := AtomizeItem(valSeq.Get(0))
	if err != nil {
		return nil, err
	}

	if valAtom.TypeName == xdm.TypeUntypedAtomic || valAtom.TypeName == xdm.TypeString {
		converted, err := CastAtomic(valAtom, xdm.TypeInteger)
		if err != nil {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("cannot cast %s to xs:integer", valAtom.TypeName), Cause: err}
		}

		valAtom = converted
	}

	if !xdm.IsSubtypeOf(valAtom.TypeName, xdm.TypeInteger) {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("format-integer: expected xs:integer, got %s", valAtom.TypeName)}
	}

	var n *big.Int

	switch v := valAtom.Value.(type) {
	case int64:
		n = big.NewInt(v)
	case *big.Int:
		n = v
	default:
		return nil, fmt.Errorf("xpath: internal error: expected integer value for %s, got %T", valAtom.TypeName, valAtom.Value)
	}

	lang := defaultFormattingLanguage
	if ec := getFnContext(ctx); ec != nil {
		lang = ec.getDefaultLanguage()
	}

	defaultLanguage := lang

	if len(args) > 2 && xdm.SequenceLen(args[2]) > 0 {
		langAtom, err := AtomizeItem(args[2].Get(0))
		if err != nil {
			return nil, err
		}

		lang = langAtom.StringVal()
	}

	lang = strings.ToLower(lang)
	if !isSupportedIntegerLanguage(lang) {
		lang = strings.ToLower(defaultLanguage)
	}

	// Bound picture scanning and integer conversion before allocating formatted
	// text; charge its output even if a caller consumes only string-length().
	if err := Charge(ctx, len(picture)); err != nil {
		return nil, err
	}

	if err := ChargeString(ctx, len(picture)); err != nil {
		return nil, err
	}

	if err := preflightNumeric(ctx, n.BitLen()); err != nil {
		return nil, err
	}

	result, err := formatIntegerPicture(n, picture, lang)
	if err != nil {
		return nil, err
	}

	if err := ChargeString(ctx, len(result)); err != nil {
		return nil, err
	}

	return xdm.SingleString(result), nil
}

func isSupportedIntegerLanguage(lang string) bool {
	switch lang {
	case formatLanguageEnglish, formatLanguageGerman, formatLanguageFrench, formatLanguageItalian:
		return true
	default:
		return false
	}
}

func formatIntegerPicture(n *big.Int, picture, lang string) (string, error) {
	if picture == "" {
		return "", &xdm.Error{Code: errCodeFODF1310, Message: "empty picture string"}
	}

	// Split on ';' to get primary token and format modifier
	primary, modifier := splitFormatModifier(picture)
	if primary == "" {
		return "", &xdm.Error{Code: errCodeFODF1310, Message: "empty primary format token"}
	}

	if modifier == "" && hasImplicitFormatModifier(primary) {
		return "", &xdm.Error{Code: errCodeFODF1310, Message: fmt.Sprintf("invalid picture: %q", picture)}
	}

	if err := validateModifier(modifier); err != nil {
		return "", err
	}

	ordinal, ordSuffix := parseModifier(modifier)

	// Determine formatting based on primary token
	negative := n.Sign() < 0
	absN := new(big.Int).Abs(n)

	var (
		result string
		fmtErr error
	)

	switch primary {
	case formatAlphaUpper:
		result = formatAlpha(absN, formatUppercase)
	case formatAlphaLower:
		result = formatAlpha(absN, formatLowercase)
	case formatRomanUpper:
		result = formatRoman(absN, formatUppercase)
	case formatRomanLower:
		result = formatRoman(absN, formatLowercase)
	case formatWordsUpper:
		result = formatWords(absN, lang, nameUpperCase)
		if ordinal {
			result = applyOrdinalWords(result, lang, nameUpperCase, ordSuffix)
		}
	case formatWordsLower:
		result = formatWords(absN, lang, nameLower)
		if ordinal {
			result = applyOrdinalWords(result, lang, nameLower, ordSuffix)
		}
	case formatWordsTitle:
		result = formatWords(absN, lang, formatCaseTitle)
		if ordinal {
			result = applyOrdinalWords(result, lang, formatCaseTitle, ordSuffix)
		}
	default:
		if tok := classifyFormatToken(primary); tok != fmtTokenDecimal {
			result, fmtErr = formatSpecialToken(absN, primary, tok)
			if fmtErr != nil {
				return "", fmtErr
			}

			if ordinal {
				result = applyOrdinalDecimal(result, absN, lang, ordSuffix)
			}
		} else {
			result, fmtErr = formatIntegerDecimal(absN, primary)
			if fmtErr != nil {
				return "", fmtErr
			}

			if ordinal {
				result = applyOrdinalDecimal(result, absN, lang, ordSuffix)
			}
		}
	}

	if negative && n.Sign() != 0 {
		result = "-" + result
	}

	return result, nil
}

type formatTokenKind int

const (
	fmtTokenDecimal formatTokenKind = iota
	fmtTokenGreekLower
	fmtTokenGreekUpper
	fmtTokenCJK
	fmtTokenCircled
	fmtTokenParenthesized
	fmtTokenFullstopDigit
	fmtTokenUnknown
)

func classifyFormatToken(primary string) formatTokenKind {
	runes := []rune(primary)
	if len(runes) == 0 {
		return fmtTokenDecimal
	}

	hasDecimal, hasLetter := false, false

	for _, r := range runes {
		if r == '#' || unicode.IsDigit(r) {
			hasDecimal = true
			continue
		}

		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
		}
	}

	if hasDecimal {
		if hasLetter {
			return fmtTokenUnknown
		}

		return fmtTokenDecimal
	}

	if len(runes) != 1 {
		return fmtTokenUnknown
	}

	r := runes[0]
	switch r {
	case '一', '二', '三', '四', '五', '六', '七', '八', '九', '十':
		return fmtTokenCJK
	}

	switch {
	case r >= greekLowerFirst && r <= greekLowerLast:
		return fmtTokenGreekLower
	case r >= greekUpperFirst && r <= greekUpperLast:
		return fmtTokenGreekUpper
	case r >= circledSymbolFirst && r <= circledSymbolLast:
		return fmtTokenCircled
	case r >= parenthesizedSymbolFirst && r <= parenthesizedSymbolLast:
		return fmtTokenParenthesized
	case r >= fullstopSymbolFirst && r <= fullstopSymbolLast:
		return fmtTokenFullstopDigit
	default:
		return fmtTokenUnknown
	}
}

func formatSpecialToken(n *big.Int, primary string, kind formatTokenKind) (string, error) {
	switch kind {
	case fmtTokenGreekLower:
		return FormatGreekAlphabetic(n, formatLowercase), nil
	case fmtTokenGreekUpper:
		return FormatGreekAlphabetic(n, formatUppercase), nil
	case fmtTokenCJK:
		return formatCJK(n), nil
	case fmtTokenCircled:
		return formatSequentialSymbol(n, circledSymbolFirst, sequentialSymbolCount), nil
	case fmtTokenParenthesized:
		return formatSequentialSymbol(n, parenthesizedSymbolFirst, sequentialSymbolCount), nil
	case fmtTokenFullstopDigit:
		return formatSequentialSymbol(n, fullstopSymbolFirst, sequentialSymbolCount), nil
	case fmtTokenUnknown:
		// Spec: if the format token is not recognized, use decimal fallback
		return formatIntegerDecimal(n, formatDecimalDefault)
	default:
		return formatIntegerDecimal(n, primary)
	}
}

// formatSequentialSymbol formats using a sequential Unicode symbol range (e.g., circled digits).
func formatSequentialSymbol(n *big.Int, startCodepoint rune, maxVal int) string {
	if !n.IsInt64() || n.Int64() < 1 || n.Int64() > int64(maxVal) {
		// Fall back to decimal for out-of-range values
		return n.String()
	}

	return string(startCodepoint + rune(n.Int64()-1)) // #nosec G115 -- The caller supplies a 20-symbol block; n is checked against that block above.
}

// CJK ideographic number formatting
func cjkDigits(index int64) string {
	return [...]string{"〇", "一", "二", "三", "四", "五", "六", "七", "八", "九"}[index]
}

func formatCJK(n *big.Int) string {
	if n.Sign() == 0 {
		return "〇"
	}

	if !n.IsInt64() {
		return n.String()
	}

	return int64ToCJK(n.Int64())
}

// cjkMyriadUnits are the myriad (10^4) grouping separators, ascending.
// Each successive unit is 10^4 times the previous: 万=10^4, 億=10^8, 兆=10^12,
// 京=10^16. int64 maxes out below 京×10 (~9.2×10^18), so this table is sufficient
// for every representable value.
func cjkMyriadUnits(index int) string { return [...]string{"", "万", "億", "兆", "京"}[index] }

func int64ToCJK(n int64) string {
	if n == 0 {
		return "〇"
	}

	if n < 0 {
		return "負" + int64ToCJK(-n)
	}

	// Split into 4-digit (myriad) groups, least-significant first.
	var groups []int64
	for n > 0 {
		groups = append(groups, n%cjkMyriadUnit)
		n /= cjkMyriadUnit
	}

	var parts []string
	// Emit most-significant group first.
	for i, g := range slices.Backward(groups) {
		if g == 0 {
			continue
		}

		parts = append(parts, cjkGroupUnder10000(g))
		parts = append(parts, cjkMyriadUnits(i))
	}

	return strings.Join(parts, "")
}

// cjkGroupUnder10000 renders a value in 1..9999 as CJK numerals. The leading
// "一" is omitted before 十/百/千 (e.g. 10 → 十, 100 → 百) per CJK convention.
func cjkGroupUnder10000(n int64) string {
	type cjkUnit struct {
		value int64
		char  string
	}

	units := []cjkUnit{
		{1000, "千"},
		{100, "百"},
		{10, "十"},
	}

	var parts []string

	for _, u := range units {
		if n >= u.value {
			q := n / u.value
			if q > 1 {
				parts = append(parts, cjkDigits(q))
			}

			parts = append(parts, u.char)
			n %= u.value
		}
	}

	if n > 0 {
		parts = append(parts, cjkDigits(n))
	}

	return strings.Join(parts, "")
}

func splitFormatModifier(picture string) (string, string) {
	idx := strings.LastIndex(picture, ";")
	if idx < 0 {
		return picture, ""
	}

	return picture[:idx], picture[idx+1:]
}

func hasImplicitFormatModifier(primary string) bool {
	if !containsDecimalPattern(primary) {
		return false
	}

	for i, r := range primary {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return validateModifier(primary[i:]) == nil
		}
	}

	return false
}

func containsDecimalPattern(primary string) bool {
	for _, r := range primary {
		if r == '#' || unicode.IsDigit(r) {
			return true
		}
	}

	return false
}

func parseModifier(mod string) (bool, string) {
	if mod == "" {
		return false, ""
	}

	ordinal := false
	suffix := ""

	for i := 0; i < len(mod); i++ {
		switch mod[i] {
		case 'o':
			ordinal = true
		case 't', 'c':
			// traditional or cardinal — no special handling
		case '(':
			end := strings.Index(mod[i:], ")")
			if end > 0 {
				suffix = mod[i+1 : i+end]
				i += end
			}
		}
	}

	return ordinal, suffix
}

func validateModifier(mod string) error {
	if mod == "" {
		return nil
	}
	// Valid modifier: [co][t]?  or [co]?[t]  followed by optional (...)
	// Characters allowed: c, o, t, and a single parenthesized group
	i := 0
	for i < len(mod) {
		switch mod[i] {
		case 'c', 'o', 't':
			i++
		case '(':
			end := strings.Index(mod[i:], ")")
			if end < 0 {
				return &xdm.Error{Code: errCodeFODF1310, Message: fmt.Sprintf("unclosed parenthesis in format modifier: %q", mod)}
			}

			i += end + 1
		default:
			return &xdm.Error{Code: errCodeFODF1310, Message: fmt.Sprintf("invalid character in format modifier: %q", mod)}
		}
	}

	return nil
}

// formatAlpha formats a number using alphabetic numbering (a=1, b=2, ..., z=26, aa=27, ...).
func formatAlpha(n *big.Int, upper bool) string {
	if n.Sign() == 0 {
		return formatZeroDigit
	}

	val := new(big.Int).Set(n)
	one := big.NewInt(1)
	twentySix := big.NewInt(latinAlphabetSize)

	var digits []rune

	base := 'a'
	if upper {
		base = 'A'
	}

	for val.Sign() > 0 {
		val.Sub(val, one)

		mod := new(big.Int)
		val.DivMod(val, twentySix, mod)
		digits = append([]rune{base + rune(mod.Int64())}, digits...) // #nosec G115 -- DivMod by 26 produces a remainder in 0..25.
	}

	return string(digits)
}

func formatRoman(n *big.Int, upper bool) string {
	if n.Sign() == 0 {
		return formatZeroDigit
	}

	if !n.IsInt64() {
		return n.String()
	}

	val := n.Int64()
	if val < 0 {
		val = -val
	}

	if val > romanMaximumValue {
		return n.String()
	}

	type romanPair struct {
		value  int64
		symbol string
	}

	table := []romanPair{
		{1000, "m"},
		{900, "cm"},
		{500, "d"},
		{400, "cd"},
		{100, "c"},
		{90, "xc"},
		{50, "l"},
		{40, "xl"},
		{10, "x"},
		{9, "ix"},
		{5, "v"},
		{4, "iv"},
		{1, "i"},
	}

	var b strings.Builder

	for _, pair := range table {
		for val >= pair.value {
			b.WriteString(pair.symbol)
			val -= pair.value
		}
	}

	result := b.String()
	if upper {
		result = strings.ToUpper(result)
	}

	return result
}

func formatWords(n *big.Int, lang, caseStyle string) string {
	if lang != formatLanguageEnglish && lang != "" {
		return formatWordsLang(n, lang, caseStyle)
	}

	words := intToEnglishWords(n)

	return applyCase(words, caseStyle)
}

func applyCase(s, caseStyle string) string {
	switch caseStyle {
	case nameUpperCase:
		return strings.ToUpper(s)
	case formatCaseTitle:
		return toTitleCase(s)
	default:
		return strings.ToLower(s)
	}
}

func toTitleCase(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			r, size := utf8.DecodeRuneInString(w)
			words[i] = string(unicode.ToUpper(r)) + strings.ToLower(w[size:])
		}
	}

	return strings.Join(words, " ")
}

func onesWords(index int64) string {
	return [...]string{
		"", "one", "two", "three", "four", "five",
		nameSix, "seven", "eight", "nine", "ten",
		"eleven", "twelve", "thirteen", "fourteen", "fifteen",
		"sixteen", "seventeen", "eighteen", "nineteen",
	}[index]
}

func tensWords(index int64) string {
	return [...]string{
		"", "", "twenty", "thirty", "forty", "fifty",
		"sixty", "seventy", "eighty", "ninety",
	}[index]
}

func intToEnglishWords(n *big.Int) string {
	if n.Sign() == 0 {
		return nameZero
	}

	if n.Sign() < 0 {
		return "minus " + intToEnglishWords(new(big.Int).Neg(n))
	}

	if n.IsInt64() {
		return int64ToEnglishWords(n.Int64())
	}

	return n.String()
}

func int64ToEnglishWords(n int64) string {
	if n == 0 {
		return nameZero
	}

	if n < 0 {
		return "minus " + int64ToEnglishWords(-n)
	}

	var parts []string

	type unit struct {
		val  int64
		name string
	}

	units := []unit{
		{wordTrillion, "trillion"},
		{wordBillion, "billion"},
		{wordMillion, "million"},
		{wordThousand, "thousand"},
	}

	for _, u := range units {
		if n >= u.val {
			parts = append(parts, int64ToEnglishWords(n/u.val)+" "+u.name)
			n %= u.val
		}
	}

	if n >= wordHundred {
		parts = append(parts, onesWords(n/wordHundred)+" hundred")
		n %= wordHundred
	}

	if n > 0 {
		if len(parts) > 0 {
			parts = append(parts, nameAnd)
		}

		if n < wordSmallNumberLimit {
			parts = append(parts, onesWords(n))
		} else {
			s := tensWords(n / numericDecimalRadix)
			if n%numericDecimalRadix > 0 {
				s += " " + onesWords(n%numericDecimalRadix)
			}

			parts = append(parts, s)
		}
	}

	return strings.Join(parts, " ")
}

func applyOrdinalWords(words, lang, caseStyle, suffix string) string {
	if lang == formatLanguageGerman {
		return applyOrdinalWordsDe(words, caseStyle, suffix)
	}

	if lang == formatLanguageFrench {
		return applyOrdinalWordsFr(words, caseStyle, suffix)
	}

	if lang == formatLanguageItalian {
		return applyOrdinalWordsIt(words, caseStyle, suffix)
	}

	result := englishOrdinalWord(words, caseStyle)

	return result
}

func englishOrdinalWord(words, caseStyle string) string {
	parts := strings.Fields(words)
	if len(parts) == 0 {
		return words
	}

	last := strings.ToLower(parts[len(parts)-1])
	ordinal := englishWordToOrdinal(last)

	parts[len(parts)-1] = ordinal
	result := strings.Join(parts, " ")

	return applyCase(result, caseStyle)
}

func englishWordToOrdinal(word string) string {
	irregulars := map[string]string{
		"one":    "first",
		"two":    "second",
		"three":  "third",
		"four":   "fourth",
		"five":   "fifth",
		nameSix:  "sixth",
		"seven":  "seventh",
		"eight":  "eighth",
		"nine":   "ninth",
		"ten":    "tenth",
		"eleven": "eleventh",
		"twelve": "twelfth",
	}
	if ord, ok := irregulars[word]; ok {
		return ord
	}

	if strings.HasSuffix(word, "y") {
		return word[:len(word)-1] + "ieth"
	}

	return word + ordinalEnglishGeneralSuffix
}

func applyOrdinalDecimal(result string, n *big.Int, lang, suffix string) string {
	// The parenthesized part like (-en) is a language hint for ordinals,
	// NOT a literal suffix. We still use language-appropriate ordinal suffixes.
	_ = suffix // language hint, not literal

	if lang != formatLanguageEnglish && lang != "" {
		// For non-English, just append the number — implementation-defined
		return result
	}

	// English ordinal suffixes
	val := new(big.Int).Abs(n)
	mod100 := new(big.Int).Mod(val, big.NewInt(ordinalLastTwoDigitsModulus)).Int64()
	mod10 := new(big.Int).Mod(val, big.NewInt(numericDecimalRadix)).Int64()

	if mod100 >= ordinalTeenFirst && mod100 <= ordinalTeenLast {
		return result + ordinalEnglishGeneralSuffix
	}

	switch mod10 {
	case ordinalFirstLastDigit:
		return result + ordinalEnglishFirstSuffix
	case ordinalSecondLastDigit:
		return result + ordinalEnglishSecondSuffix
	case ordinalThirdLastDigit:
		return result + ordinalEnglishThirdSuffix
	default:
		return result + ordinalEnglishGeneralSuffix
	}
}

func formatIntegerDecimal(n *big.Int, picture string) (string, error) {
	parsed, err := parseIntegerDecimalPicture(picture)
	if err != nil {
		return "", err
	}

	result := n.String()
	if len(result) < parsed.minDigits {
		result = strings.Repeat(formatZeroDigit, parsed.minDigits-len(result)) + result
	}

	if len(parsed.groups) > 1 {
		if integerGroupingRepeats(parsed.groups) {
			result = groupRegularIntegerDigits(result, parsed.groups[len(parsed.groups)-1], parsed.separators[len(parsed.separators)-1])
		} else {
			result = groupIrregularIntegerDigits(result, parsed.groups, parsed.separators)
		}
	}

	if parsed.zeroDigit != '0' {
		result = translateDigits(result, parsed.zeroDigit)
	}

	return result, nil
}

// pictureZeroDigit selects the first decimal digit's Unicode family.
func pictureZeroDigit(picture string) rune {
	for _, r := range picture {
		if unicode.IsDigit(r) {
			return unicodeDigitZero(r)
		}
	}

	return '0'
}

// formatIntegerDecimal formats a number using decimal digits with optional
// grouping separators and zero-padding based on the picture string.
type integerDecimalPicture struct {
	zeroDigit  rune
	groups     []int
	separators []rune
	minDigits  int
}

func parseIntegerDecimalPicture(picture string) (integerDecimalPicture, error) {
	parsed := integerDecimalPicture{zeroDigit: pictureZeroDigit(picture)}
	currentSize := 0
	seenMandatory, optionalAfterMandatory := false, false

	for _, r := range picture {
		switch {
		case r == '#':
			currentSize++
			optionalAfterMandatory = optionalAfterMandatory || seenMandatory
		case isDecimalDigitInRange(r, parsed.zeroDigit):
			currentSize++
			parsed.minDigits++
			seenMandatory = true
		default:
			if currentSize == 0 && len(parsed.groups) == 0 {
				return parsed, &xdm.Error{Code: errCodeFODF1310, Message: fmt.Sprintf("invalid picture: %q", picture)}
			}

			parsed.groups = append(parsed.groups, currentSize)
			parsed.separators = append(parsed.separators, r)
			currentSize = 0
		}
	}

	parsed.groups = append(parsed.groups, currentSize)
	// Structural errors precede the optional-digit ordering error.
	if slices.Contains(parsed.groups, 0) {
		return parsed, &xdm.Error{Code: errCodeFODF1310, Message: fmt.Sprintf("invalid picture: %q", picture)}
	}

	if optionalAfterMandatory {
		return parsed, &xdm.Error{Code: errCodeFODF1310, Message: fmt.Sprintf("invalid picture: '#' after '0' in %q", picture)}
	}

	parsed.minDigits = max(parsed.minDigits, integerMinimumDecimalDigits)

	return parsed, nil
}

func integerGroupingRepeats(groups []int) bool {
	if len(groups) == integerRepeatingGroupPair {
		return true // One separator repeats at its rightmost interval.
	}

	interval := groups[len(groups)-1]
	for _, size := range groups {
		if size != interval {
			return false
		}
	}

	return true
}

func groupRegularIntegerDigits(value string, interval int, separator rune) string {
	digits := []rune(value)

	var result []rune

	for index, digit := range slices.Backward(digits) {
		position := len(digits) - 1 - index
		if position > 0 && position%interval == 0 {
			result = append(result, separator)
		}

		result = append(result, digit)
	}

	slices.Reverse(result)

	return string(result)
}

func groupIrregularIntegerDigits(value string, groups []int, separators []rune) string {
	separatorAt := make(map[int]rune)

	position := 0
	for i := len(groups) - 1; i >= 1; i-- {
		position += groups[i]
		separatorAt[position] = separators[i-1]
	}

	digits := []rune(value)

	var result []rune

	for index, digit := range slices.Backward(digits) {
		position := len(digits) - 1 - index
		if separator, ok := separatorAt[position]; ok {
			result = append(result, separator)
		}

		result = append(result, digit)
	}

	slices.Reverse(result)

	return string(result)
}

// unicodeDigitZero returns the zero digit for the same numeric block as r.
func unicodeDigitZero(r rune) rune {
	if r >= '0' && r <= '9' {
		return '0'
	}
	// Contiguous Nd ranges can contain several adjacent digit alphabets.
	for _, block := range unicode.Nd.R16 {
		if r >= rune(block.Lo) && r <= rune(block.Hi) {
			return r - (r-rune(block.Lo))%formatterDecimalDigitCount
		}
	}

	for _, block := range unicode.Nd.R32 {
		if r >= rune(block.Lo) && r <= rune(block.Hi) { // #nosec G115 -- Unicode Nd tables contain only scalar code points.
			return r - (r-rune(block.Lo))%formatterDecimalDigitCount // #nosec G115 -- Unicode Nd tables contain only scalar code points.
		}
	}

	return '0'
}

func isDecimalDigitInRange(r rune, zero rune) bool {
	return r >= zero && r <= zero+formatterLastDecimalDigitOffset
}

func translateDigits(s string, zeroDigit rune) string {
	var b strings.Builder

	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(zeroDigit + (r - '0'))
		} else {
			b.WriteRune(r)
		}
	}

	return b.String()
}

// Language-specific word formatting

func formatWordsLang(n *big.Int, lang, caseStyle string) string {
	switch lang {
	case formatLanguageGerman:
		return applyCase(intToGermanWords(n), caseStyle)
	case formatLanguageFrench:
		return applyCase(intToFrenchWords(n), caseStyle)
	case formatLanguageItalian:
		return applyCase(intToItalianWords(n), caseStyle)
	default:
		return applyCase(intToEnglishWords(n), caseStyle)
	}
}

func intToGermanWords(n *big.Int) string {
	if n.Sign() == 0 {
		return wordGermanZero
	}

	if !n.IsInt64() {
		return n.String()
	}

	return int64ToGermanWords(n.Int64())
}

func int64ToGermanWords(n int64) string {
	if n == 0 {
		return wordGermanZero
	}

	if n < 0 {
		return "minus " + int64ToGermanWords(-n)
	}

	if n < wordThousand {
		return germanWordsUnderThousand(n)
	}

	if n < wordMillion {
		q := n / wordThousand

		w := ""
		if q == 1 {
			w = nameEin
		} else {
			w = int64ToGermanWords(q)
		}

		w += "tausend"
		if n%wordThousand != 0 {
			w += int64ToGermanWords(n % wordThousand)
		}

		return w
	}

	if n < wordBillion {
		q := n / wordMillion

		w := ""
		if q == 1 {
			w = "eine Million "
		} else {
			w = int64ToGermanWords(q) + " Millionen "
		}

		if n%wordMillion != 0 {
			w += int64ToGermanWords(n % wordMillion)
		}

		return w
	}

	return fmt.Sprintf(formatDecimalPrintf, n)
}

func germanWordsUnderThousand(n int64) string {
	ones := []string{
		"", nameEins, "zwei", nameDrei, "vier", "fünf", "sechs", wordGermanSeven, nameAcht, "neun", "zehn",
		"elf", "zwölf", "dreizehn", "vierzehn", "fünfzehn", "sechzehn", "siebzehn", "achtzehn", "neunzehn",
	}
	tens := []string{"", "", "zwanzig", "dreißig", "vierzig", "fünfzig", "sechzig", "siebzig", "achtzig", "neunzig"}

	if n < wordSmallNumberLimit {
		return ones[n] // #nosec G602 -- The caller passes 1..999; this branch restricts n to 1..19.
	}

	if n < wordHundred {
		if n%numericDecimalRadix == 0 {
			return tens[n/numericDecimalRadix]
		}

		unit := ones[n%numericDecimalRadix]
		if n%numericDecimalRadix == 1 {
			unit = nameEin
		}

		return unit + "und" + tens[n/numericDecimalRadix]
	}

	w := ones[n/wordHundred]
	if w == nameEins {
		w = nameEin
	}

	w += "hundert"
	if n%wordHundred != 0 {
		w += int64ToGermanWords(n % wordHundred)
	}

	return w
}

func applyOrdinalWordsDe(words, caseStyle, suffix string) string {
	base := germanOrdinalWord(strings.ToLower(words))
	if suffix == "" || suffix == ordinalSpellout {
		return applyCase(base, caseStyle)
	}

	return applyCase(germanOrdinalWithSuffix(base, suffix), caseStyle)
}

func germanOrdinalWord(words string) string {
	irregulars := map[string]string{
		wordGermanZero:  "nullte",
		nameEin:         "erste",
		nameEins:        "erste",
		nameDrei:        "dritte",
		wordGermanSeven: "siebte",
		nameAcht:        "achte",
	}
	if ordinal, ok := irregulars[words]; ok {
		return ordinal
	}

	if n, ok := germanWordToNumber(words); ok && n < wordSmallNumberLimit {
		return words + "te"
	}

	return words + "ste"
}

func germanWordToNumber(word string) (int64, bool) {
	units := map[string]int64{
		wordGermanZero: 0, nameEin: 1, nameEins: 1, "zwei": 2, nameDrei: 3, "vier": 4,
		"fünf": 5, "sechs": 6, wordGermanSeven: 7, nameAcht: 8, "neun": 9, "zehn": 10,
		"elf": 11, "zwölf": 12, "dreizehn": 13, "vierzehn": 14, "fünfzehn": 15,
		"sechzehn": 16, "siebzehn": 17, "achtzehn": 18, "neunzehn": 19,
	}
	if n, ok := units[word]; ok {
		return n, true
	}

	tens := []struct {
		word string
		val  int64
	}{
		{"zwanzig", 20},
		{"dreißig", 30},
		{"vierzig", 40},
		{"fünfzig", 50},
		{"sechzig", 60},
		{"siebzig", 70},
		{"achtzig", 80},
		{"neunzig", 90},
	}
	for _, ten := range tens {
		if word == ten.word {
			return ten.val, true
		}

		if !strings.HasSuffix(word, ten.word) {
			continue
		}

		prefix := strings.TrimSuffix(word, ten.word)

		prefix = strings.TrimSuffix(prefix, "und")
		if prefix == "" {
			return ten.val, true
		}

		if unit, ok := units[prefix]; ok && unit > 0 && unit < 10 {
			return ten.val + unit, true
		}
	}

	return 0, false
}

func germanOrdinalWithSuffix(base, suffix string) string {
	sfx := strings.TrimPrefix(suffix, "-")
	if sfx == "" {
		return base
	}

	base = strings.TrimSuffix(base, "e")

	return base + sfx
}

func intToFrenchWords(n *big.Int) string {
	if n.Sign() == 0 {
		return "zéro"
	}

	if !n.IsInt64() {
		return n.String()
	}

	return int64ToFrenchWords(n.Int64())
}

func int64ToFrenchWords(n int64) string {
	if n == 0 {
		return "zéro"
	}

	if n < 0 {
		return "moins " + int64ToFrenchWords(-n)
	}

	ones := []string{
		"", "un", "deux", "trois", "quatre", "cinq", nameSix, "sept", "huit", "neuf", "dix",
		"onze", "douze", "treize", "quatorze", "quinze", "seize", "dix-sept", "dix-huit", "dix-neuf",
	}
	tens := []string{"", "", "vingt", "trente", "quarante", "cinquante", "soixante", "soixante", "quatre-vingt", "quatre-vingt"} //nolint:misspell // French cardinal number, not an English spelling.

	if n < wordSmallNumberLimit {
		return ones[n]
	}

	if n < wordHundred {
		return frenchTensWords(n, ones, tens)
	}

	if n < wordThousand {
		q := n / wordHundred

		w := ""
		if q == 1 {
			w = "cent"
		} else {
			w = ones[q] + " cent"
		}

		r := n % wordHundred
		if r == 0 && q > 1 {
			w += "s"
		}

		if r != 0 {
			w += " " + int64ToFrenchWords(r)
		}

		return w
	}

	if n < wordMillion {
		q := n / wordThousand

		w := ""
		if q == 1 {
			w = "mille"
		} else {
			w = int64ToFrenchWords(q) + " mille"
		}

		r := n % wordThousand
		if r != 0 {
			w += " " + int64ToFrenchWords(r)
		}

		return w
	}

	return fmt.Sprintf(formatDecimalPrintf, n)
}

func frenchTensWords(n int64, ones, tens []string) string {
	t := n / numericDecimalRadix

	u := n % numericDecimalRadix
	if t == frenchCompositeSeventy || t == frenchCompositeNinety {
		u += numericDecimalRadix
	}

	if u == 0 {
		if t == frenchCompositeEighty {
			return "quatre-vingts"
		}

		return tens[t]
	}

	sep := "-"
	if u == frenchConjunctionOne && t != frenchCompositeEighty && t != frenchCompositeNinety {
		sep = " et "
	}

	if u == frenchElevenUnit && t == frenchCompositeSeventy {
		sep = " et "
	}

	return tens[t] + sep + ones[u]
}

func applyOrdinalWordsFr(words, caseStyle, _ string) string {
	lower := strings.ToLower(words)
	if lower == "un" {
		return applyCase("premier", caseStyle)
	}

	base := strings.TrimSuffix(lower, "e")

	return applyCase(base+"ième", caseStyle)
}

func intToItalianWords(n *big.Int) string {
	if n.Sign() == 0 {
		return nameZero
	}

	if !n.IsInt64() {
		return n.String()
	}

	return int64ToItalianWords(n.Int64())
}

func int64ToItalianWords(n int64) string {
	if n == 0 {
		return nameZero
	}

	if n < 0 {
		return "meno " + int64ToItalianWords(-n)
	}

	ones := []string{
		"", "uno", "due", "tre", "quattro", "cinque", "sei", "sette", "otto", "nove", "dieci",
		"undici", "dodici", "tredici", "quattordici", "quindici", "sedici", "diciassette", "diciotto", "diciannove",
	}
	tens := []string{"", "", "venti", "trenta", "quaranta", "cinquanta", "sessanta", "settanta", "ottanta", "novanta"}

	if n < wordSmallNumberLimit {
		return ones[n]
	}

	if n < wordHundred {
		t := n / numericDecimalRadix
		u := n % numericDecimalRadix

		base := tens[t]
		if u == 0 {
			return base
		}

		if u == italianElidedOne || u == italianElidedEight {
			base = base[:len(base)-1]
		}

		return base + ones[u]
	}

	if n < wordThousand {
		q := n / wordHundred

		w := ""
		if q == 1 {
			w = "cento"
		} else {
			w = ones[q] + "cento"
		}

		r := n % wordHundred
		if r != 0 {
			w += int64ToItalianWords(r)
		}

		return w
	}

	if n < wordMillion {
		q := n / wordThousand

		w := ""
		if q == 1 {
			w = "mille"
		} else {
			w = int64ToItalianWords(q) + "mila"
		}

		r := n % wordThousand
		if r != 0 {
			w += int64ToItalianWords(r)
		}

		return w
	}

	return fmt.Sprintf(formatDecimalPrintf, n)
}

func applyOrdinalWordsIt(words, caseStyle, suffix string) string {
	lower := strings.ToLower(words)

	switch suffix {
	case "", ordinalSpellout, ordinalSpelloutMasculine, ordinalMasculineSuffix:
		return applyCase(italianOrdinalWord(lower, ordinalMasculine), caseStyle)
	case ordinalSpelloutFeminine, ordinalFeminineSuffix:
		return applyCase(italianOrdinalWord(lower, ordinalFeminine), caseStyle)
	default:
		n := italianWordToNumber(lower)
		if n == 0 {
			return applyCase(italianOrdinalWord(lower, ordinalMasculine), caseStyle)
		}

		return applyCase(italianOrdinalWithSuffix(n, suffix), caseStyle)
	}
}

func italianOrdinalWord(words string, feminine bool) string {
	n := italianWordToNumber(words)
	if n != 0 {
		if feminine {
			if s, ok := map[int64]string{
				1: "prima", 2: "seconda", 3: "terza", 4: "quarta", 5: "quinta",
				6: "sesta", 7: "settima", 8: "ottava", 9: "nona", 10: "decima",
			}[n]; ok {
				return s
			}
		} else {
			if s, ok := map[int64]string{
				1: "primo", 2: "secondo", 3: "terzo", 4: "quarto", 5: "quinto",
				6: "sesto", 7: "settimo", 8: "ottavo", 9: "nono", 10: "decimo",
			}[n]; ok {
				return s
			}
		}
	}

	stem := strings.TrimRight(words, "aeiou")
	if stem == "" {
		stem = words
	}

	if feminine {
		return stem + "esima"
	}

	return stem + "esimo"
}

func italianWordToNumber(word string) int64 {
	italianNumbers := map[string]int64{
		"uno": 1, "due": 2, "tre": 3, "quattro": 4, "cinque": 5,
		"sei": 6, "sette": 7, "otto": 8, "nove": 9, "dieci": 10,
	}
	if n, ok := italianNumbers[word]; ok {
		return n
	}

	return 0
}

func italianOrdinalWithSuffix(n int64, suffix string) string {
	// Suffix starts with '-' for gender marker, e.g., "-o" for masculine, "-a" for feminine
	sfx := strings.TrimPrefix(suffix, "-")

	stems := map[int64]string{
		1: "prim", 2: "second", 3: "terz", 4: "quart", 5: "quint",
		6: "sest", 7: "settim", 8: "ottav", 9: "non", 10: "decim",
	}
	if stem, ok := stems[n]; ok {
		return stem + sfx
	}

	return fmt.Sprintf(italianOrdinalDecimalFormat, n)
}
