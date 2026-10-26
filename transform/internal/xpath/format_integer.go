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

const wordGermanSeven = "sieben"

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

	lang := "en"
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

	result, err := formatIntegerPicture(n, picture, lang)
	if err != nil {
		return nil, err
	}

	return xdm.SingleString(result), nil
}

func isSupportedIntegerLanguage(lang string) bool {
	switch lang {
	case "en", "de", "fr", "it":
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
	case "A":
		result = formatAlpha(absN, true)
	case "a":
		result = formatAlpha(absN, false)
	case "I":
		result = formatRoman(absN, true)
	case "i":
		result = formatRoman(absN, false)
	case "W":
		result = formatWords(absN, lang, nameUpper2)
		if ordinal {
			result = applyOrdinalWords(result, lang, nameUpper2, ordSuffix)
		}
	case "w":
		result = formatWords(absN, lang, nameLower)
		if ordinal {
			result = applyOrdinalWords(result, lang, nameLower, ordSuffix)
		}
	case "Ww":
		result = formatWords(absN, lang, "title")
		if ordinal {
			result = applyOrdinalWords(result, lang, "title", ordSuffix)
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

// FormatGreekAlphabetic uses the 24-letter Greek alphabet, excluding the
// unassigned capital U+03A2 and the context-specific lowercase final sigma.
// It is shared with XSLT numbering so both execution paths use the same digits.
func FormatGreekAlphabetic(n *big.Int, upper bool) string {
	if n.Sign() <= 0 {
		return n.String()
	}

	alphabet := []rune("αβγδεζηθικλμνξοπρστυφχψω")
	if upper {
		alphabet = []rune("ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ")
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
	case r >= 0x03B1 && r <= 0x03C9:
		return fmtTokenGreekLower
	case r >= 0x0391 && r <= 0x03A9:
		return fmtTokenGreekUpper
	case r >= 0x2460 && r <= 0x2473:
		return fmtTokenCircled
	case r >= 0x2474 && r <= 0x2487:
		return fmtTokenParenthesized
	case r >= 0x2488 && r <= 0x249B:
		return fmtTokenFullstopDigit
	default:
		return fmtTokenUnknown
	}
}

func formatSpecialToken(n *big.Int, primary string, kind formatTokenKind) (string, error) {
	switch kind {
	case fmtTokenGreekLower:
		return FormatGreekAlphabetic(n, false), nil
	case fmtTokenGreekUpper:
		return FormatGreekAlphabetic(n, true), nil
	case fmtTokenCJK:
		return formatCJK(n), nil
	case fmtTokenCircled:
		return formatSequentialSymbol(n, 0x2460, 20), nil
	case fmtTokenParenthesized:
		return formatSequentialSymbol(n, 0x2474, 20), nil
	case fmtTokenFullstopDigit:
		return formatSequentialSymbol(n, 0x2488, 20), nil
	case fmtTokenUnknown:
		// Spec: if the format token is not recognized, use decimal fallback
		return formatIntegerDecimal(n, "1")
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

	return string(startCodepoint + rune(n.Int64()-1))
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
		groups = append(groups, n%10000)
		n /= 10000
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
		return "0"
	}

	val := new(big.Int).Set(n)
	one := big.NewInt(1)
	twentySix := big.NewInt(26)

	var digits []rune

	base := 'a'
	if upper {
		base = 'A'
	}

	for val.Sign() > 0 {
		val.Sub(val, one)

		mod := new(big.Int)
		val.DivMod(val, twentySix, mod)
		digits = append([]rune{base + rune(mod.Int64())}, digits...)
	}

	return string(digits)
}

func formatRoman(n *big.Int, upper bool) string {
	if n.Sign() == 0 {
		return "0"
	}

	val := n.Int64()
	if val < 0 {
		val = -val
	}

	if val > 10000 {
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
	if lang != "en" && lang != "" {
		return formatWordsLang(n, lang, caseStyle)
	}

	words := intToEnglishWords(n)

	return applyCase(words, caseStyle)
}

func applyCase(s, caseStyle string) string {
	switch caseStyle {
	case nameUpper2:
		return strings.ToUpper(s)
	case "title":
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
		{1000000000000, "trillion"},
		{1000000000, "billion"},
		{1000000, "million"},
		{1000, "thousand"},
	}

	for _, u := range units {
		if n >= u.val {
			parts = append(parts, int64ToEnglishWords(n/u.val)+" "+u.name)
			n %= u.val
		}
	}

	if n >= 100 {
		parts = append(parts, onesWords(n/100)+" hundred")
		n %= 100
	}

	if n > 0 {
		if len(parts) > 0 {
			parts = append(parts, nameAnd)
		}

		if n < 20 {
			parts = append(parts, onesWords(n))
		} else {
			s := tensWords(n / 10)
			if n%10 > 0 {
				s += " " + onesWords(n%10)
			}

			parts = append(parts, s)
		}
	}

	return strings.Join(parts, " ")
}

func applyOrdinalWords(words, lang, caseStyle, suffix string) string {
	if lang == "de" {
		return applyOrdinalWordsDe(words, caseStyle, suffix)
	}

	if lang == "fr" {
		return applyOrdinalWordsFr(words, caseStyle, suffix)
	}

	if lang == "it" {
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

	return word + "th"
}

func applyOrdinalDecimal(result string, n *big.Int, lang, suffix string) string {
	// The parenthesized part like (-en) is a language hint for ordinals,
	// NOT a literal suffix. We still use language-appropriate ordinal suffixes.
	_ = suffix // language hint, not literal

	if lang != "en" && lang != "" {
		// For non-English, just append the number — implementation-defined
		return result
	}

	// English ordinal suffixes
	val := new(big.Int).Abs(n)
	mod100 := new(big.Int).Mod(val, big.NewInt(100)).Int64()
	mod10 := new(big.Int).Mod(val, big.NewInt(10)).Int64()

	if mod100 >= 11 && mod100 <= 13 {
		return result + "th"
	}

	switch mod10 {
	case 1:
		return result + "st"
	case 2:
		return result + "nd"
	case 3:
		return result + "rd"
	default:
		return result + "th"
	}
}

func formatIntegerDecimal(n *big.Int, picture string) (string, error) {
	parsed, err := parseIntegerDecimalPicture(picture)
	if err != nil {
		return "", err
	}

	result := n.String()
	if len(result) < parsed.minDigits {
		result = strings.Repeat("0", parsed.minDigits-len(result)) + result
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

	parsed.minDigits = max(parsed.minDigits, 1)

	return parsed, nil
}

func integerGroupingRepeats(groups []int) bool {
	if len(groups) == 2 {
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
	// Unicode decimal digit blocks are consecutive groups of 10.
	// Walk backwards from r to find the zero.
	for z := r; z >= r-9 && z >= 0; z-- {
		if !unicode.IsDigit(z) {
			return z + 1
		}
	}

	return r - 9 // Fallback: assume it's a digit 9
}

func isDecimalDigitInRange(r rune, zero rune) bool {
	return r >= zero && r <= zero+9
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
	case "de":
		return applyCase(intToGermanWords(n), caseStyle)
	case "fr":
		return applyCase(intToFrenchWords(n), caseStyle)
	case "it":
		return applyCase(intToItalianWords(n), caseStyle)
	default:
		return applyCase(intToEnglishWords(n), caseStyle)
	}
}

func intToGermanWords(n *big.Int) string {
	if n.Sign() == 0 {
		return jsonKindNull
	}

	if !n.IsInt64() {
		return n.String()
	}

	return int64ToGermanWords(n.Int64())
}

func int64ToGermanWords(n int64) string {
	if n == 0 {
		return jsonKindNull
	}

	if n < 0 {
		return "minus " + int64ToGermanWords(-n)
	}

	if n < 1000 {
		return germanWordsUnderThousand(n)
	}

	if n < 1000000 {
		q := n / 1000

		w := ""
		if q == 1 {
			w = nameEin
		} else {
			w = int64ToGermanWords(q)
		}

		w += "tausend"
		if n%1000 != 0 {
			w += int64ToGermanWords(n % 1000)
		}

		return w
	}

	if n < 1000000000 {
		q := n / 1000000

		w := ""
		if q == 1 {
			w = "eine Million "
		} else {
			w = int64ToGermanWords(q) + " Millionen "
		}

		if n%1000000 != 0 {
			w += int64ToGermanWords(n % 1000000)
		}

		return w
	}

	return fmt.Sprintf("%d", n)
}

func germanWordsUnderThousand(n int64) string {
	ones := []string{
		"", nameEins, "zwei", nameDrei, "vier", "fünf", "sechs", wordGermanSeven, nameAcht, "neun", "zehn",
		"elf", "zwölf", "dreizehn", "vierzehn", "fünfzehn", "sechzehn", "siebzehn", "achtzehn", "neunzehn",
	}
	tens := []string{"", "", "zwanzig", "dreißig", "vierzig", "fünfzig", "sechzig", "siebzig", "achtzig", "neunzig"}

	if n < 20 {
		return ones[n]
	}

	if n < 100 {
		if n%10 == 0 {
			return tens[n/10]
		}

		unit := ones[n%10]
		if n%10 == 1 {
			unit = nameEin
		}

		return unit + "und" + tens[n/10]
	}

	w := ones[n/100]
	if w == nameEins {
		w = nameEin
	}

	w += "hundert"
	if n%100 != 0 {
		w += int64ToGermanWords(n % 100)
	}

	return w
}

func applyOrdinalWordsDe(words, caseStyle, suffix string) string {
	base := germanOrdinalWord(strings.ToLower(words))
	if suffix == "" || suffix == "%spellout-ordinal" {
		return applyCase(base, caseStyle)
	}

	return applyCase(germanOrdinalWithSuffix(base, suffix), caseStyle)
}

func germanOrdinalWord(words string) string {
	irregulars := map[string]string{
		jsonKindNull:    "nullte",
		nameEin:         "erste",
		nameEins:        "erste",
		nameDrei:        "dritte",
		wordGermanSeven: "siebte",
		nameAcht:        "achte",
	}
	if ordinal, ok := irregulars[words]; ok {
		return ordinal
	}

	if n, ok := germanWordToNumber(words); ok && n < 20 {
		return words + "te"
	}

	return words + "ste"
}

func germanWordToNumber(word string) (int64, bool) {
	units := map[string]int64{
		jsonKindNull: 0, nameEin: 1, nameEins: 1, "zwei": 2, nameDrei: 3, "vier": 4,
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
	tens := []string{"", "", "vingt", "trente", "quarante", "cinquante", "soixante", "soixante", "quatre-vingt", "quatre-vingt"}

	if n < 20 {
		return ones[n]
	}

	if n < 100 {
		return frenchTensWords(n, ones, tens)
	}

	if n < 1000 {
		q := n / 100

		w := ""
		if q == 1 {
			w = "cent"
		} else {
			w = ones[q] + " cent"
		}

		r := n % 100
		if r == 0 && q > 1 {
			w += "s"
		}

		if r != 0 {
			w += " " + int64ToFrenchWords(r)
		}

		return w
	}

	if n < 1000000 {
		q := n / 1000

		w := ""
		if q == 1 {
			w = "mille"
		} else {
			w = int64ToFrenchWords(q) + " mille"
		}

		r := n % 1000
		if r != 0 {
			w += " " + int64ToFrenchWords(r)
		}

		return w
	}

	return fmt.Sprintf("%d", n)
}

func frenchTensWords(n int64, ones, tens []string) string {
	t := n / 10

	u := n % 10
	if t == 7 || t == 9 {
		u += 10
	}

	if u == 0 {
		if t == 8 {
			return "quatre-vingts"
		}

		return tens[t]
	}

	sep := "-"
	if u == 1 && t != 8 && t != 9 {
		sep = " et "
	}

	if u == 11 && t == 7 {
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

	if n < 20 {
		return ones[n]
	}

	if n < 100 {
		t := n / 10
		u := n % 10

		base := tens[t]
		if u == 0 {
			return base
		}

		if u == 1 || u == 8 {
			base = base[:len(base)-1]
		}

		return base + ones[u]
	}

	if n < 1000 {
		q := n / 100

		w := ""
		if q == 1 {
			w = "cento"
		} else {
			w = ones[q] + "cento"
		}

		r := n % 100
		if r != 0 {
			w += int64ToItalianWords(r)
		}

		return w
	}

	if n < 1000000 {
		q := n / 1000

		w := ""
		if q == 1 {
			w = "mille"
		} else {
			w = int64ToItalianWords(q) + "mila"
		}

		r := n % 1000
		if r != 0 {
			w += int64ToItalianWords(r)
		}

		return w
	}

	return fmt.Sprintf("%d", n)
}

func applyOrdinalWordsIt(words, caseStyle, suffix string) string {
	lower := strings.ToLower(words)

	switch suffix {
	case "", "%spellout-ordinal", "%spellout-ordinal-masculine", "-o":
		return applyCase(italianOrdinalWord(lower, false), caseStyle)
	case "%spellout-ordinal-feminine", "-a":
		return applyCase(italianOrdinalWord(lower, true), caseStyle)
	default:
		n := italianWordToNumber(lower)
		if n == 0 {
			return applyCase(italianOrdinalWord(lower, false), caseStyle)
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

	return fmt.Sprintf("%d°", n)
}
