// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexical"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// ordinalSystem describes a Unicode numbering system with potentially
// non-contiguous ranges and a special zero character.
type ordinalSystem struct {
	oneChar rune   // the character representing 1
	zero    rune   // the character representing 0 (0 if none)
	ranges  []rune // pairs of (first, last) codepoints for contiguous ranges starting at 1
}

type numberFormatOptions struct {
	picture           string
	groupingSeparator string
	groupingSize      int
	lang              string
	ordinal           string
}

// numberMemo caches a backward count for level="single" or level="any".
// A later walk by the same instruction may add the cached count when it reaches
// node. Reuse requires variable-free patterns and an unchanged tree; validation
// or annotation stripping of cached documents clears numberMemos.
//
// For level="any", a from match stops the walk before a memo beyond that match
// can be reached. For level="single", numberWithinFrom checks containment before
// reuse. Without a count pattern, reuse also requires the selected node's kind
// and expanded name. Attribute and namespace starts have no preceding siblings.
type numberMemo struct {
	node  xdm.Node
	count int
	kind  xdm.ElementType
	local string
	uri   string
}

func (ec *execContext) execNumber(ctx context.Context, inst *numberInst) error {
	node, err := ec.resolveNumberNode(ctx, inst)
	if err != nil {
		return err
	}

	var numbers []*big.Int

	if inst.Value != nil {
		var compatNaN bool

		numbers, compatNaN, err = ec.evaluateNumberValues(ctx, inst, node)
		if err != nil {
			return err
		}

		if compatNaN {
			return ec.addNode(ec.resultDoc.CreateText(lexicon.FloatNaN))
		}
	} else {
		for _, n := range ec.numberNodeValues(ctx, inst, node) {
			numbers = append(numbers, big.NewInt(int64(n)))
		}
	}

	if err := execNumberStartAt(ctx, inst, ec, numbers); err != nil {
		return err
	}

	options, err := ec.evaluateNumberFormatOptions(ctx, inst)
	if err != nil {
		return err
	}

	formatted := formatBigNumberList(numbers, options.picture, options.groupingSeparator, options.groupingSize, options.lang, options.ordinal)

	return ec.addNode(ec.resultDoc.CreateText(formatted))
}

func parseStartAt(value string) ([]*big.Int, bool) {
	parts := strings.FieldsFunc(strings.Trim(value, " \t\r\n"), func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' })
	if len(parts) == 0 {
		return nil, false
	}

	numbers := make([]*big.Int, len(parts))
	for i, part := range parts {
		if !decimalIntegerLexical(part, false) {
			return nil, false
		}

		numbers[i], _ = new(big.Int).SetString(part, 10)
	}

	return numbers, true
}

func decimalIntegerLexical(value string, allowPlus bool) bool {
	if value == "" {
		return false
	}

	if value[0] == '-' || allowPlus && value[0] == '+' {
		value = value[1:]
	}

	if value == "" {
		return false
	}

	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}

	return true
}

func validNumberOption(name, value string) bool {
	value = strings.Trim(value, " \t\r\n")

	switch name {
	case nameGroupingSize:
		return decimalIntegerLexical(value, true)
	case nameLetterValue:
		return value == "alphabetic" || value == "traditional"
	case lexicon.AttrLang:
		return value == "" || lexical.ValidLanguage(value)
	case nameStartAt:
		_, valid := parseStartAt(value)
		return valid
	default:
		return true
	}
}

func isAlphanumeric(r rune) bool {
	if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
		return true
	}

	return r > 127 && (unicode.IsLetter(r) || unicode.IsNumber(r))
}

func formatSingleNumber(num int, token string, groupSep string, groupSize int, lang string, ordinal string) string {
	if formatted, ok := formatWordNumber(int64(num), token, lang, ordinal); ok {
		return formatted
	}

	switch token {
	case "a":
		return toLowerAlpha(int64(num))
	case "A":
		return toUpperAlpha(int64(num))
	case "i":
		return strings.ToLower(toRoman(num))
	case "I":
		return toRoman(num)
	default:
		runes := []rune(token)
		firstRune := runes[0]

		// Non-ASCII digit: use as base of a decimal numbering system
		// (e.g., ٠ = U+0660 for Arabic-Indic digits)
		if firstRune > 127 && unicode.IsDigit(firstRune) {
			s := formatWithDigitSystem(num, digitZeroOf(firstRune), len(runes))
			if groupSep != "" && groupSize > 0 {
				s = applyGroupingSeparator(s, groupSep, groupSize)
			}

			return s
		}
		// Non-ASCII number (not a digit): ordinal numbering from that codepoint
		// (e.g., ① = U+2460 for circled digits)
		if firstRune > 127 && unicode.IsNumber(firstRune) {
			return formatWithOrdinalSystem(num, firstRune)
		}
		// Non-ASCII letter: alphabetic numbering from that codepoint
		// (e.g., α = U+03B1 for Greek lowercase: α, β, γ, ..., ω, αα, αβ, ...)
		if firstRune > 127 && unicode.IsLetter(firstRune) {
			return formatWithAlphaSystem(int64(num), firstRune)
		}

		// ASCII numeric format: determine minimum width from token (e.g., "001" = width 3)
		minWidth := len(token)

		s := strconv.Itoa(num)
		if padding := minWidth - len(s); padding > 0 {
			s = strings.Repeat("0", padding) + s
		}

		if groupSep != "" && groupSize > 0 {
			s = applyGroupingSeparator(s, groupSep, groupSize)
		}

		if ordinal != "" {
			s += numericOrdinalSuffix(num, lang)
		}

		return s
	}
}

func formatWordNumber(num int64, token string, lang string, ordinal string) (string, bool) {
	switch token {
	case "w":
		return numberToWordsLang(num, "lower", lang, ordinal), true
	case "W":
		return numberToWordsLang(num, "upper", lang, ordinal), true
	case "Ww":
		return numberToWordsLang(num, "title", lang, ordinal), true
	default:
		return "", false
	}
}

func formatAlphabeticNumber(num int64, token string) (string, bool) {
	switch token {
	case "a":
		return toLowerAlpha(num), true
	case "A":
		return toUpperAlpha(num), true
	}

	runes := []rune(token)
	if len(runes) > 0 && runes[0] > 127 && unicode.IsLetter(runes[0]) {
		return formatWithAlphaSystem(num, runes[0]), true
	}

	return "", false
}

// numericOrdinalSuffix returns the suffix for a numeric ordinal (e.g., "st", "nd", "rd", "th").
func numericOrdinalSuffix(num int, _ string) string {
	// Default to English ordinal suffixes
	n := num % 100
	if n >= 11 && n <= 13 {
		return "th"
	}

	switch num % 10 {
	case 1:
		return "st"
	case 2:
		return "nd"
	case 3:
		return "rd"
	default:
		return "th"
	}
}

func numericOrdinalSuffixBig(num *big.Int, _ string) string {
	n := new(big.Int).Rem(num, big.NewInt(100)).Int64()
	if n >= 11 && n <= 13 {
		return "th"
	}

	switch n % 10 {
	case 1:
		return "st"
	case 2:
		return "nd"
	case 3:
		return "rd"
	default:
		return "th"
	}
}

// lookupAlphabetLength maps the start character of well-known alphabets to their
// standard length, preventing over-counting into diacritical variants.
func lookupAlphabetLength(key rune) (int, bool) {
	switch key {
	case 'а', 'А':
		return 32, true
	}

	var zero int

	return zero, false
}

// formatWithAlphaSystem formats using alphabetic numbering (like a-z but with
// non-ASCII letters). Wraps at the end of the alphabet:
// Greek numbering uses the shared 24-letter alphabet; other alphabets use
// their configured contiguous range.
func formatWithAlphaSystem(num int64, start rune) string {
	if start == 'α' || start == 'Α' {
		return xpath.FormatGreekAlphabetic(big.NewInt(num), start == 'Α')
	}

	if num <= 0 {
		return strconv.FormatInt(num, 10)
	}

	// Use known alphabet length if available, otherwise detect
	seqLen, ok := lookupAlphabetLength(start)
	if !ok {
		seqLen = 0
		for r := start; unicode.IsLetter(r); r++ {
			seqLen++
			if seqLen > 100 {
				break // safety cap
			}
		}
	}

	if seqLen == 0 {
		return strconv.FormatInt(num, 10)
	}

	// Convert to base-N alphabetic representation (1-based, like a=1, b=2, ..., z=26, aa=27)
	var result []rune

	n := num
	for n > 0 {
		n-- // convert to 0-based
		result = append([]rune{start + rune(n%int64(seqLen))}, result...)
		n /= int64(seqLen)
	}

	return string(result)
}

// formatBigNumberList formats a list of *big.Int values according to an XSLT
// format string, supporting all format tokens (decimal, alphabetic, roman,
// non-ASCII digit systems) with prefix, suffix, separators, and grouping.
func formatBigNumberList(bigNums []*big.Int, format string, groupSep string, groupSize int, lang string, ordinal string) string {
	picture := parseNumberListPicture(format)

	var buf strings.Builder
	buf.WriteString(picture.prefix)

	for index, num := range bigNums {
		if index > 0 {
			buf.WriteString(picture.separator(index))
		}

		token := picture.tokens[min(index, len(picture.tokens)-1)].format
		buf.WriteString(formatNumberListToken(num, token, groupSep, groupSize, lang, ordinal))
	}

	buf.WriteString(picture.suffix)

	return buf.String()
}

func parseNumberListPicture(format string) numberListPicture {
	runes := []rune(format)

	var (
		prefix, suffix string
		tokens         []numberListToken
	)

	i := 0
	for i < len(runes) && !isAlphanumeric(runes[i]) {
		i++
	}

	prefix = string(runes[:i])

	for i < len(runes) {
		start := i
		for i < len(runes) && isAlphanumeric(runes[i]) {
			i++
		}

		if start == i {
			break
		}

		fmtStr := string(runes[start:i])

		sepStart := i
		for i < len(runes) && !isAlphanumeric(runes[i]) {
			i++
		}

		sep := string(runes[sepStart:i])

		if i >= len(runes) {
			tokens = append(tokens, numberListToken{format: fmtStr})
			suffix = sep
		} else {
			tokens = append(tokens, numberListToken{format: fmtStr, separator: sep})
		}
	}

	if len(tokens) == 0 {
		tokens = []numberListToken{{format: "1"}}
		suffix = prefix
	}

	defaultSep := "."
	if len(tokens) > 1 {
		defaultSep = tokens[len(tokens)-2].separator
		if defaultSep == "" {
			defaultSep = "."
		}
	}

	return numberListPicture{prefix: prefix, suffix: suffix, tokens: tokens, defaultSeparator: defaultSep}
}

func formatNumberListToken(num *big.Int, token, groupSep string, groupSize int, lang, ordinal string) string {
	if token == "α" || token == "Α" {
		return xpath.FormatGreekAlphabetic(num, token == "Α")
	}
	// Word and alphabetic formats support all int64 values on any architecture.
	// Other non-decimal formats require a native int.
	if num.IsInt64() {
		n64 := num.Int64()
		if formatted, ok := formatWordNumber(n64, token, lang, ordinal); ok {
			return formatted
		}

		if formatted, ok := formatAlphabeticNumber(n64, token); ok {
			return formatted
		}

		if n := int(n64); int64(n) == n64 {
			return formatSingleNumber(n, token, groupSep, groupSize, lang, ordinal)
		}
	}

	return formatBigSingleNumber(num, token, groupSep, groupSize, lang, ordinal)
}

// formatBigSingleNumber formats a *big.Int using a decimal format token.
// Supports ASCII digits with grouping and non-ASCII digit systems.
func formatBigSingleNumber(num *big.Int, token string, groupSep string, groupSize int, lang string, ordinal string) string {
	runes := []rune(token)
	firstRune := runes[0]
	// Roman numbering falls back to plain decimal outside its bounded range.
	if token == "i" || token == "I" {
		return num.String()
	}

	// Non-ASCII digit system (e.g., Arabic-Indic ٠)
	if firstRune > 127 && unicode.IsDigit(firstRune) {
		s := formatBigWithDigitSystem(num, digitZeroOf(firstRune), len(runes))
		if groupSep != "" && groupSize > 0 {
			s = applyGroupingSeparator(s, groupSep, groupSize)
		}

		return s
	}
	// Non-ASCII number tokens use a bounded ordinal system. A number beyond
	// that range falls back to plain decimal without a numeric ordinal suffix.
	if firstRune > 127 && unicode.IsNumber(firstRune) {
		return num.String()
	}

	// Default: decimal with optional grouping and min-width
	minWidth := len(token)

	s := num.String()
	if padding := minWidth - len(s); padding > 0 {
		s = strings.Repeat("0", padding) + s
	}

	if groupSep != "" && groupSize > 0 {
		s = applyGroupingSeparator(s, groupSep, groupSize)
	}

	if ordinal != "" {
		s += numericOrdinalSuffixBig(num, lang)
	}

	return s
}

// formatBigWithDigitSystem formats a *big.Int using a non-ASCII decimal digit
// system (e.g., Arabic-Indic digits starting at U+0660).
func formatBigWithDigitSystem(num *big.Int, zero rune, minWidth int) string {
	if num.Sign() < 0 {
		return "-" + formatBigWithDigitSystem(new(big.Int).Neg(num), zero, minWidth)
	}

	return localizeDecimalDigits(num.String(), zero, minWidth)
}

// digitZeroOf returns the zero digit for the Unicode digit block containing r.
func digitZeroOf(r rune) rune {
	// Unicode digit blocks are groups of 10 consecutive codepoints.
	// The zero digit is always at an offset of (r - digit_value) from r.
	// For standard digit blocks, digit_value = r % 10 when aligned at 0.
	// Use unicode.Digit to get the numeric value.
	for d := rune(0); d <= 9; d++ {
		if r-d >= 0 && unicode.IsDigit(r-d) {
			// Verify this is actually the zero of the block
			candidate := r - d
			if !unicode.IsDigit(candidate-1) || candidate == 0 {
				return candidate
			}
		}
	}
	// Fallback: assume digit value is r mod 10 offset
	return r - (r % 10)
}

// formatWithDigitSystem formats a number using a decimal digit system
// starting at the given zero codepoint.
func formatWithDigitSystem(num int, zero rune, minWidth int) string {
	negative := num < 0

	var magnitude uint
	if negative {
		magnitude = uint(-(num + 1)) + 1
	} else {
		magnitude = uint(num)
	}

	formatted := localizeDecimalDigits(strconv.FormatUint(uint64(magnitude), 10), zero, minWidth)
	if negative {
		return "-" + formatted
	}

	return formatted
}

// localizeDecimalDigits pads a nonnegative ASCII magnitude while writing each
// output digit once. Repeated string/rune-slice prepends made wide pictures
// quadratic even though the final representation is linear in the width.
func localizeDecimalDigits(digits string, zero rune, minWidth int) string {
	var out strings.Builder

	out.Grow(max(minWidth, len(digits)) * utf8.RuneLen(zero))

	for padding := minWidth - len(digits); padding > 0; padding-- {
		out.WriteRune(zero)
	}

	for _, digit := range digits {
		out.WriteRune(zero + digit - '0')
	}

	return out.String()
}

// lookupOrdinalSystem maps the "1" character to its ordinal system definition.
func lookupOrdinalSystem(key rune) (ordinalSystem, bool) {
	switch key {
	case 0x2460:
		return ordinalSystem{oneChar: 0x2460, zero: 0x24EA, ranges: []rune{0x2460, 0x2473, 0x3251, 0x325F, 0x32B1, 0x32BF}}, true
	case 0x2474:
		return ordinalSystem{oneChar: 0x2474, zero: 0, ranges: []rune{0x2474, 0x2487}}, true
	case 0x2488:
		return ordinalSystem{oneChar: 0x2488, zero: 0x1F100, ranges: []rune{0x2488, 0x249B}}, true
	case 0x24F5:
		return ordinalSystem{oneChar: 0x24F5, zero: 0, ranges: []rune{0x24F5, 0x24FE}}, true
	case 0x2776:
		return ordinalSystem{oneChar: 0x2776, zero: 0x24FF, ranges: []rune{0x2776, 0x277F, 0x24EB, 0x24F4}}, true
	case 0x278A:
		return ordinalSystem{oneChar: 0x278A, zero: 0x1F10C, ranges: []rune{0x278A, 0x2793}}, true
	case 0x2780:
		return ordinalSystem{oneChar: 0x2780, zero: 0x1F10B, ranges: []rune{0x2780, 0x2789}}, true
	case 0x3220:
		return ordinalSystem{oneChar: 0x3220, zero: 0, ranges: []rune{0x3220, 0x3229}}, true
	case 0x3280:
		return ordinalSystem{oneChar: 0x3280, zero: 0, ranges: []rune{0x3280, 0x3289}}, true
	case 0x10107:
		return ordinalSystem{oneChar: 0x10107, zero: 0, ranges: []rune{0x10107, 0x10110}}, true
	case 0x102E1:
		return ordinalSystem{oneChar: 0x102E1, zero: 0, ranges: []rune{0x102E1, 0x102EA}}, true
	case 0x10E60:
		return ordinalSystem{oneChar: 0x10E60, zero: 0, ranges: []rune{0x10E60, 0x10E69}}, true
	case 0x11052:
		return ordinalSystem{oneChar: 0x11052, zero: 0, ranges: []rune{0x11052, 0x1105B}}, true
	case 0x111E1:
		return ordinalSystem{oneChar: 0x111E1, zero: 0, ranges: []rune{0x111E1, 0x111EA}}, true
	case 0x1D360:
		return ordinalSystem{oneChar: 0x1D360, zero: 0, ranges: []rune{0x1D360, 0x1D368}}, true
	case 0x1E8C7:
		return ordinalSystem{oneChar: 0x1E8C7, zero: 0, ranges: []rune{0x1E8C7, 0x1E8CF}}, true
	case 0x1F102:
		return ordinalSystem{oneChar: 0x1F102, zero: 0x1F101, ranges: []rune{0x1F102, 0x1F10A}}, true
	}

	var zero ordinalSystem

	return zero, false
}

// formatWithOrdinalSystem formats using a known ordinal numbering system.
// Falls back to decimal when the number exceeds the system's range.
func formatWithOrdinalSystem(num int, start rune) string {
	if num < 0 {
		return strconv.Itoa(num)
	}

	sys, ok := lookupOrdinalSystem(start)
	if !ok {
		// Unknown system: detect range by finding the block boundaries.
		// First check if start-1 is also a numbering character (the zero).
		hasZero := false

		prev := start - 1
		if prev > 0 && (unicode.IsNumber(prev) || unicode.IsLetter(prev)) {
			hasZero = true
		}
		// Count consecutive same-category characters from start, capped at 10.
		rangeLen := ordinalRangeLength(start)
		// If we have a zero predecessor, the system is (zero, 1..N).
		// The range from start to the end of the system is one less than
		// the total block size starting at zero.
		if hasZero {
			totalFromZero := ordinalRangeLength(prev)

			rangeFromStart := totalFromZero - 1
			if rangeFromStart < rangeLen {
				rangeLen = rangeFromStart
			}
		}

		if num == 0 {
			if hasZero {
				return string(prev)
			}

			return strconv.Itoa(0)
		}

		if num <= rangeLen {
			return string(start + rune(num-1))
		}

		return strconv.Itoa(num)
	}

	if num == 0 {
		if sys.zero != 0 {
			return string(sys.zero)
		}

		return strconv.Itoa(0)
	}

	// Map num to the correct codepoint across potentially non-contiguous ranges
	pos := num // 1-based position in the sequence

	for i := 0; i+1 < len(sys.ranges); i += 2 {
		rangeStart := sys.ranges[i]
		rangeEnd := sys.ranges[i+1]

		rangeLen := int(rangeEnd - rangeStart + 1)
		if pos <= rangeLen {
			return string(rangeStart + rune(pos-1))
		}

		pos -= rangeLen
	}

	// Number exceeds ordinal system range: fall back to decimal
	return strconv.Itoa(num)
}

// ordinalRangeLength returns how many consecutive characters starting at r
// belong to the same Unicode category (Number or Letter). This determines
// the range of an ordinal numbering system. For unknown systems, the range
// is capped at 10 to avoid accidentally including characters from adjacent
// but unrelated numbering systems.
func ordinalRangeLength(r rune) int {
	isNum := unicode.IsNumber(r)
	count := 0

	for c := r; ; c++ {
		if isNum {
			if !unicode.IsNumber(c) {
				break
			}
		} else {
			if !unicode.IsLetter(c) {
				break
			}
		}

		count++
		if count >= 10 {
			break // cap unknown systems at 10
		}
	}

	return count
}

func applyGroupingSeparator(s string, sep string, size int) string {
	// Insert separator from right to left every 'size' digits
	if size <= 0 || sep == "" {
		return s
	}

	runes := []rune(s)

	var result []rune

	for i, j := len(runes)-1, 0; i >= 0; i, j = i-1, j+1 {
		if j > 0 && j%size == 0 {
			// Prepend separator (reversed, will be re-reversed)
			sepRunes := []rune(sep)
			for _, v := range slices.Backward(sepRunes) {
				result = append(result, v)
			}
		}

		result = append(result, runes[i])
	}
	// Reverse
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

func toLowerAlpha(n int64) string {
	if n <= 0 {
		return strconv.FormatInt(n, 10)
	}

	var buf []byte

	for n > 0 {
		n--
		buf = append([]byte{byte('a' + n%26)}, buf...)
		n /= 26
	}

	return string(buf)
}

func toUpperAlpha(n int64) string {
	return strings.ToUpper(toLowerAlpha(n))
}

func toRoman(n int) string {
	if n <= 0 || n >= 4000 {
		return strconv.Itoa(n)
	}

	vals := []struct {
		val int
		sym string
	}{
		{1000, "M"},
		{900, "CM"},
		{500, "D"},
		{400, "CD"},
		{100, "C"},
		{90, "XC"},
		{50, "L"},
		{40, "XL"},
		{10, "X"},
		{9, "IX"},
		{5, "V"},
		{4, "IV"},
		{1, "I"},
	}

	var buf strings.Builder

	for _, v := range vals {
		for n >= v.val {
			buf.WriteString(v.sym)
			n -= v.val
		}
	}

	return buf.String()
}

func execNumberStartAt(ctx context.Context, inst *numberInst, ec *execContext, bigNums []*big.Int) error {
	if inst.StartAt != nil {
		saStr, err := inst.StartAt.evaluate(ctx, ec.contextNode)
		if err != nil {
			return err
		}

		startAt, ok := parseStartAt(saStr)
		if !ok {
			return dynamicError(errCodeXTDE0030,
				"%q is not a valid value for xsl:number/@start-at", saStr)
		}

		one := big.NewInt(1)

		for i, n := range bigNums {
			offset := startAt[len(startAt)-1]
			if i < len(startAt) {
				offset = startAt[i]
			}
			// start-at shifts numbering: number = number + startAt - 1
			bigNums[i] = new(big.Int).Add(n, offset)
			bigNums[i].Sub(bigNums[i], one)
		}
	}

	return nil
}

func (ec *execContext) resolveNumberNode(ctx context.Context, inst *numberInst) (xdm.Node, error) {
	node := ec.contextNode
	if inst.Select != nil && inst.Value == nil {
		result, err := ec.evalXPath(ctx, inst.Select, node)
		if err != nil {
			return nil, err
		}

		seq := result.Sequence()
		if xdm.SequenceLen(seq) == 0 {
			return nil, dynamicError(errCodeXTTE1000,
				"xsl:number select expression returned empty sequence")
		}

		if xdm.SequenceLen(seq) > 1 {
			return nil, dynamicError(errCodeXTTE1000,
				"xsl:number select expression returned more than one item")
		}

		selected, ok := seq.Get(0).(xdm.NodeItem)
		if !ok {
			return nil, dynamicError(errCodeXTTE1000,
				"xsl:number select expression did not return a node")
		}

		node = selected.Node
	}

	// Select is evaluated first so numbering works inside an xsl:function.
	if inst.Value == nil && node == nil {
		return nil, dynamicError(errCodeXTTE0990,
			"xsl:number requires a node context when value is not specified")
	}

	return node, nil
}

func (ec *execContext) evaluateNumberValues(ctx context.Context, inst *numberInst, node xdm.Node) ([]*big.Int, bool, error) {
	result, err := ec.evalXPath(ctx, inst.Value, node)
	if err != nil {
		return nil, false, err
	}

	seq := result.Sequence()
	if ec.isCompatExpr(inst.Value) {
		number, err := compatNumberValue(seq)
		if err != nil {
			return nil, false, err
		}

		if number == nil {
			return nil, true, nil
		}

		return []*big.Int{number}, false, nil
	}

	atoms, err := xpath.AtomizeSequence(seq)
	if err != nil {
		return nil, false, err
	}

	numbers := make([]*big.Int, 0, len(atoms))
	for _, atom := range atoms {
		number, err := atomicToBigInt(atom)
		if err != nil {
			return nil, false, err
		}

		numbers = append(numbers, number)
	}

	return numbers, false, nil
}

func compatNumberValue(seq xdm.Sequence) (*big.Int, error) {
	// XSLT 1.0 uses only the first atomized item. An empty or invalid
	// numeric value outputs NaN before evaluating any formatting AVTs.
	for item := range xdm.SequenceItems(seq) {
		av, err := xpath.AtomizeItem(item)
		if err != nil {
			return nil, dynamicError(errCodeXTDE0980, "xsl:number value is not numeric")
		}

		number, err := atomicToBigInt(av)
		if err != nil {
			return nil, nil
		}

		return number, nil
	}

	return nil, nil
}

// atomicToBigInt implements xs:integer(round(number($V))) (REC §12.2).
// Conversion to xs:double precedes rounding, including for integers/decimals.
func atomicToBigInt(value xdm.AtomicValue) (*big.Int, error) {
	double, err := xpath.CastAtomic(value, xdm.TypeDouble)
	if err != nil {
		return nil, dynamicError(errCodeXTDE0980, "xsl:number value cannot be converted to a number")
	}

	rounded := math.Round(double.DoubleVal())
	if double.DoubleVal() == -0.5 {
		rounded = 0 // fn:round resolves ties toward positive infinity.
	}

	if math.IsNaN(rounded) || math.IsInf(rounded, 0) || rounded < 0 {
		return nil, dynamicError(errCodeXTDE0980, "xsl:number value is not a non-negative integer: %v", double.DoubleVal())
	}

	integer, err := xpath.CastAtomic(xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: rounded}, xdm.TypeInteger)
	if err != nil {
		return nil, dynamicErrorCause(errCodeXTDE0980, err, "xsl:number value cannot be converted to an integer")
	}

	return integer.BigInt(), nil
}

func (ec *execContext) numberNodeValues(ctx context.Context, inst *numberInst, node xdm.Node) []int {
	switch inst.Level {
	case "multiple":
		return ec.numberMultiple(ctx, inst, node)
	case "any":
		return ec.numberAny(ctx, inst, node)
	default:
		return ec.numberSingle(ctx, inst, node)
	}
}

func (ec *execContext) evaluateNumberFormatOptions(ctx context.Context, inst *numberInst) (numberFormatOptions, error) {
	options := numberFormatOptions{}

	var err error

	options.picture, err = ec.evaluateNumberAVT(ctx, inst.Format, "1")
	if err != nil {
		return numberFormatOptions{}, err
	}

	if inst.GroupingSeparator != nil && inst.GroupingSize != nil {
		options.groupingSeparator, err = ec.evaluateNumberAVT(ctx, inst.GroupingSeparator, "")
		if err != nil {
			return numberFormatOptions{}, err
		}

		groupSize, err := ec.evaluateNumberAVT(ctx, inst.GroupingSize, "")
		if err != nil {
			return numberFormatOptions{}, err
		}

		groupSize = strings.Trim(groupSize, " \t\r\n")
		if !validNumberOption(nameGroupingSize, groupSize) {
			return numberFormatOptions{}, dynamicError(errCodeXTDE0030, "invalid xsl:number grouping-size %q", groupSize)
		}

		// A size beyond the native integer range is larger than any bounded
		// output supported here and therefore cannot insert a separator.
		if decimalIntegerLexical(groupSize, true) {
			if size, err := strconv.Atoi(groupSize); err == nil && size > 0 {
				options.groupingSize = size
			}
		}
	}

	options.lang, err = ec.evaluateNumberAVT(ctx, inst.Lang, "")
	if err != nil {
		return numberFormatOptions{}, err
	}

	options.lang = strings.Trim(options.lang, " \t\r\n")
	if !validNumberOption(lexicon.AttrLang, options.lang) {
		return numberFormatOptions{}, dynamicError(errCodeXTDE0030,
			"xsl:number lang attribute is not a valid language code: %q", options.lang)
	}

	if inst.LetterValue != nil {
		letterValue, err := ec.evaluateNumberAVT(ctx, inst.LetterValue, "")
		if err != nil {
			return numberFormatOptions{}, err
		}

		if !validNumberOption(nameLetterValue, letterValue) {
			return numberFormatOptions{}, dynamicError(errCodeXTDE0030, "invalid xsl:number letter-value %q", letterValue)
		}
	}

	options.ordinal, err = ec.evaluateNumberAVT(ctx, inst.Ordinal, "")
	if err != nil {
		return numberFormatOptions{}, err
	}

	if ec.stylesheet.processorLanguage() >= 30 {
		switch strings.Trim(options.ordinal, " \t\r\n") {
		case lexicon.ValueNo, lexicon.ValueFalse, "0":
			options.ordinal = ""
		}
	}

	return options, nil
}

func (ec *execContext) evaluateNumberAVT(ctx context.Context, value *avt, fallback string) (string, error) {
	if value == nil {
		return fallback, nil
	}

	return value.evaluate(ctx, ec.contextNode)
}

// numberNodeMatches tests if a node matches the count pattern.
// If no count pattern, matches nodes with the same type and name as the context node.
func (ec *execContext) numberNodeMatches(ctx context.Context, inst *numberInst, target xdm.Node, contextNode xdm.Node) bool {
	if inst.Count != nil {
		// Special case: count="." matches any non-document node
		if inst.Count.source == "." && target.Type() != xdm.DocumentNode {
			return true
		}
		// Per XSLT 3.0 section 13.4.1, current() within a count pattern
		// refers to the node being tested against the pattern (the candidate),
		// so that predicates like [@bar = current()/@bar] evaluate relative
		// to each candidate node during the numbering walk.
		savedCurrent := ec.currentNode
		ec.currentNode = target
		result := inst.Count.matchPattern(ctx, ec, target)
		ec.currentNode = savedCurrent

		return result
	}
	// Default: same node type and expanded name
	if contextNode == nil {
		return false
	}

	if target.Type() != contextNode.Type() {
		return false
	}

	if target.Type() == xdm.ElementNode {
		te, _ := xdm.AsNode[*xdm.Element](target)
		ce, _ := xdm.AsNode[*xdm.Element](contextNode)

		return te.LocalName() == ce.LocalName() && te.URI() == ce.URI()
	}

	return target.Name() == contextNode.Name()
}

// numberFromMatches tests if a node matches the from pattern.
func (ec *execContext) numberFromMatches(ctx context.Context, inst *numberInst, node xdm.Node) bool {
	if inst.From == nil {
		return false
	}
	// Same current() semantics as numberNodeMatches: current() refers to
	// the candidate node being tested, not the xsl:number context node.
	savedCurrent := ec.currentNode
	ec.currentNode = node
	result := inst.From.matchPattern(ctx, ec, node)
	ec.currentNode = savedCurrent

	return result
}

// numberSingle implements level="single": find the first ancestor-or-self that
// matches the count pattern, then count preceding siblings that match. The
// result is empty when no ancestor-or-self matches count, or when that node
// lies outside the from subtree (see numberWithinFrom).
func (ec *execContext) numberSingle(ctx context.Context, inst *numberInst, node xdm.Node) []int {
	target := ec.numberFindAncestorOrSelf(ctx, inst, node)
	if target == nil {
		return nil
	}

	if inst.From != nil && !ec.numberWithinFrom(ctx, inst, node, target) {
		return nil
	}

	// Count preceding siblings that match count pattern, stopping at the
	// sibling the previous evaluation counted.
	memoNode, memoCount := ec.numberMemoFor(inst, node)
	count := 1

	for sib := numberPrevSibling(target); sib != nil; sib = numberPrevSibling(sib) {
		if sib == memoNode {
			count += memoCount
			break
		}

		if ec.numberNodeMatches(ctx, inst, sib, node) {
			count++
		}
	}

	ec.storeNumberMemo(inst, node, target, count)

	return []int{count}
}

// numberWithinFrom reports whether target, an ancestor-or-self of node, lies
// in the subtree rooted at the innermost ancestor-or-self of node that matches
// the from pattern (XSLT 3.0 §12.3, level="single"). The root of a tree
// always matches from, and target is never above the root, so target is
// outside only when a from match lies strictly between node and target:
// walking up from node, a from match met before target excludes it.
func (ec *execContext) numberWithinFrom(ctx context.Context, inst *numberInst, node, target xdm.Node) bool {
	for n := node; n != nil && n != target; n = n.Parent() {
		if ec.numberFromMatches(ctx, inst, n) {
			return false
		}
	}

	return true
}

// numberMultiple implements level="multiple": find all ancestors-or-self that match
// count (stopping at from), and for each count preceding siblings.
func (ec *execContext) numberMultiple(ctx context.Context, inst *numberInst, node xdm.Node) []int {
	var ancestors []xdm.Node

	for n := node; n != nil; n = n.Parent() {
		if ec.numberFromMatches(ctx, inst, n) {
			// Include the from node itself if it matches count
			if ec.numberNodeMatches(ctx, inst, n, node) {
				ancestors = append(ancestors, n)
			}

			break
		}

		if ec.numberNodeMatches(ctx, inst, n, node) {
			ancestors = append(ancestors, n)
		}

		if n.Type() == xdm.DocumentNode {
			break
		}
	}

	// Reverse to get document order (outermost first)
	for i, j := 0, len(ancestors)-1; i < j; i, j = i+1, j-1 {
		ancestors[i], ancestors[j] = ancestors[j], ancestors[i]
	}

	nums := make([]int, len(ancestors))
	for i, anc := range ancestors {
		count := 1

		for sib := numberPrevSibling(anc); sib != nil; sib = numberPrevSibling(sib) {
			if ec.numberNodeMatches(ctx, inst, sib, node) {
				count++
			}
		}

		nums[i] = count
	}

	return nums
}

// numberAny implements level="any": count all matching nodes in document order
// that precede (or are) the context node, going back to the nearest from match.
// The from node itself is included in the count if it matches count.
func (ec *execContext) numberAny(ctx context.Context, inst *numberInst, node xdm.Node) []int {
	memoNode, memoCount := ec.numberMemoFor(inst, node)
	count := 0

	cur := node
	for cur != nil {
		// Reaching the node the previous evaluation started from means no
		// from match lies between the two, so its count carries over.
		if cur == memoNode {
			count += memoCount
			break
		}

		if ec.numberNodeMatches(ctx, inst, cur, node) {
			count++
		}

		if ec.numberFromMatches(ctx, inst, cur) {
			break
		}

		cur = ec.prevInDocOrder(cur)
	}

	ec.storeNumberMemo(inst, node, node, count)

	if count == 0 {
		return nil
	}

	return []int{count}
}

// numberMemoFor returns the node and count of inst's previous evaluation when
// they apply to numbering selected, and a nil node otherwise.
func (ec *execContext) numberMemoFor(inst *numberInst, selected xdm.Node) (xdm.Node, int) {
	if !inst.memoizable {
		return nil, 0
	}

	memo, ok := ec.numberMemos[inst]
	if !ok {
		return nil, 0
	}

	if inst.Count == nil {
		kind, local, uri := numberDefaultKey(selected)
		if memo.kind != kind || memo.local != local || memo.uri != uri {
			return nil, 0
		}
	}

	return memo.node, memo.count
}

// storeNumberMemo records that the walk for selected, starting at node,
// produced count.
func (ec *execContext) storeNumberMemo(inst *numberInst, selected, node xdm.Node, count int) {
	if !inst.memoizable {
		return
	}

	memo := numberMemo{node: node, count: count}
	if inst.Count == nil {
		memo.kind, memo.local, memo.uri = numberDefaultKey(selected)
	}

	if ec.numberMemos == nil {
		ec.numberMemos = make(map[*numberInst]numberMemo)
	}

	ec.numberMemos[inst] = memo
}

// prevInDocOrder returns the previous node in document order, skipping
// attribute and namespace nodes as XPath's preceding axis does: from an
// attribute or namespace node the walk goes straight to its parent element.
func (ec *execContext) prevInDocOrder(node xdm.Node) xdm.Node {
	// Previous sibling's deepest last descendant
	if prev := numberPrevSibling(node); prev != nil {
		return ec.lastDescendant(prev)
	}
	// Otherwise, parent (including document node)
	parent := node.Parent()
	if parent == nil {
		return nil
	}

	return parent
}

// lastDescendant returns the deepest last XDM descendant of node (or node
// itself if it has no XDM children). An entity reference or an XInclude
// marker among an element's children is not an XDM node, so the walk takes
// the last child that is.
func (ec *execContext) lastDescendant(node xdm.Node) xdm.Node {
	for node.Type() == xdm.ElementNode {
		last := node.LastChild()
		for last != nil && !xdm.IsXDMChild(last) {
			last = last.PrevSibling()
		}

		if last == nil {
			return node
		}

		node = last
	}

	return node
}

func (ec *execContext) numberFindAncestorOrSelf(ctx context.Context, inst *numberInst, node xdm.Node) xdm.Node {
	for n := node; n != nil; n = n.Parent() {
		if ec.numberNodeMatches(ctx, inst, n, node) {
			return n
		}
		// Stop at document node to avoid walking above the tree
		if n.Type() == xdm.DocumentNode {
			return nil
		}
	}

	return nil
}

// numberDefaultKey returns the kind and name the default count pattern
// compares, matching numberNodeMatches.
func numberDefaultKey(node xdm.Node) (xdm.ElementType, string, string) {
	if elem, ok := node.(*xdm.Element); ok {
		return xdm.ElementNode, elem.LocalName(), elem.URI()
	}

	return node.Type(), node.Name(), ""
}

// numberPrevSibling returns the previous XDM child sibling, skipping storage nodes
// outside the XDM child model. Attribute and namespace nodes have no siblings.
func numberPrevSibling(node xdm.Node) xdm.Node {
	switch node.Type() {
	case xdm.AttributeNode, xdm.NamespaceNode:
		return nil
	}

	for prev := node.PrevSibling(); prev != nil; prev = prev.PrevSibling() {
		if xdm.IsXDMChild(prev) {
			return prev
		}
	}

	return nil
}

type numberListToken struct {
	format    string
	separator string
}

type numberListPicture struct {
	prefix           string
	suffix           string
	tokens           []numberListToken
	defaultSeparator string
}

func (picture numberListPicture) separator(index int) string {
	if index < len(picture.tokens) && picture.tokens[index-1].separator != "" {
		return picture.tokens[index-1].separator
	}

	return picture.defaultSeparator
}

func numberToWords(n int64, upper bool) string { //nolint:unparam // upper always false but kept for XSLT number-to-words spec
	result := "zero"
	if magnitude, ok := minInt64MagnitudeString(n); ok {
		result = "minus " + magnitude
	} else if n != 0 {
		ones := []string{
			"", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
			"ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen",
		}
		tens := []string{"", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"}

		result = englishNumberWords(n, ones, tens)
	}

	if upper {
		return strings.ToUpper(result)
	}

	return result
}

func englishNumberWords(n int64, ones, tens []string) string {
	if n < 0 {
		return "minus " + englishNumberWords(-n, ones, tens)
	}

	switch {
	case n < 20:
		return ones[int(n)]
	case n < 100:
		word := tens[int(n/10)]
		if n%10 != 0 {
			word += " " + ones[int(n%10)]
		}

		return word
	case n < 1000:
		word := ones[int(n/100)] + " hundred"
		if n%100 != 0 {
			word += " and " + englishNumberWords(n%100, ones, tens)
		}

		return word
	case n < 1000000:
		return englishScaledNumber(n, 1000, "thousand", ones, tens)
	case n < numberBillion:
		return englishScaledNumber(n, 1000000, "million", ones, tens)
	case n < numberTrillion:
		return englishScaledNumber(n, numberBillion, "billion", ones, tens)
	default:
		return strconv.FormatInt(n, 10)
	}
}

func englishScaledNumber(n, scale int64, name string, ones, tens []string) string {
	word := englishNumberWords(n/scale, ones, tens) + " " + name
	if n%scale != 0 {
		word += " " + englishNumberWords(n%scale, ones, tens)
	}

	return word
}
