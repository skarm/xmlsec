// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/pattern"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	xpathregex "github.com/skarm/xmlsec/transform/internal/xpath/regex"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	norm "github.com/skarm/xmlsec/internal/normalization"
)

const (
	fnNameSubstring        = "substring"
	fnNameNormalizeSpace   = "normalize-space"
	fnNameNormalizeUnicode = "normalize-unicode"
	fnNameTranslate        = "translate"
	fnNameContains         = "contains"
	fnNameStartsWith       = "starts-with"
	fnNameSubstringBefore  = "substring-before"
	fnNameSubstringAfter   = "substring-after"
	fnNameMatches          = "matches"
)

func lookupFunctionsString(name string) (*builtinFunc, bool) {
	switch name {
	case lexicon.TypeString:
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnString}, true
	case "codepoints-to-string":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnCodepointsToString}, true
	case "string-to-codepoints":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnStringToCodepoints}, true
	case "compare":
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnCompare}, true
	case "codepoint-equal":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnCodepointEqual}, true
	case nameConcat:
		return &builtinFunc{name: name, min: 2, max: -1, fn: fnConcat}, true
	case fnNameStringJoin:
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnStringJoin}, true
	case fnNameSubstring:
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnSubstring}, true
	case nameStringLength:
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnStringLength}, true
	case fnNameNormalizeSpace:
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnNormalizeSpace}, true
	case fnNameNormalizeUnicode:
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnNormalizeUnicode}, true
	case "upper-case":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnUpperCase}, true
	case "lower-case":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnLowerCase}, true
	case fnNameTranslate:
		return &builtinFunc{name: name, min: 3, max: 3, fn: fnTranslate}, true
	case fnNameContains:
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnContains}, true
	case fnNameStartsWith:
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnStartsWith}, true
	case "ends-with":
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnEndsWith}, true
	case fnNameSubstringBefore:
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnSubstringBefore}, true
	case fnNameSubstringAfter:
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnSubstringAfter}, true
	case fnNameMatches:
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnMatches}, true
	case "replace":
		return &builtinFunc{name: name, min: 3, max: 4, fn: fnReplace}, true
	case "tokenize":
		return &builtinFunc{name: name, min: 1, max: 3, fn: fnTokenize}, true
	case "analyze-string":
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnAnalyzeString}, true
	case "contains-token":
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnContainsToken}, true
	case "collation-key":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnCollationKey}, true
	}

	return nil, false
}

func fnString(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 {
		s, err := contextItemString(ctx)
		if err != nil {
			return nil, err
		}

		return xdm.SingleString(s), nil
	}

	if xdm.SequenceLen(args[0]) == 0 {
		return xdm.SingleString(""), nil
	}

	if xdm.SequenceLen(args[0]) > 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:string requires a single item, got sequence of length > 1"}
	}

	item := args[0].Get(0)
	// fn:string does not accept function items, maps, or arrays
	switch item.(type) {
	case xdm.FunctionItem, xdm.MapItem, xdm.ArrayItem:
		return nil, &xdm.Error{Code: errCodeFOTY0014, Message: fmt.Sprintf("fn:string: cannot get string value of %T", item)}
	}
	// For node items, fn:string returns the dm:string-value (text content),
	// NOT the typed/atomized value. This preserves lexical forms like "003"
	// even when the node is typed as xs:integer.
	if ni, ok := item.(xdm.NodeItem); ok {
		if fc := getFnContext(ctx); fc != nil {
			return xdm.SingleString(fc.nodeStringValue(ni.Node)), nil
		}

		return xdm.SingleString(xdm.StringValue(ni.Node)), nil
	}

	a, err := AtomizeItem(item)
	if err != nil {
		return nil, err
	}

	s, _ := atomicToString(a)

	return xdm.SingleString(s), nil
}

// Context-defaulting string functions use fn:string(.), which distinguishes
// an absent focus from function items without a string value.
func contextItemString(ctx context.Context) (string, error) {
	fc := getFnContext(ctx)
	if fc == nil || (fc.contextItem == nil && fc.node == nil) {
		return "", &xdm.Error{Code: lexicon.ErrXPDY0002, Message: errMsgContextItemAbsent}
	}

	if value, ok := fc.contextStringValue(); ok {
		return value, nil
	}

	return "", &xdm.Error{Code: errCodeFOTY0014, Message: "context function item has no string value"}
}

func fnCodepointsToString(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	seq := args[0]
	if err := fnCountOps(ctx, getFnContext(ctx), xdm.SequenceLen(seq)); err != nil {
		return nil, err
	}

	xml11 := false
	if ec := getFnContext(ctx); ec != nil {
		xml11 = ec.allowXML11Chars
	}

	isValid := isValidXMLCodepoint
	if xml11 {
		isValid = isValidXML11Codepoint
	}

	// Fast path: singleton integer (common in unicode-90 where each codepoint
	// is mapped individually via codepoints-to-string(.))
	if xdm.SequenceLen(seq) == 1 {
		cp, err := itemToCodepoint(seq.Get(0))
		if err != nil {
			return nil, err
		}

		if !isValid(cp) {
			return nil, &xdm.Error{Code: lexicon.ErrFOCH0001, Message: fmt.Sprintf("invalid XML character [x%X]", cp)}
		}

		return xdm.SingleString(string(rune(cp))), nil
	}

	var b strings.Builder

	for item := range xdm.SequenceItems(seq) {
		cp, err := itemToCodepoint(item)
		if err != nil {
			return nil, err
		}

		if !isValid(cp) {
			return nil, &xdm.Error{Code: lexicon.ErrFOCH0001, Message: fmt.Sprintf("invalid XML character [x%X]", cp)}
		}

		if err := ChargeString(ctx, utf8.RuneLen(rune(cp))); err != nil {
			return nil, err
		}

		b.WriteRune(rune(cp))
	}

	return xdm.SingleString(b.String()), nil
}

// itemToCodepoint enforces xs:integer, without narrowing arbitrary-precision
// input until its value is known to fit the Unicode scalar range.
func itemToCodepoint(item xdm.Item) (int, error) {
	a, err := AtomizeItem(item)
	if err != nil {
		return 0, err
	}

	a = xdm.PromoteSchemaType(a)
	if a.TypeName == xdm.TypeUntypedAtomic {
		a, err = CastAtomic(a, xdm.TypeInteger)
		if err != nil {
			return 0, err
		}
	}

	if !xdm.IsIntegerDerived(a.TypeName) {
		return 0, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "codepoints-to-string requires xs:integer values"}
	}

	value, fits := a.Int64Val()
	if !fits || value < 0 || value > utf8.MaxRune {
		return 0, &xdm.Error{Code: lexicon.ErrFOCH0001, Message: "codepoint is outside the Unicode scalar range"}
	}

	return int(value), nil
}

// isValidXMLCodepoint returns true if the codepoint is a valid XML character.
// Per XML 1.0 §2.2: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
func isValidXMLCodepoint(cp int) bool {
	if cp == 0x9 || cp == 0xA || cp == 0xD {
		return true
	}

	if cp >= 0x20 && cp <= 0xD7FF {
		return true
	}

	if cp >= 0xE000 && cp <= 0xFFFD {
		return true
	}

	if cp >= 0x10000 && cp <= 0x10FFFF {
		return true
	}

	return false
}

// isValidXML11Codepoint extends the XML 1.0 check to also accept XML 1.1
// restricted characters (0x01-0x1F except 0x00). XSLT 3.0 processors need
// these for features like xml-to-json with escaped="1".
func isValidXML11Codepoint(cp int) bool {
	if cp >= 0x1 && cp <= 0xD7FF {
		return true
	}

	if cp >= 0xE000 && cp <= 0xFFFD {
		return true
	}

	if cp >= 0x10000 && cp <= 0x10FFFF {
		return true
	}

	return false
}

func fnStringToCodepoints(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if s == "" {
		return nil, nil
	}
	// Build the codepoint sequence one item per character, charging the op-limit
	// and honoring context cancellation before each append (and capping the
	// length at maxNodes). A huge input string would otherwise materialize an
	// unbounded item sequence in one shot, ignoring both budgets.
	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)

	var result xdm.ItemSlice

	for _, r := range s {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		if len(result) >= maxNodes {
			return nil, ErrNodeSetLimit
		}

		result = append(result, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: big.NewInt(int64(r))})
	}

	return result, nil
}

func fnCompare(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	coll, err := getCollation(ctx, args, 2)
	if err != nil {
		return nil, err
	}
	// fn:compare returns the empty sequence if either argument is empty. Detect
	// emptiness AFTER atomization so an empty array or nilled/empty-content typed
	// node (which atomizes to (), and never to "") also yields () — a raw seqLen
	// gate would let such a value fall through to comparing "" against the other.
	s1, empty1, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	s2, empty2, err := coerceAtomizedString(ctx, args[1])
	if err != nil {
		return nil, err
	}

	if empty1 || empty2 {
		return nil, nil
	}

	cmp := coll.compare(s1, s2)

	return xdm.SingleInteger(int64(cmp)), nil
}

func fnCodepointEqual(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// fn:codepoint-equal returns the empty sequence if either argument is empty,
	// where "empty" is the post-atomization emptiness (empty array / nilled node
	// atomize to (), and never to "").
	s1, empty1, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	s2, empty2, err := coerceAtomizedString(ctx, args[1])
	if err != nil {
		return nil, err
	}

	if empty1 || empty2 {
		return nil, nil
	}

	return xdm.SingleBoolean(s1 == s2), nil
}

func fnConcat(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	var b strings.Builder

	for _, arg := range args {
		s, err := seqToStringErr(ctx, arg)
		if err != nil {
			return nil, err
		}

		if err := ChargeString(ctx, len(s)); err != nil {
			return nil, err
		}

		b.WriteString(s)
	}

	return xdm.SingleString(b.String()), nil
}

func fnStringJoin(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	sep := ""

	if len(args) > 1 {
		if getFnContext(ctx).xpath10CompatMode() {
			// The separator's expected type is xs:string, so XPath 1.0 compatibility
			// mode converts it with fn:string applied to its first item.
			sv, err := xpath10CompatStringItem(args[1])
			if err != nil {
				return nil, err
			}

			sep, _ = sv.Value.(string)
		} else {
			var err error

			sep, err = coerceArgToStringRequired(ctx, args[1])
			if err != nil {
				return nil, err
			}
		}
	}
	// Atomize the entire sequence (expands list types to multiple items).
	atoms, err := AtomizeSequence(args[0])
	if err != nil {
		return nil, err
	}

	var b strings.Builder

	for i, a := range atoms {
		if i > 0 && sep != "" {
			if err := ChargeString(ctx, len(sep)); err != nil {
				return nil, err
			}

			b.WriteString(sep)
		}

		s, err := atomicToString(a)
		if err != nil {
			return nil, err
		}

		if err := ChargeString(ctx, len(s)); err != nil {
			return nil, err
		}

		b.WriteString(s)
	}

	return xdm.SingleString(b.String()), nil
}

func fnSubstring(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	startPos, err := coerceArgToDoubleRequired(ctx, args[1])
	if err != nil {
		return nil, err
	}

	// XPath round
	rStart := roundHalfUpFloat(startPos, 0)
	end := math.Inf(1)

	if len(args) == 3 {
		length, err := coerceArgToDoubleRequired(ctx, args[2])
		if err != nil {
			return nil, err
		}

		end = rStart + roundHalfUpFloat(length, 0)
	}

	if math.IsNaN(rStart) || math.IsNaN(end) || end <= 1 || end <= rStart || math.IsInf(rStart, 1) {
		return xdm.SingleString(""), nil
	}

	startByte, endByte := len(s), len(s)
	position := 1.0

	checked := 0
	for offset := range s {
		if offset >= checked {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			checked = offset + 4096
		}

		if position >= end {
			endByte = offset
			break
		}

		if position >= rStart && startByte == len(s) {
			startByte = offset
		}

		position++
	}

	part := s[startByte:endByte]
	if !utf8.ValidString(part) {
		// Preserve the rune semantics for invalid UTF-8 supplied as an atomic
		// string, without converting the unselected part of the source.
		part = strings.Map(func(r rune) rune { return r }, part)
	} else {
		part = stringPart(s, startByte, endByte)
	}

	return xdm.SingleString(part), nil
}

func fnStringLength(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	var s string

	if len(args) == 0 {
		var err error

		s, err = contextItemString(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		var err error

		s, err = seqToStringErr(ctx, args[0])
		if err != nil {
			return nil, err
		}
	}

	return xdm.SingleInteger(int64(len([]rune(s)))), nil
}

func fnNormalizeSpace(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	var s string

	if len(args) == 0 {
		var err error

		s, err = contextItemString(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		var err error

		s, err = coerceArgToString(ctx, args[0])
		if err != nil {
			return nil, err
		}
	}

	normalized := collapseXMLWhitespace(s)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return xdm.SingleString(normalized), nil
}

func fnNormalizeUnicode(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	formName := nameNFC // default

	if len(args) > 1 {
		form, err := coerceArgToStringRequired(ctx, args[1])
		if err != nil {
			return nil, err
		}

		formName = strings.Trim(strings.ToUpper(form), " \t\r\n")
		if formName == "" {
			// Empty form string means return input unchanged
			return xdm.SingleString(s), nil
		}
	}

	if s == "" {
		return xdm.SingleString(""), nil
	}

	var nf norm.Form

	switch formName {
	case nameNFC:
		nf = norm.NFC
	case nameNFD:
		nf = norm.NFD
	case nameNFKC:
		nf = norm.NFKC
	case nameNFKD:
		nf = norm.NFKD
	case "FULLY-NORMALIZED":
		// W3C Charmod Normalization: NFC + if the result starts with a
		// composing character, prepend a space. A composing character is
		// one that can be consumed by NFC composition with a preceding
		// starter. We detect this by prepending a known starter and
		// checking whether NFC composition changes the pair.
		result, err := norm.String(ctx, norm.NFC, s)
		if err != nil {
			return nil, err
		}

		if len(result) > 0 {
			r, _ := utf8.DecodeRuneInString(result)
			if isComposingCharacter(r) {
				result = " " + result
			}
		}

		return xdm.SingleString(result), nil
	default:
		return nil, &xdm.Error{Code: errCodeFOCH0003, Message: fmt.Sprintf("unsupported normalization form: %s", formName)}
	}

	result, err := norm.String(ctx, nf, s)
	if err != nil {
		return nil, err
	}

	return xdm.SingleString(result), nil
}

// isComposingCharacter returns true if r is a character that could compose
// with a preceding character under NFC. This includes characters with CCC > 0
// and characters that appear as the trailing element of a canonical composition.
// We use norm.NFC.BoundaryBefore: a rune that does NOT start a new boundary
// can compose with a preceding character and is therefore "composing".
func isComposingCharacter(r rune) bool {
	p := norm.NFC.PropertiesString(string(r))
	return !p.BoundaryBefore()
}

// fnUpperCase uses a per-call caser for locale-independent full Unicode mapping,
// including multi-character expansions such as ß→SS.
func fnUpperCase(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	return xdm.SingleString(cases.Upper(language.Und).String(s)), nil
}

func fnLowerCase(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	return xdm.SingleString(cases.Lower(language.Und).String(s)), nil
}

func fnTranslate(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	fromStr, err := coerceArgToStringRequired(ctx, args[1])
	if err != nil {
		return nil, err
	}

	toStr, err := coerceArgToStringRequired(ctx, args[2])
	if err != nil {
		return nil, err
	}

	from := []rune(fromStr)
	to := []rune(toStr)

	mapping := make(map[rune]rune, len(from))
	remove := make(map[rune]struct{})

	for i, r := range from {
		if _, exists := mapping[r]; exists {
			continue
		}

		if _, ok := remove[r]; ok {
			continue
		}

		if i < len(to) {
			mapping[r] = to[i]
		} else {
			remove[r] = struct{}{}
		}
	}

	var b strings.Builder

	for _, r := range s {
		if _, ok := remove[r]; ok {
			continue
		}

		if rep, ok := mapping[r]; ok {
			b.WriteRune(rep)
		} else {
			b.WriteRune(r)
		}
	}

	return xdm.SingleString(b.String()), nil
}

// collationStringPair resolves the collation (arg index 2) and coerces the
// first two arguments to strings, in that order. Shared by the collation-aware
// two-string string functions (contains, starts-with, ends-with,
// substring-before, substring-after).
func collationStringPair(ctx context.Context, args []xdm.Sequence) (*collationImpl, string, string, error) {
	coll, err := getCollation(ctx, args, 2)
	if err != nil {
		return nil, "", "", err
	}

	s1, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, "", "", err
	}

	s2, err := coerceArgToString(ctx, args[1])
	if err != nil {
		return nil, "", "", err
	}

	return coll, s1, s2, nil
}

func fnContains(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	coll, s, sub, err := collationStringPair(ctx, args)
	if err != nil {
		return nil, err
	}

	if sub == "" {
		return xdm.SingleBoolean(true), nil
	}

	pos, _ := coll.indexOf(s, sub)

	return xdm.SingleBoolean(pos >= 0), nil
}

func fnStartsWith(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	coll, s, prefix, err := collationStringPair(ctx, args)
	if err != nil {
		return nil, err
	}

	if prefix == "" {
		return xdm.SingleBoolean(true), nil
	}

	ok, _ := coll.hasPrefix(s, prefix)

	return xdm.SingleBoolean(ok), nil
}

func fnEndsWith(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	coll, s, suffix, err := collationStringPair(ctx, args)
	if err != nil {
		return nil, err
	}

	if suffix == "" {
		return xdm.SingleBoolean(true), nil
	}

	ok, _ := coll.hasSuffix(s, suffix)

	return xdm.SingleBoolean(ok), nil
}

func fnSubstringBefore(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	coll, s, sep, err := collationStringPair(ctx, args)
	if err != nil {
		return nil, err
	}

	if sep == "" {
		return xdm.SingleString(""), nil
	}

	pos, _ := coll.indexOf(s, sep)
	if pos < 0 {
		return xdm.SingleString(""), nil
	}

	return xdm.SingleString(stringPart(s, 0, pos)), nil
}

func fnSubstringAfter(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	coll, s, sep, err := collationStringPair(ctx, args)
	if err != nil {
		return nil, err
	}

	if sep == "" {
		return xdm.SingleString(s), nil
	}

	pos, matchLen := coll.indexOf(s, sep)
	if pos < 0 {
		return xdm.SingleString(""), nil
	}

	return xdm.SingleString(stringPart(s, pos+matchLen, len(s))), nil
}

func fnMatches(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// Per XPath spec, xs:string? argument: empty sequence is treated as "".
	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if xdm.SequenceLen(args[1]) == 0 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:matches pattern must not be empty sequence"}
	}

	required, err := coerceArgToStringRequired(ctx, args[1])
	if err != nil {
		return nil, err
	}

	flags := ""

	if len(args) > 2 {
		if xdm.SequenceLen(args[2]) == 0 {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:matches flags must not be empty sequence"}
		}

		flags, err = coerceArgToStringRequired(ctx, args[2])
		if err != nil {
			return nil, err
		}
	}

	if err := checkVersionRegex(ctx, required, flags); err != nil {
		return nil, err
	}

	re, err := compileXPathRegex(ctx, required, flags)
	if err != nil {
		return nil, err
	}

	ok, err := re.MatchString(ctx, s)
	if err != nil {
		return nil, regexExecutionError(ctx, err, "regex match failed")
	}

	return xdm.SingleBoolean(ok), nil
}

// Matching failures must retain cancellation/limit categories; FORX0002 is
// reserved for invalid regular expression syntax, not exhausted evaluation.
func regexExecutionError(ctx context.Context, err error, operation string) error {
	if failure := ControlFailure(ctx, err); failure != nil {
		return failure
	}

	return &xdm.Error{Code: lexicon.ErrFORX0002, Message: operation + ": " + err.Error(), Cause: err}
}

func fnCollationKey(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	coll, err := getCollation(ctx, args, 1)
	if err != nil {
		return nil, err
	}

	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if coll.key == nil {
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeBase64Binary, Value: []byte(s)}), nil
	}

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeBase64Binary, Value: coll.key(s)}), nil
}

func fnReplace(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) == 0 {
		return xdm.SingleString(""), nil // input is xs:string? — empty yields ""
	}

	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if xdm.SequenceLen(args[1]) == 0 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:replace pattern must not be empty sequence"}
	}

	required, err := coerceArgToStringRequired(ctx, args[1])
	if err != nil {
		return nil, err
	}

	if xdm.SequenceLen(args[2]) == 0 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:replace replacement must not be empty sequence"}
	}

	replacement, err := coerceArgToStringRequired(ctx, args[2])
	if err != nil {
		return nil, err
	}

	flags := ""

	if len(args) > 3 {
		if xdm.SequenceLen(args[3]) == 0 {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:replace flags must not be empty sequence"}
		}

		flags, err = coerceArgToStringRequired(ctx, args[3])
		if err != nil {
			return nil, err
		}
	}

	isLiteral := strings.Contains(flags, "q")

	if err := checkVersionRegex(ctx, required, flags); err != nil {
		return nil, err
	}

	re, err := compileXPathRegex(ctx, required, flags)
	if err != nil {
		return nil, err
	}

	// XPath spec: error if pattern matches empty string
	matchesEmpty, err := re.MatchString(ctx, "")
	if err != nil {
		return nil, regexExecutionError(ctx, err, "regex match failed")
	}

	if matchesEmpty {
		return nil, &xdm.Error{Code: errCodeFORX0003, Message: "replacement pattern matches zero-length string"}
	}

	var goRepl string
	if isLiteral {
		// With q flag, replacement is literal — escape replacement token markers
		goRepl = strings.ReplaceAll(replacement, "$", "$$")
	} else {
		// Validate and translate XPath replacement string to normalized tokens.
		goRepl, err = translateXPathReplacement(replacement, re.NumSubexp())
		if err != nil {
			return nil, err
		}
	}

	replaced, err := re.ReplaceAllString(ctx, s, goRepl)
	if err != nil {
		return nil, regexExecutionError(ctx, err, "regex replace failed")
	}

	return xdm.SingleString(replaced), nil
}

// translateXPathReplacement normalizes replacement tokens for the shared engine.
// XPath uses: $N for backrefs, \$ for literal $, \\ for literal \.
// The engine uses ${N} for captures and $$ for a literal dollar sign.
// numGroups is the number of capture groups in the pattern — $N consumes the
// maximum number of digits that form a valid group reference (≤ numGroups).
func translateXPathReplacement(repl string, numGroups int) (string, error) {
	var b strings.Builder

	for i := 0; i < len(repl); i++ {
		ch := repl[i]
		switch ch {
		case '\\':
			if i+1 >= len(repl) {
				return "", &xdm.Error{Code: errCodeFORX0004, Message: "invalid replacement string: trailing backslash"}
			}

			next := repl[i+1]
			switch next {
			case '\\':
				b.WriteByte('\\')

				i++
			case '$':
				b.WriteString("$$") // Literal dollar sign

				i++
			default:
				return "", &xdm.Error{Code: errCodeFORX0004, Message: fmt.Sprintf("invalid replacement string: \\%c", next)}
			}
		case '$':
			if i+1 >= len(repl) || repl[i+1] < '0' || repl[i+1] > '9' {
				return "", &xdm.Error{Code: errCodeFORX0004, Message: "invalid replacement string: $ not followed by digit"}
			}

			i = appendXPathReplacementGroup(&b, repl, i+1, numGroups)

			i-- // outer loop will i++
		default:
			b.WriteByte(ch)
		}
	}

	return b.String(), nil
}

// appendXPathReplacementGroup consumes the longest valid capture number and
// retains following digits as literals. A nonexistent group contributes no text.
func appendXPathReplacementGroup(builder *strings.Builder, repl string, i, numGroups int) int {
	start := i
	num := 0
	validEnd := start // end of the longest valid group number

	for i < len(repl) && repl[i] >= '0' && repl[i] <= '9' {
		// Stop accumulating once num exceeds numGroups: more digits only
		// grow it, and accumulating a long digit run would wrap int
		// (past 2^31-1 where int is 32 bits) back into the group range.
		if num <= numGroups {
			num = num*10 + int(repl[i]-'0')
		}

		i++
		if num > 0 && num <= numGroups {
			validEnd = i
		}
	}
	// $0 always refers to the whole match.
	if validEnd == start && i > start && repl[start] == '0' {
		validEnd = start + 1
	}

	if validEnd == start {
		// References to nonexistent groups contribute no text.
		return i
	}

	builder.WriteString("${")
	builder.WriteString(repl[start:validEnd])
	builder.WriteByte('}')
	builder.WriteString(repl[validEnd:i])

	return i
}

func fnTokenize(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) == 0 {
		return nil, nil // input is xs:string? — empty yields empty
	}

	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if s == "" {
		return nil, nil
	}

	// 1-arg form: normalize XML whitespace (#x20, #x9, #xA, #xD), then split
	if len(args) == 1 {
		tokens := splitXMLWhitespace(s)

		result := make(xdm.ItemSlice, len(tokens))
		for i, t := range tokens {
			result[i] = xdm.AtomicValue{TypeName: xdm.TypeString, Value: t}
		}

		return result, nil
	}

	if xdm.SequenceLen(args[1]) == 0 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:tokenize pattern must not be empty sequence"}
	}

	required, err := coerceArgToStringRequired(ctx, args[1])
	if err != nil {
		return nil, err
	}

	flags := ""

	if len(args) > 2 {
		if xdm.SequenceLen(args[2]) == 0 {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:tokenize flags must not be empty sequence"}
		}

		flags, err = coerceArgToStringRequired(ctx, args[2])
		if err != nil {
			return nil, err
		}
	}

	if err := checkVersionRegex(ctx, required, flags); err != nil {
		return nil, err
	}

	re, err := compileXPathRegex(ctx, required, flags)
	if err != nil {
		return nil, err
	}

	// XPath spec: error if pattern matches zero-length string
	matchesEmpty, err := re.MatchString(ctx, "")
	if err != nil {
		return nil, regexExecutionError(ctx, err, "regex match failed")
	}

	if matchesEmpty {
		return nil, &xdm.Error{Code: errCodeFORX0003, Message: "tokenize pattern matches zero-length string"}
	}

	parts, err := re.Split(ctx, s, -1)
	if err != nil {
		return nil, regexExecutionError(ctx, err, "regex split failed")
	}

	result := make(xdm.ItemSlice, len(parts))
	for i, p := range parts {
		result[i] = xdm.AtomicValue{TypeName: xdm.TypeString, Value: p}
	}

	return result, nil
}

// splitXMLWhitespace splits s on XML whitespace (#x20, #x9, #xA, #xD),
// stripping leading/trailing whitespace and collapsing runs. Unlike
// strings.Fields, it does NOT treat Unicode whitespace (e.g. \u00A0) as
// separators.
func splitXMLWhitespace(s string) []string {
	var tokens []string

	start := -1

	for i, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if start >= 0 {
				tokens = append(tokens, stringPart(s, start, i))
				start = -1
			}
		} else {
			if start < 0 {
				start = i
			}
		}
	}

	if start >= 0 {
		tokens = append(tokens, stringPart(s, start, len(s)))
	}

	return tokens
}

func fnAnalyzeString(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	s, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	required, err := coerceArgToStringRequired(ctx, args[1])
	if err != nil {
		return nil, err
	}

	flags := ""
	if len(args) > 2 {
		flags, err = coerceArgToString(ctx, args[2])
		if err != nil {
			return nil, err
		}
	}

	if err := checkVersionRegex(ctx, required, flags); err != nil {
		return nil, err
	}

	re, err := compileXPathRegex(ctx, required, flags)
	if err != nil {
		return nil, err
	}

	matchesEmpty, err := re.MatchString(ctx, "")
	if err != nil {
		return nil, regexExecutionError(ctx, err, "regex match failed")
	}

	if matchesEmpty {
		return nil, &xdm.Error{Code: errCodeFORX0003, Message: "analyze-string pattern matches zero-length string"}
	}

	return buildAnalyzeStringResult(ctx, re, s, required, flags)
}

func buildAnalyzeStringResult(ctx context.Context, re *compiledXPathRegex, s, pattern, flags string) (xdm.Sequence, error) {
	doc := xdm.NewDefaultDocument()

	root, err := createAnalyzeStringElement(doc, "analyze-string-result")
	if err != nil {
		return nil, &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("analyze-string: failed to build result: %v", err)}
	}

	if err := root.DeclareNamespace("fn", NSFn); err != nil {
		return nil, &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("analyze-string: failed to build result: %v", err)}
	}

	if err := doc.SetDocumentElement(root); err != nil {
		return nil, &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("analyze-string: failed to build result: %v", err)}
	}

	// The nesting of fn:group elements is a STATIC property of the pattern's
	// capturing parentheses, not of the match positions: e.g. "(b)(x?)" and
	// "(b(x?))" yield identical submatch indices when the inner group is empty at
	// the boundary, yet the first nests the groups as siblings and the second
	// nests group 2 inside group 1. Compute the parent-of relationship once from
	// the pattern; the per-match positions only drive text distribution and which
	// groups participated.
	groupParents := analyzeStringGroupParents(pattern, flags)

	// Stream the matches one at a time instead of materializing every match up
	// front. An input with a huge number of matches would otherwise allocate the
	// full match slice (an O(matches) up-front cost) and build the whole result
	// tree before the op budget or a cancellation could intervene. When an op
	// budget is in force, cap the enumeration at remaining+1 matches so the
	// callback observes the one match that exhausts the budget and rejects
	// without producing the rest; an unbounded budget streams uncapped.
	ec := getFnContext(ctx)
	findLimit := -1

	if remaining, bounded := fnRemainingOps(ec); bounded {
		if n := remaining + 1; n > 0 {
			findLimit = n
		}
	}

	pos := 0

	var buildErr error

	buildFail := func(err error) bool {
		buildErr = &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("analyze-string: failed to build result: %v", err)}
		return false
	}
	iterErr := re.eachStringSubmatchIndex(ctx, s, findLimit, func(m []int) bool {
		// Charge the op-limit and honor context cancellation BEFORE building any
		// result nodes for this match: an over-budget or cancelled run stops here
		// instead of emitting an element first, and the full match slice is never
		// materialized up front.
		if err := fnCountOp(ctx, ec); err != nil {
			buildErr = err
			return false
		}

		start, end := m[0], m[1]
		if start > pos {
			if err := appendAnalyzeStringTextElement(doc, root, "non-match", s[pos:start]); err != nil {
				return buildFail(err)
			}
		}

		matchElem, err := createAnalyzeStringElement(doc, "match")
		if err != nil {
			return buildFail(err)
		}

		if err := buildAnalyzeStringMatch(doc, matchElem, s, m, groupParents); err != nil {
			return buildFail(err)
		}

		if err := root.AddChild(matchElem); err != nil {
			return buildFail(err)
		}

		pos = end

		return true
	})

	if buildErr != nil {
		return nil, buildErr
	}

	if iterErr != nil {
		return nil, regexExecutionError(ctx, iterErr, "regex match failed")
	}

	if pos < len(s) {
		if err := appendAnalyzeStringTextElement(doc, root, "non-match", s[pos:]); err != nil {
			return nil, &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("analyze-string: failed to build result: %v", err)}
		}
	}

	return xdm.ItemSlice{xdm.NodeItem{Node: root}}, nil
}

// analyzeStringGroup is a node in the capture-group tree for a single regex
// match. Nesting comes from the pattern's static parenthesis structure (F&O 3.1
// §5.6.5 fn:analyze-string); the start/end spans come from the match and drive
// text distribution.
type analyzeStringGroup struct {
	nr       int
	start    int
	end      int
	children []*analyzeStringGroup
}

// analyzeStringGroupParents computes, from the regex pattern, the parent group
// number of each capturing group. parents[i] is the parent of capturing group
// i+1 (1-based group numbers); 0 means the group is a direct child of the match.
// Group numbering follows XPath/XSD regex: the N-th capturing "(" (one NOT
// introducing a "(?..." non-capturing/modifier group) is group N. Escapes, XSD
// character-class subexpressions, and non-capturing groups are handled so the
// static nesting is exact even when two patterns produce identical match spans
// (e.g. "(b)(x?)" siblings vs "(b(x?))" nested).
//
// It MUST tokenize the SAME pattern the regex engine compiles, so it applies the
// identical preprocessing first: the "q" flag makes the whole pattern a literal
// (no groups), and the "x" flag (F&O 3.1 §5.6.1.1) runs stripFreeSpacing to
// remove unescaped whitespace (EXACTLY #x9/#xA/#xD/#x20) outside character
// classes — the same normalization compileXPathRegex applies before compiling.
// Deriving parents from the raw pattern instead would diverge from the compiler
// (e.g. "( a \ ) (b) )" with "x" compiles to "(a\)(b))" — group 2 nested in
// group 1 — but the raw form looks like two siblings).
func analyzeStringGroupParents(pattern, flags string) []int {
	if strings.ContainsRune(flags, 'q') {
		return nil // literal pattern: no capturing groups
	}

	if strings.ContainsRune(flags, 'x') {
		pattern = stripFreeSpacing(pattern)
	}

	rs := []rune(pattern)

	var parents []int
	// stack holds open group numbers; a non-capturing/modifier group pushes 0 so
	// it still balances its closing ")" without becoming a capture parent.
	var stack []int

	groupNum := 0
	inClass := false
	classStart := -1

	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if c == '\\' {
			i++ // an escaped char is a single 2-char token; skip its operand
			continue
		}

		if inClass {
			if c == ']' && i != classStart {
				inClass = false
			}

			continue
		}

		switch c {
		case '[':
			inClass = true

			classStart = i + 1
			if i+1 < len(rs) && rs[i+1] == '^' {
				classStart = i + 2
			}
		case '(':
			// After stripFreeSpacing no significant whitespace remains, so a "(?"
			// non-capturing/modifier group is detected by the immediate next rune.
			if i+1 < len(rs) && rs[i+1] == '?' {
				stack = append(stack, 0)
				continue
			}

			groupNum++
			parent := nearestCapturingGroup(stack)

			parents = append(parents, parent)
			stack = append(stack, groupNum)
		case ')':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}

	return parents
}

func nearestCapturingGroup(stack []int) int {
	for _, open := range slices.Backward(stack) {
		if open > 0 {
			return open
		}
	}

	return 0
}

// isXPathRegexWhitespace reports whether r is whitespace removed by the XPath/XSD
// regex "x" flag (F&O 3.1 §5.6.1.1): EXACTLY the four XML whitespace characters
// #x9, #xA, #xD, #x20. It is deliberately narrower than unicode.IsSpace — e.g.
// U+00A0 (NBSP) and other Unicode spaces are literal regex characters and must
// be preserved. Shared by every "x"-flag site (fn:matches/replace/tokenize via
// stripFreeSpacing, and fn:analyze-string group counting).
func isXPathRegexWhitespace(r rune) bool {
	return r == 0x09 || r == 0x0A || r == 0x0D || r == 0x20
}

// buildAnalyzeStringMatch populates matchElem with the fn:group hierarchy and
// interleaved text for one regex match. m is the submatch-index slice
// (m[0],m[1] = whole match; m[2g],m[2g+1] = group g); groupParents gives the
// static nesting. Nested capturing groups produce nested fn:group elements; the
// matched substring text is distributed so that each fn:group holds the text of
// its span not covered by a nested child, in document order. A capturing group
// that did not participate in the match (start < 0) produces no fn:group element.
//
// The fundamental invariant of fn:analyze-string is that the string value of the
// fn:match (the concatenation of all descendant text) equals the matched input
// substring. The pattern-derived nesting is the primary tree, but if it ever
// disagrees with the input (a tokenization edge would duplicate or drop text),
// fall back to a position-derived containment tree — which nests strictly by
// span containment and therefore ALWAYS reproduces the matched substring — and,
// as a final floor, to a group-less match holding just the text. Output whose
// string value differs from the input is never emitted.
func buildAnalyzeStringMatch(doc *xdm.Document, matchElem *xdm.Element, s string, m []int, groupParents []int) error {
	want := s[m[0]:m[1]]

	root := buildAnalyzeStringTreeByPattern(m, groupParents)
	if analyzeStringGroupText(root, s) != want {
		root = buildAnalyzeStringTreeByPosition(m)
	}

	if analyzeStringGroupText(root, s) != want {
		// Position containment should always preserve the string value for real
		// regex spans; this floor guarantees the invariant regardless.
		root = &analyzeStringGroup{nr: 0, start: m[0], end: m[1]}
	}

	return renderAnalyzeStringGroup(doc, matchElem, root, s)
}

// buildAnalyzeStringTreeByPattern nests the participating capturing groups using
// the static parent-of relationship derived from the pattern (groupParents).
func buildAnalyzeStringTreeByPattern(m []int, groupParents []int) *analyzeStringGroup {
	root := &analyzeStringGroup{nr: 0, start: m[0], end: m[1]}
	// Size the node table off the MATCH's group count, never off groupParents:
	// if the static parenthesis analysis and the compiled regex ever disagree on
	// the group count, this must not index out of range — analyzeStringParentOf
	// then treats an unknown group as a direct child of the match, which is
	// well-formed, and never panics.
	numGroups := len(m)/2 - 1
	nodes := make([]*analyzeStringGroup, numGroups+1)
	nodes[0] = root

	for g := 1; g <= numGroups; g++ {
		gs, ge := m[2*g], m[2*g+1]
		if gs < 0 {
			continue // group did not participate in the match
		}

		nodes[g] = &analyzeStringGroup{nr: g, start: gs, end: ge}
	}
	// Attach each participating group under its nearest participating ancestor.
	// Groups are numbered in opening-paren (document) order, so appending in that
	// order keeps sibling groups in document order.
	for g := 1; g <= numGroups; g++ {
		node := nodes[g]
		if node == nil {
			continue
		}

		parent := root

		for p := analyzeStringParentOf(groupParents, g); p > 0; p = analyzeStringParentOf(groupParents, p) {
			if p < len(nodes) && nodes[p] != nil {
				parent = nodes[p]
				break
			}
		}

		parent.children = append(parent.children, node)
	}

	return root
}

// buildAnalyzeStringTreeByPosition nests the participating capturing groups purely
// by span containment: processing groups in document (numeric) order, each group
// attaches under the innermost open ancestor whose span contains it. Real regex
// group spans are always properly nested or disjoint, so the resulting tree tiles
// the matched substring exactly — its string value always equals the input. This
// is the string-value-safe fallback when the pattern-derived nesting diverges.
func buildAnalyzeStringTreeByPosition(m []int) *analyzeStringGroup {
	root := &analyzeStringGroup{nr: 0, start: m[0], end: m[1]}
	stack := []*analyzeStringGroup{root}

	for g := 1; g < len(m)/2; g++ {
		gs, ge := m[2*g], m[2*g+1]
		if gs < 0 {
			continue
		}

		node := &analyzeStringGroup{nr: g, start: gs, end: ge}

		for len(stack) > 1 {
			top := stack[len(stack)-1]
			if top.start <= gs && ge <= top.end {
				break
			}

			stack = stack[:len(stack)-1]
		}

		parent := stack[len(stack)-1]
		parent.children = append(parent.children, node)
		stack = append(stack, node)
	}

	return root
}

// analyzeStringGroupText returns the string value a node would render: the text
// of its span not covered by a child interleaved with each child's rendered text,
// in document order — mirroring renderAnalyzeStringGroup exactly so the invariant
// check reflects the actual output.
func analyzeStringGroupText(node *analyzeStringGroup, s string) string {
	var b strings.Builder

	cursor := node.start
	for _, child := range node.children {
		if child.start > cursor {
			b.WriteString(s[cursor:child.start])
		}

		b.WriteString(analyzeStringGroupText(child, s))
		cursor = child.end
	}

	if cursor < node.end {
		b.WriteString(s[cursor:node.end])
	}

	return b.String()
}

// analyzeStringParentOf returns the static parent group number of group g, or 0
// (a direct child of the match) when g is outside the derived parents table.
func analyzeStringParentOf(groupParents []int, g int) int {
	if g >= 1 && g <= len(groupParents) {
		return groupParents[g-1]
	}

	return 0
}

// renderAnalyzeStringGroup emits, into parent, the text spans of node not covered
// by a child group interleaved with the child fn:group elements, in document order.
func renderAnalyzeStringGroup(doc *xdm.Document, parent *xdm.Element, node *analyzeStringGroup, s string) error {
	cursor := node.start
	for _, child := range node.children {
		if child.start > cursor {
			if err := parent.AppendText(s[cursor:child.start]); err != nil {
				return err
			}
		}

		groupElem, err := createAnalyzeStringElement(doc, "group")
		if err != nil {
			return err
		}

		if err := groupElem.SetAttribute("nr", fmt.Sprintf("%d", child.nr)); err != nil {
			return err
		}

		if err := renderAnalyzeStringGroup(doc, groupElem, child, s); err != nil {
			return err
		}

		if err := parent.AddChild(groupElem); err != nil {
			return err
		}

		cursor = child.end
	}

	if cursor < node.end {
		if err := parent.AppendText(s[cursor:node.end]); err != nil {
			return err
		}
	}

	return nil
}

func createAnalyzeStringElement(doc *xdm.Document, localName string) (*xdm.Element, error) {
	elem, err := doc.CreateElement(localName)
	if err != nil {
		return nil, err
	}

	if err := elem.SetActiveNamespace("fn", NSFn); err != nil {
		return nil, err
	}

	return elem, nil
}

func appendAnalyzeStringTextElement(doc *xdm.Document, parent *xdm.Element, localName, text string) error {
	elem, err := createAnalyzeStringElement(doc, localName)
	if err != nil {
		return err
	}

	if text != "" {
		if err := elem.AppendText(text); err != nil {
			return err
		}
	}

	return parent.AddChild(elem)
}

// All XPath regular expressions use one immutable, bounded pattern program.
type (
	compiledXPathRegex struct{ program *pattern.Program }
	xpathRegexCacheKey struct{ pattern, flags string }
)

func (r *compiledXPathRegex) MatchString(ctx context.Context, s string) (bool, error) {
	return r.program.Match(ctx, s, patternWork(ctx))
}

func (r *compiledXPathRegex) NumSubexp() int { return r.program.Groups() }

func (r *compiledXPathRegex) ReplaceAllString(ctx context.Context, s, replacement string) (string, error) {
	var out []byte

	last := 0

	var failure error

	err := r.program.Each(ctx, s, -1, patternWork(ctx), func(m []int) bool {
		if failure = ChargeString(ctx, m[0]-last); failure != nil {
			return false
		}

		out = append(out, s[last:m[0]]...)

		out, failure = pattern.AppendReplacement(out, replacement, s, m, func(n int) error { return ChargeString(ctx, n) })
		if failure != nil {
			return false
		}

		last = m[1]

		return true
	})
	if err != nil {
		return "", err
	}

	if failure != nil {
		return "", failure
	}

	if err = ChargeString(ctx, len(s)-last); err != nil {
		return "", err
	}

	out = append(out, s[last:]...)

	return string(out), nil
}

func (r *compiledXPathRegex) Split(ctx context.Context, s string, n int) ([]string, error) {
	var out []string

	last := 0

	var failure error

	limit := -1
	if n > 0 {
		limit = n - 1
	}

	err := r.program.Each(ctx, s, limit, patternWork(ctx), func(m []int) bool {
		if failure = Charge(ctx, 1); failure != nil {
			return false
		}

		out = append(out, stringPart(s, last, m[0]))
		last = m[1]

		return true
	})
	if err != nil {
		return nil, err
	}

	if failure != nil {
		return nil, failure
	}

	return append(out, stringPart(s, last, len(s))), nil
}

// stringPart detaches a proper substring so a small value cannot retain the
// complete source. An unchanged string keeps its existing immutable storage.
func stringPart(s string, start, end int) string {
	if start == 0 && end == len(s) {
		return s
	}

	return strings.Clone(s[start:end])
}

func (r *compiledXPathRegex) FindAllStringSubmatchIndex(ctx context.Context, s string, n int) ([][]int, error) {
	var out [][]int

	err := r.program.Each(ctx, s, n, patternWork(ctx), func(m []int) bool { out = append(out, append([]int(nil), m...)); return true })

	return out, err
}

func (r *compiledXPathRegex) eachStringSubmatchIndex(ctx context.Context, s string, limit int, fn func([]int) bool) error {
	if limit <= 0 {
		limit = -1
	}

	return r.program.Each(ctx, s, limit, patternWork(ctx), fn)
}

func patternWork(ctx context.Context) pattern.Work {
	return pattern.Work{Charge: func(n int) error { return Charge(ctx, n) }}
}

// compileXPathRegex reuses immutable programs within the owning runtime.
func compileXPathRegex(ctx context.Context, source, flags string) (*compiledXPathRegex, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(source) > 64<<10 {
		return nil, pattern.ErrLimit
	}

	if XMLSchemaVersion(ctx) == 10 && !strings.ContainsRune(flags, 'q') {
		checked := source
		if strings.ContainsRune(flags, 'x') {
			checked = stripFreeSpacing(checked)
		}

		if err := Charge(ctx, len(checked)); err != nil {
			return nil, err
		}

		if err := xpathregex.ValidateXSD10(checked); err != nil {
			return nil, xsdRegexError(err)
		}
	}

	ec := getFnContext(ctx)
	if ec == nil || ec.runtime == nil {
		return compileXPathRegexUncached(source, flags)
	}

	cache := ec.runtime.regexCache()
	key := xpathRegexCacheKey{pattern: source, flags: flags}

	if cached, ok := cache.Load(key); ok {
		return cached, nil
	}

	// Dynamic keys may be slices of much larger caller-owned strings. Bound
	// retained key bytes and compile from owned strings on a cache miss.
	if len(source) > 64<<10 || len(flags) > (64<<10)-len(source) {
		return compileXPathRegexUncached(source, flags)
	}

	key.pattern, key.flags = strings.Clone(source), strings.Clone(flags)

	compiled, err := compileXPathRegexUncached(key.pattern, key.flags)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	actual, _ := cache.LoadOrStore(key, compiled)

	return actual, nil
}

func compileXPathRegexUncached(source, flags string) (*compiledXPathRegex, error) {
	if len(source) > 64<<10 {
		return nil, pattern.ErrLimit
	}

	options := pattern.Options{Property: xpathregex.ResolveProperty, XPathAnchors: true}

	for _, flag := range flags {
		switch flag {
		case 'i':
			options.IgnoreCase = true
		case 'm':
			options.Multiline = true
		case 's':
			options.DotAll = true
		case 'x':
		case 'q':
			options.Literal = true
		default:
			return nil, &xdm.Error{Code: errCodeFORX0001, Message: fmt.Sprintf("invalid regex flag: %c", flag)}
		}
	}

	if !options.Literal {
		if strings.ContainsRune(flags, 'x') {
			source = stripFreeSpacing(source)
		}

		if err := rejectPerlSpecific(source); err != nil {
			return nil, err
		}

		if err := validateXPathRegex(source, hasXPathBackrefs(source)); err != nil {
			return nil, err
		}

		translated, err := translateXPathRegex(source, options.DotAll, options.IgnoreCase)
		if err != nil {
			return nil, err
		}

		source = translated
	}

	program, err := pattern.Compile(source, options)
	if err != nil {
		if errors.Is(err, pattern.ErrLimit) {
			return nil, err
		}

		return nil, &xdm.Error{Code: lexicon.ErrFORX0002, Message: err.Error(), Cause: err}
	}

	return &compiledXPathRegex{program: program}, nil
}

// stripFreeSpacing removes unescaped whitespace from a regex pattern (x flag).
func stripFreeSpacing(pattern string) string {
	var b strings.Builder

	runes := []rune(pattern)
	inCharClass := 0

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '\\' && i+1 < len(runes) {
			next := i + 1
			if inCharClass == 0 && isXPathRegexWhitespace(runes[next]) {
				for next < len(runes) && isXPathRegexWhitespace(runes[next]) {
					next++
				}

				if next >= len(runes) {
					b.WriteRune(r)
					break
				}
			}

			b.WriteRune(r)

			i = next
			b.WriteRune(runes[i])

			continue
		}

		switch r {
		case '[':
			inCharClass++
		case ']':
			if inCharClass > 0 {
				inCharClass--
			}
		}

		if inCharClass == 0 && isXPathRegexWhitespace(r) {
			continue
		}

		b.WriteRune(r)
	}

	return b.String()
}

// fnContainsToken implements fn:contains-token($input, $token [, $collation])
// Returns true if any string in $input, after tokenizing on whitespace,
// matches $token (compared case-insensitively if collation is default).
func fnContainsToken(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	coll, err := getCollation(ctx, args, 2)
	if err != nil {
		return nil, err
	}

	token, err := coerceArgToStringRequired(ctx, args[1])
	if err != nil {
		return nil, err
	}

	token = strings.Trim(token, " \t\r\n")
	if token == "" {
		return xdm.SingleBoolean(false), nil
	}

	for item := range xdm.SequenceItems(args[0]) {
		a, err := AtomizeItem(item)
		if err != nil {
			return nil, err
		}

		s, _ := atomicToString(a)
		for _, tok := range splitXMLWhitespace(s) {
			if coll.compare(tok, token) == 0 {
				return xdm.SingleBoolean(true), nil
			}
		}
	}

	return xdm.SingleBoolean(false), nil
}

// getCollation resolves the collation from function arguments.
// If a collation argument is provided, it resolves it using the base URI from the eval context.
// Otherwise returns the default codepoint collation.
func getCollation(ctx context.Context, args []xdm.Sequence, collationArgIdx int) (*collationImpl, error) {
	baseURI := ""
	if fc := getFnContext(ctx); fc != nil {
		baseURI = fc.baseURI
		if collationArgIdx >= len(args) || xdm.SequenceLen(args[collationArgIdx]) == 0 {
			if fc.defaultCollation != "" {
				return resolveContextCollation(ctx, fc.defaultCollation, baseURI)
			}

			return newCodepointCollation(), nil
		}
	} else if collationArgIdx >= len(args) || xdm.SequenceLen(args[collationArgIdx]) == 0 {
		return newCodepointCollation(), nil
	}

	uri, err := coerceArgToString(ctx, args[collationArgIdx])
	if err != nil {
		return nil, err
	}

	return resolveContextCollation(ctx, uri, baseURI)
}
