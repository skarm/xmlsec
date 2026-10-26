// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

const (
	jsonHexLower = "0123456789abcdef"
	jsonHexUpper = "0123456789ABCDEF"
)

func lookupFunctionsJSON(name string) (*builtinFunc, bool) {
	switch name {
	case "parse-json":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnParseJSON}, true
	case "json-doc":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnJSONDoc}, true
	}

	return nil, false
}

// jsonOptions holds parsed options for fn:parse-json.
type jsonOptions struct {
	fallback   *xdm.FunctionItem
	invalidEsc map[rune]string
	duplicates string // "reject", "use-first", "use-last" (default)
	liberal    bool
	escape     bool
	validate   bool // validate=true(): type-annotate the json-to-xml result tree
	// retainNumberLexical selects fn:json-to-xml's number handling: it retains a
	// JSON number's exact lexical form in the <number> element (F&O 3.1, W3C bug
	// 28179), whereas fn:parse-json/fn:json-doc (false) map every JSON number to
	// the canonical xs:double.
	retainNumberLexical bool
}

func fnParseJSON(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// Route empty detection through post-atomization: an empty array or a
	// nilled/empty-content typed node atomizes to the empty sequence, which per
	// F&O 3.1 makes fn:parse-json return the empty sequence — not an empty JSON
	// string. A raw seqLen==0 gate would only catch a syntactically empty
	// argument and let an atomized-empty one fall through to the "" path.
	s, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	opts, err := parseJSONOptions(ctx, args)
	if err != nil {
		return nil, err
	}

	s, invalidEsc, err := preprocessJSONStringLiterals(s)
	if err != nil {
		return nil, err
	}

	opts.invalidEsc = invalidEsc

	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()

	item, err := parseJSONValue(ctx, dec, opts, newJSONBudget(ctx), 0)
	if err != nil {
		return nil, err
	}

	// Check for trailing content after the JSON value
	var extra json.Token

	extra, err = dec.Token()
	if err == nil {
		return nil, &xdm.Error{Code: errCodeFOJS0001, Message: fmt.Sprintf("unexpected trailing content after JSON value: %v", extra)}
	}

	if !errors.Is(err, io.EOF) {
		return nil, &xdm.Error{Code: errCodeFOJS0001, Message: fmt.Sprintf("invalid trailing content: %v", err), Cause: err}
	}

	if item == nil {
		return nil, nil
	}

	return xdm.ItemSlice{item}, nil
}

// parseJSONOptions extracts and validates options from the second argument.
func parseJSONOptions(ctx context.Context, args []xdm.Sequence) (jsonOptions, error) {
	opts := jsonOptions{duplicates: duplicatesUseFirst} // XPath spec default.
	if len(args) <= 1 || xdm.SequenceLen(args[1]) == 0 {
		return opts, nil
	}

	if xdm.SequenceLen(args[1]) > 1 {
		return opts, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "options argument must be a single map"}
	}

	options, ok := args[1].Get(0).(xdm.MapItem)
	if !ok {
		return opts, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("options argument must be a map, got %T", args[1].Get(0))}
	}

	var err error

	opts.liberal, err = parseJSONBooleanOption(ctx, options, "liberal")
	if err != nil {
		return opts, err
	}

	opts.duplicates, err = parseJSONDuplicatesOption(ctx, options)
	if err != nil {
		return opts, err
	}

	opts.escape, err = parseJSONBooleanOption(ctx, options, "escape")
	if err != nil {
		return opts, err
	}

	err = finalizeJSONFallbackOption(ctx, options, &opts)

	return opts, err
}

func parseJSONBooleanOption(ctx context.Context, options xdm.MapItem, name string) (bool, error) {
	value, found := options.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: name})
	if !found {
		return false, nil
	}

	converted, err := coerceFuncallArg(ctx, value, stAtomic(xdm.TypeBoolean, xdm.OccurrenceExactlyOne), "JSON option "+name, 0, getFnContext(ctx))
	if err != nil {
		return false, err
	}

	atom, ok := converted.Get(0).(xdm.AtomicValue)
	if !ok {
		return false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "boolean option did not yield an atomic value"}
	}

	return atom.BooleanVal(), nil
}

func parseJSONDuplicatesOption(ctx context.Context, options xdm.MapItem) (string, error) {
	value, found := options.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: nameDuplicates})
	if !found {
		return duplicatesUseFirst, nil
	}

	// Apply option function conversion before cardinality: arrays flatten, and
	// an element-only typed node must retain its FOTY0012 error.
	policy, err := coerceArgToStringRequired(ctx, value)
	if err != nil {
		if isNoTypedValueError(err) {
			return duplicatesUseFirst, err
		}

		return duplicatesUseFirst, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "option 'duplicates' must be a single string", Cause: err}
	}

	switch policy {
	case duplicatesReject, duplicatesUseFirst, nameUseLast:
		return policy, nil
	default:
		return duplicatesUseFirst, &xdm.Error{Code: errCodeFOJS0005, Message: fmt.Sprintf("invalid value for 'duplicates' option: %q", policy)}
	}
}

func finalizeJSONFallbackOption(ctx context.Context, options xdm.MapItem, opts *jsonOptions) error {
	value, found := options.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: nameFallback})
	if !found {
		return nil
	}

	required := stFunc([]xdm.SequenceType{stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne)}, stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne))

	converted, err := coerceFuncallArg(ctx, value, required, "JSON fallback option", 0, getFnContext(ctx))
	if err != nil {
		return err
	}

	fallback, ok := converted.Get(0).(xdm.FunctionItem)
	if !ok {
		return &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fallback option did not yield a function"}
	}

	if opts.escape {
		return &xdm.Error{Code: errCodeFOJS0005, Message: "fallback cannot be combined with escape=true()"}
	}

	opts.fallback = &fallback

	return nil
}

// jsonBudget threads the evaluator's DoS bounds into the streaming JSON parseOptions
// shared by fn:parse-json and fn:json-to-xml. Without it, a large or deeply
// nested JSON string would build an unbounded in-memory map/array structure
// with no op-limit, node-set, depth, or cancellation accounting, bypassing the
// engine's evaluation budget. ec may be nil when the functions run outside an
// evaluation, in which case the package defaults still apply so the constructed
// structure stays bounded.
type jsonBudget struct {
	ec       *evalContext
	maxNodes int
	maxDepth int
}

func newJSONBudget(ctx context.Context) *jsonBudget {
	ec := getFnContext(ctx)

	maxDepth := DefaultMaxRecursionDepth
	if ec != nil && ec.maxRecursionDepth > 0 {
		maxDepth = ec.maxRecursionDepth
	}

	return &jsonBudget{ec: ec, maxNodes: fnMaxNodes(ec), maxDepth: maxDepth}
}

// enter accounts for one level of object/array nesting and rejects input that
// nests deeper than the recursion limit, so adversarial JSON cannot exhaust the
// goroutine stack. It returns the incremented depth for nested calls.
func (b *jsonBudget) enter(depth int) (int, error) {
	depth++
	if b.maxDepth > 0 && depth > b.maxDepth {
		return depth, ErrRecursionLimit
	}

	return depth, nil
}

// charge accounts for one constructed map entry or array member: it bounds the
// running member count against maxNodes and charges one op (which also honors
// context cancellation), so a wide JSON container respects OpLimit and stays
// cancellable.
func (b *jsonBudget) charge(ctx context.Context, count int) error {
	if b.maxNodes > 0 && count+1 > b.maxNodes {
		return ErrNodeSetLimit
	}

	return fnCountOp(ctx, b.ec)
}

func parseJSONValue(ctx context.Context, dec *json.Decoder, opts jsonOptions, b *jsonBudget, depth int) (xdm.Item, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, &xdm.Error{Code: errCodeFOJS0001, Message: fmt.Sprintf("invalid JSON: %v", err), Cause: err}
	}

	return parseJSONToken(ctx, tok, dec, opts, b, depth)
}

func parseJSONToken(ctx context.Context, token json.Token, dec *json.Decoder, opts jsonOptions, budget *jsonBudget, depth int) (xdm.Item, error) {
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			return parseJSONObject(ctx, dec, opts, budget, depth)
		case '[':
			return parseJSONArray(ctx, dec, opts, budget, depth)
		default:
			return nil, &xdm.Error{Code: errCodeFOJS0001, Message: fmt.Sprintf("unexpected JSON delimiter: %q", value)}
		}
	case string:
		text, err := applyJSONStringOptions(ctx, value, opts)
		if err != nil {
			return nil, err
		}

		return xdm.AtomicValue{TypeName: xdm.TypeString, Value: text}, nil
	case json.Number:
		if opts.retainNumberLexical {
			return xdm.JSONNumber{Lexical: value.String()}, nil
		}

		return jsonToXDM(value)
	default:
		return jsonToXDM(value)
	}
}

func parseJSONObject(ctx context.Context, dec *json.Decoder, opts jsonOptions, budget *jsonBudget, depth int) (xdm.Item, error) {
	depth, err := budget.enter(depth)
	if err != nil {
		return nil, err
	}

	object := jsonObjectBuilder{entries: make([]xdm.MapEntry, 0), index: make(map[string]int), duplicates: opts.duplicates}
	for dec.More() {
		if err := budget.charge(ctx, len(object.entries)); err != nil {
			return nil, err
		}

		key, err := parseJSONObjectKey(ctx, dec, opts)
		if err != nil {
			return nil, err
		}

		value, err := parseJSONValue(ctx, dec, opts, budget, depth)
		if err != nil {
			return nil, err
		}

		// Parse the entire value before resolving duplicate keys.
		if err := object.add(key, value); err != nil {
			return nil, err
		}
	}

	if err := consumeJSONClose(dec, '}', "object"); err != nil {
		return nil, err
	}

	return xdm.NewMap(object.entries), nil
}

type jsonObjectBuilder struct {
	entries    []xdm.MapEntry
	index      map[string]int
	duplicates string
}

func (b *jsonObjectBuilder) add(key string, item xdm.Item) error {
	value := jsonItemSequence(item)

	if previous, found := b.index[key]; found {
		switch b.duplicates {
		case duplicatesReject:
			return &xdm.Error{Code: errCodeFOJS0003, Message: fmt.Sprintf("duplicate key in JSON object: %q", key)}
		case duplicatesUseFirst:
			return nil
		case nameUseLast:
			b.entries[previous].Value = value
			return nil
		}
	}

	b.index[key] = len(b.entries)
	b.entries = append(b.entries, xdm.MapEntry{
		Key: xdm.AtomicValue{TypeName: xdm.TypeString, Value: key}, Value: value,
	})

	return nil
}

func jsonItemSequence(item xdm.Item) xdm.Sequence {
	if item == nil {
		return nil
	}

	return xdm.ItemSlice{item}
}

func parseJSONObjectKey(ctx context.Context, dec *json.Decoder, opts jsonOptions) (string, error) {
	token, err := dec.Token()
	if err != nil {
		return "", &xdm.Error{Code: errCodeFOJS0001, Message: fmt.Sprintf("invalid JSON: %v", err), Cause: err}
	}

	key, ok := token.(string)
	if !ok {
		return "", &xdm.Error{Code: errCodeFOJS0001, Message: "invalid JSON object key"}
	}

	return applyJSONStringOptions(ctx, key, opts)
}

func parseJSONArray(ctx context.Context, dec *json.Decoder, opts jsonOptions, budget *jsonBudget, depth int) (xdm.Item, error) {
	depth, err := budget.enter(depth)
	if err != nil {
		return nil, err
	}

	members := make([]xdm.Sequence, 0)
	for dec.More() {
		if err := budget.charge(ctx, len(members)); err != nil {
			return nil, err
		}

		item, err := parseJSONValue(ctx, dec, opts, budget, depth)
		if err != nil {
			return nil, err
		}

		members = append(members, jsonItemSequence(item))
	}

	if err := consumeJSONClose(dec, ']', "array"); err != nil {
		return nil, err
	}

	return xdm.NewArray(members), nil
}

func consumeJSONClose(dec *json.Decoder, expected json.Delim, kind string) error {
	token, err := dec.Token()
	if err != nil {
		return &xdm.Error{Code: errCodeFOJS0001, Message: fmt.Sprintf("invalid JSON: %v", err), Cause: err}
	}

	if delimiter, ok := token.(json.Delim); !ok || delimiter != expected {
		return &xdm.Error{Code: errCodeFOJS0001, Message: "invalid JSON: expected " + kind + " close delimiter"}
	}

	return nil
}

func preprocessJSONStringLiterals(source string) (string, map[rune]string, error) {
	preprocessor := jsonStringPreprocessor{source: source, invalidEsc: make(map[rune]string)}
	inString := false

	for i := 0; i < len(source); {
		char, size := utf8.DecodeRuneInString(source[i:])
		if !inString {
			preprocessor.output.WriteString(source[i : i+size])
			i += size
			inString = char == '"'

			continue
		}

		switch char {
		case '"':
			inString = false

			preprocessor.output.WriteRune(char)

			i += size
		case '\\':
			next, err := preprocessor.writeEscape(i)
			if err != nil {
				return "", nil, err
			}

			i = next
		default:
			if char < 0x20 {
				return "", nil, &xdm.Error{Code: errCodeFOJS0001, Message: "invalid JSON: unescaped control character in string"}
			}

			preprocessor.output.WriteString(source[i : i+size])
			i += size
		}
	}

	return preprocessor.output.String(), preprocessor.invalidEsc, nil
}

type jsonStringPreprocessor struct {
	source     string
	output     strings.Builder
	invalidEsc map[rune]string
}

func (p *jsonStringPreprocessor) writeEscape(offset int) (int, error) {
	if offset+1 >= len(p.source) {
		return 0, &xdm.Error{Code: errCodeFOJS0001, Message: "invalid JSON: trailing backslash in string"}
	}

	switch next := p.source[offset+1]; next {
	case '"', '\\', '/', 'n', 'r', 't':
		p.output.WriteString(p.source[offset : offset+2])
		return offset + 2, nil
	case 'b', 'f':
		if err := p.writePlaceholder(p.source[offset : offset+2]); err != nil {
			return 0, err
		}

		return offset + 2, nil
	case 'u':
		return p.writeUnicodeEscape(offset)
	default:
		return 0, &xdm.Error{Code: errCodeFOJS0001, Message: fmt.Sprintf("invalid JSON: invalid escape sequence \\%c", next)}
	}
}

func (p *jsonStringPreprocessor) writeUnicodeEscape(offset int) (int, error) {
	if offset+6 > len(p.source) {
		return 0, &xdm.Error{Code: errCodeFOJS0001, Message: "invalid JSON: incomplete \\u escape"}
	}

	escapeText := p.source[offset : offset+6]

	codepoint, err := parseJSONHexEscape(p.source[offset+2 : offset+6])
	if err != nil {
		return 0, err
	}

	if validJSONSurrogatePair(p.source, offset, codepoint) {
		p.output.WriteString(p.source[offset : offset+12])
		return offset + 12, nil
	}

	if codepoint >= 0xD800 && codepoint <= 0xDFFF || !isValidXMLCodepoint(int(codepoint)) {
		if err := p.writePlaceholder(escapeText); err != nil {
			return 0, err
		}
	} else {
		p.output.WriteString(escapeText)
	}

	return offset + 6, nil
}

func (p *jsonStringPreprocessor) writePlaceholder(escapeText string) error {
	placeholder, err := nextJSONPlaceholderRune(p.source, p.invalidEsc)
	if err != nil {
		return err
	}

	p.invalidEsc[placeholder] = escapeText
	p.output.WriteRune(placeholder)

	return nil
}

func validJSONSurrogatePair(source string, offset int, high uint32) bool {
	if high < 0xD800 || high > 0xDBFF || offset+12 > len(source) {
		return false
	}

	if source[offset+6] != '\\' || source[offset+7] != 'u' {
		return false
	}

	low, err := parseJSONHexEscape(source[offset+8 : offset+12])

	return err == nil && low >= 0xDC00 && low <= 0xDFFF
}

func parseJSONHexEscape(hex string) (uint32, error) {
	var cp uint32
	for _, c := range hex {
		cp <<= 4

		switch {
		case c >= '0' && c <= '9':
			cp += uint32(c - '0')
		case c >= 'a' && c <= 'f':
			cp += uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			cp += uint32(c-'A') + 10
		default:
			return 0, &xdm.Error{Code: errCodeFOJS0001, Message: fmt.Sprintf("invalid JSON: invalid hex digit in \\u escape: %c", c)}
		}
	}

	return cp, nil
}

func nextJSONPlaceholderRune(source string, used map[rune]string) (rune, error) {
	for r := rune(0xF0000); r <= 0xFFFFD; r++ {
		if _, exists := used[r]; exists {
			continue
		}

		if !strings.ContainsRune(source, r) {
			return r, nil
		}
	}

	return 0, &xdm.Error{Code: errCodeFOJS0001, Message: "exhausted JSON placeholder runes"}
}

func applyJSONStringOptions(ctx context.Context, s string, opts jsonOptions) (string, error) {
	if opts.escape {
		var b strings.Builder

		for _, r := range s {
			if raw, found := opts.invalidEsc[r]; found {
				b.WriteString(canonicalInvalidJSONEscape(raw))

				continue
			}

			appendEscapedJSONStringRune(&b, r)
		}

		return b.String(), nil
	}

	var b strings.Builder

	for _, r := range s {
		raw, found := opts.invalidEsc[r]
		if !found {
			b.WriteRune(r)
			continue
		}

		repl := string(rune(0xFFFD))

		if opts.fallback != nil {
			seq, err := opts.fallback.Invoke(ctx, []xdm.Sequence{xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeString, Value: raw}}})
			if err != nil {
				return "", err
			}

			repl, err = seqToStringErr(ctx, seq)
			if err != nil {
				return "", err
			}
		}

		b.WriteString(repl)
	}

	return b.String(), nil
}

func appendEscapedJSONStringRune(b *strings.Builder, r rune) {
	switch r {
	case '\\':
		b.WriteString(`\\`)
	case '\b':
		b.WriteString(`\b`)
	case '\f':
		b.WriteString(`\f`)
	case '\n':
		b.WriteString(`\n`)
	case '\r':
		b.WriteString(`\r`)
	case '\t':
		b.WriteString(`\t`)
	default:
		if (r >= 0x00 && r <= 0x1F) || !isValidXMLCodepoint(int(r)) {
			appendJSONCodeUnit(b, uint16(r), jsonHexLower)
			return
		}

		b.WriteRune(r)
	}
}

func appendSerializedJSONStringRune(b *strings.Builder, r rune) {
	switch r {
	case '"':
		b.WriteString(`\"`)
	case '\\':
		b.WriteString(`\\`)
	case '/':
		b.WriteString(`\/`)
	case '\b':
		b.WriteString(`\b`)
	case '\f':
		b.WriteString(`\f`)
	case '\n':
		b.WriteString(`\n`)
	case '\r':
		b.WriteString(`\r`)
	case '\t':
		b.WriteString(`\t`)
	default:
		if (r >= 0x00 && r <= 0x1F) || (r >= 0x7F && r <= 0x9F) || !isValidXMLCodepoint(int(r)) {
			appendJSONCodeUnit(b, uint16(r), jsonHexUpper)
			return
		}

		b.WriteRune(r)
	}
}

// appendJSONCodeUnit writes one UTF-16 code unit as a fixed-width JSON escape.
func appendJSONCodeUnit(b *strings.Builder, unit uint16, digits string) {
	escaped := [6]byte{'\\', 'u', digits[unit>>12], digits[(unit>>8)&0x0F], digits[(unit>>4)&0x0F], digits[unit&0x0F]}
	b.Write(escaped[:])
}

func canonicalInvalidJSONEscape(raw string) string {
	switch {
	case strings.EqualFold(raw, `\u0008`):
		return `\b`
	case strings.EqualFold(raw, `\u000c`):
		return `\f`
	default:
		return raw
	}
}

func fnJSONDoc(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// xs:string? URI argument: an atomized-empty value (empty array / nilled
	// node) returns the empty sequence just like a syntactically empty one.
	uri, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	body, err := loadTextResource(ctx, uri, "", false, textResourceJSON, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("json-doc: %w", wrapUnparsedTextError(err))
	}

	// Delegate to parse-json logic, preserving any caller-supplied options.
	parseArgs := []xdm.Sequence{xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeString, Value: body}}}
	if len(args) > 1 {
		parseArgs = append(parseArgs, args[1])
	}

	return fnParseJSON(ctx, parseArgs)
}

func jsonToXDM(v any) (xdm.Item, error) {
	switch val := v.(type) {
	case nil:
		return nil, nil //nolint:nilnil // JSON null maps to empty sequence per XPath spec
	case bool:
		return xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: val}, nil
	case json.Number:
		// Per F&O 3.1 §17.5, JSON has a single number type and every JSON
		// number maps to an xs:double in the XDM result — including integral
		// values such as 0/-0, which therefore become xs:double, not xs:integer.
		s := val.String()

		f, err := val.Float64()
		// The decoder already checked JSON grammar. xs:string to xs:double
		// conversion permits overflow to infinity (F&O 3.1 section 17.5.1).
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return nil, &xdm.Error{Code: errCodeFOJS0001, Message: "invalid JSON number: " + s}
		}

		return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(f)}, nil
	case string:
		return xdm.AtomicValue{TypeName: xdm.TypeString, Value: val}, nil
	case []any:
		members := make([]xdm.Sequence, len(val))
		for i, elem := range val {
			item, err := jsonToXDM(elem)
			if err != nil {
				return nil, err
			}

			if item == nil {
				members[i] = nil // JSON null → empty sequence
			} else {
				members[i] = xdm.ItemSlice{item}
			}
		}

		return xdm.NewArray(members), nil
	case map[string]any:
		entries := make([]xdm.MapEntry, 0, len(val))
		for k, v := range val {
			item, err := jsonToXDM(v)
			if err != nil {
				return nil, err
			}

			var value xdm.Sequence
			if item == nil {
				value = nil // JSON null → empty sequence
			} else {
				value = xdm.ItemSlice{item}
			}

			entries = append(entries, xdm.MapEntry{
				Key:   xdm.AtomicValue{TypeName: xdm.TypeString, Value: k},
				Value: value,
			})
		}

		return xdm.NewMap(entries), nil
	default:
		return nil, &xdm.Error{Code: errCodeFOJS0001, Message: fmt.Sprintf("unexpected JSON type: %T", v)}
	}
}
