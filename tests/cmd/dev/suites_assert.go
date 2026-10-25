package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform"
)

const (
	suiteUTF16BE = "utf-16be"
	suiteUTF16LE = "utf-16le"
)

func checkSuiteAssertion(ctx context.Context, evaluation *suiteEvaluation, assertion *suiteNode) error {
	if assertion == nil {
		return suiteHarness("missing result assertion")
	}

	var harness *suiteHarnessError
	if errors.As(evaluation.err, &harness) {
		return harness
	}

	// Assertion expressions have their own catalog namespace scope, including
	// bindings inherited from all-of/any-of and shadowed by individual children.
	scopedEnvironment := *evaluation.environment
	scopedEnvironment.namespaces = suiteScopedNamespaces(evaluation.environment, assertion)
	scopedEvaluation := *evaluation
	scopedEvaluation.environment = &scopedEnvironment
	evaluation = &scopedEvaluation

	switch assertion.XMLName.Local {
	case suiteResultVariable, "all-of":
		if len(assertion.Children) == 0 {
			return suiteHarness("empty result assertion")
		}

		for _, child := range assertion.Children {
			if err := checkSuiteAssertion(ctx, evaluation, child); err != nil {
				return err
			}
		}

		return nil
	case "any-of":
		var problems []error

		for _, child := range assertion.Children {
			if err := checkSuiteAssertion(ctx, evaluation, child); err == nil {
				return nil
			} else {
				problems = append(problems, err)
			}
		}

		if len(problems) == 0 {
			return suiteHarness("empty any-of assertion")
		}

		return errors.Join(problems...)
	case "not":
		if evaluation.err != nil {
			return fmt.Errorf("execution failed before a negated result assertion: %w", evaluation.err)
		}

		if len(assertion.Children) != 1 {
			return suiteHarness("not requires one assertion")
		}

		err := checkSuiteAssertion(ctx, evaluation, assertion.Children[0])
		if errors.As(err, &harness) {
			return err
		}

		if err == nil {
			return errors.New("negated assertion succeeded")
		}

		return nil
	case "error":
		return suiteErrorAssertion(evaluation.err, assertion.attr("code"), suiteScopedNamespaces(evaluation.environment, assertion))
	case "assert-serialization-error":
		_, err := evaluation.serialized(ctx)
		return suiteErrorAssertion(err, assertion.attr("code"), suiteScopedNamespaces(evaluation.environment, assertion))
	case "assert-result-document":
		return suiteSecondaryAssertion(ctx, evaluation, assertion)
	case "assert-message":
		return suiteMessageAssertion(ctx, evaluation, assertion)
	default:
		if evaluation.err != nil {
			return fmt.Errorf("unexpected execution error: %w", evaluation.err)
		}

		return checkSuiteValueAssertion(ctx, evaluation, assertion)
	}
}

func suiteSecondaryAssertion(ctx context.Context, evaluation *suiteEvaluation, assertion *suiteNode) error {
	if evaluation.err != nil {
		return fmt.Errorf("unexpected execution error: %w", evaluation.err)
	}

	if evaluation.result == nil || len(assertion.Children) != 1 {
		return suiteHarness("secondary assertion requires an XSLT result and one nested assertion")
	}

	uri, err := resolveSuiteURI(evaluation.environment.baseOutputURI, assertion.attr("uri"))
	if err != nil {
		return err
	}

	value, exists := evaluation.result.Secondary()[uri]
	if !exists {
		return fmt.Errorf("secondary result %q was not produced", uri)
	}

	secondary := *evaluation
	secondary.sequence, secondary.secondaryURI = value, uri
	secondary.err = nil

	return checkSuiteAssertion(ctx, &secondary, assertion.Children[0])
}

func suiteMessageAssertion(ctx context.Context, evaluation *suiteEvaluation, assertion *suiteNode) error {
	if len(assertion.Children) != 1 {
		return suiteHarness("message assertion requires one nested assertion")
	}

	messages := evaluation.result.Messages()
	if failure, ok := errors.AsType[*transform.Error](evaluation.err); ok {
		messages = failure.Messages()
	}

	for _, message := range messages {
		value, err := evaluation.environment.query(ctx, "parse-xml-fragment($message)", transform.Bindings{{Local: "message"}: transform.Values(transform.String(message.Text))})
		if err != nil {
			return suiteHarness("message XML: %w", err)
		}

		candidate := *evaluation

		candidate.sequence, candidate.result, candidate.err = value, nil, nil
		if err := checkSuiteAssertion(ctx, &candidate, assertion.Children[0]); err == nil {
			return nil
		} else {
			if _, ok := errors.AsType[*suiteHarnessError](err); ok {
				return err
			}
		}
	}

	return errors.New("no message satisfied the nested assertion")
}

func suiteScopedNamespaces(environment *preparedSuiteEnvironment, node *suiteNode) map[string]string {
	namespaces := make(map[string]string)
	maps.Copy(namespaces, environment.namespaces)

	suiteNamespaceDeclarations(node, namespaces)

	return namespaces
}

func suiteErrorAssertion(actual error, expected string, namespaceOptions ...map[string]string) error {
	var detail *transform.Error
	if errors.As(actual, &detail) && detail.Code != "" {
		for code := range strings.FieldsSeq(expected) {
			if code == "*" {
				return nil
			}

			name := transform.Name{Space: lexicon.NamespaceErr, Local: code}
			if strings.HasPrefix(code, "Q{") {
				space, local, ok := strings.Cut(code[2:], "}")
				if !ok || local == "" {
					return suiteHarness("invalid expected error EQName %q", code)
				}

				name = transform.Name{Space: space, Local: local}
			} else if strings.Contains(code, ":") {
				var namespaces map[string]string
				if len(namespaceOptions) != 0 {
					namespaces = namespaceOptions[0]
				}

				var err error

				name, err = suiteQName(code, namespaces)
				if err != nil {
					return err
				}
			}

			if detail.CodeName() == name {
				return nil
			}
		}
	}

	if actual == nil {
		return fmt.Errorf("expected standard error %q, evaluation succeeded", expected)
	}

	return fmt.Errorf("expected standard error %q, got %w", expected, actual)
}

func checkSuiteValueAssertion(ctx context.Context, e *suiteEvaluation, a *suiteNode) error {
	switch a.XMLName.Local {
	case "assert-empty":
		if e.sequence.Len() != 0 {
			return fmt.Errorf("expected empty sequence, got %d items", e.sequence.Len())
		}
	case "assert-count":
		count, err := strconv.Atoi(strings.TrimSpace(a.Text))
		if err != nil {
			return suiteHarness("invalid count assertion: %w", err)
		}

		if e.sequence.Len() != count {
			return fmt.Errorf("expected %d items, got %d", count, e.sequence.Len())
		}
	case "assert-true", "assert-false":
		value, err := e.sequence.Single()
		if err != nil {
			return fmt.Errorf("expected one boolean: %w", err)
		}

		actual, err := value.Boolean()
		if err != nil {
			return fmt.Errorf("boolean assertion failed: %w", err)
		}

		if actual != (a.XMLName.Local == "assert-true") {
			return errors.New("boolean value did not match the assertion")
		}
	case "assert":
		return e.assertionTrue(ctx, "boolean("+a.Text+")", nil)
	case "assert-eq":
		return e.assertionTrue(ctx, "$result eq ("+a.Text+")", nil)
	case "assert-deep-eq":
		return e.assertionTrue(ctx, "deep-equal($result, ("+a.Text+"))", nil)
	case "assert-type":
		return e.assertionTrue(ctx, "$result instance of "+a.Text, nil)
	case "assert-permutation":
		return suitePermutationAssertion(ctx, e, a.Text)
	case "assert-string-value":
		expression := "string-join(for $item in $result return string($item), ' ') eq $expected"
		if a.attr("normalize-space") == suiteTrue || a.attr("normalize-space") == "1" || a.attr("normalize-space") == "" && e.options.kind == suiteXSLT {
			expression = "normalize-space(string-join(for $item in $result return string($item), ' ')) eq normalize-space($expected)"
		}

		return e.assertionTrue(ctx, expression, transform.Bindings{{Local: "expected"}: transform.Values(transform.String(a.Text))})
	case "assert-xml":
		return suiteXMLAssertion(ctx, e, a)
	case "assert-serialization", "serialization-matches":
		return suiteSerializationAssertion(ctx, e, a)
	default:
		return suiteHarness("assertion %q is not implemented", a.XMLName.Local)
	}

	return nil
}

func suitePermutationAssertion(ctx context.Context, evaluation *suiteEvaluation, expression string) error {
	if err := evaluation.assertionTrue(ctx, "every $item in $result satisfies $item instance of xs:anyAtomicType", nil); err != nil {
		return err
	}

	expected, err := evaluation.assertionValue(ctx, expression, nil)
	if err != nil {
		return err
	}

	if expected.Len() != evaluation.sequence.Len() {
		return errors.New("permutation sequence lengths differ")
	}

	used := make([]bool, expected.Len())
	for index := range evaluation.sequence.Len() {
		value, _ := evaluation.sequence.At(index)
		part := *evaluation
		part.sequence = transform.Values(value)
		matched := false

		for candidate := range expected.Len() {
			if used[candidate] {
				continue
			}

			other, _ := expected.At(candidate)

			err := part.assertionTrue(ctx, "deep-equal($result, $candidate)", transform.Bindings{{Local: "candidate"}: transform.Values(other)})
			if err == nil {
				used[candidate], matched = true, true
				break
			}

			if _, ok := errors.AsType[*suiteHarnessError](err); ok {
				return err
			}
		}

		if !matched {
			return errors.New("no matching unused permutation item")
		}
	}

	return nil
}

func suiteExpectedBytes(e *suiteEvaluation, assertion *suiteNode) ([]byte, error) {
	if file := assertion.attr("file"); file != "" {
		raw, _, err := readSuiteReferencedFile(e.options.directory, e.item.base, assertion)
		if err != nil {
			return nil, suiteHarness("expected result file: %w", err)
		}

		return raw, nil
	}

	return []byte(assertion.Text), nil
}

func suiteXMLAssertion(ctx context.Context, e *suiteEvaluation, assertion *suiteNode) error {
	expected, err := suiteExpectedBytes(e, assertion)
	if err != nil {
		return err
	}

	// assert-xml tests the XDM result independently of a stylesheet's output
	// method, indentation or character maps. Serialize the primary sequence with
	// explicit neutral XML parameters before applying the comparison.
	serialized, err := e.assertionValue(ctx, `serialize($result, map{'method':'xml','omit-xml-declaration':true(),'indent':false()})`, nil)
	if err != nil {
		return err
	}

	actual, err := serialized.Text()
	if err != nil {
		return suiteHarness("result serialization: %w", err)
	}

	left, leftErr := parseSuiteXMLFragment(ctx, e.environment, []byte(actual))

	right, rightErr := parseSuiteXMLFragment(ctx, e.environment, expected)
	if (leftErr != nil || rightErr != nil) && !errors.Is(leftErr, transform.ErrLimit) && !errors.Is(rightErr, transform.ErrLimit) && ctx.Err() == nil {
		// XDM namespace names can be xs:anyURI strings that the XML input
		// profile rejects. Preserve exact namespace identity with one injective
		// table for both sides, then let the ordinary parser check everything
		// else. This fallback does not relax the production XML parser.
		aliases := make(map[string]string)
		maximum := suiteLimits(e.options).MaxInputBytes
		mappedActual, actualErr := rewriteSuiteNamespaceNames(ctx, []byte(actual), aliases, maximum)

		mappedExpected, expectedErr := rewriteSuiteNamespaceNames(ctx, expected, aliases, maximum)
		if errors.Is(actualErr, transform.ErrLimit) || errors.Is(expectedErr, transform.ErrLimit) {
			return fmt.Errorf("namespace comparison limit: %w", errors.Join(actualErr, expectedErr))
		}

		if actualErr == nil && expectedErr == nil {
			left, leftErr = parseSuiteXMLFragment(ctx, e.environment, mappedActual)
			right, rightErr = parseSuiteXMLFragment(ctx, e.environment, mappedExpected)
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if leftErr != nil {
		return fmt.Errorf("actual result is not an XML fragment: %w", leftErr)
	}

	if rightErr != nil {
		return suiteHarness("expected XML fragment: %w", rightErr)
	}

	ignorePrefixes := assertion.attr("ignore-prefixes") == suiteTrue || assertion.attr("ignore-prefixes") == "1"

	return compareSuiteXMLNodes(ctx, left, right, ignorePrefixes)
}

// Rewrite only namespace declaration values; every other original byte stays
// intact, including literal attribute whitespace versus character references.
// All nonreserved, nonempty URIs share one mapping, so a publisher URI that
// already resembles an alias cannot collide with another namespace name.
func rewriteSuiteNamespaceNames(ctx context.Context, data []byte, aliases map[string]string, maximum int) ([]byte, error) {
	if len(data) > maximum {
		return nil, transform.ErrLimit
	}

	if !utf8.Valid(data) {
		return nil, errors.New("namespace comparison fallback requires UTF-8 XML")
	}

	data = bytes.TrimPrefix(data, []byte("\uFEFF"))
	if bytes.HasPrefix(data, []byte("<?xml ")) {
		_, tail, ok := bytes.Cut(data, []byte("?>"))
		if !ok {
			return nil, errors.New("invalid XML declaration")
		}

		data = tail
	}

	decoder := xml.NewDecoder(bytes.NewReader(data)) // #nosec G709 -- Local comparison bytes; RawToken never resolves external entities.

	var output bytes.Buffer

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		start := decoder.InputOffset()

		token, err := decoder.RawToken()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return output.Bytes(), nil
			}

			return nil, err
		}

		span := data[start:decoder.InputOffset()]

		if _, directive := token.(xml.Directive); directive {
			return nil, errors.New("XML directives are outside the namespace comparison fallback")
		}

		if element, ok := token.(xml.StartElement); ok {
			span, err = rewriteSuiteNamespaceStartTag(ctx, span, element.Attr, aliases, maximum)
			if err != nil {
				return nil, err
			}
		}

		if len(span) > maximum-output.Len() {
			return nil, transform.ErrLimit
		}

		output.Write(span)
	}
}

func rewriteSuiteNamespaceStartTag(ctx context.Context, tag []byte, attributes []xml.Attr, aliases map[string]string, maximum int) ([]byte, error) {
	var output bytes.Buffer

	written, position := 0, 0

	for _, attribute := range attributes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// RawToken validated attribute names and quoting. Attribute order is
		// retained, so each next quoted span is the corresponding raw value.
		quoteOffset := bytes.IndexAny(tag[position:], "\"'")
		if quoteOffset < 0 {
			return nil, errors.New("missing attribute quote")
		}

		valueStart := position + quoteOffset + 1

		valueEnd := bytes.IndexByte(tag[valueStart:], tag[valueStart-1])
		if valueEnd < 0 {
			return nil, errors.New("unclosed attribute")
		}

		valueEnd += valueStart
		position = valueEnd + 1

		if attribute.Name.Space != lexicon.PrefixXMLNS && (attribute.Name.Space != "" || attribute.Name.Local != lexicon.PrefixXMLNS) {
			continue
		}

		value := attribute.Value

		if bytes.ContainsAny(tag[valueStart:valueEnd], "\t\r\n") {
			var err error

			value, err = suiteNamespaceAttributeValue(tag[valueStart:valueEnd])
			if err != nil {
				return nil, err
			}
		}

		if value == "" || value == lexicon.NamespaceXML || value == lexicon.NamespaceXMLNS {
			continue
		}

		alias := aliases[value]
		if alias == "" {
			alias = "urn:" + strconv.Itoa(len(aliases))
			aliases[value] = alias
		}

		if output.Len()+valueStart-written+len(alias) > maximum {
			return nil, transform.ErrLimit
		}

		output.Write(tag[written:valueStart])
		output.WriteString(alias)

		written = valueEnd
	}

	if len(tag)-written > maximum-output.Len() {
		return nil, transform.ErrLimit
	}

	output.Write(tag[written:])

	return output.Bytes(), nil
}

func suiteNamespaceAttributeValue(raw []byte) (string, error) {
	// Normalize literal XML whitespace before expanding character references.
	value := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	value = bytes.Map(func(r rune) rune {
		if r == '\t' || r == '\r' || r == '\n' {
			return ' '
		}

		return r
	}, value)
	value = bytes.ReplaceAll(value, []byte("\""), []byte("&quot;"))
	data := append([]byte(`<n a="`), value...)
	data = append(data, []byte(`"/>`)...)
	decoder := xml.NewDecoder(bytes.NewReader(data)) // #nosec G709 -- A single local attribute; no external entities or directives.

	token, err := decoder.RawToken()
	if err != nil {
		return "", err
	}

	element, ok := token.(xml.StartElement)
	if !ok || len(element.Attr) != 1 {
		return "", errors.New("invalid namespace attribute")
	}

	return element.Attr[0].Value, nil
}

func parseSuiteXMLFragment(ctx context.Context, environment *preparedSuiteEnvironment, data []byte) (document.Node, error) {
	data = bytes.TrimPrefix(data, []byte("\uFEFF"))
	if bytes.HasPrefix(data, []byte("<?xml ")) {
		_, tail, ok := bytes.Cut(data, []byte("?>"))
		if !ok {
			return document.Node{}, errors.New("invalid XML declaration")
		}

		data = tail
	}

	// Parse a complete document as such: whitespace outside its root is not
	// content. Fragments use the same language parser, which permits relative
	// namespace names. C14N cannot compare those names, since it must reject them.
	if parsed, err := environment.engine.Parse(ctx, data); err == nil {
		node, _ := parsed.Root().Node()
		return node.Reference(), nil
	} else if errors.Is(err, transform.ErrLimit) || ctx.Err() != nil {
		return document.Node{}, err
	}

	parsed, err := environment.query(ctx, "parse-xml-fragment($xml)", transform.Bindings{{Local: "xml"}: transform.Values(transform.String(string(data)))})
	if err != nil {
		return document.Node{}, err
	}

	value, err := parsed.Single()
	if err != nil {
		return document.Node{}, err
	}

	node, ok := value.Node()
	if !ok {
		return document.Node{}, errors.New("XML parser did not return a node")
	}

	return node.Reference(), nil
}

// Compare parsed XML rather than fn:deep-equal, which ignores comment and PI
// children of elements. Namespace prefixes remain significant unless requested
// otherwise; unused declarations and attribute order do not affect equality.
func compareSuiteXMLNodes(ctx context.Context, left, right document.Node, ignorePrefixes bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if left.Kind() != right.Kind() || left.Name() != right.Name() || !ignorePrefixes && left.Prefix() != right.Prefix() {
		return fmt.Errorf("XML node names differ: %s:%v != %s:%v", left.Prefix(), left.Name(), right.Prefix(), right.Name())
	}

	if left.Kind() != document.DocumentNode && left.Kind() != document.ElementNode && left.Value() != right.Value() {
		return fmt.Errorf("XML node values differ: %.100q != %.100q", left.Value(), right.Value())
	}

	first, _ := left.Element()
	second, _ := right.Element()

	leftAttrs, rightAttrs := first.Attributes(), second.Attributes()
	if len(leftAttrs) != len(rightAttrs) {
		return errors.New("XML attribute counts differ")
	}

	attributes := make(map[document.Name]document.Attribute, len(rightAttrs))
	for _, attribute := range rightAttrs {
		attributes[attribute.Name] = attribute
	}

	for _, attribute := range leftAttrs {
		other, found := attributes[attribute.Name]
		if !found || attribute.Value != other.Value || !ignorePrefixes && attribute.Prefix != other.Prefix {
			return fmt.Errorf("XML attribute differs: %v", attribute.Name)
		}
	}

	leftChildren, rightChildren := left.Children(), right.Children()
	if len(leftChildren) != len(rightChildren) {
		return errors.New("XML child counts differ")
	}

	for i, child := range leftChildren {
		if err := compareSuiteXMLNodes(ctx, child, rightChildren[i], ignorePrefixes); err != nil {
			return err
		}
	}

	return nil
}

func suiteSerializationAssertion(ctx context.Context, e *suiteEvaluation, assertion *suiteNode) error {
	actual, err := e.serialized(ctx)
	if err != nil {
		return fmt.Errorf("unexpected serialization error: %w", err)
	}

	expected, err := suiteExpectedBytes(e, assertion)
	if err != nil {
		return err
	}

	if assertion.XMLName.Local == "serialization-matches" {
		encoding := "UTF-8"
		if e.result != nil {
			encoding, err = e.result.OutputEncoding(e.secondaryURI)
			if err != nil {
				return suiteHarness("serialized encoding: %w", err)
			}
		}

		text, err := suiteSerializedText(actual, encoding)
		if err != nil {
			return suiteHarness("serialized text: %w", err)
		}

		return e.assertionTrue(ctx, "matches($serialized, $pattern, $flags)", transform.Bindings{{Local: "serialized"}: transform.Values(transform.String(text)), {Local: "pattern"}: transform.Values(transform.String(string(expected))), {Local: "flags"}: transform.Values(transform.String(assertion.attr("flags")))})
	}
	// The pinned publisher runner reads expected files as text and removes
	// carriage returns. Accept file CRLF line endings conservatively, retaining
	// bare CR data and every byte of the serializer's actual output.
	encoding := strings.ToLower(assertion.attr("encoding"))

	textFile := encoding == "" || encoding == "utf-8" || encoding == "utf8" || encoding == "iso-8859-1" || encoding == "us-ascii"
	if assertion.attr(suiteFile) != "" && textFile && !bytes.HasPrefix(expected, []byte{0xff, 0xfe}) && !bytes.HasPrefix(expected, []byte{0xfe, 0xff}) {
		expected = bytes.ReplaceAll(expected, []byte("\r\n"), []byte("\n"))
	}

	return compareSuiteBytes("serialized", actual, expected)
}

// Report one bounded excerpt, so large publisher fixtures stay out of reports.
func compareSuiteBytes(kind string, actual, expected []byte) error {
	if !bytes.Equal(actual, expected) {
		offset := 0
		for offset < min(len(actual), len(expected)) && actual[offset] == expected[offset] {
			offset++
		}

		start := max(0, offset-8)

		return fmt.Errorf("%s bytes differ at offset %d (actual %d bytes, expected %d): got %q, want %q", kind, offset, len(actual), len(expected), actual[start:min(len(actual), offset+24)], expected[start:min(len(expected), offset+24)])
	}

	return nil
}

// Regex assertions operate on characters, unlike assert-serialization's octets.
// Encoding comes from the result definition, not the serialized content.
func suiteSerializedText(data []byte, encoding string) (string, error) {
	label := strings.ToLower(encoding)
	if label == "utf-16" || label == "utf16" || label == suiteUTF16BE || label == suiteUTF16LE {
		return suiteSerializedUTF16(data, label)
	}

	if label == "" || label == "utf-8" || label == "utf8" {
		if !utf8.Valid(data) {
			return "", errors.New("serialized text is not UTF-8")
		}

		return string(data), nil
	}

	if label == "ascii" || label == "us-ascii" {
		for _, c := range data {
			if c >= utf8.RuneSelf {
				return "", errors.New("non-ASCII serialized byte")
			}
		}

		return string(data), nil
	}

	codec, err := htmlindex.Get(label)
	if err != nil {
		return "", err
	}

	decoded, err := codec.NewDecoder().Bytes(data)
	if err != nil {
		return "", err
	}

	if bytes.ContainsRune(decoded, utf8.RuneError) {
		// Some codecs replace malformed bytes with U+FFFD without an error.
		// A real U+FFFD is permitted only if it reconstructs these exact bytes.
		roundtrip, err := codec.NewEncoder().Bytes(decoded)
		if err != nil || !bytes.Equal(roundtrip, data) {
			return "", errors.New("invalid serialized byte sequence")
		}
	}

	return string(decoded), nil
}

func suiteSerializedUTF16(data []byte, encoding string) (string, error) {
	littleBOM := bytes.HasPrefix(data, []byte{0xff, 0xfe})
	bigBOM := bytes.HasPrefix(data, []byte{0xfe, 0xff})

	little := encoding == suiteUTF16LE
	switch encoding {
	case "utf16", "utf-16":
		if !littleBOM && !bigBOM {
			return "", errors.New("missing UTF-16 BOM")
		}

		little = littleBOM
	case suiteUTF16LE:
		if bigBOM {
			return "", errors.New("serialized encoding conflicts with UTF-16 BOM")
		}
	case suiteUTF16BE:
		if littleBOM {
			return "", errors.New("serialized encoding conflicts with UTF-16 BOM")
		}
	}

	bom := littleBOM || bigBOM
	if bom {
		data = data[2:]
	}

	if len(data)%2 != 0 {
		return "", errors.New("truncated UTF-16 serialization")
	}

	unit := func(data []byte) uint16 {
		if little {
			return uint16(data[0]) | uint16(data[1])<<8
		}

		return uint16(data[0])<<8 | uint16(data[1])
	}

	var text strings.Builder
	if bom {
		text.WriteRune('\uFEFF')
	}

	for len(data) > 0 {
		r := rune(unit(data))

		data = data[2:]
		if utf16.IsSurrogate(r) {
			if r >= 0xdc00 || len(data) == 0 {
				return "", errors.New("unpaired UTF-16 surrogate")
			}

			r = utf16.DecodeRune(r, rune(unit(data)))
			data = data[2:]

			if r == utf8.RuneError {
				return "", errors.New("unpaired UTF-16 surrogate")
			}
		}

		text.WriteRune(r)
	}

	return text.String(), nil
}
