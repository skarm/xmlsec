package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/transform"
)

func checkSuiteAssertion(ctx context.Context, evaluation *suiteEvaluation, assertion *suiteNode) error {
	if assertion == nil {
		return suiteHarness("missing result assertion")
	}

	var harness *suiteHarnessError
	if errors.As(evaluation.err, &harness) {
		return harness
	}

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
	if evaluation.result == nil || len(assertion.Children) != 1 {
		return suiteHarness("message assertion requires a successful XSLT result and one nested assertion; terminated-message capture is unavailable")
	}

	for _, message := range evaluation.result.Messages() {
		value, err := evaluation.environment.query(ctx, "parse-xml-fragment($message)", transform.Bindings{{Local: "message"}: transform.Values(transform.String(message.Text))})
		if err != nil {
			return suiteHarness("message XML: %v", err)
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

			name := transform.Name{Space: "http://www.w3.org/2005/xqt-errors", Local: code}
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
			return suiteHarness("invalid count assertion: %v", err)
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
		raw, _, err := readSuiteFile(e.options.directory, e.item.base, file)
		if err != nil {
			return nil, suiteHarness("expected result file: %v", err)
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
		return suiteHarness("result serialization: %v", err)
	}

	left, err := parseSuiteXMLFragment(ctx, []byte(actual))
	if err != nil {
		return fmt.Errorf("actual result is not an XML fragment: %w", err)
	}

	right, err := parseSuiteXMLFragment(ctx, expected)
	if err != nil {
		return suiteHarness("expected XML fragment: %v", err)
	}

	if assertion.attr("ignore-prefixes") == suiteTrue || assertion.attr("ignore-prefixes") == "1" {
		return suiteXMLDeepEqual(ctx, e, left, right)
	}

	var leftBytes, rightBytes bytes.Buffer
	if err := c14n.WriteDocument(ctx, &leftBytes, left, c14n.Options{WithComments: true}); err != nil {
		return suiteHarness("actual XML comparison: %v", err)
	}

	if err := c14n.WriteDocument(ctx, &rightBytes, right, c14n.Options{WithComments: true}); err != nil {
		return suiteHarness("expected XML comparison: %v", err)
	}

	if !bytes.Equal(leftBytes.Bytes(), rightBytes.Bytes()) {
		return errors.New("XML fragment comparison failed")
	}

	return nil
}

func parseSuiteXMLFragment(ctx context.Context, data []byte) (*document.Document, error) {
	text := strings.TrimPrefix(string(data), "\uFEFF")
	if strings.HasPrefix(text, "<?xml ") {
		_, tail, ok := strings.Cut(text, "?>")
		if !ok {
			return nil, errors.New("invalid XML declaration")
		}

		text = tail
	}

	// The catalog defines comparison of parsed/canonical XML. Parse a complete
	// document as such so whitespace outside its root is not content. A wrapper
	// is needed only for results that are XML fragments rather than documents.
	if parsed, err := document.Parse(ctx, []byte(text), document.DefaultLimits()); err == nil {
		normalized, err := parsed.XML(ctx)
		if err != nil {
			return nil, err
		}

		text = string(normalized)
	} else if errors.Is(err, document.ErrLimit) || ctx.Err() != nil {
		return nil, err
	}

	return document.Parse(ctx, []byte("<_xmlsec_test_result>"+text+"</_xmlsec_test_result>"), document.DefaultLimits())
}

func suiteXMLDeepEqual(ctx context.Context, e *suiteEvaluation, left, right *document.Document) error {
	first, err := e.environment.engine.Import(ctx, left)
	if err != nil {
		return suiteHarness("actual XML import: %v", err)
	}

	second, err := e.environment.engine.Import(ctx, right)
	if err != nil {
		return suiteHarness("expected XML import: %v", err)
	}

	return e.assertionTrue(ctx, "deep-equal($first/node(), $second/node())", transform.Bindings{{Local: "first"}: transform.Values(first.Root()), {Local: "second"}: transform.Values(second.Root())})
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
		return e.assertionTrue(ctx, "matches($serialized, $pattern, $flags)", transform.Bindings{{Local: "serialized"}: transform.Values(transform.String(string(actual))), {Local: "pattern"}: transform.Values(transform.String(string(expected))), {Local: "flags"}: transform.Values(transform.String(assertion.attr("flags")))})
	}

	if !bytes.Equal(actual, expected) {
		return errors.New("serialized bytes differ from the expected serialization")
	}

	return nil
}
