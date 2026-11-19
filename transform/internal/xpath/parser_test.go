package xpath //nolint:testpackage // Compare the internal syntax tree before compilation.

import (
	"errors"
	"reflect"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestParseControlAndPostfixExpressions(t *testing.T) {
	t.Parallel()

	left := LiteralExpr{Value: "left"}
	right := LiteralExpr{Value: "right"}
	cases := []struct {
		name   string
		source string
		want   Expr
	}{
		{
			name:   "try_catch_preserves_order_and_wildcard_forms",
			source: `try { 'left' } catch err:TYPE | *:OTHER | Q{urn:example}SAMPLE | err:* | Q{urn:example}* | fallback { 'right' } catch * { () }`,
			want: TryCatchExpr{Try: left, Catches: []CatchClause{
				{Codes: []string{"err:TYPE", "*:OTHER", "Q{urn:example}SAMPLE", "err:*", "Q{urn:example}*", "fallback"}, Expr: right},
				{Codes: []string{"*"}, Expr: SequenceExpr{}},
			}},
		},
		{
			name:   "some_preserves_order_and_namespace_of_bindings",
			source: `some $p:x in 'left', $y in $p:x satisfies $y`,
			want: QuantifiedExpr{Some: true, Bindings: []QuantifiedBinding{
				{Var: "p:x", Domain: left},
				{Var: "y", Domain: VariableExpr{Prefix: "p", Name: "p:x"}},
			}, Satisfies: VariableExpr{Name: "y"}},
		},
		{
			name:   "every_is_universal",
			source: `every $x in () satisfies $x`,
			want: QuantifiedExpr{Bindings: []QuantifiedBinding{
				{Var: "x", Domain: SequenceExpr{}},
			}, Satisfies: VariableExpr{Name: "x"}},
		},
		{
			name:   "arrow_chain_inserts_the_left_operand_first",
			source: `'left' => fn:concat('right') => $p:f()`,
			want: DynamicFunctionCall{Func: VariableExpr{Prefix: "p", Name: "p:f"}, Args: []Expr{
				FunctionCall{Prefix: "fn", Name: "concat", Args: []Expr{left, right}},
			}},
		},
		{
			name:   "arrow_with_parenthesized_target",
			source: `'left' => (fn:concat#2)('right')`,
			want:   DynamicFunctionCall{Func: NamedFunctionRef{Prefix: "fn", Name: "concat", Arity: 2}, Args: []Expr{left, right}},
		},
		{
			name:   "nested_argument_and_conditional_expressions",
			source: `string(if (true()) then string('left') else 'right')`,
			want: FunctionCall{Name: "string", Args: []Expr{IfExpr{
				Cond: FunctionCall{Name: "true"},
				Then: FunctionCall{Name: "string", Args: []Expr{left}},
				Else: right,
			}}},
		},
		{
			name:   "curly_array_collects_members_from_a_sequence",
			source: `array { 'left', 'right' }`,
			want:   ArrayConstructorExpr{Items: []Expr{SequenceExpr{Items: []Expr{left, right}}}},
		},
		{
			name:   "empty_curly_array",
			source: `array {}`,
			want:   ArrayConstructorExpr{},
		},
		{
			name:   "square_array_keeps_the_sequence_in_one_member",
			source: `[('left', 'right')]`,
			want:   ArrayConstructorExpr{SquareBracket: true, Items: []Expr{SequenceExpr{Items: []Expr{left, right}}}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tc.source)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.source, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Parse(%q) = %#v, want %#v", tc.source, got, tc.want)
			}
		})
	}
}

func TestParseRejectsMalformedClauses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		source string
		want   error
	}{
		{"try_without_catch", `try { 1 }`, ErrExpectedToken},
		{"try_body_without_closing_brace", `try { 1 catch * { 2 }`, ErrExpectedToken},
		{"catch_with_numeric_code", `try { 1 } catch 2 { 3 }`, ErrExpectedToken},
		{"catch_with_missing_code_after_bar", `try { 1 } catch err:A | { 2 }`, ErrExpectedToken},
		{"catch_without_body", `try { 1 } catch * 2`, ErrExpectedToken},
		{"catch_body_without_closing_brace", `try { 1 } catch * { 2`, ErrExpectedToken},
		{"quantifier_without_in", `some $x 'left' satisfies $x`, ErrExpectedToken},
		{"quantifier_without_second_variable", `every $x in 'left', 2 satisfies $x`, ErrExpectedToken},
		{"quantifier_without_satisfies", `every $x in 'left'`, ErrExpectedToken},
		{"arrow_with_non_callable_syntax", `'left' => 1('right')`, ErrExpectedToken},
		{"arrow_with_split_qname", `'left' => fn: concat('right')`, ErrExpectedToken},
		{"arrow_without_argument_list", `'left' => fn:string`, ErrExpectedToken},
		{"arrow_without_closing_paren", `'left' => ($f()`, ErrExpectedToken},
		{"array_without_closing_brace", `array { 1`, ErrExpectedToken},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tc.source)
			if !errors.Is(err, tc.want) || got != nil {
				t.Errorf("Parse(%q) = (%#v, %v), want (nil, %v)", tc.source, got, err, tc.want)
			}
		})
	}
}

func TestVariableTokenSeparatorsFollowXPathProfile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		version int
		source  string
		want    []xdm.AtomicValue
		wantErr error
	}{
		{
			name:    "xpath20",
			version: 20,
			source:  `some $ x in 1 satisfies $(: outer (: inner :) :)x eq 1`,
			want:    []xdm.AtomicValue{{TypeName: xdm.TypeBoolean, Value: true}},
		},
		{
			name:    "xpath31",
			version: 31,
			source:  `let $ p:name := 'kept' return $ (: comment :) p:name`,
			want:    []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: "kept"}},
		},
		{"xpath10_whitespace", 10, `$ name`, nil, ErrUnexpectedToken},
		{"xpath10_comment", 10, `$ (: comment :) name`, nil, ErrUnexpectedToken},
		{"xpath31_split_qname", 31, `let $p: name := 'invalid' return $p:name`, nil, ErrExpectedToken},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			namespaces := map[string]string{"p": "urn:example"}
			expr, err := NewCompiler().Language(tc.version, namespaces).Compile(tc.source)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Compile(%q) error = %v, want %v", tc.source, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Compile(%q): %v", tc.source, err)
			}
			result, err := NewEvaluator(DefaultEvaluatorOptions).Namespaces(namespaces).Evaluate(t.Context(), expr, nil)
			if err != nil {
				t.Fatalf("Evaluate(%q): %v", tc.source, err)
			}
			assertAtomicSequence(t, result.Sequence(), tc.want)
		})
	}
}

func TestParseSequenceTypeKindTests(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		source string
		want   xdm.SequenceType
	}{
		{
			name:   "nillable_named_element",
			source: "element(p:entry, xs:integer?)?",
			want: xdm.SequenceType{
				ItemTest:   xdm.ElementTest{Name: "p:entry", TypeName: "xs:integer", Nillable: true},
				Occurrence: xdm.OccurrenceZeroOrOne,
			},
		},
		{
			name:   "wildcard_attribute_with_type",
			source: "attribute(*, xs:string)*",
			want: xdm.SequenceType{
				ItemTest:   xdm.AttributeTest{Name: "*", TypeName: "xs:string"},
				Occurrence: xdm.OccurrenceZeroOrMore,
			},
		},
		{
			name:   "document_with_schema_element",
			source: "document-node(schema-element(p:entry))+",
			want: xdm.SequenceType{
				ItemTest:   xdm.DocumentTest{Inner: xdm.SchemaElementTest{Name: "p:entry"}},
				Occurrence: xdm.OccurrenceOneOrMore,
			},
		},
		{
			name:   "schema_attribute",
			source: "schema-attribute(p:code)",
			want:   xdm.SequenceType{ItemTest: xdm.SchemaAttributeTest{Name: "p:code"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseSequenceType(tc.source)
			if err != nil {
				t.Fatalf("ParseSequenceType(%q): %v", tc.source, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseSequenceType(%q) = %#v, want %#v", tc.source, got, tc.want)
			}
		})
	}
}

func mustParseSequenceType(t *testing.T, source string) xdm.SequenceType {
	t.Helper()
	st, err := ParseSequenceType(source)
	if err != nil {
		t.Fatalf("ParseSequenceType(%q): %v", source, err)
	}
	return st
}

func TestDocumentKindTestRequiresInnerParenthesis(t *testing.T) {
	for _, source := range []string{`document-node(element bogus))`, `document-node(element 123))`, `document-node(schema-element bogus name))`} {
		t.Run(source, func(t *testing.T) {
			if _, err := ParseSequenceType(source); err == nil {
				t.Error("malformed sequence type accepted")
			}
			if _, err := NewCompiler().Language(31, nil).Compile(`() instance of ` + source); err == nil {
				t.Error("malformed kind test accepted")
			}
		})
	}
	for _, source := range []string{`document-node()`, `document-node(element())`, `document-node(element(r))`, `document-node(schema-element(r))`} {
		if _, err := ParseSequenceType(source); err != nil {
			t.Errorf("valid sequence type %q: %v", source, err)
		}
	}
}
