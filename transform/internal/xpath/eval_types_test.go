package xpath //nolint:testpackage // Exercises type operators on both evaluation paths.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestTreatAsPreservesValuesASTAndVM(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{runtimeASTMode, "VM"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			got, err := evaluateFunctionExpression(t, `(4, 2) treat as xs:integer+`, mode)
			if err != nil {
				t.Fatal(err)
			}
			want := []int64{4, 2}
			if xdm.SequenceLen(got) != len(want) {
				t.Fatalf("treat as returned %d items, want %d", xdm.SequenceLen(got), len(want))
			}
			for i, n := range want {
				item, ok := got.Get(i).(xdm.AtomicValue)
				value, fits := item.Int64Val()
				if !ok || item.TypeName != xdm.TypeInteger || !fits || value != n {
					t.Errorf("treat as item %d = %v, want xs:integer(%d)", i+1, got.Get(i), n)
				}
			}
		})
	}
}

func TestTreatAsErrorsASTAndVM(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, source, code string
	}{
		{"empty_cannot_match_exactly_one", `() treat as xs:string`, "XPDY0050"},
		{"multiple_items_cannot_match_optional", `(1, 2) treat as xs:integer?`, "XPDY0050"},
		{"string_is_not_coerced_to_integer", `'42' treat as xs:integer`, "XPDY0050"},
		{"operand_error_is_preserved", `(1 idiv 0) treat as xs:integer`, "FOAR0001"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()

				got, err := evaluateFunctionExpression(t, tc.source, mode)
				if xdm.SequenceLen(got) != 0 || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Errorf("%s = (%v, %v), want no result and %s", tc.source, got, err, tc.code)
				}
			})
		}
	}
}

func TestCollectionTypesCheckEveryEntryAndMemberASTAndVM(t *testing.T) {
	t.Parallel()

	assertFunctionResults(t, []functionResultCase{
		{"map_checks_keys", `(map{'a': 1, 'b': 2} instance of map(xs:string, xs:integer), map{'a': 1, 2: 2} instance of map(xs:string, xs:integer))`, "true|false"},
		{"map_checks_value_cardinality", `(map{'a': (), 'b': 2} instance of map(xs:string, xs:integer?), map{'a': (), 'b': 2} instance of map(xs:string, xs:integer))`, "true|false"},
		{"map_checks_value_type", `(map{'a': 1, 'b': '2'} instance of map(xs:string, xs:integer), map{} instance of map(xs:string, xs:integer))`, "false|true"},
		{"array_checks_type_and_cardinality", `([(1, 2), 3] instance of array(xs:integer+), [1, ()] instance of array(xs:integer+), [1, '2'] instance of array(xs:integer+), [] instance of array(xs:integer+))`, "true|false|false|true"},
		{"array_lookup_uses_member_type", `([(1, 2), 3] instance of function(xs:integer) as xs:integer+, [1, ()] instance of function(xs:integer) as xs:integer+, [1] instance of function(xs:string) as xs:integer)`, "true|false|false"},
	})
}

func TestCoerceToSequenceTypeDistinguishesMatchingAndConversion(t *testing.T) {
	t.Parallel()

	target := xdm.SequenceType{
		ItemTest:   xdm.AtomicOrUnionType{Name: "double", Prefix: "xs"},
		Occurrence: xdm.OccurrenceExactlyOne,
	}
	integer := xdm.SingleInteger(7)
	if MatchesSequenceType(integer, target) {
		t.Error("an integer matched xs:double without conversion")
	}
	out, ok := CoerceToSequenceType(integer, target)
	if !ok || !MatchesSequenceType(out, target) {
		t.Fatalf("CoerceToSequenceType = (%v, %t), want one xs:double", out, ok)
	}
	got, ok := out.Get(0).(xdm.AtomicValue)
	if !ok || got.TypeName != xdm.TypeDouble || got.DoubleVal() != 7 {
		t.Errorf("coerced item = %v, want xs:double(7)", out.Get(0))
	}

	stringValue := xdm.SingleString("7")
	if out, ok := CoerceToSequenceType(stringValue, target); ok || xdm.SequenceLen(out) != 1 || out.Get(0) != stringValue.Get(0) {
		t.Errorf("CoerceToSequenceType of xs:string = (%v, %t), want unchanged input and false", out, ok)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if out, ok := CoerceToSequenceTypeContext(ctx, integer, target); ok || xdm.SequenceLen(out) != 1 || out.Get(0) != integer.Get(0) {
		t.Errorf("CoerceToSequenceTypeContext after cancellation = (%v, %t), want unchanged input and false", out, ok)
	}
}

func TestBindSequenceTypeExpandsNamesAtDeclarationSite(t *testing.T) {
	t.Parallel()

	source := `function(
		document-node(element(entry, t:Record?)),
		attribute(code, Value),
		schema-element(entry),
		schema-attribute(code)
	) as map(xs:string, array(Q{urn:member}Item?))`
	input := mustParseSequenceType(t, source)
	wantArray := xdm.ArrayTest{MemberType: xdm.SequenceType{
		ItemTest:   xdm.AtomicOrUnionType{Name: "Q{urn:member}Item"},
		Occurrence: xdm.OccurrenceZeroOrOne,
	}}
	wantMap := xdm.MapTest{
		KeyType: xdm.AtomicOrUnionType{Name: "Q{" + NSXS + "}string"},
		ValType: xdm.SequenceType{ItemTest: wantArray},
	}
	want := xdm.SequenceType{ItemTest: xdm.FunctionTest{
		ParamTypes: []xdm.SequenceType{
			{ItemTest: xdm.DocumentTest{Inner: xdm.ElementTest{Name: "Q{urn:elements}entry", TypeName: "Q{urn:types}Record", Nillable: true}}},
			{ItemTest: xdm.AttributeTest{Name: "Q{}code", TypeName: "Q{urn:elements}Value"}},
			{ItemTest: xdm.SchemaElementTest{Name: "Q{urn:elements}entry"}},
			{ItemTest: xdm.SchemaAttributeTest{Name: "Q{}code"}},
		},
		ReturnType: xdm.SequenceType{ItemTest: wantMap},
	}}

	got, err := BindSequenceType(t.Context(), input, map[string]string{"t": "urn:types"}, "urn:elements")
	if err != nil {
		t.Fatalf("BindSequenceType: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BindSequenceType = %#v, want %#v", got, want)
	}
	if original := mustParseSequenceType(t, source); !reflect.DeepEqual(input, original) {
		t.Errorf("binding changed the original sequence type: %#v, want %#v", input, original)
	}
}

func TestBindSequenceTypePropagatesNestedBudgetFailure(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		source string
		work   int
	}{
		{"document_element", "document-node(element(entry))", 1},
		{"function_parameter", "function(xs:integer) as xs:string", 1},
		{"function_result", "function() as xs:string", 1},
		{"map_key", "map(xs:string, xs:boolean)", 1},
		{"map_value", "map(xs:string, xs:boolean)", 2},
		{"array_member", "array(xs:integer)", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			st := mustParseSequenceType(t, tc.source)
			ctx := WithBudget(t.Context(), tc.work, 1, 1, 1)
			got, err := BindSequenceType(ctx, st, nil, "urn:elements")
			if !errors.Is(err, ErrBudget) || !reflect.DeepEqual(got, st) {
				t.Errorf("BindSequenceType(%s) = (%#v, %v), want original type and ErrBudget", tc.source, got, err)
			}
		})
	}
}

func TestConvertToSequenceTypeAtomicArguments(t *testing.T) {
	t.Parallel()

	untyped := func(s string) xdm.Sequence {
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeUntypedAtomic, Value: s})
	}
	cases := []struct {
		name     string
		input    xdm.Sequence
		required string
		want     []xdm.AtomicValue
		wantCode string
	}{
		{
			name:     "untyped_atomic_is_converted",
			input:    untyped("1"),
			required: "xs:boolean",
			want:     []xdm.AtomicValue{{TypeName: xdm.TypeBoolean, Value: true}},
		},
		{
			name:     "any_uri_is_promoted_to_string",
			input:    xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: "urn:entry"}),
			required: "xs:string",
			want:     []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: "urn:entry"}},
		},
		{
			name:     "array_members_are_atomized_in_order",
			input:    xdm.ItemSlice{xdm.NewArray([]xdm.Sequence{xdm.SingleString("first"), nil, xdm.SingleString("last")})},
			required: "xs:anyAtomicType+",
			want:     []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: "first"}, {TypeName: xdm.TypeString, Value: "last"}},
		},
		{
			name:     "invalid_lexical_cast_retains_its_code",
			input:    untyped("word"),
			required: "xs:integer",
			wantCode: "FORG0001",
		},
		{
			name:     "string_does_not_implicitly_cast_to_integer",
			input:    xdm.SingleString("42"),
			required: "xs:integer",
			wantCode: "XPTY0004",
		},
		{
			name:     "untyped_atomic_cannot_convert_to_namespace_sensitive_type",
			input:    untyped("xs:string"),
			required: "xs:QName",
			wantCode: "XPTY0117",
		},
		{
			name:     "map_atomization_retains_its_code",
			input:    xdm.ItemSlice{xdm.NewMap(nil)},
			required: "xs:integer?",
			wantCode: "FOTY0013",
		},
		{
			name:     "atomized_cardinality_must_match",
			input:    xdm.ItemSlice{xdm.NewArray([]xdm.Sequence{xdm.SingleInteger(1), xdm.SingleInteger(2)})},
			required: "xs:integer",
			wantCode: "XPTY0004",
		},
		{
			name:     "zero_items_satisfy_optional_type",
			required: "xs:integer?",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ConvertToSequenceType(t.Context(), tc.input, mustParseSequenceType(t, tc.required))
			if tc.wantCode != "" {
				if !errors.Is(err, &xdm.Error{Code: tc.wantCode}) {
					t.Errorf("ConvertToSequenceType(%s): %v, want %s", tc.required, err, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("ConvertToSequenceType(%s): %v", tc.required, err)
			}
			assertAtomicSequence(t, got, tc.want)
		})
	}
}

func TestConvertToSequenceTypeAdaptsCollectionLookup(t *testing.T) {
	t.Parallel()

	key := xdm.AtomicValue{TypeName: xdm.TypeString, Value: "found"}
	mapping := xdm.SingleEntryMap(key, xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: "urn:found"}))
	got, err := ConvertToSequenceType(t.Context(), xdm.ItemSlice{mapping}, mustParseSequenceType(t, "function(xs:string) as xs:string?"))
	if err != nil {
		t.Fatalf("convert map to function: %v", err)
	}
	if xdm.SequenceLen(got) != 1 {
		t.Fatalf("convert map to function returned %d items, want 1", xdm.SequenceLen(got))
	}
	fn, ok := got.Get(0).(xdm.FunctionItem)
	if !ok || fn.Arity != 1 {
		t.Fatalf("converted item = %#v, want a one-argument function", got.Get(0))
	}

	t.Run("promotes_result", func(t *testing.T) {
		t.Parallel()

		got, err := fn.Invoke(t.Context(), []xdm.Sequence{xdm.SingleString("found")})
		if err != nil {
			t.Fatalf("look up present key: %v", err)
		}
		assertAtomicSequence(t, got, []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: "urn:found"}})
	})
	t.Run("missing_key_returns_empty", func(t *testing.T) {
		t.Parallel()

		got, err := fn.Invoke(t.Context(), []xdm.Sequence{xdm.SingleString("missing")})
		if err != nil || xdm.SequenceLen(got) != 0 {
			t.Errorf("look up missing key = (%v, %v), want empty sequence", got, err)
		}
	})
	t.Run("checks_argument_type", func(t *testing.T) {
		t.Parallel()

		got, err := fn.Invoke(t.Context(), []xdm.Sequence{xdm.SingleBoolean(true)})
		if !errors.Is(err, &xdm.Error{Code: "XPTY0004"}) || xdm.SequenceLen(got) != 0 {
			t.Errorf("look up with a boolean = (%v, %v), want empty result and XPTY0004", got, err)
		}
	})
	t.Run("checks_arity", func(t *testing.T) {
		t.Parallel()

		got, err := fn.Invoke(t.Context(), nil)
		if !errors.Is(err, &xdm.Error{Code: "XPTY0004"}) || xdm.SequenceLen(got) != 0 {
			t.Errorf("look up without an argument = (%v, %v), want empty result and XPTY0004", got, err)
		}
	})
}

func TestCastToQName(t *testing.T) {
	t.Parallel()

	namespaces := map[string]string{"": "urn:default", "p": "urn:prefix", "fn": ""}
	xpathContext := &evalContext{namespaces: namespaces}
	xsdContext := &evalContext{namespaces: namespaces, qnameValueNoDefaultNS: true}
	existing := xdm.QNameValue{Prefix: "p", Local: "name", URI: "urn:original"}

	cases := []struct {
		name     string
		value    xdm.AtomicValue
		context  *evalContext
		want     xdm.QNameValue
		wantCode string
	}{
		{"typed_qname_retains_expanded_name", xdm.AtomicValue{TypeName: xdm.TypeQName, Value: existing}, xpathContext, existing, ""},
		{"notation_retains_expanded_name", xdm.AtomicValue{TypeName: xdm.TypeNOTATION, Value: existing}, xpathContext, existing, ""},
		{"explicit_prefix_on_string_subtype", xdm.AtomicValue{TypeName: xdm.TypeToken, Value: "p:name"}, xpathContext, xdm.QNameValue{Prefix: "p", Local: "name", URI: "urn:prefix"}, ""},
		{"default_namespace_applies_in_xpath", xdm.AtomicValue{TypeName: xdm.TypeUntypedAtomic, Value: "name"}, xpathContext, xdm.QNameValue{Local: "name", URI: "urn:default"}, ""},
		{"xsd_value_ignores_xpath_default", xdm.AtomicValue{TypeName: xdm.TypeString, Value: "name"}, xsdContext, xdm.QNameValue{Local: "name"}, ""},
		{"predeclared_prefix_is_resolved", xdm.AtomicValue{TypeName: xdm.TypeString, Value: "xs:string"}, nil, xdm.QNameValue{Prefix: "xs", Local: "string", URI: NSXS}, ""},
		{"explicit_empty_binding_hides_predeclared_prefix", xdm.AtomicValue{TypeName: xdm.TypeString, Value: "fn:name"}, xpathContext, xdm.QNameValue{}, "FONS0004"},
		{"undeclared_prefix", xdm.AtomicValue{TypeName: xdm.TypeString, Value: "unknown:name"}, xpathContext, xdm.QNameValue{}, "FONS0004"},
		{"invalid_lexical_name", xdm.AtomicValue{TypeName: xdm.TypeString, Value: "p:1name"}, xpathContext, xdm.QNameValue{}, "FORG0001"},
		{"incompatible_source_type", xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: true}, xpathContext, xdm.QNameValue{}, "XPTY0004"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := castToQName(tc.value, tc.context)
			if tc.wantCode != "" {
				if !errors.Is(err, &xdm.Error{Code: tc.wantCode}) {
					t.Errorf("castToQName(%#v): %v, want %s", tc.value, err, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("castToQName(%#v): %v", tc.value, err)
			}
			if want := (xdm.AtomicValue{TypeName: xdm.TypeQName, Value: tc.want}); got != want {
				t.Errorf("castToQName(%#v) = %#v, want %#v", tc.value, got, want)
			}
		})
	}
}

func TestIsSequenceSubtypeFunctionVariance(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		actual   string
		required string
		want     bool
	}{
		{"contravariant_parameter_and_covariant_result", "function(xs:decimal) as xs:integer", "function(xs:integer) as xs:decimal?", true},
		{"rejects_narrower_parameter", "function(xs:integer) as xs:integer", "function(xs:decimal) as xs:decimal?", false},
		{"rejects_broader_result", "function(xs:decimal) as xs:decimal", "function(xs:integer) as xs:integer", false},
		{"requires_matching_arity", "function(xs:decimal, xs:decimal) as xs:integer", "function(xs:integer) as xs:decimal?", false},
		{"untyped_function_is_not_a_typed_function", "function(*)", "function(xs:integer) as xs:decimal?", false},
		{"array_is_a_function", "array(xs:string)", "function(*)", true},
		{"atomic_value_is_not_a_function", "xs:string", "function(*)", false},
		{"map_missing_key_allows_empty", "map(xs:string, xs:integer)", "function(xs:string) as xs:decimal?", true},
		{"map_missing_key_prevents_required_item", "map(xs:string, xs:integer)", "function(xs:string) as xs:decimal", false},
		{"map_nonempty_sequence_must_allow_missing_key", "map(xs:string, xs:integer+)", "function(xs:string) as xs:decimal*", true},
		{"untyped_map_is_a_lookup_function", "map(*)", "function(xs:anyAtomicType) as item()*", true},
		{"array_index_requires_integer", "array(xs:string+)", "function(xs:integer) as xs:string+", true},
		{"array_does_not_accept_decimal_index", "array(xs:string)", "function(xs:decimal) as xs:string", false},
		{"untyped_array_has_unrestricted_members", "array(*)", "function(xs:integer) as item()*", true},
		{"xs_error_is_bottom", "xs:error", "xs:boolean", true},
		{"optional_bottom_matches_empty", "xs:error?", "empty-sequence()", true},
		{"all_members_of_numeric_are_atomic", "xs:numeric", "xs:anyAtomicType", true},
		{"not_all_members_of_numeric_are_decimal", "xs:numeric", "xs:decimal", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actual := mustParseSequenceType(t, tc.actual)
			required := mustParseSequenceType(t, tc.required)
			if got := isSequenceSubtype(actual, required, nil); got != tc.want {
				t.Errorf("%s subtype of %s = %t, want %t", tc.actual, tc.required, got, tc.want)
			}
		})
	}
}

func TestIsSequenceSubtypeNodeTests(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		actual   string
		required string
		want     bool
	}{
		{"named_element_matches_any_element", "element(e)", "element()", true},
		{"attribute_is_not_element", "attribute(e)", "element()", false},
		{"typed_element_matches_node", "element(e, xs:integer)", "node()", true},
		{"different_element_namespaces", "element(Q{urn:a}e)", "element(Q{urn:b}e)", false},
		{"element_type_can_be_derived", "element(e, xs:integer)", "element(e, xs:decimal)", true},
		{"incompatible_element_type", "element(e, xs:string)", "element(e, xs:decimal)", false},
		{"nillable_element_requires_nillable_supertype", "element(e, xs:integer?)", "element(e, xs:decimal)", false},
		{"unannotated_element_allows_nilled_values", "element(e)", "element(e, xs:anyType?)", true},
		{"unannotated_element_can_be_nilled", "element(e)", "element(e, xs:anyType)", false},
		{"document_recurses_to_element", "document-node(element(e))", "document-node(element())", true},
		{"any_document_does_not_specify_element", "document-node()", "document-node(element(e))", false},
		{"attribute_annotation_can_be_derived", "attribute(code, xs:integer)", "attribute(*, xs:decimal)", true},
		{"unannotated_attribute_matches_any_type", "attribute(code)", "attribute(*, xs:anyType)", true},
		{"unannotated_attribute_has_no_specific_type", "attribute(code)", "attribute(*, xs:integer)", false},
		{"specific_processing_instruction_matches_any_target", "processing-instruction('app')", "processing-instruction()", true},
		{"processing_instruction_targets_differ", "processing-instruction('app')", "processing-instruction('other')", false},
		{"namespace_node_matches_node", "namespace-node()", "node()", true},
		{"text_does_not_match_comment", "text()", "comment()", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actual := mustParseSequenceType(t, tc.actual)
			required := mustParseSequenceType(t, tc.required)
			if got := isSequenceSubtype(actual, required, nil); got != tc.want {
				t.Errorf("%s subtype of %s = %t, want %t", tc.actual, tc.required, got, tc.want)
			}
		})
	}
}
