package xpath //nolint:testpackage // Read the internal sequence-type relation directly.

import (
	"testing"
)

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
