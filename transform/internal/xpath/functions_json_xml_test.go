package xpath //nolint:testpackage // Exercises JSON and XML mapping with both XPath evaluation paths.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestJSONToXMLDuplicatePoliciesASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"default_retains_duplicate_keys_in_input_order", `json-to-xml('{"a":1,"a":2}')/*/* ! string(.)`, "1|2"},
		{"use_first_retains_first_value", `json-to-xml('{"a":1,"a":2}',map{'duplicates':'use-first'})/*/* ! string(.)`, "1"},
		{"escape_preserves_lexical_escapes", `let $j := json-to-xml('{"\u0001":"line\n"}',map{'escape':true()})/*/* return (string($j/@key),string($j/@escaped-key),string($j/@escaped),string($j))`, `\u0001|true|true|line\n`},
		{"escape_controls_in_both_key_and_value", `let $j := json-to-xml('{"\u007F":"\u0085"}',map{'escape':true()})/*/* return (string($j/@key),string($j/@escaped-key),string($j/@escaped),string($j))`, `\u007f|true|true|\u0085`},
		{"leading_byte_order_mark_is_ignored", `string(json-to-xml(codepoints-to-string(65279) || ' true')/*)`, "true"},
	})
}

func TestXMLToJSONEscapesAndScalarValuesASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"escaped_string_keeps_surrogate_pair_and_short_escapes", `xml-to-json(parse-xml('<string xmlns="http://www.w3.org/2005/xpath-functions" escaped="true">é\"\\\/\b\f\n\r\t\u0041\uD83D\uDE00</string>'))`, `"é\"\\\/\b\f\n\r\t\u0041\uD83D\uDE00"`},
		{"escaped_key_is_retained_in_output", `xml-to-json(parse-xml('<map xmlns="http://www.w3.org/2005/xpath-functions"><string key="\u0061" escaped-key="1">v</string></map>'))`, `{"\u0061":"v"}`},
		{"unpaired_high_surrogate_preserves_following_escape", `xml-to-json(parse-xml('<string xmlns="http://www.w3.org/2005/xpath-functions" escaped="true">\uD800\u0041</string>'))`, `"\uD800\u0041"`},
		{"unpaired_low_surrogate_round_trips_through_xml", `xml-to-json(json-to-xml('"\uDEAD"',map{'escape':true()}))`, `"\uDEAD"`},
		{"unpaired_surrogate_key_differs_from_replacement_and_literal_escape", `xml-to-json(parse-xml('<map xmlns="http://www.w3.org/2005/xpath-functions"><null key="\udead" escaped-key="true"/><null key="�"/><null key="\udead"/></map>'))`, `{"\udead":null,"�":null,"\\udead":null}`},
		{"boolean_lexical_values_and_empty_null", `xml-to-json(parse-xml('<array xmlns="http://www.w3.org/2005/xpath-functions"><boolean> 1 </boolean><boolean>0</boolean><null><!--empty--></null></array>'))`, `[true,false,null]`},
		{"nonstandard_attribute_namespace_is_ignored", `xml-to-json(parse-xml('<number xmlns="http://www.w3.org/2005/xpath-functions" xmlns:e="urn:e" e:note="ignored"> 1.50 </number>'))`, `1.5`},
	})
}

func TestJSONXMLMappingErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, expression, code string }{
		{"reject_duplicate_key", `json-to-xml('{"a":1,"a":2}',map{'duplicates':'reject'})`, "FOJS0003"},
		{"use_last_is_invalid_for_xml_mapping", `json-to-xml('{}',map{'duplicates':'use-last'})`, "FOJS0005"},
		{"validation_cannot_retain_duplicates", `json-to-xml('{}',map{'duplicates':'retain','validate':true()})`, "FOJS0005"},
		{"validation_requires_schema_declarations", `json-to-xml('{}',map{'validate':true()})`, "FOJS0004"},
		{"bad_escape", `xml-to-json(parse-xml('<string xmlns="http://www.w3.org/2005/xpath-functions" escaped="true">\q</string>'))`, "FOJS0007"},
		{"incomplete_unicode_escape", `xml-to-json(parse-xml('<string xmlns="http://www.w3.org/2005/xpath-functions" escaped="true">\u123</string>'))`, "FOJS0007"},
		{"invalid_hex_digit_in_escape", `xml-to-json(parse-xml('<string xmlns="http://www.w3.org/2005/xpath-functions" escaped="true">\u00g0</string>'))`, "FOJS0007"},
		{"invalid_hex_after_high_surrogate_remains_an_error", `xml-to-json(parse-xml('<string xmlns="http://www.w3.org/2005/xpath-functions" escaped="true">\uD800\u00g0</string>'))`, "FOJS0007"},
		{"equivalent_surrogate_escapes_have_equal_keys", `xml-to-json(parse-xml('<map xmlns="http://www.w3.org/2005/xpath-functions"><null key="\uDEAD" escaped-key="true"/><null key="\udead" escaped-key="true"/></map>'))`, "FOJS0006"},
		{"literal_astral_and_surrogate_pair_keys_are_equal", `xml-to-json(parse-xml('<map xmlns="http://www.w3.org/2005/xpath-functions"><null key="\uD83D\uDE00" escaped-key="true"/><null key="😀"/></map>'))`, "FOJS0006"},
		{"literal_and_hex_escaped_backslash_keys_are_equal", `xml-to-json(parse-xml('<map xmlns="http://www.w3.org/2005/xpath-functions"><null key="\u005C" escaped-key="true"/><null key="\"/></map>'))`, "FOJS0006"},
		{"literal_and_short_escaped_backslash_keys_are_equal", `xml-to-json(parse-xml('<map xmlns="http://www.w3.org/2005/xpath-functions"><null key="\\" escaped-key="true"/><null key="\"/></map>'))`, "FOJS0006"},
		{"literal_and_escaped_map_keys_compare_after_decoding", `xml-to-json(parse-xml('<map xmlns="http://www.w3.org/2005/xpath-functions"><null key="a"/><null key="\u0061" escaped-key="true"/></map>'))`, "FOJS0006"},
		{"array_member_cannot_have_a_key", `xml-to-json(parse-xml('<array xmlns="http://www.w3.org/2005/xpath-functions"><null key="a"/></array>'))`, "FOJS0006"},
		{"null_cannot_have_text", `xml-to-json(parse-xml('<null xmlns="http://www.w3.org/2005/xpath-functions">value</null>'))`, "FOJS0006"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, tc.expression, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Fatalf("%s returned %v, %v; want no output and %s", tc.expression, seq, err, tc.code)
				}
			})
		}
	}
}
