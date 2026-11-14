package xpath //nolint:testpackage // Exercises string functions through both evaluation paths.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestAnalyzeStringCaptureStructureASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{
			name:       "matched_and_unmatched_text_keep_document_order",
			expression: `let $r := analyze-string('preA12midB3post','([A-Z])([0-9]+)') return $r/* ! (local-name(.) || ':' || string(.))`,
			want:       "non-match:pre|match:A12|non-match:mid|match:B3|non-match:post",
		},
		{
			name:       "nested_groups_and_unmatched_optional_capture",
			expression: `let $r := analyze-string('preA12!B3post','(([A-Z])([0-9]+))(!)?') return $r/fn:match ! (string-join(fn:group/@nr, ',') || ':' || string-join(fn:group[@nr=1]/fn:group ! (@nr || '=' || string(.)), ',') || ':' || string(fn:group[@nr=4]))`,
			want:       "1,4:2=A,3=12:!|1:2=B,3=3:",
		},
		{
			name:       "empty_nested_and_sibling_captures_keep_distinct_parents",
			expression: `let $a := analyze-string('b','(b)(x?)'), $b := analyze-string('b','(b(x?))') return (count($a/fn:match/fn:group),count($b/fn:match/fn:group),string($b/fn:match/fn:group/fn:group/@nr),string($b/fn:match/fn:group/fn:group))`,
			want:       "2|1|2|",
		},
		{
			name:       "free_spacing_preserves_character_classes_and_non_capture_groups",
			expression: `let $r := analyze-string('q A-7 z','(?: A [ -] ) ( [0-9] )','x') return ($r/fn:non-match ! string(.), string($r/fn:match), string($r/fn:match/fn:group/@nr), string($r/fn:match/fn:group))`,
			want:       "q | z|A-7|1|7",
		},
		{
			name:       "empty_input_and_entirely_unmatched_input",
			expression: `(count(analyze-string((),'[0-9]')/*),name(analyze-string('abc','[0-9]')/*),string(analyze-string('abc','[0-9]')/*))`,
			want:       "0|fn:non-match|abc",
		},
	})
}

func TestStringMatchingAndNormalizationASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"tokenize_defaults_to_xml_whitespace", `tokenize(codepoints-to-string((32,97,160,98,9,99,13,10,100,32)))`, "a\u00a0b|c|d"},
		{"token_matching_uses_complete_tokens", `(contains-token(('alpha beta','gamma'),' beta '),contains-token('alpha beta','bet'),contains-token('abc',' '))`, "true|false|false"},
		{"token_matching_honors_collation", `(contains-token('Alpha BETA','beta','http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive'),contains-token('Alpha BETA','beta'))`, "true|false"},
		{"delimiters_honor_collation_without_changing_original_text", `(contains('preABCpost','abc','http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive'),starts-with('ABCpost','abc','http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive'),ends-with('preABC','abc','http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive'),substring-before('preABCpost','abc','http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive'),substring-after('preABCpost','abc','http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive'))`, "true|true|true|pre|post"},
		{"compatibility_forms_and_identity_form", `(normalize-unicode('①','NFKC'), string-to-codepoints(normalize-unicode('é','NFD')), normalize-unicode('①',''), normalize-unicode('①','NFKD'))`, "1|101|769|①|1"},
		{"translate_uses_first_duplicate_and_deletes_excess", `translate('aba😀cz','aab😀c','xyZ')`, "xZxz"},
		{"literal_regex_and_replacement_text", `(matches('a.b','a.b','q'),matches('axb','a.b','q'),replace('a.b a.b','a.b','$1','q'),tokenize('a.b.c','.','q'))`, "true|false|$1 $1|a|b|c"},
		{"replacement_keeps_dollar_and_backslash_literals", `replace('abc','(a)(b)','$2$1\$\\')`, "ba$\\c"},
	})
}

func TestStringFunctionErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, expression, code string }{
		{"analyze_string_requires_nonempty_matches", `analyze-string('abc','a*')`, "FORX0003"},
		{"replace_rejects_invalid_escape", `replace('abc','a','\q')`, "FORX0004"},
		{"normalization_rejects_unknown_form", `normalize-unicode('a','unknown')`, "FOCH0003"},
		{"contains_token_rejects_unknown_collation", `contains-token('alpha','alpha','urn:example:unknown-collation')`, "FOCH0002"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, tc.expression, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Errorf("%s = %v, %v, want no result and %s", tc.expression, seq, err, tc.code)
				}
			})
		}
	}
}
