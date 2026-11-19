package xpath //nolint:testpackage // Exercises string functions through both evaluation paths.

import (
	"context"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestCodepointsToStringCharacterPolicy(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, expression, want, code string
		xml11                        bool
	}{
		{"empty_sequence", `codepoints-to-string(())`, "", "", false},
		{"xml_10_boundary_characters", `codepoints-to-string((9, 10, 13, 32, 55295, 57344, 65533, 65536, 1114111))`, "\t\n\r \ud7ff\ue000\ufffd\U00010000\U0010ffff", "", false},
		{"xml_10_rejects_restricted_character", `codepoints-to-string(1)`, "", "FOCH0001", false},
		{"xml_11_accepts_restricted_characters", `codepoints-to-string((1, 31, 65536))`, "\x01\x1f\U00010000", "", true},
		{"xml_11_rejects_null", `codepoints-to-string(0)`, "", "FOCH0001", true},
		{"xml_11_rejects_surrogate", `codepoints-to-string((65, 55296))`, "", "FOCH0001", true},
		{"xml_11_rejects_noncharacter", `codepoints-to-string(65534)`, "", "FOCH0001", true},
		{"rejects_above_unicode_range", `codepoints-to-string(1114112)`, "", "FOCH0001", false},
		{"rejects_integer_larger_than_int64", `codepoints-to-string(18446744073709551681)`, "", "FOCH0001", false},
		{"converts_untyped_integer", `codepoints-to-string(xs:untypedAtomic('65'))`, "A", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			expr, err := NewCompiler().Compile(tc.expression)
			if err != nil {
				t.Fatalf("compile %q: %v", tc.expression, err)
			}
			evaluator := NewEvaluator(DefaultEvaluatorOptions)
			if tc.xml11 {
				evaluator = evaluator.AllowXML11Chars()
			}
			result, err := evaluator.Evaluate(t.Context(), expr, nil)
			if tc.code != "" {
				if !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Errorf("%s = %v, want %s", tc.expression, err, tc.code)
				}
				return
			}
			if err != nil {
				t.Fatalf("evaluate %s: %v", tc.expression, err)
			}
			seq := result.Sequence()
			if xdm.SequenceLen(seq) != 1 {
				t.Fatalf("%s returned %d items, want one string", tc.expression, xdm.SequenceLen(seq))
			}
			got, ok := seq.Get(0).(xdm.AtomicValue)
			if !ok || got.TypeName != xdm.TypeString || got.Value != tc.want {
				t.Errorf("%s = %v, want xs:string(%q)", tc.expression, seq.Get(0), tc.want)
			}
		})
	}
}

func TestStringToCodepointsHonorsResultLimit(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, input string
		want        []int64
		wantErr     error
	}{
		{"at_limit", "A😀", []int64{65, 128512}, nil},
		{"over_limit", "A😀é", nil, ErrNodeSetLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := withFnContext(t.Context(), &evalContext{maxNodes: 2})
			result, err := fnStringToCodepoints(ctx, []xdm.Sequence{xdm.SingleString(tc.input)})
			if !errors.Is(err, tc.wantErr) || xdm.SequenceLen(result) != len(tc.want) {
				t.Fatalf("string-to-codepoints(%q) = (%v, %v), want (%v, %v)", tc.input, result, err, tc.want, tc.wantErr)
			}
			for i, want := range tc.want {
				atom, ok := result.Get(i).(xdm.AtomicValue)
				got, fits := atom.Int64Val()
				if !ok || !fits || got != want || atom.TypeName != xdm.TypeInteger {
					t.Errorf("codepoint %d = %v, want xs:integer(%d)", i+1, result.Get(i), want)
				}
			}
		})
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if seq, err := fnStringToCodepoints(ctx, []xdm.Sequence{xdm.SingleString("A")}); xdm.SequenceLen(seq) != 0 || !errors.Is(err, context.Canceled) {
		t.Errorf("string-to-codepoints with canceled context = (%v, %v), want no values and context.Canceled", seq, err)
	}
}

func TestStringNormalizationAndReplacementBoundariesASTAndVM(t *testing.T) {
	t.Parallel()

	assertFunctionResults(t, []functionResultCase{
		{"fully_normalized_inserts_starter_before_leading_mark", `normalize-unicode(codepoints-to-string((769, 65)), ' fully-normalized ')`, " \u0301A"},
		{"fully_normalized_composes_without_inserting_space", `normalize-unicode(codepoints-to-string((65, 769)), 'FULLY-NORMALIZED')`, "Á"},
		{"longest_valid_replacement_group", `replace('ab','(a)(b)','$21-$0-$9')`, "b1-ab-"},
		{"longest_multidigit_capture", `replace('abcdefghij','(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)','$10$1')`, "ja"},
		{"replacement_decimal_group_and_literal_suffix", `replace('x','(x)','$00-$01-$99-$19-$099-$009')`, "x-x-9-x9-9-"},
		{"replacement_missing_group_without_captures", `replace('x','x','$99')`, "9"},
		{"replacement_empty_input_still_returns_one_string", `(count(replace((),'x','y')),replace((),'x','$','q') eq '')`, "1|true"},
		{"empty_sequence_after_atomization", `(empty(compare([], '')), empty(codepoint-equal('', [])), codepoint-equal('', ''))`, "true|true|true"},
	})
}

func TestStringFunctionsUseFocusASTAndVM(t *testing.T) {
	t.Parallel()

	assertFunctionResults(t, []functionResultCase{
		{"atomic_focus_keeps_unicode_and_xml_whitespace_rules", `'  😀  é ' ! (string(), string-length(), normalize-space())`, "  😀  é |7|😀 é"},
		{"string_join_atomizes_array_members", `string-join([(1, 2), (), 3], ':')`, "1:2:3"},
		{"join_retains_empty_string_items", `string-join(('', 'a', ''), ':')`, ":a:"},
	})
	for _, tc := range []struct{ name, expression, code string }{
		{"string_without_focus", `string()`, "XPDY0002"},
		{"length_without_focus", `string-length()`, "XPDY0002"},
		{"normalize_without_focus", `normalize-space()`, "XPDY0002"},
		{"function_focus_has_no_string_value", `(function() { 'a' }) ! string()`, "FOTY0014"},
		{"array_has_no_string_value", `string([1])`, "FOTY0014"},
		{"replace_rejects_trailing_dollar", `replace('a','a','$')`, "FORX0004"},
		{"replace_rejects_trailing_backslash", `replace('a','a','\')`, "FORX0004"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()

				seq, err := evaluateFunctionExpression(t, tc.expression, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Errorf("%s = (%v, %v), want no result and %s", tc.expression, seq, err, tc.code)
				}
			})
		}
	}
}

func TestCodepointsToStringCountsUTF8OutputBytes(t *testing.T) {
	t.Parallel()

	points := xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(65)}, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(128512)}}
	for _, tc := range []struct {
		name    string
		budget  int
		wantErr error
	}{
		{"exact_byte_limit", 5, nil},
		{"one_byte_short", 4, ErrBudget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := WithBudget(t.Context(), 100, 100, tc.budget, 10)
			result, err := fnCodepointsToString(ctx, []xdm.Sequence{points})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || xdm.SequenceLen(result) != 0 {
					t.Errorf("codepoints-to-string at %d bytes = (%v, %v), want no values and %v", tc.budget, result, err, tc.wantErr)
				}
				return
			}
			if err != nil || xdm.SequenceLen(result) != 1 {
				t.Fatalf("codepoints-to-string = (%v, %v), want one string", result, err)
			}
			if atom, ok := result.Get(0).(xdm.AtomicValue); !ok || atom.TypeName != xdm.TypeString || atom.Value != "A😀" {
				t.Errorf("codepoints-to-string result = %v, want xs:string(A😀)", result.Get(0))
			}
		})
	}
}

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
		{"normalization_accepts_absent_input_and_empty_string", `(normalize-unicode((), 'unknown') eq '', normalize-unicode('', 'NFC') eq '')`, "true|true"},
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
		{"replace_checks_pattern_for_empty_input", `replace((),'[','y')`, "FORX0002"},
		{"replace_checks_flags_for_empty_input", `replace((),'x','y','z')`, "FORX0001"},
		{"replace_checks_zero_length_match_for_empty_input", `replace((),'x*','y')`, "FORX0003"},
		{"replace_checks_replacement_for_empty_input", `replace((),'x','$')`, "FORX0004"},
		{"normalization_rejects_unknown_form", `normalize-unicode('a','unknown')`, "FOCH0003"},
		{"normalization_checks_form_for_present_empty_string", `normalize-unicode('','unknown')`, "FOCH0003"},
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

func TestFnStringUsesSchemaAwareNodeStringValue(t *testing.T) {
	t.Parallel()
	const source = `<r key=" 004 "><content>  <![CDATA[  ]]><v> one </v><!--skip--><?p skip?><v>two</v>  </content><count>004</count></r>`
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	content := doc.DocumentElement().FirstChild()
	count := content.NextSibling()
	evaluator := NewEvaluator(DefaultEvaluatorOptions).
		SchemaDeclarations(dataContentSchema{}).
		TypeAnnotations(map[xdm.Node]string{
			content: "Q{urn:test}ElementOnly",
			count:   xdm.TypeInteger,
		})
	for _, tc := range []struct{ name, query, want string }{
		{"drops_only_whitespace_owned_by_element_only_node", `string(r/content)`, " one two"},
		{"descendant_order_is_preserved_in_document_string_value", `string(.)`, " one two004"},
		{"typed_integer_retains_its_lexical_form", `r/count ! string()`, "004"},
		{"attributes_keep_their_own_whitespace", `string(r/@key)`, " 004 "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			expression, err := NewCompiler().Language(31, nil).Compile(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			got, err := evaluator.Evaluate(t.Context(), expression, doc)
			if err != nil {
				t.Fatal(err)
			}
			assertAtomicSequence(t, got.Sequence(), []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: tc.want}})
		})
	}
}
