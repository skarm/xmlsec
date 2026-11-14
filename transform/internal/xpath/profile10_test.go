package xpath //nolint:testpackage // Exercises the internal XPath 1.0 compiler and evaluator.

import (
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestXPath10ConversionAndBuiltinSemantics(t *testing.T) {
	t.Parallel()
	doc, err := (xdm.ParseOptions{}).ParseReader(t.Context(), strings.NewReader(`<r xmlns:p="urn:example"><p:n xml:id="first"> 3.5 </p:n><p:n xml:id="second">2</p:n><value>second first</value><value>second</value></r>`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, expression, want string }{
		{"numbers_use_decimal_lexical_space", `concat(number(' +1 '), '|', number('1e2'), '|', number(' -.5 '), '|', number(' '), '|', number('1.2.3'))`, "NaN|NaN|-0.5|NaN|NaN"},
		{"number_conversion_and_infinities", `concat(number(true()),'|',number(false()),'|',number(/r/missing),'|',1 div 0,'|',-1 div 0,'|',-0)`, "1|0|NaN|Infinity|-Infinity|0"},
		{"first_node_is_selected_in_document_order", `concat(string(/r/p:n), '|', number(/r/p:n), '|', name(/r/p:n), '|', local-name(/r/p:n), '|', namespace-uri(/r/p:n))`, " 3.5 |3.5|p:n|n|urn:example"},
		{"sum_reads_all_nodes_and_empty_set_is_zero", `concat(sum(/r/p:n),'|',sum(/r/missing),'|',count(/r/p:n))`, "5.5|0|2"},
		{"id_atomizes_each_input_node_and_deduplicates", `concat(count(id(/r/value)), '|', string(id(/r/value)[1]/@xml:id), '|', string(id('second missing')/@xml:id))`, "2|first|second"},
		{"numeric_predicates_and_reverse_axis_use_proximity", `concat(string(/r/p:n[0.5+0.5]/@xml:id),'|',string((/r/p:n)[2]/preceding-sibling::*[1]/@xml:id))`, "first|first"},
		{"string_and_number_argument_coercion", `concat(substring(12345, '2.5', '2'), '|', floor(' -1.2 '), '|', ceiling('-1.2'), '|', round('-1.5'), '|', contains(12345, 234))`, "34|-2|-1|-1|true"},
		{"context_and_empty_node_set", `concat(normalize-space(), '|', string(/r/absent), '|', boolean(/r/absent))`, "3.5 2second firstsecond||false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			namespaces := map[string]string{"p": "urn:example"}
			compiled, err := NewCompiler().Language(10, namespaces).Compile(tc.expression)
			if err != nil {
				t.Fatalf("Compile %q: %v", tc.expression, err)
			}
			result, err := NewEvaluator(DefaultEvaluatorOptions).Namespaces(namespaces).Evaluate(t.Context(), compiled, doc)
			if err != nil {
				t.Fatalf("Evaluate %q: %v", tc.expression, err)
			}
			assertAtomicSequence(t, result.Sequence(), []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: tc.want}})
		})
	}
}

func TestXPath10RejectsLaterGrammarAndInvalidNodeSets(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, expression string
		want             error
	}{
		{"unary_plus", "+1", &xdm.Error{Code: "XPST0003"}},
		{"atomic_sequence", "(1,2)", &xdm.Error{Code: "XPST0003"}},
		{"value_comparison", "1 eq 1", &xdm.Error{Code: "XPST0003"}},
		{"integer_division", "4 idiv 2", &xdm.Error{Code: "XPST0003"}},
		{"later_builtin", "upper-case('a')", ErrUnknownFunction},
		{"sum_requires_nodes", "sum(2)", &xdm.Error{Code: "XPTY0004"}},
		{"name_requires_nodes", "name('r')", &xdm.Error{Code: "XPTY0004"}},
		{"number_without_context", "number()", &xdm.Error{Code: "XPDY0002"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			compiled, err := NewCompiler().Language(10, nil).Compile(tc.expression)
			var result *Result
			if err == nil {
				result, err = NewEvaluator(DefaultEvaluatorOptions).Evaluate(t.Context(), compiled, nil)
			}
			if result != nil || !errors.Is(err, tc.want) {
				t.Errorf("%q returned %v, %v, want no result and %v", tc.expression, result, err, tc.want)
			}
		})
	}
}
