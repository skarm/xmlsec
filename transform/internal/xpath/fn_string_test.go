package xpath //nolint:testpackage // Supplies schema annotations for string-value evaluation.

import (
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

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
