package xpath //nolint:testpackage // Supplies explicit type annotations to the ID lookup functions.

import (
	"slices"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestIDLookupTypedNodes(t *testing.T) {
	t.Parallel()
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<r><entry><code>one</code></entry><other key="two"/><link refs="two one"/><plain refs="two"/></r>`)
	if err != nil {
		t.Fatal(err)
	}
	children := slices.Collect(xdm.Children(doc.DocumentElement()))
	if len(children) != 4 {
		t.Fatalf("fixture has %d child nodes; want 4", len(children))
	}
	entry, other, link := children[0], children[1], children[2]
	otherElement, otherOK := other.(*xdm.Element)
	linkElement, linkOK := link.(*xdm.Element)
	if !otherOK || !linkOK {
		t.Fatalf("fixture has child nodes %T and %T; want elements", other, link)
	}
	code := entry.FirstChild()
	keys, references := otherElement.Attributes(), linkElement.Attributes()
	if code == nil || len(keys) != 1 || len(references) != 1 {
		t.Fatal("fixture lacks the ID or IDREF nodes")
	}
	key, refs := keys[0], references[0]
	foreign, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<foreign>one</foreign>`)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := NewEvaluator(DefaultEvaluatorOptions).TypeAnnotations(map[xdm.Node]string{
		code: xdm.TypeID, key: xdm.TypeID, refs: "xs:IDREFS", foreign.DocumentElement(): xdm.TypeID,
	})

	for _, tc := range []struct {
		name, expr string
		want       []xdm.Node
	}{
		{"id selects the annotated element and the attribute owner in document order", `id(('two one', 'one', 'missing', '1invalid'), /r/other)`, []xdm.Node{code, other}},
		{"element-with-id returns the annotated element's parent", `element-with-id(('two', 'one'), /r)`, []xdm.Node{entry, other}},
		{"idref matches list members without duplicates", `idref(('two', 'one', 'two'), /r)`, []xdm.Node{refs}},
		{"idref input strings are individual tokens", `idref('two one', /r)`, nil},
		{"empty id input", `id((), /r)`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			compiled, err := NewCompiler().Language(31, nil).Compile(tc.expr)
			if err != nil {
				t.Fatal(err)
			}
			result, err := evaluator.Evaluate(t.Context(), compiled, doc)
			if err != nil {
				t.Fatal(err)
			}
			seq := result.Sequence()
			if xdm.SequenceLen(seq) != len(tc.want) {
				t.Fatalf("%s returned %d nodes; want %d", tc.expr, xdm.SequenceLen(seq), len(tc.want))
			}
			for i, want := range tc.want {
				got, ok := seq.Get(i).(xdm.NodeItem)
				if !ok || got.Node != want {
					t.Errorf("%s item %d = %v; want node %s in the fixture document", tc.expr, i+1, seq.Get(i), want.Name())
				}
			}
		})
	}
}
