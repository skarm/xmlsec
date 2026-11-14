package xpath //nolint:testpackage // Supplies schema content kinds and nilled properties directly to the evaluator.

import (
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

type dataContentSchema struct{ castContractSchema }

func (dataContentSchema) SchemaTypeContentKind(name string) (ContentTypeKind, bool) {
	switch name {
	case "Q{urn:test}Empty":
		return ContentTypeEmpty, true
	case "Q{urn:test}ElementOnly":
		return ContentTypeElementOnly, true
	default:
		return ContentTypeSimple, false
	}
}

func TestFnDataTypedValues(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, source string
		want         []xdm.AtomicValue
		code         string
	}{
		{"nested_arrays_skip_nilled_and_empty_elements", `data([r/nilled, [1,r/empty,2], r/count])`, []xdm.AtomicValue{
			{TypeName: xdm.TypeInteger, Value: int64(1)},
			{TypeName: xdm.TypeInteger, Value: int64(2)},
			{TypeName: xdm.TypeInteger, Value: int64(7)},
		}, ""},
		{"uses_context_node_annotation", `r/count ! data()`, []xdm.AtomicValue{{TypeName: xdm.TypeInteger, Value: int64(7)}}, ""},
		{"atomizes_attribute_and_untyped_element", `data((r/@name, r/complex/v))`, []xdm.AtomicValue{
			{TypeName: xdm.TypeUntypedAtomic, Value: "count"},
			{TypeName: xdm.TypeUntypedAtomic, Value: "kept"},
		}, ""},
		{"element_only_content_has_no_typed_value", `data(r/complex)`, nil, "FOTY0012"},
		{"first_error_comes_from_map_inside_array", `data([map{}, r/complex])`, nil, "FOTY0013"},
		{"first_error_comes_from_element_inside_array", `data([r/complex, map{}])`, nil, "FOTY0012"},
		{"empty_input_has_no_atoms", `data(())`, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const fixture = `<r name="count"><nilled/><empty/><complex><v>kept</v></complex><count>7</count></r>`
			doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), fixture)
			if err != nil {
				t.Fatal(err)
			}
			children := slices.Collect(xdm.Children(doc.DocumentElement()))
			if len(children) != 4 {
				t.Fatalf("fixture has %d children, want 4", len(children))
			}
			nilled, empty, elementOnly, count := children[0], children[1], children[2], children[3]
			evaluator := NewEvaluator(DefaultEvaluatorOptions).
				SchemaDeclarations(dataContentSchema{}).
				NilledElements(map[xdm.Node]struct{}{nilled: {}}).
				TypeAnnotations(map[xdm.Node]string{
					nilled: "Q{urn:test}ElementOnly", empty: "Q{urn:test}Empty",
					elementOnly: "Q{urn:test}ElementOnly", count: xdm.TypeInteger,
				})
			expr, err := NewCompiler().Language(31, nil).Compile(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			got, err := evaluator.Evaluate(t.Context(), expr, doc)
			if tc.code != "" {
				if got != nil || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Fatalf("%s returned %v, %v; want no result and %s", tc.source, got, err, tc.code)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: %v", tc.source, err)
			}
			seq := got.Sequence()
			if xdm.SequenceLen(seq) != len(tc.want) {
				t.Fatalf("%s returned %d items, want %d", tc.source, xdm.SequenceLen(seq), len(tc.want))
			}
			for index, want := range tc.want {
				item, ok := seq.Get(index).(xdm.AtomicValue)
				if !ok || item.TypeName != want.TypeName {
					t.Errorf("%s item %d = %v, want %v", tc.source, index+1, seq.Get(index), want)
					continue
				}
				equal := item.Value == want.Value
				if integer, ok := want.Value.(int64); ok {
					value, fits := item.Int64Val()
					equal = fits && value == integer
				}
				if !equal {
					t.Errorf("%s item %d = %v, want %v", tc.source, index+1, item, want)
				}
			}
		})
	}
}
