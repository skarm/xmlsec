package xpath //nolint:testpackage // Verify nested sequence-type binding and shared work limits.

import (
	"errors"
	"reflect"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

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
