package xdm_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func nestedFunctionType() xdm.SequenceType {
	return xdm.SequenceType{ItemTest: xdm.ArrayTest{MemberType: xdm.SequenceType{ItemTest: xdm.MapTest{KeyType: xdm.AtomicOrUnionType{Name: "string"}, ValType: xdm.SequenceType{ItemTest: xdm.FunctionTest{ParamTypes: []xdm.SequenceType{{ItemTest: xdm.AtomicOrUnionType{Name: "integer"}}}, ReturnType: xdm.SequenceType{ItemTest: xdm.AtomicOrUnionType{Name: "string"}}}}}}}}
}

func nestedParams(st xdm.SequenceType) []xdm.SequenceType {
	return st.ItemTest.(xdm.ArrayTest).MemberType.ItemTest.(xdm.MapTest).ValType.ItemTest.(xdm.FunctionTest).ParamTypes
}

func TestCloneFunctionMetadataRecursesThroughCollections(t *testing.T) {
	t.Parallel()

	input := nestedFunctionType()
	returnType := nestedFunctionType()
	sentinel := errors.New("function cause")
	function := xdm.FunctionItem{Arity: 1, Name: "f", ParamTypes: []xdm.SequenceType{input}, ReturnType: &returnType, Invoke: func(context.Context, []xdm.Sequence) (xdm.Sequence, error) {
		return xdm.SingleString("result"), sentinel
	}}
	cloned := xdm.CloneItem(function).(xdm.FunctionItem)
	nestedParams(function.ParamTypes[0])[0].Occurrence = xdm.OccurrenceZeroOrMore
	nestedParams(*function.ReturnType)[0].Void = true
	function.ParamTypes[0].Void = true
	if cloned.ParamTypes[0].Void || nestedParams(cloned.ParamTypes[0])[0].Occurrence != xdm.OccurrenceExactlyOne || nestedParams(*cloned.ReturnType)[0].Void {
		t.Fatal("cloned metadata shares nested slices")
	}
	result, err := cloned.Invoke(t.Context(), nil)
	if err != sentinel || cloned.Arity != 1 || cloned.Name != "f" { //nolint:errorlint // The callback error must be returned unchanged, preserving its identity.
		t.Fatal("clone changed function identity or closure")
	}
	assertStringItems(t, result, "result")
	if xdm.CloneSequenceTypes(nil) != nil || xdm.CloneSequenceTypePtr(nil) != nil || xdm.CloneSequences(nil) != nil {
		t.Fatal("nil cloning changed representation")
	}

	// FunctionTest return types recurse independently of parameter metadata.
	signature := xdm.SequenceType{ItemTest: xdm.FunctionTest{ReturnType: nestedFunctionType()}}
	signatureClone := xdm.CloneSequenceType(signature)
	nestedParams(signature.ItemTest.(xdm.FunctionTest).ReturnType)[0].Void = true
	if nestedParams(signatureClone.ItemTest.(xdm.FunctionTest).ReturnType)[0].Void {
		t.Fatal("function test return type shares nested parameter metadata")
	}

	plain := xdm.SequenceType{ItemTest: xdm.AnyItemTest{}, Occurrence: xdm.OccurrenceOneOrMore}
	if got := xdm.CloneSequenceType(plain); !reflect.DeepEqual(got, plain) {
		t.Fatal("immutable test metadata changed")
	}
	params := []xdm.SequenceType{plain, {Void: true}}
	for _, tc := range []struct {
		repeat bool
		index  int
		ok     bool
		want   xdm.SequenceType
	}{{false, -1, false, xdm.SequenceType{}}, {false, 0, true, plain}, {false, 1, true, params[1]}, {false, 2, false, xdm.SequenceType{}}, {true, 2, false, xdm.SequenceType{}}} {
		got, ok := xdm.FunctionParameterType(params, tc.repeat, tc.index)
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("parameter %d repeat%v: %+v,%v", tc.index, tc.repeat, got, ok)
		}
	}
	if got, ok := xdm.FunctionParameterType(params[:1], true, 1000); !ok || !reflect.DeepEqual(got, plain) {
		t.Fatal("compact repeated parameter lost metadata")
	}
	if _, ok := xdm.FunctionParameterType(nil, true, 0); ok {
		t.Fatal("empty repeated metadata matched")
	}
}

func TestCloneNodeItemMetadataPreservesIdentity(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte("<root/>"))
	if err != nil {
		t.Fatal(err)
	}
	leaf := &xdm.NodeItemUnionMember{TypeName: "Q{u}leaf"}
	original := xdm.NodeItem{Node: doc.DocumentElement(), TypeAnnotation: "Q{u}union", ActiveUnionMember: leaf, UnionMemberTypes: []string{"first", "second"}, ListItemLeaves: []*xdm.NodeItemUnionMember{leaf, nil}}
	cloned := xdm.CloneItem(original).(xdm.NodeItem)
	original.UnionMemberTypes[0] = "changed"
	original.ListItemLeaves[0] = nil
	if cloned.Node != original.Node || cloned.ActiveUnionMember != leaf || cloned.ListItemLeaves[0] != leaf || cloned.UnionMemberTypes[0] != "first" || cloned.TypeAnnotation != "Q{u}union" {
		t.Fatal("metadata cloned incorrectly or node identity changed")
	}
	if got := xdm.CloneItem(xdm.NodeItem{Node: original.Node}).(xdm.NodeItem); got.Node != original.Node {
		t.Fatal("plain node clone changed identity")
	}
}
