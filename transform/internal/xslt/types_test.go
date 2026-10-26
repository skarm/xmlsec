package xslt //nolint:testpackage // Tests cardinality after atomization and XSLT function conversion directly.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func TestSequenceTypeCardinality(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		typeName     string
		acceptsCount [3]bool // Expected acceptance for zero, one and two items.
	}{
		{"default item sequence", "", [3]bool{true, true, true}},
		{"empty sequence", "empty-sequence()", [3]bool{true, false, false}},
		{"optional", "xs:integer?", [3]bool{true, true, false}},
		{"zero or more", "xs:integer*", [3]bool{true, true, true}},
		{"exactly one", "xs:integer", [3]bool{false, true, false}},
		{"one or more", "xs:integer+", [3]bool{false, true, true}},
		{"nested comments before occurrence", "xs:integer (: outer (: inner :) :) ?", [3]bool{true, true, false}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := allowsEmptySequence(test.typeName); got != test.acceptsCount[0] {
				t.Fatalf("allows empty %q = %v", test.typeName, got)
			}
			for size := 0; size <= 2; size++ {
				seq := make(xdm.ItemSlice, size)
				for i := range seq {
					seq[i] = xdm.AtomicValue{TypeName: "xs:integer", Value: int64(i)}
				}
				sequenceType := parseSequenceType(test.typeName)
				got, err := checkSequenceType(t.Context(), seq, sequenceType, "XTTE0570", "test variable")
				if test.acceptsCount[size] {
					if err != nil || xdm.SequenceLen(got) != size {
						t.Fatalf("%q size %d = %v, %v", test.typeName, size, got, err)
					}
				} else {
					var detail *XSLTError
					if got != nil || !errors.As(err, &detail) || detail.Code != "XTTE0570" {
						t.Fatalf("%q size %d = %v, %v; want XTTE0570", test.typeName, size, got, err)
					}
				}
			}
		})
	}
}

func TestSequenceTypeAtomizationBeforeCardinality(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		seq      xdm.Sequence
		typeName string
		want     []string
		wantErr  bool
	}{
		{"array expands", xdm.ItemSlice{xdm.NewArray([]xdm.Sequence{xdm.ItemSlice{stringItem("a"), stringItem("b")}})}, "xs:string+", []string{"a", "b"}, false},
		{"expanded cardinality checked", xdm.ItemSlice{xdm.NewArray([]xdm.Sequence{xdm.ItemSlice{stringItem("a"), stringItem("b")}})}, "xs:string", nil, true},
		{"empty array atomizes to empty", xdm.ItemSlice{xdm.NewArray(nil)}, "xs:string*", nil, false},
		{"empty member atomizes to empty", xdm.ItemSlice{xdm.NewArray([]xdm.Sequence{nil})}, "xs:string?", nil, false},
		{"empty-sequence test does not atomize array", xdm.ItemSlice{xdm.NewArray(nil)}, "empty-sequence()", nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := checkSequenceType(t.Context(), test.seq, parseSequenceType(test.typeName), "XTTE0570", "test variable")
			if test.wantErr {
				var detail *XSLTError
				if got != nil || !errors.As(err, &detail) || detail.Code != "XTTE0570" {
					t.Fatalf("converted = %v, %v; want XTTE0570", got, err)
				}
				return
			}
			if err != nil || xdm.SequenceLen(got) != len(test.want) {
				t.Fatalf("converted = %v, %v; want %d items", got, err, len(test.want))
			}
			for i, want := range test.want {
				atom, ok := got.Get(i).(xdm.AtomicValue)
				if !ok || atom.TypeName != "xs:string" || atom.Value != want {
					t.Fatalf("atom %d = %+v; want xs:string %q", i, got.Get(i), want)
				}
			}
		})
	}
}

func TestSequenceTypePreservesNodeIdentity(t *testing.T) {
	t.Parallel()
	original := xdm.NewDefaultDocument().CreateText("a")
	got, err := checkSequenceType(t.Context(), xdm.ItemSlice{xdm.NodeItem{Node: original}}, parseSequenceType("text()"), "XTTE0570", "test variable")
	if err != nil || xdm.SequenceLen(got) != 1 {
		t.Fatalf("node type check = %v, %v", got, err)
	}
	node, ok := got.Get(0).(xdm.NodeItem)
	if !ok || node.Node != original {
		t.Fatal("node identity changed during type checking")
	}
}

func TestSequenceTypeAtomicConversions(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input xdm.AtomicValue
		as    string
		kind  string
		value string
	}{
		{xdm.AtomicValue{TypeName: "xs:untypedAtomic", Value: "42"}, "xs:integer", "xs:integer", "42"},
		{xdm.AtomicValue{TypeName: "xs:integer", Value: int64(42)}, "xs:double", "xs:double", "42"},
		{xdm.AtomicValue{TypeName: "xs:integer", Value: int64(42)}, "xs:decimal", "xs:integer", "42"},
		{xdm.AtomicValue{TypeName: "xs:anyURI", Value: "https://example.test/"}, "xs:string", "xs:string", "https://example.test/"},
	} {
		got, err := checkSequenceType(t.Context(), xdm.SingleAtomic(test.input), parseSequenceType(test.as), "XTTE0790", "function argument")
		if err != nil || xdm.SequenceLen(got) != 1 {
			t.Fatalf("convert %+v to %s = %v, %v", test.input, test.as, got, err)
		}
		atom, ok := got.Get(0).(xdm.AtomicValue)
		if !ok {
			t.Fatalf("converted to non-atomic %T", got.Get(0))
		}
		value, err := xpath.AtomicToString(atom)
		if err != nil || atom.TypeName != test.kind || value != test.value {
			t.Fatalf("convert %+v to %s = %+v (%q), %v", test.input, test.as, atom, value, err)
		}
	}
	got, err := checkSequenceType(t.Context(), xdm.ItemSlice{stringItem("valid"), xdm.AtomicValue{TypeName: "xs:integer", Value: int64(1)}}, parseSequenceType("xs:string+"), "XTTE0790", "function argument")
	var detail *XSLTError
	if got != nil || !errors.As(err, &detail) || detail.Code != "XTTE0790" {
		t.Fatalf("partial type failure = %v, %v", got, err)
	}
}
