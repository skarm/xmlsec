package xpath //nolint:testpackage // Compare internal XDM values after function conversion.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestConvertToSequenceTypeAtomicArguments(t *testing.T) {
	t.Parallel()

	untyped := func(s string) xdm.Sequence {
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeUntypedAtomic, Value: s})
	}
	cases := []struct {
		name     string
		input    xdm.Sequence
		required string
		want     []xdm.AtomicValue
		wantCode string
	}{
		{
			name:     "untyped_atomic_is_converted",
			input:    untyped("1"),
			required: "xs:boolean",
			want:     []xdm.AtomicValue{{TypeName: xdm.TypeBoolean, Value: true}},
		},
		{
			name:     "any_uri_is_promoted_to_string",
			input:    xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: "urn:entry"}),
			required: "xs:string",
			want:     []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: "urn:entry"}},
		},
		{
			name:     "array_members_are_atomized_in_order",
			input:    xdm.ItemSlice{xdm.NewArray([]xdm.Sequence{xdm.SingleString("first"), nil, xdm.SingleString("last")})},
			required: "xs:anyAtomicType+",
			want:     []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: "first"}, {TypeName: xdm.TypeString, Value: "last"}},
		},
		{
			name:     "invalid_lexical_cast_retains_its_code",
			input:    untyped("word"),
			required: "xs:integer",
			wantCode: "FORG0001",
		},
		{
			name:     "string_does_not_implicitly_cast_to_integer",
			input:    xdm.SingleString("42"),
			required: "xs:integer",
			wantCode: "XPTY0004",
		},
		{
			name:     "untyped_atomic_cannot_convert_to_namespace_sensitive_type",
			input:    untyped("xs:string"),
			required: "xs:QName",
			wantCode: "XPTY0117",
		},
		{
			name:     "map_atomization_retains_its_code",
			input:    xdm.ItemSlice{xdm.NewMap(nil)},
			required: "xs:integer?",
			wantCode: "FOTY0013",
		},
		{
			name:     "atomized_cardinality_must_match",
			input:    xdm.ItemSlice{xdm.NewArray([]xdm.Sequence{xdm.SingleInteger(1), xdm.SingleInteger(2)})},
			required: "xs:integer",
			wantCode: "XPTY0004",
		},
		{
			name:     "zero_items_satisfy_optional_type",
			required: "xs:integer?",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ConvertToSequenceType(t.Context(), tc.input, mustParseSequenceType(t, tc.required))
			if tc.wantCode != "" {
				if !errors.Is(err, &xdm.Error{Code: tc.wantCode}) {
					t.Errorf("ConvertToSequenceType(%s): %v, want %s", tc.required, err, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("ConvertToSequenceType(%s): %v", tc.required, err)
			}
			assertAtomicSequence(t, got, tc.want)
		})
	}
}

func TestConvertToSequenceTypeAdaptsCollectionLookup(t *testing.T) {
	t.Parallel()

	key := xdm.AtomicValue{TypeName: xdm.TypeString, Value: "found"}
	mapping := xdm.SingleEntryMap(key, xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: "urn:found"}))
	got, err := ConvertToSequenceType(t.Context(), xdm.ItemSlice{mapping}, mustParseSequenceType(t, "function(xs:string) as xs:string?"))
	if err != nil {
		t.Fatalf("convert map to function: %v", err)
	}
	if xdm.SequenceLen(got) != 1 {
		t.Fatalf("convert map to function returned %d items, want 1", xdm.SequenceLen(got))
	}
	fn, ok := got.Get(0).(xdm.FunctionItem)
	if !ok || fn.Arity != 1 {
		t.Fatalf("converted item = %#v, want a one-argument function", got.Get(0))
	}

	t.Run("promotes_result", func(t *testing.T) {
		t.Parallel()

		got, err := fn.Invoke(t.Context(), []xdm.Sequence{xdm.SingleString("found")})
		if err != nil {
			t.Fatalf("look up present key: %v", err)
		}
		assertAtomicSequence(t, got, []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: "urn:found"}})
	})
	t.Run("missing_key_returns_empty", func(t *testing.T) {
		t.Parallel()

		got, err := fn.Invoke(t.Context(), []xdm.Sequence{xdm.SingleString("missing")})
		if err != nil || xdm.SequenceLen(got) != 0 {
			t.Errorf("look up missing key = (%v, %v), want empty sequence", got, err)
		}
	})
	t.Run("checks_argument_type", func(t *testing.T) {
		t.Parallel()

		got, err := fn.Invoke(t.Context(), []xdm.Sequence{xdm.SingleBoolean(true)})
		if !errors.Is(err, &xdm.Error{Code: "XPTY0004"}) || xdm.SequenceLen(got) != 0 {
			t.Errorf("look up with a boolean = (%v, %v), want empty result and XPTY0004", got, err)
		}
	})
	t.Run("checks_arity", func(t *testing.T) {
		t.Parallel()

		got, err := fn.Invoke(t.Context(), nil)
		if !errors.Is(err, &xdm.Error{Code: "XPTY0004"}) || xdm.SequenceLen(got) != 0 {
			t.Errorf("look up without an argument = (%v, %v), want empty result and XPTY0004", got, err)
		}
	})
}
