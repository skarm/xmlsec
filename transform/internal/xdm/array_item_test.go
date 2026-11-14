package xdm_test

import (
	"errors"
	"math"
	"math/big"
	"strconv"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestArrayFlattenEmptyMembers(t *testing.T) {
	t.Parallel()

	a := xdm.NewArray([]xdm.Sequence{nil, xdm.SingleString("before"), xdm.ItemSlice{xdm.NewArrayFromImmutableMembers([]xdm.Sequence{nil, xdm.SingleString("inside")})}, nil})
	assertStringItems(t, a.Flatten(), "before", "inside")
	assertStringItems(t, xdm.NewArray([]xdm.Sequence{nil}).Flatten())
}

func TestArrayFlattenDeepOrderAndOwnership(t *testing.T) {
	t.Parallel()
	const depth = 4096
	leaf := big.NewInt(7)
	array := xdm.NewArray([]xdm.Sequence{xdm.SingleIntegerBig(leaf)})
	for i := range depth {
		array = xdm.NewArrayFromImmutableMembers([]xdm.Sequence{nil, xdm.SingleInteger(int64(i)), xdm.ItemSlice{array}, nil})
	}
	result := array.Flatten()
	if result.Len() != depth+1 {
		t.Fatal("flattened size", result.Len())
	}
	for i := range depth {
		if got := result.Get(i).(xdm.AtomicValue).IntegerVal(); got != int64(depth-i-1) {
			t.Fatal("nested array changed order", i, got)
		}
	}
	result.Get(depth).(xdm.AtomicValue).BigInt().SetInt64(99)
	if got := array.Flatten().Get(depth).(xdm.AtomicValue).IntegerVal(); got != 7 {
		t.Fatal("flatten exposed mutable leaf", got)
	}
}

func TestArrayPersistentUpdatesAndBounds(t *testing.T) {
	t.Parallel()

	payload := big.NewInt(7)
	member := xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: payload}}
	original := xdm.NewArray([]xdm.Sequence{member, nil, xdm.SingleString("tail")})
	payload.SetInt64(99)
	member[0] = stringKey("replaced")
	got, err := original.Get(1)
	if err != nil || got.Get(0).(xdm.AtomicValue).BigInt().Int64() != 7 {
		t.Fatalf("array retained caller payload: %v, %v", got, err)
	}
	got.Get(0).(xdm.AtomicValue).BigInt().SetInt64(100)
	got, err = original.Get(1)
	if err != nil || got.Get(0).(xdm.AtomicValue).BigInt().Int64() != 7 {
		t.Fatal("Get exposed array payload")
	}
	members := original.Members()
	members[0].Get(0).(xdm.AtomicValue).BigInt().SetInt64(101)
	members[2] = nil
	view, err := original.GetView(1)
	if err != nil {
		t.Fatalf("array.GetView(1): %v", err)
	}
	if view.Get(0).(xdm.AtomicValue).BigInt().Int64() != 7 {
		t.Fatal("Members exposed array payload")
	}
	tail := requireArrayMember(t, original, 3)
	assertStringItems(t, tail, "tail")
	replacement := xdm.ItemSlice{stringKey("changed")}
	updated, err := original.Put(2, replacement)
	if err != nil {
		t.Fatal(err)
	}
	replacement[0] = stringKey("mutated")
	seq := requireArrayMember(t, updated, 2)
	assertStringItems(t, seq, "changed")
	seq = requireArrayMember(t, original, 2)
	assertStringItems(t, seq)
	appended := updated.Append(xdm.SingleString("new"))
	if original.Size() != 3 || updated.Size() != 3 || appended.Size() != 4 {
		t.Fatal("persistent update changed source size")
	}
	seq = requireArrayMember(t, appended, 4)
	assertStringItems(t, seq, "new")
	sub, err := appended.SubArray(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	assertStringItems(t, sub.Flatten(), "changed", "tail")
	empty, err := original.SubArray(4, 0)
	if err != nil || empty.Size() != 0 {
		t.Fatalf("empty trailing subarray: %v, %v", empty, err)
	}
	for _, index := range []int{0, -1, 4, math.MaxInt} {
		_, err = original.Get(index)
		requireXDMCode(t, err, "FOAY0001")
		_, err = original.GetView(index)
		requireXDMCode(t, err, "FOAY0001")
		_, err = original.Put(index, nil)
		requireXDMCode(t, err, "FOAY0001")
	}
	for _, bounds := range [][2]int{{0, 0}, {5, 0}, {2, 3}, {1, math.MaxInt}, {math.MaxInt, 1}} {
		_, err = original.SubArray(bounds[0], bounds[1])
		requireXDMCode(t, err, "FOAY0001")
	}
	_, err = original.SubArray(1, -1)
	requireXDMCode(t, err, "FOAY0002")
}

func TestArrayErrorsKeepQualifiedCodes(t *testing.T) {
	t.Parallel()

	_, err := (xdm.ArrayItem{}).Get(1)

	var coded *xdm.Error
	if !errors.As(err, &coded) || coded.Code != "FOAY0001" || coded.CodeQName().Local != "FOAY0001" {
		t.Fatalf("lost structured array error: %v", err)
	}
}

// Each level contributes a value, as in recursively generated array-valued
// expressions. Immutable construction is excluded from the measured flatten.
func BenchmarkArrayFlattenNested(b *testing.B) {
	for _, depth := range []int{1, 32, 256} {
		b.Run(strconv.Itoa(depth), func(b *testing.B) {
			array := xdm.NewArrayFromImmutableMembers(nil)
			for i := range depth {
				array = xdm.NewArrayFromImmutableMembers([]xdm.Sequence{xdm.SingleInteger(int64(i)), xdm.ItemSlice{array}})
			}
			b.ReportAllocs()
			for b.Loop() {
				if result := array.Flatten(); result.Len() != depth {
					b.Fatal("wrong flattened size")
				}
			}
		})
	}
}
