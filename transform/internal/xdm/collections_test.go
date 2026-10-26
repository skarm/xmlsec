package xdm_test

import (
	"errors"
	"math"
	"math/big"
	"reflect"
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

func TestMergeMapsCombineEmptyValues(t *testing.T) {
	t.Parallel()

	for _, values := range [][]xdm.Sequence{{nil, xdm.SingleString("a")}, {xdm.SingleString("a"), nil}, {nil, nil}} {
		maps := []xdm.MapItem{xdm.SingleEntryMap(stringKey("key"), values[0]), xdm.SingleEntryMap(stringKey("key"), values[1])}
		merged, err := xdm.MergeMaps(maps, xdm.MergeCombine)
		if err != nil {
			t.Fatal(err)
		}
		value, ok := merged.Get(stringKey("key"))
		if !ok || merged.Size() != 1 {
			t.Fatal("combining an empty value lost its key")
		}
		if xdm.SequenceLen(values[0])+xdm.SequenceLen(values[1]) == 0 {
			assertStringItems(t, value)
		} else {
			assertStringItems(t, value, "a")
		}
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

func TestMapPersistentUpdatesAndOwnership(t *testing.T) {
	t.Parallel()

	keyNumber, valueNumber := big.NewInt(7), big.NewInt(42)
	value := xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: valueNumber}}
	original := xdm.NewMap([]xdm.MapEntry{{Key: xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: keyNumber}, Value: value}, {Key: stringKey("empty"), Value: nil}})
	keyNumber.SetInt64(8)
	valueNumber.SetInt64(99)
	value[0] = stringKey("overwritten")
	key := xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(7)}
	if original.Keys()[0].IntegerVal() != 7 {
		t.Fatal("constructor retained caller-owned key")
	}
	got, ok := original.Get(key)
	if !ok || got.Get(0).(xdm.AtomicValue).BigInt().Int64() != 42 || original.Contains(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(8)}) {
		t.Fatal("constructor retained mutable inputs")
	}
	got.Get(0).(xdm.AtomicValue).BigInt().SetInt64(100)
	keys := original.Keys()
	keys[0].BigInt().SetInt64(100)
	view, ok := original.GetView(key)
	if !ok || view.Get(0).(xdm.AtomicValue).BigInt().Int64() != 42 || !original.Contains(key) {
		t.Fatal("Get or Keys exposed stored payload")
	}
	if got, ok = original.Get(stringKey("empty")); !ok || got != nil {
		t.Fatalf("present empty map value: %v,%v", got, ok)
	}
	if got, ok = original.Get(stringKey("absent")); ok || got != nil {
		t.Fatal("missing map key appears present")
	}
	updated := original.Put(key, xdm.SingleString("new")).Put(stringKey("third"), xdm.SingleString("third"))
	if original.Size() != 2 || updated.Size() != 3 {
		t.Fatal("Put changed source size")
	}
	got = requireMapValue(t, updated, key)
	assertStringItems(t, got, "new")
	if keys := updated.Keys(); keys[0].IntegerVal() != 7 || keys[1].StringVal() != "empty" || keys[2].StringVal() != "third" {
		t.Fatalf("replacement changed insertion order: %v", keys)
	}
	removed := updated.Remove(stringKey("empty"))
	if removed.Size() != 2 || removed.Contains(stringKey("empty")) || !updated.Contains(stringKey("empty")) {
		t.Fatal("Remove changed original or retained deleted key")
	}
	if removed.Remove(stringKey("missing")).Size() != 2 {
		t.Fatal("missing-key removal changed map")
	}
	single := xdm.SingleEntryMap(stringKey("only"), xdm.SingleString("value"))
	if !single.Contains(stringKey("only")) || single.Contains(stringKey("other")) {
		t.Fatal("single entry lookup")
	}
	got, ok = single.GetView(stringKey("only"))
	if !ok {
		t.Fatal("single view missing")
	}
	assertStringItems(t, got, "value")
	if _, ok = single.GetView(stringKey("other")); ok {
		t.Fatal("single view matches wrong key")
	}
	if single.Remove(stringKey("only")).Size() != 0 || single.Remove(stringKey("other")).Size() != 1 {
		t.Fatal("single removal")
	}
	grown := single.Put(stringKey("second"), nil).Put(stringKey("only"), xdm.SingleString("replacement"))
	if grown.Size() != 2 {
		t.Fatal("single entry update index")
	}
	got = requireMapValue(t, grown, stringKey("only"))
	assertStringItems(t, got, "replacement")
	empty := xdm.NewMap(nil)
	if empty.Contains(key) {
		t.Fatal("empty map contains key")
	}
	if _, ok = empty.Get(key); ok {
		t.Fatal("empty map Get")
	}
}

func TestMapIterationIsolationAndEarlyError(t *testing.T) {
	t.Parallel()

	m := xdm.NewMap([]xdm.MapEntry{{Key: xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: big.NewInt(1)}, Value: xdm.SingleIntegerBig(big.NewInt(10))}, {Key: stringKey("second"), Value: xdm.SingleString("v")}})
	sentinel := errors.New("stop after first")
	calls := 0
	err := m.ForEach(func(k xdm.AtomicValue, v xdm.Sequence) error {
		calls++
		k.BigInt().SetInt64(9)
		v.Get(0).(xdm.AtomicValue).BigInt().SetInt64(99)
		return sentinel
	})
	if err != sentinel || calls != 1 {
		t.Fatalf("ForEach error/stop: %v,%d", err, calls)
	}
	value, ok := m.Get(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(1)})
	if !ok || value.Get(0).(xdm.AtomicValue).IntegerVal() != 10 {
		t.Fatal("ForEach exposed map storage")
	}
	calls = 0
	if err = m.ForEachView(func(xdm.AtomicValue, xdm.Sequence) error { calls++; return sentinel }); err != sentinel || calls != 1 {
		t.Fatal("ForEachView did not stop on exact error")
	}
	var seen []string
	if err = m.ForEach(func(k xdm.AtomicValue, _ xdm.Sequence) error { seen = append(seen, k.TypeName); return nil }); err != nil || !reflect.DeepEqual(seen, []string{xdm.TypeInteger, xdm.TypeString}) {
		t.Fatalf("iteration order: %v,%v", seen, err)
	}
	if err = m.ForEachView(func(xdm.AtomicValue, xdm.Sequence) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(m.EntriesView()) != 2 || len(m.KeysView()) != 2 {
		t.Fatal("entry views lost entries")
	}
}

func TestMapDuplicatePolicies(t *testing.T) {
	t.Parallel()

	for _, policy := range []xdm.MergePolicy{xdm.MergeUseFirst, xdm.MergeUseLast, xdm.MergeCombine, xdm.MergeReject} {
		t.Run(map[xdm.MergePolicy]string{xdm.MergeUseFirst: "first", xdm.MergeUseLast: "last", xdm.MergeCombine: "combine", xdm.MergeReject: "reject"}[policy], func(t *testing.T) {
			t.Parallel()

			entries := []xdm.MapEntry{{Key: stringKey("k"), Value: xdm.SingleString("a")}, {Key: stringKey("other"), Value: xdm.SingleString("middle")}, {Key: stringKey("k"), Value: xdm.SingleString("b")}, {Key: stringKey("k"), Value: xdm.SingleString("c")}}
			builder := xdm.NewMapBuilder(policy, 0)
			for i, entry := range entries {
				err := builder.Add(entry.Key, entry.Value)
				if policy == xdm.MergeReject && i >= 2 {
					requireXDMCode(t, err, "FOJS0003")
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if builder.Size() != 2 {
				t.Fatalf("builder distinct keys: %d", builder.Size())
			}
			maps := make([]xdm.MapItem, len(entries))
			for i, entry := range entries {
				maps[i] = xdm.SingleEntryMap(entry.Key, entry.Value)
			}
			built := builder.Build()
			merged, err := xdm.MergeMaps(maps, policy)
			if policy == xdm.MergeReject {
				requireXDMCode(t, err, "FOJS0003")
				assertStringItems(t, requireMapValue(t, built, stringKey("k")), "a")
				assertStringItems(t, requireMapValue(t, built, stringKey("other")), "middle")
				if keys := built.Keys(); len(keys) != 2 || keys[0].StringVal() != "k" || keys[1].StringVal() != "other" {
					t.Fatalf("rejected duplicate changed key order: %v", keys)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range []xdm.MapItem{built, merged} {
				if m.Size() != 2 || m.Keys()[0].StringVal() != "k" || m.Keys()[1].StringVal() != "other" {
					t.Fatal("duplicate handling changed key order")
				}
				value, ok := m.Get(stringKey("k"))
				if !ok {
					t.Fatal("missing combined key")
				}
				switch policy {
				case xdm.MergeUseFirst:
					assertStringItems(t, value, "a")
				case xdm.MergeUseLast:
					assertStringItems(t, value, "c")
				case xdm.MergeCombine:
					assertStringItems(t, value, "a", "b", "c")
				}
			}
		})
	}
	b := xdm.NewMapBuilder(xdm.MergeCombine, 1)
	for _, v := range []xdm.Sequence{nil, xdm.SingleString("v"), nil, xdm.SingleString("w")} {
		if err := b.Add(stringKey("k"), v); err != nil {
			t.Fatal(err)
		}
	}
	value := requireMapValue(t, b.Build(), stringKey("k"))
	assertStringItems(t, value, "v", "w")
}

func TestMapConstructorsOwnMutableKeys(t *testing.T) {
	t.Parallel()

	for _, construct := range []func(xdm.AtomicValue) xdm.MapItem{
		func(k xdm.AtomicValue) xdm.MapItem { return xdm.SingleEntryMap(k, nil) },
		func(k xdm.AtomicValue) xdm.MapItem { return xdm.NewMap([]xdm.MapEntry{{Key: k, Value: nil}}) },
		func(k xdm.AtomicValue) xdm.MapItem {
			b := xdm.NewMapBuilder(xdm.MergeUseFirst, 1)
			if err := b.Add(k, nil); err != nil {
				t.Fatal(err)
			}
			return b.Build()
		},
	} {
		key := big.NewInt(7)
		m := construct(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: key})
		key.SetInt64(9)
		if !m.Contains(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(7)}) || m.Contains(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(9)}) || m.Keys()[0].IntegerVal() != 7 {
			t.Fatal("map constructor retained mutable caller key")
		}
	}
}

func TestNestedValuesOwnMutableInputs(t *testing.T) {
	t.Parallel()

	key := big.NewInt(7)
	number := big.NewRat(1, 10)
	array := xdm.NewArray([]xdm.Sequence{xdm.SingleDecimal(number)})
	value := xdm.NewMap([]xdm.MapEntry{{
		Key:   xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: key},
		Value: xdm.ItemSlice{array},
	}})
	key.SetInt64(9)
	number.SetInt64(3)

	for attempt := range 2 {
		seq, ok := value.Get(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(7)})
		if !ok {
			t.Fatal("mutation changed the stored map key")
		}

		stored, ok := seq.Get(0).(xdm.ArrayItem)
		if !ok {
			t.Fatalf("stored value: %T", seq.Get(0))
		}

		member, err := stored.Get(1)
		if err != nil {
			t.Fatal(err)
		}

		atomic, ok := member.Get(0).(xdm.AtomicValue)
		if !ok || atomic.BigRat().Cmp(big.NewRat(1, 10)) != 0 {
			t.Fatalf("attempt %d: stored decimal changed: %v", attempt, member)
		}

		atomic.BigRat().SetInt64(42)
	}

	if _, ok := value.Get(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(9)}); ok {
		t.Fatal("mutated key became visible")
	}
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

func assertStringItems(t *testing.T, seq xdm.Sequence, want ...string) {
	t.Helper()
	var got []string
	for item := range xdm.SequenceItems(seq) {
		value, ok := item.(xdm.AtomicValue)
		if !ok {
			t.Fatalf("item type %T; want atomic string", item)
		}
		if value.TypeName != xdm.TypeString {
			t.Fatalf("atomic type %q; want xs:string", value.TypeName)
		}
		got = append(got, value.StringVal())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("items %q; want %q", got, want)
	}
}

func stringKey(s string) xdm.AtomicValue { return xdm.AtomicValue{TypeName: xdm.TypeString, Value: s} }

func requireXDMCode(t *testing.T, err error, code string) {
	t.Helper()
	var xe *xdm.Error
	if !errors.As(err, &xe) || xe.Code != code {
		t.Fatalf("error %v; want XDM %s", err, code)
	}
}

func requireArrayMember(t *testing.T, array xdm.ArrayItem, index int) xdm.Sequence {
	t.Helper()
	member, err := array.Get(index)
	if err != nil {
		t.Fatalf("array.Get(%d): %v", index, err)
	}
	return member
}

func requireMapValue(t *testing.T, valueMap xdm.MapItem, key xdm.AtomicValue) xdm.Sequence {
	t.Helper()
	value, found := valueMap.Get(key)
	if !found {
		t.Fatalf("map.Get(%v): key absent", key)
	}
	return value
}
