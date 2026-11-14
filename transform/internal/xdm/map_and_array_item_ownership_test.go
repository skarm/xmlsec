package xdm_test

import (
	"math/big"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

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
