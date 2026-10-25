package xdm_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestRangeSequenceBoundaries(t *testing.T) {
	for _, bounds := range [][2]int64{{-2, 2}, {math.MinInt64, math.MinInt64 + 2}, {math.MaxInt64 - 2, math.MaxInt64}} {
		seq := xdm.NewRangeSequence(bounds[0], bounds[1])
		items := xdm.Materialize(seq)

		if seq.Len() != int(bounds[1]-bounds[0])+1 || len(items) != seq.Len() {
			t.Fatalf("range %v: length %d, materialized %d", bounds, seq.Len(), len(items))
		}

		index := 0

		for item := range xdm.SequenceItems(seq) {
			for _, value := range []xdm.Item{item, seq.Get(index), items[index]} {
				assertRangeInteger(t, value, bounds[0]+int64(index))
			}

			index++
		}

		if index != seq.Len() {
			t.Fatalf("range %v: iterated %d of %d items", bounds, index, seq.Len())
		}
	}

	seq := xdm.NewRangeSequence(math.MinInt64, math.MaxInt64)
	if seq.Len() != math.MaxInt {
		t.Fatalf("overflowing range length: %d", seq.Len())
	}

	// A huge range must permit bounded consumption without materializing it.
	for item := range seq.Items() {
		atomic, ok := item.(xdm.AtomicValue)
		if !ok || atomic.BigInt().Int64() != math.MinInt64 {
			t.Fatalf("first range item: %v", item)
		}

		break
	}
}

func TestEmptySequences(t *testing.T) {
	for _, seq := range []xdm.Sequence{nil, xdm.ItemSlice(nil), xdm.NewRangeSequence(2, 1)} {
		if xdm.SequenceLen(seq) != 0 || xdm.Materialize(seq) != nil {
			t.Fatalf("empty sequence lost nil representation: %v", seq)
		}

		for item := range xdm.SequenceItems(seq) {
			t.Fatalf("empty sequence yielded %v", item)
		}
	}

	if got := xdm.Materialize(xdm.ItemSlice{}); got == nil || len(got) != 0 {
		t.Fatalf("non-nil empty slice changed: %v", got)
	}
}

func TestCloneRangeKeepsLazyStorage(t *testing.T) {
	source := xdm.NewRangeSequence(-1000, 100000)

	var cloned xdm.Sequence

	allocated := testing.AllocsPerRun(10, func() { cloned = xdm.CloneSequence(source) })

	if cloned.Len() != source.Len() {
		t.Fatal(cloned.Len())
	}

	assertRangeInteger(t, cloned.Get(0), -1000)
	assertRangeInteger(t, cloned.Get(cloned.Len()-1), 100000)

	if allocated != 0 {
		t.Fatalf("cloning range materialized items: %g allocations", allocated)
	}
}

func assertRangeInteger(t *testing.T, item xdm.Item, want int64) {
	t.Helper()

	atomic, ok := item.(xdm.AtomicValue)
	if !ok || atomic.TypeName != xdm.TypeInteger || atomic.BaseType != "" {
		t.Fatalf("range item is not a built-in integer: %#v", item)
	}

	if got, ok := atomic.Int64Val(); !ok || got != want {
		t.Fatalf("range item: %v, want %d", item, want)
	}
}

func BenchmarkRangeSequenceConsumption(b *testing.B) {
	for _, size := range []int{16, 8192} {
		seq := xdm.NewRangeSequence(1, int64(size))
		b.Run(strconv.Itoa(size)+"/Iterate", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var total int64
				for item := range xdm.SequenceItems(seq) {
					value, ok := item.(xdm.AtomicValue)
					if !ok {
						b.Fatal(item)
					}
					n, ok := value.Int64Val()
					if !ok {
						b.Fatal(value)
					}
					total += n
				}
				if total != int64(size)*(int64(size)+1)/2 {
					b.Fatal(total)
				}
			}
		})
		b.Run(strconv.Itoa(size)+"/Materialize", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if items := xdm.Materialize(seq); len(items) != size {
					b.Fatal(len(items))
				}
			}
		})
	}
}
