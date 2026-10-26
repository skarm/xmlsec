package xdm_test

import (
	"iter"
	"math"
	"reflect"
	"strconv"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestRangeSequenceBoundaries(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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
	// AllocsPerRun changes GOMAXPROCS and forbids concurrent parallel tests.

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

// iteratorSequence exercises the generic Sequence path without relying on ItemSlice.
type iteratorSequence struct {
	items   xdm.ItemSlice
	yielded *int
}

func (s iteratorSequence) Len() int                { return len(s.items) }
func (s iteratorSequence) Get(i int) xdm.Item      { return s.items[i] }
func (s iteratorSequence) Materialize() []xdm.Item { return s.items.Materialize() }
func (s iteratorSequence) Items() iter.Seq[xdm.Item] {
	return func(yield func(xdm.Item) bool) {
		for _, item := range s.items {
			if s.yielded != nil {
				*s.yielded++
			}
			if !yield(item) {
				return
			}
		}
	}
}

func TestSequenceNodeConversionRejectsMixedAndFragments(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte("<r><a/><b/></r>"))
	if err != nil {
		t.Fatal(err)
	}
	root := doc.DocumentElement()
	a, b := root.FirstChild(), root.LastChild()
	for _, generic := range []bool{false, true} {
		makeSequence := func(items xdm.ItemSlice) xdm.Sequence {
			if generic {
				return iteratorSequence{items: items}
			}
			return items
		}
		items := xdm.ItemSlice{xdm.NodeItem{Node: a}, xdm.NodeItem{Node: b}}
		nodes, ok := xdm.NodesFrom(makeSequence(items))
		if !ok || !reflect.DeepEqual(nodes, []xdm.Node{a, b}) {
			t.Fatalf("node conversion generic%v: %v,%v", generic, nodes, ok)
		}
		for _, bad := range []xdm.Item{stringKey("atomic"), xdm.NodeItem{Node: b, ResultTreeFragment: true}} {
			sequence := makeSequence(xdm.ItemSlice{xdm.NodeItem{Node: a}, bad, xdm.NodeItem{Node: b}})
			prefix, ok := xdm.AppendSequenceNodes([]xdm.Node{root}, sequence)
			if ok || !reflect.DeepEqual(prefix, []xdm.Node{root, a}) {
				t.Fatalf("mixed conversion did not retain valid prefix: %v,%v", prefix, ok)
			}
			nodes, ok = xdm.NodesFrom(sequence)
			if ok || nodes != nil {
				t.Fatal("NodesFrom leaked a partial mixed node-set")
			}
		}
	}
	for _, empty := range []xdm.Sequence{nil, xdm.ItemSlice{}} {
		nodes, ok := xdm.AppendSequenceNodes([]xdm.Node{root}, empty)
		if !ok || !reflect.DeepEqual(nodes, []xdm.Node{root}) {
			t.Fatal("empty conversion lost destination")
		}
		nodes, ok = xdm.NodesFrom(empty)
		if !ok || nodes != nil {
			t.Fatal("empty conversion changed nil representation")
		}
	}
}

func TestSequenceIteratorsStopAndCloneGenericItems(t *testing.T) {
	t.Parallel()

	yielded := 0
	seq := iteratorSequence{items: xdm.ItemSlice{stringKey("first"), stringKey("second"), stringKey("third")}, yielded: &yielded}
	for item := range xdm.SequenceItems(seq) {
		if item.(xdm.AtomicValue).StringVal() != "first" {
			t.Fatal("iterator order")
		}
		break
	}
	if yielded != 1 {
		t.Fatalf("generic iterator ignored early stop: %d", yielded)
	}
	seen := 0
	for range seq.items.Items() {
		seen++
		break
	}
	if seen != 1 {
		t.Fatal("slice iterator ignored early stop")
	}
	assertStringItems(t, xdm.CloneSequence(seq), "first", "second", "third")
	if cloned := xdm.CloneSequence(iteratorSequence{}); cloned == nil || cloned.Len() != 0 {
		t.Fatal("generic empty clone must preserve non-nil empty sequence")
	}
	members := []xdm.Sequence{nil, xdm.SingleString("original")}
	cloned := xdm.CloneSequences(members)
	members[1].(xdm.ItemSlice)[0] = stringKey("changed")
	members[0] = xdm.SingleString("changed")
	assertStringItems(t, cloned[0])
	assertStringItems(t, cloned[1], "original")
}
