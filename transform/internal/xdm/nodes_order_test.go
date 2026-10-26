package xdm_test

import (
	"cmp"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestNodeOrderCacheIndexesNamespacesBeforeAttributesAndDescendants(t *testing.T) {
	t.Parallel()

	d := parseNodeDocument(t, `<r xmlns:p="urn:p" a="1" b="2"><first><deep/></first><last/></r>`)
	r := d.DocumentElement()
	first, last := r.FirstChild(), r.LastChild()
	a, b := r.GetAttributeNodeNS("a", ""), r.GetAttributeNodeNS("b", "")
	ns := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), r)
	order := []xdm.Node{d, r, ns, a, b, first, first.FirstChild(), last}
	var cache xdm.DocOrderCache
	if cache.Position(r) != -1 || cache.Compare(r, last) != 0 {
		t.Fatal("unindexed nodes unexpectedly have known positions")
	}
	cache.BuildFrom(first)
	for i, n := range order {
		if cache.Position(n) < 0 || cache.Compare(n, n) != 0 {
			t.Fatal("indexed node lacks stable reflexive order", i)
		}
		for j := i + 1; j < len(order); j++ {
			if !cache.Less(n, order[j]) || cache.Compare(order[j], n) <= 0 {
				t.Fatalf("wrong indexed order %d,%d", i, j)
			}
		}
	}
	if !xdm.DocumentRegistered(&cache, r) || xdm.DocumentRoot(ns) != d {
		t.Fatal("descendant index did not register its actual tree root")
	}
	clone := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), r)
	if cache.Compare(ns, clone) != 0 || cache.Position(ns) != cache.Position(clone) {
		t.Fatal("equivalent namespace wrappers received different order")
	}
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			for range 50 {
				cache.BuildFrom(last)
				if cache.Compare(first, last) >= 0 || cache.Position(clone) < 0 {
					t.Error("concurrent cache lookup changed order")
				}
			}
		})
	}
	readers.Wait()
}

func TestNodeOrderSameOwnerAttributesHaveDistinctOrder(t *testing.T) {
	t.Parallel()

	for _, names := range [][]string{{"a", "b", "c"}, {"c", "a", "b"}, {"b", "c", "a"}} {
		d := xdm.NewDefaultDocument()
		r := newDraftElement(t, d, "r")
		requireNodeSuccess(t, d.AddChild(r))
		attributes := make([]xdm.Node, 0, len(names))
		for _, name := range names {
			requireNodeSuccess(t, r.SetAttribute(name, "value"))
			attributes = append(attributes, r.GetAttributeNodeNS(name, ""))
		}
		var cache xdm.DocOrderCache
		cache.BuildFrom(d)
		for i, a := range attributes {
			for j, b := range attributes {
				want := cmp.Compare(i, j)
				if got := xdm.CompareNodeOrder(a, b); got != want || got != cache.Compare(a, b) {
					t.Fatalf("attribute storage order %v: compare %s,%s=%d; want %d and cache agreement", names, a.Name(), b.Name(), got, want)
				}
			}
		}
	}
}

func TestNodeOrderAncestorAndSiblingComparisons(t *testing.T) {
	t.Parallel()

	d := parseNodeDocument(t, `<r xmlns:p="urn:p" a="1"><left><deep/></left><middle/><right><leaf/></right></r>`)
	r := d.DocumentElement()
	left := r.FirstChild()
	middle := left.NextSibling()
	right := r.LastChild()
	ns := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), r)
	a := r.GetAttributeNodeNS("a", "")
	for _, pair := range [][2]xdm.Node{{d, r}, {r, a}, {r, ns}, {ns, a}, {left, left.FirstChild()}, {left.FirstChild(), middle}, {middle, right.FirstChild()}, {left.FirstChild(), right.FirstChild()}, {a, right.FirstChild()}} {
		if xdm.CompareNodeOrder(pair[0], pair[1]) >= 0 || xdm.CompareNodeOrder(pair[1], pair[0]) <= 0 {
			t.Fatal("ancestor/sibling comparison reversed or equal", pair[0].Name(), pair[1].Name())
		}
	}
	if xdm.CompareNodeOrder(left, left) != 0 {
		t.Fatal("node did not compare equal to itself")
	}
}

func TestNodeOrderReservationResetAndDetachedRoots(t *testing.T) {
	t.Parallel()

	first := parseNodeDocument(t, `<first><a/><b/></first>`)
	second := parseNodeDocument(t, `<second/>`)
	a, b := first.DocumentElement().FirstChild(), first.DocumentElement().LastChild()
	var cache xdm.DocOrderCache
	cache.ReserveDocument(second.DocumentElement())
	cache.BuildFrom(a)
	if !xdm.DocumentRegistered(&cache, second) || cache.Compare(second.DocumentElement(), a) >= 0 {
		t.Fatal("lazy reservation lost cross-document order")
	}
	cache.ReserveDocument(second)
	if cache.Compare(a, second.DocumentElement()) <= 0 {
		t.Fatal("repeated reservation reordered a document")
	}
	cache.Reset()
	if xdm.DocumentRegistered(&cache, first) || xdm.DocumentRegistered(&cache, second) || cache.Position(a) != -1 {
		t.Fatal("reset retained registered trees or positions")
	}
	requireNodeSuccess(t, b.(xdm.MutableNode).AddSibling(a))
	cache.BuildFrom(first)
	if cache.Compare(b, a) >= 0 {
		t.Fatal("cache did not recompute after tree mutation")
	}
	detached := newDraftElement(t, first, "detached")
	child := newDraftElement(t, first, "child")
	requireNodeSuccess(t, detached.AddChild(child))
	if xdm.DocumentRoot(child) != detached {
		t.Fatal("detached subtree incorrectly rooted at its storage owner")
	}
	cache.BuildFrom(child)
	if cache.Compare(detached, child) >= 0 || !xdm.DocumentRegistered(&cache, child) {
		t.Fatal("detached root could not be indexed")
	}
	standalone := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), nil)
	if xdm.DocumentRoot(standalone) != standalone {
		t.Fatal("detached namespace acquired another root")
	}
	cache.BuildFrom(standalone)
	if cache.Position(standalone) < 0 {
		t.Fatal("detached namespace root was not indexed")
	}
	ctx := xdm.WithDocOrderCache(t.Context(), &cache)
	if xdm.DocOrderCacheFromContext(ctx) != &cache || xdm.DocOrderCacheFromContext(t.Context()) != nil || xdm.WithDocOrderCache(ctx, nil) != ctx {
		t.Fatal("context cache binding lost evaluation identity")
	}
}

func TestNodeOrderDeduplicationKeepsNamespaceIdentityAndDistinctRoots(t *testing.T) {
	t.Parallel()

	d := parseNodeDocument(t, `<r xmlns:p="urn:p" a="1"><first/><last/></r>`)
	r := d.DocumentElement()
	first, last := r.FirstChild(), r.LastChild()
	attribute := r.GetAttributeNodeNS("a", "")
	ns1 := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), r)
	ns2 := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), r)
	detached1 := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), nil)
	detached2 := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), nil)
	input := []xdm.Node{last, ns1, first, ns2, r, attribute, first, detached1, detached2, detached1}
	want := []xdm.Node{r, ns1, attribute, first, last, detached1, detached2}
	var cache xdm.DocOrderCache
	got, err := xdm.DeduplicateNodes(input, &cache, len(want))
	if err != nil || !slices.Equal(got, want) {
		t.Fatal("sorted deduplication changed identity/order", got, err)
	}
	if got, err := xdm.DeduplicateNodes(input, &cache, len(want)-1); got != nil || !errors.Is(err, xdm.ErrNodeSetLimit) {
		t.Fatal("deduplicated result exceeded limit", got, err)
	}
	preserved := []xdm.Node{last, ns1, first, r, attribute, detached1, detached2}
	got, err = xdm.DeduplicateNodesPreserveOrder(input, len(preserved))
	if err != nil || !slices.Equal(got, preserved) {
		t.Fatal("preserve-order deduplication sorted or merged distinct roots", got, err)
	}
	if got, err := xdm.DeduplicateNodesPreserveOrder(input, len(preserved)-1); got != nil || !errors.Is(err, xdm.ErrNodeSetLimit) {
		t.Fatal("preserve-order limit was ignored", got, err)
	}
	buffer := make([]xdm.Node, 3, 8)
	copy(buffer, []xdm.Node{r, first, last})
	got, err = xdm.DeduplicateNodes(buffer, &cache, 3)
	if err != nil || !slices.Equal(got, buffer) {
		t.Fatal("already sorted fast path changed result", got, err)
	}
}

func TestNodeOrderUnionAndStepResultFastPathsRespectLimits(t *testing.T) {
	t.Parallel()

	d := parseNodeDocument(t, `<r a="1" b="2"><left><x/><y/></left><right><z/></right></r>`)
	r := d.DocumentElement()
	left, right := r.FirstChild(), r.LastChild()
	x, y := left.FirstChild(), left.LastChild()
	z := right.FirstChild()
	a, b := r.GetAttributeNodeNS("a", ""), r.GetAttributeNodeNS("b", "")
	d.Freeze() // Subtests own their buffers/caches and only read the shared tree.
	for _, tc := range []struct {
		name  string
		input []xdm.Node
		split int
		want  []xdm.Node
	}{
		{"attribute child subsequence", []xdm.Node{a, b, left, right}, 2, []xdm.Node{a, b, left, right}},
		{"increasing runs", []xdm.Node{left, y, right, x, y, z}, 3, []xdm.Node{left, x, y, right, z}},
		{"unordered fallback", []xdm.Node{right, x, left, x, z, y}, 3, []xdm.Node{left, x, y, right, z}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var cache xdm.DocOrderCache
			got, err := xdm.UnionNodeSets(slices.Clone(tc.input), tc.split, &cache, len(tc.want))
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatal("union result changed", got, err)
			}
			if !xdm.DocumentRegistered(&cache, d) {
				t.Fatal("union fast path omitted document registration")
			}
			if got, err := xdm.UnionNodeSets(slices.Clone(tc.input), tc.split, &cache, len(tc.want)-1); got != nil || !errors.Is(err, xdm.ErrNodeSetLimit) {
				t.Fatal("union limit was ignored", got, err)
			}
		})
	}
	for _, tc := range []struct {
		name        string
		out, inputs []xdm.Node
		axis        xdm.AxisType
		want        []xdm.Node
	}{
		{"reverse single context", []xdm.Node{right, r, d}, []xdm.Node{z}, xdm.AxisAncestor, []xdm.Node{d, r, right}},
		{"parent duplicates", []xdm.Node{left, left, right}, []xdm.Node{x, y, z}, xdm.AxisParent, []xdm.Node{left, right}},
		{"same-depth children", []xdm.Node{x, y, z}, []xdm.Node{left, right}, xdm.AxisChild, []xdm.Node{x, y, z}},
		{"mixed-depth fallback", []xdm.Node{left, x, y, x}, []xdm.Node{left, x}, xdm.AxisDescendantOrSelf, []xdm.Node{left, x, y}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var cache xdm.DocOrderCache
			got, err := xdm.OrderStepResult(slices.Clone(tc.out), tc.inputs, tc.axis, &cache, len(tc.want))
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatal("step order/dedup changed", got, err)
			}
			if got, err := xdm.OrderStepResult(slices.Clone(tc.out), tc.inputs, tc.axis, &cache, len(tc.want)-1); got != nil || !errors.Is(err, xdm.ErrNodeSetLimit) {
				t.Fatal("step result exceeded limit", got, err)
			}
		})
	}
	var cache xdm.DocOrderCache
	got, err := xdm.MergeNodeSets([]xdm.Node{z, x, x}, []xdm.Node{right, y, x}, &cache, 4)
	if err != nil || !slices.Equal(got, []xdm.Node{x, y, right, z}) {
		t.Fatal("general merge lost ordering or overlap elimination", got, err)
	}
	if got, err := xdm.MergeNodeSets([]xdm.Node{x, y}, []xdm.Node{right, z}, &cache, 3); got != nil || !errors.Is(err, xdm.ErrNodeSetLimit) {
		t.Fatal("general merge ignored limit", got, err)
	}
}
