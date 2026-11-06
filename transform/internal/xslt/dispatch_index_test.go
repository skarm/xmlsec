package xslt //nolint:testpackage // Exercises private candidate ordering and conservative pattern indexing.

import (
	"context"
	"errors"
	"math"
	"math/big"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func TestIndexCursorMergesAndDeduplicatesPositions(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		lists [3][]int32
		want  []int32
	}{
		{"empty", [3][]int32{}, nil},
		{"one list", [3][]int32{{0, 2, 7}}, []int32{0, 2, 7}},
		{"interleaved and overlapping", [3][]int32{{0, 2, 8}, {1, 2, 5}, {0, 5, 9}}, []int32{0, 1, 2, 5, 8, 9}},
		{"duplicates in every list", [3][]int32{{1, 1, 2, 2}, {1, 2, 2}, {2, 3, 3}}, []int32{1, 2, 3}},
		{"uneven exhaustion", [3][]int32{{3}, {0, 1, 2, 4}}, []int32{0, 1, 2, 3, 4}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cursor := indexCursor{lists: test.lists}
			got := make([]int32, 0, len(test.want))
			for range len(test.want) {
				position, ok := cursor.next()
				if !ok {
					t.Fatal("cursor exhausted before all candidates", got)
				}
				got = append(got, position)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("candidate order = %v; want %v", got, test.want)
			}
			for range 2 {
				if _, ok := cursor.next(); ok {
					t.Fatal("exhausted cursor returned another candidate")
				}
			}
		})
	}
}

func TestTemplateIndexThresholdAndDuplicateBuckets(t *testing.T) {
	t.Parallel()
	templates := make([]*template, templateIndexThreshold)
	for i := range templates {
		templates[i] = &template{}
	}
	if buildTemplateIndex(templates[:templateIndexThreshold-1]) != nil {
		t.Fatal("small template list unexpectedly indexed")
	}
	idx := buildTemplateIndex(templates)
	if idx == nil || len(idx.unindexed) != templateIndexThreshold {
		t.Fatal("threshold list did not retain all unindexable templates")
	}
	got := make([]int32, 0, len(templates))
	for i := range templates {
		got = append(got, int32(i))
	}
	if !slices.Equal(idx.unindexed, got) {
		t.Fatal("template precedence changed", idx.unindexed, got)
	}
	idx = &templateIndex{byName: make(map[nameKey][]int32)}
	entries := []sigEntry{{kind: kindElement, named: true, uri: "urn:p", local: "item"}, {kind: kindElement, named: true, uri: "urn:p", local: "item"}, {kind: kindElement}, {kind: kindElement}, {kind: kindAttribute}}
	addTemplateToBuckets(idx, 3, entries)
	addTemplateToBuckets(idx, 7, entries)
	for _, bucket := range [][]int32{idx.byName[nameKey{kind: kindElement, uri: "urn:p", local: "item"}], idx.byKind[kindElement], idx.byKind[kindAttribute]} {
		if !slices.Equal(bucket, []int32{3, 7}) {
			t.Fatal("union alternatives duplicated a bucket or changed precedence", bucket)
		}
	}
}

func TestTemplateIndexCandidatesRespectKindNamespaceAndFallback(t *testing.T) {
	t.Parallel()
	child := func(test xdm.NodeTest) xpath.LocationPath {
		return xpath.LocationPath{Steps: []xpath.Step{{Axis: xpath.AxisChild, NodeTest: test}}}
	}
	item := child(xdm.NameTest{Local: "item"})
	bindings := map[string]string{"p": "urn:item"}
	rule := func(expression xpath.Expr) *pattern {
		return &pattern{Alternatives: []*patternAlt{{expr: expression}}, nsBindings: bindings, xpathDefaultNS: "urn:item"}
	}
	patterns := []*pattern{
		nil,
		rule(item),
		rule(child(xdm.ElementTest{})),
		rule(child(xdm.NameTest{Prefix: "p", Local: "item"})),
		rule(xpath.LocationPath{Steps: []xpath.Step{{Axis: xpath.AxisAttribute, NodeTest: xdm.NameTest{Local: "item"}}}}),
		rule(child(xdm.TypeTest{Kind: xdm.NodeKindText})),
		rule(child(xdm.TypeTest{Kind: xdm.NodeKindComment})),
		rule(child(xdm.PITest{Target: "target", HasTarget: true})),
		rule(xpath.RootExpr{}),
		rule(xpath.LocationPath{Steps: []xpath.Step{{Axis: xpath.AxisNamespace, NodeTest: xdm.NamespaceNodeTest{}}}}),
		rule(xpath.ContextItemExpr{}),
		rule(xpath.UnionExpr{Left: item, Right: child(xdm.ElementTest{})}),
		rule(xpath.UnionExpr{Left: item, Right: xpath.ContextItemExpr{}}),
		rule(item),
		rule(xpath.PathExpr{Filter: xpath.ContextItemExpr{}, Path: &item}),
		rule(xpath.PathStepExpr{Left: xpath.ContextItemExpr{}, Right: item}),
	}
	patterns[13].Alternatives[0].neverMatches = true
	templates := make([]*template, len(patterns))
	for i, p := range patterns {
		templates[i] = &template{Match: p}
	}
	idx := buildTemplateIndex(templates)
	if idx == nil {
		t.Fatal("template fixture must exercise indexed dispatch")
	}
	doc := xdm.NewDefaultDocument()
	element, err := doc.CreateElementNS("item", xdm.NewNamespace("p", "urn:item"))
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := doc.CreateElementNS("item", xdm.NewNamespace("q", "urn:other"))
	if err != nil {
		t.Fatal(err)
	}
	attribute, err := doc.CreateAttribute("item", "value", nil)
	if err != nil {
		t.Fatal(err)
	}
	qualified, err := doc.CreateAttribute("item", "value", xdm.NewNamespace("p", "urn:item"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		node xdm.Node
		want []int32
	}{
		{"matching element namespace", element, []int32{0, 1, 2, 3, 10, 11, 12, 14, 15}},
		{"foreign element namespace", foreign, []int32{0, 2, 10, 11, 12, 14}},
		{"unqualified attribute ignores default element namespace", attribute, []int32{0, 4, 10, 12, 14}},
		{"qualified attribute", qualified, []int32{0, 10, 12, 14}},
		{"text", doc.CreateText("text"), []int32{0, 5, 10, 12, 14}},
		{"CDATA shares text candidates", doc.CreateCDATASection("text"), []int32{0, 5, 10, 12, 14}},
		{"comment", doc.CreateComment("comment"), []int32{0, 6, 10, 12, 14}},
		{"PI target is a necessary kind-only filter", doc.CreatePI("target", "value"), []int32{0, 7, 10, 12, 14}},
		{"document", doc, []int32{0, 8, 10, 12, 14}},
		{"namespace", xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:item"), element), []int32{0, 9, 10, 12, 14}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cursor := candidates(idx, test.node)
			var got []int32
			for {
				position, ok := cursor.next()
				if !ok {
					break
				}
				got = append(got, position)
				if len(got) > len(templates) {
					t.Fatal("candidate cursor did not make progress")
				}
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("candidates = %v; want %v", got, test.want)
			}
		})
	}
}

func TestPatternIndexRootTerminalAndConservativeFallback(t *testing.T) {
	t.Parallel()
	terminal := xpath.LocationPath{Steps: []xpath.Step{
		{Axis: xpath.AxisChild, NodeTest: xdm.NameTest{Local: "parent"}},
		{Axis: xpath.AxisChild, NodeTest: xdm.NameTest{URI: "urn:explicit", Local: "item"}},
	}}
	for _, test := range []struct {
		name      string
		expr      xpath.Expr
		want      []sigEntry
		unindexed bool
	}{
		{"absolute empty path is the document", xpath.LocationPath{Absolute: true}, []sigEntry{{kind: kindDocument}}, false},
		{"relative empty path matches nothing", xpath.LocationPath{}, nil, false},
		{"pointer path uses its terminal step and explicit namespace", &terminal, []sigEntry{{kind: kindElement, named: true, uri: "urn:explicit", local: "item"}}, false},
		{"unindexable left union branch cannot be discarded", xpath.UnionExpr{Left: xpath.ContextItemExpr{}, Right: terminal}, nil, true},
		{"unindexable right union branch cannot be discarded", xpath.UnionExpr{Left: terminal, Right: xpath.ContextItemExpr{}}, nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			p := &pattern{xpathDefaultNS: "urn:default", Alternatives: []*patternAlt{{expr: test.expr}}}
			got := patternSignature(p)
			if got.unindexed != test.unindexed || !got.unindexed && !slices.Equal(got.entries, test.want) {
				t.Fatalf("pattern signature = %+v; want %+v, unindexed=%v", got, test.want, test.unindexed)
			}
		})
	}
}

func TestPatternIndexAxisAndKindGuards(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		step xpath.Step
		want []sigEntry
	}{
		{"local wildcard stays kind-only", xpath.Step{Axis: xpath.AxisChild, NodeTest: xdm.NameTest{Local: "*"}}, []sigEntry{{kind: kindElement}}},
		{"namespace wildcard stays kind-only", xpath.Step{Axis: xpath.AxisChild, NodeTest: xdm.NameTest{Prefix: "*", Local: "item"}}, []sigEntry{{kind: kindElement}}},
		{"attribute axis cannot select an element", xpath.Step{Axis: xpath.AxisAttribute, NodeTest: xdm.ElementTest{}}, nil},
		{"schema attribute stays in the attribute bucket", xpath.Step{Axis: xpath.AxisAttribute, NodeTest: xdm.SchemaAttributeTest{Name: "item"}}, []sigEntry{{kind: kindAttribute}}},
		{"schema element stays in the element bucket", xpath.Step{Axis: xpath.AxisChild, NodeTest: xdm.SchemaElementTest{Name: "item"}}, []sigEntry{{kind: kindElement}}},
		{"self document test retains documents", xpath.Step{Axis: xpath.AxisSelf, NodeTest: xdm.DocumentTest{}}, []sigEntry{{kind: kindDocument}}},
		{"self node test retains documents and side nodes", xpath.Step{Axis: xpath.AxisSelf, NodeTest: xdm.TypeTest{Kind: xdm.NodeKindNode}}, []sigEntry{{kind: kindElement}, {kind: kindAttribute}, {kind: kindText}, {kind: kindComment}, {kind: kindPI}, {kind: kindDocument}, {kind: kindNamespace}}},
		{"descendant or self retains side nodes", xpath.Step{Axis: xpath.AxisDescendantOrSelf, NodeTest: xdm.TypeTest{Kind: xdm.NodeKindNode}}, []sigEntry{{kind: kindElement}, {kind: kindAttribute}, {kind: kindText}, {kind: kindComment}, {kind: kindPI}, {kind: kindNamespace}}},
		{"child node test excludes documents attributes and namespaces", xpath.Step{Axis: xpath.AxisChild, NodeTest: xdm.TypeTest{Kind: xdm.NodeKindNode}}, []sigEntry{{kind: kindElement}, {kind: kindText}, {kind: kindComment}, {kind: kindPI}}},
		{"PI kind test", xpath.Step{Axis: xpath.AxisChild, NodeTest: xdm.TypeTest{Kind: xdm.NodeKindProcessingInstruction}}, []sigEntry{{kind: kindPI}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := stepSignature(&pattern{}, test.step)
			if got.unindexed || !slices.Equal(got.entries, test.want) {
				t.Fatalf("axis/kind signature = %+v; want %+v", got, test.want)
			}
		})
	}
}

func TestPatternIndexConsidersEveryAlternative(t *testing.T) {
	t.Parallel()
	item := xpath.LocationPath{Steps: []xpath.Step{{Axis: xpath.AxisChild, NodeTest: xdm.NameTest{Local: "item"}}}}
	for _, test := range []struct {
		name         string
		alternatives []*patternAlt
		want         []sigEntry
		unindexed    bool
	}{
		{"later indexed alternatives contribute", []*patternAlt{{expr: item}, {expr: xpath.RootExpr{}}}, []sigEntry{{kind: kindElement, named: true, local: "item"}, {kind: kindDocument}}, false},
		{"later unindexable alternative keeps fallback", []*patternAlt{{expr: item}, {expr: xpath.ContextItemExpr{}}}, nil, true},
		{"never-matching alternative cannot poison later matches", []*patternAlt{{expr: xpath.ContextItemExpr{}, neverMatches: true}, {expr: item}}, []sigEntry{{kind: kindElement, named: true, local: "item"}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := patternSignature(&pattern{Alternatives: test.alternatives})
			if got.unindexed != test.unindexed || !got.unindexed && !slices.Equal(got.entries, test.want) {
				t.Fatalf("alternative signature = %+v; want %+v, unindexed=%v", got, test.want, test.unindexed)
			}
		})
	}
}

func TestIntegerIndexClassifierPreservesExactDomain(t *testing.T) {
	for _, test := range []struct {
		name  string
		value xdm.AtomicValue
		want  int64
		ok    bool
	}{
		{"zero", xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(0)}, 0, true},
		{"min", xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(math.MinInt64)}, math.MinInt64, true},
		{"max", xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(math.MaxInt64)}, math.MaxInt64, true},
		{"fitting big integer", xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: big.NewInt(23)}, 23, true},
		{"builtin subtype", xdm.AtomicValue{TypeName: xdm.TypeUnsignedByte, Value: int64(23)}, 23, true},
		{"schema base", xdm.AtomicValue{TypeName: "Q{urn:test}integer", BaseType: xdm.TypeLong, Value: int64(23)}, 23, true},
		{"decimal", xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: big.NewRat(23, 1)}, 0, false},
		{"double", xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(23)}, 0, false},
		{"float", xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(23)}, 0, false},
		{"oversized integer", xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: new(big.Int).Lsh(big.NewInt(1), 80)}, 0, false},
		{"string", xdm.AtomicValue{TypeName: xdm.TypeString, Value: "23"}, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := indexInt64(test.value)
			if ok != test.ok || got != test.want {
				t.Fatal(got, ok, test.want, test.ok)
			}
		})
	}
}

func TestIntegerKeyIndexIsLazyOrderedAndQuerySpecific(t *testing.T) {
	ctx := t.Context()
	entries := integerIndexEntries(128)
	for i := range entries {
		entries[i].key.Value = int64(i % 64)
	}
	var table keyTable
	query := xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(5)}
	for range 2 {
		positions, indexed, err := table.integerCandidates(ctx, query, entries)
		if err != nil || indexed || positions != nil || table.integerIndex != nil {
			t.Fatal("eager index", positions, indexed, err)
		}
	}
	positions, indexed, err := table.integerCandidates(ctx, query, entries)
	if err != nil || !indexed || !slices.Equal(positions, []int{5, 69}) {
		t.Fatal("lost candidate order or multiplicity", positions, indexed, err)
	}
	for _, mixed := range []xdm.AtomicValue{
		{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(5)},
		{TypeName: xdm.TypeDecimal, Value: big.NewRat(5, 1)},
		{TypeName: xdm.TypeInteger, Value: new(big.Int).Lsh(big.NewInt(1), 80)},
	} {
		positions, indexed, err := table.integerCandidates(ctx, mixed, entries)
		if err != nil || indexed || positions != nil || table.integerIndex == nil {
			t.Fatal("mixed query must use broad bucket", positions, indexed, err)
		}
	}
	positions, indexed, err = table.integerCandidates(ctx, query, entries)
	if err != nil || !indexed || !slices.Equal(positions, []int{5, 69}) {
		t.Fatal("integer index changed after fallback queries", positions, indexed, err)
	}
}

func TestIntegerKeyIndexRejectsMixedEntriesAndOversizedCache(t *testing.T) {
	for _, test := range []struct {
		name    string
		entries []keyEntry
		ctx     context.Context
	}{
		{"mixed last entry", integerIndexEntries(64), t.Context()},
		{"collection bound", integerIndexEntries(64), xpath.WithBudget(t.Context(), 1000, 32, 10000, 128)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "mixed last entry" {
				test.entries[len(test.entries)-1].key = xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(1)}
			}
			table := keyTable{integerLookups: 2}
			query := xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(1)}
			for range 2 {
				positions, indexed, err := table.integerCandidates(test.ctx, query, test.entries)
				if err != nil || indexed || positions != nil || table.integerIndex != nil || !table.integerDisabled {
					t.Fatal("unsafe or repeated partial index", positions, indexed, err)
				}
			}
		})
	}
	for _, size := range []int{1, 63} {
		var table keyTable
		for range 4 {
			_, indexed, err := table.integerCandidates(t.Context(), xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(1)}, integerIndexEntries(size))
			if indexed || err != nil || table.integerIndex != nil {
				t.Fatal("small table built auxiliary index", size, indexed, err)
			}
		}
	}
}

func TestIntegerKeyIndexBuildFailureDoesNotPublish(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, test := range []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"work during build", xpath.WithBudget(t.Context(), 3, 1000, 10000, 128), xpath.ErrBudget},
		{"canceled", canceled, context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			table := keyTable{integerLookups: 2}
			positions, indexed, err := table.integerCandidates(test.ctx, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(1)}, integerIndexEntries(64))
			if !errors.Is(err, test.want) || indexed || positions != nil || table.integerIndex != nil {
				t.Fatal("partial index escaped failure", positions, indexed, err)
			}
		})
	}
}

func TestIntegerGroupingDisablesPrefixBeforeCardinalityExpansion(t *testing.T) {
	for _, keys := range []xdm.Sequence{nil, xdm.ItemSlice{integerIndexAtomic(1), integerIndexAtomic(1), integerIndexAtomic(3)}} {
		ctx := t.Context()
		var execution execContext
		groups := groupByAccumulator{
			byKey: make(map[string][]*groupByEntry), limit: 100, int64Prefix: true,
			equal: func(a, b xdm.Sequence) (bool, error) { return execution.groupingKeysEqual(ctx, a, b, nil) },
		}
		if err := groups.addKeys(ctx, integerIndexAtomic(1), xdm.ItemSlice{integerIndexAtomic(1)}); err != nil {
			t.Fatal(err)
		}
		if err := groups.addKeys(ctx, integerIndexAtomic(2), keys); err != nil {
			t.Fatal(err)
		}
		if groups.int64Prefix || groups.byInt64 != nil {
			t.Fatal("non-singleton key retained pure-prefix map")
		}
		if xdm.SequenceLen(keys) > 0 && (len(groups.order) != 2 || len(groups.order[0].items) != 2 || len(groups.order[1].items) != 1) {
			t.Fatal("multiple keys duplicated membership", groups.order)
		}
	}
}

func integerIndexEntries(size int) []keyEntry {
	entries := make([]keyEntry, size)
	for i := range entries {
		entries[i].key = integerIndexAtomic(int64(i))
	}
	return entries
}

func integerIndexAtomic(value int64) xdm.AtomicValue {
	return xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: value}
}
