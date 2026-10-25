package xpath //nolint:testpackage // Tests private evaluator budgets, caches, and runtime semantics.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestCollatorPoolBoundsIdleAndDropsLargeWork(t *testing.T) {
	pool := newCollatorPool(language.Und, nil)
	idleCount := func() int {
		count := 0

		for i := range pool.idle {
			if pool.idle[i].Load() != nil {
				count++
			}
		}

		return count
	}

	borrowed := make([]*collate.Collator, maxIdleCollators*8)
	for i := range borrowed {
		borrowed[i] = pool.get()
		if borrowed[i].CompareString("a", "b") >= 0 {
			t.Fatal("comparison changed")
		}
	}

	for _, c := range borrowed {
		pool.put(c, 1)
	}

	if idleCount() != maxIdleCollators {
		t.Fatal("idle collators not bounded", idleCount())
	}

	for range maxIdleCollators {
		c := pool.get()

		large := strings.Repeat("x", maxPooledCollationInput+1)
		if c.CompareString(large, large) != 0 {
			t.Fatal("large comparison changed")
		}

		pool.put(c, len(large))
	}

	if idleCount() != 0 {
		t.Fatal("large collator buffers returned to pool")
	}
}

func TestProbePoolReleasesAllScratch(t *testing.T) {
	var owner evaluationRuntime

	probe := owner.borrowProbe()
	doc := xdm.NewDefaultDocument()
	probe.ec = &evalContext{node: doc}
	probe.start = doc
	probe.contexts = make([]xdm.Node, 1, maxPooledProbeBuffer)
	backing := probe.contexts[:cap(probe.contexts)]
	backing[len(backing)-1] = doc
	probe.buf = make([]xdm.Node, 1, maxPooledProbeBuffer+1)
	probe.walk = make([]xdm.Node, 1, maxPooledProbeBuffer+1)
	probe.sizes.nested = []xdm.Node{doc}
	probe.sizes.sizes = make([]int, 1, maxPooledProbeBuffer+1)
	probe.sizes.pending = make([]pendingSubtree, 1, maxPooledProbeBuffer+1)
	probe.release(owner.probes)

	cleaned := owner.borrowProbe()
	if cleaned != probe || cleaned.ec != nil || cleaned.start != nil || cleaned.sizes.nested != nil {
		t.Fatal("probe retained invocation references")
	}

	if cleaned.buf != nil || cleaned.walk != nil || cleaned.sizes.sizes != nil || cleaned.sizes.pending != nil {
		t.Fatal("probe retained oversized numeric or node buffers")
	}

	for _, node := range backing {
		if node != nil {
			t.Fatal("unused probe capacity retained nodes")
		}
	}

	borrowed := make([]*pathProbe, maxIdlePathProbes*8)
	for i := range borrowed {
		borrowed[i] = owner.borrowProbe()
	}

	for _, p := range borrowed {
		p.release(owner.probes)
	}

	if len(owner.probes) != maxIdlePathProbes {
		t.Fatal("idle probes not bounded", len(owner.probes))
	}
}

func TestRegexCacheBoundsRetainedBytes(t *testing.T) {
	cache := newRegexLRUCache(xpathRegexCacheCapacity)

	runtime.GC()
	runtime.GC()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	for batch := range 2 {
		for i := range 128 {
			source := fmt.Sprintf("%d/%d/", batch, i) + strings.Repeat("x", (64<<10)-32)

			compiled, err := compileXPathRegexUncached(source, "q")
			if err != nil {
				t.Fatal(err)
			}

			cache.LoadOrStore(xpathRegexCacheKey{source, "q"}, compiled)
		}

		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&after)
		retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
		t.Logf("batch %d: %d retained heap bytes", batch, retained)

		if retained > 12<<20 {
			t.Fatalf("regex cache retained oversized working set: %d", retained)
		}

		if cache.bytes > xpathRegexCacheBytes || cache.ll.Len() > xpathRegexCacheCapacity {
			t.Fatal("regex cache admission limit exceeded")
		}
	}

	runtime.KeepAlive(cache)
}

func TestRegexCacheEvictionAndCancellation(t *testing.T) {
	cache := newRegexLRUCache(2)

	compiled, err := compileXPathRegexUncached("a", "")
	if err != nil {
		t.Fatal(err)
	}

	first, second, third := xpathRegexCacheKey{pattern: "a"}, xpathRegexCacheKey{pattern: "b"}, xpathRegexCacheKey{pattern: "c"}
	cache.LoadOrStore(first, compiled)
	cache.LoadOrStore(second, compiled)
	cache.Load(first)
	cache.LoadOrStore(third, compiled)

	if _, ok := cache.Load(second); ok {
		t.Fatal("least recently used pattern not evicted")
	}

	if _, ok := cache.Load(first); !ok {
		t.Fatal("hot pattern evicted")
	}

	var owner evaluationRuntime

	ctx, cancel := context.WithCancel(withFnContext(t.Context(), &evalContext{runtime: &owner}))
	cancel()

	if _, err := compileXPathRegex(ctx, "a", ""); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled compilation accepted", err)
	}

	if owner.regexes != nil {
		t.Fatal("canceled compilation populated a cache")
	}

	late := &budgetCancelContext{Context: t.Context(), remaining: 2}
	if _, err := compileXPathRegex(withFnContext(late, &evalContext{runtime: &owner}), "new", ""); !errors.Is(err, context.Canceled) {
		t.Fatal("compilation ignored late cancellation", err)
	}

	if owner.regexCache().ll.Len() != 0 {
		t.Fatal("late cancellation admitted a compiled pattern")
	}
}

func TestRegexCacheConcurrentWeightAndOversizedAdmission(t *testing.T) {
	cache := newRegexLRUCache(128)

	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := range 32 {
				source := fmt.Sprintf("%d/%d/", worker, i) + strings.Repeat("x", 32<<10)

				compiled, err := compileXPathRegexUncached(source, "q")
				if err != nil {
					t.Error(err)
					return
				}

				cache.LoadOrStore(xpathRegexCacheKey{source, "q"}, compiled)
			}
		})
	}

	wg.Wait()

	weight := 0

	for entry := cache.ll.Front(); entry != nil; entry = entry.Next() {
		stored, ok := entry.Value.(*regexLRUEntry)
		if !ok {
			t.Fatal("invalid cache entry")
		}

		weight += stored.bytes
	}

	if weight != cache.bytes || weight > xpathRegexCacheBytes || len(cache.items) > cache.cap {
		t.Fatal("concurrent cache budget mismatch", weight, cache.bytes, len(cache.items))
	}

	large, err := compileXPathRegexUncached(strings.Repeat(`\p{L}`, 4096), "")
	if err != nil {
		t.Fatal(err)
	}

	if cost := large.program.CacheCost(xpathRegexCacheBytes + 1); cost <= xpathRegexCacheBytes {
		t.Fatal("fixture did not exceed storage weight", cost)
	}

	before := cache.ll.Len()
	key := xpathRegexCacheKey{pattern: "oversized"}

	actual, loaded := cache.LoadOrStore(key, large)
	if actual != large || loaded || cache.ll.Len() != before || cache.bytes != weight {
		t.Fatal("oversized program disturbed hot cache entries")
	}

	if _, ok := cache.Load(key); ok {
		t.Fatal("oversized program admitted")
	}
}

func TestCollationCacheBoundsDynamicURIs(t *testing.T) {
	var runtime evaluationRuntime

	const prefix = "http://www.w3.org/2013/collation/UCA?lang=en;fallback=yes;unused="
	for i := range collationCacheCapacity * 3 {
		coll, err := runtime.resolveCollation(fmt.Sprintf("%s%d", prefix, i), "")
		if err != nil || coll.compare("a", "b") >= 0 {
			t.Fatalf("comparison %d: %v", i, err)
		}
	}

	count := 0

	runtime.collations.Range(func(_, _ any) bool { count++; return true })

	if count != collationCacheCapacity {
		t.Fatalf("retained %d collations", count)
	}

	first := prefix + "0"
	if _, ok := runtime.collations.Load([2]string{first, ""}); ok {
		t.Fatal("oldest URI was not evicted")
	}

	if coll, err := runtime.resolveCollation(first, ""); err != nil || coll.compare("b", "a") <= 0 {
		t.Fatalf("evicted URI: %v", err)
	}

	oversized := prefix + strings.Repeat("x", collationCacheKeyBytes)
	if coll, err := runtime.resolveCollation(oversized, ""); err != nil || coll.compare("a", "b") >= 0 {
		t.Fatalf("uncached URI: %v", err)
	}

	if _, ok := runtime.collations.Load([2]string{oversized, ""}); ok {
		t.Fatal("oversized URI retained")
	}
}

func TestCollationCacheConcurrentEviction(t *testing.T) {
	var (
		runtime evaluationRuntime
		wg      sync.WaitGroup
	)
	for worker := range 8 {
		wg.Go(func() {
			for i := range collationCacheCapacity {
				uri := fmt.Sprintf("http://www.w3.org/2013/collation/UCA?fallback=yes;unused=%d-%d", worker, i)

				coll, err := runtime.resolveCollation(uri, "")
				if err != nil {
					t.Error(err)
					return
				}

				if coll.compare("a", "b") >= 0 {
					t.Error("comparison changed")
				}
			}
		})
	}

	wg.Wait()

	count := 0

	runtime.collations.Range(func(_, _ any) bool { count++; return true })

	if count != collationCacheCapacity {
		t.Fatalf("retained %d collations after concurrent insertion", count)
	}
}

func TestNumericMagnitudeAccounting(t *testing.T) {
	for _, nbits := range []int{0, 1, 7, 8, 9, 63, 64, 65, 511, 512, 513} {
		t.Run(fmt.Sprint(nbits), func(t *testing.T) {
			n := new(big.Int)
			if nbits > 0 {
				n.Lsh(big.NewInt(1), uint(nbits-1))
			}

			want := max(1, (nbits+7)/8)

			for _, sign := range []int64{-1, 1} {
				value := xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: new(big.Int).Mul(n, big.NewInt(sign))}
				if got, ok := NumericSize(value); !ok || got != want {
					t.Fatalf("size %d, want %d", got, want)
				}
			}

			if n.Sign() != 0 {
				value := xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: new(big.Rat).SetFrac(big.NewInt(1), n)}
				if got, ok := NumericSize(value); !ok || got != want+1 {
					t.Fatalf("rational size %d, want %d", got, want+1)
				}
			}
		})
	}
}

func TestNumericDigitCountBounds(t *testing.T) {
	for _, digits := range []int64{1, 19, 100, 22000} {
		t.Run(fmt.Sprint(digits), func(t *testing.T) {
			power := new(big.Int).Exp(big.NewInt(10), big.NewInt(digits), nil)
			if got := intDigitCount(power); got != int(digits)+1 {
				t.Fatalf("digits=%d, want %d", got, digits+1)
			}

			power.Sub(power, big.NewInt(1))

			if got := intDigitCount(power); got != int(digits) {
				t.Fatalf("digits=%d, want %d", got, digits)
			}
		})
	}
}

func TestNumericPreflightBudgets(t *testing.T) {
	ctx := WithBudget(t.Context(), 1000, 100, 64, 64)

	a := new(big.Int).Lsh(big.NewInt(1), 256)
	if err := preflightInteger(ctx, TokenStar, a, a); !errors.Is(err, ErrBudget) {
		t.Fatal(err)
	}

	if err := preflightNumeric(WithBudget(t.Context(), 10, 100, 1024, 64), 4096); !errors.Is(err, ErrBudget) {
		t.Fatal(err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	if err := preflightInteger(canceled, TokenStar, big.NewInt(2), big.NewInt(2)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestNumericBudgetASTAndVM(t *testing.T) {
	const source = `fold-left(1 to 12, 2, function($a,$b){$a*$a}) mod 2`

	l, err := newVersionLexer(source, 31)
	if err != nil {
		t.Fatal(err)
	}

	ast, err := parseWithLexer(l)
	if err != nil {
		t.Fatal(err)
	}

	var evaluateAST exprEvaluator

	evaluateAST = func(ctx context.Context, ec *evalContext, expr Expr) (xdm.Sequence, error) {
		return evalWith(func(ctx context.Context, ec *evalContext, expr Expr) (xdm.Sequence, error) {
			return dispatchExpr(evaluateAST, ctx, ec, expr)
		}, ctx, ec, expr)
	}

	for _, mode := range []string{"AST", "VM"} {
		t.Run(mode, func(t *testing.T) {
			ctx := WithBudget(t.Context(), 100000, 1000, 64, 128)

			if mode == "AST" {
				ec := NewEvaluator(DefaultEvaluatorOptions).newEvalCtx(nil)
				ec.version = 31
				applyBudget(ctx, ec)
				_, err = evaluateAST(ctx, ec, ast)
			} else {
				compiled, compileErr := NewCompiler().CompileExpr(ast)
				if compileErr != nil {
					t.Fatal(compileErr)
				}

				_, err = NewEvaluator(DefaultEvaluatorOptions).Evaluate(ctx, compiled, nil)
			}

			if !errors.Is(err, ErrBudget) {
				t.Fatal(err)
			}
		})
	}
}

func TestTreeBudgetMeasuresBorrowedContent(t *testing.T) {
	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<r><x>ab</x><x>c</x><!--d--><?p e?></r>`))
	if err != nil {
		t.Fatal(err)
	}
	// Document and element accounting includes descendant text; text, comment
	// and PI nodes also charge their own content.
	for _, maximum := range []int{13, 14} {
		ctx := WithBudget(t.Context(), 100, 8, maximum, 10)

		err := ChargeTree(ctx, doc)
		if (err == nil) != (maximum == 14) {
			t.Fatal(maximum, err)
		}
	}

	large, err := (xdm.ParseOptions{}).ParseReader(t.Context(), strings.NewReader(`<r>`+strings.Repeat(`<x>abcdefghijklmnop</x>`, 8192)+`</r>`))
	if err != nil {
		t.Fatal(err)
	}

	allocated := ^uint64(0)

	for range 3 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)

		ctx := WithBudget(t.Context(), 100000, 100000, 8<<20, 128)
		if err := ChargeTree(ctx, large); err != nil {
			t.Fatal(err)
		}

		runtime.ReadMemStats(&after)
		allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)
	}

	if allocated > 8<<10 {
		t.Fatalf("measuring a tree constructed %d bytes of string values", allocated)
	}

	ctx := &budgetCancelContext{Context: t.Context(), remaining: 32}
	if err := ChargeTree(WithBudget(ctx, 100000, 100000, 8<<20, 128), large); !errors.Is(err, context.Canceled) {
		t.Fatal("tree measurement did not observe cancellation", err)
	}
}

func TestSubsequenceBackwardsCompatibility(t *testing.T) {
	ec := NewEvaluator(DefaultEvaluatorOptions).newEvalCtx(nil)
	ec.xpath10Compat = true
	ctx := ec.fnContext(t.Context())

	source := xdm.ItemSlice{xdm.SingleInteger(1).Get(0), xdm.SingleInteger(2).Get(0), xdm.SingleInteger(3).Get(0)}
	for _, tt := range []struct {
		name string
		args []xdm.Sequence
		want int
	}{
		{"omitted", []xdm.Sequence{source, xdm.SingleInteger(2)}, 2},
		{"empty", []xdm.Sequence{source, xdm.SingleInteger(2), nil}, 0},
		{"first item", []xdm.Sequence{source, xdm.SingleInteger(2), xdm.ItemSlice{xdm.SingleInteger(1).Get(0), xdm.SingleInteger(3).Get(0)}}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, err := fnSubsequence(ctx, tt.args)
			if err != nil || xdm.SequenceLen(result) != tt.want {
				t.Fatalf("length=%d error=%v", xdm.SequenceLen(result), err)
			}
		})
	}
}

func TestSubstringRuneSemantics(t *testing.T) {
	positions := []float64{math.Inf(-1), -2, -0.5, 0, 0.5, 1, 1.5, 2, 4, 7, 20, math.Inf(1), math.NaN()}
	for _, source := range []string{"", "abc", "а🙂e\u0301𐀀", "a\xff\xfeb"} {
		for _, start := range positions {
			checkSubstring(t, source, start, 0, false)

			for _, length := range positions {
				checkSubstring(t, source, start, length, true)
			}
		}
	}
}

func FuzzSubstringRuneSemantics(f *testing.F) {
	f.Add("а🙂e\u0301𐀀", 1.5, 3.0, true)
	f.Add("a\xff\xfeb", 2.0, 2.0, true)
	f.Add("abc", math.Inf(-1), math.Inf(1), true)
	f.Fuzz(func(t *testing.T, source string, start, length float64, bounded bool) {
		if len(source) > 4096 {
			t.Skip()
		}

		checkSubstring(t, source, start, length, bounded)
	})
}

func TestSubstringScanHonorsCancellation(t *testing.T) {
	ctx := &budgetCancelContext{Context: t.Context(), remaining: 8}

	_, err := fnSubstring(ctx, []xdm.Sequence{xdm.SingleString(strings.Repeat("x", 1<<20)), xdm.SingleDouble(1 << 20), xdm.SingleDouble(1)})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("substring scan ignored cancellation", err)
	}
}

func TestWhitespaceNormalizationPreservesValues(t *testing.T) {
	const word = "small"

	for _, tc := range []struct{ source, normalized, cast string }{
		{"", "", ""},
		{" \t\r\n", "", ""},
		{word, word, word},
		{" \tsmall\n ", word, word},
		{"\ta  b\nc\r", "a b c", "a b c"},
		{" a\u00a0b\u2003c ", "a\u00a0b\u2003c", "a\u00a0b\u2003c"},
		{" a\xff\xfe b ", "a\xff\xfe b", "a�� b"},
	} {
		result, err := fnNormalizeSpace(t.Context(), []xdm.Sequence{xdm.SingleString(tc.source)})
		if err != nil {
			t.Fatal(err)
		}

		value, ok := result.Get(0).(xdm.AtomicValue)
		if !ok || value.StringVal() != tc.normalized {
			t.Fatalf("normalize-space(%q): %q, want %q", tc.source, value.StringVal(), tc.normalized)
		}

		if value := collapseWhitespace(tc.source); value != tc.cast {
			t.Fatalf("collapseWhitespace(%q): %q, want %q", tc.source, value, tc.cast)
		}
	}
}

type budgetCancelContext struct {
	context.Context
	remaining int
}

func (c *budgetCancelContext) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		return context.Canceled
	}

	return nil
}

func checkSubstring(t *testing.T, source string, start, length float64, bounded bool) {
	t.Helper()

	args := []xdm.Sequence{xdm.SingleString(source), xdm.SingleDouble(start)}
	if bounded {
		args = append(args, xdm.SingleDouble(length))
	}

	actual, err := fnSubstring(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}

	var expected strings.Builder

	roundedStart := roundHalfUpFloat(start, 0)

	for i, r := range []rune(source) {
		p := float64(i + 1)
		if p >= roundedStart && (!bounded || p < roundedStart+roundHalfUpFloat(length, 0)) {
			expected.WriteRune(r)
		}
	}

	value, ok := actual.Get(0).(xdm.AtomicValue)
	if !ok || value.StringVal() != expected.String() {
		t.Fatalf("substring(%.80q, %v, %v), bounded=%v: %.80q, want %.80q", source, start, length, bounded, value.StringVal(), expected.String())
	}
}
