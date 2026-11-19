package xpath //nolint:testpackage // Exercises evaluator snapshots and reusable result ownership at their package boundary.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestEvaluatorVariableSnapshot(t *testing.T) {
	t.Parallel()
	number := big.NewInt(123)
	sequence := xdm.ItemSlice{xdm.AtomicValue{TypeName: "xs:integer", Value: number}}
	bindings := map[string]xdm.Sequence{"v": sequence}
	base := NewEvaluator(DefaultEvaluatorOptions).Variables(bindings)
	number.SetInt64(999)
	sequence[0] = xdm.AtomicValue{TypeName: "xs:integer", Value: int64(888)}
	bindings["v"] = xdm.SingleInteger(777)
	branch := base.Variables(map[string]xdm.Sequence{"v": xdm.SingleInteger(456)})
	expression := compileEvaluatorExpression(t, `string($v)`)
	assertEvaluatorString(t, base, expression, "123")
	assertEvaluatorString(t, branch, expression, "456")
	assertEvaluatorString(t, base, expression, "123")
}

func TestEvaluatorFocusAndClockIsolation(t *testing.T) {
	t.Parallel()
	at := time.Date(2024, time.February, 29, 23, 45, 6, 0, time.UTC)
	base := NewEvaluator(DefaultEvaluatorOptions).CurrentTime(at).ImplicitTimezone(time.FixedZone("unit", -5*60*60)).Focus(xdm.AtomicValue{TypeName: "xs:string", Value: "base"}, 2, 7)
	focus := compileEvaluatorExpression(t, `string-join((string(.),string(position()),string(last())), '|')`)
	branch := base.Focus(xdm.AtomicValue{TypeName: "xs:string", Value: "branch"}, 3, 9)
	assertEvaluatorString(t, base, focus, "base|2|7")
	assertEvaluatorString(t, branch, focus, "branch|3|9")
	assertEvaluatorString(t, base, focus, "base|2|7")
	clock := compileEvaluatorExpression(t, `string-join((string(current-dateTime()),string(current-date()),string(current-time()),string(implicit-timezone())), '|')`)
	assertEvaluatorString(t, base, clock, "2024-02-29T18:45:06-05:00|2024-02-29-05:00|18:45:06-05:00|-PT5H")
	assertEvaluatorString(t, base.CurrentTime(at.Add(6*time.Hour)), clock, "2024-03-01T00:45:06-05:00|2024-03-01-05:00|00:45:06-05:00|-PT5H")
	assertEvaluatorString(t, base, clock, "2024-02-29T18:45:06-05:00|2024-02-29-05:00|18:45:06-05:00|-PT5H")
}

type evaluatorFunction struct {
	value string
	err   error
}

func (evaluatorFunction) MinArity() int { return 0 }
func (evaluatorFunction) MaxArity() int { return 0 }
func (f evaluatorFunction) Call(context.Context, []xdm.Sequence) (xdm.Sequence, error) {
	if f.err != nil {
		return nil, f.err
	}
	return xdm.SingleString(f.value), nil
}

func TestEvaluatorFunctionSnapshotAndCause(t *testing.T) {
	t.Parallel()
	functions := map[string]Function{"probe": evaluatorFunction{value: "original"}}
	base := NewEvaluator(DefaultEvaluatorOptions).Functions(functions, nil)
	sentinel := errors.New("host function failed")
	functions["probe"] = evaluatorFunction{err: sentinel}
	expression := compileEvaluatorExpression(t, `probe()`)
	assertEvaluatorString(t, base, expression, "original")
	branch := base.Functions(functions, nil)
	result, err := branch.Evaluate(t.Context(), expression, nil)
	if result != nil || !errors.Is(err, sentinel) {
		t.Fatalf("host function failure = %v, %v", result, err)
	}
	assertEvaluatorString(t, base, expression, "original")
}

func TestResultCopyPreservesNodesAfterEvalStateReuse(t *testing.T) {
	t.Parallel()
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<r><n/><n/><n/></r>`)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := NewEvaluator(DefaultEvaluatorOptions)
	state := evaluator.NewEvalState(doc)
	all := compileEvaluatorExpression(t, `r/n`)
	one := compileEvaluatorExpression(t, `r/n[1]`)
	first, err := all.EvaluateReuse(t.Context(), state, doc)
	if err != nil {
		t.Fatal(err)
	}
	owned := first.Copy()
	firstNode := doc.DocumentElement().FirstChild()
	want := []xdm.Node{firstNode, firstNode.NextSibling(), firstNode.NextSibling().NextSibling()}
	if nodes, nodesErr := owned.Nodes(); nodesErr != nil || !slices.Equal(nodes, want) {
		t.Fatalf("initial nodes = %v, %v; want %v", nodes, nodesErr, want)
	}
	extracted, err := first.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	extracted[0] = nil
	if nodes, nodesErr := first.Nodes(); nodesErr != nil || !slices.Equal(nodes, want) {
		t.Fatal("Nodes exposed retained result storage", nodes, nodesErr)
	}
	second, err := one.EvaluateReuse(t.Context(), state, doc)
	if err != nil {
		t.Fatal(err)
	}
	if nodes, nodesErr := second.Nodes(); nodesErr != nil || len(nodes) != 1 || nodes[0] != want[0] {
		t.Fatal("second evaluation", nodes, nodesErr)
	}
	if nodes, nodesErr := owned.Nodes(); nodesErr != nil || !slices.Equal(nodes, want) {
		t.Fatal("Copy changed after state reuse", nodes, nodesErr)
	}
}

func compileEvaluatorExpression(t *testing.T, source string) *Expression {
	t.Helper()
	expression, err := NewCompiler().Language(31, nil).Compile(source)
	if err != nil {
		t.Fatal(err)
	}
	return expression
}

func assertEvaluatorString(t *testing.T, evaluator Evaluator, expression *Expression, want string) {
	t.Helper()
	result, err := evaluator.Evaluate(t.Context(), expression, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := result.IsString(); !ok || got != want {
		t.Fatalf("result = %v; want string %q", result.Sequence(), want)
	}
}

type axisMetadata struct {
	axis     AxisType
	explicit bool
}

func TestAxisSpecifierMetadata(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   []axisMetadata
	}{
		{`document-node()`, []axisMetadata{{AxisChild, false}}},
		{`child::document-node()`, []axisMetadata{{AxisChild, true}}},
		{`(: leading :) (document-node())`, []axisMetadata{{AxisChild, false}}},
		{`(: leading :) (child (: axis :) :: document-node())`, []axisMetadata{{AxisChild, true}}},
		{`child::n`, []axisMetadata{{AxisChild, true}}},
		{`n`, []axisMetadata{{AxisChild, false}}},
		{`@n`, []axisMetadata{{AxisAttribute, true}}},
		{`attribute(n)`, []axisMetadata{{AxisAttribute, false}}},
		{`namespace-node()`, []axisMetadata{{AxisNamespace, false}}},
		{`self::node()`, []axisMetadata{{AxisSelf, true}}},
		{`.`, nil},
		{`..`, []axisMetadata{{AxisParent, false}}},
		{`//child::n`, []axisMetadata{{AxisDescendantOrSelf, false}, {AxisChild, true}}},
	} {
		t.Run(tc.source, func(t *testing.T) {
			ast, err := Parse(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			assertAxisMetadata(t, axisMetadataFromExpr(ast), tc.want)
			compiled, err := NewCompiler().Compile(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			assertAxisMetadata(t, axisMetadataFromExpr(compiled.AST()), tc.want)
			assertAxisMetadata(t, axisMetadataFromProgram(compiled.program), tc.want)
			compiledAST, err := NewCompiler().CompileExpr(ast)
			if err != nil {
				t.Fatal(err)
			}
			assertAxisMetadata(t, axisMetadataFromExpr(compiledAST.AST()), tc.want)
			assertAxisMetadata(t, axisMetadataFromProgram(compiledAST.program), tc.want)
		})
	}
}

func assertAxisMetadata(t *testing.T, got, want []axisMetadata) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata=%v, want %v", got, want)
	}
}

func axisMetadataFromExpr(expr Expr) []axisMetadata {
	var result []axisMetadata
	WalkExpr(expr, func(node Expr) bool {
		if path, ok := AsExpr[LocationPath](node); ok {
			for _, step := range path.Steps {
				result = append(result, axisMetadata{step.Axis, step.ExplicitAxis})
			}
		}
		return true
	})
	return result
}

func axisMetadataFromProgram(program *vmProgram) []axisMetadata {
	var result []axisMetadata
	for _, instruction := range program.instructions {
		path, ok := instruction.payload.(vmLocationPathExpr)
		if !ok {
			continue
		}
		for _, step := range path.Steps {
			result = append(result, axisMetadata{step.Axis, step.ExplicitAxis})
		}
	}
	return result
}

func TestXPath10RejectsURIQualifiedNameTest(t *testing.T) {
	for _, tc := range []struct {
		source    string
		wantError bool
	}{{"Q{}n", true}, {"Q{}*", true}, {"Q{urn:other}n", true}, {"n", false}, {"*", false}} {
		t.Run(tc.source, func(t *testing.T) {
			ast, err := Parse(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			q, err := NewCompiler().Language(10, nil).CompileExpr(ast)
			var detail *xdm.Error
			if tc.wantError {
				if !errors.As(err, &detail) || detail.Code != "XPST0003" || q != nil {
					t.Errorf("queryNil=%t/error=%v; expected nil query/XPST0003", q == nil, err)
				}
			} else if err != nil || q == nil {
				t.Fatalf("bare control query=%v error=%v", q, err)
			}
		})
	}
}

func TestCompileXPath10LeavesSourceASTReusable(t *testing.T) {
	t.Parallel()

	const source = `concat(string(9007199254740993), ':', string(count(/r/n[9007199254740993 = 9007199254740992])))`
	ast, err := Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<r><n/><n/></r>`)
	if err != nil {
		t.Fatal(err)
	}

	evaluator := NewEvaluator(DefaultEvaluatorOptions)
	for _, tc := range []struct {
		version int
		want    string
	}{{31, "9007199254740993:0"}, {10, "9007199254740992:2"}, {31, "9007199254740993:0"}} {
		expr, err := NewCompiler().Language(tc.version, nil).CompileExpr(ast)
		if err != nil {
			t.Fatalf("CompileExpr version %d: %v", tc.version, err)
		}
		result, err := evaluator.Evaluate(t.Context(), expr, doc)
		if err != nil {
			t.Fatalf("Evaluate version %d: %v", tc.version, err)
		}
		if got, ok := result.IsString(); !ok || got != tc.want {
			t.Fatalf("version %d result = %q, want %q", tc.version, got, tc.want)
		}
	}
}

func TestNameTestNamespacePresence(t *testing.T) {
	for _, tc := range []struct {
		source   string
		explicit bool
	}{
		{"Q{}n", true},
		{"Q{}*", true},
		{"Q{urn:other}n", true},
		{"Q{urn:other}*", true},
		{"n", false},
		{"*", false},
		{"p:n", false},
		{"p:*", false},
		{"*:n", false},
	} {
		t.Run(tc.source, func(t *testing.T) {
			ast, err := Parse(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			checkNameTestPresence(t, nameTestFromSyntax(t, ast), tc.explicit)
			direct, err := NewCompiler().Compile(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			checkNameTestPresence(t, nameTestFromProgram(t, direct.program), tc.explicit)
			fromAST, err := NewCompiler().CompileExpr(ast)
			if err != nil {
				t.Fatal(err)
			}
			checkNameTestPresence(t, nameTestFromProgram(t, fromAST.program), tc.explicit)
		})
	}
}

func nameTestFromSyntax(t *testing.T, ast Expr) xdm.NameTest {
	t.Helper()
	var tests []xdm.NameTest
	WalkExpr(ast, func(node Expr) bool {
		if path, ok := node.(LocationPath); ok {
			for _, step := range path.Steps {
				if nt, ok := step.NodeTest.(xdm.NameTest); ok {
					tests = append(tests, nt)
				}
			}
		}
		return true
	})
	if len(tests) != 1 {
		t.Fatalf("name tests=%#v", tests)
	}
	return tests[0]
}

func nameTestFromProgram(t *testing.T, program *vmProgram) xdm.NameTest {
	t.Helper()
	var tests []xdm.NameTest
	for _, instruction := range program.instructions {
		if path, ok := instruction.payload.(vmLocationPathExpr); ok {
			for _, step := range path.Steps {
				if nt, ok := step.NodeTest.(xdm.NameTest); ok {
					tests = append(tests, nt)
				}
			}
		}
	}
	if len(tests) != 1 {
		t.Fatalf("VM name tests=%#v", tests)
	}
	return tests[0]
}

func checkNameTestPresence(t *testing.T, test xdm.NameTest, want bool) {
	t.Helper()
	if test.URIQualified != want {
		t.Fatalf("name test=%#v; expected URIQualified=%t", test, want)
	}
}

func TestManualNameTestNamespaceCompatibility(t *testing.T) {
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<r xmlns:p="urn:other"><n>plain</n><p:n>namespaced</p:n></r>`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		test xdm.NameTest
		want string
	}{
		{"legacy nonempty URI", xdm.NameTest{URI: "urn:other", Local: "n"}, "namespaced"},
		{"legacy bare name", xdm.NameTest{Local: "n"}, "namespaced"},
		{"explicit empty URI", xdm.NameTest{URIQualified: true, Local: "n"}, "plain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ast := LocationPath{Steps: []Step{{Axis: AxisChild, NodeTest: tc.test}}}
			expr, err := NewCompiler().CompileExpr(ast)
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewEvaluator(DefaultEvaluatorOptions).Namespaces(map[string]string{"": "urn:other"}).Evaluate(t.Context(), expr, doc.DocumentElement())
			if err != nil {
				t.Fatal(err)
			}
			nodes, err := result.Nodes()
			if err != nil || len(nodes) != 1 {
				t.Fatalf("nodes=%v error=%v", nodes, err)
			}
			if got := xdm.StringValue(nodes[0]); got != tc.want {
				t.Errorf("actual %q; expected %q", got, tc.want)
			}
		})
	}
}

func TestEvaluationEntryCancellation(t *testing.T) {
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<r/>`)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{`.`, `()`, `/`, `1`, `true()`} {
		t.Run(source, func(t *testing.T) {
			expr, err := NewCompiler().Compile(source)
			if err != nil {
				t.Fatal(err)
			}
			for _, deadline := range []bool{false, true} {
				ctx, cancel := context.WithCancel(t.Context())
				want := context.Canceled
				if deadline {
					cancel()
					ctx, cancel = context.WithDeadline(t.Context(), time.Unix(0, 0))
					want = context.DeadlineExceeded
				} else {
					cancel()
				}
				defer cancel()
				evaluator := NewEvaluator(DefaultEvaluatorOptions)
				if got, err := evaluator.Evaluate(ctx, expr, doc); !errors.Is(err, want) || got != nil {
					t.Errorf("Evaluate: %v, %v; want %v", got, err, want)
				}
				if got, err := evaluator.EvaluateEBV(ctx, expr, doc); !errors.Is(err, want) || got {
					t.Errorf("EvaluateEBV: %v, %v; want %v", got, err, want)
				}
				state := evaluator.NewEvalState(doc)
				if got, err := expr.EvaluateReuse(ctx, state, doc); !errors.Is(err, want) || xdm.SequenceLen(got.Sequence()) != 0 {
					t.Errorf("EvaluateReuse: %v, %v; want %v", got, err, want)
				}
				if _, err := expr.EvaluateReuse(t.Context(), state, doc); err != nil {
					t.Fatal("state after canceled call", err)
				}
			}
		})
	}
}

func TestEvaluateReuseDocumentInvocationBoundaries(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(fmt.Sprintf("unavailable=%t", unavailable), func(t *testing.T) {
			reads := 0
			evaluator := NewEvaluator(DefaultEvaluatorOptions).URIResolver(documentResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				reads++
				if unavailable && reads == 1 {
					return nil, errors.New("temporarily unavailable")
				}
				return io.NopCloser(strings.NewReader(fmt.Sprintf("<r>%d</r>", reads))), nil
			}))
			source := `string(doc('urn:test'))`
			if unavailable {
				source = `doc-available('urn:test')`
			}
			expr, err := NewCompiler().Compile(source)
			if err != nil {
				t.Fatal(err)
			}
			state := evaluator.NewEvalState(nil)
			shared := WithInvocationScope(t.Context())
			fresh := WithInvocationScope(t.Context())
			contexts := []context.Context{shared, shared, fresh, t.Context(), t.Context()}
			for i, ctx := range contexts {
				wantReads := i
				if i == 0 {
					wantReads = 1
				}
				want := fmt.Sprint(wantReads)
				if unavailable {
					want = fmt.Sprint(i > 1)
				}
				got, err := expr.EvaluateReuse(ctx, state, nil)
				if err != nil || got.StringValue() != want || reads != wantReads {
					t.Errorf("call %d: value=%q reads=%d err=%v; want %q reads=%d", i, got.StringValue(), reads, err, want, wantReads)
				}
			}
		})
	}
}
