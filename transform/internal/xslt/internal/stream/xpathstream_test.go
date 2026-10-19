package xpathstream_test

import (
	"slices"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xpath"
	xpathstream "github.com/skarm/xmlsec/transform/internal/xslt/internal/stream"
)

func TestWalkExprVisitsNestedPredicatesAndArguments(t *testing.T) {
	expr, err := xpath.Parse(`for $x in /root/item[position() = 1] return concat(string($x), 'suffix')`)
	if err != nil {
		t.Fatal(err)
	}

	var calls []string

	xpathstream.WalkExpr(expr, func(e xpath.Expr) bool {
		if call, ok := e.(xpath.FunctionCall); ok {
			calls = append(calls, call.Name)
		}

		return true
	})

	if want := []string{"position", "concat", "string"}; !slices.Equal(calls, want) {
		t.Fatalf("visited calls %v, want %v", calls, want)
	}
}

func TestWalkExprPrunesChildren(t *testing.T) {
	left := &xpath.BinaryExpr{Left: xpath.LiteralExpr{Value: "hidden"}, Right: xpath.LiteralExpr{Value: "hidden"}}
	root := &xpath.BinaryExpr{Left: left, Right: xpath.LiteralExpr{Value: "visible"}}

	var literals []string

	visited := 0

	xpathstream.WalkExpr(root, func(e xpath.Expr) bool {
		visited++
		if visited == 2 {
			return false
		}

		if literal, ok := e.(xpath.LiteralExpr); ok {
			value, ok := literal.Value.(string)
			if !ok {
				t.Fatal("unexpected literal")
			}

			literals = append(literals, value)
		}

		return true
	})

	if visited != 3 || !slices.Equal(literals, []string{"visible"}) {
		t.Fatalf("pruning visited %d nodes, literals %q", visited, literals)
	}

	xpathstream.WalkExpr(nil, func(xpath.Expr) bool { t.Fatal("nil expression visited"); return true })
}
