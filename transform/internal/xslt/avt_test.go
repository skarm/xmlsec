package xslt //nolint:testpackage // Tests private AVT scanning and simple-content construction.

import (
	"context"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func TestAVTExpressionClosingBrace(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, expression string
	}{
		{"empty expression", ""},
		{"ordinary expression", "1 + 2"},
		{"single quoted braces", `'}{'`},
		{"double quoted braces", `"}{"`},
		{"comment marker inside single quotes", `'(: } {'`},
		{"comment marker inside double quotes", `"(: } {"`},
		{"doubled quote escapes", `'it''s }{'`},
		{"nested maps and arrays", `map{'braces':'}{', 'items':array{1,map{'x':2}}}`},
		{"EQName namespace braces", `Q{urn:example}value`},
		{"nested comments containing quotes and braces", `(: ' } (: " { :) } :) 7`},
		{"Unicode before the boundary", `'é}中'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := test.expression + "}trailing}"
			if got := findAVTExprEnd(input); got != len(test.expression) {
				t.Fatalf("closing brace of %q at byte %d; want %d", input, got, len(test.expression))
			}
		})
	}
	for _, input := range []string{"1", "map{'x':1}", `'unterminated }`, `"unterminated }`, `(: unterminated }`, `(: outer (: inner :) }`} {
		t.Run("unterminated/"+input, func(t *testing.T) {
			t.Parallel()
			if got := findAVTExprEnd(input); got != -1 {
				t.Fatalf("unterminated expression %q ended at %d", input, got)
			}
		})
	}
}

func TestAVTCommentOnlyExpressions(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input string
		want  bool
	}{
		{"(: simple :)", true},
		{" \t(: one :)\r\n(: two :)", true},
		{"(: outer (: inner :) outer :)", true},
		{" \t\r\n", true},
		{"", false},
		{"(: unclosed", false},
		{"(: outer (: inner :) ", false},
		{"(: complete :) value", false},
		{"value (: comment :)", false},
		{"'(: quoted :)'", false},
		{"\u00a0(: not XML whitespace :)", false},
	} {
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()
			if got := isXPathCommentOnly(test.input); got != test.want {
				t.Fatalf("comment-only %q = %v; want %v", test.input, got, test.want)
			}
		})
	}
}

func stringItem(value string) xdm.AtomicValue {
	return xdm.AtomicValue{TypeName: "xs:string", Value: value}
}

func TestSimpleContentNormalization(t *testing.T) {
	t.Parallel()
	doc := xdm.NewDefaultDocument()
	text := func(value string) xdm.Item { return xdm.NodeItem{Node: doc.CreateText(value)} }
	for _, test := range []struct {
		name string
		seq  xdm.Sequence
		want string
	}{
		{"nil", nil, ""},
		{"empty", xdm.ItemSlice{}, ""},
		{"adjacent text", xdm.ItemSlice{text("a"), text(""), text("b")}, "ab"},
		{"empty atomic separates text", xdm.ItemSlice{text("a"), stringItem(""), text("b")}, "a||b"},
		{"empty text discarded", xdm.ItemSlice{text(""), stringItem("a"), text(""), stringItem("b"), text("")}, "a|b"},
		{"array atomization follows text normalization", xdm.ItemSlice{text("x"), text("y"), xdm.NewArray([]xdm.Sequence{xdm.ItemSlice{text("a"), text("b")}}), text("z"), text("q")}, "xy|a|b|zq"},
		{"empty array member text retained", xdm.ItemSlice{stringItem("x"), xdm.NewArray([]xdm.Sequence{xdm.ItemSlice{text(""), text("a")}})}, "x||a"},
		{"recursive arrays", xdm.ItemSlice{xdm.NewArray([]xdm.Sequence{xdm.ItemSlice{stringItem("a"), xdm.NewArray([]xdm.Sequence{xdm.ItemSlice{stringItem("b")}})}, nil}), stringItem("c")}, "a|b|c"},
		{"atomic lexical values", xdm.ItemSlice{xdm.AtomicValue{TypeName: "xs:boolean", Value: true}, xdm.AtomicValue{TypeName: "xs:integer", Value: int64(-12)}}, "true|-12"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := stringifySimpleContent(t.Context(), test.seq, "|")
			if err != nil || got != test.want {
				t.Fatalf("simple content = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestSimpleContentAtomizationFailure(t *testing.T) {
	t.Parallel()
	for _, seq := range []xdm.Sequence{
		xdm.ItemSlice{xdm.NewMap(nil)},
		xdm.ItemSlice{stringItem("prefix"), xdm.NewArray([]xdm.Sequence{xdm.ItemSlice{xdm.NewMap(nil)}})},
	} {
		got, err := stringifySimpleContent(t.Context(), seq, "|")
		if got != "" || !errors.Is(err, &xdm.Error{Code: "FOTY0013"}) {
			t.Fatalf("unatomizable content = %q, %v; want no result and FOTY0013", got, err)
		}
	}
}

func TestSimpleContentBudgets(t *testing.T) {
	t.Parallel()
	seq := xdm.ItemSlice{stringItem("ab"), stringItem("cd")}
	for _, test := range []struct {
		name       string
		ops, bytes int
		wantErr    error
	}{
		{"exact allocation", 2, 5, nil},
		{"separator costs bytes", 2, 4, xpath.ErrBudget},
		{"each item costs work", 1, 5, xpath.ErrBudget},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := xpath.WithBudget(t.Context(), test.ops, 100, test.bytes, 32)
			got, err := stringifySimpleContent(ctx, seq, "|")
			if test.wantErr == nil {
				if err != nil || got != "ab|cd" {
					t.Fatalf("exact budget = %q, %v", got, err)
				}
			} else if got != "" || !errors.Is(err, test.wantErr) {
				t.Fatalf("exhausted budget = %q, %v; want no partial result and %v", got, err, test.wantErr)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := stringifySimpleContent(ctx, seq, "|"); got != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled content = %q, %v", got, err)
	}
}

func TestSimpleContentArrayDepth(t *testing.T) {
	t.Parallel()
	var item xdm.Item = stringItem("leaf")
	for depth := 1; depth <= 3; depth++ {
		item = xdm.NewArray([]xdm.Sequence{xdm.ItemSlice{item}})
		ctx := xpath.WithBudget(t.Context(), 100, 100, 100, 2)
		got, err := stringifySimpleContent(ctx, xdm.ItemSlice{item}, "|")
		if depth <= 2 {
			if err != nil || got != "leaf" {
				t.Fatalf("depth %d within limit = %q, %v", depth, got, err)
			}
		} else if got != "" || !errors.Is(err, xpath.ErrRecursionLimit) {
			t.Fatalf("depth %d past limit = %q, %v", depth, got, err)
		}
	}
}

func TestAVTContentCompatibility(t *testing.T) {
	t.Parallel()
	doc := xdm.NewDefaultDocument()
	seq := xdm.ItemSlice{xdm.NodeItem{Node: doc.CreateText("a")}, xdm.NodeItem{Node: doc.CreateText("b")}, stringItem("c")}
	for _, test := range []struct {
		backwards bool
		want      string
	}{{false, "ab c"}, {true, "a"}} {
		got, err := stringifyAVTContent(t.Context(), seq, test.backwards)
		if err != nil || got != test.want {
			t.Fatalf("backwards=%v: %q, %v; want %q", test.backwards, got, err, test.want)
		}
	}
}
