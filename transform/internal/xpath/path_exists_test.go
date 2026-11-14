package xpath //nolint:testpackage // Checks the AST and VM paths for node existence.

import (
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestPathExists(t *testing.T) {
	t.Parallel()
	const doc = `let $d := parse-xml('<r><a><v id="miss"/><v id="hit"><leaf/></v></a><a><v id="last"/></a></r>') return `
	for _, tc := range []struct {
		name, expr string
		want       bool
	}{
		{"candidate in a later subtree", `exists($d//v[@id = 'last'])`, true},
		{"absent through all subtrees", `exists($d//v[@id = 'absent'])`, false},
		{"descendant hop followed by a child", `exists($d//v[@id = 'hit']/leaf)`, true},
		{"child belongs to a rejected candidate", `exists($d//v[@id = 'miss']/leaf)`, false},
		{"second matching sibling exists", `exists($d//v[2])`, true},
		{"position does not span sibling groups", `exists($d//v[3])`, false},
		{"position after an attribute filter", `exists($d//v[@id][2]/leaf)`, true},
		{"last sibling in each group", `exists($d//v[last()]/leaf)`, true},
		{"nested descendant hops", `exists($d//a//v[@id = 'last'])`, true},
		{"overlapping ancestor contexts", `exists($d//leaf/ancestor::*//v[@id = 'last'])`, true},
		{"empty path prefix", `exists($d/r/missing//v)`, false},
		{"descendant attribute axis", `exists($d//@id[. = 'hit'])`, true},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, doc+tc.expr, mode)
				if err != nil || xdm.SequenceLen(seq) != 1 {
					t.Fatalf("%s = %v, %v; want a single xs:boolean", tc.expr, seq, err)
				}
				got, ok := seq.Get(0).(xdm.AtomicValue)
				if !ok || got.TypeName != "xs:boolean" || got.Value != tc.want {
					t.Fatalf("%s = %+v; want xs:boolean %t", tc.expr, seq.Get(0), tc.want)
				}
			})
		}
	}
}
