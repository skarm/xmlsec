package xpath //nolint:testpackage // Exercises axes and predicates on both evaluation paths.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestPathAxesAndPredicateFocusASTAndVM(t *testing.T) {
	t.Parallel()
	const doc = `let $d := parse-xml('<r><a id="a1"><v id="v1"/><v id="v2"/></a><b id="b1"><v id="v3"/></b><a id="a2"><v id="v4"/></a></r>') return `
	assertFunctionResults(t, []functionResultCase{
		{"descendant traversal returns document order", doc + `$d//v/@id`, "v1|v2|v3|v4"},
		{"abbreviated descendant predicate uses sibling focus", doc + `($d//v[1]/@id,($d//v)[1]/@id)`, "v1|v3|v4|v1"},
		{"reverse axis applies proximity before sorting", doc + `($d/r/a[2]/preceding-sibling::*[1]/@id,($d/r/a[2]/preceding-sibling::*)[1]/@id)`, "b1|a1"},
		{"ancestor and following axes exclude self and descendants", doc + `($d//v[@id='v2']/ancestor::*[1]/@id,$d/r/a[1]/following::v/@id)`, "a1|v3|v4"},
		{"path removes duplicate nodes but simple map retains them", doc + `(($d/r/a[2],$d/r/a[1],$d/r/a[2])/v/@id,($d/r/a[2],$d/r/a[2]) ! v/@id)`, "v1|v2|v4|v4|v4"},
		{"node set operations order and deduplicate", doc + `(($d/r/a | $d/r/b)/@id,($d/r/* except $d/r/a[1])/@id,($d/r/* intersect $d/r/a)/@id)`, "a1|b1|a2|b1|a2|a1|a2"},
		{"descendant comparison predicates isolate relative paths", doc + `($d/r/*[v/@id = 'v2']/@id,$d/r/*[descendant::v[@id = 'v4']]/@id)`, "a1|a2"},
	})
}

func TestEvalLocationPathErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"mixed node and atomic path result", `parse-xml('<r/>')/(r,1)`, "XPTY0018"},
		{"atomic path step input", `(1,2)/r`, "XPTY0019"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, test.expression, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: test.code}) {
					t.Fatalf("%s = %v, %v; want no result and %s", test.expression, seq, err, test.code)
				}
			})
		}
	}
}
