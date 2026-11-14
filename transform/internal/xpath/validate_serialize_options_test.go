package xpath //nolint:testpackage // Exercises serialization option validation through both evaluators.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestValidateSerializeOptions(t *testing.T) {
	t.Parallel()
	const document = `let $d := parse-xml('<r/>') return `
	assertFunctionResults(t, []functionResultCase{
		{"XML 1.1 permits undeclaring prefixes", document + `serialize($d, map{'method':'xml','version':'1.1','omit-xml-declaration':false(),'undeclare-prefixes':true()})`, `<?xml version="1.1" encoding="UTF-8"?><r/>`},
		{"text method ignores XML prefix undeclarations", `serialize('text', map{'method':'text','undeclare-prefixes':true()})`, "text"},
		{"XML 1.0 permits a doctype without a declaration", document + `serialize($d, map{'method':'xml','version':'1.0','doctype-system':'catalog.dtd'})`, `<!DOCTYPE r SYSTEM "catalog.dtd"><r/>`},
	})

	for _, tc := range []struct{ name, options, code string }{
		{"XML version rejected with declaration omitted", `map{'method':'xml','version':'1.2'}`, "SESU0013"},
		{"HTML version rejected", `map{'method':'html','html-version':8}`, "SESU0013"},
		{"XML 1.0 prefix undeclarations rejected", `map{'method':'xml','undeclare-prefixes':true()}`, "SEPM0010"},
		{"XML 1.1 doctype requires the declaration", `map{'method':'xml','version':'1.1','doctype-system':'catalog.dtd'}`, "SEPM0009"},
		{"unsupported normalization rejected on an empty element", `map{'method':'xml','normalization-form':'fully-normalized'}`, "SESU0011"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				source := document + `serialize($d, ` + tc.options + `)`
				seq, err := evaluateFunctionExpression(t, source, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Fatalf("%s = %v, %v; want no result and %s", source, seq, err, tc.code)
				}
			})
		}
	}
}
