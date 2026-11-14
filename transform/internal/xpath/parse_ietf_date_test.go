package xpath //nolint:testpackage // Exercises date parsing on both evaluation paths.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestFnParseIETFDateASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"RFC date with numeric timezone", `parse-ietf-date('Tue, 29 Feb 2000 23:59:58 +0530')`, "2000-02-29T23:59:58+05:30"},
		{"obsolete RFC date with short year", `parse-ietf-date('Sunday, 06-Nov-94 08:49:37 GMT')`, "1994-11-06T08:49:37Z"},
		{"asctime with named timezone", `parse-ietf-date('Wed Jun 06 11:54:45 EST 2013')`, "2013-06-06T11:54:45-05:00"},
		{"end of day rolls to following month", `parse-ietf-date('29 Feb 2000 24:00:00 GMT')`, "2000-03-01T00:00:00Z"},
	})
}

func TestFnParseIETFDateErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"impossible calendar date", `parse-ietf-date('31 Feb 2024 12:00:00 GMT')`, "FORG0010"},
		{"trailing date text", `parse-ietf-date('06 Jun 1994 07:29:35 GMT trailing')`, "FORG0010"},
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
