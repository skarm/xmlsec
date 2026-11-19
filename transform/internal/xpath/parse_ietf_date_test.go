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
		{"asctime with numeric timezone", `parse-ietf-date('Jun 06 11:54:45 -05: (EST) 2013')`, "2013-06-06T11:54:45-05:00"},
		{"UTC timezone name", `parse-ietf-date('06 Jun 1994 07:29:35 UTC')`, "1994-06-06T07:29:35Z"},
		{"UTC suffix with numeric timezone", `parse-ietf-date('06 Jun 1994 07:29:35 +0530 (UTC)')`, "1994-06-06T07:29:35+05:30"},
		{"exact fractional second", `parse-ietf-date('06 Jun 1994 07:29:35.000000015 GMT')`, "1994-06-06T07:29:35.000000015Z"},
		{"subnanosecond precision does not advance the clock", `parse-ietf-date('06 Jun 1994 07:29:35.999999999999999999 GMT')`, "1994-06-06T07:29:35.999999999Z"},
		{"end of day rolls to following month", `parse-ietf-date('29 Feb 2000 24:00:00 GMT')`, "2000-03-01T00:00:00Z"},
	})
}

func TestFnParseIETFDateErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"impossible calendar date", `parse-ietf-date('31 Feb 2024 12:00:00 GMT')`, "FORG0010"},
		{"trailing date text", `parse-ietf-date('06 Jun 1994 07:29:35 GMT trailing')`, "FORG0010"},
		{"seconds outside the dateTime range", `parse-ietf-date('06 Jun 1994 07:29:60 GMT')`, "FORG0010"},
		{"nonzero end-of-day fraction", `parse-ietf-date('29 Feb 2000 24:00:00.0000000001 GMT')`, "FORG0010"},
		{"extra colon after offset minute", `parse-ietf-date('06 Jun 1994 07:29:35 -05:30:')`, "FORG0010"},
		{"double colon in timezone", `parse-ietf-date('06 Jun 1994 07:29:35 -05::')`, "FORG0010"},
		{"no separator after asctime timezone", `parse-ietf-date('Jun 06 07:29:35 +0500(EST)1994')`, "FORG0010"},
		{"Z timezone name", `parse-ietf-date('06 Jun 1994 07:29:35 Z')`, "FORG0010"},
		{"Z suffix with numeric timezone", `parse-ietf-date('06 Jun 1994 07:29:35 +0530 (Z)')`, "FORG0010"},
		{"Z timezone in asctime", `parse-ietf-date('Jun 06 07:29:35 Z 1994')`, "FORG0010"},
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
