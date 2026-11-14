package xpath //nolint:testpackage // Exercises picture formatting on both evaluation paths.

import "testing"

func TestFnFormatDatePicturesASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"calendar fields and literal brackets", `format-date(xs:date('2024-02-29'),'[[[D01] [MNn] [Y0001]]]','en','ISO',())`, "[29 February 2024]"},
	})
}
