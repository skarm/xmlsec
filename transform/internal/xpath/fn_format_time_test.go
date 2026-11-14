package xpath //nolint:testpackage // Exercises picture formatting on both evaluation paths.

import "testing"

func TestFnFormatTimePicturesASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"twelve-hour clock and fractional seconds", `format-time(xs:time('23:05:09.125Z'),'[H01]:[m01]:[s01].[f001] [h1] [Z]','en',(),())`, "23:05:09.125 11 +00:00"},
	})
}
