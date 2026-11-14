package xpath //nolint:testpackage // Checks date-time formatting on the AST and VM paths.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestFnFormatDateTime(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"weekday names and ISO day numbers", `(format-dateTime(xs:dateTime('2024-03-03T00:00:00'), '[FNn] [F1] [d1]','en','ISO',()), format-dateTime(xs:dateTime('2024-03-04T00:00:00'), '[FNn] [F1]','de','ISO',()))`, "Sunday 7 63|Montag 1"},
		{"midnight and noon in a twelve-hour clock", `(format-dateTime(xs:dateTime('2024-01-01T00:00:00'), '[h1] [PN]'), format-dateTime(xs:dateTime('2024-01-01T12:00:00'), '[h1] [PN]'))`, "12 AM|12 PM"},
		{"time-zone pictures preserve sign and minutes", `format-dateTime(xs:dateTime('2024-01-01T12:00:00-03:30'),'[Z0000] [z01:01] [Z01]')`, "-0330 GMT-03:30 -03:30"},
		{"military time zones and absence", `(format-dateTime(xs:dateTime('2024-01-01T12:00:00+02:00'),'[ZZ]'), format-dateTime(xs:dateTime('2024-01-01T12:00:00-02:00'),'[ZZ]'), format-dateTime(xs:dateTime('2024-01-01T12:00:00Z'),'[ZZ]'), format-dateTime(xs:dateTime('2024-01-01T12:00:00'),'[[[ZZ]]]'))`, "B|O|Z|[J]"},
		{"place shifts the instant across a calendar day", `format-dateTime(xs:dateTime('2024-07-01T00:30:00+02:00'),'[Y0001]-[M01]-[D01] [H01]:[m01] [ZN]','en','ISO','UTC')`, "2024-06-30 22:30 UTC"},
		{"place supplies a zone for a local date-time", `format-dateTime(xs:dateTime('2024-07-01T00:30:00'),'[H01]:[m01] [ZN]','en','ISO','UTC')`, "00:30 UTC"},
		{"unknown place leaves the supplied offset", `format-dateTime(xs:dateTime('2024-07-01T00:30:00+02:00'),'[H01]:[m01] [Z]','en','ISO','Unknown/Place')`, "00:30 +02:00"},
		{"unknown language and extension calendar identify fallback", `format-dateTime(xs:dateTime('2024-02-01T00:00:00'),'[MNn] [C]','zz','Q{urn:example}calendar',())`, "[Language: en][Calendar: AD]February ISO"},
		{"era and calendar labels", `(format-dateTime(xs:dateTime('2024-01-01T00:00:00'),'[EN] [C]'), format-dateTime(xs:dateTime('-0001-01-01T00:00:00'),'[En]'))`, "AD ISO|bc"},
		{"empty input propagates without a string result", `count(format-dateTime((), '[Y0001]'))`, "0"},
	})
}

func TestFnFormatDateTimeErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, expr, code string }{
		{"unclosed component", `format-dateTime(xs:dateTime('2024-01-01T00:00:00'), '[Y0001')`, "FOFD1340"},
		{"empty component", `format-dateTime(xs:dateTime('2024-01-01T00:00:00'), '[]')`, "FOFD1340"},
		{"undeclared calendar prefix", `format-dateTime(xs:dateTime('2024-01-01T00:00:00'), '[Y1]', 'en', 'missing:calendar', ())`, "FOFD1340"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, tc.expr, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Fatalf("%s = %v, %v; want empty result and %s", tc.expr, seq, err, tc.code)
				}
			})
		}
	}
}

func TestFnFormatDatePicturesASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"calendar fields and literal brackets", `format-date(xs:date('2024-02-29'),'[[[D01] [MNn] [Y0001]]]','en','ISO',())`, "[29 February 2024]"},
	})
}

func TestFnFormatTimePicturesASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"twelve-hour clock and fractional seconds", `format-time(xs:time('23:05:09.125Z'),'[H01]:[m01]:[s01].[f001] [h1] [Z]','en',(),())`, "23:05:09.125 11 +00:00"},
	})
}
