package xmlutil_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"

	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

func TestSAMLTimeLexicalForm(t *testing.T) {
	for _, s := range []string{
		"2026-10-18T01:02:03Z",
		"2026-10-18T01:02:03.1Z",
		"2026-10-18T01:02:03.123456789Z",
		"2026-10-18T01:02:03.100Z",
	} {
		t.Run(s, func(t *testing.T) {
			got, err := xmlutil.ParseTime(s)

			want, _ := time.Parse(time.RFC3339Nano, s)
			if err != nil || !got.Equal(want) {
				t.Fatalf("got %v, %v; want %v", got, err, want)
			}
		})
	}

	for _, s := range []string{
		"2026-10-18T1:02:03Z",
		"2026-10-18T01:02:03,1Z",
		"2026-10-18T01:02:03.Z",
		"2026-10-18T01:02:03.1234567891Z",
		"2026-10-18T01:02:03+00:00",
		"2026-02-30T01:02:03Z",
		"0000-10-18T01:02:03Z",
	} {
		t.Run(s, func(t *testing.T) {
			if got, err := xmlutil.ParseTime(s); !got.IsZero() || !errors.Is(err, xmlutil.ErrSchema) {
				t.Fatalf("invalid/unsupported dateTime accepted: %v, %v", got, err)
			}
		})
	}
}

func TestSAMLMidnight(t *testing.T) {
	for _, s := range []string{"2026-12-31T24:00:00Z", "2026-12-31T24:00:00.000Z"} {
		got, err := xmlutil.ParseTime(s)

		want := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
		if err != nil || !got.Equal(want) {
			t.Fatalf("%s: got %v, %v; want %v", s, got, err, want)
		}
	}

	for _, s := range []string{"2026-12-31T24:00:00.001Z", "2026-12-31T24:01:00Z", "9999-12-31T24:00:00Z"} {
		if got, err := xmlutil.ParseTime(s); !got.IsZero() || !errors.Is(err, xmlutil.ErrSchema) {
			t.Fatalf("invalid/unsupported midnight accepted: %v, %v", got, err)
		}
	}
}

func TestSAMLDurationLexicalFormAndPrecision(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want time.Duration
	}{
		{"PT0.1S", 100 * time.Millisecond},
		{"PT0.000000001S", time.Nanosecond},
		{"P1DT2H3M4.000000001S", 26*time.Hour + 3*time.Minute + 4*time.Second + time.Nanosecond},
		{"P364DT23H59M59.999999999S", 365*24*time.Hour - time.Nanosecond},
		{"PT31535999.999999999S", 365*24*time.Hour - time.Nanosecond},
		{"P365D", 365 * 24 * time.Hour},
	} {
		t.Run(tc.s, func(t *testing.T) {
			if got, err := xmlutil.Duration(tc.s); err != nil || got != tc.want {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}

	for _, s := range []string{"PT.5S", "PT1.S", "PT1..5S", "P1.5D", "PT0.0000000001S", "P365DT0.000000001S", "P366D", "PT999999999999999999999999999S", "PT0S", "P1DT", "PT1S1H"} {
		t.Run(s, func(t *testing.T) {
			if got, err := xmlutil.Duration(s); got != 0 || !errors.Is(err, xmlutil.ErrSchema) {
				t.Fatalf("invalid/unsupported duration accepted: %v, %v", got, err)
			}
		})
	}
}

func FuzzSAMLTimeAndDuration(f *testing.F) {
	for _, s := range []string{"2026-10-19T00:00:00Z", "2026-12-31T24:00:00Z", "2026-10-19T0:00:00Z", "2026-10-19T00:00:00,1Z", "P364DT23H59M59.999999999S", "P365DT0.000000001S", "PT.5S", "PT0.000000001S"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 128 {
			t.Skip()
		}

		if instant, err := xmlutil.ParseTime(s); err == nil {
			canonical := instant.Format(time.RFC3339Nano)

			roundtrip, err := xmlutil.ParseTime(canonical)
			if err != nil || !roundtrip.Equal(instant) || instant.Year() < 1 || instant.Year() > 9999 {
				t.Fatalf("dateTime round trip: %q -> %v -> %v, %v", s, instant, roundtrip, err)
			}
		}

		if duration, err := xmlutil.Duration(s); err == nil {
			canonical := fmt.Sprintf("PT%d.%09dS", duration/time.Second, duration%time.Second)

			roundtrip, err := xmlutil.Duration(canonical)
			if err != nil || roundtrip != duration || duration <= 0 || duration > 365*24*time.Hour {
				t.Fatalf("duration round trip: %q -> %v -> %v, %v", s, duration, roundtrip, err)
			}
		}
	})
}

func BenchmarkParseTime(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		if _, err := xmlutil.ParseTime("2026-10-09T12:34:56.123456789Z"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSimpleTextSegmentsAndBudget(t *testing.T) {
	for _, text := range []string{"<r>ab</r>", "<r>a<!--ignored--><?ignored test?><![CDATA[b]]></r>", "<r>ab<!--ignored--></r>"} {
		doc, err := document.ParseReader(t.Context(), strings.NewReader(text), document.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}

		if got, err := xmlutil.Simple(doc.Root(), 2); got != "ab" || err != nil {
			t.Fatal("simple content", got, err)
		}

		if got, err := xmlutil.Simple(doc.Root(), 1); got != "" || !errors.Is(err, xmlutil.ErrSchema) {
			t.Fatal("simple content budget", got, err)
		}
	}
}

func TestSimpleTextAvoidsCopiesBeforeBudget(t *testing.T) {
	for _, fixture := range []string{
		`<r a="allowed">` + strings.Repeat("x", 1<<20) + `</r>`,
		`<r a="allowed">` + strings.Repeat("x", 1<<19) + `<!--split-->` + strings.Repeat("x", 1<<19) + `</r>`,
	} {
		doc, err := document.ParseReader(t.Context(), strings.NewReader(fixture), document.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}

		if count := testing.AllocsPerRun(3, func() {
			if got, err := xmlutil.SimpleText(doc.Root(), 1024); got != "" || !errors.Is(err, xmlutil.ErrSchema) {
				t.Fatal("budget", len(got), err)
			}
		}); count != 0 {
			t.Fatal("over-budget text allocated", count)
		}
	}

	valid, err := document.ParseReader(t.Context(), strings.NewReader(`<r a="allowed">a<!--split-->b</r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	if got, err := xmlutil.SimpleText(valid.Root(), 2); got != "ab" || err != nil {
		t.Fatal("attributes were not validated separately", got, err)
	}

	for _, fixture := range []struct {
		text string
		want bool
	}{{"<r> \t<!--split-->\n<?pi ok?></r>", true}, {"<r> x </r>", false}, {"<r><x/></r>", false}} {
		doc, err := document.ParseReader(t.Context(), strings.NewReader(fixture.text), document.DefaultLimits())
		if err != nil || xmlutil.EmptyContent(doc.Root()) != fixture.want {
			t.Fatal("empty content", fixture.text, err)
		}
	}
}
