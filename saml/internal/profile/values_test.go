package profile_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/saml/internal/profile"
)

func TestIdentifiersAndURIs(t *testing.T) {
	for _, id := range []string{"_request", "запрос", strings.Repeat("a", 256)} {
		if !profile.ID(id) {
			t.Errorf("valid ID rejected: %q", id)
		}
	}

	for _, id := range []string{"", "1request", "prefix:request", "a b", "\xff", strings.Repeat("a", 257)} {
		if profile.ID(id) {
			t.Errorf("invalid ID accepted: %q", id)
		}
	}

	for _, uri := range []string{"urn:example:entity", "https://example.test/metadata", "urn:" + strings.Repeat("a", 2044)} {
		if !profile.URI(uri) {
			t.Errorf("valid URI rejected: %q", uri)
		}
	}

	for _, uri := range []string{"", "relative/path", "urn:with space", "urn:with\tspace", "https://example.test/%xx", "urn:" + strings.Repeat("a", 2045)} {
		if profile.URI(uri) {
			t.Errorf("invalid URI accepted: %q", uri)
		}
	}
}

func TestEndpointPolicy(t *testing.T) {
	for _, endpoint := range []string{"https://example.test/acs", "https://example.test:8443/acs?binding=post", "https://example.test/" + strings.Repeat("a", 4075)} {
		if !profile.Endpoint(endpoint, false) {
			t.Errorf("valid HTTPS endpoint rejected: %q", endpoint)
		}
	}

	if profile.Endpoint("http://example.test/acs", false) || !profile.Endpoint("http://example.test/acs", true) {
		t.Fatal("HTTP permission changed")
	}

	for _, endpoint := range []string{"/acs", "https:opaque", "https://user@example.test/acs", "https://example.test/acs#fragment", "ftp://example.test/acs", "https://example.test/" + strings.Repeat("a", 4076)} {
		if profile.Endpoint(endpoint, true) {
			t.Errorf("invalid endpoint accepted: %q", endpoint)
		}
	}
}

func TestBooleanValues(t *testing.T) {
	for _, input := range []string{"", "false", "0", "true", "1"} {
		got, err := profile.Bool(input)
		if err != nil || got != (input == "true" || input == "1") {
			t.Fatalf("Bool(%q) = %v, %v", input, got, err)
		}
	}

	for _, input := range []string{"TRUE", "yes", " true", "false "} {
		if _, err := profile.Bool(input); !errors.Is(err, profile.ErrSchema) {
			t.Errorf("invalid boolean accepted: %q: %v", input, err)
		}
	}
}

func TestSAMLTimeLexicalForm(t *testing.T) {
	for _, s := range []string{
		"2026-10-18T01:02:03Z",
		"2026-10-18T01:02:03.1Z",
		"2026-10-18T01:02:03.123456789Z",
		"2026-10-18T01:02:03.100Z",
	} {
		t.Run(s, func(t *testing.T) {
			got, err := profile.ParseTime(s)

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
			if got, err := profile.ParseTime(s); !got.IsZero() || !errors.Is(err, profile.ErrSchema) {
				t.Fatalf("invalid/unsupported dateTime accepted: %v, %v", got, err)
			}
		})
	}
}

func TestSAMLMidnight(t *testing.T) {
	for _, s := range []string{"2026-12-31T24:00:00Z", "2026-12-31T24:00:00.000Z"} {
		got, err := profile.ParseTime(s)

		want := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
		if err != nil || !got.Equal(want) {
			t.Fatalf("%s: got %v, %v; want %v", s, got, err, want)
		}
	}

	for _, s := range []string{"2026-12-31T24:00:00.001Z", "2026-12-31T24:01:00Z", "9999-12-31T24:00:00Z"} {
		if got, err := profile.ParseTime(s); !got.IsZero() || !errors.Is(err, profile.ErrSchema) {
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
			if got, err := profile.Duration(tc.s); err != nil || got != tc.want {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}

	for _, s := range []string{"PT.5S", "PT1.S", "PT1..5S", "P1.5D", "PT0.0000000001S", "P365DT0.000000001S", "P366D", "PT999999999999999999999999999S", "PT0S", "P1DT", "PT1S1H"} {
		t.Run(s, func(t *testing.T) {
			if got, err := profile.Duration(s); got != 0 || !errors.Is(err, profile.ErrSchema) {
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

		if instant, err := profile.ParseTime(s); err == nil {
			canonical := instant.Format(time.RFC3339Nano)

			roundtrip, err := profile.ParseTime(canonical)
			if err != nil || !roundtrip.Equal(instant) || instant.Year() < 1 || instant.Year() > 9999 {
				t.Fatalf("dateTime round trip: %q -> %v -> %v, %v", s, instant, roundtrip, err)
			}
		}

		if duration, err := profile.Duration(s); err == nil {
			canonical := fmt.Sprintf("PT%d.%09dS", duration/time.Second, duration%time.Second)

			roundtrip, err := profile.Duration(canonical)
			if err != nil || roundtrip != duration || duration <= 0 || duration > 365*24*time.Hour {
				t.Fatalf("duration round trip: %q -> %v -> %v, %v", s, duration, roundtrip, err)
			}
		}
	})
}

func BenchmarkParseTime(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		if _, err := profile.ParseTime("2026-10-09T12:34:56.123456789Z"); err != nil {
			b.Fatal(err)
		}
	}
}
