package xmltime_test

import (
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/xmltime"
)

func TestParseUTC(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"2000-02-29T12:34:56Z", "2000-02-29T12:34:56Z"},
		{"2024-12-31T24:00:00Z", "2025-01-01T00:00:00Z"},
		{"2024-02-29T24:00:00.000Z", "2024-03-01T00:00:00Z"},
		{"0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z"},
		{"9999-12-31T23:59:59.123456789Z", "9999-12-31T23:59:59.123456789Z"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := xmltime.ParseUTC(tc.input)
			if err != nil {
				t.Fatal(err)
			}

			if got.Format(time.RFC3339Nano) != tc.want || got.Location() != time.UTC {
				t.Fatalf("ParseUTC(%q) = %v, want %s in UTC", tc.input, got, tc.want)
			}
		})
	}

	for _, input := range []string{"", "0000-01-01T00:00:00Z", "1900-02-29T00:00:00Z", "2024-01-01T1:00:00Z", "2024-01-01T00:00:00,1Z", "2024-01-01T00:00:00.Z", "2024-01-01T00:00:00.1234567890Z", "2024-01-01T00:00:00+00:00", "2024-01-01T24:00:01Z", "2024-01-01T24:00:00.001Z", "9999-12-31T24:00:00Z", "2024-01-01T23:59:60Z", " 2024-01-01T00:00:00Z"} {
		t.Run(input, func(t *testing.T) {
			got, err := xmltime.ParseUTC(input)
			if !errors.Is(err, xmltime.ErrFormat) || !got.IsZero() {
				t.Fatalf("ParseUTC(%q) = %v, %v; want zero time and ErrFormat", input, got, err)
			}
		})
	}
}
