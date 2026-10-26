package lexical_test

import (
	"testing"

	lexicalpkg "github.com/skarm/xmlsec/transform/internal/xdm/lexical"
)

func TestCanonicalKeyValueEquivalenceClasses(t *testing.T) {
	t.Parallel()

	// These are value-space equivalences, not a required XSD serialization.
	for _, test := range []struct {
		name, kind string
		equal      []string
		different  string
	}{
		{"boolean", "boolean", []string{"true", "1", " \ttrue\n"}, "false"},
		{"false", "boolean", []string{"false", "0"}, "true"},
		{"decimal", "decimal", []string{"+00012.34000", "12.34"}, "12.3401"},
		{"integer", "integer", []string{"+001", "1"}, "2"},
		{"zero", "decimal", []string{"-0.000", "+0", "0.0"}, "0.01"},
		{"hex octets", "hexBinary", []string{"0aFF", "0Aff", " 0aff\n"}, "0aff00"},
		{"base64 octets", "base64Binary", []string{"YWI=", " Y W I =\n"}, "YWM="},
		{"single precision", "float", []string{"16777216", "16777217"}, "16777218"},
		{"double signed zero", "double", []string{"-0", "+0", "0.0E10"}, "0.1"},
		{"single overflow", "float", []string{"1e40", "INF", "+INF"}, "-INF"},
		{"negative single overflow", "float", []string{"-1e40", "-INF"}, "INF"},
		{"double overflow", "double", []string{"-1e400", "-INF"}, "INF"},
		{"NaN equality key", "double", []string{"NaN", " NaN "}, "INF"},
		{"UTC rollover", "dateTime", []string{"2000-01-01T00:30:00+01:00", "1999-12-31T23:30:00Z"}, "2000-01-01T00:30:00Z"},
		{"end of day", "dateTime", []string{"2000-02-29T24:00:00Z", "2000-03-01T00:00:00+00:00"}, "2000-02-29T00:00:00Z"},
		{"timezone presence remains significant", "dateTime", []string{"2000-01-01T00:00:00", "2000-01-01T00:00:00.000"}, "2000-01-01T00:00:00Z"},
		{"time without calendar rollover", "time", []string{"24:00:00", "00:00:00"}, "00:00:01"},
		{"time timezone", "time", []string{"11:30:00+01:00", "10:30:00Z"}, "11:30:00Z"},
		{"date timezone zero", "date", []string{"2000-02-29Z", "2000-02-29+00:00"}, "2000-03-01Z"},
		{"dateTimeStamp", "dateTimeStamp", []string{"2000-01-01T00:30:00+01:00", "1999-12-31T23:30:00Z"}, "2000-01-01T00:30:00Z"},
		{"partial year", "gYear", []string{"-2024Z", "-2024+00:00"}, "2024Z"},
		{"partial year month", "gYearMonth", []string{"2024-02Z", "2024-02+00:00"}, "2024-03Z"},
		{"partial month", "gMonth", []string{"--02Z", "--02+00:00"}, "--03Z"},
		{"partial day", "gDay", []string{"---02Z", "---02+00:00"}, "---03Z"},
		{"partial month day", "gMonthDay", []string{"--02-29Z", "--02-29+00:00"}, "--03-01Z"},
		{"duration months", "duration", []string{"P1Y2M", "P14M"}, "P15M"},
		{"negative duration months", "duration", []string{"-P1Y", "-P12M"}, "P12M"},
		{"duration seconds", "duration", []string{"P1D", "PT24H", "PT86400.000S"}, "PT86400.01S"},
		{"negative duration seconds", "duration", []string{"-P1D", "-PT24H"}, "PT24H"},
		{"duration negative zero", "duration", []string{"-PT0S", "P0D"}, "-PT0.01S"},
		{"negative duration", "duration", []string{"-P1Y2M3DT4H5M6.7S", "-P14MT273906.7S"}, "P14MT273906.7S"},
		{"dayTime duration", "dayTimeDuration", []string{"P1DT1H", "PT25H"}, "PT24H"},
		{"yearMonth duration", "yearMonthDuration", []string{"P1Y", "P12M"}, "P11M"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			key, ok := lexicalpkg.CanonicalKey(test.equal[0], test.kind)
			if !ok {
				t.Fatal("valid value has no equality key", test.equal[0])
			}
			for _, value := range test.equal[1:] {
				if got, ok := lexicalpkg.CanonicalKey(value, test.kind); !ok || got != key {
					t.Fatalf("equivalent %q produced a different key: %q/%v vs %q", value, got, ok, key)
				}
			}
			if got, ok := lexicalpkg.CanonicalKey(test.different, test.kind); !ok || got == key {
				t.Fatalf("distinct %q collided: %q/%v", test.different, got, ok)
			}
		})
	}
}

func TestCanonicalKeyRejectsStrictInvalidValues(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ kind, invalid string }{
		{"boolean", "True"},
		{"float", "+NaN"},
		{"double", "Infinity"},
		{"decimal", "1/2"},
		{"integer", "1.0"},
		{"byte", "128"},
		{"hexBinary", "0"},
		{"base64Binary", "YR=="},
		{"dateTime", "2023-02-29T00:00:00Z"},
		{"date", "2024-01-01+14:01"},
		{"time", "24:00:01"},
		{"gYear", "+2024"},
		{"gYearMonth", "2024-13"},
		{"gMonth", "--13"},
		{"gDay", "---00"},
		{"gMonthDay", "--02-30"},
		{"duration", "PT1.5"},
	} {
		if _, ok := lexicalpkg.CanonicalKey(test.invalid, test.kind); ok {
			t.Fatalf("invalid %s %q acquired a value key", test.kind, test.invalid)
		}
	}
}

func TestCanonicalKeyNormalizesNonValueComparableTypes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ kind, input, want string }{
		{"string", " \ta\nb ", " \ta\nb "},
		{"normalizedString", "a\tb\r\nc", "a b  c"},
		{"token", " \ta \r\n b ", "a b"},
		{"NMTOKENS", " a\tb\u00a0c ", "a b\u00a0c"},
		{"IDREFS", " a\nb ", "a b"},
		{"ENTITIES", " a\rb ", "a b"},
		{"unknown", " a  b ", "a b"},
	} {
		if got, valueKey := lexicalpkg.CanonicalKey(test.input, test.kind); valueKey || got != test.want {
			t.Fatalf("string-family fallback %s: %q/%v; want %q/false", test.kind, got, valueKey, test.want)
		}
	}
}
