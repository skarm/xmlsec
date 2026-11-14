package lexical_test

import (
	"testing"

	lexicalpkg "github.com/skarm/xmlsec/transform/internal/xdm/lexical"
)

func TestComparisonValueSpacesAndPrecision(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, kind, left, right string
		want                    int
	}{
		{"boolean aliases", "boolean", " true ", "1", 0},
		{"boolean stable order", "boolean", "0", "true", -1},
		{"hex case", "hexBinary", " 0aFF ", "0Aff", 0},
		{"hex byte order", "hexBinary", "00ff", "0100", -1},
		{"base64 whitespace", "base64Binary", " Y Q==\n", "YQ==", 0},
		{"base64 byte order", "base64Binary", "YQ==", "Yg==", -1},
		{"empty binary prefix", "hexBinary", "", "00", -1},
		{"single precision rounding", "float", "16777216", "16777217", 0},
		{"double precision remains distinct", "double", "16777216", "16777217", -1},
		{"negative zero", "double", "-0", "+0", 0},
		{"negative infinity", "double", "-INF", "-1e300", -1},
		{"positive infinity", "float", "INF", "1", 1},
		{"single overflow", "float", "1e40", "INF", 0},
		{"double overflow", "double", "1e400", "INF", 0},
		{"negative decimal", "decimal", "-10.01", "-10.001", -1},
		{"negative and positive", "decimal", "-0.001", "0", -1},
		{"significantly different lengths", "integer", "999", "1000", -1},
		{"unbounded integer", "integer", "999999999999999999999999999999", "1000000000000000000000000000000", -1},
		{"timestamp UTC aliases", "dateTimeStamp", "2000-01-01T01:00:00+01:00", "2000-01-01T00:00:00Z", 0},
		{"dayTime negative zero", "dayTimeDuration", "-PT0S", "P0D", 0},
		{"dayTime negative aliases", "dayTimeDuration", "-P1DT1H", "-PT25H", 0},
		{"dayTime fractional precision", "dayTimeDuration", "PT0.0001S", "PT0S", 1},
		{"yearMonth negative aliases", "yearMonthDuration", "-P1Y", "-P12M", 0},
		{"yearMonth negative zero", "yearMonthDuration", "-P0M", "P0Y", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got, ok := lexicalpkg.Compare(test.left, test.right, test.kind); !ok || got != test.want {
				t.Fatalf("Compare(%q,%q,%s) = %d,%v; want %d,true", test.left, test.right, test.kind, got, ok, test.want)
			}
			if got, ok := lexicalpkg.Compare(test.right, test.left, test.kind); !ok || got != -test.want {
				t.Fatalf("reverse Compare = %d,%v; want %d,true", got, ok, -test.want)
			}
		})
	}
}

func TestComparisonRejectsEitherInvalidOperand(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ kind, valid, invalid string }{
		{"boolean", "true", "TRUE"},
		{"float", "1", "+NaN"},
		{"double", "1", "nan"},
		{"decimal", "0.5", "1/2"},
		{"unsignedByte", "1", "256"},
		{"hexBinary", "00", "0"},
		{"base64Binary", "YQ==", "YR=="},
		{"dateTime", "2024-02-29T00:00:00Z", "2023-02-29T00:00:00Z"},
		{"date", "2024-01-01", "2024-01-01+14:01"},
		{"time", "00:00:00", "24:00:01"},
		{"gYear", "2024", "+2024"},
		{"gYearMonth", "2024-01", "2024-13"},
		{"gMonth", "--01", "--13"},
		{"gDay", "---01", "---32"},
		{"gMonthDay", "--02-29", "--02-30"},
		{"duration", "PT1S", "PT1.0"},
		{"dateTimeStamp", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00"},
		{"dayTimeDuration", "PT1S", "P1Y"},
		{"dayTimeDuration", "PT0S", "P0Y"},
		{"dayTimeDuration", "PT0S", "PT-1S"},
		{"yearMonthDuration", "P1M", "P1D"},
		{"yearMonthDuration", "P0Y", "PT0S"},
		{"yearMonthDuration", "P0Y", "P1Y-1M"},
		{"yearMonthDuration", "P0Y", "P0.5M"},
	} {
		t.Run(test.kind, func(t *testing.T) {
			t.Parallel()

			for _, operands := range [][2]string{{test.valid, test.invalid}, {test.invalid, test.valid}, {test.invalid, test.invalid}} {
				if _, ok := lexicalpkg.Compare(operands[0], operands[1], test.kind); ok {
					t.Fatalf("invalid operand accepted: %q vs %q", operands[0], operands[1])
				}
			}
		})
	}
	for _, kind := range []string{"float", "double", "string", "unknown"} {
		if _, ok := lexicalpkg.Compare("NaN", "NaN", kind); ok {
			t.Fatalf("unordered/unsupported %s comparison accepted", kind)
		}
	}
	for _, kind := range []string{"string", "anyAtomicType", "unknown"} {
		if _, ok := lexicalpkg.Compare("5", "5", kind); ok {
			t.Fatalf("unsupported %s comparison was routed through numeric comparison", kind)
		}
	}
}

func TestDecimalComparatorFallbackKeepsStrictValidationSeparate(t *testing.T) {
	t.Parallel()

	// CompareDecimal documents big.Rat-compatible fallback syntax. Compare's
	// typed XSD entry point must still reject the non-XSD decimal spellings.
	for _, test := range []struct {
		left, right string
		want        int
	}{
		{"1/2", "0.50", 0},
		{"1", "1/2", 1},
		{"1.25e2", "125", 0},
		{"not a number", "1", -2},
		{"1", ".", -2},
	} {
		if got := lexicalpkg.CompareDecimal(test.left, test.right); got != test.want {
			t.Fatalf("CompareDecimal(%q,%q)=%d; want %d", test.left, test.right, got, test.want)
		}
		if _, ok := lexicalpkg.Compare(test.left, test.right, "decimal"); ok {
			t.Fatalf("typed decimal comparator accepted non-XSD syntax %q/%q", test.left, test.right)
		}
	}
}

func TestCalendarComparisonBoundaries(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, kind, left, right string
		want                    int
		ordered                 bool
	}{
		{"UTC year rollover", "dateTime", "2000-01-01T00:30:00+01:00", "1999-12-31T23:30:00Z", 0, true},
		{"UTC leap day", "dateTime", "2000-03-01T00:30:00+01:00", "2000-02-29T23:30:00Z", 0, true},
		{"UTC forward rollover", "dateTime", "1999-12-31T23:30:00-01:00", "2000-01-01T00:30:00Z", 0, true},
		{"end of day year", "dateTime", "1999-12-31T24:00:00", "2000-01-01T00:00:00", 0, true},
		{"end of leap day", "dateTime", "2000-02-29T24:00:00Z", "2000-03-01T00:00:00Z", 0, true},
		{"end of ordinary day", "dateTime", "2000-01-14T24:00:00", "2000-01-15T00:00:00", 0, true},
		{"end of month", "dateTime", "2000-04-30T24:00:00", "2000-05-01T00:00:00", 0, true},
		{"arbitrary fractional precision", "dateTime", "2024-01-01T00:00:00.0000000000000000001Z", "2024-01-01T00:00:00Z", 1, true},
		{"arbitrary year precision", "date", "100000000000000000001-01-01", "100000000000000000000-12-31", 1, true},
		{"negative years", "date", "-100000000000000000001-01-01", "-100000000000000000000-01-01", -1, true},
		{"year zero", "date", "0000-01-01", "0001-01-01", -1, true},
		{"month field", "dateTime", "2024-02-01T00:00:00", "2024-01-31T23:59:59", 1, true},
		{"day field", "dateTime", "2024-01-02T00:00:00", "2024-01-01T23:59:59", 1, true},
		{"hour field", "dateTime", "2024-01-01T02:00:00", "2024-01-01T01:59:59", 1, true},
		{"minute field", "dateTime", "2024-01-01T01:02:00", "2024-01-01T01:01:59", 1, true},
		{"time end of day", "time", "24:00:00", "00:00:00", 0, true},
		{"time reference date", "time", "11:30:00+01:00", "10:30:00Z", 0, true},
		{"unknown timezone disjoint interval", "dateTime", "2000-01-03T00:00:00Z", "2000-01-01T00:00:00", 1, true},
		{"unknown timezone overlap", "dateTime", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00", 0, false},
		{"unknown timezone inclusive edge", "dateTime", "2000-01-01T14:00:00Z", "2000-01-01T00:00:00", 0, false},
		{"unknown timezone beyond edge", "dateTime", "2000-01-01T14:00:00.0001Z", "2000-01-01T00:00:00", 1, true},
		{"partial year", "gYear", "2023", "2024", -1, true},
		{"partial year month", "gYearMonth", "2024-02", "2024-01", 1, true},
		{"partial month", "gMonth", "--02", "--01", 1, true},
		{"partial day", "gDay", "---31", "---30", 1, true},
		{"partial month day", "gMonthDay", "--02-29", "--03-01", -1, true},
		{"partial unknown timezone", "gYear", "2024Z", "2024", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, ok := lexicalpkg.Compare(test.left, test.right, test.kind)
			if ok != test.ordered || ok && got != test.want {
				t.Fatalf("Compare = %d,%v; want %d,%v", got, ok, test.want, test.ordered)
			}
			got, ok = lexicalpkg.Compare(test.right, test.left, test.kind)
			if ok != test.ordered || ok && got != -test.want {
				t.Fatalf("reverse Compare = %d,%v; want %d,%v", got, ok, -test.want, test.ordered)
			}
		})
	}
}

func TestDurationPartialOrderPublishedExamples(t *testing.T) {
	t.Parallel()

	// XSD 1.0 Part 2 §3.2.6.2 gives these month/day and year/day examples.
	for _, test := range []struct {
		left, right string
		want        int
		ordered     bool
	}{
		{"P1Y", "P364D", 1, true},
		{"P1Y", "P365D", 0, false},
		{"P1Y", "P366D", 0, false},
		{"P1Y", "P367D", -1, true},
		{"P1M", "P27D", 1, true},
		{"P1M", "P28D", 0, false},
		{"P1M", "P31D", 0, false},
		{"P1M", "P32D", -1, true},
		{"P1Y", "P12M", 0, true},
		{"P1D", "PT24H", 0, true},
		{"-P1D", "P0D", -1, true},
		{"PT0.0000000000001S", "PT0S", 1, true},
		{"-P1Y2M3DT4H5M6.7S", "P0D", -1, true},
		{"P100000000000000000000Y", "P1200000000000000000000M", 0, true},
	} {
		t.Run(test.left+"/"+test.right, func(t *testing.T) {
			t.Parallel()

			got, ok := lexicalpkg.Compare(test.left, test.right, "duration")
			if ok != test.ordered || ok && got != test.want {
				t.Fatalf("duration Compare = %d,%v; want %d,%v", got, ok, test.want, test.ordered)
			}
			got, ok = lexicalpkg.Compare(test.right, test.left, "duration")
			if ok != test.ordered || ok && got != -test.want {
				t.Fatalf("reverse duration Compare = %d,%v", got, ok)
			}
		})
	}
}

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
		{"dayTime negative zero", "dayTimeDuration", []string{"-PT0S", "P0D"}, "-PT0.001S"},
		{"dayTime negative fraction", "dayTimeDuration", []string{"-PT0.10S", "-PT0.100S"}, "-PT0.101S"},
		{"yearMonth negative", "yearMonthDuration", []string{"-P1Y", "-P12M"}, "-P13M"},
		{"yearMonth negative zero", "yearMonthDuration", []string{"-P0M", "P0Y"}, "-P1M"},
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
		{"dateTimeStamp", "2000-01-01T00:00:00"},
		{"dayTimeDuration", "P1Y"},
		{"dayTimeDuration", "P0Y"},
		{"dayTimeDuration", "PT-1S"},
		{"yearMonthDuration", "P1D"},
		{"yearMonthDuration", "PT0S"},
		{"yearMonthDuration", "P1Y-1M"},
		{"yearMonthDuration", "P0.5M"},
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
