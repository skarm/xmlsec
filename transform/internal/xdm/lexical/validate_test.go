package lexical_test

import (
	"math/big"
	"testing"

	lexicalpkg "github.com/skarm/xmlsec/transform/internal/xdm/lexical"
)

func TestIntegerSubtypeInclusiveBounds(t *testing.T) {
	t.Parallel()

	// The literal bounds are the XSD 1.1 §3.4 integer-derived datatype facets.
	for _, test := range []struct{ kind, minimum, maximum string }{
		{"byte", "-128", "127"},
		{"short", "-32768", "32767"},
		{"int", "-2147483648", "2147483647"},
		{"long", "-9223372036854775808", "9223372036854775807"},
		{"unsignedByte", "0", "255"},
		{"unsignedShort", "0", "65535"},
		{"unsignedInt", "0", "4294967295"},
		{"unsignedLong", "0", "18446744073709551615"},
	} {
		t.Run(test.kind, func(t *testing.T) {
			t.Parallel()

			for _, bound := range []string{test.minimum, test.maximum} {
				if err := lexicalpkg.ValidateBuiltin(bound, test.kind, lexicalpkg.Version11); err != nil {
					t.Fatalf("inclusive endpoint %s rejected: %v", bound, err)
				}
			}
			minimum, _ := new(big.Int).SetString(test.minimum, 10)
			maximum, _ := new(big.Int).SetString(test.maximum, 10)
			for _, outside := range []string{minimum.Sub(minimum, big.NewInt(1)).String(), maximum.Add(maximum, big.NewInt(1)).String(), "1.0", "1e0"} {
				if err := lexicalpkg.ValidateBuiltin(outside, test.kind, lexicalpkg.Version11); err == nil {
					t.Fatalf("out-of-range/noninteger value %s accepted", outside)
				}
			}
		})
	}
	for _, test := range []struct{ kind, valid, invalid string }{
		{"positiveInteger", "1", "0"},
		{"negativeInteger", "-1", "0"},
		{"nonNegativeInteger", "-0", "-1"},
		{"nonPositiveInteger", "+0", "1"},
	} {
		if err := lexicalpkg.ValidateBuiltin(test.valid, test.kind, lexicalpkg.Version11); err != nil {
			t.Fatalf("valid boundary %s/%s rejected: %v", test.kind, test.valid, err)
		}
		if err := lexicalpkg.ValidateBuiltin(test.invalid, test.kind, lexicalpkg.Version11); err == nil {
			t.Fatalf("invalid boundary %s/%s accepted", test.kind, test.invalid)
		}
	}
}

func TestBuiltinValidationLexicalFormsAndLists(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		kind    string
		valid   []string
		invalid []string
	}{
		{"boolean", []string{"true", "1", "false", "0"}, []string{"", "TRUE", "yes", " true "}},
		{"normalizedString", []string{"a b", "a\u00a0b"}, []string{"a\tb", "a\rb", "a\nb"}},
		{"token", []string{"a b", "a\u00a0b", ""}, []string{" a", "a ", "a  b", "a\tb"}},
		{"QName", []string{"p:item", "item", "é:名"}, []string{"", ":item", "p:", "p:1item", "p:q:item", "a b"}},
		{"NOTATION", []string{"p:item"}, []string{"p::item"}},
		{"ID", []string{"item", "名"}, []string{"p:item", "1item"}},
		{"IDREF", []string{"item"}, []string{"a b"}},
		{"ENTITY", []string{"item"}, []string{"p:item"}},
		{"IDREFS", []string{"item other", " \titem\r\nother "}, []string{"", " \t\r\n", "item p:other", "item\u00a0other"}},
		{"ENTITIES", []string{"item other"}, []string{"item 1other"}},
		{"NMTOKENS", []string{"1:item a-b", "1:a\t2:b"}, []string{"", "a/b", "a\u00a0b", "a\xffb"}},
		{"dayTimeDuration", []string{"P1DT2H3M4.5S", "-PT0.0001S"}, []string{"P1M", "P1Y", "PT1H1H"}},
		{"yearMonthDuration", []string{"P10000000000000000000Y2M", "-P0M"}, []string{"P1D", "PT1S", "P1M1Y"}},
	} {
		t.Run(test.kind, func(t *testing.T) {
			t.Parallel()

			for _, value := range test.valid {
				if err := lexicalpkg.ValidateBuiltin(value, test.kind, lexicalpkg.Version11); err != nil {
					t.Fatalf("valid %q rejected: %v", value, err)
				}
			}
			for _, value := range test.invalid {
				if err := lexicalpkg.ValidateBuiltin(value, test.kind, lexicalpkg.Version11); err == nil {
					t.Fatalf("invalid %q accepted", value)
				}
			}
		})
	}
	for _, value := range []string{"", "anything"} {
		if lexicalpkg.ValidateBuiltin(value, "error", lexicalpkg.Version11) == nil {
			t.Fatal("xs:error accepted a value")
		}
		if err := lexicalpkg.ValidateBuiltin(value, "anyAtomicType", lexicalpkg.Version11); err != nil {
			t.Fatal("abstractness was mistaken for a lexical constraint", err)
		}
	}
}

func TestCalendarLexicalRangeAndEditionBoundaries(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		kind    string
		valid   []string
		invalid []string
	}{
		{"date", []string{"1900-02-28", "2000-02-29", "40000000000000000000000-02-29"}, []string{"1900-02-29", "2100-02-29", "2000-04-31", "2000-00-01", "2000-01-00"}},
		{"time", []string{"24:00:00.000Z", "23:59:59.999-14:00", "00:00:00+13:59"}, []string{"24:00:00.0001", "12:60:00", "12:00:60", "00:00:00-14:01", "00:00:00+15:00", "00:00:00Ztrailing"}},
		{"dateTimeStamp", []string{"2000-01-01T00:00:00Z", "2000-01-01T00:00:00-00:00"}, []string{"2000-01-01T00:00:00", "2000-01-01t00:00:00Z"}},
		{"gMonthDay", []string{"--02-29", "--04-30"}, []string{"--02-30", "--04-31", "--13-01", "--01-00"}},
	} {
		t.Run(test.kind, func(t *testing.T) {
			t.Parallel()

			for _, value := range test.valid {
				if err := lexicalpkg.ValidateBuiltin(value, test.kind, lexicalpkg.Version11); err != nil {
					t.Fatalf("valid calendar %q rejected: %v", value, err)
				}
			}
			for _, value := range test.invalid {
				if err := lexicalpkg.ValidateBuiltin(value, test.kind, lexicalpkg.Version11); err == nil {
					t.Fatalf("invalid calendar %q accepted", value)
				}
			}
		})
	}
	for _, test := range []struct{ kind, zeroYear string }{{"date", "0000-02-29"}, {"dateTime", "0000-02-29T00:00:00Z"}, {"gYear", "0000"}, {"gYearMonth", "0000-02"}} {
		if lexicalpkg.ValidateBuiltin(test.zeroYear, test.kind, lexicalpkg.Version10) == nil || lexicalpkg.ValidateBuiltin(test.zeroYear, test.kind, lexicalpkg.Version11) != nil {
			t.Fatalf("year zero edition boundary lost for %s", test.kind)
		}
	}
}
