package value_test

import (
	"testing"

	lexicalpkg "github.com/skarm/xmlsec/transform/internal/xdm/lexical"
)

const (
	textAB                = "a b"
	builtinTime           = "time"
	nameBase64Binary      = "base64Binary"
	nameDate              = "date"
	nameDateTime          = "dateTime"
	nameDecimal           = "decimal"
	nameDuration          = "duration"
	nameGDay              = "gDay"
	nameGMonth            = "gMonth"
	nameGMonthDay         = "gMonthDay"
	nameGYear             = "gYear"
	nameGYearMonth        = "gYearMonth"
	nameHexBinary         = "hexBinary"
	nameInteger           = "integer"
	valueInfinity         = "INF"
	valueNaN              = "NaN"
	valueNegativeInfinity = "-INF"
)

func TestLexicalScanners(t *testing.T) {
	for _, c := range []struct {
		kind           string
		valid, invalid []string
	}{
		{nameDecimal, []string{"0", "-.1", "+2.", "000.010"}, []string{"", ".", "1e2", "++1", "٢"}},
		{nameInteger, []string{"+0", "-99999999999999999999999"}, []string{"1.0", "--1", "1e1"}},
		{"double", []string{valueInfinity, "+INF", valueNegativeInfinity, valueNaN, "-.2E+3"}, []string{"+NaN", "nan", "1e", "e2", "1e2e3"}},
		{"language", []string{"en", "en-US", "zh-Hant", "abc-12345678"}, []string{"", "en-", "en_Us", "1en", "123", "abcdefghi", "en-abcdefghi"}},
		{nameDate, []string{"2024-02-29", "-12345-01-01Z", "0000-01-01", "2024-01-01+14:00"}, []string{"2023-02-29", "2024-13-01", "02024-01-01", "2024-01-01+14:01", "2024-01-01z"}},
		{builtinTime, []string{"23:59:59.01Z", "24:00:00", "01:02:03-12:30"}, []string{"24:00:01", "01:02:03.", "01:02:03+5:00"}},
		{nameDateTime, []string{"2024-02-29T24:00:00Z"}, []string{"2024-01-01 00:00:00", "2023-02-29T00:00:00"}},
		{"dateTimeStamp", []string{"2024-01-01T00:00:00Z"}, []string{"2024-01-01T00:00:00"}},
		{nameGYear, []string{"-12345", "-2024", "2024Z", "2024+14:00"}, []string{"02024", "123", "+2024", "2024+14:01"}},
		{nameGYearMonth, []string{"-12345-02", "2024-12Z"}, []string{"2024-13", "2024-1"}},
		{nameGMonth, []string{"--02", "--12+02:00"}, []string{"--00", "--13", "--02--"}},
		{nameGDay, []string{"---31Z"}, []string{"---00", "---32"}},
		{nameGMonthDay, []string{"--02-29Z"}, []string{"--02-30", "--04-31"}},
		{nameDuration, []string{"P1Y2M3DT4H5M6.7S", "-PT0S", "P0D"}, []string{"P", "PT", "P1YT", "P1M2Y", "P1.5D", "PT.1S", "PT1S2M"}},
		{"dayTimeDuration", []string{"P1DT2H", "PT0.1S"}, []string{"P1Y", "P1M", "P1DT"}},
		{"yearMonthDuration", []string{"P1Y2M", "-P0M"}, []string{"P1D", "PT1H", "P1YT"}},
		{nameHexBinary, []string{"", "0aFF"}, []string{"a", "0g", "00 11"}},
		{nameBase64Binary, []string{"", "YQ==", "Y Q==\n"}, []string{"A", "====", "YQ=", "YR==", "YQ==!"}},
		{"NCName", []string{"éclair", "имя", "𐀀"}, []string{"", "1a", "a:b", textAB}},
		{"Name", []string{":x", "a:b"}, []string{"1a", textAB}},
		{"NMTOKEN", []string{"1:a-b"}, []string{"", textAB}},
	} {
		t.Run(c.kind, func(t *testing.T) {
			for _, s := range c.valid {
				if err := lexicalpkg.ValidateBuiltin(s, c.kind, lexicalpkg.Version11); err != nil {
					t.Errorf("valid %q rejected: %v", s, err)
				}
			}

			for _, s := range c.invalid {
				if err := lexicalpkg.ValidateBuiltin(s, c.kind, lexicalpkg.Version11); err == nil {
					t.Errorf("invalid %q accepted", s)
				}
			}
		})
	}

	for _, c := range []struct{ kind, value string }{{"double", "+INF"}, {nameDate, "0000-01-01"}, {nameGYear, "0000"}} {
		if lexicalpkg.ValidateBuiltin(c.value, c.kind, lexicalpkg.Version10) == nil {
			t.Error("XSD 1.0 boundary lost", c)
		}
	}
}

func TestAnyURIEditionSyntax(t *testing.T) {
	for _, c := range []struct {
		valid  bool
		values []string
	}{
		{true, []string{"", "#fragment", "?query", "relative/path:part", "urn:a:", "http://[::1]:80/", "//user@[::ffff:192.0.2.1]/", "//[::ffff:192.000.002.001]/", "//[::000.000.000.000]/", "//[::255.255.255.255]/", "//registry:word/path", "urn:two words", "urn:a\\b^c`d", "urn:имя", "urn:a\x7fb", "urn:a%20b"}},
		{false, []string{"####", "urn:a#b#c", "%", "%xx", ":a", "1scheme:value", "urn:", "urn:#f", "//[::1", "//[::1]tail", "//[::1]:word", "//[not-ipv6]", "//[127.0.0.1]", "//[::ffff:256.0.2.1]/", "//[::ffff:192.0000.2.1]/", "//[::ffff:192.0x0.2.1]/", "http://example.test/[path]"}},
	} {
		for _, s := range c.values {
			if err := lexicalpkg.ValidateBuiltin(s, "anyURI", lexicalpkg.Version10); (err == nil) != c.valid {
				t.Errorf("XSD 1.0 %q: %v, want valid=%t", s, err, c.valid)
			}
			if err := lexicalpkg.ValidateBuiltin(s, "anyURI", lexicalpkg.Version11); err != nil {
				t.Errorf("XSD 1.1 %q: %v", s, err)
			}
		}
	}
}
