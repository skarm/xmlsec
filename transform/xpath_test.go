package transform_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

const (
	calendarDateExpression       = "xs:date('2026-01-01')"
	calendarTimeExpression       = "xs:time('12:00:00')"
	invalidTextEncodingArguments = `'urn:unread', ()`
	functionCodepointsToString   = "codepoints-to-string"
	functionConcat               = "concat"
	functionUnparsedText         = "unparsed-text"
	functionFormatDate           = "format-date"
	functionFormatTime           = "format-time"

	errCodeFOAY0001  = "FOAY0001"
	errCodeFOAY0002  = "FOAY0002"
	errCodeFOAR0001  = "FOAR0001"
	errCodeFOAR0002  = "FOAR0002"
	nameCodepointsAB = "AB"
	errCodeXPTY0117  = "XPTY0117"
	errCodeFOCH0001  = "FOCH0001"
	errCodeFOTY0013  = "FOTY0013"
	errCodeFOFD1340  = "FOFD1340"
	errCodeFOFD1350  = "FOFD1350"
	errCodeFOQM0006  = "FOQM0006"

	nameDecimalSeparator = "decimal-separator"
	nameInfinityProperty = "infinity"
	nameZeroDigit        = "zero-digit"
	namePositiveInfinity = "INF"
	namespaceVariables   = "urn:variables"
	name12Sum            = "(1,2)=>sum()"
	errCodeXPST0003      = "XPST0003"
	errCodeXPST0008      = "XPST0008"
	errCodeXPST0081      = "XPST0081"
	errCodeXPTY0004      = "XPTY0004"
	errCodeFORG0001      = "FORG0001"
	errCodeFODT0001      = "FODT0001"
	errCodeFODT0002      = "FODT0002"
	errCodeXPST0017      = "XPST0017"
	nameMatchesAbcAbC    = "matches('abc','(?:ab)c')"
)

func TestXPathCalendarOverflowCodes(t *testing.T) {
	e := engine(t, transform.Config{})
	for expression, code := range map[string]string{
		`xs:date('25252734927766555-07-28')`:                 errCodeFODT0001,
		`xs:date('-25252734927766555-06-07+02:00')`:          errCodeFODT0001,
		`xs:dateTime('18446744073709551616-05-15T16:15:00')`: errCodeFODT0001,
		`xs:gYear('99999999999999999999999999999')`:          errCodeFODT0001,
		`xs:gYearMonth('99999999999999999999999999999-01')`:  errCodeFODT0001,
		`xs:date('1000000001-02-29')`:                        errCodeFORG0001,
		`xs:dateTime('18446744073709551616-05-15T25:00:00')`: errCodeFORG0001,
		`xs:gYearMonth('99999999999999999999999999999-13')`:  errCodeFORG0001,
		`xs:date('00001000000001-01-01')`:                    errCodeFORG0001,
	} {
		_, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != code {
			t.Fatal(expression, err, code)
		}
	}

	for _, expression := range []string{`xs:date('999999999-12-31')`, `xs:date('-999999999-01-01')`, `xs:date('2000-02-29')`} {
		if _, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{}); err != nil {
			t.Fatal(expression, err)
		}
	}
}

func TestXPathFiniteDecimalDivision(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, expression := range []string{
			`1 div 3`,
			`-1 div 6`,
			`1 div 999999999999999999`,
			`xs:integer('10000000000000000000000000000000000000000') div 3`,
			`0.0000000000000000000000000000000000000001 div 3`,
			`avg((1,0,0))`,
			`xs:dayTimeDuration('PT1S') div xs:dayTimeDuration('PT3S')`,
			`xs:yearMonthDuration('P1M') div xs:yearMonthDuration('P3M')`,
		} {
			value, err := evaluate(t, e, expression, version).Single()
			if err != nil {
				t.Fatal(err)
			}

			number, err := value.Decimal()
			if err != nil {
				t.Fatal(expression, err)
			}

			if _, exact := number.FloatPrec(); !exact || number.Sign() == 0 {
				t.Fatalf("XPath %d %s: non-finite or lost decimal %s", version, expression, number)
			}

			check := `for $v in (` + expression + `) return $v eq xs:decimal(string($v))`
			if got := text(t, evaluate(t, e, check, version)); got != nameTrue {
				t.Fatalf("XPath %d %s: decimal serialization changed its value", version, expression)
			}
		}

		for expression, want := range map[string]string{
			`1 div 8`:                   "0.125",
			`1 div 999999999999999999`:  "0.000000000000000001000000000000000001",
			`-1 div 999999999999999999`: "-0.000000000000000001000000000000000001",
		} {
			if got := text(t, evaluate(t, e, expression, version)); got != want {
				t.Fatalf("XPath %d %s: %q, want %q", version, expression, got, want)
			}
		}
	}
}

func TestXPathFiniteDurationDivision(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, expression := range []string{
			`xs:dayTimeDuration('PT1S') div 3`,
			`xs:dayTimeDuration('-PT1S') div 3`,
			`xs:dayTimeDuration('PT0.0000000000000000000000000000000000000001S') div 3`,
			`avg((xs:dayTimeDuration('PT1S'),xs:dayTimeDuration('PT0S'),xs:dayTimeDuration('PT0S')))`,
		} {
			check := `for $v in (` + expression + `) return $v eq xs:dayTimeDuration(string($v)) and $v ne xs:dayTimeDuration('PT0S')`
			if got := text(t, evaluate(t, e, check, version)); got != nameTrue {
				t.Fatal(version, expression, got)
			}
		}
	}
}

func TestXPathMultilineFinalNewline(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for expression, want := range map[string]string{
			`matches(codepoints-to-string(10), '^$', 'm')`:                      nameTrue,
			`matches(concat('line', codepoints-to-string(10)), '^$', 'm')`:      nameFalse,
			`matches(concat('line', codepoints-to-string((10,10))), '^$', 'm')`: nameTrue,
			`matches(concat('line', codepoints-to-string(10)), '$', 'm')`:       nameTrue,
			`matches('', '^$', 'm')`:                                            nameTrue,
		} {
			if got := text(t, evaluate(t, e, expression, version)); got != want {
				t.Fatalf("XPath %d %s: %q, want %q", version, expression, got, want)
			}
		}
	}
}

func TestXPathXMLSchemaEditions(t *testing.T) {
	for _, edition := range []transform.XMLSchemaVersion{transform.XMLSchema10, transform.XMLSchema11} {
		e := engine(t, transform.Config{XMLSchemaVersion: edition})
		for _, tc := range []struct{ expression, modern, legacyCode string }{
			{`xs:double('+INF')`, namePositiveInfinity, errCodeFORG0001},
			{`xs:float('+INF')`, namePositiveInfinity, errCodeFORG0001},
			{`xs:double#1('+INF')`, namePositiveInfinity, errCodeFORG0001},
			{`'+INF' cast as xs:double`, namePositiveInfinity, errCodeFORG0001},
			{`xs:date('0000-01-01')`, "0000-01-01", errCodeFORG0001},
			{`xs:dateTime('0000-01-01T00:00:00')`, "0000-01-01T00:00:00", errCodeFORG0001},
			{`xs:gYear('0000')`, "0000", errCodeFORG0001},
			{`xs:gYearMonth('-0000-01')`, "0000-01", errCodeFORG0001},
			{`xs:anyURI('%gg')`, "%gg", errCodeFORG0001},
			{`xs:anyURI(':/relative')`, ":/relative", errCodeFORG0001},
			{`sum((xs:untypedAtomic('+INF'),1))`, namePositiveInfinity, errCodeFORG0001},
			{`sum(xs:untypedAtomic('+INF'))`, namePositiveInfinity, errCodeFORG0001},
			{`avg((xs:untypedAtomic('+INF'),1))`, namePositiveInfinity, errCodeFORG0001},
			{`max((xs:untypedAtomic('+INF'),1))`, namePositiveInfinity, errCodeFORG0001},
			{`min(xs:untypedAtomic('+INF'))`, namePositiveInfinity, errCodeFORG0001},
			{`math:exp(xs:untypedAtomic('+INF'))`, namePositiveInfinity, errCodeFORG0001},
			{`substring('abc',xs:untypedAtomic('+INF'))`, "", errCodeFORG0001},
			{`xs:untypedAtomic('+INF') + 1`, namePositiveInfinity, errCodeFORG0001},
			{`xs:untypedAtomic('+INF') = xs:double('INF')`, nameTrue, errCodeFORG0001},
			{`matches('-', '[a-c-1-4x-z-7-9]')`, nameTrue, "FORX0002"},
			{`matches('-', '[a-Ö-x]')`, nameTrue, "FORX0002"},
		} {
			value, err := query(t, e, tc.expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
			if edition == transform.XMLSchema10 {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != tc.legacyCode {
					t.Errorf("XSD 1.0 %s: %v, %v", tc.expression, value, err)
				}
			} else if err != nil || text(t, value) != tc.modern {
				t.Errorf("XSD 1.1 %s: %v, %v; want %q", tc.expression, value, err, tc.modern)
			}
		}

		for _, expression := range []string{
			`matches('-', '[a-z-]')`, `matches('-', '[-a-z]')`, `matches('-', '[a-z\-0-9]')`,
			`matches('b', '[a-z-[aeiou]]')`, `matches('[a-z-x]', '[a-z-x]', 'q')`,
			`xs:anyURI(' https://example.test/%20 ') eq xs:anyURI('https://example.test/%20')`,
			`xs:date('2000-02-29') eq xs:date('2000-02-29')`,
		} {
			if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != nameTrue {
				t.Fatal(edition, expression, got)
			}
		}

		wantNumber := namePositiveInfinity
		if edition == transform.XMLSchema10 {
			wantNumber = valueNaN
		}

		if got := text(t, evaluate(t, e, `number('+INF')`, transform.XPath31)); got != wantNumber {
			t.Fatal(edition, "number", got)
		}
	}

	if _, err := transform.NewEngine(transform.Config{XMLSchemaVersion: 99}); !errors.Is(err, transform.ErrInput) {
		t.Fatal("invalid datatype edition", err)
	}
}

func TestXPathFunctionRetainsDatatypeEdition(t *testing.T) {
	for _, edition := range []transform.XMLSchemaVersion{transform.XMLSchema10, transform.XMLSchema11} {
		owner := engine(t, transform.Config{XMLSchemaVersion: edition})
		for _, source := range []string{`xs:double#1`, `function($s){xs:double($s)}`, `function-lookup(xs:QName('xs:double'),1)`, `xs:double(?)`} {
			function := evaluate(t, owner, source, transform.XPath31)

			other := transform.XMLSchema10
			if edition == transform.XMLSchema10 {
				other = transform.XMLSchema11
			}

			caller := engine(t, transform.Config{XMLSchemaVersion: other})

			result, err := query(t, caller, `$convert('+INF')`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "convert"}: function}})
			if edition == transform.XMLSchema10 {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != errCodeFORG0001 {
					t.Fatal(edition, source, result, err)
				}
			} else if err != nil || text(t, result) != namePositiveInfinity {
				t.Fatal(edition, source, result, err)
			}
		}
	}
}

func TestXPathDurationOverflowCodes(t *testing.T) {
	e := engine(t, transform.Config{})
	for expression, code := range map[string]string{
		`xs:duration('P768614336404564651Y')`:                       errCodeFODT0002,
		`xs:duration('-P768614336404564651Y')`:                      errCodeFODT0002,
		`xs:yearMonthDuration('P99999999999999999999999999999M')`:   errCodeFODT0002,
		`xs:duration('P768614336404564650Y11M')`:                    errCodeFODT0002,
		`xs:duration('P99999999999999999999999999999Y1Y')`:          errCodeFORG0001,
		`xs:yearMonthDuration('P99999999999999999999999999999Y1D')`: errCodeFORG0001,
		`xs:dayTimeDuration('P99999999999999999999999999999Y')`:     errCodeFORG0001,
		`xs:dayTimeDuration('P0Y1D')`:                               errCodeFORG0001,
		`xs:dayTimeDuration('P0M')`:                                 errCodeFORG0001,
		`xs:yearMonthDuration('P1Y0D')`:                             errCodeFORG0001,
		`xs:yearMonthDuration('P1YT0S')`:                            errCodeFORG0001,
	} {
		_, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != code {
			t.Fatal(expression, err, code)
		}
	}
}

func TestXPathDurationCanonicalFormatting(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct{ expression, want string }{
		{`string(xs:duration('P14M1DT25H61M1.2300S'))`, "P1Y2M2DT2H1M1.23S"},
		{`string(xs:duration('-P1Y2M3DT4H5M6.0000012300S'))`, "-P1Y2M3DT4H5M6.00000123S"},
		{`string(xs:duration('PT0S'))`, "PT0S"},
		{`string(xs:yearMonthDuration('P0M'))`, "P0M"},
		{`string(xs:yearMonthDuration('-P25M'))`, "-P2Y1M"},
		{`string(xs:dayTimeDuration('PT86400.000000001S'))`, "P1DT0.000000001S"},
		{`string(xs:dayTimeDuration('P100000000000000000000D'))`, "P100000000000000000000D"},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			if got := text(t, evaluate(t, e, tc.expression, transform.XPath31)); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestXPathURIEscapeBytes(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct{ expression, want string }{
		{`encode-for-uri('~é/😀')`, "~%C3%A9%2F%F0%9F%98%80"},
		{`iri-to-uri('https://example.test/é%2F?q=a b#😀')`, "https://example.test/%C3%A9%2F?q=a%20b#%F0%9F%98%80"},
		{`escape-html-uri('é/&%2F')`, "%C3%A9/&%2F"},
		{`escape-html-uri(codepoints-to-string((127, 159)))`, "%7F%C2%9F"},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			if got := text(t, evaluate(t, e, tc.expression, transform.XPath31)); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestXPathCalendarFormattingSignatures(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, expression := range []string{
		`format-date('2026-01-01', '[Y]')`,
		`format-dateTime('abc', '[Y]')`,
		`format-time('12:00:00', '[H]')`,
		`format-date((xs:date('2026-01-01'), xs:date('2026-01-02')), '[Y]')`,
		`format-date#2('2026-01-01', '[Y]')`,
	} {
		_, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != errCodeXPTY0004 {
			t.Fatal(expression, err)
		}
	}

	for _, expression := range []string{
		`empty(format-date((), '[Y]'))`,
		`empty(format-time((), '[H]'))`,
		`format-date(xs:untypedAtomic('2026-01-01'), '[Y]') = '2026'`,
		`empty(function-lookup(xs:QName('fn:format-date'), 3))`,
		`empty(function-lookup(xs:QName('fn:format-time'), 4))`,
	} {
		if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != nameTrue {
			t.Fatal(expression, got)
		}
	}
}

func TestXPathStaticDecimalFormats(t *testing.T) {
	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			e := engine(t, transform.Config{})
			formats := map[transform.Name]map[string]string{
				{}:                                     {nameDecimalSeparator: ",", "grouping-separator": "."},
				{Space: "urn:format", Local: "signed"}: {nameDecimalSeparator: "!", "grouping-separator": ".", "minus-sign": "_", valueNaN: ""},
			}
			options := transform.XPathOptions{Version: version, DecimalFormats: formats}

			program, err := e.CompileXPath(t.Context(), `format-number(1234.5, '#.##0,00') || '|' || format-number(-1.5, '0!0', 'Q{urn:format}signed') || format-number(xs:double('NaN'), '0', 'Q{urn:format}signed')`, options)
			if err != nil {
				t.Fatal(err)
			}

			formats[transform.Name{}][nameDecimalSeparator] = "."
			formats[transform.Name{Space: "urn:format", Local: "signed"}]["minus-sign"] = "caller mutation"
			clear(formats)

			value, err := program.Evaluate(t.Context(), nil, transform.XPathContext{})
			if err != nil || text(t, value) != "1.234,50|_1!5" {
				t.Fatal("compiled formats did not retain an independent static context", value, err)
			}
		})
	}

	e := engine(t, transform.Config{})
	for _, properties := range []map[string]string{
		{"unknown": "x"},
		{nameDecimalSeparator: ""},
		{"digit": "two"},
		{nameZeroDigit: "1"},
		{nameDecimalSeparator: ","},
		{"digit": "1"},
		{valueNaN: "\xff"},
	} {
		_, err := e.CompileXPath(t.Context(), "1", transform.XPathOptions{DecimalFormats: map[transform.Name]map[string]string{{}: properties}})
		if !errors.Is(err, transform.ErrInput) {
			t.Fatal("invalid decimal-format properties accepted", properties, err)
		}
	}

	for _, version := range []transform.XPathVersion{transform.XPath10, transform.XPath20} {
		_, err := e.CompileXPath(t.Context(), "1", transform.XPathOptions{Version: version, DecimalFormats: map[transform.Name]map[string]string{{}: {}}})
		if !errors.Is(err, transform.ErrUnsupported) {
			t.Fatal("decimal formats accepted by an earlier XPath version", version, err)
		}
	}

	bounded := engine(t, transform.Config{Limits: transform.Limits{MaxProgramBytes: 16}})

	_, err := bounded.CompileXPath(t.Context(), "1", transform.XPathOptions{DecimalFormats: map[transform.Name]map[string]string{{}: {nameInfinityProperty: strings.Repeat("x", 17)}}})
	if !errors.Is(err, transform.ErrLimit) {
		t.Fatal("static decimal formats escaped the program budget", err)
	}
}

func TestDecimalFormatUnicodeDigitsAcrossPaths(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, zero := range []rune{'0', '\u0660', '\U0001d7d8', '\U0001d7ec'} {
		picture, expected := string(zero), string(zero+2)

		program, err := e.CompileXPath(t.Context(), "format-number(2, '"+picture+"')", transform.XPathOptions{DecimalFormats: map[transform.Name]map[string]string{{}: {nameZeroDigit: picture}}})
		if err != nil {
			t.Fatal(err)
		}

		value, err := program.Evaluate(t.Context(), nil, transform.XPathContext{})
		if err != nil || text(t, value) != expected {
			t.Fatal("XPath digit alphabet", picture, value, err)
		}

		sheet := stylesheet(t, e, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:decimal-format zero-digit="`+picture+`"/><xsl:template name="start"><xsl:value-of select="format-number(2, '`+picture+`')"/></xsl:template></xsl:stylesheet>`)

		result, err := sheet.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
		if err != nil || text(t, result.Primary()) != expected {
			t.Fatal("XSLT digit alphabet", picture, result, err)
		}

		_, err = e.CompileXPath(t.Context(), "1", transform.XPathOptions{DecimalFormats: map[transform.Name]map[string]string{{}: {nameZeroDigit: string(zero + 1)}}})
		if !errors.Is(err, transform.ErrInput) {
			t.Fatal("a nonzero Nd digit was accepted as zero-digit", zero+1, err)
		}
	}
}

func TestXPathVersions(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, v := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for source, want := range map[string]string{
			`sum(for $n in 1 to 10 return $n*$n)`:                                       "385",
			`some $n in (1,2,3) satisfies $n eq 2`:                                      nameTrue,
			`xs:decimal('0.1')+xs:decimal('0.2')`:                                       name03,
			`if (xs:decimal('0.1')+xs:decimal('0.2') eq 0.3) then 'exact' else 'wrong'`: "exact",
			`string-join(tokenize('a:b:c', ':'), ',')`:                                  "a,b,c",
			`matches('ab','a(b)')`:                                                      nameTrue,
		} {
			if got := text(t, evaluate(t, e, source, v)); got != want {
				t.Errorf("%v %s: %s", v, source, got)
			}
		}
	}

	for source, want := range map[string]string{
		`let $n := 5 return $n || '!'`:                "5!",
		`sum((1,2,3) ! (. * .))`:                      "14",
		`fold-left((1,2,3),0,function($a,$b){$a+$b})`: "6",
		`string-join(('a','b'))`:                      "ab",
		nameMatchesAbcAbC:                             nameTrue,
	} {
		for _, v := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
			if got := text(t, evaluate(t, e, source, v)); got != want {
				t.Errorf("%v %s = %s", v, source, got)
			}
		}
	}

	for source, want := range map[string]string{
		`map{'a':[1,2,3]}?a?2`:                "2",
		`parse-json('{"price":12.50}')?price`: "12.5",
		`(1,2,3) => sum()`:                    "6",
		`array:size(array {1 to 3})`:          "3",
	} {
		if got := text(t, evaluate(t, e, source, transform.XPath31)); got != want {
			t.Errorf("%s=%s", source, got)
		}
	}
}

func TestXPathCompatibilityProperty(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for expression, want := range map[string]string{
			`1 + '2'`:                        "3",
			`string-length(('ab','longer'))`: "2",
			`concat('x',('a','b'))`:          "xa",
			`substring('abcdef','2')`:        "bcdef",
		} {
			for _, compatible := range []bool{false, true} {
				q, err := e.CompileXPath(t.Context(), expression, transform.XPathOptions{Version: version, XPath10Compatibility: compatible})
				if err != nil {
					t.Fatal(version, expression, err)
				}

				value, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
				if compatible {
					if err != nil || text(t, value) != want {
						t.Fatal(version, expression, value, err)
					}
				} else {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != errCodeXPTY0004 {
						t.Fatal(version, expression, err)
					}
				}
			}
		}
	}
}

func TestXPathFunctionRetainsCompatibility(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, compatible := range []bool{false, true} {
		owner, err := e.CompileXPath(t.Context(), `function(){1+'2'}`, transform.XPathOptions{XPath10Compatibility: compatible})
		if err != nil {
			t.Fatal(err)
		}

		function, err := owner.Evaluate(t.Context(), nil, transform.XPathContext{})
		if err != nil {
			t.Fatal(err)
		}

		caller, err := e.CompileXPath(t.Context(), `$invoke()`, transform.XPathOptions{XPath10Compatibility: !compatible})
		if err != nil {
			t.Fatal(err)
		}

		value, err := caller.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "invoke"}: function}})
		if compatible {
			if err != nil || text(t, value) != "3" {
				t.Fatal(value, err)
			}
		} else {
			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXPTY0004 {
				t.Fatal(err)
			}
		}
	}
}

func TestGreekAlphabeticNumbering(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for expression, want := range map[string]string{
			`string-join((17,18,19,23,24,25,600,601)!format-integer(.,'α'),' ')`: "ρ σ τ ψ ω αα ωω ααα",
			`string-join((17,18,19,23,24,25,600,601)!format-integer(.,'Α'),' ')`: "Ρ Σ Τ Ψ Ω ΑΑ ΩΩ ΑΑΑ",
		} {
			if got := text(t, evaluate(t, e, expression, version)); got != want {
				t.Fatal(version, expression, got, want)
			}
		}
	}

	for _, version := range []string{version20, version30} {
		body := `<xsl:output method="text"/><xsl:template name="start"><xsl:for-each select="(17,18,19,23,24,25,600,601)"><xsl:if test="position() gt 1"><xsl:text> </xsl:text></xsl:if><xsl:number value="." format="α"/></xsl:for-each></xsl:template>`
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, sheet(version, body), nested)
			if err != nil || got != "ρ σ τ ψ ω αα ωω ααα" {
				t.Fatal(version, nested, got, err)
			}
		}
	}
}

func TestXPathSyntaxErrorCodes(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, source := range []string{
			"1 +", "$", "'unterminated", "1 ; 2", "sum(1", "unknown-axis::node()", "1e", "1E+", "1e-",
			"text(*)", "comment(*)", "node(*)", "processing-instruction(*)", "() instance of empty-sequence(1)",
			"p: local", "p(:comment:):local", "p:(:comment:)local", "p: *", "*: local", "* :local",
			"*(:comment:):local", "*:(:comment:)local", "fn: true()", "fn(:comment:):true()", "fn:(:comment:)true()",
		} {
			_, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{Version: version})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXPST0003 {
				t.Errorf("XPath %d %q: %v", version, source, err)
			}
		}
	}
}

func TestXPathQNameBoundaries(t *testing.T) {
	e := engine(t, transform.Config{})

	doc, err := e.Parse(t.Context(), []byte(`<r xmlns:p="urn:test"><p:local/><p:function/><p:map/><other/></r>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, source := range []string{
			`count(/r/p:*) = 3`, `count(/r/*:local) = 1`, `count(/r/*:function) = 1`,
			`count(/r/*:map) = 1`, `count(/r/p:local (:comment:)) = 1`,
			`map { 'key' : true() }?key`,
			`map { r: true() }('')`, `map { r(:comment:):true() }('')`,
			`map { r:(:comment:)true() }('')`,
		} {
			if version < transform.XPath31 && strings.HasPrefix(source, "map ") {
				continue
			}

			program, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{
				Version: version, Namespaces: map[string]string{"p": "urn:test"},
			})
			if err != nil {
				t.Fatal(source, err)
			}

			result, err := program.Evaluate(t.Context(), doc, transform.XPathContext{})
			if err != nil || text(t, result) != nameTrue {
				t.Errorf("XPath %d %s: %v, %v", version, source, result, err)
			}
		}
	}
}

func TestXPathContextualKeywords(t *testing.T) {
	e := engine(t, transform.Config{})

	doc, err := e.Parse(t.Context(), []byte(contextualKeywordXML()))
	if err != nil {
		t.Fatal(err)
	}

	root, err := query(t, e, `/r`, transform.XPath31).Evaluate(t.Context(), doc, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}

	contextItem, err := root.Single()
	if err != nil {
		t.Fatal(err)
	}

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, keyword := range []string{"for", "let", "some", "every", "if", "try", "map", "array"} {
			program := query(t, e, `count(`+keyword+`)`, version)

			value, err := program.Evaluate(t.Context(), nil, transform.XPathContext{ContextItem: contextItem})
			if err != nil || text(t, value) != "1" {
				t.Errorf("XPath %d %s: %v, %v", version, keyword, value, err)
			}

			_, err = query(t, e, keyword, version).Evaluate(t.Context(), nil, transform.XPathContext{})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != "XPDY0002" {
				t.Errorf("XPath %d %s without focus: %v", version, keyword, err)
			}
		}
	}

	namespaces := map[string]string{}
	for _, keyword := range contextualOperatorKeywords() {
		namespaces[keyword] = "http://www.w3.org/2005/xpath-functions"
	}
	for _, test := range contextualKeywordOperandCases() {
		for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
			program, err := e.CompileXPath(t.Context(), test.expression, transform.XPathOptions{Version: version, Namespaces: namespaces})
			if err != nil {
				t.Fatal(test.expression, err)
			}
			value, err := program.Evaluate(t.Context(), nil, transform.XPathContext{ContextItem: contextItem})
			if err != nil || text(t, value) != test.want {
				t.Errorf("XPath %d %s: %v, %v; want %s", version, test.expression, value, err, test.want)
			}
		}
	}
}

func contextualOperatorKeywords() []string {
	return []string{"and", "or", "div", "mod", "idiv", "eq", "ne", "lt", "le", "gt", "ge", "is", "to", "union", "intersect", "except", "instance", "treat", "cast", "castable", "as", "of", "in", "return", "satisfies", "then", "else", "where", "by", "ascending", "descending", "stable"}
}

func contextualKeywordXML() string {
	var xml strings.Builder
	xml.WriteString("<r><for/><let/><some/><every/><if/><try/><map/><array/>")
	for _, keyword := range contextualOperatorKeywords() {
		xml.WriteString("<" + keyword + ">2</" + keyword + ">")
	}
	xml.WriteString("</r>")
	return xml.String()
}

func contextualKeywordOperandCases() []struct{ expression, want string } {
	cases := make([]struct{ expression, want string }, 0, 2*len(contextualOperatorKeywords())+12)
	for _, keyword := range contextualOperatorKeywords() {
		// The preceding '*' is multiplication, so the following keyword is
		// an operand's name. Prefixes and names use the same grammar rule.
		cases = append(cases, struct{ expression, want string }{`6 * ` + keyword, "12"})
		cases = append(cases, struct{ expression, want string }{`6 * ` + keyword + `:abs(-2)`, "12"})
	}
	cases = append(cases,
		struct{ expression, want string }{`6 * *:div`, "12"},
		struct{ expression, want string }{`6 * div[1]`, "12"},
		struct{ expression, want string }{`6 * div * mod`, "24"},
		struct{ expression, want string }{`div * mod div 2`, "2"},
		struct{ expression, want string }{`*[name() eq 'div'] div 2`, "1"},
		struct{ expression, want string }{`1 instance of xs:integer* and 2 eq 2`, nameTrue},
		struct{ expression, want string }{`(1 treat as xs:integer*) eq 1`, nameTrue},
		struct{ expression, want string }{`for $x in div return $x * mod`, "4"},
		struct{ expression, want string }{`for $x in 6 * div return $x`, "12"},
		struct{ expression, want string }{`6 * div eq 12 and 6 * mod eq 12`, nameTrue},
		struct{ expression, want string }{`(6 * div) instance of xs:double`, nameTrue},
		struct{ expression, want string }{`if (6 * div) then 6 * mod else 0`, "12"},
	)
	return cases
}

func TestXPathTypeNamespaceResolution(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, tc := range []struct {
			source string
			ns     map[string]string
			code   string
		}{
			{`() instance of none`, nil, errCodeXPST0051},
			{`1 instance of integer`, nil, errCodeXPST0051},
			{`1 instance of xs:integer`, map[string]string{"xs": namespaceCustom}, errCodeXPST0051},
			{`1 instance of t:unknown`, map[string]string{"t": namespaceSchema}, errCodeXPST0051},
			{`1 instance of t:integer`, nil, "XPST0081"},
			{`1 instance of t:integer`, map[string]string{"t": namespaceSchema}, ""},
			{`1 instance of integer`, map[string]string{"": namespaceSchema}, ""},
			{`codepoints-to-string(65) eq 'A'`, map[string]string{"xs": namespaceCustom}, ""},
			{`contains('abc','a')`, map[string]string{"xs": namespaceCustom}, ""},
		} {
			program, err := e.CompileXPath(t.Context(), tc.source, transform.XPathOptions{Version: version, Namespaces: tc.ns})
			if tc.code != "" {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != tc.code {
					t.Errorf("XPath %d %s: %v; want %s", version, tc.source, err, tc.code)
				}

				continue
			}

			if err != nil {
				t.Fatal(tc.source, err)
			}

			value, err := program.Evaluate(t.Context(), nil, transform.XPathContext{})
			if err != nil || text(t, value) != nameTrue {
				t.Errorf("XPath %d %s: %v, %v", version, tc.source, value, err)
			}
		}
	}

	for _, source := range []string{
		`codepoints-to-string#1(65) eq 'A'`,
		`function-lookup(QName('http://www.w3.org/2005/xpath-functions','codepoints-to-string'),1)(65) eq 'A'`,
		`codepoints-to-string#1 instance of function(Q{http://www.w3.org/2001/XMLSchema}integer*) as Q{http://www.w3.org/2001/XMLSchema}string`,
	} {
		program, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{Version: transform.XPath31, Namespaces: map[string]string{"xs": namespaceCustom}})
		if err != nil {
			t.Fatal(source, err)
		}

		value, err := program.Evaluate(t.Context(), nil, transform.XPathContext{})
		if err != nil || text(t, value) != nameTrue {
			t.Fatal("caller namespace changed a standard function signature", source, value, err)
		}
	}
}

func TestXPathEQNameGrammar(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for _, source := range []string{
			`Q{{urn:test}local`, `Q{urn:test`, `Q{urn:test}1local`, `Q{urn:test}`,
			`$Q{{urn:test}local`, `$Q{urn:test`, `$Q{urn:test}*`,
			`1 instance of Q{{urn:test}integer`, `Q{{urn:test}true()`,
		} {
			_, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{Version: version})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXPST0003 {
				t.Errorf("XPath %d %s: %v", version, source, err)
			}
		}

		for _, source := range []string{
			`Q{http://www.w3.org/2000/xmlns/}local`, `$Q{http://www.w3.org/2000/xmlns/}v`,
			`Q{http://www.w3.org/2000/xmlns/}f()`, `1 instance of Q{http://www.w3.org/2000/xmlns/}t`,
		} {
			_, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{Version: version})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXQST0070 {
				t.Errorf("XPath %d reserved EQName %s: %v", version, source, err)
			}
		}

		for _, source := range []string{
			`Q{http://www.w3.org/2005/xpath-functions}true()`,
			`1 instance of Q{http://www.w3.org/2001/XMLSchema}integer`,
			`count(parse-xml('<r xmlns:p="urn:p"><p:a/></r>')/r/Q{ urn:p }*) = 1`,
			`let $Q{}v := 1 return $Q{}v = 1`,
		} {
			if got := text(t, evaluate(t, e, source, version)); got != nameTrue {
				t.Errorf("XPath %d %s = %s", version, source, got)
			}
		}
	}
}

func TestXPathReservedFunctionNames(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, source := range []string{"function()", "namespace-node(1)", "namespace-node()"} {
		_, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{Version: transform.XPath20})
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != errCodeXPST0017 {
			t.Errorf("XPath 2.0 %s: %v", source, err)
		}
	}

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for _, name := range []string{"attribute", "comment", "document-node", "element", "empty-sequence", "function", "if", nameItem, "namespace-node", "node", "processing-instruction", "schema-attribute", "schema-element", "switch", serializationText, "typeswitch"} {
			_, err := e.CompileXPath(t.Context(), name+"#0", transform.XPathOptions{Version: version})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXPST0003 {
				t.Errorf("XPath %d %s: %v", version, name, err)
			}
		}
	}

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		if got := text(t, evaluate(t, e, `fn:true#0()`, version)); got != nameTrue {
			t.Fatal("permitted function reference", got)
		}

		for _, name := range []string{"array", "map"} {
			for _, suffix := range []string{"#0", "()"} {
				_, err := e.CompileXPath(t.Context(), name+suffix, transform.XPathOptions{Version: version})

				want := errCodeXPST0017
				if version == transform.XPath31 {
					want = errCodeXPST0003
				}

				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != want {
					t.Errorf("XPath %d %s%s: %v", version, name, suffix, err)
				}
			}
		}
	}
}

func TestXPathInlineFunctionBody(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		_, err := e.CompileXPath(t.Context(), `function(){}()`, transform.XPathOptions{Version: version})
		if version == transform.XPath30 {
			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXPST0003 {
				t.Fatal("empty body in XPath 3.0", err)
			}
		} else if err != nil {
			t.Fatal("empty body in XPath 3.1", err)
		}

		if got := text(t, evaluate(t, e, `count(function(){()}())`, version)); got != "0" {
			t.Fatal("explicit empty sequence body", got)
		}
	}
}

func TestXPathVariableScope(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		options := transform.XPathOptions{Version: version, Namespaces: map[string]string{
			"p": namespaceVariables, "q": namespaceVariables, "": "urn:elements",
		}}
		for _, source := range []string{
			`$missing`, `some $x in () satisfies $missing`, `every $x in () satisfies $missing`,
			`false() and $missing`, `if (true()) then 1 else $missing`,
			`(for $x in 1 return $x), $x`, `for $x in $x return $x`,
		} {
			program, err := e.CompileXPath(t.Context(), source, options)
			if err != nil {
				t.Fatal(source, err)
			}

			_, err = program.Evaluate(t.Context(), nil, transform.XPathContext{})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXPST0008 {
				t.Errorf("XPath %d %s: %v", version, source, err)
			}
		}

		for _, test := range []struct{ source, want string }{
			{`for $p:x in 1 return $q:x`, "1"},
			{`count($empty)`, "0"},
			{`sum(for $p:x in 1 return ((for $q:x in 2 return $p:x), $p:x))`, "3"},
			{`sum(((for $x in 1 return $x), $x))`, "11"},
			{`$p:x + $q:x`, "14"},
			{`some $p:x in 1 satisfies $q:x = 1`, nameTrue},
		} {
			program, err := e.CompileXPath(t.Context(), test.source, options)
			if err != nil {
				t.Fatal(test.source, err)
			}

			result, err := program.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
				{Local: "x"}:                            transform.Values(transform.Integer(10)),
				{Local: "empty"}:                        transform.Values(),
				{Space: namespaceVariables, Local: "x"}: transform.Values(transform.Integer(7)),
			}})
			if err != nil || text(t, result) != test.want {
				t.Errorf("XPath %d %s: %v, %v", version, test.source, result, err)
			}
		}
	}

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for _, source := range []string{
			`for $Q{urn:variables}x in 1 return $q:x`,
			`for $q:x in 1 return $Q{urn:variables}x`,
			`function($p:x){$q:x}(1)`,
			`for $Q{}x in 1 return $x`, `$Q{}x`,
		} {
			program, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{
				Version:    version,
				Namespaces: map[string]string{"p": namespaceVariables, "q": "urn:variables"},
			})
			if err != nil {
				t.Fatal(source, err)
			}

			result, err := program.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
				{Local: "x"}: transform.Values(transform.Integer(1)),
			}})
			if err != nil || text(t, result) != "1" {
				t.Errorf("XPath %d %s: %v, %v", version, source, result, err)
			}
		}
	}
}

func TestXPathNodeContextErrors(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, source := range []string{`local-name()`, `namespace-uri()`, `name()`, `root()`, `base-uri()`} {
		for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
			program := query(t, e, source, version)
			for _, test := range []struct {
				item transform.Value
				code string
			}{
				{transform.Value{}, "XPDY0002"}, {transform.Integer(1), errCodeXPTY0004},
			} {
				_, err := program.Evaluate(t.Context(), nil, transform.XPathContext{ContextItem: test.item})

				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.code {
					t.Errorf("XPath %d %s: %v", version, source, err)
				}
			}
		}
	}
}

func TestXPathInlineParameterNames(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		options := transform.XPathOptions{
			Version:    version,
			Namespaces: map[string]string{"p": "urn:parameters", "q": "urn:parameters"},
		}
		for _, source := range []string{
			`function($p:x,$q:x){$p:x}`, `function($Q{}x,$x){$x}`,
			`function($Q{urn:parameters}x,$q:x){$q:x}`,
		} {
			_, err := e.CompileXPath(t.Context(), source, options)

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != "XQST0039" {
				t.Errorf("XPath %d %s: %v", version, source, err)
			}
		}

		program, err := e.CompileXPath(t.Context(), `function($p:x,$x){$p:x+$x}(1,2)`, options)
		if err != nil {
			t.Fatal(err)
		}

		result, err := program.Evaluate(t.Context(), nil, transform.XPathContext{})
		if err != nil || text(t, result) != "3" {
			t.Fatal("distinct expanded parameter names", result, err)
		}
	}
}

func TestXPathStaticNamespaceAndSchemaErrors(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, test := range []struct{ source, code string }{
			{`schema-element()`, errCodeXPST0003},
			{`schema-attribute()`, errCodeXPST0003},
			{`schema-element(missing)`, errCodeXPST0008},
			{`()/schema-attribute(missing)`, errCodeXPST0008},
			{`document-node(schema-element(missing))`, errCodeXPST0008},
			{`@xmlns:*`, errCodeXPST0081},
			{`@xmlns:local`, errCodeXPST0081},
			{`@p:local`, errCodeXPST0081},
			{"1\u00a0+ 2", errCodeXPST0003},
			{"1\u0085+ 2", errCodeXPST0003},
			{"1\u2003+ 2", errCodeXPST0003},
			{`() instance of xs: integer`, errCodeXPST0003},
		} {
			_, err := e.CompileXPath(t.Context(), test.source, transform.XPathOptions{
				Version: version, Namespaces: map[string]string{"p": ""},
			})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != test.code {
				t.Errorf("XPath %d %s: %v", version, test.source, err)
			}
		}

		for _, namespaces := range []map[string]string{
			{"xml": "urn:wrong"},
			{"xmlns": "urn:wrong"},
			{"p": "http://www.w3.org/XML/1998/namespace"},
			{"p": "http://www.w3.org/2000/xmlns/"},
		} {
			_, err := e.CompileXPath(t.Context(), "1", transform.XPathOptions{Version: version, Namespaces: namespaces})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXQST0070 {
				t.Errorf("XPath %d reserved namespace binding %v: %v", version, namespaces, err)
			}
		}

		for _, source := range []string{`() / element(missing)`, `() / attribute(missing)`, "concat('a\u00a0', 'b')"} {
			if _, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{Version: version}); err != nil {
				t.Fatal("valid syntax", source, err)
			}
		}
	}
}

func TestJSONOptionConversionsAndCodes(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range []struct{ expression, want string }{
		{`parse-json('true', map{'liberal': xs:untypedAtomic('false')})`, nameTrue},
		{`parse-json('true', map{'escape': [true()]})`, nameTrue},
		{`string(json-to-xml('1', map{'escape': xs:untypedAtomic('true')}))`, "1"},
		{`xml-to-json(json-to-xml('1'), map{'indent': xs:untypedAtomic('false')})`, "1"},
		{`empty(json-to-xml((),map{'validate':true()}))`, nameTrue},
		{`string(json-to-xml('1',map{'validate':false()}))`, "1"},
		{`parse-json('"\u0000"', map{'fallback': function($s) as xs:string {'?'}})`, "?"},
		{`function-lookup(xs:QName('fn:parse-json'), 2)('true', map{'liberal': xs:untypedAtomic('false')})`, nameTrue},
	} {
		values, err := query(t, e, test.expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
		if err != nil || text(t, values) != test.want {
			t.Errorf("%s: %v, %v", test.expression, values, err)
		}
	}
	for _, call := range []string{`json-to-xml`, `(json-to-xml#2)`, `function-lookup(xs:QName('fn:json-to-xml'),2)`, `json-to-xml(?,?)`} {
		_, err := query(t, e, call+`('1',map{'validate':true()})`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "FOJS0004" {
			t.Fatal(call, err)
		}
	}

	for _, function := range []string{"parse-json", "json-to-xml"} {
		for _, test := range []struct{ options, code string }{
			{`map{'liberal': ()}`, errCodeXPTY0004},
			{`map{'escape': (true(), false())}`, errCodeXPTY0004},
			{`map{'liberal': 1}`, errCodeXPTY0004},
			{`map{'liberal': xs:untypedAtomic('maybe')}`, errCodeFORG0001},
			{`map{'duplicates': 1}`, errCodeXPTY0004},
			{`map{'duplicates': 'unknown'}`, "FOJS0005"},
			{`map{'fallback': ()}`, errCodeXPTY0004},
			{`map{'fallback': 42}`, errCodeXPTY0004},
			{`map{'fallback': function(){'x'}}`, errCodeXPTY0004},
			{`map{'escape': true(), 'fallback': function($s){'x'}}`, "FOJS0005"},
			{`map{'fallback': function($s) as xs:integer {1}}`, errCodeXPTY0004},
		} {
			for _, call := range []string{function, "(" + function + "#2)"} {
				source := call + `('"\u0000"', ` + test.options + `)`
				_, err := query(t, e, source, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.code {
					t.Errorf("%s: want %s, got %v", source, test.code, err)
				}
			}
		}
	}
}

func TestXPathLexicalCasts(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for source, want := range map[string]string{
			`1 castable as xs:error`:                                 nameFalse,
			`empty(() cast as xs:error?)`:                            nameTrue,
			`'0x1p0' castable as xs:double`:                          nameFalse,
			`'1_000' castable as xs:float`:                           nameFalse,
			`'Infinity' castable as xs:double`:                       nameFalse,
			`'nan' castable as xs:double`:                            nameFalse,
			`'1e400' castable as xs:double`:                          nameTrue,
			`string(xs:double('1e400'))`:                             namePositiveInfinity,
			`1e400`:                                                  namePositiveInfinity,
			`xs:float('1.00000005960464477539062500000000001') gt 1`: nameTrue,
			`string(xs:float('-1e400'))`:                             "-INF",
			`1 div xs:double('-1e-400')`:                             "-INF",
			`xs:double('  +.5e1  ')`:                                 "5",
			"'\u00a01\u00a0' castable as xs:integer":                 nameFalse,
			"'\u00851\u0085' castable as xs:double":                  nameFalse,
			"'\u00a01\u00a0' castable as xs:float":                   nameFalse,
			`xs:normalizedString('  x  ')`:                           "  x  ",
			"xs:normalizedString('\tx\n')":                           " x ",
			"xs:token('\u00a0 x \u00a0')":                            "\u00a0 x \u00a0",
		} {
			if got := text(t, evaluate(t, e, source, version)); got != want {
				t.Errorf("XPath %d %s: %q, want %q", version, source, got, want)
			}
		}
	}

	for _, source := range []string{`1 cast as xs:error`, `'value' cast as xs:error`, `xs:error(1)`, `xs:error#1('value')`} {
		_, err := query(t, e, source, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != errCodeFORG0001 {
			t.Fatal(source, err)
		}
	}
}

func TestNumericBudgetExactness(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 64 << 10}})
	want := new(big.Int).Lsh(big.NewInt(1), 4096)

	for _, initial := range []string{"2", "xs:decimal('2')", "xs:decimal('0.5')"} {
		t.Run(initial, func(t *testing.T) {
			value, err := evaluate(t, e, `fold-left(1 to 12, `+initial+`, function($a,$b){$a*$a})`, transform.XPath31).Single()
			if err != nil {
				t.Fatal(err)
			}

			if initial == "2" {
				got, err := value.Integer()
				if err != nil || got.Cmp(want) != 0 {
					t.Fatalf("integer mismatch: %v", err)
				}
			} else {
				got, err := value.Decimal()

				expected := new(big.Rat).SetInt(want)
				if initial == "xs:decimal('0.5')" {
					expected.Inv(expected)
				}

				if err != nil || got.Cmp(expected) != 0 {
					t.Fatalf("decimal mismatch: %v", err)
				}
			}
		})
	}
}

func TestIntegerMultiplicationBoundaries(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, a := range []int64{math.MinInt64, math.MinInt64 + 1, -3037000500, -1, 0, 1, 3037000500, math.MaxInt64} {
		for _, b := range []int64{math.MinInt64, -2, -1, 0, 1, 2, math.MaxInt64} {
			t.Run(fmt.Sprintf("%d/%d", a, b), func(t *testing.T) {
				source := fmt.Sprintf(`xs:integer('%d') * xs:integer('%d')`, a, b)
				result := evaluate(t, e, source, transform.XPath31)

				value, err := result.Single()
				if err != nil {
					t.Fatal(err)
				}

				got, err := value.Integer()

				want := new(big.Int).Mul(big.NewInt(a), big.NewInt(b))
				if err != nil || got.Cmp(want) != 0 {
					t.Fatalf("%s = %v (%v), want %s", source, got, err, want)
				}
			})
		}
	}
}

func TestIntegerMinimumMultiplication(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 64}})
	for _, source := range []string{`-1 * xs:integer("-9223372036854775808")`, `xs:integer("-9223372036854775808") * -1`} {
		t.Run(source, func(t *testing.T) {
			value, err := evaluate(t, e, source, transform.XPath31).Single()
			if err != nil {
				t.Fatal(err)
			}

			got, err := value.Integer()

			want := new(big.Int).Lsh(big.NewInt(1), 63)
			if err != nil || got.Cmp(want) != 0 {
				t.Fatalf("got %v (%v), want %s", got, err, want)
			}
		})
	}
}

func TestXPathXMLWhitespaceAndJSONNumbers(t *testing.T) {
	e := engine(t, transform.Config{})

	for source, want := range map[string]string{
		"contains-token('\u00a0x\u00a0', '\u00a0x\u00a0')": nameTrue,
		"contains-token('x', '\u00a0x\u00a0')":             nameFalse,
		"count(xs:NMTOKENS('a\u1680b'))":                   "1",
		"count(xs:NMTOKENS(' a\tb '))":                     "2",
		"'a\u00a0b' castable as xs:NMTOKENS":               nameFalse,
	} {
		if got := text(t, evaluate(t, e, source, transform.XPath31)); got != want {
			t.Errorf("%s: %q, want %q", source, got, want)
		}
	}

	for _, xml := range []string{
		`<number xmlns="http://www.w3.org/2005/xpath-functions">1e400</number>`,
		"<boolean xmlns='http://www.w3.org/2005/xpath-functions'>\u00a0true\u00a0</boolean>",
		"<null xmlns='http://www.w3.org/2005/xpath-functions'>\u00a0</null>",
	} {
		program := query(t, e, `xml-to-json(parse-xml($jsonSource))`, transform.XPath31)
		_, err := program.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
			{Local: "jsonSource"}: transform.Values(transform.String(xml)),
		}})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "FOJS0006" {
			t.Errorf("invalid XML representation of JSON %q: %v", xml, err)
		}
	}
}

func TestXPathIETFDateGrammar(t *testing.T) {
	e := engine(t, transform.Config{})
	for source, want := range map[string]string{
		`year-from-dateTime(parse-ietf-date('06 Jun 0070 07:29:35 GMT'))`:             "70",
		`year-from-dateTime(parse-ietf-date('06 Jun 70 07:29:35 GMT'))`:               "1970",
		"year-from-dateTime(parse-ietf-date('Wed,\n06\rJun\n1994\t07:29:35 GMT'))":    "1994",
		`timezone-from-dateTime(parse-ietf-date('06 Jun 1994 07:29:35 +0500 (EST)'))`: "PT5H",
	} {
		if got := text(t, evaluate(t, e, source, transform.XPath31)); got != want {
			t.Errorf("%s: %q, want %q", source, got, want)
		}
	}

	for _, source := range []string{
		"06 Jun 7 07:29:35 GMT", "06 Jun 12345 07:29:35 GMT",
		"06--Jun--1994 07:29:35 GMT", "06 Jun 1994 07:29:35 -05:::",
		"Wed , 06 Jun 1994 07:29:35 GMT", "06 Jun 1994 07:29:35 GMT(unknown)",
		"06 Jun 1994 07:29:35 +0500 (unknown)", "Jun 06 07:29:35 1994 GMT",
		"\u00a006 Jun 1994 07:29:35 GMT\u00a0",
	} {
		program := query(t, e, `parse-ietf-date($date)`, transform.XPath31)
		_, err := program.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
			{Local: "date"}: transform.Values(transform.String(source)),
		}})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "FORG0010" {
			t.Errorf("invalid IETF date %q: %v", source, err)
		}
	}
}

func TestVersionBoundaries(t *testing.T) {
	e := engine(t, transform.Config{})

	cases := []struct {
		source  string
		version transform.XPathVersion
		code    string
	}{
		{`let $x:=1 return $x`, transform.XPath20, errCodeXPST0003},
		{`1 || 2`, transform.XPath20, errCodeXPST0003},
		{`1 ! (. + 1)`, transform.XPath20, errCodeXPST0003},
		{`function($x){$x}(1)`, transform.XPath20, errCodeXPST0003},
		{`Q{http://www.w3.org/2005/xpath-functions}true()`, transform.XPath20, errCodeXPST0003},
		{`head((1,2))`, transform.XPath20, errCodeXPST0017},
		{`math:pow(2,3)`, transform.XPath20, errCodeXPST0017},
		{`map{'x':1}`, transform.XPath30, errCodeXPST0003},
		{`[1,2]`, transform.XPath30, errCodeXPST0003},
		{name12Sum, transform.XPath30, errCodeXPST0003},
		{`parse-json('{}')`, transform.XPath30, errCodeXPST0017},
		{`tokenize('a b')`, transform.XPath30, errCodeXPST0017},
		{`try {1} catch * {2}`, transform.XPath31, errCodeXPST0003},
		{`for $v at $i in 1 to 2 return $i`, transform.XPath31, errCodeXPST0003},
	}
	for _, c := range cases {
		_, err := e.CompileXPath(context.Background(), c.source, transform.XPathOptions{Version: c.version})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != c.code {
			t.Errorf("%s (%v): %v", c.source, c.version, err)
		}
	}

	for _, source := range []string{nameMatchesAbcAbC, `matches('a.c','a.c','q')`} {
		_, err := query(t, e, source, transform.XPath20).Evaluate(context.Background(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "FORX0001" && detail.Code != errCodeFORX0002 {
			t.Errorf("2.0 regex %s: %v", source, err)
		}
	}

	if _, err := e.CompileXPath(context.Background(), "1", transform.XPathOptions{Version: 11}); !errors.Is(err, transform.ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestDocumentsAndBindings(t *testing.T) {
	e := engine(t, transform.Config{})
	raw := []byte(`<r xmlns:p="urn:p"><p:item>2</p:item><p:item>3</p:item></r>`)

	d, err := e.Parse(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}

	raw[1] = 'x'
	namespaces := map[string]string{"p": namespaceP}

	q, err := e.CompileXPath(context.Background(), `sum(/r/p:item) + $v:extra`, transform.XPathOptions{Namespaces: map[string]string{"p": namespaces["p"], "v": "urn:vars"}})
	if err != nil {
		t.Fatal(err)
	}

	huge := big.NewInt(7)
	value := transform.BigInteger(huge)
	huge.SetInt64(100)

	result, err := q.Evaluate(context.Background(), d, transform.XPathContext{Variables: transform.Bindings{{Space: "urn:vars", Local: "extra"}: transform.Values(value)}})
	if err != nil || text(t, result) != "12" {
		t.Fatal(text(t, result), err)
	}

	dec, err := transform.Decimal("0.125")
	if err != nil {
		t.Fatal(err)
	}

	rat, err := dec.Decimal()
	if err != nil || rat.RatString() != "1/8" {
		t.Fatal(rat, err)
	}

	rat.SetInt64(99)

	if s, err := dec.Text(); err != nil || s != "0.125" {
		t.Fatal(s, err)
	}

	m, err := transform.Map(transform.MapEntry{Key: transform.String("x"), Value: transform.Values(transform.Array(transform.Values(transform.Integer(5))))})
	if err != nil {
		t.Fatal(err)
	}

	mapped, err := query(t, e, `$data?x?1 + 1`, transform.XPath31).Evaluate(context.Background(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "data"}: transform.Values(m)}})
	if err != nil || text(t, mapped) != "6" {
		t.Fatal(mapped, err)
	}

	nodes, err := query(t, e, `/r/*`, transform.XPath31).Evaluate(context.Background(), d, transform.XPathContext{})
	if err != nil || nodes.Len() != 2 {
		t.Fatal(nodes, err)
	}

	first, _ := nodes.At(0)

	n, ok := first.Node()
	if !ok || n.Name() != (transform.Name{Space: namespaceP, Local: nameItem}) || n.StringValue() != "2" {
		t.Fatal(n)
	}

	atomic, err := query(t, e, `. + 1`, transform.XPath31).Evaluate(context.Background(), nil, transform.XPathContext{ContextItem: transform.Integer(41)})
	if err != nil || text(t, atomic) != "42" {
		t.Fatal(atomic, err)
	}
}

// F&O 2.0 (Second Edition) §15.1.10, 3.0 §14.1.9 and 3.1 §14.1.8
// require exactly one xs:double for each supplied position/length argument.
func TestSubsequenceArgumentCardinality(t *testing.T) {
	e := engine(t, transform.Config{})

	if _, err := e.CompileXPath(t.Context(), `subsequence(/r/*,2)`, transform.XPathOptions{Version: transform.XPath10}); err == nil {
		t.Fatal("XPath 1.0 accepted a function outside its library")
	}

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, source := range []string{
			`subsequence((1, 2, 3), 2, ())`,
			`subsequence((1, 2, 3), (), 2)`,
			`subsequence((1, 2, 3), 2, (1, 2))`,
			`subsequence((1, 2, 3), xs:double('NaN'), ())`,
		} {
			t.Run(fmt.Sprintf("%d/%s", version, source), func(t *testing.T) {
				q, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{Version: version})
				if err == nil {
					_, err = q.Evaluate(t.Context(), nil, transform.XPathContext{})
				}

				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != errCodeXPTY0004 {
					t.Fatalf("expected XPTY0004 during compile/evaluate, got %v", err)
				}
			})
		}

		for _, tt := range []struct{ args, want string }{
			{`2`, "2 3"},
			{`2, 0`, ""},
			{`2, -1`, ""},
			{`1.5, 1.5`, "2 3"},
			{`0, 3`, integerPairText},
			{`xs:double('NaN'), 2`, ""},
			{`1, xs:double('NaN')`, ""},
			{`1, xs:double('INF')`, integerSequenceText},
			{`xs:double('-INF')`, integerSequenceText},
			{`xs:double('INF')`, ""},
			{`xs:double('-INF'), xs:double('INF')`, ""},
			{`1, xs:double('-INF')`, ""},
		} {
			t.Run(fmt.Sprintf("%d/%s", version, tt.args), func(t *testing.T) {
				source := `string-join(for $n in subsequence((1, 2, 3), ` + tt.args + `) return string($n), ' ')`
				if got := text(t, evaluate(t, e, source, version)); got != tt.want {
					t.Fatalf("got %q, want %q", got, tt.want)
				}
			})
		}
	}
}

func TestSumUntypedPromotion(t *testing.T) {
	e := engine(t, transform.Config{})
	for source, want := range map[string]string{
		`sum((xs:untypedAtomic('2'),3))`:                          "5",
		`sum((3,xs:untypedAtomic('2')))`:                          "5",
		`sum((xs:decimal('0.25'),xs:untypedAtomic(' 2.5 ')))`:     "2.75",
		`sum((xs:float('1.5'),xs:untypedAtomic('2.5')))`:          "4",
		`sum([xs:untypedAtomic('2'),[xs:untypedAtomic('3')]])`:    "5",
		`sum((xs:untypedAtomic('INF'),xs:untypedAtomic('-INF')))`: valueNaN,
		`sum((xs:untypedAtomic('NaN'),1))`:                        valueNaN,
		`sum((xs:untypedAtomic('-0'),xs:untypedAtomic('-0')))`:    "0",
		`sum((xs:untypedAtomic('+INF'),1))`:                       namePositiveInfinity,
		`sum((xs:untypedAtomic('1e2'),1))`:                        "101",
		`sum((xs:untypedAtomic('1e9999'),1))`:                     namePositiveInfinity,
	} {
		seq := evaluate(t, e, source, transform.XPath31)
		if got := text(t, seq); got != want {
			t.Errorf("%s: %s, want %s", source, got, want)
		}

		value, _ := seq.At(0)
		if value.Type().Local != nameDouble {
			t.Errorf("%s: %v", source, value.Type())
		}
	}

	for source, code := range map[string]string{
		`sum((xs:untypedAtomic('0x1p0'),1))`:                       errCodeFORG0001,
		`sum((xs:untypedAtomic('inf'),1))`:                         errCodeFORG0001,
		`sum((xs:untypedAtomic('bad'),map{}))`:                     errCodeFOTY0013,
		`sum((xs:dayTimeDuration('PT1S'),xs:untypedAtomic('2')))`:  "FORG0006",
		`sum((xs:untypedAtomic('2'),xs:yearMonthDuration('P1M')))`: "FORG0006",
	} {
		_, err := query(t, e, source, transform.XPath31).Evaluate(context.Background(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != code {
			t.Errorf("%s: %v, want %s", source, err, code)
		}
	}
}

func TestNormalizeUnicodeLongCombiningSequences(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, form := range []string{"NFC", "NFD", "NFKC", "NFKD"} {
		query, err := e.CompileXPath(t.Context(), `normalize-unicode($normalizationSource, '`+form+`')`, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}

		for _, count := range []int{30, 31, 63, 4097} {
			input := "a" + strings.Repeat("\u0315", count) + "\u0300\u034f\u0301"

			want := "à" + strings.Repeat("\u0315", count) + "\u034f\u0301"
			if form == "NFD" || form == "NFKD" {
				want = "a\u0300" + strings.Repeat("\u0315", count) + "\u034f\u0301"
			}

			result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "normalizationSource"}: transform.Values(transform.String(input))}})
			if err != nil {
				t.Fatal(err)
			}

			got, err := result.Text()
			if err != nil || got != want {
				t.Fatalf("%s/%d: unexpected normalization: %v", form, count, err)
			}
		}
	}
}

func TestXPathBuiltinArgumentContracts(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for _, tc := range []struct {
			name, args, code string
			arity            int
		}{
			{functionCodepointsToString, `'hello'`, errCodeXPTY0004, 1},
			{functionCodepointsToString, `xs:decimal('65.0')`, errCodeXPTY0004, 1},
			{functionCodepointsToString, `xs:double(65)`, errCodeXPTY0004, 1},
			{functionCodepointsToString, `0`, errCodeFOCH0001, 1},
			{functionCodepointsToString, `xs:integer('18446744073709551616')`, errCodeFOCH0001, 1},
			{functionCodepointsToString, `xs:untypedAtomic('bad')`, errCodeFORG0001, 1},
			{functionConcat, `'a', string#1`, errCodeFOTY0013, 2},
			{functionConcat, `'a', map{}`, errCodeFOTY0013, 2},
			{functionConcat, `'a', (1,2), 'b'`, errCodeXPTY0004, 3},
			{functionUnparsedText, invalidTextEncodingArguments, errCodeXPTY0004, 2},
			{"unparsed-text-lines", invalidTextEncodingArguments, errCodeXPTY0004, 2},
			{"unparsed-text-available", invalidTextEncodingArguments, errCodeXPTY0004, 2},
			{functionUnparsedText, `(), ()`, errCodeXPTY0004, 2},
			{"local-name-from-QName", `xs:untypedAtomic('x')`, errCodeXPTY0117, 1},
			{"namespace-uri-from-QName", `parse-xml('<r>x</r>')/*`, errCodeXPTY0117, 1},
			{"prefix-from-QName", `xs:untypedAtomic('x')`, errCodeXPTY0117, 1},
			{"QName", `1, 'x'`, errCodeXPTY0004, 2},
			{"resolve-QName", `'x', (parse-xml('<r/>')/*,parse-xml('<r/>')/*)`, errCodeXPTY0004, 2},
			{"in-scope-prefixes", `1`, errCodeXPTY0004, 1},
			{"namespace-uri-for-prefix", `'p', parse-xml('<r/>')`, errCodeXPTY0004, 2},
		} {
			if version == transform.XPath30 && strings.Contains(tc.args, "map{") {
				continue
			}

			for _, call := range []string{tc.name, fmt.Sprintf("%s#%d", tc.name, tc.arity), fmt.Sprintf("function-lookup(xs:QName('fn:%s'),%d)", tc.name, tc.arity)} {
				expression := call + "(" + tc.args + ")"
				_, err := query(t, e, expression, version).Evaluate(t.Context(), nil, transform.XPathContext{})

				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != tc.code {
					t.Errorf("version %v %s: %v; want %s", version, expression, err, tc.code)
				}
			}
		}
	}

	for expression, want := range map[string]string{
		`codepoints-to-string((xs:untypedAtomic('65'),xs:unsignedByte(66)))`:                                  nameCodepointsAB,
		`codepoints-to-string([65, [], [66]])`:                                                                nameCodepointsAB,
		`concat('a', [], 'b')`:                                                                                "ab",
		`concat#3('a', [1], 'b')`:                                                                             "a1b",
		`empty(unparsed-text((), 'UTF-8'))`:                                                                   nameTrue,
		`not(unparsed-text-available((), 'UTF-8'))`:                                                           nameTrue,
		`namespace-uri-from-QName(resolve-QName('p:x', parse-xml('<r xmlns:p="urn:p"/>')/*))`:                 "urn:p",
		`codepoints-to-string#1 instance of function(xs:integer*) as xs:string`:                               nameTrue,
		`concat#3 instance of function(xs:anyAtomicType?, xs:anyAtomicType?, xs:anyAtomicType?) as xs:string`: nameTrue,
	} {
		if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != want {
			t.Errorf("%s: %q, want %q", expression, got, want)
		}
	}
}

func TestXPathCalendarPictureErrorCodes(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for _, tc := range []struct{ function, value, picture, code string }{
			{functionFormatDate, calendarDateExpression, "[b]", errCodeFOFD1340},
			{functionFormatDate, calendarDateExpression, "[y]", errCodeFOFD1340},
			{functionFormatTime, calendarTimeExpression, "[b]", errCodeFOFD1340},
			{functionFormatTime, calendarTimeExpression, "[y]", errCodeFOFD1340},
			{functionFormatDate, calendarDateExpression, "[H]", errCodeFOFD1350},
			{functionFormatTime, calendarTimeExpression, "[Y]", errCodeFOFD1350},
		} {
			_, err := query(t, e, tc.function+"("+tc.value+",'"+tc.picture+"')", version).Evaluate(t.Context(), nil, transform.XPathContext{})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != tc.code {
				t.Errorf("%v %s %s: %v, want %s", version, tc.function, tc.picture, err, tc.code)
			}
		}
	}
}

func TestXPathMissingXQueryProcessor(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, expression := range []string{
		"load-xquery-module(1)", "load-xquery-module('urn:module', 1)", "load-xquery-module#2('urn:module', 1)",
		`load-xquery-module#1(0)`, `function-lookup(xs:QName('fn:load-xquery-module'),1)(0)`,
		`load-xquery-module(0, ?) (map{})`, `apply(load-xquery-module#1, [0])`,
	} {
		_, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != errCodeFOQM0006 {
			t.Fatal("unavailable module loader", expression, err)
		}
	}

	for _, call := range []string{"load-xquery-module", "load-xquery-module#1", "function-lookup(xs:QName('fn:load-xquery-module'),1)"} {
		_, err := query(t, e, call+"('urn:module')", transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != errCodeFOQM0006 {
			t.Fatal("missing XQuery processor error", call, err)
		}
	}
}

func TestXPathOperationErrorContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for expression, code := range map[string]string{
		`'a' || string#1`:                      errCodeFOTY0013,
		`map{} || 'a'`:                         errCodeFOTY0013,
		`'a' || [map{}]`:                       errCodeFOTY0013,
		`'a' || (1,2)`:                         errCodeXPTY0004,
		`xs:double('INF') idiv 0`:              errCodeFOAR0001,
		`xs:float('-INF') idiv xs:float('-0')`: errCodeFOAR0001,
		`xs:double('NaN') idiv 1`:              errCodeFOAR0002,
		`xs:double('INF') idiv 1`:              errCodeFOAR0002,
		`xs:dayTimeDuration('PT1S') div xs:dayTimeDuration('PT0S')`:   errCodeFOAR0001,
		`xs:yearMonthDuration('P1Y') div xs:yearMonthDuration('P0M')`: errCodeFOAR0001,
		`array:subarray([1,2,3], 2, -1)`:                              errCodeFOAY0002,
		`array:subarray#3([1,2,3], 2, -1)`:                            errCodeFOAY0002,
		`array:subarray([1,2,3], 0, 0)`:                               errCodeFOAY0001,
		`array:subarray([1,2,3], 5)`:                                  errCodeFOAY0001,
		`array:subarray([1,2,3], 2, 3)`:                               errCodeFOAY0001,
	} {
		_, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != code {
			t.Errorf("%s: %v, want %s", expression, err, code)
		}
	}

	for expression, want := range map[string]string{
		`'a' || [[],[1]]`:                                               "a1",
		`() || 'a' || true()`:                                           "atrue",
		`array:size(array:subarray([1,2,3], 4))`:                        "0",
		`array:size(array:subarray([1,2,3], 4, 0))`:                     "0",
		`array:subarray([1,2,3], 2, 1)?1`:                               "2",
		`xs:yearMonthDuration('P1Y') div xs:yearMonthDuration('P2M')`:   "6",
		`xs:dayTimeDuration('PT1.5S') div xs:dayTimeDuration('PT0.5S')`: "3",
		`1 idiv xs:double('INF')`:                                       "0",
	} {
		if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != want {
			t.Errorf("%s: %q, want %q", expression, got, want)
		}
	}
}

func TestXPathInlineFunctionDefaultTypes(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for expression, want := range map[string]string{
			`(function($fs as (function(xs:string) as xs:string)*) {string-join(for $f in $fs return $f('Abc e'),'~')})((upper-case#1,lower-case#1,function($x){translate($x,'e','i')},substring-before(?, ' ')))`: "ABC E~abc e~Abc i~Abc",
			`function($a,$b){$a+$b} instance of function(item()*,item()*) as item()*`:              nameTrue,
			`function($a,$b){$a+$b} instance of function(xs:integer,xs:integer) as item()*`:        nameTrue,
			`function($a,$b){$a+$b} instance of function(item()*,item()*) as xs:integer`:           nameFalse,
			`function($a as xs:string,$b){$a} instance of function(xs:integer,item()*) as item()*`: nameFalse,
			`function($a as xs:string,$b){$a} instance of function(xs:NCName,item()*) as item()*`:  nameTrue,
			`function($a,$b as xs:integer){$b} instance of function(item()*,xs:string) as item()*`: nameFalse,
			`function(){()} instance of function() as empty-sequence()`:                            nameFalse,
			`function() as empty-sequence(){()} instance of function() as empty-sequence()`:        nameTrue,
			`(function($f as function(xs:integer) as xs:integer){$f(7)})(function($x){$x})`:        "7",
		} {
			if got := text(t, evaluate(t, e, expression, version)); got != want {
				t.Errorf("%v %s: %q, want %q", version, expression, got, want)
			}
		}

		for _, expression := range []string{
			`(function($fs as (function(xs:string) as xs:string)*) {true()})((upper-case#1,concat#2))`,
			`(function($fs as (function(xs:string) as xs:string)*) {for $f in $fs return $f('x')})((upper-case#1,function($x){1}))`,
			`(function($fs as function(xs:string) as xs:string) {true()})((upper-case#1,lower-case#1))`,
		} {
			_, err := query(t, e, expression, version).Evaluate(t.Context(), nil, transform.XPathContext{})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXPTY0004 {
				t.Errorf("function sequence conversion %v %s: %v", version, expression, err)
			}
		}
	}
}

func TestXPath20ArgumentContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for expression, code := range map[string]string{
		`codepoints-to-string('hello')`:                errCodeXPTY0004,
		`codepoints-to-string(xs:double(65))`:          errCodeXPTY0004,
		`local-name-from-QName(xs:untypedAtomic('x'))`: errCodeXPTY0004,
		`concat('a',(1,2))`:                            errCodeXPTY0004,
	} {
		_, err := query(t, e, expression, transform.XPath20).Evaluate(t.Context(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != code {
			t.Errorf("%s: %v, want %s", expression, err, code)
		}
	}

	if got := text(t, evaluate(t, e, `codepoints-to-string((xs:untypedAtomic('65'),xs:unsignedByte(66)))`, transform.XPath20)); got != nameCodepointsAB {
		t.Fatal(got)
	}
}

func standardFunctionTypeCases() map[string]string {
	return map[string]string{
		`transform#1 instance of function(map(*)) as map(*)`:                                  nameTrue,
		`transform#1 instance of function(xs:integer) as map(*)`:                              nameFalse,
		`transform(?) instance of function(map(*)) as map(*)`:                                 nameTrue,
		`load-xquery-module#1 instance of function(xs:string) as map(*)`:                      nameTrue,
		`load-xquery-module#1 instance of function(xs:integer) as map(*)`:                     nameFalse,
		`load-xquery-module(?) instance of function(xs:string) as map(*)`:                     nameTrue,
		`doc#1 instance of function(xs:string?) as document-node()?`:                          nameTrue,
		`doc(?) instance of function(xs:string?) as document-node()?`:                         nameTrue,
		`(doc#1)(?) instance of function(xs:string?) as document-node()?`:                     nameTrue,
		`doc#1 instance of function(xs:integer) as xs:string`:                                 nameFalse,
		`function-lookup(xs:QName('fn:doc'),1) instance of function(xs:integer) as xs:string`: nameFalse,
		`base-uri#0 instance of function() as xs:anyURI?`:                                     nameTrue,
		`base-uri#0 instance of function() as xs:string`:                                      nameFalse,
		`root#1 instance of function(node()?) as node()?`:                                     nameTrue,
		`data#1 instance of function(item()*) as xs:anyAtomicType*`:                           nameTrue,
		`data#1 instance of function(item()*) as xs:integer`:                                  nameFalse,
		`year-from-date#1 instance of function(xs:date?) as xs:string?`:                       nameFalse,
		`serialize#2 instance of function(item()*,item()?) as xs:string`:                      nameTrue,
		`map:get#2 instance of function(map(*),xs:anyAtomicType) as item()*`:                  nameTrue,
		`map:get(map{},?) instance of function(xs:anyAtomicType) as item()*`:                  nameTrue,
		`map:get(map{},?) instance of function(xs:anyAtomicType) as xs:string`:                nameFalse,
		`([1])(?) instance of function(xs:integer) as item()*`:                                nameTrue,
		`(map{'a':1})(?) instance of function(xs:anyAtomicType) as item()*`:                   nameTrue,
	}
}

func TestXPathCurrentDateTimeTypes(t *testing.T) {
	for _, edition := range []transform.XMLSchemaVersion{transform.XMLSchema10, transform.XMLSchema11} {
		e := engine(t, transform.Config{XMLSchemaVersion: edition})
		for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
			for expression, want := range map[string]string{
				`current-dateTime() - current-dateTime() eq xs:dayTimeDuration('PT0S')`:  nameTrue,
				`current-dateTime() + xs:dayTimeDuration('PT0S') eq current-dateTime()`:  nameTrue,
				`current-dateTime() - xs:yearMonthDuration('P0M') eq current-dateTime()`: nameTrue,
			} {
				if got := text(t, evaluate(t, e, expression, version)); got != want {
					t.Fatal(edition, version, expression, got)
				}
			}

			for _, call := range []string{`current-dateTime()`, `(current-dateTime#0)()`, `function-lookup(xs:QName('fn:current-dateTime'),0)()`} {
				typeName := "xs:dateTime"
				if edition == transform.XMLSchema11 {
					typeName = "xs:dateTimeStamp"
				}
				expression := call + ` instance of ` + typeName
				if got := text(t, evaluate(t, e, expression, version)); got != nameTrue {
					t.Fatal(edition, version, expression, got)
				}
				expression = `current-dateTime#0 instance of function() as ` + typeName
				if got := text(t, evaluate(t, e, expression, version)); got != nameTrue {
					t.Fatal(edition, version, expression, got)
				}
			}
		}
	}
}

func TestXPathStandardFunctionTypes(t *testing.T) {
	e := engine(t, transform.Config{})
	for expression, want := range standardFunctionTypeCases() {
		t.Run(expression, func(t *testing.T) {
			if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != want {
				t.Fatal(got, want)
			}
		})
	}
}

func TestXPathVersionedFunctionContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for versionIndex, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, tc := range []struct {
			name, args string
			arity      int
			want       [3]string // XPath 2.0, 3.0, 3.1.
		}{
			{"string-join", `(1,2,3),''`, 2, [3]string{errCodeXPTY0004, errCodeXPTY0004, "123"}},
			{"string-join", `(xs:untypedAtomic('a'),xs:anyURI('b')),'/'`, 2, [3]string{"a/b", "a/b", "a/b"}},
			{"string-join", `(),''`, 2, [3]string{"", "", ""}},
			{"string-join", `('a','b'),()`, 2, [3]string{errCodeXPTY0004, errCodeXPTY0004, errCodeXPTY0004}},
			{"string-join", `('a','b'),1`, 2, [3]string{errCodeXPTY0004, errCodeXPTY0004, errCodeXPTY0004}},
			{"error", `()`, 1, [3]string{errCodeXPTY0004, errCodeXPTY0004, "FOER0000"}},
			{"error", `(), 'description'`, 2, [3]string{"FOER0000", "FOER0000", "FOER0000"}},
			{"error", `(), 'description', (1,2)`, 3, [3]string{"FOER0000", "FOER0000", "FOER0000"}},
			{"error", `xs:QName('err:FOER0000')`, 1, [3]string{"FOER0000", "FOER0000", "FOER0000"}},
			{"error", `xs:untypedAtomic('err:FOER0000')`, 1, [3]string{errCodeXPTY0004, "XPTY0117", "XPTY0117"}},
		} {
			want := tc.want[versionIndex]
			calls := []string{tc.name + "(" + tc.args + ")"}
			if version != transform.XPath20 {
				arity := strconv.Itoa(tc.arity)
				calls = append(calls, tc.name+"#"+arity+"("+tc.args+")",
					"function-lookup(xs:QName('fn:"+tc.name+"'),"+arity+")("+tc.args+")")
				if version == transform.XPath31 {
					calls = append(calls, "apply("+tc.name+"#"+arity+",["+tc.args+"])")
				}
				if tc.name == "string-join" && tc.args == `(1,2,3),''` {
					calls = append(calls, `string-join((1,2,3),?)('')`, `string-join(?,'')((1,2,3))`)
				}
			}

			for _, expression := range calls {
				got, err := query(t, e, expression, version).Evaluate(t.Context(), nil, transform.XPathContext{})
				if strings.HasPrefix(want, "XPTY") || strings.HasPrefix(want, "FOER") {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != want {
						t.Errorf("%v %s: %v, want %s", version, expression, err, want)
					}
				} else if err != nil || text(t, got) != want {
					t.Errorf("%v %s: %v, %v; want %q", version, expression, got, err, want)
				}
			}
		}
	}

	for _, name := range []string{"data", "document-uri", "nilled", "node-name"} {
		for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
			if got := text(t, evaluate(t, e, "empty(fn:"+name+"(()))", version)); got != nameTrue {
				t.Errorf("%v %s: %s", version, name, got)
			}

			_, err := e.CompileXPath(t.Context(), "fn:"+name+"()", transform.XPathOptions{Version: version})
			if version == transform.XPath20 {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != "XPST0017" {
					t.Errorf("%v %s: %v", version, name, err)
				}
			} else if err != nil {
				t.Errorf("%v %s: %v", version, name, err)
			}
		}
	}

	for expression, want := range map[string]string{
		`empty(unparsed-text(()))`:         nameTrue,
		`fn:unparsed-text-available(())`:   nameFalse,
		`format-number(1,'000')`:           "001",
		`empty(fn:format-date((),'[Y]'))`:  nameTrue,
		`empty(format-dateTime((),'[Y]'))`: nameTrue,
		`empty(fn:format-time((),'[H]'))`:  nameTrue,
	} {
		_, err := e.CompileXPath(t.Context(), expression, transform.XPathOptions{Version: transform.XPath20})
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "XPST0017" {
			t.Errorf("2.0 %s: %v", expression, err)
		}
		for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
			if got := text(t, evaluate(t, e, expression, version)); got != want {
				t.Errorf("%v %s: %q, want %q", version, expression, got, want)
			}
		}
	}
}

func TestXPathQNameCastVersions(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct{ expression, old, modern string }{
		{`'local' cast as xs:QName`, "local", "local"},
		{`'local' castable as xs:QName`, nameTrue, nameTrue},
		{`for $v in 'local' return $v cast as xs:QName`, errCodeXPTY0004, "local"},
		{`for $v in 'local' return $v castable as xs:QName`, nameFalse, nameTrue},
		{`xs:untypedAtomic('local') cast as xs:QName?`, errCodeXPTY0004, "local"},
		{`xs:untypedAtomic('local') castable as xs:QName`, nameFalse, nameTrue},
		{`xs:untypedAtomic('not a name') cast as xs:QName`, errCodeXPTY0004, "FORG0001"},
		{`xs:QName('local') cast as xs:QName`, "local", "local"},
		{`xs:QName('local') castable as xs:QName`, nameTrue, nameTrue},
		{`xs:QName(())`, "", ""},
		{`() cast as xs:QName?`, "", ""},
		{`() castable as xs:QName?`, nameTrue, nameTrue},
		{`for $v in 'local' return xs:QName($v)`, errCodeXPTY0004, "local"},
		{`xs:QName(xs:untypedAtomic('local'))`, errCodeXPTY0004, "local"},
		{`xs:QName(xs:QName('local'))`, "local", "local"},
	} {
		for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
			want := tc.modern
			if version == transform.XPath20 {
				want = tc.old
			}

			got, err := query(t, e, tc.expression, version).Evaluate(t.Context(), nil, transform.XPathContext{})
			if want == errCodeXPTY0004 || want == "FORG0001" {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != want {
					t.Errorf("%v %s: %v, want %s", version, tc.expression, err, want)
				}
			} else if want == "" {
				if err != nil || got.Len() != 0 {
					t.Errorf("%v %s: %v, %v; want empty sequence", version, tc.expression, got, err)
				}
			} else if err != nil || text(t, got) != want {
				t.Errorf("%v %s: %v, %v; want %q", version, tc.expression, got, err, want)
			}
		}
	}
}

func TestXPathNumberPictureVersions(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for expression, want := range map[string]string{
			`format-number(12345.678,'9.9999e999')`: "1.2346e004",
			`format-number(12,'e0')`:                "e12",
			`format-number(12,'0e')`:                "12e",
			`format-number(12,'0.0')`:               "12.0",
		} {
			got, err := query(t, e, expression, version).Evaluate(t.Context(), nil, transform.XPathContext{})
			if version == transform.XPath30 && strings.Contains(expression, "9.9999e999") {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != "FODF1310" {
					t.Errorf("%v %s: %v", version, expression, err)
				}
			} else if err != nil || text(t, got) != want {
				t.Errorf("%v %s: %v, %v; want %q", version, expression, got, err, want)
			}
		}
	}
}

func TestXPathFunctionRetainsLibraryVersion(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for _, expression := range []string{
			`string-join#2 instance of function(xs:anyAtomicType*,xs:string) as xs:string`,
			`error#1 instance of function(xs:QName?) as item()*`,
		} {
			want := nameFalse
			if version == transform.XPath31 {
				want = nameTrue
			}
			if got := text(t, evaluate(t, e, expression, version)); got != want {
				t.Errorf("%v %s: %s, want %s", version, expression, got, want)
			}
		}

		for _, tc := range []struct{ source, args, want string }{
			{`string-join#2`, `(1,2),''`, "12"},
			{`function-lookup(xs:QName('fn:string-join'),2)`, `(1,2),''`, "12"},
			{`string-join(?,'')`, `(1,2)`, "12"},
			{`error#1`, `()`, "FOER0000"},
			{`function-lookup(xs:QName('fn:error'),1)`, `()`, "FOER0000"},
			{`error(?)`, `()`, "FOER0000"},
		} {
			function := evaluate(t, e, tc.source, version)
			want := tc.want
			if version == transform.XPath30 {
				want = errCodeXPTY0004
			}

			for _, callerVersion := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
				got, err := query(t, e, "$f("+tc.args+")", callerVersion).Evaluate(t.Context(), nil, transform.XPathContext{
					Variables: transform.Bindings{{Local: "f"}: function},
				})
				if want == "12" {
					if err != nil || text(t, got) != want {
						t.Errorf("%v -> %v %s: %v, %v", version, callerVersion, tc.source, got, err)
					}
				} else {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != want {
						t.Errorf("%v -> %v %s: %v, want %s", version, callerVersion, tc.source, err, want)
					}
				}
			}
		}
	}
}

func TestXPathRepeatedFunctionSignatures(t *testing.T) {
	e := engine(t, transform.Config{})
	for expression, want := range map[string]string{
		`function-arity(concat#123456)`:                                                                     "123456",
		`function-arity(function-lookup(xs:QName('fn:concat'),123456))`:                                     "123456",
		`concat#3 instance of function(xs:string?,xs:anyAtomicType?,xs:integer?) as xs:string`:              nameTrue,
		`concat#3 instance of function(xs:anyAtomicType?,xs:anyAtomicType*,xs:anyAtomicType?) as xs:string`: nameFalse,
		`concat('a',?,?)('b','c')`:                                                                          "abc",
		`(function($f as function(item()*,item()*,item()*) as xs:string){$f('a','b','c')})(concat#3)`:       "abc",
	} {
		if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != want {
			t.Errorf("%s: %q, want %q", expression, got, want)
		}
	}

	for _, expression := range []string{
		`concat('a',?,?)('b',(1,2))`,
		`(function($f as function(item()*,item()*,item()*) as xs:string){$f('a','b',(1,2))})(concat#3)`,
		`apply(concat#3, ['a','b',(1,2)])`,
	} {
		_, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != errCodeXPTY0004 {
			t.Fatal("repeated parameter type was lost", expression, err)
		}
	}

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for _, expression := range []string{`function-arity(concat#340282366920938463463374607431768211456)`, `function-name(concat#340282366920938463463374607431768211456)`} {
			_, err := e.CompileXPath(t.Context(), expression, transform.XPathOptions{Version: version})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeFOAR0002 {
				t.Fatal("arity capacity misclassified as a syntax error", expression, err)
			}
		}
	}
}
