package transform_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

const (
	namePositiveInfinity = "INF"
	name12Sum            = "(1,2)=>sum()"
	errCodeXPST0003      = "XPST0003"
	errCodeXPST0017      = "XPST0017"
	nameMatchesAbcAbC    = "matches('abc','(?:ab)c')"
)

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

func TestXPathLexicalCasts(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for source, want := range map[string]string{
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
	if !ok || n.Name() != (transform.Name{Space: namespaceP, Local: "item"}) || n.StringValue() != "2" {
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
				if !errors.As(err, &detail) || detail.Code != "XPTY0004" {
					t.Fatalf("expected XPTY0004 during compile/evaluate, got %v", err)
				}
			})
		}

		for _, tt := range []struct{ args, want string }{
			{`2`, "2 3"},
			{`2, 0`, ""},
			{`2, -1`, ""},
			{`1.5, 1.5`, "2 3"},
			{`0, 3`, "1 2"},
			{`xs:double('NaN'), 2`, ""},
			{`1, xs:double('NaN')`, ""},
			{`1, xs:double('INF')`, "1 2 3"},
			{`xs:double('-INF')`, "1 2 3"},
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
		`sum((xs:untypedAtomic('+INF'),1))`:                       "INF",
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
		`sum((xs:untypedAtomic('0x1p0'),1))`:                       "FORG0001",
		`sum((xs:untypedAtomic('inf'),1))`:                         "FORG0001",
		`sum((xs:untypedAtomic('bad'),map{}))`:                     "FOTY0013",
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
