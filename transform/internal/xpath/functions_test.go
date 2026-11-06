package xpath //nolint:testpackage // Checks built-in function results on the AST and VM dispatch paths.

import (
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

type functionResultCase struct{ name, expression, want string }

func assertFunctionResults(t *testing.T, cases []functionResultCase) {
	t.Helper()
	for _, test := range cases {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				source := `string-join((` + test.expression + `) ! string(.), '|')`
				seq, err := evaluateFunctionExpression(t, source, mode)
				if err != nil {
					t.Fatal(err)
				}
				if xdm.SequenceLen(seq) != 1 {
					t.Fatalf("expected one result, got %v", seq)
				}
				got, ok := seq.Get(0).(xdm.AtomicValue)
				if !ok || got.TypeName != "xs:string" || got.Value != test.want {
					t.Fatalf("%s = %+v; want xs:string %q", test.expression, seq.Get(0), test.want)
				}
			})
		}
	}
}

func evaluateFunctionExpression(t *testing.T, source, mode string) (xdm.Sequence, error) {
	t.Helper()
	ast, err := Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := NewEvaluator(DefaultEvaluatorOptions)
	if mode == runtimeASTMode {
		ec := evaluator.newEvalCtx(nil)
		ec.version = 31
		return evaluateRuntimeAST(t.Context(), ec, ast)
	}
	expression, err := NewCompiler().Language(31, nil).CompileExpr(ast)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluator.Evaluate(t.Context(), expression, nil)
	if err != nil {
		if result != nil {
			t.Fatalf("VM returned a result alongside failure: %v, %v", result.Sequence(), err)
		}
		return nil, err
	}
	if result == nil {
		t.Fatal("VM returned neither result nor error")
	}
	return result.Sequence(), nil
}

func TestArrayFunctionsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"members retain sequences and emptiness", `let $a := [(1,2),(),3] return (array:size($a),count($a?2),$a?1,$a?3)`, "3|0|1|2|3"},
		{"put preserves original", `let $a := [1,2], $b := array:put($a,1,(7,8)) return ($a?1,array:size($b),$b?1,$b?2)`, "1|2|7|8|2"},
		{"append one multi-item member", `let $a := array:append([1],(2,3)) return (array:size($a),$a?2)`, "2|2|3"},
		{"subarray boundaries", `(array:subarray([1,2,3],2)?*,array:size(array:subarray([1,2,3],4,0)))`, "2|3|0"},
		{"remove duplicate positions", `array:remove([1,2,3,4],(3,1,3))?*`, "2|4"},
		{"insert before and after last", `(array:insert-before([1,2],1,0)?*,array:insert-before([1,2],3,3)?*)`, "0|1|2|1|2|3"},
		{"head returns member not item", `(array:head([(1,2),3]),array:tail([(1,2),3])?*)`, "1|2|3"},
		{"reverse preserves member grouping", `let $a := array:reverse([(1,2),3]) return (array:size($a),$a?1,$a?2)`, "2|3|1|2"},
		{"join concatenates arrays", `let $a := array:join(([1,()],[(2,3)],[])) return (array:size($a),count($a?2),$a?3)`, "3|0|2|3"},
		{"flatten nested arrays", `array:flatten((0,[1,[2,3]],(),4))`, "0|1|2|3|4"},
		{"filter calls predicate on member", `array:filter([(1,2),(),3],function($member){count($member)=2})?*`, "1|2"},
		{"fold left order", `array:fold-left([1,2,3],'',function($a,$b){$a || $b})`, "123"},
		{"fold right order", `array:fold-right([1,2,3],'',function($a,$b){$b || $a})`, "321"},
		{"for each retains empty result member", `let $a := array:for-each([1,2,3],function($v){if ($v=2) then () else $v*10}) return (array:size($a),count($a?2),$a?*)`, "3|0|10|30"},
		{"for each pair truncates at shorter array", `array:for-each-pair([1,2,3],[10,20],function($a,$b){$a+$b})?*`, "11|22"},
		{"sort stable with supplied key", `array:sort(['bb','a','cc'],(),function($s){string-length($s)})?*`, "a|bb|cc"},
	})
}

func TestCollectionFunctionResultTypes(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{runtimeASTMode, "VM"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			seq, err := evaluateFunctionExpression(t, `(array:size([1,2,3]),map:size(map{'a':1}),map:contains(map{'a':()},'a'),map:contains(map{},'a'))`, mode)
			if err != nil || xdm.SequenceLen(seq) != 4 {
				t.Fatalf("typed collection results = %v, %v", seq, err)
			}
			for i, want := range []xdm.AtomicValue{
				{TypeName: "xs:integer", Value: int64(3)},
				{TypeName: "xs:integer", Value: int64(1)},
				{TypeName: "xs:boolean", Value: true},
				{TypeName: "xs:boolean", Value: false},
			} {
				got, ok := seq.Get(i).(xdm.AtomicValue)
				if !ok || got.TypeName != want.TypeName || got.Value != want.Value {
					t.Fatalf("result %d = %+v; want %+v", i, seq.Get(i), want)
				}
			}
		})
	}
}

func TestMapFunctionsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"empty values still have keys", `let $m := map{'empty':(),'value':(1,2)} return (map:size($m),map:contains($m,'empty'),count(map:get($m,'empty')),map:contains($m,'missing'),map:get($m,'value'))`, "2|true|0|false|1|2"},
		{"put retains original", `let $m := map{'a':1}, $n := map:put($m,'a',2) return ($m?a,$n?a,map:size($n))`, "1|2|1"},
		{"remove multiple keys and miss", `let $m := map:remove(map{'a':1,'b':2,'c':3},('a','c','missing')) return (map:size($m),map:keys($m),$m?b)`, "1|b|2"},
		{"entry retains empty sequence", `let $m := map:entry('a',()) return (map:size($m),map:contains($m,'a'),count($m?a))`, "1|true|0"},
		{"merge default uses first", `map:merge((map{'a':1},map{'a':2}))?a`, "1"},
		{"merge uses last", `map:merge((map{'a':1},map{'a':2}),map{'duplicates':'use-last'})?a`, "2"},
		{"merge combines in order", `map:merge((map{'a':(1,2)},map{'a':3}),map{'duplicates':'combine'})?a`, "1|2|3"},
		{"for each unordered results sorted", `sort(map:for-each(map{'a':1,'b':2},function($k,$v){$k || $v}))`, "a1|b2"},
		{"find traverses nested containers", `sort(array:flatten(map:find(map{'a':1,'nested':[map{'a':(2,3)}]},'a')))`, "1|2|3"},
		{"numeric keys share equality", `let $m := map{1:'one'} return (map:contains($m,xs:decimal('1.0')),$m(xs:double(1)))`, "true|one"},
	})
}

func TestJSONFunctionsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"null members retain structure", `let $m := parse-json('{"a":null,"b":[true,null,3]}') return (map:contains($m,'a'),count($m?a),array:size($m?b),$m?b?1,count($m?b?2),$m?b?3)`, "true|0|3|true|0|3"},
		{"empty input sequence", `count(parse-json(()))`, "0"},
		{"top level null", `count(parse-json('null'))`, "0"},
		{"top level string escapes", `parse-json('"a\n\t\"\\b"')`, "a\n\t\"\\b"},
		{"Unicode escape and surrogate pair", `parse-json('"\u00e9\ud83d\ude00"')`, "é😀"},
		{"duplicate default first", `parse-json('{"a":1,"a":2}')?a`, "1"},
		{"duplicate last after escape decoding", `parse-json('{"a":1,"\u0061":2}',map{'duplicates':'use-last'})?a`, "2"},
		{"JSON XML round trip", `let $m := parse-json(xml-to-json(json-to-xml('{"a":[1,null,"x"],"b":true}'))) return ($m?a?1,count($m?a?2),$m?a?3,$m?b)`, "1|0|x|true"},
	})
}

func TestDateTimeFunctionsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"date and time components", `let $d := xs:dateTime('2024-02-29T23:58:04.500-03:30') return (year-from-dateTime($d),month-from-dateTime($d),day-from-dateTime($d),hours-from-dateTime($d),minutes-from-dateTime($d),seconds-from-dateTime($d),timezone-from-dateTime($d))`, "2024|2|29|23|58|4.5|-PT3H30M"},
		{"duration components retain signs", `let $d := xs:duration('-P1Y2M3DT4H5M6.5S') return (years-from-duration($d),months-from-duration($d),days-from-duration($d),hours-from-duration($d),minutes-from-duration($d),seconds-from-duration($d))`, "-1|-2|-3|-4|-5|-6.5"},
		{"timezone rolls calendar date", `adjust-dateTime-to-timezone(xs:dateTime('2024-03-01T00:30:00+02:00'),xs:dayTimeDuration('PT0S'))`, "2024-02-29T22:30:00Z"},
		{"removing timezone retains local fields", `adjust-dateTime-to-timezone(xs:dateTime('2024-03-01T00:30:00+02:00'),())`, "2024-03-01T00:30:00"},
		{"adding timezone to unzoned value", `adjust-dateTime-to-timezone(xs:dateTime('2024-03-01T00:30:00'),xs:dayTimeDuration('-PT5H'))`, "2024-03-01T00:30:00-05:00"},
		{"month arithmetic clamps day", `xs:date('2024-01-31') + xs:yearMonthDuration('P1M')`, "2024-02-29"},
		{"year month addition with negative operand", `xs:yearMonthDuration('P1Y2M') + xs:yearMonthDuration('-P3M')`, "P11M"},
		{"year month subtraction crosses zero", `xs:yearMonthDuration('P3M') - xs:yearMonthDuration('P1Y2M')`, "-P11M"},
		{"negative durations subtract to positive", `xs:yearMonthDuration('-P3M') - xs:yearMonthDuration('-P1Y2M')`, "P11M"},
		{"year month cancellation", `xs:yearMonthDuration('P1Y') + xs:yearMonthDuration('-P12M')`, "P0M"},
		{"fractional second addition stays exact", `xs:dayTimeDuration('PT0.05S') + xs:dayTimeDuration('PT0.05S')`, "PT0.1S"},
		{"fractional second subtraction crosses zero", `xs:dayTimeDuration('PT0.05S') - xs:dayTimeDuration('PT0.15S')`, "-PT0.1S"},
		{"negative second subtraction", `xs:dayTimeDuration('-PT0.05S') - xs:dayTimeDuration('-PT0.15S')`, "PT0.1S"},
		{"date time composition", `dateTime(xs:date('2024-02-29Z'),xs:time('12:34:56Z'))`, "2024-02-29T12:34:56Z"},
		{"unavailable components stay empty", `(count(year-from-dateTime(())),count(timezone-from-date(xs:date('2024-01-01'))))`, "0|0"},
	})
}

func TestStringFunctionsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"Unicode codepoints", `(codepoints-to-string((65,233,128512)),string-to-codepoints('Aé😀'))`, "Aé😀|65|233|128512"},
		{"Unicode normalization", `normalize-unicode(codepoints-to-string((101,769)),'NFC')`, "é"},
		{"translate codepoints", `translate('bárbá','á','a')`, "barba"},
		{"substring Unicode offsets", `substring('Aé😀Z',2,2)`, "é😀"},
		{"before after empty delimiter", `(substring-before('abc',''),substring-after('abc',''))`, "|abc"},
		{"encode URI component", `encode-for-uri('café /')`, "caf%C3%A9%20%2F"},
		{"IRI percent encoding", `iri-to-uri('https://example.test/café?q=中')`, "https://example.test/caf%C3%A9?q=%E4%B8%AD"},
		{"tokenize retains empty tokens", `(count(tokenize('a,,b,',',')),tokenize('a,,b,',','),count(tokenize('',',')))`, "4|a||b||0"},
		{"replace captured groups", `replace('abc123','([a-z]+)([0-9]+)','$2-$1')`, "123-abc"},
		{"case insensitive regex and negative control", `(matches('AbC','^abc$','i'),matches('XAbC','^abc$','i'))`, "true|false"},
		{"regex multiline anchors", `(matches(codepoints-to-string((97,10,98)),'^b$','m'),matches('ab','^b$','m'))`, "true|false"},
		{"XML whitespace excludes NBSP", `normalize-space(codepoints-to-string((32,97,160,32,9,98,13,10)))`, "a\u00a0 b"},
		{"codepoint compare and absent argument", `(compare('a','b'),compare('b','a'),compare('a','a'),count(codepoint-equal((),'a')))`, "-1|1|0|0"},
	})
}

func TestNumericAndSequenceFunctionsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"half even ties", `(round-half-to-even(1.5),round-half-to-even(2.5),round-half-to-even(-1.5),round-half-to-even(125,-1))`, "2|2|-2|120"},
		{"exact decimal operators", `(xs:decimal('0.1') + xs:decimal('0.2'),xs:decimal('0.1') - xs:decimal('0.3'),xs:decimal('1.25') * xs:decimal('0.8'),xs:decimal('1') div xs:decimal('8'))`, "0.3|-0.2|1|0.125"},
		{"decimal quotient truncates toward zero", `(xs:decimal('-5.5') idiv xs:decimal('2'),xs:decimal('5.5') idiv xs:decimal('-2'))`, "-2|-2"},
		{"decimal modulo has dividend sign", `(xs:decimal('-5.5') mod xs:decimal('2'),xs:decimal('5.5') mod xs:decimal('-2'))`, "-1.5|1.5"},
		{"round ties toward positive infinity", `(round(1.5),round(-1.5),ceiling(-1.5),floor(-1.5),abs(-3))`, "2|-1|-1|-2|3"},
		{"numeric aggregate", `(sum((1,2,3)),avg((1,2,3)),min((3,1,2)),max((3,1,2)),sum((),9),count(avg(())))`, "6|2|1|3|9|0"},
		{"distinct removes duplicate values", `sort(distinct-values((3,1,3,2,1)))`, "1|2|3"},
		{"index positions are one based", `index-of(('a','b','a'),'a')`, "1|3"},
		{"insert boundaries", `(insert-before((1,2),0,0),insert-before((1,2),99,3))`, "0|1|2|1|2|3"},
		{"remove absent positions", `(remove((1,2,3),2),remove((1,2),0),remove((1,2),99))`, "1|3|1|2|1|2"},
		{"reverse ordered sequence", `reverse((1,2,3))`, "3|2|1"},
		{"head tail and cardinality", `(head((1,2,3)),tail((1,2,3)),count(head(())),count(tail(())),count(zero-or-one(())),one-or-more((4,5)),exactly-one(6))`, "1|2|3|0|0|0|4|5|6"},
		{"fold noncommutative", `(fold-left((1,2,3),'',function($a,$b){$a||$b}),fold-right((1,2,3),'',function($a,$b){$b||$a}))`, "123|321"},
		{"filter and pair function", `(filter(1 to 5,function($n){$n mod 2=0}),for-each-pair((1,2,3),(10,20),function($a,$b){$a+$b}))`, "2|4|11|22"},
	})
}

func TestFunctionErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, wantCode string }{
		{"array index zero", `array:get([1],0)`, "FOAY0001"},
		{"array index past end", `array:get([1],2)`, "FOAY0001"},
		{"array put past end", `array:put([1],2,3)`, "FOAY0001"},
		{"array empty head", `array:head([])`, "FOAY0001"},
		{"array empty tail", `array:tail([])`, "FOAY0001"},
		{"array negative subarray length", `array:subarray([1],1,-1)`, "FOAY0002"},
		{"array remove invalid position", `array:remove([1],(1,2))`, "FOAY0001"},
		{"array insert invalid position", `array:insert-before([1],3,2)`, "FOAY0001"},
		{"map duplicate reject", `map:merge((map{'a':1},map{'a':2}),map{'duplicates':'reject'})`, "FOJS0003"},
		{"map duplicate constructor", `map{'a':1,'a':2}`, "XQDY0137"},
		{"JSON trailing content", `parse-json('{}x')`, "FOJS0001"},
		{"JSON leading zero", `parse-json('01')`, "FOJS0001"},
		{"JSON trailing comma", `parse-json('[1,]')`, "FOJS0001"},
		{"JSON duplicates rejected", `parse-json('{"a":1,"a":2}',map{'duplicates':'reject'})`, "FOJS0003"},
		{"JSON invalid duplicate option", `parse-json('{}',map{'duplicates':'combine'})`, "FOJS0005"},
		{"timezone beyond fourteen hours", `adjust-dateTime-to-timezone(xs:dateTime('2024-01-01T00:00:00Z'),xs:dayTimeDuration('PT14H1M'))`, "FODT0003"},
		{"date time timezone conflict", `dateTime(xs:date('2024-01-01+02:00'),xs:time('00:00:00+03:00'))`, "FORG0008"},
		{"mixed duration kinds", `xs:yearMonthDuration('P1M') + xs:dayTimeDuration('P1D')`, "XPTY0004"},
		{"generic duration arithmetic", `xs:duration('P1M') + xs:duration('P1M')`, "XPTY0004"},
		{"duration multiplication by duration", `xs:yearMonthDuration('P1M') * xs:yearMonthDuration('P2M')`, "XPTY0004"},
		{"year month duration overflow", `xs:yearMonthDuration('P` + strconv.Itoa(math.MaxInt) + `M') + xs:yearMonthDuration('P1M')`, "FODT0002"},
		{"decimal division by zero", `xs:decimal('1') div xs:decimal('0')`, "FOAR0001"},
		{"decimal integer division by zero", `xs:decimal('1') idiv xs:decimal('0')`, "FOAR0001"},
		{"decimal modulo by zero", `xs:decimal('1') mod xs:decimal('0')`, "FOAR0001"},
		{"invalid Unicode scalar", `codepoints-to-string(0)`, "FOCH0001"},
		{"invalid regex flag", `matches('x','x','z')`, "FORX0001"},
		{"invalid regex", `matches('x','[')`, "FORX0002"},
		{"tokenize zero width", `tokenize('abc','a*')`, "FORX0003"},
		{"invalid replacement", `replace('x','x','$')`, "FORX0004"},
		{"zero or one rejects two", `zero-or-one((1,2))`, "FORG0003"},
		{"one or more rejects empty", `one-or-more(())`, "FORG0004"},
		{"exactly one rejects empty", `exactly-one(())`, "FORG0005"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, test.expression, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: test.wantCode}) {
					t.Fatalf("%s = %v, %v; want no result and %s", test.expression, seq, err, test.wantCode)
				}
			})
		}
	}
}

func TestISOWeekWithinMonthCalendarDates(t *testing.T) {
	for _, tc := range []struct {
		name, source, place string
		want                int
	}{
		{"March3_NY", "2025-03-03T12:00:00-05:00", "America/New_York", 1},
		{"March10_NY", "2025-03-10T12:00:00-04:00", "America/New_York", 2},
		{"March17_NY", "2025-03-17T12:00:00-04:00", "America/New_York", 3},
		{"March3_UTC", "2025-03-03T12:00:00-05:00", "UTC", 1},
		{"March10_UTC", "2025-03-10T12:00:00-04:00", "UTC", 2},
		{"March17_UTC", "2025-03-17T12:00:00-04:00", "UTC", 3},
		{"March3_Fixed", "2025-03-03T12:00:00-05:00", "Etc/GMT+4", 1},
		{"March10_Fixed", "2025-03-10T12:00:00-04:00", "Etc/GMT+4", 2},
		{"March17_Fixed", "2025-03-17T12:00:00-04:00", "Etc/GMT+4", 3},
		{"FallOctober27", "2025-10-27T12:00:00-04:00", "America/New_York", 5},
		{"FallNovember3", "2025-11-03T12:00:00-05:00", "America/New_York", 1},
		{"FallNovember10", "2025-11-10T12:00:00-05:00", "America/New_York", 2},
		{"December30", "2024-12-30T12:00:00-05:00", "America/New_York", 1},
		{"January1", "2025-01-01T12:00:00-05:00", "America/New_York", 1},
		{"W3CJanuary29", "2013-01-29T12:00:00-05:00", "America/New_York", 5},
		{"W3CFebruary1", "2013-02-01T12:00:00-05:00", "America/New_York", 5},
		{"LeapFebruary29", "2024-02-29T12:00:00-05:00", "America/New_York", 5},
		{"AfterLeapMarch1", "2024-03-01T12:00:00-05:00", "America/New_York", 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loc, err := time.LoadLocation(tc.place)
			if err != nil {
				t.Fatal(err)
			}
			instant, err := time.Parse(time.RFC3339, tc.source)
			if err != nil {
				t.Fatal(err)
			}
			instant = instant.In(loc)
			// F&O3.1 numbers the Monday-to-Sunday week by its Thursday's ordinal
			// within that Thursday's month. This oracle uses civil dates, not elapsed hours.
			civil := time.Date(instant.Year(), instant.Month(), instant.Day(), 12, 0, 0, 0, time.UTC)
			weekday := int(civil.Weekday())
			if weekday == 0 {
				weekday = 7
			}
			thursday := civil.AddDate(0, 0, 4-weekday)
			if oracle := (thursday.Day()-1)/7 + 1; oracle != tc.want {
				t.Fatalf("fixture/oracle = %d, want %d", oracle, tc.want)
			}
			if got := isoWeekOfMonth(instant); got != tc.want {
				t.Fatalf("week = %d, want %d (Thursday %s)", got, tc.want, thursday.Format("2006-01-02"))
			}
		})
	}
}

// TestHTMLDoctypeLegacyFallbackIdentifier covers the private legacy fallback.
// The public HTML4 prolog does not select this fallback without explicit metadata.
func TestHTMLDoctypeLegacyFallbackIdentifier(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		opts serializeOptions
		want string
	}{
		{"legacy HTML4 fallback", serializeOptions{htmlVersion: "4.01"}, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n"},
		{"HTML5 control", serializeOptions{htmlVersion: "5"}, "<!DOCTYPE html>\n"},
		{"explicit identifier control", serializeOptions{htmlVersion: "4.01", doctypeSystem: "urn:custom"}, "<!DOCTYPE html SYSTEM \"urn:custom\">\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := htmlDoctype(tc.opts); got != tc.want {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
		})
	}
}

func TestUCAMalformedOriginalByteIndex(t *testing.T) {
	for _, tc := range []struct {
		name, source, needle string
		numeric              bool
		position, length     int
	}{
		{"MalformedPrefix", "\xffa", "a", false, 1, 1},
		{"MalformedMatch", "L\xffR", "\ufffd", false, 1, 1},
		{"TruncatedPrefix", "\xe2\x82a", "a", false, 2, 1},
		{"OverlongPrefix", "\xc0\xafa", "a", false, 2, 1},
		{"SurrogatePrefix", "\xed\xa0\x80a", "a", false, 3, 1},
		{"ValidReplacement", "\ufffda", "a", false, 3, 1},
		{"Supplementary", "😀a", "a", false, 4, 1},
		{"EmptyNeedle", "\xffa", "", false, 0, 0},
		{"Miss", "\xffa", "x", false, -1, 0},
		{"NumericSplit", "100", "10", true, -1, 0},
		{"NumericWhole", "a001b", "001", true, 1, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pos, length := ucaIndexOf(strings.Compare, tc.source, tc.needle, tc.numeric)
			if pos != tc.position || length != tc.length {
				t.Fatalf("got(%d,%d); want(%d,%d)", pos, length, tc.position, tc.length)
			}
		})
	}
}

func TestUCAMalformedOriginalBytePrefixAndSuffix(t *testing.T) {
	for _, tc := range []struct {
		name, prefixSource, suffixSource, needle string
		match                                    bool
		length                                   int
	}{
		{"Malformed", "\xffa", "a\xff", "\ufffd", true, 1},
		{"Truncated", "\xc3a", "a\xc3", "\ufffd", true, 1},
		{"ValidReplacement", "\ufffda", "a\ufffd", "\ufffd", true, 3},
		{"Supplementary", "😀a", "a😀", "😀", true, 4},
		{"EmptyNeedle", "\xffa", "a\xff", "", true, 0},
		{"Miss", "\xffa", "a\xff", "x", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, length := ucaHasPrefix(strings.Compare, tc.prefixSource, tc.needle, false)
			if ok != tc.match || length != tc.length {
				t.Fatalf("prefix got(%t,%d); want(%t,%d)", ok, length, tc.match, tc.length)
			}
			ok, length = ucaHasSuffix(strings.Compare, tc.suffixSource, tc.needle, false)
			if ok != tc.match || length != tc.length {
				t.Fatalf("suffix got(%t,%d); want(%t,%d)", ok, length, tc.match, tc.length)
			}
		})
	}
}

func TestUCACandidateComparatorOrderAndMalformedFallback(t *testing.T) {
	cases := []struct {
		name, method, source, needle string
		numeric                      bool
		want                         [2]int
		candidates                   []string
	}{
		{"IndexLongerFirst", "index", "abc", "zz", false, [2]int{-1, -1}, []string{"", "ab", "abc", "a", "bc", "b", "c"}},
		{"PrefixLongerFirst", "prefix", "abc", "zz", false, [2]int{0, 0}, []string{"", "ab", "abc", "a"}},
		{"SuffixLongerFirst", "suffix", "abc", "zz", false, [2]int{0, 0}, []string{"", "bc", "abc", "c"}},
		{"ShortSourceIndex", "index", "a", "longer", false, [2]int{-1, -1}, []string{"", "a"}},
		{"ShortSourcePrefix", "prefix", "a", "longer", false, [2]int{0, 0}, []string{"", "a"}},
		{"EmptySourceIndex", "index", "", "a", false, [2]int{-1, -1}, []string{""}},
		{"EmptySourcePrefix", "prefix", "", "a", false, [2]int{0, 0}, []string{"", ""}},
		{"EmptySourceSuffix", "suffix", "", "a", false, [2]int{0, 0}, []string{"", ""}},
		{"EmptyNeedleIndex", "index", "abc", "", false, [2]int{0, 0}, nil},
		{"EmptyNeedlePrefix", "prefix", "abc", "", false, [2]int{0, 1}, nil},
		{"EmptyNeedleSuffix", "suffix", "abc", "", false, [2]int{3, 1}, nil},
		{"NumericSplitContinues", "index", "100", "10", true, [2]int{-1, -1}, []string{"", "10", "100", "1", "00", "0", "0"}},
		{"NonNumericAccepts", "index", "100", "10", false, [2]int{0, 2}, []string{"", "10"}},
		{"MalformedSourceIndex", "index", "\xffa", "a", false, [2]int{1, 2}, []string{"", "\ufffd", "\ufffda", "a"}},
		{"MalformedSourcePrefix", "prefix", "\xffa", "\ufffd", false, [2]int{1, 1}, []string{"", "\ufffd"}},
		{"MalformedSourceSuffix", "suffix", "a\xff", "\ufffd", false, [2]int{1, 1}, []string{"", "\ufffd"}},
		{"MalformedNeedle", "index", "\ufffd", "\xff", false, [2]int{-1, -1}, []string{"", "\ufffd"}},
		{"ValidReplacement", "index", "\ufffda", "a", false, [2]int{1, 2}, []string{"", "\ufffd", "\ufffda", "a"}},
		{"Supplementary", "index", "😀a", "a", false, [2]int{1, 2}, []string{"", "😀", "😀a", "a"}},
		{"CombiningNeedleRuneCount", "prefix", "é", "e\u0301", false, [2]int{0, 0}, []string{"", "é"}},
	}
	type comparison struct {
		candidate, needle string
		result            int
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var trace []comparison
			cmp := func(a, b string) int {
				r := strings.Compare(a, b)
				trace = append(trace, comparison{a, b, r})
				return r
			}
			var got [2]int
			switch tc.method {
			case "index":
				got[0], got[1] = ucaIndexOfRange(cmp, tc.source, tc.needle, tc.numeric)
			case "prefix":
				end, ok := ucaHasPrefixRange(cmp, tc.source, tc.needle, tc.numeric)
				got[0] = end
				if ok {
					got[1] = 1
				}
			case "suffix":
				start, ok := ucaHasSuffixRange(cmp, tc.source, tc.needle, tc.numeric)
				got[0] = start
				if ok {
					got[1] = 1
				}
			default:
				t.Fatal("unknown test method")
			}
			var want []comparison
			// Candidate order is explicit test data; only comparator result comes from
			// the independent strings.Compare, never from the candidate constructor.
			for _, candidate := range tc.candidates {
				want = append(want, comparison{candidate, tc.needle, strings.Compare(candidate, tc.needle)})
			}
			if got != tc.want || !reflect.DeepEqual(trace, want) {
				t.Fatalf("got%v trace%#v; want%v trace%#v", got, trace, tc.want, want)
			}
		})
	}
}

func TestUCACandidateBoundaryModes(t *testing.T) {
	for _, tc := range []struct {
		name, source, needle string
		wantBoundaries       []int
		start, end           int
		wantCandidate        string
	}{
		{"ASCII", "abc", "a", []int{}, 1, 2, "b"},
		{"EmptyASCII", "", "a", []int{}, 0, 0, ""},
		{"ASCIIWithUnicodeNeedle", "abc", "é", []int{}, 0, 2, "ab"},
		{"ASCIIControls", "\x00a", "a", []int{}, 0, 1, "\x00"},
		{"Unicode", "aéz", "a", []int{0, 1, 3, 4}, 1, 2, "é"},
		{"Combining", "e\u0301z", "é", []int{0, 1, 3, 4}, 0, 2, "e\u0301"},
		{"ValidReplacement", "\ufffda", "a", []int{0, 3, 4}, 0, 1, "\ufffd"},
		{"MalformedSourceWidthOne", "\xffa", "a", nil, 0, 1, "\ufffd"},
		{"MalformedSourceTruncated", "\xe2\x82a", "a", nil, 0, 2, "\ufffd\ufffd"},
		{"MalformedNeedle", "abc", "\xff", nil, 1, 2, "b"},
		{"EmptySourceMalformedNeedle", "", "\xff", nil, 0, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runes := []rune(tc.source)
			boundaries := ucaCandidateBoundaries(tc.source, tc.needle, len(runes))
			if !reflect.DeepEqual(boundaries, tc.wantBoundaries) {
				t.Fatalf("boundaries %#v; want %#v", boundaries, tc.wantBoundaries)
			}

			candidate := ucaCandidateString(tc.source, runes, boundaries, tc.start, tc.end)
			if candidate != tc.wantCandidate {
				t.Fatalf("candidate %q; want %q", candidate, tc.wantCandidate)
			}
		})
	}
}

func TestSerializationCharacterRunsOriginalByteBoundaries(t *testing.T) {
	t.Parallel()
	for _, form := range []string{"none", "NFC"} {
		for _, tc := range []struct {
			name, source, want string
			mapping            map[rune]string
		}{
			{"one invalid byte", "\xff", "x", map[rune]string{'\uFFFD': "x"}},
			{"two invalid bytes", "\xff\xfe", "xx", map[rune]string{'\uFFFD': "x"}},
			{"invalid middle", "A\xffB", "AxB", map[rune]string{'\uFFFD': "x"}},
			{"delete invalid middle", "A\xffB", "AB", map[rune]string{'\uFFFD': ""}},
			{"encoded replacement", "\uFFFD", "x", map[rune]string{'\uFFFD': "x"}},
			{"no map", "\xff", "\xff", nil},
			{"unrelated map", "\xff", "\xff", map[rune]string{'Q': "y"}},
			{"valid composition", "A\u030A", "Å", map[rune]string{'\uFFFD': "x"}},
		} {
			if form == "none" && tc.name == "valid composition" {
				tc.want = tc.source
			}
			t.Run(form+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("character mapping must not panic for original bytes %x: %v", tc.source, p)
					}
				}()
				opts := serializeOptions{ctx: t.Context(), normalizationForm: form, charMap: tc.mapping}
				var out strings.Builder
				emit := func(s string) error { _, err := out.WriteString(s); return err }
				if err := opts.characterRuns(tc.source, emit, emit); err != nil {
					t.Fatal(err)
				}
				if got := out.String(); got != tc.want {
					t.Fatalf("actual %q bytes %x; want %q bytes %x", got, got, tc.want, tc.want)
				}
			})
		}
	}
}

func TestSerializationMalformedRunsCallbackErrors(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("character callback stopped")
	for _, failAt := range []string{"plain", "mapped"} {
		t.Run(failAt, func(t *testing.T) {
			t.Parallel()
			opts := serializeOptions{ctx: t.Context(), charMap: map[rune]string{'\uFFFD': "x"}}
			var calls []string
			err := opts.characterRuns("A\xffB", func(s string) error {
				calls = append(calls, "plain:"+s)
				if failAt == "plain" {
					return sentinel
				}
				return nil
			}, func(s string) error { calls = append(calls, "mapped:"+s); return sentinel })
			want := []string{"plain:A"}
			if failAt == "mapped" {
				want = append(want, "mapped:x")
			}
			if !errors.Is(err, sentinel) || !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls %q/error %v; want %q/sentinel", calls, err, want)
			}
		})
	}
}

func TestSerializationJSONRunOriginalByteBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, source, want string }{
		{"one invalid byte", "\xff", `\uFFFD`},
		{"two invalid bytes", "\xff\xfe", `\uFFFD\uFFFD`},
		{"invalid middle", "A\xffB", `A\uFFFDB`},
		{"encoded replacement", "\uFFFD", `\uFFFD`},
		{"valid ASCII", "ABC", "ABC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("JSON escaping must not panic for original bytes %x: %v", tc.source, p)
				}
			}()
			var out strings.Builder
			if err := writeSerializedJSONRun(t.Context(), &out, tc.source, func(r rune) bool { return r < 128 }); err != nil {
				t.Fatal(err)
			}
			if got := out.String(); got != tc.want {
				t.Fatalf("actual %q; want %q", got, tc.want)
			}
		})
	}
	sentinel := errors.New("JSON destination stopped")
	for _, failAt := range []int{1, 2} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			t.Parallel()
			dst := &malformedJSONSentinelWriter{cause: sentinel, failAt: failAt}
			err := writeSerializedJSONRun(t.Context(), dst, "A\xffB", func(r rune) bool { return r < 128 })
			if !errors.Is(err, sentinel) || dst.calls != failAt {
				t.Fatalf("calls %d/error %v; want %d/sentinel", dst.calls, err, failAt)
			}
		})
	}
}

type malformedJSONSentinelWriter struct {
	cause         error
	failAt, calls int
}

func (w *malformedJSONSentinelWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		return 0, w.cause
	}
	return len(p), nil
}
