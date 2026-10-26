package xpath //nolint:testpackage // Checks built-in function results on the AST and VM dispatch paths.

import (
	"errors"
	"math"
	"strconv"
	"testing"

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
