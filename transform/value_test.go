package transform_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/skarm/xmlsec/transform"
)

func TestTypedValues(t *testing.T) {
	if value, err := transform.Values(transform.Integer(1), transform.Integer(2)).EffectiveBoolean(); err == nil {
		t.Fatal(value)
	}

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for source, want := range map[string]int{"(1,2)": 2, "()": 0} {
			t.Run(strconv.Itoa(int(version))+"/sequence/"+source, func(t *testing.T) {
				publishedProofVector(t, strconv.Itoa(want))
				e := engine(t, transform.Config{})
				result, err := query(t, e, source, version).Evaluate(t.Context(), nil, transform.XPathContext{})
				if err != nil || result.Len() != want {
					t.Fatal(result.Len(), err, want)
				}
				// Text is a singleton convenience conversion; evaluation exposes the XDM
				// sequence and does not silently serialize an empty or plural result.
				if _, err := result.Text(); !errors.Is(err, transform.ErrInput) {
					t.Fatal("implicit serialization", err)
				}
			})
		}
	}

	m, err := transform.Map(transform.MapEntry{Key: transform.String("a"), Value: transform.Values(transform.Integer(1))})
	if err != nil {
		t.Fatal(err)
	}

	entry, ok := m.Lookup(transform.String("a"))
	if !ok || text(t, entry) != "1" {
		t.Fatal(entry, ok)
	}

	a := transform.Array(entry)

	member, err := a.Member(0)
	if err != nil || text(t, member) != "1" {
		t.Fatal(member, err)
	}

	if _, err = a.Member(1); err == nil {
		t.Fatal("index accepted")
	}

	date := transform.DateTime(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC))
	if date.Type().Local != "dateTime" {
		t.Fatal(date.Type())
	}

	if _, err = transform.Map(transform.MapEntry{Key: transform.String("a")}, transform.MapEntry{Key: transform.String("a")}); err == nil {
		t.Fatal("duplicate key")
	}
}

func contextStringFunctionCases() []transformExpressionCase {
	var cases []transformExpressionCase
	for index, name := range []string{"string", "string-length", "normalize-space"} {
		for _, focus := range []string{"upper-case#1", "map{}", "[]"} {
			cases = append(cases, transformExpressionCase{name + " focus " + focus, "(" + focus + ")!" + name + "()", "FOTY0014"})
		}
		for _, call := range []string{"(" + name + "#0)()", "function-lookup(xs:QName('fn:" + name + "'),0)()"} {
			cases = append(cases, transformExpressionCase{name + " dynamic " + call, "(upper-case#1)!" + call, "FOTY0014"})
		}
		cases = append(cases,
			transformExpressionCase{name + " absent", name + "()", "XPDY0002"},
			transformExpressionCase{name + " atomic", "' a '!" + name + "()", []string{" a ", "3", "a"}[index]},
			transformExpressionCase{name + " node", "parse-xml('<r>003</r>')/r!" + name + "()", "003"},
		)
		if name == "string-length" {
			cases[len(cases)-1].want = "3"
		}
	}
	return cases
}

func TestContextStringFunctions(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for _, test := range contextStringFunctionCases() {
			if version == transform.XPath30 && (strings.Contains(test.expression, "map{}") || strings.Contains(test.expression, "[]")) {
				continue
			}
			q := query(t, e, test.expression, version)
			result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
			if comparisonErrorCode(test.want) {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatal(version, test.name, result, err, test.want)
				}
			} else if err != nil || text(t, result) != test.want {
				t.Fatal(version, test.name, result, err, test.want)
			}
		}
	}
}

func TestArraySubarrayIntegerBoundaries(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range []struct {
		arguments string
		want      string
	}{
		{`[1,2,3],2,2`, "2,3"},
		{`[1,2,3],4,0`, ""},
		{`[],1,0`, ""},
		{`[1],1,-1`, "FOAY0002"},
		{`[1],1,-9223372036854775808`, "FOAY0002"},
		{`[1],1,-99999999999999999999999999999`, "FOAY0002"},
		{`[1],1,xs:untypedAtomic('-99999999999999999999999999999')`, "FOAY0002"},
		{`[1],1,9223372036854775807`, "FOAY0001"},
		{`[1],1,99999999999999999999999999999`, "FOAY0001"},
		{`[1],-99999999999999999999999999999,0`, "FOAY0001"},
		{`[1],99999999999999999999999999999,0`, "FOAY0001"},
		{`[1],1,1.5`, "XPTY0004"},
	} {
		for _, callable := range []string{`array:subarray`, `array:subarray#3`, `function-lookup(QName('http://www.w3.org/2005/xpath-functions/array','subarray'),3)`} {
			expression := callable + "(" + test.arguments + ")"
			t.Run(expression, func(t *testing.T) {
				q := query(t, e, `string-join(`+expression+`?* ! string(.),',')`, transform.XPath31)
				result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
				if strings.HasPrefix(test.want, "FOAY") || test.want == "XPTY0004" {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatalf("got %v, want %s", err, test.want)
					}
				} else if err != nil || text(t, result) != test.want {
					t.Fatalf("got %v (%v), want %q", result, err, test.want)
				}
			})
		}
	}
}

func TestBinaryAggregateVersions(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, test := range []struct {
			expression string
			want       string
		}{
			{`min(xs:hexBinary('01'))`, "01"},
			{`max(xs:base64Binary('AAAA'))`, "AAAA"},
			{`min((xs:base64Binary('////'),xs:base64Binary('AAAA')))`, "AAAA"},
			{`max((xs:hexBinary('01'),xs:hexBinary('02')))`, "02"},
			{`min((xs:hexBinary('01'),xs:base64Binary('AQ==')))`, "FORG0006"},
			{`string-join(distinct-values((xs:hexBinary('01'),xs:hexBinary('01'))) ! string(.),',')`, "01"},
			{`min((2,1))`, "1"},
		} {
			// Simple-map syntax is unavailable in XPath 2.0.
			if version == transform.XPath20 && strings.Contains(test.expression, " ! ") {
				test.expression = `string(distinct-values((xs:hexBinary('01'),xs:hexBinary('01'))))`
			}
			q := query(t, e, test.expression, version)
			result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
			want := test.want
			if version < transform.XPath31 && (strings.HasPrefix(test.expression, "min(xs:") || strings.HasPrefix(test.expression, "max(xs:") || strings.HasPrefix(test.expression, "min((xs:") || strings.HasPrefix(test.expression, "max((xs:")) {
				want = "FORG0006"
			}
			if want == "FORG0006" {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != want {
					t.Fatalf("%d %s: got %v, want %s", version, test.expression, err, want)
				}
			} else if err != nil || text(t, result) != want {
				t.Fatalf("%d %s: got %v (%v), want %s", version, test.expression, result, err, want)
			}
		}
	}
}

func aggregateTimezoneExpressions() []string {
	return []string{
		`for $local in xs:dateTime('2000-01-01T00:00:00') return index-of($local,adjust-dateTime-to-timezone($local)) eq 1`,
		`for $local in xs:dateTime('2000-01-01T00:00:00'), $early in adjust-dateTime-to-timezone($local)-xs:dayTimeDuration('PT1H') return min(($local,$early)) eq $early`,
		`for $local in xs:dateTime('2000-01-01T00:00:00'), $late in adjust-dateTime-to-timezone($local)+xs:dayTimeDuration('PT1H') return max(($local,$late)) eq $late`,
		`for $local in xs:dateTime('2000-01-01T00:00:00') return count(distinct-values(($local,adjust-dateTime-to-timezone($local)))) eq 1`,
		`index-of(('A',xs:anyURI('a')),'a','http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive') = 2`,
	}
}

func TestAggregateImplicitTimezone(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, offset := range []int{-2 * 3600, 0, 2 * 3600} {
			for _, expression := range aggregateTimezoneExpressions() {
				result, err := query(t, e, expression, version).Evaluate(t.Context(), nil, transform.XPathContext{Context: transform.DynamicContext{ImplicitTimezone: time.FixedZone("", offset)}})
				if err != nil || text(t, result) != nameTrue {
					t.Fatal(version, offset, expression, result, err)
				}
			}
		}
	}
}

func randomGeneratorValueExpressions() []string {
	return []string{
		`random-number-generator(QName('urn:q','a:n'))?number eq random-number-generator(QName('urn:q','b:n'))?number`,
		`random-number-generator(xs:dateTime('2000-01-01T00:00:00Z'))?number eq random-number-generator(xs:dateTime('2000-01-01T02:00:00+02:00'))?number`,
		`random-number-generator(xs:time('12:00:00Z'))?number eq random-number-generator(xs:time('14:00:00+02:00'))?number`,
		`random-number-generator(xs:double('0'))?number eq random-number-generator(xs:double('-0'))?number`,
		`random-number-generator(xs:float('0'))?number eq random-number-generator(xs:float('-0'))?number`,
		`random-number-generator(xs:gYear('2000+00:00'))?number eq random-number-generator(xs:gYear('2000Z'))?number`,
		`random-number-generator(xs:dateTimeStamp('2000-01-01T00:00:00Z'))?number eq random-number-generator(xs:dateTimeStamp('2000-01-01T02:00:00+02:00'))?number`,
		`for $local in xs:dateTime('2000-01-01T00:00:00') return random-number-generator($local)?number eq random-number-generator(adjust-dateTime-to-timezone($local))?number`,
		`for $local in xs:time('00:00:00') return random-number-generator($local)?number eq random-number-generator(adjust-time-to-timezone($local))?number`,
		`let $r:=random-number-generator(1) return $r?next()?number eq $r?next()?number`,
		`let $r:=random-number-generator(1) return empty(function-name($r?next)) and empty(function-name($r?permute))`,
		`let $r:=random-number-generator(1) return function-arity($r?next) eq 0 and function-arity($r?permute) eq 1`,
		`random-number-generator(1)?next instance of function() as map(xs:string,item())`,
		`not(random-number-generator(1)?next instance of function() as xs:integer)`,
		`random-number-generator(1)?permute instance of function(item()*) as item()*`,
		`not(random-number-generator(1)?permute instance of function(item()*) as item())`,
		`let $r:=random-number-generator(1) return $r?number ge 0 and $r?number lt 1 and $r?next()?number ge 0 and $r?next()?number lt 1`,
		`let $r:=random-number-generator(1) return deep-equal($r?permute(1 to 20), $r?permute(1 to 20))`,
		`let $r:=random-number-generator(1) return deep-equal(sort($r?permute((1,2,2,3))), (1,2,2,3))`,
		`let $r:=random-number-generator(1) return empty($r?permute(()))`,
		`let $r:=random-number-generator(1) return $r?permute(42) eq 42`,
		`random-number-generator(1)?next()?next()?number eq random-number-generator(1)?next()?next()?number`,
	}
}

func aggregateFloatPromotionExpressions() []string {
	return []string{
		`sum((xs:decimal('16777217'),xs:float('-16777216'))) eq 0`,
		`sum((xs:float('-16777216'),xs:decimal('16777217'))) eq 0`,
		`avg((xs:decimal('16777217'),xs:float('-16777216'))) eq 0`,
		`sum((xs:float('16777216'),xs:float('1'),xs:double('-16777216'))) eq 1`,
		`sum((xs:decimal('1.000000059604644775390625000000001'),xs:float(0))) eq xs:float('1.00000011920928955078125')`,
		`min((xs:decimal('1.000000059604644775390625000000001'),xs:float(2))) eq xs:float('1.00000011920928955078125')`,
		`max((xs:decimal('1.000000059604644775390625000000001'),xs:float(0))) eq xs:float('1.00000011920928955078125')`,
		`avg((xs:decimal('1.000000059604644775390625000000001'),xs:float('1.00000011920928955078125'))) eq xs:float('1.00000011920928955078125')`,
		`sum((xs:float('16777216'),xs:float('1'),xs:float('-16777216'))) = (0,1)`,
	}
}

func TestAggregateFloatPromotion(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, expression := range aggregateFloatPromotionExpressions() {
			if got := text(t, evaluate(t, e, expression, version)); got != nameTrue {
				t.Fatal(version, expression, got)
			}
		}
	}
}

func collectionFunctionTypeCases() map[string]string {
	return map[string]string{
		`(function() as array(*) {[1]}) instance of function() as function(xs:string) as item()*`:                            "false",
		`(function() as array(*) {[1]}) instance of function() as function(xs:integer) as item()*`:                           "true",
		`(function() as array(xs:integer) {[1]}) instance of function() as function(xs:integer) as xs:integer`:               "true",
		`(function() as array(xs:integer+) {[(1,2)]}) instance of function() as function(xs:integer) as xs:integer?`:         "false",
		`(function() as map(*) {map{}}) instance of function() as function(xs:string) as xs:integer?`:                        "false",
		`(function() as map(*) {map{}}) instance of function() as function(xs:anyAtomicType) as item()*`:                     "true",
		`(function() as map(xs:integer,xs:string) {map{1:'x'}}) instance of function() as function(xs:string) as xs:string?`: "true",
		`(function() as map(xs:integer,xs:string) {map{1:'x'}}) instance of function() as function(xs:string) as xs:string`:  "false",
		`random-number-generator(1)?next instance of function() as function(xs:string) as xs:integer?`:                       "false",
		`(function($f as function(xs:string) as xs:integer?){$f('x')}) instance of function(map(*)) as item()*`:              "false",
		`[1] instance of function(xs:string) as item()*`:                                                                     "false",
		`[] instance of function(item()) as item()*`:                                                                         "false",
		`[] instance of function(xs:integer?) as item()*`:                                                                    "false",
		`[] instance of function(xs:integer*) as item()*`:                                                                    "false",
		`[] instance of function(xs:decimal) as item()*`:                                                                     "false",
		`[] instance of function(xs:integer) as item()*`:                                                                     "true",
		`[1] instance of function(xs:positiveInteger) as xs:integer`:                                                         "true",
		`[1] instance of function(xs:integer) as xs:string`:                                                                  "false",
		`map{} instance of function(item()) as item()*`:                                                                      "false",
		`map{} instance of function(map(*)) as item()*`:                                                                      "false",
		`map{} instance of function(xs:string?) as item()*`:                                                                  "false",
		`map{} instance of function(xs:string) as item()*`:                                                                   "true",
		`map{} instance of function(xs:anyAtomicType) as item()*`:                                                            "true",
		`map{1:'x'} instance of function(xs:string) as xs:integer?`:                                                          "false",
		`map{1:'x'} instance of function(xs:integer) as xs:string?`:                                                          "true",
		`map{1:'x'} instance of function(xs:integer) as xs:string`:                                                           "false",
		`map{1:()} instance of function(xs:integer) as empty-sequence()`:                                                     "true",
		`(function($f as function(xs:integer) as xs:integer){$f(1)})([42]) eq 42`:                                            "true",
		`(function($f as function(xs:string) as xs:string){$f('k')})(map{'k':'v'}) eq 'v'`:                                   "true",
	}
}

func additionalFunctionTypeCases() map[string]string {
	cases := collectionFunctionTypeCases()
	for _, expression := range randomGeneratorValueExpressions() {
		cases[expression] = nameTrue
	}
	for _, call := range []string{`default-collation()`, `default-collation#0()`, `function-lookup(xs:QName('fn:default-collation'),0)()`} {
		cases[call+` instance of xs:string`] = nameTrue
		cases[call+` instance of xs:anyURI`] = nameFalse
	}
	cases[`default-language() instance of xs:language`] = nameTrue
	cases[`array:size(array:subarray([1],2,0)) eq 0`] = nameTrue
	return cases
}

func TestRandomGeneratorFunctionValues(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, expression := range randomGeneratorValueExpressions() {
		if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != "true" {
			t.Fatal(expression, got)
		}
	}
	for _, offset := range []int{-2 * 3600, 2 * 3600} {
		for _, expression := range randomGeneratorValueExpressions() {
			result, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Context: transform.DynamicContext{ImplicitTimezone: time.FixedZone("", offset)}})
			if err != nil || text(t, result) != nameTrue {
				t.Fatal(offset, expression, result, err)
			}
		}
	}
	for _, expression := range []string{`random-number-generator((1,2))`, `random-number-generator(1)?next(1)`, `random-number-generator(1)?permute()`} {
		_, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "XPTY0004" {
			t.Fatalf("%s: got %v, want XPTY0004", expression, err)
		}
	}

	// Reusing an escaped generator must not advance mutable producer state.
	next := evaluate(t, e, `random-number-generator(1)?next`, transform.XPath31)
	q := query(t, e, `$next()?number`, transform.XPath31)
	bindings := transform.XPathContext{Variables: transform.Bindings{{Local: "next"}: next}}
	first, err := q.Evaluate(t.Context(), nil, bindings)
	if err != nil {
		t.Fatal(err)
	}
	want := text(t, first)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			result, err := q.Evaluate(t.Context(), nil, bindings)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := result.Text()
			if err != nil || got != want {
				t.Errorf("reused next returned %q (%v), want %q", got, err, want)
			}
		})
	}
	workers.Wait()
}

func TestDefaultCollationValueType(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, collation := range []string{"http://www.w3.org/2005/xpath-functions/collation/codepoint", "http://www.w3.org/2013/collation/UCA?strength=primary"} {
			calls := []string{`default-collation()`}
			if version >= transform.XPath30 {
				calls = append(calls, `default-collation#0()`, `function-lookup(xs:QName('fn:default-collation'),0)()`)
			}
			for _, call := range calls {
				expression := call + ` instance of xs:string and not(` + call + ` instance of xs:anyURI) and ` + call + ` eq '` + collation + `' and static-base-uri() instance of xs:anyURI`
				q, err := e.CompileXPath(t.Context(), expression, transform.XPathOptions{Version: version, DefaultCollation: collation, BaseURI: "urn:static-base"})
				if err != nil {
					t.Fatal(expression, err)
				}
				result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
				if err != nil || text(t, result) != "true" {
					t.Fatalf("%v %s: got %v (%v)", version, expression, result, err)
				}
			}
		}
	}
}

func TestDefaultLanguageValues(t *testing.T) {
	e := engine(t, transform.Config{})
	q := query(t, e, `default-language()`, transform.XPath31)
	typed := query(t, e, `default-language() instance of xs:language`, transform.XPath31)
	s := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:value-of select="default-language()"/></xsl:template>`))
	for _, test := range []struct {
		supplied string
		want     string
	}{
		{"", "en"}, {"fr", "fr"}, {"\t en-US \r\n", "en-US"}, {"x-unknown", "x-unknown"},
	} {
		options := transform.DynamicContext{DefaultLanguage: test.supplied}
		result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Context: options})
		if err != nil || text(t, result) != test.want {
			t.Fatalf("XPath %q: %v (%v), want %q", test.supplied, result, err, test.want)
		}
		result, err = typed.Evaluate(t.Context(), nil, transform.XPathContext{Context: options})
		if err != nil || text(t, result) != "true" {
			t.Fatal("default language lost its type", result, err)
		}
		output, err := s.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Context: options})
		if err != nil || text(t, output.Primary()) != test.want {
			t.Fatalf("XSLT %q: %v (%v)", test.supplied, output, err)
		}
	}
	for _, language := range []string{"en_US", "en US", "\t\r\n", "\u00a0en\u00a0", "9", "toolongtag"} {
		options := transform.DynamicContext{DefaultLanguage: language}
		_, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Context: options})
		if !errors.Is(err, transform.ErrInput) {
			t.Fatalf("XPath accepted invalid language %q: %v", language, err)
		}
		_, err = s.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Context: options})
		if !errors.Is(err, transform.ErrInput) {
			t.Fatalf("XSLT accepted invalid language %q: %v", language, err)
		}
	}

	for _, source := range []string{`default-language#0`, `function(){default-language()}`} {
		producer, err := query(t, e, source, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Context: transform.DynamicContext{DefaultLanguage: "\tfr "}})
		if err != nil {
			t.Fatal(err)
		}
		result, err := query(t, e, `$f()`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: producer}, Context: transform.DynamicContext{DefaultLanguage: "de"}})
		if err != nil || text(t, result) != "fr" {
			t.Fatal("escaped language lost producer context", source, result, err)
		}
	}
}

func TestCollectionFunctionTypeDomains(t *testing.T) {
	e := engine(t, transform.Config{})
	for expression, want := range collectionFunctionTypeCases() {
		t.Run(expression, func(t *testing.T) {
			if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != want {
				t.Fatalf("got %s, want %s", got, want)
			}
		})
	}
}

func deepEqualNodeCases() map[string]string {
	return map[string]string{
		`deep-equal(parse-xml('<r><!--a--><n/><?p x?></r>'),parse-xml('<r><n/></r>'))`:                                              "true",
		`deep-equal(parse-xml('<!--a--><r/><?p x?>'),parse-xml('<r/>'))`:                                                            "true",
		`deep-equal(parse-xml('<r>a<!--x-->b</r>'),parse-xml('<r>ab</r>'))`:                                                         "false",
		`deep-equal(parse-xml('<r><![CDATA[a]]></r>')/r/text(),parse-xml('<r>a</r>')/r/text())`:                                     "true",
		`deep-equal(parse-xml('<r><!--a--></r>')/r/comment(),parse-xml('<r><!--b--></r>')/r/comment())`:                             "false",
		`deep-equal(parse-xml('<r><?a x?></r>')/r/processing-instruction(),parse-xml('<r><?b x?></r>')/r/processing-instruction())`: "false",
		`deep-equal(parse-xml('<r a="x" b="y"/>'),parse-xml('<r b="y" a="x"/>'))`:                                                   "true",
		`deep-equal(parse-xml('<r>a</r>'),parse-xml('<r>b</r>'))`:                                                                   "false",
		`deep-equal(function(){1},1)`:                   "FOTY0015",
		`deep-equal(1,function(){1})`:                   "FOTY0015",
		`deep-equal(function(){1},function(){1})`:       "FOTY0015",
		`deep-equal(map{'a':function(){1}},map{'a':1})`: "FOTY0015",
		`deep-equal([function(){1}],[1])`:               "FOTY0015",
		`deep-equal(map{'a':1},map{'a':1})`:             "true",
		`deep-equal([1],[1])`:                           "true",
		`deep-equal(map{},1)`:                           "false",
	}
}

func TestDeepEqualNodeContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for expression, want := range deepEqualNodeCases() {
		t.Run(expression, func(t *testing.T) {
			result, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
			if want == "FOTY0015" {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != want {
					t.Fatalf("got %v, want %s", err, want)
				}
			} else if err != nil || text(t, result) != want {
				t.Fatalf("got %v (%v), want %s", result, err, want)
			}
		})
	}
}

func nodeAccessorExpressions() []string {
	return []string{
		`empty(node-name(parse-xml('<r xmlns="urn:r"/>')/*/namespace::*[name()='']))`,
		`node-name(parse-xml('<r xmlns:p="urn:p"/>')/r/namespace::p) eq QName('','p')`,
		`node-name(parse-xml('<r/>')/r/namespace::xml) eq QName('','xml')`,
		`empty(node-name(()))`,
		`empty(node-name(parse-xml('<r/>')))`,
		`path(parse-xml('<r><?p first?><?q other?><?p second?></r>')/r/processing-instruction('p')[2]) eq '/Q{}r[1]/processing-instruction(p)[2]'`,
		`path(parse-xml('<r><?p first?><?q other?><?p second?></r>')/r/processing-instruction('q')) eq '/Q{}r[1]/processing-instruction(q)[1]'`,
		`path(parse-xml('<r><n/><n/></r>')/r/n[2]) eq '/Q{}r[1]/Q{}n[2]'`,
		`path(parse-xml('<r><!--first--><?p other?><!--second--></r>')/r/comment()[2]) eq '/Q{}r[1]/comment()[2]'`,
	}
}

func TestNodeAccessorContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, expression := range nodeAccessorExpressions() {
		if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != nameTrue {
			t.Fatal(expression, got)
		}
	}
}

func mapMergeOptionCases() map[string]string {
	return map[string]string{
		`map:merge((),map{'duplicates':1})`:                                       "XPTY0004",
		`map:merge((),map{'duplicates':()})`:                                      "XPTY0004",
		`map:merge((),map{'duplicates':('use-first','use-last')})`:                "XPTY0004",
		`map:merge((),map{'duplicates':[]})`:                                      "XPTY0004",
		`map:merge((),map{'duplicates':function(){'use-first'}})`:                 "FOTY0013",
		`map:merge((),map{'duplicates':'bad'})`:                                   "FOJS0005",
		`map:merge((),map{'duplicates':xs:untypedAtomic('bad')})`:                 "FOJS0005",
		`map:size(map:merge((),map{'duplicates':xs:untypedAtomic('use-first')}))`: "0",
		`map:size(map:merge((),map{'duplicates':xs:anyURI('use-first')}))`:        "0",
		`map:size(map:merge((),map{'duplicates':xs:NCName('use-first')}))`:        "0",
		`map:size(map:merge((),map{'duplicates':['use-first']}))`:                 "0",
		`map:size(map:merge((),map{xs:untypedAtomic('duplicates'):'use-first'}))`: "0",
		`map:size(map:merge((),map{'unknown':function(){1}}))`:                    "0",
	}
}

func TestMapMergeOptionConversions(t *testing.T) {
	e := engine(t, transform.Config{})
	for expression, want := range mapMergeOptionCases() {
		for _, callable := range []string{`map:merge`, `(map:merge#2)`, `function-lookup(xs:QName('map:merge'),2)`} {
			source := strings.Replace(expression, "map:merge", callable, 1)
			t.Run(source, func(t *testing.T) {
				result, err := query(t, e, source, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
				if want != "0" {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != want {
						t.Fatalf("got %v, want %s", err, want)
					}
				} else if err != nil || text(t, result) != want {
					t.Fatalf("got %v (%v), want %s", result, err, want)
				}
			})
		}
	}
}

func jsonNumberExpressions() map[string]string {
	return map[string]string{
		`string(parse-json('1e400'))`:                              "INF",
		`string(parse-json('-1e400'))`:                             "-INF",
		`string(parse-json('1e99999999999999999999999999999999'))`: "INF",
		`string(parse-json('1e-4000'))`:                            "0",
		`string(parse-json('-1e-4000'))`:                           "-0",
		`parse-json('1e400') instance of xs:double`:                "true",
		`parse-json('+1')`:                                         "FOJS0001",
		`parse-json('01')`:                                         "FOJS0001",
		`parse-json('1e')`:                                         "FOJS0001",
		`parse-json('1e+')`:                                        "FOJS0001",
		`parse-json('NaN')`:                                        "FOJS0001",
		`parse-json('Infinity')`:                                   "FOJS0001",
	}
}

func TestJSONNumberConversions(t *testing.T) {
	e := engine(t, transform.Config{})
	for expression, want := range jsonNumberExpressions() {
		for _, callable := range []string{`parse-json`, `(parse-json#1)`, `function-lookup(xs:QName('fn:parse-json'),1)`} {
			source := strings.Replace(expression, "parse-json", callable, 1)
			result, err := query(t, e, source, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
			if want == "FOJS0001" {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != want {
					t.Fatalf("%s: got %v, want %s", source, err, want)
				}
			} else if err != nil || text(t, result) != want {
				t.Fatalf("%s: got %v (%v), want %s", source, result, err, want)
			}
		}
	}
	if got := text(t, evaluate(t, e, `string(json-to-xml('1e400')/*)`, transform.XPath31)); got != "1e400" {
		t.Fatal("XML representation lost the JSON numeric lexical form", got)
	}
	e = engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("-1e400")), nil
	})})
	if got := text(t, evaluate(t, e, `string(json-doc('urn:json-overflow'))`, transform.XPath31)); got != "-INF" {
		t.Fatal("JSON resource number used different conversion rules", got)
	}
}

func jsonResourceDecodingCases() []struct {
	name    string
	data    []byte
	options string
	want    string
} {
	const value = `"é🙂"`
	type resourceCase = struct {
		name    string
		data    []byte
		options string
		want    string
	}
	cases := make([]resourceCase, 0, 19)
	cases = append(cases, []resourceCase{
		{"UTF8", []byte(value), "", "é🙂"},
		{"UTF8 BOM", append([]byte{0xef, 0xbb, 0xbf}, []byte(value)...), "", "é🙂"},
		{"short UTF16BE", []byte{0, '1'}, "", "1"},
		{"raw NUL", []byte{'"', 0, '"'}, "", "�"},
		{"raw non XML", []byte("\"\uFFFE\""), "", "�"},
		{"escape raw NUL", []byte{'"', 0, '"'}, `map{'escape':true()}`, `\u0000`},
		{"fallback raw NUL", []byte{'"', 0, '"'}, `map{'fallback':function($s as xs:string) as xs:string {'fallback'}}`, "fallback"},
		{"malformed UTF8", []byte{'"', 0xff, '"'}, "", "FOUT1190"},
		{"malformed UTF16", []byte{0xfe, 0xff, 0xd8, 0}, "", "FOUT1190"},
		{"malformed UTF32", []byte{0, 0, 0xfe, 0xff, 0, 0x11, 0, 0}, "", "FOUT1190"},
		{"invalid JSON", []byte("{"), "", "FOJS0001"},
	}...)
	for _, little := range []bool{false, true} {
		var order binary.AppendByteOrder = binary.BigEndian
		name := "BE"
		if little {
			order, name = binary.LittleEndian, "LE"
		}
		for _, width := range []int{2, 4} {
			var data, bom []byte
			if width == 2 {
				bom = order.AppendUint16(nil, 0xfeff)
				for _, value := range utf16.Encode([]rune(value)) {
					data = order.AppendUint16(data, value)
				}
			} else {
				bom = order.AppendUint32(nil, 0xfeff)
				for _, value := range value {
					data = order.AppendUint32(data, uint32(value))
				}
			}
			encoding := "UTF" + strconv.Itoa(width*8) + name
			cases = append(cases,
				resourceCase{encoding, data, "", "é🙂"},
				resourceCase{encoding + " BOM", append(bom, data...), "", "é🙂"})
		}
	}
	return cases
}

func TestJSONResourceDecoding(t *testing.T) {
	for _, test := range jsonResourceDecodingCases() {
		t.Run(test.name, func(t *testing.T) {
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(test.data)), ctx.Err()
			})})
			options := test.options
			if options == "" {
				options = "map{}"
			}
			for _, call := range []string{`json-doc`, `(json-doc#2)`, `function-lookup(xs:QName('fn:json-doc'),2)`} {
				result, err := query(t, e, call+`('urn:json-encoding',`+options+`)`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
				if comparisonErrorCode(test.want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(call, result, err, test.want)
					}
				} else if err != nil || text(t, result) != test.want {
					t.Fatal(call, result, err, test.want)
				}
			}
		})
	}
	for _, test := range []struct {
		data       string
		expression string
		want       string
		limits     transform.Limits
	}{
		{strings.Repeat(" ", 1<<20) + "1", `json-doc('urn:large-source') + json-doc('urn:large-source')`, "2", transform.Limits{MaxOutputBytes: 64}},
		{"\"\x00\"", `deep-equal(json-doc('urn:small-source',map{'escape':true()}),json-doc('urn:small-source',map{'escape':true()}))`, "true", transform.Limits{MaxInputBytes: 5}},
	} {
		loads := 0
		e := engine(t, transform.Config{Limits: test.limits, Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			loads++
			return io.NopCloser(strings.NewReader(test.data)), nil
		})})
		if got := text(t, evaluate(t, e, test.expression, transform.XPath31)); got != test.want || loads != 1 {
			t.Fatal(got, loads, test.want)
		}
	}
}

func TestTextRetrievalFailuresAcrossJSON(t *testing.T) {
	const textFirst = `<xsl:value-of select="unparsed-text-available('urn:shared-failure')"/>|<xsl:try><xsl:value-of select="json-doc('urn:shared-failure')"/><xsl:catch xmlns:err="http://www.w3.org/2005/xqt-errors"><xsl:value-of select="local-name-from-QName($err:code)"/></xsl:catch></xsl:try>`
	const jsonFirst = `<xsl:try><xsl:value-of select="json-doc('urn:shared-failure')"/><xsl:catch xmlns:err="http://www.w3.org/2005/xqt-errors"><xsl:value-of select="local-name-from-QName($err:code)"/></xsl:catch></xsl:try>|<xsl:value-of select="unparsed-text-available('urn:shared-failure')"/>`
	for _, stage := range []string{"open", "read", "close"} {
		for _, body := range []string{textFirst, jsonFirst} {
			t.Run(stage+"/"+strconv.FormatBool(body == textFirst), func(t *testing.T) {
				loads := 0
				e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
					loads++
					if loads > 1 {
						return io.NopCloser(strings.NewReader("1")), nil
					}
					if stage == "open" {
						return nil, transform.ErrResource
					}
					reader := &dtdFailureReader{Reader: strings.NewReader("1")}
					if stage == "read" {
						reader.readError = transform.ErrResource
					} else {
						reader.closeError = transform.ErrResource
					}
					return reader, nil
				})})
				s := stylesheet(t, e, sheet(version30, `<xsl:output method="text"/><xsl:template name="start">`+body+`</xsl:template>`))
				result, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
				want := "false|FOUT1170"
				if body == jsonFirst {
					want = "FOUT1170|false"
				}
				if err != nil || string(result.Primary) != want || loads != 1 {
					t.Fatal(result, err, loads, want)
				}
			})
		}
	}
	loads := 0
	e := engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 256}, Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		loads++
		if loads == 1 {
			return io.NopCloser(strings.NewReader(strings.Repeat(" ", 1024) + "1")), nil
		}
		return nil, transform.ErrResource
	})})
	body := `<xsl:value-of select="unparsed-text-available('urn:oversized')"/>|<xsl:try><xsl:value-of select="json-doc('urn:oversized')"/><xsl:catch>missing</xsl:catch></xsl:try>|<xsl:value-of select="unparsed-text-available('urn:oversized')"/>`
	s := stylesheet(t, e, sheet(version30, `<xsl:output method="text"/><xsl:template name="start">`+body+`</xsl:template>`))
	result, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || string(result.Primary) != "true|missing|true" || loads != 2 {
		t.Fatal("cross-domain failure overwrote successful availability", result, err, loads)
	}
}

func TestTextResourceSnapshots(t *testing.T) {
	for _, expression := range []string{
		`unparsed-text('urn:snapshot') eq unparsed-text('urn:snapshot')`,
		`string-join(unparsed-text-lines('urn:snapshot'),'') eq unparsed-text('urn:snapshot')`,
		`if (unparsed-text-available('urn:snapshot')) then unparsed-text('urn:snapshot') eq '1' else false()`,
		`json-doc('urn:snapshot') eq json-doc('urn:snapshot')`,
		`json-doc('urn:snapshot') eq number(unparsed-text('urn:snapshot'))`,
		`number(unparsed-text('urn:snapshot')) eq json-doc('urn:snapshot')`,
	} {
		loads := 0
		e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			loads++
			return io.NopCloser(strings.NewReader(strconv.Itoa(loads))), nil
		})})
		if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != "true" || loads != 1 {
			t.Fatal(expression, got, loads)
		}
	}

	loads := 0
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		loads++
		return io.NopCloser(strings.NewReader(`{"a":1,"a":2}`)), nil
	})})
	expression := `string-join((json-doc('urn:json',map{'duplicates':'use-first'})?a,json-doc('urn:json',map{'duplicates':'use-last'})?a) ! string(.),',')`
	if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != "1,2" || loads != 1 {
		t.Fatal("JSON options were collapsed into the snapshot", got, loads)
	}

	for _, version := range []string{version20, version30} {
		loads = 0
		e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			loads++
			return io.NopCloser(strings.NewReader(strconv.Itoa(loads))), nil
		})})
		s := stylesheet(t, e, sheet(version, `<xsl:template name="start"><xsl:value-of select="unparsed-text('urn:separate-expressions')"/>:<xsl:value-of select="unparsed-text('urn:separate-expressions')"/></xsl:template>`))
		result, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil || string(result.Primary) != "1:1" || loads != 1 {
			t.Fatal("separate XSLT expressions lost their execution scope", version, result, err, loads)
		}
	}
}

func TestXSLT20TextFunctionContracts(t *testing.T) {
	for _, version := range []transform.XSLTVersion{transform.XSLT20, transform.XSLT30} {
		for _, test := range []struct {
			expression string
			want20     string
			want30     string
		}{
			{`unparsed-text-available((),())`, "false", "XPTY0004"},
			{`unparsed-text-available('urn:valid',())`, "true", "XPTY0004"},
			{`unparsed-text-available('urn:invalid','UTF-8')`, "false", "false"},
			{`unparsed-text('urn:valid')`, "ok", "ok"},
			{`unparsed-text('urn:missing')`, "XTDE1170", "FOUT1170"},
			{`unparsed-text('urn:valid#fragment')`, "XTDE1170", "FOUT1170"},
			{`unparsed-text('urn:invalid','UTF-8')`, "XTDE1190", "FOUT1190"},
			{`unparsed-text('urn:valid','unsupported-encoding')`, "XTDE1190", "FOUT1190"},
			{`unparsed-text('urn:valid','')`, "XTDE1190", "FOUT1190"},
			{`unparsed-text-available('urn:valid','')`, "false", "false"},
			{`unparsed-text((),())`, "XPTY0004", "XPTY0004"},
			{`unparsed-text-available(1)`, "XPTY0004", "XPTY0004"},
		} {
			t.Run(strconv.Itoa(int(version))+"/"+test.expression, func(t *testing.T) {
				e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
					switch uri {
					case "urn:valid":
						return io.NopCloser(strings.NewReader("ok")), nil
					case "urn:invalid":
						return io.NopCloser(strings.NewReader("\xff")), nil
					default:
						return nil, transform.ErrResource
					}
				})})
				source := sheet(version20, `<xsl:output method="text"/><xsl:template name="start"><xsl:value-of select="`+test.expression+`"/></xsl:template>`)
				s, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{ProcessorVersion: version})
				if err != nil {
					t.Fatal(err)
				}
				result, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
				want := test.want20
				if version == transform.XSLT30 {
					want = test.want30
				}
				if strings.HasPrefix(want, "XT") || strings.HasPrefix(want, "XP") || strings.HasPrefix(want, "FO") {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != want {
						t.Fatalf("got %v, want %s", err, want)
					}
				} else if err != nil || string(result.Primary) != want {
					t.Fatalf("got %q (%v), want %q", result.Primary, err, want)
				}
			})
		}
	}

	for _, cause := range []error{transform.ErrLimit, context.Canceled, context.DeadlineExceeded} {
		e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			return nil, cause
		})})
		for _, call := range []string{`unparsed-text('urn:control')`, `unparsed-text-available('urn:control')`} {
			s, err := e.CompileXSLT(t.Context(), []byte(sheet(version20, `<xsl:template name="start"><xsl:value-of select="`+call+`"/></xsl:template>`)), transform.XSLTOptions{ProcessorVersion: transform.XSLT20})
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if !errors.Is(err, cause) {
				t.Fatalf("%s lost control cause %v: %v", call, cause, err)
			}
			var detail *transform.Error
			if errors.As(err, &detail) && strings.HasPrefix(detail.Code, "XTDE11") {
				t.Fatalf("%s assigned semantic text error to %v: %v", call, cause, err)
			}
		}
	}
}

func xmlToJSONSchemaCases() []struct {
	name       string
	xml        string
	selectNode string
	want       string
} {
	return []struct {
		name       string
		xml        string
		selectNode string
		want       string
	}{
		{"document", `<number xmlns="http://www.w3.org/2005/xpath-functions">1</number>`, ".", "1"},
		{"document text", ` <number xmlns="http://www.w3.org/2005/xpath-functions">1</number>`, ".", "FOJS0006"},
		{"document comments", `<!--before--><number xmlns="http://www.w3.org/2005/xpath-functions">1</number><?after ok?>`, ".", "1"},
		{"multiple roots", `<null xmlns="http://www.w3.org/2005/xpath-functions"/><null xmlns="http://www.w3.org/2005/xpath-functions"/>`, ".", "FOJS0006"},
		{"attribute root", `<r a="x"/>`, "*/@a", "FOJS0006"},
		{"text root", `<r>x</r>`, "*/text()", "FOJS0006"},
		{"comment root", `<!--x--><r/>`, "comment()", "FOJS0006"},
		{"array key", `<array xmlns="http://www.w3.org/2005/xpath-functions"><string key="x">a</string></array>`, ".", "FOJS0006"},
		{"array escaped key", `<array xmlns="http://www.w3.org/2005/xpath-functions"><string escaped-key="false">a</string></array>`, ".", "FOJS0006"},
		{"map escaped", `<map xmlns="http://www.w3.org/2005/xpath-functions" escaped="true"><string key="a">x</string></map>`, ".", "FOJS0006"},
		{"number escaped", `<number xmlns="http://www.w3.org/2005/xpath-functions" escaped="false">1</number>`, ".", "FOJS0006"},
		{"null text", `<null xmlns="http://www.w3.org/2005/xpath-functions"> </null>`, ".", "FOJS0006"},
		{"null comments", `<null xmlns="http://www.w3.org/2005/xpath-functions"><!--ok--><?ok yes?></null>`, ".", "null"},
		{"top keys ignored", `<string xmlns="http://www.w3.org/2005/xpath-functions" key="\q" escaped-key="garbage">x</string>`, ".", `"x"`},
		{"escaped key local", `<map xmlns="http://www.w3.org/2005/xpath-functions"><map key="\u0041" escaped-key="true"><string key="\u0041">x</string></map></map>`, ".", `{"\u0041":{"\\u0041":"x"}}`},
		{"missing key", `<map xmlns="http://www.w3.org/2005/xpath-functions"><null/></map>`, ".", "FOJS0006"},
		{"invalid key boolean", `<map xmlns="http://www.w3.org/2005/xpath-functions"><null key="a" escaped-key="garbage"/></map>`, ".", "FOJS0006"},
		{"normalized duplicate", `<map xmlns="http://www.w3.org/2005/xpath-functions"><null key="A"/><null key="\u0041" escaped-key="true"/></map>`, ".", "FOJS0006"},
		{"foreign attributes ignored", `<map xmlns="http://www.w3.org/2005/xpath-functions" xmlns:f="urn:foreign" f:escaped="garbage"><string key="x" f:escaped="garbage">\q</string></map>`, ".", `{"x":"\\q"}`},
		{"array whitespace", `<array xmlns="http://www.w3.org/2005/xpath-functions"> <string>a</string> <null/> </array>`, ".", `["a",null]`},
		{"escaped string", `<string xmlns="http://www.w3.org/2005/xpath-functions" escaped="true">\u0041</string>`, ".", `"\u0041"`},
		{"invalid escape", `<string xmlns="http://www.w3.org/2005/xpath-functions" escaped="true">\q</string>`, ".", "FOJS0007"},
	}
}

func TestXMLToJSONSchemaContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range xmlToJSONSchemaCases() {
		t.Run(test.name, func(t *testing.T) {
			expression := `xml-to-json(parse-xml-fragment($xml)/(` + test.selectNode + `))`
			bindings := transform.Bindings{{Local: "xml"}: transform.Values(transform.String(test.xml))}
			result, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: bindings})
			if strings.HasPrefix(test.want, "FOJS") {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatalf("XPath got %v, want %s", err, test.want)
				}
			} else if err != nil || text(t, result) != test.want {
				t.Fatalf("XPath got %v (%v), want %s", result, err, test.want)
			}
			source := sheet(version30, `<xsl:output method="text"/><xsl:param name="xml"/><xsl:template name="start"><xsl:value-of select="`+expression+`"/></xsl:template>`)
			output, err := stylesheet(t, e, source).Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: bindings})
			if strings.HasPrefix(test.want, "FOJS") {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatalf("XSLT got %v, want %s", err, test.want)
				}
			} else if err != nil || string(output.Primary) != test.want {
				t.Fatalf("XSLT got %v (%v), want %s", output, err, test.want)
			}
		})
	}
}

func xsltHostNameCases() []struct {
	expression string
	code20     string
	want30     string
} {
	return []struct {
		expression string
		code20     string
		want30     string
	}{
		{`count(key('Q{}k','a',$d))`, "XTDE1260", "1"},
		{`count(key(' k ','a',$d))`, "XTDE1260", "1"},
		{`function-available('Q{http://www.w3.org/2005/xpath-functions}count')`, "XTDE1400", "true"},
		{`element-available('Q{http://www.w3.org/1999/XSL/Transform}value-of')`, "XTDE1440", "true"},
		{`type-available('Q{http://www.w3.org/2001/XMLSchema}string')`, "XTDE1428", "true"},
		{`system-property('Q{http://www.w3.org/1999/XSL/Transform}version')`, "XTDE1390", "3.0"},
	}
}

func TestXSLTHostNameVersions(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range xsltHostNameCases() {
		for _, processor := range []transform.XSLTVersion{transform.XSLT20, transform.XSLT30} {
			source := sheet(version20, `<xsl:output method="text"/><xsl:key name="k" match="n" use="@k"/><xsl:variable name="d"><r><n k="a"/></r></xsl:variable><xsl:template name="start"><xsl:value-of select="`+test.expression+`"/></xsl:template>`)
			s, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{ProcessorVersion: processor})
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if processor == transform.XSLT20 {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.code20 {
					t.Fatalf("%d %s: got %v, want %s", processor, test.expression, err, test.code20)
				}
			} else if err != nil || string(result.Primary) != test.want30 {
				t.Fatalf("%d %s: got %v (%v), want %s", processor, test.expression, result, err, test.want30)
			}
			if strings.Contains(test.expression, "key(") {
				continue // key is not available in the XSLT 2.0 static context.
			}
			source = sheet(version20, `<xsl:template name="start"><xsl:text use-when="`+test.expression+`">available</xsl:text></xsl:template>`)
			_, err = e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{ProcessorVersion: processor})
			if processor == transform.XSLT20 {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.code20 {
					t.Fatalf("static %d %s: got %v, want %s", processor, test.expression, err, test.code20)
				}
			} else if err != nil {
				t.Fatal("XSLT 3.0 rejected static EQName", test.expression, err)
			}
		}
	}
}

func TestTextSnapshotEncodingAndFailures(t *testing.T) {
	loads := 0
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		loads++
		return io.NopCloser(strings.NewReader("1")), nil
	})})
	expression := `if (unparsed-text('urn:encoding','UTF-8') eq '1') then unparsed-text('urn:encoding','UTF-16') else 'bad'`
	_, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
	var detail *transform.Error
	if !errors.As(err, &detail) || detail.Code != "FOUT1190" || loads != 2 {
		t.Fatal("encoding-dependent failure was cached as decoded text", err, loads)
	}

	loads = 0
	e = engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		loads++
		reader := &typedTextReader{}
		reader.Reader = strings.NewReader("\xe9")
		reader.mediaType = textLatinMediaType
		return reader, nil
	})})
	if got := text(t, evaluate(t, e, `unparsed-text('urn:metadata') eq unparsed-text('urn:metadata','UTF-8')`, transform.XPath31)); got != "true" || loads != 2 {
		t.Fatal("snapshot lost transport encoding metadata", got, loads)
	}

	loads = 0
	e = engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		loads++
		if loads == 1 {
			return nil, transform.ErrResource
		}
		return io.NopCloser(strings.NewReader("now available")), nil
	})})
	expression = `not(unparsed-text-available('urn:missing')) and not(unparsed-text-available('urn:missing'))`
	if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != "true" || loads != 1 {
		t.Fatal("ordinary retrieval failure was not stable", got, loads)
	}
	if got := text(t, evaluate(t, e, `unparsed-text('urn:missing')`, transform.XPath31)); got != "now available" || loads != 2 {
		t.Fatal("failure leaked into a later public invocation", got, loads)
	}

	loads = 0
	e = engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 256}, Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		loads++
		return io.NopCloser(strings.NewReader(strings.Repeat("x", 1024))), nil
	})})
	if got := text(t, evaluate(t, e, `unparsed-text-available('urn:budget') and unparsed-text-available('urn:budget')`, transform.XPath31)); got != "true" || loads != 1 {
		t.Fatal("availability retained oversized output or lost determinism", got, loads)
	}
	_, err = query(t, e, `if (unparsed-text-available('urn:budget')) then unparsed-text('urn:budget') else 'bad'`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
	if !errors.Is(err, transform.ErrLimit) || loads != 2 {
		t.Fatal("oversized text was reloaded or exceeded its output bound", err, loads)
	}
}

func TestEscapedTextSnapshotsUseCallerScope(t *testing.T) {
	producer := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("producer")), nil
	})})
	function := evaluate(t, producer, `if (unparsed-text('urn:snapshot') eq 'producer') then function(){unparsed-text('urn:snapshot')} else ()`, transform.XPath31)
	loads := 0
	allowed := true
	consumer := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		loads++
		if !allowed {
			return nil, transform.ErrResource
		}
		return io.NopCloser(strings.NewReader("consumer" + strconv.Itoa(loads))), nil
	})})
	q := query(t, consumer, `string-join(($f(),$f()),'|')`, transform.XPath31)
	options := transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: function}}
	for _, want := range []string{"consumer1|consumer1", "consumer2|consumer2"} {
		result, err := q.Evaluate(t.Context(), nil, options)
		if err != nil || text(t, result) != want {
			t.Fatal("escaped text snapshot retained producer or prior caller data", result, err, want)
		}
	}
	allowed = false
	_, err := q.Evaluate(t.Context(), nil, options)
	if !errors.Is(err, transform.ErrResource) || loads != 3 {
		t.Fatal("cached text bypassed the caller resolver policy", err, loads)
	}
}

func TestFunctionValuesConcurrentReuse(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, source := range []string{`function($n){sum(1 to $n)}`, `sum#1`, `function-lookup(QName("http://www.w3.org/2005/xpath-functions","sum"),1)`} {
		callable := evaluate(t, e, source, transform.XPath31)

		q := query(t, e, `$f(1 to 10)`, transform.XPath31)
		if strings.HasPrefix(source, "function(") {
			q = query(t, e, `$f(10)`, transform.XPath31)
		}

		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				out, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: callable}})
				if err != nil {
					t.Error(err)
					return
				}

				got, err := out.Text()
				if err != nil || got != "55" {
					t.Error(got, err)
				}
			})
		}

		wg.Wait()
	}
}

func TestApplicationFunctionAvailability(t *testing.T) {
	e := engine(t, transform.Config{Functions: []transform.Function{{
		Name: transform.Name{Space: "urn:availability", Local: "echo"}, Arity: 1,
		Call: func(ctx context.Context, args []transform.Sequence) (transform.Sequence, error) {
			return args[0], ctx.Err()
		},
	}}})
	for _, version := range []string{version20, version30} {
		source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:a="urn:availability" version="` + version + `"><xsl:output method="text"/><xsl:template name="start">
          <xsl:text use-when="function-available('a:echo') and function-available('a:echo',1) and not(function-available('a:echo',0)) and not(function-available('a:echo',2))">static|</xsl:text>
          <xsl:value-of select="concat(function-available('a:echo'),' ',function-available('a:echo',1),' ',function-available('a:echo',0),' ',function-available('a:echo',2))"/>
          <xsl:text>|</xsl:text><xsl:value-of select="a:echo('ok')"/>
        </xsl:template></xsl:stylesheet>`
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, source, nested)
			if err != nil || got != "static|true true false false|ok" {
				t.Fatal(version, nested, got, err)
			}
		}
	}

	legacy := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:a="urn:availability" version="1.0"><xsl:output method="text"/><xsl:template name="start"><xsl:value-of select="concat(function-available('a:echo'),'|',a:echo('ok'))"/></xsl:template></xsl:stylesheet>`
	for _, nested := range []bool{false, true} {
		got, err := resourceStylesheetResult(t, e, legacy, nested)
		if err != nil || got != "true|ok" {
			t.Fatal("legacy callback", nested, got, err)
		}
	}

	absent := engine(t, transform.Config{})
	for _, registered := range []bool{false, true} {
		producer, consumer := absent, e
		if registered {
			producer, consumer = e, absent
		}
		for _, reference := range []string{`function-available#1`, `function-available#2`, `function(){function-available('a:echo',1)}`} {
			source := sheet(version30, `<xsl:template xmlns:a="urn:availability" name="start" as="function(*)"><xsl:sequence select="`+reference+`"/></xsl:template>`)
			result, err := stylesheet(t, producer, source).CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
			if err != nil {
				t.Fatal(reference, err)
			}

			expression := `$f('a:echo')`
			if strings.HasSuffix(reference, "#2") {
				expression = `$f('a:echo',1) and not($f('a:echo',0)) and not($f('a:echo',2))`
			} else if strings.HasPrefix(reference, "function()") {
				expression = `$f()`
			}

			query, err := consumer.CompileXPath(t.Context(), expression, transform.XPathOptions{Version: transform.XPath31, Namespaces: map[string]string{"a": "urn:consumer"}})
			if err != nil {
				t.Fatal(err)
			}

			value, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: result.Primary()}})
			if err != nil {
				t.Fatal(reference, err)
			}

			available, err := value.EffectiveBoolean()
			if err != nil || available != registered {
				t.Fatal("returned availability lost its producer registry", registered, reference, available, err)
			}
		}
	}
}

func TestReturnedPackageGlobalBindings(t *testing.T) {
	library := packageSheet(`name="urn:binding-library"`, `<xsl:variable name="p:v" as="map(*)"><xsl:message select="'lazy global'"/><xsl:sequence select="map{'total':sum(1 to 100),'year':year-from-date(current-date()),'lang':default-language(),'zone':implicit-timezone()}"/></xsl:variable><xsl:function name="p:get" visibility="public"><xsl:sequence select="function($n){ string-join(($p:v?total + sum(1 to $n),$p:v?year,$p:v?lang,string($p:v?zone)) ! string(),'|') }"/></xsl:function>`)
	e := engine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
		return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(library))}, ctx.Err()
	})})
	source := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"/><xsl:variable name="p:v" select="9999"/><xsl:template name="start" visibility="public" as="function(*)"><xsl:sequence select="p:get()"/></xsl:template>`)
	result, err := stylesheet(t, e, source).CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Context: transform.DynamicContext{CurrentTime: time.Date(1999, 12, 31, 22, 0, 0, 0, time.UTC), ImplicitTimezone: time.FixedZone("producer", 3*60*60), DefaultLanguage: "fr"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Messages()) != 1 {
		t.Fatal(result.Messages())
	}
	callable := result.Primary()
	q := query(t, e, `$f(10)`, transform.XPath31)
	options := transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: callable}}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			value, err := q.Evaluate(t.Context(), nil, options)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := value.Text()
			if err != nil || got != "5105|2000|fr|PT3H" {
				t.Error(got, err)
			}
		})
	}
	wg.Wait()
	consumer := stylesheet(t, e, sheet(version30, `<xsl:param name="f" as="function(*)"/><xsl:template name="start"><xsl:sequence select="$f(10)"/></xsl:template>`))
	consumed, err := consumer.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "f"}: callable}})
	if err != nil || text(t, consumed.Primary()) != "5105|2000|fr|PT3H" || len(consumed.Messages()) != 0 {
		t.Fatal(consumed, err)
	}
	bounded := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 32}})
	_, err = query(t, bounded, `$f(10000)`, transform.XPath31).Evaluate(t.Context(), nil, options)
	if !errors.Is(err, transform.ErrLimit) {
		t.Fatal("returned function retained producer budget", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = q.Evaluate(cancelled, nil, options)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReturnedFunctionsKeepProducingParameters(t *testing.T) {
	for _, reference := range []string{`function(){ $p:v }`, `p:read#0`} {
		library := packageSheet(`name="urn:binding-library"`, `<xsl:param name="p:v" as="xs:string"/><xsl:function name="p:read" visibility="public"><xsl:sequence select="$p:v"/></xsl:function><xsl:function name="p:get" visibility="public"><xsl:sequence select="`+reference+`"/></xsl:function>`)
		e := engine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
			return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(library))}, ctx.Err()
		})})
		source := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"/><xsl:param name="f" as="function(*)?"/><xsl:template name="start" visibility="public"><xsl:sequence select="if(exists($f)) then $f() else p:get()"/></xsl:template>`)
		compiled := stylesheet(t, e, source)
		options := transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: transform.Bindings{{Space: "urn:components", Local: "v"}: transform.Values(transform.String("A"))}}
		first, err := compiled.Execute(t.Context(), nil, options)
		if err != nil {
			t.Fatal(err)
		}
		options.Parameters = transform.Bindings{{Space: "urn:components", Local: "v"}: transform.Values(transform.String("B")), {Local: "f"}: first.Primary()}
		second, err := compiled.Execute(t.Context(), nil, options)
		if err != nil || text(t, second.Primary()) != "A" {
			t.Fatal(reference, second, err)
		}
	}
}

func TestReturnedInlineGlobalNodeIdentity(t *testing.T) {
	library := packageSheet(`name="urn:binding-library"`, `<xsl:variable name="p:v" as="element()"><node/></xsl:variable><xsl:function name="p:get" visibility="public"><xsl:sequence select="function(){ $p:v }"/></xsl:function>`)
	e := engine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
		return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(library))}, ctx.Err()
	})})
	source := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"/><xsl:template name="start" visibility="public" as="function(*)"><xsl:sequence select="p:get()"/></xsl:template>`)
	result, err := stylesheet(t, e, source).CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	bindings := transform.Bindings{{Local: "f"}: result.Primary()}
	node, err := query(t, e, `$f()`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: bindings})
	if err != nil {
		t.Fatal(err)
	}
	bindings[transform.Name{Local: "n"}] = node
	comparison := query(t, e, `$f() is $n`, transform.XPath31)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			value, err := comparison.Evaluate(t.Context(), nil, transform.XPathContext{Variables: bindings})
			if err != nil || text(t, value) != "true" {
				t.Error(value, err)
			}
		})
	}
	wg.Wait()
}

func TestCopyOfRetainsNonNodeItems(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []string{version20, version30} {
		source := sheet(version, `<xsl:template name="start"><xsl:copy-of select="(1,2)"/><xsl:sequence select="3"/></xsl:template>`)
		result, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil {
			t.Fatal(err)
		}
		check := query(t, e, `deep-equal($v,(1,2,3))`, transform.XPath31)
		got, err := check.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "v"}: result.Primary()}})
		if err != nil || text(t, got) != nameTrue {
			t.Fatal(version, got, err)
		}
	}
	source := sheet(version30, `<xsl:template name="start"><xsl:copy-of select="(map{'v':42},[1,[2]],function(){3})"/></xsl:template>`)
	result, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil {
		t.Fatal(err)
	}
	check := query(t, e, `count($v) eq 3 and $v[1]?v eq 42 and $v[2] instance of array(*) and $v[2]?2 instance of array(*) and $v[3]() eq 3`, transform.XPath31)
	got, err := check.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "v"}: result.Primary()}})
	if err != nil || text(t, got) != nameTrue {
		t.Fatal(got, err)
	}
}

func TestCoercedFunctionStaticContext(t *testing.T) {
	e := engine(t, transform.Config{})
	producer, err := e.CompileXPath(t.Context(), `(function($f as function(a:float) as a:double){$f})(function($v as a:double) as a:float {a:float($v)})`, transform.XPathOptions{Version: transform.XPath31, Namespaces: map[string]string{"a": "http://www.w3.org/2001/XMLSchema"}})
	if err != nil {
		t.Fatal(err)
	}
	callable, err := producer.Evaluate(t.Context(), nil, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := e.CompileXPath(t.Context(), `$f(2) instance of xs:double and $f(2) eq 2`, transform.XPathOptions{Version: transform.XPath31, Namespaces: map[string]string{"a": "urn:shadow"}})
	if err != nil {
		t.Fatal(err)
	}
	options := transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: callable}}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			value, err := consumer.Evaluate(t.Context(), nil, options)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := value.Text()
			if err != nil || got != nameTrue {
				t.Error(got, err)
			}
		})
	}
	wg.Wait()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := consumer.Evaluate(cancelled, nil, options); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReturnedFunctionDynamicEvaluationPolicy(t *testing.T) {
	consumer := engine(t, transform.Config{})
	q := query(t, consumer, `$f()`, transform.XPath31)
	inner := sheet(version30, `<xsl:template name="start"><xsl:evaluate xpath="'42'"><xsl:fallback>inner disabled</xsl:fallback></xsl:evaluate></xsl:template>`)
	source := sheet(version30, `<xsl:param name="code"/><xsl:template name="start" as="function(*)"><xsl:sequence select="function(){string-join((string(element-available('xsl:evaluate')),system-property('xsl:supports-dynamic-evaluation'),transform(map{'stylesheet-text':$code,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output),'|')}"/></xsl:template>`)
	for _, disabled := range []bool{false, true} {
		producer := engine(t, transform.Config{DisableXSLTDynamicEvaluation: disabled})
		result, err := stylesheet(t, producer, source).CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "code"}: transform.Values(transform.String(inner))}, ResultMode: transform.ResultRaw})
		if err != nil {
			t.Fatal(err)
		}
		options := transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: result.Primary()}}
		want := "true|yes|42"
		if disabled {
			want = "false|no|inner disabled"
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				got, err := q.Evaluate(t.Context(), nil, options)
				if err != nil {
					t.Error(err)
					return
				}
				value, err := got.Text()
				if err != nil || value != want {
					t.Error(value, err, want)
				}
			})
		}
		wg.Wait()
	}
}

func TestReturnedIntrospectionStaticContexts(t *testing.T) {
	producer := engine(t, transform.Config{})
	consumer := engine(t, transform.Config{})
	for _, static := range []bool{false, true} {
		for _, reference := range []string{`element-available#1`, `function-lookup(QName('http://www.w3.org/2005/xpath-functions','element-available'),1)`} {
			global, body := "", `<xsl:sequence select="`+reference+`"/>`
			if static {
				global = `<xsl:variable static="yes" xmlns="http://www.w3.org/1999/XSL/Transform" name="f" select="` + reference + `"/>`
				body = `<xsl:sequence select="$f"/>`
			}
			source := sheet(version30, global+`<xsl:template xmlns="http://www.w3.org/1999/XSL/Transform" name="start" as="function(xs:string) as xs:boolean">`+body+`</xsl:template>`)
			value, err := stylesheet(t, producer, source).CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
			if err != nil {
				t.Fatal(static, reference, err)
			}
			invoke := query(t, consumer, `$f('evaluate')`, transform.XPath31)
			bindings := transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: value.Primary()}}
			var group sync.WaitGroup
			for range 8 {
				group.Go(func() {
					result, err := invoke.Evaluate(t.Context(), nil, bindings)
					if err != nil || text(t, result) != nameTrue {
						t.Error(static, reference, result, err)
					}
				})
			}
			group.Wait()
		}
	}
}
