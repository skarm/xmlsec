//go:build interop

package transform_test

import (
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform"
)

func TestCompareSaxonLanguageSemantics(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	e := engine(t, transform.Config{})
	for expression, want := range map[string]string{
		`string-join((1,2,3),'')`:                                   "123",
		`string-join#2((1,2,3),'')`:                                 "123",
		`function-lookup(xs:QName('fn:string-join'),2)((1,2,3),'')`: "123",
		`string-join(?,'')((1,2,3))`:                                "123",
		`string-join(('a','b'),())`:                                 errCodeXPTY0004,
		`error(())`:                                                 "FOER0000",
		`error#1(())`:                                               "FOER0000",
		`function-lookup(xs:QName('fn:error'),1)(())`:               "FOER0000",
		`error(?)(())`:                                              "FOER0000",
		`error(xs:untypedAtomic('err:FOER0000'))`:                   "XPTY0117",
		`format-number(12,'e0')`:                                    "e12",
		`format-number(12345.678,'9.9999e999')`:                     "1.2346e004",
		`for $v in 'local' return xs:QName($v)`:                     "local",
		`for $v in 'local' return $v castable as xs:QName`:          nameTrue,
		`1 cast as xs:error`:                                        errCodeFORG0001,
		`'value' cast as xs:error`:                                  errCodeFORG0001,
		`every $v in (1 div 3, 1 div 999999999999999999, avg((1,0,0)), xs:dayTimeDuration('PT1S') div xs:dayTimeDuration('PT3S')) satisfies $v eq xs:decimal(string($v))`: nameTrue,
		`matches(concat('line',codepoints-to-string(10)), '^$', 'm')`:      nameFalse,
		`matches(concat('line',codepoints-to-string((10,10))), '^$', 'm')`: nameTrue,
		`let $s := '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:output method="text"/><xsl:template name="start"><xsl:sequence select="42"/></xsl:template></xsl:stylesheet>' return transform(map{'stylesheet-text':$s,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`:                                                                                                                      "42",
		`let $s := '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="2.0"><xsl:output method="text"/><xsl:template name="start"><xsl:iterate select="1 to 2"><xsl:value-of select="map{&quot;value&quot;:.}?value"/></xsl:iterate></xsl:template></xsl:stylesheet>' return transform(map{'stylesheet-text':$s,'xslt-version':2.0000000000000000000000000001,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`: "12",
		`let $s := '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:output method="text"/><xsl:template name="start"><xsl:value-of select="(10,20)"/><xsl:value-of version="3.0" select="(30,40)"/></xsl:template></xsl:stylesheet>' return transform(map{'stylesheet-text':$s,'xslt-version':3,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`:                                                  compatSequenceText,
		`let $s := '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="urn:custom" version="3.0"><xsl:output method="text"/><xsl:template name="start"><xsl:value-of select="codepoints-to-string(65)"/></xsl:template></xsl:stylesheet>' return transform(map{'stylesheet-text':$s,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`:                                                                          "A",
		`string(parse-xml-fragment('<?xml encoding="UTF-16"?>café 中<a/>'))`:     xmlCharacters,
		`string(parse-xml-fragment('<?xml-stylesheet href="style.xsl"?>text'))`: serializationText,
		`parse-xml-fragment('<?xml version="1.0"?><a/>')`:                       errCodeFODC0006,
		`doc(':/')`:           "FODC0005",
		`() instance of none`: errCodeXPST0051,
		`1 instance of Q{http://www.w3.org/2001/XMLSchema}integer`:                                                                nameTrue,
		`count(parse-xml('<r><for/><let/><some/><every/><if/><try/><map/><array/></r>')/r/(for,let,some,every,if,try,map,array))`: "8",
		`Q{{urn:test}local`:                     errCodeXPST0003,
		`Q{urn:test`:                            errCodeXPST0003,
		`Q{http://www.w3.org/2000/xmlns/}local`: errCodeXQST0070,
		`string(parse-xml('<?xml version="1.0" encoding="UTF-16"?><r>café 中</r>')/r)`:                  xmlCharacters,
		`string(parse-xml('<?xml version="1.0" encoding="x-unregistered-encoding"?><r>café 中</r>')/r)`: xmlCharacters,
		`let $s := '<?xml version="1.0" encoding="ISO-8859-1"?><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="text"/><xsl:template name="start"><xsl:text>café 中</xsl:text></xsl:template></xsl:stylesheet>' return transform(map{'stylesheet-text':$s,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`: xmlCharacters,
		`(function($fs as (function(xs:string) as xs:string)*) {string-join(for $f in $fs return $f('Abc e'),'~')})((upper-case#1,lower-case#1,function($x){translate($x,'e','i')},substring-before(?, ' ')))`:                                                                                                                                                                            "ABC E~abc e~Abc i~Abc",
		`(function($fs as (function(xs:string) as xs:string)*) {for $f in $fs return $f('x')})((upper-case#1,function($x){1}))`:                                                                                                                                                                                                                                                           errCodeXPTY0004,
		`'a' || string#1`: errCodeFOTY0013,
		`map{} || 'a'`:    errCodeFOTY0013,
		`'a' || [map{}]`:  errCodeFOTY0013,
		`'a' || [[],[1]]`: "a1",
		`function($a,$b){$a+$b} instance of function(item()*,item()*) as xs:integer`:                        nameFalse,
		`function($a as xs:string,$b){$a} instance of function(xs:integer,item()*) as item()*`:              nameFalse,
		`function($a as xs:string,$b){$a} instance of function(xs:NCName,item()*) as item()*`:               nameTrue,
		`function(){()} instance of function() as empty-sequence()`:                                         nameFalse,
		`function() as empty-sequence(){()} instance of function() as empty-sequence()`:                     nameTrue,
		`function-arity(concat#123456)`:                                                                     "123456",
		`concat#3 instance of function(xs:string?,xs:anyAtomicType?,xs:integer?) as xs:string`:              nameTrue,
		`concat#3 instance of function(xs:anyAtomicType?,xs:anyAtomicType*,xs:anyAtomicType?) as xs:string`: nameFalse,
		`(function($f as function(item()*,item()*,item()*) as xs:string){$f('a','b',(1,2))})(concat#3)`:     errCodeXPTY0004,
		`xs:double('INF') idiv 0`:                                     errCodeFOAR0001,
		`xs:float('-INF') idiv xs:float('-0')`:                        errCodeFOAR0001,
		`xs:dayTimeDuration('PT1S') div xs:dayTimeDuration('PT0S')`:   errCodeFOAR0001,
		`xs:yearMonthDuration('P1Y') div xs:yearMonthDuration('P0M')`: errCodeFOAR0001,
		`array:subarray([1,2,3],2,-1)`:                                errCodeFOAY0002,
		`array:size(array:subarray([1,2,3],4,0))`:                     "0",
		`codepoints-to-string('hello')`:                               errCodeXPTY0004,
		`codepoints-to-string(xs:double(65))`:                         errCodeXPTY0004,
		`codepoints-to-string(xs:decimal('65.0'))`:                    errCodeXPTY0004,
		`codepoints-to-string(0)`:                                     errCodeFOCH0001,
		`codepoints-to-string(xs:integer('18446744073709551616'))`:    errCodeFOCH0001,
		`codepoints-to-string([65,[],[66]])`:                          nameCodepointsAB,
		`concat('a',string#1)`:                                        errCodeFOTY0013,
		`concat('a',map{})`:                                           errCodeFOTY0013,
		`concat('a',(1,2),'b')`:                                       errCodeXPTY0004,
		`concat#3('a',[1],'b')`:                                       "a1b",
		`unparsed-text('urn:unread',())`:                              errCodeXPTY0004,
		`unparsed-text-lines('urn:unread',())`:                        errCodeXPTY0004,
		`unparsed-text-available('urn:unread',())`:                    errCodeXPTY0004,
		`local-name-from-QName(xs:untypedAtomic('x'))`:                errCodeXPTY0117,
		`namespace-uri-from-QName(parse-xml('<r>x</r>')/*)`:           errCodeXPTY0117,
		`format-date(xs:date('2026-01-01'),'[b]')`:                    errCodeFOFD1340,
		`format-time(xs:time('12:00:00'),'[y]')`:                      errCodeFOFD1340,
		`format-date(xs:date('2026-01-01'),'[H]')`:                    errCodeFOFD1350,
		`let $n := parse-xml('<head xmlns=""><title>One</title></head>')/* return contains(parse-json(serialize($n, map{'method':'json','json-node-output-method':'html'})), '<meta http-equiv="Content-Type"') and not(exists($n//meta))`:                nameTrue,
		`let $n := parse-xml('<html xmlns="http://www.w3.org/1999/xhtml"><head><title>Two</title></head></html>')/* return contains(parse-json(serialize($n, map{'method':'json','json-node-output-method':'html'})), '<meta http-equiv="Content-Type"')`: nameTrue,
		`parse-json(serialize(parse-xml('<r><!--c--></r>')/r/comment(), map{'method':'json'}))`:               "<!--c-->",
		`parse-json(serialize(parse-xml('<r><?p x?></r>')/r/processing-instruction(), map{'method':'json'}))`: "<?p x?>",
		`parse-json(serialize(parse-xml('<r>&lt;&amp;</r>')/r/text(), map{'method':'json'}))`:                 "&lt;&amp;",
		`serialize(parse-xml('<r a="x"/>')/r/@a, map{'method':'json'})`:                                       errCodeSENR0001,
		`let $s := '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="json"/><xsl:template name="start"><xsl:sequence select="[(),1]"/></xsl:template></xsl:stylesheet>' return transform(map{'stylesheet-text':$s,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`: `[null,1]`,
		`let $s := '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="json"/><xsl:template name="start"/></xsl:stylesheet>' return transform(map{'stylesheet-text':$s,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`:                                              serializationNull,
		`let $s := '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="json"/><xsl:template name="start"><xsl:sequence select="(1,2)"/></xsl:template></xsl:stylesheet>' return transform(map{'stylesheet-text':$s,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`:  errCodeSERE0023,
		`serialize(('a', true(), '<&>'))`: "a true &lt;&amp;&gt;",
		`parse-json(serialize(parse-xml('<p>text</p>'), map{'method':'json','json-node-output-method':'text'}))`:      serializationText,
		`parse-json(serialize(parse-xml('<p>text<br/></p>'), map{'method':'json','json-node-output-method':'html'}))`: "<p>text<br></p>",
		`matches('alpha', 'alp^?ha')`:                                  nameTrue,
		`matches('alpha', 'alp^+ha')`:                                  nameFalse,
		`matches('alpha', '^{2}alpha')`:                                nameTrue,
		`matches('zalpha', '^{2}alpha')`:                               nameFalse,
		`matches('alpha', 'alp$?ha')`:                                  nameTrue,
		`matches('alpha', 'alp${2,4}ha')`:                              nameFalse,
		`matches('alpha', 'alpha$+')`:                                  nameTrue,
		`matches('alphax', 'alpha$+')`:                                 nameFalse,
		`empty(format-date((), '[Y]'))`:                                nameTrue,
		`empty(function-lookup(xs:QName('fn:format-date'), 3))`:        nameTrue,
		`empty(function-lookup(xs:QName('fn:format-time'), 4))`:        nameTrue,
		`format-date(xs:untypedAtomic('2026-01-01'), '[Y]')`:           "2026",
		`xs:date('25252734927766555-07-28')`:                           errCodeFODT0001,
		`xs:duration('P768614336404564651Y')`:                          errCodeFODT0002,
		`serialize((1,2), map{'method':'json'})`:                       errCodeSERE0023,
		`serialize([(1,2)], map{'method':'json'})`:                     errCodeSERE0023,
		`serialize(map{'x':(1,2)}, map{'method':'json'})`:              errCodeSERE0023,
		`serialize([map{'x':[(1,2)]}], map{'method':'json'})`:          errCodeSERE0023,
		`serialize(xs:double('NaN'), map{'method':'json'})`:            errCodeSERE0020,
		`serialize(map{'x':[xs:float('-INF')]}, map{'method':'json'})`: errCodeSERE0020,
		`serialize([map{'x':string#1}], map{'method':'json'})`:         errCodeSERE0021,
		`serialize([map{1:'a','1':'b'}], map{'method':'json'})`:        errCodeSERE0022,
		`serialize((), map{'method':'json'})`:                          serializationNull,
		`serialize([(), [1,2], map{'x':()}], map{'method':'json'})`:    `[null,[1,2],{"x":null}]`,
		`serialize('x', map{'use-character-maps':map{'ab':'x'}})`:      errCodeSEPM0016,
		`serialize('x', parse-xml('<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><indent value="perhaps"/></serialization-parameters>')/*)`:                                                                                                           errCodeSEPM0017,
		`serialize('x', parse-xml('<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><indent value="yes"/><indent value="no"/></serialization-parameters>')/*)`:                                                                                           errCodeSEPM0019,
		`serialize('x', parse-xml('<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><use-character-maps><character-map character="a" map-string="x"/><character-map character="a" map-string="y"/></use-character-maps></serialization-parameters>')/*)`: errCodeSEPM0018,
	} {
		t.Run(expression, func(t *testing.T) {
			compareSaxonExpression(t, ctx, e, binary, classpath, expression, want)
		})
	}
}

func TestCompareSaxonDocumentFunctionContracts(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	path := filepath.Join(t.TempDir(), "resource.xml")
	data := `<r><a xml:id="a">1</a><b xml:id="b"/></r>`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String()
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(data)), ctx.Err()
	})})
	for _, test := range documentFunctionContractCases() {
		expression := strings.ReplaceAll(test.expression, "urn:shared", uri)
		t.Run(expression, func(t *testing.T) {
			oracle := test.want
			if strings.Contains(expression, "#id") {
				oracle = "FODC0002"
			}
			if strings.Contains(expression, "document(42)") {
				oracle = "FODC0002"
			}
			if strings.Contains(expression, "document([])") {
				oracle = "FOTY0014"
			}
			compareSaxonStylesheet(t, t.Context(), e, binary, classpath, `<xsl:template name="start">`+valueOfExpression(expression)+`</xsl:template>`, test.want, oracle)
		})
	}
	for _, test := range []struct{ argument, want string }{
		{`42`, errCodeXPTY0004},
		{`[]`, errCodeXPTY0004},
		{`('urn:shared#b','urn:shared#a','urn:shared#a')`, "a,b"},
		{`('urn:shared#missing','urn:shared#b')`, "b"},
	} {
		expression := strings.ReplaceAll(`string-join(for $n in document(`+test.argument+`) return local-name($n),',')`, "urn:shared", uri)
		t.Run(expression, func(t *testing.T) {
			oracle := test.want
			if strings.Contains(expression, "#id") {
				oracle = "FODC0002"
			}
			if strings.Contains(expression, "document(42)") {
				oracle = "FODC0002"
			}
			if strings.Contains(expression, "document([])") {
				oracle = "FOTY0014"
			}
			compareSaxonStylesheet(t, t.Context(), e, binary, classpath, `<xsl:template name="start">`+valueOfExpression(expression)+`</xsl:template>`, test.want, oracle)
		})
	}
}

func TestCompareSaxonFunctionTypes(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for expression, want := range standardFunctionTypeCases() {
		t.Run(expression, func(t *testing.T) {
			oracle := want
			if expression == `base-uri#0 instance of function() as xs:anyURI?` {
				oracle = nameFalse
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, want, oracle)
		})
	}
	for expression, want := range xsltFunctionTypeCases() {
		t.Run(expression, func(t *testing.T) {
			oracle := want
			switch expression {
			case `unparsed-entity-uri('x')`:
				oracle = "XTDE1370"
			case `(1 to 1)!unparsed-entity-public-id('x')`:
				oracle = "XTDE1380"
			case `current-group#0 instance of function() as xs:string`:
				oracle = "XTDE1061"
			case `current-grouping-key#0 instance of function() as xs:integer`:
				oracle = "XTDE1071"
			}
			compareSaxonStylesheet(t, t.Context(), e, binary, classpath, `<xsl:template name="start">`+valueOfExpression(expression)+`</xsl:template>`, want, oracle)
		})
	}
}

func TestCompareSaxonErrorSourceLines(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		source := strings.Replace(sourceLineStylesheet(ending), "<xsl:sequence"+ending+"       select", "<xsl:sequence select", 1)
		expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
		compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, "7")
	}
}

func TestCompareSaxonDynamicOutputURI(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range currentOutputURICases() {
		t.Run(test.expression, func(t *testing.T) {
			source := currentOutputURIStylesheet(test.expression)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'base-output-uri':'https://output.invalid/main','delivery-format':'serialized'})('https://output.invalid/main')`
			oracle := test.want
			if strings.HasPrefix(test.expression, "empty(current-output-uri#0") || strings.HasPrefix(test.expression, "empty(function-lookup") || strings.HasPrefix(test.expression, "apply(") {
				// REC 25.3.1 clears the URI on dynamic calls. Saxon 12.10
				// retains it for named references; keep this diagnostic visible.
				oracle = nameFalse
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want, oracle)
		})
	}
	for _, call := range []string{`json-to-xml`, `(json-to-xml#2)`, `function-lookup(xs:QName('fn:json-to-xml'),2)`, `json-to-xml(?,?)`} {
		compareSaxonExpression(t, t.Context(), e, binary, classpath, call+`('1',map{'validate':true()})`, "FOJS0004")
	}
	for _, test := range dynamicHostContextCases() {
		t.Run(test.name, func(t *testing.T) {
			oracle := test.want
			// REC 14.2 and 15.6 clear these contexts for key specifiers
			// and dynamic calls. Saxon retains them in these cases.
			switch test.name {
			case "merge group", "key grouping key":
				oracle = "11"
			case "key group":
				oracle = "12"
			}
			compareSaxonStylesheet(t, t.Context(), e, binary, classpath, test.declarations+`<xsl:template name="start">`+test.body+`</xsl:template>`, test.want, oracle)
		})
	}
}

func TestCompareSaxonReadWriteConflicts(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	for _, test := range readWriteConflictCases() {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.xml")
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			uri := (&url.URL{Scheme: "file", Path: path}).String()
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(test.data)), ctx.Err()
			})})
			read := strings.ReplaceAll(test.body, "urn:shared", uri)
			write := `<xsl:result-document href="` + uri + `"><out/></xsl:result-document>`
			for order, body := range []string{read + write, write + read} {
				t.Run(strconv.Itoa(order), func(t *testing.T) {
					oracle := "XTDE1500"
					switch test.name {
					case "doc", "doc reference", "document", "source document":
						if order == 1 {
							oracle = "XTRE1500"
						}
					case "doc available":
						if order == 1 {
							oracle = nameFalse
						}
					case "JSON":
						oracle = "1"
					case "text available":
						oracle = nameTrue
					case "text", "text lookup", "text apply", "text lines", "evaluate text":
						oracle = "text"
					case "parameter document":
						oracle = ""
					}
					compareSaxonStylesheet(t, t.Context(), e, binary, classpath, `<xsl:template name="start">`+body+`</xsl:template>`, "XTDE1500", oracle)
				})
			}
		})
	}
}

func TestCompareSaxonDynamicParameterDocuments(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	dir := t.TempDir()
	prefix := (&url.URL{Scheme: "file", Path: filepath.Join(dir, "params-")}).String()
	data := make(map[string]string)
	for _, method := range []string{"text", "xml"} {
		body := `<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><method value="` + method + `"/><omit-xml-declaration value="yes"/></serialization-parameters>`
		if err := os.WriteFile(filepath.Join(dir, "params-"+method), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		data[method] = body
	}
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		for method, body := range data {
			if strings.HasSuffix(uri, "params-"+method) {
				return io.NopCloser(strings.NewReader(body)), ctx.Err()
			}
		}
		return nil, transform.ErrResource
	})})
	for _, test := range dynamicParameterDocumentCases() {
		source := sheet(version30, strings.ReplaceAll(test.body, "urn:params:", prefix))
		expression := `let $r := transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'}) return string-join((1 to 3)!$r('urn:result-'||.),'|')`
		compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
	}
}

func TestCompareSaxonSourceDocumentIdentity(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	for _, name := range []string{"source.xml", "space name.xml"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte(`<r/>`), 0o600); err != nil {
				t.Fatal(err)
			}
			uri := (&url.URL{Scheme: "file", Path: path}).String()
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(`<r/>`)), ctx.Err()
			})})
			for _, version := range []string{version20, version30} {
				source := sheet(version, `<xsl:template match="/"><xsl:value-of select="doc(document-uri(.)) is ."/><xsl:value-of select="document(document-uri(.)) is ."/></xsl:template>`)
				expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','source-node':doc('` + uri + `'),'delivery-format':'serialized'})?output`
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, "truetrue")
			}
		})
	}
}

func TestCompareSaxonTypeAvailability(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{XMLSchemaVersion: transform.XMLSchema11})
	// HE uses 1.1 builtin datatypes. Its CLI -xsdversion option also enables
	// schema awareness and requires EE; strict 1.0 has local/catalog evidence.
	for _, version := range []string{version20, version30} {
		source := sheet(version, `<xsl:template name="start"><xsl:text use-when="type-available('xs:dateTimeStamp')">available:</xsl:text><xsl:text use-when="not(type-available('xs:dateTimeStamp'))">unavailable:</xsl:text><xsl:value-of select="type-available('xs:dateTimeStamp')"/></xsl:template>`)
		expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
		compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, "available:true")
	}
}

func TestCompareSaxon20CompilerContracts(t *testing.T) {
	classpath := os.Getenv("SAXON20_CLASSPATH")
	if classpath == "" {
		t.Skip("SAXON20_CLASSPATH is not configured")
	}
	binary, err := exec.LookPath("java")
	if err != nil {
		t.Fatal("configured Saxon 2.0 requires java", err)
	}
	tests := make([]struct{ name, source, module, want string }, 0, 18)
	for _, test := range []struct{ name, prefix, importAttribute, want string }{
		{"ordered", "", "", "ok"},
		{"after output", `<xsl:output method="text"/>`, "", "XTSE0200"},
		{"after template", `<xsl:template name="earlier"/>`, "", "XTSE0200"},
		{"after include", `<xsl:include href="module.xsl"/>`, "", "XTSE0200"},
		{"after data", `<d:data xmlns:d="urn:data"/>`, "", "XTSE0200"},
		{"excluded predecessor", `<xsl:template name="earlier" use-when="false()"/>`, "", "ok"},
		{"excluded import", `<xsl:output method="text"/>`, ` use-when="false()"`, "ok"},
	} {
		source := sheetStart + version20 + `">` + test.prefix + `<xsl:import href="module.xsl"` + test.importAttribute + `/><xsl:output method="text"/><xsl:template name="start">ok</xsl:template></xsl:stylesheet>`
		tests = append(tests, struct{ name, source, module, want string }{test.name, source, sheet(version20, ""), test.want})
	}
	tests = append(tests,
		struct{ name, source, module, want string }{"reported 2.0", sheet(version20, `<xsl:template name="start"><xsl:value-of select="system-property('xsl:version')"/></xsl:template>`), sheet(version20, ""), "2.0"},
		struct{ name, source, module, want string }{"reject 3.0 instruction", sheet(version20, `<xsl:template name="start"><xsl:iterate select="1"/></xsl:template>`), sheet(version20, ""), "XTSE0010"},
	)

	for _, version := range []string{"-29", "0", "-0.0", "0.5", "+1.50"} {
		source := sheet(version, `<xsl:template name="start"><xsl:value-of select="1 to 5"/></xsl:template>`)
		tests = append(tests, struct{ name, source, module, want string }{"version " + version, source, sheet(version20, ""), "1"})
	}
	for _, kind := range []string{nameInclude, nameImport} {
		for _, rootCondition := range []bool{false, true} {
			source, module := moduleUseWhenNamespaceSources(kind, rootCondition)
			source = strings.ReplaceAll(source, "urn:module", "module.xsl")
			tests = append(tests, struct{ name, source, module, want string }{kind + strconv.FormatBool(rootCondition), source, module, "42:false"})
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { compareSaxon20Compiler(t, binary, classpath, test.source, test.module, test.want) })
	}
}

func compareSaxon20Compiler(t *testing.T, binary, classpath, source, module, want string) {
	t.Helper()
	directory := t.TempDir()
	main := filepath.Join(directory, "main.xsl")
	for name, data := range map[string]string{"main.xsl": source, "module.xsl": module} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if !strings.HasSuffix(uri, "/module.xsl") {
			return nil, transform.ErrResource
		}
		return io.NopCloser(strings.NewReader(module)), ctx.Err()
	})})
	compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{ProcessorVersion: transform.XSLT20, BaseURI: (&url.URL{Scheme: "file", Path: filepath.ToSlash(main)}).String()})
	got := ""
	if err == nil {
		result, executeErr := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		err = executeErr
		if err == nil {
			got = string(result.Primary)
		}
	}
	if err != nil {
		var detail *transform.Error
		if !errors.As(err, &detail) {
			t.Fatal(err)
		}
		got = detail.Code
	}
	if got != want {
		t.Fatal("native 2.0", got, err, want)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "-cp", classpath, "net.sf.saxon.Transform", "-xsltversion:2.0", "-xsl:"+main, "-it:start").Output()
	got = string(output)
	if err != nil {
		got = saxonDiagnosticCode(err)
	}
	if got != want {
		var detail *exec.ExitError
		if errors.As(err, &detail) {
			t.Fatalf("Saxon 2.0: %q, %s; want %q", output, detail.Stderr, want)
		}
		t.Fatalf("Saxon 2.0: %q, %v; want %q", output, err, want)
	}
}

func TestCompareSaxonDecimalCompatibilityVersions(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, version := range []string{"-29", "0", "-0.0", "0.5", "+1.50"} {
		for _, local := range []bool{false, true} {
			source := sheet(version, `<xsl:template name="start"><xsl:value-of select="1 to 5"/></xsl:template>`)
			if local {
				source = sheet(version30, `<xsl:template name="start"><xsl:value-of version="`+version+`" select="1 to 5"/></xsl:template>`)
			}
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('','start'),'delivery-format':'serialized'})?output`
			t.Run(version+strconv.FormatBool(local), func(t *testing.T) { compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, "1") })
		}
	}
}

func TestCompareSaxonModuleUseWhenNamespaces(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	for _, kind := range []string{nameInclude, nameImport} {
		for _, rootCondition := range []bool{false, true} {
			main, module := moduleUseWhenNamespaceSources(kind, rootCondition)
			path := filepath.Join(t.TempDir(), "module.xsl")
			if err := os.WriteFile(path, []byte(module), 0o600); err != nil {
				t.Fatal(err)
			}
			uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String()
			main = strings.ReplaceAll(main, "urn:module", uri)
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(module)), ctx.Err()
			})})
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(main, "'", "''") + `','initial-template':QName('','start'),'delivery-format':'serialized'})?output`
			t.Run(kind+strconv.FormatBool(rootCondition), func(t *testing.T) {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, "42:false")
			})
		}
	}
}

func TestCompareSaxonHostFunctionContracts(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range hostFunctionCases() {
		for _, version := range []string{version20, version30} {
			t.Run(test.name+version, func(t *testing.T) {
				source := hostFunctionSheet(version, test)
				expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('','start'),'delivery-format':'serialized'})?output`
				oracle := test.want30
				if test.name == "unparsed entity absent context" {
					oracle = "XTDE1370"
				}
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want30, oracle)
			})
		}
	}
}

// F&O 3.1 section 4.7.3 treats a trailing exponent separator as passive:
// without an active character after it, it belongs to the suffix. Saxon HE
// 12.10 drops it; retain the difference separately from exact agreements.
func TestCompareSaxonNumberPictureDiagnostic(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	e := engine(t, transform.Config{})
	for _, options := range [][]string{nil, {"-opt:0"}} {
		compareSaxonConfiguredExpression(t, ctx, e, binary, classpath, `format-number(12,'0e')`, "12e", options, "12")
	}
}

func TestCompareSaxonStaticParameterContracts(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	e := engine(t, transform.Config{})
	for _, test := range staticParameterCases() {
		t.Run(test.name, func(t *testing.T) {
			expression := strings.ReplaceAll(staticParameterExpression(test.argument), "$stylesheet", "'"+strings.ReplaceAll(staticParameterSheet(test), "'", "''")+"'")
			oracle := test.want
			switch test.name {
			case "implicitly required":
				oracle = "XTDE0700" // Global static parameters require XTDE0050 in XSLT 3.0 section 2.3.2.
			case "default mismatch":
				oracle = "XTDE0050" // An explicit incompatible default is not implicitly mandatory under section 9.2.2.
			case "unused default mismatch":
				oracle = "XTTE0590" // Reporting an unused default's type error is permitted.
			case "string mismatch", "empty mismatch", "multiple mismatch":
				oracle = errCodeXPTY0004 // Saxon exposes the host-side function conversion error.
			case "untyped lexical error":
				oracle = errCodeFORG0001
			case "namespace sensitive input":
				oracle = errCodeXPTY0117
			case "default type namespace":
				oracle = errCodeXPST0051 // Native uses the declaration's XPath default type namespace.
			}
			if oracle != test.want {
				t.Log("Independent diagnostic; excluded from exact agreements:", test.want, oracle)
			}
			compareSaxonExpression(t, ctx, e, binary, classpath, expression, test.want, oracle)
		})
	}
	for _, test := range staticVariableCases() {
		t.Run("variable/"+test.name, func(t *testing.T) {
			expression := strings.ReplaceAll(staticParameterExpression(""), "$stylesheet", "'"+strings.ReplaceAll(staticVariableSheet(test), "'", "''")+"'")
			oracle := test.want
			switch test.name {
			case "string mismatch":
				oracle = "XTDE0050"
			case "untyped lexical error":
				oracle = errCodeFORG0001
			case "default type namespace":
				oracle = errCodeXPST0051
			}
			if oracle != test.want {
				t.Log("Independent diagnostic; excluded from exact agreements:", test.want, oracle)
			}
			compareSaxonExpression(t, ctx, e, binary, classpath, expression, test.want, oracle)
		})
	}
}

func TestCompareSaxonPackageBindings(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	for _, test := range packageBindingCases() {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()

			mainPath, libraryPath := filepath.Join(dir, "main.xsl"), filepath.Join(dir, "library.xsl")
			for path, source := range map[string]string{mainPath: test.using, libraryPath: test.library} {
				if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			output, err := exec.CommandContext(ctx, binary, "-cp", classpath, "net.sf.saxon.Transform", "-xsl:"+mainPath, "-lib:"+libraryPath, "-it:start").Output()
			if diagnostic, separate := strings.CutPrefix(test.oracleWant, "diagnostic:"); separate {
				var failure *exec.ExitError
				if !errors.As(err, &failure) || !strings.Contains(string(failure.Stderr), diagnostic) {
					t.Fatal(output, err, test.oracleWant)
				}
				t.Log("Independent engine diagnostic; excluded from exact agreements:", diagnostic)
				return
			}

			got := string(output)
			if err != nil {
				got = saxonDiagnosticCode(err)
			}

			want := test.want
			if test.oracleWant != "" {
				want = test.oracleWant
			}

			if got != want {
				var diagnostic *exec.ExitError
				if errors.As(err, &diagnostic) {
					t.Fatalf("Saxon: %q, %s; want %q", output, diagnostic.Stderr, want)
				}

				t.Fatal(got, err, want)
			}
		})
	}
}

func TestCompareSaxonGlobalChains(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	for _, test := range packageGlobalChainCases() {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			libraries := make([]string, 0, len(test.libraries))
			for name, source := range test.libraries {
				path := filepath.Join(dir, strings.TrimPrefix(name, "urn:")+".xsl")
				if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
				libraries = append(libraries, path)
			}
			main := filepath.Join(dir, "main.xsl")
			if err := os.WriteFile(main, []byte(test.using), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.CommandContext(t.Context(), binary, "-cp", classpath, "net.sf.saxon.Transform", "-xsl:"+main, "-lib:"+strings.Join(libraries, string(os.PathListSeparator)), "-it:start").Output()
			got := string(output)
			if err != nil {
				got = saxonDiagnosticCode(err)
			}
			want := test.want
			if test.oracleWant != "" {
				want = test.oracleWant
			}
			if got != want {
				var detail *exec.ExitError
				if errors.As(err, &detail) {
					t.Fatalf("%s; want %s", detail.Stderr, want)
				}
				t.Fatal(got, err, want)
			}
		})
	}
}

func TestCompareSaxonGlobalPrecedence(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	for _, test := range globalPrecedenceCases() {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			module, main := filepath.Join(dir, "module.xsl"), filepath.Join(dir, "main.xsl")
			uri := (&url.URL{Scheme: "file", Path: module}).String()
			for path, source := range map[string]string{module: sheet(version30, test.imported), main: globalPrecedenceSheet(version30, uri, test.local)} {
				if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			output, err := exec.CommandContext(t.Context(), binary, "-cp", classpath, "net.sf.saxon.Transform", "-xsl:"+main, "-it:start").Output()
			got := string(output)
			if err != nil {
				got = saxonDiagnosticCode(err)
			}
			if got != test.want {
				var detail *exec.ExitError
				if errors.As(err, &detail) {
					t.Fatalf("%s; want %s", detail.Stderr, test.want)
				}
				t.Fatal(got, err, test.want)
			}
		})
	}
}

func checkSaxonPackageModeResult(t *testing.T, output []byte, err error, test packageModeCase) {
	t.Helper()

	if test.oracleDiagnostic != "" {
		var diagnostic *exec.ExitError
		if !errors.As(err, &diagnostic) || !strings.Contains(string(diagnostic.Stderr), test.oracleDiagnostic) {
			t.Fatal(output, err, test.oracleDiagnostic)
		}

		t.Log("Independent engine diagnostic; excluded from exact agreements:", test.oracleDiagnostic)

		return
	}

	got := string(output)
	if err != nil {
		got = saxonDiagnosticCode(err)
	}

	want := test.want
	if test.oracleWant != "" {
		want = test.oracleWant
		t.Log("Recorded implementation difference; excluded from exact agreements:", test.want, test.oracleWant)
	}

	if got != want {
		var diagnostic *exec.ExitError
		if errors.As(err, &diagnostic) {
			t.Fatalf("Saxon: %s; want %q", diagnostic.Stderr, want)
		}

		t.Fatal(got, err, want)
	}
}

func TestCompareSaxonPackageModeBindings(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	for _, test := range packageModeCases() {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()

			mainPath := filepath.Join(dir, "main.xsl")
			if err := os.WriteFile(mainPath, []byte(test.using), 0o600); err != nil {
				t.Fatal(err)
			}

			libraryPaths := make([]string, 0, len(test.libraries))
			for _, source := range test.libraries {
				path := filepath.Join(dir, "library"+strconv.Itoa(len(libraryPaths))+".xsl")
				if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}

				libraryPaths = append(libraryPaths, path)
			}

			output, err := exec.CommandContext(ctx, binary, "-cp", classpath, "net.sf.saxon.Transform", "-xsl:"+mainPath, "-lib:"+strings.Join(libraryPaths, string(os.PathListSeparator)), "-it:start").Output()

			checkSaxonPackageModeResult(t, output, err, test)
		})
	}
}

func TestCompareSaxonPackageContracts(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	e := engine(t, transform.Config{})

	for _, test := range []struct{ attributes, body, entry, want string }{
		{`_xmlns="urn:injected"`, "", nameStart, errCodeXTSE0090},
		{`__version="3.0"`, "", nameStart, errCodeXTSE0090},
		{"", `<xsl:import-schema namespace="urn:unused" use-when="false()"/>`, nameStart, "ok"},
		{"", `<xsl:expose component="template" names="missing" visibility="public"/>`, nameStart, errCodeXTSE3020},
		{"", `<xsl:param name="p"/><xsl:expose component="variable" names="p" visibility="private"/>`, nameStart, errCodeXTSE3020},
		{"", `<xsl:template name="h"/><xsl:expose component="*" names="h" visibility="public"/>`, nameStart, "XTSE3022"},
		{"", `<xsl:template name="h"/><xsl:expose component="template" names="h" visibility="hidden"/>`, nameStart, errCodeXTSE0020},
		{"", `<xsl:template name="h">ok</xsl:template><xsl:expose component="template" names="h" visibility="public"/><xsl:expose component="*" names="*" visibility="private"/>`, "h", "ok"},
		{"", `<xsl:template name="h" visibility="public">ok</xsl:template><xsl:expose component="template" names="*" visibility="private"/>`, "h", "ok"},
		{`package-version="invalid" _package-version="2.0-valid"`, "", nameStart, "ok"},
		{emptyPackageVersionAttribute, "", nameStart, errCodeXTSE0020},
		{`_package-version="{1 div 0}"`, "", nameStart, errCodeFOAR0001},
	} {
		source := packageSheet(test.attributes, test.body+`<xsl:template name="start" visibility="public">ok</xsl:template>`)
		expression := `let $s := '` + strings.ReplaceAll(source, "'", "''") + `' return transform(map{'stylesheet-text':$s,'initial-template':QName('', '` + test.entry + `'),'delivery-format':'serialized'})?output`
		t.Run(test.attributes+test.body, func(t *testing.T) { compareSaxonExpression(t, ctx, e, binary, classpath, expression, test.want) })
	}

	for _, declaration := range []string{"", `<xsl:mode name="m" visibility="private"/>`, `<xsl:expose component="mode" names="*" visibility="private"/>`} {
		source := packageSheet(`declared-modes="no"`, declaration+`<xsl:template match="." mode="m"><xsl:value-of select="."/></xsl:template>`)
		expression := `let $s := '` + strings.ReplaceAll(source, "'", "''") + `' return transform(map{'stylesheet-text':$s,'initial-mode':QName('', 'm'),'initial-match-selection':7,'delivery-format':'serialized'})?output`

		want := "7"
		if declaration != "" {
			want = errCodeXTDE0045
		}

		t.Run("initial mode "+declaration, func(t *testing.T) { compareSaxonExpression(t, ctx, e, binary, classpath, expression, want) })
	}
}

func TestCompareSaxonExposureEditionDiagnostic(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	e := engine(t, transform.Config{})
	// REC 2017 permits a NameTest for functions, without an arity. The pinned
	// Saxon incorporates the later E36 correction cited by the publisher suite;
	// the published errata page still contains no adopted correction text.
	source := packageSheet("", `<xsl:function name="p:f"><xsl:sequence select="42"/></xsl:function><xsl:expose component="function" names="p:f" visibility="public"/>`)
	expression := `let $s := '` + strings.ReplaceAll(source, "'", "''") + `' return transform(map{'stylesheet-text':$s,'initial-function':QName('urn:components','f'),'function-params':[],'delivery-format':'serialized'})?output`
	compareSaxonExpression(t, ctx, e, binary, classpath, expression, "42", errCodeXTSE3020)
}

func TestCompareSaxonResultDelivery(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	e := engine(t, transform.Config{})

	for _, test := range []struct{ body, format, assertion, want string }{
		{mixedResultTemplate, deliveryRawOption, `count($r?output) eq 5 and $r?output[1] instance of xs:integer and $r?output[3] instance of text() and $r?output[5] instance of xs:boolean`, nameTrue},
		{mixedResultTemplate, "", `$r?output instance of document-node() and string($r?output) eq '1 2true' and count($r?output/node()) eq 3`, nameTrue},
		{`<xsl:output method="json"/><xsl:template name="start"><xsl:sequence select="map{'value':3}"/></xsl:template>`, deliveryRawOption, `$r?output instance of map(*) and $r?output?value eq 3`, nameTrue},
		{`<xsl:output method="adaptive"/><xsl:template name="start"><xsl:sequence select="map{'value':3}"/></xsl:template>`, deliveryDocumentOption, `$r?output`, errCodeSENR0001},
		{`<xsl:output item-separator="|"/><xsl:template name="start"><xsl:sequence select="([1,[2]],parse-xml-fragment('AB&lt;r/>'),4)"/></xsl:template>`, deliveryDocumentOption, `string($r?output) eq '1|2|AB|4' and count($r?output/node()) eq 3`, nameTrue},
		{`<xsl:template name="start">one<xsl:result-document href="secondary" method="adaptive"><xsl:sequence select="(1,map{'value':3},2)"/></xsl:result-document></xsl:template>`, ",'base-output-uri':'https://output.invalid/main','delivery-format':'raw'", `$r('https://output.invalid/secondary')[1] eq 1 and $r('https://output.invalid/secondary')[2]?value eq 3 and $r('https://output.invalid/secondary')[3] eq 2`, nameTrue},
		{`<xsl:template name="start"><xsl:sequence select="(1,2)"/></xsl:template>`, ",'post-process':function($uri,$value){$value instance of document-node() and string($value) eq '1 2'}", `$r?output`, nameTrue},
		{`<xsl:template name="start"><xsl:result-document href="https://output.invalid/secondary"><r/></xsl:result-document></xsl:template>`, "", `map:contains($r,'output')`, nameTrue},
	} {
		source := sheetStart + version30 + `">` + test.body + `</xsl:stylesheet>`
		expression := `let $s := '` + strings.ReplaceAll(source, "'", "''") + `', $r := transform(map{'stylesheet-text':$s,'initial-template':QName('', 'start')` + test.format + `}) return ` + test.assertion
		t.Run(test.assertion, func(t *testing.T) { compareSaxonExpression(t, ctx, e, binary, classpath, expression, test.want) })
	}
}

func TestCompareSaxonResultDocumentURIs(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range resultDocumentURICases() {
		for _, format := range []string{"raw", "document", "serialized"} {
			t.Run(test.name+"/"+format, func(t *testing.T) {
				oracle := test.want
				switch test.name {
				case "relative principal alias":
					if format != "serialized" {
						oracle = "false"
					}
				case "nested absent href inherits current URI":
					oracle = "false"
				case "nested empty href resets current URI":
					if format == "raw" {
						oracle = "false"
					}
				case "catch implicit collision", "catch selected collision", "explicit rollback releases principal":
					oracle = "XTDE1490"
				}
				// Keep URI normalization/current-output-uri discrepancies and
				// Saxon's deferred principal conflict/reservation diagnostics visible.
				compareSaxonExpression(t, t.Context(), e, binary, classpath, resultDocumentURIQuery(test.body, format, test.check), test.want, oracle)
			})
		}
	}
}

func TestCompareSaxonMarkupSerializationContracts(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range markupSerializationCases() {
		t.Run(test.name, func(t *testing.T) {
			check := markupSerializationCheck(test)
			prefix := `let $s := transform(map{'stylesheet-text':'` + strings.ReplaceAll(markupSerializationSheet(test, false), "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output return `
			// Section 7.4.6 requires an explicit HTML DOCTYPE even without an
			// element. Saxon defers it to the first element and loses it here.
			switch test.name {
			case "HTML empty explicit doctype":
				compareSaxonExpression(t, t.Context(), e, binary, classpath, prefix+`$s`, test.want, "")
				return
			case "HTML rootless explicit doctype":
				compareSaxonExpression(t, t.Context(), e, binary, classpath, prefix+`$s`, test.want, `<!--lead--><?p v>`)
				return
			case "HTML rootless fallback doctype":
				compareSaxonExpression(t, t.Context(), e, binary, classpath, prefix+`$s`, test.want, `<!--lead--><?p v>text`)
				return
			}
			oracle := nameTrue
			if test.name == "HTML5 leading text" || test.name == "XHTML5 leading text" {
				// Serialization 3.1 §7.4.6 excludes automatic DOCTYPE after
				// non-whitespace text; Saxon 12.10 still emits one.
				oracle = nameFalse
			}
			if test.name == "NFD text map immunity" {
				// Saxon's text method also decomposes the mapped ç. Section 11
				// requires replacements to remain immune to normalization.
				oracle = nameFalse
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, prefix+check, nameTrue, oracle)
			if test.name == "NFD text map immunity" {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, prefix+`string-join(string-to-codepoints($s)!string(.),',')`, "97,98,35,231,35,99,807,100,101", "97,98,35,99,807,35,99,807,100,101")
			}
			if test.name == "CDATA maps excluded" {
				// Native preserves CR via a reference outside CDATA; Saxon
				// writes literal CR inside it. Keep that distinction visible.
				compareSaxonExpression(t, t.Context(), e, binary, classpath, prefix+`contains($s,codepoints-to-string(13))`, nameFalse, nameTrue)
			}
		})
	}
	for _, expression := range append(xmlSerializationExpressions(), defaultMarkupMethodExpressions()...) {
		t.Run(expression, func(t *testing.T) {
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, nameTrue)
		})
	}
}

func TestCompareSaxonContextualKeywordOperands(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	var prolog strings.Builder
	for _, keyword := range contextualOperatorKeywords() {
		prolog.WriteString(`declare namespace ` + keyword + `="http://www.w3.org/2005/xpath-functions";`)
	}
	for _, test := range contextualKeywordOperandCases() {
		t.Run(test.expression, func(t *testing.T) {
			expression := prolog.String() + `parse-xml('` + contextualKeywordXML() + `')/r ! (` + test.expression + `)`
			result, err := saxonQuery(t, t.Context(), binary, classpath, expression)
			if err != nil || string(result) != test.want {
				t.Fatalf("Saxon: %q, %v; want %q", result, err, test.want)
			}
		})
	}
}

// F&O 3.1 specifies raw delivery when build-tree="no". Saxon HE 12.10
// constructs document nodes for an omitted delivery-format even in that case.
func TestCompareSaxonBuildTreeDiagnostic(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	e := engine(t, transform.Config{})

	for _, test := range []struct{ body, assertion, oracle string }{
		{`<xsl:output method="json" build-tree="no"/><xsl:template name="start"><xsl:sequence select="map{'value':3}"/></xsl:template>`, `$r?output instance of map(*) and $r?output?value eq 3`, errCodeSENR0001},
		{unbuiltResultTemplate, `deep-equal($r?output,(1,2))`, nameFalse},
	} {
		source := sheetStart + version30 + `">` + test.body + `</xsl:stylesheet>`
		expression := `let $s := '` + strings.ReplaceAll(source, "'", "''") + `', $r := transform(map{'stylesheet-text':$s,'initial-template':QName('', 'start')}) return ` + test.assertion
		t.Run(test.assertion, func(t *testing.T) {
			compareSaxonExpression(t, ctx, e, binary, classpath, expression, nameTrue, test.oracle)
		})
	}
}

func compareSaxonExpression(t *testing.T, ctx context.Context, e *transform.Engine, binary, classpath, expression, want string, oracleWant ...string) {
	t.Helper()
	compareSaxonConfiguredExpression(t, ctx, e, binary, classpath, expression, want, nil, oracleWant...)
}

func compareSaxonConfiguredExpression(t *testing.T, ctx context.Context, e *transform.Engine, binary, classpath, expression, want string, options []string, oracleWant ...string) {
	t.Helper()

	program, err := e.CompileXPath(ctx, expression, transform.XPathOptions{Version: transform.XPath31})

	var value transform.Sequence
	if err == nil {
		value, err = program.Evaluate(ctx, nil, transform.XPathContext{})
	}

	oracle := strings.ReplaceAll(expression, "&", "&amp;")

	if comparisonErrorCode(want) {
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != want {
			t.Fatal(value, err, want)
		}
	} else if err != nil || text(t, value) != want {
		t.Fatal(value, err, want)
	}

	expected := want
	if len(oracleWant) != 0 {
		expected = oracleWant[0]
	}

	if comparisonErrorCode(expected) {
		oracle = "try { " + oracle + " } catch * { local-name-from-QName($err:code) }"
	}

	output, err := saxonQuery(t, ctx, binary, classpath, oracle, options...)

	if err != nil && comparisonErrorCode(expected) {
		if code := saxonDiagnosticCode(err); code != "" {
			output, err = []byte(code), nil
		}
	}

	if err != nil || string(output) != expected {
		var failure *exec.ExitError
		if errors.As(err, &failure) {
			t.Log(string(failure.Stderr))
		}

		t.Fatalf("Saxon %s: %q, %v; want %q", expression, output, err, expected)
	}
}

// Unicode 7.0.0 UnicodeData.txt already maps U+037F to U+03F3 and back.
// The pinned Saxon HE 12.10 case tables retain the older unchanged characters.
// Keep this diagnostic separate from agreement evidence and publisher totals.
func TestCompareSaxonUnicodeCaseDiagnostic(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	const expression = `concat(string-to-codepoints(lower-case(codepoints-to-string(895))), ':', string-to-codepoints(upper-case(codepoints-to-string(1011))))`

	e := engine(t, transform.Config{})
	if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != "1011:895" {
		t.Fatal("Unicode Yot case mapping changed", got)
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	output, err := saxonQuery(t, ctx, binary, classpath, expression)
	if err != nil || string(output) != "895:1011" {
		t.Fatalf("pinned Saxon case-table diagnostic: %q, %v", output, err)
	}
}

// Saxon HE 12.10 discards an encoding pseudo-attribute before checking its
// EncName grammar. Retain this difference separately from agreement evidence:
// XML 1.0 production [81] and F&O 14.7.1 still require well-formed input.
func TestCompareSaxonXMLDeclarationDiagnostic(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	source := `parse-xml('<?xml version="1.0" encoding="1bad"?><r/>')`
	e := engine(t, transform.Config{})
	_, err := query(t, e, source, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

	var detail *transform.Error
	if !errors.As(err, &detail) || detail.Code != errCodeFODC0006 {
		t.Fatal("malformed EncName was accepted", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	output, err := saxonQuery(t, ctx, binary, classpath, "exists("+source+")")
	if err != nil || string(output) != nameTrue {
		t.Fatalf("Saxon declaration diagnostic changed: %q, %v", output, err)
	}
}

func saxonRuntime(t *testing.T) (string, string) {
	t.Helper()

	classpath := os.Getenv("SAXON_CLASSPATH")
	if classpath == "" {
		t.Skip("SAXON_CLASSPATH is not configured")
	}

	binary, err := exec.LookPath("java")
	if err != nil {
		t.Fatal("configured Saxon requires java", err)
	}

	return classpath, binary
}

func saxonQuery(t *testing.T, ctx context.Context, binary, classpath, source string, options ...string) ([]byte, error) {
	t.Helper()
	// A query file avoids the JVM command-line charset, which can replace
	// Unicode characters under the Docker image's C locale.
	queryPath := filepath.Join(t.TempDir(), "query.xq")
	if err := os.WriteFile(queryPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	arguments := make([]string, 0, 5+len(options))
	arguments = append(arguments, "-cp", classpath, "net.sf.saxon.Query", "-q:"+queryPath, "!method=text")
	arguments = append(arguments, options...)

	return exec.CommandContext(ctx, binary, arguments...).Output()
}

func TestCompareSaxonTransformAssertionOptions(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	e := engine(t, transform.Config{EnableXSLTAssertions: true})
	source := sheet(version30, `<xsl:template name="start"><xsl:assert test="false()"/><xsl:text>after</xsl:text></xsl:template>`)

	for option, want := range map[string]string{"": afterAssertionText, falseExpression: afterAssertionText, trueExpression: errCodeXTMM9001, "xs:untypedAtomic('1')": errCodeXTMM9001, "'true'": errCodeXPTY0004, "()": errCodeXPTY0004} {
		extra := ""
		if option != "" {
			extra = ",'enable-assertions':" + option
		}

		expression := `let $s := '` + strings.ReplaceAll(source, "'", "''") + `' return transform(map{'stylesheet-text':$s,'initial-template':QName('', 'start'),'delivery-format':'serialized'` + extra + `})?output`

		t.Run(option, func(t *testing.T) { compareSaxonExpression(t, ctx, e, binary, classpath, expression, want) })
	}
}

func TestCompareSaxonAssertionPolicies(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	for _, enabled := range []bool{false, true} {
		e := engine(t, transform.Config{EnableXSLTAssertions: enabled})

		var options []string
		if enabled {
			options = []string{"--enableAssertions:on"}
		}

		for code, want := range map[string]string{
			"p:ALARM":                assertionErrorText,
			"Q{urn:assertions}ALARM": assertionErrorText,
			nameAssertionAlarm:       ":ALARM",
			"missing:ALARM":          namespaceErrors + ":" + errCodeXTMM9000,
		} {
			source := sheet(version30, `<xsl:param name="code"/><xsl:output method="text"/><xsl:template name="start"><xsl:try xmlns:p="urn:assertions" xmlns:err="http://www.w3.org/2005/xqt-errors"><xsl:assert test="false()" error-code="{$code}" select="'broken'"/><xsl:text>after</xsl:text><xsl:catch errors="*"><xsl:value-of select="concat(namespace-uri-from-QName($err:code),':',local-name-from-QName($err:code))"/></xsl:catch></xsl:try></xsl:template>`)
			expression := `let $stylesheet := '` + strings.ReplaceAll(source, "'", "''") + `' return transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'delivery-format':'serialized','enable-assertions':` + strconv.FormatBool(enabled) + `(),'stylesheet-params':map{QName('', 'code'):'` + strings.ReplaceAll(code, "'", "''") + `'}})?output`

			if !enabled {
				want = afterAssertionText
			}

			if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != want {
				t.Fatal(enabled, code, got, want)
			}

			output, err := saxonQuery(t, ctx, binary, classpath, expression, options...)
			if err != nil || string(output) != want {
				t.Fatalf("Saxon assertions %t %s: %q, %v; want %q", enabled, code, output, err, want)
			}
		}
	}
}

func TestCompareSaxonBasicProfile(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	e := engine(t, transform.Config{})

	for body, want := range map[string]string{
		`<xsl:import-schema namespace="urn:x"/>`:                                 "XTSE1650",
		`<xsl:template name="start"><r xsl:validation="strict"/></xsl:template>`: errCodeXTSE1660,
		`<xsl:template name="start"><r xsl:type="xs:string"/></xsl:template>`:    errCodeXTSE1660,
		`<xsl:template name="start"><xsl:variable name="node" as="element(*, xs:untyped)"><r xsl:validation="lax" a="value"/></xsl:variable><xsl:variable name="copy" as="element(*, xs:anyType)"><xsl:copy-of select="$node" validation="preserve"/></xsl:variable><xsl:value-of select="$copy instance of element(*, xs:untyped), $copy/@a instance of attribute(*, xs:untypedAtomic)"/></xsl:template>`: "true true",
		`<xsl:mode streamable="yes"/><xsl:template name="start"><xsl:value-of select="system-property('xsl:supports-streaming')"/></xsl:template>`:                                  "no",
		`<xsl:template name="start"><r value="{1 div 0}"/></xsl:template>`:                                                                                                          errCodeFOAR0001,
		`<xsl:template name="start"><r value="{[map{}]}"/></xsl:template>`:                                                                                                          errCodeFOTY0013,
		`<xsl:template name="start"><xsl:comment select="[map{}]"/></xsl:template>`:                                                                                                 errCodeFOTY0013,
		`<xsl:template name="start"><xsl:value-of select="[1,[2,3]]"/></xsl:template>`:                                                                                              integerSequenceText,
		`<xsl:template name="start"><xsl:variable name="r" as="element()"><r xsl:version="1.0" value="{[1,2],3}"/></xsl:variable><xsl:value-of select="$r/@value"/></xsl:template>`: "1",
		`<xsl:template name="start"><xsl:variable name="a" as="text()"><xsl:text>A</xsl:text></xsl:variable><xsl:variable name="b" as="text()"><xsl:text>B</xsl:text></xsl:variable><xsl:variable name="empty" as="text()"><xsl:text/></xsl:variable><xsl:value-of select="[$a, [], [$empty, $b], '', [1,2]]" separator="|"/></xsl:template>`: "A||B||1|2",
	} {
		compareSaxonStylesheet(t, ctx, e, binary, classpath, body, want)
	}
}

func compareSaxonStylesheet(t *testing.T, ctx context.Context, e *transform.Engine, binary, classpath, body, want string, oracleWant ...string) {
	t.Helper()

	source := sheet(version30, body)
	expression := `let $s := '` + strings.ReplaceAll(source, "'", "''") + `' return transform(map{'stylesheet-text':$s,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`

	result, err := query(t, e, expression, transform.XPath31).Evaluate(ctx, nil, transform.XPathContext{})
	got := ""

	if err != nil {
		var detail *transform.Error
		if !errors.As(err, &detail) {
			t.Fatal(err)
		}

		got = detail.Code
	} else {
		got = text(t, result)
	}

	if got != want {
		t.Fatal(body, got, want)
	}

	// The oracle runs XQuery, whose string literals decode entity references.
	output, err := saxonQuery(t, ctx, binary, classpath, strings.ReplaceAll(expression, "&", "&amp;"))

	expected := want
	if len(oracleWant) != 0 {
		expected = oracleWant[0]
	}

	got = string(output)
	if err != nil {
		got = saxonDiagnosticCode(err)
	}

	if got != expected {
		var diagnostic *exec.ExitError
		if errors.As(err, &diagnostic) {
			t.Fatalf("Saxon %s: %q, %s; want %q", body, output, diagnostic.Stderr, expected)
		}

		t.Fatalf("Saxon %s: %q, %v; want %q", body, output, err, expected)
	}
}

func TestCompareSaxonAttributeSetCycleDiagnostic(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	e := engine(t, transform.Config{})
	// XSLT 3.0 9.11 removed the old static XTSE0720 classification.
	compareSaxonStylesheet(t, ctx, e, binary, classpath, cyclicAttributeSets+activeAttributeSetTemplate, errCodeXTDE0640, "XTSE0720")
	compareSaxonStylesheet(t, ctx, e, binary, classpath, cyclicAttributeSets+`<xsl:template name="start">ok</xsl:template>`, "ok", "XTSE0720")
}

func TestCompareSaxonDeclarationContracts(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	e := engine(t, transform.Config{})
	for body, want := range map[string]string{
		indirectAttributeSetCycle + activeAttributeSetTemplate: errCodeXTDE0640,

		`<xsl:template name="start"><xsl:call-template name="missing"/></xsl:template>`:                                                           errCodeXTSE0650,
		`<xsl:template name="start"><xsl:call-template name="bad/name"/></xsl:template>`:                                                          errCodeXTSE0020,
		`<xsl:template xmlns:p="urn:application" name="p:target"/><xsl:template name="start"><xsl:call-template name="p:target"/></xsl:template>`: errCodeXTSE0280,
		`<xsl:template name="same"/><xsl:template name="same"/>`:                                                                                  errCodeXTSE0660,
		`<xsl:function name="local"/>`:    errCodeXTSE0740,
		`<xsl:function name="Q{}local"/>`: errCodeXTSE0740,
		`<xsl:function xmlns:p="urn:application" name="p:first"/><xsl:function name="p:second"/>`:                                                                                           errCodeXTSE0280,
		`<xsl:namespace-alias stylesheet-prefix="missing" result-prefix="xsl"/>`:                                                                                                            errCodeXTSE0812,
		`<xsl:namespace-alias stylesheet-prefix="xsl" result-prefix="missing"/>`:                                                                                                            errCodeXTSE0812,
		`<xsl:variable name="a" select="$b"/><xsl:variable name="b" select="$a"/><xsl:template name="start"><xsl:value-of select="$a"/></xsl:template>`:                                     errCodeXTDE0640,
		`<xsl:template name="start"><xsl:call-template name="required"/></xsl:template><xsl:template name="required"><xsl:context-item use="required"/></xsl:template>`:                     errCodeXTTE3090,
		`<xsl:template name="start"><xsl:call-template xmlns:p="urn:application" name="p:target"/></xsl:template><xsl:template xmlns:p="urn:application" name="p:target">ok</xsl:template>`: "ok",
	} {
		compareSaxonStylesheet(t, ctx, e, binary, classpath, body, want)
	}
}

func TestCompareSaxonModuleDiagnostics(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	const (
		overrideCase = "override"
		fileScheme   = "file"
	)
	// In one mixed cycle Saxon classifies the closing include edge (XTSE0180),
	// while the native processor classifies the cycle containing an import
	// (XTSE0210). Preserve that diagnostic difference explicitly.
	for _, tc := range []struct{ first, second, want, oracle string }{
		{nameInclude, nameInclude, errCodeXTSE0180, errCodeXTSE0180},
		{nameImport, nameImport, errCodeXTSE0210, errCodeXTSE0210},
		{nameInclude, nameImport, errCodeXTSE0210, errCodeXTSE0210},
		{nameImport, nameInclude, errCodeXTSE0210, errCodeXTSE0180},
		{"duplicate", "", errCodeXTSE0660, errCodeXTSE0660},
		{overrideCase, "", higherResultText, higherResultText},
	} {
		root := t.TempDir()
		firstPath, secondPath := filepath.Join(root, "first.xsl"), filepath.Join(root, "second.xsl")
		firstURI := (&url.URL{Scheme: fileScheme, Path: firstPath}).String()
		secondURI := (&url.URL{Scheme: fileScheme, Path: secondPath}).String()
		firstBody, secondBody := `<xsl:`+tc.first+` href="`+secondURI+`"/>`, `<xsl:`+tc.second+` href="`+firstURI+`"/>`
		body := `<xsl:import href="` + firstURI + `"/>`

		if tc.first == "duplicate" || tc.first == overrideCase {
			firstBody = `<xsl:template name="start">first</xsl:template><xsl:template name="start">second</xsl:template>`
			secondBody = ""
		}

		if tc.first == overrideCase {
			body += `<xsl:template name="start">higher</xsl:template>`
		}

		resources := map[string]string{firstURI: sheet(version30, firstBody), secondURI: sheet(version30, secondBody)}
		for uri, path := range map[string]string{firstURI: firstPath, secondURI: secondPath} {
			if err := os.WriteFile(path, []byte(resources[uri]), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
			value, found := resources[uri]
			if !found {
				return nil, transform.ErrResource
			}

			return io.NopCloser(strings.NewReader(value)), ctx.Err()
		})})
		compareSaxonStylesheet(t, ctx, e, binary, classpath, body, tc.want, tc.oracle)
	}
}

func TestCompareSaxonDeclarationDiagnostics(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	// Both processors reject these placements. Saxon emits the prescribed code
	// alongside XTSE0010, which it chooses as the primary diagnostic.
	for name, code := range map[string]string{nameInclude: errCodeXTSE0170, nameImport: errCodeXTSE0190} {
		source := sheet(version30, `<xsl:template name="start"><xsl:`+name+` href="urn:missing"/></xsl:template>`)
		expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start')})`
		_, err := saxonQuery(t, ctx, binary, classpath, expression)

		var diagnostic *exec.ExitError
		if !errors.As(err, &diagnostic) || !strings.Contains(string(diagnostic.Stderr), code) {
			t.Fatal(name, err)
		}
	}
}

func TestCompareSaxonEncodedXMLInputs(t *testing.T) {
	classpath, binary := saxonRuntime(t)

	e := engine(t, transform.Config{AllowSingleByteEncodings: true})
	for _, tc := range []struct{ encoding, prefix, content, want string }{
		{xmlLatinEncoding, "\xe9", "caf\xe9", "é:café"},
		{"windows-1252", "\x80", "\x80", "€:€"},
	} {
		root := t.TempDir()
		declaration := `<?xml version="1.0" encoding="` + tc.encoding + `"?>`
		source := declaration + `<r>` + tc.content + `</r>`
		style := declaration + `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="text"/><xsl:template match="/"><xsl:text>` + tc.prefix + `:</xsl:text><xsl:value-of select="/r"/></xsl:template></xsl:stylesheet>`

		inputPath, stylePath := filepath.Join(root, "source.xml"), filepath.Join(root, "style.xsl")
		if err := os.WriteFile(inputPath, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(stylePath, []byte(style), 0o600); err != nil {
			t.Fatal(err)
		}

		doc, err := e.Parse(t.Context(), []byte(source))
		if err != nil {
			t.Fatal(err)
		}

		compiled, err := e.CompileXSLT(t.Context(), []byte(style), transform.XSLTOptions{})
		if err != nil {
			t.Fatal(err)
		}

		result, err := compiled.Transform(t.Context(), doc, transform.XSLTContext{})
		if err != nil || string(result.Primary) != tc.want {
			t.Fatal(result, err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		output, err := exec.CommandContext(ctx, binary, "-cp", classpath, "net.sf.saxon.Transform", "-s:"+inputPath, "-xsl:"+stylePath).Output()

		cancel()

		if err != nil || string(output) != tc.want {
			t.Fatalf("Saxon %s: %q, %v", tc.encoding, output, err)
		}
	}
}

// Static type errors may be diagnosed before XQuery try/catch can run.
func saxonDiagnosticCode(err error) string {
	var diagnostic *exec.ExitError
	if !errors.As(err, &diagnostic) {
		return ""
	}

	for _, line := range strings.Split(string(diagnostic.Stderr), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			code := strings.TrimSuffix(fields[0], ":")
			if comparisonErrorCode(code) && !strings.HasPrefix(code, "SXWN") {
				return code
			}
		}
	}

	return ""
}

func TestCompareLibxmlXPath10(t *testing.T) {
	binary, err := exec.LookPath("xmllint")
	if err != nil {
		t.Skip("xmllint is unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	source := `<r xmlns:p="urn:p" xml:lang="en-US"><v n="2">2</v><v n="3">3</v><p:x>4</p:x></r>`
	e := engine(t, transform.Config{})

	d, err := e.Parse(ctx, []byte(source))
	if err != nil {
		t.Fatal(err)
	}

	for _, expr := range []string{`count(/r/*)`, `name(/r/v[2]/preceding-sibling::*[1])`, `count(/r/v[1]/namespace::*)`, `string(/r/v)`, `sum(/r/v/@n)`, `/r/v = false()`, `/r/missing = false()`, `/r/v != 2`, `number('+1')`, nameNumber1e2, `string(1 div 0)`, `string(-0)`, `substring('12345',1.5,2.6)`, `normalize-space(' a  b ')`, `translate('abcab','aba','XY')`, `count(/r/*[lang('en')])`} {
		t.Run(expr, func(t *testing.T) {
			q := query(t, e, expr, transform.XPath10)

			v, err := q.Evaluate(ctx, d, transform.XPathContext{})
			if err != nil {
				t.Fatal(err)
			}

			command := exec.CommandContext(ctx, binary, "--nonet", "--xpath", expr, "-")
			command.Stdin = strings.NewReader(source)

			theirs, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("xmllint: %s: %v", theirs, err)
			}

			got := text(t, v)

			want := strings.TrimRight(string(theirs), "\r\n")
			if expr == nameNumber1e2 && want == "100" {
				if got != valueNaN {
					t.Fatalf("unexpected numeric grammar: local=%q libxml=%q", got, want)
				}

				t.Log("libxml accepts exponent syntax in number(); XPath 1.0 section 4.4 requires NaN")

				return
			}

			if got != want {
				t.Fatalf("local=%q libxml=%q", got, want)
			}
		})
	}
}

func TestCompareLibxslt10(t *testing.T) {
	binary, err := exec.LookPath("xsltproc")
	if err != nil {
		t.Skip("xsltproc is unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	source := `<r><n k="a">2</n><n k="a">3</n><n k="b">bad</n></r>`
	e := engine(t, transform.Config{})

	d, err := e.Parse(ctx, []byte(source))
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	input := filepath.Join(dir, "source.xml")
	if err := os.WriteFile(input, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, body := range []string{
		`<xsl:template match="/"><xsl:value-of select="number(system-property('xsl:version'))"/></xsl:template>`,
		`<xsl:template match="/"><xsl:value-of select="/r/n"/>:<xsl:value-of select="1 div 0"/>:<xsl:value-of select="number('+1')"/></xsl:template>`,
		`<xsl:key name="by-k" match="n" use="@k"/><xsl:template match="/"><xsl:value-of select="count(key('by-k','a'))"/>:<xsl:value-of select="sum(/r/n)"/></xsl:template>`,
		`<xsl:template match="/"><xsl:variable name="v"><a>2</a></xsl:variable><xsl:value-of select="concat(string($v),':',boolean($v),':',$v + 1)"/></xsl:template>`,
		`<xsl:template match="/"><xsl:for-each select="/r/n"><xsl:sort select="@k" order="descending"/><xsl:number/><xsl:text>=</xsl:text><xsl:value-of select="."/><xsl:text>;</xsl:text></xsl:for-each></xsl:template>`,
		`<xsl:template match="/"><xsl:value-of select="format-number(0.125,'0.0%')"/></xsl:template>`,
	} {
		sheetSource := []byte(xslt10(body))

		s, err := e.CompileXSLT(ctx, sheetSource, transform.XSLTOptions{})
		if err != nil {
			t.Fatal(err)
		}

		ours, err := s.Transform(ctx, d, transform.XSLTContext{})
		if err != nil {
			t.Fatal(err)
		}

		path := filepath.Join(dir, "style.xsl")
		if err := os.WriteFile(path, sheetSource, 0o600); err != nil {
			t.Fatal(err)
		}

		theirs, err := exec.CommandContext(ctx, binary, "--nonet", "--novalid", path, input).CombinedOutput()
		if err != nil {
			t.Fatalf("xsltproc: %s: %v", theirs, err)
		}

		if string(ours.Primary) != string(theirs) {
			t.Fatalf("local=%q libxslt=%q", ours.Primary, theirs)
		}
	}
}

func TestCompareSaxonMessageContracts(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range messageContractCases() {
		t.Run(test.name, func(t *testing.T) {
			source := sheet(version30, `<xsl:template name="start">`+test.body+`</xsl:template>`)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
		})
	}
}

func TestCompareSaxonHTMLContentErrors(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range markupSerializationErrorCases() {
		// Compare fn:serialize cases here; XSLT-only version and optional
		// fully-normalized cases retain their separate native coverage.
		if test.options == "" {
			continue
		}
		t.Run(test.name, func(t *testing.T) {
			expression := `serialize(` + test.expression + `,` + test.options + `)`
			// Saxon HE 12.10 drops DEL instead of signaling SERE0014.
			// REC Serialization 3.1 §7.3 still requires the native error.
			if diagnostic, separate := map[string]string{"HTML4 control": "", "HTML4 attribute": `<r a=""></r>`, "HTML4 version parameter": "", "HTML4 separator": "ab"}[test.name]; separate {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.code, diagnostic)
				t.Log("Saxon DEL handling diagnostic; excluded from exact agreements")
				return
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.code)
		})
	}
}

func TestCompareSaxonParameterContracts(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range parameterContractCases() {
		t.Run(test.name, func(t *testing.T) {
			source := parameterContractSheet(version30, test)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			want := test.code30
			if want == "" {
				want = nameTrue
			}
			if oracle, separate := map[string]string{"global implicit mandatory": nameTrue, "named default": "XTTE0600", "node default": "XTTE0600", "empty explicit default": "XTTE0600", "unused invalid default": "XTTE0600"}[test.name]; separate {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, want, oracle)
				t.Log("Saxon parameter diagnostic; excluded from exact agreements")
				return
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, want)
		})
	}
}

func TestCompareSaxonFunctionArguments(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range functionArgumentCases() {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "atomization error" {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, functionArgumentExpression(test), test.want, "XPTY0117")
				t.Log("Saxon map-atomization diagnostic; excluded from exact agreements")
				return
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, functionArgumentExpression(test), test.want)
		})
	}
}

func TestCompareSaxonFunctionReturns(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range functionReturnCases() {
		t.Run(test.name, func(t *testing.T) {
			source := functionReturnSheet(test)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			if test.name == "function atomization result" {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want, "FOTY0013")
				t.Log("Saxon result-atomization diagnostic; native follows XSLT 3.0 section 10.3.3 XTTE0780")
				return
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
		})
	}
}

func TestCompareSaxonContextItemContracts(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range contextItemCases() {
		t.Run(test.name, func(t *testing.T) {
			source := dynamicXPathSheet(test)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			if test.name == "empty type" {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want, "XPST0003")
				t.Log("Saxon empty ItemType diagnostic; native follows XSLT 3.0 section 2.2 XTSE0020")
				return
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
		})
	}
}

func TestCompareSaxonDynamicXPathContexts(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range dynamicXPathCases() {
		t.Run(test.name, func(t *testing.T) {
			source := dynamicXPathSheet(test)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			if test.name == "XSLT lookup absent" || test.name == "private lookup absent" {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want, "false")
				t.Log("Saxon dynamic-function discovery diagnostic; excluded from exact agreements")
				return
			}
			if test.name == "empty parameter map" || test.name == "non map parameter" {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want, "XTTE3170")
				t.Log("Saxon map-type diagnostic; native follows REC section 10.4 XTTE3165")
				return
			}
			if test.name == "changing parameter map" {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want, "XPST0008")
				t.Log("Saxon changing-map diagnostic; native classifies an out-of-scope variable during static analysis")
				return
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
		})
	}
}

func TestCompareSaxonDynamicEvaluationPolicy(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	for _, disabled := range []bool{false, true} {
		e := engine(t, transform.Config{DisableXSLTDynamicEvaluation: disabled})
		options := []string{}
		if disabled {
			config := filepath.Join(t.TempDir(), "saxon.xml")
			if err := os.WriteFile(config, []byte(`<configuration xmlns="http://saxon.sf.net/ns/configuration" edition="HE"><xslt disableXslEvaluate="true"/></configuration>`), 0o600); err != nil {
				t.Fatal(err)
			}
			options = append(options, "-config:"+config)
		}
		for _, test := range dynamicEvaluationPolicyCases() {
			t.Run(test.name+map[bool]string{false: " enabled", true: " disabled"}[disabled], func(t *testing.T) {
				want := test.enabled
				if disabled {
					want = test.disabled
				}
				source := dynamicEvaluationPolicySheet(test.global, test.body)
				expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
				if comparisonErrorCode(want) && strings.HasPrefix(test.name, "requested ") {
					compareSaxonConfiguredExpression(t, t.Context(), e, binary, classpath, expression, want, options, "selected")
					t.Log("Saxon ignores an unsatisfied requested property; F&O 3.1 permits this implementation choice")
					return
				}
				compareSaxonConfiguredExpression(t, t.Context(), e, binary, classpath, expression, want, options)
			})
		}
	}
}

func TestCompareSaxonIntrospection(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range introspectionCases() {
		for _, static := range []bool{false, true} {
			t.Run(test.name+map[bool]string{true: " static", false: " runtime"}[static], func(t *testing.T) {
				source := introspectionSheet(test.scope, test.expression, test.want, static)
				expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
				want := test.want
				if static && !comparisonErrorCode(want) {
					want = "ok"
				}
				if (static && (test.name == "function negative arity" || test.name == "function padded name")) || test.name == "type-available 'bad name'" {
					oracle := "false"
					if static {
						oracle = ""
					}
					compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, want, oracle)
					t.Log("Saxon introspection diagnostic; native follows REC sections 5.1.1, 24.1.1 and 24.1.4")
					return
				}
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, want)
			})
		}
	}
}

func TestCompareSaxonIntrospectionContexts(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range introspectionContextCases() {
		t.Run(test.name, func(t *testing.T) {
			source := sheet(version30, test.global+`<xsl:template name="start">`+test.body+`</xsl:template>`)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
		})
	}
}

func TestCompareSaxonMapInstructions(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range mapInstructionCases() {
		t.Run(test.name, func(t *testing.T) {
			source := mapInstructionSheet(test.body, test.check)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
		})
	}
	for _, test := range mapMergeCombinedExpressions() {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "singleton values" {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, test.expression, nameTrue, "false")
				compareSaxonConfiguredExpression(t, t.Context(), e, binary, classpath, test.expression, nameTrue, []string{"-opt:0"})
				t.Log("Saxon optimized singleton-map merge drops combined values; disabling optimization agrees with the REC and QT3 map-merge-025")
				return
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, test.expression, nameTrue)
		})
	}
}

func TestCompareSaxonConditionalContent(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range conditionalContentCases() {
		t.Run(test.name, func(t *testing.T) {
			source := conditionalContentSheet(test)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			switch test.name {
			case "mixed arrays", "document with empty element", "attribute items individually", "conditional output before filtering", "empty array triggers replacement":
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want, "false")
				t.Log("Saxon conditional-emptiness diagnostic; native follows REC sections 8.4.1 and 8.4.2")
				return
			case "vacuous values survive unused nonempty action":
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want, "FOER0000")
				t.Log("Saxon evaluates a nonempty action for a vacuous string; retained as a diagnostic")
				return
			case "selected action error":
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want, "")
				t.Log("Saxon suppresses on-empty for a vacuous string; retained as a diagnostic")
				return
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
		})
	}
}

func TestCompareSaxonTemplateNodeResults(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range templateNodeResultCases() {
		t.Run(test.name, func(t *testing.T) {
			source := dynamicXPathSheet(test)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
		})
	}
}

func TestCompareSaxonXMLIDValues(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for expression, want := range xmlIDExpressions() {
		t.Run(expression, func(t *testing.T) {
			if expression == xmlIDInvalidValueExpression {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, want, nameFalse)
				t.Log("Saxon retains internal whitespace in this invalid xml:id; native applies the xml:id section 4 normalization before lookup. This diagnostic is separate from exact agreements")
				return
			}

			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, want)
		})
	}
	for _, test := range xmlIDConstructionCases() {
		for _, version := range []string{version20, version30} {
			t.Run(test.name+version, func(t *testing.T) {
				source := sheet(version, test.global+`<xsl:template name="start">`+test.body+`</xsl:template>`)
				expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
			})
		}
	}
}

func TestCompareSaxonCatchObjects(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range catchObjectCases() {
		for _, rollback := range []string{"yes", "no"} {
			for _, form := range []string{"body", "select"} {
				t.Run(test.name+" "+rollback+" "+form, func(t *testing.T) {
					source := catchObjectSheet(test, rollback, form)
					expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
					if test.name == "optional coordinates" {
						compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, nameTrue, "false")
						t.Log("Saxon returns an empty string for an unavailable module URI; native uses the empty sequence under XSLT section 8.3")
						return
					}
					compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, nameTrue)
				})
			}
		}
	}
}

func TestCompareSaxonDefaultNamespaceInheritance(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range namespaceInheritanceCases() {
		t.Run(test.name, func(t *testing.T) {
			source := dynamicXPathSheet(test)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			if strings.Contains(test.name, "local binding stops ancestor inheritance") {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, nameTrue, "false")
				probe := strings.ReplaceAll(expression, "empty(namespace-uri-for-prefix(", "string(namespace-uri-for-prefix(")
				compareSaxonExpression(t, t.Context(), e, binary, classpath, probe, "", "urn:ancestor")
				t.Log("Saxon passes an ancestor binding through an intermediate element's own binding; native stops inheritance under XSLT section 5.7.1")
				return
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, nameTrue)
		})
	}
}

func TestCompareSaxonPatternSyntaxContracts(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range patternSyntaxCases() {
		t.Run(test.name, func(t *testing.T) {
			source := dynamicXPathSheet(test.dynamicXPathCase)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
		})
	}
}

func TestCompareSaxonPatternVersions(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range versionedPatternCases() {
		t.Run(test.pattern, func(t *testing.T) {
			// fn:transform uses a 3.0 processor even for a 2.0 declaration.
			for _, version := range []string{version20, version30} {
				source := versionedPatternSheet(version, test.pattern)
				expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want30)
			}
		})
	}
}

func TestCompareSaxonUnionPatternPriorities(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range unionPatternCases() {
		t.Run(test.name, func(t *testing.T) {
			source := dynamicXPathSheet(test)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			if test.name == "parenthesized predicate operand retains priority" {
				compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want, "specific")
				compareSaxonConfiguredExpression(t, t.Context(), e, binary, classpath, expression, test.want, []string{"-opt:0"}, "specific")
				t.Log("Saxon assigns a different default priority to a parenthesized union followed by [true()], including with optimization disabled; native uses XSLT section 6.5's 0.5 fallback")
				return
			}
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
		})
	}
}

func TestCompareSaxonDefaultPatternPriorities(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	e := engine(t, transform.Config{})
	for _, test := range defaultPriorityCases() {
		t.Run(test.name, func(t *testing.T) {
			source := dynamicXPathSheet(test)
			expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
			compareSaxonExpression(t, t.Context(), e, binary, classpath, expression, test.want)
		})
	}
}
