//go:build interop

package transform_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

				oracle = "try { " + oracle + " } catch * { local-name-from-QName($err:code) }"
			} else if err != nil || text(t, value) != want {
				t.Fatal(value, err, want)
			}

			output, err := saxonQuery(t, ctx, binary, classpath, oracle)

			if err != nil && comparisonErrorCode(want) {
				if code := saxonDiagnosticCode(err); code != "" {
					output, err = []byte(code), nil
				}
			}

			if err != nil || string(output) != want {
				t.Fatalf("Saxon: %q, %v; want %q", output, err, want)
			}
		})
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

func saxonQuery(t *testing.T, ctx context.Context, binary, classpath, source string) ([]byte, error) {
	t.Helper()
	// A query file avoids the JVM command-line charset, which can replace
	// Unicode characters under the Docker image's C locale.
	queryPath := filepath.Join(t.TempDir(), "query.xq")
	if err := os.WriteFile(queryPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	return exec.CommandContext(ctx, binary, "-cp", classpath, "net.sf.saxon.Query", "-q:"+queryPath, "!method=text").Output()
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
		if len(fields) > 0 && comparisonErrorCode(fields[0]) {
			return fields[0]
		}
	}

	return ""
}

func comparisonErrorCode(value string) bool {
	if len(value) != 8 {
		return false
	}

	for i, c := range value {
		if i < 4 {
			if c < 'A' || c > 'Z' {
				return false
			}
		} else if c < '0' || c > '9' {
			return false
		}
	}

	return true
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
