package transform_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

const (
	errCodeSENR0001       = "SENR0001"
	serializationXML      = "xml"
	serializationHTML     = "html"
	serializationUTF8     = "UTF-8"
	serializationJSON     = "json"
	serializationText     = "text"
	serializationNull     = "null"
	serializationNodeXML  = `<p>text</p>`
	serializationControls = "controls"
	errCodeSERE0020       = "SERE0020"
	errCodeSERE0021       = "SERE0021"
	errCodeSERE0022       = "SERE0022"
	errCodeSERE0023       = "SERE0023"
	errCodeSEPM0016       = "SEPM0016"
	errCodeSEPM0017       = "SEPM0017"
	errCodeSEPM0018       = "SEPM0018"
	errCodeSEPM0019       = "SEPM0019"
)

type markupSerializationCase struct{ name, declarations, body, want, check string }

func markupSerializationCases() []markupSerializationCase {
	const before = `<xsl:comment>lead</xsl:comment><xsl:processing-instruction name="p">v</xsl:processing-instruction>`
	const xmlOutput = `<xsl:output method="xml" indent="no" omit-xml-declaration="yes" doctype-system="d.dtd"/>`
	const xhtml5 = `<xsl:output method="xhtml" html-version="5" indent="no" omit-xml-declaration="yes" include-content-type="no"/>`
	const maps = `<xsl:character-map name="m"><xsl:output-character character="a" string="A"/><xsl:output-character character="&#13;" string="BAD"/></xsl:character-map>`
	tests := []markupSerializationCase{
		{"XML default omits prefix undeclarations", `<xsl:output method="xml" indent="no" omit-xml-declaration="yes"/>`, `<r xmlns:p="urn:p" xsl:inherit-namespaces="no"><xsl:element name="c"/></r>`, `<r xmlns:p="urn:p"><c/></r>`, ""},
		{"XML 1.1 keeps requested prefix undeclarations", `<xsl:output method="xml" version="1.1" undeclare-prefixes="yes" indent="no"/>`, `<r xmlns:p="urn:p" xsl:inherit-namespaces="no"><xsl:element name="c"/></r>`, `<?xml version="1.1" encoding="UTF-8"?><r xmlns:p="urn:p"><c xmlns:p=""/></r>`, ""},
		{"XHTML5 normalizes all element prefixes", xhtml5, `<h:html xmlns:h="http://www.w3.org/1999/xhtml"><h:body><s:svg xmlns:s="http://www.w3.org/2000/svg"><s:title>x</s:title></s:svg><m:math xmlns:m="http://www.w3.org/1998/Math/MathML"><m:mi>y</m:mi></m:math></h:body></h:html>`, `<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml"><body><svg xmlns="http://www.w3.org/2000/svg"><title>x</title></svg><math xmlns="http://www.w3.org/1998/Math/MathML"><mi>y</mi></math></body></html>`, ""},
		{"XHTML5 removes unused bindings on unrelated elements", xhtml5, `<r xmlns:h="http://www.w3.org/1999/xhtml" xmlns:s="http://www.w3.org/2000/svg" xmlns:m="http://www.w3.org/1998/Math/MathML"><c>v</c></r>`, `<r><c>v</c></r>`, ""},
		{"XHTML5 retains ancestor attribute prefix", xhtml5, `<h:html xmlns:h="http://www.w3.org/1999/xhtml" h:a="v"><h:body><h:p>x</h:p></h:body></h:html>`, `<!DOCTYPE html><html xmlns:h="http://www.w3.org/1999/xhtml" xmlns="http://www.w3.org/1999/xhtml" h:a="v"><body><p>x</p></body></html>`, `matches($s,'^<!DOCTYPE html>\s*<html (xmlns:h="http://www\.w3\.org/1999/xhtml" xmlns="http://www\.w3\.org/1999/xhtml"|xmlns="http://www\.w3\.org/1999/xhtml" xmlns:h="http://www\.w3\.org/1999/xhtml") h:a="v"><body><p>x</p></body></html>$')`},
		{"XHTML5 retains local attribute prefix", xhtml5, `<h:html xmlns:h="http://www.w3.org/1999/xhtml"><h:body><h:p h:a="v">x</h:p><h:p>y</h:p></h:body></h:html>`, `<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml"><body><p xmlns:h="http://www.w3.org/1999/xhtml" h:a="v">x</p><p>y</p></body></html>`, ""},
		{"XML doctype", xmlOutput, before + `<r><c/></r>`, `<!--lead--><?p v?><!DOCTYPE r SYSTEM "d.dtd"><r><c/></r>`, ""},
		{"HTML fragment doctype once", `<xsl:output method="html" indent="no" doctype-system="d.dtd"/>`, before + `<r/><s/>`, "<!--lead--><?p v><!DOCTYPE html SYSTEM \"d.dtd\">\n<r></r><s></s>", `matches($s,'^<!--lead--><\?p v><!DOCTYPE (html|HTML)\s+SYSTEM\s+"d.dtd">\s*<r></r><s></s>$')`},
		{"XML rootless", xmlOutput, before, `<!--lead--><?p v?>`, ""},
		{"XML qualified doctype", xmlOutput, before + `<p:r xmlns:p="urn:r"/>`, `<!--lead--><?p v?><!DOCTYPE p:r SYSTEM "d.dtd"><p:r xmlns:p="urn:r"/>`, ""},
		{"XML fallback doctype", xmlOutput, before + `<r><xsl:text disable-output-escaping="yes">&lt;c/&gt;</xsl:text></r>`, `<!--lead--><?p v?><!DOCTYPE r SYSTEM "d.dtd"><r><c/></r>`, ""},
		{"XHTML doctype", `<xsl:output method="xhtml" indent="no" omit-xml-declaration="yes" doctype-system="d.dtd"/>`, before + `<r/>`, `<!--lead--><?p v?><!DOCTYPE r SYSTEM "d.dtd"><r></r>`, ""},
		{"HTML doctype", `<xsl:output method="html" indent="no" doctype-system="d.dtd"/>`, before + `<r/>`, "<!--lead--><?p v><!DOCTYPE html SYSTEM \"d.dtd\">\n<r></r>", `matches($s,'^<!--lead--><\?p v><!DOCTYPE (html|HTML)\s+SYSTEM\s+"d.dtd">\s*<r></r>$')`},
		{"HTML empty explicit doctype", `<xsl:output method="html" indent="no" doctype-system="d.dtd"/>`, "", "<!DOCTYPE html SYSTEM \"d.dtd\">\n", `matches($s,'^<!DOCTYPE (html|HTML)\s+SYSTEM\s+"d.dtd">\s*$')`},
		{"HTML rootless explicit doctype", `<xsl:output method="html" indent="no" doctype-system="d.dtd"/>`, before, "<!--lead--><?p v><!DOCTYPE html SYSTEM \"d.dtd\">\n", `matches($s,'^(<!DOCTYPE (html|HTML)\s+SYSTEM\s+"d.dtd">\s*)?<!--lead--><\?p v>(<!DOCTYPE (html|HTML)\s+SYSTEM\s+"d.dtd">\s*)?$') and contains($s,'<!DOCTYPE') and not(contains(substring-after($s,'<!DOCTYPE'),'<!DOCTYPE'))`},
		{"HTML rootless fallback doctype", `<xsl:output method="html" indent="no" doctype-system="d.dtd"/>`, before + `<xsl:text disable-output-escaping="yes">text</xsl:text>`, "<!--lead--><?p v>text<!DOCTYPE html SYSTEM \"d.dtd\">\n", `matches($s,'^(<!DOCTYPE (html|HTML)\s+SYSTEM\s+"d.dtd">\s*)?<!--lead--><\?p v>text(<!DOCTYPE (html|HTML)\s+SYSTEM\s+"d.dtd">\s*)?$') and contains($s,'<!DOCTYPE') and not(contains(substring-after($s,'<!DOCTYPE'),'<!DOCTYPE'))`},
		{"HTML fallback doctype", `<xsl:output method="html" indent="no" doctype-system="d.dtd"/>`, before + `<r><xsl:text disable-output-escaping="yes">&lt;c&gt;&lt;/c&gt;</xsl:text></r>`, "<!--lead--><?p v><!DOCTYPE html SYSTEM \"d.dtd\">\n<r><c></c></r>", `matches($s,'^<!--lead--><\?p v><!DOCTYPE (html|HTML)\s+SYSTEM\s+"d.dtd">\s*<r><c></c></r>$')`},
		{"HTML5 automatic doctype", `<xsl:output method="html" html-version="5" indent="no" include-content-type="no"/>`, before + `<html/>`, `<!--lead--><?p v><!DOCTYPE html><html></html>`, `matches($s,'^<!--lead--><\?p v><!DOCTYPE (html|HTML)>\s*<html></html>$')`},
		{"HTML5 non HTML root", `<xsl:output method="html" html-version="5" indent="no"/>`, before + `<r/>`, `<!--lead--><?p v><r></r>`, ""},
		{"HTML5 leading text", `<xsl:output method="html" html-version="5" indent="no" include-content-type="no"/>`, `text<html/>`, `text<html></html>`, ""},
		{"XHTML5 automatic doctype", `<xsl:output method="xhtml" html-version="5" indent="no" include-content-type="no"/>`, before + `<html xmlns="http://www.w3.org/1999/xhtml"/>`, `<?xml version="1.0" encoding="UTF-8"?><!--lead--><?p v?><!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml"></html>`, ""},
		{"XHTML5 leading text", `<xsl:output method="xhtml" html-version="5" indent="no" include-content-type="no"/>`, `text<html xmlns="http://www.w3.org/1999/xhtml"/>`, `<?xml version="1.0" encoding="UTF-8"?>text<html xmlns="http://www.w3.org/1999/xhtml"></html>`, ""},
		{"CDATA maps excluded", `<xsl:output method="xml" omit-xml-declaration="yes" cdata-section-elements="b" use-character-maps="m"/>` + maps, `<r a="aaa"><a>aaa</a><b>aaa&#13;]]&gt;</b></r>`, `<r a="AAA"><a>AAA</a><b><![CDATA[aaa]]>&#xD;<![CDATA[]]]]><![CDATA[>]]></b></r>`, `contains($s,'<a>AAA</a>') and contains($s,'<![CDATA[aaa') and not(contains($s,'BAD'))`},
		{"CDATA namespace union", `<xsl:output method="xml" indent="no" omit-xml-declaration="yes" xmlns="urn:r" cdata-section-elements="a"/><xsl:output xmlns="urn:r" cdata-section-elements="b"/>`, `<r xmlns="urn:r"><a>x&amp;y</a><b>z&lt;t</b><a xmlns="">x&amp;y</a></r>`, `<r xmlns="urn:r"><a><![CDATA[x&y]]></a><b><![CDATA[z<t]]></b><a xmlns="">x&amp;y</a></r>`, ""},
		{"CDATA no namespace stays exact", `<xsl:output method="xml" indent="no" omit-xml-declaration="yes" cdata-section-elements="a"/>`, `<r><a>x&amp;y</a><a xmlns="urn:r">x&amp;y</a></r>`, `<r><a><![CDATA[x&y]]></a><a xmlns="urn:r">x&amp;y</a></r>`, ""},
		{"CDATA fallback namespace stays exact", `<xsl:output method="xml" indent="no" omit-xml-declaration="yes" cdata-section-elements="a"/>`, `<r><xsl:text disable-output-escaping="yes">x</xsl:text><a xmlns="urn:r">x&amp;y</a></r>`, `<r>x<a xmlns="urn:r">x&amp;y</a></r>`, ""},
	}
	return slices.Concat(tests, characterExpansionCases())
}

func characterExpansionCases() []markupSerializationCase {
	const mapC = `<xsl:character-map name="m"><xsl:output-character character="c" string="#ç#"/></xsl:character-map>`
	const nfd = `<xsl:output method="xml" indent="no" omit-xml-declaration="yes" normalization-form="NFD" use-character-maps="m"/>`
	const nfc = `<xsl:output method="xml" indent="no" omit-xml-declaration="yes" normalization-form="NFC" use-character-maps="m"/>`
	return []markupSerializationCase{
		{"NFD character map immunity", nfd + mapC, `<r a="abcçde">abcçde</r>`, "<r a=\"ab#ç#c\u0327de\">ab#ç#c\u0327de</r>", ""},
		{"NFC map matches original", nfc + `<xsl:character-map name="m"><xsl:output-character character="é" string="BAD"/></xsl:character-map>`, "<r a=\"e\u0301\">e\u0301</r>", `<r a="é">é</r>`, ""},
		{"NFC map boundaries", nfc + `<xsl:character-map name="m"><xsl:output-character character="@" string="e"/></xsl:character-map>`, "<r a=\"@\u0301\">@\u0301</r>", "<r a=\"e\u0301\">e\u0301</r>", ""},
		{"Namespace character expansion excluded", nfd + `<xsl:character-map name="m"><xsl:output-character character="u" string="U"/></xsl:character-map>`, `<r xmlns="urn:é" u="u">u</r>`, `<r xmlns="urn:é" u="U">U</r>`, ""},
		{"Names and namespaces normalization excluded", `<xsl:output method="xml" indent="no" omit-xml-declaration="yes" normalization-form="NFD"/>`, `<é xmlns="urn:é" é="é">é</é>`, "<é xmlns=\"urn:é\" é=\"e\u0301\">e\u0301</é>", ""},
		{"NFD fallback immunity", nfd + mapC, `<r a="abcçde"><xsl:text disable-output-escaping="yes">x</xsl:text>abcçde</r>`, "<r a=\"ab#ç#c\u0327de\">xab#ç#c\u0327de</r>", ""},
		{"NFD HTML map immunity", `<xsl:output method="html" indent="no" normalization-form="NFD" use-character-maps="m"/>` + mapC, `<r a="abcçde">abcçde</r>`, "<r a=\"ab#ç#c\u0327de\">ab#ç#c\u0327de</r>", ""},
		{"NFD text map immunity", `<xsl:output method="text" normalization-form="NFD" use-character-maps="m"/>` + mapC, `<r>abcçde</r>`, "ab#ç#c\u0327de", ""},
	}
}

// DTD whitespace and the HTML name's case may vary between serializers.
// Native API tests above retain an exact-byte expectation for every case.
func markupSerializationCheck(test markupSerializationCase) string {
	if test.check != "" {
		return test.check
	}
	before, rest, found := strings.Cut(test.want, "<!DOCTYPE ")
	if found {
		declaration, after, _ := strings.Cut(rest, ">")
		pattern := "^" + regexp.QuoteMeta(before) + `\s*<!DOCTYPE ` + strings.ReplaceAll(regexp.QuoteMeta(declaration), " ", `\s+`) + `>\s*` + regexp.QuoteMeta(after) + "$"
		return `matches($s,'` + strings.ReplaceAll(pattern, "'", "''") + `')`
	}
	return `$s eq '` + strings.ReplaceAll(test.want, "'", "''") + `'`
}

func markupSerializationSheet(test markupSerializationCase, secondary bool) string {
	body := test.body
	if secondary {
		body += `<xsl:result-document href="secondary">` + test.body + `</xsl:result-document>`
	}
	return `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">` + test.declarations + `<xsl:template name="start">` + body + `</xsl:template></xsl:stylesheet>`
}

func TestMarkupSerializationContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range markupSerializationCases() {
		t.Run(test.name, func(t *testing.T) {
			compiled := stylesheet(t, e, markupSerializationSheet(test, true))
			for _, mode := range []transform.ResultMode{transform.ResultRaw, transform.ResultDefault, transform.ResultDocument} {
				result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: mode})
				if err != nil {
					t.Fatal(err)
				}
				output, err := result.Serialize(t.Context())
				if err != nil {
					t.Fatalf("mode %d: %v", mode, err)
				}
				if string(output.Primary) != test.want || string(output.Secondary["secondary"]) != test.want {
					t.Fatalf("mode %d: %q / %v, %v; want %q", mode, output.Primary, output.Secondary, err, test.want)
				}
				var writer, secondary bytes.Buffer
				if _, err := result.WriterTo(t.Context()).WriteTo(&writer); err != nil || writer.String() != test.want {
					t.Fatal(writer.String(), err)
				}
				if _, err := result.WriteSecondary(t.Context(), "secondary", &secondary); err != nil || secondary.String() != test.want {
					t.Fatal(secondary.String(), err)
				}
			}
		})
	}
}

func xmlSerializationExpressions() []string {
	return []string{
		`let $s := serialize(parse-xml('<!--lead--><?p v?><r><c/></r>'),map{'doctype-system':'d.dtd','omit-xml-declaration':true(),'indent':false()}) return matches($s,'^<!--lead--><\?p v\?>\s*<!DOCTYPE r\s+SYSTEM\s+"d.dtd">\s*<r><c/></r>$')`,
		`let $s := serialize(parse-xml('<!--lead--><p:r xmlns:p="urn:r"/>'),map{'doctype-system':'d.dtd','omit-xml-declaration':true(),'indent':false()}) return matches($s,'^<!--lead-->\s*<!DOCTYPE p:r\s+SYSTEM\s+"d.dtd">\s*<p:r xmlns:p="urn:r"/>$')`,
		`serialize(parse-xml-fragment('<!--lead--><?p v?>'),map{'doctype-system':'d.dtd','omit-xml-declaration':true()}) eq '<!--lead--><?p v?>'`,
		`let $s := serialize(parse-xml('<r a="aaa"><a>aaa</a><b>aaa</b></r>'),map{'cdata-section-elements':QName('','b'),'use-character-maps':map{'a':'A'},'omit-xml-declaration':true(),'indent':false()}) return $s eq '<r a="AAA"><a>AAA</a><b><![CDATA[aaa]]></b></r>'`,
		`serialize(parse-xml('<r a="abcçde">abcçde</r>'),map{'normalization-form':'NFD','use-character-maps':map{'c':'#ç#'},'omit-xml-declaration':true(),'indent':false()}) eq concat('<r a="ab#ç#c',codepoints-to-string(807),'de">ab#ç#c',codepoints-to-string(807),'de</r>')`,
		`serialize(parse-xml('<r xmlns="urn:é" u="u">u</r>'),map{'normalization-form':'NFD','use-character-maps':map{'u':'U'},'omit-xml-declaration':true(),'indent':false()}) eq '<r xmlns="urn:é" u="U">U</r>'`,
	}
}

func defaultMarkupMethodExpressions() []string {
	expressions := make([]string, 0, 4)
	for _, test := range []struct {
		version, name   string
		explicit, xhtml bool
	}{
		{"1.0", "html", false, false},
		{"1.0", "html", true, true},
		{"3.0", "html", false, true},
		{"3.0", "HTML", false, false},
	} {
		body := `<` + test.name + ` xmlns="http://www.w3.org/1999/xhtml"><a href="file:///café">link</a></` + test.name + `>`
		if test.explicit {
			body = `<xsl:result-document>` + body + `</xsl:result-document>`
		}
		source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="` + test.version + `"><xsl:template name="start">` + body + `</xsl:template></xsl:stylesheet>`
		want := `href="file:///café"`
		if test.xhtml {
			want = `href="file:///caf%C3%A9"`
		}
		expressions = append(expressions, `contains(transform(map{'stylesheet-text':'`+source+`','xslt-version':3,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output,'`+want+`')`)
	}
	return expressions
}

func TestSerializeMarkupContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, expression := range append(xmlSerializationExpressions(), defaultMarkupMethodExpressions()...) {
		if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != nameTrue {
			t.Fatal(expression, got)
		}
	}
}

func TestResultOutputEncoding(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, explicit := range []bool{false, true} {
		primary := `text`
		if explicit {
			primary = `<xsl:result-document encoding="{$encoding}">text</xsl:result-document>`
		}
		source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:param name="encoding"/><xsl:output method="text"/><xsl:template name="start">` + primary + `<xsl:result-document href="secondary" encoding="{$encoding}">text</xsl:result-document></xsl:template></xsl:stylesheet>`
		compiled := stylesheet(t, e, source)
		for _, mode := range []transform.ResultMode{transform.ResultRaw, transform.ResultDefault, transform.ResultDocument} {
			results := make([]*transform.Result, 0, 2)
			for _, encoding := range []string{"ISO-8859-1", "UTF-16LE"} {
				result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: mode, Parameters: transform.Bindings{{Local: "encoding"}: transform.Values(transform.String(encoding))}})
				if err != nil {
					t.Fatal(err)
				}
				results = append(results, result)
			}
			for i, encoding := range []string{"ISO-8859-1", "UTF-16LE"} {
				result := results[i]
				primaryEncoding := "UTF-8"
				if explicit {
					primaryEncoding = encoding
				}
				for uri, want := range map[string]string{"": primaryEncoding, "secondary": encoding} {
					got, err := result.OutputEncoding(uri)
					if err != nil || got != want {
						t.Fatal(explicit, mode, uri, got, err, want)
					}
				}
				if _, err := result.OutputEncoding("missing"); !errors.Is(err, transform.ErrInput) {
					t.Fatal(err)
				}
			}
		}
	}
	for _, result := range []*transform.Result{nil, new(transform.Result)} {
		if _, err := result.OutputEncoding(""); !errors.Is(err, transform.ErrInput) {
			t.Fatal(err)
		}
	}
	// The adaptive method ignores its encoding parameter and writes UTF-8.
	adaptive := markupSerializationCase{declarations: `<xsl:output method="adaptive" encoding="US-ASCII"/>`, body: `<r>ª</r>`}
	result, err := stylesheet(t, e, markupSerializationSheet(adaptive, false)).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil {
		t.Fatal(err)
	}
	if encoding, err := result.OutputEncoding(""); err != nil || encoding != "UTF-8" {
		t.Fatal(encoding, err)
	}
}

func TestOutputNameListsAcrossImports(t *testing.T) {
	const header = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">`
	modules := map[string]string{
		"urn:low":    header + `<xsl:output cdata-section-elements="a" suppress-indentation="b"/></xsl:stylesheet>`,
		"urn:middle": header + `<xsl:import href="urn:low"/><xsl:output cdata-section-elements="c" suppress-indentation="d"/></xsl:stylesheet>`,
	}
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		source, ok := modules[uri]
		if !ok {
			return nil, transform.ErrResource
		}
		return io.NopCloser(strings.NewReader(source)), ctx.Err()
	})})
	compiled := stylesheet(t, e, header+`<xsl:import href="urn:middle"/><xsl:output method="xml" indent="yes" omit-xml-declaration="yes" cdata-section-elements="e" suppress-indentation="f"/><xsl:template name="start"><r><a>x&amp;y</a><c>x&amp;y</c><e>x&amp;y</e><b><z/></b><d><z/></d><f><z/></f></r><xsl:result-document href="secondary" xmlns="urn:r" cdata-section-elements="b"><r><b>x&amp;y</b><b xmlns="">x&amp;y</b></r></xsl:result-document></xsl:template></xsl:stylesheet>`)
	result, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil {
		t.Fatal(err)
	}
	primary := string(result.Primary)
	for _, fragment := range []string{"\n", `<a><![CDATA[x&y]]></a>`, `<c><![CDATA[x&y]]></c>`, `<e><![CDATA[x&y]]></e>`, `<b><z/></b>`, `<d><z/></d>`, `<f><z/></f>`} {
		if !strings.Contains(primary, fragment) {
			t.Fatal("imported output name list lost", fragment, primary)
		}
	}
	secondary := string(result.Secondary["secondary"])
	if !strings.Contains(secondary, `<b><![CDATA[x&y]]></b>`) || !strings.Contains(secondary, `<b xmlns="">x&amp;y</b>`) {
		t.Fatal("dynamic CDATA namespace", secondary)
	}
}

type markupCutWriter struct {
	bytes.Buffer
	remaining int
}

func (w *markupCutWriter) WriteString(data string) (int, error) {
	return w.Write([]byte(data))
}

func (w *markupCutWriter) Write(data []byte) (int, error) {
	n := min(w.remaining, len(data))
	w.remaining -= n
	_, _ = w.Buffer.Write(data[:n])
	if n != len(data) {
		return n, io.ErrClosedPipe
	}
	return n, nil
}

func TestMarkupSerializationDestinationErrors(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range markupSerializationCases() {
		t.Run(test.name, func(t *testing.T) {
			result, err := stylesheet(t, e, markupSerializationSheet(test, true)).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if err != nil {
				t.Fatal(err)
			}
			for _, limit := range []int{1, len(test.want) / 2, len(test.want) - 1} {
				for _, secondary := range []bool{false, true} {
					writer := &markupCutWriter{remaining: limit}
					var n int64
					if secondary {
						n, err = result.WriteSecondary(t.Context(), "secondary", writer)
					} else {
						n, err = result.WriterTo(t.Context()).WriteTo(writer)
					}
					if !errors.Is(err, io.ErrClosedPipe) || n != int64(limit) || writer.String() != test.want[:limit] {
						t.Fatalf("limit %d, secondary %v: %d %q %v", limit, secondary, n, writer.String(), err)
					}
				}
			}
			output, err := result.Serialize(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if string(output.Primary) != test.want || string(output.Secondary["secondary"]) != test.want {
				t.Fatal("failed write changed the result", output, err)
			}
		})
	}
}

// TestStreamingSequenceAdjacency checks that atomic values are joined before
// document children are expanded.
// See https://www.w3.org/TR/xslt-xquery-serialization-31/#serdm.
func TestStreamingSequenceAdjacency(t *testing.T) {
	e := engine(t, transform.Config{})

	cases := []struct{ body, want string }{
		{`<xsl:sequence select="('a','','b')"/><xsl:sequence select="''"/><xsl:sequence select="'c'"/>`, "a  b  c"},
		{`<xsl:sequence select="'a'"/><xsl:document/><xsl:sequence select="'b'"/>`, "ab"},
		{`<xsl:sequence select="'a'"/><xsl:text/><xsl:sequence select="'b'"/>`, "ab"},
		{`<xsl:variable name="v"><a/><xsl:sequence select="('one','two')"/><b/></xsl:variable><xsl:value-of select="$v"/>`, "one two"},
	}
	for _, tc := range cases {
		s := stylesheet(t, e, sheet(version30, `<xsl:template name="start">`+tc.body+`</xsl:template>`))

		out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil {
			t.Fatal(err)
		}

		if got := string(out.Primary); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.body, got, tc.want)
		}
	}
}

func BenchmarkSerializationStreaming(b *testing.B) {
	cases := []struct{ method, encoding string }{
		{serializationXML, serializationUTF8},
		{serializationHTML, serializationUTF8},
		{serializationJSON, serializationUTF8},
		{serializationText, serializationUTF8},
		{serializationXML, "UTF-16"},
		{serializationHTML, xmlLatinEncoding},
	}
	for _, tc := range cases {
		for _, content := range []string{"plain", "escaped", serializationControls} {
			if content == serializationControls && tc.method != serializationJSON {
				continue
			}

			for _, size := range []int{16 << 10, 1 << 20} {
				b.Run(fmt.Sprintf("%s/%s/%s/%d", tc.method, serializationEncoding(tc.encoding), content, size), func(b *testing.B) {
					payload := serializationPayload(tc.method, content, size)
					result := serializationFixture(b, tc.method, tc.encoding, payload)
					benchmarkSerializationResult(b, result, size)
				})
			}
		}
	}
}

// BenchmarkNormalizationStreaming measures requested NFC over resident results.
// Compilation and result construction are excluded from serialization timings.
func BenchmarkNormalizationStreaming(b *testing.B) {
	for _, method := range []string{serializationXML, serializationHTML, serializationText} {
		for _, size := range []int{16 << 10, 1 << 20} {
			b.Run(fmt.Sprintf("%s/%d", method, size), func(b *testing.B) {
				payload := strings.Repeat("e\u0301", size/3)
				e := engine(b, transform.Config{Limits: transform.Limits{MaxOutputBytes: 16 << 20}})
				compiled := stylesheet(b, e, sheetStart+version30+`"><xsl:param name="normalizationData"/><xsl:output method="`+method+`" normalization-form="NFC" omit-xml-declaration="yes" include-content-type="no"/><xsl:template name="start"><r><xsl:value-of select="$normalizationData"/></r></xsl:template></xsl:stylesheet>`)

				result, err := compiled.CallTemplate(b.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "normalizationData"}: transform.Values(transform.String(payload))}})
				if err != nil {
					b.Fatal(err)
				}

				writer := result.WriterTo(b.Context())
				b.ReportAllocs()
				b.SetBytes(int64(len(payload)))

				for b.Loop() {
					if _, err := writer.WriteTo(io.Discard); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func serializationEncoding(name string) string {
	if name == "" {
		return serializationUTF8
	}

	return name
}

func serializationPayload(method, content string, size int) string {
	character := "x"
	if content == serializationControls {
		character = "\x01"
	}

	if content == "escaped" {
		character = "&"
		if method == serializationJSON {
			character = "\""
		}
	}

	return strings.Repeat(character, size)
}

func benchmarkSerializationResult(b *testing.B, result *transform.Result, size int) {
	b.Helper()
	b.Run("Writer", func(b *testing.B) {
		writer := result.WriterTo(b.Context())
		b.ReportAllocs()
		b.SetBytes(int64(size))

		for b.Loop() {
			if _, err := writer.WriteTo(io.Discard); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Buffered", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))

		for b.Loop() {
			if _, err := result.Serialize(b.Context()); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func serializationFixture(b *testing.B, method, encoding, payload string) *transform.Result {
	b.Helper()
	e := engine(b, transform.Config{Limits: transform.Limits{MaxOutputBytes: 16 << 20}})

	body := `<r><xsl:value-of select="$data"/></r>`
	if method == serializationJSON {
		body = `<xsl:sequence select="map{'value':$data}"/>`
	}

	compiled := stylesheet(b, e, sheetStart+version30+`"><xsl:param name="data"/><xsl:output method="`+method+`" encoding="`+serializationEncoding(encoding)+`" omit-xml-declaration="yes"/><xsl:template name="start">`+body+`</xsl:template></xsl:stylesheet>`)

	result, err := compiled.CallTemplate(b.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "data"}: transform.Values(transform.String(payload))}})
	if err != nil {
		b.Fatal(err)
	}

	return result
}

func TestSerializationExactNormalization(t *testing.T) {
	e := engine(t, transform.Config{})
	input := "a" + strings.Repeat("\u0315", 4100) + "\u0300\u034f\u0301"
	want := "à" + strings.Repeat("\u0315", 4100) + "\u034f\u0301"

	for _, method := range []string{serializationXML, serializationHTML, serializationText, serializationJSON, "adaptive"} {
		t.Run(method, func(t *testing.T) {
			body := `<r a="{$normalizationData}"><xsl:value-of select="$normalizationData"/></r>`
			if method == "json" || method == "adaptive" {
				body = `<xsl:sequence select="$normalizationData"/>`
			}

			style := stylesheet(t, e, sheetStart+version30+`"><xsl:param name="normalizationData"/><xsl:output method="`+method+`" normalization-form="NFC" omit-xml-declaration="yes" include-content-type="no"/><xsl:template name="start">`+body+`</xsl:template></xsl:stylesheet>`)

			result, err := style.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "normalizationData"}: transform.Values(transform.String(input))}})
			if err != nil {
				t.Fatal(err)
			}

			output, err := result.Serialize(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Contains(output.Primary, []byte(want)) || bytes.Count(output.Primary, []byte("\u034f")) != bytes.Count(output.Primary, []byte(want)) {
				t.Fatal("wrong normalization or CGJ insertion")
			}

			var streamed bytes.Buffer
			if _, err := result.WriterTo(t.Context()).WriteTo(&streamed); err != nil || !bytes.Equal(streamed.Bytes(), output.Primary) {
				t.Fatal("writer mismatch", err)
			}
		})
	}
}

// TestJSONSerializationRules exercises the same SER31 §9 values through the
// XPath function and both buffered and streaming XSLT result delivery.
func TestJSONSerializationRules(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct{ expression, want, code string }{
		{`(1, 2)`, "", errCodeSERE0023},
		{`[(1, 2)]`, "", errCodeSERE0023},
		{`map{'x':(1, 2)}`, "", errCodeSERE0023},
		{`[map{'x':[(1, 2)]}]`, "", errCodeSERE0023},
		{`xs:double('NaN')`, "", errCodeSERE0020},
		{`xs:double('INF')`, "", errCodeSERE0020},
		{`map{'x':[xs:float('-INF')]}`, "", errCodeSERE0020},
		{`string#1`, "", errCodeSERE0021},
		{`[map{'x':string#1}]`, "", errCodeSERE0021},
		{`map{1:'a', '1':'b'}`, "", errCodeSERE0022},
		{`[map{1:'a', '1':'b'}]`, "", errCodeSERE0022},
		{`()`, serializationNull, ""},
		{`[]`, "[]", ""},
		{emptyMapExpression, "{}", ""},
		{`[(), [1, 2], map{'x':()}]`, `[null,[1,2],{"x":null}]`, ""},
		{`[true(), false(), 1.25, 'x']`, `[true,false,1.25,"x"]`, ""},
		{`array{1, 2, (3, 4)}`, `[1,2,3,4]`, ""},
		{`parse-xml('<r/>')`, `"<r\/>"`, ""},
		{`parse-xml('<r><!--c--></r>')/r/comment()`, `"<!--c-->"`, ""},
		{`parse-xml('<r><?p x?></r>')/r/processing-instruction()`, `"<?p x?>"`, ""},
		{`parse-xml('<r>&lt;&amp;</r>')/r/text()`, `"&lt;&amp;"`, ""},
		{`parse-xml('<r a="x"/>')/r/@a`, "", errCodeSENR0001},
		{`parse-xml('<r/>')/r/namespace::*[name()='xml']`, "", errCodeSENR0001},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			expression := tc.expression
			value, err := query(t, e, `serialize(`+expression+`, map{'method':'json'})`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
			assertSerializationSequence(t, "fn:serialize", value, err, tc.want, tc.code)

			source := sheetStart + version30 + `"><xsl:output method="json"/><xsl:template name="start"><xsl:sequence select="` + strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;").Replace(expression) + `"/></xsl:template></xsl:stylesheet>`
			compiled := stylesheet(t, e, source)

			result, err := compiled.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
			if err != nil {
				assertSerializationResult(t, "CallTemplate", "", err, tc.want, tc.code)
			} else {
				output, err := result.Serialize(t.Context())
				assertSerializationOutput(t, "Serialize", output, err, tc.want, tc.code)

				var writer strings.Builder

				_, err = result.WriterTo(t.Context()).WriteTo(&writer)
				assertSerializationResult(t, "WriterTo", writer.String(), err, tc.want, tc.code)
			}

			output, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			assertSerializationOutput(t, "Transform", output, err, tc.want, tc.code)

			value, err = query(t, e, transformSerializedQuery, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
				{Local: variableStylesheet}: transform.Values(transform.String(source)),
			}})
			assertSerializationSequence(t, "fn:transform", value, err, tc.want, tc.code)
		})
	}
}

func assertSerializationSequence(t *testing.T, path string, value transform.Sequence, err error, want, code string) {
	t.Helper()

	got := ""
	if err == nil {
		got = text(t, value)
	}

	assertSerializationResult(t, path, got, err, want, code)
}

func TestSerializationEscapeBytes(t *testing.T) {
	e := engine(t, transform.Config{})
	input := "\x00\x01\x1f\"\\/\b\f\n\r\t\x7f\u009fé😀"
	bindings := transform.Bindings{{Local: sourceName}: transform.Values(transform.String(input))}

	for _, tc := range []struct{ encoding, want string }{
		{serializationUTF8, `"\u0000\u0001\u001F\"\\\/\b\f\n\r\t\u007F\u009Fé😀"`},
		{xmlASCIIEncoding, `"\u0000\u0001\u001F\"\\\/\b\f\n\r\t\u007F\u009F\u00E9\uD83D\uDE00"`},
	} {
		program := query(t, e, `serialize($source, map{'method':'json', 'encoding':'`+tc.encoding+`'})`, transform.XPath31)
		value, err := program.Evaluate(t.Context(), nil, transform.XPathContext{Variables: bindings})
		assertSerializationSequence(t, tc.encoding, value, err, tc.want, "")
	}

	want := `"\u0000\u0001\u001f\"\\\/\b\f\n\r\t` + "\x7f\u009fé😀" + `"`

	for _, normalization := range []string{"", ` normalization-form="NFC"`} {
		compiled := stylesheet(t, e, sheetStart+version30+`"><xsl:param name="source"/><xsl:output method="json"`+normalization+`/><xsl:template name="start"><xsl:sequence select="$source"/></xsl:template></xsl:stylesheet>`)

		result, err := compiled.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: bindings})
		if err != nil {
			t.Fatal(err)
		}

		output, err := result.Serialize(t.Context())
		assertSerializationOutput(t, "Serialize"+normalization, output, err, want, "")

		var streamed strings.Builder

		_, err = result.WriterTo(t.Context()).WriteTo(&streamed)
		assertSerializationResult(t, "WriterTo"+normalization, streamed.String(), err, want, "")
	}
}

func assertSerializationOutput(t *testing.T, path string, output *transform.Output, err error, want, code string) {
	t.Helper()

	got := ""
	if output != nil {
		got = string(output.Primary)
	}

	assertSerializationResult(t, path, got, err, want, code)
}

func assertSerializationResult(t *testing.T, path, got string, err error, want, code string) {
	t.Helper()

	if code != "" {
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != code {
			t.Errorf("%s: %q, %v; want %s", path, got, err, code)
		}
	} else if err != nil || got != want {
		t.Errorf("%s: %q, %v; want %q", path, got, err, want)
	}
}

// TestSerializeParameterDocuments keeps argument type errors separate from
// parameter extraction, duplicate parameters and duplicate character mappings.
func TestSerializeParameterDocuments(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for _, tc := range []struct{ body, code string }{
			{`<indent value="perhaps"/>`, errCodeSEPM0017},
			{`<unknown value="yes"/>`, errCodeSEPM0017},
			{`<indent/>`, errCodeSEPM0017},
			{`<indent value="yes" other="no"/>`, errCodeSEPM0017},
			{`<indent value="yes">text</indent>`, errCodeSEPM0017},
			{`<indent value="yes"/><indent value="no"/>`, errCodeSEPM0019},
			{`<indent xmlns="" value="yes"/>`, errCodeSEPM0017},
			{`<cdata-section-elements value="missing:name"/>`, errCodeSEPM0017},
			{`<use-character-maps value="yes"/>`, errCodeSEPM0017},
			{`<use-character-maps><wrong/></use-character-maps>`, errCodeSEPM0017},
			{`<use-character-maps><character-map character="ab"/></use-character-maps>`, errCodeSEPM0017},
			{`<use-character-maps><character-map character="a" other="x"/></use-character-maps>`, errCodeSEPM0017},
			{`<use-character-maps><character-map character="a" map-string="x"/><character-map character="a" map-string="y"/></use-character-maps>`, errCodeSEPM0018},
			{`<use-character-maps/><use-character-maps/>`, errCodeSEPM0019},
			{`<indent value="true"/>`, ""},
		} {
			params := `<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><method value="text"/>` + tc.body + `</serialization-parameters>`
			value, err := query(t, e, `serialize('x', parse-xml($params)/*)`, version).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
				{Local: "params"}: transform.Values(transform.String(params)),
			}})
			assertSerializationSequence(t, tc.body, value, err, "x", tc.code)
		}
	}

	for expression, code := range map[string]string{
		`serialize('x', 1)`:                                       errCodeXPTY0004,
		`serialize('x', parse-xml('<wrong/>')/*)`:                 errCodeXPTY0004,
		`serialize('x', (map{}, map{}))`:                          errCodeXPTY0004,
		`serialize('x', map{'indent':'yes'})`:                     errCodeXPTY0004,
		`serialize('x', map{'use-character-maps':map{'ab':'x'}})`: errCodeSEPM0016,
		`serialize('x', parse-xml('<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization" extra="x"/>')/*)`: errCodeSEPM0017,
	} {
		value, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
		assertSerializationSequence(t, expression, value, err, "", code)
	}
}

func TestJSONResultDocuments(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct{ expression, want, code string }{
		{`()`, serializationNull, ""},
		{`[(), map{'x':[1,2]}]`, `[null,{"x":[1,2]}]`, ""},
		{`[(1,2)]`, "", errCodeSERE0023},
		{`map{'x':(1,2)}`, "", errCodeSERE0023},
		{`[xs:double('NaN')]`, "", errCodeSERE0020},
		{`map{'x':string#1}`, "", errCodeSERE0021},
		{`map{1:'a','1':'b'}`, "", errCodeSERE0022},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			const uri = "urn:json-result"

			source := sheet(version30, `<xsl:template name="start"><xsl:result-document href="`+uri+`" method="json"><xsl:sequence select="`+tc.expression+`"/></xsl:result-document><xsl:text>done</xsl:text></xsl:template>`)
			compiled := stylesheet(t, e, source)

			result, err := compiled.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
			if err != nil {
				assertSerializationResult(t, "CallTemplate", "", err, tc.want, tc.code)
			} else {
				output, err := result.Serialize(t.Context())

				got := ""
				if output != nil {
					got = string(output.Secondary[uri])
				}

				assertSerializationResult(t, "secondary Serialize", got, err, tc.want, tc.code)

				var writer strings.Builder

				_, err = result.WriteSecondary(t.Context(), uri, &writer)
				assertSerializationResult(t, "WriteSecondary", writer.String(), err, tc.want, tc.code)
			}

			value, err := query(t, e, `transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'delivery-format':'serialized'})('`+uri+`')`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
				{Local: variableStylesheet}: transform.Values(transform.String(source)),
			}})
			assertSerializationSequence(t, "fn:transform secondary", value, err, tc.want, tc.code)
		})
	}
}

func dynamicParameterDocumentCases() []struct{ body, want string } {
	const loop = `<xsl:template name="start"><xsl:for-each select="('text','xml','text')"><xsl:result-document href="urn:result-{position()}" parameter-document="urn:params:{.}"><r xsl:exclude-result-prefixes="xs"><xsl:value-of select="."/></r></xsl:result-document></xsl:for-each></xsl:template>`
	const recursive = `<xsl:template name="emit"><xsl:param name="values" as="xs:string*"/><xsl:result-document href="urn:result-{count($values)}" parameter-document="urn:params:{$values[1]}"><r xsl:exclude-result-prefixes="xs"><xsl:value-of select="$values[1]"/></r><xsl:if test="count($values) gt 1"><xsl:call-template name="emit"><xsl:with-param name="values" select="tail($values)"/></xsl:call-template></xsl:if></xsl:result-document></xsl:template><xsl:template name="start"><xsl:call-template name="emit"><xsl:with-param name="values" select="('xml','text','xml')"/></xsl:call-template></xsl:template>`
	return []struct{ body, want string }{{loop, "text|<r>xml</r>|text"}, {recursive, "<r>xml</r>|text|<r>xml</r>"}}
}

func TestDynamicResultParameterDocuments(t *testing.T) {
	for _, test := range dynamicParameterDocumentCases() {
		for _, nested := range []bool{false, true} {
			calls := make(map[string]int)
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
				method, found := strings.CutPrefix(uri, "urn:params:")
				if !found || method != "text" && method != "xml" {
					return nil, transform.ErrResource
				}
				calls[uri]++
				data := `<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><method value="` + method + `"/><omit-xml-declaration value="yes"/></serialization-parameters>`
				return io.NopCloser(strings.NewReader(data)), ctx.Err()
			})})
			source := sheet(version30, test.body)
			got := ""
			if nested {
				values, err := query(t, e, `let $r := transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'delivery-format':'serialized'}) return string-join((1 to 3)!$r('urn:result-'||.),'|')`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
				if err != nil {
					t.Fatal(err)
				}
				got = text(t, values)
			} else {
				output, err := stylesheet(t, e, source).Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
				if err != nil {
					t.Fatal(err)
				}
				got = string(output.Secondary["urn:result-1"]) + "|" + string(output.Secondary["urn:result-2"]) + "|" + string(output.Secondary["urn:result-3"])
			}
			if got != test.want || calls["urn:params:text"] != 1 || calls["urn:params:xml"] != 1 {
				t.Fatal(nested, got, calls)
			}
		}
	}
}

func TestSerializeMarkupAtomics(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		if got := text(t, evaluate(t, e, `serialize(('a', true(), '<&>'))`, version)); got != "a true &lt;&amp;&gt;" {
			t.Fatal("default XML serialization", version, got)
		}
	}

	for _, method := range []string{serializationXML, serializationHTML} {
		got := text(t, evaluate(t, e, `serialize(('a', true(), '<&>'), map{'method':'`+method+`','use-character-maps':map{'a':'mapped'}})`, transform.XPath31))
		if got != "mapped true &lt;&amp;&gt;" {
			t.Fatal(method, got)
		}
	}
}

func TestSerializeJSONNodeMethods(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct{ method, node, want string }{
		{serializationXML, serializationNodeXML, serializationNodeXML},
		{serializationText, serializationNodeXML, serializationText},
		{serializationHTML, `<p>text<br/></p>`, `<p>text<br></p>`},
	} {
		value := text(t, evaluate(t, e, `parse-json(serialize(parse-xml('`+tc.node+`'), map{'method':'json','json-node-output-method':'`+tc.method+`'}))`, transform.XPath31))
		if value != tc.want {
			t.Fatal(tc.method, value, tc.want)
		}
	}
}

func TestJSONHTMLHeadMetadata(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, tc := range []struct{ xml, path string }{
		{`<head xmlns=""><title>One</title></head>`, `/*`},
		{`<html xmlns="http://www.w3.org/1999/xhtml"><head><title>Two</title></head></html>`, `/*`},
		{`<html><head><title>Three</title></head></html>`, ""},
	} {
		expression := `parse-xml($source)` + tc.path
		variables := transform.Bindings{{Local: sourceName}: transform.Values(transform.String(tc.xml))}
		program := query(t, e, `let $node := `+expression+` return let $html := parse-json(serialize($node, map{'method':'json','json-node-output-method':'html'})) return contains($html, '<meta http-equiv="Content-Type"') and not(contains($html, '<head xmlns="">')) and not(exists($node//meta))`, transform.XPath31)

		value, err := program.Evaluate(t.Context(), nil, transform.XPathContext{Variables: variables})
		if err != nil || text(t, value) != nameTrue {
			t.Fatal("fn:serialize HTML metadata or source mutation", tc, value, err)
		}

		source := sheetStart + version30 + `"><xsl:param name="source"/><xsl:output method="json" json-node-output-method="html"/><xsl:template name="start"><xsl:sequence select="` + expression + `"/></xsl:template></xsl:stylesheet>`

		output, err := stylesheet(t, e, source).Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: variables})
		if err != nil {
			t.Fatal(err)
		}

		value, err = query(t, e, `contains(parse-json($json), '<meta http-equiv="Content-Type"')`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
			{Local: serializationJSON}: transform.Values(transform.String(string(output.Primary))),
		}})
		if err != nil || text(t, value) != nameTrue {
			t.Fatal("XSLT HTML metadata", tc, value, err)
		}

		variables[transform.Name{Local: variableStylesheet}] = transform.Values(transform.String(source))

		value, err = query(t, e, `contains(parse-json(transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'delivery-format':'serialized','stylesheet-params':map{QName('', 'source'):$source}})?output), '<meta http-equiv="Content-Type"')`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: variables})
		if err != nil || text(t, value) != nameTrue {
			t.Fatal("fn:transform HTML metadata", tc, value, err)
		}
	}
}

type markupSerializationErrorCase struct{ name, attributes, expression, options, code string }

func markupSerializationErrorCases() []markupSerializationErrorCase {
	return []markupSerializationErrorCase{
		{"HTML PI", `method="html"`, `parse-xml('<r><?p a>b?></r>')/r/processing-instruction()`, `map{'method':'html'}`, "SERE0015"},
		{"HTML nested PI", `method="html"`, `parse-xml('<r><?p a>b?></r>')/r`, `map{'method':'html'}`, "SERE0015"},
		{"HTML4 control", `method="html" html-version="4.01"`, `codepoints-to-string(127)`, `map{'method':'html','html-version':4.01}`, "SERE0014"},
		{"HTML4 NEL", `method="html" html-version="4.01"`, `codepoints-to-string(133)`, `map{'method':'html','html-version':4.01}`, "SERE0014"},
		{"HTML4 attribute", `method="html" html-version="4.01"`, `parse-xml('<r a="&#127;"/>')/r`, `map{'method':'html','html-version':4.01}`, "SERE0014"},
		{"HTML4 version parameter", `method="html" version="4.01"`, `codepoints-to-string(127)`, `map{'method':'html','version':'4.01'}`, "SERE0014"},
		{"HTML4 separator", `method="html" html-version="4.01" item-separator="&#127;"`, `('a','b')`, `map{'method':'html','html-version':4.01,'item-separator':codepoints-to-string(127)}`, "SERE0014"},
		{"unavailable HTML version", `method="html" version="0.0"`, `'text'`, ``, "SESU0013"},
		{"XML composing start", `method="xml" normalization-form="fully-normalized" omit-xml-declaration="yes"`, `codepoints-to-string(769)`, ``, "SERE0012"},
	}
}

func TestMarkupSerializationContentErrors(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range markupSerializationErrorCases() {
		t.Run(test.name, func(t *testing.T) {
			expression := strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;").Replace(test.expression)
			source := sheetStart + version30 + `"><xsl:output ` + test.attributes + `/><xsl:template name="start"><xsl:sequence select="` + expression + `"/></xsl:template></xsl:stylesheet>`
			if test.options != "" {
				value, err := query(t, e, `serialize(`+test.expression+`,`+test.options+`)`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
				assertSerializationSequence(t, "fn:serialize", value, err, "", test.code)
			}
			compiled := stylesheet(t, e, source)
			for _, mode := range []transform.ResultMode{transform.ResultRaw, transform.ResultDocument} {
				result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: mode})
				if err != nil {
					t.Fatal(err)
				}
				output, err := result.Serialize(t.Context())
				assertSerializationOutput(t, "Serialize", output, err, "", test.code)
				var writer strings.Builder
				_, err = result.WriterTo(t.Context()).WriteTo(&writer)
				assertSerializationResult(t, "WriterTo", writer.String(), err, "", test.code)
			}
			value, err := query(t, e, transformSerializedQuery, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
			assertSerializationSequence(t, "fn:transform", value, err, "", test.code)
		})
	}
}
