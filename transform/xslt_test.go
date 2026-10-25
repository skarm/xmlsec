package transform_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

const nameKept = "kept"

func TestXSLT20And30(t *testing.T) {
	e := engine(t, transform.Config{})

	d, err := e.Parse(context.Background(), []byte(`<r><item category="b">3</item><item category="a">2</item><item category="b">4</item></r>`))
	if err != nil {
		t.Fatal(err)
	}

	style2 := stylesheet(t, e, sheet(version20, `<xsl:param name="offset" as="xs:integer"/><xsl:template match="/"><xsl:for-each-group select="r/item" group-by="@category"><xsl:sort select="current-grouping-key()"/><xsl:value-of select="current-grouping-key()"/><xsl:text>:</xsl:text><xsl:value-of select="sum(current-group())+$offset"/><xsl:text>;</xsl:text></xsl:for-each-group></xsl:template>`))

	out, err := style2.Transform(context.Background(), d, transform.XSLTContext{Parameters: transform.Bindings{{Local: "offset"}: transform.Values(transform.Integer(10))}})
	if err != nil || string(out.Primary) != "a:12;b:17;" {
		t.Fatal(out, err)
	}

	style3 := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:iterate select="1 to 5"><xsl:param name="sum" select="0"/><xsl:on-completion><xsl:value-of select="$sum"/></xsl:on-completion><xsl:next-iteration><xsl:with-param name="sum" select="$sum + ."/></xsl:next-iteration></xsl:iterate><xsl:message>done</xsl:message><xsl:result-document href="second.txt" method="text"><xsl:value-of select="map{'answer':42}?answer"/></xsl:result-document></xsl:template>`))

	out, err = style3.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, BaseOutputURI: "urn:outputs:"})
	if err != nil || string(out.Primary) != "15" || len(out.Secondary) != 1 || len(out.Messages) != 1 || out.Messages[0].Text != "done" {
		t.Fatal(out, err)
	}

	for _, b := range out.Secondary {
		if string(b) != "42" {
			t.Fatal(out)
		}
	}

	if style2.Version() != transform.XSLT20 || style3.Version() != transform.XSLT30 {
		t.Fatal("version")
	}
}

func TestXSLTPreservesNonXMLWhitespace(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []string{version10, version20, version30} {
		for _, text := range []string{"\u00a0", "\u1680", "\u2003"} {
			style := stylesheet(t, e, sheet(version, `<xsl:template name="start">`+text+`</xsl:template>`))

			out, err := style.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if err != nil || string(out.Primary) != text {
				t.Errorf("XSLT %s lost literal %q: %q, %v", version, text, out.Primary, err)
			}
		}
	}

	// A non-XML space before a parameter is real template content, so it
	// cannot be ignored to make an otherwise misplaced declaration valid.
	invalid := sheet(version30, "<xsl:template name='start'>\u00a0<xsl:param name='p'/></xsl:template>")
	if _, err := e.CompileXSLT(t.Context(), []byte(invalid), transform.XSLTOptions{}); err == nil {
		t.Error("significant template text ignored before parameter")
	}

	style := stylesheet(t, e, sheetStart+version30+`"><xsl:output method="xml" indent="yes" omit-xml-declaration="yes"/><xsl:param name="space"/><xsl:template name="start"><r><xsl:value-of select="$space" disable-output-escaping="yes"/><c/></r></xsl:template></xsl:stylesheet>`)

	out, err := style.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: transform.Bindings{{Local: "space"}: transform.Values(transform.String("\u00a0"))}})
	if err != nil || !strings.Contains(string(out.Primary), "\u00a0") {
		t.Errorf("indentation lost significant non-XML whitespace: %q, %v", out.Primary, err)
	}
}

func TestXSLTVersionBoundaries(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, body := range []string{
		`<xsl:template match="/"><xsl:iterate select="1"/></xsl:template>`,
		`<xsl:param name="p" static="yes" select="1"/>`,
		`<xsl:template match="/"><xsl:value-of select="map{'a':1}?a"/></xsl:template>`,
		`<xsl:template match="/" expand-text="yes">{1+1}</xsl:template>`,
		`<xsl:param name="p" as="array(*)"/>`,
	} {
		if _, err := e.CompileXSLT(context.Background(), []byte(sheet(version20, body)), transform.XSLTOptions{}); err == nil {
			t.Error("2.0 accepted", body)
		}
	}

	for _, version := range []string{"0.9", "4.0"} {
		if _, err := e.CompileXSLT(context.Background(), []byte(sheet(version, `<xsl:template match="/"/>`)), transform.XSLTOptions{}); !errors.Is(err, transform.ErrUnsupported) {
			t.Fatal(err)
		}
	}

	for _, body := range []string{`<xsl:import-schema namespace="urn:x"/>`, `<xsl:mode streamable="yes"/>`} {
		if _, err := e.CompileXSLT(context.Background(), []byte(sheet(version30, body)), transform.XSLTOptions{}); !errors.Is(err, transform.ErrUnsupported) {
			t.Fatal(err)
		}
	}
}

func TestStaticParametersAndEnvironment(t *testing.T) {
	ctx := context.Background()
	env := map[string]string{"APPLICATION": "visible"}
	e := engine(t, transform.Config{Environment: env})
	env["APPLICATION"] = "changed"

	if got := text(t, evaluate(t, e, `environment-variable('APPLICATION')`, transform.XPath31)); got != "visible" {
		t.Fatal(got)
	}

	if got := evaluate(t, engine(t, transform.Config{}), `available-environment-variables()`, transform.XPath31); got.Len() != 0 {
		t.Fatal(got)
	}

	source := sheet(version30, `<xsl:param name="feature" static="yes" as="xs:boolean"/><xsl:template name="start"><xsl:text use-when="$feature">enabled</xsl:text></xsl:template>`)

	s, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{StaticParameters: transform.Bindings{{Local: "feature"}: transform.Values(transform.Boolean(true))}})
	if err != nil {
		t.Fatal(err)
	}

	out, err := s.Transform(ctx, nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || string(out.Primary) != "enabled" {
		t.Fatal(out, err)
	}

	d, err := e.Parse(ctx, []byte(`<r xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:x https://example.invalid/ignored.xsd"/>`))
	if err != nil {
		t.Fatal(err)
	}

	out, err = stylesheet(t, e, sheet(version30, `<xsl:template match="/"><xsl:text>basic</xsl:text></xsl:template>`)).Transform(ctx, d, transform.XSLTContext{})
	if err != nil || string(out.Primary) != "basic" {
		t.Fatal(out, err)
	}

	if _, err = e.CompileXPath(ctx, `not-a-function()`, transform.XPathOptions{}); err == nil {
		t.Fatal("unknown function accepted")
	}
}

func TestStreamingIterateBreakKeepsParameters(t *testing.T) {
	e := engine(t, transform.Config{})
	s := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:iterate select="1 to 5"><xsl:param name="sum" select="0"/><xsl:on-completion><xsl:text>completed</xsl:text></xsl:on-completion><xsl:choose><xsl:when test=". = 3"><xsl:break select="$sum"/></xsl:when><xsl:otherwise><xsl:next-iteration><xsl:with-param name="sum" select="$sum+."/></xsl:next-iteration></xsl:otherwise></xsl:choose></xsl:iterate></xsl:template>`))

	out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil {
		t.Fatal(err)
	}

	if got := string(out.Primary); got != "3" {
		t.Fatalf("iterate break = %q", got)
	}
}

func TestStreamingMergeOrderAndGroups(t *testing.T) {
	e := engine(t, transform.Config{})
	s := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:merge><xsl:merge-source name="left" select="(3,1,2)" sort-before-merge="yes"><xsl:merge-key select="." data-type="number"/></xsl:merge-source><xsl:merge-source name="right" select="(2,4)"><xsl:merge-key select="." data-type="number"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="concat(current-merge-key(),':',count(current-merge-group()),':',count(current-merge-group('left')),',')"/></xsl:merge-action></xsl:merge></xsl:template>`))

	out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil {
		t.Fatal(err)
	}

	if got := string(out.Primary); got != "1:1:1,2:2:1,3:1:1,4:1:0," {
		t.Fatalf("merge order/groups = %q", got)
	}
}

func TestStreamingRejectsUnsortedMerge(t *testing.T) {
	e := engine(t, transform.Config{})
	s := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:merge><xsl:merge-source select="(2,1)"><xsl:merge-key select="." data-type="number"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="current-merge-key()"/></xsl:merge-action></xsl:merge></xsl:template>`))

	_, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err == nil || !strings.Contains(err.Error(), "XTDE2220") {
		t.Fatalf("unsorted merge error = %v", err)
	}
}

func TestStreamingNestedMergeRestoresFunctions(t *testing.T) {
	e := engine(t, transform.Config{})
	s := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:merge><xsl:merge-source name="outer" select="(1,2)"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="current-merge-key()"/><xsl:text>[</xsl:text><xsl:merge><xsl:merge-source name="inner" select="(8,9)"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="current-merge-key()"/></xsl:merge-action></xsl:merge><xsl:text>]</xsl:text><xsl:value-of select="current-merge-key()"/><xsl:text>;</xsl:text></xsl:merge-action></xsl:merge></xsl:template>`))

	out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil {
		t.Fatal(err)
	}

	if got := string(out.Primary); got != "1[89]1;2[89]2;" {
		t.Fatalf("nested merge = %q", got)
	}
}

func TestStreamingResultDocumentTransactions(t *testing.T) {
	e := engine(t, transform.Config{})

	cases := []struct{ name, body, primary, secondaryURI, secondaryText string }{
		{"secondary preflight", `<xsl:try><xsl:result-document href="outer.txt" method="text" standalone="{1 idiv 0}"><xsl:result-document href="nested.txt" method="text">bad</xsl:result-document></xsl:result-document><xsl:catch><xsl:result-document href="outer.txt" method="text">ok</xsl:result-document></xsl:catch></xsl:try>`, "", "outer.txt", "ok"},
		{"primary rollback", `<xsl:try><xsl:result-document><xsl:text>partial</xsl:text><xsl:sequence select="error()"/></xsl:result-document><xsl:catch><xsl:result-document>ok</xsl:result-document></xsl:catch></xsl:try>`, "ok", "", ""},
		{"JSON validation rollback", `<xsl:try><xsl:result-document href="data.json" method="json" build-tree="no"><xsl:sequence select="map{1:'a','1':'b'}"/></xsl:result-document><xsl:catch><xsl:result-document href="data.json" method="text">recovered</xsl:result-document></xsl:catch></xsl:try>`, "", "data.json", "recovered"},
		{"primary item capture", `<xsl:result-document method="{'json'}" build-tree="{false()}"><xsl:sequence select="map{'answer':42}"/></xsl:result-document>`, `{"answer":42}`, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := stylesheet(t, e, sheet(version30, `<xsl:template name="start">`+tc.body+`</xsl:template>`))

			out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if err != nil {
				t.Fatal(err)
			}

			if got := string(out.Primary); got != tc.primary {
				t.Fatalf("primary = %q, want %q", got, tc.primary)
			}

			if tc.secondaryURI == "" {
				if len(out.Secondary) != 0 {
					t.Fatalf("unexpected secondary outputs %v", out.Secondary)
				}

				return
			}

			if len(out.Secondary) != 1 || string(out.Secondary[tc.secondaryURI]) != tc.secondaryText {
				t.Fatalf("secondary outputs = %v", out.Secondary)
			}
		})
	}
}

func TestProcessorIdentityDuringCompilationAndExecution(t *testing.T) {
	e := engine(t, transform.Config{})

	doc, err := e.Parse(context.Background(), []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	program := stylesheet(t, e, sheet(version30, `<xsl:template match="/">
<xsl:value-of use-when="system-property('xsl:vendor') = 'xmlsec'"
select="concat(system-property('xsl:product-name'), '|', system-property('xsl:vendor-url'))"/>
</xsl:template>`))

	result, err := program.Transform(context.Background(), doc, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(result.Primary), "xmlsec|https://github.com/skarm/xmlsec"; got != want {
		t.Fatalf("processor identity=%q, want %q", got, want)
	}
}

func TestXSLTProfileResults(t *testing.T) {
	e := engine(t, transform.Config{})
	source := `<r><n category="b">3</n><n category="a">2</n><n category="b">4</n></r>`

	d, err := e.Parse(context.Background(), []byte(source))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct{ name, version, body, want string }{
		{"grouping", version20, `<xsl:template match="/"><xsl:for-each-group select="r/n" group-by="@category"><xsl:sort select="current-grouping-key()"/><xsl:value-of select="current-grouping-key()"/><xsl:text>:</xsl:text><xsl:value-of select="sum(current-group())"/><xsl:text>;</xsl:text></xsl:for-each-group></xsl:template>`, "a:2;b:7;"},
		{"functions", version20, `<xsl:function name="local:square" xmlns:local="urn:local" as="xs:integer"><xsl:param name="n" as="xs:integer"/><xsl:sequence select="$n*$n"/></xsl:function><xsl:template match="/" xmlns:local="urn:local"><xsl:value-of select="sum(for $n in 1 to 4 return local:square($n))"/></xsl:template>`, "30"},
		{"iteration", version30, `<xsl:template match="/"><xsl:iterate select="1 to 5"><xsl:param name="sum" select="0"/><xsl:on-completion><xsl:value-of select="$sum"/></xsl:on-completion><xsl:next-iteration><xsl:with-param name="sum" select="$sum+."/></xsl:next-iteration></xsl:iterate></xsl:template>`, "15"},
		{"maps-and-arrays", version30, `<xsl:template match="/"><xsl:value-of select="map{'a':[1,2]}?a?2"/></xsl:template>`, "2"},
	}
	for _, c := range cases {
		t.Run(c.version+"/"+c.name, func(t *testing.T) {
			result, err := stylesheet(t, e, sheet(c.version, c.body)).Transform(context.Background(), d, transform.XSLTContext{})
			if err != nil {
				t.Fatal(err)
			}

			if got := string(result.Primary); got != c.want {
				t.Fatalf("expected %q, got %q", c.want, got)
			}
		})
	}
}

func TestXSLT10ForwardsAttributesAreIgnored(t *testing.T) {
	e := engine(t, transform.Config{})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, attrs, body, want string }{
		{"use-when", ``, `<xsl:text use-when="false()">kept</xsl:text>`, nameKept},
		{"expand-text", `expand-text="yes"`, `<xsl:text>{1+1}</xsl:text>`, "{1+1}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.1" ` + tc.attrs + `><xsl:output method="text"/><xsl:template match="/">` + tc.body + `</xsl:template></xsl:stylesheet>`
			s := stylesheet(t, e, source)

			out, err := s.Transform(ctx, d, transform.XSLTContext{})
			if err != nil {
				t.Fatal(err)
			}

			if string(out.Primary) != tc.want {
				t.Fatalf("got %q, want %q", out.Primary, tc.want)
			}
		})
	}
}

func TestXSLT10RequiresSelect(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, instruction := range []string{`<xsl:value-of/>`, `<xsl:value-of>text</xsl:value-of>`, `<xsl:value-of select=""/>`} {
		if _, err := e.CompileXSLT(context.Background(), []byte(xslt10(`<xsl:template match="/">`+instruction+`</xsl:template>`)), transform.XSLTOptions{}); err == nil {
			t.Errorf("accepted XSLT 1.0 value-of without a valid select: %s", instruction)
		}
	}
}

func TestXSLTLiteralExpandTextAttribute(t *testing.T) {
	e := engine(t, transform.Config{})

	d, err := e.Parse(context.Background(), []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	s := stylesheet(t, e, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out expand-text="yes">{1+1}</out></xsl:template></xsl:stylesheet>`)

	out, err := s.Transform(context.Background(), d, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}

	if string(out.Primary) != `<out expand-text="yes">{1+1}</out>` {
		t.Fatalf("ordinary result attribute changed XSLT behavior: %s", out.Primary)
	}
}

func TestXSLT10ForwardsModulesPreserveSource(t *testing.T) {
	const module = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.1" expand-text="yes"><xsl:template name="module"><xsl:text use-when="false()">kept:</xsl:text><xsl:value-of select="document('')/*/@expand-text"/></xsl:template></xsl:stylesheet>`

	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(module)), nil
	})})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, instruction := range []string{"include", "import"} {
		t.Run(instruction, func(t *testing.T) {
			source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.1" expand-text="yes"><xsl:` + instruction + ` href="urn:module"/><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="document('')/*/@expand-text"/>:<xsl:call-template name="module"/></xsl:template></xsl:stylesheet>`
			s := stylesheet(t, e, source)

			out, err := s.Transform(ctx, d, transform.XSLTContext{})
			if err != nil {
				t.Fatal(err)
			}

			if string(out.Primary) != "yes:kept:yes" {
				t.Fatalf("source or forward semantics changed: %s", out.Primary)
			}
		})
	}
}

func TestXSLTSimplifiedExpandText(t *testing.T) {
	e := engine(t, transform.Config{})

	d, err := e.Parse(context.Background(), []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	s := stylesheet(t, e, `<out xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xsl:version="3.0" xsl:expand-text="yes">{1+1}</out>`)

	out, err := s.Transform(context.Background(), d, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(out.Primary), `<out>2</out>`) {
		t.Fatalf("simplified stylesheet ignored xsl:expand-text: %s", out.Primary)
	}
}

func TestXSLT10ForwardsUnknownOptionalValues(t *testing.T) {
	e := engine(t, transform.Config{})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r><n>2</n><n>1</n></r>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ body, want string }{
		{`<xsl:text disable-output-escaping="future">kept</xsl:text>`, nameKept},
		{`<xsl:text disable-output-escaping="future" version="1.0">kept</xsl:text>`, nameKept},
		{`<xsl:text version="1.0" disable-output-escaping="future">kept</xsl:text>`, nameKept},
		{`<xsl:message terminate="future">message</xsl:message><xsl:text>kept</xsl:text>`, nameKept},
		{`<xsl:for-each select="r/n"><xsl:sort order="future"/><xsl:value-of select="."/></xsl:for-each>`, "12"},
		{`<xsl:for-each select="r/n"><xsl:sort order="{'future'}" case-order="{'future'}"/><xsl:value-of select="."/></xsl:for-each>`, "12"},
		{`<xsl:message terminate="{'future'}">message</xsl:message><xsl:text>kept</xsl:text>`, nameKept},
	} {
		source := strings.Replace(xslt10(`<xsl:template match="/">`+tc.body+`</xsl:template>`), `version="1.0"`, `version="1.1"`, 1)

		s, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{})
		if err != nil {
			t.Errorf("optional future value was not ignored: %v", err)
			continue
		}

		out, err := s.Transform(ctx, d, transform.XSLTContext{})
		if err != nil || out == nil || string(out.Primary) != tc.want {
			t.Errorf("got %v, %v; want %q", out, err, tc.want)
		}
	}
}

func TestXSLT10RejectsNonFiniteNestedVersion(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []string{valueNaN, nameInfinity, "INF"} {
		source := xslt10(`<xsl:template match="/"><out xsl:version="` + version + `">text</out></xsl:template>`)
		if _, err := e.CompileXSLT(context.Background(), []byte(source), transform.XSLTOptions{}); err == nil {
			t.Errorf("accepted non-finite XSLT version: %s", version)
		}
	}
}

func TestXSLTForwardsRecoveryKeepsStrictValidation(t *testing.T) {
	e := engine(t, transform.Config{})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r><n>1</n></r>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, version := range []string{version10, version20, version30} {
		source := sheet(version, `<xsl:template match="/"><xsl:for-each select="r/n"><xsl:sort order="{'future'}"/><xsl:value-of select="."/></xsl:for-each></xsl:template>`)

		s, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{})
		if err == nil {
			_, err = s.Transform(ctx, d, transform.XSLTContext{})
		}

		if err == nil {
			t.Errorf("strict %s accepted an invalid order", version)
		}
	}

	source := strings.Replace(xslt10(`<xsl:template match="/"><out xsl:version="1.0"><xsl:text disable-output-escaping="future">text</xsl:text></out></xsl:template>`), `version="1.0"`, `version="1.1"`, 1)
	if _, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{}); err == nil {
		t.Fatal("nested xsl:version=1.0 did not disable forwards recovery")
	}
}

// XMLDSig hashes the serialized XSLT output. Reusing one compiled stylesheet
// must not randomly reorder its literal element's namespace declarations.
func TestXSLTLiteralNamespaceSerializationStable(t *testing.T) {
	e := engine(t, transform.Config{})
	s := stylesheet(t, e, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:a="urn:a" xmlns:b="urn:b" xmlns:c="urn:c" version="1.0"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><a:out><b:value c:id="x"/></a:out></xsl:template></xsl:stylesheet>`)

	d, err := e.Parse(t.Context(), []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	var first []byte

	for i := 0; i < 100; i++ {
		out, err := s.Transform(t.Context(), d, transform.XSLTContext{})
		if err != nil {
			t.Fatal(err)
		}

		if i == 0 {
			first = out.Primary
		} else if !bytes.Equal(out.Primary, first) {
			t.Fatalf("unstable XSLT bytes: %q != %q", out.Primary, first)
		}
	}
}
