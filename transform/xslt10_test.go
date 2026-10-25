package transform_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/transform"
)

func TestXSLT10XMLConstructionAndSimplifiedStylesheet(t *testing.T) {
	e := engine(t, transform.Config{})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:s="urn:style" xmlns:out="urn:result" version="1.0"><xsl:output omit-xml-declaration="yes"/><xsl:namespace-alias stylesheet-prefix="s" result-prefix="out"/><xsl:attribute-set name="meta"><xsl:attribute name="kind">ok</xsl:attribute></xsl:attribute-set><xsl:template match="/"><xsl:variable name="v"><s:item>yes</s:item></xsl:variable><root xsl:use-attribute-sets="meta"><xsl:copy-of select="$v"/></root></xsl:template></xsl:stylesheet>`

	s, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{})
	if err != nil {
		t.Fatal(err)
	}

	out, err := s.Transform(ctx, d, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}

	result, err := document.Parse(ctx, out.Primary, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	root := result.Root()
	kind, _ := root.Attribute(document.Name{Local: "kind"})

	children := root.Children()
	if kind != "ok" || len(children) != 1 || children[0].Name() != (document.Name{Space: "urn:result", Local: nameItem}) || children[0].Text() != nameYes {
		t.Fatalf("attribute sets, namespace alias or fragment copy lost: %s", out.Primary)
	}

	s, err = e.CompileXSLT(ctx, []byte(`<result xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xsl:version="1.0" small="{0.0000001}" infinity="{1 div 0}"><xsl:text>ok</xsl:text></result>`), transform.XSLTOptions{})
	if err != nil {
		t.Fatal(err)
	}

	out, err = s.Transform(ctx, d, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}

	result, err = document.Parse(ctx, out.Primary, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	small, _ := result.Root().Attribute(document.Name{Local: "small"})

	infinity, _ := result.Root().Attribute(document.Name{Local: "infinity"})
	if small != "0.0000001" || infinity != nameInfinity || result.Root().Text() != "ok" {
		t.Fatalf("simplified stylesheet or 1.0 AVT conversion lost: %s", out.Primary)
	}
}

func TestXSLT10CoreAndTemporaryTrees(t *testing.T) {
	e := engine(t, transform.Config{})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r><n k="a">2</n><n k="a">3</n><n k="b">bad</n></r>`))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		body string
		want string
	}{
		{`<xsl:key name="inf" match="n" use="1 div 0"/><xsl:key name="small" match="n" use="0.0000001"/><xsl:template match="/"><xsl:value-of select="concat(count(key('inf',1 div 0)),':',count(key('small',0.0000001)))"/></xsl:template>`, "3:3"},
		{`<xsl:template match="/"><xsl:for-each select="/r/n"><xsl:sort select="concat(.,'e2')" data-type="number"/><xsl:value-of select="@k"/></xsl:for-each></xsl:template>`, "aab"},
		{`<xsl:template match="/"><wrap xsl:version="2.0"><xsl:sequence select="1"><xsl:fallback>fallback</xsl:fallback></xsl:sequence></wrap></xsl:template>`, nameFallbackResult},
		{`<xsl:template match="/"><ext:run xmlns:ext="urn:ext" xsl:extension-element-prefixes="ext"><xsl:fallback>extension-fallback</xsl:fallback></ext:run></xsl:template>`, "extension-fallback"},
		{`<xsl:template match="/"><xsl:value-of select="document('')/*/@version"/></xsl:template>`, version10},
		{`<xsl:template match="/"><xsl:value-of select="/r/n"/>:<xsl:value-of select="1 div 0"/>:<xsl:value-of select="0.0000001"/>:<xsl:value-of select="number('+1')"/></xsl:template>`, "2:Infinity:0.0000001:NaN"},
		{`<xsl:key name="by-k" match="n" use="@k"/><xsl:template match="/"><xsl:value-of select="count(key('by-k','a'))"/>:<xsl:value-of select="sum(/r/n)"/>:<xsl:value-of select="generate-id(/r/n[1]) = generate-id(/r/n[1])"/></xsl:template>`, "2:NaN:true"},
		{`<xsl:variable name="global"><a>2</a></xsl:variable><xsl:template match="/"><xsl:variable name="local"><b>3</b></xsl:variable><xsl:value-of select="concat(string($global),':',string($local),':', $local + 1,':',boolean($local))"/></xsl:template>`, "2:3:4:true"},
		{`<xsl:template match="/"><xsl:variable name="empty"/><xsl:value-of select="concat(string($empty),':',boolean($empty),':',number($empty))"/></xsl:template>`, ":false:NaN"},
		{`<xsl:template match="/"><xsl:value-of select="concat(system-property('xsl:version'),':',function-available('sum'),':',function-available('matches'),':',element-available('xsl:sequence'))"/></xsl:template>`, "1:true:false:false"},
		{`<xsl:template match="/"><xsl:apply-templates select="/r/n" mode="m"><xsl:sort select="@k" order="descending"/></xsl:apply-templates></xsl:template><xsl:template match="n" mode="m"><xsl:number level="single"/><xsl:text>=</xsl:text><xsl:value-of select="."/><xsl:text>;</xsl:text></xsl:template>`, "3=bad;1=2;2=3;"},
		{`<xsl:template match="/"><xsl:call-template name="emit"><xsl:with-param name="p"><v>yes</v></xsl:with-param></xsl:call-template></xsl:template><xsl:template name="emit"><xsl:param name="p">default</xsl:param><xsl:value-of select="$p"/></xsl:template>`, nameYes},
		{`<xsl:template match="/"><xsl:value-of select="format-number(0.125,'0.0%')"/></xsl:template>`, "12.5%"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			s, err := e.CompileXSLT(ctx, []byte(xslt10(tc.body)), transform.XSLTOptions{Version: transform.XSLT10})
			if err != nil {
				t.Fatal(err)
			}

			if s.Version() != transform.XSLT10 {
				t.Fatal("wrong version")
			}

			out, err := s.Transform(ctx, d, transform.XSLTContext{})
			if err != nil {
				t.Fatal(err)
			}

			if string(out.Primary) != tc.want {
				t.Fatalf("got %s, want %s: %v", out.Primary, tc.want, err)
			}
		})
	}

	for _, expr := range []string{`$v/a`, `$v[1]`, `count($v)`, `$v | /r`} {
		t.Run(expr, func(t *testing.T) {
			source := xslt10(`<xsl:template match="/"><xsl:variable name="v"><a/></xsl:variable><xsl:value-of select="` + expr + `"/></xsl:template>`)

			s, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{})
			if err == nil {
				_, err = s.Transform(ctx, d, transform.XSLTContext{})
			}

			if err == nil {
				t.Error("result tree fragment accepted as node-set")
			}
		})
	}
}

func TestXSLT10ModulesAndConcurrentReuse(t *testing.T) {
	modules := map[string]string{
		"urn:test:included": `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template name="included"><xsl:text>included:</xsl:text><xsl:value-of select="document('urn:test:data')/data"/></xsl:template></xsl:stylesheet>`,
		"urn:test:imported": `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="n">old</xsl:template></xsl:stylesheet>`,
		"urn:test:data":     `<data>ok</data>`,
	}
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
		s, ok := modules[uri]
		if !ok {
			return nil, fmt.Errorf("unknown resource %s", uri)
		}

		return io.NopCloser(strings.NewReader(s)), nil
	})})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r><n/></r>`))
	if err != nil {
		t.Fatal(err)
	}

	s, err := e.CompileXSLT(ctx, []byte(sheetStart+version10+`"><xsl:import href="urn:test:imported"/><xsl:output method="text"/><xsl:include href="urn:test:included"/><xsl:template match="/"><xsl:call-template name="included"/>:<xsl:apply-templates select="/r/n"/></xsl:template><xsl:template match="n">new:<xsl:apply-imports/></xsl:template></xsl:stylesheet>`), transform.XSLTOptions{BaseURI: "urn:test:main"})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			out, err := s.Transform(ctx, d, transform.XSLTContext{})
			if err != nil {
				t.Error(err)
				return
			}

			if string(out.Primary) != "included:ok:new:old" {
				t.Errorf("got %s: %v", out.Primary, err)
			}
		})
	}

	wg.Wait()
}

func TestXSLT10RejectsModernPatternsAndFunctions(t *testing.T) {
	e := engine(t, transform.Config{})
	ctx := context.Background()

	for _, pattern := range []string{`.`, `ancestor::n`, `n[$global]`, `element(n)`} {
		source := xslt10(`<xsl:variable name="global" select="true()"/><xsl:template match="` + pattern + `"/>`)
		if _, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{}); err == nil {
			t.Errorf("invalid 1.0 match pattern accepted: %s", pattern)
		}
	}

	d, err := e.Parse(ctx, []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, expr := range []string{`key('x','y',/)`, `generate-id()`, `function-available('sum',1)`, `unparsed-entity-uri('x',/)`, `matches('a','a')`} {
		s, err := e.CompileXSLT(ctx, []byte(xslt10(`<xsl:template match="/"><xsl:value-of select="`+expr+`"/></xsl:template>`)), transform.XSLTOptions{})
		if err == nil {
			_, err = s.Transform(ctx, d, transform.XSLTContext{})
		}

		if err == nil {
			t.Errorf("modern function/arity accepted: %s", expr)
		}
	}
}

func TestXSLT10ForwardsProcessingDefersInactiveErrors(t *testing.T) {
	e := engine(t, transform.Config{})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	source := strings.Replace(xslt10(`<xsl:template match="/"><xsl:choose><xsl:when test="system-property('xsl:version') &gt;= 1.1"><xsl:future-feature/></xsl:when><xsl:otherwise>ok</xsl:otherwise></xsl:choose><xsl:if test="false()"><xsl:value-of select="not valid future syntax!"/></xsl:if></xsl:template>`), `version="1.0"`, `version="1.1"`, 1)

	s, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{Version: transform.XSLT10})
	if err != nil {
		t.Fatal(err)
	}

	out, err := s.Transform(ctx, d, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}

	if string(out.Primary) != "ok" {
		t.Fatal(string(out.Primary))
	}

	active := strings.Replace(source, `test="false()"`, `test="true()"`, 1)

	s, err = e.CompileXSLT(ctx, []byte(active), transform.XSLTOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err = s.Transform(ctx, d, transform.XSLTContext{}); err == nil {
		t.Fatal("active invalid expression did not fail")
	}
}

func TestXSLT10SerializationDefaults(t *testing.T) {
	e := engine(t, transform.Config{})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		body   string
		want   string
		absent string
	}{
		{`<html><head/><body><br/></body></html>`, `<br>`, `<!DOCTYPE html>`},
		{`<html xmlns="http://www.w3.org/1999/xhtml"><head/><body><br/></body></html>`, `<br/>`, `<meta`},
	} {
		source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/">` + tc.body + `</xsl:template></xsl:stylesheet>`

		s, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{})
		if err != nil {
			t.Fatal(err)
		}

		out, err := s.Transform(ctx, d, transform.XSLTContext{})
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Contains(out.Primary, []byte(tc.want)) || bytes.Contains(out.Primary, []byte(tc.absent)) {
			t.Fatalf("wrong v1 serialization defaults: %s", out.Primary)
		}
	}

	source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:output method="xml" omit-xml-declaration="yes" standalone="yes"/><xsl:template match="/"><r/></xsl:template></xsl:stylesheet>`

	s, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{})
	if err != nil {
		t.Fatal(err)
	}

	out, err := s.Transform(ctx, d, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(out.Primary, []byte("<?xml")) {
		t.Fatal(string(out.Primary))
	}
}

func xslt10(body string) string {
	return `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:output method="text"/>` + body + `</xsl:stylesheet>`
}
