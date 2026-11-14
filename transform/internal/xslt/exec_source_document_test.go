package xslt //nolint:testpackage // Exercises source document focus and reuse.

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSourceDocumentRestoresFocusAndReusesDocument(t *testing.T) {
	t.Parallel()
	const resolved = "https://example.test/styles/data.xml"
	reader := &closeTrackingReader{reader: strings.NewReader(`<r>  <n xml:id="target">external</n>  </r>`)}
	var calls int
	resolver := contractURIResolver(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		calls++
		if ctx.Err() != nil || uri != resolved || calls != 1 {
			t.Errorf("resource call %d: uri=%q, context error=%v; want one request to %q", calls, uri, ctx.Err(), resolved)
			return nil, errors.New("unexpected resource request")
		}
		return reader, nil
	})
	doc := stylesheetDocument(t, `<xsl:strip-space elements="r"/>`, `
		<xsl:for-each select="r/n">
			<xsl:source-document href="data.xml#target" streamable="yes">
				<xsl:value-of select="string(.) || ':' || base-uri(.) || ':' || position() || '/' || last() || '|'"/>
			</xsl:source-document>
			<xsl:source-document href="data.xml">
				<xsl:value-of select="count(r/text()) || '|'"/>
			</xsl:source-document>
			<xsl:value-of select="string(.) || ':' || position() || '/' || last() || ';'"/>
		</xsl:for-each>`)
	ss, err := NewCompiler().BaseURI("https://example.test/styles/main.xsl").Compile(t.Context(), doc)
	if err != nil {
		t.Fatal(err)
	}
	source := parseTestDocument(t, `<r><n>a</n><n>b</n></r>`)
	got, err := ss.Transform(source).URIResolver(resolver).Serialize(t.Context())
	requireSerialization(t, got, err, "external:"+resolved+":1/1|0|a:1/2;external:"+resolved+":1/1|0|b:2/2;", "")
	if calls != 1 || reader.closed != 1 {
		t.Errorf("resource open/close count = %d/%d, want 1/1", calls, reader.closed)
	}
}
