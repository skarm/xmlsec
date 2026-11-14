package xslt //nolint:testpackage // Exercises stylesheet import and include resolution.

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCompileModulesResolveFromRetrievalBase(t *testing.T) {
	t.Parallel()
	const root = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">
		<xsl:import href="parts/rules.xsl"/><xsl:output method="text"/>
		<xsl:template match="/"><xsl:apply-templates select="r"/></xsl:template>
		<xsl:template match="r"><xsl:text>principal:</xsl:text><xsl:apply-imports/></xsl:template>
	</xsl:stylesheet>`
	modules := map[string]string{
		"https://example.test/styles/parts/rules.xsl": `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">
			<xsl:include href="../labels.xsl"/><xsl:template match="r"><xsl:call-template name="label"/></xsl:template>
		</xsl:stylesheet>`,
		"https://example.test/styles/labels.xsl": `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">
			<xsl:template name="label"><xsl:text>included</xsl:text></xsl:template>
		</xsl:stylesheet>`,
	}
	readers := map[string]*closeTrackingReader{}
	resolver := contractURIResolver(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		source, found := modules[uri]
		if !found {
			t.Errorf("unexpected module URI %q", uri)
			return nil, errors.New("module not in fixture")
		}
		if readers[uri] != nil {
			t.Errorf("module %q was opened more than once", uri)
		}
		reader := &closeTrackingReader{reader: strings.NewReader(source)}
		readers[uri] = reader
		return reader, nil
	})
	ss, err := NewCompiler().BaseURI("https://example.test/styles/main.xsl").URIResolver(resolver).
		Compile(t.Context(), parseTestDocument(t, root))
	if err != nil {
		t.Fatal(err)
	}
	for uri := range modules {
		if reader := readers[uri]; reader == nil || reader.closed != 1 {
			t.Errorf("module %q reader was not opened and closed exactly once", uri)
		}
	}
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "principal:included", "")
}
