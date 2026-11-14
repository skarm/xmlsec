package xslt //nolint:testpackage // Tests dynamic lookup within and across stylesheet package scopes.

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestFnFunctionLookupPackageRespectsArityAndPackageScope(t *testing.T) {
	t.Parallel()
	const library = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		xmlns:f="urn:unit" name="urn:library" package-version="1.0" version="3.0">
		<xsl:function name="f:label" visibility="public"><xsl:sequence select="'library'"/></xsl:function>
		<xsl:function name="f:label" visibility="private">
			<xsl:param name="suffix"/>
			<xsl:sequence select="'private-' || $suffix"/>
		</xsl:function>
		<xsl:template name="f:probe" visibility="public">
			<xsl:variable name="name" select="QName('urn:unit', 'label')"/>
			<xsl:sequence select="(function-lookup($name, 0)(), function-lookup($name, 1)('inside'))"/>
		</xsl:template>
	</xsl:package>`
	const client = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		xmlns:f="urn:unit" name="urn:client" version="3.0">
		<xsl:use-package name="urn:library" package-version="1.0"/>
		<xsl:output method="text" item-separator="|"/>
		<xsl:template name="run" visibility="public">
			<xsl:variable name="name" select="QName('urn:unit', 'label')"/>
			<xsl:sequence select="(function-lookup($name, 0)(), empty(function-lookup($name, 1)))"/>
			<xsl:call-template name="f:probe"/>
			<xsl:variable name="upper" select="function-lookup(QName('http://www.w3.org/2005/xpath-functions','upper-case'), 1)"/>
			<xsl:sequence select="$upper('core')"/>
		</xsl:template>
	</xsl:package>`
	resolver := contractPackageResolver(func(_ context.Context, name, version string) (io.ReadCloser, string, error) {
		if name != "urn:library" || version != "1.0" {
			return nil, "", fmt.Errorf("unexpected package request %q version %q", name, version)
		}
		return io.NopCloser(strings.NewReader(library)), "urn:library:source", nil
	})
	ss, err := NewCompiler().PackageResolver(resolver).Compile(t.Context(), parseTestDocument(t, client))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ss.CallTemplate("run").Serialize(t.Context())
	requireSerialization(t, got, err, "library|true|library|private-inside|CORE", "")
}
