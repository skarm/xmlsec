package xslt //nolint:testpackage // Exercises package retrieval and component visibility.

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

type contractPackageResolver func(context.Context, string, string) (io.ReadCloser, string, error)

func (r contractPackageResolver) ResolvePackage(ctx context.Context, name, version string) (io.ReadCloser, string, error) {
	return r(ctx, name, version)
}

func TestCompilePackageCallsPublicComponents(t *testing.T) {
	t.Parallel()
	const library = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:unit" name="urn:library" package-version="2.1" version="3.0">
		<xsl:template name="f:label" visibility="public"><xsl:value-of select="f:internal('component')"/></xsl:template>
		<xsl:function name="f:internal" visibility="private"><xsl:param name="text"/><xsl:sequence select="upper-case($text)"/></xsl:function>
	</xsl:package>`
	reader := &closeTrackingReader{reader: strings.NewReader(library)}
	resolver := contractPackageResolver(func(ctx context.Context, name, version string) (io.ReadCloser, string, error) {
		if ctx.Err() != nil || name != "urn:library" || version != "2.*" {
			t.Errorf("package request name=%q version=%q error=%v", name, version, ctx.Err())
		}
		return reader, "https://example.test/library.xsl", nil
	})
	const app = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:unit" name="urn:app" package-version="1.0" version="3.0">
		<xsl:use-package name="urn:library" package-version="2.*"/>
		<xsl:output method="text"/>
		<xsl:template name="start" visibility="public"><xsl:call-template name="f:label"/></xsl:template>
	</xsl:package>`
	ss, err := NewCompiler().PackageResolver(resolver).Compile(t.Context(), parseTestDocument(t, app))
	if err != nil {
		t.Fatal(err)
	}
	if reader.closed != 1 {
		t.Fatalf("package reader closed %d times, want once", reader.closed)
	}
	got, err := ss.CallTemplate("start").Serialize(t.Context())
	requireSerialization(t, got, err, "COMPONENT", "")
	got, err = ss.CallFunction("Q{urn:unit}internal", xdm.SingleString("private")).Serialize(t.Context())
	requireSerialization(t, got, err, "", "XTDE0041")
}

func TestCompileUsePackageRejectsExplicitEmptyVersion(t *testing.T) {
	t.Parallel()

	const library = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" name="urn:library" version="3.0"/>`

	for _, version := range []string{"", "   "} {
		t.Run("["+version+"]", func(t *testing.T) {
			t.Parallel()

			app := `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" name="urn:app" version="3.0">
				<xsl:use-package name="urn:library" package-version="` + version + `"/>
			</xsl:package>`
			resolved := false
			resolver := contractPackageResolver(func(context.Context, string, string) (io.ReadCloser, string, error) {
				resolved = true

				return io.NopCloser(strings.NewReader(library)), "", nil
			})
			_, err := NewCompiler().PackageResolver(resolver).Compile(t.Context(), parseTestDocument(t, app))
			if err == nil || !strings.Contains(err.Error(), errCodeXTSE0020) || resolved {
				t.Fatalf("compile error = %v, dependency resolved = %v", err, resolved)
			}
		})
	}
}
