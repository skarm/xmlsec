package xslt //nolint:testpackage // Exercises package retrieval and component visibility.

import (
	"context"
	"errors"
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

func TestCompileFunctionAttributeWhitespace(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, version, functionName, required, code string
		processor                                   int
	}{
		{name: "QName 3.0", version: "3.0", functionName: " f:echo ", processor: processorXSLT30},
		{name: "QName 2.0", version: "2.0", functionName: " f:echo ", processor: processorXSLT20},
		{name: "required true", version: "3.0", functionName: "f:echo", required: ` required=" 1 "`, processor: processorXSLT30},
		{name: "required false", version: "3.0", functionName: "f:echo", required: ` required=" 0 "`, code: errCodeXTSE0020, processor: processorXSLT30},
		{name: "required disallowed in 2.0", version: "2.0", functionName: "f:echo", required: ` required=" yes "`, code: errCodeXTSE0090, processor: processorXSLT20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stylesheet := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:unit" version="` + tc.version + `">
				<xsl:output method="text"/>
				<xsl:function name="` + tc.functionName + `"><xsl:param name="value"` + tc.required + `/><xsl:sequence select="$value"/></xsl:function>
				<xsl:template name="start"><xsl:sequence select="f:echo('ready')"/></xsl:template>
			</xsl:stylesheet>`
			ss, err := NewCompiler().ProcessorVersion(tc.processor).Compile(t.Context(), parseTestDocument(t, stylesheet))
			if tc.code != "" {
				if detail, ok := errors.AsType[*XSLTError](err); ss != nil || !ok || detail.Code != tc.code {
					t.Fatalf("Compile returned stylesheet=%t, error=%v, want no stylesheet and %s", ss != nil, err, tc.code)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			got, err := ss.CallTemplate("start").Serialize(t.Context())
			requireSerialization(t, got, err, "ready", "")
		})
	}
}

func TestCompilePackageOverrideFunctionDeclaration(t *testing.T) {
	t.Parallel()

	const library = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:unit" name="urn:library" version="3.0">
		<xsl:function name="f:echo" visibility="public"><xsl:param name="value"/><xsl:sequence select="'library'"/></xsl:function>
	</xsl:package>`
	for _, tc := range []struct{ name, functionName, contextItem, required, code string }{
		{name: "QName whitespace", functionName: " f:echo "},
		{name: "required true", functionName: "f:echo", required: ` required=" 1 "`},
		{name: "required false", functionName: "f:echo", required: ` required="no"`, code: errCodeXTSE0020},
		{name: "context item disallowed", functionName: "f:echo", contextItem: `<xsl:context-item use="absent"/>`, code: errCodeXTSE0010},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resolver := contractPackageResolver(func(_ context.Context, _, _ string) (io.ReadCloser, string, error) {
				return io.NopCloser(strings.NewReader(library)), "https://example.test/library.xsl", nil
			})
			app := `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:unit" name="urn:app" version="3.0">
				<xsl:use-package name="urn:library">
					<xsl:override><xsl:function name="` + tc.functionName + `">` + tc.contextItem + `<xsl:param name="value"` + tc.required + `/><xsl:sequence select="$value"/></xsl:function></xsl:override>
				</xsl:use-package>
				<xsl:output method="text"/>
				<xsl:template name="start" visibility="public"><xsl:sequence select="f:echo('ready')"/></xsl:template>
			</xsl:package>`
			ss, err := NewCompiler().PackageResolver(resolver).Compile(t.Context(), parseTestDocument(t, app))
			if tc.code != "" {
				if detail, ok := errors.AsType[*XSLTError](err); ss != nil || !ok || detail.Code != tc.code {
					t.Fatalf("Compile returned stylesheet=%t, error=%v, want no stylesheet and %s", ss != nil, err, tc.code)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			got, err := ss.CallTemplate("start").Serialize(t.Context())
			requireSerialization(t, got, err, "ready", "")
		})
	}
}

func TestCompilePackageKeepsOrdinaryRulesOutOfAcceptedModes(t *testing.T) {
	t.Parallel()

	const library = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:unit" name="urn:library" version="3.0">
		<xsl:mode name="f:show" visibility="public"/>
		<xsl:template match="item" mode="f:show">library</xsl:template>
	</xsl:package>`
	for _, tc := range []struct{ name, attrs, use, local, callMode, want, code string }{
		{name: "multiple modes", attrs: ` declared-modes="no"`, local: `<xsl:template match="item" mode="f:show local">ordinary</xsl:template>`, callMode: "f:show", code: errCodeXTSE3050},
		{name: "declared mode", local: `<xsl:template match="item" mode="f:show">ordinary</xsl:template>`, callMode: "f:show", code: errCodeXTSE3050},
		{name: "inherited default", attrs: ` default-mode="f:show"`, local: `<xsl:template match="item">ordinary</xsl:template>`, callMode: "f:show", code: errCodeXTSE3050},
		{name: "explicit default", attrs: ` declared-modes="no" default-mode="f:show"`, local: `<xsl:template match="item" mode="local #default">ordinary</xsl:template>`, callMode: "f:show", code: errCodeXTSE3050},
		{name: "local multiple modes", attrs: ` declared-modes="no"`, local: `<xsl:template match="item" mode="local other">ordinary</xsl:template>`, callMode: "local", want: "ordinary"},
		{name: "all leaves accepted rules alone", attrs: ` declared-modes="no"`, local: `<xsl:template match="item" mode="#all">ordinary</xsl:template>`, callMode: "f:show", want: "library"},
		{name: "valid override", use: `<xsl:override><xsl:template match="item" mode="f:show">override</xsl:template></xsl:override>`, callMode: "f:show", want: "override"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resolver := contractPackageResolver(func(_ context.Context, _, _ string) (io.ReadCloser, string, error) {
				return io.NopCloser(strings.NewReader(library)), "https://example.test/library.xsl", nil
			})
			app := `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:unit" name="urn:app" version="3.0"` + tc.attrs + `>
				<xsl:use-package name="urn:library">` + tc.use + `</xsl:use-package>
				<xsl:output method="text"/>
				` + tc.local + `
				<xsl:template name="start" visibility="public"><xsl:apply-templates select="parse-xml('&lt;item/>')/*" mode="` + tc.callMode + `"/></xsl:template>
			</xsl:package>`
			ss, err := NewCompiler().PackageResolver(resolver).Compile(t.Context(), parseTestDocument(t, app))
			if tc.code != "" {
				if detail, ok := errors.AsType[*XSLTError](err); ss != nil || !ok || detail.Code != tc.code {
					t.Fatalf("Compile returned stylesheet=%t, error=%v, want no stylesheet and %s", ss != nil, err, tc.code)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			got, err := ss.CallTemplate("start").Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
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

func TestCompileUsePackageRejectsHomonymousAcceptedAttributeSets(t *testing.T) {
	t.Parallel()
	const packageRoot = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:unit" version="3.0" name="urn:`
	for _, tc := range []struct{ name, firstRule, secondRule, want, code string }{
		{"both visible", "", "", "", errCodeXTSE3050},
		{"second hidden", "", `<xsl:accept component="attribute-set" names="f:attrs" visibility="hidden"/>`, "first", ""},
		{"first hidden", `<xsl:accept component="attribute-set" names="f:attrs" visibility="hidden"/>`, "", "second", ""},
		{"first overridden and second hidden", `<xsl:override><xsl:attribute-set name="f:attrs"><xsl:attribute name="origin" select="'override'"/></xsl:attribute-set></xsl:override>`, `<xsl:accept component="attribute-set" names="f:attrs" visibility="hidden"/>`, "override", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resolver := contractPackageResolver(func(_ context.Context, name, _ string) (io.ReadCloser, string, error) {
				origin := strings.TrimPrefix(name, "urn:")
				if origin != "first" && origin != "second" {
					t.Errorf("unexpected package name %q", name)
					return nil, "", errors.New("package not in fixture")
				}
				library := packageRoot + origin + `"><xsl:attribute-set name="f:attrs" visibility="public"><xsl:attribute name="origin" select="'` + origin + `'"/></xsl:attribute-set></xsl:package>`
				return io.NopCloser(strings.NewReader(library)), "https://example.test/" + origin + ".xsl", nil
			})
			app := packageRoot + `app">
				<xsl:use-package name="urn:first">` + tc.firstRule + `</xsl:use-package>
				<xsl:use-package name="urn:second">` + tc.secondRule + `</xsl:use-package>
				<xsl:output method="text"/>
				<xsl:template name="start" visibility="public"><xsl:variable name="node" as="element()"><out xsl:use-attribute-sets="f:attrs"/></xsl:variable><xsl:value-of select="$node/@origin"/></xsl:template>
			</xsl:package>`
			ss, err := NewCompiler().PackageResolver(resolver).Compile(t.Context(), parseTestDocument(t, app))
			if tc.code != "" {
				if xsltErr, ok := errors.AsType[*XSLTError](err); ss != nil || !ok || xsltErr.Code != tc.code {
					t.Fatalf("Compile returned stylesheet=%t, error=%v, want no stylesheet and %s", ss != nil, err, tc.code)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := ss.CallTemplate("start").Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestCompileUsePackageMatchesOverridesByExpandedName(t *testing.T) {
	t.Parallel()
	const packageRoot = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:unit" version="3.0" name="urn:`
	const library = packageRoot + `library">
		<xsl:template name="p:label" visibility="public">library</xsl:template>
		<xsl:template name="p:other" visibility="public">other</xsl:template>
		<xsl:mode name="p:report" visibility="public"/>
		<xsl:template match="r" mode="p:report">mode</xsl:template>
	</xsl:package>`
	const acceptLabel = `<xsl:accept component="template" names="p:label" visibility="private"/>`
	const overrideLabel = `<xsl:override><xsl:template xmlns:a="urn:unit" name="a:label">app</xsl:template></xsl:override>`
	const callLabel = `<xsl:call-template name="p:label"/>`
	const overrideRule = `<xsl:override><xsl:template match="p:label" mode="p:report">rule</xsl:template></xsl:override>`
	const applyRule = `<xsl:apply-templates select="parse-xml('&lt;p:label xmlns:p=&quot;urn:unit&quot;/>')/*" mode="p:report"/>`

	for _, tc := range []struct{ name, accept, override, body, want, code string }{
		{"same expanded name", acceptLabel, overrideLabel, callLabel, "", errCodeXTSE3051},
		{"namespaced wildcard", `<xsl:accept component="template" names="p:*" visibility="private"/>`, overrideLabel, callLabel + `<xsl:call-template name="p:other"/>`, "appother", ""},
		{"inactive declaration", acceptLabel, `<xsl:override><xsl:template xmlns:a="urn:unit" name="a:label" use-when="false()">unused</xsl:template></xsl:override>`, callLabel, "library", ""},
		{"unnamed rule", acceptLabel, overrideRule, callLabel + applyRule, "libraryrule", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resolver := contractPackageResolver(func(_ context.Context, name, _ string) (io.ReadCloser, string, error) {
				if name != "urn:library" {
					return nil, "", errors.New("unexpected package name " + name)
				}

				return io.NopCloser(strings.NewReader(library)), "https://example.test/library.xsl", nil
			})
			app := packageRoot + `app">
				<xsl:use-package name="urn:library">` + tc.accept + tc.override + `</xsl:use-package>
				<xsl:output method="text"/>
				<xsl:template name="start" visibility="public">` + tc.body + `</xsl:template>
			</xsl:package>`
			ss, err := NewCompiler().PackageResolver(resolver).Compile(t.Context(), parseTestDocument(t, app))
			if tc.code != "" {
				if detail, ok := errors.AsType[*XSLTError](err); ss != nil || !ok || detail.Code != tc.code {
					t.Fatalf("Compile returned stylesheet=%t, error=%v, want no stylesheet and %s", ss != nil, err, tc.code)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			got, err := ss.CallTemplate("start").Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}
