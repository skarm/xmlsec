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

func TestIncludeUsesItsOwnExpandText(t *testing.T) {
	t.Parallel()
	const stylesheet = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"`
	for _, tc := range []struct{ name, principal, included, want string }{
		{"principal yes and included default", ` expand-text="yes"`, "", `before 2|included {3 + 4}|after 11`},
		{"principal default and included yes", "", ` expand-text="yes"`, `before {1 + 1}|included 7|after {5 + 6}`},
		{"included explicit no", ` expand-text="yes"`, ` expand-text="no"`, `before 2|included {3 + 4}|after 11`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			principal := stylesheet + tc.principal + `>
				<xsl:include href="module.xsl"/><xsl:output method="text"/>
				<xsl:template match="/"><xsl:text>before {1 + 1}|</xsl:text><xsl:call-template name="label"/><xsl:text>|after {5 + 6}</xsl:text></xsl:template>
			</xsl:stylesheet>`
			included := stylesheet + tc.included + `>
				<xsl:template name="label"><xsl:text>included {3 + 4}</xsl:text></xsl:template>
			</xsl:stylesheet>`
			resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
				if uri != "https://example.test/module.xsl" {
					t.Errorf("unexpected stylesheet URI %q", uri)
					return nil, errors.New("module not in fixture")
				}
				return io.NopCloser(strings.NewReader(included)), nil
			})
			ss, err := NewCompiler().BaseURI("https://example.test/main.xsl").URIResolver(resolver).
				Compile(t.Context(), parseTestDocument(t, principal))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestCompileModulesRejectPackageManifests(t *testing.T) {
	t.Parallel()

	const ns = `xmlns:xsl="http://www.w3.org/1999/XSL/Transform"`
	const module = `<xsl:stylesheet ` + ns + ` version="3.0" xml:id="module">
		<xsl:template match="/" priority="1">module</xsl:template>
	</xsl:stylesheet>`
	const manifest = `<xsl:package ` + ns + ` name="urn:unit:package" version="3.0" xml:id="module">
		<xsl:template match="/" priority="1">manifest</xsl:template>
	</xsl:package>`
	const simplified = `<document ` + ns + ` xsl:version="3.0">module</document>`
	const fragmentSimplified = `<wrapper><document ` + ns + ` xml:id="module" xsl:version="3.0">module</document></wrapper>`
	const fragmentTemplate = `<wrapper><xsl:template ` + ns + ` xml:id="module" match="/"/></wrapper>`
	const fragmentVersionless = `<wrapper><xsl:stylesheet ` + ns + ` xml:id="module"/></wrapper>`
	const fragmentInvalidVersion = `<wrapper><xsl:stylesheet ` + ns + ` xml:id="module" version="latest"/></wrapper>`
	const fragmentShadowVersion = `<wrapper><xsl:stylesheet ` + ns + ` xml:id="module" _version="{'3.0'}">
		<xsl:template match="/" priority="1">module</xsl:template>
	</xsl:stylesheet></wrapper>`
	const moduleURI = "https://example.test/module.xsl"
	for _, test := range []struct{ name, edge, source, fragment, code string }{
		{"standard module", "include", module, "", ""},
		{"simplified module", "include", simplified, "", ""},
		{"fragment-selected standard module", "include", "<wrapper>" + module + "</wrapper>", "#module", ""},
		{"fragment-selected standard import", "import", "<wrapper>" + module + "</wrapper>", "#module", ""},
		{"fragment-selected simplified module", "include", fragmentSimplified, "#module", ""},
		{"fragment-selected simplified import", "import", fragmentSimplified, "#module", ""},
		{"fragment-selected module with shadow version", "include", fragmentShadowVersion, "#module", ""},
		{"fragment-selected import with shadow version", "import", fragmentShadowVersion, "#module", ""},
		{"fragment-selected template is not a module", "include", fragmentTemplate, "#module", errCodeXTSE0165},
		{"fragment-selected template is not an import", "import", fragmentTemplate, "#module", errCodeXTSE0165},
		{"fragment-selected module requires version", "include", fragmentVersionless, "#module", errCodeXTSE0010},
		{"fragment-selected import requires version", "import", fragmentVersionless, "#module", errCodeXTSE0010},
		{"fragment-selected version must be numeric", "include", fragmentInvalidVersion, "#module", errCodeXTSE0110},
		{"fragment-selected import version must be numeric", "import", fragmentInvalidVersion, "#module", errCodeXTSE0110},
		{"included manifest", "include", manifest, "", errCodeXTSE0165},
		{"fragment-selected manifest", "include", "<wrapper>" + manifest + "</wrapper>", "#module", errCodeXTSE0165},
		{"imported manifest", "import", manifest, "", errCodeXTSE0165},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			body, want := "principal", "module"
			if test.edge == "import" {
				body += `<xsl:apply-imports/>`
				want = "principalmodule"
			}

			principal := `<xsl:stylesheet ` + ns + ` version="3.0">
				<xsl:` + test.edge + ` href="module.xsl` + test.fragment + `"/><xsl:output method="text"/>
				<xsl:template match="/" priority="-1">` + body + `</xsl:template>
			</xsl:stylesheet>`
			reader := &closeTrackingReader{reader: strings.NewReader(test.source)}
			var calls int

			resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
				calls++
				if uri != moduleURI || calls != 1 {
					t.Errorf("module request %d: %q, want one %q", calls, uri, moduleURI)

					return nil, errors.New("unexpected module request")
				}

				return reader, nil
			})
			ss, err := NewCompiler().BaseURI("https://example.test/main.xsl").URIResolver(resolver).
				Compile(t.Context(), parseTestDocument(t, principal))
			if calls != 1 || reader.closed != 1 {
				t.Errorf("module opens/closes = %d/%d, want 1/1", calls, reader.closed)
			}

			if test.code != "" {
				detail, ok := errors.AsType[*XSLTError](err)
				if ss != nil || !ok || detail.Code != test.code {
					t.Errorf("compiled stylesheet = %t, error = %v, want no stylesheet and %s", ss != nil, err, test.code)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, want, "")
		})
	}
}

func TestReviewFunctionUsesDeclarationStaticBase(t *testing.T) {
	const module = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:functions" version="3.0"><xsl:function name="f:base"><xsl:sequence select="static-base-uri()"/></xsl:function></xsl:stylesheet>`
	for _, tc := range []struct{ name, declarations, callerBase, want string }{
		{"import module", `<xsl:import href="lib/module.xsl"/>`, "", "https://example.test/lib/module.xsl"},
		{"caller override", `<xsl:function name="f:base"><xsl:sequence select="static-base-uri()"/></xsl:function>`, ` xml:base="https://example.test/caller/"`, "https://example.test/main.xsl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:functions" version="3.0">` + tc.declarations + `<xsl:output method="text"/><xsl:template match="/"><xsl:value-of` + tc.callerBase + ` select="f:base()"/></xsl:template></xsl:stylesheet>`
			resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
				if uri != "https://example.test/lib/module.xsl" {
					t.Fatalf("unexpected URI %q", uri)
				}
				return io.NopCloser(strings.NewReader(module)), nil
			})
			ss, err := NewCompiler().BaseURI("https://example.test/main.xsl").URIResolver(resolver).Compile(t.Context(), parseTestDocument(t, source))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestReviewCompilerClosesReaderReturnedWithError(t *testing.T) {
	for _, kind := range []string{"include", "package", "parameter document"} {
		t.Run(kind, func(t *testing.T) {
			reader := &closeTrackingReader{reader: strings.NewReader("")}
			sentinel := errors.New("resource failed after opening")
			compiler := NewCompiler().BaseURI("https://example.test/main.xsl")
			source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:include href="module.xsl"/></xsl:stylesheet>`
			if kind != "package" {
				if kind == "parameter document" {
					source = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output parameter-document="params.xml"/></xsl:stylesheet>`
				}
				compiler = compiler.URIResolver(contractURIResolver(func(context.Context, string) (io.ReadCloser, error) { return reader, sentinel }))
			} else {
				source = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0" name="urn:app"><xsl:use-package name="urn:lib"/></xsl:package>`
				compiler = compiler.PackageResolver(contractPackageResolver(func(context.Context, string, string) (io.ReadCloser, string, error) { return reader, "", sentinel }))
			}
			_, err := compiler.Compile(t.Context(), parseTestDocument(t, source))
			if !errors.Is(err, sentinel) {
				t.Errorf("error %v does not preserve original", err)
			}
			if reader.closed != 1 {
				t.Errorf("reader closed %d times, want once", reader.closed)
			}
		})
	}
}
