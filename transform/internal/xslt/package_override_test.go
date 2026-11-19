package xslt //nolint:testpackage // Exercises package overrides through the internal compiler and invocation.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestPackageOverrideBindsOriginalAndReplacement(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, library, override, body, want string }{
		{
			name: "function_original_uses_its_own_private_components",
			library: `<xsl:function name="p:prefix" as="xs:string"><xsl:sequence select="'library'"/></xsl:function>
				<xsl:function name="p:label" as="xs:string" visibility="public"><xsl:param name="suffix" as="xs:string"/><xsl:sequence select="p:prefix() || $suffix"/></xsl:function>
				<xsl:template name="p:report" visibility="public"><xsl:value-of select="p:label(':caller')"/></xsl:template>`,
			override: `<xsl:function name="p:label" as="xs:string"><xsl:param name="suffix" as="xs:string"/><xsl:sequence select="xsl:original($suffix) || ':app'"/></xsl:function>`,
			body:     `<xsl:call-template name="p:report"/><xsl:value-of select="'|' || p:label(':direct')"/>`,
			want:     "library:caller:app|library:direct:app",
		},
		{
			name:     "function_new_each_time_true_matches_the_default",
			library:  `<xsl:function name="p:label" visibility="public"><xsl:sequence select="'original'"/></xsl:function>`,
			override: `<xsl:function name="p:label" new-each-time="true"><xsl:sequence select="'replacement'"/></xsl:function>`,
			body:     `<xsl:value-of select="p:label()"/>`,
			want:     "replacement",
		},
		{
			name:     "function_new_each_time_numeric_true_matches_yes",
			library:  `<xsl:function name="p:label" visibility="public" new-each-time="1"><xsl:sequence select="'original'"/></xsl:function>`,
			override: `<xsl:function name="p:label" new-each-time="yes"><xsl:sequence select="'replacement'"/></xsl:function>`,
			body:     `<xsl:value-of select="p:label()"/>`,
			want:     "replacement",
		},
		{
			name:     "function_new_each_time_false_matches_numeric_false",
			library:  `<xsl:function name="p:label" visibility="public" new-each-time="false"><xsl:sequence select="'original'"/></xsl:function>`,
			override: `<xsl:function name="p:label" new-each-time="0"><xsl:sequence select="'replacement'"/></xsl:function>`,
			body:     `<xsl:value-of select="p:label()"/>`,
			want:     "replacement",
		},
		{
			name: "template_original_receives_override_argument",
			library: `<xsl:template name="p:label" visibility="public"><xsl:param name="value" as="xs:integer" required="yes"/><xsl:value-of select="'base:' || $value"/></xsl:template>
				<xsl:template name="p:report" visibility="public"><xsl:call-template name="p:label"><xsl:with-param name="value" select="2"/></xsl:call-template></xsl:template>`,
			override: `<xsl:template name="p:label"><xsl:param name="value" as="xs:integer" required="yes"/><xsl:text>app:</xsl:text><xsl:call-template name="xsl:original"><xsl:with-param name="value" select="$value + 1"/></xsl:call-template></xsl:template>`,
			body:     `<xsl:call-template name="p:report"/>`,
			want:     "app:base:3",
		},
		{
			name: "global_original_remains_distinct_from_replacement",
			library: `<xsl:variable name="p:value" as="xs:integer" visibility="public" select="8"/>
				<xsl:template name="p:report" visibility="public"><xsl:value-of select="$p:value"/></xsl:template>`,
			override: `<xsl:param name="p:value" as="xs:integer" select="$xsl:original * 2"/>`,
			body:     `<xsl:call-template name="p:report"/><xsl:value-of select="'|' || $p:value"/>`,
			want:     "16|16",
		},
		{
			name: "abstract_attribute_set_filled_by_app",
			library: `<xsl:attribute-set name="p:attributes" visibility="abstract"/>
				<xsl:template name="p:report" visibility="public"><xsl:element name="r" use-attribute-sets="p:attributes"/></xsl:template>`,
			override: `<xsl:attribute-set name="p:attributes"><xsl:attribute name="value" select="'from app'"/></xsl:attribute-set>`,
			body:     `<xsl:variable name="report" as="element()"><xsl:call-template name="p:report"/></xsl:variable><xsl:value-of select="$report/@value"/>`,
			want:     "from app",
		},
		{
			name: "mode_override_runs_before_original_rule",
			library: `<xsl:mode name="p:report" visibility="public"/>
				<xsl:template match="r" mode="p:report" priority="100"><xsl:text>base</xsl:text></xsl:template>`,
			override: `<xsl:template match="r" mode="p:report" priority="-10"><xsl:text>app:</xsl:text><xsl:next-match/></xsl:template>`,
			body:     `<xsl:apply-templates select="parse-xml('&lt;r/>')/r" mode="p:report"/>`,
			want:     "app:base",
		},
		{
			name: "mode_override_retains_all_mode_rules_in_declaring_package",
			library: `<xsl:mode name="p:report" visibility="public"/>
				<xsl:mode name="p:other" visibility="public"/>
				<xsl:template match="r" mode="#all" priority="100"><xsl:text>base</xsl:text></xsl:template>`,
			override: `<xsl:template match="r" mode="p:report"><xsl:text>first:</xsl:text><xsl:next-match/></xsl:template>
				<xsl:template match="r" mode="p:report"><xsl:text>second:</xsl:text><xsl:next-match/></xsl:template>`,
			body: `<xsl:variable name="input" select="parse-xml('&lt;r/>')/r"/>
				<xsl:apply-templates select="$input" mode="p:report"/><xsl:text>|</xsl:text>
				<xsl:apply-templates select="$input" mode="p:other"/>`,
			want: "second:first:base|base",
		},
		{
			name:     "inactive_override_does_not_replace_original",
			library:  `<xsl:template name="p:report" visibility="public"><xsl:text>base</xsl:text></xsl:template>`,
			override: `<xsl:template name="p:report" use-when="false()"><xsl:text>unused</xsl:text></xsl:template>`,
			body:     `<xsl:call-template name="p:report"/>`,
			want:     "base",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sheet, err := compilePackageOverrideFixture(t, tc.library, tc.override, tc.body)
			if err != nil {
				t.Fatal(err)
			}
			got, err := sheet.CallTemplate("start").Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestPackageOverrideRejectsIncompatibleComponents(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, library, override, code string }{
		{"final_function", `<xsl:function name="p:f" visibility="final"/>`, `<xsl:function name="p:f"/>`, "XTSE3060"},
		{"final_template", `<xsl:template name="p:t" visibility="final"/>`, `<xsl:template name="p:t"/>`, "XTSE3060"},
		{"final_variable", `<xsl:variable name="p:v" visibility="final" select="1"/>`, `<xsl:variable name="p:v" select="2"/>`, "XTSE3060"},
		{"final_attribute_set", `<xsl:attribute-set name="p:a" visibility="final"/>`, `<xsl:attribute-set name="p:a"/>`, "XTSE3060"},
		{"private_mode", `<xsl:mode name="p:m" visibility="private"/>`, `<xsl:template match="r" mode="p:m"/>`, "XTSE3060"},
		{"unnamed_mode", `<xsl:mode/>`, `<xsl:template match="r"/>`, "XTSE3440"},
		{"missing_function_arity", `<xsl:function name="p:f" visibility="public"><xsl:param name="value"/></xsl:function>`, `<xsl:function name="p:f"/>`, "XTSE3058"},
		{"missing_attribute_set", "", `<xsl:attribute-set name="p:missing"/>`, "XTSE3058"},
		{"incompatible_function_parameter", `<xsl:function name="p:f" visibility="public"><xsl:param name="value" as="xs:integer"/></xsl:function>`, `<xsl:function name="p:f"><xsl:param name="value" as="xs:string"/></xsl:function>`, "XTSE3070"},
		{"function_new_each_time_maybe_differs_from_the_default", `<xsl:function name="p:f" visibility="public"/>`, `<xsl:function name="p:f" new-each-time="maybe"/>`, "XTSE3070"},
		{"incompatible_template_parameter", `<xsl:template name="p:t" visibility="public"><xsl:param name="value" required="yes"/></xsl:template>`, `<xsl:template name="p:t"><xsl:param name="value"/></xsl:template>`, "XTSE3070"},
		{"incompatible_global_type", `<xsl:variable name="p:v" as="xs:integer" visibility="public" select="1"/>`, `<xsl:param name="p:v" as="xs:string" select="'text'"/>`, "XTSE3070"},
		{"abstract_global_has_no_original_value", `<xsl:variable name="p:v" as="xs:integer" visibility="abstract"/>`, `<xsl:variable name="p:v" as="xs:integer" select="$xsl:original"/>`, "XTSE3075"},
		{"duplicate_function_override", `<xsl:function name="p:f" visibility="public"/>`, `<xsl:function name="p:f"/><xsl:function name="p:f"/>`, "XTSE0770"},
		{"non_xslt_override_component", "", `<p:unexpected/>`, "XTSE0010"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sheet, err := compilePackageOverrideFixture(t, tc.library, tc.override, "")
			var detail *XSLTError
			if sheet != nil || !errors.As(err, &detail) || detail.Code != tc.code {
				t.Fatalf("compile returned stylesheet=%t, error=%v, want nil and %s", sheet != nil, err, tc.code)
			}
		})
	}
}

func compilePackageOverrideFixture(t *testing.T, library, override, body string) (*Stylesheet, error) {
	t.Helper()
	const packageOpen = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:p="urn:unit:components" version="3.0" package-version="1.0"`
	reader := &closeTrackingReader{reader: strings.NewReader(packageOpen + ` name="urn:unit:library">` + library + `</xsl:package>`)}
	var opens int
	resolver := contractPackageResolver(func(_ context.Context, name, version string) (io.ReadCloser, string, error) {
		opens++
		if name != "urn:unit:library" || version != "1.0" || opens != 1 {
			return nil, "", fmt.Errorf("unexpected package request %d: %q version %q", opens, name, version)
		}
		return reader, "https://styles.example/unit/library.xsl", nil
	})
	app := packageOpen + ` name="urn:unit:app">
		<xsl:use-package name="urn:unit:library" package-version="1.0"><xsl:override>` + override + `</xsl:override></xsl:use-package>
		<xsl:output method="text"/><xsl:template name="start" visibility="public">` + body + `</xsl:template></xsl:package>`
	sheet, err := NewCompiler().PackageResolver(resolver).Compile(t.Context(), parseTestDocument(t, app))
	if opens != 1 || reader.closed != 1 {
		t.Errorf("library opened %d times and closed %d times, want one open and close", opens, reader.closed)
	}
	return sheet, err
}
