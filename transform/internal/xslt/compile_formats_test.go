package xslt //nolint:testpackage // Exercises decimal and whitespace declarations in the internal compiler.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestDecimalFormatsMergePropertiesByExpandedName(t *testing.T) {
	t.Parallel()
	const declarations = `
		<xsl:decimal-format name="f:localized" decimal-separator="," grouping-separator="." zero-digit="٠"/>
		<xsl:decimal-format xmlns:other="urn:unit" name="other:localized" minus-sign="−" infinity="∞" NaN="not numeric" percent="٪" per-mille="‰"/>
		<xsl:decimal-format decimal-separator="·"/>`
	const body = `<xsl:value-of separator="|" select="(
		format-number(-1234.5, '#.##٠,٠٠', 'f:localized'),
		format-number(0.125, '٠,٠٪', 'f:localized'),
		format-number(0.125, '٠‰', 'f:localized'),
		format-number(xs:double('INF'), '٠', 'f:localized'),
		format-number(xs:double('NaN'), '٠', 'f:localized'),
		format-number(1.25, '0·00'))"/>`
	ss := compileTestStylesheet(t, declarations, body)
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "−١.٢٣٤,٥٠|١٢,٥٪|١٢٥‰|∞|not numeric|1·25", "")
}

func TestWhitespaceRulesUseExpandedNamesAndSpecificity(t *testing.T) {
	t.Parallel()
	const declarations = `
		<xsl:strip-space elements="*"/>
		<xsl:preserve-space elements="s:*" xmlns:s="urn:preserve"/>
		<xsl:strip-space elements="Q{urn:preserve}strip"/>
		<xsl:preserve-space elements="*:keep"/>
		<xsl:strip-space elements="discard" xpath-default-namespace="urn:preserve"/>`
	const body = `<xsl:value-of select="r/* ! (local-name(.) || ':' || count(text()))" separator="|"/>`
	const source = `<r xmlns:q="urn:preserve" xmlns:p="urn:other"><q:ordinary> </q:ordinary><q:strip> </q:strip><p:keep> </p:keep><q:discard> </q:discard><p:ordinary> </p:ordinary><p:keep>text</p:keep></r>`
	got, err := compileTestStylesheet(t, declarations, body).Transform(parseTestDocument(t, source)).Serialize(t.Context())
	requireSerialization(t, got, err, "ordinary:1|strip:0|keep:1|discard:0|ordinary:0|keep:1", "")
}

func TestCompileFormatDeclarationErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, declaration, code string }{
		{"decimal_separator_requires_one_character", `<xsl:decimal-format decimal-separator="::"/>`, "XTSE0020"},
		{"zero_digit_must_start_a_digit_family", `<xsl:decimal-format zero-digit="١"/>`, "XTSE1295"},
		{"decimal_symbols_must_be_distinct", `<xsl:decimal-format decimal-separator=","/>`, "XTSE1300"},
		{"same_precedence_decimal_formats_cannot_conflict", `<xsl:decimal-format name="f:d" minus-sign="−"/><xsl:decimal-format name="f:d" minus-sign="~"/>`, "XTSE1290"},
		{"decimal_format_requires_declared_prefix", `<xsl:decimal-format name="missing:d"/>`, "XTSE0280"},
		{"whitespace_rule_requires_declared_prefix", `<xsl:strip-space elements="missing:*"/>`, "XTSE0280"},
		{"whitespace_rule_requires_elements", `<xsl:preserve-space/>`, "XTSE0010"},
		{"character_map_requires_one_code_point", `<xsl:character-map name="f:c"><xsl:output-character character="ab" string="x"/></xsl:character-map>`, "XTSE0020"},
		{"attribute_set_requires_referenced_set", `<xsl:attribute-set name="first" use-attribute-sets="missing"/>`, "XTSE0710"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss, err := NewCompiler().Compile(t.Context(), stylesheetDocument(t, tc.declaration, `unreachable`))
			var detail *XSLTError
			if ss != nil || !errors.As(err, &detail) || detail.Code != tc.code {
				t.Errorf("Compile returned stylesheet=%t, error=%v, want no stylesheet and %s", ss != nil, err, tc.code)
			}
		})
	}
}

func TestCompileOutputAppliesSerializationParameterDocument(t *testing.T) {
	t.Parallel()

	const paramsURI = "https://styles.example/params.xml"
	const params = `<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><method value="text"/><item-separator value="|"/><encoding value="UTF-8"/><media-type value="text/plain"/></serialization-parameters>`
	const source = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="text" item-separator="," parameter-document="params.xml"/><xsl:template match="/"><xsl:sequence select="(2,3)"/></xsl:template></xsl:stylesheet>`

	for _, tc := range []struct {
		name, contents, want, code string
		openErr                    error
	}{
		{"resolved_document_overrides_separator", params, "2|3", "", nil},
		{"missing_document_leaves_declared_separator", "", "2,3", "", fs.ErrNotExist},
		{"wrong_root_element", "<parameters/>", "", "SEPM0017", nil},
		{"malformed_document", "<parameters>", "", "SEPM0017", nil},
		{"resolver_failure_keeps_cause", "", "", "XTSE0090", io.ErrClosedPipe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reader := &closeTrackingReader{reader: strings.NewReader(tc.contents)}
			var opens int
			resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
				opens++
				if uri != paramsURI {
					return nil, fmt.Errorf("parameter document URI = %q, want %q", uri, paramsURI)
				}
				if tc.openErr != nil {
					return nil, tc.openErr
				}
				return reader, nil
			})
			ss, err := NewCompiler().BaseURI("https://styles.example/main.xsl").URIResolver(resolver).Compile(t.Context(), parseTestDocument(t, source))
			if opens != 1 || tc.openErr == nil && reader.closed != 1 {
				t.Errorf("parameter document opens = %d, closes = %d", opens, reader.closed)
			}
			if tc.code != "" {
				static, isStatic := errors.AsType[*XSLTError](err)
				serialization, isSerialization := errors.AsType[*xdm.Error](err)
				matches := isStatic && static.Code == tc.code || isSerialization && serialization.Code == tc.code
				if ss != nil || !matches || tc.openErr != nil && !errors.Is(err, tc.openErr) {
					t.Errorf("Compile returned stylesheet=%t, error=%v, want no stylesheet and %s with cause %v", ss != nil, err, tc.code, tc.openErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			got, err := ss.Transform(parseTestDocument(t, "<r/>")).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}
