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
	"github.com/skarm/xmlsec/transform/internal/xpath"
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

func TestDecimalFormatImportPrecedenceIsPerProperty(t *testing.T) {
	t.Parallel()

	const opener = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">`
	const closer = `</xsl:stylesheet>`
	const lower = opener + `<xsl:decimal-format minus-sign="~" decimal-separator="," grouping-separator="."/>
		<xsl:decimal-format minus-sign="!"/>` + closer
	for _, tc := range []struct{ name, attributes, want, code string }{
		{"unrelated property keeps lower conflict", `infinity="infinite"`, "", errCodeXTSE1290},
		{"same property resolves conflict", `minus-sign="!"`, "!2,5", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
				if uri != "urn:unit:decimal-base" {
					return nil, fmt.Errorf("unexpected decimal format import %q", uri)
				}

				return io.NopCloser(strings.NewReader(lower)), nil
			})
			source := opener + `<xsl:import href="urn:unit:decimal-base"/><xsl:decimal-format ` + tc.attributes + `/>
				<xsl:output method="text"/><xsl:template name="start"><xsl:value-of select="format-number(-2.5, '0,0')"/></xsl:template>` + closer
			sheet, err := NewCompiler().URIResolver(resolver).Compile(t.Context(), parseTestDocument(t, source))
			if tc.code != "" {
				detail, ok := errors.AsType[*XSLTError](err)
				if sheet != nil || !ok || detail.Code != tc.code || !errors.Is(err, ErrStaticError) {
					t.Fatalf("compiled stylesheet = %t, error = %v, want static %s", sheet != nil, err, tc.code)
				}

				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := sheet.CallTemplate("start").Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestCharacterMapImportPrecedenceChoosesCompleteDeclaration(t *testing.T) {
	t.Parallel()

	const opener = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">`
	const closer = `</xsl:stylesheet>`
	const includes = `<xsl:include href="urn:unit:first"/><xsl:include href="urn:unit:second"/>`
	const higher = `<xsl:character-map name="common"><xsl:output-character character="A" string="higher"/></xsl:character-map>`
	modules := map[string]string{
		"urn:unit:first":   `<xsl:character-map name="common"><xsl:output-character character="A" string="first"/></xsl:character-map>`,
		"urn:unit:second":  `<xsl:character-map name="common"><xsl:output-character character="B" string="second"/></xsl:character-map>`,
		"urn:unit:pair":    includes,
		"urn:unit:missing": `<xsl:character-map name="common" use-character-maps="missing"/>`,
		"urn:unit:self":    `<xsl:character-map name="common" use-character-maps="common"/>`,
		"urn:unit:same":    `<xsl:character-map name="common"/><xsl:character-map name="common"/>`,
	}
	resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
		module, ok := modules[uri]
		if !ok {
			return nil, fmt.Errorf("unexpected character map module %q", uri)
		}

		return io.NopCloser(strings.NewReader(opener + module + closer)), nil
	})
	for _, tc := range []struct{ name, declarations, want, code string }{
		{"same precedence across includes", includes, "", errCodeXTSE1580},
		{"strictly higher map replaces both imported maps", `<xsl:import href="urn:unit:pair"/>` + higher, "higherB", ""},
		{"strictly higher map resolves same-module duplicate", `<xsl:import href="urn:unit:same"/>` + higher, "higherB", ""},
		{"lower reference resolves to higher map", `<xsl:import href="urn:unit:self"/>` + higher, "higherB", ""},
		{"undefined reference remains a static error in shadowed map", `<xsl:import href="urn:unit:missing"/>` + higher, "", errCodeXTSE1590},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			source := opener + tc.declarations + `<xsl:output method="text" use-character-maps="common"/>
				<xsl:template name="start"><xsl:text>AB</xsl:text></xsl:template>` + closer
			sheet, err := NewCompiler().URIResolver(resolver).Compile(t.Context(), parseTestDocument(t, source))
			if tc.code != "" {
				detail, ok := errors.AsType[*XSLTError](err)
				if sheet != nil || !ok || detail.Code != tc.code || !errors.Is(err, ErrStaticError) {
					t.Fatalf("compiled stylesheet = %t, error = %v, want static %s", sheet != nil, err, tc.code)
				}

				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := sheet.CallTemplate("start").Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
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

func TestKeyResolvesCollationAgainstDeclarationBaseURI(t *testing.T) {
	t.Parallel()
	const declarations = `
		<xsl:key name="by-value" match="a" use="@v" xml:base="collation/" collation="codepoint"/>
		<xsl:key name="by-value" match="b" use="@v" collation="http://www.w3.org/2005/xpath-functions/collation/codepoint"/>`
	const body = `<xsl:value-of select="key('by-value', 'X') ! local-name(.)" separator="|"/>`
	compiler := NewCompiler().BaseURI("http://www.w3.org/2005/xpath-functions/test.xsl")
	ss, err := compiler.Compile(t.Context(), stylesheetDocument(t, declarations, body))
	if err != nil {
		t.Fatal(err)
	}
	source := parseTestDocument(t, `<r><a v="X"/><a v="x"/><b v="X"/></r>`)
	got, err := ss.Transform(source).Serialize(t.Context())
	requireSerialization(t, got, err, "a|b", "")
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
		{"undefined_character_map_before_cycle", `<xsl:character-map name="one" use-character-maps="two"/><xsl:character-map name="two" use-character-maps="one absent"/>`, "XTSE1590"},
		{"character_map_cycle_before_undefined_output_reference", `<xsl:character-map name="one" use-character-maps="two"/><xsl:character-map name="two" use-character-maps="one"/><xsl:output use-character-maps="absent"/>`, "XTSE1600"},
		{"undefined_output_character_map", `<xsl:output use-character-maps="absent"/>`, "XTSE1590"},
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

	t.Run("shared character maps use the caller work budget", func(t *testing.T) {
		t.Parallel()
		const maps = `
			<xsl:character-map name="shared"><xsl:output-character character="A" string="a"/></xsl:character-map>
			<xsl:character-map name="left" use-character-maps="shared"/>
			<xsl:character-map name="right" use-character-maps="shared"/>
			<xsl:character-map name="both" use-character-maps="left right"/>
			<xsl:output use-character-maps="both"/>`
		sheet := compileTestStylesheet(t, maps, `<xsl:text>A</xsl:text>`)
		got, err := sheet.Transform(parseTestDocument(t, "<r/>")).Serialize(t.Context())
		requireSerialization(t, got, err, "a", "")

		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		validator := compiler{stylesheet: sheet, invocation: t.Context()}
		for _, tc := range []struct {
			ctx  context.Context
			want error
		}{
			{xpath.WithBudget(t.Context(), 18, 100, 100, 32), nil},
			{xpath.WithBudget(t.Context(), 1, 100, 100, 32), xpath.ErrBudget},
			{canceled, context.Canceled},
		} {
			if err := validator.validateDeferredReferences(tc.ctx); !errors.Is(err, tc.want) {
				t.Errorf("character map validation returned %v; want %v", err, tc.want)
			}
		}
	})
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

	t.Run("inherited parameter document overrides direct properties", func(t *testing.T) {
		t.Parallel()
		source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">
			<xsl:output method="text" parameter-document="params.xml"/>
			<xsl:output item-separator=","/>
			<xsl:template match="/"><xsl:sequence select="(2,3)"/></xsl:template>
		</xsl:stylesheet>`
		var reads []*closeTrackingReader
		resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
			if uri != paramsURI {
				return nil, fmt.Errorf("unexpected parameter document URI %q", uri)
			}

			reader := &closeTrackingReader{reader: strings.NewReader(params)}
			reads = append(reads, reader)

			return reader, nil
		})
		sheet, err := NewCompiler().BaseURI("https://styles.example/main.xsl").URIResolver(resolver).Compile(t.Context(), parseTestDocument(t, source))
		if err != nil {
			t.Fatal(err)
		}

		if len(reads) != 2 || reads[0].closed != 1 || reads[1].closed != 1 {
			t.Fatalf("parameter document reads = %d; want two reads closed once each", len(reads))
		}

		got, err := sheet.Transform(parseTestDocument(t, "<r/>")).Serialize(t.Context())
		requireSerialization(t, got, err, "2|3", "")
	})
}

func TestCompileOutputMergesByProperty(t *testing.T) {
	t.Parallel()
	const prefix = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">`
	const importModule = `<xsl:import href="urn:base-output"/>`
	for _, tc := range []struct{ name, imported, declarations, want, code string }{
		{"omitted BOM keeps same-precedence value", "", `<xsl:output method="text" byte-order-mark="yes"/><xsl:output encoding="UTF-8"/>`, "\uFEFFhello", ""},
		{"omitted BOM keeps imported value", `<xsl:output method="text" byte-order-mark="yes"/>`, importModule + `<xsl:output encoding="UTF-8"/>`, "\uFEFFhello", ""},
		{"explicit false overrides imported value", `<xsl:output method="text" byte-order-mark="yes"/>`, importModule + `<xsl:output byte-order-mark="no"/>`, "hello", ""},
		{"unrelated declaration does not hide a conflict", "", `<xsl:output method="text"/><xsl:output encoding="UTF-8"/><xsl:output method="xml"/>`, "", "XTSE1560"},
		{"higher explicit value resolves a lower conflict", `<xsl:output method="text"/><xsl:output method="xml"/>`, importModule + `<xsl:output method="text"/>`, "hello", ""},
		{"unrelated higher value cannot resolve lower conflict", `<xsl:output method="text"/><xsl:output method="xml"/>`, importModule + `<xsl:output encoding="UTF-8"/>`, "", "XTSE1560"},
		{"additional scalar conflicts are errors", "", `<xsl:output media-type="text/a"/><xsl:output media-type="text/b"/>`, "", "XTSE1560"},
		{"equivalent booleans do not conflict", "", `<xsl:output method="text" indent="no"/><xsl:output indent="false"/>`, "hello", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
				if uri != "urn:base-output" || tc.imported == "" {
					return nil, fmt.Errorf("unexpected output import %q", uri)
				}

				return io.NopCloser(strings.NewReader(prefix + tc.imported + `</xsl:stylesheet>`)), nil
			})
			source := prefix + tc.declarations + `<xsl:template match="/"><xsl:text>hello</xsl:text></xsl:template></xsl:stylesheet>`
			sheet, err := NewCompiler().URIResolver(resolver).Compile(t.Context(), parseTestDocument(t, source))
			if tc.code != "" {
				detail, ok := errors.AsType[*XSLTError](err)
				if sheet != nil || !ok || detail.Code != tc.code {
					t.Fatalf("compiled stylesheet = %t, error = %v; want %s", sheet != nil, err, tc.code)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			got, err := sheet.Transform(parseTestDocument(t, "<r/>")).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestCompileNamedOutputUsesDeclarationNamespace(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, declaration, want, code string }{
		{"unbound prefix", `<xsl:output name="out:report" method="text"/>`, "", errCodeXTSE0280},
		{"unbound prefix from sibling", `<xsl:key xmlns:out="urn:other" name="key" match="r" use="@id"/><xsl:output name="out:report"/>`, "", errCodeXTSE0280},
		{"explicit empty name", `<xsl:output name=""/>`, "", errCodeXTSE0020},
		{"declaration prefix", `<xsl:output xmlns:out="urn:report" name=" out:report " method="text"/>`, "{urn:report}report", ""},
		{"expanded name", `<xsl:output name="Q{urn:report}report" method="text"/>`, "{urn:report}report", ""},
		{"unprefixed ignores default namespace", `<xsl:output xmlns="urn:other" name="report" method="text"/>`, "report", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sheet, err := NewCompiler().Compile(t.Context(), stylesheetDocument(t, tc.declaration, `<xsl:text>principal</xsl:text>`))
			if tc.code != "" {
				detail, ok := errors.AsType[*XSLTError](err)
				if sheet != nil || !ok || detail.Code != tc.code || !errors.Is(err, ErrStaticError) {
					t.Fatalf("compiled stylesheet = %t, error = %v, want static %s", sheet != nil, err, tc.code)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}
			if output := sheet.outputs[tc.want]; output == nil || output.Name != tc.want || output.Method != "text" {
				t.Fatalf("output definition %q = %+v, want named text output", tc.want, output)
			}
		})
	}
}

func TestCompileOutputItemSeparator(t *testing.T) {
	t.Parallel()
	const inherited = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="text" item-separator="%s"/></xsl:stylesheet>`
	for _, tc := range []struct {
		name, declarations, imported, want string
		absent                             bool
	}{
		{name: "omitted", declarations: `<xsl:output method="text"/>`, want: "2 3"},
		{name: "empty", declarations: `<xsl:output method="text" item-separator=""/>`, want: "23"},
		{name: "absent", declarations: `<xsl:output method="text" item-separator="#absent"/>`, want: "2 3", absent: true},
		{name: "adaptive absent", declarations: `<xsl:output method="adaptive" item-separator="#absent"/>`, want: "2\n3", absent: true},
		{name: "inherited separator", declarations: `<xsl:import href="common.xsl"/><xsl:output method="text"/>`, imported: "|", want: "2|3"},
		{name: "inherited absence", declarations: `<xsl:import href="common.xsl"/><xsl:output method="text"/>`, imported: "#absent", want: "2 3", absent: true},
		{name: "override imported separator with empty", declarations: `<xsl:import href="common.xsl"/><xsl:output method="text" item-separator=""/>`, imported: "|", want: "23"},
		{name: "override imported absence with empty", declarations: `<xsl:import href="common.xsl"/><xsl:output method="text" item-separator=""/>`, imported: "#absent", want: "23"},
		{name: "unset imported separator", declarations: `<xsl:import href="common.xsl"/><xsl:output item-separator="#absent"/><xsl:output method="text"/>`, imported: "|", want: "2 3", absent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
				if uri != "https://styles.example/common.xsl" {
					return nil, fmt.Errorf("unexpected stylesheet URI %q", uri)
				}
				return io.NopCloser(strings.NewReader(fmt.Sprintf(inherited, tc.imported))), nil
			})
			doc := parseTestDocument(t, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">`+tc.declarations+`<xsl:template match="/"><xsl:sequence select="(2,3)"/></xsl:template></xsl:stylesheet>`)
			ss, err := NewCompiler().BaseURI("https://styles.example/main.xsl").URIResolver(resolver).Compile(t.Context(), doc)
			if err != nil {
				t.Fatal(err)
			}
			if output := ss.DefaultOutputDef(); output.ItemSeparatorAbsent != tc.absent {
				t.Errorf("explicit item-separator absence = %t, want %t", output.ItemSeparatorAbsent, tc.absent)
			}
			got, err := ss.Transform(parseTestDocument(t, "<r/>")).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestCompileOutputItemSeparatorProfiles(t *testing.T) {
	t.Parallel()
	const source = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="%s"><xsl:output method="text" item-separator="#absent"/><xsl:template match="/">text</xsl:template></xsl:stylesheet>`
	for _, version := range []string{"1.0", "2.0"} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()
			ss, err := NewCompiler().Compile(t.Context(), parseTestDocument(t, fmt.Sprintf(source, version)))
			detail, ok := errors.AsType[*XSLTError](err)
			if ss != nil || !ok || detail.Code != "XTSE0090" {
				t.Errorf("Compile returned stylesheet=%t, error=%v, want unavailable attribute error XTSE0090", ss != nil, err)
			}
		})
	}
}

func TestReviewDeclarationNamesTrimXMLWhitespace(t *testing.T) {
	for _, tc := range []struct{ name, declarations, body, want string }{
		{"key", `<xsl:key name=" by-id " match="r" use="@id"/>`, `<xsl:value-of select="count(key('by-id','a'))"/>`, "1"},
		{"attribute set", `<xsl:attribute-set name=" attrs "><xsl:attribute name="value" select="'ok'"/></xsl:attribute-set>`, `<xsl:variable name="r" as="element()"><out xsl:use-attribute-sets="attrs"/></xsl:variable><xsl:value-of select="$r/@value"/>`, "ok"},
		{"character map", `<xsl:character-map name=" chars "><xsl:output-character character="A" string="B"/></xsl:character-map><xsl:output use-character-maps="chars"/>`, `<xsl:text>A</xsl:text>`, "B"},
		{"namespace alias", `<xsl:namespace-alias xmlns:s="urn:source" xmlns:r="urn:result" stylesheet-prefix=" s " result-prefix=" r "/>`, `<xsl:variable name="r" as="element()"><s:out xmlns:s="urn:source"/></xsl:variable><xsl:value-of select="namespace-uri($r)"/>`, "urn:result"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss, err := NewCompiler().Compile(t.Context(), stylesheetDocument(t, tc.declarations, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ss.Transform(parseTestDocument(t, `<r id="a"/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}
