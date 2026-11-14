package xslt //nolint:testpackage // Checks entry validation and ensures invalid configurations never execute user code.

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestInvocationRejectsUnconfiguredStylesheet(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		invocation Invocation
		wantErr    error
	}{
		{"zero invocation", Invocation{}, errZeroInvocation},
		{"nil stylesheet", newInvocation(nil, invocationTransform), errNilStylesheet},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := test.invocation.Serialize(t.Context())
			if got != "" || !errors.Is(err, test.wantErr) {
				t.Fatalf("unconfigured entry = %q, %v; want %v", got, err, test.wantErr)
			}
		})
	}
}

func TestInvocationRejectsIncompatibleEntryOptions(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, `<xsl:template name="start"><xsl:message select="'executed'"/><xsl:text>named</xsl:text></xsl:template><xsl:function name="f:entry" visibility="public"><xsl:sequence select="'function'"/></xsl:function>`, `<xsl:message select="'executed'"/><xsl:text>matched</xsl:text>`)
	source := parseTestDocument(t, `<r/>`)
	selection := xdm.ItemSlice{}
	parameter := xdm.SingleString("argument")
	for _, test := range []struct {
		name string
		inv  Invocation
		hint string
	}{
		{"transform explicit empty selection", ss.Transform(source).Selection(selection), "Selection"},
		{"transform template parameter", ss.Transform(source).SetInitialTemplateParameter("p", parameter), "SetInitialTemplateParameter"},
		{"apply template parameter", ss.ApplyTemplates(source).SetInitialTemplateParameter("p", parameter), "SetInitialTemplateParameter"},
		{"empty template name", ss.CallTemplate(""), "template name"},
		{"named template mode", ss.CallTemplate("start").Mode("m"), "Mode"},
		{"named template selection", ss.CallTemplate("start").Selection(selection), "Selection"},
		{"named template mode parameter", ss.CallTemplate("start").SetInitialModeParameter("p", parameter), "SetInitialModeParameter"},
		{"empty function name", ss.CallFunction(""), "function name"},
		{"function mode", ss.CallFunction("Q{urn:unit}entry").Mode("m"), "Mode"},
		{"function selection", ss.CallFunction("Q{urn:unit}entry").Selection(selection), "Selection"},
		{"function template parameter", ss.CallFunction("Q{urn:unit}entry").SetInitialTemplateParameter("p", parameter), "SetInitialTemplateParameter"},
		{"function mode parameter", ss.CallFunction("Q{urn:unit}entry").SetInitialModeParameter("p", parameter), "SetInitialModeParameter"},
		{"function tunnel parameter", ss.CallFunction("Q{urn:unit}entry").SetTunnelParameter("p", parameter), "TunnelParameters"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler := &recordingMessageHandler{}
			inv := test.inv
			if inv.cfg != nil {
				inv = inv.MessageHandler(handler)
			}
			got, err := inv.Serialize(t.Context())
			if got != "" || err == nil || !strings.Contains(err.Error(), test.hint) || handler.calls != 0 {
				t.Fatalf("invalid entry = %q, %v, user callbacks=%d; want validation containing %q", got, err, handler.calls, test.hint)
			}
		})
	}
	for _, test := range []struct {
		inv  Invocation
		want string
	}{
		{ss.Transform(source), "matched"},
		{ss.ApplyTemplates(source), "matched"},
		{ss.CallTemplate("start"), "named"},
		{ss.CallFunction("Q{urn:unit}entry"), "function"},
	} {
		if got, err := test.inv.Serialize(t.Context()); err != nil || got != test.want {
			t.Fatalf("valid entry = %q, %v; want %q", got, err, test.want)
		}
	}
}

func TestInvocationDeliversDistinctResultDocuments(t *testing.T) {
	t.Parallel()
	const base = "https://output.example/jobs/main"
	const summaryURI = "https://output.example/jobs/reports/summary"
	const auditURI = "https://output.example/jobs/audit.json"
	ss := compileTestStylesheet(t, `<xsl:output name="summary" method="text" item-separator="|"/>`, `
		<xsl:value-of select="current-output-uri()"/>
		<xsl:result-document href="reports/summary" format="summary">
			<xsl:sequence select="(1,2,current-output-uri())"/>
		</xsl:result-document>
		<xsl:result-document href="audit.json" method="json" indent="no">
			<xsl:sequence select="[true(), 3]"/>
		</xsl:result-document>`)
	inv := ss.Transform(parseTestDocument(t, `<r/>`)).BaseOutputURI(base)
	result, err := inv.Execute(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Secondary) != 2 {
		t.Fatalf("secondary output count = %d, want 2", len(result.Secondary))
	}
	for _, tc := range []struct {
		name   string
		result ValueResult
		method string
		want   string
	}{
		{"primary", result.Primary, "text", base},
		{"summary", result.Secondary[summaryURI], "text", "1|2|" + summaryURI},
		{"audit", result.Secondary[auditURI], "json", "[true,3]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.result.Output == nil || tc.result.Output.Method != tc.method {
				t.Fatalf("output definition = %+v, want method %q", tc.result.Output, tc.method)
			}
			var output strings.Builder
			err := SerializeValue(t.Context(), &output, tc.result)
			requireSerialization(t, output.String(), err, tc.want, "")
		})
	}
}

func TestSerializationDeliveryMethods(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, declarations, body, want string
	}{
		{"xml_character_map_is_applied_to_text_and_attributes", `<xsl:output method="xml" omit-xml-declaration="yes" use-character-maps="m"/><xsl:character-map name="base"><xsl:output-character character="@" string="base"/><xsl:output-character character="+" string="plus"/></xsl:character-map><xsl:character-map name="m" use-character-maps="base"><xsl:output-character character="@" string="local"/></xsl:character-map>`, `<r id="@">@+</r>`, `<r id="local">localplus</r>`},
		{"html_void_elements_and_text_escaping", `<xsl:output method="html" version="4.01" indent="no" include-content-type="no"/>`, `<p><br/><span>&lt;&amp;</span></p>`, `<p><br><span>&lt;&amp;</span></p>`},
		{"xhtml_empty_element_spacing", `<xsl:output method="xhtml" version="1.0" omit-xml-declaration="yes" indent="no" include-content-type="no"/>`, `<p xmlns="http://www.w3.org/1999/xhtml"><br/><span/></p>`, `<p xmlns="http://www.w3.org/1999/xhtml"><br /><span></span></p>`},
		{"json_serializes_array_and_null", `<xsl:output method="json" indent="no"/>`, `<xsl:sequence select="[true(), (), 3.5, 'hello']"/>`, `[true,null,3.5,"hello"]`},
		{"adaptive_keeps_type_sensitive_quoting", `<xsl:output method="adaptive" item-separator="|"/>`, `<xsl:sequence select="(true(), 'text', 9)"/>`, `true()|"text"|9`},
		{"text_uses_item_separator", `<xsl:output method="text" item-separator="|"/>`, `<xsl:sequence select="(1,2,3)"/>`, "1|2|3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := parseTestDocument(t, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">`+tc.declarations+`<xsl:template match="/">`+tc.body+`</xsl:template></xsl:stylesheet>`)
			ss, err := NewCompiler().Compile(t.Context(), doc)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ss.Transform(parseTestDocument(t, `<source/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestResolvedOutputConcurrentSnapshotOwnership(t *testing.T) {
	t.Parallel()

	var state resolvedOutputState
	var workers sync.WaitGroup

	for range 8 {
		workers.Go(func() {
			for range 64 {
				separator := "original"
				def := &OutputDef{
					ResolvedCharMap:  map[rune]string{'x': "original"},
					UseCharacterMaps: []string{"original"},
					ItemSeparator:    &separator,
				}
				state.store(def)

				def.ResolvedCharMap['x'] = "changed input"
				def.UseCharacterMaps[0] = "changed input"
				separator = "changed input"

				snapshot := state.snapshot()
				if snapshot == nil || snapshot.ResolvedCharMap['x'] != "original" || len(snapshot.UseCharacterMaps) != 1 || snapshot.UseCharacterMaps[0] != "original" || snapshot.ItemSeparator == nil || *snapshot.ItemSeparator != "original" {
					t.Error("recorded output changed through another caller's input or snapshot")
					return
				}

				snapshot.ResolvedCharMap['x'] = "changed snapshot"
				snapshot.UseCharacterMaps[0] = "changed snapshot"
				*snapshot.ItemSeparator = "changed snapshot"
			}
		})
	}

	workers.Wait()

	snapshot := state.snapshot()
	if snapshot.ResolvedCharMap['x'] != "original" || snapshot.UseCharacterMaps[0] != "original" || *snapshot.ItemSeparator != "original" {
		t.Fatal("recorded output retained mutable snapshot storage")
	}
}
