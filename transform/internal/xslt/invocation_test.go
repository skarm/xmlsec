package xslt //nolint:testpackage // Checks entry validation and ensures invalid configurations never execute user code.

import (
	"errors"
	"strings"
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
