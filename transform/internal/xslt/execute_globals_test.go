package xslt //nolint:testpackage // Exercises stylesheet globals through the internal invocation API.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestGlobalBindingsUseDeclarationFocusAndDependencies(t *testing.T) {
	t.Parallel()
	const globals = `
		<xsl:param name="p" as="xs:integer" select="xs:integer(r/@base)"/>
		<xsl:variable name="doubled" as="xs:integer" select="$later * 2"/>
		<xsl:variable name="later" as="xs:integer" select="$p + count(r/item)"/>
		<xsl:variable name="caller" as="xs:string" select="name(r)"/>`
	const body = `<xsl:for-each select="r/item">
		<xsl:variable name="p" select="999"/>
		<xsl:value-of select="($doubled, $caller, string(.), $p)" separator=":"/>
		<xsl:text>;</xsl:text>
	</xsl:for-each>`
	ss := compileTestStylesheet(t, globals, body)
	for _, tc := range []struct {
		name, input, want string
		provided          xdm.Sequence
	}{
		{name: "parameter_default_uses_document_focus", input: `<r base="7"><item>A</item><item>B</item></r>`, want: "18:r:A:999;18:r:B:999;"},
		{name: "provided_parameter_overrides_default", input: `<r base="7"><item>A</item></r>`, provided: xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(4)}), want: "10:r:A:999;"},
		{name: "another_document_has_independent_globals", input: `<r base="2"><item>C</item></r>`, want: "6:r:C:999;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			inv := ss.Transform(parseTestDocument(t, tc.input))
			if tc.provided != nil {
				inv = inv.SetParameter("p", tc.provided)
			}
			got, err := inv.Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestGlobalConstructorsKeepTemporaryDocumentAndSequenceSemantics(t *testing.T) {
	t.Parallel()
	const globals = `
		<xsl:variable name="tree" xml:base="https://example.test/globals/">
			<xsl:sequence select="(1,2)"/><xsl:sequence select="3"/><n>node</n><xsl:sequence select="(4,5)"/>
		</xsl:variable>
		<xsl:variable name="typed" as="item()*"><xsl:sequence select="7"/><e/><xsl:sequence select="8"/></xsl:variable>
		<xsl:param name="default-tree"><xsl:sequence select="(6,7)"/><xsl:value-of select="r/@label"/></xsl:param>
		<xsl:param name="default-sequence" as="xs:integer*"><xsl:sequence select="(9,10)"/></xsl:param>
		<xsl:variable name="empty" as="xs:string?"/><xsl:variable name="empty-text"/>
		<xsl:param name="unset" as="xs:string?"/><xsl:param name="unset-text"/>`
	const body = `<xsl:value-of select="(
		$tree instance of document-node(), string($tree/text()[1]), string($tree/n), string($tree/text()[2]),
		base-uri($tree), empty(document-uri($tree)),
		count($typed), $typed[1] instance of xs:integer, name($typed[2]), $typed[3] instance of xs:integer,
		$default-tree instance of document-node(), string($default-tree), sum($default-sequence),
		empty($empty), $empty-text instance of xs:string, empty($unset), $unset-text instance of xs:string
	)" separator="|"/>`
	ss := compileTestStylesheet(t, globals, body)
	got, err := ss.Transform(parseTestDocument(t, `<r label="label"/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "true|1 2 3|node|4 5|https://example.test/globals/|true|3|true|e|true|true|6 7label|19|true|true|true|true", "")
}

func TestGlobalBindingErrorsReturnNoOutput(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, globals, body, code string
		parameter                 xdm.Sequence
	}{
		{name: "required_parameter_checked_even_if_unused", globals: `<xsl:param name="p" required="yes"/>`, body: `unreachable`, code: "XTDE0050"},
		{name: "parameter_override_must_match_declared_type", globals: `<xsl:param name="p" as="xs:integer" select="1"/>`, body: `<xsl:value-of select="$p"/>`, code: "XTTE0590", parameter: xdm.SingleString("wrong type")},
		{name: "variable_default_must_match_declared_type", globals: `<xsl:variable name="p" as="xs:integer" select="'wrong type'"/>`, body: `<xsl:value-of select="$p"/>`, code: "XTTE0570"},
		{name: "cycle_through_parameter_and_variable", globals: `<xsl:param name="p" select="$v"/><xsl:variable name="v" select="$p"/>`, body: `<xsl:value-of select="$p"/>`, code: "XTDE0640"},
		{name: "global_failure_is_outside_local_catch", globals: `<xsl:variable name="v" select="1 idiv 0"/>`, body: `<xsl:try><xsl:value-of select="$v"/><xsl:catch>unexpected catch</xsl:catch></xsl:try>`, code: "FOAR0001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, tc.globals, tc.body)
			inv := ss.Transform(parseTestDocument(t, `<r/>`))
			if tc.parameter != nil {
				inv = inv.SetParameter("p", tc.parameter)
			}
			got, err := inv.Serialize(t.Context())
			if tc.code == "FOAR0001" {
				if got != "" || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Errorf("serialized output = %q, error = %v; want no output and %s", got, err, tc.code)
				}
				return
			}
			requireSerialization(t, got, err, "", tc.code)
			if tc.code == "XTDE0640" && !errors.Is(err, ErrCircularRef) {
				t.Errorf("circular error lost its cause: %v", err)
			}
		})
	}
}

func TestGlobalContextItemIsIndependentOfTemplateFocus(t *testing.T) {
	t.Parallel()
	const globals = `
		<xsl:global-context-item use="required" as="xs:integer"/>
		<xsl:variable name="global" as="xs:integer" select="."/>
		<xsl:template name="start"><xsl:value-of select="$global"/></xsl:template>`
	ss := compileTestStylesheet(t, globals, `<xsl:for-each select="r/n"><xsl:value-of select="$global || ':' || string(.)"/></xsl:for-each>`)
	source := parseTestDocument(t, `<r><n>local</n></r>`)
	contextItem := xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(42)}
	for _, tc := range []struct {
		name       string
		invocation Invocation
		want, code string
	}{
		{"explicit_item_overrides_source_only_for_globals", ss.Transform(source).GlobalContextItem(contextItem), "42:local", ""},
		{"explicit_item_can_be_used_without_source", ss.CallTemplate("start").GlobalContextItem(contextItem), "42", ""},
		{"missing_required_context_item", ss.CallTemplate("start"), "", "XTDE3086"},
		{"default_document_context_has_wrong_type", ss.Transform(source), "", "XTTE0590"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.invocation.Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}
