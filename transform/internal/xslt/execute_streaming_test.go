package xslt //nolint:testpackage // Exercises source document focus and reuse.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestSourceDocumentRestoresFocusAndReusesDocument(t *testing.T) {
	t.Parallel()
	const resolved = "https://example.test/styles/data.xml"
	reader := &closeTrackingReader{reader: strings.NewReader(`<r>  <n xml:id="target">external</n>  </r>`)}
	var calls int
	resolver := contractURIResolver(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		calls++
		if ctx.Err() != nil || uri != resolved || calls != 1 {
			t.Errorf("resource call %d: uri=%q, context error=%v; want one request to %q", calls, uri, ctx.Err(), resolved)
			return nil, errors.New("unexpected resource request")
		}
		return reader, nil
	})
	doc := stylesheetDocument(t, `<xsl:strip-space elements="r"/>`, `
		<xsl:for-each select="r/n">
			<xsl:source-document href="data.xml#target" streamable="yes">
				<xsl:value-of select="string(.) || ':' || base-uri(.) || ':' || position() || '/' || last() || '|'"/>
			</xsl:source-document>
			<xsl:source-document href="data.xml">
				<xsl:value-of select="count(r/text()) || ':' || (. is doc('data.xml')) || '|'"/>
			</xsl:source-document>
			<xsl:value-of select="doc('data.xml')/r/n || ':' || string(.) || ':' || position() || '/' || last() || ';'"/>
		</xsl:for-each>`)
	ss, err := NewCompiler().BaseURI("https://example.test/styles/main.xsl").Compile(t.Context(), doc)
	if err != nil {
		t.Fatal(err)
	}
	source := parseTestDocument(t, `<r><n>a</n><n>b</n></r>`)
	got, err := ss.Transform(source).URIResolver(resolver).Serialize(t.Context())
	requireSerialization(t, got, err, "external:"+resolved+":1/1|0:true|external:a:1/2;external:"+resolved+":1/1|0:true|external:b:2/2;", "")
	if calls != 1 || reader.closed != 1 {
		t.Errorf("resource open/close count = %d/%d, want 1/1", calls, reader.closed)
	}
}

func TestExecIterateCompletionAndFocus(t *testing.T) {
	t.Parallel()
	const body = `
		<xsl:for-each select="/r/batch">
			<xsl:iterate select="n">
				<xsl:param name="total" as="xs:integer"><xsl:sequence select="xs:integer(@seed)"/></xsl:param>
				<xsl:param name="initial" select="$total"/>
				<xsl:on-completion>
					<xsl:value-of select="concat($initial, '->', $total, ';')"/>
				</xsl:on-completion>
				<xsl:value-of select="concat(., ':', position(), '/', last(), ',')"/>
				<xsl:next-iteration>
					<xsl:with-param name="total" select="$total + xs:integer(.)"/>
				</xsl:next-iteration>
			</xsl:iterate>
			<xsl:value-of select="concat(@seed, ':', position(), '/', last(), ';')"/>
		</xsl:for-each>`
	ss := compileTestStylesheet(t, "", body)
	source := parseTestDocument(t, `<r><batch seed="4"><n>2</n><n>5</n></batch><batch seed="3"/></r>`)
	got, err := ss.Transform(source).Serialize(t.Context())
	requireSerialization(t, got, err, "2:1/2,5:2/2,4->11;4:1/2;3->3;3:2/2;", "")

	for _, tc := range []struct{ name, children, want string }{
		{"completion after body", `<xsl:sequence select="."/><xsl:on-completion select="'done'"/>`, ""},
		{"parameters then completion then body", `<xsl:param name="limit" select="3"/><xsl:on-completion select="$limit"/><xsl:sequence select="."/>`, "1 2 3"},
		{"excluded body", `<xsl:sequence select="." use-when="false()"/><xsl:on-completion select="'done'"/>`, "done"},
		{"excluded completion", `<xsl:sequence select="."/><xsl:on-completion use-when="false()" select="'done'"/>`, "1 2"},
		{"inactive fallback", `<xsl:fallback/><xsl:on-completion select="'done'"/>`, "done"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			iterate := `<xsl:iterate select="1 to 2">` + tc.children + `</xsl:iterate>`
			sheet, err := NewCompiler().Compile(t.Context(), stylesheetDocument(t, "", iterate))
			if tc.want == "" {
				if detail, ok := errors.AsType[*XSLTError](err); sheet != nil || !ok || detail.Code != errCodeXTSE0010 {
					t.Fatalf("compiled stylesheet = %v, error = %v; want XTSE0010", sheet != nil, err)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			got, err := sheet.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestExecIterateBreakInSequenceConstructor(t *testing.T) {
	t.Parallel()
	const body = `
		<xsl:variable name="result" as="item()*">
			<xsl:iterate select="1 to 3">
				<xsl:param name="seen" select="0"/>
				<xsl:on-completion select="'unexpected completion'"/>
				<xsl:choose>
					<xsl:when test=". = 2">
						<xsl:break><xsl:sequence select="($seen, .)"/><end/></xsl:break>
					</xsl:when>
					<xsl:otherwise>
						<xsl:next-iteration><xsl:with-param name="seen" select="$seen + ."/></xsl:next-iteration>
					</xsl:otherwise>
				</xsl:choose>
			</xsl:iterate>
		</xsl:variable>
		<xsl:value-of select="($result[1] + $result[2], name($result[3]), count($result))" separator="|"/>`
	ss := compileTestStylesheet(t, "", body)
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "3|end|3", "")
}

func TestStreamingBodiesHaveOwnConditionalScope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, body, want string }{
		{"source_document", `<xsl:variable name="label" select="'caller'"/>
			<xsl:source-document href="urn:source"><xsl:variable name="label" select="string(r)"/>
				<xsl:on-empty select="concat($label, ':', r)"/>
			</xsl:source-document><xsl:value-of select="concat('|', $label)"/>`, "loaded:loaded|caller"},
		{"iterate", `<xsl:iterate select="(1,2)"><xsl:on-empty select="concat('empty-', ., ';')"/></xsl:iterate>`, "empty-1; empty-2;"},
		{"on_completion", `<xsl:iterate select="()"><xsl:param name="label" select="'done'"/>
			<xsl:on-completion><xsl:on-empty select="$label"/></xsl:on-completion>
		</xsl:iterate><xsl:text>|end</xsl:text>`, "done|end"},
		{"merge_action", `<xsl:merge><xsl:merge-source for-each-item="(1,2)" select="."><xsl:merge-key select="."/></xsl:merge-source>
			<xsl:merge-action><xsl:on-empty select="concat('empty-', current-merge-key(), ';')"/></xsl:merge-action>
		</xsl:merge>`, "empty-1; empty-2;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
				if uri != "urn:source" {
					return nil, fmt.Errorf("unexpected resource %q", uri)
				}
				return io.NopCloser(strings.NewReader(`<r>loaded</r>`)), nil
			})
			ss := compileTestStylesheet(t, "", tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).URIResolver(resolver).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestExecIterateRejectsWrongParameterType(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, initial, updated string }{
		{name: "initial_value", initial: "'not an integer'", updated: "$value"},
		{name: "next_iteration_value", initial: "0", updated: "'not an integer'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:iterate select="1 to 2">
				<xsl:param name="value" as="xs:integer" select="` + tc.initial + `"/>
				<xsl:on-completion select="$value"/>
				<xsl:next-iteration><xsl:with-param name="value" select="` + tc.updated + `"/></xsl:next-iteration>
			</xsl:iterate>`
			ss := compileTestStylesheet(t, "", body)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, "", "XTTE0590")
		})
	}
}

func TestExecForkKeepsBranchOrderAndFocus(t *testing.T) {
	t.Parallel()
	const body = `
		<xsl:for-each select="/r/n">
			<xsl:variable name="branches" as="item()*">
				<xsl:fork>
					<xsl:sequence select="(position(), data(@label))"/>
					<xsl:sequence select="(last(), string(.))"/>
				</xsl:fork>
			</xsl:variable>
			<xsl:value-of select="string-join($branches, ':') || ';'"/>
		</xsl:for-each>`
	ss := compileTestStylesheet(t, "", body)
	got, err := ss.Transform(parseTestDocument(t, `<r><n label="x">A</n><n label="y">B</n></r>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "1:x:2:A;2:y:2:B;", "")
}

func TestMergePreservesSourceMembershipAndSortDirection(t *testing.T) {
	t.Parallel()
	const body = `
		<xsl:merge>
			<xsl:merge-source name="left" select="(1,3,3)" sort-before-merge="yes">
				<xsl:merge-key select="." data-type="number" order="descending"/>
			</xsl:merge-source>
			<xsl:merge-source name="right" select="(4,3,2)">
				<xsl:merge-key select="." data-type="number" order="descending"/>
			</xsl:merge-source>
			<xsl:merge-action>
				<xsl:value-of select="current-merge-key() || ':' || count(current-merge-group('left')) || '/' || count(current-merge-group('right')) || ';'"/>
			</xsl:merge-action>
		</xsl:merge>`
	ss := compileTestStylesheet(t, "", body)
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "4:0/1;3:2/1;2:0/1;1:1/0;", "")
}

func TestMergeExplicitNumberFollowsSortConversion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, selectItems, want string }{
		{"numeric_lexical_space", `(1, '0x1p1', '2')`, "0x1p1;1;2;"},
		{"double_rounding", `(9007199254740993, 9007199254740992)`, "9007199254740993,9007199254740992;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:merge><xsl:merge-source select="` + tc.selectItems + `" sort-before-merge="yes">
				<xsl:merge-key select="." data-type="number"/>
			</xsl:merge-source><xsl:merge-action>
				<xsl:value-of select="string-join(current-merge-group() ! string(.), ',') || ';'"/>
			</xsl:merge-action></xsl:merge>`
			ss := compileTestStylesheet(t, "", body)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestMergeSortingPreservesSourceBindingOrder(t *testing.T) {
	t.Parallel()
	const body = `
		<xsl:variable name="items" select="('b','a')"/>
		<xsl:merge>
			<xsl:merge-source select="$items" sort-before-merge="yes"><xsl:merge-key select="."/></xsl:merge-source>
			<xsl:merge-action><xsl:value-of select="current-merge-key()"/></xsl:merge-action>
		</xsl:merge>
		<xsl:text>|</xsl:text>
		<xsl:value-of select="$items" separator=""/>`
	ss := compileTestStylesheet(t, "", body)
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "ab|ba", "")
}

func TestMergeIncompatibleKeysPreserveErrorIdentity(t *testing.T) {
	t.Parallel()
	const body = `<xsl:merge>
		<xsl:merge-source select="'text'"><xsl:merge-key select="."/></xsl:merge-source>
		<xsl:merge-source select="xs:date('2025-01-01')"><xsl:merge-key select="."/></xsl:merge-source>
		<xsl:merge-action>merged</xsl:merge-action>
	</xsl:merge>`
	source := parseTestDocument(t, `<r/>`)
	ss := compileTestStylesheet(t, "", body)
	got, err := ss.Transform(source).Serialize(t.Context())
	requireSerialization(t, got, err, "", errCodeXTTE2230)
	outer, ok := errors.AsType[*XSLTError](err)
	if !ok || !errors.Is(err, ErrDynamicError) || !isXSLTError(errors.Unwrap(outer), errCodeXTDE1030) {
		t.Fatalf("merge error lost its diagnostic cause: %v", err)
	}

	const diagnostics = `<xsl:value-of select="(namespace-uri-from-QName($err:code), local-name-from-QName($err:code), $err:description, empty($err:value))" separator="|"/>`
	const want = "http://www.w3.org/2005/xqt-errors|XTTE2230|incomparable merge key values|true"
	for _, pattern := range []string{"err:XTTE2230", "*"} {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()

			style := `<xsl:try xmlns:err="http://www.w3.org/2005/xqt-errors">` + body +
				`<xsl:catch errors="` + pattern + `">` + diagnostics + `</xsl:catch></xsl:try>`
			ss := compileTestStylesheet(t, "", style)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, want, "")
		})
	}
}

func TestExecMergeDocumentSources(t *testing.T) {
	t.Parallel()
	const base = "https://example.test/reports/main.xsl"
	const first = "https://example.test/reports/data/first.xml"
	const second = "https://example.test/reports/data/second.xml"
	const declarations = `
		<xsl:strip-space elements="r"/>
		<xsl:accumulator name="rows" as="xs:integer" initial-value="0">
			<xsl:accumulator-rule match="n" select="$value + 1"/>
		</xsl:accumulator>`
	const body = `
		<xsl:merge>
			<xsl:merge-source name="files" xml:base="data/" for-each-source="('first.xml', 'second.xml', 'first.xml')"
				select="r[count(text()) = 0]/n" streamable="yes" use-accumulators="rows">
				<xsl:merge-key select="xs:integer(@key)"/>
			</xsl:merge-source>
			<xsl:merge-action>
				<xsl:value-of select="current-merge-key() || ':' ||
					string-join(current-merge-group('files') ! (. || '/' || accumulator-before('rows') || '/' || count(../n)), ',') || ';'"/>
			</xsl:merge-action>
		</xsl:merge>
		<xsl:value-of select="name(/*)"/>`

	ss, err := NewCompiler().BaseURI(base).Compile(t.Context(), stylesheetDocument(t, declarations, body))
	if err != nil {
		t.Fatal(err)
	}
	resources := map[string]*closeTrackingReader{
		first:  {reader: strings.NewReader("<r>  <n key=\"1\">A</n>  <n key=\"2\">C</n>  </r>")},
		second: {reader: strings.NewReader("<r>  <n key=\"1\">B</n>  </r>")},
	}
	var requests []string
	resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
		requests = append(requests, uri)
		reader, ok := resources[uri]
		if !ok {
			return nil, fmt.Errorf("unexpected merge source %q", uri)
		}
		return reader, nil
	})
	got, err := ss.Transform(parseTestDocument(t, `<outer/>`)).URIResolver(resolver).Serialize(t.Context())
	requireSerialization(t, got, err, "1:A/1/1,B/1/1,A/1/1;2:C/2/1,C/2/1;outer", "")
	if !slices.Equal(requests, []string{first, second}) {
		t.Errorf("resource requests = %v, want [%s %s]", requests, first, second)
	}
	for uri, reader := range resources {
		if reader.closed != 1 {
			t.Errorf("source %s closed %d times, want once", uri, reader.closed)
		}
	}
}

func TestExecMergeSourceFailures(t *testing.T) {
	t.Parallel()
	const uri = "urn:merge:source"
	unavailable := errors.New("source unavailable")
	for _, tc := range []struct {
		name, anchors, xml, code string
		sourceErr                error
		wantRequests             int
	}{
		{name: "invalid_later_URI_prevents_open", anchors: "('urn:merge:source', 7)", code: "XPTY0004"},
		{name: "resolver_failure_retains_cause", anchors: "'urn:merge:source'", sourceErr: unavailable, code: "FODC0002", wantRequests: 1},
		{name: "malformed_source_closes_reader", anchors: "'urn:merge:source'", xml: "<r>", code: "FODC0002", wantRequests: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:merge>
				<xsl:merge-source for-each-source="` + tc.anchors + `" select="r/n"><xsl:merge-key select="."/></xsl:merge-source>
				<xsl:merge-action><unexpected/></xsl:merge-action>
			</xsl:merge>`
			ss := compileTestStylesheet(t, "", body)
			reader := &closeTrackingReader{reader: strings.NewReader(tc.xml)}
			var requests int
			resolver := contractURIResolver(func(_ context.Context, got string) (io.ReadCloser, error) {
				requests++
				if got != uri {
					t.Errorf("merge source = %q, want %q", got, uri)
				}
				if tc.sourceErr != nil {
					return nil, tc.sourceErr
				}
				return reader, nil
			})
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).URIResolver(resolver).Serialize(t.Context())
			if tc.wantRequests == 0 {
				var detail *xdm.Error
				if got != "" || !errors.As(err, &detail) || detail.Code != tc.code {
					t.Errorf("merge output = %q, error = %v, want empty output and %s", got, err, tc.code)
				}
			} else {
				requireSerialization(t, got, err, "", tc.code)
			}
			if tc.sourceErr != nil && !errors.Is(err, tc.sourceErr) {
				t.Errorf("merge error = %v, want cause %v", err, tc.sourceErr)
			}
			wantClosed := 0
			if tc.xml != "" {
				wantClosed = 1
			}
			if requests != tc.wantRequests || reader.closed != wantClosed {
				t.Errorf("resource opened/closed = %d/%d, want %d/%d", requests, reader.closed, tc.wantRequests, wantClosed)
			}
		})
	}
}

func TestExecMergeItemSources(t *testing.T) {
	t.Parallel()
	const body = `
		<xsl:merge>
			<xsl:merge-source name="nodes" for-each-item="/r/n"
				select="map{'key': position(), 'value': concat(., '/', last())}">
				<xsl:merge-key select="?key"/>
			</xsl:merge-source>
			<xsl:merge-source name="atomic" for-each-item="(10, 20, 30)"
				select="map{'key': position(), 'value': concat(., '/', last())}">
				<xsl:merge-key select="?key"/>
			</xsl:merge-source>
			<xsl:merge-action>
				<xsl:value-of select="current-merge-key() || ':' ||
					string-join(current-merge-group()?value, ',') || ';'"/>
			</xsl:merge-action>
		</xsl:merge>
		<xsl:value-of select="name(/*)"/>`
	ss := compileTestStylesheet(t, "", body)
	got, err := ss.Transform(parseTestDocument(t, `<r><n>a</n><n>b</n></r>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "1:a/2,10/3;2:b/2,20/3;3:30/3;r", "")
}

func TestAccumulatorPhasesRespectModeAndDocumentOrder(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, `
		<xsl:mode use-accumulators="count"/>
		<xsl:mode name="account"/>
		<xsl:accumulator name="count" as="xs:integer" initial-value="0" streamable="yes">
			<xsl:accumulator-rule match="n" select="$value + 1"/>
			<xsl:accumulator-rule match="n" phase="end" select="$value + 10"/>
		</xsl:accumulator>
		<xsl:template match="n" mode="account">
			<xsl:value-of select="accumulator-before('count') || '/' || accumulator-after('count') || ';'"/>
		</xsl:template>`, `<xsl:apply-templates select="r/n" mode="account"/>`)
	for _, tc := range []struct {
		input, want string
	}{
		{`<r><n/><n/><n/></r>`, "1/11;12/22;23/33;"},
		{`<r><n/></r>`, "1/11;"},
	} {
		got, err := ss.Transform(parseTestDocument(t, tc.input)).Serialize(t.Context())
		requireSerialization(t, got, err, tc.want, "")
	}

	t.Run("rule reads completed phases by node", func(t *testing.T) {
		t.Parallel()
		const declarations = `
			<xsl:accumulator name="sample" initial-value="()">
				<xsl:accumulator-rule match="n[2]" phase="end" select="(
					preceding-sibling::n[1] ! (accumulator-before('count'), accumulator-after('count')),
					accumulator-before('count'), accumulator-after('count'))"/>
			</xsl:accumulator>
			<xsl:accumulator name="count" initial-value="0">
				<xsl:accumulator-rule match="n" select="$value + 1"/>
				<xsl:accumulator-rule match="n" phase="end" select="$value + 10"/>
			</xsl:accumulator>`
		const body = `
			<xsl:variable name="tree"><r><n/><n/></r></xsl:variable>
			<xsl:sequence select="$tree/r/n[2] ! accumulator-after('sample')"/>`
		sheet := compileTestStylesheet(t, declarations, body)
		got, err := sheet.Transform(parseTestDocument(t, "<input/>")).Serialize(t.Context())
		requireSerialization(t, got, err, "1 11 12 22", "")
	})
}

func TestAccumulatorUsesLastMatchingRuleInEachPhase(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, `
		<xsl:mode use-accumulators="count"/>
		<xsl:mode name="account"/>
		<xsl:accumulator name="count" as="xs:integer" initial-value="0" streamable="yes">
			<xsl:accumulator-rule match="n" select="$value + 1"/>
			<xsl:accumulator-rule match="n[@selected]" select="$value + 10"/>
			<xsl:accumulator-rule match="n" phase="end" select="$value + 100"/>
		</xsl:accumulator>
		<xsl:template match="n" mode="account">
			<xsl:value-of select="accumulator-before('count') || '/' || accumulator-after('count') || ';'"/>
		</xsl:template>`, `<xsl:apply-templates select="r/n" mode="account"/>`)
	got, err := ss.Transform(parseTestDocument(t, `<r><n/><n selected="yes"/><n/></r>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "1/101;111/211;212/312;", "")
}

func TestAccumulatorPreservesControlFailures(t *testing.T) {
	t.Parallel()
	const read = `count(doc('optional.xml')/item)`
	const document = `https://example.test/styles/input.xml`
	const optional = `https://example.test/styles/optional.xml`
	const start = `<xsl:try><xsl:for-each select="doc('input.xml')"><xsl:value-of select="name(/*)"/>`
	const lookup = `<xsl:try><xsl:value-of select="accumulator-after('sample')"/>` +
		`<xsl:catch errors="*:FODC0002" select="':caught-lookup'"/></xsl:try>`
	const end = `</xsl:for-each><xsl:catch select="'caught-load'"/></xsl:try>`

	for _, tc := range []struct {
		name, initial, rule string
		failure             error
		inspect, fatal      bool
		want                string
	}{
		{name: "initial cancellation", initial: read, rule: `$value`, failure: context.Canceled, fatal: true},
		{name: "rule cancellation", initial: `0`, rule: read, failure: context.Canceled, fatal: true},
		{name: "rule deadline", initial: `0`, rule: read, failure: context.DeadlineExceeded, fatal: true},
		{name: "rule resource limit", initial: `0`, rule: read, failure: ErrResourceTooLarge, fatal: true},
		{name: "unused retrieval error", initial: read, rule: `$value`, failure: io.ErrUnexpectedEOF, want: "root"},
		{name: "requested retrieval error", initial: `0`, rule: read, failure: io.ErrUnexpectedEOF, inspect: true, want: "root:caught-lookup"},
		{name: "successful lookup", initial: `0`, rule: read, inspect: true, want: "root1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := start
			if tc.inspect {
				body += lookup
			}
			declaration := `<xsl:accumulator name="sample" initial-value="` + tc.initial + `">` +
				`<xsl:accumulator-rule match="root" select="` + tc.rule + `"/></xsl:accumulator>`
			sheet, err := NewCompiler().BaseURI("https://example.test/styles/main.xsl").Compile(t.Context(), stylesheetDocument(t, declaration, body+end))
			if err != nil {
				t.Fatal(err)
			}
			resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
				switch uri {
				case document:
					return io.NopCloser(strings.NewReader(`<root/>`)), nil
				case optional:
					if tc.failure != nil {
						return nil, tc.failure
					}
					return io.NopCloser(strings.NewReader(`<item/>`)), nil
				default:
					t.Errorf("unexpected resource request %q", uri)
					return nil, fmt.Errorf("unexpected resource request %q", uri)
				}
			})
			got, err := sheet.Transform(parseTestDocument(t, `<input/>`)).URIResolver(resolver).Serialize(t.Context())
			if tc.fatal {
				if got != "" || !errors.Is(err, tc.failure) {
					t.Fatalf("output = %q, err = %v; want no output and %v", got, err, tc.failure)
				}
				return
			}
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestAccumulatorApplicabilityFollowsTree(t *testing.T) {
	t.Parallel()

	const declarations = `
		<xsl:accumulator name="seen" initial-value="0" streamable="yes">
			<xsl:accumulator-rule match="n" select="$value + 1"/>
		</xsl:accumulator>`
	for _, tc := range []struct{ name, modes, body, want, code string }{
		{"initial default grants none", "", `<xsl:value-of select="r/n/accumulator-before('seen')"/>`, "", "XTDE3362"},
		{"explicit mode without attribute grants none", `<xsl:mode/>`, `<xsl:value-of select="r/n/accumulator-before('seen')"/>`, "", "XTDE3362"},
		{"secondary mode does not revoke grant", `<xsl:mode use-accumulators="#all"/><xsl:mode name="secondary" use-accumulators=""/><xsl:template mode="secondary" match="n"><xsl:value-of select="accumulator-before('seen')"/></xsl:template>`, `<xsl:apply-templates select="r/n" mode="secondary"/>`, "1", ""},
		{"temporary tree is unrestricted", `<xsl:mode name="secondary" use-accumulators=""/><xsl:template match="n" mode="secondary"><xsl:variable name="tree" as="element()"><n/></xsl:variable><xsl:value-of select="$tree/accumulator-before('seen')"/></xsl:template>`, `<xsl:apply-templates select="r/n" mode="secondary"/>`, "1", ""},
		{"copy function inherits empty grant", "", `<xsl:variable name="copy" select="copy-of(r/n)"/><xsl:value-of select="$copy/accumulator-before('seen')"/>`, "", "XTDE3362"},
		{"snapshot inherits empty grant", "", `<xsl:variable name="copy" select="snapshot(r/n)"/><xsl:value-of select="$copy/accumulator-before('seen')"/>`, "", "XTDE3362"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, declarations+tc.modes, tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r><n/></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}

	t.Run("initial invocation kind distinguishes source provenance", func(t *testing.T) {
		t.Parallel()
		const value = `<xsl:variable name="early" select="r/n/accumulator-before('seen')"/>`
		const entries = `
			<xsl:template name="start"><xsl:value-of select="$early"/></xsl:template>
			<xsl:function name="f:start" visibility="public"><xsl:sequence select="$early"/></xsl:function>`
		ss := compileTestStylesheet(t, declarations+value+entries, `<xsl:value-of select="$early"/>`)
		implicit := compileTestStylesheet(t, declarations+value+
			`<xsl:template name="xsl:initial-template"><xsl:value-of select="$early"/></xsl:template>`, "")
		source := parseTestDocument(t, `<r><n/></r>`)
		for _, tc := range []struct {
			name       string
			invocation Invocation
			want, code string
		}{
			{"initial match source is restricted", ss.Transform(source), "", errCodeXTDE3362},
			{"named template source is global context", ss.CallTemplate("start").SourceDocument(source), "1", ""},
			{"default named template accepts an independent global context", implicit.Transform(nil).GlobalContextItem(xdm.NodeItem{Node: source}), "1", ""},
			{"function source is global context", ss.CallFunction("Q{urn:unit}start").SourceDocument(source), "1", ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				got, err := tc.invocation.Serialize(t.Context())
				requireSerialization(t, got, err, tc.want, tc.code)
			})
		}
	})
}

func TestSourceDocumentAccumulatorGrantsSurviveFocusChanges(t *testing.T) {
	t.Parallel()

	const declarations = `
		<xsl:mode use-accumulators="#all"/>
		<xsl:accumulator name="seen" initial-value="0" streamable="yes">
			<xsl:accumulator-rule match="n" select="$value + 1"/>
		</xsl:accumulator>`
	const body = `
		<xsl:variable name="initial" select="."/>
		<xsl:variable name="restricted" as="document-node()">
			<xsl:source-document href="urn:source"><xsl:sequence select="."/></xsl:source-document>
		</xsl:variable>
		<xsl:variable name="permitted" as="document-node()">
			<xsl:source-document href="urn:source" use-accumulators="seen">
				<xsl:sequence select="."/>
			</xsl:source-document>
		</xsl:variable>
		<xsl:value-of select="$permitted/accumulator-after('seen')"/>
		<xsl:source-document href="urn:source">
			<xsl:value-of select="$initial/accumulator-after('seen')"/>
		</xsl:source-document>
		<xsl:try xmlns:err="http://www.w3.org/2005/xqt-errors">
			<xsl:value-of select="$restricted/accumulator-after('seen')"/>
			<xsl:catch errors="err:XTDE3362"><xsl:text>restricted</xsl:text></xsl:catch>
		</xsl:try>`

	ss := compileTestStylesheet(t, declarations, body)
	resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
		if uri != "urn:source" {
			return nil, fmt.Errorf("unexpected source URI %q", uri)
		}

		return io.NopCloser(strings.NewReader(`<r><n/><n/></r>`)), nil
	})
	got, err := ss.Transform(parseTestDocument(t, `<r><n/></r>`)).URIResolver(resolver).Serialize(t.Context())
	requireSerialization(t, got, err, "21restricted", "")
}

func TestReviewIterateCompletionKeepsStaticContext(t *testing.T) {
	for _, tc := range []struct{ name, attrs, selectValue, want string }{
		{"namespace", `xmlns:p="urn:complete"`, `namespace-uri-from-QName(xs:QName('p:item'))`, "urn:complete"},
		{"base URI", `xml:base="https://example.test/completion/"`, `static-base-uri()`, "https://example.test/completion/"},
		{"default namespace", `xpath-default-namespace="urn:complete"`, `namespace-uri-from-QName(xs:QName('item'))`, "urn:complete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss, err := NewCompiler().Compile(t.Context(), stylesheetDocument(t, "", `<xsl:iterate select="()"><xsl:on-completion `+tc.attrs+` select="`+tc.selectValue+`"/></xsl:iterate>`))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestReviewAccumulatorKeepsOwnFocus(t *testing.T) {
	for _, tc := range []struct{ name, decl, body, want string }{
		{"initial and rule focus", `<xsl:accumulator name="a" initial-value="concat(. instance of document-node(), ':', position(), '/', last())"><xsl:accumulator-rule match="r" select="concat($value, ':', position(), '/', last())"/></xsl:accumulator>`, `<xsl:variable name="tree"><r/></xsl:variable><xsl:for-each select="(10,20)"><xsl:value-of select="$tree ! accumulator-after('a')"/><xsl:text>|</xsl:text></xsl:for-each>`, "true:1/1:1/1|true:1/1:1/1|"},
		{"static base", `<xsl:accumulator name="a" xml:base="https://example.test/acc/" initial-value="static-base-uri()"><xsl:accumulator-rule match="r" select="$value"/></xsl:accumulator>`, `<xsl:variable name="tree"><r/></xsl:variable><xsl:value-of select="$tree ! accumulator-after('a')"/>`, "https://example.test/acc/"},
		{"group context absent", `<xsl:accumulator name="a" initial-value="count(current-group())"><xsl:accumulator-rule match="r" select="$value"/></xsl:accumulator>`, `<xsl:for-each-group select="(1,1)" group-by="."><xsl:variable name="tree"><r/></xsl:variable><xsl:try select="$tree ! accumulator-after('a')"><xsl:catch errors="*:XTDE1061" select="'absent'"/></xsl:try></xsl:for-each-group>`, "absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss := compileTestStylesheet(t, tc.decl, tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<input/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}
