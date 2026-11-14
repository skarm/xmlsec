package xslt //nolint:testpackage // Exercises merge ordering and source membership.

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
