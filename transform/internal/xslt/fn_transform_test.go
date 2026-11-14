package xslt //nolint:testpackage // Exercises fn:transform in a running stylesheet.

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestFnTransformResolvesStylesheetFromCallSite(t *testing.T) {
	t.Parallel()
	const nestedURI = "https://styles.example/call/inner.xsl"
	const dataURI = "https://styles.example/call/data.xml"
	const nested = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">
		<xsl:output method="text"/>
		<xsl:template name="start"><xsl:value-of select="doc('data.xml')/data"/></xsl:template>
	</xsl:stylesheet>`
	const caller = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">
		<xsl:output method="text"/>
		<xsl:template match="/" xml:base="call/">
			<xsl:value-of select="transform(map{
				'stylesheet-location':'inner.xsl',
				'initial-template':QName('', 'start'),
				'delivery-format':'serialized'
			})?output"/>
		</xsl:template>
	</xsl:stylesheet>`
	var stylesheetReads, dataReads []string
	nestedReader := &closeTrackingReader{reader: strings.NewReader(nested)}
	dataReader := &closeTrackingReader{reader: strings.NewReader("<data>nested output</data>")}
	compilerResolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
		stylesheetReads = append(stylesheetReads, uri)
		if uri != nestedURI {
			return nil, fmt.Errorf("unexpected stylesheet URI %q", uri)
		}
		return nestedReader, nil
	})
	documentResolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
		dataReads = append(dataReads, uri)
		if uri != dataURI {
			return nil, fmt.Errorf("unexpected document URI %q", uri)
		}
		return dataReader, nil
	})
	ss, err := NewCompiler().BaseURI("https://styles.example/root.xsl").URIResolver(compilerResolver).
		Compile(t.Context(), parseTestDocument(t, caller))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ss.Transform(parseTestDocument(t, "<r/>")).URIResolver(documentResolver).Serialize(t.Context())
	requireSerialization(t, got, err, "nested output", "")
	if !slices.Equal(stylesheetReads, []string{nestedURI}) || !slices.Equal(dataReads, []string{dataURI}) {
		t.Errorf("stylesheet reads = %v, document reads = %v, want [%s] and [%s]", stylesheetReads, dataReads, nestedURI, dataURI)
	}
	if nestedReader.closed != 1 || dataReader.closed != 1 {
		t.Errorf("stylesheet reader closes = %d, document reader closes = %d, want 1 each", nestedReader.closed, dataReader.closed)
	}
}
