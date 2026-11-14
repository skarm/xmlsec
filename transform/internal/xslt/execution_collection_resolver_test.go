package xslt //nolint:testpackage // Exercises collection resolution within an execution.

import (
	"context"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

type executionTestCollection struct {
	items     xdm.ItemSlice
	uris      []string
	itemCalls []string
	uriCalls  []string
}

func (r *executionTestCollection) ResolveCollection(_ context.Context, uri string) (xdm.Sequence, error) {
	r.itemCalls = append(r.itemCalls, uri)
	return r.items, nil
}

func (r *executionTestCollection) ResolveURICollection(_ context.Context, uri string) ([]string, error) {
	r.uriCalls = append(r.uriCalls, uri)
	return r.uris, nil
}

func TestExecutionCollectionResolver(t *testing.T) {
	t.Parallel()
	const (
		collectionURI = "urn:batch"
		documentURI   = "urn:member"
	)

	t.Run("preparation_preserves_item_order_and_caches_document_identity", func(t *testing.T) {
		t.Parallel()

		member := parseTestDocument(t, `<r>  <n/>  </r>`)
		member.SetURL(documentURI)
		resolver := &executionTestCollection{
			items: xdm.ItemSlice{
				stringItem("note"),
				xdm.NodeItem{Node: member},
				xdm.NodeItem{Node: member.DocumentElement().FirstChild()},
			},
			uris: []string{documentURI, "urn:other"},
		}
		ss := compileTestStylesheet(t, `<xsl:strip-space elements="*"/>`, `
			<xsl:variable name="members" select="collection('urn:batch')"/>
			<xsl:value-of select="(count($members), $members[1], count($members[2]/r/text()),
				$members[2] is collection('urn:batch')[2], $members[2] is doc('urn:member'),
				uri-collection('urn:batch'), uri-collection('urn:batch'))" separator="|"/>`)
		got, err := ss.Transform(parseTestDocument(t, `<input/>`)).CollectionResolver(resolver).Serialize(t.Context())
		requireSerialization(t, got, err, "2|note|0|true|true|urn:member|urn:other|urn:member|urn:other", "")
		if len(resolver.itemCalls) != 1 || resolver.itemCalls[0] != collectionURI {
			t.Errorf("collection lookups = %v; want [%s]", resolver.itemCalls, collectionURI)
		}
		if len(resolver.uriCalls) != 1 || resolver.uriCalls[0] != collectionURI {
			t.Errorf("URI collection lookups = %v; want [%s]", resolver.uriCalls, collectionURI)
		}
		if first := member.DocumentElement().FirstChild(); first == nil || xdm.StringValue(first) != "  " {
			t.Error("collection preparation removed whitespace from the resolver's document")
		}
	})

	t.Run("one_uri_cannot_identify_distinct_collection_members", func(t *testing.T) {
		t.Parallel()

		first := parseTestDocument(t, `<first/>`)
		second := parseTestDocument(t, `<second/>`)
		first.SetURL(documentURI)
		second.SetURL(documentURI)
		resolver := &executionTestCollection{items: xdm.ItemSlice{xdm.NodeItem{Node: first}, xdm.NodeItem{Node: second}}}
		ss := compileTestStylesheet(t, "", `<xsl:value-of select="count(collection('urn:batch'))"/>`)
		got, err := ss.Transform(parseTestDocument(t, `<input/>`)).CollectionResolver(resolver).Serialize(t.Context())
		if got != "" || !errors.Is(err, &xdm.Error{Code: "FODC0003"}) {
			t.Fatalf("output = %q, error = %v; want no output and FODC0003", got, err)
		}
	})
}
