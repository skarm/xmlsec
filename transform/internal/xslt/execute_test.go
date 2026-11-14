package xslt //nolint:testpackage // Exercises operation-local annotations on source and copied nodes.

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestRemapAnnotationsToCopyKeepsNilledSnapshotsIndependent(t *testing.T) {
	t.Parallel()

	src := parseTestDocument(t, `<r><n code="a"/></r>`).DocumentElement().FirstChild().(*xdm.Element)
	dst := parseTestDocument(t, `<r><n code="a"/></r>`).DocumentElement().FirstChild().(*xdm.Element)
	srcAttr := src.GetAttributeNodeNS("code", "")
	dstAttr := dst.GetAttributeNodeNS("code", "")
	ec := &execContext{stylesheet: &Stylesheet{}}
	ec.annotateNode(src, xdm.TypeString)
	ec.annotateNode(srcAttr, xdm.TypeToken)
	ec.markNilled(src)

	before := ec.nilledElementNodes()
	ec.remapAnnotationsToCopy(map[xdm.Node]xdm.Node{src: dst, srcAttr: dstAttr})
	wantTypes := map[xdm.Node]string{dst: xdm.TypeString, dstAttr: xdm.TypeToken}
	if !maps.Equal(ec.typeAnnotations, wantTypes) {
		t.Errorf("copy element annotation = %q, copy attribute annotation = %q, count = %d", ec.typeAnnotations[dst], ec.typeAnnotations[dstAttr], len(ec.typeAnnotations))
	}
	if !maps.Equal(before, map[xdm.Node]struct{}{src: {}}) {
		t.Error("remapping changed the nilled snapshot already returned to the caller")
	}
	after := ec.nilledElementNodes()
	if !maps.Equal(after, map[xdm.Node]struct{}{dst: {}}) {
		t.Error("remapping did not move nilled status to the copy")
	}
	ec.stylesheet.inputTypeAnnotations = validationStrip
	if got := ec.nilledElementNodes(); got != nil {
		t.Errorf("stripped input returned %d nilled nodes, want none", len(got))
	}
}

func TestTransferAnnotationsForCopySkipsExistingChildrenAndMatchesExpandedNames(t *testing.T) {
	t.Parallel()

	source := parseTestDocument(t, `<r xmlns:p="urn:one" xmlns:q="urn:two" p:code="A" q:code="B"><child/></r>`)
	out := parseTestDocument(t, `<out><existing/><r xmlns:p="urn:one" xmlns:q="urn:two" q:code="B" p:code="A"><child/></r></out>`).DocumentElement()
	srcRoot := source.DocumentElement()
	srcChild := srcRoot.FirstChild().(*xdm.Element)
	existing := out.FirstChild()
	copied := out.LastChild().(*xdm.Element)
	copiedChild := copied.FirstChild().(*xdm.Element)
	ec := &execContext{}
	ec.annotateNode(srcRoot, xdm.TypeString)
	ec.annotateNode(srcRoot.GetAttributeNodeNS("code", "urn:one"), xdm.TypeToken)
	ec.annotateNode(srcChild, xdm.TypeInteger)
	ec.markNilled(srcChild)

	ec.transferAnnotationsForCopy(source, out, existing)
	for _, tc := range []struct {
		name string
		node xdm.Node
		want string
	}{
		{"preexisting_child", existing, ""},
		{"copied_root", copied, xdm.TypeString},
		{"matching_attribute", copied.GetAttributeNodeNS("code", "urn:one"), xdm.TypeToken},
		{"same_local_name_in_another_namespace", copied.GetAttributeNodeNS("code", "urn:two"), ""},
		{"copied_child", copiedChild, xdm.TypeInteger},
	} {
		if got := ec.typeAnnotations[tc.node]; got != tc.want {
			t.Errorf("%s annotation = %q, want %q", tc.name, got, tc.want)
		}
	}
	if !ec.isNilled(copiedChild) || ec.isNilled(copied) {
		t.Error("the copied child alone should be nilled")
	}
}

func TestPreserveIDAnnotationsRegistersIDsAndReferenceKinds(t *testing.T) {
	t.Parallel()

	doc := parseTestDocument(t, `<root key="attr-id" ref="elem-id" refs="attr-id elem-id"><entry> elem-id </entry></root>`)
	root := doc.DocumentElement()
	entry := root.FirstChild()
	key, ref, refs := root.GetAttributeNodeNS("key", ""), root.GetAttributeNodeNS("ref", ""), root.GetAttributeNodeNS("refs", "")
	ec := &execContext{}
	ec.annotateNode(key, xdm.TypeID)
	ec.annotateNode(entry, xdm.TypeID)
	ec.annotateNode(ref, xdm.TypeIDREF)
	ec.annotateNode(refs, xdm.TypeIDREFS)

	ec.preserveIDAnnotations()
	if got := doc.GetElementByID("attr-id"); got != root {
		t.Error("document did not register the owner of the ID attribute")
	}
	if got := doc.GetElementByID("elem-id"); got != entry {
		t.Error("document did not register the ID element with trimmed text")
	}
	if got := doc.GetElementByID(" elem-id "); got != nil {
		t.Error("document registered the untrimmed ID")
	}
	if key.IDType() != xdm.IDAttribute || ref.IDType() != xdm.IDRefAttribute || refs.IDType() != xdm.IDRefsAttribute {
		t.Errorf("ID kinds = (%v, %v, %v), want ID, IDREF, IDREFS", key.IDType(), ref.IDType(), refs.IDType())
	}
}

func TestInstructionConstructionAndRollback(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, declarations, body, want string
	}{
		{"map_entries_keep_typed_keys", "", `<xsl:variable name="m" as="map(*)"><xsl:map><xsl:map-entry key="1" select="'numeric'"/><xsl:map-entry key="'1'" select="'string'"/></xsl:map></xsl:variable><xsl:value-of select="($m(1),$m('1'))" separator="|"/>`, "numeric|string"},
		{"attribute_set_uses_focus_and_overrides_in_order", `<xsl:attribute-set name="labels"><xsl:attribute name="id" select="@id"/><xsl:attribute name="kind">inherited</xsl:attribute></xsl:attribute-set>`, `<xsl:for-each select="r/n"><xsl:variable name="node" as="element()"><xsl:element name="item" use-attribute-sets="labels"><xsl:attribute name="kind">explicit</xsl:attribute></xsl:element></xsl:variable><xsl:value-of select="($node/@id, $node/@kind)" separator="|"/></xsl:for-each>`, "source|explicit"},
		{"copy_and_copy_of_keep_content", "", `<xsl:for-each select="r/n"><xsl:variable name="copied" as="element()"><xsl:copy><xsl:copy-of select="@* | node()"/></xsl:copy></xsl:variable><xsl:value-of select="(name($copied),$copied/@id,string($copied/child))" separator="|"/></xsl:for-each>`, "n|source|text"},
		{"catch_discards_partial_result", "", `<xsl:text>before|</xsl:text><xsl:try><xsl:text>discard|</xsl:text><xsl:sequence select="error(QName('urn:unit','f:stop'))"/><xsl:catch errors="f:stop"><xsl:text>recovered|</xsl:text></xsl:catch></xsl:try><xsl:text>after</xsl:text>`, "before|recovered|after"},
		{"iterate_break_skips_completion", "", `<xsl:iterate select="1 to 3"><xsl:on-completion select="'unexpected'"/><xsl:choose><xsl:when test=". eq 2"><xsl:break select="'stop'"/></xsl:when><xsl:otherwise><xsl:value-of select="."/></xsl:otherwise></xsl:choose></xsl:iterate>`, "1stop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, tc.declarations, tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r><n id="source"><child>text</child></n></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestExecuteSequenceConstructorConditionalOutput(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, body, want, code string
	}{
		{
			name: "on_empty_handles_vacuous_strings_without_separator",
			body: `<out>
				<xsl:sequence select="('', '')"/>
				<xsl:on-non-empty select="error()"/>
				<xsl:on-empty><xsl:text>fallback</xsl:text></xsl:on-empty>
			</out>`,
			want: "fallback",
		},
		{
			name: "on_non_empty_splices_before_and_after_ordinary_output",
			body: `<out>
				<xsl:on-non-empty><before>begin|</before></xsl:on-non-empty>
				<xsl:text>middle</xsl:text>
				<xsl:on-non-empty select="('|end', 3)"/>
				<xsl:on-empty select="error()"/>
			</out>`,
			want: "begin|middle|end 3",
		},
		{
			name: "sequence_mode_preserves_type_and_replacement_order",
			body: `<xsl:variable name="values" as="item()*">
				<xsl:on-non-empty select="(1, 2)"/>
				<xsl:sequence select="map{'k': 'value'}"/>
				<xsl:on-non-empty select="[3, 4]"/>
				<xsl:on-empty select="error()"/>
			</xsl:variable>
			<xsl:value-of select="(count($values), $values[1] + $values[2], ($values[3])('k'), ($values[4])(2))" separator="|"/>`,
			want: "4|3|value|4",
		},
		{
			name: "sequence_mode_replaces_nested_vacuous_arrays",
			body: `<xsl:variable name="values" as="item()*">
				<xsl:sequence select="[[(), ''], ['']]"/>
				<xsl:on-empty select="(4, 5)"/>
			</xsl:variable>
			<xsl:value-of select="(count($values), sum($values))" separator="|"/>`,
			want: "2|9",
		},
		{
			name: "deferred_constructor_uses_lexical_binding_at_registration",
			body: `<xsl:variable name="label" select="'outer'"/>
			<out>
				<xsl:on-non-empty select="$label"/>
				<xsl:variable name="label" select="'inner'"/>
				<xsl:text>|</xsl:text>
				<xsl:on-non-empty select="$label"/>
			</out>
			<xsl:value-of select="'|' || $label"/>`,
			want: "outer|inner|outer",
		},
		{
			name: "deferred_document_contributes_children_in_order",
			body: `<xsl:variable name="out" as="element()"><out>
				<xsl:on-non-empty><xsl:document><first/><second/></xsl:document></xsl:on-non-empty>
				<third/>
			</out></xsl:variable>
			<xsl:value-of select="$out/*/name()" separator="|"/>`,
			want: "first|second|third",
		},
		{
			name: "deferred_attribute_attaches_to_output_element",
			body: `<xsl:variable name="out" as="element()"><out>
				<xsl:on-non-empty><xsl:attribute name="status">ready</xsl:attribute></xsl:on-non-empty>
				<child/>
			</out></xsl:variable>
			<xsl:value-of select="($out/@status, name($out/*))" separator="|"/>`,
			want: "ready|child",
		},
		{
			name: "deferred_map_cannot_be_inserted_into_tree",
			body: `<out><xsl:on-empty select="map{'k': 1}"/></out>`,
			code: "XTDE0450",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, "", tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestExecuteSequenceConstructorConditionalError(t *testing.T) {
	t.Parallel()

	ss := compileTestStylesheet(t, "", `<out><xsl:on-empty select="error(QName('urn:unit', 'f:stopped'))"/></out>`)
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	wantErr := &xdm.Error{QualifiedCode: xdm.QNameValue{URI: "urn:unit", Local: "stopped"}}
	if got != "" || !errors.Is(err, wantErr) {
		t.Fatalf("output = %q, error = %v; want no output and %v", got, err, wantErr)
	}
}

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
