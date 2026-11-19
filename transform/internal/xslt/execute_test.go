package xslt //nolint:testpackage // Exercises operation-local annotations on source and copied nodes.

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func TestSnapshotPreservesAncestorBaseURIs(t *testing.T) {
	t.Parallel()
	const source = `<r xmlns:p="urn:example" xml:base="outer/"><parent xml:base="middle/"><leaf xml:base="inner/" code="test"/></parent></r>`
	const base = "https://example.test/source/document.xml"
	doc, err := (xdm.ParseOptions{BaseURI: base}).ParseText(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	doc.SetProperties(doc.Properties() | xdm.DocInternal)
	xdm.SetNodeBaseURI(doc.DocumentElement(), "https://example.test/constructed/")

	ss := compileTestStylesheet(t, "", `
		<xsl:variable name="node" select="r/parent/leaf"/>
		<xsl:variable name="element" select="snapshot($node)"/>
		<xsl:variable name="attribute" select="snapshot($node/@code)"/>
		<xsl:variable name="namespace" select="snapshot($node/namespace::p)"/>
		<xsl:value-of separator="|" select="(
			base-uri(root($element)), base-uri($element/../..), base-uri($element/..), base-uri($element),
			base-uri(root($attribute)), base-uri($attribute),
			base-uri(root($namespace)), base-uri($namespace/..), empty(base-uri($namespace)),
			empty(document-uri(root($node))), empty(document-uri(root($element))),
			empty(document-uri(root($attribute))), empty(document-uri(root($namespace)))
		)"/>`)
	got, err := ss.Transform(doc).Serialize(t.Context())
	const rootBase = "https://example.test/constructed/outer/"
	const parentBase = rootBase + "middle/"
	const leafBase = parentBase + "inner/"
	want := base + "|" + rootBase + "|" + parentBase + "|" + leafBase + "|" + base + "|" + leafBase + "|" + base + "|" + leafBase + "|true|true|true|true|true"
	requireSerialization(t, got, err, want, "")
}

func TestSnapshotRetainsDetachedTreeRoot(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, "", `
		<xsl:variable name="outer" as="element()"><outer xmlns:p="urn:example"><leaf code="1"/><leaf code="2"/></outer></xsl:variable>
		<xsl:variable name="leaf" select="$outer/leaf[2]"/>
		<xsl:variable name="element" select="snapshot($leaf)"/>
		<xsl:variable name="attribute" select="snapshot($leaf/@code)"/>
		<xsl:variable name="namespace" select="snapshot($leaf/namespace::p)"/>
		<xsl:value-of select="(
			root($leaf) instance of element(outer), root($element) instance of element(outer),
			root($attribute) instance of element(outer), root($namespace) instance of element(outer),
			count(root($element)/leaf), count(root($attribute)/leaf), count(root($namespace)/leaf),
			string($attribute), string($namespace), namespace-uri-for-prefix('p', $element)
		)"/>`)
	got, err := ss.Transform(parseTestDocument(t, `<input/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "true true true true 1 1 1 2 urn:example urn:example", "")
}

func TestSnapshotChargesCopiedTree(t *testing.T) {
	t.Parallel()

	doc := parseTestDocument(t, `<r label="kept"><target>one</target><sibling/></r>`)
	style := compileTestStylesheet(t, "", "")
	target := doc.DocumentElement().FirstChild()
	for _, tc := range []struct {
		name  string
		node  xdm.Node
		nodes int
	}{
		{"document", doc, 5},
		{"selected subtree and ancestor shells", target, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ec := &execContext{stylesheet: style}
			ctx := xpath.WithBudget(t.Context(), 100, tc.nodes, 100, 16)
			copied, err := ec.snapshotNode(ctx, tc.node)
			if err != nil || copied == nil || copied == tc.node {
				t.Fatalf("first exact-size snapshot = (%v, %v); want an independent copy", copied, err)
			}
			if tc.node == target {
				parent := copied.Parent().(*xdm.Element)
				if label, _ := parent.GetAttribute("label"); label != "kept" || copied.NextSibling() != nil {
					t.Fatalf("snapshot ancestor = %v; want the copied attribute and selected child only", parent)
				}
			}
			if copied, err = ec.snapshotNode(ctx, tc.node); copied != nil || !errors.Is(err, xpath.ErrBudget) {
				t.Fatalf("second snapshot = (%v, %v); want no result and ErrBudget", copied, err)
			}
		})
	}

	t.Run("string value", func(t *testing.T) {
		t.Parallel()
		ec := &execContext{stylesheet: style}
		ctx := xpath.WithBudget(t.Context(), 100, 5, 2, 16)
		if copied, err := ec.snapshotNode(ctx, target); copied != nil || !errors.Is(err, xpath.ErrBudget) {
			t.Fatalf("snapshot over string-value budget = (%v, %v); want no result and ErrBudget", copied, err)
		}
	})

	t.Run("canceled", func(t *testing.T) {
		t.Parallel()
		ec := &execContext{stylesheet: style}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if copied, err := ec.snapshotNode(ctx, target); copied != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled snapshot = (%v, %v); want no result and context.Canceled", copied, err)
		}
	})
}

func TestMergeSnapshotRetainsDetachedBaseAndAccumulatorState(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, `<xsl:accumulator name="seen" as="xs:integer" initial-value="0">
		<xsl:accumulator-rule match="leaf" select="$value + 1"/>
	</xsl:accumulator>`, "")
	const ownerURI = "https://example.test/source/document.xml"
	doc, err := (xdm.ParseOptions{BaseURI: ownerURI}).ParseText(t.Context(), `<root xml:base="outer/"><leaf/><leaf xml:base="inner/"/></root>`)
	if err != nil {
		t.Fatal(err)
	}
	root := doc.DocumentElement()
	xdm.UnlinkNode(root)
	node := root.LastChild()

	ec := &execContext{stylesheet: ss}
	items, err := ec.maybeSnapshotMergeItems(t.Context(), &mergeSource{StreamableAttr: true}, xdm.ItemSlice{xdm.NodeItem{Node: node}})
	if err != nil {
		t.Fatal(err)
	}
	copyNode := items[0].(xdm.NodeItem).Node
	copyRoot := documentRoot(copyNode)
	if copyRoot.Type() != xdm.ElementNode || copyRoot == root || copyRoot != copyNode.Parent() {
		t.Fatalf("snapshot root is %v, want a distinct parentless copy of %v", copyRoot.Type(), root.Type())
	}
	const leafBase = "https://example.test/source/outer/inner/"
	if got := xpath.NodeBaseURI(copyNode); got != leafBase {
		t.Errorf("snapshot base URI = %q, want %q", got, leafBase)
	}
	if err := ec.ensureAccumulatorStates(t.Context(), copyNode); err != nil {
		t.Fatal(err)
	}

	before := ec.accumulatorBeforeByNode[copyNode]["seen"]
	if xdm.SequenceLen(before) != 1 {
		t.Fatalf("snapshot first-phase accumulator state = %v, want original state 2", before)
	}
	value, ok := before.Get(0).(xdm.AtomicValue)
	if !ok {
		t.Fatalf("snapshot first-phase accumulator item = %T, want atomic value", before.Get(0))
	}
	got, err := xpath.AtomicToString(value)
	if err != nil || got != "2" {
		t.Errorf("snapshot first-phase accumulator state = %q, %v, want original state 2", got, err)
	}
}

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

func TestSortChildrenPrecedeSequenceConstructor(t *testing.T) {
	t.Parallel()

	const sortKey = `<xsl:sort select="@order"/>`
	const body = `<xsl:value-of select="."/>`
	const input = `<r><n order="2">2</n><n order="1">1</n></r>`

	for _, profile := range []struct {
		version   string
		processor int
	}{
		{"1.0", processorXSLT10},
		{"2.0", processorXSLT20},
		{"3.0", processorXSLT30},
	} {
		for _, instruction := range []struct{ name, attrs string }{
			{"for-each", ""},
			{"for-each-group", ` group-by="."`},
		} {
			if profile.processor == processorXSLT10 && instruction.attrs != "" {
				continue
			}

			for _, tc := range []struct {
				name, children, attrs, want, code string
				modern                            bool
			}{
				{name: "late after text", children: "label" + sortKey + body, code: errCodeXTSE0010},
				{name: "late after CDATA", children: `<![CDATA[label]]>` + sortKey + body, code: errCodeXTSE0010},
				{name: "late after instruction", children: `<xsl:text>label</xsl:text>` + sortKey + body, code: errCodeXTSE0010},
				{name: "leading with ignorable text", children: "\n  <!-- sort keys -->\n  " + sortKey + body, want: "12"},
				{name: "leading with preserved whitespace", children: "\n  " + sortKey + body, attrs: ` xml:space="preserve"`, want: "12"},
				{name: "conditional body removed", children: `<xsl:value-of use-when="false()" select="'discarded'"/>` + sortKey + body, want: "12", modern: true},
				{name: "conditional late sort removed", children: body + `<xsl:sort use-when="false()" select="@order"/>`, want: "21", modern: true},
			} {
				if tc.modern && profile.processor == processorXSLT10 {
					continue
				}

				t.Run(profile.version+"/"+instruction.name+"/"+tc.name, func(t *testing.T) {
					t.Parallel()

					stylesheet := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="` + profile.version + `">
						<xsl:output method="text"/>
						<xsl:template match="/"><xsl:` + instruction.name + ` select="r/n"` + instruction.attrs + tc.attrs + `>` + tc.children +
						`</xsl:` + instruction.name + `></xsl:template></xsl:stylesheet>`
					ss, err := NewCompiler().ProcessorVersion(profile.processor).Compile(t.Context(), parseTestDocument(t, stylesheet))
					if tc.code != "" {
						if detail, ok := errors.AsType[*XSLTError](err); ss != nil || !ok || detail.Code != tc.code {
							t.Fatalf("compile returned stylesheet=%t, error=%v, want no stylesheet and %s", ss != nil, err, tc.code)
						}

						return
					}

					if err != nil {
						t.Fatal(err)
					}

					got, err := ss.Transform(parseTestDocument(t, input)).Serialize(t.Context())
					requireSerialization(t, got, err, tc.want, "")
				})
			}
		}
	}
}

func TestValueOfEmptySelectionInSequenceOutput(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		version, selectExpr string
		processor, rawCount int
	}{
		{"1.0", "r/missing", processorXSLT10, 0},
		{"2.0", "()", processorXSLT20, 1},
		{"3.0", "()", processorXSLT30, 1},
	} {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			sheet := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="` + tc.version + `">
				<xsl:output method="text"/>
				<xsl:template match="/"><xsl:value-of select="` + tc.selectExpr + `"/></xsl:template>`
			if tc.rawCount > 0 {
				sheet += `<xsl:template name="typed">
					<xsl:variable name="value" as="text()"><xsl:value-of select="()"/></xsl:variable>
					<xsl:value-of select="concat(count($value), ':', string-length($value))"/>
				</xsl:template>
				<xsl:template name="adjacency">
					<out>
						<empty>[<xsl:sequence select="'a'"/><xsl:value-of select="()"/><xsl:sequence select="'b'"/>]</empty>
						<adjacent>[<xsl:sequence select="'a'"/><xsl:sequence select="'b'"/>]</adjacent>
						<space>[<xsl:sequence select="'a'"/><xsl:value-of select="'  '"/><xsl:sequence select="'b'"/>]</space>
					</out>
				</xsl:template>`
			}
			sheet += `</xsl:stylesheet>`
			ss, err := NewCompiler().ProcessorVersion(tc.processor).Compile(t.Context(), parseTestDocument(t, sheet))
			if err != nil {
				t.Fatal(err)
			}
			source := parseTestDocument(t, `<r/>`)
			t.Run("raw", func(t *testing.T) {
				t.Parallel()
				result, err := ss.Transform(source).Execute(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				items := result.Primary.Items
				if got := xdm.SequenceLen(items); got != tc.rawCount {
					t.Fatalf("raw result has %d items, want %d", got, tc.rawCount)
				}
				if tc.rawCount != 0 {
					node, ok := items.Get(0).(xdm.NodeItem)
					if !ok || xdm.IsNilNode(node.Node) || node.Node.Type() != xdm.TextNode || xdm.CharacterData(node.Node) != "" {
						t.Fatalf("raw item = %v, want a zero-length text node", items.Get(0))
					}
				}
			})
			if tc.rawCount > 0 {
				t.Run("typed", func(t *testing.T) {
					t.Parallel()
					got, err := ss.CallTemplate("typed").SourceDocument(source).Serialize(t.Context())
					requireSerialization(t, got, err, "1:0", "")
				})
				t.Run("complex content", func(t *testing.T) {
					t.Parallel()
					got, err := ss.CallTemplate("adjacency").SourceDocument(source).Serialize(t.Context())
					requireSerialization(t, got, err, "[ab][a b][a  b]", "")
				})
			}
		})
	}
}

func TestOutputItemSeparatorStaysAtSerializationBoundary(t *testing.T) {
	t.Parallel()

	const content = `<xsl:sequence select="(1,2)"/><inner/><xsl:sequence select="(3,4)"/>`
	for _, tc := range []struct{ name, separator, body, want string }{
		{"literal_element", "|", `<outer>` + content + `</outer><last/>`, "<outer>1 2<inner/>3 4</outer>|<last/>"},
		{"computed_element", "|", `<xsl:element name="outer">` + content + `</xsl:element><last/>`, "<outer>1 2<inner/>3 4</outer>|<last/>"},
		{"shallow_copy", "|", `<xsl:copy select="r">` + content + `</xsl:copy><last/>`, "<r>1 2<inner/>3 4</r>|<last/>"},
		{"nested_document", "|", `<outer><xsl:document>` + content + `</xsl:document></outer><last/>`, "<outer>1 2<inner/>3 4</outer>|<last/>"},
		{"nested_try", "|", `<outer><xsl:try>` + content + `<xsl:catch select="error()"/></xsl:try></outer><last/>`, "<outer>1 2<inner/>3 4</outer>|<last/>"},
		{"top_level_try", "|", `<xsl:try><outer>` + content + `</outer><xsl:catch select="error()"/></xsl:try><last/>`, "<outer>1 2<inner/>3 4</outer>|<last/>"},
		{"explicit_empty_separator", "", `<outer>` + content + `</outer><last/>`, "<outer>1 2<inner/>3 4</outer><last/>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			const prefix = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">
				<xsl:output method="xml" omit-xml-declaration="yes" item-separator="`
			const tail = `</xsl:template></xsl:stylesheet>`
			sheet := prefix + tc.separator + `"/><xsl:template match="/">` + tc.body + tail
			ss, err := NewCompiler().Compile(t.Context(), parseTestDocument(t, sheet))
			if err != nil {
				t.Fatal(err)
			}

			got, err := ss.Transform(parseTestDocument(t, "<r/>")).Serialize(t.Context())
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
			name: "complex_content_keeps_leading_trailing_and_repeated_empty_atomics",
			body: `<out>[<xsl:sequence select="(1, '', 2)"/>][<xsl:sequence select="('', '', 2)"/>][<xsl:sequence select="(1, '', '')"/>][<xsl:sequence select="('', '')"/>]</out>`,
			want: "[1  2][  2][1  ][ ]",
		},
		{
			name: "complex_content_keeps_empty_atomic_copies",
			body: `<out>[<xsl:copy-of select="(1, '', '', 2)"/>][<xsl:copy-of select="('', '')"/>]</out>`,
			want: "[1   2][ ]",
		},
		{
			name: "complex_content_keeps_empty_atomics_across_nested_constructor",
			body: `<out><xsl:sequence select="'before'"/>
				<xsl:if test="true()"><xsl:sequence select="('', '')"/></xsl:if>
				<xsl:sequence select="'after'"/>
			</out>`,
			want: "before   after",
		},
		{
			name: "on_non_empty_ignores_separators_but_keeps_them_without_on_empty",
			body: `<out>
				<xsl:sequence select="('', '')"/>
				<xsl:on-non-empty select="error()"/>
			</out>`,
			want: " ",
		},
		{
			name: "on_empty_of_parent_does_not_discard_child_content",
			body: `<out>
				<child><xsl:sequence select="('', '')"/></child>
				<xsl:on-empty select="error()"/>
			</out>`,
			want: " ",
		},
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
			name: "on_empty_discards_own_atomic_prefix_before_atomic_fallback",
			body: `<out><xsl:sequence select="('', '')"/><xsl:on-empty select="'fallback'"/></out>`,
			want: "fallback",
		},
		{
			name: "on_empty_discards_vacuous_copied_atomics",
			body: `<out><xsl:copy-of select="('', '')"/><xsl:on-empty select="'fallback'"/></out>`,
			want: "fallback",
		},
		{
			name: "on_empty_discards_vacuous_atomics_returned_by_try",
			body: `<out><xsl:try><xsl:sequence select="('', '')"/><xsl:catch select="error()"/></xsl:try>
				<xsl:on-empty select="'fallback'"/></out>`,
			want: "fallback",
		},
		{
			name: "nested_on_empty_discards_own_separator_without_touching_outer_text",
			body: `<out><xsl:sequence select="1"/>
				<xsl:if test="true()"><xsl:sequence select="('', '')"/><xsl:on-empty><xsl:text>fallback</xsl:text></xsl:on-empty></xsl:if>
			</out>`,
			want: "1fallback",
		},
		{
			name: "nested_on_empty_keeps_adjacency_of_prior_atomic_to_atomic_fallback",
			body: `<out><xsl:sequence select="1"/>
				<xsl:if test="true()"><xsl:sequence select="('', '')"/><xsl:on-empty select="'fallback'"/></xsl:if>
			</out>`,
			want: "1 fallback",
		},
		{
			name: "on_empty_keeps_all_separators_when_branch_is_not_vacuous",
			body: `<out><xsl:sequence select="(1, '', '', 2)"/><xsl:on-empty select="error()"/></out>`,
			want: "1   2",
		},
		{
			name: "wrapped_on_empty_keeps_the_same_vacuity_check",
			body: `<out>
				<xsl:sequence select="('', '')"/>
				<xsl:on-empty default-collation="http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive"><xsl:text>fallback</xsl:text></xsl:on-empty>
			</out>`,
			want: "fallback",
		},
		{
			name: "on_empty_handles_value_of_empty_selection",
			body: `<out>
				<xsl:value-of select="()"/>
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
			name: "deferred_attribute_after_zero_length_atomic_is_valid",
			body: `<xsl:variable name="out" as="element()"><out>
				<xsl:on-non-empty select="('', parse-xml('&lt;a status=&quot;ready&quot;/>')/a/@status)"/>
				<child/>
			</out></xsl:variable>
			<xsl:value-of select="($out/@status, name($out/*))" separator="|"/>`,
			want: "ready|child",
		},
		{
			name: "later_attribute_with_same_expanded_name_wins",
			body: `<xsl:variable name="out" as="element()"><out>
				<first>
					<xsl:on-non-empty><xsl:attribute name="p:status" namespace="urn:status">early</xsl:attribute></xsl:on-non-empty>
					<xsl:attribute name="q:status" namespace="urn:status">later</xsl:attribute>
					<child/>
				</first>
				<second>
					<xsl:attribute name="p:status" namespace="urn:status">early</xsl:attribute>
					<xsl:on-non-empty><xsl:attribute name="q:status" namespace="urn:status">later</xsl:attribute></xsl:on-non-empty>
					<child/>
				</second>
			</out></xsl:variable>
			<xsl:value-of select="$out/*/@*:status" separator="|"/>`,
			want: "later|later",
		},
		{
			name: "later_nested_conditional_attribute_wins",
			body: `<xsl:variable name="out" as="element()"><out>
				<xsl:on-non-empty><xsl:attribute name="status">early</xsl:attribute></xsl:on-non-empty>
				<xsl:if test="true()">
					<xsl:on-non-empty><xsl:attribute name="status">later</xsl:attribute></xsl:on-non-empty>
					<child/>
				</xsl:if>
			</out></xsl:variable>
			<xsl:value-of select="$out/@status"/>`,
			want: "later",
		},
		{
			name: "rolled_back_attribute_does_not_override_pending_attribute",
			body: `<xsl:variable name="out" as="element()"><out>
				<xsl:on-non-empty><xsl:attribute name="status">kept</xsl:attribute></xsl:on-non-empty>
				<xsl:try>
					<xsl:attribute name="status">discarded</xsl:attribute>
					<xsl:sequence select="error()"/>
					<xsl:catch/>
				</xsl:try>
				<child/>
			</out></xsl:variable>
			<xsl:value-of select="$out/@status"/>`,
			want: "kept",
		},
		{
			name: "deferred_attribute_after_element_is_rejected",
			body: `<out status="early"><child/>
				<xsl:on-non-empty><xsl:attribute name="status">late</xsl:attribute></xsl:on-non-empty>
			</out>`,
			code: "XTDE0410",
		},
		{
			name: "deferred_attribute_after_atomic_in_same_action_is_rejected",
			body: `<out>
				<xsl:on-non-empty select="(12, parse-xml('&lt;a status=&quot;late&quot;/>')/a/@status)"/>
				<child/>
			</out>`,
			code: "XTDE0410",
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

func TestExecuteTryCommitsAttributeAndNamespaceNodes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, body, want, code string }{
		{
			name: "tree_commit_replays_namespace_and_later_attribute_before_children",
			body: `<xsl:variable name="out" as="element()"><out>
				<xsl:on-non-empty><xsl:attribute name="status">early</xsl:attribute></xsl:on-non-empty>
				<xsl:try>
					<xsl:namespace name="q" select="'urn:explicit'"/>
					<xsl:attribute name="status">kept</xsl:attribute>
					<first/>
					<xsl:catch/>
				</xsl:try>
				<second/>
			</out></xsl:variable>
			<xsl:value-of select="($out/@status, string($out/namespace::q), $out/*/name())" separator="|"/>`,
			want: "kept|urn:explicit|first|second",
		},
		{
			name: "attribute_prefix_is_fixed_up_at_destination",
			body: `<xsl:variable name="out" as="element()"><out xmlns:p="urn:outer"><xsl:try>
				<xsl:attribute name="p:status" namespace="urn:attribute">kept</xsl:attribute>
				<xsl:catch/>
			</xsl:try><child/></out></xsl:variable>
			<xsl:value-of select="(string($out/namespace::p), namespace-uri($out/@*:status), $out/@*:status)" separator="|"/>`,
			want: "urn:outer|urn:attribute|kept",
		},
		{
			name: "raw_capture_keeps_attribute_and_namespace_once_in_order",
			body: `<xsl:variable name="items" as="item()*"><xsl:try>
				<xsl:namespace name="q" select="'urn:explicit'"/>
				<xsl:attribute name="status">kept</xsl:attribute>
				<xsl:sequence select="5"/>
				<xsl:catch/>
			</xsl:try></xsl:variable>
			<xsl:value-of select="(count($items), $items[1] instance of namespace-node(), $items[2] instance of attribute(status), $items[3])" separator="|"/>`,
			want: "3|true|true|5",
		},
		{
			name: "rollback_does_not_publish_attribute_or_namespace",
			body: `<xsl:variable name="out" as="element()"><out><xsl:try>
				<xsl:namespace name="q" select="'urn:discarded'"/>
				<xsl:attribute name="status">discarded</xsl:attribute>
				<xsl:sequence select="error()"/>
				<xsl:catch><xsl:attribute name="status">caught</xsl:attribute></xsl:catch>
			</xsl:try><child/></out></xsl:variable>
			<xsl:value-of select="($out/@status, empty($out/namespace::q), name($out/*))" separator="|"/>`,
			want: "caught|true|child",
		},
		{
			name: "destination_rejects_attribute_after_child",
			body: `<out><child/><xsl:try>
				<xsl:attribute name="status">late</xsl:attribute>
				<xsl:catch>caught inside</xsl:catch>
			</xsl:try></out>`,
			code: "XTDE0410",
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
