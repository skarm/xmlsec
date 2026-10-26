package xdm_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestCopyNodePreservesNamespaceContext(t *testing.T) {
	t.Parallel()

	source, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<parent xmlns="urn:outer" xmlns:p="urn:value"><child xmlns="" type="p:T"><nested/></child></parent>`))
	if err != nil {
		t.Fatal(err)
	}

	destination, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<target xmlns="urn:destination" xmlns:p="urn:conflict"/>`))
	if err != nil {
		t.Fatal(err)
	}

	var before, after, output bytes.Buffer

	serializer := xdm.XMLSerialization{OmitDeclaration: true}
	if err := serializer.WriteTo(&before, source); err != nil {
		t.Fatal(err)
	}

	copied, err := xdm.CopyNode(source.DocumentElement().FirstChild(), destination)
	if err != nil {
		t.Fatal(err)
	}

	if err := destination.DocumentElement().AddChild(copied); err != nil {
		t.Fatal(err)
	}

	if err := serializer.WriteTo(&output, destination); err != nil {
		t.Fatal(err)
	}

	if err := serializer.WriteTo(&after, source); err != nil {
		t.Fatal(err)
	}

	if before.String() != after.String() {
		t.Fatal("copying changed the source namespace context")
	}

	for _, want := range []string{`xmlns="urn:destination"`, `xmlns=""`, `xmlns:p="urn:value"`, `type="p:T"`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %s in %s", want, output.String())
		}
	}
}

func TestCopyDocPreservesXDMProperties(t *testing.T) {
	t.Parallel()

	source, err := (xdm.ParseOptions{BaseURI: "https://example.test/source.xml"}).Parse(t.Context(), []byte(`<r><n/></r>`))
	if err != nil {
		t.Fatal(err)
	}
	source.SetProperties(xdm.DocInternal)
	xdm.SetNodeBaseURI(source.DocumentElement(), "https://example.test/constructed/")
	copied, err := xdm.CopyDoc(source)
	if err != nil {
		t.Fatal(err)
	}
	if copied.URL() != source.URL() || copied.Properties() != source.Properties() || xdm.NodeGetBase(copied, copied.DocumentElement().FirstChild()) != xdm.NodeGetBase(source, source.DocumentElement().FirstChild()) {
		t.Fatal("snapshot clone lost XDM properties")
	}
	if copied.Snapshot() == source.Snapshot() {
		t.Fatal("copy shares source nodes")
	}
	orphan, err := xdm.CopyTree(source.DocumentElement())
	if err != nil {
		t.Fatal(err)
	}
	if orphan.Parent() != nil || orphan.Type() != xdm.ElementNode || orphan.OwnerDocument().Properties() != source.Properties() || xdm.NodeGetBase(orphan.OwnerDocument(), orphan.FirstChild()) != "https://example.test/constructed/" {
		t.Fatal("tree clone lost the parentless root, document metadata or construction base")
	}
}

func TestElementDocumentPreservesContextAndOwnership(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, source string }{
		{"inherited prefix", `<parent xmlns:p="urn:qname"><child type="p:T"><nested/></child></parent>`},
		{"XML context and default reset", `<parent xmlns="urn:outer" xmlns:p="urn:qname"><child xmlns="" xml:id="own" xml:lang="ru" xml:space="preserve" xml:base="../base/" type="p:T"><nested/></child></parent>`},
		{"shadowed prefix", `<parent xmlns="urn:outer" xmlns:p="urn:old"><p:child xmlns:p="urn:new" type="p:T"><nested xmlns=""/></p:child></parent>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertElementDocumentCopy(t, tc.source)
		})
	}
}

func assertElementDocumentCopy(t *testing.T, input string) {
	t.Helper()

	source, err := (xdm.ParseOptions{BaseURI: "https://example.test/source.xml"}).Parse(t.Context(), []byte(input))
	if err != nil {
		t.Fatal(err)
	}

	selected := source.DocumentElement().FirstChild().(*xdm.Element)

	extracted, err := xdm.ElementDocument(t.Context(), selected)
	if err != nil {
		t.Fatal(err)
	}

	if extracted.URL() != source.URL() || extracted.DocumentElement().Reference().Document() == selected.Reference().Document() {
		t.Fatal("extraction lost the document URI or shared source ownership")
	}

	if !strings.Contains(input, `xmlns=""`) {
		for _, namespace := range extracted.DocumentElement().Namespaces() {
			if namespace.Prefix() == "" && namespace.URI() == "" {
				t.Fatal("standalone extraction added a synthetic default reset")
			}
		}
	}

	var before, after bytes.Buffer

	_, raw := tree.UnwrapNode(selected.Reference())
	if err := tree.Canonical(t.Context(), &before, source.Snapshot(), raw, nil, tree.CanonicalOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := tree.Canonical(t.Context(), &after, extracted.Snapshot(), nil, nil, tree.CanonicalOptions{}); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(before.Bytes(), after.Bytes()) {
		t.Fatalf("extraction changed names, XML attributes or content: %q != %q", after.Bytes(), before.Bytes())
	}

	for _, binding := range tree.Wrap(source.Snapshot(), tree.Root(source.Snapshot()).Children[0]).NamespaceNodes() {
		actual := xdm.LookupNSByPrefix(extracted.DocumentElement(), binding.Name().Local)
		if actual == nil || actual.URI() != binding.Value() {
			t.Fatal("extraction lost a QName namespace binding", binding.Name(), binding.Value())
		}
	}

	if err := extracted.DocumentElement().SetAttribute("changed", "private"); err != nil {
		t.Fatal(err)
	}

	if selected.HasAttribute("changed") {
		t.Fatal("mutating the extracted document changed its source")
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if result, err := xdm.ElementDocument(ctx, selected); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled extraction published a document", err)
	}
}

func TestFragmentUsesProjectNodeIdentity(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	options := xdm.ParseOptions{BaseURI: "urn:fragment"}

	doc, err := options.ParseFragment(ctx, `<r xmlns:p="urn:p" p:a="v"/>text<!--c--><?go ok?><s/>`)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for node := range xdm.Children(doc) {
		count++

		ref := node.Reference()
		if !ref.Valid() || ref.Document() != doc.Snapshot() || doc.NodeView(ref) != node {
			t.Fatalf("fragment node lost project identity: %v", node.Type())
		}
	}

	if count != 5 || doc.URL() != options.BaseURI {
		t.Fatalf("fragment: children=%d, base=%q", count, doc.URL())
	}

	attr := doc.DocumentElement().GetAttributeNodeNS("a", "urn:p")
	if attr == nil || doc.NodeView(attr.Reference()) != attr {
		t.Fatal("attribute identity lost")
	}
}

func TestXMLIDViewAndMutation(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<r xml:id=" old "/>`))
	if err != nil {
		t.Fatal(err)
	}
	root := doc.DocumentElement()
	if value, _ := root.GetAttribute("xml:id"); value != "old" || doc.GetElementByID("old") != root {
		t.Fatal("parsed value and ID index differ", value)
	}
	if value, _ := root.GetAttributeNS("id", tree.XMLNamespace); value != "old" {
		t.Fatal("namespace-based getter lost normalization", value)
	}
	for _, copyDocument := range []bool{false, true} {
		destination := xdm.NewDefaultDocument()
		var copied *xdm.Element
		if copyDocument {
			destination, err = xdm.CopyDoc(doc)
			if err == nil {
				copied = destination.DocumentElement()
			}
		} else {
			var node xdm.Node
			node, err = xdm.CopyNode(root, destination)
			if err == nil {
				copied = node.(*xdm.Element)
				err = destination.AddChild(copied)
			}
		}
		if err != nil || destination.GetElementByID("old") != copied {
			t.Fatal("copy lost the normalized ID", err)
		}
		if err := copied.SetAttributeNS("id", " new\t\r\n ", xdm.NewNamespace("xml", tree.XMLNamespace)); err != nil {
			t.Fatal(err)
		}
		if destination.GetElementByID("old") != nil || destination.GetElementByID("new") != copied || copied.GetAttributeNodeNS("id", tree.XMLNamespace).Value() != "new" {
			t.Fatal("replacement kept a stale ID")
		}
		if !copied.RemoveAttribute("xml:id") || destination.GetElementByID("new") != nil {
			t.Fatal("removal kept a stale ID")
		}
		if err := copied.SetAttribute("xml:id", " third "); err != nil {
			t.Fatal(err)
		}
		if value, _ := copied.GetAttribute("xml:id"); value != "third" || destination.GetElementByID("third") != copied {
			t.Fatal("recreated attribute kept a stale value", value)
		}
	}
	if root.GetAttributeNodeNS("id", tree.XMLNamespace).Value() != "old" || doc.GetElementByID("old") != root {
		t.Fatal("mutating the copy changed the source")
	}
	var output bytes.Buffer
	if err := (xdm.XMLSerialization{OmitDeclaration: true}).WriteTo(&output, doc); err != nil || output.String() != `<r xml:id="old"/>` {
		t.Fatal("serialization disagrees with the XDM attribute", output.String(), err)
	}
	if value := tree.Root(doc.Snapshot()).Attrs[0].Value; value != " old " {
		t.Fatal("view rewrote the original XML attribute", value)
	}
}

func TestAttributeValueIteration(t *testing.T) {
	// AllocsPerRun changes GOMAXPROCS and forbids concurrent parallel tests.

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<r xml:id=" own&#x9; " xmlns:p="urn:p" p:n="value" bare=""/>`))
	if err != nil {
		t.Fatal(err)
	}
	root := doc.DocumentElement()
	type attribute struct{ local, uri, value string }
	want := []attribute{{"id", tree.XMLNamespace, "own"}, {"n", "urn:p", "value"}, {"bare", "", ""}}
	var got []attribute
	root.ForEachAttributeValue(func(local, uri, value string) bool {
		got = append(got, attribute{local, uri, value})
		return true
	})
	if root.AttributeCount() != len(want) || len(got) != len(want) {
		t.Fatal("attribute count includes namespaces or loses values", root.AttributeCount(), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal("expanded name, stored order or normalized value changed", i, got[i], want[i])
		}
	}
	if raw := tree.Root(doc.Snapshot()).Attrs[0].Value; raw != " own\t " {
		t.Fatal("iteration rewrote the original xml:id snapshot", raw)
	}
	calls := 0
	root.ForEachAttributeValue(func(string, string, string) bool { calls++; return false })
	if calls != 1 {
		t.Fatal("attribute iteration continued after early stop", calls)
	}
	if allocations := testing.AllocsPerRun(10, func() {
		root.ForEachAttributeValue(func(string, string, string) bool { return false })
	}); allocations != 0 {
		t.Fatal("early attribute iteration constructed views or a slice", allocations)
	}
}

func TestAttributeIndexMutationAndConcurrentReads(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<r first="A" xmlns:p="urn:p" p:last="B" xml:id=" own "/>`))
	if err != nil {
		t.Fatal(err)
	}
	root := doc.DocumentElement()
	removed := root.GetAttributeNodeNS("first", "")
	last := root.GetAttributeNodeNS("last", "urn:p")
	id := root.GetAttributeNodeNS("id", tree.XMLNamespace)
	if !root.RemoveAttribute("first") || removed.Parent() != nil || last.Value() != "B" || id.Value() != "own" {
		t.Fatal("removing an earlier attribute invalidated retained views")
	}
	if err := root.SetAttributeNS("last", "updated", xdm.NewNamespace("q", "urn:p")); err != nil {
		t.Fatal(err)
	}
	if last.Value() != "updated" || last.Prefix() != "q" || last.Name() != "q:last" {
		t.Fatal("replacement or prefix change lost the indexed attribute")
	}
	if err := root.SetAttribute("first", "again"); err != nil {
		t.Fatal(err)
	}
	if replacement := root.GetAttributeNodeNS("first", ""); replacement == removed || replacement.Value() != "again" || root.AttributeCount() != 3 {
		t.Fatal("re-added attribute reused a removed view or the wrong position")
	}
	destination := xdm.NewDefaultDocument()
	if err := destination.AddChild(root); err != nil {
		t.Fatal(err)
	}
	if last.OwnerDocument() != destination || last.Value() != "updated" || last.Prefix() != "q" || id.Value() != "own" || destination.GetElementByID("own") != root {
		t.Fatal("adopting the element invalidated attribute positions or xml:id")
	}
	destination.Freeze()
	before := slices.Clone(tree.Root(destination.Snapshot()).Attrs)
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			for range 100 {
				if last.Value() != "updated" || last.Prefix() != "q" || id.Value() != "own" {
					t.Error("concurrent indexed reads changed attribute metadata")
				}
				// A retained removed view uses the read-only fallback. Reading it
				// must never populate a mutable cache in a shared frozen view.
				_ = removed.Value()
				_ = removed.Prefix()
			}
		})
	}
	readers.Wait()
	if !slices.Equal(before, tree.Root(destination.Snapshot()).Attrs) {
		t.Fatal("attribute reads rewrote the published raw snapshot")
	}
}

func TestDoctypeIsOnlyOutputMetadata(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	doc, err := (xdm.ParseOptions{}).Parse(ctx, []byte(`<r><a/></r>`))
	if err != nil {
		t.Fatal(err)
	}

	doc.SetDoctype("r", "", "urn:output")

	children, err := xdm.TraverseAxis(ctx, xdm.AxisDescendant, doc, 10)
	if err != nil || len(children) != 2 {
		t.Fatalf("doctype changed the node tree: %v, %v", children, err)
	}

	clone, err := xdm.CopyDoc(doc)
	if err != nil {
		t.Fatal(err)
	}

	clone.Doctype.SystemID = "urn:changed"
	if doc.Doctype.SystemID != "urn:output" {
		t.Fatal("copy shares mutable output metadata")
	}

	var output bytes.Buffer
	if err := (xdm.XMLSerialization{OmitDeclaration: true}).WriteTo(&output, doc); err != nil {
		t.Fatal(err)
	}

	if got, want := output.String(), `<!DOCTYPE r SYSTEM "urn:output"><r><a/></r>`; got != want {
		t.Fatalf("serialization=%q, want %q", got, want)
	}

	if _, err := (xdm.ParseOptions{}).Parse(ctx, output.Bytes()); !errors.Is(err, tree.ErrUnsupported) {
		t.Fatalf("input doctype accepted: %v", err)
	}
}

func TestDetachedNamespaceNode(t *testing.T) {
	t.Parallel()

	ns := xdm.NewNamespace("p", "urn:detached")

	n := xdm.NewNamespaceNodeWrapper(ns, nil)
	if n.OwnerDocument() != nil || n.Parent() != nil || n.Type() != xdm.NamespaceNode {
		t.Fatal("detached namespace acquired an owner")
	}

	if n.Name() != "p" || xdm.CharacterData(n) != "urn:detached" {
		t.Fatal("detached namespace lost its binding")
	}
}

func TestDTDSnapshotProperties(t *testing.T) {
	t.Parallel()

	const base = "https://example.test/source.xml"
	const source = `<!DOCTYPE r [<!NOTATION bin SYSTEM "urn:bin"><!ENTITY image SYSTEM "image.bin" NDATA bin><!ENTITY external SYSTEM "parts/value.ent"><!ATTLIST n identity ID #IMPLIED refs IDREFS #IMPLIED>]><r>&external;</r>`
	original, err := (xdm.ParseOptions{AllowDTD: true, BaseURI: base, DTDOpen: func(_ context.Context, uri string) (io.ReadCloser, error) {
		if uri != "https://example.test/parts/value.ent" {
			t.Fatal(uri)
		}
		return io.NopCloser(strings.NewReader(`<?p value?><n identity="a" refs="a"/>`)), nil
	}}).ParseText(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := xdm.CopyDoc(original)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := xdm.WrapDocument(t.Context(), copied.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range []*xdm.Document{original, copied, wrapped} {
		item := doc.DocumentElement().LastChild().(*xdm.Element)
		if item.GetAttributeNodeNS("identity", "").IDType() != xdm.IDAttribute || item.GetAttributeNodeNS("refs", "").IDType() != xdm.IDRefsAttribute || doc.GetElementByID("a") != item {
			t.Fatal("snapshot lost DTD ID properties")
		}
		entity, ok := doc.UnparsedEntity("image")
		if !ok || entity.SystemID != "image.bin" || entity.BaseURI != base {
			t.Fatal(entity, ok)
		}
		for _, node := range []xdm.Node{item, doc.DocumentElement().FirstChild()} {
			if got := xdm.NodeGetBase(doc, node); got != "https://example.test/parts/value.ent" {
				t.Fatal("snapshot lost external entity base", got)
			}
		}
	}
	item := copied.DocumentElement().LastChild().(*xdm.Element)
	if err := item.SetAttribute("identity", "b"); err != nil {
		t.Fatal(err)
	}
	if copied.GetElementByID("a") != nil || copied.GetElementByID("b") != item || original.GetElementByID("a") == nil {
		t.Fatal("ID index did not follow cloned attribute mutation")
	}
	if !item.RemoveAttribute("identity") {
		t.Fatal("existing DTD ID attribute was not reported removed")
	}
	if copied.GetElementByID("b") != nil {
		t.Fatal("removed DTD ID remains indexed")
	}
	if err := item.SetAttribute("identity", "c"); err != nil {
		t.Fatal(err)
	}
	if item.GetAttributeNodeNS("identity", "").IDType() != xdm.UntypedAttribute {
		t.Fatal("new attribute inherited removed DTD declaration")
	}
}
