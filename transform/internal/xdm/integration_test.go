package xdm_test

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestElementDocumentPreservesContextAndOwnership(t *testing.T) {
	for _, input := range []string{
		`<parent xmlns:p="urn:qname"><child type="p:T"><nested/></child></parent>`,
		`<parent xmlns="urn:outer" xmlns:p="urn:qname"><child xmlns="" xml:id="own" xml:lang="ru" xml:space="preserve" xml:base="../base/" type="p:T"><nested/></child></parent>`,
		`<parent xmlns="urn:outer" xmlns:p="urn:old"><p:child xmlns:p="urn:new" type="p:T"><nested xmlns=""/></p:child></parent>`,
	} {
		t.Run(input, func(t *testing.T) { checkElementDocument(t, input) })
	}
}

func checkElementDocument(t *testing.T, input string) {
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
	ctx := context.Background()
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

func TestDoctypeIsOnlyOutputMetadata(t *testing.T) {
	ctx := context.Background()

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

func TestNestedValuesOwnMutableInputs(t *testing.T) {
	key := big.NewInt(7)
	number := big.NewRat(1, 10)
	array := xdm.NewArray([]xdm.Sequence{xdm.SingleDecimal(number)})
	value := xdm.NewMap([]xdm.MapEntry{{
		Key:   xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: key},
		Value: xdm.ItemSlice{array},
	}})
	key.SetInt64(9)
	number.SetInt64(3)

	for attempt := range 2 {
		seq, ok := value.Get(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(7)})
		if !ok {
			t.Fatal("mutation changed the stored map key")
		}

		stored, ok := seq.Get(0).(xdm.ArrayItem)
		if !ok {
			t.Fatalf("stored value: %T", seq.Get(0))
		}

		member, err := stored.Get(1)
		if err != nil {
			t.Fatal(err)
		}

		atomic, ok := member.Get(0).(xdm.AtomicValue)
		if !ok || atomic.BigRat().Cmp(big.NewRat(1, 10)) != 0 {
			t.Fatalf("attempt %d: stored decimal changed: %v", attempt, member)
		}

		atomic.BigRat().SetInt64(42)
	}

	if _, ok := value.Get(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(9)}); ok {
		t.Fatal("mutated key became visible")
	}
}

func TestArrayErrorsKeepQualifiedCodes(t *testing.T) {
	_, err := (xdm.ArrayItem{}).Get(1)

	var coded *xdm.Error
	if !errors.As(err, &coded) || coded.Code != "FOAY0001" || coded.CodeQName().Local != "FOAY0001" {
		t.Fatalf("lost structured array error: %v", err)
	}
}

func TestDetachedNamespaceNode(t *testing.T) {
	ns := xdm.NewNamespace("p", "urn:detached")

	n := xdm.NewNamespaceNodeWrapper(ns, nil)
	if n.OwnerDocument() != nil || n.Parent() != nil || n.Type() != xdm.NamespaceNode {
		t.Fatal("detached namespace acquired an owner")
	}

	if n.Name() != "p" || xdm.CharacterData(n) != "urn:detached" {
		t.Fatal("detached namespace lost its binding")
	}
}
