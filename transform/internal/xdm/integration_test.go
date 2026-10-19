package xdm_test

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

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
