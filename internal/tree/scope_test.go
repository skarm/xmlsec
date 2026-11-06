package tree_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/internal/tree"
)

func TestScopedCanonicalContextAndReparse(t *testing.T) {
	raw := []byte(`<S:Envelope xmlns:S="urn:envelope" xml:lang="ru" xml:space="preserve"><S:Body><p:message xmlns:p="urn:protocol" ID="_message"><p:value>old</p:value></p:message></S:Body></S:Envelope>`)
	d, err := tree.Parse(t.Context(), raw, tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	e := d.Root().Children()[0].Children()[0]
	scope, err := tree.ScopeDocument(d, e)
	if err != nil {
		t.Fatal(err)
	}
	var want, got bytes.Buffer
	if err := c14n.WriteElement(t.Context(), &want, e, c14n.Options{Algorithm: c14n.Canonical10}); err != nil {
		t.Fatal(err)
	}
	if err := c14n.WriteDocument(t.Context(), &got, scope, c14n.Options{Algorithm: c14n.Canonical10}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want.Bytes(), got.Bytes()) || !bytes.Contains(got.Bytes(), []byte(`xml:lang="ru"`)) {
		t.Fatalf("lost inherited context: %s != %s", got.String(), want.String())
	}
	set, err := scope.Root().Subtree(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got.Reset()
	if err := c14n.WriteNodeSet(t.Context(), &got, set, c14n.Options{Algorithm: c14n.Canonical10}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want.Bytes(), got.Bytes()) {
		t.Fatal("node-set lost scoped ancestor context")
	}
	if len(scope.Root().Attributes()) != 1 {
		t.Fatal("schema-constrained root gained attributes")
	}
	if _, err := scope.XML(t.Context()); !errors.Is(err, tree.ErrUnsupported) {
		t.Fatal("silently flattened ancestor XML attributes")
	}
	clone, err := tree.Clone(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	tree.Root(clone).Children[0].Children[0].Data = "new"
	published, err := tree.Reparse(t.Context(), clone, tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	got.Reset()
	if err := c14n.WriteDocument(t.Context(), &got, published, c14n.Options{Algorithm: c14n.Canonical10}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), bytes.Replace(want.Bytes(), []byte("old"), []byte("new"), 1)) {
		t.Fatal("reparse changed inherited context")
	}
	after, _ := d.XML(t.Context())
	if !bytes.Equal(after, raw) {
		t.Fatal("source snapshot mutated")
	}
	replacement := &tree.Node{Kind: tree.ElementNode, Name: tree.Name{Space: "urn:protocol", Local: "replacement"}, Prefix: "p"}
	draft, err := tree.ReplaceDraft(t.Context(), scope, tree.Root(scope).Children[0], replacement)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tree.Reparse(t.Context(), draft, tree.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
}

func TestScopedNodeSelectionAndNamespaceLimits(t *testing.T) {
	limits := tree.DefaultLimits()
	source, err := tree.Parse(t.Context(), []byte(`<outer xmlns:p="urn:protocol" xmlns:q="urn:context"><p:message><p:value/></p:message><unselected/></outer>`), limits)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := tree.ScopeDocument(source, source.Root().Children()[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Run("parent stays inside snapshot", func(t *testing.T) {
		if !scope.Root().Node().Parent().Same(scope.Node()) {
			t.Fatal("scoped root navigates into the outer document")
		}
	})
	t.Run("all nodes retains namespace context", func(t *testing.T) {
		all, err := scope.AllNodes(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		subtree, err := scope.Root().Subtree(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if all.Len() != subtree.Len()+1 {
			t.Fatalf("all nodes = %d; subtree plus document = %d", all.Len(), subtree.Len()+1)
		}
		for _, node := range subtree.Nodes() {
			if !all.Contains(node) {
				t.Fatalf("all nodes omitted %s %q", node.Kind(), node.Name().Local)
			}
		}
		for _, node := range all.Nodes() {
			if parent := node.Parent(); parent.Valid() && !all.Contains(parent) {
				t.Fatal("scoped node has a parent outside the selected snapshot")
			}
			for _, child := range node.Children() {
				if !all.Contains(child) || !child.Parent().Same(node) {
					t.Fatal("scoped child and parent axes disagree")
				}
			}
		}
		for _, algorithm := range []string{c14n.Exclusive, c14n.Canonical10, c14n.Canonical11} {
			var direct, selected bytes.Buffer
			if err := c14n.WriteDocument(t.Context(), &direct, scope, c14n.Options{Algorithm: algorithm}); err != nil {
				t.Fatal(err)
			}
			if err := c14n.WriteNodeSet(t.Context(), &selected, all, c14n.Options{Algorithm: algorithm}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(direct.Bytes(), selected.Bytes()) {
				t.Fatalf("%s canonical context changed: %q != %q", algorithm, direct.String(), selected.String())
			}
		}
	})
	t.Run("namespace budget includes ancestors", func(t *testing.T) {
		limits.MaxInScopeNamespaces = 2 // The original scope contains xml, p and q.
		if err := tree.CheckSnapshotLimits(t.Context(), scope, limits); !errors.Is(err, tree.ErrLimit) {
			t.Fatal("inherited namespaces bypassed snapshot limits", err)
		}
		limits.MaxInScopeNamespaces = 3
		if err := tree.CheckSnapshotLimits(t.Context(), scope, limits); err != nil {
			t.Fatal("exact inherited namespace budget was rejected", err)
		}
	})
}
