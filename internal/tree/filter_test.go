package tree_test

import (
	"context"
	"errors"
	"testing"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

func TestFilterNodeSetKeepsSnapshotsIndependent(t *testing.T) {
	ctx := context.Background()

	d, err := treepkg.Parse(ctx, []byte(`<r><a x="1">text</a><!--c--><b/></r>`), treepkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	original, err := d.AllNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}

	count := original.Len()
	for _, keep := range []func(treepkg.NodeRef) bool{func(treepkg.NodeRef) bool { return true }, func(treepkg.NodeRef) bool { return false }, func(n treepkg.NodeRef) bool { return n.Kind() == treepkg.ElementNode }} {
		selected, err := treepkg.FilterNodeSet(ctx, original, keep)
		if err != nil {
			t.Fatal(err)
		}

		for _, n := range original.Nodes() {
			if selected.Contains(n) != keep(n) {
				t.Fatal("incorrect filtered membership", n.Kind())
			}
		}
		// Immutable public set operations must work even when a no-op filter shares
		// membership with its input.
		changed, err := selected.With(d.Root().Node())
		if err != nil || !changed.Contains(d.Root().Node()) {
			t.Fatal(changed, err)
		}

		removed, err := selected.Without(d.Root().Node())
		if err != nil || removed.Contains(d.Root().Node()) {
			t.Fatal(removed, err)
		}

		if original.Len() != count || !original.Contains(d.Root().Node()) {
			t.Fatal("input selection mutated")
		}
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	if _, err := treepkg.FilterNodeSet(canceled, original, func(treepkg.NodeRef) bool { return true }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
