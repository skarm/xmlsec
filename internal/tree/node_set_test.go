package tree_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestNodeSetOperationsPreserveSnapshotAndDocumentOrder(t *testing.T) {
	t.Parallel()
	limits := tree.DefaultLimits()
	limits.MaxNodeSetNodes = 3
	const input = `<r><a/><b/><c/><d/></r>`
	doc, err := tree.Parse(t.Context(), []byte(input), limits)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := tree.Parse(t.Context(), []byte(input), limits)
	if err != nil {
		t.Fatal(err)
	}
	children := doc.Root().Node().Children()
	if len(children) != 4 {
		t.Fatalf("fixture has %d child nodes, want 4", len(children))
	}
	a, b, c, d := children[0], children[1], children[2], children[3]
	left, err := tree.NewNodeSet(doc, c, a, c)
	if err != nil {
		t.Fatal(err)
	}
	right, err := tree.NewNodeSet(doc, b, c)
	if err != nil {
		t.Fatal(err)
	}
	overLimit, err := tree.NewNodeSet(doc, b, d)
	if err != nil {
		t.Fatal(err)
	}
	wrongSnapshot, err := tree.NewNodeSet(foreign, foreign.Root().Node())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		apply func() (tree.NodeSet, error)
		want  []tree.NodeRef
		err   error
	}{
		{"union", func() (tree.NodeSet, error) { return left.Union(right) }, []tree.NodeRef{a, b, c}, nil},
		{"intersection", func() (tree.NodeSet, error) { return left.Intersect(right) }, []tree.NodeRef{c}, nil},
		{"difference", func() (tree.NodeSet, error) { return left.Difference(right) }, []tree.NodeRef{a}, nil},
		{"valid_empty_difference", func() (tree.NodeSet, error) { return left.Difference(left) }, nil, nil},
		{"add_duplicate_at_limit", func() (tree.NodeSet, error) { return left.With(b, c, b) }, []tree.NodeRef{a, b, c}, nil},
		{"remove_present_and_absent", func() (tree.NodeSet, error) { return left.Without(c, b) }, []tree.NodeRef{a}, nil},
		{"union_limit", func() (tree.NodeSet, error) { return left.Union(overLimit) }, nil, tree.ErrLimit},
		{"foreign_snapshot", func() (tree.NodeSet, error) { return left.Intersect(wrongSnapshot) }, nil, tree.ErrMalformed},
		{"uninitialized_set", func() (tree.NodeSet, error) { return left.Difference(tree.NodeSet{}) }, nil, tree.ErrMalformed},
		{"foreign_node_removal", func() (tree.NodeSet, error) { return left.Without(foreign.Root().Node()) }, nil, tree.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.apply()
			if tc.err != nil {
				if got.Valid() || !errors.Is(err, tc.err) {
					t.Fatalf("result valid=%t, error=%v; want invalid result and %v", got.Valid(), err, tc.err)
				}
				return
			}
			if err != nil || !got.Valid() || got.Document() != doc || !slices.Equal(got.Nodes(), tc.want) {
				t.Fatalf("result=%v, error=%v; want nodes %v from the original snapshot", got.Nodes(), err, tc.want)
			}
			ordered := got.Nodes()
			if len(ordered) > 0 {
				ordered[0] = tree.NodeRef{}
				if !slices.Equal(got.Nodes(), tc.want) {
					t.Error("changing the returned slice changed the set")
				}
			}
			if !slices.Equal(left.Nodes(), []tree.NodeRef{a, c}) || !slices.Equal(right.Nodes(), []tree.NodeRef{b, c}) {
				t.Error("an input set changed")
			}
		})
	}
}
