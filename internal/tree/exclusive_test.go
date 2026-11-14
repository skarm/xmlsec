package tree_test

import (
	"bytes"
	"errors"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestExclusiveSubtreeOptions(t *testing.T) {
	t.Parallel()
	const source = `<r xmlns="urn:root" xmlns:p="urn:included" xmlns:q="urn:unused"><child b="2" a="1"><!--note--><skip/><v>&#xD;</v></child></r>`
	doc, err := tree.Parse(t.Context(), []byte(source), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	child := tree.Root(doc).Children[0]
	excluded := child.Children[1]
	for _, tc := range []struct {
		name string
		opt  tree.ExclusiveOptions
		want string
		err  error
	}{
		{"ordinary_subtree", tree.ExclusiveOptions{}, `<child xmlns="urn:root" a="1" b="2"><skip></skip><v>&#xD;</v></child>`, nil},
		{"inclusive_prefix_comments_and_exclusion", tree.ExclusiveOptions{Comments: true, InclusivePrefixes: []string{"p", "#default", "p"}, Exclude: excluded}, `<child xmlns="urn:root" xmlns:p="urn:included" a="1" b="2"><!--note--><v>&#xD;</v></child>`, nil},
		{"invalid_prefix", tree.ExclusiveOptions{InclusivePrefixes: []string{"p:q"}}, "", tree.ErrMalformed},
		{"reserved_prefix", tree.ExclusiveOptions{InclusivePrefixes: []string{"xmlns"}}, "", tree.ErrMalformed},
		{"negative_output_limit", tree.ExclusiveOptions{MaxBytes: -1}, "", tree.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := tree.Exclusive(t.Context(), &out, doc, child, tc.opt)
			if !errors.Is(err, tc.err) || out.String() != tc.want {
				t.Fatalf("output=%q, error=%v; want %q, %v", out.String(), err, tc.want, tc.err)
			}
		})
	}
}

func TestExclusiveFitsExactOutputBudget(t *testing.T) {
	t.Parallel()
	const want = "<r><a></a></r>"
	doc, err := tree.ParseReader(t.Context(), iotest.OneByteReader(bytes.NewBufferString("<r><a/></r>")), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := tree.Exclusive(t.Context(), &out, doc, nil, tree.ExclusiveOptions{MaxBytes: len(want)}); err != nil || out.String() != want {
		t.Fatalf("exact budget output=%q, error=%v; want %q", out.String(), err, want)
	}
	out.Reset()
	err = tree.Exclusive(t.Context(), &out, doc, nil, tree.ExclusiveOptions{MaxBytes: len(want) - 1})
	if !errors.Is(err, tree.ErrLimit) || out.Len() >= len(want) || out.String() != want[:out.Len()] {
		t.Fatalf("short budget output=%q, error=%v; want a truncated prefix and ErrLimit", out.String(), err)
	}
}
