package tree_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestCanonicalDocumentBoundaryOrder(t *testing.T) {
	t.Parallel()

	const source = `<!--before--><?prepare?><r>text<!--inside--><?item ready?></r><?complete done?><!--after-->`
	doc, err := tree.Parse(t.Context(), []byte(source), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	const withComments = "<!--before-->\n<?prepare?>\n<r>text<!--inside--><?item ready?></r>\n<?complete done?>\n<!--after-->"
	const withoutComments = "<?prepare?>\n<r>text<?item ready?></r>\n<?complete done?>"

	for _, tc := range []struct{ name, algorithm, want string }{
		{"default", "", withoutComments},
		{"exclusive_with_comments", tree.AlgorithmExclusive + "WithComments", withComments},
		{"canonical_10_with_comments", tree.AlgorithmCanonical10 + "#WithComments", withComments},
		{"canonical_11_with_comments", tree.AlgorithmCanonical11 + "#WithComments", withComments},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out strings.Builder
			err := tree.Canonical(t.Context(), &out, doc, nil, nil, tree.CanonicalOptions{Algorithm: tc.algorithm})
			if err != nil || out.String() != tc.want {
				t.Fatalf("Canonical = (%q, %v), want (%q, nil)", out.String(), err, tc.want)
			}
		})
	}
}

func TestCanonicalJoinsBaseForSelectedOrphan(t *testing.T) {
	t.Parallel()

	const source = `<r xml:base="https://example.test/root/" xml:id="root" xml:lang="en"><section xml:base="sections/" xml:space="preserve"><item xml:base="../entry?view#part" z="last" a="first">text</item><bare/></section></r>`
	doc, err := tree.Parse(t.Context(), []byte(source), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	section := doc.Root().Children()[0]
	item, bare := section.Children()[0], section.Children()[1]

	for _, tc := range []struct {
		name, algorithm, want string
		element               tree.Element
	}{
		{"exclusive_keeps_local_base", tree.AlgorithmExclusive, `<item a="first" z="last" xml:base="../entry?view#part">text</item>`, item},
		{"canonical_10_inherits_xml_attributes", tree.AlgorithmCanonical10, `<item a="first" z="last" xml:base="../entry?view#part" xml:id="root" xml:lang="en" xml:space="preserve">text</item>`, item},
		{"canonical_11_joins_relative_base", tree.AlgorithmCanonical11, `<item a="first" z="last" xml:base="https://example.test/root/entry?view" xml:lang="en" xml:space="preserve">text</item>`, item},
		{"canonical_11_inherits_base_when_absent", tree.AlgorithmCanonical11, `<bare xml:base="https://example.test/root/sections/" xml:lang="en" xml:space="preserve"></bare>`, bare},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set, err := tc.element.Subtree(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var out strings.Builder
			err = tree.Canonical(t.Context(), &out, doc, nil, &set, tree.CanonicalOptions{Algorithm: tc.algorithm})
			if err != nil || out.String() != tc.want {
				t.Fatalf("Canonical = (%q, %v), want (%q, nil)", out.String(), err, tc.want)
			}
		})
	}
}

func TestCanonicalRejectsConflictingSelectionAndOptions(t *testing.T) {
	t.Parallel()

	doc, err := tree.Parse(t.Context(), []byte(`<r><child/></r>`), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	set, err := doc.Root().Subtree(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root(doc)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	for _, tc := range []struct {
		name    string
		ctx     context.Context
		start   *tree.Node
		set     *tree.NodeSet
		options tree.CanonicalOptions
		wantErr error
	}{
		{name: "subtree_and_set", ctx: t.Context(), start: root, set: &set, wantErr: tree.ErrMalformed},
		{name: "set_and_exclusion", ctx: t.Context(), set: &set, options: tree.CanonicalOptions{Exclude: root.Children[0]}, wantErr: tree.ErrMalformed},
		{name: "unknown_algorithm", ctx: t.Context(), options: tree.CanonicalOptions{Algorithm: "urn:unknown"}, wantErr: tree.ErrUnsupported},
		{name: "inclusive_prefixes_for_nonexclusive_algorithm", ctx: t.Context(), options: tree.CanonicalOptions{Algorithm: tree.AlgorithmCanonical11, InclusivePrefixes: []string{"p"}}, wantErr: tree.ErrUnsupported},
		{name: "canceled", ctx: canceled, wantErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out strings.Builder
			err := tree.Canonical(tc.ctx, &out, doc, tc.start, tc.set, tc.options)
			if !errors.Is(err, tc.wantErr) || out.Len() != 0 {
				t.Fatalf("Canonical = (%q, %v), want empty output and %v", out.String(), err, tc.wantErr)
			}
		})
	}
}

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
