package tree_test

import (
	"strings"
	"testing"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

func BenchmarkClone(b *testing.B) {
	d, err := treepkg.Parse(b.Context(), []byte(`<r>`+strings.Repeat(`<item a="1">text</item>`, 100)+`</r>`), treepkg.DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := treepkg.Clone(b.Context(), d); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFilterNodeSet(b *testing.B) {
	d, err := treepkg.Parse(b.Context(), []byte(`<r><drop>`+strings.Repeat(`<item a="1">text</item>`, 100)+`</drop><keep>`+strings.Repeat(`<item a="1">text</item>`, 100)+`</keep></r>`), treepkg.DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}

	set, err := d.AllNodes(b.Context())
	if err != nil {
		b.Fatal(err)
	}

	drop := d.Root().Children()[0]

	for name, keep := range map[string]func(treepkg.NodeRef) bool{
		"All":      func(treepkg.NodeRef) bool { return true },
		"None":     func(treepkg.NodeRef) bool { return false },
		"Elements": func(n treepkg.NodeRef) bool { return n.Kind() == treepkg.ElementNode },
		"Subtree":  func(n treepkg.NodeRef) bool { return !treepkg.NodeWithin(n, drop) },
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				if _, err := treepkg.FilterNodeSet(b.Context(), set, keep); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
