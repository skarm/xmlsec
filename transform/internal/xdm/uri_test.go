package xdm_test

import (
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestBuildURIReferenceFirstPortableResolution(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ reference, base, want string }{
		{"../image.svg", "https://example.test/a/doc.xml", "https://example.test/image.svg"},
		{"?q=é#part", "https://example.test/a/doc.xml?old", "https://example.test/a/doc.xml?q=é#part"},
		{"child/", "/a/doc.xml", "/a/child/"},
		{"child.xml", "/a/", "/a/child.xml"},
		{"/absolute.xml", "relative/doc.xml", "/absolute.xml"},
		{"child.xml", "", "child.xml"},
		{"https://other.test/a", `C:\a\doc.xml`, "https://other.test/a"},
		{`D:\other\absolute.xml`, "https://example.test/base", `D:\other\absolute.xml`}, //nolint:misspell // Literal Windows path; the backslash precedes the word other.
		{`..\child\`, `C:\a\doc.xml`, "C:/child/"},
		{"child.xml", `..\a\doc.xml`, "../a/child.xml"},
		{"child.xml", `\\server\share\a\doc.xml`, "//server/share/a/child.xml"},
		{"child.xml", "file:///a/doc.xml?old#old", "file:///a/child.xml"},
		{"child.xml", "http://[broken", ""},
		{"child.xml", "%zz", ""},
	} {
		if got := xdm.BuildURI(tc.reference, tc.base); got != tc.want {
			t.Fatalf("BuildURI(%q,%q)=%q; want %q", tc.reference, tc.base, got, tc.want)
		}
	}
}

func TestBuildURIPreservesFilesystemRoots(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ reference, base, want string }{
		{"child.xml", "/", "/child.xml"},
		{"child.xml", `\doc.xml`, "/child.xml"},
		{"../child.xml", `C:\doc.xml`, "C:/child.xml"},
		{".", `C:\doc.xml`, "C:/"},
		{"child.xml", `\\server\share`, "//server/share/child.xml"},
		{"../child.xml", `\\server\share\doc.xml`, "//server/share/child.xml"},
		{"child.xml", "//server/share/", "//server/share/child.xml"},
		{"draft/..?v=1#part", "/styles/main.xml", "/styles/?v=1#part"},
	} {
		if got := xdm.BuildURI(tc.reference, tc.base); got != tc.want {
			t.Errorf("BuildURI(%q,%q)=%q; want %q", tc.reference, tc.base, got, tc.want)
		}
	}
}
