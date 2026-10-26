package uripath_test

import (
	"testing"

	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
)

func TestPortablePathAndSchemeBoundaries(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		input             string
		drive, win, posix bool
		scheme            string
	}{
		{"", false, false, false, ""},
		{"C", false, false, false, ""},
		{"C:", true, true, false, ""},
		{"z:/a", true, true, false, ""},
		{`A:\a`, true, true, false, ""},
		{"C:relative", false, false, false, ""},
		{`\rooted`, false, true, false, ""},
		{`\\server\share`, false, true, false, ""},
		{"/absolute", false, false, true, ""},
		{"relative/path", false, false, false, ""},
		{"1:/bad", false, false, false, ""},
		{"é:/bad", false, false, false, ""},
		{"HTTP://host/a", false, false, false, "http"},
		{"urn:example", false, false, false, "urn"},
		{"custom+v1.2-x:resource", false, false, false, "custom+v1.2-x"},
		{"ab:resource", false, false, false, "ab"},
		{"a:b", false, false, false, ""},
		{"bad_scheme:value", false, false, false, ""},
		{"name/path:part", false, false, false, ""},
		{"scheme-without-colon", false, false, false, ""},
	} {
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()

			if uripath.HasWindowsDrivePrefix(test.input) != test.drive || uripath.IsWindowsAbsolute(test.input) != test.win || uripath.IsPOSIXAbsolute(test.input) != test.posix || uripath.IsAbsolutePath(test.input) != (test.win || test.posix) {
				t.Fatal("path shape misclassified")
			}
			if got := uripath.URIScheme(test.input); got != test.scheme || uripath.HasURIScheme(test.input) != (test.scheme != "") {
				t.Fatalf("scheme=%q; want %q", got, test.scheme)
			}
		})
	}
	for _, test := range []struct{ path, want string }{
		{`C:\dir\file.xml`, "file:///C:/dir/file.xml"},
		{"D:/dir/file.xml", "file:///D:/dir/file.xml"},
		{`\\server\share\file.xml`, "file://server/share/file.xml"},
	} {
		if got := uripath.WindowsToFileURI(test.path); got != test.want {
			t.Fatalf("WindowsToFileURI(%q)=%q; want %q", test.path, got, test.want)
		}
	}
}

func TestSlashPathArithmeticPreservesRootsAndFallbacks(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ base, ref, want string }{
		{`C:\a\b`, `..\c\item.xml`, "C:/a/c/item.xml"}, {"/a/b", "../c", "/a/c"},
	} {
		if got := uripath.JoinLocalBaseDir(test.base, test.ref); got != test.want {
			t.Fatalf("join=%q; want %q", got, test.want)
		}
	}
	for _, test := range []struct{ input, base, dir, clean string }{
		{"", ".", ".", "."},
		{"/", "/", "/", "/"},
		{"/a/b///", "/a/b", "/a/b", "/a/b"},
		{`C:\a\main.xsl`, "C:/a", "C:/a", "C:/a/main.xsl"},
		{"a.b/", "a.b", "a.b", "a.b"},
		{"a/b", "a/b", "a", "a/b"},
		{"a/./b/../main.xsl", "a", "a", "a/main.xsl"},
	} {
		if got := uripath.LocalBaseDir(test.input); got != test.base {
			t.Fatalf("LocalBaseDir(%q)=%q; want %q", test.input, got, test.base)
		}
		if got := uripath.SlashDir(test.input); got != test.dir {
			t.Fatalf("SlashDir(%q)=%q; want %q", test.input, got, test.dir)
		}
		if got := uripath.SlashClean(test.input); got != test.clean {
			t.Fatalf("SlashClean(%q)=%q; want %q", test.input, got, test.clean)
		}
	}
	for _, test := range []struct{ base, target, want string }{
		{`C:\a\b`, `C:\a\c\x.xml`, "../c/x.xml"},
		{"/a/b", "/a/b", "."},
		{"/a/b", "/a/c/item", "../c/item"},
		{"a/b", "a", ".."},
		{".", "a/b", "a/b"},
		{"/", "/a/b", "a/b"},
		{"a", "/a/b", "/a/b"},
		{"/a", "b/../c", "c"},
		{"../a", "b/./c", "b/c"},
	} {
		if got := uripath.SlashRel(test.base, test.target); got != test.want {
			t.Fatalf("SlashRel(%q,%q)=%q; want %q", test.base, test.target, got, test.want)
		}
	}
	for _, test := range []struct{ a, b, want string }{
		{"/a/one.xml", "/b/two.xml", "/"},
		{"/a/b/one.xml", "/a/c/two.xml", "/a"},
		{"a/one.xml", "b/two.xml", "."},
		{"one.xml", "two.xml", "."},
		{`C:\a\one.xml`, `C:\a\two.xml`, "C:/a"},
	} {
		if got := uripath.SlashCommonDir(test.a, test.b); got != test.want {
			t.Fatalf("common dir=%q; want %q", got, test.want)
		}
	}
}
