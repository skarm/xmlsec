package uripath_test

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
)

func TestResolveSchemaURI(t *testing.T) {
	const schemaPart = "part.xsd"

	for _, tc := range []struct {
		base string
		ref  string
		want string
	}{
		{"https://example.org/s/main.xsd", schemaPart, "https://example.org/s/part.xsd"},
		{"mem:/schemas/main.xsd", schemaPart, "mem:/schemas/part.xsd"},
		{"file:///schemas/main.xsd", schemaPart, "file:///schemas/part.xsd"},
		{"schemas", "parts/a.xsd", "schemas/parts/a.xsd"},
		{`schemas\parts`, `a.xsd`, "schemas/parts/a.xsd"},
		{"schemas", "urn:external", "urn:external"},
		{"file:///schemas/main.xsd?old#frag", "", "file:///schemas/main.xsd?old"},
		{"file:///schemas/main.xsd", "?query", "file:///schemas/main.xsd?query"},
		{"file:///schemas/main.xsd", "#", "file:///schemas/main.xsd#"},
		{"https://example.org/путь/main.xsd", "../%D0%B0?ключ=#", "https://example.org/%D0%B0?ключ=#"},
	} {
		t.Run(tc.base+"/"+tc.ref, func(t *testing.T) {
			got, err := uripath.ResolveSchemaURI(tc.ref, tc.base)
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}

	for _, ref := range []string{"../escape.xsd", `..\escape.xsd`, "sub/../../escape.xsd"} {
		if _, err := uripath.ResolveSchemaURI(ref, "schemas"); !errors.Is(err, uripath.ErrInvalidURI) {
			t.Errorf("escape %q: %v", ref, err)
		}
	}
}

func TestFileURIToPath(t *testing.T) {
	for _, uri := range []string{"file:///tmp/a%20b.xml", "file://LOCALHOST/tmp/a%20b.xml"} {
		got, err := uripath.FileURIToPath(uri)
		if err != nil || got != filepath.FromSlash("/tmp/a b.xml") {
			t.Errorf("%s: %q, %v", uri, got, err)
		}
	}

	for _, uri := range []string{"file:relative.xml", "file://localhost", "file://server/share/file.xml", "file:////server/share/file.xml", "https://example.org/a"} {
		if path, err := uripath.FileURIToPath(uri); err == nil {
			t.Errorf("nonlocal or invalid URI %q resolved to %q", uri, path)
		}
	}
}

func TestPortablePathShapes(t *testing.T) {
	for _, tc := range []struct {
		input    string
		absolute bool
		scheme   string
	}{
		{`C:\styles\main.xsl`, true, ""},
		{"D:/main.xsl", true, ""},
		{"C:relative", false, ""},
		{"/styles/main.xsl", true, ""},
		{"urn:example", false, "urn"},
		{"https://example.org/a", false, "https"},
	} {
		if uripath.IsAbsolutePath(tc.input) != tc.absolute || uripath.URIScheme(tc.input) != tc.scheme {
			t.Errorf("unexpected path classification for %q", tc.input)
		}
	}

	if got := uripath.SlashRel(`C:\a\b`, `C:\a\c\x.xml`); got != "../c/x.xml" {
		t.Errorf("relative Windows path = %q", got)
	}
}

func TestResolveIRIDotSegmentsAndEmptyComponents(t *testing.T) {
	const base = "http://a/b/c/d;p?q"
	for _, tc := range []struct{ ref, want string }{
		{"g", "http://a/b/c/g"},
		{"./g", "http://a/b/c/g"},
		{"../g", "http://a/b/g"},
		{"../../g", "http://a/g"},
		{"../../../g", "http://a/g"},
		{"g/./h", "http://a/b/c/g/h"},
		{"g/../h", "http://a/b/c/h"},
		{"g?y/../x", "http://a/b/c/g?y/../x"},
		{"g#s/../x", "http://a/b/c/g#s/../x"},
		{"?", "http://a/b/c/d;p?"},
		{"#", "http://a/b/c/d;p?q#"},
		{"g?#", "http://a/b/c/g?#"},
		{"%2E%2E/g", "http://a/b/c/%2E%2E/g"},
	} {
		got, err := uripath.ResolveIRIReference(tc.ref, base)
		if err != nil || got != tc.want {
			t.Fatalf("resolve %q: %q, %v; want %q", tc.ref, got, err, tc.want)
		}
	}

	for _, invalid := range []struct{ ref, base string }{{"g%", base}, {"g%0X", base}, {"g", "http://a/%Q0"}} {
		if got, err := uripath.ResolveIRIReference(invalid.ref, invalid.base); err == nil || got != "" {
			t.Fatalf("invalid URI accepted or partial result exposed: %q, %v", got, err)
		}
	}
}

func BenchmarkIRIResolution(b *testing.B) {
	for _, size := range []int{4, 1024} {
		ref := strings.Repeat("segment/../", size) + "file?query=#"
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(ref)))
			for b.Loop() {
				got, err := uripath.ResolveIRIReference(ref, "https://example.test/a/main.xsd")
				if err != nil || got != "https://example.test/a/file?query=#" {
					b.Fatal(got, err)
				}
			}
		})
	}
}
