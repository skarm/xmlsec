package uripath_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
)

func TestResolveSchemaURI(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

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

func TestResolveIRIDotSegmentsAndEmptyComponents(t *testing.T) {
	t.Parallel()

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

func TestIRIResolutionAuthorityAndAbsoluteOverrides(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ base, ref, want string }{
		{"http://a", "g", "http://a/g"},
		{"http://a/b/c", "//g", "http://g"},
		{"http://a/b/c", "https://other/x/../y?#", "https://other/y?#"},
		{"http://a/b/c", "/g/.", "http://a/g/"},
		{"http://a/b/c", "/g/..", "http://a/"},
		{"http://a/b/c", ".", "http://a/b/"},
		{"http://a/b/c", "..", "http://a/"},
		{"http://a/b/c", "g/../..", "http://a/"},
		{"http://a/b/c", "g/..", "http://a/b/"},
		{"http://a/b/c", ".g", "http://a/b/.g"},
	} {
		if got, err := uripath.ResolveIRIReference(test.ref, test.base); err != nil || got != test.want {
			t.Fatalf("IRI resolution %q/%q = %q,%v; want %q", test.base, test.ref, got, err, test.want)
		}
	}
	if got, err := uripath.ResolveSchemaURI(`a\..\b.xsd`, ""); err != nil || got != "b.xsd" {
		t.Fatal("empty local base did not clean slash path", got, err)
	}
	if got, err := uripath.ResolveSchemaURI("URN:external", "%invalid-base"); err != nil || got != "URN:external" {
		t.Fatal("absolute reference inherited an irrelevant base", got, err)
	}
}

func TestResourceEscapingPreservesExistingEscapesAndDelimiters(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ input, want string }{
		{"https://example.test/é x?y=中&z=%2f#", "https://example.test/%C3%A9%20x?y=%E4%B8%AD&z=%2f#"},
		{"safe:/a%20b?x=1#fragment", "safe:/a%20b?x=1#fragment"},
		{"\x00\x1f\x7f\"<>{}|\\^`", "%00%1F%7F%22%3C%3E%7B%7D%7C%5C%5E%60"},
		{"", ""},
	} {
		if got := uripath.EscapeResourceReference(test.input); got != test.want {
			t.Fatalf("escaped=%q; want %q", got, test.want)
		}
	}
	for _, good := range []string{"", "%00", "%aF", "a%20b?x=%2f#%FF"} {
		if err := uripath.ValidatePercentEncoding(good); err != nil {
			t.Fatalf("valid percent escapes rejected: %q: %v", good, err)
		}
	}
	for _, bad := range []string{"%", "%0", "%gg", "path?query=%0G", "path#fragment=%Z0"} {
		if err := uripath.ValidatePercentEncoding(bad); err == nil {
			t.Fatalf("invalid percent escape accepted: %q", bad)
		}
	}
}
