package transform_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

const (
	uriRootG        = "http://a/g"
	uriInvalidError = "FORG0002"
)

// TestResolveURIRFC3986 checks RFC 3986 sections 5.4.1 and 5.4.2. F&O returns
// absolute first arguments unchanged, before inspecting the base (including
// their dot segments).
func TestResolveURIRFC3986(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct{ relative, want string }{
		{"g:h", "g:h"},
		{"g", "http://a/b/c/g"},
		{"./g", "http://a/b/c/g"},
		{"g/", "http://a/b/c/g/"},
		{"/g", uriRootG},
		{"//g", "http://g"},
		{"?y", "http://a/b/c/d;p?y"},
		{"g?y", "http://a/b/c/g?y"},
		{"#s", "http://a/b/c/d;p?q#s"},
		{"g#s", "http://a/b/c/g#s"},
		{"g?y#s", "http://a/b/c/g?y#s"},
		{";x", "http://a/b/c/;x"},
		{"g;x", "http://a/b/c/g;x"},
		{"g;x?y#s", "http://a/b/c/g;x?y#s"},
		{"", "http://a/b/c/d;p?q"},
		{".", "http://a/b/c/"},
		{"./", "http://a/b/c/"},
		{"..", "http://a/b/"},
		{"../", "http://a/b/"},
		{"../g", "http://a/b/g"},
		{"../..", "http://a/"},
		{"../../", "http://a/"},
		{"../../g", uriRootG},
		{"../../../g", uriRootG},
		{"../../../../g", uriRootG},
		{"/./g", uriRootG},
		{"/../g", uriRootG},
		{"g.", "http://a/b/c/g."},
		{".g", "http://a/b/c/.g"},
		{"g..", "http://a/b/c/g.."},
		{"..g", "http://a/b/c/..g"},
		{"./../g", "http://a/b/g"},
		{"./g/.", "http://a/b/c/g/"},
		{"g/./h", "http://a/b/c/g/h"},
		{"g/../h", "http://a/b/c/h"},
		{"g;x=1/./y", "http://a/b/c/g;x=1/y"},
		{"g;x=1/../y", "http://a/b/c/y"},
		{"g?y/./x", "http://a/b/c/g?y/./x"},
		{"g?y/../x", "http://a/b/c/g?y/../x"},
		{"g#s/./x", "http://a/b/c/g#s/./x"},
		{"g#s/../x", "http://a/b/c/g#s/../x"},
		{"http:g", "http:g"},
		{"?", "http://a/b/c/d;p?"},
		{"#", "http://a/b/c/d;p?q#"},
	} {
		t.Run(tc.relative, func(t *testing.T) {
			expr := fmt.Sprintf(`resolve-uri(%q, 'http://a/b/c/d;p?q')`, tc.relative)
			for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
				if got := text(t, evaluate(t, e, expr, version)); got != tc.want {
					t.Errorf("XPath %v: got %q, want %q", version, got, tc.want)
				}
			}
		})
	}
}

func TestResolveURIBaseValidationAndIRIIdentity(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct{ expr, base, want, code string }{
		{`resolve-uri('g')`, "", "", "FONS0005"},
		{`resolve-uri('')`, "", "", "FONS0005"},
		{`resolve-uri('g', '')`, "https://example.test/base", "", uriInvalidError},
		{`resolve-uri('', 'relative')`, "", "", uriInvalidError},
		{`resolve-uri('', 'https://example.test/#part')`, "", "", uriInvalidError},
		{`resolve-uri('g', 'https://example.test/#')`, "", "", uriInvalidError},
		{`resolve-uri('g', 'urn:example:base')`, "", "", uriInvalidError},
		{`resolve-uri('%GG', 'https://example.test/')`, "", "", uriInvalidError},
		{`resolve-uri('https://example.test/x', '%GG')`, "", "https://example.test/x", ""},
		{`resolve-uri('https://example.test/x')`, "", "https://example.test/x", ""},
		{`resolve-uri('')`, "https://example.test/file?q", "https://example.test/file?q", ""},
		{`resolve-uri('g')`, "https://example.test/path/file", "https://example.test/path/g", ""},
		{`resolve-uri('g', 'https://example.test/é/%C3%A9/file')`, "", "https://example.test/é/%C3%A9/g", ""},
		{`resolve-uri('é/%C3%A9', 'https://example.test/path/file')`, "", "https://example.test/path/é/%C3%A9", ""},
		{`resolve-uri('g', 'HTTPS://example.test/path/file')`, "", "HTTPS://example.test/path/g", ""},
	} {
		t.Run(tc.expr+tc.base, func(t *testing.T) {
			q, err := e.CompileXPath(context.Background(), tc.expr, transform.XPathOptions{BaseURI: tc.base})
			if err != nil {
				t.Fatal(err)
			}

			result, err := q.Evaluate(context.Background(), nil, transform.XPathContext{})

			if tc.code != "" {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != tc.code {
					t.Fatalf("got %v, want %s", err, tc.code)
				}

				return
			}

			if err != nil || text(t, result) != tc.want {
				t.Fatalf("got %v, %v; want %q", result, err, tc.want)
			}
		})
	}

	for _, expr := range []string{`empty(resolve-uri(()))`, `empty(resolve-uri((), '%GG'))`, `empty(resolve-uri([], '%GG'))`} {
		if got := text(t, evaluate(t, e, expr, transform.XPath31)); got != nameTrue {
			t.Fatalf("%s: %s", expr, got)
		}
	}
}
