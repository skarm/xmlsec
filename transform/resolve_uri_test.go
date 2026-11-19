package transform_test

import (
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
	for _, tc := range []struct {
		relative string
		want     string
	}{
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
	for _, tc := range []struct {
		expr string
		base string
		want string
		code string
	}{
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
		{"resolve-uri('item', 'https://example.test//file')", "", "", uriInvalidError},
		{"resolve-uri('https://example.test/item#', '%GG')", "", "", uriInvalidError},
		{"resolve-uri('https://.example.test/item', '')", "", "", uriInvalidError},
		{"resolve-uri('?mark=', 'https://example.test/path/file')", "", "https://example.test/path/file?mark=", ""},
		{`resolve-uri('%EE%80%80', 'https://example.test/')`, "", "https://example.test/%EE%80%80", ""},
	} {
		t.Run(tc.expr+tc.base, func(t *testing.T) {
			q, err := e.CompileXPath(t.Context(), tc.expr, transform.XPathOptions{BaseURI: tc.base})
			if err != nil {
				t.Fatal(err)
			}

			result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})

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

func TestResolveIRIAuthoritySyntax(t *testing.T) {
	t.Parallel()

	e := engine(t, transform.Config{})
	for _, tc := range []struct{ name, expr, want string }{
		{"absolute_reference", `resolve-uri('test://ex%61mple/root/../item', '%GG')`, "test://ex%61mple/root/../item"},
		{"base_registered_name", `resolve-uri('item', 'test://ex%61mple/root/')`, "test://ex%61mple/root/item"},
		{"network_reference", `resolve-uri('//reader@ex%61mple:80/root', 'test://base/x')`, "test://reader@ex%61mple:80/root"},
		{"ipvfuture_literal", `resolve-uri('item', 'test://[v1.a:b]:80/root/')`, "test://[v1.a:b]:80/root/item"},
		{"ipv6_literal", `resolve-uri('item', 'test://[2001:db8::1]:80/root/')`, "test://[2001:db8::1]:80/root/item"},
		{"internationalized_userinfo", `resolve-uri('item', 'test://réader@example/root/')`, "test://réader@example/root/item"},
		{"internationalized_userinfo_ipv6", `resolve-uri('//réader@[2001:db8::1]:80/root', 'test://base/x')`, "test://réader@[2001:db8::1]:80/root"},
		{"internationalized_userinfo_ipvfuture", `resolve-uri('item', 'test://réader@[v1.a:b]:80/root/')`, "test://réader@[v1.a:b]:80/root/item"},
		{"internationalized_userinfo_registered_name", `resolve-uri('item', 'test://réader@ex%61mple/root/')`, "test://réader@ex%61mple/root/item"},
		{"invalid_userinfo_noncharacter", "resolve-uri('item', 'test://réader\uFFFE@example/root/')", ""},
		{"invalid_escape", `resolve-uri('item', 'test://ex%6Xmple/root/')`, ""},
		{"invalid_registered_name", `resolve-uri('item', 'test://ex%61mple]/root/')`, ""},
		{"invalid_ipvfuture_version", `resolve-uri('item', 'test://[vg.a:b]/root/')`, ""},
		{"invalid_ipvfuture_address", `resolve-uri('item', 'test://[v1.]/root/')`, ""},
		{"invalid_port", `resolve-uri('item', 'test://ex%61mple:no/root/')`, ""},
		{"multiple_ports", `resolve-uri('item', 'test://[v1.a:b]:12:80/root/')`, ""},
		{"multiple_ports_with_internationalized_userinfo", `resolve-uri('item', 'test://réader@example:12:80/root/')`, ""},
		{"unescaped_at_in_userinfo", `resolve-uri('item', 'test://one@two@ex%61mple/root/')`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			q, err := e.CompileXPath(t.Context(), tc.expr, transform.XPathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
			if tc.want == "" {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != uriInvalidError {
					t.Fatalf("got %v, %v; want %s", result, err, uriInvalidError)
				}

				return
			}

			if err != nil || text(t, result) != tc.want {
				t.Fatalf("got %v, %v; want %q", result, err, tc.want)
			}
		})
	}
}
