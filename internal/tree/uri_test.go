package tree_test

import (
	"testing"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

const (
	name2         = "../"
	name3         = "../../"
	name4         = "../../../"
	nameYes       = "..yes/"
	nameYes2      = "/..yes/"
	nameYes3      = "/yes/"
	nameAB        = "a/b/"
	uriHTTPABCDPQ = "http://a/b/c/d;p?q"
	uriHTTPAG     = "http://a/g"
	nameYes4      = "yes/"
)

// TestRemoveDotSegmentsAppendixA checks the private dot-segment primitive against
// the examples in C14N 1.1 Appendix A.
// Public integration, inheritance and sparse-set behavior are tested externally
// in c14n_test. No additional exported URI API exists merely for these tests.
func TestRemoveDotSegmentsAppendixA(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"no/.././/pseudo-netpath/seg/file.ext", "pseudo-netpath/seg/file.ext"},
		{"no/..//.///pseudo-netpath/seg/file.ext", "pseudo-netpath/seg/file.ext"},
		{"yes/no//..//.///pseudo-netpath/seg/file.ext", "yes/pseudo-netpath/seg/file.ext"},
		{"no/../yes", "yes"},
		{"no/../yes/", nameYes4},
		{"no/../yes/no/..", nameYes4},
		{"../../no/../..", name4},
		{"no/../..", name2},
		{"no/..", ""},
		{"no/../", ""},
		{"/a/b/c/./../../g", "/a/g"},
		{"mid/content=5/../6", "mid/6"},
		{"../../..", name4},
		{"no/../../", name2},
		{"..yes/..no/..no/..no/../../../..yes", "..yes/..yes"},
		{"..yes/..no/..no/..no/../../../..yes/", "..yes/..yes/"},
		{"../..", name3},
		{name4, name4},
		{".", ""},
		{"./", ""},
		{"./.", ""},
		{"//no/..", "/"},
		{"../../no/..", name3},
		{"../../no/../", name3},
		{"yes/no/../", nameYes4},
		{"yes/no/no/../..", nameYes4},
		{"yes/no/no/no/../../..", nameYes4},
		{"yes/no/../yes/no/no/../..", "yes/yes/"},
		{"yes/no/no/no/../../../yes", "yes/yes"},
		{"yes/no/no/no/../../../yes/", "yes/yes/"},
		{"/no/../", "/"},
		{"/yes/no/../", nameYes3},
		{"/yes/no/no/../..", nameYes3},
		{"/yes/no/no/no/../../..", nameYes3},
		{"../../..no/..", name3},
		{"../../..no/../", name3},
		{"..yes/..no/../", nameYes},
		{"..yes/..no/..no/../..", nameYes},
		{"..yes/...no/..no/..no/../../..", nameYes},
		{"..yes/..no/../..yes/..no/..no/../..", "..yes/..yes/"},
		{"/..no/../", "/"},
		{"/..yes/..no/../", nameYes2},
		{"/..yes/..no/..no/../..", nameYes2},
		{"/..yes/..no/..no/..no/../../..", nameYes2},
		{"/", "/"},
		{"/.", "/"},
		{"/./", "/"},
		{"/./.", "/"},
		{"/././", "/"},
		{"/..", "/"},
		{"/../..", "/"},
		{"/../../..", "/"},
		{"//..", "/"},
		{"//..//..", "/"},
		{"//..//..//..", "/"},
		{"/./..", "/"},
		{"/./.././..", "/"},
		{"/./.././.././..", "/"},
		{"..", name2},
		{name2, name2},
	}
	for _, tt := range cases {
		t.Run(tt.in, func(t *testing.T) {
			if got := treepkg.RemoveDotSegmentsForTest(tt.in); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestJoinURIReferences(t *testing.T) {
	cases := []struct {
		base string
		ref  string
		want string
	}{
		{"abc/", name2, ""},
		{name2, name2, name3},
		{"..", "..", name3},
		{uriHTTPABCDPQ, "g", "http://a/b/c/g"},
		{uriHTTPABCDPQ, "./g", "http://a/b/c/g"},
		{uriHTTPABCDPQ, "/g", uriHTTPAG},
		{uriHTTPABCDPQ, "//g", "http://g"},
		{uriHTTPABCDPQ, "?y", "http://a/b/c/d;p?y"},
		{uriHTTPABCDPQ, "#s", uriHTTPABCDPQ},
		{uriHTTPABCDPQ, "g?y#s", "http://a/b/c/g?y"},
		{uriHTTPABCDPQ, "../../../g", uriHTTPAG},
		{"http://a", "g", uriHTTPAG},
		{"http://a/..", "g", uriHTTPAG},
		{"foo", "bar", "bar"},
		{nameAB, "%2e%2e/c", "a/b/%2e%2e/c"},
		{"a/b/?x", "?", "a/b/?"},
		{nameAB, "urn:test:thing", "urn:test:thing"},
		{nameAB, "http://z/x//y/../", "http://z/x/"},
		{"a/", "//host/x//y", "//host/x/y"},
		{nameAB, "x//y", "a/b/x/y"},
	}
	for _, tt := range cases {
		t.Run(tt.base+"+"+tt.ref, func(t *testing.T) {
			got, err := treepkg.JoinURIReferencesForTest(tt.base, tt.ref)
			if err != nil || got != tt.want {
				t.Fatalf("got %q err %v want %q", got, err, tt.want)
			}
		})
	}

	for _, bad := range []string{"%xx", "a b", ":bad", "http://[invalid"} {
		if _, err := treepkg.JoinURIReferencesForTest(bad, "a"); err == nil {
			t.Fatalf("accepted %q", bad)
		}

		if _, err := treepkg.JoinURIReferencesForTest("a", bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
