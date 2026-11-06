package tree_test

import (
	"testing"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

const (
	parentPath                  = "../"
	twoParentsPath              = "../../"
	threeParentsPath            = "../../../"
	dotPrefixedRelativePath     = "..yes/"
	dotPrefixedAbsolutePath     = "/..yes/"
	absoluteDirectoryPath       = "/yes/"
	nestedRelativeDirectoryPath = "a/b/"
	baseURIWithQuery            = "http://a/b/c/d;p?q"
	resolvedRootURI             = "http://a/g"
	relativeDirectoryPath       = "yes/"
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
		{"no/../yes/", relativeDirectoryPath},
		{"no/../yes/no/..", relativeDirectoryPath},
		{"../../no/../..", threeParentsPath},
		{"no/../..", parentPath},
		{"no/..", ""},
		{"no/../", ""},
		{"/a/b/c/./../../g", "/a/g"},
		{"mid/content=5/../6", "mid/6"},
		{"../../..", threeParentsPath},
		{"no/../../", parentPath},
		{"..yes/..no/..no/..no/../../../..yes", "..yes/..yes"},
		{"..yes/..no/..no/..no/../../../..yes/", "..yes/..yes/"},
		{"../..", twoParentsPath},
		{threeParentsPath, threeParentsPath},
		{".", ""},
		{"./", ""},
		{"./.", ""},
		{"//no/..", "/"},
		{"../../no/..", twoParentsPath},
		{"../../no/../", twoParentsPath},
		{"yes/no/../", relativeDirectoryPath},
		{"yes/no/no/../..", relativeDirectoryPath},
		{"yes/no/no/no/../../..", relativeDirectoryPath},
		{"yes/no/../yes/no/no/../..", "yes/yes/"},
		{"yes/no/no/no/../../../yes", "yes/yes"},
		{"yes/no/no/no/../../../yes/", "yes/yes/"},
		{"/no/../", "/"},
		{"/yes/no/../", absoluteDirectoryPath},
		{"/yes/no/no/../..", absoluteDirectoryPath},
		{"/yes/no/no/no/../../..", absoluteDirectoryPath},
		{"../../..no/..", twoParentsPath},
		{"../../..no/../", twoParentsPath},
		{"..yes/..no/../", dotPrefixedRelativePath},
		{"..yes/..no/..no/../..", dotPrefixedRelativePath},
		{"..yes/...no/..no/..no/../../..", dotPrefixedRelativePath},
		{"..yes/..no/../..yes/..no/..no/../..", "..yes/..yes/"},
		{"/..no/../", "/"},
		{"/..yes/..no/../", dotPrefixedAbsolutePath},
		{"/..yes/..no/..no/../..", dotPrefixedAbsolutePath},
		{"/..yes/..no/..no/..no/../../..", dotPrefixedAbsolutePath},
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
		{"..", parentPath},
		{parentPath, parentPath},
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
		{"abc/", parentPath, ""},
		{parentPath, parentPath, twoParentsPath},
		{"..", "..", twoParentsPath},
		{baseURIWithQuery, "g", "http://a/b/c/g"},
		{baseURIWithQuery, "./g", "http://a/b/c/g"},
		{baseURIWithQuery, "/g", resolvedRootURI},
		{baseURIWithQuery, "//g", "http://g"},
		{baseURIWithQuery, "?y", "http://a/b/c/d;p?y"},
		{baseURIWithQuery, "#s", baseURIWithQuery},
		{baseURIWithQuery, "g?y#s", "http://a/b/c/g?y"},
		{baseURIWithQuery, "../../../g", resolvedRootURI},
		{"http://a", "g", resolvedRootURI},
		{"http://a/..", "g", resolvedRootURI},
		{"foo", "bar", "bar"},
		{nestedRelativeDirectoryPath, "%2e%2e/c", "a/b/%2e%2e/c"},
		{"a/b/?x", "?", "a/b/?"},
		{nestedRelativeDirectoryPath, "urn:test:thing", "urn:test:thing"},
		{nestedRelativeDirectoryPath, "http://z/x//y/../", "http://z/x/"},
		{"a/", "//host/x//y", "//host/x/y"},
		{nestedRelativeDirectoryPath, "x//y", "a/b/x/y"},
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
