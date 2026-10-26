package uripath_test

import (
	"path/filepath"
	"testing"

	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
)

func TestFileURIToPath(t *testing.T) {
	t.Parallel()

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

func TestLocalFileURIRejectsEncodedUNCPaths(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"file:///%5Cserver/share/file.xml", "file:///%2fserver/share/file.xml", "file:/%5c%5cserver/share/file.xml", "file://localhost:80/a", "file:/a%ZZ"} {
		if got, err := uripath.FileURIToPath(bad); err == nil || got != "" {
			t.Fatalf("nonlocal or malformed path accepted: %q => %q,%v", bad, got, err)
		}
	}
	if got, err := uripath.FileURIToPath("file:///tmp/%E4%B8%AD%20file.xml"); err != nil || got != filepath.FromSlash("/tmp/中 file.xml") {
		t.Fatal("local Unicode/space decoding changed", got, err)
	}
	for _, test := range []struct {
		path string
		unc  bool
	}{{"", false}, {"/", false}, {`\`, false}, {"//x", true}, {`/\x`, true}, {`\/x`, true}, {`\\x`, true}, {"/local", false}} {
		if got := uripath.IsUNCFileURIPath(test.path); got != test.unc {
			t.Fatalf("UNC shape %q=%v; want %v", test.path, got, test.unc)
		}
	}
}
