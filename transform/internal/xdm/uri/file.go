// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package uripath

import (
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
)

// FileURIToPath converts a local file URI to a filesystem path.
// The host must be empty or localhost (case-insensitive); UNC paths, opaque
// URIs and empty paths are rejected. URI escaping is decoded before conversion.
func FileURIToPath(ref string) (string, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("failed to parse file URI %q: %w", ref, err)
	}

	if u.Scheme != "file" {
		return "", fmt.Errorf("not a file URI: %q", ref)
	}

	if u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
		return "", fmt.Errorf("non-local file URI host %q in %q", u.Host, ref)
	}

	if u.Opaque != "" || u.Path == "" {
		return "", fmt.Errorf("invalid file URI %q: no local path", ref)
	}

	// A "file:////server/share" URI parses to an empty host with a path that
	// begins with two separators; on Windows filepath.FromSlash would turn that
	// into a UNC path (\\server\share) reaching a remote SMB host, defeating the
	// local-only policy. Reject every UNC form outright.
	if IsUNCFileURIPath(u.Path) {
		return "", fmt.Errorf("UNC file URI %q is not a local path", ref)
	}

	return fileURIPathFor(runtime.GOOS, u.Path), nil
}

// fileURIPathFor is the OS-parameterized conversion of a "file:" URI path
// component into a local filesystem path. The drive-letter slash strip only
// applies on Windows; on POSIX "/C:/tmp/x" is a valid absolute path and is left
// untouched. goos is threaded explicitly so the conversion is deterministically
// testable on a non-Windows CI host.
func fileURIPathFor(goos, p string) string {
	if goos == "windows" && len(p) >= 3 && p[0] == '/' && xmlchar.IsASCIILetter(p[1]) && p[2] == ':' {
		p = p[1:]
	}

	return filepath.FromSlash(p)
}

// IsUNCFileURIPath reports whether p — the (already percent-decoded) path
// component of a "file:" URI — denotes a UNC path. A UNC path begins with two
// path separators ("\\server\share"); on Windows filepath.FromSlash turns such
// a path into a remote SMB reference, defeating the local-only policy applied by
// the "file:" URI loaders.
//
// url.Parse percent-decodes u.Path, so the two leading separators may appear as
// any mix of forward slash and backslash: "//" (from "file:////server/share"),
// "/\" (from "file:///%5Cserver/share", since %5C/%5c decode to a backslash), or
// "\\" (from doubly-encoded forms). All such forms are detected here so a single
// encoded backslash cannot smuggle a UNC path past the "//"-only check.
//
// This is the single source of truth for the UNC rejection shared by
// the explicit XPath and XSLT resource loaders.
func IsUNCFileURIPath(p string) bool {
	return len(p) >= 2 && isPathSep(p[0]) && isPathSep(p[1])
}

// isPathSep reports whether c is a path separator in either POSIX ("/") or
// Windows ("\") form. A decoded "file:" URI path may contain backslashes when
// the URI percent-encoded them as %5C/%5c.
func isPathSep(c byte) bool {
	return c == '/' || c == '\\'
}
