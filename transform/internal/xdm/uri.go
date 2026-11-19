// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import (
	"net/url"
	"path"
	"strings"

	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
)

// BuildURI resolves a relative system ID against a base URI.
//
// The argument order is (reference, base), matching libxml2's xmlBuildURI.
// URI bases, including file: URIs, use IRI resolution. Local filesystem bases
// use forward-slash path joins that preserve POSIX roots and Windows volumes.
func BuildURI(systemID, base string) string {
	// An absolute systemID under either OS convention stands on its own.
	if uripath.IsWindowsAbsolute(systemID) {
		return systemID
	}

	// An absolute-URI systemID (one carrying a scheme, e.g. "http://host/p" or
	// "file:///x") stands on its own too, REGARDLESS of the base's shape. This
	// must be checked before the Windows-base branch below: when the base is a
	// native Windows path, that branch would otherwise treat the absolute URI as
	// a relative path segment and join it onto the base — collapsing "http://"
	// to "http:/" via path.Join. POSIX behavior is unchanged because the same
	// absoluteness is detected by url.Parse/IsAbs further down.
	if uripath.HasURIScheme(systemID) {
		return systemID
	}

	// A reference with no path inherits the full base path, even for a
	// filesystem base. Joining it as a relative filename would lose the
	// current document's name. URI bases use this resolver for all references.
	if systemID == "" || strings.HasPrefix(systemID, "?") || strings.HasPrefix(systemID, "#") || uripath.HasURIScheme(base) {
		resolved, err := uripath.ResolveIRIReference(systemID, base)
		if err != nil {
			return ""
		}

		return resolved
	}

	basePath, _ := splitLocalPathReference(base)

	// When the base is a native Windows path, resolve the (relative) systemID
	// against it with local-path semantics, bypassing the URI machinery so the
	// drive letter is never mistaken for a scheme. This also covers a RELATIVE
	// Windows base (a backslash-bearing path with no URI scheme, e.g.
	// "..\dir\doc.xml" as produced by filepath.Join on Windows): url.Parse would
	// treat the backslashes as opaque, drop the directory via path.Dir, and
	// resolve "world.txt" to a bare "world.txt" that no longer points inside the
	// base directory. buildLocalPathURI normalizes with uripath.ToSlash first, so
	// the directory is preserved on every OS. A backslash in a POSIX filename is
	// pathological and not a real base shape, so gating on '\' is safe.
	if uripath.IsWindowsAbsolute(basePath) || strings.ContainsRune(basePath, '\\') {
		return buildLocalPathURI(systemID, basePath)
	}

	// A previous resolution can have produced a slash-separated UNC base.
	// Keep its server and share instead of parsing the server as a URI host.
	if volume, _ := uripath.SplitLocalVolume(basePath); volume != "" && !uripath.IsPOSIXAbsolute(systemID) {
		return buildLocalPathURI(systemID, basePath)
	}

	if _, err := url.Parse(base); err != nil {
		return ""
	}

	if uripath.IsPOSIXAbsolute(systemID) {
		return systemID
	}

	// Resolve with forward-slash (path) semantics, not filepath, so the
	// returned URI/path uses '/' on every OS. On Windows filepath.Dir/Join
	// would emit '\' here and corrupt a POSIX-shaped or file:-URI base (a
	// sibling "a.Doctype" against "/dir/doc.xml" would become "\\dir\\a.Doctype").
	dir := path.Dir(basePath)
	if strings.HasSuffix(basePath, "/") {
		dir = basePath
	}

	return joinLocalPathReference(dir, systemID)
}

// buildLocalPathURI resolves a relative systemID against a native Windows base
// path. It works entirely in forward-slash space (so it is deterministic and
// testable on any GOOS): it normalizes both inputs with uripath.ToSlash (an
// unconditional backslash→slash conversion, unlike filepath.ToSlash which is a
// no-op on POSIX), strips the base's last path segment, and joins with path.Join
// (slash semantics). The forward-slash result is a valid path on Windows (the
// Win32 file APIs accept "/") and avoids the drive-letter-as-scheme corruption
// that url.Parse would produce. systemID is already known not to be
// Windows-absolute.
func buildLocalPathURI(systemID, base string) string {
	slashBase := uripath.ToSlash(base)
	slashRef := uripath.ToSlash(systemID)

	// Clean the rooted path independently of its volume. Otherwise path.Join
	// treats "C:" as a regular segment and can remove it when resolving "..".
	volume, slashBase := uripath.SplitLocalVolume(slashBase)

	if volume != "" && slashBase == "" {
		slashBase = "/"
	}

	dir := slashBase
	if idx := strings.LastIndexByte(slashBase, '/'); idx >= 0 {
		// Include the last slash so a file directly under a root keeps it.
		dir = slashBase[:idx+1]
	}

	result := joinLocalPathReference(dir, slashRef)
	// path.Join cleans the result, which collapses a leading "//" (UNC) to a
	// single "/". Restore the UNC double-slash when the base was a UNC path.
	if strings.HasPrefix(slashBase, "//") && !strings.HasPrefix(result, "//") {
		result = "/" + result
	}

	return volume + result
}

func joinLocalPathReference(dir, ref string) string {
	refPath, suffix := splitLocalPathReference(ref)
	result := path.Join(dir, refPath)

	last := path.Base(refPath)
	if !strings.HasSuffix(result, "/") && (strings.HasSuffix(refPath, "/") || last == "." || last == "..") {
		result += "/"
	}

	return result + suffix
}

func splitLocalPathReference(ref string) (string, string) {
	if i := strings.IndexAny(ref, "?#"); i >= 0 {
		return ref[:i], ref[i:]
	}

	return ref, ""
}
