// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package uripath

import (
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"strings"
)

// ResolveSchemaURI resolves a schema-location reference ref against a base
// (the FULL location of the schema that contains the reference) and returns
// the canonical name to hand to the configured loader.
//
// It is the single canonical URI-resolution helper shared by the xsd nested
// xs:include/xs:import/xs:redefine path and by xslt's schema loader, so the
// two layers cannot drift apart again. Resolution branches on ref/base type:
//
//   - An ABSOLUTE-URI ref (it has its own scheme — with or without a "//"
//     authority, e.g. "https://cdn/part.xsd", "mem:/schemas/s.xsd",
//     "urn:schemas:s", "file:/tmp/s") addresses its own location and is
//     returned UNCHANGED, regardless of base. It must never be filepath.Join'ed
//     onto a base — doing so collapses the "//" authority separator (dropping
//     the host) or produces a bogus "/work/mem:/schemas/s".
//
//   - A relative ref against a URI base (the base has a scheme) is resolved
//     with RFC 3986 [url.URL.ResolveReference] semantics. The base's last path
//     segment is treated as the document and replaced, so a sibling "part.xsd"
//     against "mem:/schemas/main.xsd" resolves to "mem:/schemas/part.xsd". The
//     base authority is preserved, so a root-relative "/p" keeps scheme+host
//     and "../" applies dot-segment rules — never filepath collapsing. The
//     base's OmitHost flag is re-applied when the base had no authority (e.g.
//     "mem:/..." stays "mem:/...", never "mem:///...") while canonical
//     empty-authority bases like "file:///..." keep their "///".
//
//   - Otherwise (a genuine local filesystem base and ref) the historical
//     [filepath] join + ".."-escape guard is used unchanged: ref is joined onto
//     base and a result that ascends above base via ".." is rejected with
//     [ErrInvalidURI]. The base here is a DIRECTORY (the containing dir of
//     the schema), matching the xsd compiler's BaseDir convention.
//
// The escape guard mirrors the defense-in-depth path normalization in xinclude
// (#420/#425); the configured loader may further constrain, but catching the
// escape here gives consistent behavior across loaders.
func ResolveSchemaURI(ref, base string) (string, error) {
	// Absolute-URI ref: address its own location verbatim.
	if URIScheme(ref) != "" {
		return ref, nil
	}
	// Relative ref against a URI base: resolve per RFC 3986.
	if URIScheme(base) != "" {
		return resolveURIReference(base, ref)
	}
	// Local filesystem base + ref. Resolve in FORWARD-SLASH space so the
	// returned name — used as a key into the configured fs.FS, whose contract
	// mandates '/' (io/fs.ValidPath) — never gains backslashes on Windows, where
	// filepath.Join/Rel/Separator would otherwise produce "schemas\\x" and miss
	// every MapFS / os.DirFS key. The shape-based detection and slash math are
	// GOOS-independent, so the escape guard is exercised identically on POSIX.
	slashRef := ToSlash(ref)
	if base == "" {
		return path.Clean(slashRef), nil
	}

	slashBase := ToSlash(base)
	p := path.Join(slashBase, slashRef)

	rel, err := filepath.Rel(slashBase, p)
	if err != nil {
		// Rel only fails when one is absolute and the other isn't;
		// nothing actionable here — accept and let the loader decide.
		return p, nil //nolint:nilerr
	}

	rel = ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("%w: %q", ErrInvalidURI, ref)
	}

	return p, nil
}

// resolveURIReference resolves a relative reference against a URI base using
// RFC 3986 semantics. The base is the FULL schema URI (e.g.
// "https://example.com/s/main.xsd"); url.URL.ResolveReference treats its last
// path segment as the document and replaces it, so a sibling "part.xsd"
// resolves to "https://example.com/s/part.xsd".
//
// It re-applies the base's OmitHost flag when the base had no authority and the
// resolved reference introduced none: net/url's ResolveReference returns a
// fresh URL that does NOT carry OmitHost, so a no-authority base like
// "mem:/schemas/main.xsd" would otherwise emit an empty "//" authority
// ("mem:///schemas/part.xsd") and miss an exact-match loader keyed on
// "mem:/...". Canonical empty-authority bases like "file:///..." (OmitHost
// false) keep their "///".
func resolveURIReference(baseURI, ref string) (string, error) {
	base, err := url.Parse(baseURI)
	if err != nil {
		return "", fmt.Errorf("%w: invalid base URI %q", ErrInvalidURI, baseURI)
	}

	refURL, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("%w: invalid reference %q", ErrInvalidURI, ref)
	}

	resolved := base.ResolveReference(refURL)
	if base.OmitHost && resolved.Host == "" && resolved.User == nil {
		resolved.OmitHost = true
	}

	return resolved.String(), nil
}
