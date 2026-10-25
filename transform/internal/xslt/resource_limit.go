// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"errors"
)

// MaxResourceBytes is the default maximum number of bytes read from a single
// external resource loaded through the configured URIResolver or
// PackageResolver — fn:doc / document(), xsl:import / xsl:include, xsl:use-package
// package loads, xsl:import-schema, fn:transform stylesheet sources, and
// serialization parameter documents. It guards against a hostile or pathological
// resource (e.g. an effectively unbounded HTTP body or a "/dev/zero"-style
// stream) exhausting memory via an unbounded io.ReadAll. XML parsing separately
// enforces the configured project limits and rejects DTDs and external entities.
//
// The cap additionally doubles as the match-count ceiling for
// xsl:analyze-string: an empty- or near-empty-matching regex matches at every
// character boundary, so the cap bounds how many matches the instruction will
// enumerate before failing with [ErrResourceTooLarge], keeping memory bounded
// regardless of input size.
const MaxResourceBytes = 10 << 20 // 10 MiB

// ErrResourceTooLarge is returned when an external resource exceeds
// [MaxResourceBytes], or when xsl:analyze-string enumerates more matches than
// the cap allows. The cap is enforced against the actual number of bytes read
// (not a Content-Length header, so a server that lies about its size cannot
// bypass it) and, for xsl:analyze-string, against the running match count. When
// a runtime read (fn:doc / document(), fn:transform stylesheet / package
// sources) or an xsl:analyze-string match enumeration trips the cap, the
// resulting error wraps both this sentinel and [ErrDynamicError]: errors.Is
// matches either one.
var ErrResourceTooLarge = errors.New("xslt: external resource exceeds maximum allowed size")

// resolveResourceLimit maps a configured cap to the value actually enforced:
// 0 selects the default [MaxResourceBytes] and a negative value disables the
// bound. Call sites pass the value configured on the Compiler / Invocation.
func resolveResourceLimit(configured int64) int64 {
	if configured == 0 {
		return MaxResourceBytes
	}

	return configured
}
