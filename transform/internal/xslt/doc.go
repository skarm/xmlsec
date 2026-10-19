// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

// Package xslt compiles and executes XSLT using transform/internal/xpath expressions and
// transform/internal/xdm values. The public transform package selects XSLT 1.0 or the
// Basic XSLT 2.0/3.0 profiles; schema awareness and streaming are unsupported.
//
// Compiled stylesheets are reusable across goroutines. Each invocation owns
// parameters, execution budgets, result trees and serialization settings.
// Source documents stay immutable; whitespace stripping uses private copies.
// Module and document loads share the XDM resolver and project XML limits.
package xslt
