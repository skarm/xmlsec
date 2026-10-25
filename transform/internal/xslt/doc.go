// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

// Package xslt compiles and executes XSLT with shared XPath expressions and
// XDM values. The public transform package selects XSLT 1.0 or Basic XSLT
// 2.0/3.0 profiles. Schema-aware processing is unavailable, and execution uses
// materialized trees without a W3C streamability guarantee.
//
// Compiled stylesheets can be reused concurrently. Each invocation owns its
// parameters, execution budgets, result trees and serialization settings.
// Source documents remain read-only; whitespace stripping uses private copies.
// Host-supplied handlers, resolvers and writers must support concurrent calls
// when shared between invocations.
//
// Module and document retrieval require explicit resolvers and follow the
// configured XML parsing and resource limits. Raw-result handlers can retain
// XDM items before serialization; ordinary output uses a result tree.
package xslt
