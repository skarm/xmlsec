// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

// Package xpath compiles and evaluates XPath over shared XDM values.
// The public transform package selects XPath 1.0, 2.0, 3.0 or 3.1 profiles,
// which constrain syntax, types and built-in functions.
//
// Compiled expressions retain static context and can be reused concurrently.
// Each evaluation owns its focus, variables and resource budgets. EvalState
// reuses mutable storage and must remain confined to one evaluation at a time.
// Caller-supplied values and node trees must remain unchanged during evaluation;
// shared resolvers, functions and trace writers must support concurrent calls.
//
// XML parsing follows xdm.ParseOptions. Resource access requires an explicit
// resolver, and fn:trace output is discarded unless a writer is configured.
// The supported public profiles are documented in transform and docs/transforms.md.
package xpath
