// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

// Package xpath compiles and evaluates XPath 1.0, 2.0, 3.0 and 3.1 expressions
// over transform/internal/xdm values. Language profiles bound syntax and built-in functions.
// Compilation owns static context; each evaluation owns variables and budgets.
// XML parsing uses xdm.ParseOptions and resources require an explicit resolver.
//
// Compiled expressions are reusable across goroutines. The public API and
// supported profiles are documented in transform and docs/transforms.md.
package xpath
