# XPath and XSLT

`transform` implements selected features of XPath 1.0/2.0/3.0/3.1 and XSLT
1.0/2.0/3.0 through one pure-Go engine. Complete Basic XSLT conformance remains
open; [suite results](language-baseline.md) record the current failures. Compiled
programs and published documents support concurrent reuse with independent
invocation contexts and budgets.

```go
engine, err := transform.NewEngine(transform.Config{})
if err != nil { return err }
source, err := engine.Parse(ctx, []byte(`<order><price>0.1</price><price>0.2</price></order>`))
if err != nil { return err }
program, err := engine.CompileXPath(ctx,
    `sum(/order/price ! xs:decimal(.)) + $extra`,
    transform.XPathOptions{Version: transform.XPath31})
if err != nil { return err }
result, err := program.Evaluate(ctx, source, transform.XPathContext{
    Variables: transform.Bindings{
        {Local: "extra"}: transform.Values(transform.Integer(2)),
    },
})
if err != nil { return err }
total, err := result.Text() // "2.3"
if err != nil { return err }
fmt.Println(total)
```

See the runnable [XPath/XSLT example](../examples/transforms/main.go) and
`go doc ./transform` for complete option contracts.

XML byte input defaults to the DTD-free UTF-8/UTF-16 profile. Explicit
`Config.AllowSingleByteEncodings` also permits declared ASCII-compatible IANA
single-byte encodings, including ASCII, ISO-8859-1 and Windows-1252. It applies
to source documents, stylesheet modules and resolved XML resources. Undefined
bytes, BOM conflicts and unsupported encodings fail; raw input and decoded UTF-8
both obey `MaxInputBytes`. The option does not enable DTDs or external entities.

`parse-xml` and `fn:transform`'s `stylesheet-text` consume already decoded
characters. Their XML encoding declarations are checked for syntax and do not
reinterpret those characters as encoded bytes. `parse-xml-fragment` accepts the
external-entity TextDecl grammar, including a required encoding declaration,
without re-decoding characters. The complete original string counts against
the input limit before any declaration is removed.

## Contexts and values

`CompileXPath` snapshots namespace bindings and the static base URI; the default
version is 3.1. An empty prefix sets the default element namespace in XPath 2.0+.
XPath 1.0 accepts only node context items and has no default element namespace.
`XPathContext` supplies variables, focus and `DynamicContext`; `ContextItem`
overrides the document argument. Context-free expressions need neither.

External variable bindings are supplied at evaluation. XPath 2.0+ checks that
every free variable has a binding before executing the expression, including
references in unselected branches or empty iteration domains; a missing binding
raises `XPST0008`. An explicitly bound empty sequence counts as a binding.
Variable identity uses expanded names, and unprefixed variables have no namespace
regardless of the default element namespace. Local bindings shadow outer bindings
with the same expanded name.

`XSLTOptions.Version` checks the principal stylesheet's declared profile.
`ProcessorVersion` independently selects the processor; zero derives it from the
principal declaration. Selected processors 1.0/2.0/3.0 use XPath 1.0/2.0/3.1.
A modern processor accepts lower stylesheet declarations while preserving local
backwards-compatible behavior across principal, imported and included modules.
`Stylesheet.Version()` reports the selected processor. A 2.0 processor with a
principal 3.0 declaration and future 4.0 declarations remain unsupported; this
option does not establish complete forwards-compatible processing.
Static parameters bind during
compilation; `XSLTContext.Parameters` supplies globals during execution.
`InitialParameters` and `TunnelParameters` supply initial template/mode arguments.

Names use `document.Name{Space, Local}` (also `transform.Name`), independently of
prefixes. `Bindings` contains typed `Sequence` values: exact integers/decimals,
other atomics, nodes, maps, arrays and functions. Go accessors use zero-based
indices; XPath array lookup is one-based. Mutable numeric getters return copies.

Both invocation contexts expose `Context DynamicContext` for stable current time,
implicit timezone, default language and trace output. The timezone is a fixed
whole-minute offset within ±14 hours. Trace output is discarded unless configured.
Namespace bindings, base URIs and default collations are static settings.

Function conversion and cardinality apply to direct calls, named references and
`function-lookup` calls. `codepoints-to-string` requires integer values; integral
floating-point or decimal values need an explicit integer cast. The optional
second argument to the text-resource functions, when supplied, must be a single
string and is validated before resource access. Conversion scans and array
atomization consume invocation work/node budgets and observe cancellation.
Variadic `concat` references store a common parameter type, using space
independent of their declared arity.
The `||` operator applies the same atomic conversion and errors as `concat`.
Inline function annotations default to `item()*` for each omitted parameter
and result type; mixed annotations and empty result types retain their meaning
in function subtype tests.
Function conversion adapts every item in a function sequence and enforces
the declared cardinality, argument/result types and materialization budget.

XPath 3.1 `fn:transform` uses the same XSLT implementation as `CompileXSLT`.
It accepts stylesheet text, nodes and explicitly resolved locations or packages.
Global/static parameters, named entry points, raw/document/serialized results and
post-processing use the shared implementation. Secondary results are returned in
the result map. The call shares its invocation's deadline, operation, storage and
resource-load budgets. It has no implicit network or filesystem access.
Dynamic stylesheet sources are bounded by `MaxProgramBytes`; for node sources,
the bound is measured by streaming XML serialization without retaining a buffer.
`xslt-version` requests a minimum processor version using exact numeric comparison:
for example 2.5 or a decimal just above 2 selects 3.0;
an unavailable version reports `FOXT0001`. Without that option, the principal
stylesheet declaration selects the processor. Complete option conversion,
forwards-compatible processing and Basic language conformance remain open; see
[suite diagnostics](language-suites.md).

## XSLT results and XML identity

`Execute`, `ApplyTemplates`, `CallTemplate` and `CallFunction` return immutable
`Result` values. They select ordinary execution, an explicit sequence, a named
template or a public function. A named template can run without a source document.

`XSLTContext.ContextItem` sets the global context independently of the source
document and initial match selection. Nil retains the source-document default;
a pointer to a zero `Value` explicitly selects absence. The initial named template
defaults its singleton focus to that global item. Initial/tunnel parameters and
public function arguments retain their typed values.

`XPathOptions.DecimalFormats` supplies default and named static formats to
XPath 3.0/3.1 `format-number`. A zero `Name` selects the unnamed format; nested
property maps use standard names such as `decimal-separator`, `zero-digit` and
`NaN`. Omitted properties use standard defaults. Compilation copies the maps,
validates formatting characters and charges their data against `MaxProgramBytes`.
These options do not modify unrelated compiled programs or engine defaults.

`Primary`, `Secondary` and `Messages` expose typed output and diagnostics.
Secondary URIs resolve against `BaseOutputURI` when supplied and never write files.
`Serialize(ctx)` returns owned `Output` bytes using effective output definitions;
`Transform` combines execution and serialization. These return no partial `Output`
on error. `Result.WriterTo(ctx)`, `WriteSecondary` and `Stylesheet.Write` write
with byte counts and permit partial output. `Stylesheet.Write` rejects secondary
results. See [streaming](streaming.md) for memory requirements and record execution.

The JSON method preserves arrays and maps without sequence normalization. Empty
sequences become `null`; multiple items at the top level, in a map value or in
an array member raise `SERE0023`. Non-finite numbers, function items and duplicate
stringified keys raise `SERE0020`, `SERE0021` and `SERE0022`, respectively;
`allow-duplicate-names` controls the last check. These rules apply to primary and
secondary results, writer output, `fn:serialize` and serialized `fn:transform`
delivery. Serialization errors retain their specific codes through `fn:transform`.
XML parameter documents for `fn:serialize` use `SEPM0017` for invalid parameter
structure, `SEPM0018` for repeated character mappings and `SEPM0019` for repeated
parameter names. Incorrect argument types remain `XPTY0004`.

`Engine.Import` / `Export` share complete XML snapshots without serialization.
`ImportNode` / `Node.Reference` preserve individual node, attribute and namespace
identity. `Result.Document(ctx)` accepts one document or element; a selected
element becomes an independent snapshot with in-scope namespaces and without
unrelated ancestors or siblings.

## Extensions and resources

- `Config.Functions` registers `Function{Name, Arity, Call}` in application
  namespaces. Each expanded name has one fixed arity. Callbacks receive immutable
  arguments, must honor context and support concurrent calls. Direct calls,
  function references and `function-lookup` use the same registry.
- `Config.PackageResolver` enables `xsl:use-package` and dynamic loading. It returns
  `PackageResource{Reader, BaseURI}`; the compiler checks name/version, components,
  overrides and cycles. Version constraints support exact, `1.2.*`, `1.2+`, `to`
  ranges and comma-separated alternatives. Readers are closed; nested loads share
  resource budgets. No lookup is implicit.
- `Config.CollectionResolver` supplies `collection` / `uri-collection` through
  callbacks returning public values. An empty URI identifies the default collection.
- `Config.Resolver` supplies byte resources for imports and URI functions through
  the shared [resource contract](usage.md#common-contracts). Files and HTTP are
  available only through explicitly configured adapters. XML resources obey parser
  limits; `Config.Environment` exposes only explicitly supplied bindings.

For `unparsed-text`, `unparsed-text-lines` and `unparsed-text-available`, an
optional `resource.TypedReader` supplies the MIME type and external charset.
External encoding information takes precedence; XML media types use XML encoding
recognition before the function's encoding argument. Without such metadata,
the existing BOM/declaration heuristics and UTF-8 default apply. Conflicting BOMs,
unsupported encodings and malformed character sequences fail. Both encoded reads
and decoded output retain their respective budgets, including through nested
`fn:transform` calls. Metadata does not broaden the XML parser's input profile.

`XPath.Analyze(ctx)` computes function/context/navigation diagnostics on demand.
Its report does not prove streamability or authorize execution.

## Policy, limits and errors

`Config{}` selects bounded defaults. `Limits` controls input/program/output bytes,
nodes, sequences, operation work, recursion and timeout. Zero fields use defaults;
negative fields fail. `MaxResourceBytes` / `MaxResources` bound aggregate external
loads. `Serialize` / `Transform` share `MaxOutputBytes` across primary, secondary
and message bytes. Each writer call gets a fresh budget for its selected result.
Temporary strings and trees also consume budgets. Execution and serialization
have separate invocation budgets. Individual limits do not specify a combined
heap or RSS ceiling.

Numeric intermediates also use `MaxOutputBytes`. An integer costs
`max(1, ceil(bitlen(abs(value))/8))` bytes, independently of sign; zero costs one
byte. An exact decimal costs the sum of that measure for its reduced `big.Rat`
numerator and positive denominator, including the denominator one. IEEE float
and double values cost four and eight bytes. Numeric admission never formats a
decimal string just to measure its length. Serialized numeric text still obeys
the serialization byte limit.

Bindings (including map keys, map/array members and supplied context items) are
counted together on entry. During evaluation, each singleton numeric expression
result is charged, including repeated evaluation or forwarding of an existing
value; exact conversions and aggregate/quotient temporaries are also charged.
Built-in numeric results are charged on direct, function-item and higher-order
calls, including each item in a returned numeric sequence.
These charges share the invocation's cumulative byte budget with constructed
strings and trees. They bound accounted data and work, rather than live storage.
XPath AST, VM, reusable evaluation and calls from XSLT use the same budget.

Before exact arithmetic, numeric parsing and rounding powers, conservative
binary size bounds and work estimates are checked against the remaining byte
and operation budgets. Decimal bounds include unreduced numerator/denominator
products. Cancellation or a resource error propagates through `castable`.
Cancellation, reduction or a small final result does not refund earlier charges;
an operation may be rejected even when its reduced result would fit. Compilation
checks numeric literals before parsing them; it does not fold arithmetic.
Checks are cooperative: an individual `math/big` operation cannot necessarily be
interrupted, and these limits do not promise an exact heap or RSS ceiling.

The compiler enforces version-specific grammar and function arities. Schema
awareness, W3C streamable execution and shadow version attributes are unsupported.
Source schema-location hints do not trigger loading. Complete W3C conformance
has not been established; supported scope is in [compatibility](compatibility.md).

`Error.Operation` identifies the operation; `Error.Code` contains the local name
of an error code where present. Use `Error.CodeName()` for the expanded QName,
including the namespace of application errors. Use `errors.Is` for `ErrInput`,
`ErrUnsupported`, `ErrLimit` and context cancellation, and `errors.As` for
structured errors.

Pattern functions share an immutable bounded engine supporting Unicode classes,
subtraction, captures and back-references. Work/storage limits and cancellation
apply; there is no linear-time guarantee for back-references or nested counted
repetitions. Patterns are capped at 64 KiB of source, 8192 instructions and 128 captures,
counted loops and nesting levels. Each match also caps work at 2000000 units
and storage at 1048576 cells, in addition to invocation budgets.

## XMLDSig v1 compatibility

`Engine` implements `reference.ExtensionProcessor` / `ReaderExtensionProcessor`
for approved XPath 1.0, Filter2 and restricted XSLT 1.0 programs. XMLDSig URIs
retain their specified language semantics.

```go
approved := reference.Transform{
    Algorithm: reference.XPath,
    XPath: []reference.XPathExpression{{Expression: "not(ancestor-or-self::volatile)"}},
}
engine, err := transform.NewEngine(transform.Config{
    AllowedPrograms: []reference.Transform{approved},
})
if err != nil { return err }
processing := reference.DefaultOptions()
processing.Extension = engine
processing.AllowedTransforms = append(processing.AllowedTransforms, approved.Algorithm)
```

The application supplies exact trusted programs, including namespace bindings.
No program is approved by default. Registration of standalone application functions
does not enable them in XMLDSig transforms. `here()`, ID rules, node-set ownership
and ordered Filter2 expansion follow XMLDSig semantics. Program approval and
resource preflight apply before execution; received XML never grants approval.

Signature builders preserve program parameters through XML serialization.
Approval must include the complete namespace context of the parameter in the
signature (for example, the signature's `ds` binding and Filter2's `xf` binding).
Detached signing preflights all serialized recipes before resolving resources or
generating SignatureValue. Building XML does not add programs to the allowlist.
