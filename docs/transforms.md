# XPath and XSLT

`transform` provides selected XPath 1.0/2.0/3.0/3.1 and XSLT 1.0/2.0/3.0 features.
Compiled programs and published documents support concurrent reuse; each call has
its own context, variables and budgets. Supported scope is in
[compatibility](compatibility.md); complete Basic XSLT conformance remains open.

```go
engine, err := transform.NewEngine(transform.Config{})
if err != nil { return err }
source, err := engine.Parse(ctx, []byte(`<order><price>0.1</price><price>0.2</price></order>`))
if err != nil { return err }
program, err := engine.CompileXPath(ctx, `sum(/order/price ! xs:decimal(.)) + $extra`,
    transform.XPathOptions{Version: transform.XPath31})
if err != nil { return err }
result, err := program.Evaluate(ctx, source, transform.XPathContext{
    Variables: transform.Bindings{{Local: "extra"}: transform.Values(transform.Integer(2))},
})
if err != nil { return err }
total, err := result.Text() // "2.3"
if err != nil { return err }
fmt.Println(total)
```

See [runnable examples](../examples/transforms/main.go) and `go doc ./transform`
for complete option contracts.

## XML input profiles

`Engine.Parse`, record input and approved XMLDSig programs use the DTD-free
UTF-8/UTF-16 security profile. `AllowSingleByteEncodings` additionally permits
supported ASCII-compatible IANA encodings; raw and decoded bytes remain bounded.

Language XML input (`doc`, `parse-xml`, stylesheets and document resources) uses
bounded nonvalidating DTD processing: entities, default attributes and declared
attribute normalization are supported. External DTD/entities require an explicit
resolver and invocation policy; there is no implicit file/network access.
Fragments reject DOCTYPE. This does not enable DTD/XSD validation or schema awareness.

Character-input functions receive already decoded text. Encoding declarations
are checked for syntax without reinterpreting the characters as encoded bytes.
Malformed encodings, entity cycles and exhausted parser budgets fail.

## Contexts and values

`CompileXPath` copies namespace bindings, collation and static base URI. Its
default version is 3.1. An empty prefix sets the default element namespace in
XPath 2.0+; unprefixed variables still have no namespace.
`XPath10Compatibility` changes conversions while retaining the selected modern
grammar. XPath 1.0 accepts only node context items.

`XPathContext` supplies typed variables, focus and `DynamicContext`.
`ContextItem` overrides the document argument; context-free expressions need
neither. Every free variable needs a binding, including unused branches;
an explicitly bound empty sequence is valid.

`Bindings` uses expanded names and immutable `Sequence` values: atomics, nodes,
maps, arrays and functions. Go indexes are zero-based; XPath array lookup is
one-based. Mutable numeric getters return copies. Function values retain their
static language context and use the current caller's resource policy/budgets.

`XSLTOptions.Version` checks the stylesheet declaration. `ProcessorVersion`
independently selects the processor; zero derives it from the principal module.
Selected 1.0/2.0/3.0 processors use XPath 1.0/2.0/3.1. Modern processors preserve
local backwards compatibility in older modules; higher/future declarations use
forwards-compatible processing. `Stylesheet.Version()` reports the processor.

Static parameters bind during compilation. `XSLTContext.Parameters` supplies
globals; `InitialParameters` / `TunnelParameters` supply initial calls.
`ContextItem` controls global context independently of initial selection.
`DynamicContext` sets stable current time, implicit timezone, language and trace
output. The timezone must be whole minutes within ±14 hours.

`XMLSchemaVersion` selects datatype/regex rules, defaulting to 1.1; it does not
validate schemas or annotate nodes. `EnableXSLTAssertions` enables direct
`xsl:assert` checking, default off. Nested `fn:transform` independently uses
`enable-assertions`. `DisableXSLTDynamicEvaluation` disables `xsl:evaluate` for
direct/nested compilation and packages; it defaults to false.

`fn:transform` uses the same engine with explicitly supplied stylesheet text,
nodes, locations or packages. It shares invocation limits and has no implicit
resource access. `xslt-version` requests a minimum; the supported 3.0 processor
handles 1.0/2.0 minima, and an omitted option selects 3.0.

## XSLT results and XML identity

`Execute`, `ApplyTemplates`, `CallTemplate` and `CallFunction` return immutable
`Result` values. Named calls can run without a source document.
`XSLTContext.ResultMode` selects delivery:

- `ResultRaw` (zero): retain typed sequence order and node identity.
- `ResultDocument`: construct normalized document nodes.
- `ResultDefault`: follow effective `build-tree`, defaulting to raw JSON/adaptive
  values and trees for other methods.

`Primary`, `Secondary` and `Messages` expose results and diagnostics. Secondary
URIs resolve against `BaseOutputURI`; they never write files. Equivalent output
URIs share reservations, and XSLT 3.0 rejects reading/writing the same resource.
Already completed secondary output is not transactionally rolled back.

`Serialize` returns owned bytes; `Transform` combines execution and serialization.
Neither publishes partial output on failure. `WriterTo`, `WriteSecondary` and
`Stylesheet.Write` allow partial writer output; `Write` rejects secondary results.
`OutputEncoding(uri)` reports each completed output's encoding. See
[streaming](streaming.md) for storage and record execution.

JSON preserves maps/arrays; empty sequences become `null`. Multiple items at the
result, map-value or array-member level raise `SERE0023`; use explicit arrays.
Node serialization defaults to XML; select `json-node-output-method="text"` for
string values. No extension output methods or external schema loading are supplied.

`Import` / `Export` share XML snapshots without serialization; `ImportNode` /
`Node.Reference` preserve individual identity. `Result.Document(ctx)` accepts one
document or element and detaches a selected element with its in-scope namespaces.
The XDM view normalizes `xml:id`; exporting preserves original XML attribute values.

## Extensions and resources

- `Config.Functions` registers application functions by expanded name and arity.
  Callbacks must honor context and support concurrent calls.
- `PackageResolver` supplies package readers/base URIs. The compiler validates
  name/version, components and cycles. No package lookup is implicit.
- `CollectionResolver` supplies `collection` / `uri-collection`; an empty URI is
  the default collection. Results are stable within an invocation.
- `Resolver` supplies imports and URI-function bytes under the shared
  [resource contract](usage.md#common-contracts). `Environment` exposes only the
  configured bindings.

Resource snapshots and document identity are invocation-local; a later call can
reload them. Every access rechecks live policy and budgets. Failed retrievals do
not authorize fallback access; cancellation/resource errors remain failures.
`resource.TypedReader` supplies MIME/charset metadata for bounded text decoding.
External encoding metadata takes precedence. `unparsed-text` returns a complete
string, and `json-doc` retains its parsed value; availability does not guarantee
that materializing a value fits the output budget.

`XPath.Analyze(ctx)` reports function/context/navigation diagnostics. It does not
authorize execution or prove streamability.

## XPath host context choices

`CompileXPath` receives a Go string and preserves its line endings, including
CR, CRLF, NEL and line separator characters inside literals. An XML stylesheet
undergoes XML line-end normalization before its XPath expressions are compiled.
Names use XML 1.0 Fifth Edition and Namespaces 1.0 Third Edition character ranges;
Unicode properties use Unicode 17.0. `XMLSchemaVersion` selects 1.0 or 1.1 datatype
rules; its default is 1.1. Optional `xs:dateTimeStamp` and `xs:error` support is
separate from schema validation.

Static defaults are compatibility mode off, codepoint collation, the `fn`
function namespace, an empty default element/type namespace and the standard
unnamed decimal format. Supplied namespace bindings are copied and their URI
values undergo XML whitespace normalization. The `xml` binding is fixed;
predeclared built-in prefixes and edition-specific functions are available.
The standalone static context has only built-in schema types and no schema
element or attribute declarations. Context items and external
variables have the broad static types `item()` and `item()*`; document and
collection results have static types `document-node()?` and `item()*`.
`BaseURI` is absent by default; callers supplying one must use an absolute IRI.
Static typing is not enabled: mandatory syntax, name and declared-type checks
run during compilation, while general value types are checked during execution.
Non-XML input comes from caller-built document trees and public `Value`/`Sequence`
constructors; it uses the same unvalidated XDM projection. Application functions
have their registered arity and generic `item()*` argument/result types.

Known collation URI families are Unicode codepoint, HTML ASCII case-insensitive,
W3C UCA and the QT3 `caseblind` alias for HTML ASCII case-insensitive comparison.
UCA uses the `x/text` collator; unsupported options may use its approximation
unless `fallback=no` requests `FOCH0002`. Unknown collation URIs raise `FOCH0002`.

The initial focus is absent. Position and size default to 1; explicitly supplied
nonzero values must be positive, and position must not exceed size. The default clock is sampled once in UTC per public call;
explicit implicit timezones use whole minutes within ±14 hours. Formatting
uses English and the supported Gregorian calendar by default, with no selected
geographical region; supplied values and the implicit timezone determine offsets.
The RNG's explicit seed mapping preserves atomic-value identity and does not
promise different sequences for different seeds. Calendar types with an optional
timezone share one seed per dynamic type, preserving determinism across implicit
timezones. `xs:dateTimeStamp` seeds retain their normalized UTC value. The number
sequence is implementation-dependent; returned `next` and `permute` functions
are repeatable and safe to reuse.

The namespace axis is supported; relative attribute/namespace order is stable
within an input view but is not a portable ordering contract.

Available collections require the configured resolver. Environment variables
come only from the copied `Config.Environment` map; the process environment is
not consulted. Warnings are not emitted. Errors are returned as `transform.Error`,
and invalid external-function results retain their type error. Trace output is
discarded unless a writer is configured. Serialization occurs through explicit
serialization functions or the host result APIs described above.

## Policy, limits and errors

`Config{}` selects bounded defaults. Limits cover input/program/output bytes,
nodes, sequences, work, recursion, resources and timeout. Zero fields use defaults;
negative fields fail. Execution and serialization have separate invocation budgets;
serialized primary, secondary and message bytes share their output limit.
Limits do not specify total heap/RSS or OS isolation.

Numeric temporaries share cumulative byte/work budgets. Integer storage is
`max(1, ceil(bitlen(abs(value))/8))`; decimals charge their reduced numerator and
positive denominator, and floats/doubles charge four/eight bytes. Exact-arithmetic
preflight can reject an unreduced intermediate even when its final value would
fit. Charges are not refunded. Individual `math/big` calls may not be interruptible.
Recurring decimal results retain at least twenty fractional places and twenty
significant digits, rounding half away from zero; terminating fractions stay exact.

Cancellation and resource failures propagate through `xsl:try`, callbacks and
nested transformations. Use `errors.Is` for `ErrInput`, `ErrUnsupported`,
`ErrLimit` and context errors. `*transform.Error` provides `Operation`, local
`Code`, expanded `CodeName()` and messages emitted before failure.

Schema awareness and W3C streamable execution are unsupported. Streaming
annotations still use materialized trees. Regex work/storage is bounded but
back-references and nested repetitions have no linear-time guarantee.
Unicode tables and their [license](../licenses/Unicode-3.0.txt) use Unicode 17.0.

## XMLDSig v1 compatibility

`Engine` implements `reference.ExtensionProcessor` / `ReaderExtensionProcessor`
for approved XPath 1.0, Filter2 and restricted XSLT 1.0 programs:

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

Approval includes the exact program and complete namespace context as serialized
in the signature. No program is approved by default; building XML grants no
approval. Standalone application functions are unavailable in these transforms.
Resource preflight and program checks happen before execution. See the
[signature-transform example](../examples/transforms/main.go).
