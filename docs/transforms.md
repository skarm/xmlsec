# XPath and XSLT

## Contents

- [XML input profiles](#xml-input-profiles)
- [Contexts and values](#contexts-and-values)
- [XSLT results and XML identity](#xslt-results-and-xml-identity)
- [Extensions and resources](#extensions-and-resources)
- [XPath host context choices](#xpath-host-context-choices)
- [Policy, limits and errors](#policy-limits-and-errors)
- [XMLDSig v1 compatibility](#xmldsig-v1-compatibility)

`transform` implements selected features of XPath 1.0/2.0/3.0/3.1 and XSLT
1.0/2.0/3.0 through one pure-Go engine. Complete Basic XSLT conformance remains
open; [validation profiles](language-baseline.md) define the required suite checks.
Compiled programs and published documents support concurrent reuse with independent
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

## XML input profiles

`Engine.Parse` and `ParseReader`, record input and approved XMLDSig programs
retain the DTD-free UTF-8/UTF-16 security profile. Explicit
`Config.AllowSingleByteEncodings` also permits declared ASCII-compatible IANA
single-byte encodings, including ASCII, ISO-8859-1 and Windows-1252. It applies
to source documents, stylesheet modules and resolved XML resources. Undefined
bytes, BOM conflicts and unsupported encodings fail; raw input and decoded UTF-8
both obey `MaxInputBytes`. This encoding option is independent of DTD processing.

`parse-xml` and `fn:transform`'s `stylesheet-text` consume already decoded
characters. Their XML encoding declarations are checked for syntax and do not
reinterpret those characters as encoded bytes. `parse-xml-fragment` accepts the
external-entity TextDecl grammar, including a required encoding declaration,
without re-decoding characters. The complete original string counts against
the input limit before any declaration is removed.

Language XML input (`parse-xml`, `doc`, XSLT stylesheets and document resources)
uses a separate bounded nonvalidating DTD mode. It expands parsed entities,
parameter entities and default attributes, normalizes declared non-CDATA
attributes, and retains DTD ID/IDREF flags, external-entity base URIs and
unparsed-entity identifiers. XDM attributes remain untyped; no DTD or schema
validation is performed. Fragments still reject DOCTYPE declarations.
Every external DTD/entity must use the explicit resolver and invocation read
policy; there is no implicit file or network access. Original and expanded
XML, aggregate resource bytes, declarations, expansion work and entity depth
are bounded. Cycles and malformed included entities fail without a partial
result; resource streams close on success, failure and cancellation.
These local controls do not establish complete XML processor conformance.

## Contexts and values

The XDM view applies [xml:id normalization](https://www.w3.org/TR/xml-id/#processing)
to ID lookup, attribute string values and XPath/XSLT serialization. Only XML
whitespace is collapsed; other Unicode spaces and other attributes are preserved.
Imports retain the original immutable XML storage and node identities. `Reference`
and `Export` return that original snapshot, including its original attribute
values; XDM normalization does not rewrite it. This bounded behavior does not
establish complete xml:id error reporting or general XML processor conformance.

`CompileXPath` snapshots namespace bindings and the static base URI; the default
version is 3.1. An empty prefix sets the default element namespace in XPath 2.0+.
XPath 1.0 accepts only node context items and has no default element namespace.
`XPathOptions.XPath10Compatibility` enables the 1.0 compatibility property with
modern grammar and functions; the default retains strict conversions. It changes
numeric/string conversion and singleton argument handling, independently of the
language version. Returned inline/named/partial/lookup function values retain
their originating static datatype/compatibility context while borrowing the
caller's current resource policy and budgets.
XPath keywords remain legal names where the grammar requires a name: for
example, `6 * div` multiplies by the value of a child named `div`. The parser
resolves the role from the expression grammar, including keyword prefixes and
following operators or clause delimiters.
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
`Stylesheet.Version()` reports the selected processor. Higher declarations, including 3.0 with a selected 2.0 processor and future
4.0 declarations, enable forwards-compatible processing: unavailable XSLT
instructions require a fallback even in unused code, and unknown future
attributes are ignored. Selected 2.0/3.0 processors still check XPath syntax,
names and standard function signatures statically. Backwards compatibility
defers unavailable extension functions outside the standard function namespace;
the selected 1.0 processor retains its legacy deferred checks. Serialization `version` on
`xsl:output`/`xsl:result-document` does not change the language mode.

The 2.0 host library includes `generate-id` without enabling newer XPath syntax.
Node functions retain their argument types and cardinality. Number/date formatters
use the selected processor's signatures and error QNames, including the 2.0
`XTDE1280`/`XTDE1310` and `XTDE1340`/`XTDE1350` codes. Match patterns use the
selected grammar: 2.0 permits pipe alternatives, child/attribute steps and its
restricted `id`/`key` roots; 3.0 adds grouped patterns and other supported roots.
Predicates retain the selected XPath expression grammar.

In 2.0, an absent current group or grouping key is empty; 3.0 raises
`XTDE1061`/`XTDE1071`. Ordinary template calls preserve grouping independently
of the focus. Stylesheet functions clear both grouping and the focus. A 2.0
initial template cannot declare a required parameter (`XTDE0060`), even if the
caller supplies it. The 3.0 processor permits supplied required parameters.
Basic 2.0 rejects `validation="lax"` and `validation="preserve"`; Basic 3.0
applies untyped stripping.

Stylesheet functions resolve global bindings independently of caller-local
variables. A 3.0 `xsl:copy` with `select` evaluates its body with the selected
node's singleton focus and clears the current template rule; an implicit
context-node copy preserves that rule. The caller's focus is restored afterward.
Loading the initial document through its document URI preserves its identity,
including `file:` URIs converted to resolver-local paths.

`type-available()` reflects the processor's supported types in both static and
runtime contexts. The optional `xs:dateTimeStamp` type is supported with either
datatype edition; `xs:numeric` is available in 3.0, whose library uses XPath 3.1,
and unavailable in 2.0. Selecting XSD 1.0 or 1.1 controls datatype and regex rules,
without enabling schema validation. A 2.0 `use-when`
context has no available documents; a 3.0 context may use the configured resolver.

Result-document hrefs, including nested instructions, resolve against the
invocation's fixed base output URI. A supplied `href`, including `href=""`,
changes `current-output-uri()` during the body; an absent attribute leaves the
current value unchanged. The previous value is restored afterward. Equivalent
resolved URIs share a reservation, including an explicit href equal to the
principal URI. Implicit
principal output claims its URI in raw and normalized delivery alike; a
duplicate is `XTDE1490`. Empty sequences do not claim an implicit result, while
explicit whitespace does. Failed result-document construction releases its
reservation, and rolled-back implicit output releases its claim. This does not
promise transaction-wide rollback of already completed secondary results.
XSLT 3.0 rejects reading and writing the same resolved absolute resource URI
with `XTDE1500`, in either order. XML, text, JSON, availability checks, collection
documents and runtime serialization-parameter documents share that check. Source
document URIs participate; `uri-collection` returns names without reading their
resources. Successful opens remain reads even if parsing fails; failed retrievals
do not reserve a read URI. Escaped functions use the live caller's resource state,
while nested transformations have separate state. Physical URI aliases are not
exhaustively identified. Dynamic `parameter-document` AVTs are evaluated on each
execution, with parsed parameters cached by resolved URI and scoped across recursion.
Parameter documents use the selected serialization schema/extraction rules.
Their supplied scalar values override declarations, retaining explicit false and
empty values; QName lists resolve in the parameter document and merge with the
corresponding declared lists. Missing resources reported as `fs.ErrNotExist` are
ignored; policy, control and other resolver errors propagate. This byte host has
no extension-method callback and rejects an unsupported namespaced method with
`SEPM0016`; XSLT leaves that extension behavior to the implementation.
`Config.EnableXSLTAssertions` enables assertion checking for direct invocations.
Nested `fn:transform` uses its `enable-assertions` option. Assertions default to disabled. A failed assertion (including a
dynamic error in its test) follows message processing with `XTMM9001` as the
default code. Error-code AVTs preserve application QNames in `Error.CodeName()`
and `xsl:catch`. An invalid supplied code follows the message fallback
`XTMM9000`; an omitted assertion code uses `XTMM9001`. A literal error-code
QName with an undeclared prefix is a static `XTSE0280`; an explicitly empty code
uses the message fallback. Cancellation and resource exhaustion propagate through
message/assertion processing. Message content is one constructed document,
including `select` followed by its body; terminating messages and failed assertions
supply that document as `$err:value`. XSLT 3.0 accepts all boolean `terminate`
synonyms, with XML whitespace stripping. Local namespaces on `xsl:catch` apply
to its expressions as well as its error-name filters. Parsed instructions expose
their start-tag line through `$err:line-number`, including included/imported
modules and UTF-16 stylesheets. Column numbers and locations without source
metadata remain empty sequences.
Static parameters bind during
compilation; `XSLTContext.Parameters` supplies globals during execution.
Lexical variable references are checked after imports and packages resolve the
winning globals, including references in unused templates and functions. Local
bindings become visible after their declaration; catch/fallback bodies retain
their own scopes. Static defaults use tree-order bindings when evaluated; a
caller-supplied static parameter does not evaluate its default.
`InitialParameters` and `TunnelParameters` supply initial template/mode arguments.
Template parameter defaults and supplied values share binding rules for named,
node and atomic template invocations. Untyped empty defaults are zero-length
strings; untyped nonempty bodies construct document nodes. Typed explicit empty
defaults still undergo conversion. A missing implicitly mandatory template
parameter uses `XTDE0610` in the 2.0 processor and `XTDE0700` in 3.0; visible
mandatory stylesheet parameters are checked when execution starts with `XTDE0050`.
Default conversion uses the selected edition (`XTTE0600` in 2.0, `XTTE0590` in
3.0); supplied parameter conversion uses `XTTE0590`. Local type namespaces and
default element namespaces come from the parameter declaration.
Named-template references are bound after imports and declarations; missing
visible targets fail compilation with `XTSE0650`, including unused ordinary
branches. A component accepted with private visibility is callable inside the
accepting package; hidden components are unavailable. Modern forwards-compatible
processing also checks named-template references statically. Duplicate names
at the effective import precedence use `XTSE0660`; a higher-precedence declaration
may override both. Function names and template calls resolve their declaration
namespace scope, with `XTSE0280` for an unbound prefix and `XTSE0740` for a
function in no namespace. Include/import cycles retain their path and use
`XTSE0180`/`XTSE0210`; global variable/parameter cycles use `XTDE0640`.
A required absent template context uses `XTTE3090`. An explicit initial mode
without a match selection uses `XTDE0044`; an ineligible mode uses `XTDE0045`.
When neither a source nor an explicit selection is supplied, an available global
context item supplies the default selection for a mode invocation.

Names use `document.Name{Space, Local}` (also `transform.Name`), independently of
prefixes. `Bindings` contains typed `Sequence` values: arbitrary-precision integers and finite decimals,
other atomics, nodes, maps, arrays and functions. Go accessors use zero-based
indices; XPath array lookup is one-based. Mutable numeric getters return copies.

Simple-content constructors and AVTs propagate atomization and conversion errors,
including `FOTY0013` for maps/functions nested in arrays. Outer text-node merging
precedes array atomization; array-member text nodes are separate atomic values.
Backwards-compatible AVTs select the first atomized value. Singleton text reuses
immutable storage; combined strings charge the shared work/byte budget.

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
the 3.0 processor handles every supported minimum, including 1.0 and 2.0.
An omitted option also selects 3.0. Values above 3.0 or an unavailable requested
product/capability report `FOXT0001`. `initial-function` requires `function-params`
(`FOXT0002` when absent). Failure to resolve a supplied stylesheet location also
reports `FOXT0002` before compilation. Compilation and execution retain more
specific language errors; cancellation and exhausted implementation budgets keep
their control causes. See the measured [suite diagnostics](language-suites.md)
and [validation profiles](language-baseline.md) for reproducible Basic-profile checks.

Package exposure uses the winning explicit, declared or wildcard visibility
in that priority order, with the last rule winning only within one priority.
Only locally declared components can be exposed; parameters remain public.
Component names and function arities are validated in their declaration's
namespace scope. The pinned 2017 Recommendation permits function NameTests
without arity; the later E36 behavior in Saxon and some suite cases is recorded
separately from exact agreement. Initial modes made private by declaration or exposure follow §6.6.1;
the contradictory broader wording in §2.3.3 is tracked by W3C bug 30405.

Root shadow attributes precede package identity/version and ordinary root
attribute checks. Their expression errors retain their language codes.
Shadow expansion uses a private module copy so `document('')` retains the
original stylesheet tree; a shadow attribute cannot itself be shadowed.
Resolved package identity is checked against the effective compiled metadata.

Accepted components have their own visibility without changing the declaring
package's objects. Public/final components default to private in the using
package; abstract components default to hidden. Incompatible wildcard accepts
are ignored, while explicit names are checked for existence and visibility.
Hidden abstract calls report `XTDE3052`; a visible abstract component in an
executable top-level package reports `XTSE3080`. Template/function/variable
signature checks retain declaration-site type names and default types.

Stylesheet function arguments use XPath function conversion, including numeric
and URI promotion, atomization and typed cast errors. Function signature names
retain the namespaces of their declarations across static calls, function items,
lookup and initial invocation. Function results use the same conversion rules
with XSLT's `XTTE0780` result error. A converted function checks arguments against
the requested signature before converting them for the original function;
incompatible calls fail when invoked. Returned adapters keep static type names
and borrow the caller's current cancellation and work limits. Their native and
Saxon atomization-code differences are recorded separately in the baseline.

`xsl:evaluate` uses its explicitly supplied variables and public/final stylesheet
functions. Private overloads do not hide public siblings, and XSLT-specific
functions are absent from the target's static library. The target always uses
ordinary XPath conversion; local backwards compatibility does not enable XPath
1.0 conversion. Namespace-context nodes replace stylesheet bindings, including
the default namespace. Source and result conversion, explicit map types and
changes to supplied variable names are checked per invocation. Dynamic source
text observes program/work limits before compilation, and `doc()` shares the
transformation's document identity. `with-param` types retain declaration names
and apply conversion before binding the receiving parameter.

`Config.DisableXSLTDynamicEvaluation` statically disables `xsl:evaluate` for
programs compiled by the engine. The default enables it. Static and runtime
`element-available`/`system-property` then report the feature unavailable;
`xsl:fallback` is evaluated, and an invoked instruction without fallback raises
`XTDE3175`. Nested transformations and package compilation inherit the setting.
Returned functions retain the producing stylesheet's feature setting for nested
compilation and introspection. Fallback bodies retain their own namespaces,
default element namespace, collation, text expansion, whitespace and `use-when`.
Unsatisfied requested processor properties produce `FOXT0001`; F&O also permits
implementations such as Saxon to ignore such requests.

XSLT availability and system-property functions resolve string QNames using the
expression's lexical declarations, including local prefix rebindings. Element
and type availability use the XML default namespace; function availability uses
the standard function namespace, and system-property uses no default namespace.
The XML default is independent of `xpath-default-namespace`. Shared argument
conversion applies to static, named and lookup calls; invalid EQNames and unbound
prefixes retain their prescribed XSLT codes. Static declarations, `use-when`,
shadow attributes, node/atomic template patterns and returned functions retain
those contexts. Full schema and extension inventories remain outside this claim.

`xsl:map` requires a sequence of maps (`XTTE3375`) and rejects duplicate keys
with `XTDE3365`, including matching `xsl:catch` dispatch. `xsl:map-entry` works
independently and atomizes its key to one atomic value through the shared type
conversion path. Map construction uses one builder; duplicate-value combination
in `map:merge` appends to builder-owned storage and preserves its inputs. Shared
work and collection limits apply while merging entries and before combining
value sequences, including intermediate maps whose final result is a scalar.



Package-local names retain their scope across calls and overrides. Dynamic
function lookup retains original declarations when another package overrides
them; abstract declarations are unavailable dynamically. Static named references
to an unimplemented abstract function still fail with `XTDE3052` when invoked.
Modes retain package identity independently of a component's lexical scope.
Private or hidden template names do not remove their match rules from a public
mode. Unnamed/private modes stay local, while accepted modes retain their rule
lists through re-export and further overrides. Rules in the using package take
precedence before pattern priority; `next-match`, named helpers and built-in
rules retain the bound mode. Atomic rules and predicates use their declaring
package's functions. Compilation charges rule-list extension to the shared work
budget and rebuilds the dispatch index. Direct `apply-imports` in an overriding
match rule reports `XTSE3460`.

`#default` and omitted mode attributes use the nearest ancestor-or-self
`default-mode`, resolved with that attribute's namespace bindings. A child
prefix redefinition does not change the ancestor's mode name. Includes/imports
without a default select the unnamed mode. Invalid mode tokens, visibility and
unbound prefixes are static errors; default-mode references participate in
`declared-modes` checks. Resolving ancestor defaults charges the shared work
budget. The suite adapter honors singleton `source/@select` for the initial
context and default match selection, independently of explicit initial-mode
selection.

Complete component/import graphs, local-rule placement and signature combinations
remain open. Indirect `apply-imports` across packages remains an independent-engine
difference under investigation. The baseline records diagnostics separately.

Attribute-set cycle detection tracks component identity across constructors and
callbacks. XSLT 3.0 reports an evaluated circularity as `XTDE0640`; unused cycles
are permitted. The 2.0 processor retains its static `XTSE0720` rule. Graph work
and recursion use the shared invocation budgets. Function cache hints preserve
proactive node identity and callbacks; a narrow scalar/self-recursion proof
allows memoization without changing those effects. Key indexes also reject
evaluated cycles in `match`, `use` and body expressions with `XTDE0640`, across
function calls. Failed indexes are removed so a caught error cannot leave an
incomplete cached index. Distinct documents and packages retain separate indexes.

Function items clear the XSLT grouping, merge, regex and output-URI context,
including inline and higher-order calls. Globals and key specifiers use their
initial group context. Stylesheet functions and key bodies can establish fresh
groups, matches and merges; nested transformations start their own context.
Local variable construction retains the current output URI.
`json-to-xml` with a nonempty input and `validate=true()` raises `FOJS0004`
in the public Basic processor; selecting XSD 1.1 datatype rules does not enable
schema validation.

## XSLT results and XML identity

`Execute`, `ApplyTemplates`, `CallTemplate` and `CallFunction` return immutable
`Result` values. They select ordinary execution, an explicit sequence, a named
template or a public function. A named template can run without a source document.

`XSLTContext.ResultMode` selects delivery of each primary and secondary value.
The zero value, `ResultRaw`, preserves the XDM sequence's order, types and node
identity. `ResultDocument` constructs document nodes through sequence
normalization; arrays are flattened, adjacent atomic values use spaces unless an
`item-separator` is supplied, adjacent text is merged and empty text disappears.
An empty result becomes an empty document. Free attributes, namespaces, maps and
functions raise `SENR0001`. `ResultDefault` follows each effective `build-tree`
setting, defaulting to raw values for JSON/adaptive and trees for other methods.
The copy uses the same work/storage budget and preserves source nodes; it does
not serialize and reparse XML. The selected mode also precedes serialization in
`Transform` and `Write`.

`fn:transform` applies the corresponding raw/document/default delivery to each
output. Raw secondary results retain their types and order. The principal map
entry is present even for an empty sequence, following the published F&O 3.1
Recommendation; W3C bug 30209 proposed a change but was not adopted into that
edition. Post-processing receives the value after the selected delivery step.
Its `enable-assertions` option uses function conversion to `xs:boolean`, defaults
to false, and independently controls each nested call. Direct invocations use
`Config.EnableXSLTAssertions`.

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
on error. After an execution failure, `errors.As` can retrieve `*transform.Error`;
its `Messages()` returns an owned copy of diagnostics already emitted, including
the terminating message. `Message.Text` contains serialized XML, with text escaped.
No partial primary or secondary result is published. `Result.WriterTo(ctx)`,
`WriteSecondary` and `Stylesheet.Write` write
with byte counts and permit partial output. `Stylesheet.Write` rejects secondary
results. See [streaming](streaming.md) for memory requirements and record execution.

`Result.OutputEncoding(uri)` reads the completed output's encoding without
serialization; an empty URI selects the primary result. It preserves dynamic
result-document settings independently for each invocation. An omitted encoding
defaults to UTF-8; adaptive output ignores that parameter and uses UTF-8.
Unknown secondary URIs and an absent result return `ErrInput`.

XML/XHTML doctypes follow leading comments and processing instructions and use
the first element's qualified name. HTML doctypes use `html` and the same
position; automatic HTML5/XHTML5 doctypes require an HTML root without preceding
non-whitespace text. Explicit HTML doctypes are retained even for an empty or
element-free result. XHTML5 retains the XML-declaration default unless explicitly
overridden. An implicit result from a 1.0 principal module defaults to XML for
an XHTML root; an explicit result-document retains XHTML auto-selection. The
root name must be lowercase `html` for method auto-selection.
CDATA and suppress-indentation name lists combine across output
declarations and imports. Unprefixed names use the declaration's XML default
namespace; matching uses expanded names. Character maps apply to attributes and
ordinary text, excluding CDATA-selected text, in primary and secondary results.
Maps match original characters before Unicode normalization. Replacements stay
unchanged, and characters introduced by normalization are not mapped again.
Element/attribute names, namespace URIs, comments and PIs stay outside character
expansion.

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
XPath 3.0 uses Serialization 3.0 parameter documents: four output methods,
`yes`/`no` booleans and lexical QNames. XPath 3.1 additionally accepts JSON,
adaptive output, boolean aliases, EQNames and map parameters. Escaped function
references retain their originating edition. Selected XSLT 2.0 rejects
`item-separator`, `suppress-indentation` and `html-version`; a selected 3.0
processor supports them even in a version 2.0 module. Serialization 3.0 validates
the whole parameter document without extension schema declarations; 3.1 validates
the selected standard children. Unselected 3.1 root content is ignored, while
duplicate child names remain errors. Foreign content inside a selected parameter
uses the published schema's lax validation, including known descendants and
explicit types. No external schema retrieval is performed.
Map options apply their declared function conversions before cardinality checks.
The method union requires strings or namespaced QNames; namespace-sensitive
options reject untyped values with `XPTY0117`. Map-form `standalone` accepts a
boolean or an empty value selecting `omit`. Character-map keys and values must
already be strings or string subtypes. No extension output methods or extension
parameter semantics are provided. These parameter checks do not enable
schema-aware XPath/XSLT.

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
  Results are stable within an XPath invocation or XSLT execution/package. Collection
  document URIs resolve to the same document through `doc`; conflicting document
  identities for one URI fail with `FODC0003`. Nested transforms inherit the explicit
  resolver and create their own caches/whitespace views.
- `Config.Resolver` supplies byte resources for imports and URI functions through
  the shared [resource contract](usage.md#common-contracts). Files and HTTP are
  available only through explicitly configured adapters. XML resources obey parser
  limits; `Config.Environment` exposes only explicitly supplied bindings.

Document availability and ordinary retrieval/parse failures share an invocation
snapshot with `doc`; another invocation can reload the resource. Every access
still checks live policy and limits, and cancellation/resource-control failures
are propagated rather than cached as unavailable. For selected XSLT 2.0,
malformed default-fallback UTF-8 with no supplied/inferred encoding uses
`XTDE1200`; explicit or metadata-selected decoding and invalid XML characters
use `XTDE1190`. A UTF-8 BOM selects the latter decoder path; the old Saxon's
`XTDE1200` choice for a malformed BOM-marked resource is recorded as an edition
interpretation difference, not an exact agreement.

For `unparsed-text`, `unparsed-text-lines` and `unparsed-text-available`, an
optional `resource.TypedReader` supplies the MIME type and external charset.
External encoding information takes precedence; XML media types use XML encoding
recognition before the function's encoding argument. Without such metadata,
the existing BOM/declaration heuristics and UTF-8 default apply. Conflicting BOMs,
unsupported encodings and malformed character sequences fail. Both encoded reads
and decoded output retain their respective budgets, including through nested
`fn:transform` calls. Metadata does not broaden the XML parser's input profile.
Completed text values are stable for the same URI and encoding arguments within
one public evaluation or transformation. Validated Unicode snapshots share the
compatible default text/JSON source; JSON parse options remain independent.
Snapshot retention is bounded by `MaxResourceBytes`. Availability probes validate
incrementally and retain at most the remaining value budget. A valid resource can
therefore be available while materializing its text still exceeds `MaxOutputBytes`.
Interrupted reads publish no successful snapshot. Cache hits recheck the live
read policy and current limits; each public call starts a fresh scope. Escaped
functions use the current caller's resource scope.
`json-doc` detects UTF-8/16/32 from the initial octets when external encoding
information is absent. It translates non-XML characters into JSON escapes before
parsing, including the selected fallback handling. Encoded and decoded input,
retained sources and parsed values keep their respective budgets.
XSLT external resource references are percent-encoded before URI resolution as
required by XSLT section 5.8; namespace names and `fn:resolve-uri` keep their own
URI rules.


`XPath.Analyze(ctx)` computes function/context/navigation diagnostics on demand.
Its report does not prove streamability or authorize execution.

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

`Config{}` selects bounded defaults. `Limits` controls input/program/output bytes,
nodes, sequences, operation work, recursion and timeout. Zero fields use defaults;
negative fields fail. `MaxResourceBytes` / `MaxResources` bound aggregate external
loads. `Serialize` / `Transform` share `MaxOutputBytes` across primary, secondary
and message bytes. Each writer call gets a fresh budget for its selected result.
Temporary strings and trees also consume budgets. Execution and serialization
have separate invocation budgets. Individual limits do not specify a combined
heap or RSS ceiling.
Cancellation and exhausted budgets, including limits returned by application
callbacks or resolvers, propagate through `xsl:try` and nested transformations.
They do not become invalid-regex or circular-reference language errors.

`Config.XMLSchemaVersion` chooses `XMLSchema10` or `XMLSchema11`; zero selects
1.1. It controls the edition-sensitive builtin lexical rules (`+INF`, year zero,
URI escapes) and regex range grammar on direct, function-item, arithmetic,
aggregate and XSLT paths. Function values retain their originating static
edition. This option does not supply schema validation or type annotations.
Static and dynamic processor properties consistently report no schema awareness
and the selected datatype/XPath editions.

Integer/decimal division and numeric/duration averages materialize recurring
fractions as finite decimal values. Terminating fractions remain exact. Recurring
results retain at least twenty fractional places and twenty significant digits,
rounding half away from zero; leading fractional zeros do not erase tiny
quotients. Duration division uses the same rule. These temporaries and their
rounding work obey the invocation's budgets.

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
awareness and W3C streamable execution are unsupported. The Basic processor
reports `XTSE1650` for schema imports and `XTSE1660` for schema-only constructors,
typed modes and sequence types requiring annotated nodes. `validation="lax"`
and `"preserve"` follow the non-schema-aware rules and act as `"strip"`.
Streaming annotations are accepted and run on materialized trees, with the same
resource limits and explicit accumulator applicability. They do not enable a
streamability analysis or bounded-memory execution; `xsl:supports-streaming`
remains `"no"`. See [XSLT 3.0 processor conformance](https://www.w3.org/TR/xslt-30/#conformance).
XSLT 3.0 shadow
attributes, including `_version`, are evaluated during compilation.
Source schema-location hints do not trigger loading. Complete W3C conformance
has not been established; supported scope is in [compatibility](compatibility.md).

`Error.Operation` identifies the operation; `Error.Code` contains the local name
of an error code where present. Use `Error.CodeName()` for the expanded QName,
including the namespace of application errors. Use `errors.Is` for `ErrInput`,
`ErrUnsupported`, `ErrLimit` and context cancellation, and `errors.As` for
structured errors.

Pattern functions share an immutable bounded engine supporting Unicode classes,
subtraction, captures and back-references. Category/case/normalization data and
block ranges use Unicode 17.0; block data comes from the
[Unicode database](https://www.unicode.org/Public/17.0.0/ucd/Blocks.txt) under the
[Unicode license](../licenses/Unicode-3.0.txt). Block names retain XSD case and
hyphens; historical Unicode 3.1 aliases remain recognized. Script names are not
XSD category escapes. Unknown names report `FORX0002` even with `i`. Multiline
`^` does not match the position after a terminal newline. Work/storage limits and cancellation
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

Greek alphabetic numbering uses a shared 24-letter alphabet for `format-integer`
and `xsl:number`, excluding the lowercase final sigma and the unused capital
U+03A2 slot. Greek numbering is implementation-defined; publisher cases assuming
a 25-letter lowercase sequence retain a visible diagnostic difference.

HTML serialization applies special HTML rules only to HTML elements; XML islands
use XML character/attribute rules, CDATA selection and `?>` processing instructions.
CDATA is ignored on HTML elements, including XHTML elements with HTML5 output.
Character maps do not change CDATA content; normalization precedes repertoire
splitting. Both writer and fallback paths choose references before octet encoding.

For `method="html"`, `html-version` takes priority over `version`; modern XSLT
output defaults to HTML5.
XSLT 1.0 retains HTML4. XHTML output without `html-version` retains its older
XHTML rules. The map form of `fn:serialize` independently defaults
`html-version` to 5 for HTML and XHTML, including an empty option. The
parameter-element form retains version fallback for HTML output. `fn:serialize` skips final octet encoding but still uses the
selected character repertoire for references and CDATA boundaries.

Invalid HTML processing instructions give `SERE0015`; forbidden HTML4 controls
give `SERE0014`. XML islands retain XML `SERE0006`/`SERE0008` rules. Unsupported
HTML versions give `SESU0013`. XML text/attributes reference C1, NEL and LINE
SEPARATOR in both XML editions. Cancellation, work/depth and writer errors remain
in force. Complete serialization conformance remains subject to the language backlog.

XML and XHTML result paths use the same XML writer for namespace reconciliation,
character expansion, CDATA and disable-output-escaping scopes. XHTML adds
name-based empty-element syntax, prefix normalization, all-head metadata
replacement and URI escaping before character mapping. It works on an owned
copy; serializing a prepared input does not mutate it. Markup that the selected
encoding cannot represent raises `SERE0008`, rather than inserting references into
names, comments or processing instructions. URI escaping preserves printable
ASCII and quotes the surrounding attribute correctly. Indentation respects
`xml:space` and XHTML inline/formatted content.

`generate-id()` identifiers survive collection of temporary nodes. Lazy atomic
identity assignment keeps shared snapshot access consistent without retaining
expired nodes; namespace identifiers use their logical owner and prefix.
