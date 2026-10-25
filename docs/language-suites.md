# XPath and XSLT suite diagnostics

The development runner reads external, unmodified checkouts of the official
[QT3](https://github.com/w3c/qt3tests) and
[XSLT 3.0](https://github.com/w3c/xslt30-test) suites. Revisions and catalog
namespaces are pinned in [w3c-suites.json](../build/w3c-suites.json). Neither the
runner nor ordinary Go checks download test material. Git HEAD must match the
pin, and tracked and untracked checkout changes are rejected.
The checkout is checked again after execution. Library Go sources (including
untracked Go files), module manifests and the suite-pin file contribute to
`source_sha256`; a change during execution invalidates the run. This identifies
the tested code even when documentation is edited before the stage commit.

These are development diagnostics. Passing a selection does not establish
complete language coverage or authoritative W3C conformance. The
[normative register](conformance.md) separately tracks obligations and gaps.
The full-catalog [baseline](language-baseline.md) records results and a
categorized backlog. Generated JSON reports stay outside the repository.

## Inputs and licenses

Clone each complete repository and check out the exact `revision` in the pin
file. Keep publisher and contributor notices, including licenses for contributed
material. QT3's `guide/running.html` links the
[W3C test suite licenses](https://www.w3.org/Consortium/Legal/2008/04-testsuite-copyright).
Use the development option described there for these diagnostics; do not infer
a public conformance claim from a filtered or adapted run. The XSLT checkout's
`readme.md` describes its catalog format, and `admin/catalog-schema.xsd` defines
the metadata. Its README does not supply a blanket license for all bundled
third-party material. The license URL in the pin is the publisher's policy
reference, not a replacement for file-specific notices. No upstream test files
are redistributed in this repository.

The only runtime dependencies of the adapter are Git, the repository's Go
toolchain and existing module dependencies. Assertion expressions use the
public XPath engine under test. This permits reproducible diagnostics but is
not an independent oracle for every assertion primitive.

## Run a selection

```sh
go run ./tests/cmd/dev suites -suite=qt3 -dir=/absolute/path/to/qt3tests \
  -version=3.1 -sets='^fn-subsequence$' -report=/tmp/qt3.json
go run ./tests/cmd/dev suites -suite=xslt30 -dir=/absolute/path/to/xslt30-test \
  -version=3.0 -sets='^(expand-text|deep-equal)$' -report=/tmp/xslt.json
make suites SUITE_ARGS='-suite=qt3 -dir=/absolute/path/to/qt3tests -version=2.0 -limit=100'
```

QT3 accepts XPath 2.0, 3.0 and 3.1. XSLT accepts 2.0 and 3.0; explicitly choose
the version for an XSLT run. `-sets` and `-match` are regular expressions over
set and case names. `-limit=0` imposes no case-count limit. `-timeout=1s` is the
default per-case deadline. To run all catalog cases, omit selection flags.
The report is written before a nonzero exit for applicable failures. A run with
no passing applicable case also exits unsuccessfully.

`-limits=default` retains the public engine defaults. The explicit development
option `-limits=language` selects 32 MiB input/resource reads, 64 MiB aggregate
resource/output/intermediate budgets, a 1 MiB program limit, two million nodes
and fifty million operations. Depth, resource-count and engine timeout defaults
remain in force; the per-case deadline also applies. Both runs record their
budgets and keep limit failures as failures. This flag does not change the
library's defaults. Catalogs, query files and directly read modules remain
limited to 16 MiB; resolved resources use the selected resource-read limit.

Every catalog case receives one outcome:

- `passed`: the implemented assertion accepted the evaluation or expected
  standard error code.
- `failed`: an assertion, implementation, resource limit, panic, unresolved
  dependency or unsupported harness operation prevented success. `kind` and
  `reason` distinguish these causes; a harness failure does not prove a library
  defect.
- `skipped`: an explicit set/case filter or case-count limit excluded the case.
- `not-applicable`: known catalog language or optional-feature dependencies
  exclude the case from the selected profile. Missing mandatory implementation
  is not a reason for this status.

Unknown dependencies fail unless another known dependency conclusively makes
the case inapplicable. The selected profile excludes XQuery, schema awareness,
normative streaming, DTD processing and XML 1.1. Unknown optional features are
reported as dependency failures until their meaning is resolved. The report
records the suite pin, library Git revision and modification state, executable
and source SHA-256, Go/platform, selected version, filters and implementation
settings. Each compiled case also records `execution_version`, the selected processor
version. The adapter sets `XSLTOptions.ProcessorVersion` independently of a lower
stylesheet declaration. A 3.0 run therefore uses the 3.0 processor with 2.0 or
1.0 modules; local backwards-compatible processing remains attached to each
stylesheet element. A 2.0 processor still cannot accept a principal 3.0 declaration,
and future 4.0 declarations remain unsupported. Those cases stay visible failures;
this dispatch change does not establish complete forwards-compatible processing.

## Deterministic environment and boundaries

The clock defaults to `2026-01-01T00:00:00Z`; `-current-time=<RFC3339>` selects
another fixed instant for the entire run. Query/stylesheet evaluation, parameter
expressions and assertions share that clock, which is recorded in the report.
Implicit timezone is UTC, language
is English and the initial default collation is Unicode codepoint. The selected
limit profile is recorded in the report. Per-case timeouts additionally bound
execution; deadline-sensitive failures require investigation, not reclassification
as a pass or skip.

Only declared URI-to-file mappings and `file:` resources confined to the suite
checkout can be read. Symlinks and traversal outside it are rejected. There is
no network fallback or result-document filesystem writer. Catalogs, queries and
directly read stylesheet modules are limited to 16 MiB; source/resource reads
also obey the selected engine limits. Catalog decoding supports
UTF-8, strict ASCII and ISO-8859-1.

The suite engine explicitly enables `Config.AllowSingleByteEncodings` and records
`allow_single_byte_encodings=true` in its settings. Original source/stylesheet
octets go through the public decoder with its ordinary byte/node limits; the
harness does not rewrite encoding declarations or transcode publisher fixtures.

Implemented environment metadata includes named catalog/set environments and
bounded reference resolution with cycle detection, namespace scopes, static base URI,
default collation, default/named decimal formats, unvalidated file/text sources,
parameters, static parameters, declared text resources, document/query collections
and an explicit context item. Static metadata is applied before source loading,
independently of its catalog order. Declared text resources retain their MIME
type and charset through `resource.TypedReader`; the engine performs decoding
under its normal budgets. Test bytes are not transcoded by the harness.
XPath cases use the selected language
version. XSLT supports a declared or environment-provided principal stylesheet,
secondary environment modules, global invocation parameters (including static
parameters before compilation), source-valued parameters, initial template/mode
parameters including tunnels, initial functions and an initial selection. The
selection expression has the absent focus required by the catalog. An explicit
global XSLT context item is independent of the source and selection; an empty
context-item declaration explicitly selects absence.

An environment `ref` selects the named environment. Its local children are
ignored, following the publisher's `runner/run-tests.xsl` `c:get-environment`
function; they do not extend the referenced environment.

Environment and invocation modules can supply a principal stylesheet/package
and secondary modules. Declared packages are resolved by name and version;
the highest matching declared version is selected using the same range parser
as the compiler, which independently validates the returned package. No undeclared
package or network fallback is added. Output metadata selects a logical base
output URI, serialization, an optional XML result tree and a raw-result variable.
Output URIs never write files. Source schema validation, resource-valued
collections and independently forced processor versions
remain harness gaps. A case requiring one fails with a reason.

Assertions include standard errors, boolean/count/empty/type/value checks,
XPath predicates, XML fragments, exact serialization, serialization regex,
atomic permutations with multiplicities, `all-of`, `any-of` and `not`. XML comparison preserves comments and prefix
differences unless `ignore-prefixes` is explicit; fragments are wrapped only
for comparison. String whitespace follows the respective catalog defaults.
Secondary-result assertions retain their URI, XDM sequence and serialization
context. Message assertions inspect successful results' serialized message XML.
Capture after termination, warning assertions and other unsupported assertions
remain failures.
An unsupported assertion or unexpected execution error cannot satisfy a
negated result assertion. Resource failures satisfy an expected error only
when the engine supplies the required standard error code.
Error matching compares expanded QNames, so an application error with the same
local name cannot satisfy an expected standard error. EQNames are supported;
prefixed expected codes use the catalog's inherited and local namespace context.

For each confirmed implementation defect, add a small regression to the
existing component tests before fixing it. Retain the original suite pin and
record remaining failures by cause; the report is a backlog, not a percentage
of normative completeness.
