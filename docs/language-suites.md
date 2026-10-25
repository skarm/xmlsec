# XPath and XSLT suite diagnostics

The development runner reads external, unmodified checkouts of the official
[QT3](https://github.com/w3c/qt3tests) and
[XSLT 3.0](https://github.com/w3c/xslt30-test) suites. Revisions and catalog
namespaces are pinned in [w3c-suites.json](../build/w3c-suites.json). Neither the
runner nor ordinary Go checks download test material. Git HEAD must match the
pin, and tracked and untracked checkout changes are rejected.

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
SHA-256, Go/platform, selected version, filters and implementation settings.

## Deterministic environment and boundaries

The clock is fixed at `2000-01-01T00:00:00Z`, implicit timezone is UTC, language
is English and the initial default collation is Unicode codepoint. The public
engine's default resource limits apply. Per-case timeouts additionally bound
execution; deadline-sensitive failures require investigation, not reclassification
as a pass or skip.

Only declared URI-to-file mappings and `file:` resources confined to the suite
checkout can be read. Symlinks and traversal outside it are rejected. There is
no network fallback or result-document filesystem writer. Each catalog, query,
stylesheet or source read is limited to 16 MiB. Catalog decoding supports
UTF-8, strict ASCII and ISO-8859-1.

Implemented environment metadata includes named catalog/set environments,
namespaces, static base URI, default collation, unvalidated file/text sources,
parameters, static parameters, declared text resources, document/query collections
and an explicit context item. Static metadata is applied before source loading,
independently of its catalog order. Text-resource transport encoding hints other
than UTF-8 remain a harness gap; the byte resolver does not expose transport
metadata or silently transcode test bytes. XPath cases use the selected language
version. XSLT supports a declared or environment-provided principal stylesheet,
secondary environment modules, global invocation parameters (including static
parameters before compilation), source-valued parameters, initial template or
mode, and an initial selection. Source
schema validation, resource-valued collections, environment inheritance,
packages, initial functions, independent XSLT context items, multiple invocation
stylesheet modules, output overrides and template/mode parameters
and forcing a 3.0 stylesheet through a 2.0 processor are harness gaps. A case
requiring one fails with a reason.

Assertions include standard errors, boolean/count/empty/type/value checks,
XPath predicates, XML fragments, exact serialization, serialization regex,
atomic permutations with multiplicities, `all-of`, `any-of` and `not`. XML comparison preserves comments and prefix
differences unless `ignore-prefixes` is explicit; fragments are wrapped only
for comparison. String whitespace follows the respective catalog defaults.
Unsupported assertions, secondary results and message/warning checks fail.
An unsupported assertion or unexpected execution error cannot satisfy a
negated result assertion. Resource failures satisfy an expected error only
when the engine supplies the required standard error code.
Error matching compares expanded QNames, so an application error with the same
local name cannot satisfy an expected standard error. EQNames are supported;
prefixed expected codes remain a harness gap until their catalog namespace
context is resolved.

For each confirmed implementation defect, add a small regression to the
existing component tests before fixing it. Retain the original suite pin and
record remaining failures by cause; the report is a backlog, not a percentage
of normative completeness.
