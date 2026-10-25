# XPath and XSLT suite diagnostics

## Contents

- [Inputs and licenses](#inputs-and-licenses)
- [Run a selection](#run-a-selection)
- [Deterministic environment and boundaries](#deterministic-environment-and-boundaries)
- [Executable clause and failure evidence](#executable-clause-and-failure-evidence)

The development runner reads external, unmodified checkouts of the official
[QT3](https://github.com/w3c/qt3tests) and
[XSLT 3.0](https://github.com/w3c/xslt30-test) suites. Revisions and catalog
namespaces are pinned in [w3c-suites.json](../build/w3c-suites.json). Neither the
runner nor ordinary Go checks download test material. Git HEAD must match the
pin, and tracked and untracked checkout changes are rejected.
The checkout is checked again after execution. Library Go sources (including
untracked Go files), module manifests and the suite-pin file contribute to
`source_sha256`; a change during execution invalidates the run. This identifies
the exact tested source independently of documentation edits.

These are development diagnostics. Passing a selection does not establish
complete language coverage or authoritative W3C conformance. The
[normative register](conformance.md) separately tracks obligations and gaps.
The [validation profiles](language-baseline.md) define the full-catalog run
configurations. Generated JSON reports stay outside the repository.

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
`-xsd-version=1.0|1.1` selects builtin datatype lexical/regex rules, with 1.0
as the suite default; it is independent of the public engine default 1.1 and does
not enable schema validation. Both `xsd-version` and `XSD_1.1` dependencies use
that actual selection. The report records `xsd_version` and `unicode_version`.
`-xpath10-compatibility` selects the modern QT3 static compatibility property;
its default is false. With this flag, only QT3 cases explicitly declaring that
dependency are applicable; the catalog contract requires strict mode for cases
without it. XSLT runs use stylesheet-local modes.
`-assertions` enables assertions in the suite's XSLT invocation; its default is false. Nested
`fn:transform` calls independently select their standard `enable-assertions` option. Reports
record both choices, and dependencies match those actual settings.

The report is written before a nonzero exit for applicable failures. A run with
no passing applicable case also exits unsuccessfully.

In the XSLT catalog, a parameter's `as` attribute is only a documentation hint;
its `select` expression determines the supplied value and type. The publisher's
[catalog schema](https://github.com/w3c/xslt30-test/blob/fddf1cf920087e791f13315d68dfbe874d97dc56/admin/catalog-schema.xsd#L268)
explicitly requires casts in `select` when conversion is intended. The adapter
preserves this distinction for static, stylesheet, template and function parameters.

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
normative streaming and XML 1.1. DTD dependencies are enabled for bounded
nonvalidating language input; external DTD/entities stay inside the declared
checkout resolver and invocation budgets. Unknown optional features are
reported as dependency failures until their meaning is resolved. The report
records the suite pin, library Git revision and modification state, executable
and source SHA-256, Go/platform, selected version, filters and implementation
settings. Each compiled case also records `execution_version`, the selected processor
version. The adapter sets `XSLTOptions.ProcessorVersion` independently of a lower
stylesheet declaration. A 3.0 run therefore uses the 3.0 processor with 2.0 or
1.0 modules; local backwards-compatible processing remains attached to each
stylesheet element. Higher/future declarations invoke forwards-compatible
processing, including 3.0 declarations with a selected 2.0 processor. Remaining
mandatory forwards-compatible failures stay visible.

Source metadata also affects applicability. A source requesting XInclude,
XML 1.1, normative streaming or stylesheet association through a processing
instruction is not loaded under this profile. The
[pinned catalog schema](https://github.com/w3c/xslt30-test/blob/fddf1cf920087e791f13315d68dfbe874d97dc56/admin/catalog-schema.xsd#L530)
requires the requested preprocessing; its XInclude rule explicitly excludes
processors without that optional facility. Streaming and association flags
apply only to the principal source (`role="."`). Named environments and collection
sources use the same checks. Invalid flags/version values remain failures,
and strict/lax source validation remains an unsupported harness operation.

A QT3 environment's schema declaration also implies a schema-awareness
dependency, as required by its
[pinned catalog schema](https://github.com/w3c/qt3tests/blob/201a6e466940cdfc727f4babfedcde5332b9f578/catalog-schema.xsd#L434).
Such cases are not applicable to this Basic profile; their requested annotations
are never silently removed. The file-free built-in functions namespace import
used by untyped JSON tests supplies no schema components and remains applicable.
The XSLT catalog has a different declaration contract: unused schema declarations
remain applicable, and requested validation still reports its actual failure.

A `unicode-version` dependency identifies an exact edition, as in the publisher
runner; it is not a minimum. The selected Unicode 17.0 case/category data cannot
satisfy exact Unicode 6.0/9.0 category counts. Those cases are reported as
not-applicable, with the edition mismatch recorded, rather than counted as fixed
language failures. Unknown dependency kinds continue to fail. The selected profile declares
implemented UCA fallback, Olson timezone formatting, AD/ISO calendars, negative years and
years above 9999, highest matching package version and supported numbering forms.
The `combinations_for_numbering` range is matched exactly: overflow tests assume
the processor's exact fallback boundary. Different optional ranges remain
not-applicable, with their dependency recorded, rather than counted as fixed
engine defects. Unsupported Buddhist/traditional-Greek formatting, implicit
remote documents and the undeclared RELAX NG extension remain excluded.
Unrecognized dependency kinds and numbering combinations remain failures unless
another dependency conclusively excludes the case.

## Deterministic environment and boundaries

The clock defaults to `2026-01-01T00:00:00Z`; `-current-time=<RFC3339>` selects
another fixed instant for the entire run. Query/stylesheet evaluation, parameter
expressions and assertions share that clock, which is recorded in the report.
Implicit timezone is UTC, language
is English and the initial default collation is Unicode codepoint. The selected
limit profile is recorded in the report. Per-case timeouts additionally bound
execution; deadline-sensitive failures require investigation, not reclassification
as a pass or skip.

Only declared URI-to-file mappings, `file:` resources and their resolved absolute
local paths confined to the suite checkout can be read. Each form uses the same
byte, cancellation and containment checks. Symlinks and traversal outside it are rejected. There is
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
parameters, static parameters, declared text resources, document/text/query collections
and an explicit context item. Static metadata is applied before source loading,
independently of its catalog order. Declared text resources retain their MIME
type and charset through `resource.TypedReader`; the engine performs decoding
under its normal budgets. Test bytes are not transcoded by the harness.
Collection text members use that same `unparsed-text()` path and retain their
retrieval URIs; query members retain their own namespace scope. Both pinned
catalogs currently contain no text-resource collection members, so their support
has local regression evidence rather than additional publisher passes.
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

Inline source XML is parsed with the content element's catalog base URI,
including inherited `xml:base`, following the publisher's `c:parse-xml` runner.
This base is independent of the environment's XPath static base; a constructed
source's base does not give it a retrieval document URI.
Catalog `file` attributes are URI references, including percent-escaped paths;
their own inherited `xml:base` controls local retrieval. Resolved paths remain
confined to the suite checkout, including symlink checks. A separate resource
`uri` controls its language identity. Declared HTTP resource files are recorded
without fetching them: unused declarations are harmless, while actual reads
report their unavailability in this offline profile.

Environment and invocation modules can supply a principal stylesheet/package
and secondary modules. Declared packages are resolved by name and version;
each source version retains its own file/base URI, even when catalog package
URIs agree. A secondary package's own expanded `xsl:package` root supplies its
name and version; stale catalog metadata does not rewrite the declaration.
Explicit catalog identities remain discovery hints for computed shadow attributes
or invalid roots, which the compiler evaluates and diagnoses itself.
The highest matching declared version is selected using the same range parser
as the compiler, which independently validates the returned package. No undeclared
package or network fallback is added. Output metadata selects a logical base
output URI, serialization, an optional XML result tree and a raw-result variable.
An omitted output `file` keeps the driver default; an empty `file` resolves
against the catalog node's base URI, including `xml:base`; `#absent` removes it.
Output URIs never write files. XSLT schema declarations register bounded local
retrieval resources without enabling validation or importing schema components.
Unused declarations can coexist with Basic execution, and requested schema
imports/types reach the compiler's prescribed errors. Schema target namespaces
do not replace distinct file retrieval URIs. Source shorthand XML-ID fragments select element values for collections,
variables and context items. File URI paths are decoded separately from their
fragments; retrieval mappings and document-uri use the fragment-free URI, while
uri-collection retains the member URI. A per-case source cache preserves repeated
collection members and their common root. Role-free file sources are registered
without eager XML parsing: doc()/document() performs the load, so malformed
resources can produce the runtime errors asserted by the catalog. Missing IDs, general XPointer schemes,
conflicting fragments/mappings and paths outside the suite root are harness
failures. Source schema validation remains a harness gap; a case requiring it
fails with a reason. QT3's file-free import of the built-in functions namespace is
recognized for untyped `json-to-xml`; `validate=true` reaches the evaluator's
`FOJS0004` without enabling schema validation. Other QT3 schema declarations
imply the optional schema-awareness dependency described above.

Assertions include standard errors, boolean/count/empty/type/value checks,
XPath predicates, XML fragments, exact serialization, serialization regex,
atomic permutations with multiplicities, `all-of`, `any-of` and `not`. XML comparison preserves comments and prefix
differences unless `ignore-prefixes` is explicit. Parsed nodes are compared
through public immutable handles, preserving PI names/data, text and attribute
values while ignoring attribute order and unused namespace declarations. Relative
namespace names remain literal; C14N is unsuitable because it must reject them.
If the normal XML parser rejects namespace names admitted by the XDM datatype
rules, the UTF-8 comparator retries with shared injective aliases for namespace
values on both sides. Only namespace declaration values are rewritten; text,
ordinary attributes, comments and processing instructions retain their bytes.
The ordinary parser still checks names, prefixes and reserved namespace bindings.
Complete documents discard outer layout whitespace; fragments retain their text. String whitespace follows the respective catalog defaults.
Expected UTF-8, ASCII and ISO-8859-1 serialization files normalize CRLF
to LF, following the pinned publisher runner's text comparison. Bare CR data,
inline expectations and the actual serializer bytes are retained. UTF-16 files
are not byte-normalized. Byte mismatches report the first differing offset and
bounded context. Serialization regex assertions operate on characters, using
`Result.OutputEncoding(uri)` for the actual primary/secondary encoding.
UTF-8, UTF-16 and the supported IANA codecs are decoded strictly, retaining a
BOM as U+FEFF for assertions that explicitly check it. Explicit UTF-16BE/LE
also support BOM-free output. Malformed byte sequences, encoding/BOM conflicts
and unavailable codecs remain harness failures. Decoder replacement characters
require an exact encoding round trip, preserving real U+FFFD while rejecting
lossy repair. A declaration-like string in text output does not select a codec.
Unless serialization is requested, the runner selects `ResultDefault`, honoring
each output's effective `build-tree` setting. Catalog `tree="yes"` requests final
tree construction; `tree="no"` requests raw XDM values. Normalization uses the
engine directly, without a serialize/parse round trip that would discard types,
identity or non-well-formed document contents.

Secondary-result assertions retain their URI, XDM sequence and serialization
context. Message assertions inspect serialized message XML from successful
results and from `transform.Error.Messages()` after failed execution. Warning
assertions and other unsupported assertions remain failures.
An unsupported assertion or unexpected execution error cannot satisfy a
negated result assertion. Resource failures satisfy an expected error only
when the engine supplies the required standard error code. Harness error wrappers preserve the original cause. Budget failures during
preparation or assertion-expression evaluation are reported as resource failures and cannot
satisfy wildcard or negated assertions. Case deadlines remain resource failures
during preparation, execution and assertions, regardless of a matching surrounding
language code.
Error matching compares expanded QNames, so an application error with the same
local name cannot satisfy an expected standard error. EQNames are supported;
prefixed expected codes use the catalog's inherited and local namespace context.

For each confirmed implementation defect, add a small regression to the
existing component tests before fixing it. Retain the original suite pin and
record remaining failures by cause; the report is a backlog, not a percentage
of normative completeness.

## Executable clause and failure evidence

`conformance.json` names exact publisher cases and finite independent controls.
A parent closes only through every applicable immediate child, or through its
own tested composition with an explicit normative basis. A processor diagnostic
is recorded separately from an agreement. Published table vectors carry literal
expected values; Appendix D publication checks carry the exact host-choice item.
These are finite evidence claims for the declared profile, not proofs over all
possible expressions or a broader standards certification.

Run the configured native and `-tags=interop` tests with `go test -json -count=1`.
Set both Saxon classpaths, `SERIALIZATION_SCHEMA_DIR`, `JSON_SCHEMA_FILE`,
`XMLSEC_QT3_DIR` and `XMLSEC_XSLT_DIR`; use `XMLSEC_REQUIRE_P3_PROOFS=1` for
`TestQT3ResidualCauses`, `TestXSLTResidualCauses` and the JSON schema comparison.
Missing inputs then fail instead of silently omitting these external checks.
The JSON schema is the published [XSLT 3.0 Appendix B.1 schema](https://www.w3.org/TR/2017/REC-xslt-30-20170608/#schema-for-json), SHA-256
`3ba9d28cc77ac0ba876a7e3dd88308381c4e32334ea412b17961968a37ba6f9d`.
Keep checkouts, jars, schemas, JSON event streams and reports outside the repository.
When using Docker, mount the repository checkout with its Git metadata read-only,
alongside the external suites and engine/schema inputs. The image includes Git
for checkout-pin and source-digest validation.

Keep the sources and register fixed while producing the thirteen full-catalog
baseline runs and captured test streams. The repository runner records the actual
source/register hashes before and after each Go process, its exit status, and its
complete package events. The merger checks each capture individually; it never
restamps old event files using a newer report. Failed, interrupted, malformed or
mixed-revision captures cannot close evidence.

Capture the configured native, independent and causal runs (the paths below are
external output files, not committed fixtures). Exclude the two final gates until
their input artifact has been merged, and run the causal tests once separately:

```sh
XMLSEC_REQUIRE_P3_PROOFS=1 go run ./tests/cmd/dev proof capture \
  -out /tmp/native.proof.json -- -timeout=10m \
  -skip='^Test(Language(NormativeEvidence|ResidualCoverage)|(QT3|XSLT)ResidualCauses)$' ./...
XMLSEC_REQUIRE_P3_PROOFS=1 go run ./tests/cmd/dev proof capture \
  -out /tmp/interop.proof.json -- -tags=interop -timeout=20m \
  -run='^TestCompare' ./transform
XMLSEC_REQUIRE_P3_PROOFS=1 go run ./tests/cmd/dev proof capture \
  -out /tmp/residuals.proof.json -- -timeout=10m \
  -run='^Test(QT3|XSLT)ResidualCauses$' ./tests/cmd/dev
go run ./tests/cmd/dev proof merge -out /tmp/proof-events.json \
  /tmp/native.proof.json /tmp/interop.proof.json /tmp/residuals.proof.json
XMLSEC_REQUIRE_P3_PROOFS=1 XMLSEC_P3_TEST_EVENTS=/tmp/proof-events.json \
  XMLSEC_P3_SUITE_REPORTS='/tmp/qt20.json:/tmp/qt30.json:/tmp/qt31.json:...' \
  go test -count=1 -timeout=20m ./tests/cmd/dev \
  -run '^TestLanguage(NormativeEvidence|ResidualCoverage)$'
```

Capture shards with the same command when splitting independent runs. Supply every
capture to `proof merge`; the final gate checks the union of exact witnesses.
Capture files retain their own identities inside the merged artifact. Ordinary
`go test -json` streams and manually stamped envelopes are not accepted.
A failed capture or merge invalidates its selected output rather than leaving a
previous successful file there. The runner prevents accidental reuse; it is not
an authentication mechanism for artifacts intentionally edited by their owner.

Supply all thirteen reports listed in the [validation profiles](language-baseline.md), with the platform path-list
separator (`:` on Unix). The final gate validates settings, pins, complete catalog
inventories and totals; replays each cited publisher input with its original full
assertion; checks exact passing subtests and oracle/vector markers; and requires a
passing causal check for every remaining failed case. Each retained failure also
names its exact language/XSD/limits/assertion/compatibility profile, failure kind,
standard error-code alternatives and typed cause. A new profile failure, panic,
harness cause or error code requires a new review; another failure of the same
publisher case cannot inherit its old explanation. It rejects stale source or
register digests, changed sources/checkouts, skipped witnesses, obsolete failure
classifications and new unclassified failures. Original failures are replayed
before any bounded input, feature or fixture counterfactual; the intervention and
its assertion are retained in the existing component/development tests.
