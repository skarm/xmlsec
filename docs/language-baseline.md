# Language suite baseline

Recorded on 2026-10-24 with Go 1.27.3, darwin/arm64 and `GOMAXPROCS=2`.
Tested Go sources, module manifests and suite pins have SHA-256
`b7efaa2697a32f5f5f7e0acfeb4247f7943e7263d223a24356a7fc82eaf0b20d`.
Reports identify the working tree as based on `6fa60c4`,
`library_modified=true`; documentation is outside the source checksum.

Complete XPath and Basic XSLT conformance remain open. These diagnostics and
repository checks do not establish normative coverage. Keep this file as the
current snapshot; implementation history is available in Git.

## Full-catalog outcomes

All runs traverse the full pinned catalogs without filters or case-count limits.
The five main runs use XSD 1.0 datatype/regex rules and `-assertions`:

- QT3, XPath 2.0: 15,178 passed, 93 failed, 0 skipped, 16,550 not-applicable, out of 31,821 cases.
- QT3, XPath 3.0: 19,246 passed, 101 failed, 0 skipped, 12,474 not-applicable, out of 31,821 cases.
- QT3, XPath 3.1: 21,949 passed, 172 failed, 0 skipped, 9,700 not-applicable, out of 31,821 cases.
- xslt30-test, XSLT 2.0: 5,576 passed, 95 failed, 0 skipped, 8,930 not-applicable, out of 14,601 cases.
- xslt30-test, XSLT 3.0: 7,873 passed, 159 failed, 0 skipped, 6,569 not-applicable, out of 14,601 cases.

Three additional full-catalog controls use the same sources and budgets:

- XSD 1.1, XPath 3.1: 21,993 passed, 172 failed, 0 skipped, 9,656 not-applicable.
- XSD 1.1, XSLT 3.0: 7,878 passed, 158 failed, 0 skipped, 6,565 not-applicable.
- Assertions disabled, XSD 1.0, XSLT 3.0: 7,862 passed, 159 failed, 0 skipped, 6,580 not-applicable.

The last control's eleven-case difference reflects assertion policy and catalog
applicability. Public and adapter assertion checking default to disabled;
nested `fn:transform` independently uses its standard option, also default false.
The XSD selection controls builtin datatype/regex rules, without schema validation
or schema-aware processing. No recovered panic occurred in any of the eight runs.
Every run exits unsuccessfully because applicable failures remain.

## Reproduction

Use clean external checkouts at these revisions:

- QT3: `201a6e466940cdfc727f4babfedcde5332b9f578`.
- xslt30-test: `fddf1cf920087e791f13315d68dfbe874d97dc56`.

[Pins and license references](../build/w3c-suites.json) and the
[adapter contract](language-suites.md) describe checkout validation, dependencies,
resource policy and report fields. Publisher fixtures and generated JSON reports
stay outside this repository.

```sh
go build -o /tmp/xmlsec-suites ./tests/cmd/dev
GOMAXPROCS=2 /tmp/xmlsec-suites suites -suite=qt3 -dir=/absolute/path/to/qt3tests \
  -version=3.1 -xsd-version=1.0 -limits=default -timeout=1s -assertions -report=/tmp/qt3-31.json
GOMAXPROCS=2 /tmp/xmlsec-suites suites -suite=xslt30 -dir=/absolute/path/to/xslt30-test \
  -version=3.0 -xsd-version=1.0 -limits=default -timeout=1s -assertions -report=/tmp/xslt-30.json
```

Repeat QT3 with versions 2.0 and 3.0, and XSLT with 2.0. For the controls, select
`-xsd-version=1.1` or omit `-assertions`. Reports are written before the expected
nonzero exit. Use the stated toolchain and public default budgets, plus the
one-second case deadline; deadline-sensitive failures need investigation on
another machine. The default fixed clock is `2026-01-01T00:00:00Z`, timezone UTC.

The adapter enables bounded single-byte XML decoding; the public default is
DTD-free UTF-8/UTF-16. Reports record Unicode 17.0, actual `execution_version`,
source/executable digests, suite checkout state, clock, timezone, limits and
decoding policy. A source change or modified suite invalidates the run.

## Failure backlog by reporting category

- QT3, XPath 2.0: 0 assertion, 85 harness, 8 resource-limit.
- QT3, XPath 3.0: 4 assertion, 91 harness, 6 resource-limit.
- QT3, XPath 3.1: 4 assertion, 158 harness, 10 resource-limit.
- xslt30-test, XSLT 2.0: 66 assertion, 22 harness, 7 resource-limit.
- xslt30-test, XSLT 3.0: 115 assertion, 33 harness, 11 resource-limit.

A category identifies the failing phase, not a confirmed engine defect.
Schema-bearing environments, DTD input, relative namespace names, unsupported
harness assertions and missing language behavior remain visible failures.
Missing mandatory implementation must not be reclassified as not-applicable.
XML/serialization mismatches include a bounded excerpt of the differing bytes;
a failed transformation remains the cause of secondary-result assertion failure.

Specific unresolved cases include:

- XPath 3.0/3.1 `parse-xml-006`, `-008`, `-009`, `-010`: DTD processing is required;
  the security parser rejects DTDs. These are the four assertion failures in each version.
- `fn-transform-43`: its quantified assertion can parse an empty principal value;
  the resulting assertion-evaluation error remains a harness failure.
- XSLT `output-0102c` and `output-0103c`: fixtures require `&gt;` where native emits
  a permitted literal `>` in an attribute. Publisher fixtures remain unchanged.
- XSLT `static-012` and `static-013`: expected codes differ from the native
  global-parameter missing-value/type errors (`XTDE0050`/`XTTE0590`).
- XSLT `static-013c`: `select="111"` supplies an integer; its catalog
  `as="xs:string"` hint does not convert it. The expected type error remains a failure.
- XSLT 2.0 `collection-005`: the stylesheet uses XSLT 3.0 `xsl:mode`; the visible
  `XTSE0010` assertion failure remains after source loading was corrected.

## Language work and remaining priorities

The [normative register](conformance.md) links obligations to bounded evidence;
it does not assert complete implementation or positive/negative coverage.
Host-library, formatter, initial-template, grouping, source-line and circular-key error contracts
have direct regressions and 3.0 Saxon controls. Standard F&O signatures retain
their versioned types across direct, named, lookup, partial, public-adapter and
static paths. Document fragment ordering and the bounded XML prolog probe have
local regressions. Decimal compatibility versions, module namespace conditions and
1.0/2.0 import order have direct regressions and strict 2.0/modern 3.0 controls.
Complete strict 2.0 grammar and Basic validation remain open.
Remaining work includes:

1. Numeric values and casts: complete datatype/value-space distinctions, schema
   types and independent clause evidence.
2. Function contracts: remaining static/dynamic error precedence, options and
   conversion/context combinations beyond the shared versioned signature catalog.
3. Sequences, focus and names: remaining axes, typed input, identity and
   package/context combinations; complete pattern grammar, nested operators,
   priorities and runtime error recovery.
4. Processor versions: complete Basic and forwards-compatible processing.
5. Dates, collations, regex, Unicode and serialization: remaining calendar
   arithmetic and complete regex/serialization obligations.
6. Resources, callbacks and packages: resource-valued catalog collections,
   remaining component/import graphs, parameter/signature combinations, escaping
   functions/global contexts, local-rule placement and callback/error combinations.

General XML/DTD input, schema validation, schema-aware XSLT and normative W3C
streamability require separate implementations.

## Validation and independent engines

For the tested sources, `make check`, `make lint`, relevant race checks and the
full Docker transform comparison run passed. The latter used ready Saxon HE 12.10
publisher jars, ready Saxon HE 9.4.0.9J in explicit XSLT 2.0 mode, libxml2 and
libxslt, with networking disabled and no skipped tests.
See [testing instructions](testing.md) for setup and commands.

Exact agreements and known differences have separate expectations in the existing
[comparison tests](../transform/comparison_v1_test.go). Diagnostics cover:

- Edition, XML parsing and serialization: Greek case mappings, EncName handling,
  CDATA CRs, HTML DOCTYPE output and character-map normalization.
- Error selection and execution policy: include/import cycles, declaration
  placement, attribute-set cycles, context items, `xsl:evaluate`, transform
  delivery, processor selection and static parameter/variable conversions.
- Packages, modes and values: component visibility/overrides, import scope,
  function/node identity, key comparison, invalid xml:id whitespace, optimized map
  merging and passive exponent suffixes in number pictures.
- Dynamic context: Saxon retains output URIs for three named-reference paths,
  a merge group for a function reference, and grouping state in two key specifiers.
- Function types/errors: base-URI return metadata, premature grouping-reference
  errors, unparsed-entity context codes, doc fragment codes and document input
  conversion differ in explicit diagnostic cases.
- Resource identity: Saxon emits four old `XTRE1500` codes, suppresses one
  availability conflict and misses sixteen text/JSON/parameter-document conflicts.
- Content construction: conditional emptiness, namespace inheritance and the
  default priority of `(n | r/m)[true()]`. A standalone Saxon collection catalog
  also ignores member URI fragments and cannot establish agreement with those
  publisher environments.

These differences are not counted as exact agreements. Full clause evidence
and the applicable failures above remain open.
