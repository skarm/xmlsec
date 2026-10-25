# Language suite baseline

Recorded on 2026-10-24 with Go 1.27.3, darwin/arm64 and `GOMAXPROCS=2`.
Tested Go sources, module manifests and suite pins have SHA-256
`fe804b218c748360634b242679a10f55d33b333d4daa1317c4fda8d9fd223b15`.
Reports identify the working tree as based on `9ad85aa`,
`library_modified=true`; documentation is outside the source checksum.

Complete XPath and Basic XSLT conformance remain open. These diagnostics and
repository checks do not establish normative coverage. Keep this file as the
current snapshot; implementation history is available in Git.

## Full-catalog outcomes

All runs traverse the full pinned catalogs without filters or case-count limits.
The five main runs use XSD 1.0 datatype/regex rules and `-assertions`:

- QT3, XPath 2.0: 15,220 passed, 78 failed, 0 skipped, 16,523 not-applicable, out of 31,821 cases.
- QT3, XPath 3.0: 19,292 passed, 82 failed, 0 skipped, 12,447 not-applicable, out of 31,821 cases.
- QT3, XPath 3.1: 22,039 passed, 109 failed, 0 skipped, 9,673 not-applicable, out of 31,821 cases.
- xslt30-test, XSLT 2.0: 5,663 passed, 69 failed, 0 skipped, 8,869 not-applicable, out of 14,601 cases.
- xslt30-test, XSLT 3.0: 8,000 passed, 103 failed, 0 skipped, 6,498 not-applicable, out of 14,601 cases.

Controls with the same sources and budgets:
- XSD 1.1, XPath 3.1: 22,083 passed, 109 failed, 0 skipped, 9,629 not-applicable.
- XSD 1.1, XSLT 3.0: 8,005 passed, 102 failed, 0 skipped, 6,494 not-applicable.
- Assertions disabled, XSD 1.0, XSLT 3.0: 7,989 passed, 103 failed, 0 skipped, 6,509 not-applicable.

The last control's eleven-case difference reflects assertion policy and catalog
applicability. Public and adapter assertion checking default to disabled;
nested `fn:transform` independently uses its standard option, also default false.
The XSD selection controls builtin datatype/regex rules, without schema validation
or schema-aware processing. No recovered panic occurred; every run exits unsuccessfully because failures remain.

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

The adapter enables bounded single-byte XML decoding and language DTD input;
Engine.Parse, record input and XMLDSig retain DTD-free UTF-8/UTF-16. Reports record Unicode 17.0, actual `execution_version`,
source/executable digests, suite checkout state, clock, timezone, limits and
decoding policy. A source change or modified suite invalidates the run.

## Failure backlog by reporting category

- QT3, XPath 2.0: 0 assertion, 70 harness, 8 resource-limit.
- QT3, XPath 3.0: 0 assertion, 76 harness, 6 resource-limit.
- QT3, XPath 3.1: 0 assertion, 99 harness, 10 resource-limit.
- xslt30-test, XSLT 2.0: 53 assertion, 7 harness, 9 resource-limit.
- xslt30-test, XSLT 3.0: 76 assertion, 12 harness, 15 resource-limit.

A category identifies the failing phase, not a confirmed engine defect.
Schema-bearing environments, unsupported harness assertions and
missing language behavior remain visible failures.
Missing mandatory implementation must not be reclassified as not-applicable.
XML/serialization mismatches include a bounded excerpt of the differing bytes;
a failed transformation remains the cause of secondary-result assertion failure.

Specific unresolved cases:
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

- HTML `output-0602a`/`-0603a` require namespace removal/redeclaration beyond the
  published rules; the former's publisher comment acknowledges that interpretation.
  `output-0724` and `attribute-0301` require an unescaped
  `input/@value`, contrary to the published Appendix D; [W3C qtspecs issue 21](https://github.com/w3c/qtspecs/issues/21)
  remains open. No fixture or outcome has been suppressed.

## Language work and remaining priorities

The [normative register](conformance.md) links obligations to bounded evidence;
it does not assert complete implementation or positive/negative coverage.
Bounded local and Saxon controls cover function signatures, value/cardinality
errors, version modes, static preprocessing, module aliases, document references,
namespace input, built-in templates and prepared input/context identity.
Shared XML/HTML/XHTML controls cover CDATA, references/repertoires, version
selection, original URI values, namespace scope, all-head metadata, inline and
`xml:space` indentation, writer/fallback output and input ownership. GC/concurrent
controls protect temporary and namespace `generate-id()` identity. They do not
establish complete Basic semantics, grammar or clause coverage.
XPath and XSLT now share serialization sequence normalization: a single XML
declaration, document flattening, coalesced text before normalization and escaped
separators. Raw/document output enforces the same DOCTYPE shape errors. All six
XPath/XSLT methods bound character-map expansion before buffer growth. JSON maps
original string characters, preserves syntax/replacements and normalizes before
escaping C1, quotes, backslashes and unencodable characters. Text excludes
comments/PIs. Shared adaptive rules cover functions, QName/primitive atomics,
container sequences, mapped quotes and delegated XML parameters/declarations.
Adaptive recovers unencodable markup using UTF-8, before writing the item;
invalid XML characters retain their serialization errors.
Remaining work:
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

Language DTD input now covers entity/default normalization, physical-entity bases,
ID/IDREF flags and unparsed identifiers. Static/runtime stylesheet expressions and
includes retain external-entity bases, including `use-when-0136`.
General XML processor conformance, schema
validation, schema-aware XSLT and normative W3C streamability remain separate work.

## Validation and independent engines

`make check`, zero-issue lint and relevant race checks pass. External consumer
checks, including race and writer allocation/error bounds, pass. The complete
Docker transform comparison passes without skips using ready Saxon HE 12.10,
Saxon HE 9.4.0.9J in XSLT 2.0 mode, libxml2 and libxslt, with networking disabled.
See [testing instructions](testing.md) and the existing
[comparison tests](../transform/comparison_v1_test.go).

Predicates allow permitted empty-tag, entity, HTML DOCTYPE and outer-layout
spelling. Separate native/oracle expectations retain static error selection,
resource/context identity, conditional construction, HTML5 URI recognition,
MathML metadata, CDATA CR/C1/NEL/LS, XML-island PI and map-default differences.
XHTML controls also retain Saxon's leading-text DOCTYPE and unescaped
`source/@src` diagnostics. Publisher expectations remain unchanged.
DTD controls separately retain Saxon differences in CR normalization, unused
predefined/NCName declarations, copied ID flags, constructed document entities
and entity read/write tracking. DTD fuzzing completed 538,965 inputs without failure.

Sequence controls retain Saxon's detached CDATA text loss and normalization
before text coalescence as separate exact-output diagnostics. Complete clause
evidence and applicable failures remain open.
