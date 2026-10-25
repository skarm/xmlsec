# Language suite baseline

Recorded on 2026-10-24 with Go 1.27.3, darwin/arm64 and `GOMAXPROCS=2`.
Tested Go sources, module manifests and suite pins have SHA-256
`84db9ff7b741bdd2547150305e85c309c82f4f8f4bdc17989a4ec6f77f9f02ae`.
Reports identify the working tree as based on `a5421e7`,
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
- xslt30-test, XSLT 3.0: 7,986 passed, 101 failed, 0 skipped, 6,514 not-applicable, out of 14,601 cases.

Controls with the same sources and budgets:

- XSD 1.1, XPath 3.1: 22,083 passed, 109 failed, 0 skipped, 9,629 not-applicable.
- XSD 1.1, XSLT 3.0: 7,991 passed, 100 failed, 0 skipped, 6,510 not-applicable.
- Assertions disabled, XSD 1.0, XSLT 3.0: 7,975 passed, 101 failed, 0 skipped, 6,525 not-applicable.

Source metadata excludes fifteen normative-streaming cases and one XInclude
case from the XSLT 3.0 selections. Fourteen previously counted passes and two
failures had ignored that preprocessing. This is an applicability correction.

The last control's eleven-case difference reflects assertion policy and catalog
applicability. Public and adapter assertion checking default to disabled;
nested `fn:transform` independently uses its standard option, also default false.
The XSD selection controls builtin datatype/regex rules, without schema validation
or schema-aware processing. No recovered panic occurred; every run exits unsuccessfully because failures remain.

An additional full-catalog `-limits=language` control, with the same one-second
case deadline, gives XPath 3.1: 22,042 passed, 106 failed; XSLT 3.0: 7,988 passed,
99 failed. Both have zero skips and unchanged applicability. Three XPath and two
XSLT resource failures pass; `fn-transform-27` instead reaches a failing assertion
because its timing/cache expectation sees the fixed clock. The
[F&O cache option](https://www.w3.org/TR/2017/REC-xpath-functions-31-20170321/#func-transform)
is an efficiency hint. That diagnostic remains failed, without changing the clock
or publisher expectation. Expanded-budget results do not replace default results.

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
- xslt30-test, XSLT 2.0: 53 assertion, 5 harness, 11 resource-limit.
- xslt30-test, XSLT 3.0: 74 assertion, 10 harness, 17 resource-limit.

A category identifies the failing phase, not a confirmed engine defect.
Schema-bearing environments, unsupported harness assertions and
missing language behavior remain visible failures.
XPath 3.1 retains 98 schema/validation preparation failures, one assertion-query
error and ten resource failures. XSLT 3.0 retains five unsupported warning
assertions, four unmapped remote sources and one missing-source declaration;
its seventeen resource failures include two parameter-compilation budgets.
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

## Six-area review

The stage's diagnostic review and reproducible reporting cover all six roadmap
areas. [The acceptance record](conformance.md#stage-3-diagnostic-acceptance-record)
links the evidence; [the normative register](conformance.md) retains incomplete
implementation and clause-coverage states.

1. Numeric types/casts: finite decimal and duration division, exact integer
   boundaries and cumulative numeric budgets across AST, VM, bindings and XSLT.
2. Function contracts: versioned signatures/cardinality, promotions and expanded
   error codes across direct, named, lookup, partial and converted calls.
3. Sequences/focus/names: raw/document/serialized delivery, normalized text,
   namespace/QName scope, global/selection context and GC-safe node identity.
4. Versions/compatibility: selected processor versus module declarations,
   local backwards/forwards processing, static preprocessing and import scopes.
5. Dates/collation/regex/Unicode/serialization: calendar overflow, edition rules,
   bounded regex and six shared serialization methods. Character maps expand
   original characters under budgets; JSON normalizes before escaping, and
   adaptive serialization delegates XML parameters and uses UTF-8 recovery for
   unencodable markup before writing. Invalid XML characters still fail.
6. Resources/callbacks/packages/collections: scoped typed resource reads,
   visibility/version selection, stable document/text/query members and bounded
   source preparation, including declared optional preprocessing.

The backlog above remains the acceptance boundary for further language work.
Close schema-bearing/strict-validation cases with an explicit typed-input model
and its own requirements; do not strip annotations to make cases pass. Resolve
remaining assertion differences against the pinned REC/errata before changing
code or expectations. Re-run resource failures under a separately reported
budget to distinguish a bound from incorrect behavior. Complete clause-specific
positive, negative and independent evidence is still required for a full claim.
General XML processor conformance, schema-aware XSLT and normative W3C
streamability are separate work.

## Validation and independent engines

`make check`, zero-issue lint and relevant race checks pass. External consumer
checks, including race and writer allocation/error bounds, pass. The complete
Docker transform comparison passed before the vocabulary relocation, without
skips, using ready Saxon HE 12.10,
Saxon HE 9.4.0.9J in XSLT 2.0 mode, libxml2 and libxslt, with networking disabled.
See [testing instructions](testing.md) and the existing
[comparison tests](../transform/comparison_v1_test.go).

Comparisons distinguish permitted lexical alternatives from exact agreements.
Separate native/oracle diagnostics retain edition/error-code choices, focus and
resource identity, HTML/XHTML namespaces and URI handling, DTD normalization and
copied flags, detached CDATA text, coalescing before Unicode normalization and
adaptive character-map/repertoire recovery. Publisher fixtures remain unchanged.
DTD fuzzing completed 538,965 inputs without failure. Complete clause evidence
and applicable failures remain open.
