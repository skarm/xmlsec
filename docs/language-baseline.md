# Language suite baseline

Recorded on 2026-10-23 with Go 1.27.3, darwin/arm64 and `GOMAXPROCS=2`.
The Go sources, module manifests and suite pins have SHA-256
`fda956c03d7d9d97d56d500d0b185ea2c05094a9a0881c31dbabea464132d8e6`.
Reports were generated from the working tree based on stage-0 commit `3b31263`
before the language-stage commit and correctly record `library_modified=true`.
The commit containing this baseline retains those tested sources. Documentation is outside the source
checksum.

All five full catalogs were traversed without filters or a case-count limit,
using public default budgets and a one-second case deadline. The adapter
explicitly enables bounded single-byte XML decoding; the public default stays
DTD-free UTF-8/UTF-16. Each run exits unsuccessfully because applicable failures
remain. Complete XPath and Basic XSLT implementation conformance remains open.

## Full-catalog outcomes

- QT3, XPath 2.0: 15,145 passed, 128 failed, 0 skipped, 16,548 not-applicable, out of 31,821 cases.
- QT3, XPath 3.0: 19,198 passed, 156 failed, 0 skipped, 12,467 not-applicable, out of 31,821 cases.
- QT3, XPath 3.1: 21,848 passed, 280 failed, 0 skipped, 9,693 not-applicable, out of 31,821 cases.
- xslt30-test, XSLT 2.0: 5,221 passed, 2,118 failed, 0 skipped, 7,262 not-applicable, out of 14,601 cases.
- xslt30-test, XSLT 3.0: 7,279 passed, 2,440 failed, 0 skipped, 4,882 not-applicable, out of 14,601 cases.

Pins are QT3 `201a6e466940cdfc727f4babfedcde5332b9f578` and xslt30-test
`fddf1cf920087e791f13315d68dfbe874d97dc56`. See the
[pins and license references](../build/w3c-suites.json) and
[adapter contract](language-suites.md). Publisher fixtures and generated JSON
reports remain outside this repository.

Reports retain each case's catalog location, outcome, reason and compiled
processor version, plus source/executable digests, clean suite checkout state,
platform, clock, timezone, limits and decoding setting. The selected processor
is independent of lower stylesheet declarations. This corrects earlier runs
that selected XSLT 3.0 cases but executed a declared 2.0 stylesheet with a 2.0
processor. Deadline-sensitive results still need investigation on another
machine. None of these totals measures normative coverage.

```sh
go build -o /tmp/xmlsec-suites ./tests/cmd/dev
GOMAXPROCS=2 /tmp/xmlsec-suites suites -suite=qt3 -dir=/absolute/path/to/qt3tests \
  -version=3.1 -limits=default -timeout=1s -report=/tmp/qt3-31.json
GOMAXPROCS=2 /tmp/xmlsec-suites suites -suite=xslt30 -dir=/absolute/path/to/xslt30-test \
  -version=3.0 -limits=default -timeout=1s -report=/tmp/xslt-30.json
```

Use clean pinned checkouts and the stated Go version. Repeat QT3 with versions
2.0 and 3.0, and XSLT with 2.0. Reports are written before the expected nonzero
exit for applicable failures. Default limits include 8 MiB input/output, 32 MiB
aggregate resources, 128 resource loads, a 64 KiB program, 100,000 nodes, two
million operations, depth 128 and a three-second engine invocation timeout;
the one-second case deadline also applies.

## Failure backlog by reporting category

- XPath 2.0: 35 assertion, 85 harness, 8 resource-limit.
- XPath 3.0: 33 assertion, 26 dependency, 91 harness, 6 resource-limit.
- XPath 3.1: 39 assertion, 74 dependency, 157 harness, 10 resource-limit.
- XSLT 2.0: 275 assertion, 142 dependency, 284 harness, 1,380 resource-limit, 37 unsupported-profile.
- XSLT 3.0: 471 assertion, 189 dependency, 261 harness, 1,392 resource-limit, 127 unsupported-profile.

A category identifies the failing phase, not a distinct confirmed engine defect.
A source-read or schema error during environment preparation is a harness
failure even if its reason includes a limit. Schema-bearing environments,
relative namespace names, additional assertions and incomplete forwards-compatible
processing remain visible failures. Missing mandatory behavior does not become
an optional Basic feature or a skip.

## Priorities for language closure

1. Numeric types, casts, precision and budgets: expected `FORG0001` mismatches
   remain for `+INF`, URI lexical boundaries and year zero under the catalog's
   XSD 1.0 selection. Complete 1.0/1.1 datatype distinctions remain open.
   Shared XSLT `validrange` and `allLegalChars` construction exceeds default
   budgets; the separate larger-budget probe below does not remove those failures.
2. Signatures, cardinality and errors: selected signatures and conversions have
   local and independent regressions; the whole function inventory remains open.
   XPath 3.1 `fn-subsequence` has 105 passes and two inapplicable cases;
   `fn-error` has 90 passes and eight inapplicable cases. Full static/dynamic
   error precedence and option conversions still need closure.
3. Sequences, focus and names: contextual keywords, EQName grammar/reserved URI,
   expanded type names and frozen builtin signature namespaces have regressions.
   The full axes, identity, type, namespace and sequence contracts remain open.
   XPath 3.1 `fn-position` has 67 passes, `fn-last` 54 passes and 15 inapplicable
   cases, and `fn-deep-equal` retains one failure.
4. Versions and compatibility: a selected modern processor uses its XPath grammar
   and function library with lower stylesheet declarations, preserving per-element
   backwards compatibility across includes/imports. A 2.0 processor cannot yet
   accept a principal 3.0 declaration, and future 4.0 declarations remain
   unsupported. Complete forwards-compatible processing and static host-function
   availability errors remain gaps.
5. Dates, collations, regex, Unicode and serialization: XPath 3.1
   `fn-format-number` has 248 passes, four failures and 17 inapplicable cases;
   `fn-serialize` retains 26 schema-environment failures. UCA, timezone and
   numbering choices contribute to unresolved dependencies. Full normalization,
   regex/XSD edition and serialization contracts remain open. Two Greek Unicode
   case expectations disagree with the catalog's selected Unicode data; they
   remain official failures, with an independent diagnostic below.
6. Resources, callbacks, packages and collections: XPath 3.1 `fn-transform` has
   109 passes, nine failures and six inapplicable cases; `fn-collection` has 22
   passes, one failure and ten inapplicable cases. `fn-uri-collection` has seven
   passes and `fn-json-doc` 68. Complete collection determinism, resource-valued
   collections, package/conflict behavior, assertion forms and message capture
   after termination remain gaps. General DTD processing, schema awareness and
   normative streamability require separate implementations.

The normative register links named contracts, implementation and evidence gaps.
Its completed inventory does not assert complete implementation or a complete
positive/negative test mapping.

## Explicit-budget resource probe

Ten XSLT 3.0 cases were repeated with `-limits=language` and a ten-second case
deadline; the engine's three-second invocation timeout remains in force.
This selects 32 MiB input/per-resource reads, 64 MiB aggregate resource/output
budgets, a 1 MiB program, two million nodes and fifty million operations.
It changes neither public defaults nor full-catalog totals.

The probe records 2 passed, 8 failed, 14,591 skipped and 0 not-applicable:

- `avt-2201` and `match-015` now pass with their original encoded XML inputs.
- `regex-classes-001/002` pass the node cap but reach the regex work budget.
- `unicode90-C-001/002` still exceed the explicit 32 MiB source-read cap.
- `unicode90-Cc-001/002` and `unicode90-Co-001/002` reach their assertions and fail.

A larger resource budget is not a semantic correctness fix.

```sh
GOMAXPROCS=2 /tmp/xmlsec-suites suites -suite=xslt30 -dir=/absolute/path/to/xslt30-test \
  -version=3.0 -limits=language -timeout=10s \
  -sets='^(avt|match|regex-classes|unicode-90)$' \
  -match='^(avt-2201|match-015|regex-classes-00[12]|unicode90-(Cc|Co|C)-00[12])$' \
  -report=/tmp/xslt-resource-probe.json
```

## Fixes and validation

XML byte decoding supports explicit ASCII-compatible single-byte encodings
under both original-byte and decoded UTF-8 limits. Default parser policy stays
unchanged. Unicode `parse-xml`, fragment and `stylesheet-text` inputs retain
declaration grammar checks without re-decoding characters. Fragment TextDecl
processing counts the complete original input before removing a declaration.
The full-document XML assertion path parses declarations and external whitespace
before comparing XML, while fragment whitespace retains its meaning.

Shared XPath paths now validate EQNames and contextual keywords, resolve type
names through their expanded namespaces and preserve builtin signature types
when a caller rebinds `xs`. `doc` distinguishes malformed URI syntax from
resource/base-resolution failures. Processor selection is separate from effective
stylesheet versions across direct, module and `fn:transform` paths;
`xslt-version` requests a minimum processor using exact numeric comparison;
values just above a version boundary retain their decimal precision. Unavailable
versions use FOXT0001.
Small positive/negative regressions extend existing test files.

Compared case by case with `80177f9`, XPath 2.0/3.0/3.1 gain 7/11/16 passes;
no formerly passing XPath case fails. XSLT 3.0 gains 888 passes without a lost
pass. XSLT 2.0 gains 743 and loses one, for a net gain of 742. Skipped and
not-applicable outcomes are unchanged. These are suite-case counts, not counts
of independent defects.

The lost XSLT 2.0 pass is publisher case `result-document-1006`: it invokes
3.0-only `current-output-uri()` while selecting a 2.0+ dependency, then expects
a result-document error. It formerly passed because the 3.0 host function leaked
into the 2.0 processor. The corrected 2.0 function library leaves that case
failing; the missing precise static host-function error remains a separate gap.
The 3.0 selection passes it. No publisher case is rewritten or excluded.

The adapter clock remains `2026-01-01T00:00:00Z` in both compared baselines.
A complete XPath 3.1 control run with the older 2000 clock records 21,844 passes
and 284 failures, four fewer passes. The report records the actual selected
clock; parameter and assertion evaluation share it.

`make check`, `make lint`, relevant race checks and existing Docker
libxml2/libxslt comparisons pass. The existing comparison file runs 95 successful
Saxon HE 12.10 query agreements plus two original-octet XML transformations,
using ready publisher jars in Docker with no new Java/C adapter sources.
Two disagreements remain separate diagnostics: Saxon accepts an invalid EncName
after stripping its declaration, and its Greek U+037F/U+03F3 case mapping differs
from the native mapping. Native case behavior agrees with the
[Unicode 7.0 data](https://www.unicode.org/Public/7.0.0/ucd/UnicodeData.txt)
selected by the QT3 cases and the library's
[Unicode 17.0 data](https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt).
Neither diagnostic is counted as successful agreement; the official failures
remain visible. No recovered panic was observed in the full runs.

This completes the reproducible diagnostic baseline and measurable backlog.
Applicable Basic failures and complete independent clause evidence remain open;
repository gates and a completed register inventory do not establish them.
