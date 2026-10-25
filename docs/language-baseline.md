# Language suite baseline

This development snapshot was recorded on 2026-10-22 from clean library commit
`903073ec3b10c287dd86f4384b617b5fe93636fd`, using Go 1.27.3 on darwin/arm64.
It diagnoses the selected bounded profiles; it does not establish complete
Basic XSLT or XPath conformance. The full catalogs were traversed without a
set/case filter or case-count limit. All five runs exited unsuccessfully because
applicable failures remain.

## Outcomes

- QT3, XPath 2.0: 15,119 passed, 154 failed, 0 skipped, 16,548
  not-applicable, out of 31,821 catalog cases.
- QT3, XPath 3.0: 19,024 passed, 330 failed, 0 skipped, 12,467
  not-applicable, out of 31,821 catalog cases.
- QT3, XPath 3.1: 21,110 passed, 1,018 failed, 0 skipped, 9,693
  not-applicable, out of 31,821 catalog cases.
- xslt30-test, XSLT 2.0: 4,201 passed, 3,138 failed, 0 skipped, 7,262
  not-applicable, out of 14,601 catalog cases.
- xslt30-test, XSLT 3.0: 5,569 passed, 4,150 failed, 0 skipped, 4,882
  not-applicable, out of 14,601 catalog cases.

Generated JSON reports belong outside the repository. Each report records every
case with its set, name, catalog file and outcome; every non-pass has a reason.
It also records the executable SHA-256, pinned suite revision, implementation
limits, one-second case deadline and deterministic dynamic context. Those
settings are part of the result. Wall-clock deadlines can vary by machine; a
repeated deadline failure needs investigation. These counts are not percentages
of normative coverage and do not distinguish every cause of a shared failure.

```sh
go run ./tests/cmd/dev suites -suite=qt3 -dir=/absolute/path/to/qt3tests \
  -version=3.1 -timeout=1s -report=/tmp/qt3-current.json
go run ./tests/cmd/dev suites -suite=xslt30 -dir=/absolute/path/to/xslt30-test \
  -version=3.0 -timeout=1s -report=/tmp/xslt-current.json
```

Check out the baseline library commit to reproduce its implementation; running
the command on a later commit evaluates that later implementation. Repeat with
`-version=2.0` or `3.0` for the other QT3 selections and `-version=2.0` for XSLT.
See [adapter semantics and boundaries](language-suites.md) and
[suite pins](../build/w3c-suites.json) for preparation and interpretation.

## Remaining work by cause

XPath 3.1 failures comprise 799 harness failures, 134 assertion/implementation
failures, 74 unresolved dependencies, 10 resource-limit failures and one
unsupported-profile failure. Common
harness gaps are decimal-format metadata, text-resource transport metadata and
schema-bearing environments. The global environment of `app-spec-examples`
contains named decimal formats, so its harness gap blocks
many otherwise unrelated examples. The 548 affected examples are not 548
confirmed library defects.

XPath 2.0 has 59 assertion, 87 harness and 8 resource-limit failures. XPath 3.0
has 114 assertion, 184 harness, 26 dependency and 6 resource-limit failures.
Implementation work includes static/dynamic error codes, casts and numeric
boundaries, focus/cardinality and version-specific syntax. Standalone XPath
3.1 now uses the engine's bounded XSLT implementation for `fn:transform`;
static-parameter dependencies and processor compatibility modes still fail
some of its official tests at this baseline. UCA fallback, timezone and
numbering dependencies need explicit interpretation before classification.

XSLT 3.0 failures comprise 1,380 harness failures, 1,390 resource-limit failures,
1,049 assertion/implementation failures, 189 unresolved dependencies and 142
unsupported-profile failures. XSLT 2.0 has 756 harness, 1,378 resource-limit,
801 assertion, 142 dependency and 61 unsupported-profile failures. The main
harness gaps are packages, output overrides, multiple invocation stylesheet
modules, input encodings and additional invocation forms. A shared
`validrange` variable exceeds the selected node budget in 1,254 Unicode cases;
another shared variable, `allLegalChars`, exceeds it in 120 cases. These
failures need a separate budgeted language run and resource assessment.
Oversized source files and source trees also remain explicit failures. Some
resource failures occur during environment preparation and therefore have
`kind=harness`; the reason retains the underlying limit. The categories identify
where the adapter failed, not an exhaustive root-cause classification.

Encoding restrictions, relative namespace URIs and unsupported language
declarations are recorded as failures within the selected test run, even when
the library documents its narrower XML security profile. They do not become
optional Basic language requirements. None of these runs observed a recovered
panic; this says nothing about unexecuted optional profiles or independent
security assessment.

## Regression fixes before this baseline

The first selected runs exposed missing XPDY0130 for XPath 3.0/3.1 limits,
incorrect value-template and `xsl:value-of` error codes, and failure to construct
nonempty parentless attributes. Commit `5d08572` fixes those paths and adds
local positive/negative regressions to existing component tests. At that commit,
`fn-subsequence` has 105 passed and 2 inapplicable cases; the selected
`expand-text`/`deep-equal` sets have 59 passed, 2 failed and 3 inapplicable cases.
The remaining two failures use relative namespace URIs.

`make check`, `make lint` and race tests for `./transform/...` passed for the
fix. Subsequent commits add declared resources, collections and permutation
assertions (`4070253`), preserve syntax/JSON error semantics and expanded error
QNames (`c675bb0`), and supply invocation parameters before stylesheet compilation
(`5cae7cd`). They include local regressions in existing tests; repository gates
and relevant race tests passed.

Commits `260fb36`, `a2bf8f9` and `d00cab5` correct lexical boundaries,
reserved function grammar, expanded variable scope and static namespace/schema
checks. Commit `903073e` connects standalone `fn:transform` to the bounded XSLT
engine and preserves copied nodes' namespace context. Compared case by case
with the clean `5cae7cd` XPath 3.1 run, 224 formerly failing cases pass and no
formerly passing case fails; skipped and not-applicable counts are unchanged.
The static-parameter dependency regression discovered in this baseline has
subsequently been reproduced in both public APIs and fixed in the shared
compiler, with local positive/negative tests. A later full-suite run is needed
before attributing new aggregate counts to that fix.

For comparison, clean commit `5d08572` recorded 20,391 passed and 1,737 failed
for XPath 3.1, and 4,620 passed and 5,099 failed for XSLT 3.0, with the same
catalog sizes and not-applicable counts. Both library and adapter changes
contribute to the difference. In particular, the adapter now rejects invocation
items it previously ignored, so an aggregate improvement does not imply that
every previously passing case still passes. Compare case identities and reasons
in generated reports outside the repository. Official-suite failures remain
separate from ordinary repository gates. Narrowing selection or relabeling
failures cannot close the gap.
