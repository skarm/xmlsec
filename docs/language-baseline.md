# Language validation profiles

The language gate checks complete pinned QT3 and xslt30-test catalogs under
thirteen configurations. [w3c-suites.json](../build/w3c-suites.json) pins publisher
revisions; [language-suites](language-suites.md) gives commands and prerequisites.

## Catalog profiles

The five primary runs use XSD 1.0, enabled XSLT assertions, default engine budgets
and a one-second per-case deadline:

- QT3 with XPath 2.0, 3.0 and 3.1.
- xslt30-test with XSLT 2.0 and 3.0.

Run complete catalogs without filters or a case-count limit. Unsupported
mandatory behavior remains a failure; schema awareness and W3C streamability
are separate unsupported roles.

## Required controls

Eight additional full-catalog runs select:

- XPath 3.1 and XSLT 3.0 with XSD 1.1: two runs.
- XSLT 3.0 with assertions disabled: one run.
- XPath 3.1 and XSLT 3.0 with expanded language budgets: two runs.
- XPath 2.0, 3.0 and 3.1 with XPath 1.0 compatibility: three runs.

Datatype editions do not enable schema validation. Expanded budgets retain
bounded work/depth and the per-case deadline. Compatibility runs select explicit
matching catalog dependencies. The standalone suite command exits nonzero when
no applicable case passes.

## Local XPath 2.0 compatibility check

Run `go test -count=1 -v ./tests/cmd/dev -run '^TestLocalXPath20Compatibility$'`
to exercise XPath 2.0 with the XPath 1.0 compatibility property enabled and
disabled using project-owned cases. The pinned QT3 catalog has no applicable
case for this profile: its explicit compatibility cases require XPath 3.0
through a test-set or case dependency. The complete XPath 2.0 compatibility
report still records every publisher outcome. The language gate accepts this
empty profile only after checking the pinned catalog's applicability and
confirming that both current local controls passed. Other profiles require a
passing publisher case.

## Results and evidence

Reports bind outcomes to source, catalog and configuration identities. The
[normative register](conformance.md) separately links obligations to exact tests,
publisher cases and independent evidence. Preserve original failed assertions
and classify their causes; pass rates do not measure normative coverage.

The [executable gate](language-suites.md#executable-clause-and-failure-evidence)
rejects stale reports, skipped witnesses and unclassified failures. Keep external
inputs and generated reports outside Git.
