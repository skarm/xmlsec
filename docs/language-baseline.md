# Language validation profiles


The language gate checks complete pinned QT3 and xslt30-test catalogs under
thirteen configurations. [w3c-suites.json](../build/w3c-suites.json) defines the
publisher revisions. The [suite runner](language-suites.md) describes installation,
execution and source-bound report capture.

## Catalog profiles

The five primary configurations select XSD 1.0, enabled XSLT assertions, public
default budgets and a one-second per-case deadline:

- QT3 with XPath 2.0.
- QT3 with XPath 3.0.
- QT3 with XPath 3.1.
- xslt30-test with XSLT 2.0.
- xslt30-test with XSLT 3.0.

Run complete catalogs without set or case filters and without a case-count limit.
An unsupported mandatory feature remains a failure rather than a skip.
Schema awareness and W3C streamability are separate unsupported roles.

## Required controls

Eight additional configurations exercise independent host choices while retaining
the complete catalogs and per-case deadline:

- XPath 3.1 with XSD 1.1.
- XSLT 3.0 with XSD 1.1.
- XSLT 3.0 with assertions disabled.
- XPath 3.1 with the expanded language budgets.
- XSLT 3.0 with the expanded language budgets.
- XPath 2.0 with XPath 1.0 compatibility enabled.
- XPath 3.0 with XPath 1.0 compatibility enabled.
- XPath 3.1 with XPath 1.0 compatibility enabled.

Datatype selection changes built-in lexical and regex rules; it does not enable
schema validation. Expanded budgets retain deadline, depth and work checks.
Compatibility runs select only explicit matching catalog dependencies; a
configuration with no passing applicable case exits unsuccessfully.

## Results and evidence

Generate reports from the source being assessed. Reports bind outcomes to source,
module, catalog and configuration identities. Do not reuse counts from another
source revision or treat pass rates as normative coverage percentages.

The [normative register](conformance.json) names obligations, exact positive and
negative controls, publisher cases and independent evidence. Its executable gate
requires every applicable structural child or an explicit composition check.
Processor disagreements remain diagnostics rather than independent agreements.

Each failed case keeps its original assertion, selected profile, failure kind,
reason and causal controls. Missing implementation, resource limits, unavailable
inputs and permitted standard outcomes remain distinct. Stale reports, skipped
witnesses and unclassified failures cannot close evidence.

Keep publisher checkouts, jars, schemas, event streams and generated JSON reports
outside the repository. See [capture and validation commands](language-suites.md#executable-clause-and-failure-evidence)
and [independent engines](testing.md#independent-engines).
