# XPath and XSLT suite diagnostics

The development runner reads unmodified official [QT3](https://github.com/w3c/qt3tests)
and [xslt30-test](https://github.com/w3c/xslt30-test) checkouts, pinned in
[w3c-suites.json](../build/w3c-suites.json). It downloads nothing. HEAD must match
the pin, and tracked/untracked changes are rejected before and after execution.

These diagnostics record implementation, harness and resource failures. A passing
selection is not complete conformance; [language-baseline](language-baseline.md)
defines the thirteen full-catalog configurations.

## Inputs and licenses

Clone complete repositories outside this checkout and select the pinned revisions.
Retain publisher/contributor and file-specific notices; the pin's license URL does
not replace those notices. Upstream test files are not redistributed here.

The adapter needs Git, the repository Go toolchain and existing module dependencies.
Assertions use the public engine under test, so the adapter is not an independent
oracle for every assertion primitive.

## Run a selection

```sh
go run ./tests/cmd/dev suites -suite=qt3 -dir=/absolute/path/to/qt3tests \
  -version=3.1 -sets='^fn-subsequence$' -report=/tmp/qt3.json
go run ./tests/cmd/dev suites -suite=xslt30 -dir=/absolute/path/to/xslt30-test \
  -version=3.0 -sets='^(expand-text|deep-equal)$' -report=/tmp/xslt.json
```

QT3 versions are 2.0/3.0/3.1; XSLT versions are 2.0/3.0. `-sets` and `-match`
are regular expressions. Omit filters and leave `-limit=0` for complete catalogs.
The default per-case deadline is `-timeout=1s`.

`-xsd-version=1.0|1.1` selects datatype/regex rules; suite default is 1.0.
`-xpath10-compatibility` selects explicitly matching QT3 dependencies; XSLT uses
stylesheet-local modes. `-assertions` enables direct XSLT assertions, default off.
Nested `fn:transform` retains its own assertion option.

`-limits=default` uses public budgets. `-limits=language` expands input/resource
reads to 32 MiB, aggregate resource/output budgets to 64 MiB, programs to 1 MiB,
nodes to two million and work to fifty million operations. Other bounds and
the case deadline remain in force. This does not change library defaults.

Reports are written before nonzero exit on applicable failures. No passing
applicable case also means failure. Outcomes are:

- `passed`: the original assertion accepted the result or expected standard error.
- `failed`: assertion, implementation, limit, panic, dependency or harness failure;
  `kind` and `reason` identify the cause.
- `skipped`: excluded by explicit filters or case-count limits.
- `not-applicable`: a known dependency excludes the selected profile.

Missing mandatory implementation and unknown dependencies remain failures.
Schema awareness, W3C streaming, XQuery and XML 1.1 are outside this profile.
Unicode dependencies require an exact edition. A resource deadline cannot satisfy
an expected language error; unsupported assertions cannot pass through negation.

## Deterministic environment and boundaries

The default clock is `2026-01-01T00:00:00Z`; `-current-time` selects another fixed
RFC 3339 instant. Timezone is UTC, language English and default collation codepoint.
Reports record pins, source/executable hashes, platform, versions and settings.
Source changes during execution invalidate the run.

Only declared resources and local paths confined to the suite checkout can be
read. Traversal and escaping symlinks fail. There is no network fallback or
result-document filesystem writer. Catalog/file URI references honor percent
encoding and inherited `xml:base`; resource identity is tracked separately.
Original publisher octets/assertions are retained, including encoding declarations.

The adapter supports scoped environments, typed parameters, sources, collections,
package/module declarations and initial XSLT calls. Unsupported preprocessing,
validation, metadata or assertions retain explicit outcomes. Add a component
regression for each confirmed engine defect; do not rewrite publisher fixtures
or treat pass rates as normative coverage.

## Executable clause and failure evidence

The [register](conformance.md) links obligations to exact publisher cases, positive/
negative subtests, independent processors/vectors and causal controls. The final
gate combines current test captures with all thirteen full-catalog reports.

Prepare both Saxon classpaths, `SERIALIZATION_SCHEMA_DIR`, `JSON_SCHEMA_FILE`,
`XMLSEC_QT3_DIR` and `XMLSEC_XSLT_DIR`; see [independent engines](testing.md#independent-engines).
`XMLSEC_REQUIRE_P3_PROOFS=1` makes missing required inputs fail.
Serialization schemas come from the W3C
[3.0](https://www.w3.org/TR/2014/REC-xslt-xquery-serialization-30-20140408/#serparams-schema)
and [3.1](https://www.w3.org/TR/2017/REC-xslt-xquery-serialization-31-20170321/#serparams-schema)
Recommendations, with SHA-256 pins
`1cbcc49ac5ed8942ba58276699254469ca2144e229f68faeeb48f784c1037953` and
`256736a2f4e7923e888047dee757c17bc3ee707e285f00639fd8fb1d962d11b0`.
The [XSLT 3.0 JSON schema](https://www.w3.org/TR/2017/REC-xslt-30-20170608/#schema-for-json)
pin is `3ba9d28cc77ac0ba876a7e3dd88308381c4e32334ea412b17961968a37ba6f9d`.

Keep inputs and generated captures/reports outside Git. Sources and register must
stay fixed across baseline runs and captures. Docker mounts need the checkout's
Git metadata and prepared inputs, with networking disabled.

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

`proof capture` records actual process events, exit status and source/register
hashes before/after execution. `proof merge` validates each capture without
restamping it. Ordinary `go test -json` files or manually stamped envelopes are
not accepted. Supply all report paths using the platform path-list separator
(`:` on Unix); the command above abbreviates the thirteen-path list.

The gate rejects stale/mixed revisions, skipped witnesses, changed suite pins,
unclassified failures and diagnostics mislabeled as independent agreement.
It replays original assertions before causal counterfactuals. Captures prevent
accidental reuse; they do not authenticate deliberately edited artifacts.
