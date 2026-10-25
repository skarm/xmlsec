# Language suite baseline

Recorded on 2026-10-25 with `go version go1.27.3 darwin/arm64`, `GOMAXPROCS=2`.
Source/module/pin SHA-256:
`17770e1768eb9d334b6fcf7afc80092084d6b8139b4b2dc6e3be3badf5a3318c`.
Reports identify revision `f510bfc`, `library_modified=true`; documentation is
outside this checksum. History belongs in Git. Claims remain restricted to the
selected profiles; finite evidence does not establish broader W3C certification.

## Complete catalogs

All thirteen runs traverse unchanged pinned catalogs, without filters or case
limits, with **zero skips**. Main runs select XSD 1.0, enabled assertions,
public default budgets and a one-second case deadline. Counts below are
**passed / failed / not-applicable**:

- XPath 2.0: **15,219 / 9 / 16,593**.
- XPath 3.0: **19,278 / 20 / 12,523**.
- XPath 3.1: **22,034 / 16 / 9,771**.
- XSLT 2.0: **5,673 / 59 / 8,869**.
- XSLT 3.0: **8,002 / 85 / 6,514**.

Controls retain the complete catalogs and deadline:

- XSD 1.1, XPath 3.1: **22,078 / 16 / 9,727**.
- XSD 1.1, XSLT 3.0: **8,007 / 84 / 6,510**.
- Assertions disabled, XSLT 3.0: **7,991 / 85 / 6,525**.
- Expanded limits, XPath 3.1: **22,037 / 13 / 9,771**.
- Expanded limits, XSLT 3.0: **8,004 / 83 / 6,514**.
- XPath compatibility, 2.0: **0 / 0 / 31,821**.
- XPath compatibility, 3.0: **5 / 0 / 31,816**.
- XPath compatibility, 3.1: **5 / 0 / 31,816**.

QT3 has 31,821 catalog cases and xslt30-test has 14,601. The compatibility flag
selects only explicit catalog dependencies; the 2.0 control has no applicable
cases. Runs with failures or no passing applicable case exit unsuccessfully.
XSD selection changes builtin datatype/regex rules and does not enable validation.
Expanded budgets preserve timeout, depth, operation and size checks.

## Executed evidence

The [register](conformance.json) closes case evidence for **2,228 applicable
records** across the eleven selected XPath/F&O/Basic XSLT/serialization documents.
Structural parents include every applicable immediate child; additional host
composition rules have their own controls. Exact publisher inputs retain their
original full assertions. Independent processor disagreements and unsupported
optional normalization remain diagnostics, not agreements.

The runner stamps each actual test process before and after execution; merging
rejects stale or incomplete streams. The final gate checks exact passing subtests
and oracle/vector markers, replays publisher cases, and binds every remaining
failure to its profile, typed cause and passing causal tests. A new failure cannot
inherit the explanation of another edition or an earlier failure kind.

There are **153 distinct remaining failed cases**: 35 resource limits,
92 fixture/input or edition-contract mismatches, 8 optional-feature cases
and 18 permitted outcomes. All have original-case replays and explicit
countercontrols in the existing tests. The register also retains fixed regressions;
154 causal records cover both the visible backlog and those repairs.

Examples include older-edition date rounding, parameter-schema extraction,
optional warning channels, DTD input construction, unavailable resources and
bounded recursion/regex work. Per-case reasons and exact checks live in the
register. `collection-006` passes in 3.0 but its `XSLT20+` dependency incorrectly
admits a package/reserved-name fixture to 2.0. `output-0308` now passes in both
editions and independently: named principal character maps survive delivery.

## Reproduction

Pins: QT3 `201a6e466940cdfc727f4babfedcde5332b9f578`; xslt30-test
`fddf1cf920087e791f13315d68dfbe874d97dc56`. See the [adapter and complete proof
workflow](language-suites.md), [ready independent engines](testing.md) and
[license/pin file](../build/w3c-suites.json). Checkouts, jars, schemas, event streams
and generated JSON reports remain outside the repository.

The verification runs include module/docs/vet/CGO-free build checks, all native
and race tests including the external consumer, zero-issue lint, every configured
transform comparison group, and the QT3/XSLT causal tests. Schema awareness,
W3C streamability and general XML processor conformance remain separate roles.
