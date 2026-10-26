# Normative traceability

[conformance.json](conformance.json) is a development register linking standards
requirements to implementation and evidence. It is read by `make docs`, language
proof capture and the [language validation gate](language-suites.md#executable-clause-and-failure-evidence).
It is not runtime configuration and application users do not need to read it.

## Register structure

- `documents`: selected standard editions, sources and reviewed errata.
- `profiles`: roles, operation modes and their requirement matrix.
- `requirements`: supported capabilities and their test files.
- `normative_requirements`: individual contracts, applicability, implementation,
  positive/negative tests, independent evidence, policy and remaining gaps.
- `residual_evidence`: reviewed explanations and causal checks for remaining
  publisher-suite failures.

Capability counts and suite pass rates are not percentages of standards coverage.
The pinned standard and adopted corrections control the meaning of each contract.

## Implementation, policy and applicability

Implementation, policy and evidence are separate states. An implemented algorithm
may be forbidden by default; denying it does not close an implementation gap.
Missing code does not make a mandatory requirement inapplicable.

Incomplete profiles retain their gaps and closure criteria. A full claim needs a
complete reviewed inventory, implemented applicable requirements and sufficient
local and independent evidence. No profile currently claims full conformance.

## Evidence and validation

```sh
make docs
```

The checker validates schema, IDs, states, document/profile/mode associations,
source editions, errata, policy and matrix consistency. Referenced code, fixtures,
exported APIs and test functions must exist inside the repository.

Local coverage names real Go tests, including positive and negative cases.
Independent coverage needs external fixtures or a declared processor/publisher
case; an internal round trip alone is insufficient. The static checker does not
run those tests or assess the quality of their assertions.

Language proofs additionally bind reports and exact passing subtests to current
source/register hashes. The executable gate rejects stale captures, skipped
witnesses and unclassified failures. See the [capture commands](language-suites.md#executable-clause-and-failure-evidence).

## Current boundaries

Supported profiles and exclusions live in [compatibility](compatibility.md),
primary sources in [standards](standards.md), and full-catalog configurations in
[language-baseline](language-baseline.md). The JSON register retains the detailed
backlog. A consistent register does not establish complete conformance or an
independent security audit.
