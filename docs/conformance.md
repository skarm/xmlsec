# Normative traceability

## Contents

- [Register structure](#register-structure)
- [Implementation, policy and applicability](#implementation-policy-and-applicability)
- [Evidence and validation](#evidence-and-validation)
- [Current boundaries](#current-boundaries)

[conformance.json](conformance.json) separates capabilities from normative
contracts for all 20 selected profiles. Inventories identify clauses, grammar
productions, datatypes, algorithms, properties, role/binding/message triples and
formal function/operator contracts. Related rules and conditional branches may
share one contract record; this is not a count of individual MUST sentences.
Implementation, local evidence and independent evidence have separate states.
Checking the register establishes consistency, not standards conformance or an
independent security assessment.

## Register structure

Schema version 4 contains four linked inventories:

- `documents` pins a published edition and records errata sources, review state
  and interpretation. Correction items have explicit identifiers, clauses and
  dispositions, with a separate review date. A publisher's draft is not a
  published edition.
- `profiles` selects a standard role and operation modes, links package docs and
  capability IDs. Its `matrix` accounts for every pinned document and selected
  operation, links assessed requirement IDs and identifies remaining clause
  regions with a closure criterion.
  Claims are `restricted`, `target` or `full`. None currently claims full conformance.
- `requirements` preserves the original capability IDs and test-file references.
  One capability entry is not one normative clause.
- `normative_requirements` identifies a document, clause, normative level,
  applicability, implementation, positive/negative tests, independent evidence,
  policy and remaining gap. Statements are short paraphrases; the pinned
  document and applicable adopted corrections control their meaning.

`norm.source` points into the pinned edition; `norm.errata` records its selected
correction IDs. A draft proposal cannot be listed as an adopted correction. The document's
`errata.review` records whether its complete correction inventory was reviewed.
An empty correction list with a pending review does not assert that no errata
exist. The register date identifies this snapshot, not a promise that publisher
material will remain unchanged.

## Implementation, policy and applicability

Implementation states are `implemented`, `limited`, `unimplemented` and
`not-applicable`. Policy separately records whether the default or a separate
compatibility mode enables, requires opt-in, forbids or lacks the capability.
An algorithm can be required to implement and forbidden by application policy.
Policy denial cannot close an implementation gap.

XMLDSig's `LegacyVerificationPolicy` opts into SHA-1 digests and RSA-SHA1/DSA-SHA1
verification; `LegacyHMACPolicy` selects the separate shared-secret model.
Neither permits legacy public-key signature generation or changes the default
policy. They are disabled in FIPS mode. These algorithm policies,
`ModernPolicy`, `ParameterizedPolicy`, `HMACPolicy` and explicit resolvers select
specific features; they do not establish a full standard claim or enable
unimplemented protocol/format profiles.

Applicability includes role, profile, mode and reason. Missing code never makes
a requirement optional or inapplicable. The checker currently accepts role-based
non-applicability only for a role different from the selected profile role.
Future optional-feature conditions need an explicit normative basis before
broadening that rule.

Every partial profile and incomplete obligation needs a gap and closure criterion.
A partial profile also names its `unmapped_clauses` per document; a complete
inventory cannot retain such entries. A document, mode or obligation cannot be
deleted from its matrix without failing the checker. This checks consistency
against the reviewed selection; it cannot discover a clause the reviewer omitted.
A full claim requires a complete clause inventory, reviewed errata, implemented
applicable obligations and closed evidence gaps. Declaring an inventory complete
still requires normative review: software cannot prove every clause was listed.

## Evidence and validation

Run `make docs`. The checker rejects unknown fields, invalid states, duplicate
IDs, unknown document/profile/mode associations, unsupported policy grants and
inconsistent full claims. It also checks every document/mode/matrix association,
rejects foreign normative-source URLs and invented/unselected correction IDs,
and distinguishes OPTIONAL availability from mandatory full-claim duties.
Sources must be HTTPS URLs rooted in the pinned edition. Code, package docs and
fixture paths must be regular files inside the repository.

API references use `package.Symbol` or `package.Type.Member`, with a repository
package path such as `saml/sp.ServiceProvider`. They identify directly declared
exported functions, types, methods or fields. For a type alias, name the public
type itself rather than a member inherited from its target.

Local `tests.status` is `covered`, `partial`, `pending` or `not-applicable`.
`covered` needs positive and negative checks; `partial` needs at least one real
check and an explicit gap; `pending` claims no checks and keeps a closure
criterion. Non-applicable evidence requires a different standard role. Missing
tests are recorded as missing, rather than filled with unrelated round trips.
Neither partial nor pending local evidence permits a full conformance claim.

Evidence names a `_test.go` file and an actual `func TestName(*testing.T)`
declaration. Comments, methods and functions with another testing signature do
not count. The checker inspects source, including tagged interoperability tests;
it does not run them or assess assertions. A table-driven function can contain
both positive and negative cases; the reviewer must check the cited cases.

`covered` interoperability needs checks and independent fixture files. An
internal round trip alone does not qualify. `pending` remains a gap even when
unit tests pass; `not-applicable` needs a reason. Pass rates are not normative
coverage percentages.

Language records additionally carry `evidence`: each obligation names exact
positive/negative subtests, an independent processor or pinned publisher case,
and a source. Published vectors include a literal expected value and its basis.
Publisher bundles contain explicit case names and selected language/XSD editions;
their original complete assertions are replayed. The fixture pin identifies
external material without copying it into the repository. `evidence_from`
requires every structural child, or direct composition controls with a normative
basis; a nearby function's passing test cannot close an unrelated clause.
Informative passages retain their own non-applicable reference role.

`residual_evidence` records each original full-catalog failure's disposition,
cause and exact causal checks. The [executable language gate](language-suites.md#executable-clause-and-failure-evidence)
checks current source/register identities, actual passing events and independent
oracle/vector markers, then joins every failure from all thirteen reports to
these controls. A stale report, skipped witness, unclassified new failure or
processor disagreement recorded as an agreement fails this gate.

## Current boundaries

The profile records are the maintained backlog. In particular:

- The document security parser remains DTD-free. Language XML input separately
  implements bounded nonvalidating DTD processing, including entity expansion,
  default attributes and declared attribute normalization. External resources
  require explicit resolution policy. These features do not establish complete
  XML 1.0 processor conformance.
  Its inventory distinguishes 79 current XML productions, 19 namespace
  productions, named well-formedness/validity constraints and processor prose.
  Validity reporting belongs to the separately identified validating role.
- C14N consumes an already parsed node model. Sparse output may be a fragment;
  the C14N writer does not supply DTD preprocessing. Its input, ordering, node
  rendering, inheritance, base joining and exclusive namespace rules are
  inventoried separately. Non-UCS NFC preprocessing and complete octet-input
  behavior remain implementation/evidence gaps.
- XMLDSig and KeyInfo have complete clause inventories for the selected roles.
  Full XML/LEIRI behavior and additional optional formats retain implementation
  and evidence gaps. Mandatory algorithms have a separate inventory; algorithm
  availability does not grant application use.
- External Manifest/KeyInfo fragments use complete allowlisted resolver URIs.
  The adapter supplies identified octets; external XML selection, redirect/media
  metadata and complete LEIRI processing are not inferred. Explicit base options
  resolve the selected URI-valued `xml:base` contexts. Typed transformed Manifests
  use authenticated derived scopes, without original-node coverage claims.
- XML Encryption implements AES-GCM, explicit legacy CBC/TripleDES, ConcatKDF,
  ECDH-ES and TripleDES key wrap within the
  [documented profiles](compatibility.md#supported-scope). Legacy data ciphers
  and OAEP/SHA-1 require separate explicit permissions. Algorithm availability
  alone does not close the register's normative or independent-evidence gaps.
  RSA PKCS#1 v1.5 remains unsupported and is optional in XML Encryption 1.1.
- Each XPath version and Basic XSLT have clause/function and pinned suite
  inventories. Source-bound reports distinguish implementation defects, resource
  limits, input-model constraints, optional features and permitted or invalid
  fixture outcomes.
  Independent case evidence and causal controls are executed separately from the
  catalog pass-rate report. Schema awareness and W3C streamability are separate roles.
- SAML role duties include encrypted counterparts of plaintext elements handled
  by a mode, including applicable IDs and attributes. Approved Errata 05 is
  selected and linked per base document and role. Mandatory Artifact/SOAP, ECP,
  logout and NameID management, the selected edition's algorithms and complete
  producer identifier lifecycle rules remain implementation gaps. Metadata IOP
  key acceptance is distinct from Conformance's optional well-known-location
  publication/resolution feature; neither is inferred from a callback.
- Closed XAdES and with-time B-T retain their separate validation contracts.
  `NewHistoricalValidator` implements a bounded subset of the published
  EN 319 102-1 V1.4.1 (2024-06) workflow, separately from EN 319 132-1 V1.3.1
  properties. General evidence records, historical countersignature and
  attribute-authority workflows, and remaining indication branches are outside
  this subset; see [trust and evidence](usage.md#keys-trust-and-evidence).

An extension is ready after its normative basis, implementation, positive and
negative tests, independent compatibility where applicable, resource behavior
and documentation agree. Recording an unsupported gap does not implement it.
