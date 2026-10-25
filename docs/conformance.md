# Normative traceability

[conformance.json](conformance.json) separates capabilities from individual
standard obligations. Its clause inventory is partial. Checking the register
establishes consistency, not standards conformance or an independent security
assessment.

## Register structure

Schema version 2 contains four linked inventories:

- `documents` pins a published edition and records errata sources, review state
  and interpretation. A publisher's draft is not a published edition.
- `profiles` selects a standard role and operation modes, links package docs and
  capability IDs, and records the remaining inventory gap and closure criterion.
  Claims are `restricted`, `target` or `full`. None currently claims full conformance.
- `requirements` preserves the original capability IDs and test-file references.
  One capability entry is not one normative clause.
- `normative_requirements` identifies a document, clause, normative level,
  applicability, implementation, positive/negative tests, independent evidence,
  policy and remaining gap. Statements are short paraphrases; the pinned
  document and applicable adopted corrections control their meaning.

`norm.errata` records the corrections selected for an entry. The document's
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

No general legacy compatibility policy currently exists. `ModernPolicy`,
`ParameterizedPolicy`, `HMACPolicy` and explicit resolvers select existing
features; they do not add missing algorithms or establish a full standard claim.

Applicability includes role, profile, mode and reason. Missing code never makes
a requirement optional or inapplicable. The checker currently accepts role-based
non-applicability only for a role different from the selected profile role.
Future optional-feature conditions need an explicit normative basis before
broadening that rule.

Every partial profile and incomplete obligation needs a gap and closure criterion.
A full claim requires a complete clause inventory, reviewed errata, implemented
applicable obligations and closed evidence gaps. Declaring an inventory complete
still requires normative review: software cannot prove every clause was listed.

## Evidence and validation

Run `make docs`. The checker rejects unknown fields, invalid states, duplicate
IDs, unknown document/profile/mode associations, unsupported policy grants and
inconsistent full claims. Sources must be HTTPS URLs. Code, package docs and
fixture paths must be regular files inside the repository.

API references use `package.Symbol` or `package.Type.Member`, with a repository
package path such as `saml/sp.ServiceProvider`. They identify directly declared
exported functions, types, methods or fields. For a type alias, name the public
type itself rather than a member inherited from its target.

Evidence names a `_test.go` file and an actual `func TestName(*testing.T)`
declaration. Comments, methods and functions with another testing signature do
not count. The checker inspects source, including tagged interoperability tests;
it does not run them or assess assertions. A table-driven function can contain
both positive and negative cases; the reviewer must check the cited cases.

`covered` interoperability needs checks and independent fixture files. An
internal round trip alone does not qualify. `pending` remains a gap even when
unit tests pass; `not-applicable` needs a reason. Pass rates are not normative
coverage percentages.

## Current boundaries

The profile records are the maintained backlog. In particular:

- The DTD-free parser is not a complete XML 1.0 processor. A future general
  mode must implement applicable DTD/entity/default/normalization rules through
  explicit bounded resource resolution; the default security mode stays separate.
- C14N consumes an already parsed node model. Sparse output may be a fragment;
  the C14N writer does not supply DTD preprocessing.
- XMLDSig 1.1 requires SHA-1 digest/HMAC and DSA-SHA1 verification support for
  a full implementation claim. Their exclusion from ordinary policy does not
  close these implementation gaps. Generation and verification duties differ.
- XML Encryption 1.1 section 5.1.1 requires more than AES-GCM: missing CBC,
  TripleDES, legacy OAEP, ConcatKDF, ECDH-ES, wrap and digest obligations remain
  applicable. RSA-v1.5 is optional in that edition.
- Each XPath version and Basic XSLT need a complete applicable clause/suite
  inventory. Schema awareness and W3C streamability are separate features.
- SAML role duties include encrypted counterparts of plaintext elements handled
  by a mode, including applicable IDs and attributes. Approved Errata 05 is
  selected; a complete role/binding correction matrix remains open.
- Closed XAdES and with-time B-T do not implement the historical AdES workflow.
  The future process baseline is published EN 319 102-1 V1.4.1 (2024-06),
  separately from EN 319 132-1 V1.3.1 properties.

An extension is ready after its normative basis, implementation, positive and
negative tests, independent compatibility where applicable, resource behavior
and documentation agree. Recording an unsupported gap does not implement it.
