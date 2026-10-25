# Normative traceability

[conformance.json](conformance.json) separates capabilities from individual
standard obligations. Its overall clause inventory is partial; the required-algorithm subset is
inventoried separately for generation and verification. Checking the register
establishes consistency, not standards conformance or an independent security
assessment.

## Register structure

Schema version 3 contains four linked inventories:

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
- The selected XMLDSig/KeyInfo stage-4 profile is complete against the acceptance
  list below. The overall XMLDSig clause inventory remains partial, including full
  XML/LEIRI and additional optional formats. Mandatory algorithms have a separate
  complete inventory; implementation availability does not grant application use.
- External Manifest/KeyInfo fragments use complete allowlisted resolver URIs.
  The adapter supplies identified octets; external XML selection, redirect/media
  metadata and complete LEIRI processing are not inferred. Explicit base options
  resolve the selected URI-valued `xml:base` contexts. Typed transformed Manifests
  use authenticated derived scopes, without original-node coverage claims.
- XML Encryption 1.1 section 5.1.1 requires more than AES-GCM: missing CBC,
  TripleDES, ConcatKDF, ECDH-ES and TripleDES wrap obligations remain applicable.
  Legacy OAEP/SHA-1 now has an explicit compatibility option for AES-GCM keys;
  this does not implement transport of unsupported mandatory TripleDES keys.
  RSA-v1.5 is optional in that edition.
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

## Stage 0 acceptance record

The register covers all declared profiles with document, role and operation
matrices. Every assessed requirement retains its normative basis, implementation
API/code, positive/negative evidence, independent-evidence state, default and
compatibility permissions, and remaining gap/closure. Missing mandatory behavior
stays applicable. Unimplemented algorithms and validation workflows are unavailable
rather than described as policy-enabled or outside their required standard role.

Publisher editions and correction inventories were reviewed on 2026-10-22.
W3C draft proposals, RFC verified/held/rejected items, Approved SAML Errata 05 and
published ETSI editions have distinct dispositions. SAML corrections are assigned
to their affected base documents. Selected corrections are linked to assessed
requirements; remaining per-clause and per-role assessment regions stay explicit.
This register work does not implement the open requirements of later stages.

`TestNormativeConformanceChecks`, `TestConformanceEvidenceNamesRealTests` and
`TestConformanceOptionalImplementationAndCorrections` validate missing document,
mode and obligation links, false completeness, invalid evidence, policy grants,
source/edition mismatches, correction IDs and mandatory/optional distinctions.
They extend the existing development-runner test file. `make docs` checks the
actual register together with README, compatibility and package-document links.

The complete **register contract** is separate from complete individual-clause
inventories or full implementation conformance. The latter remain explicitly
partial wherever `unmapped_clauses` is nonempty; no profile is promoted to full
conformance by this stage or by a passing repository gate.

## Stage 2 acceptance record

Subtree imports and XDM element-document extraction share the namespace-context
copy routine behind `tree.ImportSubtree` and `tree.ExtractSubtree`. It preserves
prefixes used only in QName-valued strings. Imports guard an absent/empty default
binding against the destination parent; standalone extraction retains explicit
resets without adding a redundant one. Extracted documents own
their nodes. Source snapshots, sibling bindings and the caller's namespace maps
remain unchanged. `TestImportSubtreeKeepsNamespaceContextAndSnapshots`,
`TestXMLWriterRestoresNamespaceScopes`, `TestCopyNodePreservesNamespaceContext`
and `TestElementDocumentPreservesContextAndOwnership` check these boundaries.

`TestNormativeCanonicalVectors` requires all 138 fixed exact-byte cases across
document, subtree and sparse node-set inputs. Its selectors cover document,
element, text, comment, PI, attribute and namespace nodes. The corpus includes
default namespaces, rebinding and sibling restoration, omitted attributes and
bindings, PrefixList, Unicode ordering, xml:id/lang/space/base and original-order
comments/PIs. Normative processing rules control the result. The unchanged
independent JDK/libxml2 adapters replay the corpus; documented disagreements
remain diagnostics, not successful compatibility evidence. C14N 1.1's compound
base join with fragment removal is transcribed directly from section 2.4 when
both independent paths disagree with that rule.

`TestNormativeCanonicalRejections` checks 24 rejection fixtures through both
byte and one-byte-reader parsing. It separates malformed names/bindings/XML from
unsupported input features and canonicalization options. Existing tests cover
mixed snapshots, invalid handles, cancellation and expanded-node/output budgets.
`TestCanonicalPartialWriterErrors` checks every accepted output prefix, including
UTF-8 and escape boundaries, through all three public writer paths. Errors are
propagated without buffering the entire canonical result.

The input contract remains explicit: UTF-8/UTF-16 XML 1.0, DTD-free snapshots,
absolute nonempty namespace names, normalized XML line ends/literal attribute
whitespace, character references and predefined entities. Declared entities,
DTD defaults/type annotations, external resources and a general XML processor
mode are absent. The writer operates on that retained model; it does not perform
missing XML preprocessing. C14N 1.1 base fix-up still rejects whitespace-bearing
URI references. These input/model restrictions remain recorded separately from
the tested canonical byte rules. No full XML processor profile is claimed.

## Stage 4 acceptance record

The selected extension profile includes bounded external Manifests, existing
KeyInfo forms, approved RetrievalMethod pipelines and URI-valued base contexts.
Completion here concerns this roadmap stage; it is not a full XMLDSig/XML Base
claim. Stage 0 XML processing and stages 2/3 language/canonicalization inventories
retain their own recorded obligations.

- Builder/parser/verifier agreement: existing enveloped/enveloping/detached and
  selected-template APIs, parameterized PSS/HMAC/transform XML, Object content and
  X509Data construction are covered by `TestCoreForms`,
  `TestCoreAlgorithmsAndCanonicalization`, `TestDetachedProgramParameters`,
  `TestParameterizedPSSXML`, `TestHMACTemplateChecksAllReferences` and
  `TestBuildX509DataGroups`.
- Coverage, multiple signatures and local Manifests: `TestCoreDiagnosticsAndWrapping`,
  `TestCoreMultisignaturesAndPreservation`, `TestBuilderAppendAndDuplicateIDs`,
  `TestManifestGraphAndMixedReferences` and `TestManifestDisabledAndBadNestedDigest`
  distinguish required nodes/bytes, signature selection and Manifest contents.
- External graph and retrieval extension: `TestExternalManifestGraph`,
  `TestTransformedManifestSnapshots`, `TestTransformedManifestResultIdentity`,
  `TestRetrievalTransformChains`, `TestKeyInfoURIContexts` and
  `TestXMLDSigStage4IndependentURIContexts` cover independent scopes, exact resolved
  authorization, cycle/depth/graph/byte/node bounds and frozen resource identity.
- Authentication and trust: `TestTransformedManifestAuthenticationAndLimits`,
  `TestExternalManifestAuthenticationOrder`, `TestKeyInfoResourceOrderAndInvalidPreflight`
  and `TestVerifySignatureWithExplicitKeyInfoTrust` check discovery/private-signer
  ordering, valid incoming references with invalid children, diagnostic status and
  an explicit application trust selector. KeyInfo never establishes trust itself.
- Independent evidence: existing JDK/Python/core/keyinfo/parameter corpora, the
  fixed eleven-case stage-4 corpus, `TestXMLSecStage4Vectors`,
  `TestXMLSecRetrievalMethods` and `TestXMLSecX509DataGroups` cover both signature
  directions in the declared intersection and reject negative mutations. The
  installed CLI's bare RSA/EC RetrievalMethod and recursive external Manifest
  boundaries remain explicit diagnostic controls.
- Operational evidence: existing fuzz targets exercise the new valid paths;
  resource-limit, cancellation/reader-close, replay and race tests cover the selected
  operations. `TestStage4CLI` checks every new fixed signature through the CLI.

### Required algorithms and operation modes

The `xmldsig11-algorithms` profile inventories every REQUIRED algorithm in XMLDSig
1.1 section 6.1, with separate generate/verify records. Its complete inventory
refers only to that algorithm set, not all clauses of XMLDSig or its dependencies.
The generation and verification records cover SHA-1/SHA-256 digests,
HMAC-SHA1/HMAC-SHA256, RSA-SHA256, ECDSA-SHA256 on P-256, C14N 1.0/1.1 and Exclusive
C14N without comments, Base64 encoding/transform and Enveloped Signature. DSA-SHA1
has the required verification record; its generation is OPTIONAL and disabled.
KeyValue's RSA/DSA/named-P-256 descriptions are tracked separately in the broader
KeyInfo profile. RSA-SHA1 verification, comment-preserving C14N and approved
XPath/Filter2 are available beyond this required subset; XSLT is an explicitly
selected optional transform profile.

Default signing/acceptance remains RSA/ECDSA SHA-2. HMAC uses its separate secret
model. SHA-1 digest/HMAC and DSA/RSA-SHA1 verification require explicit compatibility
policies and are disabled in FIPS mode. Stronger key/tag/resource bounds restrict
accepted use without reclassifying mandatory algorithm availability as optional.
PGP/SPKI/MgmtData, arbitrary explicit EC parameters and DSA-SHA256 are optional
extensions not selected for this stage. Missing mandatory processing obligations
of the broader standard stay recorded; policy restrictions do not close them.
