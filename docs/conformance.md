# Normative traceability

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

## Current boundaries

The profile records are the maintained backlog. In particular:

- The DTD-free parser is not a complete XML 1.0 processor. A future general
  mode must implement applicable DTD/entity/default/normalization rules through
  explicit bounded resource resolution; the default security mode stays separate.
  Its inventory distinguishes 79 current XML productions, 19 namespace
  productions, named well-formedness/validity constraints and processor prose.
  Validity reporting belongs to the separately identified validating role.
- C14N consumes an already parsed node model. Sparse output may be a fragment;
  the C14N writer does not supply DTD preprocessing. Its input, ordering, node
  rendering, inheritance, base joining and exclusive namespace rules are
  inventoried separately. Non-UCS NFC preprocessing and complete octet-input
  behavior remain implementation/evidence gaps.
- The selected XMLDSig/KeyInfo stage-4 profile is complete against the acceptance
  list below. Its complete clause inventory retains gaps for full XML/LEIRI and
  additional optional formats. Mandatory algorithms have a separate inventory; implementation availability does not grant application use.
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
- Each XPath version and Basic XSLT have clause/function and pinned suite
  inventories. Applicable language failures and incomplete independent clause
  evidence remain open. Schema awareness and W3C streamability are separate roles.
- SAML role duties include encrypted counterparts of plaintext elements handled
  by a mode, including applicable IDs and attributes. Approved Errata 05 is
  selected and linked per base document and role. Mandatory Artifact/SOAP, ECP,
  logout and NameID management, the selected edition's algorithms and complete
  producer identifier lifecycle rules remain implementation gaps. Metadata IOP
  key acceptance is distinct from Conformance's optional well-known-location
  publication/resolution feature; neither is inferred from a callback.
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
requirements; each selected correction has a normative trace, including explicit other-role
dispositions. Corrected ASN.1 definitions and bibliographic/editorial changes
remain distinct from newly implemented wire behavior.
This register work does not implement the open requirements of later stages.

The 2026-10-23 XML/Namespaces and C14N review separates processor, validating,
document-author and application duties. The historical XML appendix-B name
classes and namespace orphan productions do not replace the current grammar.
Complete inventories retain gaps for DTD processing, legal 1.x declarations,
relative namespace acceptance, transport encoding and C14N preprocessing.

`TestNormativeConformanceChecks`, `TestConformanceEvidenceNamesRealTests` and
`TestConformanceOptionalImplementationAndCorrections` validate missing document,
mode and obligation links, false completeness, invalid evidence, policy grants,
source/edition mismatches, correction IDs and mandatory/optional distinctions.
They extend the existing development-runner test file. `make docs` checks the
actual register together with README, compatibility and package-document links.

All selected profile matrices now have named clause/contract inventories. Their
implementation, format/input, policy and evidence gaps remain visible at those
contracts. This granularity groups related requirements, including a function's
signature, rules and errors, or a property's syntax and byte binding. A complete
inventory does not mean that each grouped rule has implementation or test
coverage; those states must be assessed before a full claim. No profile is
promoted to full conformance by this stage or a passing repository gate.

The key/CMS/PKI/timestamp records distinguish parsing, generation and verification,
including required legacy algorithms, absent BER/container alternatives,
revocation forms and complete TSA service duties. XAdES property availability is
separate from EN 319 102-1 creation and validation processes. The historical
workflow remains unimplemented. SAML records retain full SP/IdP mandatory duties
even though the public API implements a solicited WebSSO subset. Selected XSD
lexical/value contracts do not establish schema validation or PSVI support.

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

## Stage 3 diagnostic acceptance record

Pinned, unmodified QT3 and xslt30-test catalogs are exercised through the public
APIs for XPath 2.0/3.0/3.1 and XSLT 2.0/3.0 selections. The full-catalog
[baseline](language-baseline.md) records pass/fail/skip/not-applicable counts,
failure causes, limits and the remaining work in the roadmap's six language
areas. An explicit larger-budget sample distinguishes resource boundaries from
encoding and language behavior. Its filtered results are kept separate from
the unfiltered default runs. No mandatory failure is removed from the backlog.

Reports identify the suite revision, executable and Go-source digests, dynamic
context, selected limits and each compiled case's actual language version.
Source changes and modified suite checkouts invalidate a run. The
[adapter contract](language-suites.md) covers scoped namespaces and decimal
formats, reference-selected environments, declared resources/collections/packages,
invocation parameters and entry points, logical outputs and secondary/message
assertions. The compiler and suite adapter share the package-version range parser.

`TestXSLTExplicitGlobalContext` compares direct invocation and `fn:transform`:
the initial named template uses the global singleton focus independently of the
match selection and rejects absent/incorrectly typed required contexts.
`TestDecimalFormatUnicodeDigitsAcrossPaths` and
`TestDecimalFormatEmptyStringProperties` cover Unicode zero digits and explicit
empty NaN/infinity strings; conflicting declarations fail. Their narrow normative
records do not promote the complete formatting or processor inventory to complete.
`TestSuiteStaticContextsAndReferences`, `TestSuiteStylesheetVersionDeclarations`,
`TestSuiteExplicitBudgets` and `TestSuiteXSLTInvocationsAndResults` extend the
existing adapter test file, including negative controls.

Repository checks, lint, relevant race checks and Docker libxml2/libxslt
comparisons pass. The existing comparison file also runs 137 Saxon HE 12.10 query agreements and
two original-octet XML transformations. Known diagnostic differences
remain separate from exact agreements; complete independent clause fixtures remain pending.
Basic XSLT, complete XPath conformance, additional XML input encodings/schema
processing and unimplemented assertion forms retain explicit gaps. Schema awareness and normative streamability remain separate directions.

The resource closure block preserves resource MIME/charset metadata end to end,
including HTTP and nested transforms. Its bounded decoding contract is checked
by `TestTextResourceMediaType`, `TestXSLTTextResourceMediaType` and
`TestHTTPTextMetadataAndDecodedLimit`. Calendar/duration representability and
lexical errors are distinguished, formatter overloads and function conversion
are enforced, and quantified anchors retain bounded zero-width matching.
`TestCompareSaxonLanguageSemantics` replays 101 fixed queries with ready Saxon HE
12.10 binaries. `TestCompareSaxonAssertionPolicies` adds eight enabled/disabled
assertion and QName comparisons; `TestCompareSaxonBasicProfile` adds eleven
Basic and simple-content comparisons. They do not supply complete clause fixtures. Edition-specific regex differences have local controls; complete independent edition-specific fixtures remain pending.

The explicit assertion switch defaults off; the comparable enabled baseline opts
in. Named, inline, lookup and partial function values retain datatype and
compatibility context. Package versions keep distinct retrieval URIs. Basic
schema-only constructs use prescribed static errors, while lax/preserve act as
strip. Streaming annotations execute with materialized trees and enforce
accumulator applicability, without a streamability claim. AVTs and simple
content preserve expanded errors and follow text normalization before array
atomization. Shared budgets bound their work and strings; singleton text retains
immutable storage. Assertion namespace scopes are inherited and isolated.
The next component checks declaration-site QName names, static named-template
binding after imports, duplicate-name conflicts after precedence resolution and
prescribed circularity/context/mode errors. `TestXSLTDeclarationContracts` and
`TestXSLTModuleCyclesAndPrecedence` supply local positive/negative cases. Saxon
adds twelve exact declaration comparisons and five exact module comparisons;
one mixed-cycle code choice and two multi-diagnostic placements are recorded
separately. These tests close their stated regressions, not all outstanding Basic duties.

Raw result delivery now preserves mixed item order/types and node identity for
primary and secondary values. Explicit document construction and effective
`build-tree` defaults use shared sequence normalization, including separators,
arrays, empty results, copied nodes and prescribed rejection errors. The suite
runner selects this final-tree mode directly. Per-call `fn:transform` assertions
use their own typed option, default false. Local tests cover each mode and
shared budget/cancellation boundaries; independent comparisons and build-tree
diagnostics remain separate. Complete Basic duties remain open.

Package exposure now chooses the most specific applicable rule, preserving
declared visibility against wildcards and excluding components accepted from
other packages and parameters. Component syntax/arity and namespace scope have local tests.
Root shadow processing precedes package identity checks, preserves prescribed
expression errors and keeps `document('')` source trees unchanged. Basic schema
resource declarations reach actual compiler errors without pretending to validate
sources. Function NameTests under REC 2017 versus E36 and the conflicting initial
mode wording are explicit edition/interpretation records, not adopted errata claims.

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

The datatype/compatibility closure block uses explicit XSD 1.0/1.1 lexical and
regex selection across constructors, numeric promotion, function values and XSLT.
Recurring numeric/duration division and averages now produce finite decimals;
tiny nonzero quotients retain significant digits. Higher/future XSLT declarations
exercise fallback and deferred errors, static function name/arity checks run after
all declarations, and serialization versions do not change language semantics.
`fn:transform` uses the 3.0 processor for supported minimums and reports actual
capabilities. Unicode 17.0 block data includes historical aliases with XSD name
syntax. Collection/document identities and stable results are tested through
direct XPath, XSLT and nested transforms, including whitespace stripping and
conflicting-URI failures. Existing test files contain all new regressions.
The refreshed full-catalog baseline separates new passes from corrected exact
Unicode-edition dependencies and retains mandatory failures as failures.
