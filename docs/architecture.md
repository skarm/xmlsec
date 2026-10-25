# Package architecture review

Reviewed on 2026-10-25 against `3eb1ede`. This is a structural review and
behavior-preserving refactor, not a new standards-conformance baseline or a
security certification. Existing W3C failures and incomplete XAdES historical
processing are not closed by these changes.

## Scope and assessment

This repository is a library with one public module, one optional CLI and a
separate external-consumer test module. `golang.org/x/text` is its only direct
module dependency. There is no application service/container layer to introduce.
The library exposes 22 public packages; the module root intentionally has no Go
package. Public package paths remain unchanged.

The review covered the complete local package/import graph, public declarations,
resource and trust configuration, concrete call paths, interfaces, test-package
boundaries, examples, build tags, CI and Docker verification. The package
inventory excludes commands, examples and the `tests` directory when comparing
library/internal packages: 62 before, 59 after. This includes internal test
helpers; it is not a count of packages reachable by every application.

The existing feature-oriented layout is appropriate. XML snapshots, signature
formats, certificate policy and SAML workflows have distinct responsibilities.
The confirmed problems were internal duplication, unused implementation,
duplicated transport configuration and inconsistent vocabulary ownership.

## Main subsystem boundaries

- `document` exposes immutable handles backed by `internal/tree`; `c14n` supplies
  a separate canonicalization API over those handles. The small public facades
  preserve the shared snapshot model and deliberately hide mutation primitives.
- `reference` executes bounded transform programs. `internal/transformxml`
  parses their XML representation for signature/property consumers.
- `xmldsig` authenticates signatures and references. `keyinfo` handles untrusted
  key descriptions; `keys` handles binary/key-container encodings. Parsing a key
  description and deciding certificate trust are separate operations.
- `xmlenc` owns encryption policy and key relationships. Shared cryptographic
  identifiers do not combine its policy with XMLDSig policy.
- `cms`, `timestamp`, `pki` and `xades` compose format authentication, timestamp
  binding, certificate/evidence policy and XML signature properties. The
  historical workflow uses exact-byte inputs from format adapters.
- `evidence` owns untrusted observations. `evidence/collect` is its optional HTTP
  adapter; keeping it a subpackage prevents offline evidence users from depending
  directly on its collector implementation. `resource` owns general explicit
  resource adapters used by transform/encryption consumers.
- `transform` is the public XPath/XSLT boundary. Its internal XDM, pattern,
  XPath and XSLT implementations have shared node/type and compiler state;
  further splitting requires more than moving files.
- `saml/{binding,metadata,protocol,sp,idp,state,replay}` separates wire bindings,
  metadata, protocol validation, orchestration and atomic stores. The shared
  internal expiry queue is used by both stores; their acceptance contracts differ.
- `cmd/xmlsec` owns flags, local I/O and publication. Examples and development
  commands compose library APIs. Test helpers have no production consumers.

## Confirmed findings and changes

1. **Medium — duplicated XPath AST traversal.**
   `transform/internal/xslt/internal/stream/xpathstream.go` copied the traversal
   already maintained in `xpath/streamability.go`; XSLT had to know a second
   package to inspect XPath nodes. XSLT now calls `xpath.WalkExpr`. The existing
   XPath traversal retains support for lowered VM nodes, and the two visitor
   tests moved into the existing XPath runtime tests. Unused query wrappers
   were deleted. Risk: traversal order or pruning changes; the existing visitor,
   pattern and language tests check the affected behavior. **Fixed.**

2. **Medium — misplaced XSLT metadata and unused duplicate grammar.**
   `xslt/internal/elements` served only XSLT, exported its private metadata and
   constructed attribute maps/parent lists that the production compiler never
   consumed. The metadata is now private in `xslt/element_info*.go`, retaining
   version, context and implementation facts. The unused duplicate attribute and
   parent definitions were removed; `grammar.go` and actual child validators
   retain their existing rules. Context tests moved into the existing
   `package_version_test.go`; the obsolete mutable-metadata API test was removed.
   Risk: mixing metadata with validation; this refactor leaves validation rules
   unchanged and verifies compilation/introspection behavior. **Fixed.**

3. **Low — unused integer conversion package.**
   `xdm/intconv` had no caller except its own tests, including no build-tag or
   consumer-module caller. Both its implementation and orphan tests were
   removed. No replacement package or wrapper was introduced. Risk: a missed
   internal caller; repository search, package listing and compilation check it.
   **Fixed.**

4. **Medium — mixed vocabulary and processor responsibilities.**
   `internal/lexicon` contained XPath-specific function-name analysis in
   addition to constants, while consumers repeated serialization parameter
   names and XMLDSig element names. XPath spelling analysis now lives privately
   in XPath; its test moved into existing runtime tests. The vocabulary package
   has no imports or runtime functions. XMLDSig local names and SAML endpoint
   names are shared there; serialization readers use the existing parameter
   constants. Public metadata service constants allow callers to select
   `role.Endpoints(metadata.SingleSignOnService)` without a magic string.
   Risk: conflating equal spellings from different protocols; XMLDSig element
   names remain distinct from SAML Redirect query fields. Test expected XML and
   protocol values remain independent literals. **Fixed.**

5. **Medium — repeated untyped proof roles.**
   The format adapter, workflow graph and PKI time-sliding code passed role
   strings and maintained duplicate accepted-role checks. `historicalproof.Kind`
   now owns the seven role constants and their closed-set validation. Exact
   roles flow through the adapter, graph and proof lookup; public diagnostic
   reports still expose their existing strings. Untrusted `evidence.Kind` and
   authenticated PKI evidence types remain separate contracts. Risk: changing
   a role binding or allowing an unknown role; existing historical acceptance,
   rejection and ownership tests retain those checks. **Fixed.**

6. **Medium — unused HTTP transport configuration in language processors.**
   Internal XPath/XSLT setters, invocation state and two HTTP loaders duplicated
   the public resource-adapter path. No public caller or tagged test configured
   those internal clients; public transforms use resolvers. The unused client
   path was removed. Processors retain URI/decoding/read-budget policy; HTTP
   request handling remains in `resource.HTTPResolver`. Among library packages,
   direct `net/http` imports now belong only to `resource` and `evidence/collect`.
   This does not assert that HTTP is absent from transitive dependencies.
   Risk: losing resource policy, content-type information or cancellation in a
   nested transform; resource and independent transform checks cover these.
   **Fixed.**

7. **Low — Docker proof capture assumed a primary Git checkout.**
   A worktree's `.git` file points outside the source mount, so DSS proof capture
   could not inspect its source identity. `build/dss.sh` now mounts common Git
   metadata read-only for worktrees. It retains the same offline Docker and
   explicit fixture-trust boundaries. Risk: incorrect Git path resolution;
   shell checks and a real worktree-based DSS run verify it. **Fixed.**

8. **Medium — stale independent archive-input computation.**
   The complete interoperability run exposed two failing test groups already
   reproducible on the unchanged `3eb1ede`. The helper in
   `tests/interop/evidence_test.go` canonicalized SignedInfo using the signature
   method instead of the archive method required by EN 319 132-1 5.5.2.3. The
   helper now uses the archive method consistently. It still obtains canonical
   bytes from independent libxml2 and checks RFC3161 bindings with OpenSSL;
   production archive code is not used to supply its expected input. Risk:
   weakening an oracle to match production; baseline failures, independent
   positive/reverse exchanges and existing wrong-imprint controls distinguish
   this correction. No production rule or fixture was changed. **Fixed.**

## Structure before and after

Relevant former structure:

```text
internal/lexicon/fn{,_test}.go
transform/internal/
  xdm/intconv/{intconv.go,intconv_test.go}
  xpath/{streamability.go,runtime_test.go}
  xslt/internal/
    elements/{elements.go,data.go,shared_constants.go,elements_test.go}
    stream/{xpathstream.go,xpathstream_test.go}
```

Current structure:

```text
internal/
  lexicon/                     # shared immutable vocabulary
  historicalproof/proof.go     # proof facts, Kind and validation
transform/internal/
  xpath/{streamability.go,runtime_test.go} # traversal and lexical analysis
  xslt/
    element_info.go
    element_info_data.go
    package_version_test.go    # existing file, includes metadata tests
```

Three private packages were removed. No public package was moved, no compatibility
wrapper was needed, and no test file or third-party dependency was added.
The XSLT-to-stream-to-XPath detour and XSLT-to-elements imports disappeared.
The XAdES adapter now explicitly imports the shared vocabulary and proof-role
contract; reducing every import count is not a goal in itself.

## Packages retained and migration alternatives

- Merging `document` and `c14n`, `keys` and `keyinfo`, or CMS/timestamp/XAdES
  would change public import paths and join independent contracts. Keeping
  forwarding compatibility packages would add wrappers rather than simplify
  the library. No such migration is justified by the reviewed call paths.
- Moving public packages beneath `internal` would break the external consumer.
  Existing nested public SAML packages already express useful feature ownership.
- `historicalproof` must remain independent of `historical`: PKI consumes proof
  facts, while the workflow depends on PKI. Merging them would create an import
  cycle or require exposing a new trust-construction interface.
- `internal/{ber,der,x509cert,x509crl,x509name,signature,ecdsakey}` have distinct
  encoding/validation responsibilities and several real consumers. Combining
  them into a generic crypto utility package would broaden dependencies.
- The large XPath/XSLT and PKI implementations are maintenance risks, not proof
  that package splitting is beneficial. Their private compiler/path state needs
  a separate contract design before any substantial split. Moving files alone
  or adding interfaces for each type would not resolve that cost.
- Public string options remain strings where arbitrary URIs or expanded names
  are part of the contract. Named constants improve finite vocabularies without
  rejecting extensions or breaking callers with string variables. Budgets,
  trust policy and coincidentally equal words remain with their actual owners.

## Verification and review passes

The initial focused XPath/XSLT tests passed before changes. Each structural
stage was compiled and tested. Public `go doc -all` output was compared for all
22 public packages: only six additive SAML service constants and their related
documentation differ; no existing public signature was removed or changed.

The old and new metadata tables were compared for all 80 recognized elements:
minimum version, context and implementation flags are identical. Two final
review passes found no further substantial architecture change to make:

- The first rechecked all package directions, public declarations, vocabulary
  ownership, proof-role boundaries and production versus test dependencies.
- The second rechecked the staged changes against actual consumer/build paths,
  tagged test coverage and independent results; removed packages have no stale
  callers, and the remaining small packages have concrete consumers or contracts.

Completed checks:

- `go test -count=1 ./...` and `go test -race -count=1 ./...`: passed, including
  `TestExternalConsumer` and its separate module in both modes.
- `go vet ./...`, `go mod verify`, `go mod tidy -diff`: passed.
- `CGO_ENABLED=0 go build ./...`: passed; the Windows/amd64 cross-build also passed.
- `golangci-lint run --config build/.golangci.yml ./...`: zero issues, including
  the configured `interop` build tag; `shellcheck build/dss.sh` passed.
- `go run ./tests/cmd/dev examples`: all 15 examples passed.
- `go run ./tests/cmd/dev docs`: documentation and 79 capability entries checked.
- The complete `tests/interop` suite passed with ready xmlsec1/OpenSSL/libxml2;
  the optional XMLENC schema and RFC9879 cases passed in a separate configured
  run, and the actual DSS 6.5.1 worktree run passed separately.
- Sixteen affected transform comparison groups passed against Saxon 12.10/9.4,
  libxml2/libxslt and the published serialization schemas, with no skips.
- Both conditional legacy-policy tests passed separately with
  `GODEBUG=fips140=on`. This is a runtime-policy check, not a certification claim.

Ordinary native/race runs each had six conditional skips: the two FIPS cases
covered separately and four external W3C proof gates. The full thirteen W3C
catalog runs were not repeated for a new language baseline. The four optional
interop skips were covered by the configured published-vector and DSS runs.
No new skips were introduced to make the checks pass; signature and imprint
rejection expectations remain in place.

The seven actual native/independent test captures share the same source and
register identities before and after execution. Reports, downloaded engines
and temporary proof artifacts stay outside the repository.

## Result and remaining scope

Package ownership is clearer, redundant implementation and unnecessary nesting
are reduced, and shared finite vocabularies have explicit owners. No service
layer, registry framework, new interface hierarchy or public package migration
was introduced. These are local structural improvements; no performance gain
or complete standards implementation is claimed.

The optional large-package migrations above remain design choices requiring
their own evidence and compatibility plan. This review did not identify a
justified safe reason to perform them. Existing standards and feature gaps
remain documented in [compatibility](compatibility.md) and the
[language baseline](language-baseline.md).
