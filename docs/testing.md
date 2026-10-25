# Testing

Run commands from the module root with the Go version in [go.mod](../go.mod).
Make recipes are in [build/Makefile](../build/Makefile) and require a POSIX shell:

```sh
make check                 # modules, docs, vet, tests, CGO-free build
make race
make lint                  # requires the CI-pinned golangci-lint
make fmt                   # gofmt, gofumpt, goimports
make examples
make fuzz FUZZ_ARGS='-time=5s'
```

`TestCompareSaxonLanguageSemantics` extends the existing optional transform
comparison tests. Set `SAXON_CLASSPATH` to a ready Saxon HE classpath, including
its resolver dependencies. It compares fixed XPath queries and error codes;
no Java adapter is compiled. This run used the publisher's
[Saxon HE 12.10 archive](https://github.com/Saxonica/Saxon-HE/releases/tag/SaxonHE12-10),
SHA-256 `1c7db9f726df835349c64edd631de0310eca31291100230064eba153f607b0be`,
inside Docker with networking disabled. The archive and jars stay outside the
repository. Known XSD 1.0/1.1 regex range differences are excluded from successful
comparison evidence; local tests exercise the explicit `XMLSchemaVersion` selection.

```sh
SAXON_CLASSPATH='/absolute/path/saxon-he-12.10.jar:/absolute/path/lib/*' \
  go test -tags=interop -count=1 -v ./transform -run '^TestCompareSaxonLanguageSemantics$'
```

`TestCompareSaxon20CompilerContracts` additionally requires `SAXON20_CLASSPATH`
pointing to the ready [Saxon HE 9.4.0-9 jar](https://repo.maven.apache.org/maven2/net/sf/saxon/Saxon-HE/9.4.0-9/Saxon-HE-9.4.0-9.jar),
SHA-256 `c52862d33cd5bb34ed20d48a5ff62bc475e4279c16fd13460a19f726d1dcf62f`.
It invokes the published CLI with `-xsltversion:2.0`, verifies the reported version
and rejection of a 3.0 instruction, then checks decimal versions, import order and
module namespace scope. A modern engine's 3.0 handling of a version 2.0 stylesheet
does not establish strict 2.0 behavior. Keep this jar outside the repository; set
both Saxon classpaths for a complete `-run '^TestCompare'` Docker run. Use
`-timeout=20m` for the complete transform comparison; each JVM startup contributes
to the suite runtime. `make interop` supplies this overall test timeout.

[CI](../.github/workflows/ci.yml) defines tool versions and platform checks.
The Go development runner also works without make:

```sh
go run ./tests/cmd/dev docs
go run ./tests/cmd/dev examples
go run ./tests/cmd/dev fuzz -list
```

Pinned external QT3/XSLT diagnostics have a separate
[suite runner](language-suites.md), explicit language/feature selection and JSON
outcomes. They are optional and do not affect ordinary Go checks.

`TestXMLSecRetrievalMethods` in the existing signature interoperability suite
exchanges thirteen retrieval recipes each direction using the installed `xmlsec1`
binary: six C14N forms, Base64/XML, XPath, enveloped/XPath, Filter2, XSLT, raw certificates and
two Base64 steps. X509Data/raw-certificate forms are the measured intersection;
four additional RSA/EC XML/DER controls record that this xmlsec1 CLI cannot
retrieve those bare key roots. Those controls verify core cryptography with an
explicit native key and validate Go retrieval on both signature directions; they
are not claimed as native key-form discovery. Inputs and outputs stay in temporary
directories. KeyInfo tests also check whole-chain
preflight, immutable resource snapshots, cancellation/close/final-read failures,
cycles, aggregate limits and explicit trust ordering. Legacy DSA context tests
reuse the pinned JDK signature/key fixtures, preserving their signed bytes.

`testdata/next/dsig-stage4-vectors.json` contains eleven fixed signatures,
templates, resolver inputs, approved programs and exact reference digest-input
bytes produced by ready xmlsec1 1.3.10/OpenSSL 3.6.5/libxml2 2.15.4 binaries with
networking disabled. Its recipes cover XPath/Filter2/XSLT/PrefixList/`here()`
retrieval, raw-certificate Base64, an external KeyInfo fragment and four transformed
Manifest forms. Disposable private material is excluded. This is a signed test
corpus, not a generated diagnostic report.

`TestXMLDSigStage4IndependentVectors` verifies those signatures, pins discovered
keys, compares exact digest-input bytes and rejects payload/parameter/namespace
mutations. `TestXMLSecStage4Vectors` rechecks the stored native signatures and
fresh Go signatures with installed xmlsec1, including strict KeyInfo discovery.
Four stored URI contexts use xmllint's independently computed inherited bases
and Python's RFC 3986 join; Go checks the resolved identity separately for signed
references and KeyInfo. The live test rechecks libxml2's bases. This does not claim
that xmlsec1's URI mapping implements XML Base or recursive external Manifests.

The existing Manifest and KeyInfo fuzz targets include these valid cases.
Transform-result tests separately cover different outputs from one URI,
independent derived IDs, authenticated discovery order, graph/node/byte limits,
private-signer ordering, concurrent replay and nested-content failures. All new
tests extend existing files. Optional PGP/SPKI/MgmtData, explicit arbitrary EC
parameters, DSA-SHA256, DTD/entity processing and complete LEIRI handling are not
part of stage 4's selected profile.

## Test layout

Keep unit tests, fuzz targets, benchmarks and helpers beside their component in
existing `_test.go` files; split by responsibility when useful. Use external
`package_name_test` for public API checks, package-internal tests for private
state, and `example_test.go` for executable GoDoc examples. Build/platform
constraints may require separate files.

Cross-package workflows live in `tests/integration`. `TestExternalConsumer` copies
the separate module in `tests/testdata/consumer` outside the repository and runs
it with a local module replacement, `GOWORK=off` and `-mod=readonly`. Ordinary
root tests include it; root race runs forward `-race`.

```sh
go test -count=1 ./tests -run '^TestExternalConsumer$'
```

Shared repository helpers are in `internal/testutil`; public fixtures in
`testdata`. Optional C/Java oracles are in `tests/interop/testdata`, with Go
adapters in `tests/interop/cmd`. [conformance.json](conformance.json) separates
capabilities from normative obligations. `make docs` checks documentation links,
schema and state consistency, edition references, local code/fixture paths,
exported APIs and named positive/negative/interoperability test functions.
See [normative traceability](conformance.md); this validates the register without
running cited tests or proving completeness of the clause inventory.

Legacy XMLDSig fixtures in `testdata/legacy-dsig` were produced and validated by
OpenJDK 27's public JSR 105 API. Their manifest records the producer, source
hashes and fixture hashes. Private DSA/RSA keys were discarded. The HMAC fixture
uses the public test secret `aa` repeated 80 times; it is not a production key.
Ordinary component tests check exact SPKI, all reference digests, coverage,
policy denials, malformed signatures/keys, cancellation and input limits.
HMAC also uses the independent RFC 2202 section 3 case 6 expected bytes.

```sh
go test -tags=interop -count=1 -v ./tests/interop -run '^TestLegacySignatureFixtures$'
GODEBUG=fips140=only go test -count=1 ./xmldsig -run '^TestLegacyMethodsFIPS$'
```

The interop test replays the committed JDK signatures and verifies Go-generated
HMAC-SHA1 and SHA-1 reference digests in JDK. `CoreOracle` has explicit
`legacy-fixture`, `verify-legacy` and `verify-legacy-hmac` modes: only these
compatibility modes disable JSR 105 secure validation. All modes retain the
same-document URI resolver and hardened XML parser; ordinary oracle modes
retain secure validation. DSAKeyValue builders emit complete 1024/160 parameters;
the parser can obtain omitted P/Q/G from explicit `Options.DSAParameters`.
Component tests remove those unsigned fields from the independent fixture and
verify the original signed bytes with the same SPKI pin. Other DSA parameter
sizes and automatic parameter inference remain outside this scope.

`TestExternalManifestInterop` in the existing interoperability profile tests
uses OpenJDK 27 JSR 105 to generate external Manifest references and nested
digests, verifies them through both the Go API and CLI, and verifies Go's
signature in JDK. Changing only the nested payload keeps the parent reference
valid and causes both implementations to reject recursive validation.
The oracle explicitly unmarshals the original external Manifest references;
JSR 105's core validation alone does not assert their success.

```sh
go test -tags=interop -count=1 -v ./tests/interop -run '^TestExternalManifestInterop$'
```

Local Manifest tests cover independent ID/namespace scopes, shared nodes,
source-preserving transforms, cycles, malformed XML, graph/byte limits,
resource closure, and the absence of nested I/O before parent authentication.
Generated exchange files remain in the test's temporary directory. A small
committed JDK vector in `testdata/next/external-manifest-vector.json` fixes the
original signature, public key and resource bytes for ordinary Go regressions;
it records its oracle source hash and contains no private key.

`TestXMLSecExternalManifestURIContext` uses the ready xmlsec1 executable for a
bidirectional external fragment exchange. The native engine selects an ID from
its XML source; the Go adapter supplies the identified standalone Manifest
octets. A local DTD types the ID only in the native test input; production Go
parsing remains DTD-free. Native verification rejects a changed selected
Manifest. Changing only its nested payload is rejected by Go recursive checking
while xmlsec1 core validation still succeeds; this boundary is asserted.
`TestXMLSecRelativeURIContext` also records that this CLI profile opens the
literal relative URI instead of applying inherited `xml:base`. It then exchanges
identical bytes through an explicit native literal mapping and Go's resolved
allowlist. This is not independent confirmation of XML Base processing.

Component tests in the existing Manifest test file cover retrieval bases,
inherited/empty `xml:base`, query/fragment escaping, exact authorization before
I/O, caller-option snapshots, retained replay identity, shared resolved edges,
separate fragment scopes, alias cycles and graph limits. RFC 3986 section 5 and
XML Base sections 4.2-4.4 supply the selected resolution rules. Fixed independent
fixtures now cover the selected additional URI contexts in the stage-4 corpus above;
broader LEIRI and retrieval-metadata handling remain outside the bounded profile.
`TestExternalExtensionContextIsNotReused` verifies that repeated or aliased
resource URIs cannot bypass a trusted processor's runtime denial at a different
original expression element. Extension results are not shared between references;
built-in chains keep their resource-result cache and replay behavior.

## Performance

Run packages sequentially and compare repeated samples with `benchstat`:

```sh
make bench BENCH_ARGS='-benchtime=1s -count=6'
go test ./transform -run '^$' -bench '^BenchmarkEngineXSLT/1024/3.0$' \
  -benchtime=5s -cpuprofile=/tmp/xmlsec-cpu.out -memprofile=/tmp/xmlsec-heap.out \
  -o /tmp/xmlsec-transform.test
pprof -top /tmp/xmlsec-cpu.out
pprof -top -alloc_space /tmp/xmlsec-heap.out
pprof -top -inuse_space /tmp/xmlsec-heap.out
```

These commands use an installed standalone `pprof`; `go tool pprof` is also
usable when the Go installation supplies it.

Exclude fixture setup from timed loops. Record Go version, OS/CPU, runtime
settings and input sizes. Run race tests separately from measurements. Use mutex,
block and execution-trace profiles for concurrency questions. Distinguish
[allocation, retained storage and sampled peaks](streaming.md#measuring-memory);
short or single-iteration timings do not establish performance.

The stage-4 checkpoint compares the existing `BenchmarkVerifySignature` and
`BenchmarkParseKeyInfo` against `738c2df` on Go 1.27.3, darwin/arm64, with
`GOMAXPROCS=1`, eight alternating before/after pairs and 150 ms timed samples.
Signature verification keeps 467 allocations/op and adds 240 B/op (about
224,739 → 224,979 B/op) for the expanded result/graph metadata. Inline KeyInfo
parsing stays at 60 allocations and 5,736 B/op. Median times were 132.100 →
132.174 µs and 2.5835 → 2.5415 µs respectively; these short samples do not establish
a timing improvement or general peak/retained-memory behavior. Raw measurements
and build exports stay outside the repository.

The 2026-10-22 KeyInfo checkpoint compares the existing `BenchmarkParseKeyInfo`
against `7fbc54d` on Go 1.27.3, darwin/arm64, Apple M4 Pro. Eight alternating
before/after pairs (`-count=1 -benchtime=300ms -benchmem`) measured 60 allocations
in both versions and 5,640 → 5,736 B/op (+96 bytes). Lazy retrieval caches avoid
three extra allocations for ordinary inline keys. With the default 12 Go
processors, median time was 2.341 → 2.391 µs (+2.14%, p=0.047); a separate
eight-sample `GOMAXPROCS=1` comparison was 2.568 → 2.639 µs (p=0.169).
These are narrow fixture measurements, not a general performance guarantee.

Separate Linux/arm64 Docker profiling on Go 1.27.2 used a three-second benchmark
without race. CPU samples showed substantial allocator/GC work; about 36% of
sampled allocated bytes came from `base64.NewDecoder`. The post-GC `inuse_space`
sample was empty after discarding results; this does not measure retained caller
results or peak RSS. The macOS CPU sample was dominated by `runtime.kevent` and
was not used to identify application hotspots. Raw profiles and benchmark logs
remain temporary artifacts rather than tracked reports.

The 2026-10-22 external-URI checkpoint compares the existing
`BenchmarkVerifySignature` against `0fbd504`, using Go 1.27.3, darwin/arm64,
Apple M4 Pro and `GOMAXPROCS=1`. Eight alternating before/after pairs
(`-benchtime=150ms -benchmem`) used isolated source exports containing only this
block's changes. Median time was 134.9 → 133.8 µs (p=1.000), with 467 allocations
in both versions and about 112 additional B/op (+0.05%). This measures the
existing inline fixture; external-pipeline scaling and peak RSS were not measured.

The X509Data construction checkpoint compares `BenchmarkBuildCertificateKeyInfo`
with `afcdbd8`, adding the same benchmark to that isolated source export. Go 1.27.3,
darwin/arm64, Apple M4 Pro and `GOMAXPROCS=1` used eight alternating pairs with
`-benchtime=150ms -benchmem`. Both versions measured 20,496 B/op and 133 allocations;
median time was 20.51 → 21.06 µs (p=0.083). This is a one-certificate legacy-builder
fixture; no claim is made about new-group scaling, retained heap or peak RSS.

## Independent engines

The ordinary C14N tests read 138 exact-byte vectors and 24 rejection fixtures from
[normative-vectors.json](../c14n/testdata/normative-vectors.json). Their producer
metadata records OpenJDK, libxml2 and both existing adapter source hashes. Cases
cover all six algorithm URIs, document/subtree/sparse inputs, all seven node
kinds, namespace rebinding and sibling restoration, selected/omitted attributes
and bindings, PrefixList, inherited XML attributes, comments/PIs and normalization.
Rejection cases distinguish malformed XML, unavailable input-model features and
invalid canonicalization options. Both byte and one-byte reader inputs are checked.
Partial writer tests exercise every output byte boundary, including inside UTF-8
characters and escapes, across document, subtree and node-set paths.

Recheck the committed vectors against the installed JDK without C dependencies:

```sh
go test -tags=interop -count=1 -v ./tests/interop -run '^TestCanonicalVectorsAgainstJDK$'
```

`TestCanonicalVectorsAgainstLibXML` replays the same fixed corpus against
libxml2. Each unexplained mismatch fails. Documented oracle limitations are
reported as diagnostics and excluded from agreement; their normative bytes stay
mandatory in ordinary tests. This includes loose/omitted attributes, DOM
namespace-axis ownership, nearest inherited XML attributes, empty selections,
fragment removal during C14N 1.1 base joining and original-order comment/PI line
breaks. A case with a diagnostic is not evidence of oracle agreement.

The JDK adapter uses its subtree API for subtree requests; arbitrary DOM
namespace-axis node sets have different limitations. For a manual libxml2 check,
compile `tests/interop/testdata/c14n-oracle.c` with its development flags and feed
each vector's XML, algorithm mode and XPath selection. On macOS, SDK headers
can be selected explicitly when pkg-config is unavailable:

```sh
cc -Wall -Wextra -Werror -O2 tests/interop/testdata/c14n-oracle.c \
  -I"$(xcrun --show-sdk-path)/usr/include/libxml2" -lxml2 -o /tmp/c14n-oracle
/tmp/c14n-oracle --version
```

The oracle CLI documents its arguments. A fixture `SUBTREE:path` selection maps
to `path/descendant-or-self::node() | path/descendant-or-self::*/@* |
path/descendant-or-self::*/namespace::*` for the libxml2 node-set API. Canonical
bytes remain checked against the cited processing rules and errata, not only
agreement between implementations.

The `interop` build tag enables optional comparisons; native engines are not
production dependencies. Run the complete Linux check in Docker:

```sh
make interop-docker
```

The [Dockerfile](../build/interop.Dockerfile) installs the required Go toolchain,
OpenSSL, xmlsec1, JDK, libxml2 and libxslt. The default run checks versions,
executes race tests, then both interoperability suites with networking disabled.
System packages follow Debian repositories; versions are not pinned. Override
`DOCKER` or `INTEROP_DOCKER_IMAGE` through make if needed.

Native equivalents:

```sh
make interop
make interop INTEROP_ARGS='-suite=all -xmlsec1=/absolute/path/to/xmlsec1'
```

The default `portable` suite requires OpenSSL 3+, JDK 21+, a C compiler,
pkg-config and libxml2 development headers. It compares XML/XPath/XSLT,
signatures and supported evidence profiles with independent engines.

## xmlsec1 comparisons

The `xmlsec` suite requires OpenSSL-backed xmlsec1 1.3.10+, OpenSSL 3.5+ for
EdDSA/PBMAC1, and matching development headers for the C buffer probe. `XMLSEC1`
or `-xmlsec1` selects the executable; tests never install dependencies.

To run only the xmlsec1 groups:

```sh
docker build --file build/interop.Dockerfile --tag xmlsec-interop:local .
docker run --rm --network=none xmlsec-interop:local \
  go test -v -count=1 -tags=interop -timeout=15m ./tests/interop \
  -run '^TestXMLSec' -args -suite=xmlsec
```

These groups exchange signatures, Manifest subresources, HMAC, AES-GCM XML/byte encryption,
Element/Content replacement and DER/protected keys. Negative controls reject
modified ciphertext, incorrect passwords/MACs and malformed encodings. Known
[oracle differences](compatibility.md#known-oracle-differences) are asserted as
diagnostics, excluded from successful exchange counts; unexpected differences fail.

`TestXMLSecX509DataGroups` exchanges nine X509Data forms in each direction:
certificate, issuer/serial, subject, SKI, SHA-256/384/512 certificate digests,
certificate plus CRL, and a combined group. Both payload and KeyInfo are referenced;
altered content or authenticated selectors fail. Native verification uses strict
key discovery and an explicit certificate store, without a public-key fallback.
A separate native-generation case asks xmlsec1 to populate certificate/selector
placeholders and checks their values against the OpenSSL-issued identity. The
OpenSSL CLI also generates a v2 CRL. Native `--insecure` avoids treating the
disposable self-signed identity as PKIX evidence; Go verification pins its key.
These are representation/signature checks, not chain or revocation validation.
Generated identities and exchange files stay in temporary directories.

`TestXMLSecEncryption` also checks all 25 SHA-1/SHA-224/SHA-256/SHA-384/SHA-512
OAEP/MGF1 combinations for the 1.1 URI, and all five digest choices with the
1.0 URI's fixed MGF1-SHA1. Both empty and binary labels, opaque/XML plaintext,
parameter mismatches and damaged tags are covered. These exchanges use the
installed `xmlsec1` CLI directly. SHA-1/legacy URI selection is explicit on
the Go side; default parameters do not broaden when compatibility is enabled.

```sh
go test ./xmlenc -run '^TestOAEP' -count=1
GODEBUG=fips140=only go test ./xmlenc -run '^TestOAEPLegacyFIPSPolicy$' -count=1
```

The latter checks policy denial before private-key operations. It does not
assert execution of the entire AES-GCM profile in FIPS-only mode.

CMS BER tests reuse the existing independent CMS fixtures. They change only
permitted envelope/content encodings and check that normalization reproduces
the exact original definite container and verifies the independent signature.
Malformed EOC, primitive indefinite lengths, non-octet chunks, structural/byte/
content limits, cancellation and non-DER signed attributes are rejected.
The existing CMS fuzz target exercises both strict and explicit BER parsers.

`TestCMSBEROpenSSL` generates chunked indefinite SignedData with the installed
OpenSSL CLI, verifies RSA/ECDSA signatures and content in Go, and verifies both
original BER and normalized output in OpenSSL. Both reject altered content.
It requires no Java/C adapter and writes exchange data only to temporary files.

```sh
go test ./cms -run '^TestCMSBER' -count=1
docker run --rm --network=none xmlsec-interop:local \
  go test -tags=interop -count=1 -v ./tests/interop -run '^TestCMSBEROpenSSL$'
```
