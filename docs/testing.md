# Testing

## Contents

- [Test layout](#test-layout)
- [Performance](#performance)
- [Independent engines](#independent-engines)
- [xmlsec1 comparisons](#xmlsec1-comparisons)
- [XAdES baseline and historical checks](#xades-baseline-and-historical-checks)

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

`TestCompareSaxonLanguageSemantics` compares XPath queries and error codes
against an explicitly configured Saxon processor. Set `SAXON_CLASSPATH` to a
ready Saxon HE classpath, including its resolver dependencies. No Java adapter
is compiled. The pinned input is the publisher's
[Saxon HE 12.10 archive](https://github.com/Saxonica/Saxon-HE/releases/tag/SaxonHE12-10),
SHA-256 `1c7db9f726df835349c64edd631de0310eca31291100230064eba153f607b0be`.
Run Docker comparisons with networking disabled. Keep the archive and jars
outside the repository. Known XSD 1.0/1.1 regex range differences are excluded from successful
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

`TestCompareSerializationParameterSchemas` checks the shared serialization cases
with ready `xmllint` and the schemas embedded in the pinned Serialization
[3.0 REC](https://www.w3.org/TR/2014/REC-xslt-xquery-serialization-30-20140408/#serparams-schema)
and [3.1 REC](https://www.w3.org/TR/2017/REC-xslt-xquery-serialization-31-20170321/#serparams-schema).
It validates the whole 3.0 document and only selected standard parameters in 3.1,
as each edition prescribes. Saxon's different extraction diagnostics remain
separate. Schemas and generated reports stay outside the repository.

Prepare the document-licensed W3C schemas once, then run without network access:

```sh
python3 - <<'PY'
import html, pathlib, re, urllib.request
root = pathlib.Path('/tmp/xmlsec-serialization-schemas')
root.mkdir(exist_ok=True)
for edition, date in [('30', '20140408'), ('31', '20170321')]:
    year = date[:4]
    url = f'https://www.w3.org/TR/{year}/REC-xslt-xquery-serialization-{edition}-{date}/'
    source = html.unescape(urllib.request.urlopen(url).read().decode())
    start = source.index('<xs:schema')
    end = source.index('</xs:schema>', start) + len('</xs:schema>')
    schema = re.sub(r'</?(?:a|span)[^>]*>', '', source[start:end])
    (root / f'ser{edition}.xsd').write_text(schema)
PY
SERIALIZATION_SCHEMA_DIR=/tmp/xmlsec-serialization-schemas \
  go test -tags=interop -count=1 ./transform -run '^TestCompareSerializationParameterSchemas$'
```

The test pins extracted-schema SHA-256 values `1cbcc49ac5ed8942ba58276699254469ca2144e229f68faeeb48f784c1037953`
and `256736a2f4e7923e888047dee757c17bc3ee707e285f00639fd8fb1d962d11b0`.
An absent directory option leaves this optional external check unconfigured;
a configured missing or changed schema fails the check.

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

Fixed XMLDSig exchange vectors are in `testdata/next/dsig-stage4-vectors.json`;
legacy JDK fixtures are in `testdata/legacy-dsig`. Their manifests retain
producer versions, source hashes and fixture hashes. Generated exchange files
and disposable private keys stay outside Git. See the
[oracle differences](compatibility.md#known-oracle-differences) before treating
processor agreement as normative evidence.

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

The JDK adapter enables legacy algorithms only in its explicit compatibility
modes; ordinary oracle modes retain secure validation. All modes keep the
same-document resolver and hardened XML parser.

External Manifest regressions use the fixed
`testdata/next/external-manifest-vector.json` and live JDK/xmlsec1 exchanges:

```sh
go test -tags=interop -count=1 -v ./tests/interop -run '^TestExternalManifestInterop$'
```

Native core validation and recursive Go validation have different boundaries;
see [known oracle differences](compatibility.md#known-oracle-differences).

## Performance

The [performance and storage guide](performance.md) describes execution paths,
retained state and benchmark families. Measure isolated operations and complete
workflows separately.
Keep raw reports, profiles, traces and baseline source exports outside Git.

Run packages sequentially. Use identical benchmark sources and inputs for the
baseline and changed production sources, alternate their order, collect at least
six samples and compare with `benchstat`:

```sh
GOMAXPROCS=2 make bench BENCH_ARGS='-benchtime=300ms -count=6'
benchstat /tmp/before.bench /tmp/after.bench
```

Collect CPU profiles separately from allocation-per-object or trace runs:

```sh
GOMAXPROCS=2 go test ./transform -run '^$' -bench '^BenchmarkEngineXSLT/1024/3.0$' \
  -benchtime=5s -cpuprofile=/tmp/xmlsec-cpu.out -o /tmp/xmlsec-transform.test
GOMAXPROCS=2 go test ./transform -run '^$' -bench '^BenchmarkEngineXSLT/1024/3.0$' \
  -benchtime=1s -memprofile=/tmp/xmlsec-heap.out -memprofilerate=1 \
  -o /tmp/xmlsec-transform.test
go tool pprof -top /tmp/xmlsec-cpu.out
go tool pprof -top -alloc_space /tmp/xmlsec-heap.out
go tool pprof -top -inuse_space /tmp/xmlsec-heap.out
```

Use separate mutex/block profiles and traces for contention/scheduling questions.
Exclude setup from timed loops; record Go/platform, GOMAXPROCS, GC defaults and
fixture sizes. Race and heavily instrumented timings are diagnostic, not paired
performance results. Check small inputs as well as large ones.

The opt-in sustained harness uses only loopback HTTP and in-process fixtures:

```sh
XMLSEC_SOAK_DURATION=10m XMLSEC_SOAK_SCENARIO=transform \
  XMLSEC_SOAK_OUT=/tmp/transform-soak.json \
  go test -count=1 -timeout=12m -v ./tests/integration/saml -run '^TestSustainedLoad$'
```

Repeat with `XMLSEC_SOAK_SCENARIO=http` and `saml`. Each process runs the same
shared objects continuously through four equal phases: GOMAXPROCS/workers
1/1, 2/4, 4/12 and 2/4. Slow I/O, larger operations and HTTP dependency failures
are part of the workload; expected failures remain counted separately.
The SAML fixture advances real time and uses explicit short freshness/lifetime
policies with the ordinary bounded stores. Cancellation drains in-flight work.
Never point this harness at production.

Histograms bound latency storage and round up within 2.2%; instrumentation and
background load affect absolute timings. Ten-second heap samples can miss peaks.
Record process CPU and peak RSS separately (on macOS, `/usr/bin/time -l`), and
inspect post-GC heap and goroutines with the shared objects still alive.
`TotalAlloc`/B/op are accumulated allocation, not live heap, peak heap or RSS.
Keep sources fixed during final suite runs and source-bound proof captures;
see [the complete language workflow](language-suites.md).

## Independent engines

Ordinary C14N tests use the exact-byte and rejection cases in
[normative-vectors.json](../c14n/testdata/normative-vectors.json). Producer metadata
records OpenJDK, libxml2 and adapter source hashes.

Recheck the committed vectors against the installed JDK without C dependencies:

```sh
go test -tags=interop -count=1 -v ./tests/interop -run '^TestCanonicalVectorsAgainstJDK$'
```

`TestCanonicalVectorsAgainstLibXML` replays the same fixed corpus against
libxml2. Each unexplained mismatch fails. Documented oracle limitations are
reported as diagnostics and excluded from agreement; their normative bytes stay
mandatory in ordinary tests. See [known oracle differences](compatibility.md#known-oracle-differences).
A diagnostic is not evidence of oracle agreement.

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

The X509Data exchange uses strict native key discovery with an explicit
certificate store. Its disposable identities establish representation and
signature checks, not chain or revocation validity. XMLENC exchanges include
OAEP/MGF1 parameters, explicit legacy policy and authenticated plaintext release.

```sh
go test ./xmlenc -run '^TestOAEP' -count=1
GODEBUG=fips140=only go test ./xmlenc -run '^TestOAEPLegacyFIPSPolicy$' -count=1
```

The latter checks policy denial before private-key operations. It does not
assert execution of the entire AES-GCM profile in FIPS-only mode.

`TestCMSBEROpenSSL` exchanges chunked indefinite SignedData with the installed
OpenSSL CLI. It verifies signatures and content before and after normalization;
malformed envelopes and altered content remain rejection cases.

```sh
go test ./cms -run '^TestCMSBER' -count=1
docker run --rm --network=none xmlsec-interop:local \
  go test -tags=interop -count=1 -v ./tests/interop -run '^TestCMSBEROpenSSL$'
```

## XAdES baseline and historical checks

`TestXAdESBaselineFormats` exchanges 24 topology/canonicalization combinations
with ready xmlsec1, checks certificate/policy hashes with OpenSSL and validates
the property grammar with xmllint against pinned official XAdES V1.3.1 schemas.
Set `XADES_SCHEMA_DIR` to the two ETSI schemas and their W3C2008 XMLDSig import;
the test verifies their SHA-256 pins before use. `XMLSEC_REQUIRE_P7_PROOFS=1`
turns missing independent dependencies into failures. Schemas and binaries are
not committed; the DSS input pairs below are generated outside the checkout.

`TestIndependentEvidence` checks the literal RSA/ECDSA inclusive-archive
imprints against lxml/libxml2 and OpenSSL. It rejects input that canonicalizes
SignedInfo with a method different from the archive method.

The ready DSS 6.5.1 demonstration bundle provides a separate process comparison.
Use the [official release](https://github.com/esig/dss-demonstrations/releases/tag/6.5.1)
and [prebuilt bundle](https://ec.europa.eu/digital-building-blocks/artifact/repository/esignaturedss/eu/europa/ec/joinup/sd-dss/dss-demo-bundle/6.5.1/dss-demo-bundle-6.5.1.zip).
The bundle SHA-256 is
`f0e10bb218795b966824887a8c73b555ab9d88a8e84997882d3e5a807cc9cb37`.
Extract its Tomcat directory; `build/dss.sh` additionally verifies the exact WAR.
Generate the sufficient/insufficient pair outside the checkout:

```sh
XMLSEC_P7_EXPORT_FIXTURES=/tmp/xmlsec-history go test ./xades \
  -run '^TestHistoricalExpiredTSAArchiveEvidence$' -count=1
XMLSEC_DSS_TOMCAT=/path/to/extracted/apache-tomcat-11.0.27 \
XMLSEC_DSS_FIXTURE_DIR=/tmp/xmlsec-history XMLSEC_DSS_CA_PEM=root.pem \
XMLSEC_DSS_IMAGE=xmlsec-interop:local sh build/dss.sh
```

The image needs the ready JDK and Go/module dependencies from the existing
interop build. Offline runs may supply `XMLSEC_DSS_GOMODCACHE` and
`XMLSEC_DSS_GOCACHE`. `XMLSEC_DSS_REPORT_DIR` saves complete reports and a
source-bound capture. The runner imports only the explicit fixture CA, disables
trust-list loading, starts DSS and Go in one `--network none` container, and
stops the server afterward. It creates no Java/C adapter or persistent job.
For a Git worktree, it also mounts the common Git metadata read-only so that
source-bound capture can resolve the checkout's `.git` file.

The main pair requires the same primary signature, intact references and exact
best-signature times. A sufficient archive must recover the old timestamp's
trust in DSS's detailed report, beyond a top-level success indication. Both
engines reject the insufficient pair as indeterminate. Their negative
sub-indications differ: DSS uses `OUT_OF_BOUNDS_NOT_REVOKED`; this bounded
workflow conservatively retains `OUT_OF_BOUNDS_NO_POE` without post-expiry CA
assurance. DSS's default optional-timestamp policy also differs from
`RequireAllTimestamps=true` for disjoint/overlapping clock cases. These are
recorded diagnostic boundaries, not complete EN319102-1 process agreement or
an independent security assessment.
