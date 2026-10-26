# Testing

Run from the module root using the Go version in [go.mod](../go.mod).
Make requires a POSIX shell; [CI](../.github/workflows/ci.yml) pins tool versions.

```sh
make check                 # modules, docs, vet, tests, CGO-free build
make race
make lint                  # requires golangci-lint
make fmt
make examples
make fuzz FUZZ_ARGS='-time=5s'
```

Without make, use `go test ./...`, `go test -race ./...` and
`go run ./tests/cmd/dev docs`. Ordinary tests need no external XML engines.
FIPS policy tests rerun themselves in a FIPS-only child process when needed.

## Test layout

- Component tests, fuzz targets and benchmarks live beside their implementation.
  Use external test packages for public APIs and internal tests for private state.
- `tests/integration` covers workflows across packages. `tests/testdata/consumer`
  is a separate module; ordinary root tests run it, forwarding `-race` when set.
- Shared helpers live in `internal/testutil`; fixed vectors live in `testdata`.
  Keep generated reports, disposable keys and external checkouts outside Git.

Use test-owned contexts, `t.TempDir`, `t.Cleanup` and `b.Loop`. Test contexts are
canceled before cleanup: a helper that exits during cleanup needs its own bounded
context. Use `testing/synctest` for in-process timer/cancellation tests and
`httptest.NewTestServer` for HTTP tests. External processes and load/memory
measurements retain real clocks; external HTTP clients need a loopback listener.

Keep process-wide allocation, heap and GC measurements sequential. Independent
functional tests may use `t.Parallel`; cleanup must wait for their subtests.

`make docs` checks Markdown links and the [conformance register](conformance.md).
It does not execute cited tests or prove standards conformance.

## Performance

See [performance](performance.md#measure-the-current-code) for benchmarks,
profiles and the optional sustained-load harness.

## Independent engines

The complete Linux interoperability run uses Docker:

```sh
make interop-docker
```

The [image](../build/interop.Dockerfile) supplies native tools, runs race tests and
interoperability checks, and disables networking during execution. System
package versions follow Debian repositories.

For a prepared host:

```sh
make interop
make interop INTEROP_ARGS='-suite=all -xmlsec1=/absolute/path/to/xmlsec1'
```

The portable suite needs OpenSSL 3+, JDK 21+, a C compiler, pkg-config and libxml2
headers. Optional checks skip when unconfigured; tests never install dependencies.
Known disagreements are recorded in [compatibility](compatibility.md#known-oracle-differences).

Transform comparisons additionally use prepared inputs outside the repository:

- `SAXON_CLASSPATH`: [Saxon HE 12.10](https://github.com/Saxonica/Saxon-HE/releases/tag/SaxonHE12-10)
  and resolver dependencies. Archive SHA-256:
  `1c7db9f726df835349c64edd631de0310eca31291100230064eba153f607b0be`.
- `SAXON20_CLASSPATH`: [Saxon HE 9.4.0-9](https://repo.maven.apache.org/maven2/net/sf/saxon/Saxon-HE/9.4.0-9/Saxon-HE-9.4.0-9.jar)
  for strict XSLT 2.0 comparisons. JAR SHA-256:
  `c52862d33cd5bb34ed20d48a5ff62bc475e4279c16fd13460a19f726d1dcf62f`.
- `SERIALIZATION_SCHEMA_DIR`: extracted W3C Serialization 3.0/3.1 schemas;
  `JSON_SCHEMA_FILE`: the XSLT JSON schema. The tests verify their pinned hashes.
  See [language evidence](language-suites.md#executable-clause-and-failure-evidence).

Pinned QT3/XSLT catalogs have a separate [runner](language-suites.md).
A selected passing run is not a complete language-conformance result.

After preparing the inputs described in
[language evidence](language-suites.md#executable-clause-and-failure-evidence),
run `go run ./tests/cmd/dev proof configure` once with the six input variables
and a working Java executable on PATH. This stores their paths in a
checkout-specific directory under the OS user cache, outside the repository.
The four language evidence/residual tests then run from an ordinary IDE or
`go test` invocation. Missing or stale captures and all thirteen catalog reports
are rebuilt automatically for the current sources and register. The first run
can take several minutes; subsequent runs reuse the matching snapshot.
Explicit environment inputs override cached paths. Unconfigured checkouts retain
optional external tests. `go run ./tests/cmd/dev proof prepare` warms the evidence
cache without running the final gate.
Published reference values (`P3_VECTOR`) are logged only during `proof capture`;
the runner enables `XMLSEC_PROOF_CAPTURE=1` in its child process automatically.

## xmlsec1 comparisons

The `xmlsec` suite requires OpenSSL-backed xmlsec1 1.3.10+ and matching headers;
EdDSA/PBMAC1 checks require OpenSSL 3.5+. Select the executable with `XMLSEC1`
or `-xmlsec1`.

```sh
go test -tags=interop -count=1 -timeout=15m ./tests/interop \
  -run '^TestXMLSec' -args -suite=xmlsec
```

## XAdES baseline and historical checks

`TestXAdESBaselineFormats` uses xmlsec1, OpenSSL and xmllint. Set `XADES_SCHEMA_DIR`
to the ETSI XAdES V1.3.1 schemas and W3C2008 XMLDSig import; tests verify their pins.
`XMLSEC_REQUIRE_P7_PROOFS=1` makes missing proof dependencies fail.

Historical DSS comparisons use the official
[DSS 6.5.1 bundle](https://ec.europa.eu/digital-building-blocks/artifact/repository/esignaturedss/eu/europa/ec/joinup/sd-dss/dss-demo-bundle/6.5.1/dss-demo-bundle-6.5.1.zip),
SHA-256 `f0e10bb218795b966824887a8c73b555ab9d88a8e84997882d3e5a807cc9cb37`.
Extract its Tomcat directory, then run:

```sh
XMLSEC_P7_EXPORT_FIXTURES=/tmp/xmlsec-history go test ./xades \
  -run '^TestHistoricalExpiredTSAArchiveEvidence$' -count=1
XMLSEC_DSS_TOMCAT=/path/to/extracted/apache-tomcat-11.0.27 \
XMLSEC_DSS_FIXTURE_DIR=/tmp/xmlsec-history XMLSEC_DSS_CA_PEM=root.pem \
XMLSEC_DSS_IMAGE=xmlsec-interop:local sh build/dss.sh
```

The [script](../build/dss.sh) verifies the WAR, uses only the fixture CA and runs
DSS and Go inside an offline container. `XMLSEC_DSS_REPORT_DIR` selects saved
reports. These checks compare the documented historical subset, not complete
ETSI validation.

Interop command failures save stdout/stderr in `t.ArtifactDir()`. Retain artifacts
with `go test -artifacts -outputdir=/absolute/path`; `-json` includes suite metadata.
