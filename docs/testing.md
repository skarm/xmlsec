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

[CI](../.github/workflows/ci.yml) defines tool versions and platform checks.
The Go development runner also works without make:

```sh
go run ./tests/cmd/dev docs
go run ./tests/cmd/dev examples
go run ./tests/cmd/dev fuzz -list
```

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
adapters in `tests/interop/cmd`. [conformance.json](conformance.json) maps supported
requirements to tests; `make docs` checks those paths and documentation links.

## Performance

Run packages sequentially and compare repeated samples with `benchstat`:

```sh
make bench BENCH_ARGS='-benchtime=1s -count=6'
go test ./transform -run '^$' -bench '^BenchmarkEngineXSLT/1024/3.0$' \
  -benchtime=5s -cpuprofile=/tmp/xmlsec-cpu.out -memprofile=/tmp/xmlsec-heap.out \
  -o /tmp/xmlsec-transform.test
go tool pprof -top /tmp/xmlsec-cpu.out
go tool pprof -top -alloc_space /tmp/xmlsec-heap.out
go tool pprof -top -inuse_space /tmp/xmlsec-heap.out
```

Exclude fixture setup from timed loops. Record Go version, OS/CPU, runtime
settings and input sizes. Run race tests separately from measurements. Use mutex,
block and execution-trace profiles for concurrency questions. Distinguish
[allocation, retained storage and sampled peaks](streaming.md#measuring-memory);
short or single-iteration timings do not establish performance.

## Independent engines

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

To run only the six xmlsec1 groups:

```sh
docker build --file build/interop.Dockerfile --tag xmlsec-interop:local .
docker run --rm --network=none xmlsec-interop:local \
  go test -v -count=1 -tags=interop -timeout=15m ./tests/interop \
  -run '^TestXMLSec' -args -suite=xmlsec
```

These groups exchange signatures, HMAC, AES-GCM XML/byte encryption,
Element/Content replacement and DER/protected keys. Negative controls reject
modified ciphertext, incorrect passwords/MACs and malformed encodings. Known
[oracle differences](compatibility.md#known-oracle-differences) are asserted as
diagnostics, excluded from successful exchange counts; unexpected differences fail.
