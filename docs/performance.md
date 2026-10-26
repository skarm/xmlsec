# Performance and storage

## Choose an execution path

Compile reusable XPath/XSLT programs once; invocations have separate contexts,
variables and budgets. Reader/writer APIs avoid complete byte slices where the
operation allows it. XML parsing and ordinary XSLT still retain trees/results.
Use `Stylesheet.WriteRecords` for independent subtrees without cross-record
navigation, sorting or grouping. See [streaming](streaming.md).

XMLDSig and detached CMS can hash input incrementally. Pure Ed25519 needs the
complete message; Ed25519ph is a separate explicitly selected algorithm.
XML Encryption retains bounded complete messages. `evidence.Store` moves payloads
to temporary files, while subsequent parsing still retains models.

## Retained state

Node handles and values retain their owning snapshots. `Result.Document(ctx)`
can detach a selected element into an independent document. Close evidence
records/stores to release their storage.

SAML memory stores retain entries until pruning or their configured capacity.
State reads do not consume requests. Redirect signing keeps at most four idle
DEFLATE compressors; active calls can allocate more, and reset does not erase
internal history.

Byte/node/work limits bound their documented quantities, not total heap or RSS.
Trees, indexes, callbacks, simultaneous representations and the Go runtime add
storage. Allocation volume (`B/op`, `TotalAlloc`) is not retained or peak memory.

## Measure the current code

Use the same sources, fixtures, policies and toolchain for comparisons. Record
platform, CPU count, GOMAXPROCS and GC settings; exclude setup from timed loops.
Compare small/large inputs and serial/concurrent workflows. Collect repeated
samples and compare them with `benchstat`:

```sh
GOMAXPROCS=2 make bench BENCH_ARGS='-benchtime=300ms -count=6'
benchstat /tmp/before.bench /tmp/after.bench
```

Collect CPU and heap profiles separately; race/profiling instrumentation changes
timings. For example:

```sh
go test ./transform -run '^$' -bench '^BenchmarkEngineXSLT/1024/3.0$' \
  -benchtime=5s -cpuprofile=/tmp/xmlsec-cpu.out -o /tmp/xmlsec-transform.test
go tool pprof -top /tmp/xmlsec-cpu.out
```

The optional sustained-load harness uses local fixtures and loopback HTTP:

```sh
XMLSEC_SOAK_DURATION=10m XMLSEC_SOAK_SCENARIO=transform \
  go test -count=1 -timeout=12m -artifacts -outputdir=/tmp/xmlsec-soak \
  ./tests/integration/saml -run '^TestSustainedLoad$'
```

Scenarios are `transform`, `http` and `saml`. `XMLSEC_SOAK_OUT` overrides the
saved JSON report path. The harness measures throughput, latency, allocation,
sampled heap and cancellation. Samples can miss peaks; measure process RSS
separately. Keep profiles and generated reports outside Git.
