# Performance and storage

## Contents

- [Choose an execution path](#choose-an-execution-path)
- [Retained state](#retained-state)
- [Measure the current code](#measure-the-current-code)

## Choose an execution path

Compile XPath expressions and XSLT stylesheets once when reusing the same
program and static policy. Published programs support concurrent invocations;
each invocation has separate variables, context and budgets.

Use reader and writer APIs when a complete input or output byte slice is
unnecessary. XML parsing still retains a tree, and ordinary XSLT execution retains
its result before serialization. `Stylesheet.WriteRecords` processes independent
records when cross-record navigation, sorting and grouping are unnecessary.
The [streaming guide](streaming.md) describes storage for each API family.

XMLDSig and detached CMS hash supported input incrementally. Pure Ed25519 needs
a complete message; Ed25519ph is a separate algorithm that both endpoints must
select explicitly. XML Encryption uses complete bounded messages. GCM decryption
releases plaintext only after authentication.

`evidence.Observation` retains complete untrusted bytes in memory. Use
`evidence.Store` and `collect.HTTP.CollectTo` to retain payloads in private temporary
files. Close records and stores when finished. File storage adds filesystem I/O,
and subsequent parsing still retains certificate or evidence models.

The CLI serializes file output through a bounded buffer into a same-directory
temporary file, then renames it after successful serialization and close.
Application stdout buffers output before publication. JSON encoding can retain a
complete encoded value; a writer parameter alone does not establish fixed memory.

## Retained state

Documents, node handles and result values retain the snapshots they reference.
Keeping a small subtree handle can therefore retain its complete source document.
`Result.Document(ctx)` creates an independent snapshot for a selected element.
Mutable byte and certificate accessors return owned copies where documented.

SAML Redirect signing retains at most four idle DEFLATE compressors. Concurrent
bursts can allocate additional active compressors; excess idle instances are
discarded. Reset detaches the output writer but does not erase the compressor's
internal byte history. The count limit is not a portable byte-size guarantee.

Memory state and replay stores retain entries up to their configured capacities.
State Put/Get and replay Consume prune expired entries; Len reports stored counts
without pruning. Reading request state does not consume it, so completed logins
can leave state until expiration and later pruning. Atomic multi-identifier
consumption uses a lock; throughput under contention depends on the application
workload.

Input, output, node and operation limits bound their documented quantities.
They do not specify total heap or RSS. Trees, indexes, temporary representations,
callbacks, caches and the Go runtime contribute additional storage. Exact Unicode
normalization can retain an unfinished combining sequence within operation
budgets. No universal constant-memory or latency guarantee applies.

## Measure the current code

Run benchmarks against the exact source, toolchain, fixtures and policy used by
the application. Record Go version, platform, CPU count, GOMAXPROCS and GC settings.
Keep fixture construction and compilation outside timed loops. Compare small and
large inputs, serial calls and concurrent complete workflows.

The benchmark families include:

- `document.BenchmarkDocumentOperations` for document and selection operations.
- `transform.BenchmarkEngineXPath`, `BenchmarkEngineXSLT` and
  `BenchmarkEngineParallel` for language execution.
- `cms.BenchmarkCMS`, `BenchmarkCMSBER` and `BenchmarkCMSBERReader` for CMS paths.
- `resource.BenchmarkEvidenceCollect` and `BenchmarkEvidenceStorage` for
  collection and storage adapters.
- `saml/binding.BenchmarkSignRedirect` and `BenchmarkVerifyRedirect` for bindings.
- `tests/integration/saml.BenchmarkLogin`, `BenchmarkSPBegin`,
  `BenchmarkSPConsumePOST` and `BenchmarkLoginParallel` for complete SAML flows.
- `xades.BenchmarkHistoricalValidation` for the historical evidence workflow.
- `cmd/xmlsec.BenchmarkDocumentIO` for CLI XML input and file output.

Allocation volume (`B/op` or `TotalAlloc`) is not retained or peak memory.
Post-GC heap profiles measure retained objects; sampled peaks can miss short
allocations. Measure process RSS separately. Profiling, tracing and race
instrumentation can alter timings.

See [benchmark and profiling commands](testing.md#performance) for repeated
samples, `benchstat`, CPU and heap profiles, and the sustained local load harness.
Keep raw measurements, profiles, traces and generated reports outside Git.
