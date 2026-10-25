# Performance and storage

## Contents

- [Choose an execution path](#choose-an-execution-path)
- [Retained state](#retained-state)
- [Measure the current code](#measure-the-current-code)
- [Measured changes](#measured-changes)

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

## Measured changes

The paired results below describe feature snapshots measured before the later
package review. Experiments used Go 1.27.3 on darwin/arm64, an Apple M4 Pro and
default GC settings, with GOMAXPROCS fixed at 2 or 4 within each comparison.
Baseline production was `a8d1cfb`; both sides used the same benchmark definitions
and fixture parameters, six samples and alternating order. Storage figures
compare memory and file sinks within the same implementation. CPU profiles ran separately from
allocation and heap profiles. Per-operation figures measure allocation volume;
explicit live-storage figures denote retained heap after GC. RSS is separate.

- **Sustained load.** Fresh source-bound runs on source `975e83bb6cd1` each
  completed at least 600 seconds, with shared objects surviving four phases of
  GOMAXPROCS/workers: 1/1, 2/4, 4/12 and 2/4. Engine, HTTP and SAML completed
  473,654 / 9,075,753 / 345,520 successful operations with zero unexpected errors;
  HTTP separately counted 71,462 injected dependency failures. Throughput by
  phase was 446/798/1065/849, 4191/20348/18195/17771 and 298/552/864/589 ops/s.
  Maximum phase p99 was 70.08 / 2.14 / 81.55 ms; cancellation drain stayed below
  0.307 ms. Goroutines returned to 2/3/2 respectively. Post-GC heap changed from
  9.39 to 9.62 MB, 1.33 to 1.68 MB and 0.34 to 13.45 MB; SAML retained request,
  replay and compressor state. Its store counts fell after the twelve-worker
  phase from 3813/11403/3802 to 2473/7407/2470 records. Sampled heap peaks were
  38.68/6.43/35.47 MB; OS maximum RSS was 118.73/29.28/87.31 MB. OS user+system
  CPU was 1266.77/760.53/1280.98 seconds, including the loopback HTTP server.
  GC pauses totaled 4.26/8.78/4.50 seconds. Separate contention profiles expose
  store/cache locks without establishing a complete-login bottleneck. These
  overlapping local runs and bounded latency instrumentation describe this
  workload; they do not establish production capacity or before/after speedups.
- **Computational packages.** Direct benchmarks cover `pattern` (12 cases),
  `xpath/regex` (5), `xpath/number` (14) and `xpath/text` (24), plus cold, warm
  and concurrent evaluator regex-cache calls. Inputs include ambiguous pattern
  failures, backreferences, Unicode classes, malformed syntax, exact decimals,
  long pictures and 64-byte/1-MiB text in several encodings. Integer remainder
  division replaces per-digit rational reduction: 128-digit formatting fell
  from 22.71 to 2.97 microseconds and 26,040 to 1,416 bytes. Reusing decoder
  scratch reduced 1-MiB Latin-1 discard allocations from about 893 KB to 54 KB.
  Pattern state snapshots and the bounded regex-cache lock remain; profiles
  did not justify another cache or a capture-state rewrite.
- **Streaming and storage.** Direct file evidence storage used about 37 KiB
  per 8-MiB object versus 16.27 MiB for an in-memory observation. Files add
  creation, close and cleanup costs, especially for small objects. SAML POST
  writers retain the signed document and serialize on demand; a preflight
  serialization preserves the form-limit check before state/replay commit.
  An 8-MiB known-size XMLENC input fell from 16.03 to 8.01 MiB allocated; actual
  EOF, source errors and authentication still precede plaintext publication.
  CRL entry preallocation saved 14.9% at 65,536 entries, but early duplicate
  rejection allocated 3.8% more. A retained CRL lookup index was rejected for
  its extra 6.64 MB of live storage without a resolved complete-Verify speedup.
  CLI timestamp input now hashes through a reader. Per-record suite/proof
  output reduced a 31,821-record report from 25.80 MiB to about 34 KiB allocated;
  atomic file publication costs more than overwriting a small report.
- **Serialization.** Common embedded-XML JSON output removes the complete
  inner XML string and its escaped copy: large WriterTo allocation fell from
  5.44 MB to 47 KB. XHTML reuses its private normalization tree, reducing the
  8,192-element writer from 13.45 to 7.65 MiB. Large unquoted adaptive values
  borrow their input; the quoted streaming experiment was slower and removed.
  Character-mapped/normalized fallback paths were measured and retained.
  Shared ASCII normalization batching reduced a 1-MiB public text writer from
  8.20 to 0.64 ms while preserving Unicode composition across write boundaries.
  Exact unfinished combining segments, immutable trees and collected output
  remain necessary representations.
- **Language suites.** All thirteen complete pinned-catalog configurations ran
  again on the same source, without filters or case-count limits and with zero
  skipped cases. Primary failure counts remained 9/20/16 for XPath 2.0/3.0/3.1
  and 59/85 for XSLT 2.0/3.0. All controls preserved their prior failure identities;
  no new, changed or resolved failure was observed. The XPath 2.0 compatibility
  control has no applicable publisher cases and exits unsuccessfully; the 3.0
  and 3.1 compatibility controls each pass five cases. Fresh source-bound
  normative, residual and causal gates passed against these reports and the
  ordinary/race, Saxon, crypto, schema/vector, FIPS and DSS captures. All 97
  independent language comparison groups completed as two exhaustive,
  nonoverlapping batches under the unchanged per-process watchdog.
  See [language validation profiles](language-baseline.md) for their scope.

The package review also removed repeated numeric-padding growth, bounded HTML
URI scratch, eliminated ACS candidate slices and avoided repeated URI parsing.
Small inputs and adverse inputs were measured alongside large valid inputs;
allocation reductions alone do not establish complete-workflow speedups.
