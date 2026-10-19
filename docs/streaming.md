# Streaming and memory

Reader/writer APIs avoid collecting complete byte slices when the operation
allows it. They preserve limits and cancellation. Caller-supplied streams stay
open; streams acquired from resolvers/transports are closed on every path,
including failure. Blocking adapters must honor context themselves.
The same requirement applies to caller-owned readers and writers: checking a
context cannot preempt an arbitrary blocked `Read` or `Write`. A reader/writer
signature alone says nothing about constant memory or early output.

## Parsing and ownership

`document.ParseReader`, `Engine.ParseReader` and `CompileXSLTReader` parse
incrementally but retain a complete XML tree. URI-loaded XML follows the same
path. Working storage includes the current lexical token; a large start tag,
comment or unfinished reference can require token-sized storage. DTDs and
external entities are rejected.

`unparsed-text()` returns a complete decoded string; `unparsed-text-lines()`
returns materialized lines. Availability checks validate and discard input.
JSON retrieval materializes its decoded source while parsing and retains the
parsed XDM value. Those representations can coexist during the operation.

XML node handles retain their owner document for identity and navigation.
`Result.Document(ctx)` makes an independent snapshot of a selected element.
`transform.String` shares the supplied immutable Go string; use `strings.Clone`
when a short substring must release a much larger backing string. Parsed CMS
and timestamp objects retain their encoded DER. Mutable public getters return
owned copies as documented.

## Independent XML records

Use `document.ReadRecords` for callback processing, or `Stylesheet.WriteRecords`
to apply one compiled stylesheet to independent subtrees:

```go
_, err := sheet.WriteRecords(ctx, destination, source, transform.StreamOptions{
    Records: document.RecordOptions{
        Path: []document.Name{{Local: "feed"}, {Local: "item"}},
        MaxInputBytes: 64 << 20,
        MaxRecords: 10_000,
    },
    Separator: "\n",
    MaxOutputBytes: 64 << 20,
})
if err != nil { return err } // Earlier records may already have been written.
```

The path starts at the document root and uses exact namespace URIs/local names.
Each record owns its snapshot and preserves in-scope namespaces and inherited
`xml:lang`, `xml:space` and resolved `xml:base`. The enclosing XML is validated
outside selected records too.

Working storage covers the current record, lexical token, ancestor context,
result and any serialization intermediates. The compiled stylesheet, parameter
values and invocation resources also occupy memory. Retaining records in a
callback retains their data; a collecting destination retains all output.

Every transformation gets a fresh invocation budget; `/item` addresses the record
root. Cross-record axes, sorting/grouping, keys and enclosing-document positions
are unavailable.
W3C `streamable="yes"` execution is unsupported.

`RecordOptions.Limits` bounds each record and lexical tokens outside records;
`MaxDepth` also bounds ancestors. `MaxInputBytes` and `MaxRecords` cap the complete
stream/count when nonzero. `WriteRecords` intersects record and engine limits;
its timeout covers the complete operation. `StreamOptions.MaxOutputBytes`
optionally caps total output, while per-record output limits always apply.

Each result has its own declaration/DOCTYPE/BOM. `Separator` separates results;
the operation does not add an enclosing XML root. Secondary results are rejected;
use explicit execution and `Result.WriteSecondary` for those. Earlier output
and callbacks are not rolled back after a later error. See the runnable
[record example](../examples/streaming/main.go).

## Serialization

`Result.WriterTo(ctx)` returns standard `io.WriterTo`. Call `WriteTo(dst)` for
primary output, or `Result.WriteSecondary` for a named secondary result.
`Stylesheet.Write` combines execution and primary serialization. All return
`(int64, error)`, counting bytes accepted by the destination even on failure.

```go
source := result.WriterTo(ctx) // io.WriterTo
n, err := source.WriteTo(destination)
if err != nil { return err } // Discard output, including the reported n bytes.
fmt.Printf("Wrote %d bytes\n", n)
```

Ordinary XSLT execution retains its input and complete result before the first
serialized byte. XML/HTML/text escaping, common JSON output and supported
encoding conversions write incrementally; this does not make evaluation an
input-to-output stream.

XHTML, adaptive output, disable-output-escaping and FULLY-NORMALIZED can require
an extra tree and serialized bytes proportional to the current result. JSON
embedded nodes, character maps and normalization can buffer individual values;
one value can be as large as the result. Writer methods select these paths
automatically. Record processing applies them to one record's result at a time.

NFC/NFD/NFKC/NFKD output emits completed normalization segments without inserting
CGJ. An uninterrupted combining sequence needs storage proportional to its length,
within the operation's budgets. Exact normalization has no constant-memory
guarantee for arbitrary Unicode input.

Writer errors may follow a valid prefix. The caller decides whether to discard
output or stage it transactionally. `Result.Serialize` and `Stylesheet.Transform`
collect complete `Output` values and return no partial output on error.

## Cryptographic and protocol APIs

- `reference.Write` writes final transform bytes to a writer/hash; `WriteReader`
  also accepts source octets. Raw/Base64 chains use bounded buffers; XML/XPath/XSLT
  transforms retain trees/results. `Process` collects the final bytes. Extensions
  with `ReaderExtensionProcessor` use readers/writers; other extensions receive
  complete bounded octets. Reader-capable extensions may also buffer; their
  implementation determines storage. `Octets` copies its input, and
  `Output.Bytes()` copies the collected output. The whole chain is approved
  before execution.
- XMLDSig RSA/ECDSA, RSA-PSS, HMAC and Ed25519ph hash incrementally, including the
  `SignMessageReader`, `VerifyMessageReader` and HMAC reader APIs. Pure Ed25519
  retains the complete bounded message; `xmldsig.Ed25519ph` with `ModernPolicy`
  is the distinct prehash algorithm. Both endpoints must select the same method.
- `ReferenceResult.WriteDigestInput` replays approved transforms and checks their
  digest. External replay reopens the resolver and rejects changed input. Keep
  the resolver available; discard partial replay output after an error.
- `cms.SignReader` writes DER and hashes detached content once for all signers.
  It starts writing only after EOF and signature self-verification; bounded
  hashing does not provide early output. Attached signing retains the content.
  `SignedData.VerifyReader` does not retain detached content; use `ContentSize()`.
  Embedded content and parsed DER/models remain materialized. `DiscardContent`
  omits the verification result's extra message copy, not the parsed container.
- `timestamp.ImprintReader` and `CreateRequestReader` hash incrementally.
  `WriteResponse` writes around CMS output; `IssueResponse` collects it. Parsing
  tokens/responses retains bounded complete DER. Parsed tokens can be reused
  for verification; `Token.WriterTo(ctx)` and `SignedData.WriterTo(ctx)` replay DER.
- `saml/binding.WritePOST` / `WritePOSTForm` serialize, encode and escape directly;
  `DecodePOSTReader` decodes into the XML parser. Metadata reader methods retain
  XML snapshots. Redirect produces a complete signed query. SP/IdP outbound
  objects retain complete POST forms; use binding writers for incremental output.
- `keys` PEM/DER parsers, PKIX/OCSP, KeyInfo and XAdES retain bounded key,
  certificate or evidence models. `WriteEncryptedPrivate`, `WritePKCS12` and
  `pki.WriteOCSPResponse` write encoded segments; their byte counterparts collect
  the same output. Export still retains cryptographic snapshots/ciphertext.
- XML Encryption uses complete AES-GCM messages and releases plaintext only after
  authentication. Unknown-length external ciphertext can temporarily occupy both
  chunks and contiguous GCM input. XML replacement and signature/XAdES editing
  retain source and result snapshots. These APIs do not promise constant memory.

## Measuring memory

Byte limits count their documented input, output or intermediate data; they do
not specify total live heap or RSS. Trees, indexes, object overhead, simultaneous
representations, runtime caches and GC can add memory. No API-wide heap multiplier
or fixed-memory ceiling is promised.

Run [benchmarks and profiles](testing.md#performance) with fixtures outside timed
loops. Distinguish retained tree/model storage from serialization buffers and
owned output bytes. Allocation volume (`B/op`, `TotalAlloc`) is not peak memory.
Consumer retention tests collect with only results alive; peak tests sample
`HeapAlloc`. Sampling can miss short peaks and includes uncollected garbage;
neither metric measures process RSS or proves an exact memory ceiling.
