# Streaming and memory

Reader/writer APIs avoid complete byte slices where an operation permits it.
They do not imply constant memory or early output. Caller-owned streams remain
open; resolver/transport streams are closed. Blocking adapters must arrange
cancellation themselves. See [common contracts](usage.md#common-contracts).

## Parsing and ownership

`document.ParseReader`, `Engine.ParseReader` and `CompileXSLTReader` parse
incrementally but retain complete trees and current lexical tokens. Large tags,
comments or unfinished references can require token-sized storage. Language
resources have a separate [DTD/encoding profile](transforms.md#xml-input-profiles).

Node handles retain their owner document. `Result.Document(ctx)` detaches one
selected element into an independent snapshot. Small string views can retain a
large backing string; use `strings.Clone` when needed. Parsed CMS/timestamp
objects retain encoded data. Text/JSON retrieval also materializes values.

## Independent XML records

`document.ReadRecords` processes selected subtrees in callbacks.
`Stylesheet.WriteRecords` transforms independent records with one compiled stylesheet:

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
if err != nil { return err } // Earlier output may already have been written.
```

Paths start at the document root and use expanded names. Each record owns its
snapshot and inherited namespace/XML context; enclosing XML is validated too.
Storage includes the current record, lexical token, ancestor context, resources
and result. Retaining records or collecting output retains those bytes.

Each record gets a fresh invocation budget. Record limits bound record/token
storage; `MaxDepth` also bounds ancestors. Stream byte/count/output limits apply
when configured, and the timeout covers the entire operation.

Cross-record navigation, grouping, sorting and keys are unavailable. This is not
W3C `streamable="yes"` execution. Results are separated, not wrapped in a new XML
root; declarations/DOCTYPE/BOM belong to each result. Secondary results are
rejected. A later failure does not roll back prior output or callbacks.
See the [record example](../examples/streaming/main.go).

## Serialization

`Result.WriterTo(ctx)` and `WriteSecondary` serialize a chosen result;
`Stylesheet.Write` combines execution and primary serialization and rejects
secondary results. Returned byte counts include accepted output on failure.

Ordinary XSLT retains its input and complete result before serialization starts.
Common XML/HTML/text/JSON escaping and encoding conversion write incrementally;
XHTML, disable-output-escaping and some normalization paths may retain additional
trees or bytes. Exact Unicode normalization may retain an entire unfinished
combining sequence within operation budgets.

Writer errors may follow a valid prefix. Stage output when atomic publication
is required. `Result.Serialize` / `Stylesheet.Transform` collect complete output
and return no partial value on error.

## Cryptographic and protocol APIs

- `reference.Write` / `WriteReader` stream approved transform output to a writer
  or hash. Raw/Base64 paths use bounded buffers; XML/XPath/XSLT retain trees/results.
  `WriteDigestInput` replays approved transforms and rejects changed external input.
- RSA/ECDSA/PSS, HMAC and Ed25519ph hash incrementally. Pure Ed25519 retains a
  complete bounded message and is a different algorithm from Ed25519ph.
- CMS reader APIs can hash detached content without retaining it. Embedded
  content, parsed models and normalized BER/DER remain materialized.
  Timestamp imprint/request reader APIs hash incrementally; tokens retain DER.
- SAML POST writers encode directly; decoding and metadata parsing retain XML.
  Redirect signing produces a complete query. Key, PKIX, KeyInfo and XAdES APIs
  retain bounded cryptographic/evidence models.
- `evidence.Observation` retains complete bytes. `evidence.Store` / `CollectTo`
  use private temporary files; close records and stores. Open record readers
  remain caller-owned. Parsing stored records still builds models.
- XML Encryption retains complete bounded messages and releases GCM plaintext
  only after authentication. XML edits retain source and result snapshots.
- CLI file output uses a same-directory temporary file and rename after success.
  Application stdout buffers output to avoid publishing a serialization prefix;
  JSON encoding can also retain a complete encoded value.

## Measuring memory

Input/output/work limits do not specify total live heap or RSS. Trees, indexes,
simultaneous representations and runtime overhead add storage. `B/op` and
`TotalAlloc` measure allocation volume; sampled heap can miss peaks and includes
uncollected garbage. Measure RSS separately. See [performance](performance.md)
for benchmark/profile commands.
