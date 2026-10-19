// Package reference processes XMLDSig reference transform chains over immutable
// node sets and octet streams. Its output is digest input, not a verified
// signature or an application trust decision.
//
// # Resolve and process
//
// [NewSameDocumentResolver] indexes the application-selected ID attribute;
// [NewSameDocumentResolverWithRules] supports explicit per-element ID rules.
// Resolution accepts the bounded same-document URI and XPointer forms
// documented by [SameDocumentResolver.Resolve]. It applies their
// comment-selection rules without inferring IDs from schemas or fetching
// external resources.
//
// Wrap input with [Octets] or [Nodes], then call [Process] with an explicit
// transform chain and [Options]. The processor performs required XML/node-set
// conversions and, when permitted, final implicit Canonical XML 1.0. A
// successful [Output] contains owned digest bytes and a diagnostic processing
// trace. Errors return no partial Output, and processing leaves the source
// snapshot unchanged. [Write] streams final bytes directly to a writer or hash.
// [WriteReader] also consumes original octets incrementally. These operations
// return a [Report] without retaining final output bytes. Base64 and
// canonicalization pass octets between stages incrementally. XML processing
// retains trees; extensions without [ReaderExtensionProcessor] use complete
// intermediate octet buffers. Reader-capable extensions may also buffer data;
// their own contracts determine working storage. [Octets] copies its input,
// and [Output.Bytes] returns a copy of the buffered result. Use WriteReader
// with a non-collecting destination when those byte copies are unnecessary.
// Any error may leave partial writer output.
//
// # Extensions and resource policy
//
// Built-ins cover canonicalization, the enveloped-signature transform and
// Base64. XPath, Filter2 and XSLT require an application-approved
// [ExtensionProcessor] and corresponding AllowedTransforms entries.
// [PrepareTransforms] approves extension programs before chain execution or
// resource resolution; [ValidateTransforms] checks configuration and parameter
// structure only.
//
// Budgets bound input, intermediate/output bytes, transforms and node visits.
// Built-ins perform no network or filesystem access. Extension implementations
// must enforce their own execution limits and honor cancellation; a context
// cannot preempt arbitrary blocking callback code. Node-set extension results
// must retain snapshot identity and stay within the permitted input selection.
// Parameter budgets are checked before snapshot allocation. Approval callbacks
// receive independent parameter copies and cannot modify the executed program.
package reference
