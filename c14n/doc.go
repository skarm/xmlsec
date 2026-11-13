// Package c14n writes canonical XML from immutable document snapshots.
// It implements Canonical XML 1.0 and 1.1 and Exclusive XML Canonicalization 1.0,
// each with or without comments.
//
// # Choose an input
//
// [WriteDocument] includes the document-level processing instructions and selected
// comments. [WriteElement] canonicalizes a complete subtree with attributes and
// in-scope namespaces, using the original ancestor context. [WriteNodeSet]
// processes precisely the supplied selection; it does not evaluate XPath or add
// descendants merely because their parent was selected.
//
// An explicit node set can be sparse, so its canonical output may be an XML
// fragment rather than a well-formed document. Inclusive algorithms apply their
// respective inherited xml:* and xml:base rules to omitted ancestors.
// Input is the parsed node model supplied by document, including its line-end
// and attribute normalization. The default DTD-free parser does not expand
// declared entities or supply DTD defaults; [document.ParseOptions] can enable
// that preprocessing before canonicalization. The writer does not perform DTD
// processing itself and rejects relative namespace names accepted by that mode.
// These contracts do not establish full XML processor conformance.
//
// # Algorithms and output
//
// An empty [Options.Algorithm] selects [Exclusive]. [Options.InclusivePrefixes]
// is supported only by [Exclusive] and [ExclusiveWithComments]. A nonempty
// list with Canonical XML 1.0 or 1.1 returns an error matching
// [document.ErrUnsupported], including when comments are enabled.
//
// Canonicalization writes incrementally from an already retained snapshot.
// Escaping uses fixed-size buffers even for large text or attribute values;
// attribute sorting and namespace state need additional storage that grows with
// element width, ancestor depth and bindings. Scratch storage is reused across
// siblings. No complete canonical byte buffer is built unless the destination
// collects it. This API retains the input tree and any supplied node set.
// It leaves the input unchanged.
// [Options.MaxOutputBytes] bounds emitted bytes. Blocking writers must support
// cancellation themselves.
// Canonical bytes alone establish neither a valid signature nor application trust.
//
// # Errors
//
// Use [errors.Is] with errors from [WriteDocument], [WriteElement] and
// [WriteNodeSet].
//
//   - [document.ErrMalformed] covers a nil context or writer, a missing document,
//     an invalid element or node set, or an invalid inclusive prefix.
//   - [document.ErrUnsupported] covers an unknown algorithm, a relative
//     namespace name, or a nonempty inclusive prefix list used with Canonical
//     XML 1.0 or 1.1.
//   - [document.ErrLimit] covers a negative output budget, output that would
//     exceed the budget, or a list of more than 128 inclusive prefixes.
//   - [context.Canceled] and [context.DeadlineExceeded] report cancellation and
//     deadline expiry.
//   - [io.ErrShortWrite] covers a short write without an error or an invalid
//     byte count. Errors from a conforming destination writer are preserved for
//     [errors.Is] as well.
//
// After any error, discard the output and any hash state that consumed it.
package c14n
