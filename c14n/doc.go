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
//
// # Algorithms and output
//
// An empty [Options.Algorithm] selects [Exclusive]. InclusivePrefixes applies only
// to Exclusive C14N: #default names the default namespace, and the prefix list
// does not reselect omitted namespace nodes or rewrite QName-valued strings.
//
// Canonicalization writes incrementally from an already retained snapshot.
// Escaping uses fixed-size buffers even for large text or attribute values;
// attribute sorting and namespace state need additional storage that grows with
// element width, ancestor depth and bindings. Scratch storage is reused across
// siblings. No complete canonical byte buffer is built unless the destination
// collects it. This API retains the input tree and any supplied node set.
// It leaves the input unchanged.
// MaxOutputBytes bounds emitted bytes. Discard all partial output after any error,
// including cancellation or a writer failure, along with any hash state fed by
// that output. Blocking writers must support cancellation themselves.
// Canonical bytes alone establish neither a valid signature nor application trust.
package c14n
