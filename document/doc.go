// Package document parses and navigates immutable, namespace-aware XML
// snapshots. It supplies the shared document and node handles used by
// canonicalization, signature, encryption and transform packages.
//
// # Parse and navigate
//
// [Parse] accepts a context and explicit [Limits]; [DefaultLimits] supplies the
// default resource policy. [ParseReader] consumes a reader incrementally while
// retaining the complete tree and current lexical token. A large text node,
// comment or start tag can require token-sized storage. [ReadRecords] emits
// independent subtrees without constructing the enclosing tree. Start at
// Document.Root and navigate elements, attributes and other node kinds without
// exposing a mutable tree. [Name] uses an expanded namespace URI and local
// name, independent of the source prefix. The parser accepts UTF-8 and UTF-16
// XML 1.0. The default rejects DTDs and external entities; ID
// attributes are configured by consumers. Names follow XML 1.0 Fifth Edition,
// including supplementary characters through U+EFFFF. This is not a complete
// XML processor conformance claim.
//
// In the default mode, nonempty namespace names must be absolute URIs. The
// parser normalizes XML line endings and literal attribute whitespace, expands
// character references and the five predefined entities, and preserves the
// resulting Unicode sequence. The default parser invokes no resource resolver.
//
// [ParseOptions] with NonValidating enables a separate bounded XML 1.0
// nonvalidating processor: DTD entities, attribute defaults and normalization,
// Namespaces 1.0 relative namespace names and supported single-byte encodings.
// XML 1.x declarations are processed using XML 1.0 syntax. External subsets and
// entities require an explicit [EntityResolver]; there is no automatic I/O.
// DTD notation, unparsed-entity and processing-instruction information is
// available through Document.DTD as owned copies. Serialization writes the
// expanded tree and omits the original DTD. DTD validity and XSD validation are
// not performed. Security consumers must deliberately choose their input mode.
//
// # Node selections and output
//
// [NewNodeSet] selects individual nodes from one snapshot. Selecting an element
// does not select its attributes, namespace nodes or descendants. Use
// Element.Subtree or Document.AllNodes to construct complete selections. An
// empty initialized set is valid; the zero [NodeSet] is not.
//
// Document.XML and Document.WriteXML produce ordinary UTF-8 serialization,
// without an XML declaration. They preserve document content but do not produce
// canonical bytes; use github.com/skarm/xmlsec/c14n for signature digest input.
// Both accept cancellation. XML collects the complete output; WriteXML writes
// incrementally with an explicit output byte limit. Parse limits do not impose
// a separate serialized-output budget on XML. WriteXML leaves its destination
// open; arbitrary blocked I/O requires cancellation support from the stream.
//
// # Ownership
//
// Parsed documents own their data and support concurrent reads. An [Element],
// [Node] or [NodeSet] belongs to exactly one [Document]. After signing,
// replacing, decrypting or reparsing XML, use handles from the returned
// snapshot rather than carrying handles across documents. Operations that
// publish a changed snapshot retain both source and result trees until the new
// snapshot has been validated. Data and node limits constrain accepted input,
// not exact Go heap usage or RSS.
package document
