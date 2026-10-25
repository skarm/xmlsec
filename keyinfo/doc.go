// Package keyinfo builds and reads bounded XMLDSig key descriptions. It
// preserves key candidates and X509Data selectors as untrusted hints; parsing
// never establishes an identity, trust anchor or valid signature.
//
// # Build or inspect descriptions
//
// [Build] creates a standalone KeyInfo document from [Template]. Public keys
// use XML KeyValue or DEREncodedKeyValue; Ed25519 requires the DER
// representation. Building does not resolve references or sign the result.
// Legacy DSA builders emit complete 1024/160 P/Q/G/Y parameters. Parsing can
// fill omitted P/Q/G only from [Options.DSAParameters], an explicit, snapshotted
// application context. Optional generation hints establish neither provenance
// nor trust. Other DSA parameter sizes remain unsupported.
//
// [Parse] reads an explicitly selected KeyInfo in an immutable document and
// returns a [Result] containing [Candidate] values, names and [X509Group]
// collections. Accessors copy mutable key/certificate data. X509Data grouping
// and selector spellings are retained without inferring chain relationships or
// trust.
// [Template.X509Data] builds separate nonempty groups of certificates, v2 CRLs,
// issuer/serial pairs, subject names, plain subject key identifiers and certificate
// digests. [Template.Certificates] retains its separate first group. Original DER
// bytes and supplied DN spellings are preserved; serial numbers use the same
// bounded nonnegative decimal normalization as Parse. Build does not match hints
// against certificates. Selector-only groups produce no key candidates and cause
// no lookup. Use signed references to KeyInfo/X509Data when their metadata must be
// authenticated, then apply the application's selector and certificate policy.
//
// # References and representation policy
//
// [Options.AllowedKeyData] selects expanded QNames: nil permits supported
// forms, while an explicit empty list denies all. KeyInfoReference and the
// supported RetrievalMethod forms use bounded resolution with cycle detection.
// External resources require an exact URI allowlist and [ResourceResolver].
// [ExternalResources.BaseURI] explicitly enables relative URI and inherited
// xml:base resolution, using the containing resource's retrieval URI for nested
// links. Authorize the complete resolved URI, including any fragment; the
// resolver returns its identified octets or standalone XML. There is no automatic
// external XML selector. Empty and fragment-only links stay in their own document.
// Signed-data and KeyInfo resource permissions remain separate.
// The default RetrievalMethod policy permits raw certificates and one optional
// Base64 transform. [Options.RetrievalProcessing] opts into the shared reference
// processor: Base64, all six C14N algorithms, enveloped, and explicitly approved
// XPath/Filter2/XSLT programs. Parameter parsing is shared with XMLDSig. Type
// applies after the complete chain; XML results must form one bounded document.
// Byte/node budgets apply across chains, including repeated links. Transformed
// snapshots retain graph identity for cycle detection.
//
// Key discovery can precede signature authentication, so resolvers must
// constrain access and honor cancellation. The package supplies no network
// client. Use an application trust selector with
// github.com/skarm/xmlsec/xmldsig, and compose github.com/skarm/xmlsec/pki when
// certificate trust is required.
//
// Parsing retains bounded XML and key/certificate/CRL models. Decoded blob and
// aggregate budgets are checked before allocation. Within one Parse invocation,
// the default resource policy rejects conflicting XML/certificate or encoded/raw
// forms. Explicit RetrievalProcessing instead caches the immutable original
// resource bytes once and applies each authorized interpretation to that source.
package keyinfo
