// Package keyinfo builds and reads bounded XMLDSig key descriptions. It
// preserves key candidates and X509Data selectors as untrusted hints; parsing
// never establishes an identity, trust anchor or valid signature.
//
// # Build or inspect descriptions
//
// [Build] creates a standalone KeyInfo document from [Template]. Public keys
// use XML KeyValue or DEREncodedKeyValue; Ed25519 requires the DER
// representation. Building does not resolve references or sign the result.
//
// [Parse] reads an explicitly selected KeyInfo in an immutable document and
// returns a [Result] containing [Candidate] values, names and [X509Group]
// collections. Accessors copy mutable key/certificate data. X509Data grouping
// and selector spellings are retained without inferring chain relationships or
// trust.
//
// # References and representation policy
//
// [Options.AllowedKeyData] selects expanded QNames: nil permits supported
// forms, while an explicit empty list denies all. KeyInfoReference and the
// supported RetrievalMethod forms use bounded resolution with cycle detection.
// External resources require an exact URI allowlist and [ResourceResolver].
// RetrievalMethod transforms are restricted to the supported raw-certificate
// Base64 case.
//
// Key discovery can precede signature authentication, so resolvers must
// constrain access and honor cancellation. The package supplies no network
// client. Use an application trust selector with
// github.com/skarm/xmlsec/xmldsig, and compose github.com/skarm/xmlsec/pki when
// certificate trust is required.
//
// Parsing retains bounded XML and key/certificate/CRL models. Decoded blob and
// aggregate budgets are checked before allocation. Within one Parse invocation,
// a resource URI cannot have conflicting XML/certificate or encoded/raw forms.
package keyinfo
