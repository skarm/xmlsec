// Package binding encodes SAML HTTP-POST forms and signs or verifies the
// HTTP-Redirect DEFLATE binding. It handles transport representation and
// binding integrity, with separate protocol and session checks in higher-level
// packages.
//
// # HTTP-POST
//
// [EncodePOST] serializes XML to form fields without signing it. [DecodePOST]
// returns an unauthenticated [POSTMessage]; callers must verify its XML and
// protocol expectations before accepting it. [RenderPOSTForm] builds an HTML
// form for a trusted destination, without scripts or automatic navigation.
//
// # HTTP-Redirect
//
// [SignRedirect] returns a raw query component for an endpoint chosen from
// trusted configuration or metadata. [VerifyRedirect] authenticates the
// original encoded query values before inflation and XML parsing. Pass the
// received raw query; re-encoding parsed parameters changes the bytes protected
// by the signature. Limits bound query, compressed data, decompressed XML and
// parsing work.
//
// RelayState is opaque and distinguishes absence from a present empty string.
// It is not an authorized redirect destination. A [RedirectResult] proves
// binding integrity with a trusted key, not accepted issuer, audience,
// destination, request correlation, replay rejection or an authenticated
// browser session. Use github.com/skarm/xmlsec/saml/protocol for message
// validation and github.com/skarm/xmlsec/saml/sp or
// github.com/skarm/xmlsec/saml/idp for stateful flows.
//
// [WritePOST] and [WritePOSTForm] serialize XML through Base64 and escaping
// directly into a caller-owned writer. Byte-returning form methods collect the
// same output path. Writer failures may leave partial forms, which must be
// discarded. [DecodePOSTReader] decodes form fields and XML incrementally,
// retaining the document and small RelayState; it validates trailing fields
// before returning. HTTP-Redirect queries remain complete strings for their
// signed wire representation. Inflation and XML parsing run only after
// signature verification. Protocol XML snapshots remain materialized.
package binding
