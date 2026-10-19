// Package timestamp creates and verifies RFC 3161 timestamp requests, responses
// and CMS tokens with RFC 5816 certificate binding. Applications supply TSA
// trust, policy identifiers, time and any transport.
//
// # Request, issue and inspect
//
// [CreateRequest] binds data to a message imprint and generates a nonce unless
// the caller explicitly supplies or omits it. Keep the [Request] for response
// checking. [IssueResponse] signs caller-supplied policy, serial number and
// time assertions; it is an encoder, not a trusted clock or a complete TSA
// service.
//
// [ParseRequest], [ParseResponse] and [InspectToken] expose unverified
// structure. Parsing or reading a token's claimed GenTime does not establish
// trusted time.
//
// # Verify evidence
//
// [NewVerifier] requires explicit roots, permitted TSA policies and a
// revocation policy or an explicit unchecked-revocation opt-in.
// [Verifier.VerifyResponse] checks the response against its original request.
// [Verifier.VerifyToken] requires an expected imprint and any required
// nonce/policy binding. Successful [Result] values contain authenticated token
// information and the TSA trust result.
//
// PKIX and freshness checks use the explicit verification time, never silently
// the token's claimed GenTime. The TSA certificate must meet this profile's
// critical, timeStamping-only EKU requirement. This is current-time evidence
// validation, not general historical AdES or archive recovery.
//
// # Transport boundary
//
// [Verifier.Fetch] invokes an application-owned [Transport], bounds and closes
// its response stream, then verifies it against the request. The package never
// opens network connections itself. The transport and its reader must honor
// context cancellation, including during blocked I/O.
//
// # Input and storage
//
// [ImprintReader] and [CreateRequestReader] hash arbitrary-length messages with
// bounded working storage and explicit cancellation. [WriteResponse] issues
// directly to a writer; [IssueResponse] collects that output.
// [ParseTokenReader] creates an immutable [Token]. Its [Token.UnverifiedInfo]
// supports choosing an imprint hash; [Verifier.Verify] must authenticate the
// token before those claims are accepted. [Result.Token] returns the same
// immutable model and [Token.WriterTo] emits its DER without copying it.
// DER/certificate getters still return owned copies. [ParseResponseReader] and
// [Verifier.VerifyResponseReader] read definite-length DER into a bounded
// response buffer; response verification parses the CMS token once into
// separate owned storage. The temporary response buffer and parsed token can
// coexist; this is not constant-memory token parsing. [Verifier.Fetch] uses
// this path and closes its transport response.
package timestamp
