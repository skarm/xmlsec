// Package state retains pending, solicited SAML requests and their browser
// correlation data. It supports request lookup without letting an unauthenticated
// response consume a legitimate login attempt.
//
// # Store pending requests
//
// [Pending] records partner IDs, request ID, RelayState, the chosen ACS, requested
// authentication conditions and expiration. [BrowserDigest] hashes an
// application-generated browser/session secret; the application must generate
// and protect that secret separately from RelayState.
//
// [Store.Put] inserts without replacing an unexpired request. [Store.Get] returns
// owned, unexpired state without removing it. Successful lookup is not one-time
// acceptance: the SP performs protocol/browser checks and then atomically consumes
// identifiers through github.com/skarm/xmlsec/saml/replay.
//
// # Memory and deployment
//
// [NewMemoryStore] constructs a concurrency-safe store bounded by [Config]. Expired
// entries are pruned during Put and Get; unexpired entries are never evicted to
// make room, and capacity exhaustion returns [ErrCapacity]. Stored values and
// returned request context lists are copied.
//
// [MemoryStore] coordinates one process. Multi-instance deployments need a shared Store
// and shared atomic replay storage. This package manages neither browser cookies
// nor application sessions.
package state
