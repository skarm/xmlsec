// Package replay records scoped SAML identifiers for atomic replay rejection.
// It supplies a store contract for protocol orchestrators and a bounded,
// concurrency-safe in-memory implementation.
//
// # Atomic consumption
//
// [Store.Consume] records every supplied [Entry] or none. Combine identifiers that
// must succeed together, such as request, response and assertion IDs, in one call
// rather than using separate check-then-insert operations. Call only after
// cryptographic, protocol and browser-correlation checks have succeeded.
// An unexpired identifier already present in the store causes [ErrReplay].
//
// # Memory and deployment
//
// [NewMemoryStore] constructs a [MemoryStore] store with explicit capacity and TTL limits.
// Consume prunes expired entries but never evicts unexpired records to admit new
// ones. Capacity exhaustion returns [ErrCapacity] without partial insertion.
// [MemoryStore.Len] reports the stored count without pruning.
//
// Memory coordinates one process. Multi-instance SP/IdP deployments require a
// shared Store with the same all-or-none contract and trusted expiration handling.
// Store callbacks must honor context; cancellation after a committed consumption
// does not roll it back. The store records acceptance decisions and does not verify
// XML or authenticate a user itself.
package replay
