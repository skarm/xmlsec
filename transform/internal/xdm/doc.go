// Package xdm provides the values, sequences, node identity and navigation
// shared by the XPath and XSLT processors. Node views borrow internal/tree
// storage; parsing and XML serialization use the project parser and writer.
// The package does not depend on either language compiler or evaluator.
//
// Documents remain mutable during construction. Call Freeze before publishing
// a view for shared use, and keep its underlying storage and metadata unchanged
// while readers retain it. FromDocument caches a frozen view; WrapDocument
// creates an unfrozen view over caller-owned storage.
//
// ParseOptions selects XML limits, DTD processing and byte-encoding policy.
// External resources require explicit resolvers. Serializer callbacks and
// resource adapters retain responsibility for their own concurrency safety.
package xdm
