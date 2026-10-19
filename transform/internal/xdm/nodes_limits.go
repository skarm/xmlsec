// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import "errors"

const (
	// DefaultMaxRecursionDepth is the maximum expression processing depth,
	// matching libxml2's XPATH_MAX_RECURSION_DEPTH.
	DefaultMaxRecursionDepth = 5000

	// DefaultMaxNodeSetLength is the maximum number of nodes in a node-set,
	// matching libxml2's XPATH_MAX_NODESET_LENGTH.
	DefaultMaxNodeSetLength = 10_000_000
)

// ErrNodeSetLimit is returned when a node-set exceeds DefaultMaxNodeSetLength.
var ErrNodeSetLimit = errors.New("xpath: node-set length limit exceeded")
