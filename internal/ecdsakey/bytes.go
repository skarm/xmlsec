// Package ecdsakey encodes caller-supplied ECDSA keys without panicking on
// malformed key values.
package ecdsakey

import (
	"crypto/ecdsa"
	"errors"
)

// ErrInvalid reports an incomplete ECDSA key that cannot be encoded.
var ErrInvalid = errors.New("invalid ECDSA key")

// PublicBytes returns the uncompressed encoding of key, or an error for an
// invalid key, including a nil key or missing coordinates.
func PublicBytes(key *ecdsa.PublicKey) (raw []byte, err error) {
	if key == nil {
		return nil, ErrInvalid
	}

	// Go 1.27's Bytes method dereferences nil coordinates in malformed keys.
	// Confine recovery to this standard-library encoding call.
	defer func() {
		if recover() != nil {
			raw, err = nil, ErrInvalid
		}
	}()

	return key.Bytes()
}

// PrivateBytes returns the raw scalar encoding of key, or an error for an
// invalid key, including a nil key or missing coordinates or scalar.
func PrivateBytes(key *ecdsa.PrivateKey) (raw []byte, err error) {
	if key == nil {
		return nil, ErrInvalid
	}

	// Go 1.27's Bytes method dereferences nil fields in malformed keys.
	// Confine recovery to this standard-library encoding call.
	defer func() {
		if recover() != nil {
			raw, err = nil, ErrInvalid
		}
	}()

	return key.Bytes()
}
