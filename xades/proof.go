// Adapted from greatliontech/xmldsig, validation.go (Indication) and lta.go
// (poeSet.addSig), commit e85d23950bbe14604ddf891307949c1151f436de.
// Copyright 2026 Great Lion Technologies. SPDX-License-Identifier: Apache-2.0
// Source: https://github.com/greatliontech/xmldsig/tree/e85d23950bbe14604ddf891307949c1151f436de
// The complete license is in licenses/Apache-2.0.txt.
// No upstream NOTICE file was present in this snapshot.
// Changes: restricted profile labels, immutable reports and timestamp accuracy
// upper bounds; no archive-object POE or full EN 319 102-1 recovery is exposed.

package xades

import (
	"time"
)

const (
	indicationFailed        = "failed"
	indicationIndeterminate = "indeterminate"
	indicationPassed        = "passed"
)

// Indication describes the outcome within the report's named profile. The zero
// value is Indeterminate and must never be treated as an acceptable signature.
type Indication uint8

const (
	// Indeterminate indicates that validation cannot establish the required result.
	Indeterminate Indication = iota
	// Passed indicates successful profile validation.
	Passed
	// Failed indicates failed profile validation.
	Failed
)

// String returns a human-readable name without serializing payload data.
func (i Indication) String() string {
	switch i {
	case Passed:
		return indicationPassed
	case Failed:
		return indicationFailed
	default:
		return indicationIndeterminate
	}
}

// signatureProof records only the earliest upper bound from a verified token.
// It can move earlier when another trusted proof is added, never later.
type signatureProof struct {
	// at is the earliest trusted upper bound retained for the signature proof.
	at time.Time
	// present distinguishes a recorded proof from the zero-value timestamp.
	present bool
}

// add retains t only when no proof exists or t establishes an earlier upper bound.
func (p *signatureProof) add(t time.Time) {
	if !p.present || t.Before(p.at) {
		p.at, p.present = t, true
	}
}
