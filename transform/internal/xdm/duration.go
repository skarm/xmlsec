// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import (
	"math"
	"math/big"
)

// Exact-duration reconstruction uses this binary precision and half-second
// rounding offset after removing the exact fractional component.
const (
	durationRecoveryPrecisionBits = 256
	durationRecoveryHalfSecond    = 0.5
)

// DurationToRat's selector chooses total months or total day-time seconds.
// Map-key normalization uses both representations to preserve duration identity.
const (
	durationMonthsMode  = true
	durationSecondsMode = false
)

// DurationToRat converts a Duration to an exact big.Rat value.
// For yearMonthDuration, the value is total months; for dayTimeDuration, total seconds.
func DurationToRat(d Duration, isYM bool) *big.Rat {
	var r *big.Rat
	if isYM {
		r = new(big.Rat).SetInt64(int64(d.Months))
	} else if d.SecRat != nil {
		// SecRat holds the EXACT total dayTime seconds magnitude (>=0). Prefer it
		// over the lossy float64 Seconds field so that values beyond 2^53 (e.g.
		// PT9007199254740992S vs PT9007199254740993S) stay distinct.
		r = new(big.Rat).Set(d.SecRat)
	} else {
		// d.Seconds is the total seconds INCLUDING any fractional part, while
		// d.FracSec (when set) holds the exact fractional component in [0,1).
		// Building the rational from d.Seconds and then adding d.FracSec would
		// double-count the fraction. When FracSec is present, derive the
		// whole-second count and add the exact fraction once.
		secs := d.Seconds
		if d.FracSec != nil {
			// Recover the whole-second count by removing the (possibly rounded)
			// fractional part from Seconds before truncation. Subtracting FracSec
			// first prevents float64 rounding from inflating the integer portion
			// for fractions extremely close to 1 (e.g. PT0.999...9S where Seconds
			// rounds up to 1.0).
			fracFloat, _ := d.FracSec.Float64()
			secs = math.Trunc(d.Seconds - fracFloat + durationRecoveryHalfSecond)
		}
		// Use big.Float → big.Rat to handle values exceeding int64 range
		bf := new(big.Float).SetPrec(durationRecoveryPrecisionBits).SetFloat64(secs)

		r, _ = bf.Rat(new(big.Rat))
		if d.FracSec != nil {
			r.Add(r, d.FracSec)
		}
	}

	if d.Negative {
		r.Neg(r)
	}

	return r
}
