package xdm //nolint:testpackage // Verifies that cloned floats detach their private big.Float storage.

import (
	"math"
	"testing"
)

func sameFloat(a, b float64) bool {
	return (math.IsNaN(a) && math.IsNaN(b)) || (a == b && math.Signbit(a) == math.Signbit(b))
}

func TestFloatRoundingAndNegation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ input, want float64 }{{16777217, 16777216}, {math.MaxFloat64, math.Inf(1)}, {-math.MaxFloat64, math.Inf(-1)}, {math.SmallestNonzeroFloat64, 0}, {-math.SmallestNonzeroFloat64, math.Copysign(0, -1)}, {math.NaN(), math.NaN()}, {math.Copysign(0, -1), math.Copysign(0, -1)}} {
		value := NewFloat(tc.input)
		if !sameFloat(value.Float64(), tc.want) || value.Precision() != PrecisionFloat {
			t.Fatalf("single(%g)=%g (%d bits); want %g", tc.input, value.Float64(), value.Precision(), tc.want)
		}
	}
	for _, input := range []float64{1.5, -2.5, 0, math.Copysign(0, -1), math.Inf(1), math.Inf(-1), math.NaN()} {
		value := NewDouble(input)
		negated := value.Neg()
		if !sameFloat(value.Float64(), input) || !sameFloat(negated.Float64(), -input) || negated.Precision() != PrecisionDouble {
			t.Fatalf("negation %g => %g changed input/precision", input, negated.Float64())
		}
		if value.IsNaN() != math.IsNaN(input) || value.IsInf(0) != math.IsInf(input, 0) || value.IsInf(1) != math.IsInf(input, 1) || value.IsInf(-1) != math.IsInf(input, -1) || value.IsZero() != (input == 0) || value.Signbit() != (!math.IsNaN(input) && math.Signbit(input)) {
			t.Fatalf("IEEE classification %g", input)
		}
		wantSpecial := math.IsNaN(input) || math.IsInf(input, 0) || (input == 0 && math.Signbit(input))
		if value.IsSpecial() != wantSpecial {
			t.Fatalf("special classification %g", input)
		}
		narrowed := value.WithPrecision(PrecisionFloat)
		if narrowed.Precision() != PrecisionFloat || !sameFloat(narrowed.Float64(), input) || value.Precision() != PrecisionDouble {
			t.Fatalf("precision change lost special/value %g", input)
		}
	}
	high := NewDouble(16777217)
	low := high.WithPrecision(PrecisionFloat)
	if low.Float64() != 16777216 || high.Float64() != 16777217 {
		t.Fatal("WithPrecision did not independently round finite value")
	}
}

func TestFloatCloneDetachesBigFloat(t *testing.T) {
	t.Parallel()

	original := NewDouble(1.25)
	cloned := CloneItem(AtomicValue{TypeName: TypeDouble, Value: original}).(AtomicValue).FloatVal()
	original.bf.SetInt64(99)
	if cloned.Float64() != 1.25 || cloned.Precision() != PrecisionDouble {
		t.Fatal("atomic float clone retained mutable magnitude")
	}
	for _, input := range []float64{math.NaN(), math.Inf(-1), math.Copysign(0, -1)} {
		value := NewFloat(input)
		cloned := value.clone()
		value.bf.SetPrec(PrecisionDouble)
		if !sameFloat(cloned.Float64(), input) || cloned.Precision() != PrecisionFloat {
			t.Fatal("special float clone did not detach precision/state")
		}
	}
	var absent *FloatValue
	if absent.clone() != nil {
		t.Fatal("nil clone did not preserve nil")
	}
}
