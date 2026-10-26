package xdm_test

import (
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestNumericConversionsRespectPrecisionAndBaseType(t *testing.T) {
	t.Parallel()

	for _, value := range []any{float64(16777217), float32(16777216), xdm.NewDouble(16777217)} {
		a := xdm.AtomicValue{TypeName: "Q{u}float", BaseType: xdm.TypeFloat, Value: value}
		if a.ToFloat64() != 16777216 || a.DoubleVal() != 16777216 || a.FloatVal().Float64() != 16777216 || a.FloatVal().Precision() != xdm.PrecisionFloat {
			t.Fatalf("float narrowing failed for %T", value)
		}
	}
	for _, value := range []any{float64(16777217), xdm.NewDouble(16777217)} {
		a := xdm.AtomicValue{TypeName: "Q{u}double", BaseType: xdm.TypeDouble, Value: value}
		if a.ToFloat64() != 16777217 || a.FloatVal().Float64() != 16777217 || a.FloatVal().Precision() != xdm.PrecisionDouble {
			t.Fatalf("double incorrectly narrowed for %T", value)
		}
	}
	for _, a := range []xdm.AtomicValue{{TypeName: xdm.TypeInteger, Value: int64(25)}, {TypeName: "Q{u}integer", BaseType: xdm.TypeLong, Value: big.NewInt(25)}, {TypeName: "Q{u}decimal", BaseType: xdm.TypeDecimal, Value: big.NewRat(25, 1)}} {
		if !a.IsNumeric() || a.ToFloat64() != 25 {
			t.Fatalf("numeric conversion: %v", a)
		}
	}

	decimal := xdm.AtomicValue{TypeName: "Q{u}decimal", BaseType: xdm.TypeDecimal, Value: big.NewRat(-1, 8)}
	if decimal.ToFloat64() != -0.125 {
		t.Fatal("decimal conversion discarded fractional magnitude/sign")
	}

	a := xdm.AtomicValue{TypeName: xdm.TypeInteger, BaseType: xdm.TypeFloat, Value: int64(16777217)}
	if a.ToFloat64() != 16777217 {
		t.Fatal("builtin numeric type did not take precedence over BaseType")
	}
	for _, value := range []any{int64(math.MinInt64), big.NewInt(math.MaxInt64)} {
		a := xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: value}
		n, ok := a.Int64Val()
		if !ok || n != a.IntegerVal() {
			t.Fatalf("in-range Int64Val: %d,%v", n, ok)
		}
	}
	over := new(big.Int).Lsh(big.NewInt(1), 63)
	if n, ok := (xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: over}).Int64Val(); ok || n != 0 {
		t.Fatalf("overflow Int64Val: %d,%v", n, ok)
	}
	if n, ok := (xdm.AtomicValue{TypeName: xdm.TypeString, Value: "1"}).Int64Val(); ok || n != 0 {
		t.Fatalf("string Int64Val: %d,%v", n, ok)
	}
	if (xdm.AtomicValue{Value: "123456789012345678901234567890"}).BigInt().String() != "123456789012345678901234567890" || (xdm.AtomicValue{Value: int64(-7)}).BigInt().Int64() != -7 {
		t.Fatal("BigInt parse/promotion")
	}
	if (xdm.AtomicValue{Value: "3/7"}).BigRat().Cmp(big.NewRat(3, 7)) != 0 {
		t.Fatal("BigRat rational parsing")
	}
	for _, value := range []any{"invalid", true} {
		if (xdm.AtomicValue{Value: value}).BigInt().Sign() != 0 || (xdm.AtomicValue{Value: value}).BigRat().Sign() != 0 {
			t.Fatal("invalid numeric input must return zero")
		}
	}
	if !(xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(math.NaN())}).IsNaN() || (xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(1)}).IsNaN() || (xdm.AtomicValue{TypeName: xdm.TypeString, Value: "NaN"}).IsNaN() {
		t.Fatal("atomic NaN classification")
	}
	if (xdm.AtomicValue{TypeName: xdm.TypeString, Value: "5"}).IsNumeric() {
		t.Fatal("numeric-looking string classified numeric")
	}
}

func TestAtomicCloningDetachesMutablePayloads(t *testing.T) {
	t.Parallel()

	integer := big.NewInt(7)
	rational := big.NewRat(3, 4)
	binary := []byte{1, 2}
	fraction, total := big.NewRat(1, 4), big.NewRat(5, 4)
	duration := xdm.Duration{Seconds: 1.25, FracSec: fraction, SecRat: total}
	original := xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: integer}, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: rational}, xdm.AtomicValue{TypeName: xdm.TypeHexBinary, Value: binary}, xdm.AtomicValue{TypeName: xdm.TypeDuration, Value: duration}, xdm.AtomicValue{TypeName: xdm.TypeDuration, Value: &duration}}
	clone := xdm.CloneSequence(original)
	integer.SetInt64(99)
	rational.SetInt64(99)
	binary[0] = 99
	fraction.SetInt64(99)
	total.SetInt64(99)
	if clone.Get(0).(xdm.AtomicValue).BigInt().Int64() != 7 || clone.Get(1).(xdm.AtomicValue).BigRat().Cmp(big.NewRat(3, 4)) != 0 || !reflect.DeepEqual(clone.Get(2).(xdm.AtomicValue).BytesVal(), []byte{1, 2}) {
		t.Fatal("atomic numeric/binary clone aliases input")
	}
	for _, i := range []int{3, 4} {
		value := clone.Get(i).(xdm.AtomicValue).Value
		var d xdm.Duration
		if v, ok := value.(xdm.Duration); ok {
			d = v
		} else {
			d = *value.(*xdm.Duration)
		}
		if d.FracSec.Cmp(big.NewRat(1, 4)) != 0 || d.SecRat.Cmp(big.NewRat(5, 4)) != 0 {
			t.Fatal("duration clone aliases rational fields")
		}
	}
	// A flattened leaf must also be detached from the array's immutable storage.
	a := xdm.NewArray([]xdm.Sequence{clone})
	flattened := a.Flatten()
	flattened.Get(0).(xdm.AtomicValue).BigInt().SetInt64(500)
	member := requireArrayMember(t, a, 1)
	if member.Get(0).(xdm.AtomicValue).BigInt().Int64() != 7 {
		t.Fatal("flattened atomic mutated original array")
	}
}

func TestDurationExactSeconds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		d    xdm.Duration
		ym   bool
		want string
	}{
		{xdm.Duration{Months: 25, Seconds: 100, Negative: true}, true, "-25"},
		{xdm.Duration{Seconds: 1.5, FracSec: big.NewRat(1, 2)}, false, "3/2"},
		{xdm.Duration{Seconds: 1, FracSec: new(big.Rat).SetFrac(big.NewInt(999999999999999999), big.NewInt(1000000000000000000))}, false, "999999999999999999/1000000000000000000"},
		{xdm.Duration{Seconds: 9007199254740992, SecRat: new(big.Rat).SetInt(new(big.Int).SetUint64(9007199254740993)), Negative: true}, false, "-9007199254740993"},
		{xdm.Duration{Seconds: 2.5, Negative: true}, false, "-5/2"},
		{xdm.Duration{Negative: true}, false, "0"},
	}
	for _, tc := range cases {
		want, ok := new(big.Rat).SetString(tc.want)
		if !ok {
			t.Fatal("bad fixture")
		}
		var originalSeconds, originalFraction *big.Rat
		if tc.d.SecRat != nil {
			originalSeconds = new(big.Rat).Set(tc.d.SecRat)
		}
		if tc.d.FracSec != nil {
			originalFraction = new(big.Rat).Set(tc.d.FracSec)
		}
		got := xdm.DurationToRat(tc.d, tc.ym)
		if got.Cmp(want) != 0 {
			t.Fatalf("duration %+v YM%v: %s; want %s", tc.d, tc.ym, got, want)
		}
		got.SetInt64(999)
		if originalSeconds != nil && tc.d.SecRat.Cmp(originalSeconds) != 0 {
			t.Fatal("conversion result aliases source seconds")
		}
		if originalFraction != nil && tc.d.FracSec.Cmp(originalFraction) != 0 {
			t.Fatal("conversion result aliases source fraction")
		}
	}
}

func TestDecimalRendering(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value *big.Rat
		want  string
	}{{big.NewRat(0, 1), "0"}, {big.NewRat(-10, 1), "-10"}, {big.NewRat(1, 8), "0.125"}, {big.NewRat(-1, 200), "-0.005"}, {big.NewRat(1, 3), "0.33333333333333333333"}} {
		if got := xdm.DecimalToString(tc.value); got != tc.want {
			t.Fatalf("decimal %s rendered %q; want %q", tc.value, got, tc.want)
		}
	}
}

func TestSchemaTypePromotionAndAncestry(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value any
		want  string
	}{{int64(1), xdm.TypeInteger}, {big.NewInt(1), xdm.TypeInteger}, {big.NewRat(1, 2), xdm.TypeDecimal}, {xdm.NewDouble(1), xdm.TypeDouble}, {float64(1), xdm.TypeDouble}, {true, xdm.TypeBoolean}, {"s", xdm.TypeString}, {time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), xdm.TypeDateTime}, {xdm.Duration{}, xdm.TypeDuration}, {[]byte{1}, xdm.TypeBase64Binary}, {xdm.QNameValue{Local: "n"}, xdm.TypeQName}} {
		got := xdm.PromoteSchemaType(xdm.AtomicValue{TypeName: "Q{u}custom", Value: tc.value})
		if got.TypeName != tc.want || !reflect.DeepEqual(got.Value, tc.value) {
			t.Fatalf("promotion for %T: %v", tc.value, got)
		}
	}
	builtin := xdm.AtomicValue{TypeName: xdm.TypeDate, BaseType: xdm.TypeString, Value: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}
	if !reflect.DeepEqual(xdm.PromoteSchemaType(builtin), builtin) {
		t.Fatal("builtin type changed by promotion")
	}
	custom := xdm.AtomicValue{TypeName: "Q{u}date", BaseType: xdm.TypeDate, Value: builtin.Value}
	if xdm.PromoteSchemaType(custom).TypeName != xdm.TypeDate || !xdm.IsAtomicSubtypeOf(custom, xdm.TypeAnyAtomicType) || xdm.IsAtomicSubtypeOf(custom, xdm.TypeDateTime) {
		t.Fatal("custom date's base type not respected")
	}
	unknown := xdm.AtomicValue{TypeName: "Q{u}unknown", Value: struct{}{}}
	if !reflect.DeepEqual(xdm.PromoteSchemaType(unknown), unknown) || xdm.IsAtomicSubtypeOf(unknown, xdm.TypeString) {
		t.Fatal("unknown type inferred without valid backing")
	}
	if xdm.IsAtomicSubtypeOf(xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: builtin.Value}, xdm.TypeDate) {
		t.Fatal("sibling date/dateTime types conflated")
	}
	for _, tc := range [][2]string{{xdm.TypeByte, xdm.TypeInteger}, {xdm.TypeUnsignedByte, xdm.TypeDecimal}, {xdm.TypePositiveInteger, xdm.TypeNumeric}, {xdm.TypeNegativeInteger, xdm.TypeDecimal}, {xdm.TypeID, xdm.TypeString}, {xdm.TypeENTITY, xdm.TypeToken}, {xdm.TypeDateTimeStamp, xdm.TypeDateTime}, {xdm.TypeDayTimeDuration, xdm.TypeDuration}} {
		if !xdm.IsSubtypeOf(tc[0], tc[1]) || !xdm.BuiltinIsSubtypeOf(tc[0], tc[1]) || xdm.IsSubtypeOf(tc[1], tc[0]) {
			t.Fatalf("subtype direction: %v", tc)
		}
	}
	if !xdm.IsSubtypeOf(xdm.TypeDouble, xdm.TypeNumeric) || !xdm.IsSubtypeOf(xdm.TypeFloat, xdm.TypeNumeric) || xdm.IsSubtypeOf(xdm.TypeBoolean, xdm.TypeNumeric) || xdm.IsSubtypeOf("Q{u}unknown", xdm.TypeAnyType) {
		t.Fatal("numeric or unknown ancestry")
	}
	if !xdm.IsStringDerived(xdm.TypeNCName) || xdm.IsStringDerived(xdm.TypeInteger) || !xdm.IsKnownXSDType(xdm.TypeNMTOKENS) || xdm.IsKnownXSDType("Q{u}unknown") {
		t.Fatal("derived type classification")
	}
}

func TestSchemaAnnotationNames(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input, local, ns string
		ok               bool
	}{{"Q{urn:a}name", "name", "urn:a", true}, {"Q{}name", "name", "", true}, {"p:name", "name", "", true}, {"name", "name", "", true}, {"xs:string", "", "", false}, {"xsd:integer", "", "", false}, {"Q{broken", "", "", false}, {"Q{u}", "", "", false}, {"", "", "", false}} {
		local, ns, ok := xdm.SchemaAnnotationParts(tc.input)
		if local != tc.local || ns != tc.ns || ok != tc.ok {
			t.Fatalf("annotation %q: %q,%q,%v", tc.input, local, ns, ok)
		}
	}
	if xdm.QAnnotation("urn:a", "name") != "Q{urn:a}name" {
		t.Fatal("qualified annotation")
	}
}
