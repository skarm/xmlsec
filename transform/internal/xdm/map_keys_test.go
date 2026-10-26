package xdm_test

import (
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestMapKeyValueEquality(t *testing.T) {
	t.Parallel()

	date := time.Date(2020, 2, 29, 12, 30, 0, 123, time.UTC)
	cases := []struct {
		name                  string
		key, equal, different xdm.AtomicValue
	}{
		{"numeric domain", xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(1)}, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: big.NewRat(2, 2)}, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: big.NewRat(11, 10)}},
		{"big integer", xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: new(big.Int).Lsh(big.NewInt(1), 2000)}, xdm.AtomicValue{TypeName: "Q{u}huge", BaseType: xdm.TypeInteger, Value: new(big.Int).Lsh(big.NewInt(1), 2000)}, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 2000), big.NewInt(1))}},
		{"exact decimal", xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: big.NewRat(9007199254740993, 2)}, xdm.AtomicValue{TypeName: "Q{u}decimal", BaseType: xdm.TypeDecimal, Value: big.NewRat(9007199254740993, 2)}, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: big.NewRat(9007199254740992, 2)}},
		{"float rounding", xdm.AtomicValue{TypeName: "Q{u}float", BaseType: xdm.TypeFloat, Value: float64(16777217)}, xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(16777216)}, xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(16777217)}},
		{"double integer boundary", xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: math.Ldexp(1, 63)}, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: new(big.Int).Lsh(big.NewInt(1), 63)}, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(math.MinInt64)}},
		{"negative zero", xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(math.Copysign(0, -1))}, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(0)}, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(-1)}},
		{"NaN", xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(math.NaN())}, xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(math.NaN())}, xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(math.Inf(1))}},
		{"infinity", xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: math.Inf(1)}, xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(math.Inf(1))}, xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: math.Inf(-1)}},
		{"URI string", xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: "urn:a"}, stringKey("urn:a"), stringKey("urn:b")},
		{"untyped string", xdm.AtomicValue{TypeName: xdm.TypeUntypedAtomic, Value: "a"}, stringKey("a"), stringKey("b")},
		{"derived string", xdm.AtomicValue{TypeName: "Q{u}token", BaseType: xdm.TypeToken, Value: "a"}, stringKey("a"), stringKey("b")},
		{"derived URI", xdm.AtomicValue{TypeName: "Q{u}uri", BaseType: xdm.TypeAnyURI, Value: "urn:a"}, stringKey("urn:a"), stringKey("urn:b")},
		{"QName prefix", xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{Prefix: "p", Local: "name", URI: "urn:a"}}, xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{Prefix: "q", Local: "name", URI: "urn:a"}}, xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{Prefix: "p", Local: "name", URI: "urn:b"}}},
		{"time zone", xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: date}, xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: date.In(time.FixedZone("offset", 3*3600))}, xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: date.Add(time.Nanosecond)}},
		{"absent time zone", xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: time.Date(2020, 2, 29, 12, 30, 0, 0, xdm.NoTimezone())}, xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: time.Date(2020, 2, 29, 12, 30, 0, 0, xdm.NoTimezone())}, xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: time.Date(2020, 2, 29, 12, 30, 0, 0, time.UTC)}},
		{"binary content", xdm.AtomicValue{TypeName: xdm.TypeHexBinary, Value: []byte{0, 255}}, xdm.AtomicValue{TypeName: xdm.TypeHexBinary, Value: []byte{0, 255}}, xdm.AtomicValue{TypeName: xdm.TypeHexBinary, Value: []byte{0, 254}}},
		{"boolean domain", xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: true}, xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: true}, xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: false}},
		{"duration", xdm.AtomicValue{TypeName: xdm.TypeDuration, Value: xdm.Duration{Seconds: 1.5, FracSec: big.NewRat(1, 2)}}, xdm.AtomicValue{TypeName: "Q{u}duration", BaseType: xdm.TypeDayTimeDuration, Value: xdm.Duration{SecRat: big.NewRat(3, 2)}}, xdm.AtomicValue{TypeName: xdm.TypeDuration, Value: xdm.Duration{Seconds: 1.25, FracSec: big.NewRat(1, 4)}}},
		{"duration zero", xdm.AtomicValue{TypeName: xdm.TypeYearMonthDuration, Value: xdm.Duration{Negative: true}}, xdm.AtomicValue{TypeName: xdm.TypeDayTimeDuration, Value: xdm.Duration{}}, xdm.AtomicValue{TypeName: xdm.TypeYearMonthDuration, Value: xdm.Duration{Months: 1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Exercise both the index-free single-entry and indexed lookup paths.
			for _, m := range []xdm.MapItem{xdm.SingleEntryMap(tc.key, xdm.SingleString("found")), xdm.NewMap([]xdm.MapEntry{{Key: tc.key, Value: xdm.SingleString("found")}, {Key: stringKey("unrelated"), Value: nil}})} {
				value, ok := m.Get(tc.equal)
				if !ok {
					t.Fatal("equal value missed stored key")
				}
				assertStringItems(t, value, "found")
				if m.Contains(tc.different) {
					t.Fatal("distinct value collided with stored key")
				}
			}
		})
	}
}
