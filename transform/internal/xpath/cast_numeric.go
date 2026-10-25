// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"encoding/base64"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func castToDouble(v xdm.AtomicValue) (xdm.AtomicValue, error) {
	switch v.TypeName {
	case xdm.TypeDouble:
		return v, nil
	case xdm.TypeFloat:
		// Promote float to double precision (preserving the float32-precision value)
		return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(v.DoubleVal())}, nil
	case xdm.TypeInteger:
		if iv, ok := v.Value.(int64); ok {
			return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(float64(iv))}, nil
		}

		f, _ := new(big.Float).SetInt(v.BigInt()).Float64()

		return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(f)}, nil
	case xdm.TypeDecimal:
		f, _ := v.BigRat().Float64()
		return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(f)}, nil
	case xdm.TypeBoolean:
		if v.BooleanVal() {
			return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(1)}, nil
		}

		return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(0)}, nil
	case xdm.TypeString, xdm.TypeUntypedAtomic:
		return CastFromString(v.StringVal(), xdm.TypeDouble)
	default:
		// Integer-derived subtypes (xs:int, xs:long, xs:positiveInteger, …) store
		// their value as int64/*big.Int just like xs:integer, so promote through
		// the integer value space.
		if xdm.IsIntegerDerived(v.TypeName) {
			f, _ := new(big.Float).SetInt(v.BigInt()).Float64()
			return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(f)}, nil
		}

		if xdm.IsStringDerived(v.TypeName) {
			return CastFromString(v.StringVal(), xdm.TypeDouble)
		}
	}

	return xdm.AtomicValue{}, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("cannot cast %s to xs:double", v.TypeName)}
}

func castToFloat(v xdm.AtomicValue) (xdm.AtomicValue, error) {
	// When casting from string, use the xs:float lexical rules directly
	// (XSD 1.1 accepts "INF", lexicon.FloatNegINF, "+INF", "NaN")
	if v.TypeName == xdm.TypeString || v.TypeName == xdm.TypeUntypedAtomic || xdm.IsStringDerived(v.TypeName) {
		return castStringToFloat(strings.Trim(v.StringVal(), " \t\r\n"))
	}
	// For non-string sources, promote through double then narrow
	dbl, err := castToDouble(v)
	if err != nil {
		return xdm.AtomicValue{}, err
	}

	f := dbl.DoubleVal()

	return xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(f)}, nil
}

// castStringToFloat rounds directly to binary32, avoiding double rounding.
func castStringToFloat(s string) (xdm.AtomicValue, error) {
	f, err := parseXPathFloating(s, 32)
	if err != nil {
		return xdm.AtomicValue{}, castError(s, xdm.TypeFloat)
	}

	return xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(f)}, nil
}

func castToInteger(v xdm.AtomicValue) (xdm.AtomicValue, error) {
	switch v.TypeName {
	case xdm.TypeInteger:
		return v, nil
	case xdm.TypeDouble, xdm.TypeFloat:
		f := v.DoubleVal()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return xdm.AtomicValue{}, &xdm.Error{Code: errCodeFOCA0002, Message: "cannot cast NaN/INF to xs:integer"}
		}

		bi, _ := new(big.Float).SetFloat64(f).Int(nil)

		return xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: bi}, nil
	case xdm.TypeDecimal:
		// Truncate rational toward zero
		r := v.BigRat()
		q := new(big.Int).Quo(r.Num(), r.Denom())

		return xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: q}, nil
	case xdm.TypeBoolean:
		if v.BooleanVal() {
			return xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(1)}, nil
		}

		return xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(0)}, nil
	default:
		return castStringLikeOrFail(v, xdm.TypeInteger)
	}
}

func castToDecimal(v xdm.AtomicValue) (xdm.AtomicValue, error) {
	switch v.TypeName {
	case xdm.TypeInteger:
		if iv, ok := v.Value.(int64); ok {
			return xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: new(big.Rat).SetInt64(iv)}, nil
		}

		r := new(big.Rat).SetInt(v.BigInt())

		return xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: r}, nil
	case xdm.TypeDouble, xdm.TypeFloat:
		f := v.DoubleVal()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return xdm.AtomicValue{}, &xdm.Error{Code: errCodeFOCA0002, Message: "cannot cast NaN/INF to xs:decimal"}
		}

		r := new(big.Rat).SetFloat64(f)

		return xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: r}, nil
	case xdm.TypeBoolean:
		if v.BooleanVal() {
			return xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: big.NewRat(1, 1)}, nil
		}

		return xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: big.NewRat(0, 1)}, nil
	default:
		return castStringLikeOrFail(v, xdm.TypeDecimal)
	}
}

func castToBoolean(v xdm.AtomicValue) (xdm.AtomicValue, error) {
	switch v.TypeName {
	case xdm.TypeBoolean:
		return v, nil
	case xdm.TypeInteger:
		if iv, ok := v.Value.(int64); ok {
			return xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: iv != 0}, nil
		}

		return xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: v.BigInt().Sign() != 0}, nil
	case xdm.TypeDouble, xdm.TypeFloat:
		f := v.DoubleVal()
		return xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: f != 0 && !math.IsNaN(f)}, nil
	case xdm.TypeDecimal:
		return xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: v.BigRat().Sign() != 0}, nil
	default:
		return castStringLikeOrFail(v, xdm.TypeBoolean)
	}
}

func castToBase64Binary(v xdm.AtomicValue) (xdm.AtomicValue, error) {
	switch v.TypeName {
	case xdm.TypeHexBinary:
		return xdm.AtomicValue{TypeName: xdm.TypeBase64Binary, Value: v.BytesVal()}, nil
	default:
		return castStringLikeOrFail(v, xdm.TypeBase64Binary)
	}
}

// xsdBase64Encoding is base64.StdEncoding with Strict() to reject non-zero
// trailing bits before padding (per XSD base64Binary lexical rules).

// decodeXSDBase64 decodes a base64 string per XSD lexical rules:
// - whitespace (space, tab, CR, LF) is stripped before decoding
// - trailing non-zero bits before padding are rejected (strict mode)
func decodeXSDBase64(s string) ([]byte, error) {
	// Strip whitespace per XSD base64Binary lexical space (collapse)
	var cleaned strings.Builder

	for _, c := range s {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			cleaned.WriteRune(c)
		}
	}

	return base64.StdEncoding.Strict().DecodeString(cleaned.String())
}

func castToHexBinary(v xdm.AtomicValue) (xdm.AtomicValue, error) {
	switch v.TypeName {
	case xdm.TypeBase64Binary:
		return xdm.AtomicValue{TypeName: xdm.TypeHexBinary, Value: v.BytesVal()}, nil
	default:
		return castStringLikeOrFail(v, xdm.TypeHexBinary)
	}
}

// castStringLikeOrFail casts a string-like source (xs:string, xs:untypedAtomic,
// or any string-derived type) to targetType via CastFromString. Any other
// source type yields XPTY0004. It is the shared fallthrough tail for the
// non-string cast helpers; targetType doubles as the error message literal
// since the Type* constants are their own lexical names (e.g. "xs:integer").
func castStringLikeOrFail(v xdm.AtomicValue, targetType string) (xdm.AtomicValue, error) {
	switch {
	case v.TypeName == xdm.TypeString || v.TypeName == xdm.TypeUntypedAtomic || xdm.IsStringDerived(v.TypeName):
		return CastFromString(v.StringVal(), targetType)
	}

	return xdm.AtomicValue{}, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("cannot cast %s to %s", v.TypeName, targetType)}
}
