// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import (
	"math/big"
	"time"
)

// PromoteSchemaType promotes a user-defined schema type to its built-in base
// type, based on the underlying Go value type. If the type is already a known
// XSD type, the value is returned unchanged.
func PromoteSchemaType(a AtomicValue) AtomicValue {
	if IsKnownXSDType(a.TypeName) {
		return a
	}
	// If the value carries a known built-in base type, use it directly.
	if a.BaseType != "" && IsKnownXSDType(a.BaseType) {
		return AtomicValue{TypeName: a.BaseType, Value: a.Value}
	}

	switch v := a.Value.(type) {
	case int64:
		return AtomicValue{TypeName: TypeInteger, Value: v}
	case *big.Int:
		return AtomicValue{TypeName: TypeInteger, Value: v}
	case *big.Rat:
		return AtomicValue{TypeName: TypeDecimal, Value: v}
	case *FloatValue:
		return AtomicValue{TypeName: TypeDouble, Value: v}
	case float64:
		return AtomicValue{TypeName: TypeDouble, Value: v}
	case bool:
		return AtomicValue{TypeName: TypeBoolean, Value: v}
	case string:
		return AtomicValue{TypeName: TypeString, Value: v}
	case time.Time:
		// Default to xs:dateTime — callers can narrow further
		return AtomicValue{TypeName: TypeDateTime, Value: v}
	case Duration:
		return AtomicValue{TypeName: TypeDuration, Value: v}
	case []byte:
		return AtomicValue{TypeName: TypeBase64Binary, Value: v}
	case QNameValue:
		return AtomicValue{TypeName: TypeQName, Value: v}
	}

	return a
}
