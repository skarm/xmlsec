// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

// IsIntegerDerived returns true if the type is xs:integer or one of its derived types.
func IsIntegerDerived(typeName string) bool {
	switch typeName {
	case TypeInteger,
		TypeLong, TypeInt, TypeShort, TypeByte,
		TypeUnsignedLong, TypeUnsignedInt, TypeUnsignedShort, TypeUnsignedByte,
		TypeNonNegativeInteger, TypeNonPositiveInteger,
		TypePositiveInteger, TypeNegativeInteger:
		return true
	}

	return false
}
