// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

// IsStringDerived returns true if the type derives from xs:string in the type hierarchy.
func IsStringDerived(typeName string) bool {
	for typeName != "" && typeName != TypeAnyAtomicType {
		if typeName == TypeString {
			return true
		}

		typeName = xsdTypeParent(typeName)
	}

	return false
}
