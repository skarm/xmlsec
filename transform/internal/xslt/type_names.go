// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// isBuiltinSubtypeOf delegates to the xpath built-in type hierarchy.
func isBuiltinSubtypeOf(typeName, baseTypeName string) bool {
	return xdm.BuiltinIsSubtypeOf(typeName, baseTypeName)
}
