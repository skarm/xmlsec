// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// makeFloatResult creates an AtomicValue with the appropriate FloatValue
// for the given type name (TypeFloat or TypeDouble).
func makeFloatResult(typeName string, f float64) xdm.AtomicValue {
	if typeName == xdm.TypeFloat {
		return xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(f)}
	}

	return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(f)}
}
