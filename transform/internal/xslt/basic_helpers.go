// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func findDocumentElement(doc *xdm.Document) *xdm.Element {
	for child := range xdm.Children(doc) {
		if child.Type() == xdm.ElementNode {
			elem, _ := xdm.AsNode[*xdm.Element](child)
			return elem
		}
	}

	return nil
}
