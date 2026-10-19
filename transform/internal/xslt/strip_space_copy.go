// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import "github.com/skarm/xmlsec/transform/internal/xdm"

// copyAndStrip uses the project's clone operation and XSLT's existing whitespace
// rules. The node map is built before filtering, preserving attribute identity.
func copyAndStrip(src *xdm.Document, strip, preserve []nameTest, buildNodeMap bool) (*xdm.Document, map[xdm.Node]xdm.Node, error) {
	dst, err := xdm.CopyDoc(src)
	if err != nil {
		return nil, nil, err
	}

	var nodeMap map[xdm.Node]xdm.Node
	if buildNodeMap {
		nodeMap = make(map[xdm.Node]xdm.Node)
	}

	ec := &execContext{stylesheet: &Stylesheet{stripSpace: strip, preserveSpace: preserve}}

	var walk func(xdm.Node, xdm.Node)

	walk = func(a, b xdm.Node) {
		if nodeMap != nil {
			nodeMap[a] = b
			if ea, ok := a.(*xdm.Element); ok {
				eb, ok := b.(*xdm.Element)
				if !ok {
					panic("clone changed XML node kind")
				}

				mapElementAttributes(nodeMap, ea, eb)
			}
		}

		x, y := a.FirstChild(), b.FirstChild()
		for x != nil && y != nil {
			nx, ny := x.NextSibling(), y.NextSibling()
			if !ec.shouldStripWhitespace(y) {
				walk(x, y)
			}

			x, y = nx, ny
		}

		xdm.FilterChildren(b, func(n xdm.Node) bool { return !ec.shouldStripWhitespace(n) })
	}
	walk(src, dst)

	return dst, nodeMap, nil
}
