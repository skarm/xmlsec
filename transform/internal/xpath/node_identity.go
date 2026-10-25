// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"encoding/hex"
	"strconv"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// StableNodeID returns a non-recycled identifier, even after a temporary node
// has been collected. Namespace-axis wrappers identify their logical owner and
// prefix rather than the newly allocated wrapper. Components are delimited so
// different owner/prefix combinations cannot collide.
func StableNodeID(n xdm.Node) string {
	if n == nil {
		return ""
	}

	if nsk, ok := xdm.NamespaceNodeKey(n); ok {
		parentHex := strconv.FormatUint(xdm.NodeIdentity(nsk.Parent), 16)

		prefixHex := hex.EncodeToString([]byte(nsk.Prefix))
		if prefixHex == "" {
			prefixHex = "00"
		}

		return "idns" + parentHex + "p" + prefixHex
	}

	return "idn" + strconv.FormatUint(xdm.NodeIdentity(n), 16)
}

// nodeIdentityKey is a map key for node identity (see xdm.SameNode): the
// NamespaceNodeKey of a namespace node of an element, the pointer of any other
// node.
type nodeIdentityKey struct {
	node xdm.Node
	ns   xdm.NSNodeKey
}

func makeNodeIdentityKey(n xdm.Node) nodeIdentityKey {
	if nsk, ok := xdm.NamespaceNodeKey(n); ok {
		return nodeIdentityKey{ns: nsk}
	}

	return nodeIdentityKey{node: n}
}
