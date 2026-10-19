// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// StableNodeID returns a unique string identifier for a node.  For a
// namespace node of an element (which the namespace axis recreates on each
// traversal) the ID is derived from the parent element pointer and the
// namespace prefix, so that the same logical namespace node always gets the
// same ID. Any other node, a parentless namespace node included, gets an ID
// derived from its pointer.
func StableNodeID(n xdm.Node) string {
	if n == nil {
		return ""
	}

	if nsk, ok := xdm.NamespaceNodeKey(n); ok {
		parentHex := strings.TrimPrefix(fmt.Sprintf("%p", nsk.Parent), "0x")

		prefixHex := hex.EncodeToString([]byte(nsk.Prefix))
		if prefixHex == "" {
			prefixHex = "00"
		}

		return "idns" + parentHex + prefixHex
	}

	return fmt.Sprintf("id%p", n)
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
