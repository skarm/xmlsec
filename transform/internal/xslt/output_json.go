// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"io"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// serializeJSONItems serializes a sequence of items as JSON output.
// Per XSLT 3.0 §26: the sequence is serialized as a single JSON value.
func serializeJSONItems(w io.Writer, items xdm.Sequence, _ *xdm.Document, outDef *OutputDef) error {
	return writeJSONItems(w, items, outDef)
}

// serializeItemJSON handles the leaf items of the streaming JSON serializer.
func serializeItemJSON(item xdm.Item, outDef *OutputDef) (string, error) {
	switch v := item.(type) {
	case xdm.NodeItem:
		nodeMethod := methodXML
		if outDef != nil && outDef.JSONNodeOutputMethod != "" {
			nodeMethod = outDef.JSONNodeOutputMethod
		}

		var (
			s   string
			err error
		)
		if nodeMethod == methodXHTML {
			s, err = serializeXHTMLNodeForJSON(v.Node)
		} else {
			s, err = xpath.SerializeNodeForJSON(v, nodeMethod)
		}

		if err != nil {
			return "", err
		}

		return jsonEscapeString(s), nil

	case xdm.AtomicValue:
		s, err := xpath.AtomicToString(v)
		if err != nil {
			return "", err
		}

		if v.IsNumeric() {
			if s == valueNaN || s == "INF" || s == "-INF" || s == "+INF" {
				return "", dynamicError("SERE0020", "cannot serialize NaN or infinity as JSON")
			}

			return s, nil
		}

		if v.TypeName == xdm.TypeBoolean {
			return s, nil
		}

		return jsonEscapeString(s), nil
	default:
		return "", dynamicError("SERE0021", "cannot serialize %T as JSON", item)
	}
}

// jsonEscapeString returns a JSON-escaped double-quoted string.
func jsonEscapeString(s string) string {
	var buf strings.Builder
	buf.WriteByte('"')

	for _, r := range s {
		if escaped := jsonRuneEscape(r); escaped != "" {
			buf.WriteString(escaped)
		} else {
			buf.WriteRune(r)
		}
	}

	buf.WriteByte('"')

	return buf.String()
}
