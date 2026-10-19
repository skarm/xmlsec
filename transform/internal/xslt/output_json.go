// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"bytes"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// serializeJSONItems serializes a sequence of items as JSON output.
// Per XSLT 3.0 §26: the sequence is serialized as a single JSON value.
func serializeJSONItems(w io.Writer, items xdm.Sequence, doc *xdm.Document, outDef *OutputDef) error {
	if xdm.SequenceLen(items) == 0 && doc != nil {
		return serializeAdaptiveItems(w, items, doc, nil, "", "")
	}

	return writeJSONItems(w, items, outDef, false)
}

// serializeItemJSON serializes a single XDM item as JSON. The json-node-output
// method and its serialization parameters (e.g. html-version) are taken from
// outDef, which may be nil.
func serializeItemJSON(item xdm.Item, outDef *OutputDef) (string, error) {
	nodeMethod := ""
	if outDef != nil {
		nodeMethod = outDef.JSONNodeOutputMethod
	}

	switch v := item.(type) {
	case xdm.MapItem:
		return serializeMapJSON(v, outDef)
	case xdm.ArrayItem:
		return serializeArrayJSON(v, outDef)
	case xdm.NodeItem:
		if nodeMethod != "" && nodeMethod != methodText {
			htmlVersion := ""
			if outDef != nil {
				htmlVersion = outDef.HTMLVersion
			}

			s, err := serializeNodeWithMethod(v.Node, nodeMethod, htmlVersion)
			if err != nil {
				return "", err
			}

			return jsonEscapeString(s), nil
		}

		return jsonEscapeString(nodeStringValue(v.Node)), nil
	case xdm.AtomicValue:
		return serializeAtomicJSON(v), nil
	default:
		if av, ok := item.(xdm.AtomicValue); ok {
			return serializeAtomicJSON(av), nil
		}

		return jsonEscapeString(fmt.Sprintf("%v", item)), nil
	}
}

func serializeMapJSON(m xdm.MapItem, outDef *OutputDef) (string, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')

	first := true

	var serErr error

	_ = m.ForEach(func(k xdm.AtomicValue, v xdm.Sequence) error {
		if serErr != nil {
			return serErr
		}

		if !first {
			buf.WriteByte(',')
		}

		first = false
		ks, _ := xpath.AtomicToString(k)
		buf.WriteString(jsonEscapeString(ks))
		buf.WriteByte(':')

		vLen := 0
		if v != nil {
			vLen = xdm.SequenceLen(v)
		}

		switch vLen {
		case 1:
			s, err := serializeItemJSON(v.Get(0), outDef)
			if err != nil {
				serErr = err
				return err
			}

			buf.WriteString(s)
		case 0:
			buf.WriteString("null")
		default:
			members := make([]xdm.Sequence, vLen)
			for i := range vLen {
				members[i] = xdm.ItemSlice{v.Get(i)}
			}

			s, err := serializeItemJSON(xdm.NewArray(members), outDef)
			if err != nil {
				serErr = err
				return err
			}

			buf.WriteString(s)
		}

		return nil
	})

	if serErr != nil {
		return "", serErr
	}

	buf.WriteByte('}')

	return buf.String(), nil
}

func serializeArrayJSON(a xdm.ArrayItem, outDef *OutputDef) (string, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')

	members := a.Members()
	for i, member := range members {
		if i > 0 {
			buf.WriteByte(',')
		}

		mLen := 0
		if member != nil {
			mLen = xdm.SequenceLen(member)
		}

		switch mLen {
		case 1:
			s, err := serializeItemJSON(member.Get(0), outDef)
			if err != nil {
				return "", err
			}

			buf.WriteString(s)
		case 0:
			buf.WriteString("null")
		default:
			// Multi-item member: serialize as array
			submembers := make([]xdm.Sequence, mLen)
			for j := range mLen {
				submembers[j] = xdm.ItemSlice{member.Get(j)}
			}

			s, err := serializeItemJSON(xdm.NewArray(submembers), outDef)
			if err != nil {
				return "", err
			}

			buf.WriteString(s)
		}
	}

	buf.WriteByte(']')

	return buf.String(), nil
}

func serializeAtomicJSON(v xdm.AtomicValue) string {
	typeName := v.TypeName
	switch typeName {
	case "xs:boolean":
		b, _ := xpath.AtomicToString(v)
		return b
	case "xs:integer", "xs:int", "xs:long", "xs:short", "xs:byte",
		"xs:unsignedInt", "xs:unsignedLong", "xs:unsignedShort", "xs:unsignedByte",
		"xs:positiveInteger", "xs:nonNegativeInteger", "xs:negativeInteger", "xs:nonPositiveInteger":
		s, _ := xpath.AtomicToString(v)
		return s
	case "xs:double", "xs:float", "xs:decimal":
		s, _ := xpath.AtomicToString(v)
		if s == valueNaN || s == "INF" || s == "-INF" || s == "+INF" {
			return jsonEscapeString(s)
		}

		return s
	default:
		s, _ := xpath.AtomicToString(v)
		return jsonEscapeString(s)
	}
}

// jsonEscapeString returns a JSON-escaped double-quoted string.
func jsonEscapeString(s string) string {
	var buf bytes.Buffer
	buf.WriteByte('"')

	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString("\\\"")
		case '\\':
			buf.WriteString("\\\\")
		case '\n':
			buf.WriteString("\\n")
		case '\r':
			buf.WriteString("\\r")
		case '\t':
			buf.WriteString("\\t")
		case '\b':
			buf.WriteString("\\b")
		case '\f':
			buf.WriteString("\\f")
		case '/':
			buf.WriteString("\\/")
		default:
			if r < 0x20 {
				fmt.Fprintf(&buf, "\\u%04x", r)
			} else {
				buf.WriteRune(r)
			}
		}
	}

	buf.WriteByte('"')

	return buf.String()
}
