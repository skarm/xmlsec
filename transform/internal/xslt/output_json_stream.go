package xslt

import (
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func writeJSONItems(w io.Writer, seq xdm.Sequence, out *OutputDef, member bool) error {
	size := xdm.SequenceLen(seq)
	if size == 0 && member {
		return writeFullString(w, "null")
	}

	if size == 1 {
		return writeJSONItem(w, seq.Get(0), out)
	}

	if err := writeFullString(w, "["); err != nil {
		return err
	}

	first := true
	for item := range xdm.SequenceItems(seq) {
		if !first {
			if err := writeFullString(w, ","); err != nil {
				return err
			}
		}

		first = false

		if err := writeJSONItem(w, item, out); err != nil {
			return err
		}
	}

	return writeFullString(w, "]")
}

func writeJSONItem(w io.Writer, item xdm.Item, out *OutputDef) error {
	switch v := item.(type) {
	case xdm.MapItem:
		return writeJSONMap(w, v, out)
	case xdm.ArrayItem:
		return writeJSONArray(w, v, out)
	case xdm.AtomicValue:
		if v.TypeName == xdm.TypeString || xdm.IsStringDerived(v.TypeName) || v.TypeName == xdm.TypeUntypedAtomic || v.TypeName == xdm.TypeAnyURI {
			text, err := xpath.AtomicToString(v)
			if err != nil {
				return err
			}

			return writeJSONString(w, text, out)
		}
	}

	text, err := serializeItemJSON(item, out)
	if err != nil {
		return err
	}

	if out != nil && (len(out.ResolvedCharMap) > 0 || out.NormalizationForm != "") {
		text = applyCharMapJSON(text, out.ResolvedCharMap, out.NormalizationForm)
	}

	return writeFullString(w, text)
}

func writeJSONString(w io.Writer, value string, out *OutputDef) error {
	if out != nil && (len(out.ResolvedCharMap) > 0 || out.NormalizationForm != "") {
		return writeFullString(w, applyCharMapJSON(jsonEscapeString(value), out.ResolvedCharMap, out.NormalizationForm))
	}

	if err := writeFullString(w, "\""); err != nil {
		return err
	}

	start := 0

	for offset, r := range value {
		escaped := jsonRuneEscape(r)

		width := utf8.RuneLen(r)
		if r == utf8.RuneError {
			_, width = utf8.DecodeRuneInString(value[offset:])
			if width == 1 {
				escaped = "�"
			}
		}

		if escaped == "" {
			continue
		}

		if err := writeFullString(w, value[start:offset]); err != nil {
			return err
		}

		if err := writeFullString(w, escaped); err != nil {
			return err
		}

		start = offset + width
	}

	if err := writeFullString(w, value[start:]); err != nil {
		return err
	}

	return writeFullString(w, "\"")
}

func writeJSONMap(w io.Writer, v xdm.MapItem, out *OutputDef) error {
	if err := writeFullString(w, "{"); err != nil {
		return err
	}

	first := true

	err := v.ForEachView(func(key xdm.AtomicValue, value xdm.Sequence) error {
		if !first {
			if err := writeFullString(w, ","); err != nil {
				return err
			}
		}

		first = false

		text, err := xpath.AtomicToString(key)
		if err != nil {
			return err
		}

		if err := writeJSONString(w, text, out); err != nil {
			return err
		}

		if err := writeFullString(w, ":"); err != nil {
			return err
		}

		return writeJSONItems(w, value, out, true)
	})
	if err != nil {
		return err
	}

	return writeFullString(w, "}")
}

func writeJSONArray(w io.Writer, v xdm.ArrayItem, out *OutputDef) error {
	if err := writeFullString(w, "["); err != nil {
		return err
	}

	for i, value := range v.MembersView() {
		if i > 0 {
			if err := writeFullString(w, ","); err != nil {
				return err
			}
		}

		if err := writeJSONItems(w, value, out, true); err != nil {
			return err
		}
	}

	return writeFullString(w, "]")
}

func jsonRuneEscape(r rune) string {
	switch r {
	case '"':
		return `\"`
	case '\\':
		return `\\`
	case '\b':
		return `\b`
	case '\f':
		return `\f`
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	case '/':
		return `\/`
	default:
		if r < 0x20 {
			return fmt.Sprintf(`\u%04x`, r)
		}

		return ""
	}
}
