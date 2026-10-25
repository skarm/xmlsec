package xslt

import (
	"io"
	"unicode/utf8"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// JSON serialization does not normalize sequences into arrays (SER31 §9).
// The same cardinality rules apply to the result and every map/array member.
func writeJSONItems(w io.Writer, seq xdm.Sequence, out *OutputDef) error {
	switch xdm.SequenceLen(seq) {
	case 0:
		return writeFullString(w, "null")
	case 1:
		return writeJSONItem(w, seq.Get(0), out)
	default:
		return dynamicError("SERE0023", "JSON serialization requires at most one item")
	}
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
	seen := make(map[string]struct{}, v.Size())

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

		if _, exists := seen[text]; exists && (out == nil || !out.AllowDuplicateNames) {
			return dynamicError(errCodeSERE0022, "duplicate key %q in JSON output", text)
		}

		seen[text] = struct{}{}

		if err := writeJSONString(w, text, out); err != nil {
			return err
		}

		if err := writeFullString(w, ":"); err != nil {
			return err
		}

		return writeJSONItems(w, value, out)
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

		if err := writeJSONItems(w, value, out); err != nil {
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
			const hex = "0123456789abcdef"

			escaped := [6]byte{'\\', 'u', '0', '0', hex[(r>>4)&0x0F], hex[r&0x0F]}

			return string(escaped[:])
		}

		return ""
	}
}
