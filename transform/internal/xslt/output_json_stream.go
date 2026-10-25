package xslt

import (
	"context"
	"io"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// JSON serialization does not normalize sequences into arrays (SER31 §9).
// The same cardinality rules apply to the result and every map/array member.
func writeJSONItems(ctx context.Context, w io.Writer, seq xdm.Sequence, out *OutputDef, depth int) error {
	switch xdm.SequenceLen(seq) {
	case 0:
		return writeFullString(w, "null")
	case 1:
		return writeJSONItem(ctx, w, seq.Get(0), out, depth)
	default:
		return dynamicError("SERE0023", "JSON serialization requires at most one item")
	}
}

func writeJSONItem(ctx context.Context, w io.Writer, item xdm.Item, out *OutputDef, depth int) error {
	if depth > xpath.DepthLimit(ctx, 128) {
		return xpath.ErrBudget
	}

	if err := xpath.Charge(ctx, 1); err != nil {
		return err
	}

	switch v := item.(type) {
	case xdm.MapItem:
		return writeJSONMap(ctx, w, v, out, depth)
	case xdm.ArrayItem:
		return writeJSONArray(ctx, w, v, out, depth)
	case xdm.NodeItem:
		method := lexicon.MethodXML
		if out != nil && out.JSONNodeOutputMethod != "" {
			method = out.JSONNodeOutputMethod
		}

		value, err := xpath.SerializeNodeForJSON(ctx, v, method)
		if err != nil {
			return err
		}

		return writeJSONString(ctx, w, value, out)
	case xdm.AtomicValue:
		if !v.IsNumeric() && v.TypeName != xdm.TypeBoolean {
			value, err := xpath.AtomicToString(v)
			if err != nil {
				return err
			}

			return writeJSONString(ctx, w, value, out)
		}
	}

	value, ok := item.(xdm.AtomicValue)
	if !ok {
		return dynamicError("SERE0021", "cannot serialize %T as JSON", item)
	}

	text, err := xpath.AtomicToString(value)
	if err != nil {
		return err
	}

	if value.IsNumeric() && (text == lexicon.FloatNaN || text == "INF" || text == "-INF" || text == "+INF") {
		return dynamicError("SERE0020", "cannot serialize NaN or infinity as JSON")
	}

	return writeFullString(w, text)
}

func writeJSONString(ctx context.Context, w io.Writer, value string, out *OutputDef) error {
	var (
		charMap   map[rune]string
		form      string
		canEncode func(rune) bool
	)

	if out != nil {
		charMap, form = out.ResolvedCharMap, out.NormalizationForm
		canEncode = out.canEncode
	}

	return xpath.WriteJSONString(ctx, w, value, charMap, form, canEncode)
}

func writeJSONMap(ctx context.Context, w io.Writer, v xdm.MapItem, out *OutputDef, depth int) error {
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
			return dynamicError(lexicon.ErrSERE0022, "duplicate key %q in JSON output", text)
		}

		seen[text] = struct{}{}

		if err := writeJSONString(ctx, w, text, out); err != nil {
			return err
		}

		if err := writeFullString(w, ":"); err != nil {
			return err
		}

		return writeJSONItems(ctx, w, value, out, depth+1)
	})
	if err != nil {
		return err
	}

	return writeFullString(w, "}")
}

func writeJSONArray(ctx context.Context, w io.Writer, v xdm.ArrayItem, out *OutputDef, depth int) error {
	if err := writeFullString(w, "["); err != nil {
		return err
	}

	for i, value := range v.MembersView() {
		if i > 0 {
			if err := writeFullString(w, ","); err != nil {
				return err
			}
		}

		if err := writeJSONItems(ctx, w, value, out, depth+1); err != nil {
			return err
		}
	}

	return writeFullString(w, "]")
}
