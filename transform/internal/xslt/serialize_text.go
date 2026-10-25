package xslt

import (
	"context"
	"io"
	"unicode/utf8"

	norm "github.com/skarm/xmlsec/internal/normalization"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func streamTextValue(ctx context.Context, dst io.Writer, result ValueResult, definition *OutputDef) error {
	text := textValueWriter{ctx: ctx, destination: dst, charMap: definition.ResolvedCharMap}
	if form, ok := resolveNormForm(definition.NormalizationForm); ok {
		text.form = &form
	}

	sequence := serializationSequence{ctx: ctx, definition: definition}
	for item, err := range sequence.items(result.Items) {
		if err != nil {
			return err
		}

		if item.Node == nil {
			if err := text.write(item.Text); err != nil {
				return err
			}

			continue
		}

		err = xdm.Walk(item.Node, xdm.NodeWalkerFunc(func(node xdm.Node) error {
			if err := xpath.Charge(ctx, 1); err != nil {
				return err
			}

			if node.Type() == xdm.TextNode || node.Type() == xdm.CDATASectionNode {
				return text.write(xdm.CharacterData(node))
			}

			return nil
		}))
		if err != nil {
			return err
		}
	}

	return text.flush()
}

type textValueWriter struct {
	ctx         context.Context
	destination io.Writer
	charMap     map[rune]string
	form        *norm.Form
	normalized  io.WriteCloser
}

func (w *textValueWriter) plain(value string) error {
	target := w.destination
	if w.form != nil {
		if err := xpath.ChargeString(w.ctx, len(value)); err != nil {
			return err
		}

		if w.normalized == nil {
			w.normalized = norm.NewWriter(w.ctx, w.destination, *w.form)
		}

		target = w.normalized
	}

	for len(value) > 0 {
		end := min(4096, len(value))
		if err := writeFullString(target, value[:end]); err != nil {
			return err
		}

		value = value[end:]
	}

	return nil
}

func (w *textValueWriter) write(value string) error {
	if len(w.charMap) == 0 {
		return w.plain(value)
	}

	start := 0

	for offset, r := range value {
		replacement, ok := w.charMap[r]
		if !ok {
			continue
		}

		if err := w.plain(value[start:offset]); err != nil {
			return err
		}

		if err := w.flush(); err != nil {
			return err
		}

		if err := writeFullString(w.destination, replacement); err != nil {
			return err
		}

		start = offset + utf8.RuneLen(r)
	}

	return w.plain(value[start:])
}

func (w *textValueWriter) flush() error {
	if w.normalized == nil {
		return nil
	}

	err := w.normalized.Close()
	w.normalized = nil

	return err
}
