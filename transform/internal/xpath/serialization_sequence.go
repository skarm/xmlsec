package xpath

import (
	"context"
	"iter"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// SerializationItems applies array flattening, atomic spacing, document
// flattening and standalone-node checks shared by XPath and XSLT. Coalescing is
// required before Unicode normalization; without it, text can remain borrowed
// chunks with the same serialized representation.
func SerializationItems(ctx context.Context, seq xdm.Sequence, separator *string, coalesce bool) iter.Seq2[xdm.XMLItem, error] {
	return func(yield func(xdm.XMLItem, error) bool) {
		state := serializationItems{ctx: ctx, separator: separator, coalesce: coalesce, yield: yield}
		if state.append(seq, 0) {
			state.flush()
		}
	}
}

type serializationItems struct {
	ctx            context.Context
	separator      *string
	yield          func(xdm.XMLItem, error) bool
	pending        string
	buffer         strings.Builder
	previousAtomic bool
	previousItem   bool
	coalesce       bool
	hasText        bool
}

func (s *serializationItems) fail(err error) bool { s.yield(xdm.XMLItem{}, err); return false }

func (s *serializationItems) append(seq xdm.Sequence, depth int) bool {
	if depth > DepthLimit(s.ctx, 128) {
		return s.fail(ErrBudget)
	}

	for item := range xdm.SequenceItems(seq) {
		if err := Charge(s.ctx, 1); err != nil {
			return s.fail(err)
		}

		if array, ok := item.(xdm.ArrayItem); ok {
			for _, member := range array.MembersView() {
				if !s.append(member, depth+1) {
					return false
				}
			}

			continue
		}

		if !s.item(item) {
			return false
		}
	}

	return true
}

func (s *serializationItems) item(item xdm.Item) bool {
	if s.previousItem && s.separator != nil && !s.text(*s.separator) {
		return false
	}

	switch value := item.(type) {
	case xdm.AtomicValue:
		if s.previousAtomic && s.separator == nil && !s.text(" ") {
			return false
		}

		text, err := atomicToString(value)
		if err != nil {
			return s.fail(err)
		}

		if !s.text(text) {
			return false
		}

		s.previousAtomic = true
	case xdm.NodeItem:
		if !s.node(value.Node) {
			return false
		}

		s.previousAtomic = false
	default:
		return s.fail(&xdm.Error{Code: errCodeSENR0001, Message: "cannot serialize maps or functions using this output method"})
	}

	s.previousItem = true

	return true
}

func (s *serializationItems) node(node xdm.Node) bool {
	if xdm.IsNilNode(node) || node.Type() == xdm.AttributeNode || node.Type() == xdm.NamespaceNode {
		return s.fail(&xdm.Error{Code: errCodeSENR0001, Message: "cannot serialize a free attribute or namespace"})
	}

	switch node.Type() {
	case xdm.DocumentNode:
		for child := range xdm.Children(node) {
			if !s.node(child) {
				return false
			}
		}

		return true
	case xdm.TextNode, xdm.CDATASectionNode:
		return s.text(xdm.CharacterData(node))
	}

	if !s.flush() {
		return false
	}

	var err error
	if element, ok := node.(*xdm.Element); ok {
		node, err = elementWithInScopeNamespaces(element)
	} else if parent := node.Parent(); parent != nil && parent.Type() == xdm.ElementNode {
		// The normalized sequence gives a selected PI/comment a new document
		// parent; its source parent cannot select HTML XML-island rules.
		node, err = xdm.CopyNode(node, xdm.NewDefaultDocument())
	}

	if err != nil {
		return s.fail(err)
	}

	return s.yield(xdm.XMLItem{Node: node}, nil)
}

func (s *serializationItems) text(value string) bool {
	if value == "" {
		return true
	}

	if !s.coalesce {
		return s.yield(xdm.XMLItem{Text: value}, nil)
	}

	if !s.hasText {
		s.pending = value
		s.hasText = true

		return true
	}

	if s.buffer.Len() == 0 {
		if err := ChargeString(s.ctx, len(s.pending), len(value)); err != nil {
			return s.fail(err)
		}

		s.buffer.WriteString(s.pending)
		s.pending = ""
	} else if err := ChargeString(s.ctx, len(value)); err != nil {
		return s.fail(err)
	}

	s.buffer.WriteString(value)

	return true
}

func (s *serializationItems) flush() bool {
	if !s.hasText {
		return true
	}

	value := s.pending

	if s.buffer.Len() != 0 {
		value = s.buffer.String()
	}

	s.hasText = false
	s.pending = ""
	s.buffer.Reset()

	return s.yield(xdm.XMLItem{Text: value}, nil)
}

// NormalizeSerialization constructs an owned result tree when a caller needs
// tree construction or XHTML prefix/metadata changes. Ordinary XML/HTML writers
// can consume SerializationItems directly without copying element subtrees.
func NormalizeSerialization(ctx context.Context, seq xdm.Sequence, separator *string, baseURI string) (*xdm.Document, error) {
	doc := xdm.NewDefaultDocument()
	doc.SetURL(baseURI)

	for item, err := range SerializationItems(ctx, seq, separator, true) {
		if err != nil {
			return nil, err
		}

		var node xdm.Node
		if item.Node == nil {
			node = doc.CreateText(item.Text)
		} else {
			if err = ChargeTree(ctx, item.Node); err != nil {
				return nil, err
			}

			if element, ok := item.Node.(*xdm.Element); ok {
				subtree, copyErr := xdm.ElementDocument(ctx, element)
				if copyErr != nil {
					return nil, copyErr
				}

				node = subtree.DocumentElement()
			} else {
				node, err = xdm.CopyNode(item.Node, doc)
				if err != nil {
					return nil, err
				}
			}
		}

		if err = doc.AddChild(node); err != nil {
			return nil, err
		}
	}

	return doc, nil
}

func (opts serializeOptions) serializationContext() context.Context {
	if opts.ctx != nil {
		return opts.ctx
	}

	return context.Background()
}

func (opts serializeOptions) serializationSeparator() *string {
	if opts.itemSeparatorSet {
		return &opts.itemSeparator
	}

	return nil
}

type serializationBuffer struct {
	strings.Builder
	ctx context.Context
	err error
}

func (w *serializationBuffer) charge(size int) error {
	if w.err == nil {
		w.err = ChargeString(w.ctx, size)
	}

	if w.err == nil {
		w.err = Charge(w.ctx, 1+size/64)
	}

	return w.err
}

// NewSerializationBuffer bounds legacy in-memory serializers before growth.
// Result preserves the first failure even when an old write site ignores it.
func NewSerializationBuffer(ctx context.Context) *serializationBuffer {
	return &serializationBuffer{ctx: ctx}
}

func (w *serializationBuffer) Result() (string, error) {
	if w.err != nil {
		return "", w.err
	}

	return w.String(), w.ctx.Err()
}

func (w *serializationBuffer) Write(data []byte) (int, error) {
	if err := w.charge(len(data)); err != nil {
		return 0, err
	}

	return w.Builder.Write(data)
}

func (w *serializationBuffer) WriteString(data string) (int, error) {
	if err := w.charge(len(data)); err != nil {
		return 0, err
	}

	return w.Builder.WriteString(data)
}

func (w *serializationBuffer) WriteByte(value byte) error {
	if err := w.charge(1); err != nil {
		return err
	}

	return w.Builder.WriteByte(value)
}

func (w *serializationBuffer) WriteRune(value rune) (int, error) {
	size := utf8.RuneLen(value)
	if size < 0 {
		size = utf8.RuneLen(utf8.RuneError)
	}

	if err := w.charge(size); err != nil {
		return 0, err
	}

	return w.Builder.WriteRune(value)
}

// ValidateSerializationDocument enforces the document shape required when a
// host requests an XML/XHTML DOCTYPE or standalone declaration.
func ValidateSerializationDocument(ctx context.Context, seq xdm.Sequence, separator *string) error {
	roots := 0

	for item, err := range SerializationItems(ctx, seq, separator, false) {
		if err != nil {
			return err
		}

		if item.Node != nil && item.Node.Type() == xdm.ElementNode {
			roots++
		}

		if roots > 1 || item.Node == nil && item.Text != "" {
			return &xdm.Error{Code: "SEPM0004", Message: "doctype or standalone requires document-shaped output"}
		}
	}

	return nil
}
