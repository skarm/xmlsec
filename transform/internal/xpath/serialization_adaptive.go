package xpath

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// AdaptiveSerialization shares SER31 §10 value representations between hosts.
// XML parameters apply to each delegated node; the separator applies only to
// the outer sequence, while container members use parenthesized comma lists.
type AdaptiveSerialization struct {
	// XML supplies serialization parameters for node items.
	XML xdm.XMLSerialization
	// ItemSeparator separates outer sequence items. Nil selects a newline; a pointer to
	// an empty string selects no separator.
	ItemSeparator *string
}

// WriteTo serializes seq under ctx and the shared evaluation budgets. It leaves dst
// open and may leave partial output on error.
func (options AdaptiveSerialization) WriteTo(ctx context.Context, dst io.Writer, seq xdm.Sequence) error {
	state := adaptiveSerialization{ctx: ctx, dst: dst, options: options}

	separator := "\n"
	if options.ItemSeparator != nil {
		separator = *options.ItemSeparator
	}

	return state.sequence(seq, separator, false, 0)
}

type adaptiveSerialization struct {
	ctx     context.Context
	dst     io.Writer
	options AdaptiveSerialization
}

func (s *adaptiveSerialization) write(value string) error {
	if err := Charge(s.ctx, 1+len(value)/64); err != nil {
		return err
	}

	return writeSerializationString(s.dst, value)
}

func (s *adaptiveSerialization) sequence(seq xdm.Sequence, separator string, member bool, depth int) error {
	if depth > DepthLimit(s.ctx, 128) {
		return ErrBudget
	}

	wrap := member && xdm.SequenceLen(seq) != 1
	if wrap {
		if err := s.write("("); err != nil {
			return err
		}
	}

	first := true
	for item := range xdm.SequenceItems(seq) {
		if !first {
			if err := s.write(separator); err != nil {
				return err
			}
		}

		if err := s.item(item, depth); err != nil {
			return err
		}

		first = false
	}

	if wrap {
		return s.write(")")
	}

	return s.ctx.Err()
}

func (s *adaptiveSerialization) item(item xdm.Item, depth int) error {
	if err := Charge(s.ctx, 1); err != nil {
		return err
	}

	switch value := item.(type) {
	case xdm.AtomicValue:
		return s.atomic(value)
	case xdm.NodeItem:
		return s.node(value.Node)
	case xdm.ArrayItem:
		return s.array(value, depth)
	case xdm.MapItem:
		return s.mapping(value, depth)
	case xdm.FunctionItem:
		name := "(anonymous-function)"

		if value.Name != "" {
			switch value.Namespace {
			case NSFn:
				name = "fn:" + value.Name
			case NSMath:
				name = "math:" + value.Name
			case NSMap:
				name = "map:" + value.Name
			case NSArray:
				name = "array:" + value.Name
			case NSXS:
				name = "xs:" + value.Name
			default:
				name = "Q{" + value.Namespace + "}" + value.Name
			}
		}

		return s.write(name + "#" + strconv.Itoa(value.Arity))
	default:
		return &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("cannot serialize %T adaptively", item)}
	}
}

func (s *adaptiveSerialization) atomic(value xdm.AtomicValue) error {
	text, err := atomicToString(value)
	if err != nil {
		return err
	}

	switch {
	case value.TypeName == xdm.TypeBoolean:
		return s.write(text + "()")
	case value.TypeName == xdm.TypeString || xdm.IsStringDerived(value.TypeName) || value.TypeName == xdm.TypeUntypedAtomic || value.TypeName == xdm.TypeAnyURI:
		return s.quoted(text)
	case xdm.IsSubtypeOf(value.TypeName, xdm.TypeDecimal):
		return s.write(text)
	case value.TypeName == xdm.TypeDouble:
		text, err = boundedFormatNumber(s.ctx, value, "0.0##########################e0", DefaultDecimalFormat())
		if err != nil {
			return err
		}

		return s.write(text)
	case value.TypeName == xdm.TypeQName || value.TypeName == xdm.TypeNOTATION:
		name, ok := value.Value.(xdm.QNameValue)
		if !ok {
			return &xdm.Error{Code: errCodeFOER0000, Message: "invalid QName value"}
		}

		return s.write("Q{" + name.URI + "}" + name.Local)
	default:
		primitive := adaptivePrimitiveType(value.TypeName)
		if err := s.write(primitive + "("); err != nil {
			return err
		}

		if err := s.quoted(text); err != nil {
			return err
		}

		return s.write(")")
	}
}

func adaptivePrimitiveType(name string) string {
	for _, primitive := range []string{xdm.TypeDateTime, xdm.TypeDuration, xdm.TypeString} {
		if xdm.IsSubtypeOf(name, primitive) {
			return primitive
		}
	}

	return name
}

func (s *adaptiveSerialization) quoted(value string) error {
	// Quotes are doubled before the resulting text undergoes character mapping.
	// A quote introduced by a map is emitted verbatim, never doubled again.
	quotes := strings.Count(value, `"`)

	if err := ChargeString(s.ctx, len(value), quotes, 2); err != nil {
		return err
	}

	// Quotes, maps and normalization retain their character-expansion order.
	// Unquoted large values need only framing; retaining the short path avoids
	// additional writer calls on tiny values.
	if len(value) < 4096 || quotes != 0 || len(s.options.XML.CharacterMap) != 0 || serializeNormalizationActive(s.options.XML.Normalization) {
		quoted := `"` + strings.ReplaceAll(value, `"`, `""`) + `"`

		text, err := SerializeTextValue(s.ctx, quoted, s.options.XML.CharacterMap, s.options.XML.Normalization)
		if err != nil {
			return err
		}

		return s.write(text)
	}

	if err := Charge(s.ctx, 1+(len(value)+2)/64); err != nil {
		return err
	}

	if err := writeSerializationString(s.dst, `"`); err != nil {
		return err
	}

	if err := writeSerializationString(s.dst, value); err != nil {
		return err
	}

	return writeSerializationString(s.dst, `"`)
}

func (s *adaptiveSerialization) node(node xdm.Node) error {
	if xdm.IsNilNode(node) {
		return &xdm.Error{Code: errCodeFOER0000, Message: "nil adaptive node"}
	}

	writer, err := s.nodeWriter(node)
	if err != nil {
		return err
	}

	switch node.Type() {
	case xdm.AttributeNode, xdm.NamespaceNode:
		name := node.Name()
		if node.Type() == xdm.NamespaceNode {
			if name == "" {
				name = "xmlns"
			} else {
				name = "xmlns:" + name
			}
		}

		if err := s.write(name + `="`); err != nil {
			return err
		}

		if err := writer.WriteAttributeValue(s.ctx, s.dst, xdm.StringValue(node)); err != nil {
			return err
		}

		return s.write(`"`)
	}

	sequence := xdm.ItemSlice{xdm.NodeItem{Node: node}}
	if writer.Doctype != nil || writer.Standalone != "" {
		if err := ValidateSerializationDocument(s.ctx, sequence, nil); err != nil {
			return err
		}
	}
	// Sequence normalization for the delegated XML method provides one document
	// per node item. Source DTD/declaration metadata is outside XDM.
	if err := writer.WriteTo(s.dst, xdm.NewDefaultDocument()); err != nil {
		return err
	}

	_, coalesce := serializeNormForm(writer.Normalization)

	return writer.WriteSequence(s.ctx, s.dst, SerializationItems(s.ctx, sequence, nil, coalesce))
}

// SER31 §10 leaves recovery from delegated serialization errors to the host.
// Adaptive output uses UTF-8 for an item whose markup cannot use the requested
// repertoire. Choose that recovery before writing; character references still
// handle ordinary text/attributes and XML character validity remains enforced.
func (s *adaptiveSerialization) nodeWriter(node xdm.Node) (xdm.XMLSerialization, error) {
	writer := s.options.XML

	canEncode := writer.CanEncode
	if canEncode == nil && writer.ASCII {
		canEncode = func(r rune) bool { return r < 128 }
	}

	if canEncode == nil {
		return writer, nil
	}

	unencodable := false
	check := func(value string) error {
		if err := Charge(s.ctx, 1+len(value)/64); err != nil {
			return err
		}

		for _, r := range value {
			if !canEncode(r) {
				unencodable = true
				break
			}
		}

		return nil
	}
	err := xdm.Walk(node, xdm.NodeWalkerFunc(func(n xdm.Node) error {
		if err := Charge(s.ctx, 1); err != nil {
			return err
		}

		switch value := n.(type) {
		case *xdm.Element:
			if err := check(n.Name()); err != nil {
				return err
			}

			for _, attr := range value.Attributes() {
				if err := check(attr.Name()); err != nil {
					return err
				}
			}
		case *xdm.ProcessingInstruction:
			if err := check(n.Name()); err != nil {
				return err
			}

			return check(xdm.CharacterData(n))
		case *xdm.Comment:
			return check(xdm.CharacterData(n))
		}

		return nil
	}))

	if unencodable {
		writer.Encoding = "UTF-8"
		writer.ASCII = false
		writer.CanEncode = nil
	}

	return writer, err
}

func (s *adaptiveSerialization) array(value xdm.ArrayItem, depth int) error {
	if err := s.write("["); err != nil {
		return err
	}

	for i, member := range value.MembersView() {
		if i != 0 {
			if err := s.write(","); err != nil {
				return err
			}
		}

		if err := s.sequence(member, ",", true, depth+1); err != nil {
			return err
		}
	}

	return s.write("]")
}

func (s *adaptiveSerialization) mapping(value xdm.MapItem, depth int) error {
	if err := s.write("map{"); err != nil {
		return err
	}

	first := true

	err := value.ForEachView(func(key xdm.AtomicValue, member xdm.Sequence) error {
		if !first {
			if err := s.write(","); err != nil {
				return err
			}
		}

		first = false

		if err := s.atomic(key); err != nil {
			return err
		}

		if err := s.write(":"); err != nil {
			return err
		}

		return s.sequence(member, ",", true, depth+1)
	})
	if err != nil {
		return err
	}

	return s.write("}")
}
