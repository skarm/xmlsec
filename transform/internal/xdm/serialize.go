package xdm

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/xmloutput"
)

// XMLSerialization combines XDM declaration metadata with the project XML writer's options.
// XML character and name validation is always enforced by internal/tree.
type XMLSerialization struct {
	tree.XMLWriteOptions
	OmitDeclaration, OmitDoctype, CompactDeclaration bool
	Encoding, Standalone                             string
	Doctype                                          *Doctype
}

func (w XMLSerialization) WriteTo(dst io.Writer, n Node) error {
	if n == nil || dst == nil {
		return errors.New("nil XML serialization input")
	}

	if d, ok := n.(*Document); ok {
		if err := w.declaration(dst, d); err != nil {
			return err
		}

		if !w.OmitDoctype && w.Doctype == nil {
			w.Doctype = d.Doctype
		}
	}

	return w.WriteSequence(context.Background(), dst, func(yield func(XMLItem, error) bool) {
		if doc, ok := n.(*Document); ok {
			for child := range Children(doc) {
				if !yield(XMLItem{Node: child}, nil) {
					return
				}
			}
		} else {
			yield(XMLItem{Node: n}, nil)
		}
	})
}

func writeDoctype(dst io.Writer, d *Doctype) error {
	return xmloutput.WriteDoctype(dst, d.Name, d.PublicID, d.SystemID)
}

func (w XMLSerialization) declaration(dst io.Writer, d *Document) error {
	if w.OmitDeclaration || d.standalone == StandaloneNoXMLDecl {
		return nil
	}

	version := w.Version
	if version == "" {
		version = d.Version()
	}

	if version == "" {
		version = "1.0"
	}

	enc := w.Encoding
	if enc == "" {
		enc = d.Encoding()
	}

	decl := fmt.Sprintf("<?xml version=\"%s\" encoding=\"%s\"", version, enc)
	if w.Standalone != "" {
		decl += " standalone=\"" + w.Standalone + "\""
	}

	separator := "\n"
	if w.CompactDeclaration {
		separator = ""
	}

	if _, err := io.WriteString(dst, decl+"?>"+separator); err != nil {
		return err
	}

	return nil
}
