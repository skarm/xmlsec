package xdm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/xmloutput"
)

// XMLSerialization combines XDM declaration metadata with the project XML writer's options.
// XML character and name validation is always enforced by internal/tree.
type XMLSerialization struct {
	tree.XMLWriteOptions
	OmitDeclaration, OmitDoctype, CompactDeclaration bool
	Encoding, Standalone                             string
}

func (w XMLSerialization) WriteTo(dst io.Writer, n Node) error {
	if n == nil || dst == nil {
		return errors.New("nil XML serialization input")
	}

	var nodes []*tree.Node
	if d, ok := n.(*Document); ok {
		nodes = d.raw.Children
		if err := w.declaration(dst, d); err != nil {
			return err
		}

		if !w.OmitDoctype && d.Doctype != nil {
			if err := writeDoctype(dst, d.Doctype); err != nil {
				return err
			}
		}
	} else {
		nodes = []*tree.Node{n.view().raw}
	}

	options := w.XMLWriteOptions

	options.SelfClose, options.Reconcile = true, true
	if strings.EqualFold(w.Encoding, "US-ASCII") {
		options.ASCII = true
	}

	_, err := tree.WriteXMLFragmentOptions(context.Background(), dst, nodes, int(^uint(0)>>1), options)

	return err
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
