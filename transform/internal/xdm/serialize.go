package xdm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/internal/xmloutput"
)

// XML declaration fragments preserve the exact output spelling and quoting.
// Version suffixes accept only decimal digits after the XML 1.x prefix.
const (
	xmlDeclarationVersionPrefix = "1."
	xmlDeclarationDigits        = "0123456789"
	xmlDeclarationFormat        = "<?xml " + lexicon.DeclVersion + "=\"%s\" " + lexicon.DeclEncoding + "=\"%s\""
	standaloneAttributePrefix   = " " + lexicon.DeclStandalone + "=\""
)

// XMLSerialization combines XDM declaration metadata with the project XML writer's options.
// XML character and name validation is always enforced by internal/tree.
type XMLSerialization struct {
	tree.XMLWriteOptions
	// OmitDeclaration suppresses the XML declaration for document output.
	OmitDeclaration bool
	// OmitDoctype suppresses document type output.
	OmitDoctype bool
	// CompactDeclaration omits the newline that otherwise follows the XML declaration.
	CompactDeclaration bool
	// Encoding overrides the document's encoding label for serialization.
	Encoding string
	// Standalone emits an explicit standalone attribute when nonempty.
	Standalone string
	// Doctype overrides document type metadata. Nil uses the document's declaration when
	// available.
	Doctype *Doctype
}

// WriteTo serializes a borrowed node with declaration metadata using a background
// context. It leaves dst open and can leave partial output on error; use
// WriteSequence when cancellation is required.
func (w XMLSerialization) WriteTo(dst io.Writer, n Node) error {
	if IsNilNode(n) || nilcheck.IsNil(dst) {
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

func (w XMLSerialization) declaration(dst io.Writer, d *Document) error {
	if w.OmitDeclaration || d.standalone == StandaloneNoXMLDecl {
		return nil
	}

	version := w.Version
	if version == "" {
		version = d.Version()
	}

	if version == "" {
		version = lexicon.XMLVersion10
	}

	enc := w.Encoding
	if enc == "" {
		enc = d.Encoding()
	}

	versionDigits, versionPrefix := strings.CutPrefix(version, xmlDeclarationVersionPrefix)
	if !versionPrefix || versionDigits == "" || strings.Trim(versionDigits, xmlDeclarationDigits) != "" {
		return fmt.Errorf("%w: invalid XML declaration version %q", tree.ErrMalformed, version)
	}

	if !xmlchar.IsValidEncName(enc) {
		return fmt.Errorf("%w: invalid XML declaration encoding %q", tree.ErrMalformed, enc)
	}

	if w.Standalone != "" && w.Standalone != lexicon.ValueYes && w.Standalone != lexicon.ValueNo {
		return fmt.Errorf("%w: invalid XML declaration standalone %q", tree.ErrMalformed, w.Standalone)
	}

	decl := fmt.Sprintf(xmlDeclarationFormat, version, enc)
	if w.Standalone != "" {
		decl += standaloneAttributePrefix + w.Standalone + "\""
	}

	separator := "\n"
	if w.CompactDeclaration {
		separator = ""
	}

	declaration := decl + "?>" + separator

	n, err := io.WriteString(dst, declaration)
	if err != nil {
		return err
	}

	if n != len(declaration) {
		return io.ErrShortWrite
	}

	return nil
}

func writeDoctype(dst io.Writer, d *Doctype) error {
	return xmloutput.WriteDoctype(dst, d.Name, d.PublicID, d.SystemID)
}
