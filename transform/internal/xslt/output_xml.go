package xslt

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// XML result paths share escaping, maps, normalization, CDATA and DOE scopes.
func serializeXML(w io.Writer, doc *xdm.Document, definition *OutputDef, charMap map[rune]string) error {
	options := streamXMLWriteOptions(definition, strings.ToLower(definition.Encoding))
	options.CharacterMap, options.DOEMarkers = charMap, true

	writer := xdm.XMLSerialization{XMLWriteOptions: options, Encoding: definition.Encoding, OmitDeclaration: definition.OmitDeclaration, OmitDoctype: definition.DoctypeSystem == "", CompactDeclaration: !definition.Indent}
	if definition.Standalone == lexicon.ValueYes || definition.Standalone == lexicon.ValueNo {
		writer.Standalone = definition.Standalone
	}

	if definition.DoctypeSystem != "" {
		writer.Doctype = &xdm.Doctype{PublicID: definition.DoctypePublic, SystemID: definition.DoctypeSystem}
	}

	return xmlInvalidCharError(writer.WriteTo(w, doc))
}

func serializeEncodedXML(w io.Writer, doc *xdm.Document, definition *OutputDef, charMap map[rune]string) error {
	output, finish, err := encodedOutput(context.Background(), w, definition)
	if err != nil {
		return err
	}

	if err = serializeXML(output, doc, definition, charMap); err != nil {
		return err
	}

	return finish()
}

func writeFullString(w io.Writer, s string) error {
	n, err := io.WriteString(w, s)
	if err != nil {
		return err
	}

	if n != len(s) {
		return io.ErrShortWrite
	}

	return nil
}

func writeFullBytes(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err != nil {
		return err
	}

	if n != len(data) {
		return io.ErrShortWrite
	}

	return nil
}

type shortWriteCheckingWriter struct {
	dst io.Writer
}

func (w shortWriteCheckingWriter) Write(data []byte) (int, error) {
	n, err := w.dst.Write(data)
	if err == nil && n != len(data) {
		return n, io.ErrShortWrite
	}

	return n, err
}

// xmlInvalidCharError maps the writer's ErrInvalidXMLChar sentinel to the
// XSLT serialization error SERE0006, passing every other error (and nil)
// through unchanged.
func xmlInvalidCharError(err error) error {
	if err != nil && errors.Is(err, tree.ErrMalformed) {
		return dynamicError(lexicon.ErrSERE0006, "%s", err.Error())
	}

	return err
}
