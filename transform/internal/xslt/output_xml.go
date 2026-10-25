// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	stream "github.com/skarm/xmlsec/transform/internal/xdm/xmlwriter"
)

func serializeXML(w io.Writer, doc *xdm.Document, outDef *OutputDef, charMap map[rune]string) error {
	// For non-UTF-8 encodings, use the stream-based serializer which
	// always outputs UTF-8. The encoding conversion is handled by
	// serializeResult's transcoding layer.
	targetEnc := strings.ToLower(outDef.Encoding)
	isNonUTF8 := targetEnc != "" && targetEnc != lexicon.EncodingUTF8 && targetEnc != lexicon.EncodingUTF8Alt
	// When the document has no document element (e.g., result-document
	// producing only comments and text), use the stream-based serializer
	// which does not inject newlines between top-level children.
	noDocElem := doc.DocumentElement() == nil
	// The stream-based serializer honors the XML 1.1 output-version declaration
	// and the undeclare-prefixes namespace-undeclaration output; the default
	// xdm.XMLSerialization path does neither, so route to it when either applies.
	needsXML11 := outDef.UndeclarePrefixes || (outDef.Version != "" && outDef.Version != lexicon.XSLTVersion10)
	if len(charMap) > 0 || hasDOEMarkers(doc) || isNonUTF8 || len(outDef.CDATASections) > 0 || (outDef.Indent && len(outDef.SuppressIndentation) > 0) || noDocElem || needsXML11 {
		return serializeXMLWithCharMap(w, doc, outDef, charMap)
	}

	if outDef.Encoding != "" && doc.Encoding() == lexicon.EncodingUTF8Alt {
		doc.SetEncoding(outDef.Encoding)
	}
	// Per XSLT spec, doctype-public without doctype-system is ignored for xml method.
	if outDef.DoctypeSystem == "" && outDef.DoctypePublic != "" {
		outDef.DoctypePublic = ""
	}

	if outDef.DoctypeSystem != "" && doc.Doctype == nil {
		rootName := methodHTML // default
		if root := doc.DocumentElement(); root != nil {
			rootName = root.Name()
		}

		doc.SetDoctype(rootName, outDef.DoctypePublic, outDef.DoctypeSystem)
	}
	// This path only handles XML 1.0-family output (needsXML11 is false above),
	// so a character invalid in XML 1.0 is a SERE0006 serialization error. The
	// check is folded into the writer's existing escape pass (no extra traversal).
	// Apply a valid output definition version so XML 1.0 overrides a document's
	// own version on this direct writer path.
	writer := xdm.XMLSerialization{}
	if version := validOutputXMLVersion(outDef.Version); version != "" {
		writer.Version = version
	}

	writerNormalizationForm := outDef.NormalizationForm
	if writerNormalizationForm == lexicon.NormFullyNormalized {
		writerNormalizationForm = normalizationFormNFC
	} else if _, ok := resolveNormForm(writerNormalizationForm); !ok {
		writerNormalizationForm = ""
	}

	writer.Normalization = writerNormalizationForm
	writer.Indent = outDef.Indent

	writer.OmitDeclaration = outDef.OmitDeclaration
	if outDef.Standalone == lexicon.ValueYes || outDef.Standalone == lexicon.ValueNo {
		writer.Standalone = outDef.Standalone
	}

	writer.CompactDeclaration = !outDef.Indent

	return xmlInvalidCharError(writer.WriteTo(w, doc))
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
		return dynamicError(errCodeSERE0006, "%s", err.Error())
	}

	return err
}

// injectStandalone inserts standalone="yes" or standalone="no" into the
// XML declaration before the closing "?>".
func injectStandalone(xml, value string) string {
	const declEnd = "?>"

	idx := strings.Index(xml, declEnd)
	if idx < 0 {
		return xml
	}

	return xml[:idx] + " standalone=\"" + value + "\"" + xml[idx:]
}

// serializeXMLWithCharMap serializes an XML document applying character map
// substitutions. Replacement strings are written raw (not escaped).
func serializeXMLWithCharMap(w io.Writer, doc *xdm.Document, outDef *OutputDef, charMap map[rune]string) error {
	// Buffer and post-process when standalone or indent="no".
	needStandalone := !outDef.OmitDeclaration && (outDef.Standalone == lexicon.ValueYes || outDef.Standalone == lexicon.ValueNo)

	needStripNewline := !outDef.Indent && !outDef.OmitDeclaration
	if needStandalone || needStripNewline {
		var buf strings.Builder
		if err := serializeXMLWithCharMapInner(&buf, doc, outDef, charMap); err != nil {
			return err
		}

		out := buf.String()
		if needStandalone {
			out = injectStandalone(out, outDef.Standalone)
		}

		if needStripNewline {
			if idx := strings.Index(out, "?>\n"); idx >= 0 {
				out = out[:idx+2] + out[idx+3:]
			}
		}

		return writeFullString(w, out)
	}

	return serializeXMLWithCharMapInner(w, doc, outDef, charMap)
}

func serializeXMLWithCharMapInner(w io.Writer, doc *xdm.Document, outDef *OutputDef, charMap map[rune]string) error {
	sw := stream.NewWriter(shortWriteCheckingWriter{dst: w})
	// XML 1.1 output serializes restricted control characters as decimal
	// character references. Set this up front so it applies even when the XML
	// declaration is omitted (StartDocument, when written, sets it too).
	if outDef.Version == "1.1" {
		sw = sw.XMLVersion("1.1")
	}

	if !outDef.OmitDeclaration {
		enc := outDef.Encoding
		if enc == "" {
			enc = lexicon.EncodingUTF8U
		}
		// The output XML version defaults to 1.0; xsl:output/@version="1.1"
		// selects an XML 1.1 declaration.
		xmlVersion := lexicon.XSLTVersion10
		if outDef.Version == "1.1" {
			xmlVersion = outDef.Version
		}

		if err := sw.StartDocument(xmlVersion, enc, ""); err != nil {
			return err
		}
	}

	doctype := doc.Doctype
	if outDef.DoctypeSystem != "" {
		doctype = &xdm.Doctype{PublicID: outDef.DoctypePublic, SystemID: outDef.DoctypeSystem}
	}

	// Build CDATA section element set for fast lookup.
	var cdataSet map[string]struct{}
	if len(outDef.CDATASections) > 0 {
		cdataSet = make(map[string]struct{}, len(outDef.CDATASections))
		for _, name := range outDef.CDATASections {
			cdataSet[name] = struct{}{}
		}
	}

	enc := strings.ToLower(outDef.Encoding)

	// Build suppress-indentation set
	var suppressSet map[string]struct{}
	if len(outDef.SuppressIndentation) > 0 {
		suppressSet = make(map[string]struct{}, len(outDef.SuppressIndentation))
		for _, name := range outDef.SuppressIndentation {
			suppressSet[name] = struct{}{}
		}
	}

	ictx := &xmlIndentCtx{
		indent:            outDef.Indent,
		suppressSet:       suppressSet,
		undeclarePrefixes: outDef.UndeclarePrefixes,
	}

	serializer := xmlTreeSerializer{
		doctype:           doctype,
		writer:            &sw,
		charMap:           charMap,
		cdataElems:        cdataSet,
		encoding:          enc,
		normalizationForm: outDef.NormalizationForm,
		indent:            ictx,
	}
	if err := serializer.children(doc); err != nil {
		return err
	}

	return sw.Flush()
}

// xmlIndentCtx tracks indentation state for XML serialization with
// suppress-indentation support.
type xmlIndentCtx struct {
	suppressSet map[string]struct{}
	depth       int
	indent      bool
	suppressed  bool // true when inside a suppress-indentation element
	// undeclarePrefixes enables serialization of XML 1.1 prefixed namespace
	// undeclarations (xmlns:pfx="") from empty-URI namespace declarations in the
	// result tree. A default-namespace undeclaration (xmlns="") is always
	// serialized regardless (it is valid in XML 1.0).
	undeclarePrefixes bool
}

func (ic *xmlIndentCtx) writeIndent(sw *stream.Writer) error {
	if !ic.indent || ic.suppressed {
		return nil
	}

	buf := make([]byte, 1+ic.depth*2)

	buf[0] = '\n'
	for i := 1; i < len(buf); i++ {
		buf[i] = ' '
	}

	return sw.WriteRaw(string(buf))
}

// xmlTreeSerializer keeps the output policy and indentation state together
// while each recursive traversal owns its disable-output-escaping state.
type xmlTreeSerializer struct {
	doctype           *xdm.Doctype
	writer            *stream.Writer
	charMap           map[rune]string
	cdataElems        map[string]struct{}
	encoding          string
	normalizationForm string
	indent            *xmlIndentCtx
}

func (serializer xmlTreeSerializer) children(parent xdm.Node) error {
	doeActive := false
	doctypeEmitted := false
	children := collectChildren(parent)
	hasChildElements := slices.ContainsFunc(children, func(child xdm.Node) bool { return child.Type() == xdm.ElementNode })

	for _, child := range children {
		// DOE markers affect only the remaining siblings in this traversal.
		if child.Type() == xdm.ProcessingInstructionNode {
			switch child.Name() {
			case nameDisableOutputEscaping:
				doeActive = true
				continue
			case "enable-output-escaping":
				doeActive = false
				continue
			}
		}

		switch child.Type() {
		case xdm.ElementNode:
			elem, _ := xdm.AsNode[*xdm.Element](child)
			if parent.Type() == xdm.DocumentNode && serializer.doctype != nil && !doctypeEmitted {
				if err := serializer.writer.WriteDTD(elem.Name(), serializer.doctype.PublicID, serializer.doctype.SystemID); err != nil {
					return err
				}

				doctypeEmitted = true
			}

			if err := serializer.element(elem); err != nil {
				return err
			}
		case xdm.TextNode, xdm.CDATASectionNode:
			if err := serializer.text(parent, xdm.CharacterData(child), doeActive, hasChildElements); err != nil {
				return err
			}
		case xdm.CommentNode:
			if err := serializer.writer.WriteComment(xdm.CharacterData(child)); err != nil {
				return err
			}
		case xdm.ProcessingInstructionNode:
			if err := serializer.writer.WritePI(child.Name(), xdm.CharacterData(child)); err != nil {
				return err
			}
		}
	}

	return nil
}

func collectChildren(n xdm.Node) []xdm.Node {
	var children []xdm.Node
	for child := range xdm.Children(n) {
		children = append(children, child)
	}

	return children
}

func (serializer xmlTreeSerializer) element(elem *xdm.Element) error {
	if err := serializer.indent.writeIndent(serializer.writer); err != nil {
		return err
	}

	if err := serializer.writer.StartElementNS(elem.Prefix(), elem.LocalName(), elem.URI()); err != nil {
		return err
	}

	if err := serializer.namespaces(elem); err != nil {
		return err
	}

	for _, attr := range elem.Attributes() {
		if err := writeAttrWithCharMap(serializer.writer, attr.Name(), attr.Value(), serializer.charMap, serializer.normalizationForm); err != nil {
			return err
		}
	}

	wasSuppressed := serializer.indent.suppressed
	if elemMatchesSuppressSet(elem, serializer.indent.suppressSet) {
		serializer.indent.suppressed = true
	}

	serializer.indent.depth++
	if err := serializer.children(elem); err != nil {
		return err
	}

	serializer.indent.depth--
	// Indent the closing tag only when the element contains child elements.
	if elemHasChildElements(elem) {
		if err := serializer.indent.writeIndent(serializer.writer); err != nil {
			return err
		}
	}

	serializer.indent.suppressed = wasSuppressed

	return serializer.writer.EndElement()
}

// expandedElemName returns the expanded name for matching suppress-indentation.
func expandedElemName(elem *xdm.Element) string {
	if uri := elem.URI(); uri != "" {
		return xdm.ClarkName(uri, elem.LocalName())
	}

	return elem.LocalName()
}

// elemMatchesSuppressSet checks if the element name (with prefix or expanded)
// matches the suppress-indentation set.
func elemMatchesSuppressSet(elem *xdm.Element, suppressSet map[string]struct{}) bool {
	if len(suppressSet) == 0 {
		return false
	}

	if _, ok := suppressSet[expandedElemName(elem)]; ok {
		return true
	}

	return false
}

func elemHasChildElements(elem *xdm.Element) bool {
	for child := range xdm.Children(elem) {
		if child.Type() == xdm.ElementNode {
			return true
		}
	}

	return false
}

// writeAttrWithCharMap writes an XML attribute with character map awareness.
// Mapped characters are written raw (unescaped) while unmapped characters
// go through normal XML attribute escaping.
func writeAttrWithCharMap(sw *stream.Writer, name, value string, charMap map[rune]string, normalizationForm string) error {
	if len(charMap) == 0 {
		return sw.WriteAttribute(name, normalizeText(value, normalizationForm))
	}

	hasMapped := false

	for _, r := range value {
		if _, ok := charMap[r]; ok {
			hasMapped = true
			break
		}
	}

	if !hasMapped {
		return sw.WriteAttribute(name, normalizeText(value, normalizationForm))
	}

	if err := sw.StartAttribute(name); err != nil {
		return err
	}

	var unmapped strings.Builder

	flushUnmapped := func() error {
		if unmapped.Len() == 0 {
			return nil
		}

		if err := sw.WriteString(normalizeText(unmapped.String(), normalizationForm)); err != nil {
			return err
		}

		unmapped.Reset()

		return nil
	}

	for _, r := range value {
		if repl, ok := charMap[r]; ok {
			if err := flushUnmapped(); err != nil {
				return err
			}

			if err := sw.WriteRaw(repl); err != nil {
				return err
			}
		} else {
			unmapped.WriteRune(r)
		}
	}

	if err := flushUnmapped(); err != nil {
		return err
	}

	return sw.EndAttribute()
}

func (serializer xmlTreeSerializer) text(parent xdm.Node, text string, doeActive, hasChildElements bool) error {
	// Formatting whitespace is omitted only while indentation is enabled
	// outside a suppress-indentation subtree containing element children.
	if serializer.indent.indent && !serializer.indent.suppressed && hasChildElements && isXMLWhitespaceOnly(text) {
		return nil
	}

	if doeActive {
		return serializer.writer.WriteRaw(normalizeRawXMLContent(text, serializer.normalizationForm))
	}

	if inCDATAElement(parent, serializer.cdataElems) {
		return writeCDATAWithEncoding(serializer.writer, text, serializer.encoding, serializer.normalizationForm)
	}

	return writeTextWithCharMap(serializer.writer, text, serializer.charMap, serializer.normalizationForm)
}

// writeTextWithCharMap writes text content, applying character map substitutions.
// Mapped characters are written raw (unescaped), unmapped characters are written
// as normal text (with XML escaping).
func writeTextWithCharMap(sw *stream.Writer, text string, charMap map[rune]string, normalizationForm string) error {
	var unmapped strings.Builder

	flushUnmapped := func() error {
		if unmapped.Len() == 0 {
			return nil
		}

		if err := sw.WriteString(normalizeText(unmapped.String(), normalizationForm)); err != nil {
			return err
		}

		unmapped.Reset()

		return nil
	}

	for _, r := range text {
		if repl, ok := charMap[r]; ok {
			// Flush any accumulated unmapped text first
			if err := flushUnmapped(); err != nil {
				return err
			}

			if err := sw.WriteRaw(repl); err != nil {
				return err
			}
		} else {
			unmapped.WriteRune(r)
		}
	}

	return flushUnmapped()
}

func (serializer xmlTreeSerializer) namespaces(elem *xdm.Element) error {
	elemPrefix := elem.Prefix()
	for _, ns := range elem.Namespaces() {
		if ns.Prefix() == elemPrefix {
			continue // already declared by StartElementNS
		}
		// The "xml" prefix is predefined by the Namespaces in XML
		// spec and bound implicitly everywhere, so a redundant,
		// non-canonical xmlns:xml declaration must never be emitted.
		if ns.Prefix() == methodXML {
			continue
		}

		if ns.Prefix() == "" {
			if err := serializer.writer.WriteAttribute("xmlns", ns.URI()); err != nil {
				return err
			}
		} else {
			// A prefixed namespace undeclaration (empty URI) is an XML 1.1
			// construct; emit it only when undeclare-prefixes is enabled,
			// otherwise the prefix is simply left undeclared in the output.
			if ns.URI() == "" && !serializer.indent.undeclarePrefixes {
				continue
			}

			if err := serializer.writer.WriteAttribute("xmlns:"+ns.Prefix(), ns.URI()); err != nil {
				return err
			}
		}
	}

	return nil
}
