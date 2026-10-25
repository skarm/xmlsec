// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/xmloutput"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	htmlpkg "github.com/skarm/xmlsec/transform/internal/xdm/html"

	"golang.org/x/text/encoding/htmlindex"

	"github.com/skarm/xmlsec/internal/lexicon"
	stream "github.com/skarm/xmlsec/transform/internal/xdm/xmlwriter"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// SerializeItems writes a sequence of items (maps, arrays, atomics, nodes)
// using the specified output definition's method (json or adaptive).
// This is used for result-documents with method="json" or method="adaptive".
// An element, document, comment, or processing-instruction node item carrying
// a character invalid for the target XML version fails with the serialization
// error SERE0006, emitting no truncated output. Other item kinds (text,
// attribute nodes, and atomics) are not range-checked and emit their content
// unmodified.
func SerializeItems(ctx context.Context, w io.Writer, items xdm.Sequence, doc *xdm.Document, outDef *OutputDef) error {
	if outDef == nil {
		outDef = defaultOutputDef()
	}

	switch outDef.Method {
	case lexicon.MethodJSON:
		return serializeJSONItems(ctx, w, items, doc, outDef)
	case lexicon.MethodAdaptive:
		// Adaptive serialization uses its version serialization parameter for every
		// XML fallback and embedded element/document/comment/PI writer. An absent
		// version uses the XML 1.0 default; html-style versions never reach here.
		return serializeAdaptiveItems(ctx, w, items, doc, outDef)
	default:
		if items != nil && xdm.SequenceLen(items) > 0 {
			return serializeItemsWithSeparator(w, items, doc, outDef)
		}

		return SerializeResult(w, doc, outDef)
	}
}

// serializeItemsWithSeparator serializes a sequence of items using the specified
// output method, joining them with the item-separator.
func serializeItemsWithSeparator(w io.Writer, items xdm.Sequence, _ *xdm.Document, outDef *OutputDef) error {
	sep := "\n"
	if outDef.ItemSeparator != nil {
		sep = *outDef.ItemSeparator
	} else if outDef.ItemSeparatorAbsent {
		sep = ""
	}

	idx := 0
	for item := range xdm.SequenceItems(items) {
		if idx > 0 && sep != "" {
			if err := writeFullString(w, sep); err != nil {
				return err
			}
		}

		if err := serializeSeparatedItem(w, item, outDef); err != nil {
			return err
		}

		idx++
	}

	return nil
}

// serializeSeparatedItem keeps each node item buffered until its XML validity
// checks succeed, while atomic and other items are written directly.
func serializeSeparatedItem(w io.Writer, item xdm.Item, outDef *OutputDef) error {
	switch v := item.(type) {
	case xdm.NodeItem:
		return serializeSeparatedNode(w, v.Node, outDef)
	case xdm.AtomicValue:
		s, _ := xpath.AtomicToString(v)
		return writeFullString(w, s)
	default:
		return writeFullString(w, fmt.Sprintf("%v", item))
	}
}

func serializeSeparatedNode(w io.Writer, node xdm.Node, outDef *OutputDef) error {
	var buf bytes.Buffer

	switch node.(type) {
	case *xdm.Element, *xdm.Document:
		writer := separatedItemXMLWriter(outDef)
		if err := writer.WriteTo(&buf, node); err != nil {
			return xmlInvalidCharError(err)
		}
	default:
		writeSeparatedNodeContent(&buf, node)
	}

	return writeFullBytes(w, buf.Bytes())
}

// separatedItemXMLWriter applies an XML version only for XML/XHTML methods.
// HTML versions must not reach the XML writer's OutputVersion validation.
func separatedItemXMLWriter(outDef *OutputDef) xdm.XMLSerialization {
	writer := xdm.XMLSerialization{OmitDeclaration: true}
	if outDef.Method == lexicon.MethodXML || outDef.Method == lexicon.MethodXHTML {
		writer.Version = validOutputXMLVersion(outDef.Version)
	}

	return writer
}

// writeSeparatedNodeContent writes leaf nodes without adding an XML declaration.
func writeSeparatedNodeContent(buf *bytes.Buffer, node xdm.Node) {
	if node.Type() == xdm.CommentNode {
		buf.WriteString("<!--")
		buf.WriteString(xdm.CharacterData(node))
		buf.WriteString("-->")
	} else if node.Type() == xdm.ProcessingInstructionNode {
		buf.WriteString("<?")
		buf.WriteString(node.Name())

		if c := xdm.CharacterData(node); c != "" {
			buf.WriteByte(' ')
			buf.WriteString(c)
		}

		buf.WriteString("?>")
	} else {
		buf.WriteString(xdm.CharacterData(node))
	}
}

// SerializeResult writes the result document to a writer according to the
// output definition. If outDef is nil, defaults to XML output. XDM has no DTD
// node, so a DTD the document carries (for example one xsl:copy-of keeps with
// a copied source document's unparsed entities) is not written: the output
// definition alone decides the document type declaration. doc itself is left
// unchanged.
func SerializeResult(w io.Writer, doc *xdm.Document, outDef *OutputDef) error {
	var charMap map[rune]string
	if outDef != nil {
		charMap = outDef.ResolvedCharMap
	}

	return serializeResult(w, doc, outDef, charMap)
}

// withoutDoctype copies a document before dropping serialization metadata.
func withoutDoctype(doc *xdm.Document) (*xdm.Document, error) {
	if doc.Doctype == nil {
		return doc, nil
	}

	cp, err := xdm.CopyDoc(doc)
	if err != nil {
		return nil, err
	}

	cp.Doctype = nil

	return cp, nil
}

func serializeResult(w io.Writer, doc *xdm.Document, outDef *OutputDef, charMaps ...map[rune]string) error {
	doc, docErr := withoutDoctype(doc)
	if docErr != nil {
		return docErr
	}

	if outDef == nil {
		outDef = defaultOutputDef()
	} else {
		// Clone so html/xhtml auto-detection below never mutates the
		// caller-supplied OutputDef (it may be shared/reused).
		outDef = cloneOutputDef(outDef)
	}

	// XSLT 3.0 §20: When no output method is explicitly specified, auto-detect
	// based on the document element.
	autoHTML := allowsHTMLAutoDetection(outDef, doc)
	detectOutputMethod(outDef, doc, autoHTML)

	// Validate serialization parameters before proceeding.
	if err := validateSerializationParams(context.Background(), outDef, doc); err != nil {
		return err
	}

	var charMap map[rune]string
	if len(charMaps) > 0 {
		charMap = charMaps[0]
	}

	if outDef.Method == lexicon.MethodHTML {
		return serializeEncodedHTML(w, doc, outDef, charMap)
	}

	if outDef.Method == lexicon.MethodXHTML {
		return serializeEncodedXHTML(w, doc, outDef, charMap)
	}

	if outDef.Method == lexicon.MethodXML {
		return serializeEncodedXML(w, doc, outDef, charMap)
	}

	enc := strings.ToLower(outDef.Encoding)
	isUTF16 := enc == lexicon.EncodingUTF16 || enc == nameUtf16
	needsEncodingConversion := enc != "" && enc != lexicon.EncodingUTF8 && enc != lexicon.EncodingUTF8Alt && !isUTF16

	needsNormalization := outDef.NormalizationForm != "" && outDef.NormalizationForm != normalizationFormNone

	// A character-map replacement is immune to normalization. Each output
	// method preserves that provenance while serializing, so normalization is
	// applied there instead of to a byte stream containing both kinds of text.
	// This keeps caller-provided raw output from being interpreted as metadata.
	charMapNormalizesContent := needsNormalization && len(charMap) > 0

	// Buffer when post-processing is needed. Character-map-aware serializers
	// normalize their ordinary content before writing it, so they do not need a
	// normalization-only buffer.
	needsBuffer := needsEncodingConversion || (needsNormalization && !charMapNormalizesContent) || isUTF16

	var (
		target io.Writer
		buf    bytes.Buffer
	)
	if needsBuffer {
		target = &buf
	} else {
		target = w
	}

	// Emit BOM if requested or if UTF-16 (UTF-16 always gets a BOM per spec).
	if err := serializeResultByteOrderMark(outDef, isUTF16, w); err != nil {
		return err
	}

	if err := serializeResultContent(target, doc, outDef, charMap); err != nil {
		return err
	}

	if needsBuffer {
		data := buf.Bytes()

		// Apply Unicode normalization if requested
		if needsNormalization && !charMapNormalizesContent {
			data = applyUnicodeNormalization(data, outDef.NormalizationForm)
		}

		if isUTF16 {
			return transcodeToUTF16(w, data)
		}

		if needsEncodingConversion {
			return transcodeToEncoding(w, data, enc)
		}

		return writeFullBytes(w, data)
	}

	return nil
}

// serializeResultContent dispatches the effective output method after parameter
// validation and BOM emission, before normalization or encoding conversion.
func serializeResultContent(w io.Writer, doc *xdm.Document, outDef *OutputDef, charMap map[rune]string) error {
	switch outDef.Method {
	case lexicon.MethodText:
		return serializeText(w, doc, charMap, outDef.NormalizationForm)
	case lexicon.MethodHTML:
		return serializeHTMLResult(w, doc, outDef, charMap)
	case lexicon.MethodXHTML:
		return serializeXHTML(w, doc, outDef, charMap)
	case lexicon.MethodJSON:
		return serializeJSONResult(w, doc, outDef, charMap)
	case lexicon.MethodAdaptive:
		return serializeAdaptiveItems(context.Background(), w, nil, doc, outDef)
	default:
		return serializeXML(w, doc, outDef, charMap)
	}
}

func serializeHTMLResult(w io.Writer, doc *xdm.Document, outDef *OutputDef, charMap map[rune]string) error {
	return serializeHTML(w, doc, outDef, charMap)
}

func serializeJSONResult(w io.Writer, doc *xdm.Document, outDef *OutputDef, _ map[rune]string) error {
	return serializeJSONItems(context.Background(), w, nil, doc, outDef)
}

func serializeText(w io.Writer, doc *xdm.Document, charMap map[rune]string, normalizationForm string) error {
	// Text output: just write the text content of the document
	sw := stream.NewWriter(shortWriteCheckingWriter{dst: w})

	var unmapped strings.Builder

	flushUnmapped := func() error {
		if unmapped.Len() == 0 {
			return nil
		}

		if err := sw.WriteRaw(normalizeText(unmapped.String(), normalizationForm)); err != nil {
			return err
		}

		unmapped.Reset()

		return nil
	}

	err := xdm.Walk(doc, xdm.NodeWalkerFunc(func(n xdm.Node) error {
		switch n.Type() {
		case xdm.TextNode, xdm.CDATASectionNode:
			text := xdm.CharacterData(n)
			if len(charMap) == 0 {
				return sw.WriteRaw(normalizeText(text, normalizationForm))
			}

			for _, r := range text {
				if replacement, ok := charMap[r]; ok {
					if err := flushUnmapped(); err != nil {
						return err
					}

					if err := sw.WriteRaw(replacement); err != nil {
						return err
					}

					continue
				}

				unmapped.WriteRune(r)
			}
		}

		return nil
	}))
	if err != nil {
		return err
	}

	if err := flushUnmapped(); err != nil {
		return err
	}

	return sw.Flush()
}

// validateSerializationParams checks serialization parameters for errors
// per the XSLT 3.0 serialization spec.
func validateSerializationParams(ctx context.Context, outDef *OutputDef, doc *xdm.Document) error {
	method := outDef.Method

	// SEPM0004: standalone != "omit" with multiple element children of root
	if err := validateSerializationParamsStandalone(outDef, method, doc); err != nil {
		return err
	}

	// SEPM0004: doctype-system with multiple element children of root
	if err := validateOutputDoctype(outDef, method, doc); err != nil {
		return err
	}

	// SEPM0009: omit-xml-declaration="yes" conflicts with standalone or doctype-system
	// Only applicable for xml/xhtml methods — text/html/json don't have XML declarations.
	if err := validateSerializationParamsLanguageVersion(outDef, method); err != nil {
		return err
	}

	// SEPM0010: undeclare-prefixes="yes" with version="1.0"
	if outDef.UndeclarePrefixes && (method == lexicon.MethodXML || method == lexicon.MethodXHTML) && (outDef.Version == "" || outDef.Version == lexicon.XSLTVersion10) {
		return dynamicError(lexicon.ErrSEPM0010,
			"undeclare-prefixes=\"yes\" is not allowed with version=\"1.0\"")
	}

	if !isValidPublicID(outDef.DoctypePublic) || !xmloutput.ValidSystemID(outDef.DoctypeSystem) {
		return dynamicError(lexicon.ErrSEPM0016, "invalid doctype identifier")
	}

	enc := strings.ToLower(outDef.Encoding)
	if enc != "" && enc != lexicon.EncodingUTF8 && enc != lexicon.EncodingUTF8Alt && enc != lexicon.EncodingUTF16 && enc != nameUtf16 {
		_, encErr := htmlindex.Get(enc)
		if encErr != nil {
			return dynamicError(errCodeSESU0007,
				"unsupported encoding %q for %s output method", outDef.Encoding, method)
		}
	}

	// SESU0013: unsupported effective version for HTML output.
	if err := validateHTMLVersion(method, outDef); err != nil {
		return err
	}

	// SESU0011: unsupported normalization-form
	if outDef.NormalizationForm != "" && outDef.NormalizationForm != normalizationFormNone {
		switch outDef.NormalizationForm {
		case normalizationFormNFC, "NFD", "NFKC", "NFKD", lexicon.NormFullyNormalized:
			// supported
		default:
			return dynamicError(lexicon.ErrSESU0011,
				"unsupported normalization-form %q", outDef.NormalizationForm)
		}
	}

	// SERE0012: fully-normalized and result begins with combining character
	if doc != nil && outDef.NormalizationForm == lexicon.NormFullyNormalized {
		if err := checkFullyNormalized(doc); err != nil {
			return err
		}
	}

	if doc != nil && method == lexicon.MethodHTML {
		if err := xpath.ValidateHTMLItem(ctx, xdm.XMLItem{Node: doc}, effectiveHTMLVersion5(outDef)); err != nil {
			return err
		}
	}

	return nil
}

func countRootElements(doc *xdm.Document) int {
	count := 0

	for child := range xdm.Children(doc) {
		if child.Type() == xdm.ElementNode {
			count++
		}
	}

	return count
}

// isValidPublicID checks if a string is a valid public identifier.
// Valid characters: [a-zA-Z0-9], space, newline, '-', '(', ')', '+', ',',
// '.', '/', ':', '=', '?', ';', '!', '*', '#', '@', '$', '_', '%'
func isValidPublicID(s string) bool { return xmloutput.ValidPublicID(s) }

// checkFullyNormalized checks if the result tree violates fully-normalized
// constraints (e.g., starts with a combining character).
func checkFullyNormalized(doc *xdm.Document) error {
	var firstErr error

	werr := xdm.Walk(doc, xdm.NodeWalkerFunc(func(n xdm.Node) error {
		if n.Type() == xdm.TextNode || n.Type() == xdm.CDATASectionNode {
			content := xdm.CharacterData(n)
			if len(content) > 0 {
				r, _ := utf8.DecodeRuneInString(content)
				if unicode.In(r, unicode.Mn, unicode.Mc, unicode.Me) {
					firstErr = dynamicError(errCodeSERE0012,
						"fully-normalized output begins with combining character U+%04X", r)

					return firstErr
				}
			}
		}

		return nil
	}))
	if firstErr == nil {
		// Surfaces a tree cycle (ErrWalkCycle); nil in the normal case.
		firstErr = werr
	}

	return firstErr
}

// requestedHTMLVersion applies html-version precedence, then version, then
// the implementation-defined modern HTML default (5.0).
func requestedHTMLVersion(definition *OutputDef) string {
	return htmlpkg.RequestedVersion(definition.HTMLVersion, definition.Version)
}

func effectiveHTMLVersion5(definition *OutputDef) bool {
	return isHTMLVersion5(requestedHTMLVersion(definition))
}

// isHTMLVersion5 returns true when the html-version string represents
// version 5 or higher (e.g. "5", "5.0", "5.00", "5.1").
func isHTMLVersion5(v string) bool {
	if v == "" {
		return false
	}

	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return false
	}

	return f >= 5.0
}

// detectOutputMethod applies the host-language default for an unspecified method.
func detectOutputMethod(outDef *OutputDef, doc *xdm.Document, autoHTML bool) {
	if !outDef.MethodExplicit && outDef.Method == lexicon.MethodXML {
		if root := doc.DocumentElement(); root != nil {
			if autoHTML && root.LocalName() == lexicon.MethodHTML && root.URI() == "" {
				// Root is "html" in no namespace → HTML output method.
				outDef.Method = lexicon.MethodHTML
				outDef.OmitDeclaration = true
			} else if outDef.languageVersion != 10 && !outDef.implicitXMLMethod && root.LocalName() == lexicon.MethodHTML && root.URI() == lexicon.NamespaceXHTML {
				// Root is "html" in XHTML namespace → XHTML output method.
				outDef.Method = lexicon.MethodXHTML
			}
		}
	}
}

func validateSerializationParamsLanguageVersion(outDef *OutputDef, method string) error {
	if outDef.languageVersion != 10 && outDef.OmitDeclaration && (method == lexicon.MethodXML || method == lexicon.MethodXHTML) {
		if outDef.Standalone == lexicon.ValueYes || outDef.Standalone == lexicon.ValueNo {
			return dynamicError(lexicon.ErrSEPM0009,
				"omit-xml-declaration=\"yes\" conflicts with standalone=%q", outDef.Standalone)
		}

		if outDef.DoctypeSystem != "" && outDef.Version != "" && outDef.Version != lexicon.XSLTVersion10 {
			return dynamicError(lexicon.ErrSEPM0009,
				"omit-xml-declaration=\"yes\" conflicts with doctype-system and version=%q", outDef.Version)
		}
	}

	return nil
}

func serializeResultByteOrderMark(outDef *OutputDef, isUTF16 bool, w io.Writer) error {
	if outDef.ByteOrderMark || isUTF16 {
		if isUTF16 {
			// UTF-16 BE BOM
			if werr := writeFullBytes(w, []byte{0xFE, 0xFF}); werr != nil {
				return werr
			}
		} else {
			// UTF-8 BOM
			if werr := writeFullBytes(w, []byte{0xEF, 0xBB, 0xBF}); werr != nil {
				return werr
			}
		}
	}

	return nil
}

func validateSerializationParamsStandalone(outDef *OutputDef, method string, doc *xdm.Document) error {
	if outDef.Standalone == lexicon.ValueYes || outDef.Standalone == lexicon.ValueNo {
		if method == lexicon.MethodXML || method == lexicon.MethodXHTML {
			elemCount := countRootElements(doc)
			if elemCount > 1 {
				return dynamicError(errCodeSEPM0004,
					"standalone=%q specified but result has %d root elements", outDef.Standalone, elemCount)
			}
		}
	}

	return nil
}

// allowsHTMLAutoDetection excludes XSLT 1.0 results with leading non-whitespace
// text; newer language versions inspect the document element directly.
func allowsHTMLAutoDetection(outDef *OutputDef, doc *xdm.Document) bool {
	if outDef.languageVersion == 10 {
		for child := range xdm.Children(doc) {
			if child.Type() == xdm.ElementNode {
				break
			}

			if child.Type() == xdm.TextNode && !isXMLWhitespaceOnly(xdm.CharacterData(child)) {
				return false
			}
		}
	}

	return true
}

// validateHTMLVersion checks the effective version, including auto-detected
// HTML output and html-version overrides of version.
func validateHTMLVersion(method string, definition *OutputDef) error {
	if method != lexicon.MethodHTML {
		return nil
	}

	requested := requestedHTMLVersion(definition)
	if !htmlpkg.SupportedVersion(requested) {
		return dynamicError(lexicon.ErrSESU0013, "unsupported HTML version %q", requested)
	}

	return nil
}

// validateOutputDoctype requires a single document element for XML doctypes.
func validateOutputDoctype(outDef *OutputDef, method string, doc *xdm.Document) error {
	if outDef.DoctypeSystem != "" {
		if method == lexicon.MethodXML || method == lexicon.MethodXHTML {
			elemCount := countRootElements(doc)
			if elemCount > 1 {
				return dynamicError(errCodeSEPM0004,
					"doctype-system specified but result has %d root elements", elemCount)
			}
		}
	}

	return nil
}

// deferredMarkupSeparator records an item separator that belongs
// immediately before right. Keeping it outside the DOM preserves declaration-free
// adaptive serialization while the output contains only top-level markup.
type deferredMarkupSeparator struct {
	right xdm.MutableNode
	text  string
}

type conditionalKind int

const (
	conditionalOnEmpty conditionalKind = iota + 1
	conditionalOnNonEmpty
)

type conditionalAction struct {
	placeholder       xdm.MutableNode
	selectExpr        *xpath.Expression
	localVars         *varScope
	staticBaseURI     string
	xpathDefaultNS    string
	sourceModule      string
	body              []instruction
	kind              conditionalKind
	sourceLine        int
	hasXPathDefaultNS bool
	prevWasAtomic     bool // whether the output preceding this action was an atomic value
}

type conditionalScope struct {
	pendingStart   int // first raw item produced by this sequence constructor
	hasOutput      bool
	actions        []conditionalAction
	untrackedNodes []xdm.MutableNode // nodes added via addNodeUntracked; removed when on-empty fires
}

type outputFrame struct {
	implicitPrimary     *bool                      // shared claim, present only on frames contributing to the principal result
	current             xdm.MutableNode            // current insertion point
	doc                 *xdm.Document              // result document being built
	seqPlaceholders     map[xdm.Node]xdm.ItemSlice // placeholder PI node -> buffered xsl:sequence items, resolved by evaluateBodyAsDocument
	itemSeparator       *string                    // item-separator serialization parameter; nil means default (" " between adjacent atomics)
	pendingItems        xdm.ItemSlice              // captured items from xsl:sequence
	deferredMarkupSeps  []deferredMarkupSeparator  // top-level adaptive markup separators, held outside the DOM until XML fallback is required
	conditionalScopes   []conditionalScope
	emptyAtomicGen      uint64 // seqConstructorGen when prevWasAtomic was set by an empty-string atomic
	outputSerial        int    // monotonically increases whenever visible output is produced
	seqConstructorGen   uint64 // incremented each time executeSequenceConstructor is called
	captureItems        bool   // when true, xsl:sequence adds to pendingItems instead of DOM
	separateTextNodes   bool   // when true, text nodes are captured as separate string items (prevents DOM merging)
	sequenceMode        bool   // when true, all nodes (text, element, attr, comment, PI) are captured as separate items
	documentConstructor bool   // when true, the frame builds a document node tree; xsl:sequence output is marked with placeholders in the DOM so it interleaves in document order with literal result elements
	prevWasAtomic       bool   // true when last xsl:sequence output was an atomic value (for inter-call space separation)
	prevHadOutput       bool   // true when any item (node or atomic) was previously output; used for item-separator between non-atomic items
}

// materializeDeferredMarkupSeps restores deferred separators in
// document order when a non-markup node requires XML fallback.
func (out *outputFrame) materializeDeferredMarkupSeps() error {
	for _, deferred := range out.deferredMarkupSeps {
		separator := out.doc.CreateText(deferred.text)
		if err := deferred.right.Replace(separator, deferred.right); err != nil {
			return err
		}
	}

	out.deferredMarkupSeps = nil

	return nil
}

// hasChildContent reports whether elem already has a child that an attribute
// must not follow (XTDE0410). The placeholder comment an xsl:on-empty or
// xsl:on-non-empty instruction leaves in elem is not content.
func (out *outputFrame) hasChildContent(elem *xdm.Element) bool {
	for child := elem.FirstChild(); child != nil; child = child.NextSibling() {
		if !out.isConditionalPlaceholder(child) {
			return true
		}
	}

	return false
}

// isConditionalPlaceholder reports whether n is the placeholder of a pending
// xsl:on-empty or xsl:on-non-empty instruction.
func (out *outputFrame) isConditionalPlaceholder(n xdm.Node) bool {
	if n.Type() != xdm.CommentNode {
		return false
	}

	for _, scope := range out.conditionalScopes {
		for _, action := range scope.actions {
			if action.placeholder != nil && xdm.Node(action.placeholder) == n {
				return true
			}
		}
	}

	return false
}

func (out *outputFrame) noteOutput() {
	out.outputSerial++
	if out.implicitPrimary != nil {
		*out.implicitPrimary = true
	}
}

// captureSequenceItems records captured sequence items for later assembly.
//
// In a document-constructor frame (variable/param body without as) at the
// document-node level, the items are recorded behind a placeholder PI inserted
// at the current position in the DOM, so they keep document order with literal
// result elements built directly into the tree (evaluateBodyAsDocument resolves
// the placeholders). In every other case the items are appended to pendingItems
// as before. Callers should only invoke this with a non-empty item slice.
func (out *outputFrame) captureSequenceItems(items xdm.ItemSlice) {
	if out.documentConstructor && out.current == out.doc {
		ph := out.doc.CreatePI(seqPlaceholderTarget, "")
		if err := out.current.AddChild(ph); err == nil {
			if out.seqPlaceholders == nil {
				out.seqPlaceholders = make(map[xdm.Node]xdm.ItemSlice)
			}

			out.seqPlaceholders[ph] = items
			out.noteOutput()

			return
		}
		// AddChild on a document node only fails for invalid input; fall back
		// to buffering so output order is preserved as best-effort.
	}

	out.pendingItems = append(out.pendingItems, items...)
	out.noteOutput()
}

// validOutputXMLVersion returns v when it is a valid XML VersionNum suitable for
// the writer's OutputVersion override, or "" otherwise. The html/xhtml output
// methods carry a non-XML Version (e.g. "4.01"), which must never reach
// OutputVersion (it would fail serialization with ErrInvalidOutputVersion).
func validOutputXMLVersion(v string) string {
	if isValidOutputXMLVersion(v) {
		return v
	}

	return ""
}

// isValidOutputXMLVersion reports whether v is a valid XML VersionNum
// ("1." followed by one or more digits, XML §2.8).
func isValidOutputXMLVersion(v string) bool {
	rest, ok := strings.CutPrefix(v, "1.")
	if !ok || rest == "" {
		return false
	}

	for i := range len(rest) {
		if rest[i] < '0' || rest[i] > '9' {
			return false
		}
	}

	return true
}

func defaultOutputDef() *OutputDef {
	return &OutputDef{Method: lexicon.MethodXML, Encoding: lexicon.EncodingUTF8U}
}
