// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// seqPlaceholderTarget is the PI target used to mark, within a
// document-constructor frame, the position where buffered xsl:sequence output
// must be inserted so it keeps document order with literal result elements.
const seqPlaceholderTarget = "helium-xsl-sequence-placeholder"

type sequenceOutputState struct {
	prevWasAtomic bool
	prevHadOutput bool
	hadAtomic     bool
}

func (ec *execContext) execValueOf(ctx context.Context, inst *valueOfInst) error {
	var value string

	empty := false

	var err error

	switch {
	case inst.Select != nil:
		value, empty, err = ec.evaluateValueOfSelect(ctx, inst)
	case len(inst.Body) > 0:
		value, err = ec.evaluateValueOfBody(ctx, inst)
	}

	if err != nil || empty {
		return err
	}

	return ec.writeConstructedText(value, inst.DisableOutputEscaping && ec.temporaryOutputDepth == 0)
}

func (ec *execContext) evaluateValueOfSelect(ctx context.Context, inst *valueOfInst) (string, bool, error) {
	var value string

	emptySequence := false
	// Default separator for select is " "
	separator := " "

	if inst.Separator != nil {
		var err error

		separator, err = inst.Separator.evaluate(ctx, ec.contextNode)
		if err != nil {
			return "", false, err
		}
	}

	result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
	if err != nil {
		return "", false, err
	}

	seq := result.Sequence()
	// XSLT 1.0 behavior (backwards-compatible processing): with a select and no
	// explicit separator, xsl:value-of outputs the string value of the FIRST
	// item only; the rest are discarded after atomization (§3.10.1).
	if inst.Separator == nil && seq != nil && xdm.SequenceLen(seq) > 1 && ec.isCompatExpr(inst.Select) {
		seq = xdm.ItemSlice{seq.Get(0)}
	}

	if seq == nil || xdm.SequenceLen(seq) == 0 {
		emptySequence = true
	}
	// FOTY0013: maps and functions cannot be atomized
	if err := checkAtomizable(seq); err != nil {
		return "", false, err
	}
	// XSLT spec §11.3: zero-length text nodes in the result sequence
	// are discarded before stringification.
	filtered := filterZeroLengthTextNodes(seq)

	filtered = mergeAdjacentTextNodes(filtered)
	if ec.stylesheet.processorLanguage() == 10 {
		value, err = xpath.XPath10String(filtered)
		if err != nil {
			return "", false, err
		}
	} else {
		value, err = stringifySimpleContent(ctx, filtered, separator)
		if err != nil {
			return "", false, err
		}
	}

	return value, emptySequence, nil
}

// checkAtomizable returns FOTY0013 if the sequence contains any map or
// function items, which cannot be atomized.
func checkAtomizable(seq xdm.Sequence) error {
	for i, size := 0, xdm.SequenceLen(seq); i < size; i++ {
		item := seq.Get(i)
		switch item.(type) {
		case xdm.MapItem:
			return dynamicError(lexicon.ErrFOTY0013, "cannot atomize a map item")
		case xdm.FunctionItem:
			return dynamicError(lexicon.ErrFOTY0013, "cannot atomize a function item")
		}
	}

	return nil
}

// filterZeroLengthTextNodes removes zero-length text nodes from a sequence.
// Per XSLT spec §11.3, these are discarded during xsl:value-of processing.
func filterZeroLengthTextNodes(seq xdm.Sequence) xdm.Sequence {
	// Most value-of results contain no empty text nodes. Delay allocating an
	// output until a removal is needed, retaining the original owned sequence.
	size := xdm.SequenceLen(seq)

	first := 0
	for ; first < size; first++ {
		if ni, ok := seq.Get(first).(xdm.NodeItem); ok && ni.Node.Type() == xdm.TextNode && xdm.CharacterData(ni.Node) == "" {
			break
		}
	}

	if first == size {
		return seq
	}

	result := make(xdm.ItemSlice, 0, xdm.SequenceLen(seq))
	for i := range size {
		item := seq.Get(i)
		if ni, ok := item.(xdm.NodeItem); ok {
			if ni.Node.Type() == xdm.TextNode && len(xdm.CharacterData(ni.Node)) == 0 {
				continue
			}
		}

		result = append(result, item)
	}

	return result
}

func (ec *execContext) evaluateValueOfBody(ctx context.Context, inst *valueOfInst) (string, error) {
	// Default separator for body content is "" (zero-length string)
	separator := ""

	if inst.Separator != nil {
		var err error

		separator, err = inst.Separator.evaluate(ctx, ec.contextNode)
		if err != nil {
			return "", err
		}
	}
	// XSLT 2.0: value-of body is temporary output state (XTDE1480).
	// XSLT 3.0 relaxes this restriction.
	isV2TempOutput := ec.stylesheet.processorLanguage() < 30
	if isV2TempOutput {
		ec.temporaryOutputDepth++
	}

	val, err := ec.evaluateBodySeparateText(ctx, inst.Body)
	if isV2TempOutput {
		ec.temporaryOutputDepth--
	}

	if err != nil {
		return "", err
	}
	// XSLT spec §11.3: adjacent text nodes in the result are merged
	// before the separator is applied.
	val = mergeAdjacentTextNodes(val)

	return stringifySimpleContent(ctx, val, separator)
}

// writeConstructedText surrounds DOE text with serializer markers only when its
// caller is outside a temporary output state.
func (ec *execContext) writeConstructedText(value string, disableEscaping bool) error {
	if disableEscaping {
		// Insert DOE marker PI so the serializer writes this text raw.
		pi := ec.resultDoc.CreatePI(nameDisableOutputEscaping, "")
		if err := ec.addNode(pi); err != nil {
			return err
		}

		text := ec.resultDoc.CreateText(value)
		if err := ec.addNode(text); err != nil {
			return err
		}

		piEnd := ec.resultDoc.CreatePI("enable-output-escaping", "")

		return ec.addNode(piEnd)
	}

	text := ec.resultDoc.CreateText(value)

	return ec.addNode(text)
}

func (ec *execContext) execText(ctx context.Context, inst *textInst) error {
	value := inst.Value
	if inst.TVT != nil {
		ctx = withExecContext(ctx, ec)

		var err error

		value, err = inst.TVT.evaluate(ctx, ec.contextNode)
		if err != nil {
			return err
		}
		// For TVTs that evaluate to empty, in sequenceMode create a
		// zero-length text node (needed for function return values
		// that use text nodes to break atomic adjacency). Outside
		// sequenceMode, just break atomic adjacency chains.
		if value == "" {
			out := ec.currentOutput()
			if out.sequenceMode {
				text := ec.resultDoc.CreateText("")
				return ec.addNode(text)
			}

			out.prevWasAtomic = false

			return nil
		}
	}
	// xsl:text with empty literal content produces a zero-length text node
	// only in sequenceMode (needed for as="text()" variables to receive
	// exactly 1 item). Outside sequenceMode, empty literal text is not
	// added to the result tree but it DOES break atomic adjacency chains:
	// <xsl:text/> between two xsl:sequence instructions prevents the
	// inter-atomic space separator from being inserted (XSLT 3.0 §5.7.2).
	if value == "" && inst.TVT == nil {
		out := ec.currentOutput()
		if out.sequenceMode {
			text := ec.resultDoc.CreateText("")
			return ec.addNode(text)
		}

		out.prevWasAtomic = false

		return nil
	}
	// XSLT 3.0 §20.1: disable-output-escaping is ignored when writing
	// to a temporary tree (variable/parameter body) or sequence mode.
	textDOEEffective := inst.DisableOutputEscaping && ec.temporaryOutputDepth == 0

	return ec.writeConstructedText(value, textDOEEffective)
}

func (ec *execContext) execLiteralText(ctx context.Context, inst *literalTextInst) error {
	value := inst.Value
	if inst.TVT != nil {
		// Text value template: evaluate like an avt
		ctx = withExecContext(ctx, ec)

		var err error

		value, err = inst.TVT.evaluate(ctx, ec.contextNode)
		if err != nil {
			return err
		}
	}

	if value == "" {
		// Empty literal text breaks the atomic adjacency chain,
		// preventing inter-atomic space insertion (XSLT 3.0 §5.7.2).
		// In sequenceMode, create a zero-length text node (needed for
		// function return values that use text boundaries to break
		// atomic adjacency in the caller). Outside sequenceMode, just
		// break adjacency.
		out := ec.currentOutput()
		if out.sequenceMode {
			text := ec.resultDoc.CreateText("")
			return ec.addNode(text)
		}

		out.prevWasAtomic = false

		return nil
	}

	text := ec.resultDoc.CreateText(value)

	return ec.addNode(text)
}

func (ec *execContext) execXSLSequence(ctx context.Context, inst *xslSequenceInst) error {
	result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
	if err != nil {
		return err
	}

	out := ec.currentOutput()
	if out.captureXSLSequence(result.Sequence()) {
		return nil
	}

	state := sequenceOutputState{prevWasAtomic: out.prevWasAtomic, prevHadOutput: out.prevHadOutput}

	seq := flattenArraysInSequence(result.Sequence())
	for item := range xdm.SequenceItems(seq) {
		switch value := item.(type) {
		case xdm.NodeItem:
			state.prevWasAtomic = false
			state.hadAtomic = false

			emitted, err := ec.writeXSLSequenceNode(value.Node)
			if err != nil {
				return err
			}

			if emitted {
				state.prevHadOutput = true
			}
		case xdm.AtomicValue:
			if err := ec.writeXSLSequenceAtomic(out, &state, value); err != nil {
				return err
			}
		case xdm.FunctionItem, xdm.MapItem, *xdm.ArrayItem:
			if !out.captureItems && !ec.isItemOutputMethod() {
				return dynamicError(errCodeXTDE0450, "cannot add a %T to the result tree", item)
			}

			out.pendingItems = append(out.pendingItems, item)
		default:
			if out.captureItems {
				out.pendingItems = append(out.pendingItems, item)
			}
		}
	}

	out.prevWasAtomic = state.hadAtomic || state.prevWasAtomic
	out.prevHadOutput = state.prevHadOutput

	return nil
}

func (ec *execContext) writeXSLSequenceNode(node xdm.Node) (bool, error) {
	if normalizeNode(node) == nil {
		return false, nil
	}

	switch node.Type() {
	case xdm.AttributeNode:
		attr, _ := xdm.AsNode[*xdm.Attribute](node)
		return false, ec.copyAttributeNodeToOutput(attr)
	case xdm.NamespaceNode:
		ns, _ := xdm.AsNode[*xdm.NamespaceNodeWrapper](node)
		return false, ec.copyNamespaceNodeToOutput(ns)
	case xdm.DocumentNode:
		return true, ec.copySequenceDocumentChildren(node)
	}

	copied, err := xdm.CopyNode(node, ec.resultDoc)
	if err != nil {
		return false, err
	}

	if err := ec.addNode(copied); err != nil {
		return false, err
	}

	if elem, ok := copied.(*xdm.Element); ok {
		ec.fixNamespacesAfterCopy(elem)
		fixDescendantDefaultNS(elem)
	}

	return true, nil
}

func (ec *execContext) copySequenceDocumentChildren(doc xdm.Node) error {
	for child := range xdm.Children(doc) {
		if !xdm.IsXDMChild(child) {
			continue
		}

		if _, err := ec.writeXSLSequenceNode(child); err != nil {
			return err
		}
	}

	return nil
}

func (ec *execContext) writeXSLSequenceAtomic(out *outputFrame, state *sequenceOutputState, atomic xdm.AtomicValue) error {
	value, err := xpath.AtomicToString(atomic)
	if err != nil {
		return err
	}

	if value == "" {
		// Empty atomics separate across constructor generations, but do not
		// create tracked output or separators within one expression.
		if state.prevWasAtomic && out.emptyAtomicGen != out.seqConstructorGen {
			if err := ec.writeSequenceSeparator(out, false); err != nil {
				return err
			}
		}

		out.emptyAtomicGen = out.seqConstructorGen
		state.hadAtomic = true

		return nil
	}

	if state.prevWasAtomic || (state.prevHadOutput && out.itemSeparator != nil) {
		if err := ec.writeSequenceSeparator(out, true); err != nil {
			return err
		}
	}

	if err := ec.writeAtomicText(value); err != nil {
		return err
	}

	state.prevWasAtomic = true
	state.hadAtomic = true
	state.prevHadOutput = true

	return nil
}

func (ec *execContext) writeSequenceSeparator(out *outputFrame, tracked bool) error {
	separator := " "
	if out.itemSeparator != nil {
		separator = *out.itemSeparator
	}

	if separator == "" {
		return nil
	}

	text := ec.resultDoc.CreateText(separator)
	if tracked {
		return ec.addNode(text)
	}

	return ec.addNodeUntracked(text)
}

func (ec *execContext) writeAtomicText(value string) error {
	text := ec.resultDoc.CreateText(value)
	ec.markAtomicTextNode(text)

	return ec.addNode(text)
}

// outputSequence writes a sequence of items to the current output.
func (ec *execContext) outputSequence(seq xdm.Sequence) error {
	out := ec.currentOutput()
	if out.captureItems {
		if seq != nil && xdm.SequenceLen(seq) > 0 {
			out.captureSequenceItems(xdm.Materialize(seq))
		}

		return nil
	}

	seq = flattenArraysInSequence(seq)
	prevWasAtomic := out.prevWasAtomic

	for item := range xdm.SequenceItems(seq) {
		switch value := item.(type) {
		case xdm.NodeItem:
			prevWasAtomic = false

			if _, err := ec.writeXSLSequenceNode(value.Node); err != nil {
				return err
			}
		case xdm.AtomicValue:
			if err := ec.writeOutputSequenceAtomic(out, value, prevWasAtomic); err != nil {
				return err
			}

			prevWasAtomic = true
		case xdm.FunctionItem, xdm.MapItem:
			if !out.captureItems && !ec.isItemOutputMethod() {
				return dynamicError(errCodeXTDE0450, "cannot add non-node item to the result tree")
			}

			out.pendingItems = append(out.pendingItems, item)
			out.noteOutput()
		}
	}

	out.prevWasAtomic = prevWasAtomic

	return nil
}

func (ec *execContext) writeOutputSequenceAtomic(out *outputFrame, atomic xdm.AtomicValue, prevWasAtomic bool) error {
	value, err := xpath.AtomicToString(atomic)
	if err != nil {
		return err
	}

	if value == "" {
		return nil
	}

	if prevWasAtomic || (out.prevHadOutput && out.itemSeparator != nil) {
		if err := ec.writeSequenceSeparator(out, true); err != nil {
			return err
		}
	}

	return ec.writeAtomicText(value)
}

// mergeAdjacentTextNodes merges consecutive text node items in a sequence
// into single text nodes. Per XSLT spec §11.3, adjacent text nodes are
// merged before separator insertion in xsl:value-of.
func mergeAdjacentTextNodes(seq xdm.Sequence) xdm.Sequence {
	seqLen := xdm.SequenceLen(seq)
	if seqLen <= 1 {
		return seq
	}

	result := make(xdm.ItemSlice, 0, seqLen)
	for i := 0; i < seqLen; i++ {
		ni, ok := seq.Get(i).(xdm.NodeItem)
		if !ok || ni.Node.Type() != xdm.TextNode {
			result = append(result, seq.Get(i))
			continue
		}
		// Merge consecutive text nodes
		j := i + 1

		var sb strings.Builder
		sb.WriteString(xdm.CharacterData(ni.Node))

		for j < seqLen {
			nj, ok := seq.Get(j).(xdm.NodeItem)
			if !ok || nj.Node.Type() != xdm.TextNode {
				break
			}

			sb.WriteString(xdm.CharacterData(nj.Node))

			j++
		}

		if j > i+1 {
			doc := ni.Node.OwnerDocument()
			text := doc.CreateText(sb.String())
			result = append(result, xdm.NodeItem{Node: text})
			i = j - 1
		} else {
			result = append(result, seq.Get(i))
		}
	}

	return result
}

// removeZeroLengthTextNodes removes text nodes with zero-length string
// value from the sequence. Per XSLT 3.0 §5.7.2, zero-length text nodes
// in the result sequence are removed before separator insertion.
func removeZeroLengthTextNodes(seq xdm.Sequence) xdm.Sequence {
	var result xdm.ItemSlice

	changed := false

	for item := range xdm.SequenceItems(seq) {
		ni, ok := item.(xdm.NodeItem)
		if ok && ni.Node.Type() == xdm.TextNode && len(xdm.CharacterData(ni.Node)) == 0 {
			changed = true
			continue
		}

		result = append(result, item)
	}

	if !changed {
		return seq
	}

	return result
}

// captureXSLSequence captures only the constructor's root insertion point;
// items nested inside a constructed element must be emitted into that element.
func (out *outputFrame) captureXSLSequence(seq xdm.Sequence) bool {
	if out.documentConstructor {
		if !out.captureItems || out.current != out.doc {
			return false
		}

		if seq != nil && xdm.SequenceLen(seq) > 0 {
			out.captureSequenceItems(xdm.Materialize(seq))
		}

		return true
	}

	atRoot := out.doc != nil && (out.current == out.doc.DocumentElement() || out.current == out.doc)
	if !out.captureItems || !atRoot {
		return false
	}

	if seq != nil && xdm.SequenceLen(seq) > 0 {
		out.pendingItems = append(out.pendingItems, xdm.Materialize(seq)...)
		out.noteOutput()
	}

	return true
}

// atomizeSequence converts each item in the sequence to an atomic value.
// Arrays are flattened before atomization.
func atomizeSequence(seq xdm.Sequence) xdm.Sequence {
	seq = flattenArraysInSequence(seq)

	result := make(xdm.ItemSlice, 0, xdm.SequenceLen(seq))
	for item := range xdm.SequenceItems(seq) {
		av, err := xpath.AtomizeItem(item)
		if err != nil {
			result = append(result, xdm.AtomicValue{TypeName: xdm.TypeString, Value: stringifyItem(item)})
		} else {
			result = append(result, av)
		}
	}

	return result
}
