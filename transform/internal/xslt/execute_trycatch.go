// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func (ec *execContext) execMessage(ctx context.Context, inst *messageInst) error {
	var (
		value   string
		bodySeq xdm.ItemSlice
	)

	if inst.Select != nil {
		result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
		if err != nil {
			// Errors evaluating message content are recoverable
			value = err.Error()
		} else {
			bodySeq = xdm.Materialize(result.Sequence())

			s, serr := serializeMessageSequence(bodySeq)
			if serr != nil {
				return dynamicErrorCause(errCodeSERE0006, serr,
					"xsl:message content could not be serialized: %s", serr)
			}

			value = s
		}
	}

	if returned0, matchedBranch := execMessageBody(ctx, inst, ec, &value, &bodySeq); matchedBranch {
		return returned0
	}

	terminate := false

	if inst.Terminate != nil {
		termStr, err := inst.Terminate.evaluate(ctx, ec.contextNode)
		if err != nil {
			return err
		}

		termStr = strings.TrimSpace(termStr)
		switch termStr {
		case lexicon.ValueYes, lexicon.ValueTrue, "1":
			terminate = true
		case lexicon.ValueNo, lexicon.ValueFalse, "0":
			terminate = false
		default:
			// XTDE0030: avt value is not a valid xs:boolean
			return dynamicError(errCodeXTDE0030,
				"xsl:message/@terminate value %q is not a valid boolean (yes|no|true|false|1|0)", termStr)
		}
	}

	if ec.msgHandler != nil {
		if err := ec.msgHandler.HandleMessage(value, terminate); err != nil {
			return err
		}
	}

	if terminate {
		errorCode := errCodeXTMM9000

		if inst.ErrorCode != nil {
			code, err := inst.ErrorCode.evaluate(ctx, ec.contextNode)
			if err == nil && code != "" {
				errorCode = code
			}
		}

		return &XSLTError{
			Code:    errorCode,
			Message: value,
			Value:   bodySeq,
			Cause:   ErrTerminated,
		}
	}

	return nil
}

// serializeMessageSequence converts a sequence to a string suitable for
// xsl:message output. Node items (elements, documents) are serialized as
// XML so that the message preserves markup structure. Atomic values are
// converted to their string representations and joined with spaces.
func serializeMessageSequence(seq xdm.Sequence) (string, error) {
	if seq == nil || xdm.SequenceLen(seq) == 0 {
		return "", nil
	}

	var sb strings.Builder

	prevWasAtomic := false

	for item := range xdm.SequenceItems(seq) {
		ni, isNode := item.(xdm.NodeItem)
		if !isNode {
			// Atomic value — stringify and space-separate
			av, err := xpath.AtomizeItem(item)
			if err != nil {
				continue
			}

			s, err := xpath.AtomicToString(av)
			if err != nil {
				continue
			}

			if prevWasAtomic && sb.Len() > 0 {
				sb.WriteByte(' ')
			}

			sb.WriteString(s)

			prevWasAtomic = true

			continue
		}

		prevWasAtomic = false

		var buf bytes.Buffer

		switch n := ni.Node.(type) {
		case *xdm.Document:
			if err := (xdm.XMLSerialization{OmitDeclaration: true}).WriteTo(&buf, n); err != nil {
				return "", err
			}
		case *xdm.Element:
			if err := (xdm.XMLSerialization{}).WriteTo(&buf, n); err != nil {
				return "", err
			}
		case *xdm.Comment:
			// Serialize comments as XML so they roundtrip properly
			buf.WriteString("<!--")
			buf.WriteString(xdm.CharacterData(n))
			buf.WriteString("-->")
		case *xdm.ProcessingInstruction:
			buf.WriteString("<?")
			buf.WriteString(n.Name())

			if c := xdm.CharacterData(n); len(c) > 0 {
				buf.WriteByte(' ')
				buf.WriteString(c)
			}

			buf.WriteString("?>")
		default:
			// Text, CDATA, etc. — use string value
			sb.WriteString(xdm.CharacterData(ni.Node))
			continue
		}

		sb.WriteString(buf.String())
	}

	return sb.String(), nil
}

func execMessageBody(ctx context.Context, inst *messageInst, ec *execContext, value *string, bodySeq *xdm.ItemSlice) (returned0 error, matchedBranch bool) {
	if len(inst.Body) > 0 {
		// XSLT 2.0: message body is temporary output state (XTDE1480).
		// XSLT 3.0 relaxes this restriction.
		isV2TempOutput := ec.stylesheet.version != "" && ec.stylesheet.version < "3.0"
		if isV2TempOutput {
			ec.temporaryOutputDepth++
		}

		val, err := ec.evaluateBody(ctx, inst.Body)
		if isV2TempOutput {
			ec.temporaryOutputDepth--
		}

		if err != nil {
			// XTDE1480 is a fatal error, not recoverable.
			if isXSLTError(err, errCodeXTDE1480) {
				return err, true
			}
			// Other errors evaluating message body are recoverable
			(*value) += err.Error()
		} else {
			(*bodySeq) = append((*bodySeq), xdm.Materialize(val)...)

			s, serr := serializeMessageSequence(val)
			if serr != nil {
				return dynamicErrorCause(errCodeSERE0006, serr,
					"xsl:message content could not be serialized: %s", serr), true
			}

			(*value) += s
		}
	}

	return
}

func (ec *execContext) execTryCatch(ctx context.Context, inst *tryCatchInst) error {
	if !inst.RollbackOutput {
		return ec.execTryCatchNoRollback(ctx, inst)
	}

	root, err := ec.beginTryOutput()
	if err != nil {
		return err
	}

	savedVarScope := ec.localVars
	ec.pushVarScope()
	tryErr := ec.executeTryBody(ctx, inst)

	tryFrame := ec.outputStack[len(ec.outputStack)-1]
	ec.outputStack = ec.outputStack[:len(ec.outputStack)-1]
	ec.localVars = savedVarScope

	// Circular references are rejected before catch selection or control flow.
	if tryErr != nil && errors.Is(tryErr, ErrCircularRef) {
		return dynamicError(errCodeXTDE0640, "%s", tryErr.Error())
	}

	if tryErr != nil && (errors.Is(tryErr, errBreak) || errors.Is(tryErr, errNextIter)) {
		if err := ec.copyTryChildren(root); err != nil {
			return err
		}

		return tryErr
	}

	if tryErr == nil {
		return ec.commitTryOutput(root, tryFrame)
	}

	return ec.executeMatchedCatch(ctx, inst.Catches, tryErr)
}

func (ec *execContext) beginTryOutput() (*xdm.Element, error) {
	doc := xdm.NewDefaultDocument()

	root, err := doc.CreateElement("_try")
	if err != nil {
		return nil, err
	}

	if err := doc.AddChild(root); err != nil {
		return nil, err
	}

	// Inherit capture so maps, arrays and function items can flow through.
	capture := ec.currentOutput().captureItems
	ec.outputStack = append(ec.outputStack, &outputFrame{doc: doc, current: root, captureItems: capture})

	return root, nil
}

func (ec *execContext) executeTryBody(ctx context.Context, inst *tryCatchInst) error {
	if inst.Select != nil {
		result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
		if err != nil {
			return err
		}

		return ec.outputSequence(result.Sequence())
	}

	for _, child := range inst.Try {
		if err := ec.executeInstruction(ctx, child); err != nil {
			return err
		}
	}

	return nil
}

func (ec *execContext) commitTryOutput(root *xdm.Element, frame *outputFrame) error {
	if err := ec.copyTryChildren(root); err != nil {
		return err
	}

	// Preserve ordering with surrounding DOM nodes in document constructors.
	if len(frame.pendingItems) > 0 {
		ec.currentOutput().captureSequenceItems(frame.pendingItems)
	}

	return nil
}

func (ec *execContext) executeMatchedCatch(ctx context.Context, clauses []*catchClause, tryErr error) error {
	namespace, code, description, qname := caughtErrorDetails(tryErr)

	clause := matchingCatchClause(clauses, catchErrorClark(code, qname))
	if clause == nil {
		return tryErr
	}

	ec.pushVarScope()
	defer ec.popVarScope()

	ec.bindCatchVariables(namespace, description, qname, ec.caughtTryValue(tryErr))

	if clause.Select != nil {
		result, err := ec.evalXPath(ctx, clause.Select, ec.contextNode)
		if err != nil {
			return err
		}

		return ec.outputSequence(result.Sequence())
	}

	return ec.executeSequenceConstructor(ctx, clause.Body)
}

func (ec *execContext) bindCatchVariables(namespace, description string, code xdm.QNameValue, value xdm.Sequence) {
	ec.setVar(xdm.ClarkName(namespace, "code"), xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeQName, Value: code}})
	ec.setVar(xdm.ClarkName(namespace, "description"), xdm.SingleString(description))
	ec.setVar(xdm.ClarkName(namespace, "value"), value)
	ec.setVar(xdm.ClarkName(namespace, "module"), xdm.SingleString(ec.errSourceModule))
	ec.setVar(xdm.ClarkName(namespace, "line-number"), xdm.SingleInteger(int64(ec.errSourceLine)))
	ec.setVar(xdm.ClarkName(namespace, "column-number"), xdm.SingleInteger(0))
}

// execTryCatchNoRollback writes directly to the parent output and rejects
// ordinary errors after output has been committed.
func (ec *execContext) execTryCatchNoRollback(ctx context.Context, inst *tryCatchInst) error {
	out := ec.currentOutput()
	serial := out.outputSerial
	savedVarScope := ec.localVars
	ec.pushVarScope()
	tryErr := ec.executeTryBody(ctx, inst)
	ec.localVars = savedVarScope

	if tryErr == nil {
		return nil
	}

	if errors.Is(tryErr, errBreak) || errors.Is(tryErr, errNextIter) {
		return tryErr
	}

	if out.outputSerial != serial {
		return dynamicError(errCodeXTDE3530,
			"xsl:try with rollback-output='no': output was written before error and cannot be rolled back")
	}

	// This path establishes catch variables even if no clause matches.
	ec.pushVarScope()
	defer ec.popVarScope()

	namespace, code, description, qname := caughtErrorDetails(tryErr)
	ec.bindCatchVariables(namespace, description, qname, xdm.EmptySequence())

	if clause := matchingCatchClause(inst.Catches, catchErrorClark(code, qname)); clause != nil {
		return ec.executeSequenceConstructor(ctx, clause.Body)
	}

	return tryErr
}

func (ec *execContext) copyTryChildren(root *xdm.Element) error {
	for child := range xdm.Children(root) {
		copied, err := xdm.CopyNode(child, ec.resultDoc)
		if err != nil {
			return err
		}

		if err := ec.addNode(copied); err != nil {
			return err
		}
	}

	return nil
}

func (ec *execContext) caughtTryValue(tryErr error) xdm.Sequence {
	xsltError, found := errors.AsType[*XSLTError](tryErr)
	if !found {
		return xdm.EmptySequence()
	}

	value, ok := xsltError.Value.(xdm.Sequence)
	if !ok || xdm.SequenceLen(value) == 0 {
		return xdm.EmptySequence()
	}

	// Copy nodes into the result document; failed copies retain the item.
	var copied xdm.ItemSlice

	for item := range xdm.SequenceItems(value) {
		if node, ok := item.(xdm.NodeItem); ok {
			duplicate, err := xdm.CopyNode(node.Node, ec.resultDoc)
			if err == nil {
				copied = append(copied, xdm.NodeItem{Node: duplicate})
				continue
			}
		}

		copied = append(copied, item)
	}

	return copied
}

func matchingCatchClause(clauses []*catchClause, code string) *catchClause {
	for _, clause := range clauses {
		if catchMatches(clause, code) {
			return clause
		}
	}

	return nil
}

func catchErrorClark(code string, qname xdm.QNameValue) string {
	if qname.URI != "" {
		return xdm.ClarkName(qname.URI, qname.Local)
	}

	return code
}

// catchMatches returns true if a catch clause matches the given error code.
// errClark is the error code in Clark notation: "{uri}local" or just "local" if no namespace.
func catchMatches(clause *catchClause, errClark string) bool {
	if len(clause.Errors) == 0 {
		return true // no errors attribute = match all
	}

	errLocal := errClark
	if strings.HasPrefix(errClark, "{") {
		if _, after, ok := strings.Cut(errClark, "}"); ok {
			errLocal = after
		}
	}

	for _, pattern := range clause.Errors {
		if pattern == "*" {
			return true
		}
		// *:local — match any namespace with this local name
		if strings.HasPrefix(pattern, "*:") {
			if pattern[2:] == errLocal {
				return true
			}

			continue
		}
		// Q{ns}* — match any local name in this namespace
		if strings.HasSuffix(pattern, "}*") {
			ns := pattern[1 : len(pattern)-2]
			if strings.HasPrefix(errClark, "{"+ns+"}") {
				return true
			}

			continue
		}
		// Both errClark and pattern are in the same format from resolveQName:
		// - Prefixed names → "{uri}local" (Clark notation)
		// - Unprefixed names → "local" (no namespace)
		if pattern == errClark {
			return true
		}
	}

	return false
}

// caughtErrorDetails resolves the most specific typed cause for catch matching.
func caughtErrorDetails(tryErr error) (string, string, string, xdm.QNameValue) {
	errNS := lexicon.NamespaceErr
	errCode := errCodeXSLT0000
	errDesc := tryErr.Error()

	var errQName xdm.QNameValue

	if xErr, ok := errors.AsType[*XSLTError](tryErr); ok {
		errCode = xErr.Code
		errDesc = xErr.Message
		errQName = xdm.QNameValue{Prefix: lexicon.PrefixErr, URI: errNS, Local: errCode}
		// If this is a wrapper error (like XTDE0045 for avt), check inner
		// cause for a more specific error code.
		if xErr.Cause != nil {
			if innerXP, ok := errors.AsType[*xdm.Error](xErr.Cause); ok {
				errCode = innerXP.Code
				errDesc = innerXP.Message
				errQName = innerXP.CodeQName()
			} else if innerXS, ok := errors.AsType[*XSLTError](xErr.Cause); ok {
				errCode = innerXS.Code
				errDesc = innerXS.Message
				errQName = xdm.QNameValue{Prefix: lexicon.PrefixErr, URI: errNS, Local: innerXS.Code}
			}
		}
	} else if xpErr, ok := errors.AsType[*xdm.Error](tryErr); ok {
		errCode = xpErr.Code
		errDesc = xpErr.Message
		errQName = xpErr.CodeQName()
	}

	if errQName.Local == "" {
		errQName = xdm.QNameValue{Prefix: lexicon.PrefixErr, URI: errNS, Local: errCode}
	}

	return errNS, errCode, errDesc, errQName
}
