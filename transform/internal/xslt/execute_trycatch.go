// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func (ec *execContext) execMessage(ctx context.Context, inst *messageInst) error {
	return ec.execMessageWithDefaults(ctx, inst, false, errCodeXTMM9000)
}

func (ec *execContext) execMessageWithDefaults(ctx context.Context, inst *messageInst, terminate bool, defaultCode string) error {
	message, err := ec.messageDocument(ctx, inst)
	if err != nil {
		return err
	}

	message.Output = &OutputDef{Method: lexicon.MethodXML, MethodExplicit: true, OmitDeclaration: true}

	var output messageWriter

	output.ctx = ctx
	if err := SerializeValue(ctx, &output, message); err != nil {
		if failure := preserveControlFailure(ctx, err); failure != nil {
			return failure
		}

		output.Reset()

		if _, failure := output.WriteString(err.Error()); failure != nil {
			return failure
		}
	}

	value := output.String()

	if inst.Terminate != nil {
		termStr, err := inst.Terminate.evaluate(ctx, ec.contextNode)
		if err != nil {
			return err
		}

		var valid bool

		terminate, valid = parseMessageTerminate(termStr, ec.stylesheet.processorLanguage() >= 30)
		if !valid {
			return dynamicError(errCodeXTDE0030, "invalid xsl:message/@terminate value %q", termStr)
		}
	}

	errorCode, err := ec.messageErrorCode(ctx, inst, defaultCode)
	if err != nil {
		return err
	}

	if ec.msgHandler != nil {
		if err := ec.msgHandler.HandleMessage(value, terminate); err != nil {
			return err
		}
	}

	if terminate {
		return &XSLTError{
			Code:          errorCode.Local,
			QualifiedCode: errorCode,
			Message:       value,
			Value:         message.Items,
			Cause:         ErrTerminated,
		}
	}

	return nil
}

// Cancellation and exhausted budgets must terminate execution rather than
// being converted into recoverable content or type errors.
func preserveControlFailure(ctx context.Context, err error) error {
	if failure := xpath.ControlFailure(ctx, err); failure != nil {
		return failure
	}

	if errors.Is(err, ErrResourceTooLarge) {
		return err
	}

	return nil
}

func (ec *execContext) messageErrorCode(ctx context.Context, inst *messageInst, fallback string) (xdm.QNameValue, error) {
	defaultName := xdm.QNameValue{Prefix: lexicon.PrefixErr, URI: lexicon.NamespaceErr, Local: fallback}
	if inst.ErrorCode == nil {
		return defaultName, nil
	}
	// An invalid supplied code follows the xsl:message fallback; xsl:assert
	// changes the default only when the attribute is omitted.
	defaultName.Local = errCodeXTMM9000

	value, err := inst.ErrorCode.evaluate(ctx, ec.contextNode)
	if err != nil {
		return defaultName, preserveControlFailure(ctx, err)
	}

	value = strings.Trim(value, " \t\r\n")
	if isValidEQName(value) {
		uri, local, _ := strings.Cut(value[2:], "}")
		if !strings.ContainsAny(uri, "{}") {
			return xdm.QNameValue{URI: uri, Local: local}, nil
		}
	}

	if prefix, local, found := strings.Cut(value, ":"); found {
		uri, bound := inst.ErrorNamespaces[prefix]
		if bound && uri != "" && xmlchar.IsValidNCName(prefix) && xmlchar.IsValidNCName(local) {
			return xdm.QNameValue{Prefix: prefix, URI: uri, Local: local}, nil
		}
	} else if xmlchar.IsValidNCName(value) {
		return xdm.QNameValue{Local: value}, nil
	}

	return defaultName, nil
}

// The message is one constructed document, including select followed by body.
// This supplies the document node required by $err:value after termination.
func (ec *execContext) messageDocument(ctx context.Context, inst *messageInst) (ValueResult, error) {
	body := inst.Body
	if inst.Select != nil {
		body = append([]instruction{&copyOfInst{Select: inst.Select, CopyNamespaces: true}}, body...)
	}

	temporary := ec.stylesheet.processorLanguage() < 30
	if temporary {
		ec.temporaryOutputDepth++
		defer func() { ec.temporaryOutputDepth-- }()
	}

	items, err := ec.evaluateBodyAsSequence(ctx, body)
	if err != nil {
		if failure := preserveControlFailure(ctx, err); failure != nil {
			return ValueResult{}, failure
		}

		if temporary && isXSLTError(err, errCodeXTDE1480) {
			return ValueResult{}, err
		}

		items = xdm.SingleString(err.Error())
	}

	normalized, err := normalizeValue(ctx, ValueResult{Items: items}, nil, "")
	if err == nil {
		return normalized, nil
	}

	if failure := preserveControlFailure(ctx, err); failure != nil {
		return ValueResult{}, failure
	}

	normalized, err = normalizeValue(ctx, ValueResult{Items: xdm.SingleString(err.Error())}, nil, "")

	return normalized, err
}

// Boolean synonyms are introduced by the XSLT 3.0 processor. XML whitespace
// stripping must not silently admit NBSP or other non-XML separators.
func parseMessageTerminate(value string, modern bool) (bool, bool) {
	value = strings.Trim(value, " \t\r\n")
	switch value {
	case lexicon.ValueYes:
		return true, true
	case lexicon.ValueNo:
		return false, true
	case lexicon.ValueTrue, "1":
		return true, modern
	case lexicon.ValueFalse, "0":
		return false, modern
	default:
		return false, false
	}
}

type messageWriter struct {
	strings.Builder
	ctx context.Context
}

func (w *messageWriter) Write(p []byte) (int, error) {
	if err := xpath.ChargeString(w.ctx, len(p)); err != nil {
		return 0, err
	}

	return w.Builder.Write(p)
}

func (w *messageWriter) WriteString(value string) (int, error) {
	if err := xpath.ChargeString(w.ctx, len(value)); err != nil {
		return 0, err
	}

	return w.Builder.WriteString(value)
}

func (ec *execContext) execTryCatch(ctx context.Context, inst *tryCatchInst) error {
	if !inst.RollbackOutput {
		return ec.execTryCatchNoRollback(ctx, inst)
	}

	savedImplicitPrimary := ec.primaryClaimedImplicitly

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

	ec.primaryClaimedImplicitly = savedImplicitPrimary

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
	ec.outputStack = append(ec.outputStack, &outputFrame{doc: doc, current: root, captureItems: capture, implicitPrimary: ec.currentOutput().implicitPrimary})

	return root, nil
}

func (ec *execContext) executeTryBody(ctx context.Context, inst *tryCatchInst) error {
	if inst.Select != nil {
		result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
		if err != nil {
			return err
		}

		if err := ec.outputSequence(result.Sequence()); err != nil {
			return err
		}

		return ec.checkImplicitPrimaryOutput()
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
	if failure := preserveControlFailure(ctx, tryErr); failure != nil {
		return failure
	}

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

	var module, line xdm.Sequence
	if ec.errSourceModule != "" {
		module = xdm.SingleString(ec.errSourceModule)
	}

	if ec.errSourceLine > 0 {
		line = xdm.SingleInteger(int64(ec.errSourceLine))
	}

	ec.setVar(xdm.ClarkName(namespace, "module"), module)
	ec.setVar(xdm.ClarkName(namespace, "line-number"), line)
	ec.setVar(xdm.ClarkName(namespace, "column-number"), xdm.EmptySequence())
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

	if failure := preserveControlFailure(ctx, tryErr); failure != nil {
		return failure
	}

	if out.outputSerial != serial {
		return dynamicError(errCodeXTDE3530,
			"xsl:try with rollback-output='no': output was written before error and cannot be rolled back")
	}

	return ec.executeMatchedCatch(ctx, inst.Catches, tryErr)
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
	if xpathError, found := errors.AsType[*xdm.Error](tryErr); found && xpathError.Value != nil {
		return xpathError.Value
	}

	xsltError, found := errors.AsType[*XSLTError](tryErr)
	if !found {
		return xdm.EmptySequence()
	}

	value, ok := xsltError.Value.(xdm.Sequence)
	if !ok || xdm.SequenceLen(value) == 0 {
		return xdm.EmptySequence()
	}

	return value
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
		errQName = xErr.CodeQName()
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
				errQName = innerXS.CodeQName()
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

	return errNS, errQName.Local, errDesc, errQName
}
