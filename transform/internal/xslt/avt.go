// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// avt is a compiled Attribute Value template. It consists of alternating
// literal strings and XPath expressions enclosed in curly braces.
type avt struct {
	parts []avtPart
}

// staticValue returns the literal string value if the avt contains no
// dynamic XPath expressions, and true. If the avt contains any dynamic
// parts, it returns ("", false).
func (a *avt) staticValue() (string, bool) {
	if a == nil {
		return "", false
	}

	var sb strings.Builder

	for _, p := range a.parts {
		if p.expr != nil {
			return "", false
		}

		sb.WriteString(p.literal)
	}

	return sb.String(), true
}

func (a *avt) evaluate(ctx context.Context, node xdm.Node) (string, error) {
	if a == nil {
		return "", nil
	}

	// If the context carries an execContext, use the Evaluator-based path
	ec := getExecContext(ctx)

	var sb strings.Builder

	for _, p := range a.parts {
		if p.expr != nil {
			var (
				result *xpath.Result
				err    error
			)
			if ec != nil {
				result, err = ec.evalXPath(ctx, p.expr, node)
			} else {
				result, err = xpath.NewEvaluator(xpath.DefaultEvaluatorOptions).Evaluate(ctx, p.expr, node)
			}

			if err != nil {
				return "", &XSLTError{Code: errCodeXTDE0045, Message: "AVT evaluation error: " + err.Error(), Cause: err}
			}
			// XSLT 1.0 behavior (backwards-compatible processing): when converting
			// the AVT expression value to a string, all items after the first are
			// discarded (§5.6.1).
			if ec != nil && isBackwardsCompatible(ec.stylesheet.version) {
				s, err := xpath.XPath10String(result.Sequence())
				if err != nil {
					return "", err
				}

				sb.WriteString(s)
			} else if seq := result.Sequence(); ec != nil && seq != nil && xdm.SequenceLen(seq) > 1 && ec.isCompatExpr(p.expr) {
				sb.WriteString(stringifyItem(seq.Get(0)))
			} else {
				sb.WriteString(stringifyResult(result))
			}
		} else {
			sb.WriteString(p.literal)
		}
	}

	return sb.String(), nil
}

func stringifyItem(item xdm.Item) string {
	av, err := xpath.AtomizeItem(item)
	if err != nil {
		return ""
	}

	s, err := xpath.AtomicToString(av)
	if err != nil {
		return ""
	}

	return s
}

func (a *avt) evaluateStatic(ctx context.Context, eval xpath.Evaluator, node xdm.Node) (string, error) {
	if a == nil {
		return "", nil
	}

	var sb strings.Builder

	for _, p := range a.parts {
		if p.expr != nil {
			result, err := eval.Evaluate(ctx, p.expr, node)
			if err != nil {
				return "", &XSLTError{Code: errCodeXTDE0045, Message: "AVT evaluation error: " + err.Error(), Cause: err}
			}

			sb.WriteString(stringifyResult(result))
		} else {
			sb.WriteString(p.literal)
		}
	}

	return sb.String(), nil
}

// stringifyResult converts an xpath.Result to its string representation.
// Adjacent text nodes are merged before items are joined with spaces,
// consistent with the XSLT 3.0 simple content construction rules (§5.7.2).
func stringifyResult(r *xpath.Result) string {
	return stringifySimpleContent(r.Sequence(), " ")
}

func stringifySequenceWithSep(seq xdm.Sequence, sep string) string {
	seq = flattenArraysInSequence(seq)
	if seq == nil || xdm.SequenceLen(seq) == 0 {
		return ""
	}
	// Atomize the entire sequence at once so that list-typed nodes
	// are decomposed into their individual atomic items (each one
	// rendered in canonical form).
	atoms, err := xpath.AtomizeSequence(seq)
	if err != nil {
		// Fall back to per-item atomization on error.
		var sb strings.Builder

		i := 0
		for item := range xdm.SequenceItems(seq) {
			if i > 0 {
				sb.WriteString(sep)
			}

			av, atomErr := xpath.AtomizeItem(item)
			if atomErr != nil {
				continue
			}

			s, strErr := xpath.AtomicToString(av)
			if strErr != nil {
				continue
			}

			sb.WriteString(s)

			i++
		}

		return sb.String()
	}

	if len(atoms) == 1 {
		value, err := xpath.AtomicToString(atoms[0])
		if err != nil {
			return ""
		}

		return value
	}

	var sb strings.Builder

	for i, av := range atoms {
		if i > 0 {
			sb.WriteString(sep)
		}

		s, strErr := xpath.AtomicToString(av)
		if strErr != nil {
			continue
		}

		sb.WriteString(s)
	}

	return sb.String()
}

// stringifySimpleContent implements XSLT 3.0 §5.7.2 simple content
// construction: adjacent text nodes are merged first, zero-length
// text nodes are removed, then remaining items are separated by the
// given separator string.
func stringifySimpleContent(seq xdm.Sequence, sep string) string {
	seq = flattenArraysInSequence(seq)
	if seq == nil || xdm.SequenceLen(seq) == 0 {
		return ""
	}

	merged := mergeAdjacentTextNodes(seq)
	// Step 2: remove zero-length text nodes so they don't produce
	// stray separators (e.g. empty TVTs in sequence mode).
	merged = removeEmptyTextNodes(merged)

	return stringifySequenceWithSep(merged, sep)
}

func removeEmptyTextNodes(seq xdm.Sequence) xdm.Sequence {
	if seq == nil {
		return nil
	}

	seqLen := xdm.SequenceLen(seq)

	result := make(xdm.ItemSlice, 0, seqLen)
	for i := range seqLen {
		item := seq.Get(i)

		ni, ok := item.(xdm.NodeItem)
		if ok && ni.Node.Type() == xdm.TextNode && len(xdm.CharacterData(ni.Node)) == 0 {
			continue
		}

		result = append(result, item)
	}

	return result
}

// flattenArraysInSequence recursively replaces any ArrayItem in the
// sequence with its flattened members.  Non-array items pass through
// unchanged.  This implements the XSLT 3.0 rule that arrays appearing
// in sequence constructors, apply-templates select, value-of, etc.
// are expanded before further processing.
func flattenArraysInSequence(seq xdm.Sequence) xdm.Sequence {
	if seq == nil {
		return nil
	}

	hasArray := false

	for i, size := 0, seq.Len(); i < size; i++ {
		item := seq.Get(i)
		if _, ok := item.(xdm.ArrayItem); ok {
			hasArray = true
			break
		}
	}

	if !hasArray {
		return seq
	}

	var result xdm.ItemSlice

	for item := range xdm.SequenceItems(seq) {
		if arr, ok := item.(xdm.ArrayItem); ok {
			result = append(result, xdm.Materialize(arr.Flatten())...)
		} else {
			result = append(result, item)
		}
	}

	return result
}

type avtPart struct {
	literal string
	expr    *xpath.Expression
}

// compileAVT compiles an attribute value template string.
// AVTs contain literal text interspersed with {expr} XPath expressions.
// {{ and }} are escape sequences for literal { and }.
func (c *compiler) compileAVT(s string, nsBindings map[string]string) (*avt, error) {
	var parts []avtPart

	i := 0
	for i < len(s) {
		switch s[i] {
		case '{':
			if i+1 < len(s) && s[i+1] == '{' {
				// escaped {{
				parts = appendLiteral(parts, "{")
				i += 2

				continue
			}

			end := findAVTExprEnd(s[i+1:])
			if end < 0 {
				return nil, staticError(errCodeXTSE0580, "unterminated AVT expression in %q", s)
			}

			exprStr := s[i+1 : i+1+end]
			// Empty expression {} or comment-only expression {(: ... :)}
			// produce empty string per XSLT 3.0 spec.
			trimmed := strings.TrimSpace(exprStr)
			if returned1, matchedBranch := compileAVTIsXPathCommentOnly(trimmed, c, &parts, exprStr, nsBindings); matchedBranch {
				return nil, returned1
			}

			i = i + 1 + end + 1
		case '}':
			if i+1 < len(s) && s[i+1] == '}' {
				// escaped }}
				parts = appendLiteral(parts, "}")
				i += 2

				continue
			}

			return nil, staticError(errCodeXTSE0580, "unmatched } in AVT %q", s)
		default:
			// literal text until next { or }
			j := i + 1
			for j < len(s) && s[j] != '{' && s[j] != '}' {
				j++
			}

			parts = appendLiteral(parts, s[i:j])
			i = j
		}
	}

	return &avt{parts: parts}, nil
}

// findAVTExprEnd finds the index of the closing '}' for an avt expression,
// tracking brace nesting (for EQName Q{uri}local, map{}, array{}) and
// skipping braces inside string literals.
func findAVTExprEnd(s string) int {
	depth := 0
	commentDepth := 0
	inSingle := false
	inDouble := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if commentDepth > 0 {
			if i+1 < len(s) && ch == ':' && s[i+1] == ')' {
				commentDepth--
				i++ // skip ')'
			} else if i+1 < len(s) && ch == '(' && s[i+1] == ':' {
				commentDepth++
				i++ // skip ':'
			}

			continue
		}

		switch {
		case i+1 < len(s) && ch == '(' && s[i+1] == ':' && !inSingle && !inDouble:
			commentDepth++
			i++ // skip ':'
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '"' && !inSingle:
			inDouble = !inDouble
		case ch == '{' && !inSingle && !inDouble:
			depth++
		case ch == '}' && !inSingle && !inDouble:
			if depth == 0 {
				return i
			}

			depth--
		}
	}

	return -1
}

// isXPathCommentOnly checks if a string consists only of XPath comments.
// E.g., "(: this is a comment :)" or "(: nested (: comment :) :)"
func isXPathCommentOnly(s string) bool {
	i := 0
	for i < len(s) {
		if i+1 < len(s) && s[i] == '(' && s[i+1] == ':' {
			depth := 1

			j := i + 2
			for j < len(s) && depth > 0 {
				if j+1 < len(s) && s[j] == '(' && s[j+1] == ':' {
					depth++
					j += 2

					continue
				}

				if j+1 < len(s) && s[j] == ':' && s[j+1] == ')' {
					depth--
					j += 2

					continue
				}

				j++
			}

			if depth != 0 {
				return false
			}

			i = j
		} else if s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' {
			i++
		} else {
			return false
		}
	}

	return i > 0
}

func appendLiteral(parts []avtPart, s string) []avtPart {
	if len(parts) > 0 && parts[len(parts)-1].expr == nil {
		parts[len(parts)-1].literal += s
		return parts
	}

	return append(parts, avtPart{literal: s})
}

func compileAVTIsXPathCommentOnly(trimmed string, c *compiler, parts *[]avtPart, exprStr string, nsBindings map[string]string) (returned1 error, matchedBranch bool) {
	if trimmed == "" || isXPathCommentOnly(trimmed) {
		if isBackwardsCompatible(c.stylesheet.version) {
			return staticError("XTSE0370", "empty XPath 1.0 AVT expression"), true
		}

		(*parts) = appendLiteral((*parts), "")
	} else {
		expr, err := c.compileXPath(exprStr, nsBindings)
		if err != nil {
			return staticError(errCodeXTSE0580, "invalid XPath in AVT: %v", err), true
		}

		(*parts) = append((*parts), avtPart{expr: expr})
	}

	return
}

// stringifySequence converts a Sequence to its string representation
// by atomizing each item and joining with spaces.
func stringifySequence(seq xdm.Sequence) string {
	return stringifySequenceWithSep(seq, " ")
}
