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
				return "", err
			}
			// XSLT 1.0 behavior (backwards-compatible processing): when converting
			// the AVT expression value to a string, all items after the first are
			// discarded (§5.6.1).
			if ec != nil && ec.stylesheet.processorLanguage() == 10 {
				s, err := xpath.XPath10String(result.Sequence())
				if err != nil {
					return "", err
				}

				sb.WriteString(s)
			} else {
				seq := result.Sequence()

				value, err := stringifyAVTContent(ctx, seq, ec != nil && ec.isCompatExpr(p.expr))
				if err != nil {
					return "", err
				}

				sb.WriteString(value)
			}
		} else {
			sb.WriteString(p.literal)
		}
	}

	return sb.String(), nil
}

func (a *avt) evaluateStatic(ctx context.Context, eval xpath.Evaluator, node xdm.Node) (string, error) {
	if a == nil {
		return "", nil
	}

	var sb strings.Builder

	for _, p := range a.parts {
		if p.expr != nil {
			if err := eval.ValidateExpression(ctx, p.expr); err != nil {
				return "", err
			}

			result, err := eval.Evaluate(ctx, p.expr.BindDefaultCollation(lexicon.CollationCodepoint), node)
			if err != nil {
				return "", err
			}

			value, err := stringifyResult(ctx, result)
			if err != nil {
				return "", err
			}

			sb.WriteString(value)
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

// stringifyResult converts an xpath.Result to its string representation.
// Adjacent text nodes are merged before items are joined with spaces,
// consistent with the XSLT 3.0 simple content construction rules (§5.7.2).
func stringifyResult(ctx context.Context, r *xpath.Result) (string, error) {
	return stringifySimpleContent(ctx, r.Sequence(), " ")
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
func stringifySimpleContent(ctx context.Context, seq xdm.Sequence, sep string) (string, error) {
	if xdm.SequenceLen(seq) == 1 {
		if _, array := seq.Get(0).(xdm.ArrayItem); !array {
			if err := xpath.Charge(ctx, 1); err != nil {
				return "", err
			}

			atoms, err := xpath.AtomizeSequence(seq)
			if err != nil {
				return "", err
			}

			if len(atoms) == 1 {
				// Reuse immutable singleton text instead of retaining another copy.
				return xpath.AtomicToString(atoms[0])
			}
		}
	}

	state := simpleContentState{ctx: ctx, separator: sep, depthLimit: xpath.DepthLimit(ctx, 128)}
	if err := state.appendSequence(seq, 0, true); err != nil {
		return "", err
	}

	return state.value.String(), nil
}

func stringifyAVTContent(ctx context.Context, seq xdm.Sequence, backwards bool) (string, error) {
	if !backwards {
		return stringifySimpleContent(ctx, seq, " ")
	}

	state := simpleContentState{ctx: ctx, depthLimit: xpath.DepthLimit(ctx, 128), firstOnly: true}
	if err := state.appendSequence(seq, 0, false); err != nil {
		return "", err
	}

	return state.value.String(), nil
}

// Simple content flattens arrays, merges adjacent text and propagates conversion
// errors without materializing an expanded array or a second atomic sequence.
type simpleContentState struct {
	ctx          context.Context
	separator    string
	value        strings.Builder
	depthLimit   int
	firstOnly    bool
	hasItem      bool
	previousText bool
}

func (s *simpleContentState) appendSequence(seq xdm.Sequence, depth int, normalizeText bool) error {
	if depth > s.depthLimit {
		return xpath.ErrRecursionLimit
	}

	for item := range xdm.SequenceItems(seq) {
		if err := xpath.Charge(s.ctx, 1); err != nil {
			return err
		}

		if err := s.appendItem(item, depth, normalizeText); err != nil {
			return err
		}
	}

	return s.ctx.Err()
}

func (s *simpleContentState) appendItem(item xdm.Item, depth int, normalizeText bool) error {
	if array, ok := item.(xdm.ArrayItem); ok {
		s.previousText = false
		err := s.appendArray(array, depth)
		s.previousText = false

		return err
	}

	if node, ok := item.(xdm.NodeItem); normalizeText && ok && node.Node.Type() == xdm.TextNode {
		value := xdm.CharacterData(node.Node)
		if value == "" {
			return nil
		}

		if err := s.appendString(value, s.previousText); err != nil {
			return err
		}

		s.previousText = true

		return nil
	}

	s.previousText = false
	if atom, ok := item.(xdm.AtomicValue); ok {
		return s.appendAtomic(atom)
	}

	atoms, err := xpath.AtomizeSequence(xdm.ItemSlice{item})
	if err != nil {
		return err
	}

	for _, atom := range atoms {
		if err := s.appendAtomic(atom); err != nil {
			return err
		}
	}

	return nil
}

// Arrays are atomized after the outer text-node normalization. Their member
// text nodes are separate atomic values, even when empty (XSLT 3.0 §5.7.2).
func (s *simpleContentState) appendArray(array xdm.ArrayItem, depth int) error {
	for i := 1; i <= array.Size(); i++ {
		member, _ := array.Get(i)
		if err := s.appendSequence(member, depth+1, false); err != nil {
			return err
		}
	}

	return nil
}

func (s *simpleContentState) appendAtomic(atom xdm.AtomicValue) error {
	value, err := xpath.AtomicToString(atom)
	if err != nil {
		return err
	}

	return s.appendString(value, false)
}

func (s *simpleContentState) appendString(value string, merge bool) error {
	if s.firstOnly && s.hasItem {
		return nil
	}

	if err := xpath.ChargeString(s.ctx, len(value)); err != nil {
		return err
	}

	if s.hasItem && !merge {
		if err := xpath.ChargeString(s.ctx, len(s.separator)); err != nil {
			return err
		}

		s.value.WriteString(s.separator)
	}

	s.value.WriteString(value)
	s.hasItem = true

	return nil
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
				return nil, staticError(errCodeXTSE0350, "unterminated value template expression in %q", s)
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

			return nil, staticError(errCodeXTSE0370, "unmatched } in value template %q", s)
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
		if c.stylesheet.processorLanguage() == 10 {
			return staticError("XTSE0370", "empty XPath 1.0 AVT expression"), true
		}

		*parts = appendLiteral(*parts, "")
	} else {
		expr, err := c.compileXPath(exprStr, nsBindings)
		if err != nil {
			return err, true
		}

		*parts = append(*parts, avtPart{expr: expr})
	}

	return
}

// stringifySequence converts a Sequence to its string representation
// by atomizing each item and joining with spaces.
func stringifySequence(seq xdm.Sequence) string {
	return stringifySequenceWithSep(seq, " ")
}
