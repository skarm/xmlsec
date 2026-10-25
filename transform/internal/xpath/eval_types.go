// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

// errCoerceMismatch is a sentinel returned by coerceToSequenceTypeE for a plain
// type or cardinality mismatch — one with no more-specific typed error. Callers
// map it to XPTY0004. A more-specific typed error (FOTY0013 from atomizing a
// function/map item, FORG0001 from an invalid cast, …) is returned directly so
// it can be surfaced to try/catch instead of being collapsed into XPTY0004.
var errCoerceMismatch = errors.New("xpath: sequence type mismatch")

// CoerceToSequenceType applies XPath 3.1 function coercion rules (§3.1.5.2):
// atomization, numeric promotion (integer→float/double, float→double),
// URI-to-string promotion, and function coercion.  Returns the coerced
// sequence and true on success, or the original sequence and false on failure.
func CoerceToSequenceType(seq xdm.Sequence, st xdm.SequenceType) (xdm.Sequence, bool) {
	return coerceToSequenceType(context.Background(), seq, st, nil)
}

// CoerceToSequenceTypeContext is CoerceToSequenceType with an explicit context,
// threaded to the schema-aware cast a user-defined (union/faceted) target may
// trigger so its facet validation participates in cancellation.
func CoerceToSequenceTypeContext(ctx context.Context, seq xdm.Sequence, st xdm.SequenceType) (xdm.Sequence, bool) {
	return coerceToSequenceType(ctx, seq, st, nil)
}

// ConvertToSequenceType applies function conversion with error propagation.
// Plain type/cardinality mismatches are XPTY0004; cast, atomization and control
// errors retain their own codes and causes.
func ConvertToSequenceType(ctx context.Context, seq xdm.Sequence, st xdm.SequenceType) (xdm.Sequence, error) {
	return (Evaluator{}).ConvertToSequenceType(ctx, seq, st, 31)
}

// ConvertToSequenceType applies function conversion in this evaluator's static
// typing context, using the live invocation's limits. version is the XPath
// language version; XPath 1.0 compatibility conversion is never applied.
func (e Evaluator) ConvertToSequenceType(ctx context.Context, seq xdm.Sequence, st xdm.SequenceType, version int) (xdm.Sequence, error) {
	ec := e.newEvalCtx(nil)
	ec.version, ec.xpath10Compat = version, false
	applyBudget(ctx, ec)

	value, err := coerceToSequenceTypeE(ctx, seq, st, ec)
	if errors.Is(err, errCoerceMismatch) {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("value does not match required type %v", st)}
	}

	return value, err
}

// BindSequenceType expands signature names at their declaration site. Function
// metadata can then cross modules and survive a caller rebinding its prefixes.
func BindSequenceType(ctx context.Context, st xdm.SequenceType, namespaces map[string]string, defaultNS string) (xdm.SequenceType, error) {
	if err := Charge(ctx, 1); err != nil {
		return st, err
	}

	name := func(lexical, ns string) string {
		if lexical == "" || lexical == "*" {
			return lexical
		}

		_, local := splitEQName(lexical)

		return "Q{" + resolveStaticNameURI(lexical, namespaces, ns) + "}" + local
	}

	child := func(t xdm.SequenceType) (xdm.SequenceType, error) {
		return BindSequenceType(ctx, t, namespaces, defaultNS)
	}
	switch t := st.ItemTest.(type) {
	case xdm.AtomicOrUnionType:
		t.Prefix, t.Name = "", name(joinQName(t.Prefix, t.Name), defaultNS)
		st.ItemTest = t
	case xdm.ElementTest:
		t.Name, t.TypeName = name(t.Name, defaultNS), name(t.TypeName, defaultNS)
		st.ItemTest = t
	case xdm.AttributeTest:
		t.Name, t.TypeName = name(t.Name, ""), name(t.TypeName, defaultNS)
		st.ItemTest = t
	case xdm.SchemaElementTest:
		t.Name = name(t.Name, defaultNS)
		st.ItemTest = t
	case xdm.SchemaAttributeTest:
		t.Name = name(t.Name, "")
		st.ItemTest = t
	case xdm.DocumentTest:
		if t.Inner != nil {
			inner, err := child(xdm.SequenceType{ItemTest: t.Inner})
			if err != nil {
				return st, err
			}

			t.Inner = inner.ItemTest
		}

		st.ItemTest = t
	case xdm.FunctionTest:
		if t.AnyFunction {
			return st, nil
		}

		params := make([]xdm.SequenceType, len(t.ParamTypes))
		for i, param := range t.ParamTypes {
			bound, err := child(param)
			if err != nil {
				return st, err
			}

			params[i] = bound
		}

		result, err := child(t.ReturnType)
		if err != nil {
			return st, err
		}

		t.ParamTypes, t.ReturnType = params, result
		st.ItemTest = t
	case xdm.MapTest:
		if t.AnyType {
			return st, nil
		}

		key, err := child(xdm.SequenceType{ItemTest: t.KeyType})
		if err != nil {
			return st, err
		}

		value, err := child(t.ValType)
		if err != nil {
			return st, err
		}

		t.KeyType, t.ValType = key.ItemTest, value
		st.ItemTest = t
	case xdm.ArrayTest:
		if t.AnyType {
			return st, nil
		}

		member, err := child(t.MemberType)
		if err != nil {
			return st, err
		}

		t.MemberType = member
		st.ItemTest = t
	}

	return st, nil
}

// MatchesSequenceType checks if a sequence matches a SequenceType using
// the XPath 3.1 SequenceType matching rules (no coercion).
func MatchesSequenceType(seq xdm.Sequence, st xdm.SequenceType) bool {
	return matchesSequenceType(seq, st, nil)
}

func evalInstanceOfExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e InstanceOfExpr) (xdm.Sequence, error) {
	seq, err := evalFn(ctx, ec, e.Expr)
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(matchesSequenceType(seq, e.Type, ec)), nil
}

// qnameCastLexical prepares the (lexical, nsMap) used to re-validate an
// ALREADY-RESOLVED QName VALUE against a schema-aware QName/NOTATION-derived cast
// target. The source value's prefix may be bound only on the instance node and
// absent from the assertion's STATIC namespace map, so re-serializing to
// `prefix:local` and re-resolving against the static map would fail even though
// the value is already valid. Instead it binds the lexical's prefix to the value's
// OWN namespace URI in a COPY of base, so schema validation resolves to the same
// URI. A no-namespace value keeps its bare local name. Used only inside the
// schema-aware cast fallback, so existing xpath cast behavior is unchanged.
func qnameCastLexical(qv xdm.QNameValue, base map[string]string) (string, map[string]string) {
	if qv.URI == "" {
		return qv.Local, base
	}

	ns := make(map[string]string, len(base)+1)
	maps.Copy(ns, base)

	prefix := qv.Prefix
	if prefix == "" {
		for i := 0; ; i++ {
			cand := fmt.Sprintf("ns%d", i)
			if _, taken := ns[cand]; !taken {
				prefix = cand
				break
			}
		}
	}

	ns[prefix] = qv.URI

	return prefix + ":" + qv.Local, ns
}

func schemaAwareCast(ctx context.Context, ec *evalContext, av xdm.AtomicValue, targetType string) (xdm.AtomicValue, error) {
	return schemaAwareCastRec(ctx, ec, av, targetType, make(map[string]struct{}))
}

func schemaAwareCastRec(ctx context.Context, ec *evalContext, av xdm.AtomicValue, targetType string, seen map[string]struct{}) (xdm.AtomicValue, error) {
	result, err := CastAtomicContext(ctx, av, targetType)
	if err == nil {
		return result, nil
	}

	if errors.Is(err, ErrBudget) || ctx.Err() != nil {
		return xdm.AtomicValue{}, errors.Join(err, ctx.Err())
	}

	if ec == nil || ec.schemaDeclarations == nil {
		return xdm.AtomicValue{}, err
	}

	if _, active := seen[targetType]; active {
		return xdm.AtomicValue{}, err
	}

	seen[targetType] = struct{}{}
	defer delete(seen, targetType)

	schemaErr := err

	if local, ns, ok := xdm.SchemaAnnotationParts(targetType); ok {
		annName := xdm.QAnnotation(ns, local)
		if builtinBase := resolveToBuiltinBase(local, ns, ec.schemaDeclarations); builtinBase != "" {
			result, baseErr := schemaAwareCastViaBuiltin(ctx, ec, av, targetType, annName, builtinBase, err)
			if baseErr == nil {
				return result, nil
			}

			schemaErr = baseErr
		}
	}

	if members := ec.schemaDeclarations.UnionMemberTypes(targetType); len(members) > 0 {
		for _, memberType := range members {
			result, castErr := schemaAwareCastRec(ctx, ec, av, memberType, seen)
			if castErr == nil {
				// F&O 3.1 §19.3.5 allows already-typed values to cast to the
				// first castable atomic member of a union. Any facets on the target
				// union then apply to that resulting member value, not to the
				// original typed source lexical; string/untypedAtomic sources keep
				// the lexical casting path from §19.2.
				targetValue := av
				if av.TypeName != xdm.TypeString && av.TypeName != xdm.TypeUntypedAtomic {
					targetValue = result
				}

				if targetErr := schemaAwareValidateTarget(ctx, ec, targetValue, targetType); targetErr != nil {
					return xdm.AtomicValue{}, targetErr
				}

				return result, nil
			}
		}
	}

	return xdm.AtomicValue{}, schemaErr
}

func schemaAwareValidateTarget(ctx context.Context, ec *evalContext, av xdm.AtomicValue, targetType string) error {
	local, ns, ok := xdm.SchemaAnnotationParts(targetType)
	if !ok {
		return nil
	}

	s, nsForCast := schemaAwareCastLexical(av, ec.namespaces)

	annName := xdm.QAnnotation(ns, local)
	if err := ec.schemaDeclarations.ValidateCastWithNS(ctx, s, annName, nsForCast); err != nil {
		return &xdm.Error{Code: errCodeFORG0001, Message: fmt.Sprintf("cannot cast %q to %s: %v", s, targetType, err)}
	}

	return nil
}

func schemaAwareCastLexical(av xdm.AtomicValue, base map[string]string) (string, map[string]string) {
	s, _ := AtomicToString(av)
	if qv, isQV := av.Value.(xdm.QNameValue); isQV {
		return qnameCastLexical(qv, base)
	}

	return s, base
}

func schemaAwareFacetLexical(src, cast xdm.AtomicValue, base map[string]string) (string, map[string]string) {
	if src.TypeName == xdm.TypeString || src.TypeName == xdm.TypeUntypedAtomic {
		return schemaAwareCastLexical(src, base)
	}

	return schemaAwareCastLexical(cast, base)
}

func schemaAwareCastViaBuiltin(ctx context.Context, ec *evalContext, av xdm.AtomicValue, targetType, annName, builtinBase string, fallback error) (xdm.AtomicValue, error) {
	if builtinBase == xdm.TypeNOTATION || builtinBase == xdm.TypeQName {
		_, isQV := av.Value.(xdm.QNameValue)

		srcOK := av.TypeName == xdm.TypeString || av.TypeName == xdm.TypeUntypedAtomic ||
			av.TypeName == xdm.TypeQName || av.TypeName == xdm.TypeNOTATION || isQV
		if !srcOK {
			return xdm.AtomicValue{}, fallback
		}

		s, nsForCast := schemaAwareCastLexical(av, ec.namespaces)
		if vErr := ec.schemaDeclarations.ValidateCastWithNS(ctx, s, annName, nsForCast); vErr != nil {
			return xdm.AtomicValue{}, &xdm.Error{Code: errCodeFORG0001, Message: fmt.Sprintf("cannot cast %q to %s: %v", s, targetType, vErr)}
		}

		qv, qErr := castToQName(av, ec)
		if qErr != nil {
			return xdm.AtomicValue{}, qErr
		}

		qv.BaseType = builtinBase
		qv.TypeName = targetType

		return qv, nil
	}

	result, castErr := CastAtomicContext(ctx, av, builtinBase)
	if castErr != nil {
		return xdm.AtomicValue{}, castErr
	}

	s, nsForCast := schemaAwareFacetLexical(av, result, ec.namespaces)
	if facetErr := ec.schemaDeclarations.ValidateCastWithNS(ctx, s, annName, nsForCast); facetErr != nil {
		return xdm.AtomicValue{}, &xdm.Error{Code: errCodeFORG0001, Message: fmt.Sprintf("cannot cast %q to %s: %v", s, targetType, facetErr)}
	}

	result.BaseType = builtinBase
	result.TypeName = targetType

	return result, nil
}

func evalCastExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e CastExpr) (xdm.Sequence, error) {
	targetType := resolveAtomicTypeName(e.Type, ec)
	if isAbstractCastTarget(targetType) {
		return nil, &xdm.Error{
			Code:    errCodeXPST0080,
			Message: fmt.Sprintf("cannot use abstract type %s as cast target", targetType),
		}
	}

	seq, err := evalFn(ctx, ec, e.Expr)
	if err != nil {
		return nil, err
	}
	// Atomize THROUGH the stream (atomizeSingletonOperand) so a schema-typed node
	// whose typed value is a list/union expands to its atoms; the cast cardinality
	// (singleton, or empty when `as T?`) is then applied to the ATOMIZED result, not
	// the raw item count — a single node atomizing to >1 value is a cardinality error.
	atoms, err := atomizeSingletonOperand(seq)
	if err != nil {
		return nil, err
	}

	if len(atoms) == 0 {
		if e.AllowEmpty {
			return nil, nil
		}

		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "cast requires non-empty sequence"}
	}

	if len(atoms) > 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "cast requires singleton"}
	}

	av := atoms[0]
	// xs:QName cast from string requires namespace context
	if targetType == xdm.TypeQName {
		if !qnameCastOperandAllowed(ec, e.Expr, av) {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "XPath 2.0 QName cast requires a string literal or QName value"}
		}

		result, err := castToQName(av, ec)
		if err != nil {
			return nil, err
		}

		return xdm.SingleAtomic(result), nil
	}
	// xs:numeric is a union type: if already numeric return as-is, else cast to double
	if targetType == xdm.TypeNumeric {
		if av.IsNumeric() {
			return xdm.SingleAtomic(av), nil
		}

		result, err := CastAtomicContext(ctx, av, xdm.TypeDouble)
		if err != nil {
			return nil, err
		}

		return xdm.SingleAtomic(result), nil
	}
	// A user-defined list type (xs:list) casts to a SEQUENCE of item atoms.
	if ec != nil && ec.schemaDeclarations != nil {
		if itemType, ok := ec.schemaDeclarations.ListItemType(targetType); ok {
			return castToUserList(ctx, ec, av, targetType, itemType)
		}
	}

	result, err := CastAtomicContext(ctx, av, targetType)
	if err != nil {
		if result, err = schemaAwareCast(ctx, ec, av, targetType); err != nil {
			return nil, err
		}
	}

	return xdm.SingleAtomic(result), nil
}

func evalCastableExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e CastableExpr) (xdm.Sequence, error) {
	targetType := resolveAtomicTypeName(e.Type, ec)
	// Abstract types raise a static error even for castable (XPST0080)
	if isAbstractCastTarget(targetType) {
		return nil, &xdm.Error{
			Code:    errCodeXPST0080,
			Message: fmt.Sprintf("cannot use abstract type %s as castable target", targetType),
		}
	}

	seq, err := evalFn(ctx, ec, e.Expr)
	if err != nil {
		return nil, err
	}
	// Atomize THROUGH the stream so a schema-typed node whose typed value is a
	// list/union expands; castable's cardinality (singleton, or empty when `as T?`)
	// is applied to the ATOMIZED result — a node atomizing to >1 value is NOT
	// castable to a single atomic type.
	atoms, err := atomizeSingletonOperand(seq)
	if err != nil {
		// Atomizing a function/map/array is a type error (FOTY0013) that
		// PROPAGATES from `castable as`, and never makes it false — the operand
		// isn't a bad lexical, it's not atomizable at all (F&O 3.1 §19.1; QT3
		// CastableAs666/668). Other atomization failures mean "not castable".
		var xpErr *xdm.Error
		if errors.As(err, &xpErr) && xpErr.Code == errCodeFOTY0013 {
			return nil, err
		}

		return xdm.SingleBoolean(false), nil
	}

	if len(atoms) == 0 {
		return xdm.SingleBoolean(e.AllowEmpty), nil
	}

	if len(atoms) > 1 {
		return xdm.SingleBoolean(false), nil
	}

	av := atoms[0]
	// xs:QName cast from string requires namespace context
	if targetType == xdm.TypeQName {
		if !qnameCastOperandAllowed(ec, e.Expr, av) {
			return xdm.SingleBoolean(false), nil
		}

		_, castErr := castToQName(av, ec)

		return xdm.SingleBoolean(castErr == nil), nil
	}
	// xs:ENTITIES, xs:IDREFS, xs:NMTOKENS are list types:
	// castable returns true if the string is a whitespace-separated list of
	// at least one valid member (NCName for ENTITIES/IDREFS, NMTOKEN for NMTOKENS).
	if targetType == xdm.TypeENTITIES || targetType == xdm.TypeIDREFS || targetType == xdm.TypeNMTOKENS {
		s, err := AtomicToString(av)
		if err != nil {
			return xdm.SingleBoolean(false), nil //nolint:nilerr // castable returns false on conversion failure
		}

		return xdm.SingleBoolean(isValidListCastable(s, targetType)), nil
	}
	// xs:numeric is a union type
	if targetType == xdm.TypeNumeric {
		if av.IsNumeric() {
			return xdm.SingleBoolean(true), nil
		}

		_, castErr := CastAtomicContext(ctx, av, xdm.TypeDouble)
		if errors.Is(castErr, ErrBudget) || ctx.Err() != nil {
			return nil, errors.Join(castErr, ctx.Err())
		}

		return xdm.SingleBoolean(castErr == nil), nil
	}
	// A user-defined list type (xs:list): castable iff a string/untypedAtomic
	// source tokenizes into tokens each castable to the item type, and the whole
	// value satisfies the list type's own facets. A multi-item (already-expanded)
	// list-typed source was rejected by the singleton cardinality check above.
	if ec != nil && ec.schemaDeclarations != nil {
		if itemType, ok := ec.schemaDeclarations.ListItemType(targetType); ok {
			return xdm.SingleBoolean(castableToUserList(ctx, ec, av, targetType, itemType)), nil
		}
	}

	_, castErr := schemaAwareCast(ctx, ec, av, targetType)
	if errors.Is(castErr, ErrBudget) || ctx.Err() != nil {
		return nil, errors.Join(castErr, ctx.Err())
	}

	return xdm.SingleBoolean(castErr == nil), nil
}

// castableToUserList reports whether av is castable to a user-defined list type
// (F&O 3.1 §19.1.2): a string/untypedAtomic source is split on XSD whitespace and
// each token must be castable to the list's item type, then the whole normalized
// value must satisfy the list type's own facets (length/pattern). Any other
// already-typed atomic source is not castable to a list (its lexical is not a list
// literal). An empty token set (an empty/whitespace-only source) is the empty list,
// castable iff the list facets accept zero items.
func castableToUserList(ctx context.Context, ec *evalContext, av xdm.AtomicValue, listType, itemType string) bool {
	if av.TypeName != xdm.TypeString && av.TypeName != xdm.TypeUntypedAtomic {
		return false
	}

	s, err := AtomicToString(av)
	if err != nil {
		return false
	}

	for _, tok := range xsdListFields(s) {
		if _, castErr := schemaAwareCast(ctx, ec, xdm.AtomicValue{TypeName: xdm.TypeString, Value: tok}, itemType); castErr != nil {
			return false
		}
	}

	return ec.schemaDeclarations.ValidateCastWithNS(ctx, s, listType, ec.namespaces) == nil
}

// castToUserList casts a string/untypedAtomic source to a user-defined list type,
// returning the sequence of item atoms (each typed as the item type). Mirrors
// castableToUserList's tokenize-and-cast semantics; a token that is not castable
// to the item type, a non-string source, or a list-facet violation is FORG0001.
func castToUserList(ctx context.Context, ec *evalContext, av xdm.AtomicValue, listType, itemType string) (xdm.Sequence, error) {
	if av.TypeName != xdm.TypeString && av.TypeName != xdm.TypeUntypedAtomic {
		return nil, &xdm.Error{Code: errCodeFORG0001, Message: fmt.Sprintf("cannot cast %s to list type %s", av.TypeName, listType)}
	}

	s, err := AtomicToString(av)
	if err != nil {
		return nil, err
	}

	if vErr := ec.schemaDeclarations.ValidateCastWithNS(ctx, s, listType, ec.namespaces); vErr != nil {
		return nil, &xdm.Error{Code: errCodeFORG0001, Message: fmt.Sprintf("cannot cast %q to %s: %v", s, listType, vErr)}
	}

	tokens := xsdListFields(s)

	items := make(xdm.ItemSlice, 0, len(tokens))
	for _, tok := range tokens {
		cast, castErr := schemaAwareCast(ctx, ec, xdm.AtomicValue{TypeName: xdm.TypeString, Value: tok}, itemType)
		if castErr != nil {
			return nil, &xdm.Error{Code: errCodeFORG0001, Message: fmt.Sprintf("cannot cast token %q to %s: %v", tok, itemType, castErr)}
		}

		items = append(items, cast)
	}

	return items, nil
}

// isValidListCastable checks whether a string value is castable to
// a list type (xs:ENTITIES, xs:IDREFS, xs:NMTOKENS). The string must
// contain at least one whitespace-separated token, and each token must
// be valid for the list's member type (NCName for ENTITIES/IDREFS,
// NMTOKEN for NMTOKENS).
func isValidListCastable(s string, listType string) bool {
	tokens := xsdListFields(s)
	if len(tokens) == 0 {
		return false
	}

	for _, tok := range tokens {
		switch listType {
		case xdm.TypeENTITIES, xdm.TypeIDREFS:
			if !reNCName(tok) {
				return false
			}
		case xdm.TypeNMTOKENS:
			if !reNMTOKEN(tok) {
				return false
			}
		}
	}

	return true
}

func evalTreatAsExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e TreatAsExpr) (xdm.Sequence, error) {
	seq, err := evalFn(ctx, ec, e.Expr)
	if err != nil {
		return nil, err
	}

	if !matchesSequenceType(seq, e.Type, ec) {
		return nil, &xdm.Error{Code: errCodeXPDY0050, Message: fmt.Sprintf("treat as: sequence does not match required type %v (actual length %d)", e.Type, xdm.SequenceLen(seq))}
	}

	return seq, nil
}

// resolveToBuiltinBase walks the schema type hierarchy from a user-defined type
// to find the ultimate built-in XSD base type (e.g., xs:integer). Returns ""
// if the type is not found in schema declarations.
func resolveToBuiltinBase(local, ns string, decls SchemaDeclarations) string {
	current := local

	currentNS := ns
	for range 32 {
		baseType, ok := decls.LookupSchemaType(current, currentNS)
		if !ok {
			return ""
		}

		if xdm.IsKnownXSDType(baseType) {
			return baseType
		}
		// Parse the Q{ns}local format for the next iteration.
		newLocal, newNS, parsed := xdm.SchemaAnnotationParts(baseType)
		if !parsed {
			return ""
		}

		current = newLocal
		currentNS = newNS
	}

	return ""
}

// resolveAtomicTypeName uses the same expanded-name rules as static validation.
func resolveAtomicTypeName(tn AtomicTypeName, ec *evalContext) string {
	var namespaces map[string]string
	if ec != nil {
		namespaces = ec.namespaces
	}

	lexical := joinQName(tn.Prefix, tn.Name)
	_, local := splitEQName(lexical)

	uri := resolveStaticNameURI(lexical, namespaces, namespaces[""])
	if uri == lexicon.NamespaceXSD {
		return "xs:" + local
	}

	return xdm.QAnnotation(uri, local)
}

// coerceToSequenceType is the boolean-returning wrapper retained for callers that
// only need success/failure. It discards the specific error code; callers that
// must surface FOTY0013/FORG0001 should use coerceToSequenceTypeE.
func coerceToSequenceType(ctx context.Context, seq xdm.Sequence, st xdm.SequenceType, ec *evalContext) (xdm.Sequence, bool) {
	out, err := coerceToSequenceTypeE(ctx, seq, st, ec)
	if err != nil {
		return seq, false
	}

	return out, true
}

// coerceToSequenceTypeE is the error-propagating coercion. On a plain type or
// cardinality mismatch it returns errCoerceMismatch; on a typed atomization/cast
// failure it returns that underlying error (FOTY0013, FORG0001, …). Atomization
// errors take precedence over cardinality rejection, matching the spec ordering
// (atomization happens before the occurrence check).
func coerceToSequenceTypeE(ctx context.Context, seq xdm.Sequence, st xdm.SequenceType, ec *evalContext) (xdm.Sequence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Backwards-compatible function conversion precedes ordinary conversion.
	if ec.xpath10CompatMode() && !st.Void {
		newSeq, done, err := coerceXPath10Compat(seq, st, ec)
		if done {
			return newSeq, err
		}

		seq = newSeq
	}

	// item() needs only the O(1) cardinality check, preserving lazy ranges.
	if !st.Void {
		if _, anyItem := st.ItemTest.(xdm.AnyItemTest); anyItem {
			if !coercionOccurrenceMatches(xdm.SequenceLen(seq), st.Occurrence) {
				return seq, errCoerceMismatch
			}

			return seq, nil
		}
	}

	// Matching a concrete item type scans the sequence; charge before walking
	// a lazy input. The item()* shortcut above remains constant-time.
	if err := fnCountOps(ctx, ec, xdm.SequenceLen(seq)); err != nil {
		return nil, err
	}

	if matchesSequenceType(seq, st, ec) {
		return seq, nil
	}

	if _, ok := st.ItemTest.(xdm.FunctionTest); ok {
		var namespaces map[string]string
		if ec != nil {
			namespaces = ec.namespaces
		}

		bound, err := BindSequenceType(ctx, st, namespaces, namespaces[""])
		if err != nil {
			return nil, err
		}

		fnTest := bound.ItemTest.(xdm.FunctionTest) //nolint:forcetypeassert // binding preserves the item-test kind

		return coerceFunctionSequence(ctx, seq, st.Occurrence, fnTest, ec)
	}

	target, ok := st.ItemTest.(xdm.AtomicOrUnionType)
	if !ok {
		return seq, errCoerceMismatch
	}

	targetType := resolveAtomicTypeName(AtomicTypeName(target), ec)

	atoms, err := atomizeForSequenceCoercion(ctx, seq, st.Occurrence, ec)
	if err != nil {
		return seq, err
	}

	result := make(xdm.ItemSlice, len(atoms))
	for i, atom := range atoms {
		converted, err := coerceAtomicFunctionArgument(ctx, atom, targetType, ec)
		if err != nil {
			return seq, err
		}

		result[i] = converted
	}

	if !coercionOccurrenceMatches(len(result), st.Occurrence) {
		return seq, errCoerceMismatch
	}

	return result, nil
}

func coerceFunctionSequence(ctx context.Context, seq xdm.Sequence, occurrence xdm.Occurrence, target xdm.FunctionTest, ec *evalContext) (xdm.Sequence, error) {
	length := xdm.SequenceLen(seq)
	if !coercionOccurrenceMatches(length, occurrence) {
		return seq, errCoerceMismatch
	}

	if length > fnMaxNodes(ec) {
		return nil, ErrNodeSetLimit
	}

	result := make(xdm.ItemSlice, 0, length)

	for item := range xdm.SequenceItems(seq) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if matchesFunctionItemTest(item, target, ec) {
			result = append(result, item)
			continue
		}

		adapted, ok := coerceFunctionItem(item, target, ec)
		if !ok {
			return seq, errCoerceMismatch
		}

		result = append(result, adapted)
	}

	return result, nil
}

func coercionOccurrenceMatches(length int, occurrence xdm.Occurrence) bool {
	switch occurrence {
	case xdm.OccurrenceExactlyOne:
		return length == 1
	case xdm.OccurrenceZeroOrOne:
		return length <= 1
	case xdm.OccurrenceOneOrMore:
		return length > 0
	default:
		return true
	}
}

// atomizeForSequenceCoercion flattens arrays and list-typed nodes. Singleton
// targets stop after the second atom; typed-value errors encountered before
// that limit still propagate, before the cardinality mismatch is reported.
func atomizeForSequenceCoercion(ctx context.Context, seq xdm.Sequence, occurrence xdm.Occurrence, ec *evalContext) ([]xdm.AtomicValue, error) {
	maxAtoms := 0
	if occurrence == xdm.OccurrenceExactlyOne || occurrence == xdm.OccurrenceZeroOrOne {
		maxAtoms = 1
	}

	var atoms []xdm.AtomicValue

	tooMany := false

	err := atomizeBounded(ctx, ec, seq, func(atom xdm.AtomicValue) (bool, error) {
		if len(atoms) >= fnMaxNodes(ec) {
			return false, ErrNodeSetLimit
		}

		atoms = append(atoms, atom)
		if maxAtoms > 0 && len(atoms) > maxAtoms {
			tooMany = true
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		return nil, err
	}

	if tooMany {
		return nil, errCoerceMismatch
	}

	return atoms, nil
}

// coerceAtomicFunctionArgument applies numeric/URI promotion, then untyped
// conversion, then subtype acceptance in the function-conversion order.
func coerceAtomicFunctionArgument(ctx context.Context, value xdm.AtomicValue, target string, ec *evalContext) (xdm.AtomicValue, error) {
	if target == xdm.TypeAnyAtomicType {
		return value, nil // Abstract atomic supertype needs no concrete cast.
	}

	// Schema-derived numerics are normalized to their built-in base before
	// promotion so that the conversion agrees with atomicMatchesTargetType.
	switch target {
	case xdm.TypeDouble:
		if canPromoteAtomicToDouble(value, ec) {
			return castToDouble(xdm.PromoteSchemaType(value))
		}
	case xdm.TypeFloat:
		if atomicMatchesTargetType(value, xdm.TypeInteger, ec) || atomicMatchesTargetType(value, xdm.TypeDecimal, ec) {
			return castToFloat(xdm.PromoteSchemaType(value))
		}
	case xdm.TypeString:
		if atomicMatchesTargetType(value, xdm.TypeAnyURI, ec) {
			promoted := xdm.PromoteSchemaType(value)
			return xdm.AtomicValue{TypeName: xdm.TypeString, Value: promoted.Value}, nil
		}
	}

	if value.TypeName == xdm.TypeUntypedAtomic {
		if ec != nil && ec.version >= 30 && (target == xdm.TypeQName || target == xdm.TypeNOTATION) {
			return xdm.AtomicValue{}, &xdm.Error{Code: "XPTY0117", Message: "untypedAtomic cannot be converted to a namespace-sensitive type by function conversion"}
		}

		if target == xdm.TypeNumeric {
			target = xdm.TypeDouble
		}

		// User-defined unions and restricted types need schema-aware casting
		// to select a castable member and validate its facets.
		if ec != nil && ec.schemaDeclarations != nil && !xdm.IsKnownXSDType(target) {
			return schemaAwareCast(ctx, ec, value, target)
		}

		return CastAtomicContext(ctx, value, target)
	}

	if atomicMatchesTargetType(value, target, ec) {
		return value, nil
	}

	return xdm.AtomicValue{}, errCoerceMismatch
}

func canPromoteAtomicToDouble(value xdm.AtomicValue, ec *evalContext) bool {
	return atomicMatchesTargetType(value, xdm.TypeDouble, ec) || atomicMatchesTargetType(value, xdm.TypeFloat, ec) ||
		atomicMatchesTargetType(value, xdm.TypeInteger, ec) || atomicMatchesTargetType(value, xdm.TypeDecimal, ec)
}

func coerceFunctionItem(item xdm.Item, target xdm.FunctionTest, ec *evalContext) (xdm.Item, bool) {
	if target.AnyFunction {
		return nil, false
	}

	// Maps and arrays are function items of arity 1 per XPath 3.1, so they
	// participate in function coercion just like an inline/named function.
	actual, ok := asFunctionItem(item)
	if !ok {
		return nil, false
	}

	if actual.Arity >= 0 && actual.Arity != len(target.ParamTypes) {
		return nil, false
	}

	if ec == nil {
		ec = (Evaluator{}).newEvalCtx(nil)
		ec.version = 31
	}

	paramTypes := append([]xdm.SequenceType(nil), target.ParamTypes...)
	returnType := target.ReturnType
	// The adapter only needs typing information. Do not retain the producing
	// evaluation's focus, variables, resource resolvers or diagnostic writers.
	captured := &evalContext{
		namespaces: ec.namespaces, schemaDeclarations: ec.schemaDeclarations,
		typeAnnotations: ec.typeAnnotations, nilledElements: ec.nilledElements,
		preservedIDAnnotations: ec.preservedIDAnnotations, idNodes: ec.idNodes,
		version: ec.version, xmlSchemaVersion: ec.xmlSchemaVersion,
		strictPrefixes: ec.strictPrefixes, qnameValueNoDefaultNS: ec.qnameValueNoDefaultNS,
		allowXML11Chars: ec.allowXML11Chars,
		opLimit:         ec.opLimit, maxNodes: ec.maxNodes, maxRecursionDepth: ec.maxRecursionDepth,
	}

	return xdm.FunctionItem{
		Arity:      len(paramTypes),
		Name:       actual.Name,
		Namespace:  actual.Namespace,
		ParamTypes: paramTypes,
		ReturnType: &returnType,
		Invoke: func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
			if len(args) != len(paramTypes) {
				return nil, &xdm.Error{
					Code:    lexicon.ErrXPTY0004,
					Message: fmt.Sprintf("arity mismatch: expected %d arguments, got %d", len(paramTypes), len(args)),
				}
			}

			// Keep the required type's static context while borrowing the live
			// caller's work state, including on calls after this coercion returns.
			invokeCtx := calleeContext(ctx, captured)
			applyBudget(ctx, invokeCtx)

			callArgs, err := coerceFunctionItemArgs(ctx, xdm.FunctionItem{ParamTypes: paramTypes}, args, invokeCtx)
			if err != nil {
				return nil, err
			}

			callArgs, err = coerceFunctionItemArgs(ctx, actual, callArgs, invokeCtx)
			if err != nil {
				return nil, err
			}

			result, err := actual.Invoke(ctx, callArgs)
			if err != nil {
				return nil, err
			}

			coercedResult, rerr := coerceToSequenceTypeE(ctx, result, target.ReturnType, invokeCtx)
			if rerr != nil && !errors.Is(rerr, errCoerceMismatch) {
				return nil, rerr
			}

			if rerr != nil {
				return nil, &xdm.Error{
					Code:    lexicon.ErrXPTY0004,
					Message: fmt.Sprintf("function result does not match required type %v", target.ReturnType),
				}
			}

			return coercedResult, nil
		},
	}, true
}

func coerceFunctionItemArgs(ctx context.Context, actual xdm.FunctionItem, args []xdm.Sequence, ec *evalContext) ([]xdm.Sequence, error) {
	callArgs := append([]xdm.Sequence(nil), args...)

	for i, arg := range args {
		parameter, declared := xdm.FunctionParameterType(actual.ParamTypes, actual.RepeatParamType, i)
		if !declared {
			continue
		}

		// Preserve typed atomization/conversion errors; only a plain mismatch
		// becomes XPTY0004.
		coerced, err := coerceToSequenceTypeE(ctx, arg, parameter, ec)
		if err != nil && !errors.Is(err, errCoerceMismatch) {
			return nil, err
		}

		if err != nil {
			return nil, &xdm.Error{
				Code:    lexicon.ErrXPTY0004,
				Message: fmt.Sprintf("function argument %d does not match required type %v", i+1, parameter),
			}
		}

		callArgs[i] = coerced
	}

	return callArgs, nil
}

// atomicMatchesTargetType reports whether an atomic value satisfies an
// AtomicOrUnionType item test whose resolved name is targetType. Beyond the
// built-in subtype hierarchy and schema-declaration ancestry, it honors the
// value's own BaseType: a schema-derived value whose built-in BaseType is a
// subtype of (or promotes to) the target must match, because the numeric (and
// other) builtins accept it via PromoteSchemaType. Without this the static
// signature gate would reject, e.g., abs($v) for $v of a custom type derived
// from xs:decimal even though fnAbs promotes and handles it.
func atomicMatchesTargetType(av xdm.AtomicValue, targetType string, ec *evalContext) bool {
	if targetType == xdm.TypeAnyAtomicType {
		return true
	}

	if xdm.IsSubtypeOf(av.TypeName, targetType) {
		return true
	}
	// Schema-derived value carrying a built-in BaseType: match using the base
	// type, mirroring PromoteSchemaType (which the builtins use). Only built-in
	// base types are trusted here so acceptance is not broadened for unrelated
	// user types.
	if av.BaseType != "" && xdm.IsKnownXSDType(av.BaseType) && xdm.IsSubtypeOf(av.BaseType, targetType) {
		return true
	}
	// Fall back to schema declarations for user-defined types whose ancestry is
	// only known to the compiled schema.
	if ec != nil && ec.schemaDeclarations != nil {
		// xs:numeric is a synthetic union the schema layer does not model, so
		// resolve it against its member built-in types.
		if targetType == xdm.TypeNumeric {
			return ec.schemaDeclarations.IsSubtypeOf(av.TypeName, xdm.TypeDecimal) ||
				ec.schemaDeclarations.IsSubtypeOf(av.TypeName, xdm.TypeFloat) ||
				ec.schemaDeclarations.IsSubtypeOf(av.TypeName, xdm.TypeDouble)
		}

		if ec.schemaDeclarations.IsSubtypeOf(av.TypeName, targetType) {
			return true
		}
		// A user-defined UNION target matches when the value is an instance of
		// one of its member types (XPath 3.1 §2.5.6.2 union sequence-type
		// matching): the union's members are not base-chain subtypes of the
		// union, so IsSubtypeOf alone never admits them. Members may themselves
		// be unions, so recurse.
		if atomicMatchesUnionMember(av, targetType, ec, nil) {
			return true
		}

		return false
	}

	return false
}

// atomicMatchesUnionMember reports whether av is an instance of one of the
// member types of the union named targetType (or, recursively, a nested union
// member). It returns false when targetType is not a union. The visited set
// guards against a pathological cyclic union graph.
func atomicMatchesUnionMember(av xdm.AtomicValue, targetType string, ec *evalContext, visited map[string]struct{}) bool {
	if ec == nil || ec.schemaDeclarations == nil {
		return false
	}

	members := ec.schemaDeclarations.UnionMemberTypes(targetType)
	if len(members) == 0 {
		return false
	}

	if _, seen := visited[targetType]; seen {
		return false
	}

	if visited == nil {
		visited = make(map[string]struct{})
	}

	visited[targetType] = struct{}{}
	defer delete(visited, targetType)

	for _, m := range members {
		// Direct (non-union) instance match against the member type. This mirrors
		// the non-union branches of atomicMatchesTargetType; the union recursion is
		// handled below with the shared visited set, and never by re-entering
		// atomicMatchesTargetType (which would reset the cycle guard).
		if m == xdm.TypeAnyAtomicType {
			return true
		}

		if xdm.IsSubtypeOf(av.TypeName, m) {
			return true
		}

		if av.BaseType != "" && xdm.IsKnownXSDType(av.BaseType) && xdm.IsSubtypeOf(av.BaseType, m) {
			return true
		}

		if ec.schemaDeclarations.IsSubtypeOf(av.TypeName, m) {
			return true
		}

		if atomicMatchesUnionMember(av, m, ec, visited) {
			return true
		}
	}

	return false
}

func matchesSequenceType(seq xdm.Sequence, st xdm.SequenceType, ec *evalContext) bool {
	if st.Void {
		return xdm.SequenceLen(seq) == 0
	}

	switch st.Occurrence {
	case xdm.OccurrenceExactlyOne:
		if xdm.SequenceLen(seq) != 1 {
			return false
		}
	case xdm.OccurrenceZeroOrOne:
		if xdm.SequenceLen(seq) > 1 {
			return false
		}
	case xdm.OccurrenceOneOrMore:
		if xdm.SequenceLen(seq) == 0 {
			return false
		}
	case xdm.OccurrenceZeroOrMore:
		// any length ok
	}

	for item := range xdm.SequenceItems(seq) {
		if !matchesItemType(item, st.ItemTest, ec) {
			return false
		}
	}

	return true
}

func matchesItemType(item xdm.Item, test xdm.NodeTest, ec *evalContext) bool {
	if test == nil {
		return true
	}

	switch t := test.(type) {
	case xdm.AnyItemTest:
		return true
	case xdm.TypeTest, xdm.NameTest, xdm.ElementTest, xdm.AttributeTest,
		xdm.SchemaElementTest, xdm.SchemaAttributeTest, xdm.DocumentTest, xdm.PITest, xdm.NamespaceNodeTest:
		return matchesNodeItemType(item, test, ec)
	case xdm.AtomicOrUnionType:
		value, ok := item.(xdm.AtomicValue)
		return ok && atomicMatchesTargetType(value, resolveAtomicTypeName(AtomicTypeName(t), ec), ec)
	case xdm.FunctionTest:
		return matchesFunctionItemTest(item, t, ec)
	case xdm.MapTest:
		return matchesMapItemTest(item, t, ec)
	case xdm.ArrayTest:
		array, ok := item.(xdm.ArrayItem)
		return ok && (t.AnyType || arrayMembersMatchType(array, t.MemberType, ec))
	default:
		return false
	}
}

func matchesNodeItemType(item xdm.Item, test xdm.NodeTest, ec *evalContext) bool {
	node, ok := item.(xdm.NodeItem)
	if !ok {
		return false
	}

	switch t := test.(type) {
	case xdm.TypeTest:
		return matchTypeTest(t, node.Node)
	case xdm.NameTest:
		// Bare name tests in sequence types select elements only.
		return matchNameTest(t, node.Node, AxisChild, ec)
	case xdm.ElementTest:
		return nodeItemMatchesAnnotation(node, t.TypeName, xdm.TypeUntyped, ec) &&
			matchNodeTest(t, node.Node, AxisChild, ec)
	case xdm.AttributeTest:
		return nodeItemMatchesAnnotation(node, t.TypeName, xdm.TypeUntypedAtomic, ec) &&
			matchNodeTest(t, node.Node, AxisAttribute, ec)
	case xdm.SchemaElementTest:
		return matchesSchemaElementItem(node, t, ec)
	case xdm.SchemaAttributeTest:
		return matchesSchemaAttributeItem(node, t, ec)
	case xdm.DocumentTest, xdm.PITest:
		return matchNodeTest(test, node.Node, AxisChild, ec)
	case xdm.NamespaceNodeTest:
		return node.Node.Type() == xdm.NamespaceNode
	default:
		return false
	}
}

func nodeItemMatchesAnnotation(node xdm.NodeItem, typeName, fallback string, ec *evalContext) bool {
	if typeName == "" {
		return true
	}

	annotation := node.TypeAnnotation
	if annotation == "" {
		annotation = fallback
	}

	return matchesAnnotationSubtype(annotation, resolveTestTypeName(typeName, ec), ec)
}

func matchesAnnotationSubtype(annotation, target string, ec *evalContext) bool {
	return xdm.IsSubtypeOf(annotation, target) ||
		(ec != nil && ec.schemaDeclarations != nil && ec.schemaDeclarations.IsSubtypeOf(annotation, target))
}

func matchesSchemaElementItem(node xdm.NodeItem, test xdm.SchemaElementTest, ec *evalContext) bool {
	if node.Node.Type() != xdm.ElementNode || ec == nil || ec.schemaDeclarations == nil {
		return false
	}

	local, ns := resolveSchemaTestName(test.Name, ec, false)

	annotation := node.TypeAnnotation
	if annotation == "" {
		annotation = nodeTypeAnnotation(node.Node, ec)
	}

	nameMatch := xdm.LocalNameOf(node.Node) == local && xdm.NodeNamespaceURI(node.Node) == ns
	if !nameMatch {
		// A differently named node must belong to the head's substitution
		// group and carry a validated type, not merely derive from its type.
		return ec.schemaDeclarations.IsSubstitutionGroupMember(xdm.LocalNameOf(node.Node), xdm.NodeNamespaceURI(node.Node), local, ns) &&
			annotation != "" && annotation != xdm.TypeUntyped
	}

	typeName, found := ec.schemaDeclarations.LookupSchemaElement(local, ns)
	if !found || annotation == "" || annotation == xdm.TypeUntyped {
		return false
	}

	return matchesAnnotationSubtype(annotation, typeName, ec)
}

func matchesSchemaAttributeItem(node xdm.NodeItem, test xdm.SchemaAttributeTest, ec *evalContext) bool {
	if node.Node.Type() != xdm.AttributeNode || ec == nil || ec.schemaDeclarations == nil {
		return false
	}

	local, ns := resolveSchemaTestName(test.Name, ec, true)
	if xdm.LocalNameOf(node.Node) != local || xdm.NodeNamespaceURI(node.Node) != ns {
		return false
	}

	typeName, found := ec.schemaDeclarations.LookupSchemaAttribute(local, ns)
	if !found {
		return false
	}

	annotation := node.TypeAnnotation
	if annotation == "" {
		annotation = nodeTypeAnnotation(node.Node, ec)
	}

	// Untyped constructed attributes match when name and declaration exist;
	// xsl:type may not yet have propagated their attribute annotations.
	return annotation == "" || annotation == xdm.TypeUntypedAtomic || matchesAnnotationSubtype(annotation, typeName, ec)
}

func matchesFunctionItemTest(item xdm.Item, test xdm.FunctionTest, ec *evalContext) bool {
	if test.AnyFunction {
		switch item.(type) {
		case xdm.FunctionItem, xdm.MapItem, xdm.ArrayItem:
			return true
		default:
			return false
		}
	}

	switch value := item.(type) {
	case xdm.FunctionItem:
		return matchesTypedFunctionItem(value, test, ec)
	case xdm.MapItem:
		return matchesMapFunctionItem(value, test, ec)
	case xdm.ArrayItem:
		return len(test.ParamTypes) == 1 && arrayMembersMatchType(value, test.ReturnType, ec)
	default:
		return false
	}
}

func matchesTypedFunctionItem(value xdm.FunctionItem, test xdm.FunctionTest, ec *evalContext) bool {
	if value.Arity >= 0 && value.Arity != len(test.ParamTypes) {
		return false
	}

	// Function parameters are contravariant and the return is covariant.
	if len(value.ParamTypes) > 0 && len(test.ParamTypes) > 0 {
		for i, parameter := range test.ParamTypes {
			actual, declared := xdm.FunctionParameterType(value.ParamTypes, value.RepeatParamType, i)
			if declared && !isSequenceSubtype(parameter, actual, ec) {
				return false
			}
		}
	}

	if value.ReturnType != nil {
		return isSequenceSubtype(*value.ReturnType, test.ReturnType, ec)
	}

	return true
}

func matchesMapFunctionItem(value xdm.MapItem, test xdm.FunctionTest, ec *evalContext) bool {
	if len(test.ParamTypes) != 1 {
		return false
	}

	rt := test.ReturnType
	// Missing map keys may yield empty; a function test must allow that.
	if !rt.Void && (rt.Occurrence == xdm.OccurrenceExactlyOne || rt.Occurrence == xdm.OccurrenceOneOrMore) {
		return false
	}

	allMatch := true
	_ = value.ForEachView(func(key xdm.AtomicValue, val xdm.Sequence) error {
		if matchesItemType(key, test.ParamTypes[0].ItemTest, ec) && !matchesSequenceType(val, rt, ec) {
			allMatch = false
		}

		return nil
	})

	return allMatch
}

func matchesMapItemTest(item xdm.Item, test xdm.MapTest, ec *evalContext) bool {
	value, ok := item.(xdm.MapItem)
	if !ok {
		return false
	}

	if test.AnyType {
		return true
	}

	allMatch := true
	_ = value.ForEachView(func(key xdm.AtomicValue, val xdm.Sequence) error {
		if !matchesItemType(key, test.KeyType, ec) {
			allMatch = false
		}

		if allMatch && !matchesSequenceType(val, test.ValType, ec) {
			allMatch = false
		}

		return nil
	})

	return allMatch
}

func arrayMembersMatchType(array xdm.ArrayItem, memberType xdm.SequenceType, ec *evalContext) bool {
	for _, member := range array.MembersView() {
		if !matchesSequenceType(member, memberType, ec) {
			return false
		}
	}

	return true
}

// isSequenceSubtype checks if type A is a subtype of type B.
// This is used for function subtyping checks.
func isSequenceSubtype(a, b xdm.SequenceType, ec *evalContext) bool {
	// Void (empty-sequence()) is subtype of anything with ZeroOrMore or ZeroOrOne occurrence
	if a.Void {
		return b.Void || b.Occurrence == xdm.OccurrenceZeroOrMore || b.Occurrence == xdm.OccurrenceZeroOrOne
	}

	if b.Void {
		return a.Void
	}
	// Check occurrence compatibility: A's occurrence must be at least as restrictive as B's
	if !occurrenceSubtype(a.Occurrence, b.Occurrence) {
		return false
	}

	return isItemTypeSubtype(a.ItemTest, b.ItemTest, ec)
}

func occurrenceSubtype(a, b xdm.Occurrence) bool {
	switch b {
	case xdm.OccurrenceZeroOrMore:
		return true // anything is subtype of *
	case xdm.OccurrenceOneOrMore:
		return a == xdm.OccurrenceExactlyOne || a == xdm.OccurrenceOneOrMore
	case xdm.OccurrenceZeroOrOne:
		return a == xdm.OccurrenceExactlyOne || a == xdm.OccurrenceZeroOrOne
	case xdm.OccurrenceExactlyOne:
		return a == xdm.OccurrenceExactlyOne
	}

	return false
}

func isItemTypeSubtype(a, b xdm.NodeTest, ec *evalContext) bool {
	if b == nil || isAnyItemTest(b) {
		return true // item() is supertype of everything
	}

	if a == nil || isAnyItemTest(a) {
		return false // item() is not subtype of anything more specific
	}
	// Same type category checks
	switch bt := b.(type) {
	case xdm.AtomicOrUnionType:
		at, ok := a.(xdm.AtomicOrUnionType)
		if !ok {
			return false
		}

		aType := resolveAtomicTypeName(AtomicTypeName(at), ec)
		bType := resolveAtomicTypeName(AtomicTypeName(bt), ec)

		return xdm.IsSubtypeOf(aType, bType)
	case xdm.MapTest:
		return isMapTestSubtype(a, bt, ec)
	case xdm.ArrayTest:
		return isArrayTestSubtype(a, bt, ec)
	case xdm.TypeTest:
		return isNodeKindTestSubtype(a, bt)
	case xdm.NameTest:
		// element/attribute name tests — A must be the same or more specific name
		at, ok := a.(xdm.NameTest)
		if !ok {
			return false
		}

		if bt.Local == "*" {
			return true
		}

		return at.Local == bt.Local && at.Prefix == bt.Prefix
	case xdm.ElementTest:
		return isElementTestSubtype(a, bt, ec)
	case xdm.DocumentTest:
		at, ok := a.(xdm.DocumentTest)
		if !ok {
			return false
		}

		return bt.Inner == nil || at.Inner != nil && isItemTypeSubtype(at.Inner, bt.Inner, ec)
	case xdm.AttributeTest:
		at, ok := a.(xdm.AttributeTest)
		if !ok {
			return false
		}

		if bt.Name == "" {
			return true
		}

		return sameTypeTestName(at.Name, bt.Name, ec, true)
	case xdm.FunctionTest:
		return isFunctionTestSubtype(a, bt, ec)
	}

	return false
}

func isMapTestSubtype(a xdm.NodeTest, bt xdm.MapTest, ec *evalContext) bool {
	at, ok := a.(xdm.MapTest)
	if !ok {
		// FunctionTest might be supertype of MapTest
		return false
	}

	if bt.AnyType {
		return true // map(*) is supertype of all maps
	}

	if at.AnyType {
		return false // map(*) is not subtype of typed map
	}

	return isItemTypeSubtype(at.KeyType, bt.KeyType, ec) &&
		isSequenceSubtype(at.ValType, bt.ValType, ec)
}

func isArrayTestSubtype(a xdm.NodeTest, bt xdm.ArrayTest, ec *evalContext) bool {
	at, ok := a.(xdm.ArrayTest)
	if !ok {
		return false
	}

	if bt.AnyType {
		return true
	}

	if at.AnyType {
		return false
	}

	return isSequenceSubtype(at.MemberType, bt.MemberType, ec)
}

func isNodeKindTestSubtype(a xdm.NodeTest, bt xdm.TypeTest) bool {
	// node() and its kind specializations
	if bt.Kind == xdm.NodeKindNode {
		// node() is supertype of all node-related tests
		switch a.(type) {
		case xdm.TypeTest, xdm.ElementTest, xdm.AttributeTest, xdm.DocumentTest, xdm.NameTest:
			return true
		}

		return false
	}

	at, ok := a.(xdm.TypeTest)
	if !ok {
		return false
	}
	// Same kind or at is more specific
	return at.Kind == bt.Kind
}

func isElementTestSubtype(a xdm.NodeTest, bt xdm.ElementTest, ec *evalContext) bool {
	at, ok := a.(xdm.ElementTest)
	if !ok {
		return false
	}

	if bt.Name == "" && bt.TypeName == "" {
		return true // element() matches any element
	}

	if bt.Name != "" && bt.Name != "*" && !sameTypeTestName(at.Name, bt.Name, ec, false) {
		return false
	}
	// Check type annotation: if bt specifies a type, at must have a
	// compatible type annotation. element(N) without TypeName
	// is equivalent to element(N, xs:anyType?) (nillable), which
	// is NOT a subtype of element(N, T) (non-nillable).
	if bt.TypeName != "" {
		if at.TypeName == "" {
			return false // untyped element(N) is not subtype of typed element(N, T)
		}

		bType := resolveTestTypeName(bt.TypeName, ec)
		if !matchesAnnotationSubtype(resolveTestTypeName(at.TypeName, ec), bType, ec) {
			return false
		}
		// Nillable: element(N, T?) is not subtype of element(N, T)
		if at.Nillable && !bt.Nillable {
			return false
		}
	}

	return true
}

func sameTypeTestName(a, b string, ec *evalContext, attribute bool) bool {
	aLocal, aURI := resolveSchemaTestName(a, ec, attribute)
	bLocal, bURI := resolveSchemaTestName(b, ec, attribute)

	return aLocal == bLocal && aURI == bURI
}

func isFunctionTestSubtype(a xdm.NodeTest, bt xdm.FunctionTest, ec *evalContext) bool {
	// MapTest and ArrayTest are subtypes of FunctionTest
	if bt.AnyFunction {
		switch a.(type) {
		case xdm.FunctionTest, xdm.MapTest, xdm.ArrayTest:
			return true
		}

		return false
	}
	// Typed function test: check contravariant params and covariant return
	switch at := a.(type) {
	case xdm.FunctionTest:
		if at.AnyFunction {
			return false
		}

		if len(at.ParamTypes) != len(bt.ParamTypes) {
			return false
		}

		for i := range bt.ParamTypes {
			// Contravariant: B's param must be subtype of A's param
			if !isSequenceSubtype(bt.ParamTypes[i], at.ParamTypes[i], ec) {
				return false
			}
		}

		return isSequenceSubtype(at.ReturnType, bt.ReturnType, ec)
	case xdm.MapTest:
		// Map is function(xs:anyAtomicType) as item()*
		if len(bt.ParamTypes) != 1 {
			return false
		}

		return true // Maps can be subtype of compatible function tests
	case xdm.ArrayTest:
		if len(bt.ParamTypes) != 1 {
			return false
		}

		return true
	}

	return false
}

func isAnyItemTest(t xdm.NodeTest) bool {
	_, ok := t.(xdm.AnyItemTest)
	return ok
}

// XPath 2.0 restricts lexical QName casts to string literal operands. Inspect
// the source expression, rather than an evaluated or constant-folded value.
func qnameCastOperandAllowed(ec *evalContext, source Expr, value xdm.AtomicValue) bool {
	if ec == nil || ec.version != 20 || value.TypeName == xdm.TypeQName || value.BaseType == xdm.TypeQName {
		return true
	}

	literal, ok := source.(LiteralExpr)
	if !ok {
		return false
	}

	_, ok = literal.Value.(string)

	return ok
}

// castToQName resolves lexical QNames in the evaluator's namespace context.
func castToQName(v xdm.AtomicValue, ec *evalContext) (xdm.AtomicValue, error) {
	// QName → QName: identity
	if v.TypeName == xdm.TypeQName {
		return v, nil
	}

	// NOTATION → QName: NOTATION values are QName-like.
	if v.TypeName == xdm.TypeNOTATION {
		return xdm.AtomicValue{TypeName: xdm.TypeQName, Value: v.Value}, nil
	}

	if _, ok := v.Value.(xdm.QNameValue); ok {
		return xdm.AtomicValue{TypeName: xdm.TypeQName, Value: v.Value}, nil
	}

	// Only string and untypedAtomic can be cast to QName
	if v.TypeName != xdm.TypeString && v.TypeName != xdm.TypeUntypedAtomic {
		return xdm.AtomicValue{}, &xdm.Error{
			Code:    lexicon.ErrXPTY0004,
			Message: fmt.Sprintf("cannot cast %s to %s", v.TypeName, xdm.TypeQName),
		}
	}

	prefix, local, _, validNC := xdm.SplitLexicalQName(v.StringVal())
	if !validNC {
		return xdm.AtomicValue{}, &xdm.Error{
			Code:    errCodeFORG0001,
			Message: fmt.Sprintf("invalid QName: %q", strings.TrimSpace(v.StringVal())),
		}
	}

	uri := ""

	if prefix != "" {
		resolved := false

		if ec != nil && ec.namespaces != nil {
			if ns, ok := ec.namespaces[prefix]; ok {
				uri = ns
				resolved = true
			}
		}

		if !resolved {
			// Fall back to default prefix mappings (fn, xs, math, map, array, err)
			if ns, ok := PredeclaredNamespace(prefix); ok {
				uri = ns
				resolved = true
			}
		}

		if !resolved {
			return xdm.AtomicValue{}, &xdm.Error{
				Code:    errCodeFONS0004,
				Message: fmt.Sprintf("no namespace binding for prefix %q", prefix),
			}
		}
	} else {
		// No prefix: check default namespace in context. Under XSD value-space
		// semantics (qnameValueNoDefaultNS), an unprefixed QName/NOTATION VALUE has
		// no namespace — the XPath default element namespace is NOT applied (opt-in;
		// default xpath behavior is unchanged).
		if ec != nil && ec.namespaces != nil && !ec.qnameValueNoDefaultNS {
			if ns, ok := ec.namespaces[""]; ok {
				uri = ns
			}
		}
	}

	return xdm.AtomicValue{
		TypeName: xdm.TypeQName,
		Value:    xdm.QNameValue{Prefix: prefix, Local: local, URI: uri},
	}, nil
}
