// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"fmt"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

type atomicTypeRequirement struct {
	prefix string
	name   string
}

type prefixValidationPlan struct {
	prefixes    []string
	atomicTypes []atomicTypeRequirement
}

func (p prefixValidationPlan) Validate(namespaces map[string]string, strict bool, decls SchemaDeclarations) error {
	for _, prefix := range p.prefixes {
		if err := validatePrefix(prefix, namespaces, strict); err != nil {
			return err
		}
	}

	for _, req := range p.atomicTypes {
		lexical := joinQName(req.prefix, req.name)

		prefix, local := splitEQName(lexical)
		if !strings.HasPrefix(lexical, "Q{") {
			if err := validatePrefix(prefix, namespaces, strict); err != nil {
				return err
			}
		}

		uri := resolveStaticNameURI(lexical, namespaces, namespaces[""])
		if uri == lexicon.NamespaceXSD {
			if knownXSTypeNames(local) && local != nameNMTOKENS && local != nameIDREFS && local != nameENTITIES {
				continue
			}
		} else if decls != nil {
			if _, ok := decls.LookupSchemaType(local, uri); ok {
				continue
			}
		}

		return &xdm.Error{Code: "XPST0051", Message: fmt.Sprintf("unknown atomic or union type %s", lexical)}
	}

	return nil
}

// knownXSTypeNames lists valid type local names in the xs: namespace
// for use in SequenceType (instance of, cast as, etc.).
func knownXSTypeNames(key string) bool {
	switch key {
	case nameString, "integer", "decimal", "double", "float", fnNameBoolean, nameDate, nameDateTime, nameTime, nameDuration, "dayTimeDuration", "yearMonthDuration", "anyURI", nameQName, nameBase64Binary, nameHexBinary, "untypedAtomic", "anyAtomicType", "long", "int", "short", "byte", "unsignedLong", "unsignedInt", "unsignedShort", "unsignedByte", "nonNegativeInteger", "nonPositiveInteger", "positiveInteger", "negativeInteger", "normalizedString", "token", "language", nameName, "NCName", "NMTOKEN", "ENTITY", "ID", "IDREF", nameGDay, nameGMonth, nameGMonthDay, nameGYear, nameGYearMonth, "dateTimeStamp", nameError, "numeric", "NOTATION", nameNMTOKENS, nameIDREFS, nameENTITIES:
		return true
	}

	return false
}

// validatePrefix checks if a non-empty prefix is bound in user namespaces or defaultPrefixNS.
// When strict is true, the defaultPrefixNS fallback is skipped (XSLT mode).
func validatePrefix(prefix string, namespaces map[string]string, strict bool) error {
	if prefix == "" || prefix == "*" {
		return nil
	}

	if namespaces != nil {
		if uri, ok := namespaces[prefix]; ok {
			if uri != "" {
				return nil
			}

			return undefinedPrefixError(prefix)
		}
	}

	if !strict {
		if _, ok := PredeclaredNamespace(prefix); ok {
			return nil
		}
	}

	if prefix == lexicon.PrefixXML {
		return nil
	}

	return undefinedPrefixError(prefix)
}

func undefinedPrefixError(prefix string) error {
	return &xdm.Error{
		Code:    errCodeXPST0081,
		Message: "undeclared namespace prefix: " + prefix,
	}
}

type prefixPlanBuilder struct {
	prefixes        []string
	atomicTypes     []atomicTypeRequirement
	seenPrefixes    map[string]struct{}
	seenAtomicTypes map[atomicTypeRequirement]struct{}
}

func newPrefixPlanBuilder() prefixPlanBuilder {
	return prefixPlanBuilder{}
}

func (b prefixPlanBuilder) plan() prefixValidationPlan {
	return prefixValidationPlan{
		prefixes:    b.prefixes,
		atomicTypes: b.atomicTypes,
	}
}

func appendPrefixChecks(plan *prefixPlanBuilder, node Expr) {
	if node == nil {
		return
	}

	appendExprLocalPrefixChecks(plan, node)

	switch n := node.(type) {
	case FunctionCall:
		appendPrefixChecksList(plan, n.Args)
	case CastExpr:
		appendPrefixChecks(plan, n.Expr)
	case CastableExpr:
		appendPrefixChecks(plan, n.Expr)
	case InstanceOfExpr:
		appendPrefixChecks(plan, n.Expr)
	case TreatAsExpr:
		appendPrefixChecks(plan, n.Expr)
	case IfExpr:
		appendPrefixChecks(plan, n.Cond)
		appendPrefixChecks(plan, n.Then)
		appendPrefixChecks(plan, n.Else)
	case FLWORExpr:
		for _, clause := range n.Clauses {
			appendFLWORClausePrefixChecks(plan, clause)
		}

		appendPrefixChecks(plan, n.Return)
	case QuantifiedExpr:
		for _, b := range n.Bindings {
			appendPrefixChecks(plan, b.Domain)
		}

		appendPrefixChecks(plan, n.Satisfies)
	case TryCatchExpr:
		appendPrefixChecks(plan, n.Try)

		for _, c := range n.Catches {
			appendPrefixChecks(plan, c.Expr)
		}
	case DynamicFunctionCall:
		appendPrefixChecks(plan, n.Func)
		appendPrefixChecksList(plan, n.Args)
	case InlineFunctionExpr:
		appendPrefixChecks(plan, n.Body)
	case MapConstructorExpr:
		for _, p := range n.Pairs {
			appendPrefixChecks(plan, p.Key)
			appendPrefixChecks(plan, p.Value)
		}
	case ArrayConstructorExpr:
		appendPrefixChecksList(plan, n.Items)
	case SequenceExpr:
		appendPrefixChecksList(plan, n.Items)
	case BinaryExpr, UnaryExpr, ConcatExpr, SimpleMapExpr, RangeExpr, UnionExpr, IntersectExceptExpr:
		appendOperatorPrefixChecks(plan, node)
	case PathExpr, PathStepExpr, FilterExpr, LookupExpr, UnaryLookupExpr:
		appendPathPrefixChecks(plan, node)
	}
}

func appendPrefixChecksList(plan *prefixPlanBuilder, nodes []Expr) {
	for _, node := range nodes {
		appendPrefixChecks(plan, node)
	}
}

func appendExprLocalPrefixChecks(plan *prefixPlanBuilder, node Expr) {
	switch n := node.(type) {
	case VariableExpr:
		addPrefixCheck(plan, n.Prefix)
	case FunctionCall:
		addPrefixCheck(plan, n.Prefix)
	case NamedFunctionRef:
		addPrefixCheck(plan, n.Prefix)
	case CastExpr:
		addCastTypePrefixCheck(plan, n.Type)
	case CastableExpr:
		addCastTypePrefixCheck(plan, n.Type)
	case InstanceOfExpr:
		appendSequenceTypePrefixChecks(plan, n.Type)
	case TreatAsExpr:
		appendSequenceTypePrefixChecks(plan, n.Type)
	case vmLocationPathExpr:
		for i := range n.Steps {
			appendNodeTestPrefixChecks(plan, n.Steps[i].NodeTest)

			for _, pred := range n.Steps[i].Predicates {
				appendVMPredicatePrefixChecks(plan, pred)
			}
		}
	case *LocationPath:
		for i := range n.Steps {
			appendStepLocalPrefixChecks(plan, &n.Steps[i])
		}
	case vmPathExpr:
		appendExprLocalPrefixChecksPath(&n, plan)
	case PathExpr:
		if n.Path != nil {
			for i := range n.Path.Steps {
				appendStepLocalPrefixChecks(plan, &n.Path.Steps[i])
			}
		}
	case FLWORExpr:
		for _, clause := range n.Clauses {
			appendFLWORClauseLocalPrefixChecks(plan, clause)
		}
	case QuantifiedExpr:
		for _, b := range n.Bindings {
			addVarNamePrefixCheck(plan, b.Var)
		}
	case TryCatchExpr:
		for _, c := range n.Catches {
			for _, code := range c.Codes {
				addCatchCodePrefixCheck(plan, code)
			}
		}
	case InlineFunctionExpr:
		for _, param := range n.Params {
			addVarNamePrefixCheck(plan, param.Name)

			if param.TypeHint != nil {
				appendSequenceTypePrefixChecks(plan, *param.TypeHint)
			}
		}

		if n.ReturnType != nil {
			appendSequenceTypePrefixChecks(plan, *n.ReturnType)
		}
	}
}

func appendStepLocalPrefixChecks(plan *prefixPlanBuilder, s *Step) {
	appendNodeTestPrefixChecks(plan, s.NodeTest)
}

func appendVMPredicatePrefixChecks(plan *prefixPlanBuilder, pred Expr) {
	switch p := pred.(type) {
	case vmPositionPredicateExpr:
		return
	case vmAttributeExistsPredicateExpr:
		appendNodeTestPrefixChecks(plan, p.NodeTest)
	case vmAttributeEqualsStringPredicateExpr:
		appendNodeTestPrefixChecks(plan, p.NodeTest)
		appendPrefixChecks(plan, p.Fallback)
	default:
		appendPrefixChecks(plan, pred)
	}
}

func appendNodeTestPrefixChecks(plan *prefixPlanBuilder, nt xdm.NodeTest) {
	if nt == nil {
		return
	}

	switch t := nt.(type) {
	case xdm.NameTest:
		addPrefixCheck(plan, t.Prefix)
	case xdm.AtomicOrUnionType:
		addAtomicOrUnionTypeCheck(plan, t)
	case xdm.ElementTest:
		addQNameStringPrefixCheck(plan, t.Name)
		addQNameStringPrefixCheck(plan, t.TypeName)
	case xdm.AttributeTest:
		addQNameStringPrefixCheck(plan, t.Name)
		addQNameStringPrefixCheck(plan, t.TypeName)
	case xdm.SchemaElementTest:
		addQNameStringPrefixCheck(plan, t.Name)
	case xdm.SchemaAttributeTest:
		addQNameStringPrefixCheck(plan, t.Name)
	case xdm.DocumentTest:
		appendNodeTestPrefixChecks(plan, t.Inner)
	case xdm.FunctionTest:
		for _, pt := range t.ParamTypes {
			appendSequenceTypePrefixChecks(plan, pt)
		}

		appendSequenceTypePrefixChecks(plan, t.ReturnType)
	case xdm.MapTest:
		appendNodeTestPrefixChecks(plan, t.KeyType)
		appendSequenceTypePrefixChecks(plan, t.ValType)
	case xdm.ArrayTest:
		appendSequenceTypePrefixChecks(plan, t.MemberType)
	}
}

func appendSequenceTypePrefixChecks(plan *prefixPlanBuilder, st xdm.SequenceType) {
	appendNodeTestPrefixChecks(plan, st.ItemTest)
}

func appendFLWORClausePrefixChecks(plan *prefixPlanBuilder, clause FLWORClause) {
	appendFLWORClauseLocalPrefixChecks(plan, clause)

	switch c := clause.(type) {
	case ForClause:
		appendPrefixChecks(plan, c.Expr)
	case LetClause:
		appendPrefixChecks(plan, c.Expr)
	}
}

func appendFLWORClauseLocalPrefixChecks(plan *prefixPlanBuilder, clause FLWORClause) {
	switch c := clause.(type) {
	case ForClause:
		addVarNamePrefixCheck(plan, c.Var)

		if c.PosVar != "" {
			addVarNamePrefixCheck(plan, c.PosVar)
		}
	case LetClause:
		addVarNamePrefixCheck(plan, c.Var)
	}
}

func addPrefixCheck(plan *prefixPlanBuilder, prefix string) {
	if prefix == "" || prefix == "*" {
		return
	}

	if plan.seenPrefixes == nil {
		plan.seenPrefixes = make(map[string]struct{}, 4)
	}

	if _, ok := plan.seenPrefixes[prefix]; ok {
		return
	}

	plan.seenPrefixes[prefix] = struct{}{}
	plan.prefixes = append(plan.prefixes, prefix)
}

func addVarNamePrefixCheck(plan *prefixPlanBuilder, varName string) {
	if strings.HasPrefix(varName, "Q{") {
		return
	}

	if prefix, _, ok := strings.Cut(varName, ":"); ok {
		addPrefixCheck(plan, prefix)
	}
}

// addQNameStringPrefixCheck extracts the prefix from a "prefix:local" QName string
// and adds it to the prefix validation plan. Handles Q{uri}local and empty strings.
func addQNameStringPrefixCheck(plan *prefixPlanBuilder, qname string) {
	if qname == "" || qname == "*" {
		return
	}

	addVarNamePrefixCheck(plan, qname)
}

// addCatchCodePrefixCheck extracts the prefix from a catch error code
// and adds it to the prefix validation plan. Handles wildcards and Q{uri} forms.
func addCatchCodePrefixCheck(plan *prefixPlanBuilder, code string) {
	if code == "" || code == "*" {
		return
	}

	if strings.HasPrefix(code, "Q{") {
		return // URIQualifiedName, no prefix to validate
	}

	if prefix, _, ok := strings.Cut(code, ":"); ok {
		if prefix != "*" {
			addPrefixCheck(plan, prefix)
		}
	}
}

// addCastTypePrefixCheck validates the prefix of a cast/castable target type. The
// parseOptions splits a braced-URI Q{uri}local target on its first colon, so reconstruct
// the lexical form and route through addQNameStringPrefixCheck, which skips Q{}
// names (their namespace is literal and needs no binding) and validates an ordinary
// prefix.
func addCastTypePrefixCheck(plan *prefixPlanBuilder, t AtomicTypeName) {
	addQNameStringPrefixCheck(plan, joinQName(t.Prefix, t.Name))
}

func addAtomicOrUnionTypeCheck(plan *prefixPlanBuilder, t xdm.AtomicOrUnionType) {
	req := atomicTypeRequirement{prefix: t.Prefix, name: t.Name}

	if plan.seenAtomicTypes == nil {
		plan.seenAtomicTypes = make(map[atomicTypeRequirement]struct{}, 4)
	}

	if _, ok := plan.seenAtomicTypes[req]; ok {
		return
	}

	plan.seenAtomicTypes[req] = struct{}{}
	plan.atomicTypes = append(plan.atomicTypes, req)
}

func appendOperatorPrefixChecks(plan *prefixPlanBuilder, node Expr) {
	switch n := node.(type) {
	case BinaryExpr:
		appendPrefixChecks(plan, n.Left)
		appendPrefixChecks(plan, n.Right)
	case UnaryExpr:
		appendPrefixChecks(plan, n.Operand)
	case ConcatExpr:
		appendPrefixChecks(plan, n.Left)
		appendPrefixChecks(plan, n.Right)
	case SimpleMapExpr:
		appendPrefixChecks(plan, n.Left)
		appendPrefixChecks(plan, n.Right)
	case RangeExpr:
		appendPrefixChecks(plan, n.Start)
		appendPrefixChecks(plan, n.End)
	case UnionExpr:
		appendPrefixChecks(plan, n.Left)
		appendPrefixChecks(plan, n.Right)
	case IntersectExceptExpr:
		appendPrefixChecks(plan, n.Left)
		appendPrefixChecks(plan, n.Right)
	}
}

func appendPathPrefixChecks(plan *prefixPlanBuilder, node Expr) {
	switch n := node.(type) {
	case PathExpr:
		appendPrefixChecks(plan, n.Filter)
	case PathStepExpr:
		appendPrefixChecks(plan, n.Left)
		appendPrefixChecks(plan, n.Right)
	case FilterExpr:
		appendPrefixChecks(plan, n.Expr)

		for _, pred := range n.Predicates {
			appendPrefixChecks(plan, pred)
		}
	case LookupExpr:
		appendPrefixChecks(plan, n.Expr)
		appendPrefixChecks(plan, n.Key)
	case UnaryLookupExpr:
		appendPrefixChecks(plan, n.Key)
	}
}

func appendExprLocalPrefixChecksPath(n *vmPathExpr, plan *prefixPlanBuilder) {
	if n.Path != nil {
		for i := range n.Path.Steps {
			appendNodeTestPrefixChecks(plan, n.Path.Steps[i].NodeTest)

			for _, pred := range n.Path.Steps[i].Predicates {
				appendVMPredicatePrefixChecks(plan, pred)
			}
		}
	}
}
