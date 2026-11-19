package xpath

import "github.com/skarm/xmlsec/transform/internal/xdm"

type profileVisitor func(any) error

func (visit profileVisitor) walk(nodes ...any) error {
	for _, node := range nodes {
		if err := visit.walkNode(astNodeValue(node)); err != nil {
			return err
		}
	}

	return nil
}

func walkProfileList[T any](visit profileVisitor, nodes []T) error {
	for _, node := range nodes {
		if err := visit.walk(node); err != nil {
			return err
		}
	}

	return nil
}

//nolint:gocyclo // Each AST variant declares its children in visitation order.
func (visit profileVisitor) walkNode(node any) error {
	switch n := node.(type) {
	case nil:
		return nil
	case []Expr:
		return walkProfileList(visit, n)
	case []Step:
		return walkProfileList(visit, n)
	case []FLWORClause:
		return walkProfileList(visit, n)
	case []QuantifiedBinding:
		return walkProfileList(visit, n)
	case []CatchClause:
		return walkProfileList(visit, n)
	case []FunctionParam:
		return walkProfileList(visit, n)
	case []MapConstructorPair:
		return walkProfileList(visit, n)
	case []xdm.SequenceType:
		return walkProfileList(visit, n)
	case []vmLocationStep:
		return walkProfileList(visit, n)
	}

	if err := visit(node); err != nil {
		return err
	}

	switch n := node.(type) {
	case LocationPath:
		return visit.walk(n.Steps)
	case Step:
		return visit.walk(n.NodeTest, n.Predicates)
	case BinaryExpr:
		return visit.walk(n.Left, n.Right)
	case UnaryExpr:
		return visit.walk(n.Operand)
	case ConcatExpr:
		return visit.walk(n.Left, n.Right)
	case SimpleMapExpr:
		return visit.walk(n.Left, n.Right)
	case RangeExpr:
		return visit.walk(n.Start, n.End)
	case UnionExpr:
		return visit.walk(n.Left, n.Right)
	case IntersectExceptExpr:
		return visit.walk(n.Left, n.Right)
	case FilterExpr:
		return visit.walk(n.Expr, n.Predicates)
	case PathExpr:
		return visit.walk(n.Filter, n.Path)
	case PathStepExpr:
		return visit.walk(n.Left, n.Right)
	case LookupExpr:
		return visit.walk(n.Expr, n.Key)
	case UnaryLookupExpr:
		return visit.walk(n.Key)
	case FLWORExpr:
		return visit.walk(n.Clauses, n.Return)
	case ForClause:
		return visit.walk(n.Expr)
	case LetClause:
		return visit.walk(n.Expr)
	case QuantifiedExpr:
		return visit.walk(n.Bindings, n.Satisfies)
	case QuantifiedBinding:
		return visit.walk(n.Domain)
	case IfExpr:
		return visit.walk(n.Cond, n.Then, n.Else)
	case TryCatchExpr:
		return visit.walk(n.Try, n.Catches)
	case CatchClause:
		return visit.walk(n.Expr)
	case InstanceOfExpr:
		return visit.walk(n.Expr, n.Type)
	case CastExpr:
		return visit.walk(n.Expr, n.Type)
	case CastableExpr:
		return visit.walk(n.Expr, n.Type)
	case TreatAsExpr:
		return visit.walk(n.Expr, n.Type)
	case FunctionCall:
		return visit.walk(n.Args)
	case DynamicFunctionCall:
		return visit.walk(n.Func, n.Args)
	case InlineFunctionExpr:
		return visit.walk(n.Params, n.ReturnType, n.Body)
	case FunctionParam:
		return visit.walk(n.TypeHint)
	case MapConstructorExpr:
		return visit.walk(n.Pairs)
	case MapConstructorPair:
		return visit.walk(n.Key, n.Value)
	case ArrayConstructorExpr:
		return visit.walk(n.Items)
	case SequenceExpr:
		return visit.walk(n.Items)
	case xdm.SequenceType:
		return visit.walk(n.ItemTest)
	case xdm.DocumentTest:
		return visit.walk(n.Inner)
	case xdm.FunctionTest:
		return visit.walk(n.ParamTypes, n.ReturnType)
	case xdm.MapTest:
		return visit.walk(n.KeyType, n.ValType)
	case xdm.ArrayTest:
		return visit.walk(n.MemberType)
	case vmLocationPathExpr:
		return visit.walk(n.Steps)
	case vmLocationStep:
		return visit.walk(n.NodeTest, n.Predicates)
	case vmPathExpr:
		return visit.walk(n.Filter, n.Path)
	case vmAttributeExistsPredicateExpr:
		return visit.walk(n.NodeTest)
	case vmAttributeEqualsStringPredicateExpr:
		return visit.walk(n.NodeTest, n.Fallback)
	}

	return nil
}

//nolint:gocyclo // Pointer forms of the closed AST interfaces map to their values.
func astNodeValue(node any) any {
	switch n := node.(type) {
	case *LiteralExpr:
		return astPointerValue(n)
	case *VariableExpr:
		return astPointerValue(n)
	case *RootExpr:
		return astPointerValue(n)
	case *ContextItemExpr:
		return astPointerValue(n)
	case *LocationPath:
		return astPointerValue(n)
	case *BinaryExpr:
		return astPointerValue(n)
	case *UnaryExpr:
		return astPointerValue(n)
	case *ConcatExpr:
		return astPointerValue(n)
	case *SimpleMapExpr:
		return astPointerValue(n)
	case *RangeExpr:
		return astPointerValue(n)
	case *UnionExpr:
		return astPointerValue(n)
	case *IntersectExceptExpr:
		return astPointerValue(n)
	case *FilterExpr:
		return astPointerValue(n)
	case *PathExpr:
		return astPointerValue(n)
	case *PathStepExpr:
		return astPointerValue(n)
	case *LookupExpr:
		return astPointerValue(n)
	case *UnaryLookupExpr:
		return astPointerValue(n)
	case *FLWORExpr:
		return astPointerValue(n)
	case *ForClause:
		return astPointerValue(n)
	case *LetClause:
		return astPointerValue(n)
	case *QuantifiedExpr:
		return astPointerValue(n)
	case *IfExpr:
		return astPointerValue(n)
	case *TryCatchExpr:
		return astPointerValue(n)
	case *InstanceOfExpr:
		return astPointerValue(n)
	case *CastExpr:
		return astPointerValue(n)
	case *CastableExpr:
		return astPointerValue(n)
	case *TreatAsExpr:
		return astPointerValue(n)
	case *FunctionCall:
		return astPointerValue(n)
	case *DynamicFunctionCall:
		return astPointerValue(n)
	case *NamedFunctionRef:
		return astPointerValue(n)
	case *InlineFunctionExpr:
		return astPointerValue(n)
	case *PlaceholderExpr:
		return astPointerValue(n)
	case *MapConstructorExpr:
		return astPointerValue(n)
	case *ArrayConstructorExpr:
		return astPointerValue(n)
	case *SequenceExpr:
		return astPointerValue(n)
	case *xdm.SequenceType:
		return astPointerValue(n)
	case *xdm.NameTest:
		return astPointerValue(n)
	case *xdm.TypeTest:
		return astPointerValue(n)
	case *xdm.PITest:
		return astPointerValue(n)
	case *xdm.ElementTest:
		return astPointerValue(n)
	case *xdm.AttributeTest:
		return astPointerValue(n)
	case *xdm.DocumentTest:
		return astPointerValue(n)
	case *xdm.SchemaElementTest:
		return astPointerValue(n)
	case *xdm.SchemaAttributeTest:
		return astPointerValue(n)
	case *xdm.NamespaceNodeTest:
		return astPointerValue(n)
	case *xdm.FunctionTest:
		return astPointerValue(n)
	case *xdm.MapTest:
		return astPointerValue(n)
	case *xdm.ArrayTest:
		return astPointerValue(n)
	case *xdm.AnyItemTest:
		return astPointerValue(n)
	case *xdm.AtomicOrUnionType:
		return astPointerValue(n)
	case *compiledExprRef:
		return astPointerValue(n)
	case *vmPositionPredicateExpr:
		return astPointerValue(n)
	case *vmAttributeExistsPredicateExpr:
		return astPointerValue(n)
	case *vmAttributeEqualsStringPredicateExpr:
		return astPointerValue(n)
	case *vmLocationPathExpr:
		return astPointerValue(n)
	case *vmPathExpr:
		return astPointerValue(n)
	default:
		return node
	}
}

func astPointerValue[T any](node *T) any {
	if node == nil {
		return nil
	}

	return *node
}
