// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"reflect"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// TypeNameRef identifies a referenced type by its resolved namespace URI and local
// name. Prefix retains the lexical spelling for diagnostics and is empty for
// unprefixed or URI-qualified names.
type TypeNameRef struct {
	// Prefix retains the lexical prefix, or empty for an unprefixed or URI-qualified
	// name.
	Prefix string
	// Name is the local type name retained for diagnostics.
	Name string
	// URI is the namespace resolved from the expression's static context.
	URI string
}

// FunctionNameRef identifies a static function call or named function reference by its
// resolved namespace, local name and arity. Arrow-call arity includes the implicit
// left operand; Prefix retains the lexical spelling for diagnostics.
type FunctionNameRef struct {
	// Prefix retains the lexical prefix for diagnostics.
	Prefix string
	// Name is the local function name.
	Name string
	// URI is the resolved function namespace, independent of the default element
	// namespace.
	URI string
	// Arity is the static argument count, including the implicit left operand of an arrow
	// call.
	Arity int
}

// StaticReferences summarizes names and schema-component tests in a compiled
// expression. Hosts can use it to impose restrictions beyond namespace validation.
// Reporting a schema reference does not make that component available or enable
// schema-aware processing.
type StaticReferences struct {
	// FreeVariables lists lexical variable names not bound by an enclosing for, let,
	// quantified expression or inline-function parameter.
	FreeVariables []string
	// TypeNames lists resolved type references in type operators, kind tests and nested
	// item types. Unprefixed names use the default element/type namespace.
	TypeNames []TypeNameRef
	// FunctionNames lists static call targets and named function references, including
	// constructor calls and arrow targets. Unprefixed function names use the function
	// namespace rather than the default element namespace.
	FunctionNames []FunctionNameRef
	// SchemaComponentTests lists schema-element() and schema-attribute() tests as
	// diagnostic strings for hosts that restrict references to schema declarations.
	SchemaComponentTests []string
}

// StaticReferences walks the compiled syntax and resolves type and function names
// using the supplied namespace bindings and predeclared prefixes. It reports
// references for static analysis without evaluating the expression or retrieving
// resources.
func (e *Expression) StaticReferences(namespaces map[string]string) StaticReferences {
	ast := e.astExpr()
	c := &staticRefCollector{bound: map[string]int{}, namespaces: namespaces}
	c.walk(ast)

	return StaticReferences{
		FreeVariables:        c.freeVars,
		TypeNames:            c.typeNames,
		FunctionNames:        c.funcNames,
		SchemaComponentTests: c.schemaComponentTests,
	}
}

type staticRefCollector struct {
	visits int
	// bound is a REFCOUNT of in-scope variable bindings keyed by expanded name, not a
	// flat present/absent set: an inner for/let/quantified/inline-function binding may
	// SHADOW an outer one of the same name, so binding increments and leaving scope
	// decrements (deleting at zero). Restoring the prior count on exit keeps the outer
	// binding visible to later references instead of unbinding it — a flat set with an
	// unconditional delete would wrongly report the still-bound outer variable as free.
	bound                map[string]int
	namespaces           map[string]string
	freeVars             []string
	typeNames            []TypeNameRef
	funcNames            []FunctionNameRef
	schemaComponentTests []string
	seenFree             map[string]struct{}
}

// bindVar enters a variable binding for the duration of an enclosed scope.
func (c *staticRefCollector) bindVar(key string) {
	key = VariableKey(key, c.namespaces)
	c.bound[key]++
}

// unbindVar leaves a variable binding, restoring any shadowed outer binding.
func (c *staticRefCollector) unbindVar(key string) {
	key = VariableKey(key, c.namespaces)
	if c.bound[key] <= 1 {
		delete(c.bound, key)
		return
	}

	c.bound[key]--
}

func (c *staticRefCollector) addFreeVar(key string) {
	lexical := key

	key = VariableKey(key, c.namespaces)
	if c.bound[key] > 0 {
		return
	}

	if c.seenFree == nil {
		c.seenFree = map[string]struct{}{}
	}

	if _, ok := c.seenFree[key]; ok {
		return
	}

	c.seenFree[key] = struct{}{}
	c.freeVars = append(c.freeVars, lexical)
}

// addAtomicType records a type name from a split (Prefix, Name) pair — e.g. an
// AtomicOrUnionType / AtomicTypeName from the parseOptions. It reconstructs the lexical
// form (so a braced-URI Q{uri}local mis-split by splitQName round-trips) before
// recording, so URI resolution is uniform across all forms.
func (c *staticRefCollector) addAtomicType(prefix, name string) {
	if name == "" {
		return
	}

	c.addTypeNameLexical(joinQName(prefix, name))
}

// addTypeNameLexical records a type name held as a raw lexical EQName string (as
// element()/attribute() kind tests store their type annotation, or as reconstructed
// from a split pair), resolving its namespace URI against the default ELEMENT
// namespace for an unprefixed name. The local name is split EQName-aware so a
// braced-URI Q{uri}local yields the bare local name, not a colon-corrupted fragment.
func (c *staticRefCollector) addTypeNameLexical(lexical string) {
	if lexical == "" {
		return
	}

	prefix, local := splitEQName(lexical)
	uri := resolveStaticNameURI(lexical, c.namespaces, c.namespaces[""])
	c.typeNames = append(c.typeNames, TypeNameRef{Prefix: prefix, Name: local, URI: uri})
}

// addFunctionName records a static function-reference callee QName + arity, resolving
// its namespace URI against the default FUNCTION namespace (fn) for an unprefixed name.
func (c *staticRefCollector) addFunctionName(prefix, name string, arity int) {
	if name == "" {
		return
	}

	lexical := joinQName(prefix, name)
	dispPrefix, dispLocal := splitEQName(lexical)
	uri := resolveStaticNameURI(lexical, c.namespaces, NSFn)
	c.funcNames = append(c.funcNames, FunctionNameRef{Prefix: dispPrefix, Name: dispLocal, URI: uri, Arity: arity})
}

// walkSequenceType collects every atomic-or-union type name named anywhere in a
// sequence type, INCLUDING the user type names nested inside array(T), map(K,V),
// and function(P...) as R item types. A purely top-level scan would miss a
// forbidden user-defined type hidden inside such a parameterized item type (e.g.
// "instance of array(t:T)"), so the walk descends recursively into the item test.
func (c *staticRefCollector) walkSequenceType(st xdm.SequenceType) {
	// A Void / empty-sequence() type carries NO item test (nil ItemTest), so skip it.
	// derefNodeTest also tolerates a nil interface (defense in depth), but guarding here
	// keeps the intent explicit and avoids a needless reflect call.
	if st.Void || st.ItemTest == nil {
		return
	}

	c.walkItemTest(st.ItemTest)
}

// walkItemTest collects atomic-or-union type names reachable from an item test,
// recursing through the parameterized array/map/function item types and the
// type-annotated kind tests (element()/attribute()/document-node()).
func (c *staticRefCollector) walkItemTest(it xdm.NodeTest) {
	it, ok := derefNodeTest(it)
	if !ok {
		return
	}

	switch t := it.(type) {
	case xdm.AtomicOrUnionType:
		c.addAtomicType(t.Prefix, t.Name)
	case xdm.ElementTest:
		// element(name?, type?) — the optional second arg is a user/built-in type
		// annotation. The name arg is an element NAME test, not a type, so it is not
		// recorded. TypeName is the raw lexical "prefix:local" (parseOptions scanQName).
		c.addTypeNameLexical(t.TypeName)
	case xdm.AttributeTest:
		c.addTypeNameLexical(t.TypeName)
	case xdm.SchemaElementTest:
		// schema-element(E) / schema-attribute(A) reference a GLOBAL element/attribute
		// DECLARATION — a schema component that is not part of every static context. The
		// reference is reported so a conformance-restricted caller (e.g. XSD 1.1 CTA,
		// whose static context per §F.2 has only built-in type definitions) can reject it.
		c.schemaComponentTests = append(c.schemaComponentTests, "schema-element("+t.Name+")")
	case xdm.SchemaAttributeTest:
		c.schemaComponentTests = append(c.schemaComponentTests, "schema-attribute("+t.Name+")")
	case xdm.DocumentTest:
		c.walkItemTest(t.Inner)
	case xdm.ArrayTest:
		if !t.AnyType {
			c.walkSequenceType(t.MemberType)
		}
	case xdm.MapTest:
		if !t.AnyType {
			c.walkItemTest(t.KeyType)
			c.walkSequenceType(t.ValType)
		}
	case xdm.FunctionTest:
		if !t.AnyFunction {
			for _, pt := range t.ParamTypes {
				c.walkSequenceType(pt)
			}

			c.walkSequenceType(t.ReturnType)
		}
	}
}

func (c *staticRefCollector) walk(node Expr) { //nolint:gocyclo // One traversal must cover every expression kind and its lexical scope.
	c.visits++

	node, ok := derefExprNode(node)
	if !ok {
		return
	}

	switch n := node.(type) {
	case VariableExpr:
		c.addFreeVar(n.Name)
	case CastExpr:
		c.addAtomicType(n.Type.Prefix, n.Type.Name)
		c.walk(n.Expr)
	case CastableExpr:
		c.addAtomicType(n.Type.Prefix, n.Type.Name)
		c.walk(n.Expr)
	case InstanceOfExpr:
		c.walkSequenceType(n.Type)
		c.walk(n.Expr)
	case TreatAsExpr:
		c.walkSequenceType(n.Type)
		c.walk(n.Expr)
	case FunctionCall:
		// Arity is the argument count; for a desugared arrow (1 => f()) the parseOptions has
		// already prepended the left operand, so len(Args) is the true static arity.
		c.addFunctionName(n.Prefix, n.Name, len(n.Args))

		for _, arg := range n.Args {
			c.walk(arg)
		}
	case NamedFunctionRef:
		c.addFunctionName(n.Prefix, n.Name, n.Arity)
	case DynamicFunctionCall:
		// A dynamic call applies a function VALUE (e.g. an inline function literal,
		// `function($x){...}(1)`, or a variable/expression yielding a function). No
		// out-of-context NAMED function is referenced: an inline function literal is an
		// in-context XPath 3.1 language construct (its body is walked below, so any named
		// function / out-of-context type it uses IS still gated), and a NamedFunctionRef
		// or FunctionCall target is recorded when n.Func is walked. So nothing is recorded
		// for the call itself — higher-order / inline functions are not forbidden by the
		// CTA static context (§F.2 restricts the available NAMED function signatures and
		// type definitions, not the use of function values), only their named referents.
		c.walk(n.Func)

		for _, arg := range n.Args {
			c.walk(arg)
		}
	case PathExpr:
		c.walk(n.Filter)
		c.walkLocationPath(n.Path)
	case *LocationPath:
		c.walkLocationPath(n)
	case LocationPath:
		c.walkLocationPath(&n)
	case PathStepExpr:
		c.walk(n.Left)
		c.walk(n.Right)
	case FilterExpr:
		c.walk(n.Expr)

		for _, p := range n.Predicates {
			c.walk(p)
		}
	case BinaryExpr:
		c.walk(n.Left)
		c.walk(n.Right)
	case UnaryExpr:
		c.walk(n.Operand)
	case ConcatExpr:
		c.walk(n.Left)
		c.walk(n.Right)
	case SimpleMapExpr:
		c.walk(n.Left)
		c.walk(n.Right)
	case RangeExpr:
		c.walk(n.Start)
		c.walk(n.End)
	case UnionExpr:
		c.walk(n.Left)
		c.walk(n.Right)
	case IntersectExceptExpr:
		c.walk(n.Left)
		c.walk(n.Right)
	case IfExpr:
		c.walk(n.Cond)
		c.walk(n.Then)
		c.walk(n.Else)
	case FLWORExpr:
		c.walkFLWOR(n)
	case QuantifiedExpr:
		c.walkQuantified(n)
	case TryCatchExpr:
		c.walkTryCatch(n)
	case InlineFunctionExpr:
		c.walkInlineFunction(n)
	case LookupExpr:
		c.walk(n.Expr)
		c.walk(n.Key)
	case UnaryLookupExpr:
		c.walk(n.Key)
	case MapConstructorExpr:
		for _, p := range n.Pairs {
			c.walk(p.Key)
			c.walk(p.Value)
		}
	case ArrayConstructorExpr:
		for _, item := range n.Items {
			c.walk(item)
		}
	case SequenceExpr:
		for _, item := range n.Items {
			c.walk(item)
		}
	}
}

func (c *staticRefCollector) walkLocationPath(lp *LocationPath) {
	if lp == nil {
		return
	}

	for i := range lp.Steps {
		// A step's node test may be a type-annotated kind test (e.g.
		// self::element(*, t:T)), which carries a user/built-in type name.
		c.walkItemTest(lp.Steps[i].NodeTest)

		for _, p := range lp.Steps[i].Predicates {
			c.walk(p)
		}
	}
}

// walkFLWOR evaluates for/let clauses left to right: each clause's expression is
// in the scope established by the PRIOR clauses, and the clause's own variable
// becomes bound for the clauses that follow and the return expression.
func (c *staticRefCollector) walkFLWOR(n FLWORExpr) {
	var added []string

	for _, clause := range n.Clauses {
		switch cl := clause.(type) {
		case ForClause:
			c.walk(cl.Expr)
			c.bindVar(cl.Var)

			added = append(added, cl.Var)
			if cl.PosVar != "" {
				c.bindVar(cl.PosVar)
				added = append(added, cl.PosVar)
			}
		case LetClause:
			c.walk(cl.Expr)
			c.bindVar(cl.Var)
			added = append(added, cl.Var)
		}
	}

	c.walk(n.Return)

	for _, k := range added {
		c.unbindVar(k)
	}
}

// walkTryCatch walks a try/catch expression. Each catch body runs with the
// implicit error variables ($err:code, …) bound by the evaluator, so they are
// bound (refcounted, restoring any shadowed outer binding) for the duration of the
// body and a reference to one is not reported as a free variable.
func (c *staticRefCollector) walkTryCatch(n TryCatchExpr) {
	c.walk(n.Try)

	for _, ct := range n.Catches {
		for _, k := range catchErrorVarKeys() {
			c.bindVar(k)
		}

		c.walk(ct.Expr)

		for _, k := range catchErrorVarKeys() {
			c.unbindVar(k)
		}
	}
}

// walkQuantified binds every quantifier variable for the satisfies expression;
// each binding's domain is in the scope of the prior bindings.
func (c *staticRefCollector) walkQuantified(n QuantifiedExpr) {
	added := make([]string, 0, len(n.Bindings))

	for _, b := range n.Bindings {
		c.walk(b.Domain)
		c.bindVar(b.Var)
		added = append(added, b.Var)
	}

	c.walk(n.Satisfies)

	for _, k := range added {
		c.unbindVar(k)
	}
}

// walkInlineFunction collects references from an inline function LITERAL
// (function($v as T) as R { body }): its parameter and return SEQUENCE TYPES may
// name user-defined atomic types (which the CTA static check forbids), so they are
// walked alongside the body, mirroring the namespace validator's traversal. The
// parameters are bound for the duration of the body.
func (c *staticRefCollector) walkInlineFunction(n InlineFunctionExpr) {
	added := make([]string, 0, len(n.Params))

	for _, p := range n.Params {
		if p.TypeHint != nil {
			c.walkSequenceType(*p.TypeHint)
		}

		c.bindVar(p.Name)
		added = append(added, p.Name)
	}

	if n.ReturnType != nil {
		c.walkSequenceType(*n.ReturnType)
	}

	c.walk(n.Body)

	for _, k := range added {
		c.unbindVar(k)
	}
}

// VariableKey resolves a variable's expanded name for binding and scope checks.
// An unprefixed variable has no namespace, independently of the default element
// namespace. Unknown prefixes remain lexical for the separate prefix validator.
func VariableKey(name string, namespaces map[string]string) string {
	if strings.HasPrefix(name, "Q{") {
		name = name[1:]
	}

	if strings.HasPrefix(name, "{}") {
		return name[2:]
	}

	if strings.HasPrefix(name, "{") {
		return name
	}

	if prefix, local, ok := strings.Cut(name, ":"); ok {
		uri, known := namespaces[prefix]
		if !known {
			uri, known = PredeclaredNamespace(prefix)
		}

		if known && uri != "" {
			return xdm.ClarkName(uri, local)
		}
	}

	return name
}

// derefNodeTest is the NodeTest analogue of derefExpr, normalizing a pointer-form
// item test (e.g. &ArrayTest{...}) to its value form. ok is false for a nil node
// test (a nil interface — e.g. an empty-sequence() type's ItemTest — yields the
// reflect.Invalid kind, NOT a panic; a typed nil pointer is caught by IsNil), so a
// caller can rely on this being nil-safe.
func derefNodeTest(it xdm.NodeTest) (xdm.NodeTest, bool) {
	rv := reflect.ValueOf(it)
	if rv.Kind() != reflect.Pointer {
		return it, it != nil
	}

	if rv.IsNil() {
		return nil, false
	}

	if nt, ok := rv.Elem().Interface().(xdm.NodeTest); ok {
		return nt, true
	}

	return it, true
}

// derefExprNode normalizes any pointer-form Expr to its value form via reflection.
// CompileExpr stores caller-built ASTs unchanged and the VM lowerer accepts both
// value and pointer node forms (e.g. &CastExpr{...}), so StaticReferences must too.
// (The package's other derefExpr in streamability.go only covers a fixed handful of
// pointer types, so it is not reused here.) ok is false for a nil node (including a
// typed nil pointer).
func derefExprNode(node Expr) (Expr, bool) {
	rv := reflect.ValueOf(node)
	if rv.Kind() != reflect.Pointer {
		return node, node != nil
	}

	if rv.IsNil() {
		return nil, false
	}

	if e, ok := rv.Elem().Interface().(Expr); ok {
		return e, true
	}

	return node, true
}

// catchErrorVarKeys are the implicit error variables the evaluator binds inside a
// try/catch catch clause (XPath/XQuery error namespace, conventional "err" prefix),
// keyed by the SAME lexical "err:local" form a reference site produces. They are
// bound for the scope of each catch body so a reference to one is not reported as a
// free variable. Kept in sync with eval_control.go buildCatchContext.
func catchErrorVarKeys() [7]string {
	return [7]string{
		"err:code",
		"err:description",
		"err:value",
		"err:module",
		"err:line-number",
		"err:column-number",
		"err:additional",
	}
}

// resolveStaticNameURI resolves the namespace URI of a lexical EQName for the
// static analysis, uniformly across the three name forms — matching the resolution
// the parseOptions/Validate/evaluator apply to these names:
//   - Q{uri}local  -> uri (the braced URI literally);
//   - prefix:local -> the in-scope binding if present, else the predeclared binding
//     (xs/fn/math/map/array/err);
//   - local        -> defaultNS, which the caller supplies as the default ELEMENT
//     namespace for a type name, or the default FUNCTION namespace (fn) for a
//     function name.
//
// An unresolved prefix yields "".
func resolveStaticNameURI(lexical string, namespaces map[string]string, defaultNS string) string {
	if strings.HasPrefix(lexical, "Q{") {
		if i := strings.IndexByte(lexical, '}'); i >= 0 {
			return lexical[2:i]
		}
	}

	prefix, _ := splitQName(lexical)
	if prefix == "" {
		return defaultNS
	}

	if ns, ok := namespaces[prefix]; ok {
		return ns
	}

	if pn, ok := PredeclaredNamespace(prefix); ok {
		return pn
	}

	return ""
}

// joinQName reconstructs the lexical "prefix:local" form (or "local"/"Q{uri}local"
// when prefix is empty) from a split QName.
func joinQName(prefix, name string) string {
	if prefix == "" {
		return name
	}

	return prefix + ":" + name
}

// splitEQName splits a lexical EQName into (prefix, local) without corrupting a
// braced-URI Q{uri}local — for which it returns an EMPTY prefix and the local name
// after "}" (plain splitQName would split on the first colon inside the URI). For
// "prefix:local" / "local" it behaves like splitQName.
func splitEQName(lexical string) (prefix, local string) {
	if strings.HasPrefix(lexical, "Q{") {
		if _, after, ok := strings.Cut(lexical, "}"); ok {
			return "", after
		}
	}

	return splitQName(lexical)
}
