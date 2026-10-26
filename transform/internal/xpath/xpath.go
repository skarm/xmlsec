// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"slices"
	"sync"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// Expression retains a compiled XPath program and its static context. Public adapters
// select an explicit language profile. Expressions can be reused concurrently when
// supplied values and callbacks obey the evaluation ownership contract.
type Expression struct {
	// staticNamespaces captures immutable prefix bindings; nil uses evaluator bindings.
	staticNamespaces map[string]string
	// defaultXMLNamespace retains the host XML default independently of XPath's default
	// element/type namespace.
	defaultXMLNamespace string
	// staticCollation overrides the evaluator's default collation when bound.
	staticCollation string
	// deferred retains an error reported only if a deferred expression is evaluated.
	deferred error
	// source retains the original expression text for diagnostics and syntax analysis.
	source string
	// ast optionally retains the parsed syntax tree for internal analysis.
	ast Expr
	// program holds the immutable compiled evaluation instructions.
	program *vmProgram
	// prefixPlan caches namespace-prefix checks for static validation.
	prefixPlan prefixValidationPlan
	version    int // 10, 20, 30 or 31 selects a profile; zero leaves internal visibility unrestricted.
}

// DeferredExpression preserves an invalid expression for XSLT 1.0 forwards
// processing, which reports a syntax error only if that expression is evaluated.
func DeferredExpression(err error, version int) *Expression {
	return &Expression{deferred: err, version: version}
}

// BindNamespaces returns a copy bound to an immutable static namespace context.
// Unbound expressions retain the evaluator-supplied namespace behavior.
func (e *Expression) BindNamespaces(ns map[string]string) *Expression {
	copyExpr := *e
	copyExpr.staticNamespaces = maps.Clone(ns)

	return &copyExpr
}

// BindNamespaceContext also captures the host language's XML default namespace,
// which can differ from XPath's default element/type namespace.
func (e *Expression) BindNamespaceContext(ns map[string]string, defaultXMLNamespace string) *Expression {
	bound := e.BindNamespaces(ns)
	bound.defaultXMLNamespace = defaultXMLNamespace

	return bound
}

// BindDefaultCollation returns a copy with the host language's immutable
// static default collation. Unbound expressions use the evaluator's setting.
func (e *Expression) BindDefaultCollation(uri string) *Expression {
	bound := *e
	bound.staticCollation = uri

	return &bound
}

// Validate runs static namespace prefix validation using the given bindings.
// This catches undeclared namespace prefixes in function calls, type names, etc.
func (e *Expression) Validate(namespaces map[string]string) error {
	return e.ValidateWithSchema(namespaces, nil)
}

// ValidateWithSchema is like Validate but also supplies the in-scope schema
// declarations. When decls is non-nil, an unprefixed atomic/schema type name is
// permitted (it resolves against the default element/type namespace or as a
// no-namespace schema type at evaluation time) instead of raising XPST0081.
func (e *Expression) ValidateWithSchema(namespaces map[string]string, decls SchemaDeclarations) error {
	if e == nil {
		return e.requireCompiledProgram()
	}

	if e.deferred != nil {
		return nil //nolint:nilerr // XSLT 1.0 forwards processing defers the error until evaluation.
	}

	if err := e.requireCompiledProgram(); err != nil {
		return err
	}

	return e.prefixPlan.Validate(namespaces, e.staticNamespaces != nil || e.version == 10, decls, e.version)
}

// String returns the original XPath expression string.
func (e *Expression) String() string {
	return e.source
}

func (e *Expression) requireCompiledProgram() error {
	if e != nil && e.deferred != nil {
		return e.deferred
	}

	if e == nil || e.program == nil {
		return fmt.Errorf("xpath: expression has no compiled program")
	}

	return nil
}

// evaluate evaluates the expression. When the expression is a node-list
// producer and the nodes need no type annotations (vmProgram.execute), it
// returns the node list and true, and the caller keeps the list in the
// Result; otherwise it returns the result sequence.
func (e *Expression) evaluate(ctx context.Context, ec *evalContext) (xdm.Sequence, []xdm.Node, bool, error) {
	if err := e.requireCompiledProgram(); err != nil {
		return nil, nil, false, err
	}

	seq, nodes, isNodes, err := e.program.execute(ctx, ec)
	if err != nil {
		return nil, nil, false, err
	}

	return seq, nodes, isNodes, nil
}

func (e *Expression) astExpr() Expr {
	if e.ast != nil {
		return e.ast
	}

	if e.source == "" {
		return nil
	}

	ast, err := Parse(e.source)
	if err != nil {
		return nil
	}

	return ast
}

// Result holds an XPath evaluation sequence. Results from EvaluateReuse can borrow
// mutable state storage and must be consumed or copied before that state is reused.
type Result struct {
	// seq is the result sequence, or a *resultNodes for a result that is a
	// list of nodes without type annotations.
	seq xdm.Sequence
}

// Copy returns a result whose sequence storage and mutable value payloads are
// independent of EvalState reuse. Node identities and function closures remain shared.
// Use Copy to retain a result beyond the next EvaluateReuse call.
func (r Result) Copy() Result {
	if rn, ok := r.seq.(*resultNodes); ok {
		if len(rn.nodes) == 0 {
			return Result{}
		}

		return Result{seq: &resultNodes{nodes: slices.Clone(rn.nodes)}}
	}

	if xdm.SequenceLen(r.seq) == 0 {
		return Result{}
	}

	return Result{seq: xdm.CloneSequence(r.seq)}
}

// Sequence returns the raw result sequence.
func (r *Result) Sequence() xdm.Sequence {
	return r.items()
}

// EBV returns the effective boolean value of the result (XPath 3.1 §2.4.3),
// the value EBV(r.Sequence()) returns: false for the empty sequence, true
// for a sequence that starts with a node, the value of a single boolean,
// string, untypedAtomic, anyURI or numeric item, and a FORG0006 error for
// anything else. A node-list result answers from its node list without
// building its sequence.
func (r *Result) EBV() (bool, error) {
	if rn, ok := r.seq.(*resultNodes); ok {
		return len(rn.nodes) > 0, nil
	}

	return EBV(r.seq)
}

// IsNodeSet returns true if the result consists entirely of nodes.
func (r *Result) IsNodeSet() bool {
	if _, ok := r.seq.(*resultNodes); ok {
		return true
	}

	for item := range xdm.SequenceItems(r.seq) {
		if ni, ok := item.(xdm.NodeItem); !ok || ni.ResultTreeFragment {
			return false
		}
	}

	return true
}

// Nodes extracts all nodes from the result.
// Returns ErrNotNodeSet if any non-node items are present.
func (r *Result) Nodes() ([]xdm.Node, error) {
	if rn, ok := r.seq.(*resultNodes); ok {
		if len(rn.nodes) == 0 {
			return nil, nil
		}

		return slices.Clone(rn.nodes), nil
	}

	if xdm.SequenceLen(r.seq) == 0 {
		return nil, nil
	}

	nodes := make([]xdm.Node, 0, r.seq.Len())
	for item := range xdm.SequenceItems(r.seq) {
		ni, ok := item.(xdm.NodeItem)
		if !ok || ni.ResultTreeFragment {
			return nil, ErrNotNodeSet
		}

		nodes = append(nodes, ni.Node)
	}

	return nodes, nil
}

// IsAtomic returns true if the result is a single atomic value.
func (r *Result) IsAtomic() bool {
	if _, ok := r.seq.(*resultNodes); ok {
		return false
	}

	if xdm.SequenceLen(r.seq) != 1 {
		return false
	}

	_, ok := r.seq.Get(0).(xdm.AtomicValue)

	return ok
}

// Atomics extracts all atomic values from the result.
func (r *Result) Atomics() ([]xdm.AtomicValue, error) {
	var result []xdm.AtomicValue

	for item := range xdm.SequenceItems(r.items()) {
		av, ok := item.(xdm.AtomicValue)
		if !ok {
			return nil, fmt.Errorf("%w: item is %T, not AtomicValue", ErrTypeMismatch, item)
		}

		result = append(result, av)
	}

	return result, nil
}

// IsBoolean returns the boolean value and true if the result is a single boolean.
func (r *Result) IsBoolean() (bool, bool) {
	if _, ok := r.seq.(*resultNodes); ok {
		return false, false
	}

	if xdm.SequenceLen(r.seq) != 1 {
		return false, false
	}

	av, ok := r.seq.Get(0).(xdm.AtomicValue)
	if !ok || av.TypeName != xdm.TypeBoolean {
		return false, false
	}

	b, ok := av.Value.(bool)

	return b, ok
}

// IsNumber returns the float64 value and true if the result is a single number.
func (r *Result) IsNumber() (float64, bool) {
	if _, ok := r.seq.(*resultNodes); ok {
		return 0, false
	}

	if xdm.SequenceLen(r.seq) != 1 {
		return 0, false
	}

	av, ok := r.seq.Get(0).(xdm.AtomicValue)
	if !ok {
		return 0, false
	}

	return av.ToFloat64(), av.TypeName == xdm.TypeDouble || xdm.IsIntegerDerived(av.TypeName) || av.TypeName == xdm.TypeDecimal || av.TypeName == xdm.TypeFloat
}

// IsString returns the string value and true if the result is a single string.
func (r *Result) IsString() (string, bool) {
	if _, ok := r.seq.(*resultNodes); ok {
		return "", false
	}

	if xdm.SequenceLen(r.seq) != 1 {
		return "", false
	}

	av, ok := r.seq.Get(0).(xdm.AtomicValue)
	if !ok || av.TypeName != xdm.TypeString {
		return "", false
	}

	s, ok := av.Value.(string)

	return s, ok
}

func (r Result) items() xdm.Sequence {
	if rn, ok := r.seq.(*resultNodes); ok {
		return rn.sequence()
	}

	return r.seq
}

// Compiler configures shared XPath compilation, including language profile, namespace
// bindings, host-function visibility and compilation context. Fluent methods return
// updated configuration copies.
type Compiler struct {
	// cfg retains compiler options copied by fluent configuration methods.
	cfg *compilerCfg
}

type compilerCfg struct {
	// context supplies the host compilation budget for numeric literals.
	context context.Context
	// version selects explicit XPath syntax and function visibility; zero skips profile
	// restrictions.
	version int
	// namespaces supplies static bindings for language-profile validation.
	namespaces map[string]string
	// hostFunction reports host-defined functions visible to static validation.
	hostFunction func(uri, name string, arity int) bool
}

// NewCompiler creates a new Compiler with default settings.
func NewCompiler() Compiler {
	return Compiler{cfg: &compilerCfg{}}
}

// Context supplies a shared compilation budget for numeric literals.
func (c Compiler) Context(ctx context.Context) Compiler {
	cfg := compilerCfg{}
	if c.cfg != nil {
		cfg = *c.cfg
	}

	cfg.context = ctx
	c.cfg = &cfg

	return c
}

// Compile parses an expression and builds a reusable evaluation program. An explicitly
// selected profile checks syntax and function availability before compilation.
func (c Compiler) Compile(expr string) (*Expression, error) {
	version := 0
	if c.cfg != nil {
		version = c.cfg.version
	}

	l, err := newVersionLexer(expr, version)
	if err != nil {
		return nil, syntaxError(err, version)
	}

	if c.cfg != nil && c.cfg.context != nil {
		for _, token := range l.tokens {
			if token.Type == TokenNumber {
				if err := preflightNumericLexical(c.cfg.context, token.Value, ""); err != nil {
					return nil, err
				}
			}
		}
	}

	if c.cfg != nil && c.cfg.version != 0 {
		if err := validateVersionTokens(l.tokens, c.cfg.version); err != nil {
			return nil, err
		}

		ast, err := parseWithLexer(l)
		if err != nil {
			return nil, syntaxError(err, version)
		}

		if err := validateVersionExpr(ast, c.cfg.version, c.cfg.namespaces, c.cfg.hostFunction); err != nil {
			return nil, err
		}

		if version == 10 {
			ast = xpath10Literals(ast)
		}

		compiled, err := c.CompileExpr(ast)
		if err == nil {
			compiled.source = expr
			compiled.version = c.cfg.version
		}

		return compiled, err
	}

	program, prefixPlan, err := compileFromLexer(l)
	if err != nil {
		return nil, syntaxError(err, version)
	}

	return &Expression{
		source:     expr,
		program:    program,
		prefixPlan: prefixPlan,
	}, nil
}

// MustCompile is like Compile but panics on error.
func (c Compiler) MustCompile(expr string) *Expression {
	e, err := c.Compile(expr)
	if err != nil {
		panic("xpath: Compile(" + expr + "): " + err.Error())
	}

	return e
}

// CompileExpr compiles a pre-parsed AST Expr into an Expression.
func (c Compiler) CompileExpr(ast Expr) (*Expression, error) {
	version := 0
	if c.cfg != nil {
		version = c.cfg.version
	}

	if version == 10 {
		if err := validateXPath10Expr(ast); err != nil {
			return nil, err
		}

		ast = xpath10Literals(ast)
	}

	program, prefixPlan, err := compileVMProgram(ast)
	if err != nil {
		return nil, err
	}

	return &Expression{
		ast:        ast,
		version:    version,
		program:    program,
		prefixPlan: prefixPlan,
	}, nil
}

// resultNodes is a result that is a list of nodes without type annotations.
// Its sequence, the NodeItem of every node, is built by the first call that
// needs it and shared by every copy of the Result value. It implements
// Sequence through that sequence, but the Result accessors read the node list
// directly and Sequence returns the built ItemSlice.
type resultNodes struct {
	nodes []xdm.Node
	once  sync.Once
	seq   xdm.ItemSlice
}

func (rn *resultNodes) Len() int { return len(rn.nodes) }

func (rn *resultNodes) Get(i int) xdm.Item { return rn.sequence()[i] }

func (rn *resultNodes) Items() iter.Seq[xdm.Item] { return rn.sequence().Items() }

func (rn *resultNodes) Materialize() []xdm.Item { return rn.sequence() }

// sequence returns the NodeItem of every node, building it on first use.
func (rn *resultNodes) sequence() xdm.ItemSlice {
	rn.once.Do(rn.build)
	return rn.seq
}

func (rn *resultNodes) build() {
	seq := make(xdm.ItemSlice, len(rn.nodes))
	for i, n := range rn.nodes {
		seq[i] = xdm.NodeItem{Node: n}
	}

	rn.seq = seq
}
