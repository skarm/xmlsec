// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	unparsedtext "github.com/skarm/xmlsec/transform/internal/xpath/text"
)

const maxNodeSetLength = xdm.DefaultMaxNodeSetLength

// DefaultMaxRecursionDepth bounds nested expressions in each evaluation.
const DefaultMaxRecursionDepth = xdm.DefaultMaxRecursionDepth

type evalContextFrame struct {
	node        xdm.Node
	contextItem xdm.Item
	position    int
	size        int
}

type evalContext struct {
	node                 xdm.Node
	contextItem          xdm.Item    // non-nil when context item is not a node (simple map over atomics)
	uriResolver          URIResolver // custom URI resolver for fn:unparsed-text, fn:doc, etc.
	resourceReads        xdm.ResourceReadPolicy
	collectionResolver   CollectionResolver
	variableResolver     VariableResolver   // lazy resolver for variables not in static scope
	functionResolver     FunctionResolver   // lazy resolver for functions (not visible to function-lookup)
	schemaDeclarations   SchemaDeclarations // schema element/attribute declarations for schema-element()/schema-attribute() tests
	traceWriter          io.Writer          // destination for fn:trace output (nil = os.Stderr)
	runtime              *evaluationRuntime
	invocation           *invocationState
	vars                 *variableScope
	namespaces           map[string]string
	defaultXMLNamespace  string
	functions            map[string]Function
	fnsNS                map[QualifiedName]Function
	opCount              *int // shared via pointer across copies; safe because eval is single-goroutine
	docOrder             *xdm.DocOrderCache
	currentTime          *time.Time     // set once at construction for stable fn:current-*
	implicitTimezone     *time.Location // for fn:adjust-*-to-timezone (1-arg form)
	defaultDecimalFormat *DecimalFormat
	decimalFormats       map[QualifiedName]DecimalFormat
	docCache             map[string]xdm.Node
	// httpClient is intentionally stored here (not only in Context) so that
	// built-in functions can access it through getFnContext without an extra
	// indirection. It is pointer-sized and nil when unused, so copies via
	// withNode/withContextItem are negligible. The net/http dependency is
	// already transitively required by golang.org/x/text.
	httpClient             *http.Client
	typeAnnotations        map[xdm.Node]string   // node → xs:... type (from xslt schema awareness)
	nilledElements         map[xdm.Node]struct{} // elements confirmed nilled (xsi:nil="true") by XSD validation
	preservedIDAnnotations map[xdm.Node]string   // ID/IDREF annotations preserved after input-type-annotations="strip"
	idNodes                map[xdm.Node]struct{} // PSVI is-id nodes (from xsd validation); supplements the type-annotation is-id check for list/union types
	parseOptions           *xdm.ParseOptions     // injected parseOptions for fn:parse-xml, fn:parse-xml-fragment, fn:doc (nil = default XML limits)
	defaultLanguage        string                // for fn:default-language and formatting fallbacks
	defaultCollation       string                // for string functions without explicit collation
	baseURI                string                // static base URI for resolving relative URIs
	version                int                   // xmlsec language profile, selected by the compiled expression.
	xmlSchemaVersion       int
	position               int
	size                   int
	depth                  int
	maxRecursionDepth      int // snapshot of DefaultMaxRecursionDepth at newEvalCtx
	opLimit                int
	maxNodes               int
	maxResourceBytes       int64 // per-resource read cap for fn:unparsed-text / fn:doc / fn:json-doc (0 = unparsedtext default)
	strictPrefixes         bool  // skip defaultPrefixNS fallback in prefix validation
	qnameValueNoDefaultNS  bool  // XSD: an unprefixed QName/NOTATION VALUE atomizes to no namespace
	allowXML11Chars        bool  // when true, codepoints-to-string allows XML 1.1 restricted characters (0x01-0x1F)
	xpath10Compat          bool  // XPath 1.0 compatibility mode (XSLT backwards-compatible processing)
}

func (ec *evalContext) xmlParseOptions() xdm.ParseOptions {
	p := xdm.ParseOptions{}
	if ec != nil && ec.parseOptions != nil {
		p = *ec.parseOptions
	}

	if p.AllowDTD {
		p.DTDOpen = func(ctx context.Context, uri string) (io.ReadCloser, error) {
			return unparsedtext.OpenURI(ctx, unparsedTextConfig(ctx), uri)
		}
	}

	return p
}

func (ec *evalContext) pushNodeContext(n xdm.Node, pos, size int) evalContextFrame {
	frame := evalContextFrame{
		node:        ec.node,
		contextItem: ec.contextItem,
		position:    ec.position,
		size:        ec.size,
	}
	ec.node = n
	ec.contextItem = nil
	ec.position = pos
	ec.size = size

	return frame
}

func (ec *evalContext) pushContextItem(item xdm.Item, pos, size int) evalContextFrame {
	frame := evalContextFrame{
		node:        ec.node,
		contextItem: ec.contextItem,
		position:    ec.position,
		size:        ec.size,
	}
	ec.contextItem = item
	ec.node = nil
	ec.position = pos
	ec.size = size

	return frame
}

func (ec *evalContext) restoreContext(frame evalContextFrame) {
	ec.node = frame.node
	ec.contextItem = frame.contextItem
	ec.position = frame.position
	ec.size = frame.size
}

// contextStringValue returns the string value of the current context item.
// For node context items, it returns the XPath string value of the node.
// For atomic context items, it returns the string representation.
// Returns ("", false) if no context item is set.
func (ec *evalContext) contextStringValue() (string, bool) {
	if ec.contextItem != nil {
		if av, ok := ec.contextItem.(xdm.AtomicValue); ok {
			s, _ := atomicToString(av)
			return s, true
		}

		if ni, ok := ec.contextItem.(xdm.NodeItem); ok {
			return ec.nodeStringValue(ni.Node), true
		}

		return "", false
	}

	if ec.node != nil {
		return ec.nodeStringValue(ec.node), true
	}

	return "", false
}

// getCurrentTime returns the cached current time for this evaluation.
func (ec *evalContext) getCurrentTime() time.Time {
	return *ec.currentTime
}

// getImplicitTimezone returns the implicit timezone for the dynamic context.
// If not explicitly set, it falls back to the system local timezone.
func (ec *evalContext) getImplicitTimezone() *time.Location {
	if ec.implicitTimezone != nil {
		return ec.implicitTimezone
	}

	return time.Local
}

// resolveDefaultCollation returns the collation implementation for the
// dynamic context's default collation URI.  Returns nil when the default
// is the codepoint collation (the XPath default), so callers can fast-path.
func (ec *evalContext) resolveDefaultCollation() *collationImpl {
	if ec.defaultCollation == "" || ec.defaultCollation == lexicon.CollationCodepoint {
		return nil
	}

	coll, err := ec.runtime.resolveCollation(ec.defaultCollation, "")
	if err != nil {
		return nil
	}

	return coll
}

func (ec *evalContext) getDefaultLanguage() string {
	if ec.defaultLanguage != "" {
		return ec.defaultLanguage
	}

	return "en"
}

func (ec *evalContext) withVar(name string, val xdm.Sequence) *evalContext {
	cp := *ec
	cp.vars = scopeWithBinding(ec.vars, VariableKey(name, ec.namespaces), val)

	return &cp
}

// fnContext returns a context.Context carrying this evalContext for built-in
// function calls.
func (ec *evalContext) fnContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, fnContextKey{}, ec)
}

// pushScope sets ec.vars to scope in place and returns the previous scope.
// The caller must call restoreScope when done to avoid corrupting state.
func (ec *evalContext) pushScope(scope *variableScope) *variableScope {
	old := ec.vars
	ec.vars = scope

	return old
}

func (ec *evalContext) restoreScope(old *variableScope) {
	ec.vars = old
}

func (ec *evalContext) countOps(ctx context.Context, n int) error {
	// Charge checks cancellation before charging the shared invocation budget.
	if err := Charge(ctx, n); err != nil {
		return err
	}

	if ec.opLimit <= 0 {
		return nil
	}
	// Saturate instead of wrapping: where int is 32 bits a long evaluation
	// can count past 2^31-1, and a wrapped (negative) count would never
	// reach the limit again. A total past math.MaxInt exceeds every limit.
	if n > math.MaxInt-*ec.opCount {
		*ec.opCount = math.MaxInt
		return ErrOpLimit
	}

	*ec.opCount += n
	if *ec.opCount > ec.opLimit {
		return ErrOpLimit
	}

	return nil
}

type variableScope struct {
	parent      *variableScope
	name        string
	value       xdm.Sequence
	singleValue bool
	values      map[string]xdm.Sequence
}

func newVariableScope(vars map[string]xdm.Sequence) *variableScope {
	return scopeWithBindings(nil, vars)
}

func scopeWithBindings(parent *variableScope, bindings map[string]xdm.Sequence) *variableScope {
	if len(bindings) == 0 {
		return parent
	}

	if len(bindings) == 1 {
		for name, value := range bindings {
			return scopeWithBinding(parent, name, value)
		}
	}

	values := make(map[string]xdm.Sequence, len(bindings))
	maps.Copy(values, bindings)

	return &variableScope{parent: parent, values: values}
}

func (s *variableScope) Lookup(name string) (xdm.Sequence, bool) {
	for scope := s; scope != nil; scope = scope.parent {
		if scope.singleValue {
			if scope.name == name {
				return scope.value, true
			}

			continue
		}

		if seq, ok := scope.values[name]; ok {
			return seq, true
		}
	}

	return nil, false
}

func scopeWithBinding(parent *variableScope, name string, value xdm.Sequence) *variableScope {
	return &variableScope{
		parent:      parent,
		name:        name,
		value:       value,
		singleValue: true,
	}
}

type exprEvaluator func(context.Context, *evalContext, Expr) (xdm.Sequence, error)

func evalWith(evalFn exprEvaluator, ctx context.Context, ec *evalContext, expr Expr) (xdm.Sequence, error) {
	ec.depth++
	if ec.maxRecursionDepth > 0 && ec.depth > ec.maxRecursionDepth {
		return nil, ErrRecursionLimit
	}
	defer func() { ec.depth-- }()

	result, err := evalFn(ctx, ec, expr)
	if err == nil && xdm.SequenceLen(result) == 1 {
		if value, ok := result.Get(0).(xdm.AtomicValue); ok {
			err = ChargeNumber(ctx, value)
		}
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

func evalContextItemExpr(ctx context.Context, ec *evalContext) (xdm.Sequence, error) {
	if ec.contextItem != nil {
		return xdm.ItemSlice{ec.contextItem}, nil
	}

	if xdm.IsNilNode(ec.node) {
		return nil, &xdm.Error{Code: errCodeXPDY0002, Message: errMsgContextItemAbsent}
	}

	return xdm.ItemSlice{nodeItemFor(ctx, ec, ec.node)}, nil
}

func evalRootExpr(ctx context.Context, ec *evalContext) (xdm.Sequence, error) {
	if xdm.IsNilNode(ec.node) {
		if ec.contextItem != nil {
			return nil, &xdm.Error{Code: errCodeXPTY0020, Message: "a path requires a node context item"}
		}

		return nil, &xdm.Error{Code: errCodeXPDY0002, Message: errMsgContextItemAbsent}
	}

	root := xdm.DocumentRoot(ec.node)
	// XPDY0050: the root of the context node's tree must be a document node.
	if root.Type() != xdm.DocumentNode {
		return nil, &xdm.Error{Code: errCodeXPDY0050, Message: textRootOfTheTreeContainingTheContextNode}
	}

	return xdm.ItemSlice{nodeItemFor(ctx, ec, root)}, nil
}

func dispatchExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, expr Expr) (xdm.Sequence, error) {
	switch e := expr.(type) {
	case compiledExprRef:
		return nil, fmt.Errorf("%w: compiled expression reference outside VM", ErrUnsupportedExpr)
	case LiteralExpr:
		return evalLiteral(e)
	case VariableExpr:
		return evalVariable(ctx, ec, e)
	case ContextItemExpr:
		return evalContextItemExpr(ctx, ec)
	case RootExpr:
		return evalRootExpr(ctx, ec)
	case *LocationPath:
		return evalLocationPath(evalFn, ctx, ec, e)
	case FilterExpr:
		return evalFilterExpr(evalFn, ctx, ec, e)
	case PathExpr:
		return evalPathExpr(evalFn, ctx, ec, e)
	case PathStepExpr:
		return evalPathStepExpr(evalFn, ctx, ec, e)
	case LookupExpr:
		return evalLookupExpr(evalFn, ctx, ec, e)
	case UnaryLookupExpr:
		return evalUnaryLookupExpr(evalFn, ctx, ec, e)
	case FLWORExpr:
		return evalFLWOR(evalFn, ctx, ec, e)
	case QuantifiedExpr:
		return evalQuantifiedExpr(evalFn, ctx, ec, e)
	case IfExpr:
		return evalIfExpr(evalFn, ctx, ec, e)
	case TryCatchExpr:
		return evalTryCatchExpr(evalFn, ctx, ec, e)
	case InstanceOfExpr:
		return evalInstanceOfExpr(evalFn, ctx, ec, e)
	case CastExpr:
		return evalCastExpr(evalFn, ctx, ec, e)
	case CastableExpr:
		return evalCastableExpr(evalFn, ctx, ec, e)
	case TreatAsExpr:
		return evalTreatAsExpr(evalFn, ctx, ec, e)
	case SequenceExpr, FunctionCall, DynamicFunctionCall, NamedFunctionRef, InlineFunctionExpr, MapConstructorExpr, ArrayConstructorExpr:
		return dispatchFunctionExpr(evalFn, ctx, ec, expr)
	case BinaryExpr, UnaryExpr, ConcatExpr, SimpleMapExpr, RangeExpr, UnionExpr, IntersectExceptExpr:
		return dispatchOperatorExpr(evalFn, ctx, ec, expr)
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedExpr, expr)
	}
}

func dispatchFunctionExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, expr Expr) (xdm.Sequence, error) {
	switch e := expr.(type) {
	case SequenceExpr:
		return evalSequenceExpr(evalFn, ctx, ec, e)
	case FunctionCall:
		return evalFunctionCall(evalFn, ctx, ec, e)
	case DynamicFunctionCall:
		return evalDynamicFunctionCall(evalFn, ctx, ec, e)
	case NamedFunctionRef:
		return evalNamedFunctionRef(ctx, ec, e)
	case InlineFunctionExpr:
		return evalInlineFunctionExpr(evalFn, ctx, ec, e)
	case MapConstructorExpr:
		return evalMapConstructorExpr(evalFn, ctx, ec, e)
	case ArrayConstructorExpr:
		return evalArrayConstructorExpr(evalFn, ctx, ec, e)
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedExpr, expr)
	}
}

func dispatchOperatorExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, expr Expr) (xdm.Sequence, error) {
	switch e := expr.(type) {
	case BinaryExpr:
		return evalBinaryExpr(evalFn, ctx, ec, e)
	case UnaryExpr:
		return evalUnaryExpr(evalFn, ctx, ec, e)
	case ConcatExpr:
		return evalConcatExpr(evalFn, ctx, ec, e)
	case SimpleMapExpr:
		return evalSimpleMapExpr(evalFn, ctx, ec, e)
	case RangeExpr:
		return evalRangeExpr(evalFn, ctx, ec, e)
	case UnionExpr:
		return evalUnionExpr(evalFn, ctx, ec, e)
	case IntersectExceptExpr:
		return evalIntersectExceptExpr(evalFn, ctx, ec, e)
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedExpr, expr)
	}
}
