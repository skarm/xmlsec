// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

// Namespace URIs for standard XPath 3.1 function namespaces.
const (
	NSFn    = lexicon.NamespaceFn
	NSMath  = lexicon.NamespaceMath
	NSMap   = lexicon.NamespaceMap
	NSArray = lexicon.NamespaceArray
	NSErr   = lexicon.NamespaceErr
	NSXS    = lexicon.NamespaceXSD
)

// Function is the interface for XPath 3.1 functions, both built-in and user-defined.
type Function interface {
	MinArity() int
	MaxArity() int // -1 = variadic
	Call(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error)
}

// DynamicRefRestricted marks a Function that must not be used via
// named function reference (e.g. current-group#0). When the XPath
// evaluator encounters a NamedFunctionRef for such a function, it
// creates a function item that raises the specified error on call.
type DynamicRefRestricted interface {
	NoDynamicRef() bool
	DynRefErrorCode() string
}

// DynamicRefSnapshotProvider marks a Function that needs to capture
// state at reference creation time.  When the XPath evaluator creates
// a NamedFunctionRef for such a function, it calls Snapshot() to obtain
// a FunctionItem whose Invoke closure captures the current state.
type DynamicRefSnapshotProvider interface {
	DynamicRefSnapshot(ctx context.Context, arity int) (xdm.FunctionItem, bool)
}

// TypedFunction extends Function with type signature information.
// Implementations that expose parameter and return types enable
// correct instance-of checks and function coercion for user-defined functions.
type TypedFunction interface {
	Function
	FuncParamTypes() []xdm.SequenceType
	FuncReturnType() *xdm.SequenceType
}

// TypedFunctionByArity is like TypedFunction but for multi-arity functions
// that have different type signatures per arity.
type TypedFunctionByArity interface {
	Function
	FuncParamTypesForArity(arity int) []xdm.SequenceType
	FuncReturnTypeForArity(arity int) *xdm.SequenceType
}

// PredeclaredNamespace resolves a standard XPath namespace prefix.
func PredeclaredNamespace(prefix string) (string, bool) {
	switch prefix {
	case "fn":
		return NSFn, true
	case nameMath:
		return NSMath, true
	case keywordMap:
		return NSMap, true
	case keywordArray:
		return NSArray, true
	case lexicon.PrefixErr:
		return NSErr, true
	case "xs":
		return NSXS, true
	}

	return "", false
}

// PredeclaredNamespaces returns caller-owned standard namespace bindings.
func PredeclaredNamespaces() map[string]string {
	return map[string]string{"fn": NSFn, nameMath: NSMath, keywordMap: NSMap, keywordArray: NSArray, lexicon.PrefixErr: NSErr, "xs": NSXS}
}

// IsBuiltinFunction returns true if name is a registered XPath built-in function.
func IsBuiltinFunction(name string) bool {
	_, ok := lookupBuiltin(QualifiedName{URI: NSFn, Name: name})
	return ok
}

// IsBuiltinFunctionNS returns true if name in the given namespace is a registered built-in function.
func IsBuiltinFunctionNS(uri, name string) bool {
	_, ok := lookupBuiltin(QualifiedName{URI: uri, Name: name})
	return ok
}

// BuiltinFunctionAcceptsArity returns true if a built-in function accepts
// the given arity. It does NOT distinguish standard from extension functions; for a
// conformance-restricted context use StandardFunctionAcceptsArity.
func BuiltinFunctionAcceptsArity(uri, name string, arity int) bool {
	fn, ok := lookupBuiltin(QualifiedName{URI: uri, Name: name})
	if !ok {
		return false
	}

	return arity >= fn.MinArity() && (fn.MaxArity() < 0 || arity <= fn.MaxArity())
}

// StandardFunctionAcceptsArity reports whether (uri, name) is a STANDARD F&O 3.1
// function or a built-in type constructor (i.e. registered and NOT a helium
// extension) that accepts the given arity. Conformance-restricted static contexts
// such as XSD 1.1 conditional type assignment must use this, and never
// BuiltinFunctionAcceptsArity, so that forward-looking extension functions (e.g.
// fn:flatten) are not treated as available.
func StandardFunctionAcceptsArity(uri, name string, arity int) bool {
	fn, ok := lookupBuiltin(QualifiedName{URI: uri, Name: name})
	if !ok || isExtensionBuiltin(fn) {
		return false
	}

	return arity >= fn.MinArity() && (fn.MaxArity() < 0 || arity <= fn.MaxArity())
}

// isExtensionBuiltin identifies built-ins outside F&O 3.1. They remain
// static-call-only so function-lookup cannot bypass a restricted static context.
func isExtensionBuiltin(fn Function) bool {
	bf, ok := fn.(*builtinFunc)
	return ok && bf.extension
}

func namespacePrefixFor(uri string) string {
	switch uri {
	case NSFn:
		return "fn"
	case NSMath:
		return nameMath
	case NSMap:
		return keywordMap
	case NSArray:
		return keywordArray
	case NSErr:
		return lexicon.PrefixErr
	case NSXS:
		return "xs"
	}

	return ""
}

// resolvedFunction carries a resolved function together with the identity used
// to find it. Signature enforcement keys off the resolved URI/local name (not the
// raw call syntax) and only consults the built-in signature registry when the
// resolved function actually is the registered built-in.
type resolvedFunction struct {
	fn        Function
	uri       string // resolved namespace URI
	name      string // resolved local name (Q{uri}local stripped)
	isBuiltin bool   // true only when fn came from the built-in registry
}

// resolveFunctionInfo finds a function by prefix, local name, and arity,
// reporting the resolved identity (URI + local name) and whether the result is
// the built-in function.
// Resolution order:
//  1. User-registered functions by local name (ec.functions)
//  2. User-registered functions by QualifiedName (ec.fnsNS)
//  3. Built-in functions by QualifiedName (builtinFunctions3)
//  4. Default fn: namespace (no prefix = fn:)
func resolveFunctionInfo(ctx context.Context, ec *evalContext, prefix, name string, arity int) (resolvedFunction, error) {
	if prefix == "" && strings.HasPrefix(name, "Q{") {
		if idx := strings.Index(name, "}"); idx >= 0 {
			uri := name[2:idx]
			local := name[idx+1:]

			return resolveFunctionByURIInfo(ctx, ec, uri, local, arity)
		}
	}

	if prefix == "" && ec.functions != nil {
		if fn, ok := ec.functions[name]; ok {
			if err := checkArity(fn, name, arity); err != nil {
				return resolvedFunction{}, err
			}

			return resolvedFunction{fn: fn, uri: NSFn, name: name}, nil
		}
	}

	// Resolve prefix to namespace URI
	uri, err := resolvePrefix(ec, prefix)
	if err != nil {
		return resolvedFunction{}, err
	}

	return resolveFunctionByURIInfo(ctx, ec, uri, name, arity)
}

func resolveFunctionByURIInfo(ctx context.Context, ec *evalContext, uri, name string, arity int) (resolvedFunction, error) {
	// User functions by qualified name
	if ec.fnsNS != nil {
		qn := QualifiedName{URI: uri, Name: name}
		if fn, ok := ec.fnsNS[qn]; ok {
			if err := checkArity(fn, name, arity); err != nil {
				return resolvedFunction{}, err
			}

			return resolvedFunction{fn: fn, uri: uri, name: name}, nil
		}
	}

	// Built-in functions
	qn := QualifiedName{URI: uri, Name: name}
	if fn, ok := lookupBuiltin(qn); ok && functionVisible(ec.version, uri, name, arity) {
		if err := checkArity(fn, name, arity); err != nil {
			return resolvedFunction{}, err
		}

		return resolvedFunction{fn: fn, uri: uri, name: name, isBuiltin: true}, nil
	}

	// Check function resolver (not visible to function-lookup)
	if ec.functionResolver != nil {
		fn, ok, err := ec.functionResolver.ResolveFunction(ctx, uri, name, arity)
		if err != nil {
			return resolvedFunction{}, err
		}

		if ok {
			return resolvedFunction{fn: fn, uri: uri, name: name}, nil
		}
	}

	return resolvedFunction{}, fmt.Errorf("%w: %s#%d", ErrUnknownFunction, name, arity)
}

func resolvePrefix(ec *evalContext, prefix string) (string, error) {
	if prefix == "" {
		return NSFn, nil
	}

	if ec.namespaces != nil {
		if uri, ok := ec.namespaces[prefix]; ok {
			return uri, nil
		}
	}

	if uri, ok := PredeclaredNamespace(prefix); ok {
		return uri, nil
	}

	return "", &xdm.Error{Code: errCodeFONS0004, Message: "undeclared namespace prefix: " + prefix}
}

func checkArity(fn Function, name string, arity int) error {
	minArity := fn.MinArity()
	maxArity := fn.MaxArity()

	if arity < minArity {
		return fmt.Errorf("%w: %s requires at least %d arguments, got %d", ErrArityMismatch, name, minArity, arity)
	}

	if maxArity >= 0 && arity > maxArity {
		return fmt.Errorf("%w: %s accepts at most %d arguments, got %d", ErrArityMismatch, name, maxArity, arity)
	}

	return nil
}

// builtinFunc is a simple implementation of Function for built-in functions.
type builtinFunc struct {
	name string
	min  int
	max  int // -1 = variadic
	fn   func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error)
	// extension is true for functions helium provides BEYOND the F&O 3.1 standard
	// function library (forward-looking XPath/XQuery 4.0 functions). They are available
	// for evaluation, but are NOT part of a conformance-restricted static context such
	// as XSD 1.1 conditional type assignment (§F.2 admits only the standard library and
	// the built-in type constructors).
	extension bool
}

func (f *builtinFunc) MinArity() int { return f.min }

func (f *builtinFunc) MaxArity() int { return f.max }

func (f *builtinFunc) Call(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return f.fn(ctx, args)
}

// seqToStringErr atomizes the argument to a string, propagating errors.
// For list-typed nodes, atomization may produce multiple items → XPTY0004.
// Atomization is content-kind-aware in a schema-aware run (atomizeTypedValue):
// atomizing an element-only-typed node raises err:FOTY0012 (it has no typed
// value); a nilled/empty-content element contributes no atoms.
func seqToStringErr(ctx context.Context, seq xdm.Sequence) (string, error) {
	if xdm.SequenceLen(seq) == 0 {
		return "", nil
	}

	atoms, err := atomizeTypedValue(ctx, seq)
	if err != nil {
		return "", err
	}

	if len(atoms) == 0 {
		return "", nil
	}

	if len(atoms) > 1 {
		return "", &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("expected single string, got sequence of length %d", len(atoms))}
	}

	return atomicToString(atoms[0])
}

// isNoTypedValueError reports whether err is an atomization error for a value
// that has no atomizable typed value: err:FOTY0012 (an element-only-typed node)
// or err:FOTY0013 (a function or map item). Option extractors that otherwise map
// a conversion failure to their own bad-value error code (XPTY0004 / FOJS0005)
// must let these dynamic errors surface unchanged, masking none of them, so
// that atomizing such a value as an option value reports FOTY0012/FOTY0013
// consistently with fn:data and the xs:string? coercion.
func isNoTypedValueError(err error) bool {
	var xerr *xdm.Error
	if !errors.As(err, &xerr) {
		return false
	}

	return xerr.Code == errCodeFOTY0012 || xerr.Code == errCodeFOTY0013
}

// coerceArgToStringRequired applies XPath 3.1 function coercion rules for xs:string params.
// Like coerceArgToString but rejects an empty *atomized* sequence (for non-optional
// string parameters). Cardinality is checked after atomization, so a value such as
// an empty array — which atomizes to the empty sequence — is rejected, while
// ([], "x") (which atomizes to the single string "x") is accepted.
func coerceArgToStringRequired(ctx context.Context, seq xdm.Sequence) (string, error) {
	s, empty, err := coerceAtomizedString(ctx, seq)
	if err != nil {
		return "", err
	}

	if empty {
		return "", &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected xs:string, got empty sequence"}
	}

	return s, nil
}

// coerceArgToString applies XPath 3.1 function coercion rules for xs:string? params.
// Accepts: empty sequence → "", xs:string/xs:anyURI → as-is, xs:untypedAtomic → cast.
// Rejects all other types with XPTY0004.
func coerceArgToString(ctx context.Context, seq xdm.Sequence) (string, error) {
	s, _, err := coerceAtomizedString(ctx, seq)
	return s, err
}

// coerceAtomizedString performs XPath function conversion to xs:string?: it
// atomizes the argument FIRST (arrays flatten to their members, list-typed nodes
// expand to their tokens), THEN checks cardinality. Atomization is streamed and
// stops as soon as a second item appears, so a too-long sequence is rejected
// without materializing it. Returns empty=true when the atomized sequence is
// empty (the caller decides whether that is "" or an error).
//
// Atomization is content-kind-aware in a schema-aware run: it routes through
// atomizeStreamCont with the typed-value pre-check (typedValueItemCheck), so
// atomizing an element-only-typed node raises err:FOTY0012 (it has no typed
// value) and a nilled/empty-content element contributes no atoms — cardinality
// is still applied AFTER atomization, so an empty-array member flattens away
// and ([], "x") stays a single "x". Without a schema-aware provider the check
// is nil and this is byte-identical to plain atomizeStream.
func coerceAtomizedString(ctx context.Context, seq xdm.Sequence) (value string, empty bool, err error) {
	var (
		first xdm.AtomicValue
		count int
	)

	if _, serr := atomizeStreamCont(seq, typedValueItemCheck(ctx), func(av xdm.AtomicValue) (bool, error) {
		count++
		if count == 1 {
			first = av
			return true, nil
		}
		// A second atomized item: too many for xs:string?. Stop here rather
		// than atomizing the rest of a potentially huge sequence.
		return false, nil
	}); serr != nil {
		return "", false, serr
	}

	if count == 0 {
		return "", true, nil
	}

	if count > 1 {
		return "", false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected xs:string?, got sequence of length > 1"}
	}

	switch first.TypeName {
	case xdm.TypeString, xdm.TypeAnyURI, xdm.TypeUntypedAtomic,
		xdm.TypeNormalizedString, xdm.TypeToken, xdm.TypeLanguage, xdm.TypeName, xdm.TypeNCName,
		xdm.TypeNMTOKEN, xdm.TypeNMTOKENS, xdm.TypeENTITY, xdm.TypeID, xdm.TypeIDREF, xdm.TypeIDREFS:
		s, ok := first.Value.(string)
		if !ok {
			return "", false, fmt.Errorf("xpath: internal error: expected string for %s", first.TypeName)
		}

		return s, false, nil
	default:
		// User-defined types: check if the underlying value is a string.
		if s, ok := first.Value.(string); ok {
			return s, false, nil
		}

		return "", false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("expected xs:string?, got %s", first.TypeName)}
	}
}

// coerceArgToInteger applies XPath 3.1 function coercion rules for xs:integer params.
// Accepts: xs:integer (and subtypes), xs:untypedAtomic (cast to integer).
// Rejects all other types with XPTY0004.
func coerceArgToInteger(seq xdm.Sequence) (int64, error) {
	switch xdm.SequenceLen(seq) {
	case 0:
		return 0, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected xs:integer, got empty sequence"}
	case 1:
	default:
		return 0, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected xs:integer, got sequence of length > 1"}
	}

	a, err := AtomizeItem(seq.Get(0))
	if err != nil {
		return 0, err
	}

	if a.TypeName == xdm.TypeUntypedAtomic {
		casted, cerr := castToInteger(a)
		if cerr != nil {
			return 0, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("cannot cast %s to xs:integer", a.TypeName)}
		}

		a = casted
	}

	if !xdm.IsSubtypeOf(a.TypeName, xdm.TypeInteger) {
		return 0, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("expected xs:integer, got %s", a.TypeName)}
	}

	switch v := a.Value.(type) {
	case int64:
		return v, nil
	case *big.Int:
		// Int64() silently wraps a value outside int64 range. Clamp to the
		// signed-64 extremes so callers treat it as out of range, and never as a
		// wrapped (valid-looking) position.
		if v.IsInt64() {
			return v.Int64(), nil
		}

		if v.Sign() < 0 {
			return math.MinInt64, nil
		}

		return math.MaxInt64, nil
	default:
		return 0, fmt.Errorf("xpath: internal error: expected integer value for %s, got %T", a.TypeName, a.Value)
	}
}

// coerceArgToDoubleRequired applies XPath 3.1 function coercion rules for xs:double params.
// Accepts any numeric type and xs:untypedAtomic after casting. Rejects empty and multi-item sequences.
func coerceArgToDoubleRequired(seq xdm.Sequence) (float64, error) {
	a, err := extractSingleAtomicArg(seq, "xs:double")
	if err != nil {
		if xpErr, ok := errors.AsType[*xdm.Error](err); ok {
			switch {
			case strings.Contains(xpErr.Message, "empty sequence"):
				return 0, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected xs:double, got empty sequence"}
			case strings.Contains(xpErr.Message, "length > 1"):
				return 0, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected xs:double, got sequence of length > 1"}
			}
		}

		return 0, err
	}

	if a.TypeName == xdm.TypeUntypedAtomic {
		casted, cerr := CastAtomic(a, xdm.TypeDouble)
		if cerr != nil {
			return 0, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("cannot cast %s to xs:double", a.TypeName)}
		}

		a = casted
	}

	if !a.IsNumeric() {
		return 0, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("expected xs:double, got %s", a.TypeName)}
	}

	a = xdm.PromoteSchemaType(a)

	return a.ToFloat64(), nil
}

// extractSingleAtomicArg enforces that seq contains exactly one item and atomizes it.
// Used for function parameters typed as xs:anyAtomicType (not optional).
func extractSingleAtomicArg(seq xdm.Sequence, fnName string) (xdm.AtomicValue, error) {
	switch xdm.SequenceLen(seq) {
	case 0:
		return xdm.AtomicValue{}, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fnName + ": expected single atomic value, got empty sequence"}
	case 1:
		return AtomizeItem(seq.Get(0))
	default:
		return xdm.AtomicValue{}, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fnName + ": expected single atomic value, got sequence of length > 1"}
	}
}

// coerceToInteger applies function coercion rules for xs:integer to a single AtomicValue.
// Accepts: xs:integer (and subtypes), xs:untypedAtomic (cast to integer).
// Rejects double, float, decimal, and all other types with XPTY0004.
func coerceToInteger(a xdm.AtomicValue) (xdm.AtomicValue, error) {
	if a.TypeName == xdm.TypeUntypedAtomic {
		casted, cerr := castToInteger(a)
		if cerr != nil {
			return xdm.AtomicValue{}, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("cannot cast %s to xs:integer", a.TypeName)}
		}

		return casted, nil
	}

	if !xdm.IsSubtypeOf(a.TypeName, xdm.TypeInteger) {
		return xdm.AtomicValue{}, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("expected xs:integer, got %s", a.TypeName)}
	}

	return a, nil
}

func lookupFunctions(name string) (*builtinFunc, bool) {
	switch name {
	case fnNameBoolean:
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnBoolean}, true
	case fnNameNot:
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnNot}, true
	case nameTrue:
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnTrue}, true
	case nameFalse:
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnFalse}, true
	}

	return nil, false
}

func fnBoolean(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	b, err := EBV(args[0])
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(b), nil
}

func fnNot(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	b, err := EBV(args[0])
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(!b), nil
}

func fnTrue(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	return xdm.SingleBoolean(true), nil
}

func fnFalse(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	return xdm.SingleBoolean(false), nil
}

func lookupFunctions2(name string) (*builtinFunc, bool) {
	switch name {
	case nameError:
		return &builtinFunc{name: name, min: 0, max: 3, fn: fnError}, true
	case "trace":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnTrace}, true
	}

	return nil, false
}

func fnError(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	code := xdm.QNameValue{Prefix: lexicon.PrefixErr, URI: NSErr, Local: errCodeFOER0000}
	msg := "error() called"

	if len(args) > 0 {
		qv, hasCode, err := coerceErrorCode(args[0])
		if err != nil {
			return nil, err
		}

		if hasCode {
			code = qv
		}
	}

	if len(args) > 1 {
		var err error

		msg, err = coerceArgToStringRequired(ctx, args[1])
		if err != nil {
			return nil, err
		}
	}

	return nil, &xdm.Error{Code: code.Local, Message: msg, QualifiedCode: code}
}

func coerceErrorCode(seq xdm.Sequence) (xdm.QNameValue, bool, error) {
	switch xdm.SequenceLen(seq) {
	case 0:
		return xdm.QNameValue{}, false, nil
	case 1:
	default:
		return xdm.QNameValue{}, false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:error code argument must be xs:QName?"}
	}

	a, err := AtomizeItem(seq.Get(0))
	if err != nil {
		return xdm.QNameValue{}, false, err
	}

	if a.TypeName != xdm.TypeQName {
		return xdm.QNameValue{}, false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:error code argument must be xs:QName?"}
	}

	return a.QNameVal(), true, nil
}

func fnTrace(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	writer := io.Discard
	if ec := getFnContext(ctx); ec != nil && ec.traceWriter != nil {
		writer = ec.traceWriter
	}

	write := func(value string) error {
		n, err := io.WriteString(writer, value)
		if err == nil && n != len(value) {
			return io.ErrShortWrite
		}

		return err
	}
	label := ""

	if len(args) > 1 {
		var err error

		label, err = coerceArgToStringRequired(ctx, args[1])
		if err != nil {
			return nil, err
		}
	}

	prefix := "[trace] "
	if label != "" {
		prefix += label + ": "
	}

	if err := write(prefix); err != nil {
		return nil, err
	}

	for i := range xdm.SequenceLen(args[0]) {
		if err := Charge(ctx, 1); err != nil {
			return nil, err
		}

		if i > 0 {
			if err := write(", "); err != nil {
				return nil, err
			}
		}

		item := args[0].Get(i)

		value := fmt.Sprintf("<%T>", item)
		if atomic, err := AtomizeItem(item); err == nil {
			value, err = atomicToString(atomic)
			if err != nil {
				return nil, err
			}
		}

		if err := write(value); err != nil {
			return nil, err
		}
	}

	if err := write("\n"); err != nil {
		return nil, err
	}

	return args[0], nil
}
