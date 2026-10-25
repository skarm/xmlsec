// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"path"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

const maxTransformDepth = 10

type transformProgramLimitKey struct{}

// WithTransformProgramLimit bounds dynamically supplied XPath and stylesheet programs.
// Nested fn:transform calls inherit the same limit and invocation budgets.
func WithTransformProgramLimit(ctx context.Context, maxBytes int) context.Context {
	if previous, ok := ctx.Value(transformProgramLimitKey{}).(int); ok && previous > 0 && (maxBytes <= 0 || previous < maxBytes) {
		maxBytes = previous
	}

	return context.WithValue(ctx, transformProgramLimitKey{}, maxBytes)
}

// TransformOption configures the fn:transform implementation returned by
// [TransformFunction].
type TransformOption interface {
	applyTransform(*transformFnConfig)
}

// WithTransformURIResolver sets the resolver used to read a stylesheet-location
// and to resolve resources (fn:doc/document()/fn:unparsed-text and external
// entities) referenced while compiling and running the transformed stylesheet.
// Resource access is opt-in: without a resolver, stylesheet-location and fn:doc
// fail (FOXT0003 / FODC0002).
func WithTransformURIResolver(r xpath.URIResolver) TransformOption {
	return transformOptionFunc(func(c *transformFnConfig) { c.innerURIResolver = r })
}

// WithTransformCollectionResolver supplies the explicit collection policy used
// by nested stylesheets, independently of their invocation-local caches.
func WithTransformCollectionResolver(r xpath.CollectionResolver) TransformOption {
	return transformOptionFunc(func(c *transformFnConfig) { c.collectionResolver = r })
}

// WithTransformPackageResolver sets the resolver used for the package-name /
// package-version options.
func WithTransformPackageResolver(r PackageResolver) TransformOption {
	return transformOptionFunc(func(c *transformFnConfig) { c.packageResolver = r })
}

// WithTransformHTTPClient sets an opt-in HTTP client for retrieving http(s)
// resources inside the transformed stylesheet.
func WithTransformHTTPClient(client *http.Client) TransformOption {
	return transformOptionFunc(func(c *transformFnConfig) { c.httpClient = client })
}

// WithTransformBaseURI sets the base URI against which a relative
// stylesheet-location (and stylesheet-text base) is resolved.
func WithTransformBaseURI(uri string) TransformOption {
	return transformOptionFunc(func(c *transformFnConfig) { c.baseURI = uri })
}

// WithTransformMaxResourceBytes sets the per-resource read cap (0 = default,
// negative = unbounded).
func WithTransformMaxResourceBytes(n int64) TransformOption {
	return transformOptionFunc(func(c *transformFnConfig) { c.maxResourceBytes = n })
}

// WithTransformParseOptions sets the base parseOptions governing parse policy for the
// dynamically-loaded stylesheet and runtime source parses.
func WithTransformParseOptions(p xdm.ParseOptions) TransformOption {
	return transformOptionFunc(func(c *transformFnConfig) {
		pp := p
		c.parseOptions = &pp
	})
}

// TransformFunction returns an [xpath.Function] implementing fn:transform()
// that can be registered on a standalone xpath.Evaluator via
// Evaluator.Functions (in the fn: namespace, name "transform"), so callers that
// drive xpath directly — with no outer running stylesheet — can invoke
// fn:transform. It shares its implementation with the in-stylesheet fn:transform
// (ec.fnTransform); the deps the in-stylesheet path inherits from its execution
// context are supplied here explicitly through TransformOption values.
func TransformFunction(options ...TransformOption) xpath.TypedFunctionByArity {
	cfg := &transformFnConfig{}
	for _, o := range options {
		o.applyTransform(cfg)
	}
	// Adapt the xpath resolver to a compile-time module resolver for the
	// nested compile and stylesheet-location reads.
	if cfg.innerURIResolver != nil && cfg.stylesheetResolver == nil {
		cfg.stylesheetResolver = cfg.innerURIResolver
	}

	if cfg.parseOptions != nil && cfg.parseOptions.AllowDTD {
		opts := *cfg.parseOptions
		opts.DTDOpen = func(ctx context.Context, uri string) (io.ReadCloser, error) {
			return openDocumentVia(ctx, uri, cfg.stylesheetResolver, cfg.httpClient)
		}
		cfg.parseOptions = &opts
	}

	c := NewCompiler()
	if cfg.stylesheetResolver != nil {
		c = c.URIResolver(cfg.stylesheetResolver)
	}

	if cfg.packageResolver != nil {
		c = c.PackageResolver(cfg.packageResolver)
	}

	c = c.MaxResourceBytes(cfg.maxResourceBytes)
	if cfg.parseOptions != nil {
		c = c.ParseOptions(*cfg.parseOptions)
	}

	cfg.nestedCompiler = c

	return &xsltFunc{min: 1, max: 1, fn: cfg.run, name: fnNameTransform, signature: xpath.HostBuiltin(31, fnNameTransform)}
}

// paramKeyToClark converts an XPath map key to the Clark notation string
// used internally for parameter lookup. QName keys are expanded to {uri}local;
// non-QName keys (xs:string) pass through AtomicToString unchanged.
func paramKeyToClark(key xdm.AtomicValue) (string, error) {
	if q, ok := key.Value.(xdm.QNameValue); ok {
		if q.URI != "" {
			return xdm.ClarkName(q.URI, q.Local), nil
		}

		return q.Local, nil
	}

	return xpath.AtomicToString(key)
}

func (ec *execContext) xsltFunctionsNS() map[xpath.QualifiedName]xpath.Function {
	if ec.cachedFnsNS != nil {
		return ec.cachedFnsNS
	}

	ec.cachedFnsNS = make(map[xpath.QualifiedName]xpath.Function, len(ec.stylesheet.functions)+1)

	// Register XSLT document() in the fn: namespace so fn:document() works.
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameDocument}] = &xsltFunc{min: 1, max: 2, fn: ec.fnDocument}

	// Override fn:doc to preserve source document identity and apply
	// xsl:strip-space rules to loaded documents.
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameDoc}] = &xsltFunc{min: 1, max: 1, fn: ec.fnDoc, signature: xpath.HostBuiltin(ec.stylesheet.xpathVersion(), nameDoc)}

	// Register XSLT built-in functions in the fn: namespace so they are
	// discoverable via function-lookup with an explicit namespace.
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: funcSystemProperty}] = newIntrospectionFunc(funcSystemProperty, ec.fnSystemProperty)
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: funcAvailableSystemProperties}] = &xsltFunc{min: 0, max: 0, fn: fnAvailableSystemProperties}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameCurrentOutputURI}] = &xsltFunc{min: 0, max: 0, fn: ec.fnCurrentOutputURI}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameStreamAvailable}] = &xsltFunc{min: 1, max: 1, fn: ec.fnStreamAvailable}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameUnparsedEntityUri}] = &xsltFunc{min: 1, max: 2, fn: ec.fnUnparsedEntityURI}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameUnparsedEntityPublicId}] = &xsltFunc{min: 1, max: 2, fn: ec.fnUnparsedEntityPublicID}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameKey2}] = &keyFunction{ec: ec, scope: ec.effectiveStylesheet()}

	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: lexicon.FnGenerateID}] = xpath.HostBuiltin(ec.stylesheet.xpathVersion(), lexicon.FnGenerateID)
	if ec.stylesheet.processorLanguage() <= 20 {
		for _, name := range []string{lexicon.FnFormatNumber, "format-date", "format-dateTime", "format-time"} {
			ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: name}] = newLegacyFormatFunction(ec.stylesheet.xpathVersion(), name)
		}
	}

	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameElementAvailable}] = newIntrospectionFunc(fnNameElementAvailable, ec.fnElementAvailable)
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameFunctionAvailable}] = newIntrospectionFunc(fnNameFunctionAvailable, ec.fnFunctionAvailable)
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameTypeAvailable}] = newIntrospectionFunc(fnNameTypeAvailable, fnTypeAvailable)
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameCurrent}] = &xsltFunc{min: 0, max: 0, fn: ec.fnCurrent, noDynRef: true, dynRefError: errCodeXTDE1360}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameCurrentGroup}] = &xsltFunc{min: 0, max: 0, fn: ec.fnCurrentGroup, noDynRef: true, dynRefError: errCodeXTDE1061}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameCurrentGroupingKey}] = &xsltFunc{min: 0, max: 0, fn: ec.fnCurrentGroupingKey, noDynRef: true, dynRefError: errCodeXTDE1071}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameCurrentMergeGroup}] = &xsltFunc{min: 0, max: 1, fn: ec.fnCurrentMergeGroup}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameCurrentMergeKey}] = &xsltFunc{min: 0, max: 0, fn: ec.fnCurrentMergeKey}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameRegexGroup}] = &xsltFunc{min: 1, max: 1, fn: ec.fnRegexGroup}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameAccumulatorBefore}] = &xsltFunc{min: 1, max: 1, fn: func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
		return ec.accumulatorLookup(ctx, args, nameAccumulatorBefore, func() (map[xdm.Node]map[string]xdm.Sequence, map[xdm.Node]map[string]error) {
			return ec.accumulatorBeforeByNode, ec.accumulatorBeforeErrorByNode
		})
	}}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameAccumulatorAfter}] = &xsltFunc{min: 1, max: 1, fn: func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
		return ec.accumulatorLookup(ctx, args, nameAccumulatorAfter, func() (map[xdm.Node]map[string]xdm.Sequence, map[xdm.Node]map[string]error) {
			return ec.accumulatorAfterByNode, ec.accumulatorAfterErrorByNode
		})
	}}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameCopyOf}] = &xsltFunc{min: 0, max: 1, fn: ec.fnCopyOf}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: funcSnapshot}] = &xsltFunc{min: 0, max: 1, fn: ec.fnSnapshot}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameTransform}] = &xsltFunc{min: 1, max: 1, fn: ec.fnTransform}

	// Dynamic lookup sees declarations in the calling package, excluding
	// abstract declarations and components accepted from other packages.
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: "function-lookup"}] = &xsltFunc{min: 2, max: 2, fn: ec.fnFunctionLookupPackage}

	if ec.currentPackage != nil {
		// Per-package function scope: all functions from the current
		// package (including private), plus public functions from
		// packages it uses.
		for _, def := range ec.currentPackage.functions {
			ec.registerUserFunc(def)
		}
	} else {
		for _, def := range ec.stylesheet.functions {
			ec.registerUserFunc(def)
		}
	}

	if ec.stylesheet.processorLanguage() == 20 {
		for name := range ec.cachedFnsNS {
			if name.URI == xpath.NSFn && xslt30Function(name.Name) {
				delete(ec.cachedFnsNS, name)
			}
		}
	}

	for name, function := range ec.cachedFnsNS {
		if name.URI == xpath.NSFn {
			if host, ok := function.(*xsltFunc); ok {
				ec.prepareHostFunction(name.Name, host)
			}
		}
	}

	return ec.cachedFnsNS
}

// xsltEvaluateFunctionsNS returns the namespaced function map for use with
// xsl:evaluate (XSLT 3.0 section 10.4). Filter each overload independently:
// private/hidden functions are unavailable without hiding public siblings.
func (ec *execContext) xsltEvaluateFunctionsNS() map[xpath.QualifiedName]xpath.Function {
	result := make(map[xpath.QualifiedName]xpath.Function)

	for name, function := range ec.xsltFunctionsNS() {
		if name.URI == xpath.NSFn && !xpath.StandardFunctionAcceptsArity(name.URI, name.Name, function.MinArity()) {
			continue
		}

		switch fn := function.(type) {
		case *xslUserFunc:
			if fn.def.Visibility == visPublic || fn.def.Visibility == visFinal {
				result[name] = fn
			}
		case *xslMultiArityFunc:
			var visible *xslMultiArityFunc

			for _, variant := range fn.variants {
				if variant.def.Visibility != visPublic && variant.def.Visibility != visFinal {
					continue
				}

				if visible == nil {
					visible = &xslMultiArityFunc{minArity: variant.MinArity(), maxArity: variant.MaxArity()}
				}

				visible.addVariant(variant)
			}

			if visible != nil {
				result[name] = visible
			}
		default:
			result[name] = function
		}
	}

	return result
}

// registerUserFunc registers an XSL user function into cachedFnsNS,
// handling multi-arity overloads by wrapping them in xslMultiArityFunc.
func (ec *execContext) registerUserFunc(def *xslFunction) {
	qn := def.Name

	uf := &xslUserFunc{def: def, ec: ec}
	if existing, ok := ec.cachedFnsNS[qn]; ok {
		if maf, ok := existing.(*xslMultiArityFunc); ok {
			maf.addVariant(uf)
		} else {
			maf := &xslMultiArityFunc{minArity: existing.MinArity(), maxArity: existing.MaxArity()}
			if euf, ok := existing.(*xslUserFunc); ok {
				maf.variants = append(maf.variants, euf)
			}

			maf.addVariant(uf)
			ec.cachedFnsNS[qn] = maf
		}
	} else {
		ec.cachedFnsNS[qn] = uf
	}
}

// fnFunctionLookupPackage preserves the dynamic component scope in 3.5.3.6.
func (ec *execContext) fnFunctionLookupPackage(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	result, err := xpath.CallFunctionLookup(ctx, args)
	if err != nil || result == nil || result.Len() == 0 {
		return result, err
	}

	fi, ok := result.Get(0).(xdm.FunctionItem)
	if !ok {
		return result, nil
	}

	qn := xpath.QualifiedName{URI: fi.Namespace, Name: fi.Name}
	if !ec.stylesheetFunctionDefined(qn, fi.Arity) {
		return result, nil
	}

	def := ec.dynamicStylesheetFunction(qn, fi.Arity)
	if def == nil {
		return nil, nil
	}

	fn := &xslUserFunc{def: def, ec: ec}
	item, _ := fn.DynamicRefSnapshot(ctx, fi.Arity)

	return xdm.ItemSlice{item}, nil
}

func (ec *execContext) stylesheetFunctionDefined(qn xpath.QualifiedName, arity int) bool {
	functions := ec.effectiveStylesheet().functions
	if arity >= 0 {
		return functions[funcKey{Name: qn, Arity: arity}] != nil
	}

	for key := range functions {
		if key.Name == qn {
			return true
		}
	}

	return false
}

func dynamicDeclaration(scope *Stylesheet, def *xslFunction) *xslFunction {
	if def == nil {
		return nil
	}

	if def.AcceptedFrom != nil {
		if def.Visibility == visAbstract {
			return nil
		}

		return def
	}

	for def.OriginalFunc != nil && def.OwnerPackage != scope {
		def = def.OriginalFunc
	}

	if def.Visibility == visAbstract || def.AcceptedFrom != nil || def.OwnerPackage != nil && def.OwnerPackage != scope {
		return nil
	}

	return def
}

func (ec *execContext) dynamicStylesheetFunction(qn xpath.QualifiedName, arity int) *xslFunction {
	scope := ec.effectiveStylesheet()
	if arity >= 0 {
		return dynamicDeclaration(scope, scope.functions[funcKey{Name: qn, Arity: arity}])
	}

	for key, def := range scope.functions {
		if key.Name == qn {
			if own := dynamicDeclaration(scope, def); own != nil {
				return own
			}
		}
	}

	return nil
}

func (ec *execContext) findXSLFunctionByArity(qn xpath.QualifiedName, arity int) *xslFunction {
	fk := funcKey{Name: qn, Arity: arity}
	return ec.stylesheet.functions[fk]
}

// xsltEvaluateFunctions keeps only host overrides of standard F&O functions.
// XSLT-specific functions are absent from the target expression's static library.
func (ec *execContext) xsltEvaluateFunctions() map[string]xpath.Function {
	result := make(map[string]xpath.Function)

	for name, function := range ec.xsltFunctions() {
		if xpath.StandardFunctionAcceptsArity(xpath.NSFn, name, function.MinArity()) {
			result[name] = function
		}
	}

	return result
}

// fnTransform implements fn:transform() for the in-stylesheet path. It builds a
// transformFnConfig from the running execution context — inheriting the outer
// stylesheet's resolvers, resource cap and XML limits —
// and delegates to the shared implementation (run), so the in-stylesheet and
// standalone (TransformFunction) paths run identical logic.
func (ec *execContext) fnTransform(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	ctx = ec.xpathContext(ctx)

	cfg := &transformFnConfig{
		// The static base URI of the fn:transform CALL — used to resolve a
		// relative stylesheet-location, stylesheet-base-uri, and base-output-uri —
		// is the effective static base URI at the call site (honoring an xml:base
		// on the calling template/element), NOT the bare module URI.
		baseURI:            ec.effectiveStaticBaseURI(),
		nestedCompiler:     ec.stylesheet.newNestedCompiler().MaxResourceBytes(ec.resourceLimit()),
		stylesheetResolver: ec.stylesheet.uriResolver,
		packageResolver:    ec.stylesheet.packageResolver,
		maxResourceBytes:   ec.resourceLimit(),

		parseOptions: ec.inputParseOptions(),
	}
	if ec.transformConfig != nil {
		cfg.innerURIResolver = ec.transformConfig.uriResolver
		cfg.collectionResolver = ec.transformConfig.collectionResolver
		cfg.httpClient = ec.transformConfig.httpClient
	}

	return cfg.run(ctx, args)
}

// newNestedCompiler creates a Compiler pre-configured with the same
// resolver, package resolver, and import schemas that were used to
// compile this stylesheet, so that fn:transform nested compiles
// behave consistently with top-level compilation.
func (ss *Stylesheet) newNestedCompiler() Compiler {
	c := NewCompiler()
	if ss.uriResolver != nil {
		c = c.URIResolver(ss.uriResolver)
	}

	if ss.packageResolver != nil {
		c = c.PackageResolver(ss.packageResolver)
	}

	if ss.maxResourceBytes != 0 {
		c = c.MaxResourceBytes(ss.maxResourceBytes)
	}

	if ss.parseOptions != nil {
		c = c.ParseOptions(*ss.parseOptions)
	}

	return c
}

type transformDepthKey struct{}

const transformSerialized = "serialized"

// transformFnConfig carries the resolvers, resource caps and XML limits for
// fn:transform. It
// decouples the shared implementation (run) from the running execution context,
// so both the in-stylesheet path (ec.fnTransform) and the standalone
// TransformFunction feed the same logic.
type transformFnConfig struct {
	// baseURI resolves a relative stylesheet-location.
	baseURI string
	// nestedCompiler is the pre-configured compiler used to compile the
	// dynamically-loaded stylesheet/package/stylesheet-text.
	nestedCompiler Compiler
	// stylesheetResolver reads an explicit stylesheet-location.
	stylesheetResolver URIResolver
	// packageResolver resolves a package-name/package-version.
	packageResolver PackageResolver

	// innerURIResolver serves fn:doc/document()/fn:unparsed-text evaluated
	// inside the dynamically-run stylesheet, and external-entity loading during
	// its parse.
	innerURIResolver   xpath.URIResolver
	collectionResolver xpath.CollectionResolver
	// httpClient is the opt-in HTTP client for the inner transform's resource
	// retrieval.
	httpClient *http.Client
	// maxResourceBytes is the per-resource read cap (0 = default, <0 = unbounded).
	maxResourceBytes int64

	parseOptions *xdm.ParseOptions
}

// run is the shared fn:transform implementation — it dynamically compiles and
// executes an XSLT stylesheet from the options map, using the resolvers and
// resource policy carried on cfg.
func (cfg *transformFnConfig) run(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	depth, _ := ctx.Value(transformDepthKey{}).(int)
	if depth >= maxTransformDepth {
		return nil, dynamicErrorCause(errCodeFOXT0004, xpath.ErrBudget, "fn:transform: maximum recursion depth (%d) exceeded", maxTransformDepth)
	}

	ctx = context.WithValue(ctx, transformDepthKey{}, depth+1)

	if len(args) != 1 || args[0] == nil || xdm.SequenceLen(args[0]) != 1 {
		return nil, dynamicError(lexicon.ErrXPTY0004, "fn:transform requires a single map argument")
	}

	options, ok := args[0].Get(0).(xdm.MapItem)
	if !ok {
		return nil, dynamicError(lexicon.ErrXPTY0004, "fn:transform argument must be a map")
	}

	request := newTransformRequest(options, cfg.baseURI)
	if err := validateTransformOptions(ctx, options, request.deliveryFormat); err != nil {
		return nil, err
	}

	assertions, err := transformBooleanOption(ctx, options, "enable-assertions")
	if err != nil {
		return nil, err
	}

	ctx = WithAssertions(ctx, assertions)

	compiler, staticParams := transformStaticParameters(cfg.nestedCompiler, transformMapSeq(options, "static-params"))

	processor, err := transformProcessorVersion(options)
	if err != nil {
		return nil, err
	}

	compiler = compiler.ProcessorVersion(processor).MaxResourceBytes(cfg.programLimit(ctx))

	stylesheet, err := cfg.compileTransformStylesheet(ctx, compiler, request)
	if err != nil {
		return nil, err
	}

	if stylesheet == nil {
		return nil, dynamicError(errCodeFOXT0002, "fn:transform: no stylesheet specified (stylesheet-location, stylesheet-node, stylesheet-text, or package-name required)")
	}

	invocation := request.newInvocation(ctx, cfg, staticParams)
	source := request.prepareSource(invocation)

	resultDoc, err := executeTransform(ctx, source, stylesheet, invocation)
	if err != nil {
		return nil, err
	}

	result, err := request.deliver(ctx, resultDoc, invocation)
	if err != nil {
		return nil, err
	}

	if callback, ok := transformPostProcess(options); ok {
		result, err = applyTransformPostProcess(ctx, callback, result, request.baseOutputURI)
		if err != nil {
			return nil, err
		}
	}

	return xdm.ItemSlice{result}, nil
}

func transformStaticParameters(nestedCompiler Compiler, staticParamsSeq xdm.Sequence) (Compiler, map[string]xdm.Sequence) {
	var staticParamValues map[string]xdm.Sequence

	if staticParamsSeq != nil && xdm.SequenceLen(staticParamsSeq) > 0 {
		if sm, ok := staticParamsSeq.Get(0).(xdm.MapItem); ok {
			staticParamValues = make(map[string]xdm.Sequence, sm.Size())
			_ = sm.ForEach(func(key xdm.AtomicValue, value xdm.Sequence) error {
				name, sErr := paramKeyToClark(key)
				if sErr != nil {
					return nil //nolint:nilerr // skip unparseable static param keys
				}

				nestedCompiler = nestedCompiler.SetStaticParameter(name, value)
				staticParamValues[name] = value

				return nil
			})
		}
	}

	return nestedCompiler, staticParamValues
}

// transformPostProcess returns the post-process function item from the
// fn:transform options map, or ok=false when the option is absent or is not a
// function item.
func transformPostProcess(m xdm.MapItem) (xdm.FunctionItem, bool) {
	seq := transformMapSeq(m, "post-process")
	if !transformOptionPresent(seq) {
		return xdm.FunctionItem{}, false
	}

	fi, ok := seq.Get(0).(xdm.FunctionItem)

	return fi, ok
}

// applyTransformPostProcess invokes the post-process callback once per result
// entry, passing (result-URI, result-value), and returns a new result map whose
// values are the callback return values. The principal "output" entry is passed
// the base output URI; each secondary entry is passed its href key.
func applyTransformPostProcess(ctx context.Context, fi xdm.FunctionItem, result xdm.MapItem, baseOutputURI string) (xdm.MapItem, error) {
	if fi.Invoke == nil {
		return result, nil
	}

	out := xdm.MapItem{}

	for _, key := range result.Keys() {
		value, _ := result.Get(key)

		uri := baseOutputURI
		if s, err := xpath.AtomicToString(key); err == nil && s != nameOutput {
			uri = s
		}

		processed, err := fi.Invoke(ctx, []xdm.Sequence{xdm.SingleString(uri), value})
		if err != nil {
			return xdm.MapItem{}, err
		}

		out = out.Put(key, processed)
	}

	return out, nil
}

// transformCapabilities is helium's advertised value for each XSLT-namespace
// requested-property that fn:transform can reason about. supports-streaming is
// false: helium materializes source documents into a DOM, and streams nothing.
func lookuptransformCapabilities(ctx context.Context, key string) (bool, bool) {
	switch key {
	case nameSupportsDynamicEvaluation:
		return !dynamicEvaluationDisabled(ctx), true
	case nameSupportsSerialization, textSupportsBackwardsCompatibility, nameSupportsNamespaceAxis, textSupportsHigherOrderFunctions:
		return true, true
	case nameSupportsStreaming, nameIsSchemaAware:
		return false, true
	}

	var zero bool

	return zero, false
}

// validateTransformOptions enforces the fn:transform option-map constraints that
// are independent of the compiled stylesheet (F&O 3.1 §16.3.2): exactly one
// stylesheet source, mutually-exclusive invocation options, a legal
// delivery-format, correctly-typed option values, and satisfiable requested
// properties. The no-invocation check is applied post-compile in run(), because
// it depends on the presence of an xsl:initial-template default template.
func validateTransformOptions(ctx context.Context, m xdm.MapItem, deliveryFormat string) error {
	sources := 0

	for _, k := range []string{"stylesheet-location", "stylesheet-node", "stylesheet-text", "package-name"} {
		if transformOptionPresent(transformMapSeq(m, k)) {
			sources++
		}
	}

	if sources != 1 {
		return dynamicError(errCodeFOXT0002, "fn:transform: exactly one of stylesheet-location, stylesheet-node, stylesheet-text, package-name must be supplied (got %d)", sources)
	}

	entryPoints := 0

	for _, k := range []string{"initial-template", "initial-mode", "initial-function"} {
		if transformOptionPresent(transformMapSeq(m, k)) {
			entryPoints++
		}
	}

	if entryPoints > 1 {
		return dynamicError(errCodeFOXT0002, "fn:transform: at most one of initial-template, initial-mode, initial-function may be supplied")
	}

	if transformOptionPresent(transformMapSeq(m, "initial-function")) {
		if _, present := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: "function-params"}); !present {
			return dynamicError(errCodeFOXT0002, "fn:transform: initial-function requires function-params")
		}
	}

	if transformOptionPresent(transformMapSeq(m, "source-node")) && transformOptionPresent(transformMapSeq(m, "initial-match-selection")) {
		return dynamicError(errCodeFOXT0002, "fn:transform: source-node and initial-match-selection are mutually exclusive")
	}

	switch deliveryFormat {
	case "", fnNameDocument, transformSerialized, lexicon.OutputRaw:
	default:
		return dynamicError(errCodeFOXT0002, "fn:transform: delivery-format %q is not one of document, serialized, raw", deliveryFormat)
	}

	if err := validateTransformXSLTVersion(m); err != nil {
		return err
	}

	if err := validateTransformGlobalContextItem(m); err != nil {
		return err
	}

	for _, name := range []string{"stylesheet-params", "static-params", "template-params", "tunnel-params"} {
		if err := validateTransformParamMap(name, transformMapSeq(m, name)); err != nil {
			return err
		}
	}

	return checkTransformCapabilities(ctx, transformMapSeq(m, "requested-properties"))
}

func transformBooleanOption(ctx context.Context, options xdm.MapItem, key string) (bool, error) {
	seq, present := options.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: key})
	if !present {
		return false, nil
	}

	value, err := xpath.ConvertToSequenceType(ctx, seq, xdm.SequenceType{ItemTest: xdm.AtomicOrUnionType{Prefix: "xs", Name: lexicon.TypeBoolean}})
	if err != nil {
		return false, err
	}

	atom, ok := value.Get(0).(xdm.AtomicValue)
	if !ok {
		return false, dynamicError(lexicon.ErrXPTY0004, "fn:transform: %s requires one boolean", key)
	}

	return atom.BooleanVal(), nil
}

// validateTransformGlobalContextItem enforces that the global-context-item
// option, when the key is present in the map, holds EXACTLY ONE item (F&O 3.1
// §16.3.2: its required type is item()). A present-but-empty or multi-item value
// is an XPTY0004 type error — it must NOT be silently treated as absent or
// truncated to its first item. An omitted key is fine (the global context item
// then defaults to the source-node root, or is absent).
func validateTransformGlobalContextItem(m xdm.MapItem) error {
	seq, ok := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: lexicon.XSLTElementGlobalContextItem})
	if !ok {
		return nil
	}

	if seq == nil || xdm.SequenceLen(seq) != 1 {
		return dynamicError(lexicon.ErrXPTY0004, "fn:transform: global-context-item must be exactly one item")
	}

	return nil
}

// validateTransformXSLTVersion validates the requested minimum processor version.
func validateTransformXSLTVersion(m xdm.MapItem) error {
	_, err := transformProcessorVersion(m)
	return err
}

func transformProcessorVersion(m xdm.MapItem) (int, error) {
	seq, present := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: "xslt-version"})
	if !present {
		return 30, nil
	}

	if xdm.SequenceLen(seq) != 1 {
		return 0, dynamicError(lexicon.ErrXPTY0004, "fn:transform: xslt-version requires one numeric value")
	}

	av, err := xpath.AtomizeItem(seq.Get(0))
	if err != nil || !av.IsNumeric() {
		return 0, dynamicError(lexicon.ErrXPTY0004, "fn:transform: xslt-version requires one numeric value")
	}

	// The option requests a minimum, not an exact processor. Use the modern
	// processor's backwards-compatible behavior for every supported
	// minimum, consistently with an omitted option.
	compatible, err := xpath.ValueCompare(xpath.TokenLe, av, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(3)})
	if err != nil {
		return 0, err
	}

	if compatible {
		return 30, nil
	}

	text, err := xpath.AtomicToString(av)
	if err != nil {
		return 0, err
	}

	return 0, dynamicError(errCodeFOXT0001, "fn:transform: no processor supports requested XSLT version %s", text)
}

// validateTransformParamMap checks that a parameter-map option
// (stylesheet-params, static-params, template-params, tunnel-params), when
// present, is a map whose keys are all xs:QName. A non-map value is an XPTY0004
// type error; a non-QName key is FOXT0002.
func validateTransformParamMap(name string, seq xdm.Sequence) error {
	if !transformOptionPresent(seq) {
		return nil
	}

	sm, ok := seq.Get(0).(xdm.MapItem)
	if !ok {
		return dynamicError(lexicon.ErrXPTY0004, "fn:transform: %s must be a map", name)
	}

	for _, key := range sm.Keys() {
		if key.TypeName != xdm.TypeQName {
			return dynamicError(errCodeFOXT0002, "fn:transform: %s keys must be supplied as QNames", name)
		}
	}

	return nil
}

// checkTransformCapabilities inspects the requested-properties option and raises
// FOXT0001 when a recognized XSLT-namespace property is requested with a value
// helium cannot satisfy. Non-map values are XPTY0004; properties outside the
// XSLT namespace, or ones helium does not model, are ignored.
func checkTransformCapabilities(ctx context.Context, seq xdm.Sequence) error {
	if !transformOptionPresent(seq) {
		return nil
	}

	sm, ok := seq.Get(0).(xdm.MapItem)
	if !ok {
		return dynamicError(lexicon.ErrXPTY0004, "fn:transform: requested-properties must be a map")
	}

	for _, key := range sm.Keys() {
		qv, ok := key.Value.(xdm.QNameValue)
		if !ok || qv.URI != lexicon.NamespaceXSLT {
			continue
		}

		if qv.Local == nameProductName {
			value, _ := sm.Get(key)
			if xdm.SequenceLen(value) != 1 {
				return dynamicError(lexicon.ErrXPTY0004, "fn:transform: product-name must be one string")
			}

			atom, err := xpath.AtomizeItem(value.Get(0))
			if err != nil {
				return err
			}

			name, err := xpath.AtomicToString(atom)
			if err != nil {
				return err
			}

			if name != processorProductName {
				return dynamicError(errCodeFOXT0001, "fn:transform: requested product %q is unavailable", name)
			}

			continue
		}

		want, known := lookuptransformCapabilities(ctx, qv.Local)

		if !known {
			continue
		}

		val, ok := sm.Get(key)
		if !ok {
			continue
		}

		got, ok := transformSeqBool(val)
		if !ok {
			continue
		}

		if got != want {
			return dynamicError(errCodeFOXT0001, "fn:transform: requested property %q cannot be satisfied", qv.Local)
		}
	}

	return nil
}

func (cfg *transformFnConfig) compileTransformStylesheet(ctx context.Context, compiler Compiler, request transformRequest) (*Stylesheet, error) {
	if request.stylesheetLoc != "" {
		return cfg.compileTransformLocation(ctx, compiler, request.stylesheetLoc)
	}

	if request.packageName != "" {
		return cfg.compileTransformPackage(ctx, compiler, request.packageName, request.packageVersion)
	}

	if text := transformStringOption(request.options, "stylesheet-text"); text != "" {
		return cfg.compileTransformText(ctx, compiler, text, request.stylesheetBaseURI)
	}

	return cfg.compileTransformNode(ctx, compiler, transformMapSeq(request.options, "stylesheet-node"), request.stylesheetBaseURI)
}

func (cfg *transformFnConfig) programLimit(ctx context.Context) int64 {
	return dynamicProgramLimit(ctx, cfg.maxResourceBytes)
}

func dynamicProgramLimit(ctx context.Context, resourceBytes int64) int64 {
	limit := resolveResourceLimit(resourceBytes)
	if bound, ok := ctx.Value(transformProgramLimitKey{}).(int); ok && bound > 0 && (limit <= 0 || int64(bound) < limit) {
		limit = int64(bound)
	}

	return limit
}

// The XSLT error code takes precedence over the generic FOXT0003 fallback.
func transformFailure(cause error, format string, args ...any) error {
	if errors.Is(cause, ErrLanguageUnsupported) {
		return dynamicErrorCause(errCodeFOXT0001, cause, format, args...)
	}

	if specific, ok := errors.AsType[*XSLTError](cause); ok && specific.Code != "" {
		return cause
	}

	if specific, ok := errors.AsType[*xdm.Error](cause); ok && specific.Code != "" {
		return cause
	}

	return dynamicErrorCause(errCodeFOXT0003, cause, format, args...)
}

type transformProgramCounter struct {
	ctx       context.Context
	remaining int64
}

func (w *transformProgramCounter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}

	if int64(len(data)) > w.remaining {
		return 0, xpath.ErrBudget
	}

	w.remaining -= int64(len(data))

	return len(data), nil
}

func (cfg *transformFnConfig) compileTransformLocation(ctx context.Context, nestedCompiler Compiler, stylesheetLoc string) (*Stylesheet, error) {
	// Resolve relative to the current stylesheet base URI.
	loc := resolveStylesheetLocation(cfg.baseURI, stylesheetLoc)

	baseURI := loc

	if cfg.stylesheetResolver == nil {
		return nil, dynamicError(errCodeFOXT0003, "fn:transform: cannot read stylesheet %q: no URIResolver configured (filesystem access is opt-in)", stylesheetLoc)
	}

	rc, resolveErr := cfg.stylesheetResolver.Resolve(ctx, loc)
	if resolveErr != nil {
		return nil, transformFailure(resolveErr, "fn:transform: cannot resolve stylesheet %q: %v", stylesheetLoc, resolveErr)
	}

	doc, parseErr := parseXMLResource(ctx, cfg.parseOptions, rc, baseURI, cfg.programLimit(ctx))
	if parseErr != nil {
		return nil, dynamicErrorCause(errCodeFOXT0003, parseErr, "fn:transform: cannot parse stylesheet %q: %v", stylesheetLoc, parseErr)
	}

	ss, compileErr := nestedCompiler.BaseURI(baseURI).Compile(ctx, doc)
	if compileErr != nil {
		return nil, transformFailure(compileErr, "fn:transform: cannot compile stylesheet %q: %v", stylesheetLoc, compileErr)
	}

	return ss, nil
}

func (cfg *transformFnConfig) compileTransformPackage(ctx context.Context, nestedCompiler Compiler, packageName, packageVersion string) (*Stylesheet, error) {
	if !ParseVersionConstraint(packageVersion).Valid() {
		return nil, dynamicError(errCodeFOXT0002, "invalid package version range %q", packageVersion)
	}
	// Resolve via package-name / package-version using the PackageResolver
	// stored on the compiled stylesheet (set at compile time).
	resolver := cfg.packageResolver
	if resolver == nil {
		return nil, dynamicError(errCodeFOXT0002, "fn:transform: package-name specified but no PackageResolver available")
	}

	rc, location, resolveErr := resolver.ResolvePackage(ctx, packageName, packageVersion)
	if resolveErr != nil {
		return nil, dynamicErrorCause(errCodeFOXT0003, resolveErr, "fn:transform: cannot resolve package %q (version %q): %v", packageName, packageVersion, resolveErr)
	}

	doc, parseErr := parseXMLResource(ctx, cfg.parseOptions, rc, location, cfg.programLimit(ctx))
	if parseErr != nil {
		return nil, dynamicErrorCause(errCodeFOXT0003, parseErr, "fn:transform: cannot parse package %q: %v", packageName, parseErr)
	}

	if err := checkResolvedPackage(doc, packageName, packageVersion); err != nil {
		return nil, err
	}

	compiler := nestedCompiler
	if location != "" {
		compiler = compiler.BaseURI(location)
	}

	ss, compileErr := compiler.Compile(ctx, doc)
	if compileErr != nil {
		return nil, transformFailure(compileErr, "fn:transform: cannot compile package %q: %v", packageName, compileErr)
	}

	if err := checkCompiledPackage(ss, packageName, packageVersion); err != nil {
		return nil, err
	}

	return ss, nil
}

func (cfg *transformFnConfig) compileTransformText(ctx context.Context, nestedCompiler Compiler, stylesheetText, stylesheetBaseURI string) (*Stylesheet, error) {
	// stylesheet-text: the stylesheet source is supplied inline as a string.
	// Parse it and compile. The base URI comes from the stylesheet-base-uri
	// option when supplied (a relative value resolved against the call's
	// static base URI). Without that option the text has no base URI.
	baseURI := ""
	if stylesheetBaseURI != "" {
		baseURI = resolveStylesheetLocation(cfg.baseURI, stylesheetBaseURI)
	}

	parseOptions := xdm.ParseOptions{}
	if cfg.parseOptions != nil {
		parseOptions = *cfg.parseOptions
	}

	parseOptions.BaseURI = baseURI

	doc, parseErr := parseOptions.WithByteLimit(cfg.programLimit(ctx)).ParseText(ctx, stylesheetText)
	if parseErr != nil {
		return nil, transformFailure(parseErr, "fn:transform: cannot parse stylesheet-text: %v", parseErr)
	}

	compiler := nestedCompiler.BaseURI(baseURI)

	ss, compileErr := compiler.Compile(ctx, doc)
	if compileErr != nil {
		return nil, transformFailure(compileErr, "fn:transform: cannot compile stylesheet-text: %v", compileErr)
	}

	return ss, nil
}

func (cfg *transformFnConfig) compileTransformNode(ctx context.Context, compiler Compiler, nodes xdm.Sequence, stylesheetBaseURI string) (*Stylesheet, error) {
	if !transformOptionPresent(nodes) {
		return nil, dynamicError(errCodeFOXT0002, "fn:transform: no stylesheet specified (stylesheet-location, stylesheet-node, stylesheet-text, or package-name required)")
	}

	node, ok := nodes.Get(0).(xdm.NodeItem)
	if !ok {
		return nil, dynamicError(errCodeFOXT0002, "fn:transform: no stylesheet specified (stylesheet-location, stylesheet-node, stylesheet-text, or package-name required)")
	}

	if node.Node.Type() != xdm.DocumentNode && node.Node.Type() != xdm.ElementNode {
		return nil, dynamicError(errCodeFOXT0002, "fn:transform: stylesheet-node must be a document or element node")
	}

	owner := owningDocument(node.Node)

	// Compilation applies the root's own xml:base once. Include inherited and
	// construction bases here, without pre-applying that same attribute.
	baseURI := xdm.NodeGetBaseBeforeXMLBase(node.Node.OwnerDocument(), node.Node)
	if stylesheetBaseURI != "" {
		baseURI = resolveStylesheetLocation(cfg.baseURI, stylesheetBaseURI)
	}

	compileDoc, err := stylesheetNodeCompileDocument(ctx, node.Node, owner)
	if err != nil {
		return nil, dynamicErrorCause(errCodeFOXT0003, err, "fn:transform: cannot prepare stylesheet node: %v", err)
	}

	if limit := cfg.programLimit(ctx); limit > 0 {
		counter := &transformProgramCounter{ctx: ctx, remaining: limit}
		if err := (xdm.XMLSerialization{OmitDeclaration: true}).WriteTo(counter, compileDoc); err != nil {
			return nil, transformFailure(err, "fn:transform: stylesheet-node exceeds its program budget: %v", err)
		}
	}

	if baseURI != "" {
		compiler = compiler.BaseURI(baseURI)
	}

	stylesheet, err := compiler.Compile(ctx, compileDoc)
	if err != nil {
		return nil, transformFailure(err, "fn:transform: cannot compile stylesheet: %v", err)
	}

	return stylesheet, nil
}

// A stylesheet-node element defines the module root, even when it is
// parentless or embedded in a larger input tree. Extraction preserves in-scope
// namespaces and avoids adding a synthetic default namespace declaration.
func stylesheetNodeCompileDocument(ctx context.Context, n xdm.Node, owner *xdm.Document) (*xdm.Document, error) {
	elem, ok := n.(*xdm.Element)
	if !ok {
		return owner, nil
	}

	if owner != nil && owner.DocumentElement() == elem {
		return owner, nil
	}

	return xdm.ElementDocument(ctx, elem)
}

// resolveRelativeURI resolves a reference against a base URI.
//
// Absoluteness is decided with [uripath.URIScheme] (RFC 3986): an absolute-URI ref
// (it carries its own scheme, e.g. "urn:shared", "file:/modules/m.xsl") is
// returned unchanged and must never be filepath.Join'ed onto a local base
// (which would corrupt it into "/styles/urn:shared"). A relative ref against a
// URI base is resolved with RFC 3986 semantics (scheme/authority preserved);
// against a local filesystem base it uses filepath.Join semantics.
// Resolution of the URI cases is delegated to the shared canonical
// [uripath.ResolveSchemaURI] helper.
func resolveRelativeURI(base, ref string) string {
	if uripath.URIScheme(ref) != "" || uripath.URIScheme(base) != "" {
		resolved, err := uripath.ResolveSchemaURI(ref, base)
		if err != nil {
			return ref
		}

		return resolved
	}
	// Local filesystem base: resolve with forward-slash (path) semantics so the
	// result uses '/' on every OS; on Windows filepath.Dir/Join would emit '\'.
	return uripath.JoinLocalBaseDir(path.Dir(uripath.ToSlash(base)), ref)
}

// resolveStylesheetLocation resolves an fn:transform stylesheet-location loc
// against the current stylesheet base URI.
//
// Absoluteness is decided with [uripath.URIScheme] (RFC 3986), not filepath.IsAbs:
// when base is a URI (it has a scheme), a filepath-absolute or root-relative
// loc such as "/inner.xsl" must be resolved against the base scheme/authority
// (mem://pkg/main.xsl + /inner.xsl -> mem://pkg/inner.xsl), and is never passed
// through verbatim. Only a purely-local absolute path against a local base is
// left unchanged.
func resolveStylesheetLocation(base, loc string) string {
	if base == "" {
		return loc
	}
	// uripath.IsAbsolutePath recognizes both POSIX- and Windows-absolute shapes
	// regardless of GOOS, so a purely-local absolute loc against a local base is
	// left unchanged on every OS.
	if uripath.URIScheme(base) != "" || !uripath.IsAbsolutePath(loc) {
		return resolveRelativeURI(base, loc)
	}

	return loc
}

type transformOptionFunc func(*transformFnConfig)

func (f transformOptionFunc) applyTransform(c *transformFnConfig) { f(c) }

type transformRequest struct {
	options                                                       xdm.MapItem
	stylesheetLoc, packageName, packageVersion, stylesheetBaseURI string
	initialTemplate, initialMode, initialFunction                 string
	deliveryFormat, baseOutputURI                                 string
	initialMatchSelection, sourceNode, globalContextItem          xdm.Sequence
}

func newTransformRequest(options xdm.MapItem, baseURI string) transformRequest {
	request := transformRequest{
		options:               options,
		stylesheetLoc:         transformStringOption(options, "stylesheet-location"),
		packageName:           transformStringOption(options, "package-name"),
		packageVersion:        transformStringOption(options, namePackageVersion),
		initialTemplate:       transformQNameOption(options, "initial-template"),
		initialMode:           transformStringOption(options, "initial-mode"),
		initialFunction:       transformQNameOption(options, "initial-function"),
		deliveryFormat:        transformStringOption(options, "delivery-format"),
		baseOutputURI:         transformStringOption(options, "base-output-uri"),
		stylesheetBaseURI:     transformStringOption(options, "stylesheet-base-uri"),
		initialMatchSelection: transformMapSeq(options, "initial-match-selection"),
		sourceNode:            transformMapSeq(options, "source-node"),
		globalContextItem:     transformMapSeq(options, lexicon.XSLTElementGlobalContextItem),
	}
	if request.baseOutputURI != "" {
		request.baseOutputURI = canonicalResultURIKey(request.baseOutputURI, baseURI)
	}

	return request
}

func transformQNameOption(options xdm.MapItem, key string) string {
	seq := transformMapSeq(options, key)
	if !transformOptionPresent(seq) {
		return ""
	}

	value, err := xpath.AtomizeItem(seq.Get(0))
	if err != nil {
		return ""
	}

	if value.TypeName == xdm.TypeQName {
		if name, ok := value.Value.(xdm.QNameValue); ok {
			if name.URI != "" {
				return xdm.ClarkName(name.URI, name.Local)
			}

			return name.Local
		}
	}

	text, err := xpath.AtomicToString(value)
	if err != nil {
		return ""
	}

	return text
}

func (request transformRequest) newInvocation(ctx context.Context, cfg *transformFnConfig, staticParamValues map[string]xdm.Sequence) *transformConfig {
	outputBaseURI := request.baseOutputURI
	if outputBaseURI == "" {
		outputBaseURI = cfg.baseURI
	}

	invocation := &transformConfig{
		initialTemplate:    request.initialTemplate,
		initialMode:        request.initialMode,
		initialFunction:    request.initialFunction,
		baseOutputURI:      request.baseOutputURI,
		outputBaseURI:      outputBaseURI,
		uriResolver:        cfg.innerURIResolver,
		collectionResolver: cfg.collectionResolver,
		httpClient:         cfg.httpClient,
		maxResourceBytes:   cfg.maxResourceBytes,
		parseOptions:       cfg.parseOptions,
		rawCapture:         true,
		rawSequence:        true,
		valueResults:       make(map[string]ValueResult),
	}
	if invocation.collectionResolver == nil {
		invocation.collectionResolver = xpath.EvaluationCollections(ctx)
	}

	if transformOptionPresent(request.globalContextItem) {
		invocation.globalContextItem = request.globalContextItem.Get(0)
	}

	request.applyParameters(invocation, staticParamValues)

	return invocation
}

func (request transformRequest) applyParameters(fnTransformCfg *transformConfig, staticParamValues map[string]xdm.Sequence) {
	stylesheetParamsSeq := transformMapSeq(request.options, "stylesheet-params")
	templateParamsSeq := transformMapSeq(request.options, "template-params")
	tunnelParamsSeq := transformMapSeq(request.options, "tunnel-params")
	functionParamsSeq := transformMapSeq(request.options, "function-params")
	// Apply map-valued options from the fn:transform options map.
	for _, mp := range []struct {
		seq    xdm.Sequence
		target *map[string]xdm.Sequence
	}{
		{stylesheetParamsSeq, &fnTransformCfg.sequenceParams},
		{templateParamsSeq, &fnTransformCfg.initialTemplateParams},
		{tunnelParamsSeq, &fnTransformCfg.initialTemplateTunnel},
	} {
		if mp.seq == nil || xdm.SequenceLen(mp.seq) == 0 {
			continue
		}

		sm, ok := mp.seq.Get(0).(xdm.MapItem)
		if !ok {
			continue
		}

		params := make(map[string]xdm.Sequence, sm.Size())
		_ = sm.ForEach(func(key xdm.AtomicValue, value xdm.Sequence) error {
			name, sErr := paramKeyToClark(key)
			if sErr != nil {
				return nil //nolint:nilerr // skip unparseable param keys
			}

			params[name] = value

			return nil
		})
		*mp.target = params
	}

	// Merge static params as runtime params so the externally supplied
	// values override the compiled select="..." defaults at runtime.
	// Explicit stylesheet-params take precedence over static-params.
	if len(staticParamValues) > 0 {
		if fnTransformCfg.sequenceParams == nil {
			fnTransformCfg.sequenceParams = make(map[string]xdm.Sequence, len(staticParamValues))
		}

		for name, val := range staticParamValues {
			if _, exists := fnTransformCfg.sequenceParams[name]; !exists {
				fnTransformCfg.sequenceParams[name] = val
			}
		}
	}

	// Apply function-params (array of sequences) for initial-function.
	if functionParamsSeq != nil && xdm.SequenceLen(functionParamsSeq) > 0 {
		if arr, ok := functionParamsSeq.Get(0).(xdm.ArrayItem); ok {
			fnTransformCfg.initialFunctionParams = arr.Members()
		}
	}
}

func (request transformRequest) prepareSource(invocation *transformConfig) *xdm.Document {
	var sourceDoc *xdm.Document

	var sourceNode xdm.Node

	if transformOptionPresent(request.sourceNode) {
		if item, ok := request.sourceNode.Get(0).(xdm.NodeItem); ok {
			sourceNode = item.Node
			sourceDoc = owningDocument(item.Node)
		}
	}

	if _, provided := request.options.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: "initial-match-selection"}); provided {
		if xdm.SequenceLen(request.initialMatchSelection) == 1 {
			if item, ok := request.initialMatchSelection.Get(0).(xdm.NodeItem); ok {
				if owner := owningDocument(item.Node); owner != nil {
					sourceDoc = owner
				}
			}
		}

		invocation.initialMatchSelection = request.initialMatchSelection
		if invocation.initialMatchSelection == nil {
			invocation.initialMatchSelection = xdm.ItemSlice{}
		}
	} else if sourceNode != nil {
		if _, document := sourceNode.(*xdm.Document); !document {
			invocation.initialMatchSelection = request.sourceNode
		}
	}

	// Only source-node supplies the default global context. An initial match
	// selection drives template matching independently (F&O 3.1 §16.3.2).
	if invocation.globalContextItem == nil {
		if sourceNode != nil {
			invocation.globalContextItem = xdm.NodeItem{Node: xdm.DocumentRoot(sourceNode)}
		} else {
			invocation.globalContextAbsent = true
		}
	}

	return sourceDoc
}

func (request transformRequest) deliver(ctx context.Context, resultDoc *xdm.Document, cfg *transformConfig) (xdm.MapItem, error) {
	key := xdm.AtomicValue{TypeName: xdm.TypeString, Value: nameOutput}
	if request.baseOutputURI != "" {
		key.Value = request.baseOutputURI
	}

	if request.deliveryFormat == transformSerialized {
		return request.deliverSerialized(ctx, resultDoc, cfg, key)
	}

	execution := &Execution{Primary: ValueResult{Document: resultDoc, Items: cfg.rawCapturedItems, Output: cfg.resolvedOutputDef}, Secondary: cfg.valueResults}

	if request.deliveryFormat != lexicon.OutputRaw {
		var forceTree *bool

		if request.deliveryFormat == fnNameDocument {
			enabled := true
			forceTree = &enabled
		}

		var err error

		execution, err = NormalizeExecution(ctx, execution, forceTree, request.baseOutputURI)
		if err != nil {
			return xdm.MapItem{}, err
		}
	}

	result := xdm.MapItem{}.Put(key, execution.Primary.Items)
	for uri, value := range execution.Secondary {
		result = result.Put(xdm.AtomicValue{TypeName: xdm.TypeString, Value: uri}, value.Items)
	}

	return result, nil
}

// deliverSerialized uses the same complete value sequences and serializer as
// the public XSLT API, including JSON/adaptive results with no document tree.
func (request transformRequest) deliverSerialized(ctx context.Context, doc *xdm.Document, cfg *transformConfig, key xdm.AtomicValue) (xdm.MapItem, error) {
	params := transformMapSeq(request.options, "serialization-params")
	output := applySerializationParams(cfg.resolvedOutputDef, params)
	result := xdm.MapItem{}

	value := ValueResult{Document: doc, Items: cfg.rawCapturedItems, Output: output}

	s, err := serializeDeliveredValue(ctx, value)
	if err != nil {
		return xdm.MapItem{}, err
	}

	result = result.Put(key, xdm.SingleString(s))

	for uri, value := range cfg.valueResults {
		s, err := serializeDeliveredValue(ctx, value)
		if err != nil {
			return xdm.MapItem{}, err
		}

		result = result.Put(xdm.AtomicValue{TypeName: xdm.TypeString, Value: uri}, xdm.SingleString(s))
	}

	return result, nil
}

func serializeDeliveredValue(ctx context.Context, value ValueResult) (string, error) {
	var buf bytes.Buffer
	if err := SerializeValue(ctx, &buf, value); err != nil {
		return "", transformFailure(err, "fn:transform: serialization error: %v", err)
	}

	return buf.String(), nil
}

// applySerializationParams returns an OutputDef with the fn:transform
// serialization-params option applied over base. base is returned unchanged when
// no params are supplied. Recognized keys (string or fn/output-namespace QName)
// map to the corresponding OutputDef fields.
func applySerializationParams(base *OutputDef, seq xdm.Sequence) *OutputDef {
	if !transformOptionPresent(seq) {
		return base
	}

	sm, ok := seq.Get(0).(xdm.MapItem)
	if !ok {
		return base
	}

	out := cloneOutputDef(base)
	if out == nil {
		out = defaultOutputDef()
	}

	versionExplicit := false

	for _, key := range sm.Keys() {
		name := serializationParamName(key)
		if name == "" {
			continue
		}

		if name == lexicon.SerializationVersion {
			versionExplicit = true
		}

		val, ok := sm.Get(key)
		if !ok {
			continue
		}
		// A recognized parameter present with an empty-sequence value overrides
		// the inherited xsl:output value by resetting the parameter to its
		// serialization default (F&O 3.1 §16.3.2), leaving no
		// inherited value in place.
		if !transformOptionPresent(val) {
			resetSerializationParam(out, name)
			continue
		}

		applySerializationParam(out, name, val)
	}
	// The version parameter's default is method-dependent, so an inherited xml
	// version="1.0" must not carry into an html/xhtml method selected via
	// serialization-params. When these params switch the method to html/xhtml
	// without supplying an explicit version — and the base stylesheet did not
	// declare one either (VersionRaw empty) — unset Version so the
	// method-appropriate serialization default applies instead of the inherited
	// "1.0" (which the html method rejects with SESU0007). An explicit base
	// version (e.g. <xsl:output method="html" version="1.0"/>) is preserved so
	// it still raises SESU0007.
	if !versionExplicit && out.VersionRaw == "" && out.MethodExplicit && (out.Method == lexicon.MethodHTML || out.Method == lexicon.MethodXHTML) {
		out.Version = ""
	}

	return out
}

// resetSerializationParam resets a recognized serialization parameter (by local
// name) to its serialization default on out. An unrecognized name is ignored.
func resetSerializationParam(out *OutputDef, name string) {
	switch name {
	case lexicon.SerializationMethod:
		out.Method = lexicon.MethodXML
		out.MethodExplicit = false
	case lexicon.SerializationIndent:
		out.Indent = false
	case lexicon.SerializationOmitXMLDeclaration:
		out.OmitDeclaration = false
		out.OmitDeclarationExplicit = false
	case lexicon.SerializationByteOrderMark:
		out.ByteOrderMark = false
	case lexicon.SerializationUndeclarePrefixes:
		out.UndeclarePrefixes = false
	case lexicon.SerializationEncoding:
		out.Encoding = lexicon.EncodingUTF8U
	case lexicon.SerializationVersion:
		out.Version = lexicon.XSLTVersion10
	case lexicon.SerializationStandalone:
		out.Standalone = ""
	case lexicon.SerializationMediaType:
		out.MediaType = ""
	case lexicon.SerializationDoctypePublic:
		out.DoctypePublic = ""
	case lexicon.SerializationDoctypeSystem:
		out.DoctypeSystem = ""
	case lexicon.SerializationItemSeparator:
		out.ItemSeparator = nil
	case lexicon.SerializationCDATASectionElements:
		out.CDATASections = nil
	case lexicon.SerializationSuppressIndentation:
		out.SuppressIndentation = nil
	case lexicon.SerializationUseCharacterMaps:
		out.ResolvedCharMap = nil
	}
}

// serializationParamName returns the local name of a serialization-params map
// key, which may be supplied either as an xs:string or as an xs:QName in the
// serialization-parameter (fn/output) namespace.
func serializationParamName(key xdm.AtomicValue) string {
	if qv, ok := key.Value.(xdm.QNameValue); ok {
		return qv.Local
	}

	s, err := xpath.AtomicToString(key)
	if err != nil {
		return ""
	}

	return s
}

// applySerializationParam applies a single serialization parameter (identified
// by its local name) to out.
func applySerializationParam(out *OutputDef, name string, val xdm.Sequence) {
	switch name {
	case lexicon.SerializationMethod:
		if s, ok := transformSeqString(val); ok {
			out.Method = s
			out.MethodExplicit = true
		}
	case lexicon.SerializationIndent:
		if b, ok := transformSeqBool(val); ok {
			out.Indent = b
		}
	case lexicon.SerializationOmitXMLDeclaration:
		if b, ok := transformSeqBool(val); ok {
			out.OmitDeclaration = b
			out.OmitDeclarationExplicit = true
		}
	case lexicon.SerializationByteOrderMark:
		if b, ok := transformSeqBool(val); ok {
			out.ByteOrderMark = b
		}
	case lexicon.SerializationUndeclarePrefixes:
		if b, ok := transformSeqBool(val); ok {
			out.UndeclarePrefixes = b
		}
	case lexicon.SerializationEncoding:
		if s, ok := transformSeqString(val); ok {
			out.Encoding = s
		}
	case lexicon.SerializationVersion:
		if s, ok := transformSeqString(val); ok {
			out.Version = s
		}
	case lexicon.SerializationStandalone:
		if s, ok := transformSeqString(val); ok {
			out.Standalone = s
		}
	case lexicon.SerializationMediaType:
		if s, ok := transformSeqString(val); ok {
			out.MediaType = s
		}
	case lexicon.SerializationDoctypePublic:
		if s, ok := transformSeqString(val); ok {
			out.DoctypePublic = s
		}
	case lexicon.SerializationDoctypeSystem:
		if s, ok := transformSeqString(val); ok {
			out.DoctypeSystem = s
		}
	case lexicon.SerializationItemSeparator:
		if s, ok := transformSeqString(val); ok {
			out.ItemSeparator = &s
		}
	case lexicon.SerializationCDATASectionElements:
		out.CDATASections = mergeSerializationQNames(out.CDATASections, val)
	case lexicon.SerializationSuppressIndentation:
		out.SuppressIndentation = mergeSerializationQNames(out.SuppressIndentation, val)
	case lexicon.SerializationUseCharacterMaps:
		applyUseCharacterMapsParam(out, val)
	}
}

// serializationQNameClarkName returns the Clark-notation name ({uri}local, or
// the bare local name when there is no namespace) of a serialization-params
// value item that is an xs:QName. Non-QName items yield "".
func serializationQNameClarkName(item xdm.Item) string {
	av, err := xpath.AtomizeItem(item)
	if err != nil {
		return ""
	}

	qv, ok := av.Value.(xdm.QNameValue)
	if !ok {
		return ""
	}

	if qv.URI != "" {
		return xdm.ClarkName(qv.URI, qv.Local)
	}

	return qv.Local
}

// mergeSerializationQNames unions the Clark names of the xs:QName items in val
// into base. The cdata-section-elements / suppress-indentation values supplied
// via serialization-params accumulate onto the stylesheet's xsl:output set,
// replacing none of it (F&O 3.1 §16.3.2), skipping duplicates.
func mergeSerializationQNames(base []string, val xdm.Sequence) []string {
	seen := make(map[string]struct{}, len(base))
	for _, n := range base {
		seen[n] = struct{}{}
	}

	for i := range xdm.SequenceLen(val) {
		name := serializationQNameClarkName(val.Get(i))
		if name == "" {
			continue
		}

		if _, ok := seen[name]; ok {
			continue
		}

		seen[name] = struct{}{}
		base = append(base, name)
	}

	return base
}

// applyUseCharacterMapsParam merges the (character → replacement) entries of a
// use-character-maps serialization-param map into out.ResolvedCharMap. Its
// value is a map(xs:string, xs:string) keyed by single characters; entries
// override any inherited mapping for the same character.
func applyUseCharacterMapsParam(out *OutputDef, val xdm.Sequence) {
	sm, ok := val.Get(0).(xdm.MapItem)
	if !ok {
		return
	}

	if out.ResolvedCharMap == nil {
		out.ResolvedCharMap = make(map[rune]string, sm.Size())
	}

	_ = sm.ForEach(func(key xdm.AtomicValue, value xdm.Sequence) error {
		ks, err := xpath.AtomicToString(key)
		if err != nil {
			return nil //nolint:nilerr // skip unparseable character-map keys
		}

		runes := []rune(ks)
		if len(runes) != 1 {
			return nil // character-map keys are single characters
		}

		rs, ok := transformSeqString(value)
		if !ok {
			return nil
		}

		out.ResolvedCharMap[runes[0]] = rs

		return nil
	})
}

func transformStringOption(options xdm.MapItem, key string) string {
	value, _ := transformSeqString(transformMapSeq(options, key))
	return value
}

// owningDocument walks up from n to the document that contains it,
// returning nil when n is not part of any document.
func owningDocument(n xdm.Node) *xdm.Document {
	for n != nil {
		if d, ok := n.(*xdm.Document); ok {
			return d
		}

		n = n.Parent()
	}

	return nil
}

// transformOptionPresent reports whether a sequence-valued fn:transform option
// is present and non-empty.
func transformOptionPresent(seq xdm.Sequence) bool {
	return seq != nil && xdm.SequenceLen(seq) > 0
}

// transformMapSeq returns the raw sequence bound to a string-keyed fn:transform
// option, or nil when the key is absent.
func transformMapSeq(m xdm.MapItem, key string) xdm.Sequence {
	seq, ok := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: key})
	if !ok {
		return nil
	}

	return seq
}

// transformSeqBool extracts a boolean value from a single-item sequence,
// accepting the full xs:boolean space that helium recognizes: an xs:boolean
// atomic item, or the string / xs:untypedAtomic lexical forms true/false/1/0/
// yes/no (parsed via parseXSDBool). Any other value reports ok=false.
func transformSeqBool(seq xdm.Sequence) (bool, bool) {
	if !transformOptionPresent(seq) {
		return false, false
	}

	av, err := xpath.AtomizeItem(seq.Get(0))
	if err != nil {
		return false, false
	}

	if b, ok := av.Value.(bool); ok {
		return b, true
	}

	if av.TypeName != xdm.TypeString && av.TypeName != xdm.TypeUntypedAtomic {
		return false, false
	}

	s, err := xpath.AtomicToString(av)
	if err != nil {
		return false, false
	}

	return parseXSDBool(s)
}

// transformSeqString extracts a string value from a single-item sequence,
// reporting whether extraction succeeded.
func transformSeqString(seq xdm.Sequence) (string, bool) {
	if !transformOptionPresent(seq) {
		return "", false
	}

	av, err := xpath.AtomizeItem(seq.Get(0))
	if err != nil {
		return "", false
	}

	s, err := xpath.AtomicToString(av)
	if err != nil {
		return "", false
	}

	return s, true
}
