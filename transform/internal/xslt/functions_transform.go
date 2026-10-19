// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"bytes"
	"context"
	"net/http"
	"path"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

const maxTransformDepth = 10

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
func TransformFunction(options ...TransformOption) xpath.Function {
	cfg := &transformFnConfig{}
	for _, o := range options {
		o.applyTransform(cfg)
	}
	// Adapt the xpath resolver to a compile-time module resolver for the
	// nested compile and stylesheet-location reads.
	if cfg.innerURIResolver != nil && cfg.stylesheetResolver == nil {
		cfg.stylesheetResolver = cfg.innerURIResolver
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

	return &xsltFunc{min: 1, max: 1, fn: cfg.run}
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
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameDoc}] = &xsltFunc{min: 1, max: 1, fn: ec.fnDoc}

	// Register XSLT built-in functions in the fn: namespace so they are
	// discoverable via function-lookup with an explicit namespace.
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: funcSystemProperty}] = &xsltFunc{min: 1, max: 1, fn: ec.fnSystemProperty}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: funcAvailableSystemProperties}] = &xsltFunc{min: 0, max: 0, fn: ec.fnAvailableSystemProperties}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameCurrentOutputURI}] = &xsltFunc{min: 0, max: 0, fn: ec.fnCurrentOutputURI}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameStreamAvailable}] = &xsltFunc{min: 1, max: 1, fn: ec.fnStreamAvailable}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameUnparsedEntityUri}] = &xsltFunc{min: 1, max: 2, fn: ec.fnUnparsedEntityURI}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameUnparsedEntityPublicId}] = &xsltFunc{min: 1, max: 2, fn: ec.fnUnparsedEntityPublicID}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameKey2}] = &xsltFunc{min: 2, max: 3, fn: ec.fnKey}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameGenerateId}] = &xsltFunc{min: 0, max: 1, fn: ec.fnGenerateID}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameElementAvailable}] = &xsltFunc{min: 1, max: 1, fn: ec.fnElementAvailable}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameFunctionAvailable}] = &xsltFunc{min: 1, max: 2, fn: ec.fnFunctionAvailable}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameTypeAvailable}] = &xsltFunc{min: 1, max: 1, fn: ec.fnTypeAvailable}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameCurrent}] = &xsltFunc{min: 0, max: 0, fn: ec.fnCurrent}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameCurrentGroup}] = &xsltFunc{min: 0, max: 0, fn: ec.fnCurrentGroup, noDynRef: true, dynRefError: errCodeXTDE1061}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: fnNameCurrentGroupingKey}] = &xsltFunc{min: 0, max: 0, fn: ec.fnCurrentGroupingKey, noDynRef: true, dynRefError: errCodeXTDE1071}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameCurrentMergeGroup}] = &xsltFunc{min: 0, max: 1, fn: ec.fnCurrentMergeGroup}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameCurrentMergeKey}] = &xsltFunc{min: 0, max: 0, fn: ec.fnCurrentMergeKey}
	ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: nameRegexGroup}] = &regexGroupFunc{ec: ec}
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

	// Per spec §20.3.3, function-lookup within a package must return the
	// original (pre-override) function, not the override. Register a
	// custom function-lookup that handles this when in a package context.
	if ec.currentPackage != nil {
		ec.cachedFnsNS[xpath.QualifiedName{URI: xpath.NSFn, Name: "function-lookup"}] = &xsltFunc{min: 2, max: 2, fn: ec.fnFunctionLookupPackage}
	}

	if ec.currentPackage != nil {
		// Per-package function scope: all functions from the current
		// package (including private), plus public functions from
		// packages it uses.
		for _, def := range ec.currentPackage.functions {
			if def.Visibility == visAbstract {
				continue // abstract functions have no implementation
			}

			ec.registerUserFunc(def)
		}

		for _, usedPkg := range ec.currentPackage.usedPackages {
			for _, def := range usedPkg.functions {
				if def.Visibility == visPublic || def.Visibility == visFinal || def.Visibility == "" {
					ec.registerUserFunc(def)
				}
			}
		}
	} else {
		for _, def := range ec.stylesheet.functions {
			ec.registerUserFunc(def)
		}
	}

	return ec.cachedFnsNS
}

// xsltEvaluateFunctionsNS returns the namespaced function map for use with
// xsl:evaluate. Per XSLT 3.0 §20.3, user-defined stylesheet functions
// (xsl:function) are NOT available in xsl:evaluate unless they are
// explicitly declared as public or final.
func (ec *execContext) xsltEvaluateFunctionsNS() map[xpath.QualifiedName]xpath.Function {
	all := ec.xsltFunctionsNS()
	excluded := make(map[xpath.QualifiedName]struct{})

	fns := ec.stylesheet.functions
	if ec.currentPackage != nil {
		fns = ec.currentPackage.functions
	}

	for _, def := range fns {
		vis := def.Visibility
		if vis == visPublic || vis == visFinal {
			continue // explicitly public → available in xsl:evaluate
		}

		excluded[def.Name] = struct{}{}
	}

	result := make(map[xpath.QualifiedName]xpath.Function, len(all))
	for k, v := range all {
		if _, skip := excluded[k]; skip {
			continue
		}

		result[k] = v
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

// fnFunctionLookupPackage is a package-aware implementation of function-lookup
// per spec §20.3.3. Within a package, function-lookup must return the original
// (pre-override) function definition, not the override. This implementation
// looks up the function, and if it's an overridden xsl:function, substitutes
// the original definition.
func (ec *execContext) fnFunctionLookupPackage(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// Delegate to the standard function-lookup implementation first
	result, err := xpath.CallFunctionLookup(ctx, args)
	if err != nil {
		return nil, err
	}

	if result == nil || result.Len() == 0 {
		return result, nil
	}

	fi, ok := result.Get(0).(xdm.FunctionItem)
	if !ok {
		return result, nil
	}

	qn := xpath.QualifiedName{URI: fi.Namespace, Name: fi.Name}
	fk := funcKey{Name: qn, Arity: fi.Arity}

	pkgFn, exists := ec.currentPackage.functions[fk]
	if !exists {
		return result, nil // not a package function
	}

	if pkgFn.OriginalFunc == nil {
		return result, nil // not overridden
	}

	origDef := pkgFn.OriginalFunc
	if origDef.Visibility == visAbstract {
		// Original is abstract — no implementation to look up
		return nil, nil //nolint:nilnil
	}

	origUF := &xslUserFunc{def: origDef, ec: ec}
	origFI, _ := origUF.DynamicRefSnapshot(ctx, fi.Arity)

	return xdm.ItemSlice{origFI}, nil
}

// findXSLFunction finds an xsl:function by QName and arity (-1 = any).
func (ec *execContext) findXSLFunction(qn xpath.QualifiedName, arity int) *xslFunction {
	if arity < 0 {
		// Any arity: just check if any overload exists
		for fk, def := range ec.stylesheet.functions {
			if fk.Name == qn {
				return def
			}
		}

		return nil
	}

	fk := funcKey{Name: qn, Arity: arity}

	return ec.stylesheet.functions[fk]
}

func (ec *execContext) findXSLFunctionByArity(qn xpath.QualifiedName, arity int) *xslFunction {
	fk := funcKey{Name: qn, Arity: arity}
	return ec.stylesheet.functions[fk]
}

// xsltEvaluateFunctions returns XSLT built-in functions available in
// xsl:evaluate dynamic context. Per XSLT 3.0 section 20.3, current()
// is excluded.
func (ec *execContext) xsltEvaluateFunctions() map[string]xpath.Function {
	fns := ec.xsltFunctions()

	evalFns := make(map[string]xpath.Function, len(fns))
	for k, v := range fns {
		switch k {
		case "current", funcSystemProperty, "current-output-uri", "available-system-properties":
			continue
		}

		evalFns[k] = v
	}

	return evalFns
}

// fnTransform implements fn:transform() for the in-stylesheet path. It builds a
// transformFnConfig from the running execution context — inheriting the outer
// stylesheet's resolvers, resource cap and XML limits —
// and delegates to the shared implementation (run), so the in-stylesheet and
// standalone (TransformFunction) paths run identical logic.
func (ec *execContext) fnTransform(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
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
		cfg.httpClient = ec.transformConfig.httpClient
	}

	return cfg.run(ctx, args)
}

// resultDocCollector implements ResultDocumentHandler for fn:transform,
// collecting secondary result documents and their output definitions into maps.
type resultDocCollector struct {
	results    map[string]*xdm.Document
	outputDefs map[string]*OutputDef
}

func (c resultDocCollector) HandleResultDocument(href string, doc *xdm.Document, outDef *OutputDef) error {
	// Key by the fully-resolved absolute output URI captured during execution
	// (SetURL on the result document), NOT the raw href. A nested
	// xsl:result-document resolves its href against the DYNAMIC current output
	// URI of the enclosing result document, not the top-level base output URI, so
	// re-resolving the raw href against the base here would key it wrongly.
	key := href

	if doc != nil {
		if u := doc.URL(); u != "" {
			key = u
		}
	}

	c.results[key] = doc
	if outDef != nil && c.outputDefs != nil {
		c.outputDefs[key] = outDef
	}

	return nil
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
	innerURIResolver xpath.URIResolver
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
		return nil, dynamicError(errCodeFOXT0004, "fn:transform: maximum recursion depth (%d) exceeded", maxTransformDepth)
	}

	ctx = context.WithValue(ctx, transformDepthKey{}, depth+1)

	if len(args) != 1 || args[0] == nil || xdm.SequenceLen(args[0]) != 1 {
		return nil, dynamicError(errCodeFOXT0001, "fn:transform requires a single map argument")
	}

	options, ok := args[0].Get(0).(xdm.MapItem)
	if !ok {
		return nil, dynamicError(errCodeFOXT0001, "fn:transform argument must be a map")
	}

	request := newTransformRequest(options, cfg.baseURI)
	if err := validateTransformOptions(options, request.deliveryFormat); err != nil {
		return nil, err
	}

	compiler, staticParams := transformStaticParameters(cfg.nestedCompiler, transformMapSeq(options, "static-params"))

	stylesheet, err := cfg.compileTransformStylesheet(ctx, compiler, request)
	if err != nil {
		return nil, err
	}

	if stylesheet == nil {
		return nil, dynamicError(errCodeFOXT0002, "fn:transform: no stylesheet specified (stylesheet-location, stylesheet-node, stylesheet-text, or package-name required)")
	}

	secondary := resultDocCollector{results: make(map[string]*xdm.Document), outputDefs: make(map[string]*OutputDef)}
	invocation := request.newInvocation(cfg, staticParams, secondary)
	source := request.prepareSource(invocation)

	resultDoc, err := executeTransform(ctx, source, stylesheet, invocation)
	if err != nil {
		return nil, err
	}

	result, err := request.deliver(resultDoc, invocation, stylesheet, secondary)
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
func lookuptransformCapabilities(key string) (bool, bool) {
	switch key {
	case nameIsSchemaAware, nameSupportsSerialization, textSupportsBackwardsCompatibility, nameSupportsNamespaceAxis, nameSupportsDynamicEvaluation, textSupportsHigherOrderFunctions:
		return true, true
	case nameSupportsStreaming:
		return false, true
	}

	var zero bool

	return zero, false
}

// validateTransformOptions enforces the fn:transform option-map constraints that
// are independent of the compiled stylesheet (F&O 3.1 §14.8.3): exactly one
// stylesheet source, mutually-exclusive invocation options, a legal
// delivery-format, correctly-typed option values, and satisfiable requested
// properties. The no-invocation check is applied post-compile in run(), because
// it depends on the presence of an xsl:initial-template default template.
func validateTransformOptions(m xdm.MapItem, deliveryFormat string) error {
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

	if transformOptionPresent(transformMapSeq(m, "source-node")) && transformOptionPresent(transformMapSeq(m, "initial-match-selection")) {
		return dynamicError(errCodeFOXT0002, "fn:transform: source-node and initial-match-selection are mutually exclusive")
	}

	switch deliveryFormat {
	case "", fnNameDocument, "serialized", lexicon.OutputRaw:
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

	return checkTransformCapabilities(transformMapSeq(m, "requested-properties"))
}

// validateTransformGlobalContextItem enforces that the global-context-item
// option, when the key is present in the map, holds EXACTLY ONE item (F&O 3.1
// §14.8: its required type is item()). A present-but-empty or multi-item value
// is an XPTY0004 type error — it must NOT be silently treated as absent or
// truncated to its first item. An omitted key is fine (the global context item
// then defaults to the source-node root, or is absent).
func validateTransformGlobalContextItem(m xdm.MapItem) error {
	seq, ok := m.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: "global-context-item"})
	if !ok {
		return nil
	}

	if seq == nil || xdm.SequenceLen(seq) != 1 {
		return dynamicError(errCodeXPTY0004, "fn:transform: global-context-item must be exactly one item")
	}

	return nil
}

// validateTransformXSLTVersion checks that the xslt-version option, when
// present, is a numeric value (an XPTY0004 type error otherwise).
func validateTransformXSLTVersion(m xdm.MapItem) error {
	seq := transformMapSeq(m, "xslt-version")
	if !transformOptionPresent(seq) {
		return nil
	}

	av, err := xpath.AtomizeItem(seq.Get(0))
	if err != nil {
		return dynamicError(errCodeXPTY0004, "fn:transform: xslt-version: %v", err)
	}

	if !av.IsNumeric() {
		return dynamicError(errCodeXPTY0004, "fn:transform: xslt-version must be a numeric value")
	}

	return nil
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
		return dynamicError(errCodeXPTY0004, "fn:transform: %s must be a map", name)
	}

	for _, key := range sm.Keys() {
		if key.TypeName != xdm.TypeQName {
			return dynamicError(errCodeFOXT0002, "fn:transform: %s keys must be supplied as QNames", name)
		}
	}

	return nil
}

// checkTransformCapabilities inspects the requested-properties option and raises
// FOXT0006 when a recognized XSLT-namespace property is requested with a value
// helium cannot satisfy. Non-map values are XPTY0004; properties outside the
// XSLT namespace, or ones helium does not model, are ignored.
func checkTransformCapabilities(seq xdm.Sequence) error {
	if !transformOptionPresent(seq) {
		return nil
	}

	sm, ok := seq.Get(0).(xdm.MapItem)
	if !ok {
		return dynamicError(errCodeXPTY0004, "fn:transform: requested-properties must be a map")
	}

	for _, key := range sm.Keys() {
		qv, ok := key.Value.(xdm.QNameValue)
		if !ok || qv.URI != lexicon.NamespaceXSLT {
			continue
		}

		want, known := lookuptransformCapabilities(qv.Local)
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
			return dynamicError(errCodeFOXT0006, "fn:transform: requested property %q cannot be satisfied", qv.Local)
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

func (cfg *transformFnConfig) compileTransformLocation(ctx context.Context, nestedCompiler Compiler, stylesheetLoc string) (*Stylesheet, error) {
	// Resolve relative to the current stylesheet base URI.
	loc := resolveStylesheetLocation(cfg.baseURI, stylesheetLoc)

	baseURI := loc

	if cfg.stylesheetResolver == nil {
		return nil, dynamicError(errCodeFOXT0003, "fn:transform: cannot read stylesheet %q: no URIResolver configured (filesystem access is opt-in)", stylesheetLoc)
	}

	rc, resolveErr := cfg.stylesheetResolver.Resolve(ctx, loc)
	if resolveErr != nil {
		return nil, dynamicError(errCodeFOXT0003, "fn:transform: cannot resolve stylesheet %q: %v", stylesheetLoc, resolveErr)
	}

	doc, parseErr := parseXMLResource(ctx, cfg.parseOptions, rc, baseURI, cfg.maxResourceBytes)
	if parseErr != nil {
		return nil, dynamicErrorCause(errCodeFOXT0003, parseErr, "fn:transform: cannot parse stylesheet %q: %v", stylesheetLoc, parseErr)
	}

	ss, compileErr := nestedCompiler.BaseURI(baseURI).Compile(ctx, doc)
	if compileErr != nil {
		return nil, dynamicErrorCause(errCodeFOXT0003, compileErr, "fn:transform: cannot compile stylesheet %q: %v", stylesheetLoc, compileErr)
	}

	return ss, nil
}

func (cfg *transformFnConfig) compileTransformPackage(ctx context.Context, nestedCompiler Compiler, packageName, packageVersion string) (*Stylesheet, error) {
	if !ParseVersionConstraint(packageVersion).valid {
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

	doc, parseErr := parseXMLResource(ctx, cfg.parseOptions, rc, location, cfg.maxResourceBytes)
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
		return nil, dynamicErrorCause(errCodeFOXT0003, compileErr, "fn:transform: cannot compile package %q: %v", packageName, compileErr)
	}

	return ss, nil
}

func (cfg *transformFnConfig) compileTransformText(ctx context.Context, nestedCompiler Compiler, stylesheetText, stylesheetBaseURI string) (*Stylesheet, error) {
	// stylesheet-text: the stylesheet source is supplied inline as a string.
	// Parse it and compile. The base URI comes from the stylesheet-base-uri
	// option when supplied (a relative value resolved against the call's
	// static base URI); otherwise it falls back to the call's static base URI.
	baseURI := cfg.baseURI
	if stylesheetBaseURI != "" {
		baseURI = resolveStylesheetLocation(cfg.baseURI, stylesheetBaseURI)
	}

	doc, parseErr := parseXMLReader(ctx, cfg.parseOptions, strings.NewReader(stylesheetText), baseURI, cfg.maxResourceBytes)
	if parseErr != nil {
		return nil, dynamicErrorCause(errCodeFOXT0003, parseErr, "fn:transform: cannot parse stylesheet-text: %v", parseErr)
	}

	compiler := nestedCompiler
	if baseURI != "" {
		compiler = compiler.BaseURI(baseURI)
	}

	ss, compileErr := compiler.Compile(ctx, doc)
	if compileErr != nil {
		return nil, dynamicErrorCause(errCodeFOXT0003, compileErr, "fn:transform: cannot compile stylesheet-text: %v", compileErr)
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

	owner := owningDocument(node.Node)
	if owner == nil {
		return nil, dynamicError(errCodeFOXT0003, "fn:transform: stylesheet-node is not part of a document")
	}

	baseURI := xdm.NodeGetBase(owner, node.Node)
	if stylesheetBaseURI != "" {
		baseURI = resolveStylesheetLocation(cfg.baseURI, stylesheetBaseURI)
	}

	compileDoc, err := stylesheetNodeCompileDocument(node.Node, owner)
	if err != nil {
		return nil, dynamicErrorCause(errCodeFOXT0003, err, "fn:transform: cannot prepare stylesheet node: %v", err)
	}

	if baseURI != "" {
		compiler = compiler.BaseURI(baseURI)
	}

	stylesheet, err := compiler.Compile(ctx, compileDoc)
	if err != nil {
		return nil, dynamicErrorCause(errCodeFOXT0003, err, "fn:transform: cannot compile stylesheet: %v", err)
	}

	return stylesheet, nil
}

// stylesheetNodeCompileDocument returns the document that fn:transform should
// compile for a stylesheet-node value. When n is an element that is not owner's
// document element (a simplified/literal-result stylesheet supplied as a
// fragment child, or an element nested in a larger tree), a fresh document is
// built with a deep copy of that element as its document element, so the element
// itself becomes the stylesheet root. Otherwise owner is compiled unchanged.
func stylesheetNodeCompileDocument(n xdm.Node, owner *xdm.Document) (*xdm.Document, error) {
	elem, ok := n.(*xdm.Element)
	if !ok {
		return owner, nil
	}

	if de := owner.DocumentElement(); de != nil && xdm.Node(de) == n {
		return owner, nil
	}

	doc := xdm.NewDefaultDocument()

	copied, err := xdm.CopyNode(elem, doc)
	if err != nil {
		return nil, err
	}

	if err := doc.AddChild(copied); err != nil {
		return nil, err
	}

	return doc, nil
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
		globalContextItem:     transformMapSeq(options, "global-context-item"),
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

func (request transformRequest) newInvocation(cfg *transformFnConfig, staticParamValues map[string]xdm.Sequence, secondary resultDocCollector) *transformConfig {
	outputBaseURI := request.baseOutputURI
	if outputBaseURI == "" {
		outputBaseURI = cfg.baseURI
	}

	invocation := &transformConfig{
		initialTemplate:  request.initialTemplate,
		initialMode:      request.initialMode,
		initialFunction:  request.initialFunction,
		baseOutputURI:    request.baseOutputURI,
		outputBaseURI:    outputBaseURI,
		resultDocHandler: secondary,
		uriResolver:      cfg.innerURIResolver,
		httpClient:       cfg.httpClient,
		maxResourceBytes: cfg.maxResourceBytes,
		parseOptions:     cfg.parseOptions,
		rawCapture:       request.deliveryFormat == lexicon.OutputRaw,
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

	if transformOptionPresent(request.initialMatchSelection) {
		if xdm.SequenceLen(request.initialMatchSelection) == 1 {
			if item, ok := request.initialMatchSelection.Get(0).(xdm.NodeItem); ok {
				if owner := owningDocument(item.Node); owner != nil {
					sourceDoc = owner
				}
			}
		}

		invocation.initialMatchSelection = request.initialMatchSelection
	} else if sourceNode != nil {
		if _, document := sourceNode.(*xdm.Document); !document {
			invocation.initialMatchSelection = request.sourceNode
		}
	}

	if sourceDoc == nil && invocation.globalContextItem == nil {
		invocation.globalContextAbsent = true
	}

	if sourceDoc == nil {
		sourceDoc = xdm.NewDefaultDocument()
	}

	return sourceDoc
}

func (request transformRequest) deliver(resultDoc *xdm.Document, fnTransformCfg *transformConfig, ss *Stylesheet, secondary resultDocCollector) (xdm.MapItem, error) {
	baseOutputURI := request.baseOutputURI
	deliveryFormat := request.deliveryFormat
	serializationParamsSeq := transformMapSeq(request.options, "serialization-params")
	secondaryResults := secondary.results
	secondaryOutputDefs := secondary.outputDefs
	capturedItems := fnTransformCfg.rawCapturedItems

	principalKey := xdm.AtomicValue{TypeName: xdm.TypeString, Value: nameOutput}
	if baseOutputURI != "" {
		principalKey = xdm.AtomicValue{TypeName: xdm.TypeString, Value: baseOutputURI}
	}

	result := xdm.MapItem{}

	switch deliveryFormat {
	case "raw":
		// Raw delivery: return the XDM items from the transformation. Merge DOM
		// children with any captured non-node items (function items, maps, etc.
		// that cannot be represented as DOM children).
		var seq xdm.ItemSlice
		for child := range xdm.Children(resultDoc) {
			seq = append(seq, xdm.NodeItem{Node: child})
		}

		if capturedItems != nil && xdm.SequenceLen(capturedItems) > 0 {
			seq = append(seq, xdm.Materialize(capturedItems)...)
		}

		if len(seq) > 0 {
			result = result.Put(principalKey, seq)
		}
		// Secondary results are returned as document nodes in raw mode.
		for uri, doc := range secondaryResults {
			result = result.Put(xdm.AtomicValue{TypeName: xdm.TypeString, Value: uri}, xdm.ItemSlice{xdm.NodeItem{Node: doc}})
		}
	case "serialized":
		// Serialized delivery: serialize the result document to a string. The
		// serialization-params option overrides the stylesheet's own xsl:output
		// parameters for the principal result.
		if documentHasChildren(resultDoc) {
			outDef := applySerializationParams(fnTransformCfg.resolvedOutputDef, serializationParamsSeq)

			s, serErr := serializeDeliveredResult(resultDoc, outDef)
			if serErr != nil {
				return xdm.MapItem{}, dynamicError(errCodeFOXT0003, "fn:transform: serialization error: %v", serErr)
			}

			result = result.Put(principalKey, xdm.SingleString(s))
		}
		// Serialize secondary results too.
		for uri, doc := range secondaryResults {
			outDef := secondaryOutputDefs[uri]
			if outDef == nil {
				outDef = ss.outputs[""]
			}

			s, serErr := serializeDeliveredResult(doc, outDef)
			if serErr != nil {
				return xdm.MapItem{}, dynamicError(errCodeFOXT0003, "fn:transform: serialization error: %v", serErr)
			}

			result = result.Put(xdm.AtomicValue{TypeName: xdm.TypeString, Value: uri}, xdm.SingleString(s))
		}
	default:
		// Default: return the result document
		if documentHasChildren(resultDoc) {
			result = result.Put(principalKey, xdm.ItemSlice{xdm.NodeItem{Node: resultDoc}})
		}

		for uri, doc := range secondaryResults {
			result = result.Put(xdm.AtomicValue{TypeName: xdm.TypeString, Value: uri}, xdm.ItemSlice{xdm.NodeItem{Node: doc}})
		}
	}

	return result, nil
}

// documentHasChildren reports whether doc has any child nodes, i.e. whether the
// transformation wrote any principal result content. An empty principal result
// tree yields no principal entry in the fn:transform result map (W3C bug 30209).
func documentHasChildren(doc *xdm.Document) bool {
	if doc == nil {
		return false
	}

	for range xdm.Children(doc) {
		return true
	}

	return false
}

// serializeDeliveredResult serializes doc to a string for the fn:transform
// "serialized" delivery format. SerializeResult disables xdm.XMLSerialization's
// per-document-child terminators on the direct XML path, so top-level text
// newlines returned here are result content and are preserved unless serializer
// indentation intentionally discards whitespace-only text because indentation
// is enabled and the result has an element child.
func serializeDeliveredResult(doc *xdm.Document, outDef *OutputDef) (string, error) {
	var buf bytes.Buffer
	if err := SerializeResult(&buf, doc, outDef); err != nil {
		return "", err
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

		if name == paramVersion {
			versionExplicit = true
		}

		val, ok := sm.Get(key)
		if !ok {
			continue
		}
		// A recognized parameter present with an empty-sequence value overrides
		// the inherited xsl:output value by resetting the parameter to its
		// serialization default (F&O 3.1 §14.8.3), leaving no
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
	if !versionExplicit && out.VersionRaw == "" && out.MethodExplicit && (out.Method == methodHTML || out.Method == methodXHTML) {
		out.Version = ""
	}

	return out
}

// resetSerializationParam resets a recognized serialization parameter (by local
// name) to its serialization default on out. An unrecognized name is ignored.
func resetSerializationParam(out *OutputDef, name string) {
	switch name {
	case paramMethod:
		out.Method = methodXML
		out.MethodExplicit = false
	case paramIndent:
		out.Indent = false
	case paramOmitXMLDeclaration:
		out.OmitDeclaration = false
		out.OmitDeclarationExplicit = false
	case paramByteOrderMark:
		out.ByteOrderMark = false
	case paramUndeclarePrefixes:
		out.UndeclarePrefixes = false
	case paramEncoding:
		out.Encoding = lexicon.EncodingUTF8U
	case paramVersion:
		out.Version = lexicon.XSLTVersion10
	case paramStandalone:
		out.Standalone = ""
	case paramMediaType:
		out.MediaType = ""
	case paramDoctypePublic:
		out.DoctypePublic = ""
	case paramDoctypeSystem:
		out.DoctypeSystem = ""
	case paramItemSeparator:
		out.ItemSeparator = nil
	case paramCDATASectionElements:
		out.CDATASections = nil
	case paramSuppressIndentation:
		out.SuppressIndentation = nil
	case paramUseCharacterMaps:
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
	case paramMethod:
		if s, ok := transformSeqString(val); ok {
			out.Method = s
			out.MethodExplicit = true
		}
	case paramIndent:
		if b, ok := transformSeqBool(val); ok {
			out.Indent = b
		}
	case paramOmitXMLDeclaration:
		if b, ok := transformSeqBool(val); ok {
			out.OmitDeclaration = b
			out.OmitDeclarationExplicit = true
		}
	case paramByteOrderMark:
		if b, ok := transformSeqBool(val); ok {
			out.ByteOrderMark = b
		}
	case paramUndeclarePrefixes:
		if b, ok := transformSeqBool(val); ok {
			out.UndeclarePrefixes = b
		}
	case paramEncoding:
		if s, ok := transformSeqString(val); ok {
			out.Encoding = s
		}
	case paramVersion:
		if s, ok := transformSeqString(val); ok {
			out.Version = s
		}
	case paramStandalone:
		if s, ok := transformSeqString(val); ok {
			out.Standalone = s
		}
	case paramMediaType:
		if s, ok := transformSeqString(val); ok {
			out.MediaType = s
		}
	case paramDoctypePublic:
		if s, ok := transformSeqString(val); ok {
			out.DoctypePublic = s
		}
	case paramDoctypeSystem:
		if s, ok := transformSeqString(val); ok {
			out.DoctypeSystem = s
		}
	case paramItemSeparator:
		if s, ok := transformSeqString(val); ok {
			out.ItemSeparator = &s
		}
	case paramCDATASectionElements:
		out.CDATASections = mergeSerializationQNames(out.CDATASections, val)
	case paramSuppressIndentation:
		out.SuppressIndentation = mergeSerializationQNames(out.SuppressIndentation, val)
	case paramUseCharacterMaps:
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
// replacing none of it (F&O 3.1 §14.8.3), skipping duplicates.
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
