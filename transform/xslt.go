package transform

import (
	"context"
	"errors"
	"io"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xslt"
)

// XSLTVersion selects the stylesheet language. XSLT 3.0 uses XPath 3.1.
type XSLTVersion uint8

const (
	// XSLT10 selects XSLT 1.0 with XPath 1.0.
	XSLT10 XSLTVersion = 10
	// XSLT20 selects Basic XSLT 2.0 with XPath 2.0.
	XSLT20 XSLTVersion = 20
	// XSLT30 selects Basic XSLT 3.0 with XPath 3.1.
	XSLT30 XSLTVersion = 30
)

// ResultMode selects post-processing of principal and secondary XSLT values.
type ResultMode uint8

const (
	// ResultRaw preserves the raw XDM sequence, including types and node identity.
	ResultRaw ResultMode = iota
	// ResultDocument constructs document nodes through sequence normalization.
	ResultDocument
	// ResultDefault follows each output's effective build-tree setting. Without
	// an explicit setting, JSON/adaptive keep raw values; other methods build trees.
	ResultDefault
)

// XSLTOptions selects the static stylesheet context and language profile. A 1.x
// declaration uses XSLT 1.0 with forwards-compatible processing.
type XSLTOptions struct {
	// Version is checked against the stylesheet's declared profile.
	// Zero derives the profile from that declaration.
	Version XSLTVersion
	// ProcessorVersion selects the processor independently of the stylesheet's
	// effective version. Zero derives it from the principal declaration.
	ProcessorVersion XSLTVersion
	// BaseURI resolves relative stylesheet imports and includes.
	BaseURI string
	// StaticParameters binds static stylesheet parameters during compilation.
	// Values cannot be replaced through XSLTContext.Parameters.
	StaticParameters Bindings
}

// XSLTContext supplies invocation parameters and an optional named entry point.
// The zero value applies templates to the source in the default mode. A named
// template that needs no source can be called with a nil source document.
type XSLTContext struct {
	// Context supplies invocation time, timezone, language and trace output.
	Context DynamicContext
	// ResultMode defaults to ResultRaw. It affects Execute and all entry points;
	// serialized Transform output still follows the stylesheet's output settings.
	ResultMode ResultMode
	// ContextItem selects the global context independently of the source and
	// initial match selection. Nil uses the source document; a pointer to a zero
	// Value explicitly leaves the global context absent.
	ContextItem *Value
	// Parameters supplies global stylesheet parameters for this invocation.
	Parameters Bindings
	// InitialParameters supplies non-tunnel parameters to the initial template or mode.
	InitialParameters Bindings
	// TunnelParameters supplies tunnel parameters to the initial invocation.
	TunnelParameters Bindings
	// Template selects a named initial template. It is mutually exclusive with Mode.
	Template Name
	// Mode selects the initial mode; zero uses the stylesheet's default mode.
	Mode Name
	// BaseOutputURI resolves secondary result URIs. Without a base, relative
	// result URIs remain relative. No file is written implicitly.
	BaseOutputURI string
	selection     *Sequence
	function      Name
	arguments     []Sequence
}

// Stylesheet retains immutable compiled XSLT and supports concurrent transformations.
type Stylesheet struct {
	engine  *Engine
	native  *xslt.Stylesheet
	version XSLTVersion
}

// Version reports the selected processor language.
func (s *Stylesheet) Version() XSLTVersion {
	if s == nil {
		return 0
	}

	return s.version
}

// Transform runs a stylesheet with fresh parameters, budgets and output buffers.
// It returns no partial result if execution, serialization or any limit fails.
func (s *Stylesheet) Transform(ctx context.Context, d *Document, options XSLTContext) (*Output, error) {
	result, err := s.Execute(ctx, d, options)
	if err != nil {
		return nil, err
	}

	return result.Serialize(ctx)
}

// Write computes a complete Result, then serializes its primary output to w.
// Serialization uses the same incremental or buffered paths as Result.WriterTo.
// It returns the number of written bytes. Errors may leave partial output;
// the caller owns w and must discard that output. Secondary results are available
// through Execute and Result.WriteSecondary; this operation rejects secondary outputs.
func (s *Stylesheet) Write(ctx context.Context, w io.Writer, d *Document, options XSLTContext) (int64, error) {
	if nilcheck.IsNil(w) {
		return 0, wrap("write XSLT", ErrInput)
	}

	result, err := s.Execute(ctx, d, options)
	if err != nil {
		return 0, err
	}

	if len(result.native.Secondary) != 0 {
		return 0, wrap("write XSLT", ErrUnsupported)
	}

	return result.WriterTo(ctx).WriteTo(w)
}

func (s *Stylesheet) prepare(ctx context.Context, d *Document, options XSLTContext) (context.Context, context.CancelFunc, xslt.Invocation, *outputCollector, error) {
	if s == nil || s.native == nil {
		return nil, nil, xslt.Invocation{}, nil, wrap("transform XSLT", ErrInput)
	}

	if options.ResultMode > ResultDefault {
		return nil, nil, xslt.Invocation{}, nil, wrap("transform XSLT", ErrInput)
	}

	ctx, cancel, err := s.engine.invocation(ctx)
	if err != nil {
		return nil, nil, xslt.Invocation{}, nil, wrap("transform XSLT", err)
	}

	ctx = s.engine.languageContext(ctx)

	ctx, err = s.engine.dynamicContext(ctx, options.Context)
	if err != nil {
		cancel()
		return nil, nil, xslt.Invocation{}, nil, wrap("execute XSLT", err)
	}

	ready := false
	defer func() {
		if !ready {
			cancel()
		}
	}()

	if options.Template.Local != "" && options.Mode.Local != "" && s.version == XSLT20 {
		return nil, nil, xslt.Invocation{}, nil, xsltError("execute XSLT", &xdm.Error{Code: "XTDE0047", Message: "XSLT 2.0 invocation specifies both an initial mode and an initial template"})
	}

	if options.Template.Local != "" && options.Mode.Local != "" || options.function.Local != "" && (options.Template.Local != "" || options.Mode.Local != "" || len(options.InitialParameters) != 0 || len(options.TunnelParameters) != 0) {
		return nil, nil, xslt.Invocation{}, nil, wrap("transform XSLT", ErrInput)
	}

	bindings, err := nativeBindings(ctx, options.Parameters, s.engine.limits)
	if err != nil {
		return nil, nil, xslt.Invocation{}, nil, wrap("transform XSLT", err)
	}

	parameters := xslt.NewParameters()
	for name, value := range bindings {
		parameters.Set(name, value)
	}

	var source *xdm.Document

	if d != nil {
		if d.native == nil {
			return nil, nil, xslt.Invocation{}, nil, wrap("transform XSLT", ErrInput)
		}

		if err := checkInputDocument(ctx, d.native, s.engine.limits); err != nil {
			return nil, nil, xslt.Invocation{}, nil, wrap("transform XSLT", err)
		}

		source = d.native
	}

	invocation, err := s.initialInvocation(ctx, source, options)
	if err != nil {
		return nil, nil, xslt.Invocation{}, nil, err
	}

	output := &Output{Secondary: make(map[string][]byte)}
	collector := outputCollector{ctx: ctx, output: output, limit: s.engine.limits.MaxOutputBytes}

	invocation = invocation.CollectionResolver(s.engine.collectionResolver()).GlobalParameters(parameters).MessageHandler(&collector).TraceWriter(checkedTrace{ctx: ctx, writer: traceWriter(options.Context.TraceWriter)}).BaseOutputURI(options.BaseOutputURI)
	if s.engine.resolver != nil {
		invocation = invocation.URIResolver(resourceAdapter{engine: s.engine})
	}

	ready = true

	return ctx, cancel, invocation, &collector, nil
}

func traceWriter(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}

	return w
}

func (s *Stylesheet) initialInvocation(ctx context.Context, source *xdm.Document, options XSLTContext) (xslt.Invocation, error) {
	invocation := s.native.Transform(source)
	if options.Template.Local != "" {
		invocation = s.native.CallTemplate(expandedName(options.Template)).SourceDocument(source)
	}

	if options.Mode.Local != "" {
		invocation = invocation.Mode(expandedName(options.Mode))
	}

	if options.selection != nil {
		if options.Template.Local != "" || options.function.Local != "" {
			return xslt.Invocation{}, wrap("execute XSLT", ErrInput)
		}

		if err := checkSequence(ctx, options.selection.items, s.engine.limits, true); err != nil {
			return xslt.Invocation{}, wrap("execute XSLT", err)
		}

		items := options.selection.items
		if items == nil {
			items = xdm.ItemSlice{}
		}

		invocation = s.native.ApplyTemplates(source).Mode(expandedName(options.Mode)).Selection(items)
	}

	if options.function.Local != "" {
		var args []xdm.Sequence

		checker := sequenceChecker{ctx: ctx, limits: s.engine.limits, input: true}
		for _, argument := range options.arguments {
			if err := checker.walk(argument.items, 0); err != nil {
				return xslt.Invocation{}, wrap("execute XSLT", err)
			}

			args = append(args, xdm.CloneSequence(argument.items))
		}

		invocation = s.native.CallFunction(expandedName(options.function), args...).SourceDocument(source)
	}

	if options.ContextItem != nil {
		item := options.ContextItem.item
		if item != nil {
			if err := checkSequence(ctx, xdm.ItemSlice{item}, s.engine.limits, true); err != nil {
				return xslt.Invocation{}, wrap("execute XSLT", err)
			}

			item = xdm.CloneItem(item)
		}

		invocation = invocation.GlobalContextItem(item)
	}

	initial, err := nativeBindings(ctx, options.InitialParameters, s.engine.limits)
	if err != nil {
		return xslt.Invocation{}, wrap("execute XSLT", err)
	}

	for name, value := range initial {
		if options.Template.Local != "" {
			invocation = invocation.SetInitialTemplateParameter(name, value)
		} else {
			invocation = invocation.SetInitialModeParameter(name, value)
		}
	}

	tunnel, err := nativeBindings(ctx, options.TunnelParameters, s.engine.limits)
	if err != nil {
		return xslt.Invocation{}, wrap("execute XSLT", err)
	}

	for name, value := range tunnel {
		invocation = invocation.SetTunnelParameter(name, value)
	}

	return invocation, nil
}

// Message retains xsl:message output without publishing it to a global stream.
type Message struct {
	// Text is the serialized xsl:message content.
	Text string
	// Terminate reports whether the message requested termination.
	Terminate bool
}

// Output contains owned serialized primary and secondary result bytes and messages.
// The application receives secondary documents; serialization does not write files
// for them.
type Output struct {
	// Primary contains the owned serialized principal result bytes.
	Primary []byte
	// Secondary maps resolved result URIs to owned bytes. Entries never write files.
	Secondary map[string][]byte
	// Messages contains xsl:message output in execution order.
	Messages []Message
}

// CompileXSLT compiles a stylesheet under the same policy as CompileXPath.
func (e *Engine) CompileXSLT(ctx context.Context, source []byte, options XSLTOptions) (*Stylesheet, error) {
	ctx, cancel, err := e.invocation(ctx)
	if err != nil {
		return nil, wrap("compile XSLT", err)
	}
	defer cancel()

	ctx = e.languageContext(ctx)

	if len(source) > e.limits.MaxProgramBytes {
		return nil, wrap("compile XSLT", ErrLimit)
	}

	parse := e.languageParseOptions().WithByteLimit(int64(e.limits.MaxProgramBytes))
	parse.BaseURI = options.BaseURI

	native, err := parse.Parse(ctx, source)
	if err != nil {
		return nil, err
	}

	return e.compileStylesheet(ctx, native, options)
}

// CompileXSLTReader incrementally reads a stylesheet under the program byte limit.
// It does not close src. The compiled stylesheet can be reused concurrently.
func (e *Engine) CompileXSLTReader(ctx context.Context, src io.Reader, options XSLTOptions) (*Stylesheet, error) {
	ctx, cancel, err := e.invocation(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	if nilcheck.IsNil(src) {
		return nil, wrap("compile XSLT", ErrInput)
	}

	ctx = e.languageContext(ctx)
	parse := e.languageParseOptions().WithByteLimit(int64(e.limits.MaxProgramBytes))
	parse.BaseURI = options.BaseURI

	doc, err := parse.ParseReader(ctx, src)
	if err != nil {
		return nil, wrap("compile XSLT", err)
	}

	return e.compileStylesheet(ctx, doc, options)
}

func (e *Engine) compileStylesheet(ctx context.Context, doc *xdm.Document, options XSLTOptions) (*Stylesheet, error) {
	version, err := xslt.CheckProcessorLanguage(doc, int(options.Version), int(options.ProcessorVersion))
	if err != nil {
		return nil, xsltError("compile XSLT", err)
	}

	if len(options.StaticParameters) > 0 && version < 30 {
		return nil, wrap("compile XSLT", ErrUnsupported)
	}

	bindings, err := nativeBindings(ctx, options.StaticParameters, e.limits)
	if err != nil {
		return nil, wrap("compile XSLT", err)
	}

	parameters := xslt.NewParameters()
	for name, value := range bindings {
		parameters.Set(name, value)
	}

	compiler := xslt.NewCompiler().ProcessorVersion(version).ParseOptions(e.languageParseOptions()).BaseURI(options.BaseURI).StaticParameters(parameters).MaxResourceBytes(int64(e.limits.MaxInputBytes))
	if e.packages != nil {
		compiler = compiler.PackageResolver(packageAdapter{engine: e})
	}

	if e.resolver != nil {
		compiler = compiler.URIResolver(resourceAdapter{engine: e})
	}

	sheet, err := compiler.Compile(ctx, doc)
	if err != nil {
		return nil, xsltError("compile XSLT", err)
	}

	return &Stylesheet{engine: e, native: sheet, version: map[int]XSLTVersion{10: XSLT10, 20: XSLT20, 30: XSLT30}[version]}, nil
}

func xsltError(operation string, err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, xslt.ErrLanguageUnsupported) {
		err = errors.Join(ErrUnsupported, err)
	}

	code := ""

	if xs, ok := errors.AsType[*xslt.XSLTError](err); ok {
		code = xs.CodeQName().Local
	}

	if errors.Is(err, xslt.ErrResourceTooLarge) {
		err = errors.Join(ErrLimit, err)
	}

	result := wrap(operation, err)

	var wrapped *Error
	if errors.As(result, &wrapped) && code != "" {
		wrapped.Code = code

		if xs, ok := errors.AsType[*xslt.XSLTError](err); ok {
			name := xs.CodeQName()
			wrapped.name = Name{Space: name.URI, Local: name.Local}
		}
	}

	return result
}

type outputCollector struct {
	ctx    context.Context
	output *Output
	limit  int
	used   int
}

func (c *outputCollector) HandleMessage(text string, terminate bool) error {
	if len(text) > c.limit-c.used {
		return ErrLimit
	}

	c.used += len(text)
	c.output.Messages = append(c.output.Messages, Message{Text: text, Terminate: terminate})

	return c.ctx.Err()
}
