package transform

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/resource"
	"github.com/skarm/xmlsec/transform/internal/pattern"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

var (
	// ErrInput reports invalid API input or an invalid zero-value handle.
	ErrInput = errors.New("transform: invalid input")
	// ErrUnsupported reports an unsupported language version or optional feature.
	ErrUnsupported = errors.New("transform: unsupported feature")
	// ErrLimit reports exhaustion of an invocation's resource budget.
	ErrLimit = errors.New("transform: resource limit exceeded")
	// ErrResource reports unavailable or disallowed external resources.
	ErrResource = resource.ErrResource
)

// Limits bounds both XPath and XSLT. Zero fields select defaults; negative
// fields are invalid. MaxNodes also bounds intermediate sequences and trees.
type Limits struct {
	// MaxInputBytes bounds XML input and each resolved resource; the default is 8 MiB.
	MaxInputBytes int
	// MaxResourceBytes bounds aggregate external bytes per invocation; the default is 32 MiB.
	MaxResourceBytes int
	// MaxResources bounds external resource loads per invocation; the default is 128.
	MaxResources int
	// MaxProgramBytes bounds a program's source; the default is 64 KiB.
	MaxProgramBytes int
	// MaxOutputBytes bounds serialized output and intermediate value sizes;
	// the default is 8 MiB. Numeric magnitudes use binary bytes (at least one
	// per integer; decimals count numerator plus denominator). Evaluated numeric
	// occurrences and temporaries share the cumulative string/tree budget.
	// Preflight bounds can exceed reduced results; see docs/transforms.md.
	MaxOutputBytes int
	// MaxNodes bounds input trees and intermediate collections; the default is 100,000.
	MaxNodes int
	// MaxOperations bounds evaluation work; the default is 2,000,000 operations.
	MaxOperations int
	// MaxDepth bounds XML depth and evaluation recursion; the default is 128,
	// and values above 512 are rejected.
	MaxDepth int
	// Timeout bounds each compilation or invocation; the default is three seconds.
	// Zero selects that default and does not disable the deadline.
	Timeout time.Duration
}

// DefaultLimits returns an independent set of bounded defaults.
func DefaultLimits() Limits {
	return Limits{MaxInputBytes: 8 << 20, MaxResourceBytes: 32 << 20, MaxResources: 128, MaxProgramBytes: 64 << 10, MaxOutputBytes: 8 << 20, MaxNodes: 100_000, MaxOperations: 2_000_000, MaxDepth: 128, Timeout: 3 * time.Second}
}

// Config contains engine-wide policy. No implicit file or network access is
// performed. Resolver may be used concurrently and must honor its context.
type Config struct {
	Limits Limits
	// XMLSchemaVersion selects builtin datatype lexical rules and the regular
	// expression range grammar. Zero selects XMLSchema11. This does not enable
	// XML Schema validation or schema-aware XPath/XSLT.
	XMLSchemaVersion XMLSchemaVersion
	// EnableXSLTAssertions enables xsl:assert for direct XSLT invocations.
	// Nested fn:transform calls use their own enable-assertions option, default false.
	EnableXSLTAssertions bool
	// DisableXSLTDynamicEvaluation statically disables xsl:evaluate in compiled
	// stylesheets and nested transforms. xsl:fallback remains available.
	DisableXSLTDynamicEvaluation bool
	// AllowSingleByteEncodings permits ASCII-compatible IANA single-byte XML
	// encodings in addition to UTF-8/UTF-16. Raw and decoded bytes share the
	// input limit. Engine.Parse and the XMLDSig input profile remain DTD-free.
	AllowSingleByteEncodings bool
	// Functions registers application functions by expanded name. The registry
	// is copied; callbacks must honor context and support concurrent calls.
	Functions []Function
	// PackageResolver enables xsl:use-package. Nil disables package loading.
	PackageResolver PackageResolver
	// CollectionResolver supplies collection() and uri-collection(), including
	// the default collection. Nil leaves collections unavailable.
	CollectionResolver CollectionResolver
	// Resolver authorizes external byte resources. Nil disables resource access.
	Resolver Resolver
	// Environment supplies the environment-variable functions. The map is copied;
	// the process environment is never read implicitly.
	Environment map[string]string
	// AllowedPrograms enables exact XMLDSig 1.0 transform programs. It is an
	// application-owned allowlist, independent of registered Functions.
	AllowedPrograms []reference.Transform
}

// Resolver supplies application-approved resources for imports and URI functions.
// Implementations must support concurrent use and honor cancellation, including
// during reads. The engine closes every non-nil returned stream, even on error.
type Resolver = resource.Resolver

// ResolverFunc adapts a function to Resolver.
type ResolverFunc = resource.ResolverFunc

// Engine owns immutable policy and creates compiled programs.
// Its zero value is invalid; construct it with NewEngine.
type Engine struct {
	packages                      PackageResolver
	collections                   CollectionResolver
	functions                     map[xpath.QualifiedName]xpath.Function
	functionNames                 map[string]xpath.Function
	limits                        Limits
	resolver                      Resolver
	environment                   map[string]string
	v1                            *v1Processor
	xmlSchemaVersion              XMLSchemaVersion
	xsltAssertions                bool
	xsltDynamicEvaluationDisabled bool
	allowSingleByteEncodings      bool
}

// NewEngine validates policy and returns a reusable engine. Config{} is valid.
func NewEngine(config Config) (*Engine, error) {
	if config.XMLSchemaVersion == 0 {
		config.XMLSchemaVersion = XMLSchema11
	}

	if config.XMLSchemaVersion != XMLSchema10 && config.XMLSchemaVersion != XMLSchema11 {
		return nil, wrap("configure", ErrInput)
	}

	limits := config.Limits
	d := DefaultLimits()

	fields := []struct {
		value    *int
		fallback int
	}{{&limits.MaxInputBytes, d.MaxInputBytes}, {&limits.MaxResourceBytes, d.MaxResourceBytes}, {&limits.MaxResources, d.MaxResources}, {&limits.MaxProgramBytes, d.MaxProgramBytes}, {&limits.MaxOutputBytes, d.MaxOutputBytes}, {&limits.MaxNodes, d.MaxNodes}, {&limits.MaxOperations, d.MaxOperations}, {&limits.MaxDepth, d.MaxDepth}}
	for _, field := range fields {
		if *field.value < 0 {
			return nil, wrap("configure", ErrInput)
		}

		if *field.value == 0 {
			*field.value = field.fallback
		}
	}

	if limits.Timeout < 0 || limits.MaxDepth > 512 {
		return nil, wrap("configure", ErrInput)
	}

	if limits.Timeout == 0 {
		limits.Timeout = d.Timeout
	}

	if nilcheck.IsNil(config.Resolver) {
		config.Resolver = nil
	}

	e := &Engine{limits: limits, resolver: config.Resolver, environment: maps.Clone(config.Environment), allowSingleByteEncodings: config.AllowSingleByteEncodings, xmlSchemaVersion: config.XMLSchemaVersion, xsltAssertions: config.EnableXSLTAssertions, xsltDynamicEvaluationDisabled: config.DisableXSLTDynamicEvaluation}
	if !nilcheck.IsNil(config.CollectionResolver) {
		e.collections = config.CollectionResolver
	}

	if !nilcheck.IsNil(config.PackageResolver) {
		e.packages = config.PackageResolver
	}

	if err := e.registerFunctions(config.Functions); err != nil {
		return nil, wrap("configure", err)
	}

	if len(config.AllowedPrograms) > 0 {
		var err error

		e.v1, err = newV1Processor(e, config.AllowedPrograms)
		if err != nil {
			return nil, wrap("approve XMLDSig transforms", err)
		}
	}

	return e, nil
}

func wrap(operation string, err error) error {
	if err == nil {
		return nil
	}

	code := ""
	if xp, ok := errors.AsType[*xdm.Error](err); ok {
		code = xp.CodeQName().Local
	}

	if errors.Is(err, pattern.ErrLimit) || errors.Is(err, xpath.ErrBudget) || errors.Is(err, xpath.ErrOpLimit) || errors.Is(err, xpath.ErrRecursionLimit) || errors.Is(err, xpath.ErrNodeSetLimit) || errors.Is(err, document.ErrLimit) {
		err = errors.Join(ErrLimit, err)
	}

	return &Error{Operation: operation, Code: code, cause: err}
}

func (e *Engine) invocation(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if e == nil || e.limits.MaxNodes == 0 || ctx == nil {
		return nil, nil, ErrInput
	}

	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, e.limits.Timeout)
	ctx = xpath.WithFunctions(ctx, nil)
	ctx = context.WithValue(ctx, resourceBudgetKey{}, &resourceBudget{bytes: e.limits.MaxResourceBytes, loads: e.limits.MaxResources})
	ctx = xpath.WithEnvironment(ctx, e.environment)

	return xpath.WithBudget(ctx, e.limits.MaxOperations, e.limits.MaxNodes, e.limits.MaxOutputBytes, e.limits.MaxDepth), cancel, nil
}

func (e *Engine) parseOptions() xdm.ParseOptions {
	limits := document.DefaultLimits()
	limits.MaxBytes = e.limits.MaxInputBytes
	limits.MaxDepth = e.limits.MaxDepth
	limits.MaxNodes = e.limits.MaxNodes

	return xdm.ParseOptions{Limits: limits, AllowSingleByteEncodings: e.allowSingleByteEncodings, AllowRelativeNamespaces: true}
}

// Language parsing supports DTD semantics; security snapshots and approved
// XMLDSig transforms keep parseOptions' DTD-free input policy.
func (e *Engine) languageParseOptions() xdm.ParseOptions {
	options := e.parseOptions()
	options.AllowDTD = true
	options.DTDOpen = resourceAdapter{engine: e}.Resolve

	return options
}

// Error describes an operation and preserves the standard XPath/XSLT error
// code, when available. errors.Is also preserves cancellation and limit errors.
type Error struct {
	Operation string
	// Code is the local part of the XPath, XSLT or application error code,
	// or empty when none is available. CodeName also preserves its namespace.
	Code     string
	name     Name
	cause    error
	messages []Message
}

// Messages returns an owned copy of XSLT diagnostics emitted before failure.
// It exposes no partial primary or secondary result.
func (e *Error) Messages() []Message {
	if e == nil {
		return nil
	}

	return slices.Clone(e.messages)
}

// Error implements error.
func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("transform %s [%s]: %v", e.Operation, e.Code, e.cause)
	}

	return fmt.Sprintf("transform %s: %v", e.Operation, e.cause)
}

// Unwrap exposes the original cause.
func (e *Error) Unwrap() error { return e.cause }

// CodeName returns the expanded error QName, or a zero Name when no code exists.
// Standard codes use http://www.w3.org/2005/xqt-errors. Application errors may
// use another namespace, including the empty namespace.
func (e *Error) CodeName() Name {
	if e == nil || e.Code == "" {
		return Name{}
	}

	if e.name.Local != "" {
		return e.name
	}

	if detail, ok := errors.AsType[*xdm.Error](e.cause); ok {
		name := detail.CodeQName()
		if name.Local != "" {
			return Name{Space: name.URI, Local: name.Local}
		}
	}

	return Name{Space: xpath.NSErr, Local: e.Code}
}
