package xslt

import (
	"context"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// InvocationResources is the live resource policy for one language invocation.
// Nil resolvers explicitly deny access; static language context remains captured
// by the compiled program or function value.
type InvocationResources struct {
	URIResolver      xpath.URIResolver
	Packages         PackageResolver
	Collections      xpath.CollectionResolver
	ParseOptions     xdm.ParseOptions
	MaxResourceBytes int64
}

type invocationResourcesKey struct{}

// WithInvocationResources supplies caller policy without retaining mutable
// execution caches or changing the lexical context of a saved function.
func WithInvocationResources(ctx context.Context, resources InvocationResources) context.Context {
	return context.WithValue(ctx, invocationResourcesKey{}, resources)
}

func invocationResources(ctx context.Context) (InvocationResources, bool) {
	resources, ok := ctx.Value(invocationResourcesKey{}).(InvocationResources)
	return resources, ok
}

func rebaseFunctionResources(ctx context.Context, cfg *transformConfig) {
	resources, ok := invocationResources(ctx)
	if !ok || cfg == nil {
		return
	}

	cfg.uriResolver = resources.URIResolver
	cfg.collectionResolver = resources.Collections
	cfg.maxResourceBytes = resources.MaxResourceBytes
	options := resources.ParseOptions
	cfg.parseOptions = &options
}

func (cfg *transformFnConfig) invocationConfig(ctx context.Context) *transformFnConfig {
	resources, ok := invocationResources(ctx)
	if !ok {
		return cfg
	}

	local := *cfg
	local.innerURIResolver = resources.URIResolver
	local.stylesheetResolver = resources.URIResolver
	local.packageResolver = resources.Packages
	local.collectionResolver = resources.Collections
	local.maxResourceBytes = resources.MaxResourceBytes
	options := resources.ParseOptions
	local.parseOptions = &options

	compiler := NewCompiler().MaxResourceBytes(local.maxResourceBytes).ParseOptions(options)
	if local.stylesheetResolver != nil {
		compiler = compiler.URIResolver(local.stylesheetResolver)
	}

	if local.packageResolver != nil {
		compiler = compiler.PackageResolver(local.packageResolver)
	}

	local.nestedCompiler = compiler

	return &local
}
