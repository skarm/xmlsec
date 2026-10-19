package transform

import (
	"context"
	"io"
)

// PackageResource supplies stylesheet source and its base URI for relative imports.
type PackageResource struct {
	// Reader supplies package source. The engine closes it even when resolution
	// or compilation fails.
	Reader io.ReadCloser
	// BaseURI is the source document URI used to resolve relative imports.
	BaseURI string
}

// PackageResolver locates an application-approved XSLT package by name and
// version range. Package names are identifiers, not implicit resource URLs.
// Implementations must honor cancellation and support concurrent calls.
type PackageResolver interface {
	// ResolvePackage resolves a package name and package version range. The engine
	// owns the returned reader and closes it, including when resolution fails.
	ResolvePackage(context.Context, string, string) (PackageResource, error)
}

// PackageResolverFunc adapts an application callback to PackageResolver.
type PackageResolverFunc func(context.Context, string, string) (PackageResource, error)

// ResolvePackage calls f. A nil callback reports ErrResource.
func (f PackageResolverFunc) ResolvePackage(ctx context.Context, name, version string) (PackageResource, error) {
	if f == nil {
		return PackageResource{}, ErrResource
	}

	return f(ctx, name, version)
}

type packageAdapter struct{ engine *Engine }

func (a packageAdapter) ResolvePackage(ctx context.Context, name, version string) (io.ReadCloser, string, error) {
	var baseURI string

	reader, err := a.engine.openResource(ctx, a.engine.limits.MaxProgramBytes, func() (io.ReadCloser, error) {
		resource, err := a.engine.packages.ResolvePackage(ctx, name, version)
		baseURI = resource.BaseURI

		return resource.Reader, err
	})

	return reader, baseURI, err
}
