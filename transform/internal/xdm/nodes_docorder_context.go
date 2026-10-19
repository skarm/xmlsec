// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import "context"

// WithDocOrderCache returns a context that makes cache available to XPath
// evaluators in this module. It is for internal callers that can guarantee the
// described documents are not mutated while the cache is reused.
func WithDocOrderCache(ctx context.Context, cache *DocOrderCache) context.Context {
	if cache == nil {
		return ctx
	}

	return context.WithValue(ctx, docOrderCacheContextKey{}, cache)
}

// DocOrderCacheFromContext returns the document-order cache carried by ctx.
func DocOrderCacheFromContext(ctx context.Context) *DocOrderCache {
	cache, _ := ctx.Value(docOrderCacheContextKey{}).(*DocOrderCache)
	return cache
}

type docOrderCacheContextKey struct{}
