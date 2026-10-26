// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"net/url"

	"github.com/skarm/xmlsec/transform/internal/unparsedtext"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
)

// ContextBaseURI exposes the calling XPath static base to host functions. The
// presence flag distinguishes an absent base in an evaluation from no evaluator
// context, and preserves bases captured by named/lookup/partial function items.
func ContextBaseURI(ctx context.Context) (string, bool) {
	if ec := getFnContext(ctx); ec != nil {
		return ec.baseURI, true
	}

	return "", false
}

func baseURIFromContext(ctx context.Context) string {
	if ec := getFnContext(ctx); ec != nil {
		return ec.baseURI
	}

	return ""
}

func parseURIReference(raw string) (*url.URL, error) {
	if err := unparsedtext.ValidatePercentEncoding(raw); err != nil {
		return nil, err
	}

	return url.Parse(raw)
}

func resolveURIReference(base, ref string) (string, error) {
	return uripath.ResolveIRIReference(ref, base)
}
