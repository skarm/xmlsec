// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"errors"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	unparsedtext "github.com/skarm/xmlsec/transform/internal/xpath/text"
)

func lookupFunctionsUnparsedText(name string) (*builtinFunc, bool) {
	switch name {
	case fnNameUnparsedText:
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnUnparsedText}, true
	case fnNameUnparsedTextAvailable:
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnUnparsedTextAvailable}, true
	case nameUnparsedTextLines:
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnUnparsedTextLines}, true
	}

	return nil, false
}

func unparsedTextConfig(ctx context.Context) *unparsedtext.Config {
	ec := getFnContext(ctx)
	if ec == nil {
		return &unparsedtext.Config{
			BaseURI: baseURIFromContext(ctx),
		}
	}

	cfg := &unparsedtext.Config{
		BaseURI:    ec.baseURI,
		HTTPClient: ec.httpClient,
		MaxBytes:   ec.maxResourceBytes,
		CheckBytes: func(n int) error { return ChargeString(ctx, n) },
		ReadPolicy: ec.resourceReads,
	}
	if ec.uriResolver != nil {
		cfg.URIResolver = ec.uriResolver
	}

	return cfg
}

func wrapUnparsedTextError(err error) error {
	if err == nil {
		return nil
	}

	if ue, ok := errors.AsType[*unparsedtext.Error](err); ok {
		return &xdm.Error{Code: ue.Code, Message: ue.Message, Cause: err}
	}

	return err
}

func fnUnparsedText(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// xs:string? href: an atomized-empty argument (empty array / nilled node)
	// returns the empty sequence, like a syntactically empty one.
	href, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	encoding := ""
	if len(args) > 1 {
		encoding, err = coerceArgToString(ctx, args[1])
		if err != nil {
			return nil, err
		}
	}

	text, err := unparsedtext.LoadText(ctx, unparsedTextConfig(ctx), href, encoding)
	if err != nil {
		return nil, wrapUnparsedTextError(err)
	}

	return xdm.SingleString(text), nil
}

func fnUnparsedTextAvailable(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// An empty href (syntactic or atomized-empty) makes the resource
	// unavailable → false.
	href, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if empty {
		return xdm.SingleBoolean(false), nil
	}

	encoding := ""
	if len(args) > 1 {
		encoding, err = coerceArgToString(ctx, args[1])
		if err != nil {
			return nil, err
		}
	}

	available, err := unparsedtext.CheckAvailability(ctx, unparsedTextConfig(ctx), href, encoding)
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(available), nil
}

func fnUnparsedTextLines(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// xs:string? href: an atomized-empty argument returns the empty sequence,
	// like a syntactically empty one.
	href, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	encoding := ""
	if len(args) > 1 {
		encoding, err = coerceArgToString(ctx, args[1])
		if err != nil {
			return nil, err
		}
	}

	// Bound line production by the EFFECTIVE budget actually in force for this
	// call — the smaller of the node-set cap (maxNodes) and the remaining op
	// budget — so an OpLimit far below maxNodes stops splitting after ~OpLimit
	// lines instead of allocating a []string proportional to the resource's full
	// line count. LoadTextLinesBounded stops once limit+1 lines would be produced;
	// the +1 lets the op charge below detect the overflow precisely.
	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)
	limit := maxNodes
	opBounded := false

	if rem, bounded := fnRemainingOps(ec); bounded && rem < limit {
		limit = rem
		opBounded = true
	}
	// SplitLinesBounded treats limit <= 0 as "no bound"; a fully-exhausted op
	// budget (rem == 0) must still cap allocation, so floor the splitter bound at
	// 1. The op charge below then rejects the single produced line via ErrOpLimit.
	splitLimit := limit
	if opBounded && splitLimit < 1 {
		splitLimit = 1
	}

	lines, truncated, err := unparsedtext.LoadTextLinesBounded(ctx, unparsedTextConfig(ctx), href, encoding, splitLimit)
	if err != nil {
		return nil, wrapUnparsedTextError(err)
	}
	// Charge the produced lines against the op-counter (honoring cancellation)
	// BEFORE materializing one Item per line, matching how functions_array /
	// functions_map guard one-shot materialization. When the op budget is the
	// binding constraint this surfaces ErrOpLimit; truncation past the node-set
	// cap surfaces ErrNodeSetLimit.
	if err := fnCountOps(ctx, ec, len(lines)); err != nil {
		return nil, err
	}

	if truncated {
		return nil, ErrNodeSetLimit
	}

	result := make(xdm.ItemSlice, len(lines))
	for i, line := range lines {
		result[i] = xdm.AtomicValue{TypeName: xdm.TypeString, Value: line}
	}

	return result, nil
}
