// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"errors"
	"strings"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/unparsedtext"
	"github.com/skarm/xmlsec/transform/internal/xdm"
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
		BaseURI: ec.baseURI,

		MaxBytes:       ec.maxResourceBytes,
		CheckBytes:     func(n int) error { return ChargeString(ctx, n) },
		ReadPolicy:     ec.resourceReads,
		ControlFailure: ControlFailure,
	}
	if ec.uriResolver != nil {
		cfg.URIResolver = ec.uriResolver
	}

	return cfg
}

type textSnapshotKey struct{}

type textResourceName struct {
	uri              string
	encoding         string
	explicitEncoding bool
	json             bool
}

type textResourceSnapshot struct {
	text         string
	rawBytes     int64
	decodedBytes int64
	oversized    bool
	err          error
}

type textSnapshotStore struct {
	values   map[textResourceName]*textResourceSnapshot
	retained int64
	limit    int64
}

type textResourceMode uint8

const (
	textResourceValue textResourceMode = iota
	textResourceAvailable
	textResourceLines
	textResourceJSON
)

func textResourceStore(ctx context.Context, ec *evalContext) *textSnapshotStore {
	cache, _ := InvocationState(ctx, textSnapshotKey{}, func() any {
		limit, _ := ctx.Value(textResourceCacheLimitKey{}).(int64)
		if limit <= 0 {
			if ec != nil {
				limit = ec.maxResourceBytes
			}

			if limit <= 0 {
				limit = unparsedtext.DefaultMaxBytes
			}
		}

		return &textSnapshotStore{values: make(map[textResourceName]*textResourceSnapshot), limit: limit}
	}).(*textSnapshotStore)

	return cache
}

func loadTextResource(ctx context.Context, href, encoding string, explicit bool, mode textResourceMode, lineLimit int, lineFailure error) (string, error) {
	if explicit && encoding == "" && mode != textResourceJSON {
		return "", &unparsedtext.Error{Code: unparsedtext.ErrCodeEncoding, Message: "empty encoding name"}
	}

	ec := getFnContext(ctx)
	cfg := unparsedTextConfig(ctx)

	uri, err := unparsedtext.ResolveURI(ctx, cfg, href)
	if err != nil {
		return "", err
	}

	key := textResourceName{uri: uri, encoding: encoding, explicitEncoding: explicit, json: mode == textResourceJSON}

	cache := textResourceStore(ctx, ec)
	if cached, found := cache.values[key]; found {
		return readTextResourceSnapshot(ctx, ec, cfg, key.uri, cached, mode)
	}
	// json-doc is defined through the default unparsed-text value, with
	// additional encoding/character domains. A successful compatible source
	// must agree in both directions, regardless of later JSON parse options.
	textKey := textResourceName{uri: uri}
	if mode == textResourceJSON {
		if cached, found := cache.values[textKey]; found && (cached.err == nil && !cached.oversized || sharedTextRetrievalFailure(cached.err)) {
			cache.values[key] = cached
			return readTextResourceSnapshot(ctx, ec, cfg, uri, cached, mode)
		}
	}

	if len(cache.values) >= fnMaxNodes(ec) {
		return "", ErrNodeSetLimit
	}

	entry, compatible := readTextResourceSource(ctx, cfg, uri, encoding, mode, lineLimit, lineFailure, cache.limit-cache.retained)
	if ControlFailure(ctx, entry.err) != nil || errors.Is(entry.err, tree.ErrLimit) {
		return "", entry.err
	}

	if _, policyFailure := errors.AsType[*xdm.ResourceAccessError](entry.err); policyFailure {
		return "", entry.err
	}

	if int64(len(entry.text)) > cache.limit-cache.retained {
		return "", ErrBudget
	}

	cache.retained += int64(len(entry.text))

	cache.values[key] = entry
	if mode == textResourceJSON && compatible && entry.err == nil {
		if _, exists := cache.values[textKey]; !exists {
			cache.values[textKey] = entry // One immutable string, not a second copy.
		}
	}

	if sharedTextRetrievalFailure(entry.err) {
		if mode == textResourceJSON {
			if _, exists := cache.values[textKey]; !exists {
				cache.values[textKey] = entry
			}
		} else if !explicit {
			jsonKey := textResourceName{uri: uri, json: true}
			if _, exists := cache.values[jsonKey]; !exists {
				cache.values[jsonKey] = entry
			}
		}
	}

	return entry.text, entry.err
}

func sharedTextRetrievalFailure(err error) bool {
	detail, ok := errors.AsType[*unparsedtext.Error](err)
	return ok && detail.Code == unparsedtext.ErrCodeRetrieval
}

func readTextResourceSnapshot(ctx context.Context, ec *evalContext, cfg *unparsedtext.Config, uri string, snapshot *textResourceSnapshot, mode textResourceMode) (string, error) {
	if err := fnCountOp(ctx, ec); err != nil {
		return "", err
	}

	maximum := cfg.MaxBytes
	if maximum == 0 {
		maximum = unparsedtext.DefaultMaxBytes
	}

	if maximum > 0 && (snapshot.rawBytes > maximum || snapshot.decodedBytes > maximum) {
		return "", ErrBudget
	}

	if ec != nil && ec.resourceReads != nil {
		if err := ec.resourceReads.CheckRead(ctx, uri); err != nil {
			return "", &xdm.ResourceAccessError{Cause: err}
		}

		if snapshot.err == nil {
			if err := ec.resourceReads.RecordRead(ctx, uri); err != nil {
				return "", &xdm.ResourceAccessError{Cause: err}
			}
		}
	}

	if snapshot.err != nil {
		return "", snapshot.err
	}

	if mode == textResourceAvailable {
		return "", nil
	}

	if snapshot.oversized {
		return "", ErrBudget
	}

	if mode != textResourceJSON {
		if err := ChargeString(ctx, len(snapshot.text)); err != nil {
			return "", err
		}
	}

	return snapshot.text, nil
}

func readTextResourceSource(ctx context.Context, cfg *unparsedtext.Config, uri, encoding string, mode textResourceMode, lineLimit int, lineFailure error, retentionLimit int64) (*textResourceSnapshot, bool) {
	entry := &textResourceSnapshot{}
	remaining := configureTextResourceRead(ctx, cfg, entry, mode, retentionLimit)

	var body strings.Builder

	discarded := false
	counter := textLineCounter{limit: lineLimit}
	consume := func(chunk []byte) error {
		if mode != textResourceJSON {
			entry.decodedBytes += int64(len(chunk))
		}

		if mode == textResourceLines && counter.write(chunk) {
			return lineFailure
		}

		if mode == textResourceAvailable {
			entry.oversized = remaining >= 0 && entry.decodedBytes > remaining
			if entry.oversized || entry.decodedBytes > retentionLimit {
				discarded = true

				body.Reset()
			}

			if discarded {
				return nil
			}
		} else if int64(len(chunk)) > retentionLimit-int64(body.Len()) {
			return ErrBudget
		}

		if body.Cap()-body.Len() < len(chunk) {
			body.Grow(max(len(chunk), body.Cap()))
		}

		_, err := body.Write(chunk)

		return err
	}

	compatible := false
	if mode == textResourceJSON {
		compatible, entry.err = unparsedtext.ReadJSONText(ctx, cfg, uri, consume)
	} else {
		entry.err = unparsedtext.ReadText(ctx, cfg, uri, encoding, consume)
	}

	if entry.err == nil && mode == textResourceLines && counter.finish() {
		entry.err = lineFailure
	}

	if entry.err == nil && discarded && !entry.oversized {
		entry.err = ErrBudget
	}

	if entry.err == nil && !entry.oversized {
		entry.text = body.String()
	}

	return entry, compatible
}

func configureTextResourceRead(ctx context.Context, cfg *unparsedtext.Config, entry *textResourceSnapshot, mode textResourceMode, retentionLimit int64) int64 {
	cfg.ReadBytes = func(n int) { entry.rawBytes += int64(n) }
	remaining := int64(-1)

	if mode == textResourceAvailable {
		cfg.CheckBytes = nil // A validation probe does not produce an XDM string.

		if budget := getBudget(ctx); budget != nil {
			remaining = int64(budget.bytes - budget.usedBytes)
		}
	}

	if mode == textResourceJSON {
		retained := int64(0)
		cfg.CheckBytes = func(n int) error {
			if int64(n) > retentionLimit-retained {
				return ErrBudget
			}

			retained += int64(n)

			return ctx.Err()
		}
		cfg.DecodedBytes = func(n int) { entry.decodedBytes += int64(n) }
	}

	return remaining
}

// textLineCounter detects line overflow while decoding, before the rest of the
// resource or an entire result string can be materialized.
type textLineCounter struct {
	limit  int
	lines  int
	skipLF bool
	tail   bool
}

func (c *textLineCounter) write(chunk []byte) bool {
	for _, value := range chunk {
		if c.skipLF {
			c.skipLF = false

			if value == '\n' {
				continue
			}
		}

		if value == '\r' || value == '\n' {
			c.lines++
			c.tail = false

			c.skipLF = value == '\r'
			if c.limit > 0 && c.lines > c.limit {
				return true
			}
		} else {
			c.tail = true
		}
	}

	return false
}

func (c *textLineCounter) finish() bool {
	return c.limit > 0 && c.tail && c.lines >= c.limit
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

	text, err := loadTextResource(ctx, href, encoding, len(args) > 1, textResourceValue, 0, nil)
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

	_, err = loadTextResource(ctx, href, encoding, len(args) > 1, textResourceAvailable, 0, nil)
	if ControlFailure(ctx, err) != nil || errors.Is(err, tree.ErrLimit) {
		return nil, err
	}

	if _, policyFailure := errors.AsType[*xdm.ResourceAccessError](err); policyFailure {
		return nil, err
	}

	return xdm.SingleBoolean(err == nil), nil
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

	lineFailure := ErrNodeSetLimit
	if opBounded {
		lineFailure = ErrOpLimit
	}

	body, err := loadTextResource(ctx, href, encoding, len(args) > 1, textResourceLines, splitLimit, lineFailure)
	lines, truncated := unparsedtext.SplitLinesBounded(body, splitLimit)

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
