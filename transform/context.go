package transform

import (
	"context"
	"io"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	lexicalpkg "github.com/skarm/xmlsec/transform/internal/xdm/lexical"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func (e *Engine) xpathDecimalFormats(ctx context.Context, evaluator xpath.Evaluator, formats map[Name]map[string]string, version XPathVersion) (xpath.Evaluator, error) {
	if len(formats) == 0 {
		return evaluator, nil
	}

	if version < XPath30 {
		return evaluator, ErrUnsupported
	}

	if len(formats) > e.limits.MaxNodes {
		return evaluator, ErrLimit
	}

	named := make(map[xpath.QualifiedName]xpath.DecimalFormat, len(formats))
	used := 0

	for name, properties := range formats {
		if err := ctx.Err(); err != nil {
			return evaluator, err
		}

		if name != (Name{}) && (!xpath.ValidNCName(name.Local) || !utf8.ValidString(name.Space)) {
			return evaluator, ErrInput
		}

		for _, length := range []int{len(name.Space), len(name.Local)} {
			if length > e.limits.MaxProgramBytes-used {
				return evaluator, ErrLimit
			}

			used += length
		}

		for property, v := range properties {
			for _, length := range []int{len(property), len(v)} {
				if length > e.limits.MaxProgramBytes-used {
					return evaluator, ErrLimit
				}

				used += length
			}
		}

		format, err := xpathDecimalFormat(properties)
		if err != nil {
			return evaluator, err
		}

		if name == (Name{}) {
			evaluator = evaluator.DefaultDecimalFormat(format)
		} else {
			named[xpath.QualifiedName{URI: name.Space, Name: name.Local}] = format
		}
	}

	return evaluator.NamedDecimalFormats(named), nil
}

func xpathDecimalFormat(properties map[string]string) (xpath.DecimalFormat, error) {
	format := xpath.DefaultDecimalFormat()
	characters := map[string]*rune{
		"decimal-separator":  &format.DecimalSeparator,
		"grouping-separator": &format.GroupingSeparator,
		"minus-sign":         &format.MinusSign,
		"percent":            &format.Percent,
		"per-mille":          &format.PerMille,
		"zero-digit":         &format.ZeroDigit,
		"digit":              &format.Digit,
		"pattern-separator":  &format.PatternSeparator,
		"exponent-separator": &format.ExponentSeparator,
	}

	for property, v := range properties {
		if !utf8.ValidString(v) {
			return format, ErrInput
		}

		if character := characters[property]; character != nil {
			if utf8.RuneCountInString(v) != 1 {
				return format, ErrInput
			}

			*character, _ = utf8.DecodeRuneInString(v)
		} else {
			switch property {
			case "infinity":
				format.Infinity = v
			case "NaN":
				format.NaN = v
			default:
				return format, ErrInput
			}
		}
	}

	if !xpath.DecimalZeroDigit(format.ZeroDigit) {
		return format, ErrInput
	}

	seen := make(map[rune]struct{})
	for digit := format.ZeroDigit; digit < format.ZeroDigit+10; digit++ {
		seen[digit] = struct{}{}
	}

	for _, character := range []rune{format.DecimalSeparator, format.GroupingSeparator, format.Percent, format.PerMille, format.Digit, format.PatternSeparator, format.ExponentSeparator} {
		if _, duplicate := seen[character]; duplicate {
			return format, ErrInput
		}

		seen[character] = struct{}{}
	}

	return format, nil
}

// DynamicContext supplies shared XPath and XSLT execution settings.
// The current time and implicit timezone are fixed for each invocation.
type DynamicContext struct {
	// CurrentTime is shared by all current-date/time calls in one invocation.
	// Zero samples the clock once at invocation start, in UTC.
	CurrentTime time.Time
	// ImplicitTimezone defaults to CurrentTime.Location(). Its offset at the
	// invocation time must be a whole minute within -14 to +14 hours.
	ImplicitTimezone *time.Location
	// DefaultLanguage is an xs:language value; XML whitespace is collapsed.
	// Empty selects the default language, en.
	DefaultLanguage string
	// TraceWriter receives XPath trace and XSLT trace output. Nil discards it.
	// The caller owns the writer and synchronizes concurrent invocations.
	TraceWriter io.Writer
}

// CollectionResolver supplies immutable collections and their member URIs.
// Callbacks must honor context and support concurrent use. Empty URI identifies
// the default collection; no implicit collection is provided by the engine.
type CollectionResolver interface {
	// ResolveCollection returns the members of collection(uri).
	// An empty URI requests the default collection.
	ResolveCollection(context.Context, string) (Sequence, error)
	// ResolveURICollection returns the member URIs of uri-collection(uri).
	// An empty URI requests the default URI collection.
	ResolveURICollection(context.Context, string) ([]string, error)
}

func (e *Engine) dynamicContext(ctx context.Context, options DynamicContext) (context.Context, error) {
	language := options.DefaultLanguage
	if language != "" {
		language = xmlchar.CollapseSpace(language)
		if !lexicalpkg.ValidLanguage(language) {
			return nil, ErrInput
		}
	}

	now := options.CurrentTime
	if now.IsZero() {
		now = time.Now().UTC()
	}

	zone := options.ImplicitTimezone
	if zone == nil {
		zone = now.Location()
	}

	_, offset := now.In(zone).Zone()
	if offset%60 != 0 || offset < -14*60*60 || offset > 14*60*60 {
		return nil, ErrInput
	}

	zone = time.FixedZone("", offset)
	now = now.In(zone)

	return xpath.WithEvaluationContext(ctx, xpath.EvaluationContext{CurrentTime: now, Timezone: zone, Language: language, Trace: checkedTrace{ctx: ctx, writer: traceWriter(options.TraceWriter)}, Collections: e.collectionResolver()}), nil
}

func (e *Engine) collectionResolver() xpath.CollectionResolver {
	if e.collections == nil {
		return nil
	}

	return collectionAdapter{engine: e}
}

type checkedTrace struct {
	ctx    context.Context
	writer io.Writer
}

func (w checkedTrace) Write(p []byte) (int, error) {
	if err := xpath.ChargeString(w.ctx, len(p)); err != nil {
		return 0, err
	}

	n, err := w.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}

	return n, err
}

type collectionAdapter struct{ engine *Engine }

func (a collectionAdapter) ResolveCollection(ctx context.Context, uri string) (xdm.Sequence, error) {
	if err := xpath.Charge(ctx, 1); err != nil {
		return nil, err
	}

	seq, err := a.engine.collections.ResolveCollection(ctx, uri)
	if err != nil {
		return nil, err
	}

	if err := checkSequence(ctx, seq.items, a.engine.limits, true); err != nil {
		return nil, err
	}

	if err := xpath.Charge(ctx, seq.Len()); err != nil {
		return nil, err
	}

	return xdm.CloneSequence(seq.items), nil
}

func (a collectionAdapter) ResolveURICollection(ctx context.Context, uri string) ([]string, error) {
	if err := xpath.Charge(ctx, 1); err != nil {
		return nil, err
	}

	values, err := a.engine.collections.ResolveURICollection(ctx, uri)
	if err != nil {
		return nil, err
	}

	if len(values) > a.engine.limits.MaxNodes {
		return nil, ErrLimit
	}

	for _, v := range values {
		if err := xpath.ChargeString(ctx, len(v)); err != nil {
			return nil, err
		}
	}

	return slices.Clone(values), ctx.Err()
}
