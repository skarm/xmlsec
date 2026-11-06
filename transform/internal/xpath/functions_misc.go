// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"hash/maphash"
	"math/big"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

//nolint:gochecknoglobals // One immutable process seed hashes canonical atomic values consistently.
var randomSeedHash = sync.OnceValue(maphash.MakeSeed)

// Dynamic-context accessors use standard local names. The RNG map keys are
// F&O result members; its number key has no XML Schema type-name role.
const (
	fnNameStaticBaseURI    = "static-base-uri"
	fnNameDefaultCollation = "default-collation"
	fnNameCurrentDate      = "current-date"
	fnNameCurrentTime      = "current-time"
	fnNameImplicitTimezone = "implicit-timezone"
	rngNumberKey           = "number"
	rngNextKey             = "next"
	rngPermuteKey          = "permute"
	errCodeFOQM0006        = "FOQM0006"
)

// Zero clock fields select civil midnight while retaining the implicit zone.
const currentDateMidnightField = 0

func lookupFunctionsMisc(name string) (*builtinFunc, bool) {
	switch name {
	case fnNameStaticBaseURI:
		return &builtinFunc{name: name, min: builtinArityZero, max: builtinArityZero, fn: fnStaticBaseURI}, true
	case fnNameDefaultCollation:
		return &builtinFunc{name: name, min: builtinArityZero, max: builtinArityZero, fn: fnDefaultCollation}, true
	case fnNameAvailableEnvironmentVariables:
		return &builtinFunc{name: name, min: builtinArityZero, max: builtinArityZero, fn: fnAvailableEnvVars}, true
	case fnNameEnvironmentVariable:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnEnvironmentVariable}, true
	case fnNameCurrentDateTime:
		return &builtinFunc{name: name, min: builtinArityZero, max: builtinArityZero, fn: fnCurrentDateTime}, true
	case fnNameCurrentDate:
		return &builtinFunc{name: name, min: builtinArityZero, max: builtinArityZero, fn: fnCurrentDate}, true
	case fnNameCurrentTime:
		return &builtinFunc{name: name, min: builtinArityZero, max: builtinArityZero, fn: fnCurrentTime}, true
	case fnNameImplicitTimezone:
		return &builtinFunc{name: name, min: builtinArityZero, max: builtinArityZero, fn: fnImplicitTimezone}, true
	case fnNameDefaultLanguage:
		return &builtinFunc{name: name, min: builtinArityZero, max: builtinArityZero, fn: fnDefaultLanguage}, true
	case fnNameRandomNumberGenerator:
		return &builtinFunc{name: name, min: builtinArityZero, max: builtinArityOne, fn: fnRandomNumberGenerator}, true
	case nameLoadXQueryModule:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityTwo, fn: fnLoadXQueryModule}, true
	case fnNameTransform:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnTransform}, true
	}

	return nil, false
}

func fnStaticBaseURI(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	if ec := getFnContext(ctx); ec != nil && ec.baseURI != "" {
		return xdm.SingleAtomic(xdm.AtomicValue{
			TypeName: xdm.TypeAnyURI,
			Value:    ec.baseURI,
		}), nil
	}

	return nil, nil
}

func fnDefaultCollation(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	uri := lexicon.CollationCodepoint
	if ec := getFnContext(ctx); ec != nil && ec.defaultCollation != "" {
		uri = ec.defaultCollation
	}

	return xdm.SingleString(uri), nil
}

func fnAvailableEnvVars(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	environment := environmentFrom(ctx)

	keys := make([]string, 0, len(environment))
	for name := range environment {
		keys = append(keys, name)
	}

	sort.Strings(keys)

	result := make(xdm.ItemSlice, len(keys))
	for i, name := range keys {
		result[i] = xdm.AtomicValue{TypeName: xdm.TypeString, Value: name}
	}

	return result, nil
}

func fnEnvironmentVariable(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	name, err := coerceArgToStringRequired(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if value, ok := environmentFrom(ctx)[name]; ok {
		return xdm.SingleString(value), nil
	}

	return nil, nil
}

func fnCurrentDateTime(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	now := currentTimeFromCtx(ctx)

	typeName := xdm.TypeDateTime
	if XMLSchemaVersion(ctx) == schemaEdition11 {
		typeName = xdm.TypeDateTimeStamp
	}

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: typeName, Value: now}), nil
}

func fnCurrentDate(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	now := currentTimeFromCtx(ctx)
	date := time.Date(now.Year(), now.Month(), now.Day(), currentDateMidnightField, currentDateMidnightField, currentDateMidnightField, currentDateMidnightField, now.Location())

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeDate, Value: date}), nil
}

func fnCurrentTime(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	now := currentTimeFromCtx(ctx)
	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeTime, Value: now}), nil
}

func currentTimeFromCtx(ctx context.Context) time.Time {
	if ec := getFnContext(ctx); ec != nil {
		return ec.getCurrentTime().In(ec.getImplicitTimezone())
	}

	return time.Now()
}

func fnRandomNumberGenerator(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	var seed int64

	if len(args) > 0 && xdm.SequenceLen(args[0]) > 0 {
		a, err := AtomizeItem(args[0].Get(0))
		if err != nil {
			return nil, err
		}

		seed = randomAtomicSeed(a)
	} else {
		seed = currentTimeFromCtx(ctx).UnixNano()
	}

	return xdm.ItemSlice{makeRNGMap(seed)}, nil
}

// Equal atomic seed values select equivalent generators. Timezone-optional
// types deliberately share a seed per dynamic type: their eq relation can use
// any implicit timezone, while the RNG itself must remain context-independent.
// Distinct seed values need not select distinct generators. dateTimeStamp has
// a mandatory timezone and retains value-sensitive canonical UTC hashing.
func randomAtomicSeed(value xdm.AtomicValue) int64 {
	switch xdm.PromoteSchemaType(value).TypeName {
	case xdm.TypeDateTime, xdm.TypeDate, xdm.TypeTime,
		xdm.TypeGYear, xdm.TypeGYearMonth, xdm.TypeGMonth, xdm.TypeGMonthDay, xdm.TypeGDay:
		return int64(maphash.Comparable(randomSeedHash(), value.TypeName)) // #nosec G115 -- Seed conversion intentionally preserves all 64 hash bits.
	default:
		return int64(maphash.Comparable(randomSeedHash(), xdm.NormalizeMapKey(value))) // #nosec G115 -- Seed conversion intentionally preserves all 64 hash bits.
	}
}

func makeRNGMap(seed int64) xdm.MapItem {
	rng := rand.New(rand.NewSource(seed)) // #nosec G404 -- XPath random-number-generator is reproducible and is not used for cryptographic keys or nonces.
	number := rng.Float64()
	nextSeed := rng.Int63()
	itemType := stItem(xdm.OccurrenceExactlyOne)
	itemsType := stItem(xdm.OccurrenceZeroOrMore)
	generatorType := xdm.SequenceType{ItemTest: xdm.MapTest{
		KeyType: stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne).ItemTest, ValType: itemType,
	}}

	nextFn := xdm.FunctionItem{
		Arity: builtinArityZero, ReturnType: &generatorType,
		Invoke: func(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
			return xdm.ItemSlice{makeRNGMap(nextSeed)}, nil
		},
	}

	permuteFn := xdm.FunctionItem{
		Arity: builtinArityOne, ParamTypes: []xdm.SequenceType{itemsType}, ReturnType: &itemsType,
		Invoke: func(ctx context.Context, callArgs []xdm.Sequence) (xdm.Sequence, error) {
			seq := callArgs[0]
			ec := getFnContext(ctx)

			length := xdm.SequenceLen(seq)
			if length > fnMaxNodes(ec) {
				return nil, ErrNodeSetLimit
			}

			if err := fnCountOps(ctx, ec, length); err != nil {
				return nil, err
			}

			perm := make(xdm.ItemSlice, length)
			for i := range length {
				if err := ctx.Err(); err != nil {
					return nil, err
				}

				perm[i] = seq.Get(i)
			}

			localRng := rand.New(rand.NewSource(seed)) // #nosec G404 -- XPath permutation repeats the generator seed; cryptographic randomness is not required.

			localRng.Shuffle(len(perm), func(i, j int) {
				perm[i], perm[j] = perm[j], perm[i]
			})

			return perm, ctx.Err()
		},
	}

	return xdm.NewMap([]xdm.MapEntry{
		{Key: xdm.AtomicValue{TypeName: xdm.TypeString, Value: rngNumberKey}, Value: xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(number)}}},
		{Key: xdm.AtomicValue{TypeName: xdm.TypeString, Value: rngNextKey}, Value: xdm.ItemSlice{nextFn}},
		{Key: xdm.AtomicValue{TypeName: xdm.TypeString, Value: rngPermuteKey}, Value: xdm.ItemSlice{permuteFn}},
	})
}

func fnDefaultLanguage(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	if ec := getFnContext(ctx); ec != nil {
		return xdm.SingleAtomic(xdm.AtomicValue{
			TypeName: xdm.TypeLanguage,
			Value:    ec.getDefaultLanguage(),
		}), nil
	}

	return xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: xdm.TypeLanguage,
		Value:    defaultFormattingLanguage,
	}), nil
}

func fnImplicitTimezone(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	var offset int
	if ec := getFnContext(ctx); ec != nil {
		_, offset = ec.getCurrentTime().In(ec.getImplicitTimezone()).Zone()
	} else {
		_, offset = time.Now().Zone()
	}

	absOffset := offset
	if offset < 0 {
		absOffset = -offset
	}
	// Carry the exact integer-second magnitude in SecRat so the timezone-duration
	// path is exact by construction (sign lives in Negative).
	d := xdm.Duration{
		Seconds: float64(absOffset),
		SecRat:  big.NewRat(int64(absOffset), 1),
	}
	if offset < 0 {
		d.Negative = true
	}

	return boundedDurationResult(ctx, xdm.AtomicValue{TypeName: xdm.TypeDayTimeDuration, Value: d})
}

func fnLoadXQueryModule(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	return nil, &xdm.Error{Code: errCodeFOQM0006, Message: "the selected profile has no XQuery processor"}
}

func fnTransform(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	return nil, &xdm.Error{Code: errCodeFOER0000, Message: "fn:transform is not implemented"}
}
