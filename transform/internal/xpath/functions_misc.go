// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"math/big"
	"math/rand"
	"sort"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

func lookupFunctionsMisc(name string) (*builtinFunc, bool) {
	switch name {
	case "static-base-uri":
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnStaticBaseURI}, true
	case "default-collation":
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnDefaultCollation}, true
	case "available-environment-variables":
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnAvailableEnvVars}, true
	case "environment-variable":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnEnvironmentVariable}, true
	case "current-dateTime":
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnCurrentDateTime}, true
	case "current-date":
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnCurrentDate}, true
	case "current-time":
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnCurrentTime}, true
	case "implicit-timezone":
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnImplicitTimezone}, true
	case "default-language":
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnDefaultLanguage}, true
	case "random-number-generator":
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnRandomNumberGenerator}, true
	case nameLoadXQueryModule:
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnLoadXQueryModule}, true
	case "transform":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnTransform}, true
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

	return xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: xdm.TypeAnyURI,
		Value:    uri,
	}), nil
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
	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: now}), nil
}

func fnCurrentDate(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	now := currentTimeFromCtx(ctx)
	date := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

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

		s, _ := atomicToString(a)
		// Use string hash as seed for reproducibility
		for _, c := range s {
			seed = seed*31 + int64(c)
		}
	} else {
		seed = currentTimeFromCtx(ctx).UnixNano()
	}

	return xdm.ItemSlice{makeRNGMap(seed)}, nil
}

func makeRNGMap(seed int64) xdm.MapItem {
	rng := rand.New(rand.NewSource(seed))
	number := rng.Float64()

	nextFn := xdm.FunctionItem{
		Arity: 0,
		Name:  "next",
		Invoke: func(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
			nextSeed := rng.Int63()
			return xdm.ItemSlice{makeRNGMap(nextSeed)}, nil
		},
	}

	permuteFn := xdm.FunctionItem{
		Arity: 1,
		Name:  "permute",
		Invoke: func(_ context.Context, callArgs []xdm.Sequence) (xdm.Sequence, error) {
			seq := callArgs[0]
			perm := make(xdm.ItemSlice, xdm.SequenceLen(seq))
			copy(perm, xdm.Materialize(seq))

			localRng := rand.New(rand.NewSource(seed))

			sort.SliceStable(perm, func(i, j int) bool {
				return localRng.Intn(2) == 0
			})

			return perm, nil
		},
	}

	return xdm.NewMap([]xdm.MapEntry{
		{Key: xdm.AtomicValue{TypeName: xdm.TypeString, Value: nameNumber}, Value: xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(number)}}},
		{Key: xdm.AtomicValue{TypeName: xdm.TypeString, Value: "next"}, Value: xdm.ItemSlice{nextFn}},
		{Key: xdm.AtomicValue{TypeName: xdm.TypeString, Value: "permute"}, Value: xdm.ItemSlice{permuteFn}},
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
		Value:    "en",
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

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeDayTimeDuration, Value: d}), nil
}

func fnLoadXQueryModule(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	return nil, &xdm.Error{Code: "FOQM0006", Message: "the selected profile has no XQuery processor"}
}

func fnTransform(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	return nil, &xdm.Error{Code: errCodeFOER0000, Message: "fn:transform is not implemented"}
}
