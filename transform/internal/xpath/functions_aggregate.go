// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func lookupFunctionsAggregate(name string) (*builtinFunc, bool) {
	switch name {
	case fnNameCount:
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnCount}, true
	case "avg":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnAvg}, true
	case "max":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnMax}, true
	case "min":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnMin}, true
	case nameSum:
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnSum}, true
	case "distinct-values":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnDistinctValues}, true
	}

	return nil, false
}

func fnCount(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return xdm.SingleInteger(int64(xdm.SequenceLen(args[0]))), nil
}

// aggregateTypeFamily classifies an atomic value for aggregate type checking.
// A schema-derived value (e.g. a restriction of xs:dayTimeDuration) carries a
// custom TypeName whose BaseType names the built-in ancestor; classify on the
// effective built-in type so the duration/numeric/string families recognize it.
func aggregateTypeFamily(a xdm.AtomicValue) string {
	if family := aggregateTypeFamilyByName(a.TypeName); family != "" {
		return family
	}

	if a.BaseType != "" && xdm.IsKnownXSDType(a.BaseType) {
		return aggregateTypeFamilyByName(a.BaseType)
	}

	return ""
}

func aggregateTypeFamilyByName(typeName string) string {
	if xdm.IsIntegerDerived(typeName) {
		return xdm.FamilyNumeric
	}

	if xdm.IsStringDerived(typeName) {
		return lexicon.TypeString
	}

	switch typeName {
	case xdm.TypeDecimal, xdm.TypeDouble, xdm.TypeFloat:
		return xdm.FamilyNumeric
	case xdm.TypeUntypedAtomic:
		return xdm.FamilyNumeric // untypedAtomic promotes to double
	case xdm.TypeString, xdm.TypeAnyURI:
		return lexicon.TypeString
	case xdm.TypeYearMonthDuration:
		return xdm.FamilyDurationYM
	case xdm.TypeDayTimeDuration:
		return xdm.FamilyDurationDT
	case xdm.TypeDuration:
		return lexicon.TypeDuration
	case xdm.TypeDate:
		return lexicon.TypeDate
	case xdm.TypeDateTime, xdm.TypeDateTimeStamp:
		return lexicon.TypeDateTime
	case xdm.TypeTime:
		return lexicon.TypeTime
	case xdm.TypeBoolean:
		return lexicon.TypeBoolean
	case xdm.TypeBase64Binary:
		return lexicon.TypeBase64Binary
	case xdm.TypeHexBinary:
		return lexicon.TypeHexBinary
	}

	return ""
}

// resolveCollationArg resolves the optional collation argument at args[idx].
// Returns nil collation (use default) if the argument is absent or is the
// codepoint collation.
func resolveCollationArg(ctx context.Context, args []xdm.Sequence, idx int) (*collationImpl, error) {
	if len(args) <= idx || xdm.SequenceLen(args[idx]) == 0 {
		return nil, nil
	}

	uri, err := coerceArgToString(ctx, args[idx])
	if err != nil {
		return nil, err
	}

	if uri == lexicon.CollationCodepoint {
		return nil, nil
	}

	return resolveContextCollation(ctx, uri, "")
}

// validateCollationArg checks if the collation argument at args[idx] is supported.
func validateCollationArg(ctx context.Context, args []xdm.Sequence, idx int) error {
	_, err := resolveCollationArg(ctx, args, idx)
	return err
}

func fnAvg(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	atoms, err := AtomizeSequence(args[0])
	if err != nil {
		return nil, err
	}

	if len(atoms) == 0 {
		return nil, nil
	}

	var family string

	allDecOrInt := true
	sumRat := new(big.Rat)

	var sumFloat float64

	widest, err := prepareAggregateNumericValues(ctx, atoms)
	if err != nil {
		return nil, err
	}

	for i, a := range atoms {
		// Charge bounded batches before work; exact arithmetic below also
		// checks cancellation at every math/big operation.
		if i%64 == 0 {
			if err := Charge(ctx, min(64, len(atoms)-i)); err != nil {
				return nil, err
			}
		}

		a, err = promoteForAggregate(ctx, a)
		if err != nil {
			return nil, err
		}

		if err := checkSumAvgType(a); err != nil {
			return nil, err
		}

		newFamily := aggregateTypeFamily(a)

		family, err = checkAggregateHomogeneity(family, newFamily)
		if err != nil {
			return nil, err
		}

		if numericTypeWidth(a.TypeName) > numericTypeWidth(widest) {
			widest = a.TypeName
		}

		term, exact, err := addAverageNumber(ctx, sumRat, a, widest)
		if err != nil {
			return nil, err
		}

		allDecOrInt = allDecOrInt && exact

		sumFloat = addAverageFloat(sumFloat, term, widest)
	}

	if family == xdm.FamilyDurationYM || family == xdm.FamilyDurationDT {
		atomSeq := make(xdm.ItemSlice, len(atoms))
		for i, a := range atoms {
			atomSeq[i] = a
		}

		return avgDurations(ctx, atomSeq, family)
	}

	count := len(atoms)
	if allDecOrInt {
		// avg returns decimal for integer/decimal inputs
		countRat := new(big.Rat).SetInt64(int64(count))
		if err := preflightDecimal(ctx, TokenDiv, sumRat, countRat); err != nil {
			return nil, err
		}

		return decimalQuotient(ctx, new(big.Rat).Quo(sumRat, countRat))
	}
	// Float/double path
	avg := sumFloat / float64(count)
	if widest == xdm.TypeFloat {
		return xdm.SingleFloat(float64(float32(sumFloat) / float32(count))), nil
	}

	return xdm.SingleDouble(avg), nil
}

func addAverageFloat(sum, term float64, widest string) float64 {
	if widest == xdm.TypeFloat {
		return float64(float32(sum) + float32(term))
	}

	return sum + term
}

func addAverageNumber(ctx context.Context, sum *big.Rat, value xdm.AtomicValue, widest string) (float64, bool, error) {
	exact := xdm.IsIntegerDerived(value.TypeName) || value.TypeName == xdm.TypeDecimal
	if exact {
		term := toRat(value)
		if err := preflightDecimal(ctx, TokenPlus, sum, term); err != nil {
			return 0, false, err
		}

		sum.Add(sum, term)

		if err := ChargeNumber(ctx, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: sum}); err != nil {
			return 0, false, err
		}
	}

	if widest == xdm.TypeFloat {
		return float64(numericToFloat32(value)), exact, nil
	}

	return value.ToFloat64(), exact, nil
}

func prepareAggregateNumericValues(ctx context.Context, atoms []xdm.AtomicValue) (string, error) {
	widest := xdm.TypeInteger

	for i, original := range atoms {
		if err := Charge(ctx, 1); err != nil {
			return "", err
		}

		value, err := promoteForAggregate(ctx, original)
		if err != nil {
			return "", err
		}

		atoms[i] = value
		if numericTypeWidth(value.TypeName) > numericTypeWidth(widest) {
			widest = value.TypeName
		}
	}

	return widest, nil
}

func avgDurations(ctx context.Context, seq xdm.Sequence, family string) (xdm.Sequence, error) {
	count := xdm.SequenceLen(seq)

	if family == xdm.FamilyDurationDT {
		// Sum and divide dayTime seconds EXACTLY so large or fractional averages
		// canonicalize precisely (matching the duration*number path).
		totalSecs := new(big.Rat)

		for item := range xdm.SequenceItems(seq) {
			a, _ := AtomizeItem(item)
			totalSecs.Add(totalSecs, xdm.DurationToRat(a.DurationVal(), false))
		}

		avgSecs, err := finiteDecimalValue(ctx, new(big.Rat).Quo(totalSecs, new(big.Rat).SetInt64(int64(count))))
		if err != nil {
			return nil, err
		}

		negative := avgSecs.Sign() < 0

		absSecs := avgSecs
		if negative {
			absSecs = new(big.Rat).Neg(avgSecs)
		}

		secs, frac := durationFromRatSeconds(absSecs)

		return xdm.SingleAtomic(xdm.AtomicValue{
			TypeName: xdm.TypeDayTimeDuration,
			Value:    xdm.Duration{Seconds: secs, FracSec: frac, SecRat: absSecs, Negative: negative},
		}), nil
	}

	totalMonths := new(big.Int)

	for item := range xdm.SequenceItems(seq) {
		a, _ := AtomizeItem(item)

		d := a.DurationVal()
		if d.Negative {
			totalMonths.Sub(totalMonths, big.NewInt(int64(d.Months)))
		} else {
			totalMonths.Add(totalMonths, big.NewInt(int64(d.Months)))
		}
	}
	// fn:avg is defined as fn:sum(...) div count, so the intermediate sum must
	// itself be a representable yearMonthDuration. Reject a month total that
	// overflows the value space (matching op:add-yearMonthDurations) before
	// dividing.
	if !totalMonths.IsInt64() {
		return nil, &xdm.Error{Code: errCodeFODT0002, Message: textDurationOverflow}
	}
	// Divide the exact month total by the count using rational arithmetic so
	// large totals (e.g. avg of two P9007199254740993M values) keep full
	// precision instead of losing a month through a float64 round-trip. Per
	// XPath F&O the result is rounded "half towards positive infinity", matching
	// op:divide-yearMonthDuration behavior.
	avgRat := new(big.Rat).SetFrac(totalMonths, big.NewInt(int64(count)))
	rounded := ratRound(avgRat)
	avgInt := new(big.Int).Quo(rounded.Num(), rounded.Denom())

	negative := avgInt.Sign() < 0

	absInt := avgInt
	if negative {
		absInt = new(big.Int).Neg(avgInt)
	}

	if !absInt.IsInt64() || absInt.Int64() > int64(math.MaxInt) {
		return nil, &xdm.Error{Code: errCodeFODT0002, Message: textDurationOverflow}
	}

	return xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: xdm.TypeYearMonthDuration,
		Value:    xdm.Duration{Months: int(absInt.Int64()), Negative: negative},
	}), nil
}

// promoteForAggregate promotes an atomic value for aggregate operations.
func promoteForAggregate(ctx context.Context, a xdm.AtomicValue) (xdm.AtomicValue, error) {
	if a.TypeName == xdm.TypeDecimal {
		if s, ok := a.Value.(string); ok {
			dec, err := CastFromStringContext(ctx, s, xdm.TypeDecimal)
			if err != nil {
				return xdm.AtomicValue{}, err
			}

			return dec, nil
		}
	}

	if a.TypeName == xdm.TypeUntypedAtomic {
		f, err := CastAtomicContext(ctx, a, xdm.TypeDouble)
		if err != nil {
			return xdm.AtomicValue{}, err
		}

		return f, nil
	}

	if xdm.IsIntegerDerived(a.TypeName) && a.TypeName != xdm.TypeInteger {
		return xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: a.Value}, nil
	}
	// User-defined schema types: prefer the value's built-in BaseType when it
	// names a known XSD type (so e.g. xs:float width is preserved), otherwise
	// promote based on the underlying Go value.
	if !xdm.IsKnownXSDType(a.TypeName) && a.TypeName != "" {
		if a.BaseType != "" && xdm.IsKnownXSDType(a.BaseType) {
			return xdm.PromoteSchemaType(a), nil
		}

		switch a.Value.(type) {
		case int64, *big.Int:
			return xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: a.Value}, nil
		case *big.Rat:
			return xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: a.BigRat()}, nil
		case float64, *xdm.FloatValue:
			return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: a.Value}, nil
		case float32:
			return xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: a.Value}, nil
		}
	}

	return a, nil
}

func numericTypeWidth(typeName string) int {
	switch typeName {
	case xdm.TypeDouble:
		return 4
	case xdm.TypeFloat:
		return 3
	case xdm.TypeDecimal:
		return 2
	default:
		return 1
	}
}

func fnMax(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	atoms, err := AtomizeSequence(args[0])
	if err != nil {
		return nil, err
	}

	if len(atoms) == 0 {
		return nil, nil
	}

	coll, err := getCollation(ctx, args, 1)
	if err != nil {
		return nil, err
	}

	if coll.isCodepoint() {
		coll = nil
	}

	return maxMinCommon(ctx, atoms, true, coll)
}

func fnMin(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	atoms, err := AtomizeSequence(args[0])
	if err != nil {
		return nil, err
	}

	if len(atoms) == 0 {
		return nil, nil
	}

	coll, err := getCollation(ctx, args, 1)
	if err != nil {
		return nil, err
	}

	if coll.isCodepoint() {
		coll = nil
	}

	return maxMinCommon(ctx, atoms, false, coll)
}

func maxMinCommon(ctx context.Context, atoms []xdm.AtomicValue, isMax bool, coll *collationImpl) (xdm.Sequence, error) {
	fnName := "fn:min"
	if isMax {
		fnName = "fn:max"
	}

	if len(atoms) == 1 {
		return maxMinSingle(ctx, atoms[0], fnName)
	}

	state := maxMinAccumulator{fnName: fnName, isMax: isMax, coll: coll, widest: xdm.TypeInteger, first: true}
	if ec := getFnContext(ctx); ec != nil {
		state.implicitTZ = ec.getImplicitTimezone()
	}

	for _, original := range atoms {
		if err := state.add(ctx, original); err != nil {
			return nil, err
		}
	}

	return state.result(), nil
}

func maxMinSingle(ctx context.Context, value xdm.AtomicValue, fnName string) (xdm.Sequence, error) {
	// Validate the single item while retaining derived types.
	if value.TypeName == xdm.TypeUntypedAtomic {
		var err error

		value, err = promoteForAggregate(ctx, value)
		if err != nil {
			return nil, err
		}
	}

	if _, err := maxMinTypeFamily(ctx, value, fnName); err != nil {
		return nil, err
	}

	return xdm.SingleAtomic(value), nil
}

type maxMinAccumulator struct {
	fnName          string
	isMax           bool
	coll            *collationImpl
	implicitTZ      *time.Location
	family          string
	best, bestOrig  xdm.AtomicValue
	widest          string
	first, hasNaN   bool
	sawNonURIString bool
}

func (s *maxMinAccumulator) add(ctx context.Context, original xdm.AtomicValue) error {
	value, err := promoteForAggregate(ctx, original)
	if err != nil {
		return err
	}

	family, err := maxMinTypeFamily(ctx, value, s.fnName)
	if err != nil {
		return err
	}

	if s.family == "" {
		s.family = family
	} else if s.family != family {
		return &xdm.Error{
			Code:    errCodeFORG0006,
			Message: fmt.Sprintf("incompatible types in %s: %s and %s", s.fnName, s.family, family),
		}
	}

	// anyURI promotes to string only if a non-URI string also occurs.
	if family == lexicon.TypeString && xdm.IsStringDerived(value.TypeName) {
		s.sawNonURIString = true
	}

	if family == xdm.FamilyNumeric && numericTypeWidth(value.TypeName) > numericTypeWidth(s.widest) {
		s.widest = value.TypeName
	}

	if (value.TypeName == xdm.TypeDouble || value.TypeName == xdm.TypeFloat) && value.FloatVal().IsNaN() {
		s.hasNaN = true
		return nil
	}

	if s.first {
		s.best, s.bestOrig, s.first = value, original, false
		return nil
	}

	selected, err := s.selects(value)
	if err != nil {
		return err
	}

	if selected {
		s.best, s.bestOrig = value, original
	}

	return nil
}

func maxMinTypeFamily(ctx context.Context, value xdm.AtomicValue, fnName string) (string, error) {
	family := aggregateTypeFamily(value)

	legacyBinary := false
	if ec := getFnContext(ctx); ec != nil && ec.version != 0 && ec.version < 31 {
		legacyBinary = family == lexicon.TypeBase64Binary || family == lexicon.TypeHexBinary
	}

	if family == "" || family == lexicon.TypeDuration || legacyBinary {
		return "", &xdm.Error{
			Code:    errCodeFORG0006,
			Message: fmt.Sprintf("invalid type %s for %s", value.TypeName, fnName),
		}
	}

	return family, nil
}

func (s *maxMinAccumulator) selects(value xdm.AtomicValue) (bool, error) {
	if s.coll != nil && s.family == lexicon.TypeString {
		order := s.coll.compare(value.StringVal(), s.best.StringVal())
		return (s.isMax && order > 0) || (!s.isMax && order < 0), nil
	}

	operator := TokenLt
	if s.isMax {
		operator = TokenGt
	}

	return ValueCompareWithImplicitTimezone(operator, value, s.best, s.implicitTZ)
}

func (s *maxMinAccumulator) result() xdm.Sequence {
	if s.hasNaN {
		nanType := s.widest
		if nanType != xdm.TypeFloat {
			nanType = xdm.TypeDouble
		}

		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: nanType, Value: xdm.NewDouble(math.NaN())})
	}

	if s.family == xdm.FamilyNumeric {
		// All integer subtypes retain the selected item's original type.
		if s.widest == xdm.TypeInteger {
			return xdm.SingleAtomic(s.bestOrig)
		}

		return xdm.SingleAtomic(promoteResult(s.best, s.widest))
	}

	// Only a selected anyURI is converted; selected string subtypes are retained.
	if s.family == lexicon.TypeString && s.sawNonURIString && s.bestOrig.TypeName == xdm.TypeAnyURI {
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeString, Value: s.best.StringVal()})
	}

	return xdm.SingleAtomic(s.bestOrig)
}

// promoteResult promotes the result of fn:max/fn:min to the widest numeric type.
func promoteResult(best xdm.AtomicValue, widest string) xdm.AtomicValue {
	// Always rebuild an xs:float result through NewFloat, even when best is already
	// typed xs:float: a schema-derived xs:float can be backed by a double-precision
	// FloatValue that must be narrowed to single precision.
	if widest == xdm.TypeFloat {
		return xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(float64(numericToFloat32(best)))}
	}

	if best.TypeName == widest {
		return best
	}

	switch widest {
	case xdm.TypeDouble:
		return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(best.ToFloat64())}
	case xdm.TypeDecimal:
		if xdm.IsIntegerDerived(best.TypeName) {
			if v, ok := best.Value.(int64); ok {
				return xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: new(big.Rat).SetInt64(v)}
			}

			return xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: new(big.Rat).SetInt(best.BigInt())}
		}
	}

	return best
}

func fnSum(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// Atomizing also flattens arrays.
	atoms, err := AtomizeSequence(args[0])
	if err != nil {
		return nil, err
	}

	if len(atoms) == 0 {
		if len(args) > 1 {
			return args[1], nil
		}

		return xdm.SingleInteger(0), nil
	}

	if len(atoms) == 1 {
		return sumSingle(ctx, atoms[0])
	}

	widest, err := prepareAggregateNumericValues(ctx, atoms)
	if err != nil {
		return nil, err
	}

	sum := aggregateSum{
		allInt: true, allDecOrInt: true, widest: widest,
		sumInt: new(big.Int), sumRat: new(big.Rat),
	}

	for i, value := range atoms {
		if i%64 == 0 {
			if err := Charge(ctx, min(64, len(atoms)-i)); err != nil {
				return nil, err
			}
		}

		if err := sum.add(ctx, value); err != nil {
			return nil, err
		}
	}

	if sum.family == xdm.FamilyDurationYM || sum.family == xdm.FamilyDurationDT {
		atomSeq := make(xdm.ItemSlice, len(atoms))
		for i, atom := range atoms {
			atomSeq[i] = atom
		}

		return sumDurations(atomSeq, sum.family)
	}

	return sum.numericResult(), nil
}

func sumSingle(ctx context.Context, value xdm.AtomicValue) (xdm.Sequence, error) {
	// Promote untypedAtomic but preserve derived integer types.
	if value.TypeName == xdm.TypeUntypedAtomic {
		var err error

		value, err = promoteForAggregate(ctx, value)
		if err != nil {
			return nil, err
		}
	}

	if err := checkSumAvgType(value); err != nil {
		return nil, err
	}

	return xdm.SingleAtomic(value), nil
}

type aggregateSum struct {
	family, widest      string
	allInt, allDecOrInt bool
	sumInt              *big.Int
	sumRat              *big.Rat
	sumFloat            float64
}

func (s *aggregateSum) add(ctx context.Context, value xdm.AtomicValue) error {
	// Untyped node values promote straight to IEEE double.
	if value.TypeName == xdm.TypeUntypedAtomic {
		return s.addUntyped(ctx, value)
	}

	value, err := promoteForAggregate(ctx, value)
	if err != nil {
		return err
	}

	if err := checkSumAvgType(value); err != nil {
		return err
	}

	s.family, err = checkAggregateHomogeneity(s.family, aggregateTypeFamily(value))
	if err != nil {
		return err
	}

	if numericTypeWidth(value.TypeName) > numericTypeWidth(s.widest) {
		s.widest = value.TypeName
	}

	if xdm.IsIntegerDerived(value.TypeName) || value.TypeName == xdm.TypeDecimal {
		if err := preflightDecimal(ctx, TokenPlus, s.sumRat, toRat(value)); err != nil {
			return err
		}

		if xdm.IsIntegerDerived(value.TypeName) {
			if err := preflightInteger(ctx, TokenPlus, s.sumInt, value.BigInt()); err != nil {
				return err
			}
		}
	}

	s.addNumeric(value)

	if xdm.IsIntegerDerived(value.TypeName) || value.TypeName == xdm.TypeDecimal {
		return ChargeNumber(ctx, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: s.sumRat})
	}

	return nil
}

func checkSumAvgType(a xdm.AtomicValue) error {
	family := aggregateTypeFamily(a)
	switch family {
	case xdm.FamilyNumeric, xdm.FamilyDurationYM, xdm.FamilyDurationDT:
		return nil
	}

	return &xdm.Error{
		Code:    errCodeFORG0006,
		Message: fmt.Sprintf("invalid type %s for aggregate function", a.TypeName),
	}
}

func (s *aggregateSum) addUntyped(ctx context.Context, value xdm.AtomicValue) error {
	converted, err := CastAtomicContext(ctx, value, xdm.TypeDouble)
	if err != nil {
		return err
	}

	s.family, err = checkAggregateHomogeneity(s.family, xdm.FamilyNumeric)
	if err != nil {
		return err
	}

	s.widest = xdm.TypeDouble
	s.allInt, s.allDecOrInt = false, false
	s.sumFloat += converted.ToFloat64()

	return nil
}

func (s *aggregateSum) addNumeric(value xdm.AtomicValue) {
	if xdm.IsIntegerDerived(value.TypeName) {
		s.addInteger(value)
		return
	}

	s.allInt = false
	if value.TypeName == xdm.TypeDecimal {
		s.sumRat.Add(s.sumRat, value.BigRat())
		s.addFloating(value)

		return
	}

	s.allDecOrInt = false
	s.addFloating(value)
}

func (s *aggregateSum) addFloating(value xdm.AtomicValue) {
	if s.widest == xdm.TypeFloat {
		s.sumFloat = float64(float32(s.sumFloat) + numericToFloat32(value))
	} else {
		s.sumFloat += value.ToFloat64()
	}
}

func (s *aggregateSum) addInteger(value xdm.AtomicValue) {
	if number, ok := value.Value.(int64); ok {
		s.sumInt.Add(s.sumInt, big.NewInt(number))
		s.sumRat.Add(s.sumRat, new(big.Rat).SetInt64(number))
		s.addFloating(value)

		return
	}

	s.sumInt.Add(s.sumInt, value.BigInt())
	s.sumRat.Add(s.sumRat, new(big.Rat).SetInt(value.BigInt()))
	s.addFloating(value)
}

func (s *aggregateSum) numericResult() xdm.Sequence {
	if s.allInt {
		return xdm.SingleIntegerBig(s.sumInt)
	}

	if s.allDecOrInt {
		return xdm.SingleDecimal(s.sumRat)
	}

	if s.widest == xdm.TypeFloat {
		return xdm.SingleFloat(s.sumFloat)
	}

	return xdm.SingleDouble(s.sumFloat)
}

func checkAggregateHomogeneity(family, newFamily string) (string, error) {
	if family == "" {
		return newFamily, nil
	}

	if family == newFamily {
		return family, nil
	}

	if family == xdm.FamilyNumeric && newFamily == xdm.FamilyNumeric {
		return xdm.FamilyNumeric, nil
	}

	return "", &xdm.Error{
		Code:    errCodeFORG0006,
		Message: fmt.Sprintf("incompatible types in aggregate: %s and %s", family, newFamily),
	}
}

func sumDurations(seq xdm.Sequence, family string) (xdm.Sequence, error) {
	if family == xdm.FamilyDurationDT {
		// Accumulate dayTime seconds EXACTLY so large totals (beyond float64's
		// 2^53 range) and fractional seconds canonicalize precisely.
		totalSecs := new(big.Rat)

		for item := range xdm.SequenceItems(seq) {
			a, _ := AtomizeItem(item)
			totalSecs.Add(totalSecs, xdm.DurationToRat(a.DurationVal(), false))
		}

		negative := totalSecs.Sign() < 0

		absSecs := totalSecs
		if negative {
			absSecs = new(big.Rat).Neg(totalSecs)
		}

		secs, frac := durationFromRatSeconds(absSecs)

		return xdm.SingleAtomic(xdm.AtomicValue{
			TypeName: xdm.TypeDayTimeDuration,
			Value:    xdm.Duration{Seconds: secs, FracSec: frac, SecRat: absSecs, Negative: negative},
		}), nil
	}

	// Accumulate months via big.Int so a total near the int limit does not wrap
	// to an invalid negative lexical; reject anything that overflows int.
	totalMonths := new(big.Int)

	for item := range xdm.SequenceItems(seq) {
		a, _ := AtomizeItem(item)
		d := a.DurationVal()

		m := big.NewInt(int64(d.Months))
		if d.Negative {
			totalMonths.Sub(totalMonths, m)
		} else {
			totalMonths.Add(totalMonths, m)
		}
	}

	negative := totalMonths.Sign() < 0

	absMonths := totalMonths
	if negative {
		absMonths = new(big.Int).Neg(totalMonths)
	}

	if !absMonths.IsInt64() || absMonths.Int64() > int64(math.MaxInt) {
		return nil, &xdm.Error{Code: errCodeFODT0002, Message: "yearMonthDuration sum overflow"}
	}

	return xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: xdm.TypeYearMonthDuration,
		Value:    xdm.Duration{Months: int(absMonths.Int64()), Negative: negative},
	}), nil
}

func fnDistinctValues(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) == 0 {
		return nil, nil
	}

	if err := validateCollationArg(ctx, args, 1); err != nil {
		return nil, err
	}

	coll, err := getCollation(ctx, args, 1)
	if err != nil {
		return nil, err
	}

	var implicitTZ *time.Location
	if ec := getFnContext(ctx); ec != nil {
		implicitTZ = ec.getImplicitTimezone()
	}

	// Atomize all input so list-typed nodes become separate atomic values.
	atoms, err := AtomizeSequence(args[0])
	if err != nil {
		return nil, err
	}

	values := distinctValueAccumulator{coll: coll, implicitTZ: implicitTZ, seenFast: make(map[string]struct{})}
	for _, atom := range atoms {
		if err := values.add(atom); err != nil {
			return nil, err
		}
	}

	seq := make(xdm.ItemSlice, len(values.result))
	for i, value := range values.result {
		seq[i] = value
	}

	return seq, nil
}

type distinctGroup uint8

const (
	distinctGroupUnknown distinctGroup = iota
	distinctGroupString
	distinctGroupBoolean
	distinctGroupDecimalInt
	distinctGroupFloat
	distinctGroupDouble
)

type distinctValueAccumulator struct {
	coll                                       *collationImpl
	implicitTZ                                 *time.Location
	result                                     []xdm.AtomicValue
	seenFast                                   map[string]struct{}
	numericDecInt, numericFloat, numericDouble []xdm.AtomicValue
	seenNaN                                    bool
}

func (s *distinctValueAccumulator) add(value xdm.AtomicValue) error {
	// Untyped atomic values compare as strings.
	if value.TypeName == xdm.TypeUntypedAtomic {
		value = xdm.AtomicValue{TypeName: xdm.TypeString, Value: value.StringVal()}
	}

	// op:is-same-key treats every NaN as equal.
	if isAtomicNaN(value) {
		if !s.seenNaN {
			s.seenNaN = true
			s.result = append(s.result, value)
		}

		return nil
	}

	if group, key, ok := distinctValueFastKey(value); ok {
		return s.addFast(value, group, key)
	}

	if !s.seenByValue(value) {
		s.result = append(s.result, value)
	}

	return nil
}

func distinctValueFastKey(a xdm.AtomicValue) (distinctGroup, string, bool) {
	// Classify on the effective built-in type so a schema-derived value (custom
	// TypeName whose BaseType names the built-in ancestor) shares a fast-key
	// family with its built-in equivalent. Otherwise a schema-derived xs:NCName
	// and an equal xs:string would land in different buckets and never collapse.
	et := distinctEffectiveType(a)
	switch {
	case xdm.IsStringDerived(et):
		return distinctGroupString, "s:" + a.StringVal(), true
	case et == xdm.TypeAnyURI:
		return distinctGroupString, "s:" + stringFromAtomic(a), true
	case et == xdm.TypeBoolean:
		return distinctGroupBoolean, "b:" + strconv.FormatBool(a.BooleanVal()), true
	case xdm.IsIntegerDerived(et) || et == xdm.TypeDecimal:
		// Promote via BaseType so a schema-derived integer/decimal (custom TypeName,
		// built-in BaseType, backed by int64/*big.Int/*big.Rat) keys on its effective
		// value. The un-promoted toRatForCompare would produce 0.
		return distinctGroupDecimalInt, "n:" + toRatForCompare(xdm.PromoteSchemaType(a)).RatString(), true
	case et == xdm.TypeFloat:
		// Promote via BaseType so a schema-derived float (custom TypeName, built-in
		// BaseType, backed by float64/float32/*FloatValue) keys on its effective
		// value. The un-promoted ToFloat64 would produce 0.
		f := float32(xdm.PromoteSchemaType(a).ToFloat64())
		if f == 0 {
			f = 0
		}

		return distinctGroupFloat, "f:" + strconv.FormatUint(uint64(math.Float32bits(f)), 16), true
	case et == xdm.TypeDouble:
		f := xdm.PromoteSchemaType(a).ToFloat64()
		if f == 0 {
			f = 0
		}

		return distinctGroupDouble, "d:" + strconv.FormatUint(math.Float64bits(f), 16), true
	default:
		return distinctGroupUnknown, "", false
	}
}

func (s *distinctValueAccumulator) addFast(value xdm.AtomicValue, group distinctGroup, key string) error {
	// Collation-equal strings must share their bucket.
	if s.coll != nil && group == distinctGroupString {
		key = "s:" + string(s.coll.key(value.StringVal()))
	}

	if _, exists := s.seenFast[key]; exists {
		return nil
	}

	found, err := distinctValueSeenInOtherNumericGroups(
		value, group, s.coll, s.implicitTZ, s.numericDecInt, s.numericFloat, s.numericDouble,
	)
	if err != nil {
		return err
	}

	if found {
		return nil
	}

	s.seenFast[key] = struct{}{}
	s.result = append(s.result, value)

	switch group {
	case distinctGroupDecimalInt:
		s.numericDecInt = append(s.numericDecInt, value)
	case distinctGroupFloat:
		s.numericFloat = append(s.numericFloat, value)
	case distinctGroupDouble:
		s.numericDouble = append(s.numericDouble, value)
	}

	return nil
}

func distinctValueSeenInOtherNumericGroups(
	a xdm.AtomicValue,
	group distinctGroup,
	coll *collationImpl,
	implicitTZ *time.Location,
	decimalInts []xdm.AtomicValue,
	floats []xdm.AtomicValue,
	doubles []xdm.AtomicValue,
) (bool, error) {
	switch group {
	case distinctGroupDecimalInt:
		return distinctValueSeenInSet(a, coll, implicitTZ, floats, doubles)
	case distinctGroupFloat:
		return distinctValueSeenInSet(a, coll, implicitTZ, decimalInts, doubles)
	case distinctGroupDouble:
		return distinctValueSeenInSet(a, coll, implicitTZ, decimalInts, floats)
	default:
		return false, nil
	}
}

func distinctValueSeenInSet(
	a xdm.AtomicValue,
	coll *collationImpl,
	implicitTZ *time.Location,
	sets ...[]xdm.AtomicValue,
) (bool, error) {
	for _, set := range sets {
		for _, existing := range set {
			eq, err := distinctValueEqual(a, existing, coll, implicitTZ)
			if err != nil {
				continue
			}

			if eq {
				return true, nil
			}
		}
	}

	return false, nil
}

func (s *distinctValueAccumulator) seenByValue(value xdm.AtomicValue) bool {
	for _, existing := range s.result {
		if isAtomicNaN(existing) {
			continue
		}

		equal, err := distinctValueEqual(value, existing, s.coll, s.implicitTZ)
		if err != nil {
			continue // Incomparable values remain distinct.
		}

		if equal {
			return true
		}
	}

	return false
}

// distinctEffectiveType returns the built-in type that governs distinct-values
// fast-key classification: the TypeName itself when it is a known built-in, or
// the BaseType of a schema-derived value when its TypeName is not built-in.
func distinctEffectiveType(a xdm.AtomicValue) string {
	if a.TypeName != "" && xdm.IsKnownXSDType(a.TypeName) {
		return a.TypeName
	}

	if a.BaseType != "" && xdm.IsKnownXSDType(a.BaseType) {
		return a.BaseType
	}

	return a.TypeName
}

func distinctValueEqual(a, b xdm.AtomicValue, coll *collationImpl, implicitTZ *time.Location) (bool, error) {
	if coll != nil {
		aStr := xdm.IsStringDerived(a.TypeName) || a.TypeName == xdm.TypeAnyURI

		bStr := xdm.IsStringDerived(b.TypeName) || b.TypeName == xdm.TypeAnyURI
		if aStr && bStr {
			return coll.compare(stringFromAtomic(a), stringFromAtomic(b)) == 0, nil
		}
	}

	return ValueCompareWithImplicitTimezone(TokenEq, a, b, implicitTZ)
}

// isAtomicNaN returns true if the atomic value is a float or double NaN. It is
// BaseType-aware: a schema-derived float/double (custom TypeName whose BaseType
// names the built-in ancestor) is classified on its effective numeric type so a
// schema-derived NaN collapses with a built-in NaN.
func isAtomicNaN(a xdm.AtomicValue) bool {
	switch distinctEffectiveType(a) {
	case xdm.TypeDouble, xdm.TypeFloat:
		return a.FloatVal().IsNaN()
	}

	return false
}
