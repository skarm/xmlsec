// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath/number"
)

// DecimalFormat aliases the shared decimal-picture symbol and formatting
// configuration.
type DecimalFormat = number.DecimalFormat

// DefaultDecimalFormat returns the shared default decimal formatting symbols.
func DefaultDecimalFormat() DecimalFormat {
	return number.DefaultDecimalFormat()
}

// DecimalZeroDigit identifies the first digit of each Unicode Nd group of ten.
// Adjacent mathematical digit alphabets can share one contiguous Nd range.
func DecimalZeroDigit(character rune) bool {
	if !unicode.IsDigit(character) {
		return false
	}

	for _, block := range unicode.Nd.R16 {
		if character >= rune(block.Lo) && character <= rune(block.Hi) {
			return (character-rune(block.Lo))%10 == 0
		}
	}

	for _, block := range unicode.Nd.R32 {
		if character >= rune(block.Lo) && character <= rune(block.Hi) { // #nosec G115 -- Standard Unicode Nd tables contain code points at most utf8.MaxRune.
			return (character-rune(block.Lo))%10 == 0 // #nosec G115 -- Standard Unicode Nd tables contain code points at most utf8.MaxRune.
		}
	}

	return false
}

func defaultDecimalFormat(ctx context.Context) number.DecimalFormat {
	if ec := getFnContext(ctx); ec != nil && ec.defaultDecimalFormat != nil {
		return *ec.defaultDecimalFormat
	}

	return number.DefaultDecimalFormat()
}

func resolveDecimalFormat(ctx context.Context, name string) (number.DecimalFormat, error) {
	name = strings.Trim(name, " \t\r\n")
	if name == "" {
		return defaultDecimalFormat(ctx), nil
	}

	qname, err := resolveDecimalFormatName(ctx, name)
	if err != nil {
		return number.DecimalFormat{}, err
	}

	if ec := getFnContext(ctx); ec != nil && ec.decimalFormats != nil {
		if df, ok := ec.decimalFormats[qname]; ok {
			return df, nil
		}
	}

	return number.DecimalFormat{}, &xdm.Error{Code: errCodeFODF1280, Message: fmt.Sprintf("unknown decimal format: %s", name)}
}

func resolveDecimalFormatName(ctx context.Context, name string) (QualifiedName, error) {
	if strings.HasPrefix(name, "Q{") {
		end := strings.Index(name, "}")
		if end < 0 || end == len(name)-1 {
			return QualifiedName{}, &xdm.Error{Code: errCodeFODF1280, Message: fmt.Sprintf("unknown decimal format: %s", name)}
		}

		return QualifiedName{URI: name[2:end], Name: name[end+1:]}, nil
	}

	if prefix, local, ok := strings.Cut(name, ":"); ok {
		uri := ""
		if ec := getFnContext(ctx); ec != nil && ec.namespaces != nil {
			uri = ec.namespaces[prefix]
		}

		if uri == "" {
			if ns, ok := PredeclaredNamespace(prefix); ok {
				uri = ns
			}
		}

		if uri == "" {
			return QualifiedName{}, &xdm.Error{Code: errCodeFODF1280, Message: fmt.Sprintf("unknown decimal format: %s", name)}
		}

		return QualifiedName{URI: uri, Name: local}, nil
	}

	return QualifiedName{Name: name}, nil
}

func boundedFormatNumber(ctx context.Context, value xdm.AtomicValue, picture string, df number.DecimalFormat) (string, error) {
	if ec := getFnContext(ctx); ec != nil && ec.version != 0 && ec.version < 31 {
		df.ExponentDisabled = true
	}

	// Picture width bounds the scaling powers used by the exact formatter.
	// Reject excessive pictures before parsing/scaling, and account for the
	// resulting text even when a surrounding expression consumes only its length.
	if err := ChargeString(ctx, len(picture)); err != nil {
		return "", err
	}

	if err := preflightRound(ctx, value, len(picture)); err != nil {
		return "", err
	}

	result, err := formatNumber(value, picture, df)
	if err == nil {
		err = ChargeString(ctx, len(result))
	}

	return result, err
}

func formatNumber(a xdm.AtomicValue, picture string, df number.DecimalFormat) (string, error) {
	f := a.ToFloat64()

	isNaN := math.IsNaN(f)
	isPosInf := math.IsInf(f, 1)
	isNegInf := math.IsInf(f, -1)
	negative := f < 0 || (f == 0 && math.Signbit(f))

	var precise *big.Rat

	if xdm.IsIntegerDerived(a.TypeName) {
		if v, ok := a.Value.(int64); ok {
			precise = new(big.Rat).SetInt64(v)
		} else {
			precise = new(big.Rat).SetInt(a.BigInt())
		}
	} else if a.TypeName == xdm.TypeDecimal {
		precise = new(big.Rat).Set(a.BigRat())
	} else if (a.TypeName == xdm.TypeDouble || a.TypeName == xdm.TypeFloat) && !isNaN && !isPosInf && !isNegInf {
		if s, err := atomicToString(a); err == nil {
			precise = parseCanonicalFloatRat(s)
		}
	}

	if negative {
		f = math.Abs(f)
		if precise != nil {
			precise = new(big.Rat).Abs(precise)
		}
	}

	if (a.TypeName == xdm.TypeDouble || a.TypeName == xdm.TypeFloat) && precise != nil {
		precise = scaledFloatPrecise(a.TypeName, f, picture, negative, df, precise)
	}

	result, err := number.FormatNumber(f, isNaN, isPosInf, isNegInf, negative, precise, picture, df)
	if err != nil {
		return "", &xdm.Error{Code: errCodeFODF1310, Message: fmt.Sprintf("invalid picture: %q", picture)}
	}

	return result, nil
}

func scaledFloatPrecise(typeName string, f float64, picture string, negative bool, df number.DecimalFormat, precise *big.Rat) *big.Rat {
	pp, err := number.ParsePicture(selectedNumberPicture(picture, negative, df), df)
	if err != nil || (!pp.IsPercent && !pp.IsPerMille) {
		return precise
	}

	scaled := f
	divisor := int64(100)

	if pp.IsPercent {
		scaled *= 100
	} else {
		scaled *= 1000
		divisor = 1000
	}

	if math.IsNaN(scaled) || math.IsInf(scaled, 0) {
		return nil
	}

	scaledLexical := formatXPathDouble(scaled)
	if typeName == xdm.TypeFloat {
		scaledLexical = formatXPathFloat(scaled)
	}

	scaledRat := parseCanonicalFloatRat(scaledLexical)
	if scaledRat == nil {
		return nil
	}

	return new(big.Rat).Quo(scaledRat, new(big.Rat).SetInt64(divisor))
}

func selectedNumberPicture(picture string, negative bool, df number.DecimalFormat) string {
	parts := strings.SplitN(picture, string(df.PatternSeparator), 3)
	if negative && len(parts) > 1 {
		return parts[1]
	}

	return parts[0]
}

func parseCanonicalFloatRat(s string) *big.Rat {
	if idx := strings.IndexAny(s, "eE"); idx >= 0 {
		mantissa := parseCanonicalFloatRat(s[:idx])
		if mantissa == nil {
			return nil
		}

		exp, err := strconv.Atoi(s[idx+1:])
		if err != nil {
			return nil
		}

		scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(absInt(exp))), nil)
		if exp >= 0 {
			return mantissa.Mul(mantissa, new(big.Rat).SetInt(scale))
		}

		return mantissa.Quo(mantissa, new(big.Rat).SetInt(scale))
	}

	if r, ok := new(big.Rat).SetString(s); ok {
		return r
	}

	return nil
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}

	return v
}
