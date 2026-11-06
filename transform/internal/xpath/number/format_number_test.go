package number_test

import (
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xpath/number"
)

func TestFormatNumber(t *testing.T) {
	const twoDecimals = "0.00"

	for _, tc := range []struct {
		value   float64
		picture string
		want    string
	}{
		{12345.625, "#,##0.00", "12,345.62"},
		{1.125, twoDecimals, "1.12"},
		{1.375, twoDecimals, "1.38"},
		{42.7, twoDecimals, "42.70"},
		{-12.5, "0.00;(0.00)", "(12.50)"},
		{0.125, "0.0%", "12.5%"},
		{0.125, "0.0‰", "125.0‰"},
		{math.Inf(1), twoDecimals, "Infinity"},
		{math.Inf(-1), twoDecimals, "-Infinity"},
		{math.NaN(), twoDecimals, "NaN"},
	} {
		t.Run(tc.picture+tc.want, func(t *testing.T) {
			got, err := number.FormatNumber(tc.value, math.IsNaN(tc.value), math.IsInf(tc.value, 1), math.IsInf(tc.value, -1), math.Signbit(tc.value), nil, tc.picture, number.DefaultDecimalFormat())
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}

	precise := new(big.Rat).SetFrac64(100000000000000001, 100)

	got, err := number.FormatNumber(1e15, false, false, false, false, precise, twoDecimals, number.DefaultDecimalFormat())
	if err != nil || got != "1000000000000000.01" {
		t.Fatalf("decimal precision lost: %q, %v", got, err)
	}
}

func TestParsePictureRejectsInvalidGrammar(t *testing.T) {
	for _, picture := range []string{"0.0.0", "0%‰", "0,,0"} {
		if _, err := number.ParsePicture(picture, number.DefaultDecimalFormat()); err == nil {
			t.Errorf("invalid picture %q accepted", picture)
		}
	}
}

func TestExactRoundingBoundariesAndOwnership(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		value, want string
		precision   int
	}{
		{"2.5", "2", 0},
		{"3.5", "4", 0},
		{"-2.5", "-2", 0},
		{"-3.5", "-4", 0},
		{"-2.49", "-2", 0},
		{"-2.51", "-3", 0},
		{"1.245", "1.24", 2},
		{"1.255", "1.26", 2},
		{"9.995", "10", 2},
		{"-9.995", "-10", 2},
		{"125", "120", -1},
		{"135", "140", -1},
		{"-125", "-120", -1},
		{"-135", "-140", -1},
		{"1/8", "1/8", 3},
		{"1/8", "1/8", 1001},
		{"42", "0", -1001},
	} {
		t.Run(tc.value+"/"+strconv.Itoa(tc.precision), func(t *testing.T) {
			t.Parallel()
			source, ok := new(big.Rat).SetString(tc.value)
			if !ok {
				t.Fatal(tc.value)
			}
			want, ok := new(big.Rat).SetString(tc.want)
			if !ok {
				t.Fatal(tc.want)
			}
			before := source.RatString()
			got := number.RatRoundHalfToEven(source, tc.precision)
			if got.Cmp(want) != 0 || source.RatString() != before {
				t.Fatalf("rounded %s to %s; want %s, source %s", tc.value, got, want, source)
			}
			got.SetInt64(999)
			if source.RatString() != before {
				t.Fatal("rounded result aliases its input")
			}
		})
	}
}

func TestDecimalDigitsAndWideRounding(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		value string
		want  int
	}{{"42", 0}, {"1/8", 3}, {"1/40", 3}, {"1/125", 3}, {"1/3", math.MaxInt}, {"1/7", math.MaxInt}, {"1/9", math.MaxInt}} {
		value, ok := new(big.Rat).SetString(test.value)
		if !ok {
			t.Fatal(test.value)
		}
		if got := number.RatDecimalDigits(value); got != test.want {
			t.Errorf("decimal digits(%s) = %d; want %d", value, got, test.want)
		}
	}
	for _, test := range []struct {
		value, want string
		precision   int
	}{
		{"1/7", "0.1429", 4},
		{"1/9", "0.1111", 4},
		{"0." + strings.Repeat("0", 1000) + "59", "0." + strings.Repeat("0", 1000) + "6", 1001},
		{"-0." + strings.Repeat("0", 1000) + "59", "-0." + strings.Repeat("0", 1000) + "6", 1001},
		{"125" + strings.Repeat("0", 1001), "12" + strings.Repeat("0", 1002), -1002},
		{"42", "0", math.MinInt},
	} {
		value, ok := new(big.Rat).SetString(test.value)
		if !ok {
			t.Fatal(test.value)
		}
		want, ok := new(big.Rat).SetString(test.want)
		if !ok {
			t.Fatal(test.want)
		}
		if got := number.RatRoundHalfToEven(value, test.precision); got.Cmp(want) != 0 {
			t.Errorf("precision %d: got %s; want %s", test.precision, got, want)
		}
	}
}

func TestIntegerHalfEvenRoundingDistanceAndOwnership(t *testing.T) {
	t.Parallel()

	check := func(value *big.Rat) {
		t.Helper()

		before := value.RatString()
		got := number.RatRoundHalfToEvenInt(value)
		distance := new(big.Rat).Sub(value, new(big.Rat).SetInt(got))
		distance.Abs(distance)
		comparison := distance.Cmp(big.NewRat(1, 2))
		if comparison > 0 || comparison == 0 && got.Bit(0) != 0 {
			t.Fatalf("rounded %s to %s, distance %s; want nearest integer with even ties", value, got, distance)
		}
		got.SetInt64(999)
		if value.RatString() != before {
			t.Fatal("rounding changed or aliased its source", before, value)
		}
	}
	for numerator := int64(-64); numerator <= 64; numerator++ {
		for denominator := int64(1); denominator <= 33; denominator++ {
			check(big.NewRat(numerator, denominator))
		}
	}
	// Exercise multiword division around half, with even/odd quotients and
	// both signs. The distance/parity oracle does not perform quotient rounding.
	denominator := new(big.Int).Lsh(big.NewInt(1), 128)
	for _, odd := range []int64{0, 1} {
		quotient := new(big.Int).Lsh(big.NewInt(1), 256)
		quotient.Add(quotient, big.NewInt(odd))
		for _, offset := range []int64{-1, 0, 1} {
			numerator := new(big.Int).Mul(quotient, denominator)
			remainder := new(big.Int).Rsh(new(big.Int).Set(denominator), 1)
			remainder.Add(remainder, big.NewInt(offset))
			numerator.Add(numerator, remainder)
			value := new(big.Rat).SetFrac(numerator, denominator)
			check(value)
			check(new(big.Rat).Neg(value))
		}
	}
}

func TestScaledHalfEvenRoundingDistanceAndOwnership(t *testing.T) {
	t.Parallel()

	for precision := -3; precision <= 3; precision++ {
		exponent := precision
		if exponent < 0 {
			exponent = -exponent
		}
		quantum := new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(exponent)), nil))
		if precision > 0 {
			quantum.Inv(quantum)
		}
		for numerator := int64(-24); numerator <= 24; numerator++ {
			for denominator := int64(1); denominator <= 17; denominator++ {
				value := big.NewRat(numerator, denominator)
				before := value.RatString()
				got := number.RatRoundHalfToEven(value, precision)
				units := new(big.Rat).Quo(got, quantum)
				distance := new(big.Rat).Sub(value, got)
				distance.Quo(distance.Abs(distance), quantum)
				comparison := distance.Cmp(big.NewRat(1, 2))
				if !units.IsInt() || comparison > 0 || comparison == 0 && units.Num().Bit(0) != 0 {
					t.Fatalf("precision %d: rounded %s to %s, distance %s units; want nearest with even ties", precision, value, got, distance)
				}
				got.SetInt64(999)
				if value.RatString() != before {
					t.Fatal("scaled rounding changed or aliased its source", before, value)
				}
			}
		}
	}
}

func TestScientificAndFractionGroupingPictures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ value, picture, want string }{
		{"0", "0.00e00", "0.00e00"},
		{"12.5", "00.0e00", "12.5e00"},
		{"0.00125", "0.00e00", "1.25e-03"},
		{"1250", "##.00e0", "12.50e2"},
		{"0.0125", ".###e0", ".125e-1"},
		{"1250", "#.###e0", "0.125e4"},
		{"0.123456", "0.00,00,00", "0.12,34,56"},
		{"0.1", "0.##,##", "0.1"},
		{"0.12345", "0.##,##", "0.12,34"},
	} {
		t.Run(tc.value+"/"+tc.picture, func(t *testing.T) {
			t.Parallel()
			value, ok := new(big.Rat).SetString(tc.value)
			if !ok {
				t.Fatal(tc.value)
			}
			before := value.RatString()
			f, _ := value.Float64()
			for _, precise := range []*big.Rat{nil, value} {
				got, err := number.FormatNumber(f, false, false, false, false, precise, tc.picture, number.DefaultDecimalFormat())
				if err != nil || got != tc.want || value.RatString() != before {
					t.Fatalf("precise=%v: %q, %v; want %q, unchanged input", precise != nil, got, err, tc.want)
				}
			}
		})
	}
}

func TestFractionLongDivisionOwnership(t *testing.T) {
	df := number.DefaultDecimalFormat()
	for _, tc := range []struct {
		value string
		want  string
		min   int
		max   int
	}{
		{"1/7", strings.Repeat("142857", 21) + "14", 128, 128},
		{"1/8", "125", 0, 128},
		{"1/8", "12500", 5, 5},
		{"1/8", "125", 5, 3},
		{"1/8", "12", 0, 2},
		{"1/8", "", 0, 0},
		{"1/1024", "00097", 0, 5},
		{"1/1024", "", 0, 2},
		{"1/1024", "00", 2, 2},
		{"99/100", "9", 0, 1},
		{"0", "000", 3, 128},
	} {
		r, ok := new(big.Rat).SetString(tc.value)
		if !ok {
			t.Fatal(tc.value)
		}
		before := r.RatString()
		got := number.FormatRatFrac(r, tc.min, tc.max, df)
		if got != tc.want || r.RatString() != before {
			t.Fatalf("%s: %q, source %s; want %q", tc.value, got, r.RatString(), tc.want)
		}
	}
	df.ZeroDigit = '٠'
	if got := number.FormatRatFrac(big.NewRat(1, 8), 5, 5, df); got != "١٢٥٠٠" {
		t.Fatal("localized fractional digits", got)
	}
}

func BenchmarkFractionFormattingWidth(b *testing.B) {
	for _, width := range []int{3, 128, 4096} {
		for _, test := range []struct {
			name  string
			value *big.Rat
		}{
			{"RoundedSeventh", number.RatRoundHalfToEven(big.NewRat(1, 7), width)},
			{"LeadingZeros", big.NewRat(1, 1024)},
			{"TrailingZeros", big.NewRat(1, 8)},
		} {
			b.Run(test.name+"/"+strconv.Itoa(width), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					_ = number.FormatRatFrac(test.value, min(3, width), width, number.DefaultDecimalFormat())
				}
			})
		}
	}
}

func TestWideIntegerPictures(t *testing.T) {
	for _, tc := range []struct {
		name, picture, want string
		value               float64
	}{
		{"integer padding", "000000", "000042", 42},
		{"wide integer", strings.Repeat("0", 4096), strings.Repeat("0", 4094) + "42", 42},
		{"exponent padding", "0e000000", "1e000004", 10000},
		{"negative exponent padding", "0e000000", "1e-000004", 0.0001},
		{"wide exponent", "0e" + strings.Repeat("0", 4096), "1e" + strings.Repeat("0", 4095) + "4", 10000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := number.FormatNumber(tc.value, false, false, false, false, nil, tc.picture, number.DefaultDecimalFormat())
			if err != nil || got != tc.want {
				t.Fatalf("formatted %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	integer := big.NewInt(42)
	df := number.DefaultDecimalFormat()
	df.ZeroDigit = '٠'
	df.GroupingSeparator = '·'
	got := number.FormatBigInt(integer, 6, []int{3, 3}, true, df)
	if got != "٠٠٠·٠٤٢" || integer.Int64() != 42 {
		t.Fatalf("localized grouping/ownership: %q, %s", got, integer)
	}
}

func BenchmarkNumberFormatting(b *testing.B) {
	df := number.DefaultDecimalFormat()
	for _, tc := range []struct {
		name    string
		picture string
		precise *big.Rat
	}{
		{"Short", "0.00", nil},
		{"Grouping", "#,##0.00", nil},
		{"Precise", "0." + strings.Repeat("0", 128), new(big.Rat).SetFrac64(1, 7)},
		{"LongPicture", strings.Repeat("prefix", 128) + "0.00", nil},
	} {
		b.Run(tc.name, func(b *testing.B) {
			pp, err := number.ParsePicture(tc.picture, df)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("Parse", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := number.ParsePicture(tc.picture, df); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("Format", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := number.FormatNumber(12345.625, false, false, false, false, tc.precise, tc.picture, df); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("ParsedReuse", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if tc.precise != nil {
						_ = number.FormatDecimalPrecise(tc.precise, pp, df)
					} else {
						_ = number.FormatFloat(12345.625, pp, df)
					}
				}
			})
		})
	}
	b.Run("InvalidPicture", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := number.ParsePicture("0.0.0", df); err == nil {
				b.Fatal("accepted")
			}
		}
	})
	b.Run("Parallel", func(b *testing.B) {
		pp, err := number.ParsePicture("#,##0.00", df)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = number.FormatFloat(12345.625, pp, df)
			}
		})
	})
}

func BenchmarkIntegerPictureWidth(b *testing.B) {
	for _, width := range []int{3, 64, 4096} {
		b.Run(strconv.Itoa(width), func(b *testing.B) {
			integer := big.NewInt(42)
			df := number.DefaultDecimalFormat()
			b.Run("Integer", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					_ = number.FormatBigInt(integer, width, nil, false, df)
				}
			})
			picture := "0e" + strings.Repeat("0", width)
			b.Run("Exponent", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := number.FormatNumber(10000, false, false, false, false, nil, picture, df); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
