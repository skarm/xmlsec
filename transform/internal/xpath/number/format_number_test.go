package number_test

import (
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"

	number "github.com/skarm/xmlsec/transform/internal/xpath/number"
)

func TestFormatNumber(t *testing.T) {
	const twoDecimals = "0.00"

	for _, tc := range []struct {
		value   float64
		picture string
		want    string
	}{
		{12345.625, "#,##0.00", "12,345.62"},
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
