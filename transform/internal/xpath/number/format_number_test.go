package icu_test

import (
	"math"
	"math/big"
	"testing"

	icu "github.com/skarm/xmlsec/transform/internal/xpath/number"
)

func TestFormatNumber(t *testing.T) {
	const twoDecimals = "0.00"

	for _, tc := range []struct {
		value         float64
		picture, want string
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
			got, err := icu.FormatNumber(tc.value, math.IsNaN(tc.value), math.IsInf(tc.value, 1), math.IsInf(tc.value, -1), math.Signbit(tc.value), nil, tc.picture, icu.DefaultDecimalFormat())
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}

	precise := new(big.Rat).SetFrac64(100000000000000001, 100)

	got, err := icu.FormatNumber(1e15, false, false, false, false, precise, twoDecimals, icu.DefaultDecimalFormat())
	if err != nil || got != "1000000000000000.01" {
		t.Fatalf("decimal precision lost: %q, %v", got, err)
	}
}

func TestParsePictureRejectsInvalidGrammar(t *testing.T) {
	for _, picture := range []string{"0.0.0", "0%‰", "0,,0"} {
		if _, err := icu.ParsePicture(picture, icu.DefaultDecimalFormat()); err == nil {
			t.Errorf("invalid picture %q accepted", picture)
		}
	}
}
