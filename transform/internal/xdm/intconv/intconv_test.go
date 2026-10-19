package intconv_test

import (
	"errors"
	"math"
	"strconv"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm/intconv"
)

func TestAtoi(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int
		err   error
	}{
		{"0", 0, nil},
		{"-1", -1, nil},
		{"+42", 42, nil},
		{"9223372036854775807", math.MaxInt, nil},
		{"-9223372036854775808", math.MinInt, nil},
		{"9223372036854775808", 0, strconv.ErrRange},
		{"-9223372036854775809", 0, strconv.ErrRange},
		{"", 0, strconv.ErrSyntax},
		{"1.0", 0, strconv.ErrSyntax},
		{" 1", 0, strconv.ErrSyntax},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := intconv.Atoi(tc.input)
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Fatalf("got %d, %v; want %d, %v", got, err, tc.want, tc.err)
			}
		})
	}
}
