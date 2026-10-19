package nilcheck_test

import (
	"io"
	"testing"

	"github.com/skarm/xmlsec/internal/nilcheck"
)

type (
	namedMap   map[string]int
	namedSlice []int
	namedFunc  func()
	namedChan  chan int
)

func TestIsNil(t *testing.T) {
	var (
		pointer     *int
		reader      io.Reader
		typedReader *nilReader
	)
	for _, tc := range []struct {
		name  string
		value any
		want  bool
	}{
		{"nil", nil, true},
		{"pointer", pointer, true},
		{"reader interface", reader, true},
		{"reader containing nil pointer", io.Reader(typedReader), true},
		{"map", map[string]int(nil), true},
		{"named map", namedMap(nil), true},
		{"slice", []int(nil), true},
		{"named slice", namedSlice(nil), true},
		{"function", (func())(nil), true},
		{"named function", namedFunc(nil), true},
		{"channel", (chan int)(nil), true},
		{"named channel", namedChan(nil), true},
		{"receive channel", (<-chan int)(nil), true},
		{"send channel", (chan<- int)(nil), true},
		{"non-nil pointer to nil interface", &reader, false},
		{"non-nil pointer", new(int), false},
		{"non-nil reader", &nilReader{}, false},
		{"empty map", map[string]int{}, false},
		{"empty slice", []int{}, false},
		{"function value", func() {}, false},
		{"channel value", make(chan int), false},
		{"struct", struct{}{}, false},
		{"zero number", 0, false},
		{"false", false, false},
		{"empty string", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nilcheck.IsNil(tc.value); got != tc.want {
				t.Fatalf("IsNil(%T) = %t, want %t", tc.value, got, tc.want)
			}
		})
	}
}

type nilReader struct{}

func (*nilReader) Read([]byte) (int, error) { panic("nil check must not call Read") }
