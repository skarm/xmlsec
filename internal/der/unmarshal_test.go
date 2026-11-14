package der_test

import (
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
)

func TestUnmarshalValidatesCompleteValueBeforeDecoding(t *testing.T) {
	t.Parallel()
	type record struct {
		Number int
		Label  string
	}
	want := record{Number: 42, Label: "note"}
	raw, err := asn1.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got record
	if err := der.Unmarshal(raw, &got); err != nil || got != want {
		t.Fatalf("decoded %+v with error %v, want %+v", got, err, want)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"trailing_value", append(append([]byte(nil), raw...), der.Int(7)...)},
		{"different_type", der.Octets([]byte("note"))},
		{"truncated_sequence", raw[:len(raw)-1]},
		{"empty_input", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			before := record{Number: 1, Label: "original"}
			got := before
			if err := der.Unmarshal(tc.raw, &got); !errors.Is(err, der.ErrInvalidDER) || got != before {
				t.Fatalf("decoded %+v with error %v; want unchanged destination and ErrInvalidDER", got, err)
			}
		})
	}
}
