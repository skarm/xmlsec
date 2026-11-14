package der_test

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
)

func TestExplicitRequiresOneChildAndMatchingTag(t *testing.T) {
	t.Parallel()
	const tag = 33
	child := der.Int(17)
	for _, tc := range []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"one_child_under_high_context_tag", der.Ctx(tag, child), true},
		{"wrong_context_tag", der.Ctx(tag+1, child), false},
		{"wrong_class", der.Wrap(asn1.ClassApplication, tag, true, child), false},
		{"primitive", der.Wrap(asn1.ClassContextSpecific, tag, false, child), false},
		{"empty", der.Ctx(tag), false},
		{"two_children", der.Ctx(tag, child, der.Int(18)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			value, err := der.Read(tc.raw, len(tc.raw))
			if err != nil {
				t.Fatalf("read wrapper fixture: %v", err)
			}
			got, err := der.Explicit(value, tag)
			if !tc.ok {
				if !errors.Is(err, der.ErrInvalidDER) || len(got.FullBytes) != 0 {
					t.Fatalf("result=%x, error=%v; want no child and ErrInvalidDER", got.FullBytes, err)
				}
				return
			}
			var integer int
			if err != nil || !bytes.Equal(got.FullBytes, child) {
				t.Fatalf("result=%x, error=%v; want the original child %x", got.FullBytes, err, child)
			}
			if err := der.Decode(got, &integer); err != nil || integer != 17 {
				t.Fatalf("decoded %d with error %v, want 17", integer, err)
			}
		})
	}
}
