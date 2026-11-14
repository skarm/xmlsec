package tree_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf16"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

func TestXMLPrologValidation(t *testing.T) {
	for _, test := range []struct {
		source string
		valid  bool
	}{
		{`<r/>`, true},
		{`<r>`, true},
		{`<r><unfinished`, true},
		{`<r/><s/>`, true},
		{`<?xml version="1.0"?><!--ok--><r a="v">`, true},
		{``, false},
		{`<?xml version="1.0"?>`, false},
		{`<r a=>`, false},
		{`<r a="1" a="2">`, false},
		{`<p:r>`, false},
		{`<!DOCTYPE r><r>`, false},
		{`text<r>`, false},
		{`<!--invalid--comment--><r>`, false},
	} {
		encoded := make([]byte, 2, 2+2*len(test.source))
		encoded[0], encoded[1] = 0xff, 0xfe
		for _, value := range utf16.Encode([]rune(test.source)) {
			encoded = append(encoded, byte(value), byte(value>>8))
		}
		for _, data := range [][]byte{[]byte(test.source), encoded} {
			err := treepkg.CheckXMLProlog(t.Context(), bytes.NewReader(data), treepkg.DefaultLimits(), false)
			if (err == nil) != test.valid {
				t.Fatal(test.source, data, err, test.valid)
			}
		}
	}
	limits := treepkg.DefaultLimits()
	limits.MaxBytes = 32
	if err := treepkg.CheckXMLProlog(t.Context(), strings.NewReader(strings.Repeat(" ", 64)+`<r/>`), limits, false); !errors.Is(err, treepkg.ErrLimit) {
		t.Fatal(err)
	}
	if err := treepkg.CheckXMLProlog(t.Context(), iotest.ErrReader(io.ErrClosedPipe), treepkg.DefaultLimits(), false); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := treepkg.CheckXMLProlog(ctx, strings.NewReader(`<r>`), treepkg.DefaultLimits(), false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
