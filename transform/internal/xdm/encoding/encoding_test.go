package encoding_test

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/transform/internal/xdm/encoding"

	"golang.org/x/text/transform"
)

func TestLoadDecodesIncrementally(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		want  string
	}{
		{"ANSI_X3.4-1968", []byte("XML"), "XML"},
		{" UTF_16LE ", []byte{0x41, 0, 0x3d, 0xd8, 0, 0xde}, "A😀"},
		{"utf-16be", []byte{0, 0x41, 0xd8, 0x3d, 0xde, 0}, "A😀"},
		{"utf-16", []byte{0xfe, 0xff, 0, 0x41}, "A"},
		{"utf-32be", []byte{0, 0, 0, 0x41, 0, 1, 0xf6, 0}, "A😀"},
		{"ucs4-2143", []byte{0, 0, 0x41, 0, 1, 0, 0, 0xf6}, "A😀"},
		{"ucs4-3412", []byte{0, 0x41, 0, 0, 0xf6, 0, 0, 1}, "A😀"},
		{"ISO-8859-1", []byte{0x80, 0xe9}, "\u0080é"},
		{"windows-1252", []byte{0x80, 0x81}, "€\u0081"},
		{"ibm1141", []byte{0xc1, 0x9f}, "A€"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			codec := encoding.Load(tc.name)
			if codec == nil {
				t.Fatal("codec unavailable")
			}

			decoder := codec.NewDecoder()
			for range 2 {
				decoder.Reset()

				got, err := io.ReadAll(transform.NewReader(iotest.OneByteReader(bytes.NewReader(tc.input)), decoder))
				if err != nil || string(got) != tc.want {
					t.Fatalf("decoded %q, %v; want %q", got, err, tc.want)
				}
			}
		})
	}

	if encoding.Load("not-an-encoding") != nil {
		t.Fatal("unknown encoding accepted")
	}
}

func TestLoadRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		want  error
	}{
		{"us-ascii", []byte{0x80}, encoding.ErrInvalidASCII},
		{"utf-16le", []byte{0x41}, encoding.ErrInvalidEncodedChar},
		{"utf-16be", []byte{0xd8, 0}, encoding.ErrInvalidEncodedChar},
		{"utf-16le", []byte{0, 0xdc}, encoding.ErrInvalidEncodedChar},
		{"utf-32be", []byte{0, 0, 0xd8, 0}, encoding.ErrInvalidEncodedChar},
		{"utf-32le", []byte{0, 0, 0x11, 0}, encoding.ErrInvalidEncodedChar},
		{"ucs4-2143", []byte{0, 0, 0}, encoding.ErrInvalidEncodedChar},
		{"ucs4-3412", []byte{0, 0, 0}, encoding.ErrInvalidEncodedChar},
	} {
		t.Run(tc.name, func(t *testing.T) {
			codec := encoding.Load(tc.name)
			if codec == nil {
				t.Fatal("codec unavailable")
			}

			_, err := io.ReadAll(transform.NewReader(iotest.OneByteReader(bytes.NewReader(tc.input)), codec.NewDecoder()))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	codec := encoding.Load("utf-16be")

	got, err := codec.NewDecoder().Bytes([]byte{0xff, 0xfd})
	if err != nil || string(got) != "\ufffd" {
		t.Fatalf("literal U+FFFD rejected: %q, %v", got, err)
	}
}
