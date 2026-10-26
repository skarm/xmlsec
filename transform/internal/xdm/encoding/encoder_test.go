package encoding_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"golang.org/x/text/transform"

	"github.com/skarm/xmlsec/transform/internal/xdm/encoding"
)

func TestEncoderEmitsExactByteOrderAndSingleByteMappings(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, text string
		want       []byte
	}{
		{"utf-8", "A😀", []byte{0x41, 0xf0, 0x9f, 0x98, 0x80}},
		{"utf-16le", "A😀", []byte{0x41, 0, 0x3d, 0xd8, 0, 0xde}},
		{"utf-16be", "A😀", []byte{0, 0x41, 0xd8, 0x3d, 0xde, 0}},
		{"utf-16", "A😀", []byte{0xff, 0xfe, 0x41, 0, 0x3d, 0xd8, 0, 0xde}},
		{"utf-32be", "A😀", []byte{0, 0, 0, 0x41, 0, 1, 0xf6, 0}},
		{"utf-32le", "A😀", []byte{0x41, 0, 0, 0, 0, 0xf6, 1, 0}},
		{"utf-32", "A😀", []byte{0, 0, 0xfe, 0xff, 0, 0, 0, 0x41, 0, 1, 0xf6, 0}},
		{"ucs4-2143", "A😀", []byte{0, 0, 0x41, 0, 1, 0, 0, 0xf6}},
		{"ucs4-3412", "A😀", []byte{0, 0x41, 0, 0, 0xf6, 0, 0, 1}},
		{"iso-8859-1", "A\u0080\u009fé", []byte{0x41, 0x80, 0x9f, 0xe9}},
		{"windows-1252", "A€\u0081é", []byte{0x41, 0x80, 0x81, 0xe9}},
		{"ibm1141", "A€", []byte{0xc1, 0x9f}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			codec := encoding.Load(test.name)
			if codec == nil {
				t.Fatal("codec missing")
			}
			encoder := codec.NewEncoder()
			for range 2 {
				encoder.Reset()
				got, err := io.ReadAll(transform.NewReader(iotest.OneByteReader(strings.NewReader(test.text)), encoder))
				if err != nil || !bytes.Equal(got, test.want) {
					t.Fatalf("encoder = %x, %v; want %x", got, err, test.want)
				}
			}
		})
	}
}

func TestBOMDecoderDefaultsOverridesAndReset(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		input []byte
		want  string
	}{
		{"utf-16", []byte{0xfe, 0xff, 0, 0x41}, "A"},
		{"utf-16", []byte{0xff, 0xfe, 0x41, 0}, "A"},
		{"utf-16", []byte{0x41, 0}, "A"},
		{"utf-32", []byte{0, 0, 0xfe, 0xff, 0, 0, 0, 0x41}, "A"},
		{"utf-32", []byte{0xff, 0xfe, 0, 0, 0x41, 0, 0, 0}, "A"},
		{"utf-32", []byte{0, 0, 0, 0x41}, "A"},
	} {
		t.Run(fmt.Sprintf("%s/%X", test.name, test.input), func(t *testing.T) {
			t.Parallel()

			decoder := encoding.Load(test.name).NewDecoder()
			for range 2 {
				decoder.Reset()
				got, err := io.ReadAll(transform.NewReader(iotest.OneByteReader(bytes.NewReader(test.input)), decoder))
				if err != nil || string(got) != test.want {
					t.Fatalf("decode = %q, %v; want %q", got, err, test.want)
				}
			}
		})
	}
	decoder := encoding.Load("utf-16").NewDecoder()
	buffer := make([]byte, 16)
	if nd, ns, err := decoder.Transform(buffer, []byte{0xfe, 0xff, 0xd8, 0, 0xdc, 0}, true); err != nil || ns != 6 || string(buffer[:nd]) != "𐀀" {
		t.Fatal("BE surrogate pair", buffer[:nd], ns, err)
	}
	decoder.Reset()
	// Under stale BE validation D8 00 would be an unpaired high surrogate;
	// after Reset it is the valid default-LE scalar U+00D8.
	if nd, ns, err := decoder.Transform(buffer, []byte{0xd8, 0}, true); err != nil || ns != 2 || string(buffer[:nd]) != "Ø" {
		t.Fatal("Reset retained prior BOM byte order", buffer[:nd], ns, err)
	}
	for _, test := range []struct {
		name  string
		input []byte
		want  error
	}{
		{"utf-16", []byte{0xff}, encoding.ErrInvalidEncodedChar},
		{"utf-32", []byte{0, 0, 0xfe}, transform.ErrShortSrc},
		{"utf-16be", []byte{0xd8, 0, 0, 0x41}, encoding.ErrInvalidEncodedChar},
		{"utf-16be", []byte{0xd8, 0, 0xe0, 0}, encoding.ErrInvalidEncodedChar},
	} {
		if _, err := encoding.Load(test.name).NewDecoder().Bytes(test.input); !errors.Is(err, test.want) {
			t.Fatalf("malformed %s %x = %v", test.name, test.input, err)
		}
	}
}

func TestRepertoireProbeResetsStateAfterUnsupportedCharacters(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		yes, no rune
	}{
		{"iso-8859-1", 'é', '中'}, {"windows-1252", '€', '😀'}, {"iso-2022-jp", 'あ', '😀'},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			probe := encoding.Repertoire(encoding.Load(test.name).NewEncoder())
			for range 3 {
				if !probe(test.yes) || probe(test.no) || !probe('A') || !probe(test.yes) {
					t.Fatal("probe reused failed/shifted encoder state")
				}
			}
		})
	}
}

func TestASCIILabelAliasesAndNonAliases(t *testing.T) {
	t.Parallel()

	for _, label := range []string{"ascii", " ANSI_X3.4-1968 ", "iso_646.irv:1991", "IBM367"} {
		if !encoding.IsASCII(label) {
			t.Fatalf("ASCII alias not recognized: %q", label)
		}
	}
	if encoding.IsASCII("utf-8") || encoding.IsASCII("ascii-compatible") {
		t.Fatal("non-ASCII codec mislabeled strict ASCII")
	}
}

func TestDecoderScalarBoundaries(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		input []byte
		want  string
	}{
		{"ascii", []byte{0, 0x7e, 0x7f}, "\x00~\x7f"},
		{"utf-16be", []byte{0xdb, 0xff, 0xdf, 0xff}, "\U0010ffff"},
		{"utf-16le", []byte{0xff, 0xdb, 0xff, 0xdf}, "\U0010ffff"},
		{"utf-32be", []byte{0, 0x10, 0xff, 0xff}, "\U0010ffff"},
		{"utf-32le", []byte{0xff, 0xff, 0x10, 0}, "\U0010ffff"},
		{"utf-32be", []byte{0, 0, 0xff, 0xfd}, "\ufffd"},
	} {
		got, err := encoding.Load(test.name).NewDecoder().Bytes(test.input)
		if err != nil || string(got) != test.want {
			t.Fatalf("%s scalar %x = %q, %v; want %q", test.name, test.input, got, err, test.want)
		}
	}
}
