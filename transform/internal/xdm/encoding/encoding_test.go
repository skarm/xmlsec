package encoding_test

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"golang.org/x/text/transform"

	"github.com/skarm/xmlsec/transform/internal/unparsedtext"
	"github.com/skarm/xmlsec/transform/internal/xdm/encoding"
)

func TestLoadDecodesIncrementally(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

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
	t.Parallel()

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
		{"euc-jp", []byte{0xff}, encoding.ErrInvalidEncodedChar},
		{"shift-jis", []byte{0xff}, encoding.ErrInvalidEncodedChar},
		{"iso-2022-jp", []byte{0x1b}, encoding.ErrInvalidEncodedChar},
		{"big5", []byte{0xff}, encoding.ErrInvalidEncodedChar},
		{"euc-kr", []byte{0xff}, encoding.ErrInvalidEncodedChar},
		{"hz-gb-2312", []byte{0xff}, encoding.ErrInvalidEncodedChar},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

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

func TestLegacyCodecsDecodeValidTextWithoutReplacement(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"euc-jp", "shift-jis", "iso-2022-jp", "big5", "euc-kr", "hz-gb-2312"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			codec := encoding.Load(name)
			// The strict legacy decoder relies on U+FFFD not being a member of
			// the codec's character repertoire, unlike the Unicode codecs.
			if _, err := codec.NewEncoder().String("\ufffd"); err == nil {
				t.Fatal("U+FFFD is representable; replacement detection would reject valid input")
			}
			const want = "A中"
			encoded, err := codec.NewEncoder().String(want)
			if err != nil {
				t.Fatal(err)
			}
			decoder := codec.NewDecoder()
			for range 2 {
				decoder.Reset()
				got, err := io.ReadAll(transform.NewReader(iotest.OneByteReader(strings.NewReader(encoded)), decoder))
				if err != nil || string(got) != want {
					t.Fatalf("decoded %q, %v; want %q", got, err, want)
				}
			}
		})
	}
}

func BenchmarkCodecDecoding(b *testing.B) {
	for _, size := range []int{64, 65536} {
		text := strings.Repeat("café日本😀", max(1, size/len("café日本😀")))
		for _, name := range []string{"utf-8", "utf-16le", "iso-8859-1"} {
			codec := encoding.Load(name)
			source := text
			if name == "iso-8859-1" {
				source = strings.Repeat("café", max(1, size/5))
			}
			encoded, err := codec.NewEncoder().Bytes([]byte(source))
			if err != nil {
				b.Fatal(err)
			}
			b.Run(name+"/"+strconv.Itoa(size), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(encoded)))
				for b.Loop() {
					if _, err := codec.NewDecoder().Bytes(encoded); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func TestUndefinedSingleByteDecodeRejectsSubstitution(t *testing.T) {
	t.Parallel()

	for _, input := range [][]byte{{0xa1}, {'A', 0xa1, 'B'}} {
		if got, err := encoding.Load("iso-8859-6").NewDecoder().Bytes(input); !errors.Is(err, encoding.ErrInvalidEncodedChar) {
			t.Fatalf("undefined octet decoded to %q, %v; want ErrInvalidEncodedChar", got, err)
		}
		got, err := unparsedtext.DecodeText(input, "iso-8859-6")
		var detail *unparsedtext.Error
		if got != "" || !errors.As(err, &detail) || detail.Code != unparsedtext.ErrCodeEncoding || !errors.Is(err, encoding.ErrInvalidEncodedChar) {
			t.Fatalf("undefined octet text %q, %v; want empty/FOUT1190 retaining ErrInvalidEncodedChar", got, err)
		}
	}
}

func TestSingleByteDecodePreservesAssignedAndReplacementCharacters(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, label string
		input       []byte
		want        string
	}{
		{"assigned Arabic", "iso-8859-6", []byte{0xc7}, "ا"},
		{"assigned ISO88591", "iso-8859-1", []byte{0xa1}, "¡"},
		{"missing C1 fallback", "iso-8859-6", []byte{0x80}, "\u0080"},
		{"Windows Euro assigned C1", "windows-1252", []byte{0x80}, "€"},
		{"Windows missing C1 fallback", "windows-1252", []byte{0x81}, "\u0081"},
		{"genuine UTF8 replacement", "utf-8", []byte{0xef, 0xbf, 0xbd}, "\ufffd"},
		{"genuine UTF16 replacement", "utf-16be", []byte{0xff, 0xfd}, "\ufffd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := encoding.Load(tc.label).NewDecoder().Bytes(tc.input)
			if err != nil || string(got) != tc.want {
				t.Fatalf("codec got %q, %v; want %q", got, err, tc.want)
			}
			text, err := unparsedtext.DecodeText(tc.input, tc.label)
			if err != nil || text != tc.want {
				t.Fatalf("text got %q, %v; want %q", text, err, tc.want)
			}
			// Unicode codecs may emit a BOM, so the exact inverse-byte assertion
			// belongs only to these independently specified single-byte mappings.
			if tc.label != "utf-8" && tc.label != "utf-16be" {
				encoded, err := encoding.Load(tc.label).NewEncoder().Bytes([]byte(tc.want))
				if err != nil || !bytes.Equal(encoded, tc.input) {
					t.Fatalf("encoder got %x, %v; want %x", encoded, err, tc.input)
				}
			}
		})
	}
}

func TestUndefinedSingleByteTransformCountsAndReset(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		input      []byte
		capacity   int
		want       string
		wantSource int
	}{
		{"first octet", []byte{0xa1}, 8, "", 0},
		{"after prefix", []byte{'A', 0xa1, 'B'}, 8, "A", 1},
		{"no destination", []byte{0xa1}, 0, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			decoder := encoding.Load("iso-8859-6").NewDecoder()
			dst := make([]byte, tc.capacity)
			nd, ns, err := decoder.Transform(dst, tc.input, true)
			if nd != len(tc.want) || ns != tc.wantSource || !errors.Is(err, encoding.ErrInvalidEncodedChar) || string(dst[:nd]) != tc.want {
				t.Fatalf("Transform = %q (%d,%d), %v; want %q (%d,%d), ErrInvalidEncodedChar", dst[:nd], nd, ns, err, tc.want, len(tc.want), tc.wantSource)
			}
			decoder.Reset()
			dst = make([]byte, 4)
			nd, ns, err = decoder.Transform(dst, []byte{0xc7, 0x80}, true)
			if nd != 4 || ns != 2 || err != nil || string(dst[:nd]) != "ا\u0080" {
				t.Fatalf("Reset after rejection = %q (%d,%d), %v; want Arabic/C1 (4,2), nil", dst[:nd], nd, ns, err)
			}
		})
	}

	decoder := encoding.Load("iso-8859-6").NewDecoder()
	input := []byte{'A', 0xc7, 'B'}
	dst := make([]byte, 2)
	nd, ns, err := decoder.Transform(dst, input, true)
	if nd != 1 || ns != 1 || !errors.Is(err, transform.ErrShortDst) || string(dst[:nd]) != "A" {
		t.Fatalf("short destination = %q (%d,%d), %v; want A (1,1), ErrShortDst", dst[:nd], nd, ns, err)
	}
	dst = make([]byte, 3)
	nd, consumed, err := decoder.Transform(dst, input[ns:], true)
	if nd != 3 || consumed != 2 || err != nil || string(dst[:nd]) != "اB" {
		t.Fatalf("retry = %q (%d,%d), %v; want اB (3,2), nil", dst[:nd], nd, consumed, err)
	}

	decoder.Reset()
	dst = make([]byte, 4)
	nd, ns, err = decoder.Transform(dst, []byte{0xc7, 0x80}, true)
	if nd != 4 || ns != 2 || err != nil || string(dst[:nd]) != "ا\u0080" {
		t.Fatalf("Reset = %q (%d,%d), %v; want Arabic/C1 (4,2), nil", dst[:nd], nd, ns, err)
	}
}
