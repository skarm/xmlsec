package unparsedtext_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/unparsedtext"
	"github.com/skarm/xmlsec/transform/internal/xdm/encoding"
)

const textUTF8 = "utf-8"

func TestResolveTextURIPreservesEmptyPathSegment(t *testing.T) {
	t.Parallel()

	cfg := &unparsedtext.Config{BaseURI: "https://example.test/a/b/main.xml"}
	for _, tc := range []struct{ reference, want string }{
		{"../..//value.txt", "https://example.test//value.txt"},
		{"../../value.txt", "https://example.test/value.txt"},
	} {
		got, err := unparsedtext.ResolveURI(t.Context(), cfg, tc.reference)
		if err != nil || got != tc.want {
			t.Errorf("ResolveURI(%q) = %q, %v; want %q", tc.reference, got, err, tc.want)
		}
	}
}

func TestLoadTextResourceBoundsAndOwnership(t *testing.T) {
	for _, tc := range []struct {
		input    string
		wantCode string
	}{{"abc", ""}, {"abcd", unparsedtext.ErrCodeRetrieval}, {"a\x00", unparsedtext.ErrCodeEncoding}} {
		t.Run(tc.input, func(t *testing.T) {
			reader := &trackedReader{Reader: strings.NewReader(tc.input)}
			cfg := &unparsedtext.Config{BaseURI: "mem:///dir/main", MaxBytes: 3, URIResolver: resolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
				if ctx != t.Context() || uri != "mem:///dir/data" {
					t.Errorf("resolver inputs: %v, %q", ctx, uri)
				}

				return reader, nil
			})}

			got, err := unparsedtext.LoadText(t.Context(), cfg, "data", "")
			if !reader.closed {
				t.Fatal("resource not closed")
			}

			if tc.wantCode == "" {
				if err != nil || got != tc.input {
					t.Fatalf("got %q, %v", got, err)
				}

				return
			}

			var detail *unparsedtext.Error
			if !errors.As(err, &detail) || detail.Code != tc.wantCode || got != "" {
				t.Fatalf("got %q, %v; want %s", got, err, tc.wantCode)
			}
		})
	}

	if _, err := unparsedtext.LoadText(t.Context(), nil, "file:///unconfigured", ""); err == nil {
		t.Fatal("implicit file access enabled")
	}
}

func TestDecodeText(t *testing.T) {
	for _, tc := range []struct {
		input    []byte
		encoding string
		hint     string
		want     string
	}{
		{[]byte{0xef, 0xbb, 0xbf, 'x'}, "", textUTF8, "x"},
		{[]byte{0xff, 0xfe, 'x', 0}, "utf-16", "", "x"},
		{[]byte{0xe9}, "", "iso-8859-1", "é"},
		{[]byte("\x00\x00\xfe\xff\x00\x00\x00x"), "", "", "x"},
		{[]byte("\x00\x00\xfe\xff\x00\x00\x00x"), "utf-32be", "", "x"},
		{[]byte("\xff\xfe\x00\x00x\x00\x00\x00"), "utf-32le", "", "x"},
		{[]byte("\xff\xfe\x00\x00x\x00\x00\x00"), "utf-32", "", "x"},
		{[]byte("\xff\xfe\x00\x00x\x00\x00\x00"), "", "application/json; charset=utf-32", "x"},
	} {
		got, err := unparsedtext.DecodeText(tc.input, tc.encoding, tc.hint)
		if err != nil || got != tc.want {
			t.Errorf("decode % x with encoding %q and metadata %q = %q, %v; want %q", tc.input, tc.encoding, tc.hint, got, err, tc.want)
		}
	}

	for _, tc := range []struct {
		input    []byte
		encoding string
	}{
		{[]byte{0xff}, textUTF8},
		{[]byte{0xff, 0xfe, 'x', 0}, textUTF8},
		{[]byte("\xff\xfe\x00\x00x\x00\x00\x00"), "utf-32be"},
		{[]byte("\xff\xfe\x00\x00x\x00\x00\x00"), "utf-16le"},
		{[]byte{0xd8, 0}, "utf-16be"},
		{[]byte("x"), "not-an-encoding"},
		{[]byte{0xff}, "euc-jp"},
		{[]byte{0xff}, "shift-jis"},
		{[]byte{0x1b}, "iso-2022-jp"},
		{[]byte{0xff}, "big5"},
		{[]byte{0xff}, "euc-kr"},
		{[]byte{0xff}, "hz-gb-2312"},
	} {
		var detail *unparsedtext.Error
		if _, err := unparsedtext.DecodeText(tc.input, tc.encoding); !errors.As(err, &detail) || detail.Code != unparsedtext.ErrCodeEncoding {
			t.Fatalf("malformed encoding accepted: %v", err)
		}
	}
}

func TestDecodeXMLTextDoesNotTreatStylesheetPIAsDeclaration(t *testing.T) {
	const xml = "<?xml-stylesheet encoding='invalid-but-legal-PI-data'?>\n<doc/>"
	got, err := unparsedtext.DecodeText([]byte(xml), "", "application/xml")
	if err != nil || got != xml {
		t.Fatalf("decode XML = %q, %v; want %q", got, err, xml)
	}
}

func TestDecodeTextAcceptsUTF8AliasesWithBOM(t *testing.T) {
	const want = "café\ufffd"
	for _, label := range []string{"unicode-1-1-utf-8", "unicode-2-0-utf-8", "x-unicode-2-0-utf-8"} {
		for _, config := range []struct{ encoding, hint string }{{label, ""}, {"", "text/plain; charset=" + label}} {
			got, err := unparsedtext.DecodeText([]byte("\xef\xbb\xbf"+want), config.encoding, config.hint)
			if err != nil || got != want {
				t.Errorf("encoding %q, metadata %q = %q, %v; want %q", config.encoding, config.hint, got, err, want)
			}
		}
	}
}

func TestSplitLinesBounded(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"a\r\nb\rc\n", []string{"a", "b", "c"}},
		{"\n\n", []string{"", ""}},
		{"a\u0085b", []string{"a\u0085b"}},
	} {
		if got := unparsedtext.SplitLines(tc.input); !slices.Equal(got, tc.want) {
			t.Errorf("lines(%q) = %q, want %q", tc.input, got, tc.want)
		}

		got, truncated := unparsedtext.SplitLinesBounded(tc.input, 1)

		want := tc.want
		if len(want) > 2 {
			want = want[:2]
		}

		if !slices.Equal(got, want) || truncated != (len(tc.want) > 1) {
			t.Errorf("bounded lines(%q) = %q, %v", tc.input, got, truncated)
		}
	}
}

func TestTextReaderPreservesStatefulEncoding(t *testing.T) {
	text := strings.Repeat("日本語abc", 10000)
	codec := encoding.Load("iso-2022-jp")

	source, err := codec.NewEncoder().Bytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}

	cfg := &unparsedtext.Config{URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(iotest.OneByteReader(bytes.NewReader(source))), nil
	})}

	got, err := unparsedtext.LoadText(t.Context(), cfg, "urn:text", "iso-2022-jp")
	if err != nil || got != text {
		t.Fatalf("stateful decoding changed: %v", err)
	}
}

func TestTextReaderRejectsDecodedExpansion(t *testing.T) {
	cfg := &unparsedtext.Config{MaxBytes: 3, URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("\xe9\xe9\xe9")), nil
	})}
	if got, err := unparsedtext.LoadText(t.Context(), cfg, "urn:text", "iso-8859-1"); got != "" || !errors.Is(err, tree.ErrLimit) {
		t.Fatal(got, err)
	}
}

func TestTextValidationPreservesSimultaneousReadFailure(t *testing.T) {
	readFailure := errors.New("read failed")
	for _, tc := range []struct {
		name, tail, encoding, wantCode string
		maxBytes                       int64
		wantLimit                      bool
	}{
		{name: "malformed UTF-8", tail: "\xff", encoding: textUTF8, wantCode: unparsedtext.ErrCodeEncoding},
		{name: "decoded byte cap", tail: "\xe9\xe9", encoding: "iso-8859-1", wantCode: unparsedtext.ErrCodeRetrieval, maxBytes: 8, wantLimit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedReader{Reader: io.MultiReader(
				strings.NewReader("prefix"),
				iotest.DataErrReader(io.MultiReader(strings.NewReader(tc.tail), iotest.ErrReader(readFailure))),
			)}
			cfg := &unparsedtext.Config{MaxBytes: tc.maxBytes, URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				return body, nil
			})}
			text, err := unparsedtext.LoadText(t.Context(), cfg, textResourceURI, tc.encoding)
			var detail *unparsedtext.Error
			if text != "" || !body.closed || !errors.As(err, &detail) || detail.Code != tc.wantCode || !errors.Is(err, readFailure) || errors.Is(err, tree.ErrLimit) != tc.wantLimit {
				t.Fatalf("LoadText = (%q, %v), closed=%t; want %s retaining read failure and limit=%t", text, err, body.closed, tc.wantCode, tc.wantLimit)
			}
		})
	}
}

func TestLineLimitDoesNotHideCloseFailure(t *testing.T) {
	failure := errors.New("close failed")

	cfg := &unparsedtext.Config{URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return closeFailure{Reader: strings.NewReader("a\nb\nc\n"), err: failure}, nil
	})}
	if _, _, err := unparsedtext.LoadTextLinesBounded(t.Context(), cfg, "urn:text", "", 1); !errors.Is(err, failure) {
		t.Fatal(err)
	}
}

func TestLineLimitDoesNotHideReadFailure(t *testing.T) {
	failure := errors.New("read failed")
	body := &trackedReader{Reader: io.MultiReader(
		strings.NewReader("first "),
		iotest.DataErrReader(io.MultiReader(strings.NewReader("line\nsecond line\n"), iotest.ErrReader(failure))),
	)}
	cfg := &unparsedtext.Config{URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return body, nil
	})}
	lines, truncated, err := unparsedtext.LoadTextLinesBounded(t.Context(), cfg, "urn:text", "", 1)
	if lines != nil || truncated || !errors.Is(err, failure) || !body.closed {
		t.Fatalf("lines = %q, truncated = %t, closed = %t, error = %v; want read failure and closed stream", lines, truncated, body.closed, err)
	}
}

func TestLineLimitCompletion(t *testing.T) {
	failure := errors.New("close failed")
	for _, tc := range []struct {
		name     string
		closeErr error
		cancel   bool
	}{
		{name: "successful truncation"},
		{name: "close failure joined with EOF", closeErr: errors.Join(io.EOF, failure)},
		{name: "cancellation on close", cancel: true},
		{name: "cancellation and close failure", cancel: true, closeErr: failure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			closed := 0
			cfg := &unparsedtext.Config{URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				return closeFailure{Reader: strings.NewReader("a\nb\nc\n"), err: tc.closeErr, onClose: func() {
					closed++
					if tc.cancel {
						cancel()
					}
				}}, nil
			})}

			lines, truncated, err := unparsedtext.LoadTextLinesBounded(ctx, cfg, "urn:text", "", 1)
			if closed != 1 {
				t.Fatalf("resource closed %d times; want 1", closed)
			}

			if tc.closeErr == nil && !tc.cancel {
				if err != nil || !truncated || !slices.Equal(lines, []string{"a", "b"}) {
					t.Fatalf("successful truncation: %q, %v, %v", lines, truncated, err)
				}

				return
			}

			if lines != nil || truncated || err == nil {
				t.Fatalf("failure returned partial success: %q, %v, %v", lines, truncated, err)
			}

			if tc.closeErr != nil && !errors.Is(err, failure) {
				t.Fatalf("close failure lost: %v", err)
			}

			if tc.cancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}

func FuzzTextLines(f *testing.F) {
	for _, text := range []string{"", "a\r\nb\rc\n", "\n\n", "a🙂\r\nb", strings.Repeat("x", 4095) + "\r\ny"} {
		f.Add(text, uint8(1))
	}

	f.Fuzz(func(t *testing.T, text string, bound uint8) {
		if len(text) > 64<<10 || !utf8.ValidString(text) || unparsedtext.ValidateXMLChars(text) != nil {
			t.Skip()
		}

		var want []string

		normalized := strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(text)
		if normalized != "" {
			want = strings.Split(normalized, "\n")
			if strings.HasSuffix(normalized, "\n") {
				want = want[:len(want)-1]
			}
		}

		limit := int(bound)

		truncated := limit > 0 && len(want) > limit
		if truncated {
			want = want[:limit+1]
		}

		cfg := &unparsedtext.Config{URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(iotest.OneByteReader(strings.NewReader(text))), nil
		})}

		got, more, err := unparsedtext.LoadTextLinesBounded(t.Context(), cfg, "urn:text", "", limit)
		if err != nil || more != truncated || !slices.Equal(got, want) {
			t.Fatalf("lines: %q, %v, %v; want %q, %v", got, more, err, want, truncated)
		}
	})
}

func BenchmarkTextResources(b *testing.B) {
	for _, size := range []int{64, 1 << 20} {
		for _, tc := range []struct {
			name     string
			unit     string
			encoding string
			valid    bool
		}{
			{"ASCII", "abcdef\n", "utf-8", true},
			{"Unicode", "é日本\r\n", "utf-8", true},
			{"InvalidUTF8", "abc\xff", "utf-8", false},
			{"Latin1", "caf\xe9\n", "iso-8859-1", true},
		} {
			b.Run(tc.name+"/"+strconv.Itoa(size), func(b *testing.B) {
				input := strings.Repeat(tc.unit, max(1, size/len(tc.unit)))
				cfg := &unparsedtext.Config{MaxBytes: 4 << 20, URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(input)), nil
				})}
				for _, mode := range []string{"Collect", "Discard", "Lines"} {
					b.Run(mode, func(b *testing.B) {
						b.ReportAllocs()
						if tc.valid {
							b.SetBytes(int64(len(input)))
						}
						for b.Loop() {
							var err error
							switch mode {
							case "Collect":
								_, err = unparsedtext.LoadText(b.Context(), cfg, "urn:bench", tc.encoding)
							case "Discard":
								err = unparsedtext.ReadText(b.Context(), cfg, "urn:bench", tc.encoding, func([]byte) error { return nil })
							default:
								_, err = unparsedtext.LoadTextLines(b.Context(), cfg, "urn:bench", tc.encoding)
							}
							if (err == nil) != tc.valid {
								b.Fatal(err)
							}
						}
					})
				}
			})
		}
	}
}

type resolverFunc func(context.Context, string) (io.ReadCloser, error)

func (f resolverFunc) Resolve(ctx context.Context, uri string) (io.ReadCloser, error) {
	return f(ctx, uri)
}

type trackedReader struct {
	io.Reader
	closed bool
}

func (r *trackedReader) Close() error { r.closed = true; return nil }

type closeFailure struct {
	io.Reader
	err     error
	onClose func()
}

func (r closeFailure) Close() error {
	if r.onClose != nil {
		r.onClose()
	}

	return r.err
}

func TestReviewXMLMediaDetectsDeclaredUTF16WithoutBOM(t *testing.T) {
	for _, name := range []string{"UTF-16BE", "UTF-16LE"} {
		t.Run(name, func(t *testing.T) {
			want := `<?xml version="1.0" encoding="` + name + `"?><root>é</root>`
			input, err := encoding.Load(name).NewEncoder().Bytes([]byte(want))
			if err != nil {
				t.Fatal(err)
			}
			got, err := unparsedtext.DecodeText(input, "", "application/xml")
			if err != nil || got != want {
				t.Fatalf("DecodeText = (%q, %v), want (%q, nil)", got, err, want)
			}
		})
	}
}
