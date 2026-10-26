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
	iencoding "github.com/skarm/xmlsec/transform/internal/xdm/encoding"
	unparsedtext "github.com/skarm/xmlsec/transform/internal/xpath/text"
)

const textUTF8 = "utf-8"

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
	} {
		got, err := unparsedtext.DecodeText(tc.input, tc.encoding, tc.hint)
		if err != nil || got != tc.want {
			t.Fatalf("decoded %q, %v; want %q", got, err, tc.want)
		}
	}

	for _, tc := range []struct {
		input    []byte
		encoding string
	}{
		{[]byte{0xff}, textUTF8},
		{[]byte{0xff, 0xfe, 'x', 0}, textUTF8},
		{[]byte{0xd8, 0}, "utf-16be"},
		{[]byte("x"), "not-an-encoding"},
	} {
		var detail *unparsedtext.Error
		if _, err := unparsedtext.DecodeText(tc.input, tc.encoding); !errors.As(err, &detail) || detail.Code != unparsedtext.ErrCodeEncoding {
			t.Fatalf("malformed encoding accepted: %v", err)
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
	codec := iencoding.Load("iso-2022-jp")

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

func TestLineLimitDoesNotHideCloseFailure(t *testing.T) {
	failure := errors.New("close failed")

	cfg := &unparsedtext.Config{URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return closeFailure{Reader: strings.NewReader("a\nb\nc\n"), err: failure}, nil
	})}
	if _, _, err := unparsedtext.LoadTextLinesBounded(t.Context(), cfg, "urn:text", "", 1); !errors.Is(err, failure) {
		t.Fatal(err)
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
	err error
}

func (r closeFailure) Close() error { return r.err }

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
