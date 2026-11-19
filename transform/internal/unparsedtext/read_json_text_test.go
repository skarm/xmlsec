package unparsedtext_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/transform/internal/unparsedtext"
)

func TestReadJSONTextDetectsUnicode(t *testing.T) {
	for _, tc := range []struct {
		name, input, media, want string
		compatible               bool
	}{
		{name: "utf8_with_bom", input: "\xef\xbb\xbf[\"é\"]", want: `["é"]`, compatible: true},
		{name: "utf8_bom_with_charset_alias", input: "\xef\xbb\xbf[\"é\"]", media: "application/json; charset=unicode-1-1-utf-8", want: `["é"]`, compatible: true},
		{name: "utf16be_with_bom", input: "\xfe\xff\x00[\x00]\x00\n", want: "[]\n", compatible: true},
		{name: "utf16be_without_bom", input: "\x00[\x00]", want: "[]"},
		{name: "utf16le_without_bom", input: "[\x00]\x00", want: "[]"},
		{name: "short_utf16be_without_bom", input: "\x001", want: "1"},
		{name: "short_utf16le_without_bom", input: "1\x00", want: "1"},
		{name: "utf32be_without_bom", input: "\x00\x00\x00[\x00\x00\x00]", want: "[]"},
		{name: "utf32le_without_bom", input: "[\x00\x00\x00]\x00\x00\x00", want: "[]"},
		{name: "utf32be_with_bom", input: "\x00\x00\xfe\xff\x00\x00\x00[\x00\x00\x00]", want: "[]", compatible: true},
		{name: "utf32le_bom_with_generic_charset", input: "\xff\xfe\x00\x00[\x00\x00\x00]\x00\x00\x00", media: "application/json; charset=utf-32", want: "[]", compatible: true},
		{name: "transport_charset", input: "\"caf\xe9\"", media: "application/json; charset=iso-8859-1", want: `"café"`, compatible: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := mediaReader{trackedReader: &trackedReader{Reader: iotest.OneByteReader(strings.NewReader(tc.input))}, media: tc.media}
			encoded, decoded, retained := 0, 0, 0
			cfg := &unparsedtext.Config{
				URIResolver: resolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
					if uri != textResourceURI {
						t.Errorf("resolver URI = %q, want %q", uri, textResourceURI)
					}
					return body, nil
				}),
				ReadBytes: func(n int) { encoded += n }, DecodedBytes: func(n int) { decoded += n },
				CheckBytes: func(n int) error { retained += n; return nil },
			}
			var output bytes.Buffer
			compatible, err := unparsedtext.ReadJSONText(t.Context(), cfg, textResourceURI, func(chunk []byte) error {
				_, err := output.Write(chunk)
				return err
			})
			if err != nil || output.String() != tc.want || compatible != tc.compatible {
				t.Fatalf("JSON text = (%q, compatible=%t, %v), want (%q, compatible=%t, nil)", output.String(), compatible, err, tc.want, tc.compatible)
			}
			if compatible {
				text, err := unparsedtext.DecodeText([]byte(tc.input), "", tc.media)
				if err != nil || text != output.String() {
					t.Errorf("compatible text = %q, %v; want %q, nil", text, err, output.String())
				}
			}
			if !body.closed || encoded != len(tc.input) || decoded != len(tc.want) || retained != len(tc.want) {
				t.Errorf("closed=%t, bytes read/decoded/retained=%d/%d/%d, want true and %d/%d/%d", body.closed, encoded, decoded, retained, len(tc.input), len(tc.want), len(tc.want))
			}
		})
	}
}

func TestReadJSONTextReportsEncodingFailureAndClosesResource(t *testing.T) {
	for _, tc := range []struct {
		name, input, media string
	}{
		{name: "charset_conflicts_with_bom", input: "\xfe\xff\x00[\x00]", media: "application/json; charset=utf-8"},
		{name: "incomplete_utf8_character", input: "\xc3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := mediaReader{trackedReader: &trackedReader{Reader: strings.NewReader(tc.input)}, media: tc.media}
			cfg := &unparsedtext.Config{URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) { return body, nil })}
			calls := 0
			_, err := unparsedtext.ReadJSONText(t.Context(), cfg, textResourceURI, func([]byte) error {
				calls++
				return nil
			})
			var detail *unparsedtext.Error
			if !errors.As(err, &detail) || detail.Code != unparsedtext.ErrCodeEncoding || !body.closed || calls != 0 {
				t.Errorf("ReadJSONText error=%v, closed=%t, consume calls=%d, want encoding failure, closed reader and no output", err, body.closed, calls)
			}
		})
	}
}

func TestReadJSONTextEscapesAndAccountsForNonXMLCharacters(t *testing.T) {
	const input, want = "\"a\x00é\"", `"a\u0000é"`
	budgetFailure := errors.New("output budget exceeded")
	for _, tc := range []struct {
		name    string
		maxSize int
		want    string
		wantErr error
	}{
		{name: "accept_expanded_size", maxSize: len(want), want: want},
		{name: "reject_before_consume", maxSize: len(want) - 1, wantErr: budgetFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedReader{Reader: strings.NewReader(input)}
			decoded, charged := 0, 0
			cfg := &unparsedtext.Config{
				URIResolver:  resolverFunc(func(context.Context, string) (io.ReadCloser, error) { return body, nil }),
				DecodedBytes: func(n int) { decoded += n },
				CheckBytes: func(n int) error {
					charged += n
					if charged > tc.maxSize {
						return budgetFailure
					}
					return nil
				},
			}
			var output bytes.Buffer
			compatible, err := unparsedtext.ReadJSONText(t.Context(), cfg, textResourceURI, func(chunk []byte) error {
				_, err := output.Write(chunk)
				return err
			})
			if !errors.Is(err, tc.wantErr) || output.String() != tc.want || (err == nil && compatible) {
				t.Errorf("JSON text = (%q, compatible=%t, %v), want %q and %v", output.String(), compatible, err, tc.want, tc.wantErr)
			}
			if !body.closed || decoded != len(input) || charged != len(want) {
				t.Errorf("closed=%t, decoded=%d, charged=%d, want true, %d and %d", body.closed, decoded, charged, len(input), len(want))
			}
		})
	}
}
