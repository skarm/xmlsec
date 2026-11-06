package html //nolint:testpackage // Verifies internal byte-alignment and defensive writer bookkeeping.

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

type limitedEncodingWriter struct {
	bytes.Buffer
	limit  int
	silent bool
}

func (w *limitedEncodingWriter) Write(p []byte) (int, error) {
	n := min(len(p), w.limit)
	w.limit -= n
	_, _ = w.Buffer.Write(p[:n])
	if n < len(p) && !w.silent {
		return n, io.ErrClosedPipe
	}
	return n, nil
}

func TestLatin1WriterReturnsOnlyCompleteInputCharacters(t *testing.T) {
	t.Parallel()

	const source = "Aé中😀"
	const encoded = "A\xe9&#20013;&#128512;"
	for _, test := range []struct{ limit, consumed int }{{0, 0}, {1, 1}, {2, 3}, {3, 3}, {9, 3}, {10, 6}, {18, 6}, {19, 10}} {
		out := &limitedEncodingWriter{limit: test.limit}
		writer := latin1EncodingWriter{w: out, strict: true}
		n, err := writer.Write([]byte(source))
		if n != test.consumed || out.String() != encoded[:test.limit] || (test.limit < len(encoded) && !errors.Is(err, io.ErrClosedPipe)) || (test.limit == len(encoded) && err != nil) {
			t.Fatalf("limit %d: Write = %d, %q, %v; want consumed %d", test.limit, n, out.String(), err, test.consumed)
		}
	}
	out := &limitedEncodingWriter{limit: 1, silent: true}
	if n, err := (&latin1EncodingWriter{w: out, strict: true}).Write([]byte("Aé")); n != 1 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("silent partial encoded write accepted", n, err)
	}
	for _, test := range []struct {
		text, want string
		strict     bool
	}{
		{"plain ASCII", "plain ASCII", true},
		{"A€é中", "A\x80\xe9中", false},
	} {
		var output bytes.Buffer
		if n, err := (&latin1EncodingWriter{w: &output, strict: test.strict}).Write([]byte(test.text)); n != len(test.text) || err != nil || output.String() != test.want {
			t.Fatal("encoded output or consumed length", n, output.String(), err)
		}
	}
}

func TestMarkupNameValidationAndStickyFailure(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"", "bad name", "bad/attribute", "bad=attribute", "bad\x00attribute", string([]byte{'a', 0xff})} {
		d := htmlDumper{}
		d.checkName("attribute", name)
		if d.err == nil {
			t.Fatalf("unsafe attribute name accepted: %q", name)
		}
	}
	for _, name := range []string{"", "bad?tag", "bad&tag", "bad/tag", "bad\x7ftag", string([]byte{'a', 0xff})} {
		d := htmlDumper{}
		d.checkElementName(name)
		if d.err == nil {
			t.Fatalf("unsafe element name accepted: %q", name)
		}
	}
	for _, name := range []string{"valid", "name-with.dots_1", "é", "\ufffd"} {
		d := htmlDumper{}
		d.checkElementName(name)
		d.checkName("attribute", name)
		if d.err != nil {
			t.Fatal("safe Unicode/name rejected", name, d.err)
		}
	}
	first := errors.New("first failure")
	d := htmlDumper{}
	d.check(first)
	d.check(errors.New("later failure"))
	d.checkName("attribute", "")
	d.checkElementName("")
	var output bytes.Buffer
	d.writeString(&output, "forbidden")
	if !errors.Is(d.err, first) || output.Len() != 0 {
		t.Fatal("sticky first error was replaced or output continued", d.err, output.String())
	}
}

func TestMappedMalformedUTF8SourceBoundaries(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, source, form, want, attributeWant string
		mapping                                 map[rune]string
	}{
		{"one malformed byte", "\xff", "NFC", "x", "x", map[rune]string{'\uFFFD': "x"}},
		{"two malformed bytes", "\xff\xfe", "NFC", "xx", "xx", map[rune]string{'\uFFFD': "x"}},
		{"malformed middle", "A\xffB", "NFC", "AxB", "AxB", map[rune]string{'\uFFFD': "x"}},
		{"encoded replacement", "\uFFFD", "NFC", "x", "x", map[rune]string{'\uFFFD': "x"}},
		{"without map", "\xff", "NFC", "\xff", "\xff", nil},
		{"unrelated map", "\xff", "NFC", "\xff", "\xff", map[rune]string{'Q': "y"}},
		{"without normalization", "\xff", "none", "x", "x", map[rune]string{'\uFFFD': "x"}},
		{"valid composition", "A\u030A", "NFC", "Å", "&Aring;", map[rune]string{'\uFFFD': "x"}},
	} {
		for _, attribute := range []bool{false, true} {
			route := "text"
			if attribute {
				route = "attribute"
			}

			t.Run(tc.name+"/"+route, func(t *testing.T) {
				t.Parallel()

				defer func() {
					if p := recover(); p != nil {
						t.Errorf("serialization must not panic for a raw Go string: %v", p)
					}
				}()

				doc := xdm.NewDefaultDocument()
				var node xdm.Node = doc.CreateText(tc.source)
				want := tc.want
				if attribute {
					element, err := doc.CreateElement("r")
					if err != nil {
						t.Fatal(err)
					}

					if err := element.SetAttribute("a", tc.source); err != nil {
						t.Fatal(err)
					}

					node, want = element, `<r a="`+tc.attributeWant+`"></r>`
				}

				var output bytes.Buffer

				err := NewWriter().Format(false).CharacterMap(tc.mapping).Normalization(tc.form).WriteTo(&output, node)
				if err != nil {
					t.Fatal(err)
				}

				if output.String() != want {
					t.Fatalf("got %q, want %q", output.String(), want)
				}
			})
		}
	}
}

func TestMappedMalformedUTF8PreservesCallbackOrderAndError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("mapped segment callback failed")
	dumper := NewWriter().CharacterMap(map[rune]string{'\uFFFD': "x"}).Normalization("NFC").dumper()
	var segments []string

	err := dumper.normalizedContent("A\xffB", func(segment string, mapped bool) error {
		segments = append(segments, segment)
		if mapped {
			return sentinel
		}

		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want callback error", err)
	}

	if !reflect.DeepEqual(segments, []string{"A", "x"}) {
		t.Fatalf("got callback segments %q, want [A x]", segments)
	}
}
