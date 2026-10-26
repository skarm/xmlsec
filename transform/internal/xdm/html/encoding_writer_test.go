package html //nolint:testpackage // Verifies internal byte-alignment and defensive writer bookkeeping.

import (
	"bytes"
	"errors"
	"io"
	"testing"
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
