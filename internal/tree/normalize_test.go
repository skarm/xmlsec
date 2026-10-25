package tree_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/normalization"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

func TestLexicalNormalizationOwnsOneCopyAndPreservesReferences(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"<r a=\"a\r\nb\rc\nd\te&#xA;&#xD;&#x9;\">x\r\ny\rz</r>", "<r a=\"a b c d e&#xA;&#xD;&#x9;\">x\ny\nz</r>"},
		{"<!--a\r\nb--><?p a\rb?><r><![CDATA[a\r\nb\rc]]></r>", "<!--a\nb--><?p a\nb?><r><![CDATA[a\nb\nc]]></r>"},
		{"<r>\r\r\n\n\r</r>", "<r>\n\n\n\n</r>"},
		{"<r a='x\ny'>ж</r>", "<r a='x y'>ж</r>"},
	} {
		input := []byte(tc.in)
		original := bytes.Clone(input)

		got, err := treepkg.NormalizeLexicalForTest(input)
		if err != nil || string(got) != tc.want {
			t.Fatalf("%q: %q, %v", tc.in, got, err)
		}

		if !bytes.Equal(input, original) {
			t.Fatal("normalization mutated caller bytes")
		}

		got[0] = '!'

		if !bytes.Equal(input, original) {
			t.Fatal("normalization returned caller storage")
		}
	}
}

// TestUnicodeNormalizationConformance exercises all five columns and all four
// forms of Unicode 17's official NormalizationTest, including the fallback for
// a long combining sequence in the same normalization block.
func TestUnicodeNormalizationConformance(t *testing.T) {
	data, err := os.ReadFile("../../tests/testdata/unicode/NormalizationTest-17.0.0.txt")
	if err != nil {
		t.Fatal(err)
	}

	prefix := "q" + strings.Repeat("\u0315", 31) + "\u0300\u034f"
	normalizedPrefix := "q\u0300" + strings.Repeat("\u0315", 31) + "\u034f"
	count := 0

	for lineNo, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line == "" || strings.HasPrefix(line, "@") {
			continue
		}

		columns := strings.Split(line, ";")
		if len(columns) < 5 {
			t.Fatalf("line %d: invalid fixture", lineNo+1)
		}

		values := make([]string, 5)
		for i := range values {
			var value strings.Builder

			for encoded := range strings.FieldsSeq(columns[i]) {
				r, err := strconv.ParseInt(encoded, 16, 32)
				if err != nil {
					t.Fatal(err)
				}

				value.WriteRune(rune(r))
			}

			values[i] = value.String()
		}

		for _, tc := range []struct {
			form     normalization.Form
			expected []int
		}{
			{normalization.NFC, []int{1, 1, 1, 3, 3}},
			{normalization.NFD, []int{2, 2, 2, 4, 4}},
			{normalization.NFKC, []int{3, 3, 3, 3, 3}},
			{normalization.NFKD, []int{4, 4, 4, 4, 4}},
		} {
			for column, input := range values {
				want := values[tc.expected[column]]
				if got := tc.form.String(input); got != want {
					t.Fatalf("line %d form %d column %d: %U != %U", lineNo+1, tc.form, column+1, []rune(got), []rune(want))
				}

				assertNormalizationWriter(t, tc.form, input, want)
			}

			if got := tc.form.String(prefix + values[0]); got != normalizedPrefix+values[tc.expected[0]] {
				t.Fatalf("long run, line %d form %d: %U", lineNo+1, tc.form, []rune(got))
			}
		}

		count++
	}

	if count < 19000 {
		t.Fatal("incomplete official corpus", count)
	}

	t.Logf("checked %d official normalization rows", count)
}

func assertNormalizationWriter(t *testing.T, form normalization.Form, input, want string) {
	t.Helper()

	var output bytes.Buffer

	writer := normalization.NewWriter(t.Context(), &output, form)
	if _, err := io.WriteString(writer, input); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); err != nil || output.String() != want {
		t.Fatalf("writer form %d: %U != %U, %v", form, []rune(output.String()), []rune(want), err)
	}
}

func TestExactNormalizationWriter(t *testing.T) {
	for _, form := range []normalization.Form{normalization.NFC, normalization.NFD, normalization.NFKC, normalization.NFKD} {
		input := "a" + strings.Repeat("\u0315", 4100) + "\u0300\u034f\u0300\u1100\u1161\u11a8\ufb03"

		want := form.String(input)
		if strings.Count(want, "\u034f") != 1 {
			t.Fatal("inserted or removed CGJ")
		}

		var borrowed bytes.Buffer
		if err := form.EachBytes(t.Context(), input, func(part []byte) error { _, err := borrowed.Write(part); return err }); err != nil || borrowed.String() != want {
			t.Fatal("borrowed normalization segments", err)
		}

		var output bytes.Buffer

		writer := normalization.NewWriter(t.Context(), &output, form)
		for i := 0; i < len(input); i++ {
			if _, err := writer.Write([]byte{input[i]}); err != nil {
				t.Fatal(err)
			}
		}

		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}

		if output.String() != want {
			t.Fatal("normalization changed across byte boundaries")
		}

		output.Reset()

		writer = normalization.NewWriter(t.Context(), &output, form)
		if _, err := io.WriteString(writer, input); err != nil {
			t.Fatal(err)
		}

		if err := writer.Close(); err != nil || output.String() != want {
			t.Fatal("string writer changed long normalization segments", err)
		}

		normal, err := normalization.IsNormal(t.Context(), form, []byte(want))
		if err != nil || !normal {
			t.Fatal("exact normalization check", err)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())

	writer := normalization.NewWriter(ctx, io.Discard, normalization.NFC)
	if _, err := writer.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}

	cancel()

	if err := writer.Close(); !errors.Is(err, context.Canceled) {
		t.Fatal("close ignored cancellation", err)
	}

	writer = normalization.NewWriter(t.Context(), normalizationFailWriter{}, normalization.NFC)
	if _, err := writer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("close lost write error", err)
	}

	writer = normalization.NewWriter(t.Context(), io.Discard, normalization.NFC)
	if _, err := writer.Write([]byte{0xe2}); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("incomplete UTF-8 accepted", err)
	}
}

type normalizationFailWriter struct{}

func (normalizationFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
