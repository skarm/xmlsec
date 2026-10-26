package html_test

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/html"
)

func TestHTMLSerialization(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<html><body><input disabled="disabled"/><br/><script>if (a &lt; b) x &amp;&amp; y;</script><a href="/café">A &amp; B</a></body></html>`))
	if err != nil {
		t.Fatal(err)
	}

	var output strings.Builder

	writer := html.NewWriter().DefaultDTD(false).Format(false)
	if err := writer.WriteTo(&output, doc); err != nil {
		t.Fatal(err)
	}

	want := `<html><body><input disabled><br><script>if (a < b) x && y;</script><a href="/caf%C3%A9">A &amp; B</a></body></html>`
	if output.String() != want {
		t.Fatalf("got %q, want %q", output.String(), want)
	}

	failure := errors.New("destination failed")
	if err := writer.WriteTo(errorWriter{failure}, doc); !errors.Is(err, failure) {
		t.Fatalf("destination failure lost: %v", err)
	}
}

func TestHTMLCharacterMapBeforeNormalization(t *testing.T) {
	t.Parallel()

	const attributeSource = "e\u0301|"
	const textSource = "A\u030A" + attributeSource
	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte("<p title=\""+attributeSource+"\">"+textSource+"</p>"))
	if err != nil {
		t.Fatal(err)
	}

	var output strings.Builder

	// Mapping the combining accent must prevent it from composing with e.
	// The replacement for | remains decomposed; only unmapped A + ring composes.
	w := html.NewWriter().Format(false).DefaultDTD(false).Normalization("NFC").CharacterMap(map[rune]string{'\u0301': "&accent;", '|': "e\u0301"})
	if err := w.WriteTo(&output, doc); err != nil {
		t.Fatal(err)
	}

	const mapped = "e&accent;e\u0301"
	if got, want := output.String(), "<p title=\""+mapped+"\">Å"+mapped+"</p>"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if title, _ := doc.DocumentElement().GetAttribute("title"); title != attributeSource || xdm.CharacterData(doc) != textSource {
		t.Fatal("serialization changed the source character content")
	}
}

func TestHTMLLatin1CharacterReferences(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<p a="café中😀">café中😀</p>`))
	if err != nil {
		t.Fatal(err)
	}

	doc.SetEncoding("ISO-8859-1")

	var output strings.Builder

	writer := html.NewWriter().DefaultDTD(false).Format(false)
	if err := writer.WriteTo(&output, doc); err != nil {
		t.Fatal(err)
	}

	want := "<p a=\"caf&eacute;&#20013;&#128512;\">caf\xe9&#20013;&#128512;</p>"
	if output.String() != want {
		t.Fatalf("got %q, want %q", output.String(), want)
	}

	failure := errors.New("latin-1 destination failed")
	if err := writer.WriteTo(errorWriter{failure}, doc); !errors.Is(err, failure) {
		t.Fatalf("destination failure lost: %v", err)
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestXMLIslandCharacterErrors(t *testing.T) {
	t.Parallel()

	for _, cdata := range []bool{false, true} {
		for _, kind := range []string{"text", "attribute", "comment", "PI", "unencodable PI"} {
			doc := xdm.NewDefaultDocument()
			root, err := doc.CreateElementNS("r", xdm.NewNamespace("p", "urn:p"))
			if err != nil {
				t.Fatal(err)
			}
			if err := root.DeclareNamespace("p", "urn:p"); err != nil {
				t.Fatal(err)
			}
			if err := doc.AddChild(root); err != nil {
				t.Fatal(err)
			}
			code := "SERE0006"
			switch kind {
			case "text":
				err = root.AddChild(doc.CreateText("\x01"))
			case "attribute":
				err = root.SetAttribute("a", "\x01")
			case "comment":
				err = root.AddChild(doc.CreateComment("\x01"))
			case "PI":
				err = root.AddChild(doc.CreatePI("p", "\x01"))
			case "unencodable PI":
				err = root.AddChild(doc.CreatePI("p", "é"))
				code = "SERE0008"
			}
			if err != nil {
				t.Fatal(err)
			}
			writer := html.NewWriter().Format(false).DefaultDTD(false).PreserveCase(true).Repertoire(func(r rune) bool { return r < 128 })
			if cdata {
				writer = writer.CDATAElements(map[string]struct{}{"{urn:p}r": {}})
			}
			var output strings.Builder
			err = writer.WriteTo(&output, doc)
			var detail *xdm.Error
			if !errors.As(err, &detail) || detail.Code != code {
				t.Fatal(cdata, kind, output.String(), err, code)
			}
		}
	}
}

func BenchmarkHTMLSequenceWriter(b *testing.B) {
	for _, size := range []int{16, 1024} {
		doc, err := (xdm.ParseOptions{}).Parse(b.Context(), []byte(`<html><body>`+strings.Repeat(`<input disabled="disabled"/><a href="/café">e&#x301; &amp; 中</a>`, size)+`</body></html>`))
		if err != nil {
			b.Fatal(err)
		}
		writer := html.NewWriter().DefaultDTD(false).Format(false)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := writer.WriteTo(io.Discard, doc); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestURIAttributeNormalizationAndLateErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, input, escaped string }{
		{"empty", "", ""},
		{"NFC and markup", "/cafe\u0301?x=1&y=\"v\"", "/caf%C3%A9?x=1&amp;y=&quot;v&quot;"},
		{"long exact normalization", "/a" + strings.Repeat("\u0315", 80) + "\u0300", "/%C3%A0" + strings.Repeat("%CC%95", 80)},
		{"ampersand across output blocks", strings.Repeat("a", 63) + "&{x}&y", strings.Repeat("a", 63) + "&{x}&amp;y"},
		{"large URI", strings.Repeat("/café", 2048), strings.Repeat("/caf%C3%A9", 2048)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := xdm.NewDefaultDocument()
			root, err := doc.CreateElement("a")
			if err != nil {
				t.Fatal(err)
			}
			if err := root.SetAttribute("href", tc.input); err != nil {
				t.Fatal(err)
			}
			if err := doc.AddChild(root); err != nil {
				t.Fatal(err)
			}
			if err := root.AddChild(doc.CreateText("link")); err != nil {
				t.Fatal(err)
			}
			writer := html.NewWriter().DefaultDTD(false).Format(false)
			want := `<a href="` + tc.escaped + `">link</a>`
			for range 2 {
				var out strings.Builder
				if err := writer.WriteTo(&out, doc); err != nil || out.String() != want {
					t.Fatalf("URI output %q, %v; want %q", out.String(), err, want)
				}
			}
			for _, limit := range []int{1, len(want) / 2} {
				out := &uriCutWriter{remaining: limit}
				if err := writer.WriteTo(out, doc); !errors.Is(err, io.ErrClosedPipe) || out.String() != want[:limit] {
					t.Fatalf("late output prefix/error: %q, %v; want %q", out.String(), err, want[:limit])
				}
			}
			if original, present := root.GetAttribute("href"); !present || original != tc.input {
				t.Fatalf("serialization mutated URI: %q", original)
			}
		})
	}
}

type uriCutWriter struct {
	bytes.Buffer
	remaining int
}

func (w *uriCutWriter) WriteString(p string) (int, error) { return w.Write([]byte(p)) }

func (w *uriCutWriter) Write(p []byte) (int, error) {
	n := min(w.remaining, len(p))
	w.remaining -= n
	_, _ = w.Buffer.Write(p[:n])
	if n != len(p) {
		return n, io.ErrClosedPipe
	}
	return n, nil
}

func BenchmarkHTMLURIAttributeSize(b *testing.B) {
	for _, size := range []int{0, 8, 64, 8192} {
		doc := xdm.NewDefaultDocument()
		root, err := doc.CreateElement("a")
		if err != nil {
			b.Fatal(err)
		}
		if err := root.SetAttribute("href", strings.Repeat("/café", size/6)); err != nil {
			b.Fatal(err)
		}
		if err := doc.AddChild(root); err != nil {
			b.Fatal(err)
		}
		writer := html.NewWriter().DefaultDTD(false).Format(false)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := writer.WriteTo(io.Discard, doc); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
