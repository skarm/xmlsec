package html_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/html"
)

func TestHTMLSerialization(t *testing.T) {
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
	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte("<p>e\u0301|</p>"))
	if err != nil {
		t.Fatal(err)
	}

	var output strings.Builder

	w := html.NewWriter().Format(false).DefaultDTD(false).Normalization("NFC").CharacterMap(map[rune]string{'|': "&marker;"})
	if err := w.WriteTo(&output, doc); err != nil {
		t.Fatal(err)
	}

	if got, want := output.String(), "<p>é&marker;</p>"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestHTMLLatin1CharacterReferences(t *testing.T) {
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
