package html_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/html"
)

func TestHTMLSequenceOrderingCancellationAndFailures(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<span>node</span>`))
	if err != nil {
		t.Fatal(err)
	}
	writer := html.NewWriter().DefaultDTD(false).Format(false)
	var out bytes.Buffer
	items := func(yield func(xdm.XMLItem, error) bool) {
		for _, item := range []xdm.XMLItem{{Text: "before<&"}, {Node: doc}, {Text: "after"}} {
			if !yield(item, nil) {
				return
			}
		}
	}
	if err := writer.WriteSequence(t.Context(), &out, items); err != nil || out.String() != `before&lt;&amp;<span>node</span>after` {
		t.Fatalf("sequence order/escaping: %q, %v", out.String(), err)
	}
	failure := errors.New("upstream sequence failed")
	continued := false
	out.Reset()
	err = writer.WriteSequence(t.Context(), &out, func(yield func(xdm.XMLItem, error) bool) {
		if !yield(xdm.XMLItem{Text: "prefix"}, nil) {
			return
		}
		if !yield(xdm.XMLItem{}, failure) {
			return
		}
		continued = true
		yield(xdm.XMLItem{Text: "forbidden"}, nil)
	})
	if !errors.Is(err, failure) || out.String() != "prefix" || continued {
		t.Fatal("sequence error lost or iteration continued", out.String(), err, continued)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out.Reset()
	if err := writer.WriteSequence(ctx, &out, items); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal("canceled sequence emitted output", out.String(), err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	out.Reset()
	err = writer.WriteSequence(ctx, &out, func(yield func(xdm.XMLItem, error) bool) {
		if !yield(xdm.XMLItem{Text: "first"}, nil) {
			return
		}
		cancel()
		continued = yield(xdm.XMLItem{Text: "forbidden"}, nil)
	})
	if !errors.Is(err, context.Canceled) || out.String() != "first" || continued {
		t.Fatal("mid-sequence cancellation lost", out.String(), err, continued)
	}
	if err := writer.WriteSequence(t.Context(), errorWriter{failure}, items); !errors.Is(err, failure) {
		t.Fatal("destination error lost", err)
	}
	if err := writer.WriteTo(silentShortWriter{}, doc); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("silent short node write accepted", err)
	}
}

type silentShortWriter struct{}

func (silentShortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

func TestHTMLWriterOptionsAndVirtualMetadata(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<HTML><HEAD><META HTTP-EQUIV=" Content-Type " CONTENT="old"/><meta name="keep" content="unchanged"/></HEAD><BODY><A HREF="/café" title="e&#x301;|">e&#x301;|</A></BODY></HTML>`))
	if err != nil {
		t.Fatal(err)
	}
	base := html.NewWriter().DefaultDTD(false).Format(false)
	var plain bytes.Buffer
	if err := base.WriteTo(&plain, doc); err != nil {
		t.Fatal(err)
	}
	configured := base.PreserveCase(true).EscapeURIAttributes(false).Normalization("NFC").CharacterMap(map[rune]string{'|': "<mapped>"}).ContentType(`text/html; x="quoted"`)
	var got bytes.Buffer
	if err := configured.WriteTo(&got, doc); err != nil {
		t.Fatal(err)
	}
	want := `<HTML><HEAD><meta http-equiv="Content-Type" content="text/html; x=&quot;quoted&quot;"><meta name="keep" content="unchanged"></HEAD><BODY><A HREF="/café" title="é<mapped>">é<mapped></A></BODY></HTML>`
	if got.String() != want {
		t.Fatalf("configured HTML = %q; want %q", got.String(), want)
	}
	var again bytes.Buffer
	if err := base.WriteTo(&again, doc); err != nil || again.String() != plain.String() {
		t.Fatal("writer configuration or virtual metadata mutated source", again.String(), err)
	}
	for _, form := range []string{"NFD", "NFKC", "NFKD", "none"} {
		var output bytes.Buffer
		text := xdm.NewDefaultDocument().CreateText("é|ﬁ")
		if err := base.Normalization(form).WriteTo(&output, text); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"NFD": "e\u0301|ﬁ", "NFKC": "é|fi", "NFKD": "e\u0301|fi", "none": "é|ﬁ"}[form]
		if output.String() != want {
			t.Fatalf("%s normalization = %q; want %q", form, output.String(), want)
		}
	}
}

func TestHTMLRawTextControlEscapingAndDOE(t *testing.T) {
	t.Parallel()

	doc := xdm.NewDefaultDocument()
	root, err := doc.CreateElement("div")
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.AddChild(root); err != nil {
		t.Fatal(err)
	}
	for _, node := range []xdm.Node{doc.CreateText("safe<&\u0080"), doc.CreatePI("disable-output-escaping", ""), doc.CreateText("<raw>&"), doc.CreatePI("enable-output-escaping", ""), doc.CreateText("<&")} {
		if err := root.AddChild(node); err != nil {
			t.Fatal(err)
		}
	}
	var got bytes.Buffer
	writer := html.NewWriter().DefaultDTD(false).Format(false).DOEMarkers(true).EscapeControlChars(true)
	if err := writer.WriteTo(&got, doc); err != nil {
		t.Fatal(err)
	}
	if want := `<div>safe&lt;&amp;&#x80;<raw>&&lt;&amp;</div>`; got.String() != want {
		t.Fatalf("DOE/control output = %q; want %q", got.String(), want)
	}
	for _, test := range []struct{ input, want string }{
		{`<script>if (a &lt; b) x &amp; y</script>`, `<script>if (a < b) x & y</script>`},
		{`<p>&lt; &amp; &gt;</p>`, `<p>&lt; &amp; &gt;</p>`},
	} {
		input, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(test.input))
		if err != nil {
			t.Fatal(err)
		}
		got.Reset()
		if err := writer.WriteTo(&got, input); err != nil || got.String() != test.want {
			t.Fatal("raw text scope escaped incorrectly", got.String(), test.want, err)
		}
	}
}

func TestHTMLDoctypeIdentifiers(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ public, system, want string }{
		{"", "", "<!DOCTYPE html>\n"},
		{"", "about:legacy-compat", "<!DOCTYPE html>\n"},
		{"", "example.dtd", "<!DOCTYPE html SYSTEM \"example.dtd\">\n"},
		{"public-id", "example.dtd", "<!DOCTYPE html PUBLIC \"public-id\" \"example.dtd\">\n"},
		{"public-id", "", "<!DOCTYPE html PUBLIC \"public-id\">\n"},
	} {
		doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<p>text</p>`))
		if err != nil {
			t.Fatal(err)
		}
		doc.Doctype = &xdm.Doctype{Name: "html", PublicID: test.public, SystemID: test.system}
		var output strings.Builder
		if err := html.NewWriter().Format(false).WriteTo(&output, doc); err != nil || output.String() != test.want+"<p>text</p>" {
			t.Fatalf("DOCTYPE output = %q, %v", output.String(), err)
		}
	}
}

func TestHTMLDefaultFormatting(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<html><body><div><p>one</p><p>two</p></div></body></html>`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := html.WriteString(doc)
	if err != nil || !strings.Contains(got, "\n<p>one</p>") || !strings.Contains(got, "\n<p>two</p>") || !strings.HasSuffix(got, "</html>\n") {
		t.Fatalf("formatted default output = %q, %v", got, err)
	}
}
