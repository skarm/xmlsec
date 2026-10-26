package stream_test

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"

	stream "github.com/skarm/xmlsec/transform/internal/xdm/xmlwriter"
)

func TestCDATAConvenienceAndEveryChunkBoundary(t *testing.T) {
	t.Parallel()

	const content = "first]]>middle]]>last"
	for split := -1; split <= len(content); split++ {
		var output strings.Builder
		w := stream.NewWriter(&output)
		writeSteps(t, func() error { return w.StartElement("root") })
		if split < 0 {
			writeSteps(t, func() error { return w.WriteCDATA(content) })
		} else {
			writeSteps(t, w.StartCDATA, func() error { return w.WriteString(content[:split]) }, func() error { return w.WriteString(content[split:]) }, w.EndCDATA)
		}
		writeSteps(t, w.EndElement)
		if !strings.Contains(output.String(), "<![CDATA[") {
			t.Fatal("CDATA was replaced with ordinary text", output.String())
		}
		decoder := xml.NewDecoder(strings.NewReader(output.String()))
		var text strings.Builder
		for {
			token, err := decoder.Token()
			if err == io.EOF { //nolint:errorlint // Only bare EOF is completion; wrapped or joined failures must propagate.
				break
			}
			if err != nil {
				t.Fatalf("CDATA split %d produced malformed XML: %s: %v", split, output.String(), err)
			}
			if chars, ok := token.(xml.CharData); ok {
				text.Write(chars)
			}
		}
		if text.String() != content {
			t.Fatalf("CDATA split %d changed content: %q; want %q", split, text.String(), content)
		}
	}
}

func TestDoctypeLiteralsAndAutomaticClose(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, pub, sys, want string
		quote                byte
	}{
		{"plain", "", "", `<!DOCTYPE root>`, '"'},
		{"system", "", "local.dtd", `<!DOCTYPE root SYSTEM "local.dtd">`, '"'},
		{"system quote switch", "", `a"b.dtd`, `<!DOCTYPE root SYSTEM 'a"b.dtd'>`, '"'},
		{"public", "-//Example//DTD Test 1.0//EN", "local.dtd", `<!DOCTYPE root PUBLIC "-//Example//DTD Test 1.0//EN" "local.dtd">`, '"'},
		{"public quote switch", "public's id", "local.dtd", `<!DOCTYPE root PUBLIC "public's id" 'local.dtd'>`, '\''},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var output strings.Builder
			w := stream.NewWriter(&output).QuoteChar(test.quote)
			writeSteps(t, func() error { return w.WriteDTD("root", test.pub, test.sys) })
			if output.String() != test.want {
				t.Fatalf("doctype=%q; want %q", output.String(), test.want)
			}
		})
	}
	var output strings.Builder
	w := stream.NewWriter(&output)
	writeSteps(t, func() error { return w.StartDTD("root", "", "local.dtd") }, w.EndDocument)
	if output.String() != "<!DOCTYPE root SYSTEM \"local.dtd\">\n" {
		t.Fatal("EndDocument did not finish the pending DTD", output.String())
	}
	output.Reset()
	w = stream.NewWriter(&output).Indent("  ")
	writeSteps(t, func() error { return w.WriteDTD("root", "public", "local.dtd") }, func() error { return w.StartElement("root") }, w.EndElement)
	if got, want := output.String(), "\n<!DOCTYPE root\nPUBLIC \"public\"\n       \"local.dtd\">\n<root/>"; got != want {
		t.Fatalf("indented doctype=%q; want %q", got, want)
	}
}

func TestDeclarationAndDoctypeValidationPrecedesOutput(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		call func(*stream.Writer) error
	}{
		{"version injection", func(w *stream.Writer) error { return w.StartDocument(`1.0"?><injected/>`, "", "") }},
		{"empty version suffix", func(w *stream.Writer) error { return w.StartDocument("1.", "", "") }},
		{"wrong version grammar", func(w *stream.Writer) error { return w.StartDocument("2.0", "", "") }},
		{"encoding syntax", func(w *stream.Writer) error { return w.StartDocument("1.0", "UTF 8", "") }},
		{"unsupported encoding", func(w *stream.Writer) error { return w.StartDocument("1.0", "X-No-Such-Encoding", "") }},
		{"standalone syntax", func(w *stream.Writer) error { return w.StartDocument("1.0", "", "YES") }},
		{"empty DTD name", func(w *stream.Writer) error { return w.StartDTD("", "", "") }},
		{"DTD name injection", func(w *stream.Writer) error { return w.StartDTD("root injected", "", "") }},
		{"public without system", func(w *stream.Writer) error { return w.StartDTD("root", "public", "") }},
		{"public alphabet", func(w *stream.Writer) error { return w.StartDTD("root", "<invalid>", "local.dtd") }},
		{"unquotable system", func(w *stream.Writer) error { return w.StartDTD("root", "", `both'"quotes`) }},
		{"invalid system character", func(w *stream.Writer) error { return w.StartDTD("root", "", "bad\x00") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var output strings.Builder
			w := stream.NewWriter(&output)
			if err := test.call(&w); err == nil || output.Len() != 0 {
				t.Fatalf("invalid declaration emitted bytes: %q, %v", output.String(), err)
			}
			writeSteps(t, func() error { return w.StartElement("root") }, w.EndElement)
			if output.String() != "<root/>" {
				t.Fatal("rejected declaration changed later element state", output.String())
			}
		})
	}
}

func TestRejectedNamesNamespacesAndContentLeaveStartTagUntouched(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		call func(*stream.Writer) error
	}{
		{"element name", func(w *stream.Writer) error { return w.StartElement("a b") }},
		{"attribute name", func(w *stream.Writer) error { return w.StartAttribute("a b") }},
		{"element prefix", func(w *stream.Writer) error { return w.StartElementNS("a:b", "item", "urn:p") }},
		{"element local", func(w *stream.Writer) error { return w.StartElementNS("p", "a:b", "urn:p") }},
		{"attribute local", func(w *stream.Writer) error { return w.StartAttributeNS("p", "a:b", "urn:p") }},
		{"xmlns prefix", func(w *stream.Writer) error { return w.StartElementNS("xmlns", "item", "urn:p") }},
		{"xml rebind", func(w *stream.Writer) error { return w.StartElementNS("xml", "item", "urn:p") }},
		{"XML namespace wrong prefix", func(w *stream.Writer) error {
			return w.StartAttributeNS("p", "item", "http://www.w3.org/XML/1998/namespace")
		}},
		{"xmlns namespace", func(w *stream.Writer) error { return w.StartAttributeNS("p", "item", "http://www.w3.org/2000/xmlns/") }},
		{"namespace character", func(w *stream.Writer) error { return w.StartElementNS("p", "item", "urn:\x00") }},
		{"text character", func(w *stream.Writer) error { return w.WriteElement("item", "\x00") }},
		{"namespaced text character", func(w *stream.Writer) error { return w.WriteElementNS("p", "item", "urn:p", "\xff") }},
		{"attribute character", func(w *stream.Writer) error { return w.WriteAttribute("a", "\x00") }},
		{"namespaced attribute character", func(w *stream.Writer) error { return w.WriteAttributeNS("p", "a", "urn:p", "\x00") }},
		{"comment delimiter", func(w *stream.Writer) error { return w.WriteComment("a--b") }},
		{"comment ending", func(w *stream.Writer) error { return w.WriteComment("a-") }},
		{"comment character", func(w *stream.Writer) error { return w.WriteComment("a\x00") }},
		{"PI target", func(w *stream.Writer) error { return w.StartPI("XmL") }},
		{"PI name", func(w *stream.Writer) error { return w.StartPI("bad target") }},
		{"PI delimiter", func(w *stream.Writer) error { return w.WritePI("probe", "bad?>") }},
		{"PI character", func(w *stream.Writer) error { return w.WritePI("probe", "bad\x00") }},
		{"CDATA character", func(w *stream.Writer) error { return w.WriteCDATA("bad\x00") }},
		{"nested DTD", func(w *stream.Writer) error { return w.StartDTD("child", "", "") }},
		{"second document", func(w *stream.Writer) error { return w.StartDocument("", "", "") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var output strings.Builder
			w := stream.NewWriter(&output)
			writeSteps(t, func() error { return w.StartElement("root") })
			before := output.String()
			if err := test.call(&w); err == nil || output.String() != before {
				t.Fatalf("rejected operation changed output: %q, %v", output.String(), err)
			}
			writeSteps(t, func() error { return w.WriteElementNS("p", "good", "urn:p", "ok") }, w.EndElement)
			if got, want := output.String(), `<root><p:good xmlns:p="urn:p">ok</p:good></root>`; got != want {
				t.Fatalf("rejected operation changed subsequent scopes: %q; want %q", got, want)
			}
		})
	}
}

func TestUnopenedConstructsAreRejectedWithoutPoisoningWriter(t *testing.T) {
	t.Parallel()

	for _, operation := range []struct {
		name string
		call func(*stream.Writer) error
	}{
		{"EndElement", func(w *stream.Writer) error { return w.EndElement() }},
		{"FullEndElement", func(w *stream.Writer) error { return w.FullEndElement() }},
		{"StartAttribute", func(w *stream.Writer) error { return w.StartAttribute("a") }},
		{"EndAttribute", func(w *stream.Writer) error { return w.EndAttribute() }},
		{"EndComment", func(w *stream.Writer) error { return w.EndComment() }},
		{"EndPI", func(w *stream.Writer) error { return w.EndPI() }},
		{"StartCDATA", func(w *stream.Writer) error { return w.StartCDATA() }},
		{"EndCDATA", func(w *stream.Writer) error { return w.EndCDATA() }},
		{"EndDTD", func(w *stream.Writer) error { return w.EndDTD() }},
	} {
		var output strings.Builder
		w := stream.NewWriter(&output)
		if err := operation.call(&w); err == nil || output.Len() != 0 {
			t.Fatalf("%s without an open construct produced %q, %v", operation.name, output.String(), err)
		}
		writeSteps(t, func() error { return w.StartElement("root") }, w.EndElement)
		if output.String() != "<root/>" {
			t.Fatalf("%s rejection poisoned later state: %q", operation.name, output.String())
		}
	}
}

func TestStickyDestinationErrorsPrecedeConvenienceValidation(t *testing.T) {
	t.Parallel()

	failure := errors.New("destination failed")
	dst := &failingWriter{err: failure}
	w := stream.NewWriter(dst)
	if err := w.StartElement("root"); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	calls := dst.calls
	for _, operation := range []struct {
		name string
		call func(*stream.Writer) error
	}{
		{"StartDocument", func(w *stream.Writer) error { return w.StartDocument("", "", "") }},
		{"EndDocument", func(w *stream.Writer) error { return w.EndDocument() }},
		{"StartElementNS", func(w *stream.Writer) error { return w.StartElementNS("p", "a", "urn:p") }},
		{"FullEndElement", func(w *stream.Writer) error { return w.FullEndElement() }},
		{"WriteElement", func(w *stream.Writer) error { return w.WriteElement("a", "\x00") }},
		{"WriteElementNS", func(w *stream.Writer) error { return w.WriteElementNS("p", "a", "urn:p", "\x00") }},
		{"StartAttribute", func(w *stream.Writer) error { return w.StartAttribute("a") }},
		{"StartAttributeNS", func(w *stream.Writer) error { return w.StartAttributeNS("p", "a", "urn:p") }},
		{"EndAttribute", func(w *stream.Writer) error { return w.EndAttribute() }},
		{"WriteAttribute", func(w *stream.Writer) error { return w.WriteAttribute("a", "\x00") }},
		{"WriteAttributeNS", func(w *stream.Writer) error { return w.WriteAttributeNS("p", "a", "urn:p", "\x00") }},
		{"WriteRaw", func(w *stream.Writer) error { return w.WriteRaw("raw") }},
		{"StartComment", func(w *stream.Writer) error { return w.StartComment() }},
		{"EndComment", func(w *stream.Writer) error { return w.EndComment() }},
		{"WriteComment", func(w *stream.Writer) error { return w.WriteComment("bad--") }},
		{"StartPI", func(w *stream.Writer) error { return w.StartPI("probe") }},
		{"EndPI", func(w *stream.Writer) error { return w.EndPI() }},
		{"WritePI", func(w *stream.Writer) error { return w.WritePI("probe", "bad?>") }},
		{"StartCDATA", func(w *stream.Writer) error { return w.StartCDATA() }},
		{"EndCDATA", func(w *stream.Writer) error { return w.EndCDATA() }},
		{"WriteCDATA", func(w *stream.Writer) error { return w.WriteCDATA("\x00") }},
		{"StartDTD", func(w *stream.Writer) error { return w.StartDTD("root", "", "") }},
		{"EndDTD", func(w *stream.Writer) error { return w.EndDTD() }},
		{"WriteDTD", func(w *stream.Writer) error { return w.WriteDTD("root", "", "") }},
	} {
		if err := operation.call(&w); !errors.Is(err, failure) || dst.calls != calls {
			t.Fatalf("%s replaced sticky error or wrote again: %v, calls=%d; want %d", operation.name, err, dst.calls, calls)
		}
	}
	var zero stream.Writer
	if err := zero.StartElement("root"); err == nil || !errors.Is(zero.Flush(), err) {
		t.Fatal("zero writer did not retain its missing-destination error", err)
	}
}
