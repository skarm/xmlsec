package stream_test

import (
	"encoding/xml"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	stream "github.com/skarm/xmlsec/transform/internal/xdm/xmlwriter"
)

func TestDocumentDeclarationAndAutomaticConstructClosing(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		open func(*testing.T, *stream.Writer) error
		want string
	}{
		{"element and attribute", func(t *testing.T, w *stream.Writer) error {
			writeSteps(t, func() error { return w.StartElement("root") }, func() error { return w.StartAttribute("a") })
			return w.WriteString("value")
		}, `<root a="value"/>`},
		{"comment", func(t *testing.T, w *stream.Writer) error {
			writeSteps(t, func() error { return w.StartElement("root") }, w.StartComment)
			return w.WriteString("comment")
		}, `<root><!--comment--></root>`},
		{"PI", func(t *testing.T, w *stream.Writer) error {
			writeSteps(t, func() error { return w.StartElement("root") }, func() error { return w.StartPI("probe") })
			return w.WriteString(" value")
		}, `<root><?probe value?></root>`},
		{"CDATA", func(t *testing.T, w *stream.Writer) error {
			writeSteps(t, func() error { return w.StartElement("root") }, w.StartCDATA)
			return w.WriteString("<&")
		}, `<root><![CDATA[<&]]></root>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var output strings.Builder
			w := stream.NewWriter(&output)
			writeSteps(t, func() error { return w.StartDocument("", "", "") }, func() error { return test.open(t, &w) }, w.EndDocument)
			if want := "<?xml version=\"1.0\"?>\n" + test.want + "\n"; output.String() != want {
				t.Fatalf("document=%q; want %q", output.String(), want)
			}
		})
	}
	var output strings.Builder
	w := stream.NewWriter(&output).QuoteChar('\'')
	writeSteps(t, func() error { return w.StartDocument("1.1", "UTF-8", "yes") }, func() error { return w.WriteElement("root", "\x01") }, w.EndDocument)
	if got, want := output.String(), "<?xml version='1.1' encoding='UTF-8' standalone='yes'?>\n<root>&#1;</root>\n"; got != want {
		t.Fatalf("configured declaration=%q; want %q", got, want)
	}
}

func TestWriterQuoteEscapingRawOutputAndFullEnd(t *testing.T) {
	t.Parallel()

	for _, quote := range []byte{'"', '\'', '!'} {
		var output strings.Builder
		w := stream.NewWriter(&output).QuoteChar(quote)
		writeSteps(t, func() error { return w.StartElement("root") }, func() error { return w.WriteAttribute("a", "\"'\t\n\r<&>") }, func() error { return w.WriteString("\"'\t\n\r<&>") }, func() error { return w.WriteRaw("<raw/>") }, w.EndElement)
		wantAttribute := ` a="&quot;'&#9;&#10;&#13;&lt;&amp;&gt;"`
		if quote == '\'' {
			wantAttribute = ` a='"&apos;&#9;&#10;&#13;&lt;&amp;&gt;'`
		}
		want := "<root" + wantAttribute + ">\"'\t\n&#13;&lt;&amp;&gt;<raw/></root>"
		if output.String() != want {
			t.Fatalf("quoted/escaped output=%q; want %q", output.String(), want)
		}
	}
	var output strings.Builder
	w := stream.NewWriter(&output)
	writeSteps(t, func() error { return w.StartElement("root") }, func() error { return w.StartAttribute("a") }, func() error { return w.WriteRaw("&amp;") }, w.FullEndElement)
	if output.String() != `<root a="&amp;"></root>` {
		t.Fatal("FullEndElement did not close an open attribute explicitly", output.String())
	}
}

func TestWriterIndentationDoesNotAddDuplicateConstructNewlines(t *testing.T) {
	t.Parallel()

	var output strings.Builder
	w := stream.NewWriter(&output).Indent("  ")
	writeSteps(t, func() error { return w.StartDocument("", "", "") }, func() error { return w.WriteComment("before") }, func() error { return w.WritePI("probe", "value") }, func() error { return w.StartElement("root") }, func() error { return w.WriteElement("child", "value") }, w.EndElement, w.EndDocument)
	want := "<?xml version=\"1.0\"?>\n<!--before-->\n<?probe value?>\n<root>\n  <child>value</child>\n</root>"
	if output.String() != want {
		t.Fatalf("indented document=%q; want %q", output.String(), want)
	}
}

func TestDefaultNamespaceUndeclarationAndRejectedAttributeRecovery(t *testing.T) {
	t.Parallel()

	var output strings.Builder
	w := stream.NewWriter(&output)
	writeSteps(t, func() error { return w.StartElementNS("", "root", "urn:root") }, func() error { return w.StartElementNS("", "plain", "") }, w.EndElement, func() error { return w.StartElementNS("", "sibling", "urn:root") }, w.EndElement, w.EndElement)
	if got, want := output.String(), `<root xmlns="urn:root"><plain xmlns=""/><sibling/></root>`; got != want {
		t.Fatalf("default namespace scopes=%q; want %q", got, want)
	}
	output.Reset()
	w = stream.NewWriter(&output)
	writeSteps(t, func() error { return w.StartElement("root") }, func() error { return w.WriteString("text") })
	before := output.String()
	if err := w.StartAttributeNS("p", "late", "urn:p"); err == nil || output.String() != before {
		t.Fatal("attribute after content changed the writer", output.String(), err)
	}
	writeSteps(t, func() error { return w.StartElementNS("p", "child", "urn:p") }, w.EndElement, w.EndElement)
	decoder := xml.NewDecoder(strings.NewReader(output.String()))
	var names []xml.Name
	for {
		token, err := decoder.Token()
		if err == io.EOF { //nolint:errorlint // Only bare EOF is completion; wrapped or joined failures must propagate.
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if start, ok := token.(xml.StartElement); ok {
			names = append(names, start.Name)
		}
	}
	if !slices.Equal(names, []xml.Name{{Local: "root"}, {Space: "urn:p", Local: "child"}}) {
		t.Fatal("rejected attribute leaked its namespace into child scope", names)
	}
}

func TestPIAndCommentChunkGuardsPreservePriorOutput(t *testing.T) {
	t.Parallel()

	var output strings.Builder
	w := stream.NewWriter(&output)
	writeSteps(t, func() error { return w.StartElement("root") }, func() error { return w.StartPI("probe") }, func() error { return w.WriteString(" ?") }, func() error { return w.WriteString("") })
	before := output.String()
	if err := w.WriteString(">injected"); err == nil || output.String() != before {
		t.Fatal("split PI terminator was accepted", output.String(), err)
	}
	writeSteps(t, func() error { return w.WriteString(" safe") }, w.EndPI, w.StartComment, func() error { return w.WriteString("ends-") })
	before = output.String()
	if err := w.EndComment(); err == nil || output.String() != before {
		t.Fatal("comment ending with dash was closed", output.String(), err)
	}
	writeSteps(t, func() error { return w.WriteString("safe") }, w.EndComment, w.EndElement)
	if got, want := output.String(), `<root><?probe ? safe?><!--ends-safe--></root>`; got != want {
		t.Fatalf("validation recovery=%q; want %q", got, want)
	}
}

func TestAttributeNamespaceConflictRejectsOnlyTheCurrentScope(t *testing.T) {
	t.Parallel()

	var output strings.Builder
	w := stream.NewWriter(&output)
	writeSteps(t, func() error { return w.StartElementNS("p", "root", "urn:root") })
	before := output.String()
	if err := w.WriteAttributeNS("p", "bad", "urn:other", "value"); err == nil || output.String() != before {
		t.Fatal("same-scope prefix conflict was accepted or emitted output", err, output.String())
	}
	writeSteps(t,
		func() error { return w.WriteAttributeNS("p", "same", "urn:root", "ok") },
		func() error { return w.WriteAttributeNS("xml", "lang", "", "en") },
		func() error { return w.WriteAttributeNS("q", "other", "urn:other", "ok") },
		func() error { return w.StartElementNS("p", "child", "urn:child") },
		func() error { return w.WriteAttributeNS("p", "same", "urn:child", "ok") },
		w.EndElement,
		func() error { return w.StartElementNS("p", "sibling", "urn:root") }, w.EndElement, w.EndElement,
	)
	want := `<p:root p:same="ok" xml:lang="en" q:other="ok" xmlns:p="urn:root" xmlns:q="urn:other"><p:child p:same="ok" xmlns:p="urn:child"/><p:sibling/></p:root>`
	if output.String() != want {
		t.Fatalf("namespace conflict recovery or scope restoration=%q; want %q", output.String(), want)
	}
}

type flushProbe struct {
	strings.Builder
	err     error
	flushes int
	closes  int
}

func (p *flushProbe) Flush() error { p.flushes++; return p.err }
func (p *flushProbe) Close() error { p.closes++; return nil }

func TestFlushFailureIsStickyAndDestinationRemainsBorrowed(t *testing.T) {
	t.Parallel()

	failure := errors.New("flush failed")
	dst := &flushProbe{err: failure}
	w := stream.NewWriter(dst)
	writeSteps(t, func() error { return w.StartElement("root") }, w.EndElement)
	before := dst.String()
	for _, got := range []error{w.Flush(), w.EndDocument(), w.WriteElement("other", "text"), w.Flush(), w.Error()} {
		if !errors.Is(got, failure) {
			t.Fatal("flush failure was replaced", got)
		}
	}
	if dst.flushes != 1 || dst.closes != 0 || dst.String() != before {
		t.Fatal("destination used after sticky failure or closed by borrower", dst.flushes, dst.closes, dst.String())
	}
}
