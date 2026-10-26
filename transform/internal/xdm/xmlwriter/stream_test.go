package stream_test

import (
	"encoding/xml"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"

	stream "github.com/skarm/xmlsec/transform/internal/xdm/xmlwriter"
)

const rootNamespace = "urn:root"

func TestWriterNamespaceScopesAndCDATAChunks(t *testing.T) {
	t.Parallel()

	var output strings.Builder

	w := stream.NewWriter(&output)
	writeSteps(t,
		func() error { return w.StartElementNS("p", "root", rootNamespace) },
		func() error { return w.WriteAttributeNS("p", "attribute", rootNamespace, `a"&<`) },
		func() error { return w.WriteElementNS("p", "child", "urn:child", "") },
		func() error { return w.StartElementNS("p", "sibling", rootNamespace) },
		w.StartCDATA,
		func() error { return w.WriteString("A&B]]") },
		func() error { return w.WriteString(">C") },
		w.EndCDATA, w.EndElement, w.EndElement, w.Flush,
	)

	decoder := xml.NewDecoder(strings.NewReader(output.String()))

	var (
		names []xml.Name
		text  strings.Builder
	)

	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			t.Fatalf("malformed writer output %q: %v", output.String(), err)
		}

		switch v := token.(type) {
		case xml.StartElement:
			names = append(names, v.Name)
			if len(names) == 1 {
				index := slices.IndexFunc(v.Attr, func(attr xml.Attr) bool {
					return attr.Name == (xml.Name{Space: rootNamespace, Local: "attribute"})
				})
				if index < 0 {
					t.Fatal("namespaced attribute lost")
				}

				if v.Attr[index].Value != `a"&<` {
					t.Errorf("attribute = %q", v.Attr[index].Value)
				}
			}
		case xml.CharData:
			text.Write(v)
		}
	}

	want := []xml.Name{{Space: rootNamespace, Local: "root"}, {Space: "urn:child", Local: "child"}, {Space: rootNamespace, Local: "sibling"}}
	if !slices.Equal(names, want) || text.String() != "A&B]]>C" {
		t.Fatalf("namespace/text round trip: %v, %q", names, text.String())
	}
}

func TestWriterRetainsDestinationErrors(t *testing.T) {
	t.Parallel()

	failure := errors.New("destination failed")
	for _, err := range []error{nil, failure} {
		dst := &failingWriter{err: err}
		w := stream.NewWriter(dst)

		want := err
		if want == nil {
			want = io.ErrShortWrite
		}

		if got := w.StartElement("root"); !errors.Is(got, want) {
			t.Fatalf("StartElement = %v, want %v", got, want)
		}

		calls := dst.calls

		for _, got := range []error{w.WriteString("ignored"), w.EndElement(), w.Flush(), w.Error()} {
			if !errors.Is(got, want) {
				t.Errorf("sticky error = %v, want %v", got, want)
			}
		}

		if dst.calls != calls {
			t.Fatal("destination called after failure")
		}
	}
}

func TestWriterRejectsCommentDelimiterAcrossChunks(t *testing.T) {
	t.Parallel()

	var output strings.Builder

	w := stream.NewWriter(&output)
	writeSteps(t, w.StartComment, func() error { return w.WriteString("ends-") })

	before := output.String()
	if err := w.WriteString("-bad"); err == nil || output.String() != before {
		t.Fatalf("split comment delimiter accepted: %q, %v", output.String(), err)
	}
}

func TestWriterXML11ControlReferences(t *testing.T) {
	t.Parallel()

	var output strings.Builder

	w := stream.NewWriter(&output).XMLVersion("1.1")
	writeSteps(t, func() error { return w.WriteElement("root", "\x01\u0085\u2028") }, w.Flush)

	if got, want := output.String(), "<root>&#1;&#133;&#8232;</root>"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	output.Reset()

	w = stream.NewWriter(&output)
	if err := w.WriteElement("root", "\x01"); err == nil {
		t.Fatal("XML 1.0 control character accepted")
	}
}

func TestWriterRejectsShortStringWrite(t *testing.T) {
	t.Parallel()

	dst := &shortStringWriter{}

	w := stream.NewWriter(dst)
	if err := w.StartElement("root"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short StringWriter write = %v", err)
	}

	if dst.String() != "<" {
		t.Fatalf("unexpected output after short write: %q", dst.String())
	}
}

func writeSteps(t testing.TB, steps ...func() error) {
	t.Helper()

	for _, step := range steps {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
}

type failingWriter struct {
	calls int
	err   error
}

func (w *failingWriter) Write([]byte) (int, error) { w.calls++; return 0, w.err }

type shortStringWriter struct{ strings.Builder }

func (*shortStringWriter) WriteString(string) (int, error) { return 0, nil }

func BenchmarkNamespaceWriterDepth(b *testing.B) {
	for _, depth := range []int{4, 64} {
		prefixes := make([]string, depth)
		uris := make([]string, depth)
		for i := range depth {
			prefixes[i] = "p" + strconv.Itoa(i)
			uris[i] = "urn:depth:" + strconv.Itoa(i)
		}
		b.Run(strconv.Itoa(depth), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				w := stream.NewWriter(io.Discard)
				for i := range depth {
					if err := w.StartElementNS(prefixes[i], "node", uris[i]); err != nil {
						b.Fatal(err)
					}
				}
				if err := w.WriteString("text<&>é"); err != nil {
					b.Fatal(err)
				}
				for range depth {
					if err := w.EndElement(); err != nil {
						b.Fatal(err)
					}
				}
				if err := w.Flush(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
