package xdm_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"iter"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func xmlItems(items ...xdm.XMLItem) iter.Seq2[xdm.XMLItem, error] {
	return func(yield func(xdm.XMLItem, error) bool) {
		for _, item := range items {
			if !yield(item, nil) {
				return
			}
		}
	}
}

type failingXMLWriter struct{ cause error }

func (w failingXMLWriter) Write([]byte) (int, error) { return 0, w.cause }

func TestXMLSerializationSequenceOrderAndMetadata(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<r xml:id="  value  ">é&amp;&lt;</r>`)
	if err != nil {
		t.Fatal(err)
	}
	writer := xdm.XMLSerialization{Encoding: "us-ascii", Doctype: &xdm.Doctype{Name: "ignored", SystemID: "urn:output"}}
	var out bytes.Buffer
	err = writer.WriteSequence(t.Context(), &out, xmlItems(xdm.XMLItem{Text: "before &"}, xdm.XMLItem{Node: doc.DocumentElement(), Text: "ignored"}, xdm.XMLItem{Node: doc.DocumentElement()}, xdm.XMLItem{Text: "after"}))
	want := `before &amp;<!DOCTYPE r SYSTEM "urn:output"><r xml:id="value">&#233;&amp;&lt;</r><r xml:id="value">&#233;&amp;&lt;</r>after`
	if err != nil || out.String() != want {
		t.Fatalf("sequence XML %q; want %q (%v)", out.String(), want, err)
	}
	if attr, ok := doc.DocumentElement().GetAttributeNS("id", "http://www.w3.org/XML/1998/namespace"); !ok || attr != "value" {
		t.Fatalf("source xml:id content: %v,%v", attr, ok)
	}
	if writer.Doctype.Name != "ignored" {
		t.Fatal("sequence serializer changed supplied declaration")
	}
	out.Reset()
	err = (xdm.XMLSerialization{OmitDoctype: true, Doctype: writer.Doctype}).WriteSequence(t.Context(), &out, xmlItems(xdm.XMLItem{Node: doc.DocumentElement()}))
	if err != nil || out.String() != `<r xml:id="value">é&amp;&lt;</r>` {
		t.Fatalf("omitted doctype output %q,%v", out.String(), err)
	}
}

func TestXMLSerializationDeclarationChoicesAndErrors(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<?xml version="1.0"?><r/>`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		writer xdm.XMLSerialization
		want   string
	}{{xdm.XMLSerialization{}, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<r/>"}, {xdm.XMLSerialization{CompactDeclaration: true, Encoding: "US-ASCII", Standalone: "yes"}, `<?xml version="1.0" encoding="US-ASCII" standalone="yes"?><r/>`}, {xdm.XMLSerialization{OmitDeclaration: true}, "<r/>"}} {
		var out bytes.Buffer
		if err := tc.writer.WriteTo(&out, doc); err != nil || out.String() != tc.want {
			t.Fatalf("document XML %q; want %q (%v)", out.String(), tc.want, err)
		}
	}
	var out bytes.Buffer
	if err := (xdm.XMLSerialization{}).WriteTo(&out, nil); err == nil {
		t.Fatal("nil node accepted")
	}
	if err := (xdm.XMLSerialization{}).WriteTo(nil, doc); err == nil {
		t.Fatal("nil writer accepted")
	}
	sentinel := errors.New("disk full")
	for _, writer := range []xdm.XMLSerialization{{}, {OmitDeclaration: true}, {OmitDeclaration: true, Doctype: &xdm.Doctype{Name: "r", SystemID: "urn:out"}}} {
		if err := writer.WriteTo(failingXMLWriter{sentinel}, doc); !errors.Is(err, sentinel) {
			t.Fatalf("writer error lost: %v", err)
		}
	}
}

func TestXMLSerializationErrorMappingAndIteratorStop(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("source failed")
	var out bytes.Buffer
	calls := 0
	err := (xdm.XMLSerialization{}).WriteSequence(t.Context(), &out, func(yield func(xdm.XMLItem, error) bool) {
		calls++
		if !yield(xdm.XMLItem{Text: "prefix"}, nil) {
			return
		}
		calls++
		if !yield(xdm.XMLItem{}, sentinel) {
			return
		}
		calls++
		yield(xdm.XMLItem{Text: "unreachable"}, nil)
	})
	if !errors.Is(err, sentinel) || calls != 2 || out.String() != "prefix" {
		t.Fatalf("source failure handling %q,%v,%d", out.String(), err, calls)
	}
	out.Reset()
	err = (xdm.XMLSerialization{}).WriteSequence(t.Context(), &out, xmlItems(xdm.XMLItem{Text: "\x00"}))
	requireXDMCode(t, err, "SERE0006")
	if !errors.Is(err, tree.ErrMalformed) {
		t.Fatal("malformed XML cause lost")
	}
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<é/>`)
	if err != nil {
		t.Fatal(err)
	}
	err = (xdm.XMLSerialization{Encoding: "US-ASCII"}).WriteSequence(t.Context(), io.Discard, xmlItems(xdm.XMLItem{Node: doc.DocumentElement()}))
	requireXDMCode(t, err, "SERE0008")
	if !errors.Is(err, tree.ErrUnencodable) {
		t.Fatal("encoding failure cause lost")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out.Reset()
	err = (xdm.XMLSerialization{}).WriteSequence(ctx, &out, xmlItems(xdm.XMLItem{Text: "none"}))
	if !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatalf("cancelled XML wrote %q: %v", out.String(), err)
	}
}

func TestXMLSerializationStandaloneAttributeEscaping(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := (xdm.XMLSerialization{}).WriteAttributeValue(t.Context(), &out, "\"<&\t\n\r")
	if err != nil || out.String() != `&quot;&lt;&amp;&#x9;&#xA;&#xD;` {
		t.Fatalf("attribute output %q: %v", out.String(), err)
	}
	err = (xdm.XMLSerialization{}).WriteAttributeValue(t.Context(), io.Discard, "\x00")
	requireXDMCode(t, err, "SERE0006")
	if !errors.Is(err, tree.ErrMalformed) {
		t.Fatal("attribute character cause lost")
	}
	sentinel := errors.New("attribute target failed")
	if err := (xdm.XMLSerialization{}).WriteAttributeValue(t.Context(), failingXMLWriter{sentinel}, "text"); !errors.Is(err, sentinel) {
		t.Fatalf("attribute target cause %v", err)
	}
}
