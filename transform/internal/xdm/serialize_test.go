package xdm_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"iter"
	"math"
	"reflect"
	"strings"
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

type declarationShortWriter struct {
	output bytes.Buffer
	cause  error
	failed bool
	after  int
}

func (w *declarationShortWriter) WriteString(s string) (int, error) { return w.Write([]byte(s)) }

func (w *declarationShortWriter) Write(p []byte) (int, error) {
	if w.failed {
		w.after++
	}
	if strings.HasPrefix(string(p), "<?xml") {
		w.failed = true
		n, _ := w.output.Write(p[:len(p)-1])
		return n, w.cause
	}
	return w.output.Write(p)
}

func TestXMLDeclarationChecksShortWritesAndPreservesCause(t *testing.T) {
	t.Parallel()
	doc := parseNodeDocument(t, `<r/>`)
	sentinel := errors.New("declaration destination failed")
	for _, cause := range []error{nil, sentinel} {
		out := &declarationShortWriter{cause: cause}
		err := (xdm.XMLSerialization{}).WriteTo(out, doc)
		want := cause
		if want == nil {
			want = io.ErrShortWrite
		}
		if !out.failed || !errors.Is(err, want) || out.after != 0 {
			t.Fatalf("error=%v; want %v, declaration attempted=%v, later writes=%d", err, want, out.failed, out.after)
		}
	}
}

func TestXMLDeclarationRejectsInvalidMetadataBeforeWriting(t *testing.T) {
	t.Parallel()
	for _, writer := range []xdm.XMLSerialization{
		{Version: `1.0" extra="yes`},
		{Version: "1."},
		{Version: "2.0"},
		{Encoding: `UTF-8" extra="yes`},
		{Encoding: "1UTF8"},
		{Encoding: "UTF 8"},
		{Standalone: `yes" extra="yes`},
		{Standalone: "YES"},
	} {
		doc := parseNodeDocument(t, `<r/>`)
		var output bytes.Buffer
		if err := writer.WriteTo(&output, doc); err == nil || output.Len() != 0 {
			t.Errorf("invalid declaration emitted %q; error=%v", output.String(), err)
		}
	}
	for _, encoding := range []bool{false, true} {
		doc := parseNodeDocument(t, `<r/>`)
		if encoding {
			doc.SetEncoding("bad encoding")
		} else {
			doc.SetVersion("1.0\" bad=\"yes")
		}
		var output bytes.Buffer
		if err := (xdm.XMLSerialization{}).WriteTo(&output, doc); err == nil || output.Len() != 0 {
			t.Error("invalid source declaration metadata was emitted", output.String(), err)
		}
		output.Reset()
		if err := (xdm.XMLSerialization{OmitDeclaration: true}).WriteTo(&output, doc); err != nil || output.String() != "<r/>" {
			t.Fatal("omitted declaration consumed unused metadata", output.String(), err)
		}
	}
	for _, version := range []string{"1.0", "1.1", "1.23"} {
		for _, encoding := range []string{"UTF-8", "ISO_8859-1", "custom.encoding"} {
			doc := parseNodeDocument(t, `<r/>`)
			var output bytes.Buffer
			writer := xdm.XMLSerialization{Version: version, Encoding: encoding, Standalone: "no", CompactDeclaration: true}
			if err := writer.WriteTo(&output, doc); err != nil || !strings.HasPrefix(output.String(), `<?xml version="`+version+`" encoding="`+encoding+`" standalone="no"?>`) {
				t.Fatal("valid declaration spelling rejected", output.String(), err)
			}
		}
	}
}

func TestXMLSerializationRejectsTypedNilInputs(t *testing.T) {
	t.Parallel()
	doc := parseNodeDocument(t, `<r/>`)
	var absentDocument *xdm.Document
	var absentWriter *bytes.Buffer
	for _, run := range []func() error{
		func() error { return (xdm.XMLSerialization{}).WriteTo(io.Discard, absentDocument) },
		func() error { return (xdm.XMLSerialization{}).WriteTo(absentWriter, doc) },
	} {
		func() {
			defer func() {
				if value := recover(); value != nil {
					t.Errorf("typed nil input panicked: %v", value)
				}
			}()
			if err := run(); err == nil {
				t.Error("typed nil input was accepted")
			}
		}()
	}
}

func TestIDWalkSupportsDocumentRootAndPreservesDuplicatePolicy(t *testing.T) {
	t.Parallel()
	doc := parseNodeDocument(t, `<r Id="same" ID="same"><a xml:id="same"/><b token="typed"/><c AssertionID="hidden"/></r>`)
	root := doc.DocumentElement()
	root.FirstChild().NextSibling().(*xdm.Element).GetAttributeNodeNS("token", "").SetIDType(xdm.IDAttribute)
	want, err := xdm.BuildIDIndex(t.Context(), root)
	requireNodeSuccess(t, err)
	got, err := xdm.BuildIDIndex(t.Context(), doc)
	requireNodeSuccess(t, err)
	if !reflect.DeepEqual(got, want) || len(got["same"]) != 2 || len(got["typed"]) != 1 || len(got["hidden"]) != 0 {
		t.Fatal("document-root ID index changed completeness or ID profile", got, want)
	}
	for id, expected := range want {
		if actual := xdm.FindElementsByID(doc, id); !reflect.DeepEqual(actual, expected) {
			t.Fatal("document-root ID search disagrees with index", id, actual, expected)
		}
	}
	for _, node := range []xdm.Node{nil, (*xdm.Document)(nil), (*xdm.Element)(nil), (*xdm.Attribute)(nil)} {
		index, err := xdm.BuildIDIndex(nil, node)
		if err != nil || len(index) != 0 || len(xdm.FindElementsByID(node, "same")) != 0 {
			t.Fatal("nil ID root produced a result", node, index, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	mid := &cancelAfterErrChecks{Context: ctx, cancel: cancel, remaining: 2}
	index, err := xdm.BuildIDIndex(mid, doc)
	cancel()
	if index != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled document walk returned partial ID index", index, err)
	}
}

func TestInScopeNamespacesIncludesImplicitXMLAndOmitsUndeclarations(t *testing.T) {
	t.Parallel()
	doc := parseNodeDocument(t, `<r xmlns="urn:r" xmlns:p="urn:old"><child xmlns="" xmlns:p="urn:new"><leaf/></child></r>`)
	leaf := doc.DocumentElement().FirstChild().FirstChild().(*xdm.Element)
	scope := xdm.InScopeNamespaces(leaf, false)
	if len(scope) != 2 || scope["xml"] == nil || scope["xml"].URI() != tree.XMLNamespace || scope["p"] == nil || scope["p"].URI() != "urn:new" {
		t.Fatal("implicit binding or namespace shadowing/undeclaration lost", scope)
	}
	if scope = xdm.InScopeNamespaces(leaf, true); len(scope) != 1 || scope["p"] == nil {
		t.Fatal("dropXML changed non-xml scope", scope)
	}
	if uri, found := xdm.LookupNSPrefixURI(leaf, "xml"); found || uri != "" {
		t.Fatal("lexical namespace profile gained implicit binding", uri, found)
	}
}

func TestAtomicIsNaNRecognizesSupportedFloatRepresentations(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{xdm.TypeDouble, xdm.TypeFloat} {
		for _, value := range []any{math.NaN(), float32(math.NaN()), xdm.NewDouble(math.NaN())} {
			for _, custom := range []bool{false, true} {
				a := xdm.AtomicValue{TypeName: kind, Value: value}
				if custom {
					a.TypeName, a.BaseType = "Q{u}derived", kind
				}
				if !a.IsNaN() || !math.IsNaN(a.ToFloat64()) {
					t.Error("supported NaN representation missed", a)
				}
			}
		}
	}
	for _, a := range []xdm.AtomicValue{
		{TypeName: xdm.TypeString, Value: "NaN"},
		{TypeName: xdm.TypeDouble, Value: math.Inf(1)},
		{TypeName: xdm.TypeFloat, Value: math.Copysign(0, -1)},
		{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(1)},
	} {
		if a.IsNaN() {
			t.Error("non-NaN classified as NaN", a)
		}
	}
}
