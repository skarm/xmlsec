package c14n_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
)

const (
	canonicalEmptyChildXML = "<c></c>"
	xmlRXmlnsUrnRCXmlnsR   = "<r xmlns=\"urn:r\"><c xmlns=\"\"/></r>"
	emptyRootXML           = "<r/>"
	explicitEmptyRootXML   = "<r></r>"
)

func TestExclusive(t *testing.T) {
	tests := []struct {
		name, input, want string
		opt               c14n.Options
		child             bool
	}{
		{name: "empty", input: emptyRootXML, want: explicitEmptyRootXML},
		{name: "attr order", input: `<r b="2" a="1"/>`, want: `<r a="1" b="2"></r>`},
		{name: "nested and sibling attribute order", input: `<r z="0"><a d="4" b="2" c="3" a="1"><b y="2" x="1"/></a><empty/><c b="2" a="1"/></r>`, want: `<r z="0"><a a="1" b="2" c="3" d="4"><b x="1" y="2"></b></a><empty></empty><c a="1" b="2"></c></r>`},
		{name: "unused namespace", input: `<r xmlns:p="urn:p"><c/></r>`, want: `<r><c></c></r>`},
		{name: "visible prefix", input: `<r xmlns:p="urn:p"><p:c/></r>`, want: `<r><p:c xmlns:p="urn:p"></p:c></r>`},
		{name: "default reset", input: xmlRXmlnsUrnRCXmlnsR, want: `<r xmlns="urn:r"><c xmlns=""></c></r>`},
		{name: "rebind", input: `<p:r xmlns:p="urn:one"><p:c xmlns:p="urn:two"/><p:d/></p:r>`, want: `<p:r xmlns:p="urn:one"><p:c xmlns:p="urn:two"></p:c><p:d></p:d></p:r>`},
		{name: "attribute namespace order", input: `<r xmlns:b="urn:b" xmlns:a="urn:a" b:x="b" z="0" a:z="a"/>`, want: `<r xmlns:a="urn:a" xmlns:b="urn:b" z="0" a:z="a" b:x="b"></r>`},
		{name: "inclusive list", input: `<r xmlns:p="urn:p"/>`, opt: c14n.Options{InclusivePrefixes: []string{"p"}}, want: `<r xmlns:p="urn:p"></r>`},
		{name: "inclusive missing prefix", input: emptyRootXML, opt: c14n.Options{InclusivePrefixes: []string{"missing"}}, want: explicitEmptyRootXML},
		{name: "inclusive default", input: `<p:r xmlns="urn:d" xmlns:p="urn:p"/>`, opt: c14n.Options{InclusivePrefixes: []string{"#default"}}, want: `<p:r xmlns="urn:d" xmlns:p="urn:p"></p:r>`},
		{name: "xml attributes", input: `<r xml:lang="ru"/>`, want: `<r xml:lang="ru"></r>`},
		{name: "comments omitted", input: `<!--a--><r><!--b--></r><!--c-->`, want: explicitEmptyRootXML},
		{name: "comments outside", input: `<!--a--><r><!--b--></r><!--c-->`, opt: c14n.Options{WithComments: true}, want: "<!--a-->\n<r><!--b--></r>\n<!--c-->"},
		{name: "PI outside", input: `<?a first?><r><?b second?></r><?c?>`, want: "<?a first?>\n<r><?b second?></r>\n<?c?>"},
		{name: "escaping", input: `<r a="&lt;&amp;&quot;&#x9;&#xA;&#xD;">&lt;&amp;&gt;&#xD;</r>`, want: `<r a="&lt;&amp;&quot;&#x9;&#xA;&#xD;">&lt;&amp;&gt;&#xD;</r>`},
		{name: "CDATA", input: `<r><![CDATA[<data>]]></r>`, want: `<r>&lt;data&gt;</r>`},
		{name: "subtree ancestor", input: `<r xmlns:p="urn:p" xml:lang="ru"><p:c/></r>`, child: true, want: `<p:c xmlns:p="urn:p"></p:c>`},
		{name: "subtree no empty default", input: xmlRXmlnsUrnRCXmlnsR, child: true, want: canonicalEmptyChildXML},
		{name: "line endings", input: "<r a='a\r\nb\tc'>x\r\ny\rz</r>", want: "<r a=\"a b c\">x\ny\nz</r>"},
		// Independently transcribed from W3C Exclusive C14N §2.2 (no layout whitespace).
		{name: "W3C re-enveloping", input: `<n2:pdu xmlns:n1="http://example.com" xmlns:n2="http://foo.example" xml:lang="fr" xml:space="retain"><n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"/></n1:elem2></n2:pdu>`, child: true, want: `<n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"></n3:stuff></n1:elem2>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := document.Parse(t.Context(), []byte(tt.input), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}

			original, err := d.XML(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			var out bytes.Buffer
			if tt.child {
				err = c14n.WriteElement(context.Background(), &out, d.Root().Children()[0], tt.opt)
			} else {
				err = c14n.WriteDocument(context.Background(), &out, d, tt.opt)
			}

			if err != nil {
				t.Fatal(err)
			}

			if out.String() != tt.want {
				t.Fatalf("got  %q\nwant %q", out.String(), tt.want)
			}

			after, err := d.XML(t.Context())
			if err != nil || !bytes.Equal(original, after) {
				t.Fatalf("canonicalization changed the source snapshot: %v", err)
			}
		})
	}
}

func TestCanonicalErrors(t *testing.T) {
	d, _ := document.Parse(t.Context(), []byte(emptyRootXML), document.DefaultLimits())
	if err := c14n.WriteDocument(context.Background(), io.Discard, d, c14n.Options{MaxOutputBytes: 1}); !errors.Is(err, document.ErrLimit) {
		t.Fatal(err)
	}

	if err := c14n.WriteDocument(context.Background(), shortWriter{}, d, c14n.Options{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}

	if err := c14n.WriteDocument(context.Background(), io.Discard, d, c14n.Options{InclusivePrefixes: []string{"bad:prefix"}}); err == nil {
		t.Fatal("invalid prefix accepted")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := c14n.WriteDocument(ctx, io.Discard, d, c14n.Options{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	if err := c14n.WriteElement(context.Background(), io.Discard, document.Element{}, c14n.Options{}); err == nil {
		t.Fatal("zero element accepted")
	}
}

func TestNamespaceFramesStayLocalToSubtrees(t *testing.T) {
	d, err := document.Parse(t.Context(), []byte(`<r xmlns:a="urn:one"><a:n xmlns:a="urn:two"><a:c/></a:n><a:n/><n xmlns="urn:def"><x xmlns=""/></n><a:n/></r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	for _, algorithm := range []string{c14n.Exclusive, c14n.Canonical10, c14n.Canonical11} {
		var out bytes.Buffer
		if err := c14n.WriteDocument(t.Context(), &out, d, c14n.Options{Algorithm: algorithm}); err != nil {
			t.Fatal(err)
		}

		expected := `<r><a:n xmlns:a="urn:two"><a:c></a:c></a:n><a:n xmlns:a="urn:one"></a:n><n xmlns="urn:def"><x xmlns=""></x></n><a:n xmlns:a="urn:one"></a:n></r>`
		if algorithm != c14n.Exclusive {
			expected = `<r xmlns:a="urn:one"><a:n xmlns:a="urn:two"><a:c></a:c></a:n><a:n></a:n><n xmlns="urn:def"><x xmlns=""></x></n><a:n></a:n></r>`
		}

		if out.String() != expected {
			t.Fatalf("%s: %s", algorithm, out.String())
		}
	}
}

func FuzzIdempotent(f *testing.F) {
	for _, s := range []string{emptyRootXML, xmlRXmlnsUrnRCXmlnsR, `<r xmlns:p="urn:p"><p:a/><p:b/></r>`, `<?pi?><r a="&#x9;">t</r>`, `<r z="0"><a b="2" a="1"><b x="1"/></a><empty/><c d="4" a="1"/></r>`} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			t.Skip()
		}

		d, e := document.Parse(t.Context(), b, document.DefaultLimits())
		if e != nil {
			return
		}

		for _, alg := range []string{c14n.Exclusive, c14n.Canonical10, c14n.Canonical11} {
			var first, second bytes.Buffer

			opt := c14n.Options{Algorithm: alg, WithComments: true}
			if e = c14n.WriteDocument(context.Background(), &first, d, opt); e != nil {
				continue
			}

			canonical, err := document.Parse(t.Context(), first.Bytes(), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}

			if err = c14n.WriteDocument(context.Background(), &second, canonical, opt); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(first.Bytes(), second.Bytes()) {
				t.Fatalf("%s not idempotent: %q / %q", alg, first.Bytes(), second.Bytes())
			}
		}
	})
}

func BenchmarkExclusive(b *testing.B) {
	d, err := document.Parse(b.Context(), []byte(`<r xmlns="urn:r">`+strings.Repeat(`<item a="1" b="2">text</item>`, 100)+`</r>`), document.DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if err := c14n.WriteDocument(context.Background(), io.Discard, d, c14n.Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCanonicalNodeSet(b *testing.B) {
	d, err := document.Parse(b.Context(), []byte(`<r xmlns="urn:r" xml:base="https://example.test/a/"><a xml:base="../b/"><c x="1">text</c><d>text</d></a></r>`), document.DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}

	nodes, err := d.Root().Children()[0].Subtree(b.Context())
	if err != nil {
		b.Fatal(err)
	}

	for _, alg := range []string{c14n.Canonical10, c14n.Exclusive, c14n.Canonical11} {
		b.Run(alg, func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				if err := c14n.WriteNodeSet(context.Background(), io.Discard, nodes, c14n.Options{Algorithm: alg}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestCanonicalFinalWriteCancellation(t *testing.T) {
	doc, err := document.ParseReader(t.Context(), strings.NewReader(`<r/>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	set, err := doc.AllNodes(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	for _, write := range []func(context.Context, io.Writer) error{
		func(ctx context.Context, dst io.Writer) error {
			return c14n.WriteDocument(ctx, dst, doc, c14n.Options{})
		},
		func(ctx context.Context, dst io.Writer) error {
			return c14n.WriteElement(ctx, dst, doc.Root(), c14n.Options{})
		},
		func(ctx context.Context, dst io.Writer) error {
			return c14n.WriteNodeSet(ctx, dst, set, c14n.Options{})
		},
	} {
		ctx, cancel := context.WithCancel(t.Context())
		writer := &cancelWriter{cancel: cancel, size: len("<r></r>")}
		err := write(ctx, struct{ io.Writer }{writer})

		cancel()

		if !errors.Is(err, context.Canceled) || writer.String() != "<r></r>" {
			t.Fatal("last-write cancellation lost", writer.String(), err)
		}

		var nilBuffer *bytes.Buffer
		if err := write(t.Context(), nilBuffer); !errors.Is(err, document.ErrMalformed) {
			t.Fatal("typed-nil destination", err)
		}
	}
}

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }

type cancelWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
	size   int
}

func (w *cancelWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if w.Len() == w.size {
		w.cancel()
	}

	return n, err
}
