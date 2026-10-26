package document_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/document"
)

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		xml  string
	}{
		{"empty", ""},
		{"surrogate reference", `<r>&#xD800;</r>`},
		{"surrogate attribute", `<r a="&#55296;"/>`},
		{"CDATA outside", `<![CDATA[ ]]><r/>`},
		{"multiple roots", "<a/><b/>"},
		{"mismatch", "<a></b>"},
		{"unbound element", "<p:a/>"},
		{"unbound attribute", "<a p:b='1'/>"},
		{"duplicate lexical", "<a x='1' x='2'/>"},
		{"duplicate expanded", `<a xmlns:p="urn:x" xmlns:q="urn:x" p:x="1" q:x="2"/>`},
		{"namespace alias xml", `<a xmlns:p="http://www.w3.org/XML/1998/namespace"/>`},
		{"wrong xml binding", `<a xmlns:xml="urn:x"/>`},
		{"xmlns prefix", `<xmlns:a/>`},
		{"relative namespace", `<a xmlns="relative"/>`},
		{"prefix undeclare", `<a xmlns:p=""/>`},
		{"doctype", `<!DOCTYPE a [<!ENTITY x "hi">]><a>&x;</a>`},
		{"entity", `<a>&unknown;</a>`},
		{"nul", "<a>\x00</a>"},
		{"declaration position", " \n<?xml version='1.0'?><a/>"},
		{"declaration version", `<?xml version="1.1"?><a/>`},
		{"declaration case", `<?XML version="1.0"?><a/>`},
		{"declaration duplicate", `<?xml version="1.0" version="1.0"?><a/>`},
		{"missing separator", `<a x="1"y="2"/>`},
		{"comment", `<a><!--x--y--></a>`},
		{"outside text", `oops<a/>`},
		{"invalid qname", `<p:x:y xmlns:p="urn:p"/>`},
		{"double quote as element name", `<">">`},
		{"single quote as element name", `<'>'>`},
		{"double quote in element name", `<r">">`},
		{"single quote in element name", `<r'>'>`},
		{"bad close", `<a></a x>`},
		{"declaration markup", `<?xml version='1.0'/><foo a='x'?>`},
		{"attribute literal less-than", `<r a='<'/>`},
		{"malformed named entity", `<r>&amp junk;</r>`},
		{"empty PI target", `<? ?><r/>`},
		{"overlapping PI delimiter", `<?>`},
		{"overlapping comment delimiter", `<!-->`},
		{"overlapping empty comment", `<!--->`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := document.Parse(t.Context(), []byte(tt.xml), document.DefaultLimits()); err == nil {
				t.Fatal("accepted malformed or unsupported XML")
			}
		})
	}
}

func TestParseFifthEditionNames(t *testing.T) {
	for _, name := range []string{"\U00010000", "\u037f", "\u4e00", "\U000effff", "a\u0300", "\u200c"} {
		input := "<?" + name + " data?><" + name + " xmlns:p='urn:unicode' p:" + name + "='v'>&lt;&#x9;</" + name + ">"

		doc, err := document.ParseReader(t.Context(), iotest.OneByteReader(strings.NewReader(input)), document.DefaultLimits())
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}

		if doc.Root().Name().Local != name || doc.Root().Text() != "<\t" {
			t.Fatal("name or text changed")
		}

		if value, ok := doc.Root().Attribute(document.Name{Space: "urn:unicode", Local: name}); !ok || value != "v" {
			t.Fatal("attribute identity changed")
		}

		for _, little := range []bool{true, false} {
			encoded := encoded16(input, little, true)

			decoded, err := document.ParseReader(t.Context(), iotest.OneByteReader(bytes.NewReader(encoded)), document.DefaultLimits())
			if err != nil || decoded.Root().Name().Local != name {
				t.Fatalf("UTF-16 name: %v", err)
			}
		}

		out, err := doc.XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		again, err := document.Parse(t.Context(), out, document.DefaultLimits())
		if err != nil || again.Root().Name().Local != name {
			t.Fatal("round trip", err)
		}
	}

	for _, name := range []string{"\U000f0000", "\u037e", "\u0300", "0name", "a:b:c", ":a", "a:"} {
		if _, err := document.Parse(t.Context(), []byte("<"+name+"/>"), document.DefaultLimits()); err == nil {
			t.Fatalf("accepted invalid name %q", name)
		}
	}
}

func TestLongCharacterReferences(t *testing.T) {
	for _, digits := range []int{4090, 4096, 8192, 65536} {
		for _, prefix := range []string{"&#", "&#x"} {
			number := "65"
			if prefix == "&#x" {
				number = "41"
			}

			input := "<r>" + strings.Repeat("x", 4090) + prefix + strings.Repeat("0", digits) + number + ";&amp;</r>"

			doc, err := document.ParseReader(t.Context(), iotest.OneByteReader(strings.NewReader(input)), document.DefaultLimits())
			if err != nil || doc.Root().Text() != strings.Repeat("x", 4090)+"A&" {
				t.Fatal("long reference/chunk boundary", err)
			}

			limits := document.DefaultLimits()

			limits.MaxBytes = len(input) - 1
			if _, err := document.Parse(t.Context(), []byte(input), limits); !errors.Is(err, document.ErrLimit) {
				t.Fatal("long reference bypassed input limit", err)
			}
		}
	}

	for _, suffix := range []string{"65", "x41", "65;&bad;"} {
		if _, err := document.Parse(t.Context(), []byte("<r>&#"+strings.Repeat("0", 65536)+suffix+"</r>"), document.DefaultLimits()); err == nil {
			t.Fatal("accepted malformed long reference")
		}
	}
}

func TestSnapshot(t *testing.T) {
	src := []byte(`<r xmlns="urn:r" xmlns:p="urn:p" ID="root" p:a="1">text<c/>more</r>`)

	d, err := document.Parse(t.Context(), src, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	for i := range src {
		src[i] = 'x'
	}

	root := d.Root()
	if root.Name() != (document.Name{Space: "urn:r", Local: "r"}) {
		t.Fatal(root.Name())
	}

	if v, ok := root.Attribute(document.Name{Local: "ID"}); !ok || v != "root" {
		t.Fatal(v, ok)
	}

	a := root.Attributes()
	a[0].Value = "changed"

	if v, _ := root.Attribute(document.Name{Local: "ID"}); v != "root" {
		t.Fatal("attributes alias tree")
	}

	c := root.Children()
	c[0] = document.Element{}

	if !root.Children()[0].Valid() {
		t.Fatal("children alias tree")
	}

	if root.Text() != "textmore" {
		t.Fatal(root.Text())
	}

	if ns, ok := root.Namespace("p"); !ok || ns != "urn:p" {
		t.Fatal(ns, ok)
	}

	b, err := d.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	b[0] = '!'

	b, err = d.XML(t.Context())
	if err != nil || b[0] != '<' {
		t.Fatal("serialization aliases tree")
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 50 {
				_ = root.Text()
				_, _ = d.XML(t.Context())
				_ = root.Children()
			}
		})
	}

	wg.Wait()
}

func TestNormalization(t *testing.T) {
	d, err := document.Parse(t.Context(), []byte("<r a='x\t\r\ny&#x9;&#xA;&#xD;'/>"), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	got, _ := d.Root().Attribute(document.Name{Local: "a"})
	if got != "x  y\t\n\r" {
		t.Fatalf("got %q", got)
	}
}

func TestXMLLexicalObligations(t *testing.T) {
	for _, tc := range []struct {
		input  string
		output string
	}{
		{`<?xml version = '1.0' encoding = 'UTF-8' standalone = 'no'?><r/>`, `<r></r>`},
		{`<?xml version="1.0" standalone="yes"?><r></r>`, `<r></r>`},
		{`<?p?><r><!--%ignored;--><?p %ignored;?><![CDATA[<&%ignored;]]></r><?end data?>`, `<?p?><r><!--%ignored;--><?p %ignored;?>&lt;&amp;%ignored;</r><?end data?>`},
		{`<r a="&quot;&apos;&lt;&gt;&amp;&#x9;&#10;&#13;">&lt;&amp;&#60;&#38;&#x1F600;</r>`, `<r a="&quot;'&lt;>&amp;&#x9;&#xA;&#xD;">&lt;&amp;&lt;&amp;😀</r>`},
		{"<r>\r\n\r\n\t \u007f\u0085\ufdd0\U0010ffff</r>", "<r>\n\n\t \u007f\u0085\ufdd0\U0010ffff</r>"},
		{`<r xml:space="invalid" xml:lang=""><a/></r>`, `<r xml:space="invalid" xml:lang=""><a></a></r>`},
		{`<xmlFuture xmlns:xmlFuture="urn:future"><xmlFuture:n/></xmlFuture>`, `<xmlFuture xmlns:xmlFuture="urn:future"><xmlFuture:n></xmlFuture:n></xmlFuture>`},
	} {
		doc, err := document.ParseReader(t.Context(), iotest.OneByteReader(strings.NewReader(tc.input)), document.DefaultLimits())
		if err != nil {
			t.Fatal(tc.input, err)
		}

		out, err := doc.XML(t.Context())
		if err != nil || string(out) != tc.output {
			t.Errorf("XML %s: %s, %v; want %s", tc.input, out, err, tc.output)
		}
	}

	for _, input := range []string{
		`<?xml?><r/>`, `<?xml version="1.0"encoding="UTF-8"?><r/>`,
		`<?xml encoding="UTF-8" version="1.0"?><r/>`, `<?xml version="1.0" standalone="maybe"?><r/>`,
		`<?xml version="1.0" encoding="1bad"?><r/>`, `<?xml version="1.0" encoding="UTF&#45;8"?><r/>`,
		`<r><?p:x?></r>`, `<r><!--ends---></r>`, `<r><![CDATA[unfinished</r>`,
		`<r>&#X20;</r>`, `<r>&#x110000;</r>`, `<r>&#xFFFE;</r>`, `<r a="&#xFFFF;"/>`,
		`<r>&#-1;</r>`, `<r>&#x;</r>`, `<r>&#;</r>`, `<r>&#32</r>`,
	} {
		if _, err := document.Parse(t.Context(), []byte(input), document.DefaultLimits()); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
}

func TestNamespaceStringIdentity(t *testing.T) {
	for _, pair := range [][2]string{
		{"urn:example", "urn:Example"}, {"urn:x", "urn:%78"}, {"urn:é", "urn:e\u0301"},
	} {
		input := `<r xmlns:p="` + pair[0] + `" xmlns:q="` + pair[1] + `" p:a="one" q:a="two"/>`

		doc, err := document.Parse(t.Context(), []byte(input), document.DefaultLimits())
		if err != nil {
			t.Fatal(input, err)
		}

		for i, want := range []string{"one", "two"} {
			got, ok := doc.Root().Attribute(document.Name{Space: pair[i], Local: "a"})
			if !ok || got != want {
				t.Fatal("namespace identity was normalized", pair, got, ok)
			}
		}

		duplicate := strings.ReplaceAll(input, pair[1], pair[0])
		if _, err := document.Parse(t.Context(), []byte(duplicate), document.DefaultLimits()); err == nil {
			t.Fatal("duplicate expanded attributes were accepted", duplicate)
		}
	}
}

func TestLimitsAndContext(t *testing.T) {
	tests := []struct {
		name   string
		xml    string
		change func(*document.Limits)
	}{
		{"bytes", "<a/>", func(l *document.Limits) { l.MaxBytes = 3 }},
		{"depth", "<a><b/></a>", func(l *document.Limits) { l.MaxDepth = 1 }},
		{"nodes", "<a>text</a>", func(l *document.Limits) { l.MaxNodes = 1 }},
		{"attributes", "<a x='1' y='2'/>", func(l *document.Limits) { l.MaxAttributesPerElement = 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := document.DefaultLimits()
			tt.change(&l)

			_, err := document.Parse(t.Context(), []byte(tt.xml), l)
			if !errors.Is(err, document.ErrLimit) {
				t.Fatal(err)
			}
		})
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := document.Parse(ctx, []byte("<a/>"), document.DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{0xff, 0xfe, '<', 0, 'r', 0, '/', 0, '>', 0})

	for _, s := range []string{"<r/>", "<r xmlns='urn:r' a='&#xD;'/>", "<?xml version='1.0'?><r><!--c--></r>", "<!DOCTYPE x><x/>", "<?>", "<!-->", "<𐀀 Ϳ='value'>x</𐀀>"} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			t.Skip()
		}

		d, err := document.Parse(t.Context(), b, document.DefaultLimits())
		if err != nil {
			return
		}

		out, err := d.XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		if _, err := document.Parse(t.Context(), out, document.DefaultLimits()); err != nil {
			t.Fatalf("serialization not parseable: %s: %v", out, err)
		}
	})
}

func FuzzParseReader(f *testing.F) {
	for _, source := range []string{`<reader-fixture/>`, `<r a="&#xD;&#x9;&#xA;">text&#xD;🙂</r>`, `<?xml version="1.0"?><r><!--c--><![CDATA[a<b]]><?p i?></r>`, `<r xmlns:p="urn:p"><p:a/></r>`, `<r>bad]]>text</r>`, `<!DOCTYPE r><r/>`, `<r a="unterminated>`, "\xff\xfe<\x00r\x00/\x00>\x00"} {
		f.Add([]byte(source))
	}

	f.Fuzz(func(t *testing.T, source []byte) {
		if len(source) > 32<<10 {
			t.Skip()
		}

		limits := document.DefaultLimits()
		limits.MaxBytes = 32 << 10
		whole, wholeErr := document.Parse(t.Context(), source, limits)

		streamed, streamErr := document.ParseReader(t.Context(), iotest.OneByteReader(bytes.NewReader(source)), limits)
		if (wholeErr == nil) != (streamErr == nil) {
			t.Fatalf("chunking changes validity: %v / %v", wholeErr, streamErr)
		}

		if wholeErr != nil {
			for _, kind := range []error{document.ErrMalformed, document.ErrLimit, document.ErrUnsupported, io.ErrUnexpectedEOF} {
				if errors.Is(wholeErr, kind) != errors.Is(streamErr, kind) {
					t.Fatalf("chunking changes error: %v / %v", wholeErr, streamErr)
				}
			}

			return
		}

		first, err := whole.XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		second, err := streamed.XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(first, second) {
			t.Fatalf("chunking changes snapshot: %q / %q", first, second)
		}
	})
}

func TestStreamXML(t *testing.T) {
	for _, s := range []string{`<?pi a?><r xmlns:p="urn:p" p:a="&amp;&#xA;&quot;">a &lt;&gt; &amp; <p:e/><!--c--></r>`, `<r/>`, `<r xml:space="preserve"> a <![CDATA[ b ]]></r>`} {
		t.Run(s, func(t *testing.T) {
			d, e := document.Parse(t.Context(), []byte(s), document.DefaultLimits())
			if e != nil {
				t.Fatal(e)
			}

			want, e := d.XML(t.Context())
			if e != nil {
				t.Fatal(e)
			}

			var b bytes.Buffer

			n, e := d.WriteXML(t.Context(), &b, len(want))
			if e != nil || n != int64(len(want)) || !bytes.Equal(b.Bytes(), want) {
				t.Fatal(n, e, b.String())
			}

			b.Reset()

			_, e = d.WriteXML(t.Context(), &b, len(want)-1)
			if !errors.Is(e, document.ErrLimit) || b.Len() >= len(want) {
				t.Fatal(e, b.Len())
			}

			_, e = d.WriteXML(t.Context(), shortXMLWriter{}, 1000)
			if !errors.Is(e, io.ErrShortWrite) {
				t.Fatal(e)
			}

			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			b.Reset()

			_, e = d.WriteXML(ctx, &b, 1000)
			if !errors.Is(e, context.Canceled) || b.Len() != 0 {
				t.Fatal(e)
			}
		})
	}
}

func BenchmarkDocumentOperations(b *testing.B) {
	raw := []byte(`<r xmlns:p="urn:p">` + strings.Repeat(`<p:item a="1">text&amp;more</p:item>`, 100) + `</r>`)

	d, err := document.Parse(b.Context(), raw, document.DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}

	b.Run("XML", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			if _, err := d.XML(b.Context()); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Children", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			if len(d.Root().Children()) != 100 {
				b.Fatal("children")
			}
		}
	})
	b.Run("AllNodes", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			if _, err := d.AllNodes(b.Context()); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkDeepParse(b *testing.B) {
	raw := []byte(strings.Repeat(`<p:n xmlns:p="urn:p" p:a="v">`, 128) + strings.Repeat(`</p:n>`, 128))
	limits := document.DefaultLimits()
	limits.MaxDepth = 256

	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))

	for b.Loop() {
		if _, err := document.Parse(b.Context(), raw, limits); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParse(b *testing.B) {
	src := []byte(`<r xmlns="urn:r">` + strings.Repeat(`<item ID="x" a="value">text</item>`, 100) + `</r>`)

	b.ReportAllocs()
	b.SetBytes(int64(len(src)))

	for b.Loop() {
		if _, err := document.Parse(b.Context(), src, document.DefaultLimits()); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLongCharacterReference measures a valid reference with leading zeros.
// The expanded result remains one character as the encoded input grows.
func BenchmarkLongCharacterReference(b *testing.B) {
	for _, size := range []int{4 << 10, 16 << 10, 64 << 10} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			source := []byte("<r>&#" + strings.Repeat("0", size) + "65;</r>")

			b.ReportAllocs()
			b.SetBytes(int64(len(source)))

			for b.Loop() {
				doc, err := document.Parse(b.Context(), source, document.DefaultLimits())
				if err != nil || doc.Root().Text() != "A" {
					b.Fatal("reference changed", err)
				}
			}
		})
	}
}

// BenchmarkXMLNamespaces measures inherited namespace handling during XML output.
func BenchmarkXMLNamespaces(b *testing.B) {
	for _, depth := range []int{8, 128} {
		b.Run(strconv.Itoa(depth), func(b *testing.B) {
			var raw bytes.Buffer
			for i := range depth {
				_, _ = fmt.Fprintf(&raw, `<n xmlns:p%d="urn:p%d">`, i, i)
			}

			raw.WriteString(strings.Repeat(`</n>`, depth))

			d, err := document.Parse(b.Context(), raw.Bytes(), document.DefaultLimits())
			if err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()

			for b.Loop() {
				if _, err := d.XML(b.Context()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type shortXMLWriter struct{}

func (shortXMLWriter) Write(p []byte) (int, error) { return 0, nil }

func mustDoc(t *testing.T, input string) *document.Document {
	t.Helper()

	d, err := document.Parse(t.Context(), []byte(input), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	return d
}
