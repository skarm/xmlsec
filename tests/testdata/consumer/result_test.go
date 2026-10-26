package consumer_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/text/encoding/htmlindex"
	textunicode "golang.org/x/text/encoding/unicode"
	texttransform "golang.org/x/text/transform"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/transform"
)

func TestResultsRetainTypesOrderAndOutputDefinitions(t *testing.T) {
	e := newEngine(t, transform.Config{})
	s := compileSheet(t, e, `<xsl:output omit-xml-declaration="yes"/><xsl:template name="start"><xsl:sequence select="1,2"/><a/><xsl:sequence select="3,4"/><xsl:result-document href="secondary.json" method="json"><xsl:sequence select="map{'answer':42}"/></xsl:result-document></xsl:template>`)
	options := transform.XSLTContext{BaseOutputURI: "https://result.test/"}
	r, err := s.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, options)
	if err != nil {
		t.Fatal(err)
	}
	if r.Primary().Len() != 5 {
		t.Fatal(r.Primary().Len())
	}
	secondary := r.Secondary()
	value, err := secondary["https://result.test/secondary.json"].Single()
	if err != nil || value.Kind() != transform.MapValue {
		t.Fatal(value.Kind(), err)
	}
	delete(secondary, "https://result.test/secondary.json")
	if len(r.Secondary()) != 1 {
		t.Fatal("caller mutated result")
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for _, uri := range []string{"", "https://result.test/secondary.json"} {
				encoding, err := r.OutputEncoding(uri)
				if err != nil || encoding != "UTF-8" {
					t.Error(encoding, err)
				}
			}
			out, err := r.Serialize(t.Context())
			if err != nil {
				t.Error(err)
				return
			}
			if string(out.Primary) != "1 2<a/>3 4" || !bytes.Contains(out.Secondary["https://result.test/secondary.json"], []byte(`"answer":42`)) {
				t.Errorf("unexpected serialization: %#v", out)
			}
			out.Primary[0] = 'x'
		})
	}
	group.Wait()
	options.Template = document.Name{Local: "start"}
	legacy, err := s.Transform(t.Context(), nil, options)
	if err != nil || string(legacy.Primary) != "1 2<a/>3 4" || !bytes.Contains(legacy.Secondary["https://result.test/secondary.json"], []byte(`"answer":42`)) {
		t.Fatal(legacy, err)
	}
}

func TestResultDocumentCopiesOnlySelectedElement(t *testing.T) {
	e := newEngine(t, transform.Config{})
	d, err := e.Parse(t.Context(), []byte(`<outer xmlns:p="urn:p"><keep>p:value</keep><secret/></outer>`))
	if err != nil {
		t.Fatal(err)
	}
	s := compileSheet(t, e, `<xsl:output omit-xml-declaration="yes"/><xsl:template name="start"><xsl:sequence select="/outer/keep"/></xsl:template>`)
	r, err := s.CallTemplate(t.Context(), d, document.Name{Local: "start"}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.Document(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	exported, err := e.Export(t.Context(), result)
	if err != nil {
		t.Fatal(err)
	}
	if exported.Root().Name().Local != "keep" {
		t.Fatal("unselected owner document returned")
	}
	if uri, ok := exported.Root().Namespace("p"); !ok || uri != "urn:p" {
		t.Fatal("inherited namespace lost")
	}
	out, err := r.Serialize(t.Context())
	if err != nil || bytes.Contains(out.Primary, []byte("secret")) || !bytes.Contains(out.Primary, []byte(`xmlns:p="urn:p"`)) {
		t.Fatal(out, err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.Document(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestXMLSerializationRejectsMapWithoutPartialOutput(t *testing.T) {
	e := newEngine(t, transform.Config{})
	s := compileSheet(t, e, `<xsl:template name="start"><a/><xsl:sequence select="map{'answer':42}"/></xsl:template>`)
	r, err := s.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.Serialize(t.Context())
	var coded *transform.Error
	if out != nil || !errors.As(err, &coded) || coded.Code != "SENR0001" {
		t.Fatal(out, err)
	}
	if _, err := r.Document(t.Context()); err == nil {
		t.Fatal("mixed sequence accepted as an XML document")
	}
}

func TestHTMLSerializationChecksDoctypeWriteErrors(t *testing.T) {
	e := newEngine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 1}})
	s := compileSheet(t, e, `<xsl:output method="html" html-version="4.01" doctype-system="system"/><xsl:template name="start"/>`)
	result, err := s.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	output, err := result.Serialize(t.Context())
	if output != nil || !errors.Is(err, transform.ErrLimit) {
		t.Fatal(output, err)
	}
}

func TestHTMLSerializationQuotesDoctypeIdentifiers(t *testing.T) {
	e := newEngine(t, transform.Config{})
	s := compileSheet(t, e, `<xsl:output method="html" html-version="4.01" doctype-system="a&quot;b"/><xsl:template name="start"><html/></xsl:template>`)
	result, err := s.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	output, err := result.Serialize(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(output.Primary, []byte(`<!DOCTYPE html SYSTEM 'a"b'>`)) {
		t.Fatal(string(output.Primary))
	}
}

func TestResultStreamsPartialOutputAndCountsBytes(t *testing.T) {
	engine := newEngine(t, transform.Config{})
	sheet := compileSheet(t, engine, `<xsl:output method="xml" omit-xml-declaration="yes"/><xsl:template name="start"><r>first</r><xsl:sequence select="map{}"/></xsl:template>`)
	result, err := sheet.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	var partial bytes.Buffer
	n, err := result.WriterTo(t.Context()).WriteTo(&partial)
	var coded *transform.Error
	if n == 0 || n != int64(partial.Len()) || !errors.As(err, &coded) || coded.Code != "SENR0001" {
		t.Fatal(n, partial.String(), err)
	}
	if output, err := result.Serialize(t.Context()); output != nil || err == nil {
		t.Fatal(output, err)
	}
	sheet = compileSheet(t, engine, `<xsl:output method="xml"/><xsl:template name="start"><r>data</r></xsl:template>`)
	failure := errors.New("writer failed")
	writer := &prefixFailure{remaining: 7, failure: failure}
	n, err = sheet.Write(t.Context(), writer, nil, transform.XSLTContext{Template: document.Name{Local: "start"}})
	if n != 7 || !errors.Is(err, failure) {
		t.Fatal(n, err)
	}
}

func TestResultWriterToHonorsWriterErrors(t *testing.T) {
	engine := newEngine(t, transform.Config{})
	sheet := compileSheet(t, engine, `<xsl:output omit-xml-declaration="yes"/><xsl:template name="start"><r>data</r></xsl:template>`)
	result, err := sheet.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}

	source := result.WriterTo(t.Context())
	failure := errors.New("destination failed")
	for _, tc := range []struct {
		name    string
		failure error
		want    error
	}{
		{"partial write with error", failure, failure},
		{"short write without error", nil, io.ErrShortWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			destination := &prefixFailure{remaining: 7, failure: tc.failure}
			if n, err := source.WriteTo(destination); n != 7 || !errors.Is(err, tc.want) {
				t.Fatalf("WriteTo: %d bytes, %v", n, err)
			}
		})
	}

	var out bytes.Buffer
	if n, err := source.WriteTo(&out); err != nil || n != int64(out.Len()) || out.String() != `<r>data</r>` {
		t.Fatalf("reuse after failure: %d bytes, %q, %v", n, out.Bytes(), err)
	}
}

func TestSecondaryOutputMustBeConsumedExplicitly(t *testing.T) {
	sheet := compileSheet(t, newEngine(t, transform.Config{}), `<xsl:output method="text"/><xsl:template name="start">main<xsl:result-document href="extra" method="text">extra</xsl:result-document></xsl:template>`)
	xsltContext := transform.XSLTContext{Template: document.Name{Local: "start"}}
	if n, err := sheet.Write(t.Context(), io.Discard, nil, xsltContext); n != 0 || !errors.Is(err, transform.ErrUnsupported) {
		t.Fatal(n, err)
	}
	result, err := sheet.Execute(t.Context(), nil, xsltContext)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	n, err := result.WriteSecondary(t.Context(), "extra", &output)
	if err != nil || n != 5 || output.String() != "extra" {
		t.Fatal(n, err, output.String())
	}
}

func TestStreamedSerializationPreservesOutputPolicy(t *testing.T) {
	cases := []struct {
		output string
		body   string
		want   string
	}{
		{`method="xml" omit-xml-declaration="yes" normalization-form="NFC"`, `<r>e&#x301;</r>`, `<r>é</r>`},
		{`method="xml" omit-xml-declaration="yes" cdata-section-elements="r"`, `<r>&lt;content&gt;</r>`, `<r><![CDATA[<content>]]></r>`},
		{`method="xml" omit-xml-declaration="yes" encoding="US-ASCII"`, `<r>я</r>`, `<r>&#1103;</r>`},
		{`method="xml" omit-xml-declaration="yes" encoding="US-ASCII" cdata-section-elements="r"`, `<r>я</r>`, `<r>&#1103;</r>`},
		{`method="html" html-version="5"`, `<xsl:comment>before</xsl:comment><p>after</p>`, `<!--before--><p>after</p>`},
		{`method="html" html-version="5"`, `<html><head/><body><input checked="checked"/><script>&lt;x&gt;&amp;</script><br/></body></html>`, `<!DOCTYPE html><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"></head><body><input checked><script><x>&</script><br></body></html>`},
		{`method="html" html-version="5"`, `<html><head><meta http-equiv="Content-Type" content="old"/></head><body>&#x85;</body></html>`, `<!DOCTYPE html><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"></head><body>&#x85;</body></html>`},
		{`method="text" normalization-form="NFC"`, `<xsl:sequence select="('e','&#x301;')"/>`, `e ́`},
		{`method="xml" omit-xml-declaration="yes" indent="yes" suppress-indentation="r"`, `<r><a><b/></a></r>`, `<r><a><b/></a></r>`},
		{`method="json"`, `<xsl:sequence select="map{'data':['я',true(),42]}"/>`, `{"data":["я",true,42]}`},
	}
	for _, tc := range cases {
		t.Run(tc.output+tc.body, func(t *testing.T) {
			engine := newEngine(t, transform.Config{})
			source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output ` + tc.output + `/><xsl:template name="start">` + tc.body + `</xsl:template></xsl:stylesheet>`
			sheet, err := engine.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{})
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			n, err := sheet.Write(t.Context(), &output, nil, transform.XSLTContext{Template: document.Name{Local: "start"}})
			if err != nil || n != int64(output.Len()) || output.String() != tc.want {
				t.Fatal(n, err, output.String(), tc.want)
			}
		})
	}
}

func TestDoctypeSerialization(t *testing.T) {
	ctx := t.Context()
	e := newEngine(t, transform.Config{})
	for _, method := range []string{"xml", "html"} {
		q, err := e.CompileXPath(ctx, `serialize(parse-xml('<r/>'), map{'method':'`+method+`','doctype-system':'a"b','omit-xml-declaration':true()})`, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		result, err := q.Evaluate(ctx, nil, transform.XPathContext{})
		if err != nil {
			t.Fatal(err)
		}
		s, err := result.Text()
		if err != nil || !strings.Contains(s, `SYSTEM 'a"b'`) {
			t.Fatalf("%s: %q, %v", method, s, err)
		}
		if method == "xml" {
			decoder := xml.NewDecoder(strings.NewReader(s))
			for {
				_, err := decoder.Token()
				if err != nil {
					if err == io.EOF {
						break
					}

					t.Fatal(err)
				}
			}
		}
	}
}

func TestXSLTRecordsStreamOutput(t *testing.T) {
	engine := newEngine(t, transform.Config{})
	source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="xml" omit-xml-declaration="yes"/><xsl:template match="/"><out><xsl:value-of select="item/@id"/></out></xsl:template></xsl:stylesheet>`
	sheet, err := engine.CompileXSLTReader(t.Context(), strings.NewReader(source), transform.XSLTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	reader := &gatedInput{first: strings.NewReader(`<feed><item id="1"/>`), rest: strings.NewReader(`<item id="2"/></feed>`), ready: func() bool { return output.Len() > 0 }}
	n, err := sheet.WriteRecords(t.Context(), &output, reader, transform.StreamOptions{Records: document.RecordOptions{Path: []document.Name{{Local: "feed"}, {Local: "item"}}}, Separator: "\n"})
	if err != nil || reader.early || output.String() != "<out>1</out>\n<out>2</out>" || n != int64(output.Len()) {
		t.Fatal(n, err, output.String(), reader.early)
	}
}

func TestStreamCancellationAndLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	err := document.ReadRecords(ctx, strings.NewReader(`<f><r/><r/></f>`), document.RecordOptions{Path: []document.Name{{Local: "f"}, {Local: "r"}}}, func(*document.Document) error { calls++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
	sheet := compileSheet(t, newEngine(t, transform.Config{}), `<xsl:output method="text"/><xsl:template match="/">value</xsl:template>`)
	var output bytes.Buffer
	n, err := sheet.WriteRecords(t.Context(), &output, strings.NewReader(`<f><r/><r/></f>`), transform.StreamOptions{Records: document.RecordOptions{Path: []document.Name{{Local: "f"}, {Local: "r"}}}, MaxOutputBytes: 7})
	if !errors.Is(err, transform.ErrLimit) || n != int64(output.Len()) || output.String() != "value" {
		t.Fatal(n, output.String(), err)
	}
	options := document.RecordOptions{Path: []document.Name{{Local: "f"}, {Local: "r"}}, MaxInputBytes: 12}
	if err := document.ReadRecords(t.Context(), strings.NewReader(`<f><r/></f>   extra`), options, func(*document.Document) error { return nil }); err == nil {
		t.Fatal("whole stream byte limit ignored")
	}
}

func TestRecordMessagesCanStopProcessing(t *testing.T) {
	sheet := compileSheet(t, newEngine(t, transform.Config{}), `<xsl:output method="text"/><xsl:template match="/"><xsl:message>notice</xsl:message>result</xsl:template>`)
	failure := errors.New("diagnostic consumer stopped")
	options := transform.StreamOptions{Records: document.RecordOptions{Path: []document.Name{{Local: "f"}, {Local: "r"}}}, OnMessage: func(message transform.Message) error {
		if message.Text != "notice" {
			t.Fatal(message)
		}
		return failure
	}}
	var output bytes.Buffer
	n, err := sheet.WriteRecords(t.Context(), &output, strings.NewReader(`<f><r/><r/></f>`), options)
	if n != 0 || output.Len() != 0 || !errors.Is(err, failure) {
		t.Fatal(n, output.String(), err)
	}
}

func TestResultWritersBoundSerializationMemory(t *testing.T) {
	const size = 1 << 20
	for _, encoding := range []string{"UTF-8", "UTF-16", "ISO-8859-1", "ISO-2022-JP"} {
		for _, method := range []string{"xml", "html", "text"} {
			t.Run(method+"/"+encoding, func(t *testing.T) {
				body := `<r><xsl:value-of select="/*"/></r>`
				if method == "html" {
					body = `<html><head><title>test</title></head><body><xsl:value-of select="/*"/></body></html>`
				}
				result := streamingResult(t, "<r>"+strings.Repeat("&amp;", size)+"</r>", `method="`+method+`" encoding="`+encoding+`" omit-xml-declaration="yes"`, body)
				var sink streamingSink
				if _, err := result.WriterTo(t.Context()).WriteTo(&sink); err != nil {
					t.Fatal(err)
				}
				if sink.bytes < size || sink.largest > 32<<10 {
					t.Fatal("unbounded write", sink.bytes, sink.largest)
				}
				allocated := allocatedDuring(t, func() error { _, err := result.WriterTo(t.Context()).WriteTo(sha256.New()); return err })
				if allocated > 256<<10 {
					t.Fatalf("writer allocated %d bytes for already computed result", allocated)
				}
				failure := errors.New("sink stopped")
				allocated = allocatedDuring(t, func() error {
					dst := &prefixFailure{remaining: 128, failure: failure}
					n, err := result.WriterTo(t.Context()).WriteTo(dst)
					if n != 128 || !errors.Is(err, failure) {
						return errors.New("early destination failure was lost")
					}
					return nil
				})
				if allocated > 256<<10 {
					t.Fatalf("writer allocated %d bytes before first output failure", allocated)
				}
			})
		}
	}
}

func TestEncodedSerializationPreservesCharactersAndEncoderState(t *testing.T) {
	for _, encoding := range []string{"UTF-16", "UTF-16LE", "ISO-8859-1", "ISO-2022-JP"} {
		t.Run(encoding, func(t *testing.T) {
			text := strings.Repeat("a", 32767) + "é日本😀" + strings.Repeat("b", 8193)
			result := streamingResult(t, "<r>"+text+"</r>", `method="xml" encoding="`+encoding+`" omit-xml-declaration="yes"`, `<r><xsl:value-of select="/*"/></r>`)
			var encoded bytes.Buffer
			if _, err := result.WriterTo(t.Context()).WriteTo(&encoded); err != nil {
				t.Fatal(err)
			}
			codec, err := htmlindex.Get(encoding)
			if err != nil {
				t.Fatal(err)
			}
			if encoding == "UTF-16" {
				codec = textunicode.UTF16(textunicode.BigEndian, textunicode.UseBOM)
			}
			decoded, err := io.ReadAll(texttransform.NewReader(bytes.NewReader(encoded.Bytes()), codec.NewDecoder()))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := document.Parse(t.Context(), decoded, document.DefaultLimits())
			if err != nil || doc.Root().Text() != text {
				t.Fatalf("lost characters or encoder shift state: %v", err)
			}
		})
	}
}

func TestHTMLWritersBoundAttributesAndMappedRawText(t *testing.T) {
	const count = 1 << 18
	cases := []struct {
		name         string
		input        string
		declarations string
		output       string
		body         string
		want         string
	}{
		// F&O escape-html-uri preserves printable ASCII, including space.
		{"URI", strings.Repeat("e\u0301 &amp;", count), "", `method="html"`, `<a href="{/*}">link</a>`, `<a href="` + strings.Repeat("%C3%A9 &amp;", count) + `">link</a>`},
		{"raw-text", strings.Repeat("a", count*4), `<xsl:character-map name="m"><xsl:output-character character="a" string="ab"/></xsl:character-map>`, `method="html" use-character-maps="m"`, `<script><xsl:value-of select="/*"/></script>`, `<script>` + strings.Repeat("ab", count*4) + `</script>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEngine(t, transform.Config{Limits: transform.Limits{MaxInputBytes: 16 << 20, MaxOutputBytes: 16 << 20, Timeout: time.Minute}})
			sheet := compileSheet(t, e, tc.declarations+`<xsl:output `+tc.output+`/><xsl:template match="/">`+tc.body+`</xsl:template>`)
			doc, err := e.ParseReader(t.Context(), strings.NewReader("<r>"+tc.input+"</r>"))
			if err != nil {
				t.Fatal(err)
			}
			result, err := sheet.Execute(t.Context(), doc, transform.XSLTContext{})
			if err != nil {
				t.Fatal(err)
			}
			want := sha256.Sum256([]byte(tc.want))
			allocated := allocatedDuring(t, func() error {
				hash := sha256.New()
				n, err := result.WriterTo(t.Context()).WriteTo(hash)
				if err != nil {
					return err
				}
				if int(n) != len(tc.want) || !bytes.Equal(hash.Sum(nil), want[:]) {
					return errors.New("HTML attribute or character map changed output")
				}
				return nil
			})
			if allocated > 256<<10 {
				t.Fatalf("HTML %s allocated %d bytes", tc.name, allocated)
			}
		})
	}
}

func TestJSONNodeSerializationKeepsEncoding(t *testing.T) {
	result := streamingResult(t, "<r/>", `method="json" encoding="UTF-16"`, `<xsl:variable name="n"><r>é</r></xsl:variable><xsl:sequence select="map{'n':$n}"/>`)
	var output bytes.Buffer
	if _, err := result.WriterTo(t.Context()).WriteTo(&output); err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(texttransform.NewReader(&output, textunicode.UTF16(textunicode.BigEndian, textunicode.ExpectBOM).NewDecoder()))
	if err != nil || string(decoded) != `{"n":"<r>é<\/r>"}` {
		t.Fatalf("JSON node encoding: %q %v", decoded, err)
	}
}

func TestWriterSerializationSupportsBufferedOptions(t *testing.T) {
	cases := []struct {
		output string
		body   string
		want   string
	}{
		{`method="xml" omit-xml-declaration="yes"`, `<r><xsl:text disable-output-escaping="yes">&lt;b&gt;raw&lt;/b&gt;</xsl:text></r>`, `<r><b>raw</b></r>`},
		{`method="xhtml" omit-xml-declaration="yes"`, `<r><br/></r>`, `<r><br></br></r>`},
		{`method="xhtml" html-version="5" omit-xml-declaration="yes"`, `<r xmlns="http://www.w3.org/1999/xhtml"><br/></r>`, `<r xmlns="http://www.w3.org/1999/xhtml"><br /></r>`},
		{`method="html" normalization-form="NFC"`, `<p>e&#x301;</p>`, `<p>é</p>`},
		{`method="text" normalization-form="FULLY-NORMALIZED"`, `<p>e&#x301;</p>`, `é`},
		{`method="adaptive"`, `<xsl:sequence select="(1,2)"/>`, "1\n2"},
		{`method="json"`, `<xsl:variable name="n"><r/></xsl:variable><xsl:sequence select="map{'n':$n}"/>`, `{"n":"<r\/>"}`},
	}
	for _, tc := range cases {
		t.Run(tc.output, func(t *testing.T) {
			result := streamingResult(t, "<r/>", tc.output, tc.body)
			var dst bytes.Buffer
			n, err := result.WriterTo(t.Context()).WriteTo(&dst)
			if err != nil || int(n) != len(tc.want) || dst.String() != tc.want {
				t.Fatalf("writer output: %d %q %v", n, dst.String(), err)
			}
			output, err := result.Serialize(t.Context())
			if err != nil || string(output.Primary) != tc.want {
				t.Fatalf("explicit buffered output: %v %v", output, err)
			}
		})
	}
}

func streamingResult(t *testing.T, input, output, body string) *transform.Result {
	t.Helper()
	e := newEngine(t, transform.Config{Limits: transform.Limits{MaxInputBytes: 16 << 20, MaxOutputBytes: 16 << 20, Timeout: time.Minute}})
	s := compileSheet(t, e, `<xsl:output `+output+`/><xsl:template match="/">`+body+`</xsl:template>`)
	d, err := e.ParseReader(t.Context(), strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Execute(t.Context(), d, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSerializeBoundsCharacterMapExpansion(t *testing.T) {
	e := newEngine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 64 << 10}})
	variables := transform.Bindings{
		{Local: "input"}:       transform.Values(transform.String(strings.Repeat("a", 4096))),
		{Local: "replacement"}: transform.Values(transform.String(strings.Repeat("b", 4096))),
	}
	for _, method := range []string{"xml", "html", "xhtml", "text", "json", "adaptive"} {
		t.Run(method, func(t *testing.T) {
			q, err := e.CompileXPath(t.Context(), `serialize($input,map{'method':'`+method+`','use-character-maps':map{'a':$replacement}})`, transform.XPathOptions{Version: transform.XPath31})
			if err != nil {
				t.Fatal(err)
			}
			// The requested expansion is 16 MiB; the invocation permits 64 KiB.
			allocated := allocatedDuring(t, func() error {
				got, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Variables: variables})
				if !errors.Is(err, transform.ErrLimit) || got.Len() != 0 {
					return errors.New("serialization output budget was ignored")
				}
				return nil
			})
			if allocated > 1<<20 {
				t.Fatalf("allocated %d bytes before rejecting character-map expansion", allocated)
			}
		})
	}
}

func TestXSLTBoundsCharacterMapExpansion(t *testing.T) {
	e := newEngine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 64 << 10}})
	bindings := transform.Bindings{{Local: "input"}: transform.Values(transform.String(strings.Repeat("a", 4096)))}
	for _, method := range []string{"xml", "html", "xhtml", "text", "json", "adaptive"} {
		t.Run(method, func(t *testing.T) {
			source := `<xsl:param name="input"/><xsl:output method="` + method + `" use-character-maps="m"/><xsl:character-map name="m"><xsl:output-character character="a" string="` + strings.Repeat("b", 4096) + `"/></xsl:character-map><xsl:template name="start"><xsl:sequence select="$input"/></xsl:template>`
			compiled := compileSheet(t, e, source)
			allocated := allocatedDuring(t, func() error {
				output, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: "start"}, Parameters: bindings})
				if !errors.Is(err, transform.ErrLimit) || output != nil {
					return errors.New("XSLT serialization output budget was ignored")
				}
				return nil
			})
			if allocated > 1<<20 {
				t.Fatalf("allocated %d bytes before rejecting character-map expansion", allocated)
			}
		})
	}
}
