package transform_test

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

const (
	serializationXML  = "xml"
	serializationHTML = "html"
	serializationUTF8 = "UTF-8"
	serializationJSON = "json"
	serializationText = "text"
)

// TestStreamingSequenceAdjacency checks that atomic values are joined before
// document children are expanded.
// See https://www.w3.org/TR/xslt-xquery-serialization-31/#serdm.
func TestStreamingSequenceAdjacency(t *testing.T) {
	e := engine(t, transform.Config{})

	cases := []struct{ body, want string }{
		{`<xsl:sequence select="('a','','b')"/><xsl:sequence select="''"/><xsl:sequence select="'c'"/>`, "a  b  c"},
		{`<xsl:sequence select="'a'"/><xsl:document/><xsl:sequence select="'b'"/>`, "ab"},
		{`<xsl:sequence select="'a'"/><xsl:text/><xsl:sequence select="'b'"/>`, "ab"},
		{`<xsl:variable name="v"><a/><xsl:sequence select="('one','two')"/><b/></xsl:variable><xsl:value-of select="$v"/>`, "one two"},
	}
	for _, tc := range cases {
		s := stylesheet(t, e, sheet(version30, `<xsl:template name="start">`+tc.body+`</xsl:template>`))

		out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil {
			t.Fatal(err)
		}

		if got := string(out.Primary); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.body, got, tc.want)
		}
	}
}

func BenchmarkSerializationStreaming(b *testing.B) {
	cases := []struct{ method, encoding string }{
		{serializationXML, serializationUTF8},
		{serializationHTML, serializationUTF8},
		{serializationJSON, serializationUTF8},
		{serializationText, serializationUTF8},
		{serializationXML, "UTF-16"},
		{serializationHTML, "ISO-8859-1"},
	}
	for _, tc := range cases {
		for _, content := range []string{"plain", "escaped"} {
			for _, size := range []int{16 << 10, 1 << 20} {
				b.Run(fmt.Sprintf("%s/%s/%s/%d", tc.method, serializationEncoding(tc.encoding), content, size), func(b *testing.B) {
					payload := serializationPayload(tc.method, content, size)
					result := serializationFixture(b, tc.method, tc.encoding, payload)
					benchmarkSerializationResult(b, result, size)
				})
			}
		}
	}
}

// BenchmarkNormalizationStreaming measures requested NFC over resident results.
// Compilation and result construction are excluded from serialization timings.
func BenchmarkNormalizationStreaming(b *testing.B) {
	for _, method := range []string{serializationXML, serializationHTML, serializationText} {
		for _, size := range []int{16 << 10, 1 << 20} {
			b.Run(fmt.Sprintf("%s/%d", method, size), func(b *testing.B) {
				payload := strings.Repeat("e\u0301", size/3)
				e := engine(b, transform.Config{Limits: transform.Limits{MaxOutputBytes: 16 << 20}})
				compiled := stylesheet(b, e, sheetStart+version30+`"><xsl:param name="normalizationData"/><xsl:output method="`+method+`" normalization-form="NFC" omit-xml-declaration="yes" include-content-type="no"/><xsl:template name="start"><r><xsl:value-of select="$normalizationData"/></r></xsl:template></xsl:stylesheet>`)

				result, err := compiled.CallTemplate(b.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "normalizationData"}: transform.Values(transform.String(payload))}})
				if err != nil {
					b.Fatal(err)
				}

				writer := result.WriterTo(b.Context())
				b.ReportAllocs()
				b.SetBytes(int64(len(payload)))

				for b.Loop() {
					if _, err := writer.WriteTo(io.Discard); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func serializationEncoding(name string) string {
	if name == "" {
		return serializationUTF8
	}

	return name
}

func serializationPayload(method, content string, size int) string {
	character := "x"
	if content == "escaped" {
		character = "&"
		if method == serializationJSON {
			character = "\""
		}
	}

	return strings.Repeat(character, size)
}

func benchmarkSerializationResult(b *testing.B, result *transform.Result, size int) {
	b.Helper()
	b.Run("Writer", func(b *testing.B) {
		writer := result.WriterTo(b.Context())
		b.ReportAllocs()
		b.SetBytes(int64(size))

		for b.Loop() {
			if _, err := writer.WriteTo(io.Discard); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Buffered", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))

		for b.Loop() {
			if _, err := result.Serialize(b.Context()); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func serializationFixture(b *testing.B, method, encoding, payload string) *transform.Result {
	b.Helper()
	e := engine(b, transform.Config{Limits: transform.Limits{MaxOutputBytes: 16 << 20}})

	body := `<r><xsl:value-of select="$data"/></r>`
	if method == serializationJSON {
		body = `<xsl:sequence select="map{'value':$data}"/>`
	}

	compiled := stylesheet(b, e, sheetStart+version30+`"><xsl:param name="data"/><xsl:output method="`+method+`" encoding="`+serializationEncoding(encoding)+`" omit-xml-declaration="yes"/><xsl:template name="start">`+body+`</xsl:template></xsl:stylesheet>`)

	result, err := compiled.CallTemplate(b.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "data"}: transform.Values(transform.String(payload))}})
	if err != nil {
		b.Fatal(err)
	}

	return result
}

func TestSerializationExactNormalization(t *testing.T) {
	e := engine(t, transform.Config{})
	input := "a" + strings.Repeat("\u0315", 4100) + "\u0300\u034f\u0301"
	want := "à" + strings.Repeat("\u0315", 4100) + "\u034f\u0301"

	for _, method := range []string{serializationXML, serializationHTML, serializationText, "json", "adaptive"} {
		t.Run(method, func(t *testing.T) {
			body := `<r a="{$normalizationData}"><xsl:value-of select="$normalizationData"/></r>`
			if method == "json" || method == "adaptive" {
				body = `<xsl:sequence select="$normalizationData"/>`
			}

			style := stylesheet(t, e, sheetStart+version30+`"><xsl:param name="normalizationData"/><xsl:output method="`+method+`" normalization-form="NFC" omit-xml-declaration="yes" include-content-type="no"/><xsl:template name="start">`+body+`</xsl:template></xsl:stylesheet>`)

			result, err := style.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "normalizationData"}: transform.Values(transform.String(input))}})
			if err != nil {
				t.Fatal(err)
			}

			output, err := result.Serialize(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if !strings.Contains(string(output.Primary), want) || strings.Count(string(output.Primary), "\u034f") != strings.Count(string(output.Primary), want) {
				t.Fatal("wrong normalization or CGJ insertion")
			}

			var streamed strings.Builder
			if _, err := result.WriterTo(t.Context()).WriteTo(&streamed); err != nil || streamed.String() != string(output.Primary) {
				t.Fatal("writer mismatch", err)
			}
		})
	}
}
