package transform_test

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

// BenchmarkEngineXPath measures invocation cost for scalar and node results.
// Fixtures and compilation are outside the timed loops. Publishing nodes enforces
// ownership and input policy.
func BenchmarkEngineXPath(b *testing.B) {
	for _, size := range []int{16, 1024, 8192} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			e := engine(b, transform.Config{})

			d, err := e.Parse(b.Context(), []byte(`<r>`+strings.Repeat(`<item a="2">text</item>`, size)+`</r>`))
			if err != nil {
				b.Fatal(err)
			}

			for _, version := range []transform.XPathVersion{transform.XPath10, transform.XPath31} {
				for name, source := range map[string]string{"Count": `count(/r/item)`, "Sum": `sum(/r/item/@a)`, "Nodes": `/r/item[@a='2']`} {
					b.Run(fmt.Sprintf("%d/%s", version, name), func(b *testing.B) {
						q := query(b, e, source, version)
						b.ReportAllocs()

						for b.Loop() {
							if _, err := q.Evaluate(b.Context(), d, transform.XPathContext{}); err != nil {
								b.Fatal(err)
							}
						}
					})
				}
			}
		})
	}
}

// BenchmarkXPathEscaping measures repeated escapes through compiled public APIs.
func BenchmarkXPathEscaping(b *testing.B) {
	const uriInput = " é/😀"

	for _, tc := range []struct {
		name       string
		expression string
		input      string
	}{
		{"URI", `encode-for-uri($source)`, uriInput},
		{"IRI", `iri-to-uri($source)`, uriInput},
		{"HTMLURI", `escape-html-uri($source)`, uriInput},
		{"JSONASCII", `serialize($source, map{'method':'json', 'encoding':'US-ASCII'})`, "\x01é😀"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			e := engine(b, transform.Config{})
			program := query(b, e, tc.expression, transform.XPath31)
			input := strings.Repeat(tc.input, 2048)
			ctx := transform.XPathContext{Variables: transform.Bindings{{Local: sourceName}: transform.Values(transform.String(input))}}

			b.ReportAllocs()
			b.SetBytes(int64(len(input)))

			for b.Loop() {
				if _, err := program.Evaluate(b.Context(), nil, ctx); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkEngineXSLT(b *testing.B) {
	b.Run("Compile", func(b *testing.B) {
		for _, tc := range []struct {
			name    string
			pattern string
		}{
			{"Simple", "n"},
			{"Pipe", "n | r/m"},
			{"Keyword", "n union r/m"},
			{"Parenthesized", "(n | r/m)"},
			{"Comments", "n (: ' :) | r/m"},
		} {
			b.Run(tc.name, func(b *testing.B) {
				e := engine(b, transform.Config{})
				source := []byte(sheet(version30, strings.Repeat(`<xsl:template match="`+tc.pattern+`"/>`, 50)))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := e.CompileXSLT(b.Context(), source, transform.XSLTOptions{}); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	})

	for _, size := range []int{16, 1024} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			e := engine(b, transform.Config{})

			d, err := e.Parse(b.Context(), []byte(`<r>`+strings.Repeat(`<item a="2">text</item>`, size)+`</r>`))
			if err != nil {
				b.Fatal(err)
			}

			for _, version := range []string{version10, version30} {
				b.Run(version, func(b *testing.B) {
					s := stylesheet(b, e, sheetStart+version+`"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out><xsl:apply-templates select="r/item"/></out></xsl:template><xsl:template match="item"><v n="{@a}"><xsl:value-of select="."/></v></xsl:template></xsl:stylesheet>`)
					b.ReportAllocs()

					for b.Loop() {
						if _, err := s.Transform(b.Context(), d, transform.XSLTContext{}); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func BenchmarkEngineParallel(b *testing.B) {
	e := engine(b, transform.Config{})

	d, err := e.Parse(b.Context(), []byte(`<r>`+strings.Repeat(`<item a="2">text</item>`, 1024)+`</r>`))
	if err != nil {
		b.Fatal(err)
	}

	q := query(b, e, `sum(/r/item/@a)`, transform.XPath31)
	s := stylesheet(b, e, sheet(version30, `<xsl:template match="/"><xsl:value-of select="sum(r/item/@a)"/></xsl:template>`))
	b.Run("XPath", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := q.Evaluate(b.Context(), d, transform.XPathContext{}); err != nil {
					b.Error(err)
				}
			}
		})
	})
	b.Run("XSLT", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := s.Transform(b.Context(), d, transform.XSLTContext{}); err != nil {
					b.Error(err)
				}
			}
		})
	})
}

// BenchmarkXSLTNamespaceConstruction covers leaf constructors and nested result
// elements. Namespace inheritance can only affect element children, while text,
// comments and processing instructions must keep their original order/content.
func BenchmarkXSLTNamespaceConstruction(b *testing.B) {
	for _, body := range []struct{ name, source string }{
		{"Text", `<v><xsl:value-of select="."/></v>`},
		{"NoNamespaces", `<v><xsl:value-of select="."/></v>`},
		{"MixedLeaves", `<v><xsl:text>a</xsl:text><xsl:comment>c</xsl:comment><xsl:processing-instruction name="p">i</xsl:processing-instruction><xsl:value-of select="."/></v>`},
		{"Elements", `<v><n><xsl:value-of select="."/></n></v>`},
	} {
		b.Run(body.name, func(b *testing.B) {
			e := engine(b, transform.Config{})
			d, err := e.Parse(b.Context(), []byte(`<r>`+strings.Repeat(`<item>text</item>`, 1024)+`</r>`))
			if err != nil {
				b.Fatal(err)
			}
			source := sheet(version30, `<xsl:template match="/"><out><xsl:for-each select="r/item">`+body.source+`</xsl:for-each></out></xsl:template>`)
			if body.name == "NoNamespaces" {
				source = strings.Replace(source, ` xmlns:xs="http://www.w3.org/2001/XMLSchema"`, "", 1)
			}
			s := stylesheet(b, e, source)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := s.Transform(b.Context(), d, transform.XSLTContext{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkXPathNodeReferences includes evaluating a selection and converting
// its attribute/namespace results for use by document and c14n APIs.
func BenchmarkXPathNodeReferences(b *testing.B) {
	for _, axis := range []string{"@*", "namespace::*"} {
		b.Run(axis, func(b *testing.B) {
			for _, count := range []int{1, 16, 128} {
				b.Run(strconv.Itoa(count), func(b *testing.B) {
					var source strings.Builder
					source.WriteString(`<r`)
					for i := range count {
						if axis == "@*" {
							fmt.Fprintf(&source, ` a%d="v"`, i)
						} else {
							fmt.Fprintf(&source, ` xmlns:p%d="urn:%d"`, i, i)
						}
					}
					source.WriteString(`/>`)
					e := engine(b, transform.Config{})
					d, err := e.Parse(b.Context(), []byte(source.String()))
					if err != nil {
						b.Fatal(err)
					}
					q := query(b, e, `/*/`+axis, transform.XPath31)
					want := count
					if axis == "namespace::*" {
						want++ // The predefined xml binding is always in scope.
					}
					b.ReportAllocs()
					for b.Loop() {
						result, err := q.Evaluate(b.Context(), d, transform.XPathContext{})
						if err != nil || result.Len() != want {
							b.Fatal("node selection changed cardinality", result.Len(), err)
						}
						for i := range result.Len() {
							value, _ := result.At(i)
							node, ok := value.Node()
							if !ok || !node.Reference().Valid() {
								b.Fatal("invalid node reference")
							}
						}
					}
				})
			}
		})
	}
}

// BenchmarkDynamicCollation measures reuse of one compiled query by callers
// choosing a collation dynamically. Binding construction is outside the loop.
func BenchmarkDynamicCollation(b *testing.B) {
	e := engine(b, transform.Config{})
	q := query(b, e, `compare('a', 'b', $uri)`, transform.XPath31)
	options := transform.XPathContext{Variables: transform.Bindings{{Local: variableURI}: transform.Values(transform.String("http://www.w3.org/2013/collation/UCA?lang=en"))}}

	for _, parallel := range []bool{false, true} {
		b.Run(strconv.FormatBool(parallel), func(b *testing.B) {
			b.ReportAllocs()

			if parallel {
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if _, err := q.Evaluate(b.Context(), nil, options); err != nil {
							b.Error(err)
						}
					}
				})

				return
			}

			for b.Loop() {
				if _, err := q.Evaluate(b.Context(), nil, options); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkTypedSort measures typed numeric sorting of a prepared mixed
// decimal/float sequence. Values, bindings and compilation are outside the loop.
func BenchmarkTypedSort(b *testing.B) {
	for _, size := range []int{256, 2048} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			e := engine(b, transform.Config{})
			q := query(b, e, fmt.Sprintf(`for $i in 1 to %d return if ($i mod 31 = 0) then xs:float(($i * 7919) mod %d) else xs:decimal(($i * 7919) mod %d) + 0.125`, size, size, size), transform.XPath31)

			items, err := q.Evaluate(b.Context(), nil, transform.XPathContext{})
			if err != nil {
				b.Fatal(err)
			}

			for _, keys := range []int{1, 2} {
				b.Run(strconv.Itoa(keys), func(b *testing.B) {
					s := stylesheet(b, e, sheet(version30, `<xsl:param name="items"/><xsl:template name="run" as="xs:anyAtomicType*"><xsl:perform-sort select="$items">`+strings.Repeat(`<xsl:sort select="."/>`, keys)+`</xsl:perform-sort></xsl:template>`))
					options := transform.XSLTContext{Template: transform.Name{Local: "run"}, Parameters: transform.Bindings{{Local: "items"}: items}}

					b.ReportAllocs()

					for b.Loop() {
						result, err := s.Execute(b.Context(), nil, options)
						if err != nil {
							b.Fatal(err)
						}

						if result.Primary().Len() != size {
							b.Fatal("sort dropped values")
						}
					}
				})
			}
		})
	}
}

func BenchmarkNumericBudgetGrowth(b *testing.B) {
	for _, limit := range []int{64, 256, 1024} {
		b.Run(strconv.Itoa(limit), func(b *testing.B) {
			e := engine(b, transform.Config{Limits: transform.Limits{MaxOutputBytes: limit}})
			q := query(b, e, `fold-left(1 to 80, 2, function($a,$b){$a*$a}) mod 2`, transform.XPath31)
			b.ReportAllocs()

			for b.Loop() {
				if _, err := q.Evaluate(b.Context(), nil, transform.XPathContext{}); !errors.Is(err, transform.ErrLimit) {
					b.Fatal(err)
				}
			}
		})
	}
}
