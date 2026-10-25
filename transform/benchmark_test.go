package transform_test

import (
	"context"
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

			d, err := e.Parse(context.Background(), []byte(`<r>`+strings.Repeat(`<item a="2">text</item>`, size)+`</r>`))
			if err != nil {
				b.Fatal(err)
			}

			for _, version := range []transform.XPathVersion{transform.XPath10, transform.XPath31} {
				for name, source := range map[string]string{"Count": `count(/r/item)`, "Sum": `sum(/r/item/@a)`, "Nodes": `/r/item[@a='2']`} {
					b.Run(fmt.Sprintf("%d/%s", version, name), func(b *testing.B) {
						q := query(b, e, source, version)
						b.ReportAllocs()

						for b.Loop() {
							if _, err := q.Evaluate(context.Background(), d, transform.XPathContext{}); err != nil {
								b.Fatal(err)
							}
						}
					})
				}
			}
		})
	}
}

func BenchmarkEngineXSLT(b *testing.B) {
	for _, size := range []int{16, 1024} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			e := engine(b, transform.Config{})

			d, err := e.Parse(context.Background(), []byte(`<r>`+strings.Repeat(`<item a="2">text</item>`, size)+`</r>`))
			if err != nil {
				b.Fatal(err)
			}

			for _, version := range []string{version10, version30} {
				b.Run(version, func(b *testing.B) {
					s := stylesheet(b, e, sheetStart+version+`"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out><xsl:apply-templates select="r/item"/></out></xsl:template><xsl:template match="item"><v n="{@a}"><xsl:value-of select="."/></v></xsl:template></xsl:stylesheet>`)
					b.ReportAllocs()

					for b.Loop() {
						if _, err := s.Transform(context.Background(), d, transform.XSLTContext{}); err != nil {
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

	d, err := e.Parse(context.Background(), []byte(`<r>`+strings.Repeat(`<item a="2">text</item>`, 1024)+`</r>`))
	if err != nil {
		b.Fatal(err)
	}

	q := query(b, e, `sum(/r/item/@a)`, transform.XPath31)
	s := stylesheet(b, e, sheet(version30, `<xsl:template match="/"><xsl:value-of select="sum(r/item/@a)"/></xsl:template>`))
	b.Run("XPath", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := q.Evaluate(context.Background(), d, transform.XPathContext{}); err != nil {
					b.Error(err)
				}
			}
		})
	})
	b.Run("XSLT", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := s.Transform(context.Background(), d, transform.XSLTContext{}); err != nil {
					b.Error(err)
				}
			}
		})
	})
}

// BenchmarkDynamicCollation measures reuse of one compiled query by callers
// choosing a collation dynamically. Binding construction is outside the loop.
func BenchmarkDynamicCollation(b *testing.B) {
	e := engine(b, transform.Config{})
	q := query(b, e, `compare('a', 'b', $uri)`, transform.XPath31)
	options := transform.XPathContext{Variables: transform.Bindings{{Local: "uri"}: transform.Values(transform.String("http://www.w3.org/2013/collation/UCA?lang=en"))}}

	for _, parallel := range []bool{false, true} {
		b.Run(strconv.FormatBool(parallel), func(b *testing.B) {
			b.ReportAllocs()

			if parallel {
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if _, err := q.Evaluate(context.Background(), nil, options); err != nil {
							b.Error(err)
						}
					}
				})

				return
			}

			for b.Loop() {
				if _, err := q.Evaluate(context.Background(), nil, options); err != nil {
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

			items, err := q.Evaluate(context.Background(), nil, transform.XPathContext{})
			if err != nil {
				b.Fatal(err)
			}

			for _, keys := range []int{1, 2} {
				b.Run(strconv.Itoa(keys), func(b *testing.B) {
					s := stylesheet(b, e, sheet(version30, `<xsl:param name="items"/><xsl:template name="run" as="xs:anyAtomicType*"><xsl:perform-sort select="$items">`+strings.Repeat(`<xsl:sort select="."/>`, keys)+`</xsl:perform-sort></xsl:template>`))
					options := transform.XSLTContext{Template: transform.Name{Local: "run"}, Parameters: transform.Bindings{{Local: "items"}: items}}

					b.ReportAllocs()

					for b.Loop() {
						result, err := s.Execute(context.Background(), nil, options)
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
