package transform_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

// Explicit JSON normalization must also handle the common case where the input
// already has the requested form, including large ASCII and composed Unicode.
func BenchmarkJSONNormalization(b *testing.B) {
	for name, unit := range map[string]string{"ASCII": "x", "Composed": "é", "Decomposed": "e\u0301"} {
		b.Run(name, func(b *testing.B) {
			for _, size := range []int{16, 65536} {
				b.Run(strconv.Itoa(size), func(b *testing.B) {
					e := engine(b, transform.Config{})
					q := query(b, e, `serialize($source, map{'method':'json', 'normalization-form':'NFC'})`, transform.XPath31)
					input := strings.Repeat(unit, size)
					options := transform.XPathContext{Variables: transform.Bindings{{Local: "source"}: transform.Values(transform.String(input))}}
					b.ReportAllocs()
					b.SetBytes(int64(len(input)))
					for b.Loop() {
						if _, err := q.Evaluate(b.Context(), nil, options); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func BenchmarkJSONNormalizationParallel(b *testing.B) {
	e := engine(b, transform.Config{})
	q := query(b, e, `serialize($source, map{'method':'json', 'normalization-form':'NFC', 'use-character-maps':map{'|':'mapped'}})`, transform.XPath31)
	inputs := make([]transform.XPathContext, 0, 3)
	for _, source := range []string{strings.Repeat("x", 4096), strings.Repeat("é e\u0301 | ", 512), "a" + strings.Repeat("\u0301", 128)} {
		inputs = append(inputs, transform.XPathContext{Variables: transform.Bindings{{Local: "source"}: transform.Values(transform.String(source))}})
	}
	b.ReportAllocs()
	b.SetParallelism(3)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, err := q.Evaluate(b.Context(), nil, inputs[i%len(inputs)]); err != nil {
				b.Error(err)
				return
			}
			i++
		}
	})
}
