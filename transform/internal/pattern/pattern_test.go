package pattern_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	patternpkg "github.com/skarm/xmlsec/transform/internal/pattern"
)

const nameAB = "a.b"

func TestMatchSemantics(t *testing.T) {
	for _, c := range []struct {
		pattern string
		input   string
		options patternpkg.Options
		want    bool
	}{
		{`^(ab|a)b$`, "ab", patternpkg.Options{}, true},
		{`^(a|aa)*b$`, strings.Repeat("a", 300), patternpkg.Options{}, false},
		{`^a{1001}$`, strings.Repeat("a", 1001), patternpkg.Options{}, true},
		{`^a{1001}$`, strings.Repeat("a", 1000), patternpkg.Options{}, false},
		{`^a{1001,}$`, strings.Repeat("a", 1002), patternpkg.Options{}, true},
		{`^(a?){3}b$`, "b", patternpkg.Options{}, true},
		{`^(a?)*b$`, "b", patternpkg.Options{}, true},
		{`^(ab)\1$`, "abab", patternpkg.Options{}, true},
		{`^(ab)\1$`, "abAB", patternpkg.Options{}, false},
		{`^([md])[aeiou]\1$`, "Mum", patternpkg.Options{IgnoreCase: true}, true},
		{`^(a)?b\1$`, "b", patternpkg.Options{}, true},
		{`^(a)\12$`, "aa2", patternpkg.Options{}, true},
		{`^[a-z-[aeiou]]+$`, "bcdf", patternpkg.Options{}, true},
		{`^[a-z-[aeiou]]+$`, "bcaf", patternpkg.Options{}, false},
		{`^[A-Z-[IO]]+$`, "abc", patternpkg.Options{IgnoreCase: true}, true},
		{`^[A-Z-[IO]]+$`, "i", patternpkg.Options{IgnoreCase: true}, false},
		{`^[a-z-[d-z-[x]]]$`, "x", patternpkg.Options{}, true},
		{`^[^Q]$`, "q", patternpkg.Options{IgnoreCase: true}, false},
		{`^\p{Lu}$`, "a", patternpkg.Options{IgnoreCase: true}, false},
		{`^\P{Lu}$`, "a", patternpkg.Options{IgnoreCase: true}, true},
		{`^[\p{Lu}q]$`, "Q", patternpkg.Options{IgnoreCase: true}, true},
		{`^[\p{Lu}q]$`, "b", patternpkg.Options{IgnoreCase: true}, false},
		{`^[A-Z]$`, "K", patternpkg.Options{IgnoreCase: true}, true},
		{`^\d+$`, "٢٣", patternpkg.Options{}, true},
		{`^\s$`, "\v", patternpkg.Options{}, false},
		{`^\S$`, "\v", patternpkg.Options{}, true},
		{`^.$`, "\r", patternpkg.Options{}, false},
		{`^.$`, "\r", patternpkg.Options{DotAll: true}, true},
		{nameAB, nameAB, patternpkg.Options{Literal: true}, true},
		{nameAB, "axb", patternpkg.Options{Literal: true}, false},
		{`(?i)^ab(?-i:c)$`, "ABc", patternpkg.Options{}, true},
		{`(?i)^ab(?-i:c)$`, "ABC", patternpkg.Options{}, false},
		{`^(?m:b)$`, "x\nb", patternpkg.Options{}, false},
	} {
		t.Run(c.pattern+"/"+c.input, func(t *testing.T) {
			p := compileTest(t, c.pattern, c.options)

			got, err := p.Match(t.Context(), c.input, patternpkg.Work{})
			if err != nil || got != c.want {
				t.Fatalf("match=%v, want=%v, error=%v", got, c.want, err)
			}
		})
	}
}

func TestMatchCapturesAndStreaming(t *testing.T) {
	for _, c := range []struct {
		pattern string
		input   string
		options patternpkg.Options
		want    [][]int
	}{
		{`a.*a`, "abracadabra", patternpkg.Options{}, [][]int{{0, 11}}},
		{`a.*?a`, "abracadabra", patternpkg.Options{}, [][]int{{0, 4}, {5, 8}}},
		{`(α)(β)?`, "α αβ", patternpkg.Options{}, [][]int{{0, 2, 0, 2, -1, -1}, {3, 7, 3, 5, 5, 7}}},
		{`(a)(b(c))`, "abc", patternpkg.Options{}, [][]int{{0, 3, 0, 1, 1, 3, 2, 3}}},
		{`a{1,2}?`, "aaa", patternpkg.Options{}, [][]int{{0, 1}, {1, 2}, {2, 3}}},
		{`^a*`, "aa baa", patternpkg.Options{}, [][]int{{0, 2}}},
		{`^a+`, "aa\naa", patternpkg.Options{Multiline: true}, [][]int{{0, 2}, {3, 5}}},
		{`a*`, "aβ", patternpkg.Options{}, [][]int{{0, 1}, {3, 3}}},
		{``, "αβ", patternpkg.Options{}, [][]int{{0, 0}, {2, 2}, {4, 4}}},
	} {
		t.Run(c.pattern+"/"+c.input, func(t *testing.T) {
			p := compileTest(t, c.pattern, c.options)

			var got [][]int

			err := p.Each(t.Context(), c.input, -1, patternpkg.Work{}, func(m []int) bool {
				got = append(got, m)
				return true
			})
			if err != nil || !slices.EqualFunc(got, c.want, slices.Equal) {
				t.Fatalf("captures=%v, want=%v, error=%v", got, c.want, err)
			}
		})
	}
}

func TestLimitsAndCancellation(t *testing.T) {
	anchor := compileTest(t, `^{1000000}`, patternpkg.Options{})
	if _, err := anchor.Match(t.Context(), "x", patternpkg.Work{MaxSteps: 10}); !errors.Is(err, patternpkg.ErrLimit) {
		t.Fatal("zero-width repeat escaped the work budget", err)
	}

	p := compileTest(t, `^(a|aa)*b$`, patternpkg.Options{})
	for _, work := range []patternpkg.Work{{MaxSteps: 10}, {MaxCells: 10}} {
		if _, err := p.Match(t.Context(), strings.Repeat("a", 500), work); !errors.Is(err, patternpkg.ErrLimit) {
			t.Fatal("resource error lost", err)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	steps := 0

	work := patternpkg.Work{Charge: func(n int) error {
		steps += n
		if steps > 30 {
			cancel()
		}

		return nil
	}}
	if _, err := p.Match(ctx, strings.Repeat("a", 500), work); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}

	for _, source := range []string{strings.Repeat("(", 129) + "a" + strings.Repeat(")", 129), `a{999999999999999999999999999999999999}`} {
		if _, err := patternpkg.Compile(source, patternpkg.Options{}); !errors.Is(err, patternpkg.ErrLimit) {
			t.Fatalf("unbounded compilation: %v", err)
		}
	}

	for _, source := range []string{`[`, `()\2`, `(a\1)`, `\1(a)`, `[z-a]`, `a{3,2}`, `a**`, `\x{110000}`} {
		if _, err := patternpkg.Compile(source, patternpkg.Options{}); err == nil {
			t.Fatalf("malformed pattern accepted: %s", source)
		}
	}
	// Replacement charges before copying the capture, including literal chunks.
	var charged int

	_, err := patternpkg.AppendReplacement(nil, `${1}${1}`, "capture", []int{0, 7, 0, 7}, func(n int) error { charged += n; return patternpkg.ErrLimit })
	if !errors.Is(err, patternpkg.ErrLimit) || charged != 7 {
		t.Fatal("unbounded replacement", charged, err)
	}
}

func TestConcurrentProgram(t *testing.T) {
	p := compileTest(t, `^([α-ω]+)\1$`, patternpkg.Options{})

	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 20 {
				ok, err := p.Match(t.Context(), "αβαβ", patternpkg.Work{})
				if err != nil || !ok {
					t.Error(ok, err)
				}
			}
		})
	}

	wg.Wait()
}

func FuzzPattern(f *testing.F) {
	for _, source := range []string{`a*`, `(a)\1`, `[a-z-[aeiou]]`, `((a?)*){2,}`, `\p{L}+`} {
		f.Add(source, "αabc\n")
	}

	f.Fuzz(func(t *testing.T, source, input string) {
		if len(source) > 4096 || len(input) > 4096 {
			t.Skip()
		}

		p, err := patternpkg.Compile(source, patternpkg.Options{})
		if err != nil {
			return
		}

		err = p.Each(t.Context(), input, 100, patternpkg.Work{MaxSteps: 20_000, MaxCells: 20_000}, func(m []int) bool {
			if len(m) != 2*(p.Groups()+1) || m[0] < 0 || m[0] > m[1] || m[1] > len(input) {
				t.Fatalf("invalid match: %v", m)
			}

			for group := 1; group <= p.Groups(); group++ {
				if m[2*group] < -1 || m[2*group+1] < m[2*group] || m[2*group+1] > len(input) {
					t.Fatalf("invalid group: %v", m)
				}
			}

			return true
		})
		if err != nil && !errors.Is(err, patternpkg.ErrLimit) {
			t.Fatal(err)
		}
	})
}

func compileTest(t testing.TB, source string, options patternpkg.Options) *patternpkg.Program {
	t.Helper()

	p, err := patternpkg.Compile(source, options)
	if err != nil {
		t.Fatal(err)
	}

	return p
}

// BenchmarkPrograms separates immutable program reuse from parsing costs and
// includes a bounded ambiguous failure rather than unbounded backtracking.
func BenchmarkPrograms(b *testing.B) {
	for _, tc := range []struct {
		name   string
		source string
		input  string
	}{
		{"Short", `^[a-z]+[0-9]+$`, "hello123"},
		{"Large", `^[a-z]+[0-9]+$`, strings.Repeat("a", 8192) + "123"},
		{"AmbiguousFailure", `^(a|aa)*b$`, strings.Repeat("a", 128)},
		{"Backref", `^([a-z]+)\1$`, strings.Repeat("abc", 32)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			p, err := patternpkg.Compile(tc.source, patternpkg.Options{})
			if err != nil {
				b.Fatal(err)
			}
			b.Run("Compile", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := patternpkg.Compile(tc.source, patternpkg.Options{}); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("Reuse", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := p.Match(b.Context(), tc.input, patternpkg.Work{}); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("Parallel", func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if _, err := p.Match(b.Context(), tc.input, patternpkg.Work{}); err != nil {
							b.Error(err)
							return
						}
					}
				})
			})
		})
	}
}
