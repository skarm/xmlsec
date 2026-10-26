package xpathregex_test

import (
	"strings"
	"testing"
	"unicode"

	"github.com/skarm/xmlsec/transform/internal/pattern"
	xpathregex "github.com/skarm/xmlsec/transform/internal/xpath/regex"
)

func TestTranslateXPathCharacterClasses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		pattern string
		yes     string
		no      string
		dotAll  bool
	}{
		{`^\s$`, "\t", "\u00a0", false},
		{`^\d$`, "٣", "A", false},
		{`^\i\c*$`, "p:name-1", "1name", false},
		{`^.$`, "x", "\r", false},
		{`^.$`, "\r", "", true},
		{`^\p{IsBasicLatin}+$`, "Ab1", "é", false},
	} {
		t.Run(tc.pattern+tc.yes, func(t *testing.T) {
			t.Parallel()
			translated, err := xpathregex.Translate(tc.pattern, tc.dotAll, false)
			if err != nil {
				t.Fatal(err)
			}

			compiled, err := pattern.Compile(translated, pattern.Options{Property: xpathregex.ResolveProperty})
			if err != nil {
				t.Fatal(err)
			}

			yes, err := compiled.Match(t.Context(), tc.yes, pattern.Work{})
			if err != nil {
				t.Fatal(err)
			}

			no, err := compiled.Match(t.Context(), tc.no, pattern.Work{})
			if err != nil {
				t.Fatal(err)
			}

			if !yes || no {
				t.Fatalf("translated %q: expected match %q and rejection %q", translated, tc.yes, tc.no)
			}
		})
	}
}

func TestValidateXPathRegex(t *testing.T) {
	t.Parallel()
	for _, p := range []string{`(?=a)`, `(?<=a)b`, `(?i)a`} {
		if err := xpathregex.RejectPerlSpecific(p); err == nil {
			t.Errorf("Perl construct %q accepted", p)
		}
	}

	for _, p := range []string{`\p{UnknownProperty}`, `[a-z`} {
		if err := xpathregex.Validate(p, false); err == nil {
			t.Errorf("invalid pattern %q accepted", p)
		}
	}

	if xpathregex.HasBackrefs(`\\1`) || !xpathregex.HasBackrefs(`(a)\1`) {
		t.Fatal("escaped slash confused with back-reference")
	}

	if err := xpathregex.Validate(`(a)\1`, false); err == nil {
		t.Fatal("back-reference accepted while disabled")
	}
}

func BenchmarkTranslation(b *testing.B) {
	for _, tc := range []struct {
		name   string
		source string
		valid  bool
	}{
		{"Short", `^\i\c*$`, true},
		{"Unicode", `^[\p{L}-[\p{IsBasicLatin}]]+$`, true},
		{"Large", strings.Repeat(`[a-z-[aeiou]]`, 256), true},
		{"Malformed", strings.Repeat(`[a-z]`, 256) + `\p{UnknownProperty}`, false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, err := xpathregex.Translate(tc.source, false, false)
				if (err == nil) != tc.valid {
					b.Fatal(err)
				}
			}
		})
	}
	// ResolveProperty is a shared immutable Unicode-table lookup; independent
	// parallel calls exercise its supported concurrent use without a fake cache.
	b.Run("PropertyParallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if xpathregex.ResolveProperty("IsBasicLatin") == nil {
					b.Error("missing property")
					return
				}
			}
		})
	})
}

func TestTranslateCharacterClassesAndSubtraction(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		source, yes, no string
	}{
		{`[a-z-[aeiou]]+`, "bcdf", "ae"},
		{`[a-z-[d-f-[e]]]`, "e", "d"},
		{`[\i-[A-Z]]`, "é", "A"},
		{`[\c-[\i]]`, "1", "A"},
		{`[\I]`, "1", "é"},
		{`[\C]`, " ", "-"},
		{`[\d]`, "٣", "a"},
		{`[\D]`, "a", "٣"},
		{`[\w]`, "$", "!"},
		{`[\W]`, "!", "$"},
		{`\I`, "1", "é"},
		{`\C`, " ", "-"},
		{`\D`, "a", "٣"},
		{`\w`, "$", ","},
		{`\W`, ",", "$"},
		{`\S`, "\u00a0", "\n"},
		{`\.`, ".", "x"},
		{`[\[\]]`, "]", "a"},
		{`\P{IsBasicLatin}`, "é", "A"},
		{`[\P{Lu}]`, "a", "A"},
	} {
		t.Run(test.source, func(t *testing.T) {
			t.Parallel()
			compiled := compileXPathPattern(t, "^(?:"+test.source+")$", false, false)
			assertRegexMatch(t, compiled, test.yes, true)
			assertRegexMatch(t, compiled, test.no, false)
		})
	}
}

func TestUnicodePropertiesRemainCaseSensitiveUnderIgnoreCase(t *testing.T) {
	t.Parallel()
	// F&O 3.1 §5.6.2: the i flag leaves property escapes unchanged.
	// https://www.w3.org/TR/2017/REC-xpath-functions-31-20170321/#flags
	for _, test := range []struct{ source, yes, no string }{
		{`\p{Lu}`, "A", "a"},
		{`\p{Ll}`, "a", "A"},
		{`\p{IsBasicLatin}`, "K", "K"},
		{`\P{IsBasicLatin}`, "K", "K"},
	} {
		t.Run(test.source, func(t *testing.T) {
			t.Parallel()
			compiled := compileXPathPattern(t, "^(?:"+test.source+")$", false, true)
			assertRegexMatch(t, compiled, test.yes, true)
			assertRegexMatch(t, compiled, test.no, false)
		})
	}
}

func TestDotAllPreservesEscapedAndClassDots(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		source, yes, no string
		dotAll          bool
	}{
		{`.`, "a", "\r", false},
		{`.`, "\r", "", true},
		{`[.]`, ".", "\n", true},
		{`\.`, ".", "\r", true},
	} {
		t.Run(test.source+test.yes, func(t *testing.T) {
			t.Parallel()
			compiled := compileXPathPattern(t, "^(?:"+test.source+")$", test.dotAll, false)
			assertRegexMatch(t, compiled, test.yes, true)
			assertRegexMatch(t, compiled, test.no, false)
		})
	}
}

func TestTranslationRejectsMalformedClassesAndProperties(t *testing.T) {
	t.Parallel()
	for _, source := range []string{`[]`, `[^]`, `[a[b]]`, `[-[a]]`, `[^-[a]]`, `[a--b]`, `[--z]`, `\p{Lu`, `\p{Unknown}`, `\P{IsNoSuchBlock}`, `[\p{Unknown}]`, `\p{Greek}`} {
		t.Run(source, func(t *testing.T) {
			t.Parallel()
			if translated, err := xpathregex.Translate("prefix"+source, false, false); err == nil || translated != "" {
				t.Fatalf("Translate accepted %q or returned partial output: %q, %v", source, translated, err)
			}
		})
	}
}

func TestXSD10HyphenPlacementAndRangeEndpoints(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		source string
		valid  bool
	}{
		{`a-b`, true},
		{`[-a]`, true},
		{`[a-]`, true},
		{`[a-z]`, true},
		{`[^-a]`, true},
		{`[^a-z]`, true},
		{`[\-a]`, true},
		{`[a\-z]`, true},
		{`[a-z-[aeiou]]`, true},
		{`[a-z-[\p{IsGreek}]]`, true},
		{`[a-b-c]`, false},
		{`[^a-b-c]`, false},
		{`[a-\d]`, false},
		{`[\d-a]`, false},
		{`[a-\p{Lu}]`, false},
		{`[\p{Lu}-a]`, false},
	} {
		t.Run(test.source, func(t *testing.T) {
			t.Parallel()
			err := xpathregex.ValidateXSD10(test.source)
			if (err == nil) != test.valid {
				t.Fatalf("XSD 1.0 hyphen validation = %v; want valid=%v", err, test.valid)
			}
		})
	}
}

func TestBackreferenceGrammarAndCaptureNumbering(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		source, yes, no string
	}{
		{`(a)\1`, "aa", "ab"},
		{`(?:a)(b)\1`, "abb", "aba"},
		{`(a(b)\2)`, "abb", "aba"},
		{`(a)\11`, "aa1", "aaa"},
		{`(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)(l)\12`, "abcdefghijkll", "abcdefghijkla2"},
		{`(a)\` + strings.Repeat("1", 30), "aa" + strings.Repeat("1", 29), "aa"},
	} {
		t.Run(test.source, func(t *testing.T) {
			t.Parallel()
			compiled := compileXPathPattern(t, "^(?:"+test.source+")$", false, false)
			assertRegexMatch(t, compiled, test.yes, true)
			assertRegexMatch(t, compiled, test.no, false)
			if err := xpathregex.Validate(test.source, false); err == nil {
				t.Fatal("back-reference survived disabled back-references")
			}
		})
	}
	for _, source := range []string{`\0`, `\1(a)`, `(a\1)`, `((a)\1)`, `(?:a)\1`, `(a)\2`} {
		t.Run("invalid/"+source, func(t *testing.T) {
			t.Parallel()
			if err := xpathregex.Validate(source, true); err == nil {
				t.Fatal("invalid or open capture reference accepted")
			}
		})
	}
}

func TestBackreferenceDetectionSkipsEscapesAndClasses(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		source string
		want   bool
	}{
		{`(a)\1`, true},
		{`[a](b)\1`, true},
		{`\[\1`, true},
		{`\\1`, false},
		{`[\1]`, false},
		{`[\\1]`, false},
		{`\١`, false},
		{"a\\", false},
		{`plain`, false},
	} {
		if got := xpathregex.HasBackrefs(test.source); got != test.want {
			t.Errorf("HasBackrefs(%q) = %v; want %v", test.source, got, test.want)
		}
	}
}

func TestQuantifierGrammarAndEscapedBraces(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ source, yes, no string }{
		{`a{2}`, "aa", "a"},
		{`a{2,}`, "aaa", "a"},
		{`a{2,3}`, "aaa", "aaaa"},
		{`(?:ab){2}`, "abab", "ab"},
		{`[{}]`, "{", "a"},
		{`\{2\}`, "{2}", "22"},
	} {
		t.Run(test.source, func(t *testing.T) {
			t.Parallel()
			compiled := compileXPathPattern(t, "^(?:"+test.source+")$", false, false)
			assertRegexMatch(t, compiled, test.yes, true)
			assertRegexMatch(t, compiled, test.no, false)
		})
	}
	for _, source := range []string{`{1}a`, `a{}`, `a{,2}`, `a{2,a}`, `a{1,2,3}`, `a{2`, `a}`, `a|{2}`, `({2})`, `a{{2}}`} {
		t.Run("invalid/"+source, func(t *testing.T) {
			t.Parallel()
			if err := xpathregex.Validate(source, true); err == nil {
				t.Fatal("invalid quantifier grammar accepted")
			}
		})
	}
}

func TestPerlSpecificSyntaxAndEscapedLookalikes(t *testing.T) {
	t.Parallel()
	for _, source := range []string{`\b`, `\B`, `\A`, `\Z`, `\z`, `\x41`, `\u0041`, `\U00000041`, `(?i)a`, `(?=a)`, `(?!a)`, `(?<=a)b`, `(?<name>a)`, `(?>a)`} {
		if err := xpathregex.RejectPerlSpecific(source); err == nil {
			t.Errorf("Perl syntax accepted: %q", source)
		}
	}
	for _, source := range []string{`(?:a)`, `\\b`, `\(\?`, `\p{Lu}`, `plain`} {
		if err := xpathregex.RejectPerlSpecific(source); err != nil {
			t.Errorf("XPath syntax rejected: %q: %v", source, err)
		}
	}
}

func TestUnicodeBlockResolverBoundsAndUnknownNames(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		first, last rune
	}{
		{"IsBasicLatin", 0, 0x7f},
		{"IsEmoticons", 0x1f600, 0x1f64f},
	} {
		table := xpathregex.ResolveProperty(test.name)
		if table == nil || !unicode.Is(table, test.first) || !unicode.Is(table, test.last) || unicode.Is(table, test.last+1) {
			t.Fatal("Unicode block boundaries lost", test.name)
		}
		if test.first > 0 && unicode.Is(table, test.first-1) {
			t.Fatal("character before block accepted", test.name)
		}
	}
	for _, name := range []string{"Lu", "Greek", "Is", "IsUnknown", "Isbasiclatin"} {
		if xpathregex.ResolveProperty(name) != nil {
			t.Fatal("unknown or non-block property resolved", name)
		}
	}
}

func compileXPathPattern(t *testing.T, source string, dotAll, ignoreCase bool) *pattern.Program {
	t.Helper()
	if err := xpathregex.RejectPerlSpecific(source); err != nil {
		t.Fatal(err)
	}
	if err := xpathregex.Validate(source, true); err != nil {
		t.Fatal(err)
	}
	translated, err := xpathregex.Translate(source, dotAll, ignoreCase)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := pattern.Compile(translated, pattern.Options{IgnoreCase: ignoreCase, Property: xpathregex.ResolveProperty})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func assertRegexMatch(t *testing.T, compiled *pattern.Program, value string, want bool) {
	t.Helper()
	if got, err := compiled.Match(t.Context(), value, pattern.Work{}); err != nil || got != want {
		t.Fatalf("Match(%q) = %v, %v; want %v", value, got, err, want)
	}
}
