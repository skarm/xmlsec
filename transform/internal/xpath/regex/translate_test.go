package xpathregex_test

import (
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/pattern"
	xpathregex "github.com/skarm/xmlsec/transform/internal/xpath/regex"
)

func TestTranslateXPathCharacterClasses(t *testing.T) {
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
