package xpathregex_test

import (
	"testing"

	"github.com/skarm/xmlsec/transform/internal/pattern"
	xpathregex "github.com/skarm/xmlsec/transform/internal/xpath/regex"
)

func TestTranslateXPathCharacterClasses(t *testing.T) {
	for _, tc := range []struct {
		pattern, yes, no string
		dotAll           bool
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
