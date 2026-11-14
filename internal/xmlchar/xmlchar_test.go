package xmlchar_test

import (
	"fmt"
	"testing"

	"github.com/skarm/xmlsec/internal/xmlchar"
)

func TestCharacterBoundaries(t *testing.T) {
	for _, tc := range []struct {
		r          rune
		xml10      bool
		xml11      bool
		restricted bool
	}{
		{-1, false, false, false},
		{0, false, false, false},
		{1, false, true, true},
		{8, false, true, true},
		{9, true, true, false},
		{10, true, true, false},
		{11, false, true, true},
		{13, true, true, false},
		{31, false, true, true},
		{32, true, true, false},
		{0x7f, true, true, true},
		{0x85, true, true, false},
		{0x9f, true, true, true},
		{0xa0, true, true, false},
		{0xd7ff, true, true, false},
		{0xd800, false, false, false},
		{0xdfff, false, false, false},
		{0xe000, true, true, false},
		{0xfffd, true, true, false},
		{0xfffe, false, false, false},
		{0xffff, false, false, false},
		{0x10000, true, true, false},
		{0x10ffff, true, true, false},
		{0x110000, false, false, false},
	} {
		t.Run(fmt.Sprintf("U+%04X", tc.r), func(t *testing.T) {
			if got := xmlchar.IsChar(tc.r); got != tc.xml10 {
				t.Errorf("XML 1.0 Char = %v, want %v", got, tc.xml10)
			}

			if got := xmlchar.IsXML11Char(tc.r); got != tc.xml11 {
				t.Errorf("XML 1.1 Char = %v, want %v", got, tc.xml11)
			}

			if got := xmlchar.IsXML11RestrictedChar(tc.r); got != tc.restricted {
				t.Errorf("restricted = %v, want %v", got, tc.restricted)
			}

			if got := xmlchar.IsLiteralChar(tc.r, true); got != (tc.xml11 && !tc.restricted) {
				t.Errorf("XML 1.1 literal = %v", got)
			}

			if got := xmlchar.IsLiteralChar(tc.r, false); got != tc.xml10 {
				t.Errorf("XML 1.0 literal = %v", got)
			}
		})
	}
}

func TestXMLNames(t *testing.T) {
	for _, tc := range []struct {
		input  string
		name   bool
		ncname bool
	}{
		{"", false, false},
		{"root", true, true},
		{"_a-1.2", true, true},
		{"имя", true, true},
		{"a\u0301", true, true},
		{"\u0301a", false, false},
		{"a:b", true, false},
		{":a::", true, false},
		{"1a", false, false},
		{"a b", false, false},
		{"a\x00", false, false},
		{"\xff", false, false},
		{"\ufffd", true, true},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := xmlchar.IsValidName(tc.input); got != tc.name {
				t.Errorf("Name = %v, want %v", got, tc.name)
			}

			if got := xmlchar.IsValidNCName(tc.input); got != tc.ncname {
				t.Errorf("NCName = %v, want %v", got, tc.ncname)
			}
		})
	}
}

func TestXMLWhitespace(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  bool
	}{{"", true}, {" \t\r\n", true}, {"\u00a0", false}, {"\u0085", false}, {"x", false}} {
		if xmlchar.IsAllSpace(tc.input) != tc.want || xmlchar.IsAllSpace([]byte(tc.input)) != tc.want {
			t.Errorf("IsAllSpace(%q) != %v", tc.input, tc.want)
		}

		for _, r := range tc.input {
			if xmlchar.IsSpace(r) != tc.want {
				t.Errorf("IsSpace(%U) != %v", r, tc.want)
			}
		}
	}
}

func TestCollapseSpace(t *testing.T) {
	for input, want := range map[string]string{
		"": "", " \t\r\n": "", "id": "id", "  id \t": "id",
		" one\t\r\ntwo  three ":  "one two three",
		" \u00a0id\u0085\u2003 ": "\u00a0id\u0085\u2003",
		"\xff \xfe":              "\xff \xfe",
	} {
		if got := xmlchar.CollapseSpace(input); got != want {
			t.Errorf("CollapseSpace(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestIsValidEncName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, label string
		want        bool
	}{
		{"single_ascii_letter", "Z", true},
		{"mixed_case_and_punctuation", "Iso_8859-1.0", true},
		{"empty", "", false},
		{"starts_with_digit", "8bit", false},
		{"space_inside", "utf 8", false},
		{"non_ascii_letter", "café", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := xmlchar.IsValidEncName(tc.label); got != tc.want {
				t.Errorf("IsValidEncName(%q) = %t, want %t", tc.label, got, tc.want)
			}
		})
	}
}

func TestIsValidPITarget(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, target string
		want         bool
	}{
		{"ordinary", "xml-stylesheet", true},
		{"non_ascii_name", "étiquette", true},
		{"encoded_replacement_character", "\ufffd", true},
		{"reserved_in_any_case", "xMl", false},
		{"empty", "", false},
		{"colon_is_disallowed", "p:target", false},
		{"invalid_encoding", "\xff", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := xmlchar.IsValidPITarget(tc.target); got != tc.want {
				t.Errorf("IsValidPITarget(%q) = %t, want %t", tc.target, got, tc.want)
			}
		})
	}
}

func TestIsValidQName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, qname string
		want        bool
	}{
		{"unprefixed", "item", true},
		{"unicode_prefix_and_local", "préfixe:名", true},
		{"empty", "", false},
		{"missing_prefix", ":item", false},
		{"missing_local", "prefix:", false},
		{"more_than_one_colon", "a:b:c", false},
		{"local_starts_with_digit", "a:1b", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := xmlchar.IsValidQName(tc.qname); got != tc.want {
				t.Errorf("IsValidQName(%q) = %t, want %t", tc.qname, got, tc.want)
			}
		})
	}
}
