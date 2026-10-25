package xslt //nolint:testpackage // Exercises private XSLT element metadata ownership.

import (
	"strings"
	"testing"
)

const version10 = "1.0"

func TestPackageVersionComparison(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"001.2", "1.2.0", 0},
		{"1.9", "1.10", -1},
		{"1.0-rc", version10, -1},
		{"1.0-alpha", "1.0-beta", -1},
		{strings.Repeat("9", 100), "100000000000000000000", 1},
	} {
		a, b := ParsePackageVersion(tc.a), ParsePackageVersion(tc.b)
		if got := a.Compare(b); got != tc.want || b.Compare(a) != -tc.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestVersionConstraintMatches(t *testing.T) {
	for _, tc := range []struct {
		constraint, version string
		want                bool
	}{
		{"*", version10, true},
		{version10, "1.0.0", true},
		{version10, "1.1", false},
		{"1.2.*", "1.2.9", true},
		{"1.2.*", "1.3", false},
		{"1.2+", "1.2", true},
		{"1.2+", "1.1", false},
		{"1.0 to 2.0", "2.0", true},
		{"1.0 to 2.0", "2.1", false},
		{"to 2.0", "1.9", true},
		{"1.0, 3.0+", "3.1", true},
		{"1..0", version10, false},
		{"1.0\u00a0to 2.0", "1.5", false},
		{"*", "1..0", false},
		{"*", "1.0-1bad", false},
	} {
		if got := ParseVersionConstraint(tc.constraint).Matches(ParsePackageVersion(tc.version)); got != tc.want {
			t.Errorf("%q matches %q = %v, want %v", tc.constraint, tc.version, got, tc.want)
		}
	}
}

func TestElementContexts(t *testing.T) {
	for _, tc := range []struct {
		name, version         string
		topLevel, instruction bool
	}{
		{"template", "1.0", true, false},
		{"value-of", "1.0", false, true},
		{"iterate", "3.0", false, true},
		{"not-an-xslt-element", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if minXSLTElementVersion(tc.name) != tc.version || isTopLevelXSLTElement(tc.name) != tc.topLevel || isXSLTInstruction(tc.name) != tc.instruction {
				t.Fatal("incorrect version or permitted context")
			}
		})
	}
}
