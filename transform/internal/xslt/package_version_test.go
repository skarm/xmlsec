package xslt_test

import (
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xslt"
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
		a, b := xslt.ParsePackageVersion(tc.a), xslt.ParsePackageVersion(tc.b)
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
		if got := xslt.ParseVersionConstraint(tc.constraint).Matches(xslt.ParsePackageVersion(tc.version)); got != tc.want {
			t.Errorf("%q matches %q = %v, want %v", tc.constraint, tc.version, got, tc.want)
		}
	}
}
