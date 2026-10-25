package packageversion_test

import (
	"testing"

	"github.com/skarm/xmlsec/internal/packageversion"
)

func TestVersionParsingAndOrder(t *testing.T) {
	for _, tc := range []struct {
		left, right string
		want        int
	}{
		{"001.02", "1.2.0", 0},
		{"999999999999999999999999999999", "1000000000000000000000000000000", -1},
		{"1.2", "1.10", -1},
		{"1.2", "1.2-alpha", 1},
		{"1.2-alpha", "1.2-beta", -1},
		{"1.2-alpha", "1.2", -1},
	} {
		left, right := packageversion.Parse(tc.left), packageversion.Parse(tc.right)
		if !left.Valid() || !right.Valid() || left.Compare(right) != tc.want || right.Compare(left) != -tc.want {
			t.Errorf("%q versus %q: %d, want %d", tc.left, tc.right, left.Compare(right), tc.want)
		}
	}

	version := packageversion.Parse(" \t001.00-release\r\n")
	if !version.Valid() || version.Raw != "001.00-release" || version.Name != "release" || len(version.Numbers) != 2 || version.Numbers[0] != "1" || version.Numbers[1] != "0" {
		t.Fatalf("normalized version: %+v", version)
	}

	for _, value := range []string{"", "1..2", ".1", "1.", "1.2-", "1.2-1bad", "-1", "1. 2", "1.é"} {
		if packageversion.Parse(value).Valid() {
			t.Errorf("invalid version accepted: %q", value)
		}
	}
}

func TestConstraints(t *testing.T) {
	for _, tc := range []struct {
		constraint string
		version    string
		want       bool
	}{
		{"", "999999999999999999999.1", true},
		{"*", "1.0-beta", true},
		{"1.2", "1.2.0", true},
		{"1.2", "1.2.1", false},
		{"1.2.*", "1.2.999", true},
		{"1.2.*", "1.3", false},
		{"1.2.*", "1", false},
		{"1.2+", "1.2-alpha", false},
		{"1.2+", "2", true},
		{"to 2.1", "2.1.0", true},
		{"to 2.1", "2.1.1", false},
		{"1 to 2.*", "2.999", true},
		{"1 to 2.*", "3", false},
		{"1 to 2, 4+", "3", false},
		{"1 to 2, 4+", "4.1", true},
		{"1.2-alpha.*", "1.2-alpha", true},
		{"1.2-alpha.*", "1.2.1-alpha", false},
	} {
		constraint := packageversion.ParseConstraint(tc.constraint)
		if !constraint.Valid() || constraint.Matches(packageversion.Parse(tc.version)) != tc.want {
			t.Errorf("constraint %q, version %q: want %v", tc.constraint, tc.version, tc.want)
		}
	}

	for _, value := range []string{"1\u00a0to\u00a02", "1 to", "to", "1,,2", "bad", "1+extra", "1 to 2 to 3", "*.*"} {
		if packageversion.ParseConstraint(value).Valid() {
			t.Errorf("invalid constraint accepted: %q", value)
		}
	}

	if (packageversion.Constraint{}).Matches(packageversion.Parse("1")) || packageversion.ParseConstraint("*").Matches(packageversion.Version{}) {
		t.Fatal("zero-value version/constraint accepted")
	}
}
