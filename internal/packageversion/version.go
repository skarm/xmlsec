// Package packageversion parses the XSLT package version and range syntax.
// Derived from lestrrat-go/helium.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt.
package packageversion

import (
	"strings"
	"unicode"

	"github.com/skarm/xmlsec/internal/xmlchar"
)

// Version retains arbitrary precision integer portions as decimal strings.
type Version struct {
	Numbers   []string
	Name, Raw string
	valid     bool
}

// Parse reads a package version, preserving arbitrarily large numeric components.
func Parse(s string) Version {
	s = strings.Trim(s, " \t\r\n")
	v := Version{Raw: s}

	numbers := s
	if n, name, ok := strings.Cut(s, "-"); ok {
		if !xmlchar.IsValidNCName(name) {
			return v
		}

		numbers, v.Name = n, name
	}

	for part := range strings.SplitSeq(numbers, ".") {
		if part == "" {
			return v
		}

		for _, c := range part {
			if c < '0' || c > '9' {
				return v
			}
		}

		part = strings.TrimLeft(part, "0")
		if part == "" {
			part = "0"
		}

		v.Numbers = append(v.Numbers, part)
	}

	v.valid = true

	return v
}

// Valid reports whether the package-version lexical form is valid.
func (v Version) Valid() bool { return v.valid }

// Compare orders versions numerically and then by their optional name suffix.
func (v Version) Compare(other Version) int {
	for i := 0; i < max(len(v.Numbers), len(other.Numbers)); i++ {
		a, b := "0", "0"
		if i < len(v.Numbers) {
			a = v.Numbers[i]
		}

		if i < len(other.Numbers) {
			b = other.Numbers[i]
		}

		if len(a) < len(b) {
			return -1
		}

		if len(a) > len(b) {
			return 1
		}

		if c := strings.Compare(a, b); c != 0 {
			return c
		}
	}

	if v.Name == "" && other.Name != "" {
		return 1
	}

	if v.Name != "" && other.Name == "" {
		return -1
	}

	return strings.Compare(v.Name, other.Name)
}

// Constraint is a parsed union of package-version ranges.
type Constraint struct {
	alternatives []versionRange
	valid        bool
}
type versionRange struct {
	lower, upper                 *Version
	prefix, wildcard, prefixOnly bool
}

// Valid reports whether the version-range lexical form is valid.
func (c Constraint) Valid() bool { return c.valid }

// ParseConstraint reads the XSLT version-range syntax; empty selects any version.
func ParseConstraint(s string) Constraint {
	s = strings.Trim(s, " \t\r\n")
	if s == "" || s == "*" {
		return Constraint{valid: true, alternatives: []versionRange{{wildcard: true}}}
	}

	for _, r := range s {
		if unicode.IsSpace(r) && !strings.ContainsRune(" \t\r\n", r) {
			return Constraint{}
		}
	}

	result := Constraint{valid: true}

	for part := range strings.SplitSeq(s, ",") {
		r, ok := parseVersionRange(part)
		if !ok {
			return Constraint{}
		}

		result.alternatives = append(result.alternatives, r)
	}

	return result
}

func parseVersionRange(part string) (versionRange, bool) {
	fields := strings.Fields(part)
	r := versionRange{}

	switch {
	case len(fields) == 2 && fields[0] == "to":
		upper, prefix := parseUpperVersion(fields[1])
		if !upper.valid {
			return versionRange{}, false
		}

		r.upper, r.prefix = &upper, prefix
	case len(fields) == 3 && fields[1] == "to":
		lower := Parse(fields[0])

		upper, prefix := parseUpperVersion(fields[2])
		if !lower.valid || !upper.valid {
			return versionRange{}, false
		}

		r.lower, r.upper, r.prefix = &lower, &upper, prefix
	case len(fields) == 1:
		value := fields[0]
		if before, ok := strings.CutSuffix(value, "+"); ok {
			lower := Parse(before)
			if !lower.valid {
				return versionRange{}, false
			}

			r.lower = &lower
		} else {
			v, prefix := parseUpperVersion(value)
			if !v.valid {
				return versionRange{}, false
			}

			r.upper, r.prefix, r.prefixOnly = &v, prefix, prefix
			if !prefix {
				r.lower = &v
			}
		}
	default:
		return versionRange{}, false
	}

	return r, true
}

func parseUpperVersion(s string) (Version, bool) {
	v, prefix := strings.CutSuffix(s, ".*")
	return Parse(v), prefix
}

// Matches reports whether a valid version satisfies any alternative range.
func (c Constraint) Matches(v Version) bool {
	if !c.valid || !v.valid {
		return false
	}

	for _, r := range c.alternatives {
		if r.wildcard {
			return true
		}

		if r.lower != nil && v.Compare(*r.lower) < 0 {
			continue
		}

		if r.prefixOnly {
			if versionPrefix(v, *r.upper) {
				return true
			}

			continue
		}

		if r.upper == nil || v.Compare(*r.upper) <= 0 || r.prefix && versionPrefix(v, *r.upper) {
			return true
		}
	}

	return false
}

func versionPrefix(v, prefix Version) bool {
	if len(v.Numbers) < len(prefix.Numbers) {
		return false
	}

	for i, n := range prefix.Numbers {
		if v.Numbers[i] != n {
			return false
		}
	}

	return prefix.Name == "" || len(v.Numbers) == len(prefix.Numbers) && v.Name == prefix.Name
}
