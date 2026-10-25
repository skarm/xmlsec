// Derived from lestrrat-go/helium.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt.

package xslt

import "github.com/skarm/xmlsec/internal/packageversion"

// PackageVersion aliases the shared parsed XSLT package-version representation.
type PackageVersion = packageversion.Version

// VersionConstraint aliases the shared union of package-version ranges.
type VersionConstraint = packageversion.Constraint

// ParsePackageVersion parses an XSLT package version while retaining
// arbitrary-precision numeric components.
func ParsePackageVersion(s string) PackageVersion { return packageversion.Parse(s) }

// ParseVersionConstraint parses the version range syntax accepted for package
// selection.
func ParseVersionConstraint(s string) VersionConstraint { return packageversion.ParseConstraint(s) }
