// Derived from lestrrat-go/helium.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt.

package xslt

import "github.com/skarm/xmlsec/internal/packageversion"

type PackageVersion = packageversion.Version

type VersionConstraint = packageversion.Constraint

func ParsePackageVersion(s string) PackageVersion { return packageversion.Parse(s) }

func ParseVersionConstraint(s string) VersionConstraint { return packageversion.ParseConstraint(s) }
