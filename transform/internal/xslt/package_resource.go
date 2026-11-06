package xslt

import (
	"context"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// Absent package-version selects lexical package version 1; it is independent of the stylesheet language version.
const (
	defaultPackageVersion = "1"
)

type (
	packageStackKey struct{}
	packageIdentity struct {
		name    string
		version PackageVersion
	}
)

func enterPackage(ctx context.Context, doc *xdm.Document) (context.Context, error) {
	const (
		packageDependencyDepthFallback = 128
	)

	root := doc.DocumentElement()
	if root == nil || root.URI() != lexicon.NamespaceXSLT || root.LocalName() != namePackage {
		return ctx, nil
	}

	version, present := root.GetAttribute(namePackageVersion)
	if !present {
		version = defaultPackageVersion
	}

	parsed := ParsePackageVersion(version)
	if !parsed.Valid() {
		return nil, staticError(errCodeXTSE0020, "invalid package version %q", version)
	}

	identity := packageIdentity{name: getAttr(root, xslAttrName), version: parsed}

	stack, _ := ctx.Value(packageStackKey{}).([]packageIdentity)
	if len(stack) >= xpath.DepthLimit(ctx, packageDependencyDepthFallback) {
		return nil, xpath.ErrBudget
	}

	for _, parent := range stack {
		if parent.name == identity.name && parent.version.Compare(parsed) == 0 {
			return nil, staticError(errCodeXTSE3005, "cyclic package dependency %q", identity.name)
		}
	}

	if err := xpath.Charge(ctx, 1); err != nil {
		return nil, err
	}

	copyStack := append(append([]packageIdentity(nil), stack...), identity)

	return context.WithValue(ctx, packageStackKey{}, copyStack), nil
}

func checkResolvedPackage(doc *xdm.Document, name, version string) error {
	const (
		shadowAttrPackageVersion = "_package-version"
	)

	root := doc.DocumentElement()
	if root == nil || root.URI() != lexicon.NamespaceXSLT || root.LocalName() != namePackage {
		return staticError(errCodeXTSE3000, "resolved package does not match %q", name)
	}

	if _, shadow := root.GetAttribute(shadowAttrName); !shadow && getAttr(root, xslAttrName) != name {
		return staticError(errCodeXTSE3000, "resolved package does not match %q", name)
	}

	if _, shadow := root.GetAttribute(shadowAttrPackageVersion); shadow {
		return nil
	}

	actual := getAttr(root, namePackageVersion)
	if actual == "" {
		actual = defaultPackageVersion
	}

	if !ParseVersionConstraint(version).Matches(ParsePackageVersion(actual)) {
		return staticError(errCodeXTSE3000, "package %q version %q does not match %q", name, actual, version)
	}

	return nil
}

func checkCompiledPackage(ss *Stylesheet, name, version string) error {
	if !ss.isPackage || ss.packageName != name || !ParseVersionConstraint(version).Matches(ParsePackageVersion(ss.packageVersion)) {
		return staticError(errCodeXTSE3000, "resolved package does not match %q version %q", name, version)
	}

	return nil
}
