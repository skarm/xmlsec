package xslt

import (
	"context"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type (
	packageStackKey struct{}
	packageIdentity struct {
		name    string
		version PackageVersion
	}
)

func enterPackage(ctx context.Context, doc *xdm.Document) (context.Context, error) {
	root := doc.DocumentElement()
	if root == nil || root.URI() != lexicon.NamespaceXSLT || root.LocalName() != namePackage {
		return ctx, nil
	}

	version, present := root.GetAttribute(namePackageVersion)
	if !present {
		version = "1"
	}

	parsed := ParsePackageVersion(version)
	if !parsed.Valid() {
		return nil, staticError(errCodeXTSE0020, "invalid package version %q", version)
	}

	identity := packageIdentity{name: getAttr(root, xslAttrName), version: parsed}

	stack, _ := ctx.Value(packageStackKey{}).([]packageIdentity)
	if len(stack) >= xpath.DepthLimit(ctx, 128) {
		return nil, xpath.ErrBudget
	}

	for _, parent := range stack {
		if parent.name == identity.name && parent.version.Compare(parsed) == 0 {
			return nil, staticError("XTSE3005", "cyclic package dependency %q", identity.name)
		}
	}

	if err := xpath.Charge(ctx, 1); err != nil {
		return nil, err
	}

	copyStack := append(append([]packageIdentity(nil), stack...), identity)

	return context.WithValue(ctx, packageStackKey{}, copyStack), nil
}

func checkResolvedPackage(doc *xdm.Document, name, version string) error {
	root := doc.DocumentElement()
	if root == nil || root.URI() != lexicon.NamespaceXSLT || root.LocalName() != namePackage {
		return staticError(errCodeXTSE3000, "resolved package does not match %q", name)
	}

	if _, shadow := root.GetAttribute("_name"); !shadow && getAttr(root, xslAttrName) != name {
		return staticError(errCodeXTSE3000, "resolved package does not match %q", name)
	}

	if _, shadow := root.GetAttribute("_package-version"); shadow {
		return nil
	}

	actual := getAttr(root, namePackageVersion)
	if actual == "" {
		actual = "1"
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
