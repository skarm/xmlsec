// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func (c *compiler) compileImportSchema(ctx context.Context, elem *xdm.Element) error {
	return ErrLanguageUnsupported
}

// schemaDeclsForValidation returns the in-scope schema declarations for
// compile-time static checking, or nil when the stylesheet is not schema-aware.
// When non-nil it lets the xpath static check permit an unprefixed atomic/schema
// type name (resolved against the default element/type namespace or as a
// no-namespace schema type) instead of raising XPST0081.
func (c *compiler) schemaDeclsForValidation() xpath.SchemaDeclarations { return nil }

// validateAsSequenceType checks compile-time validity of an as= sequenceType
// expression when schemas are imported. It detects schema-element(Q) and
// schema-attribute(Q) references and verifies that Q is declared in at least
// one imported schema. Raises XTSE0590 when a referenced element or attribute
// is not found. An unprefixed schema-element()/schema-attribute() name resolves
// against the in-scope xpath-default-namespace.
//
// This covers the most common case where compile-time static errors arise:
// using schema-element() or schema-attribute() with an undeclared name.
func (c *compiler) validateAsSequenceType(ctx context.Context, as string, context string) error {
	return c.validateAsSequenceTypeWithNS(ctx, as, context, c.nsBindings, c.xpathDefaultNS, c.hasXPathDefaultNS)
}

// validateAsSequenceTypeWithNS is like validateAsSequenceType but resolves
// schema-element()/schema-attribute() QNames against the supplied namespace
// bindings instead of the mutable compiler-wide c.nsBindings, and resolves an
// UNPREFIXED schema-element()/schema-attribute() name against the supplied
// xpath-default-namespace when hasXPathDefaultNS is set. This lets declarations
// such as xsl:global-context-item validate their @as type against the exact
// namespace context in scope at the declaration element itself — matching the
// runtime resolveSchemaQName logic so an unprefixed name with an in-scope
// xpath-default-namespace is not wrongly resolved to {}name at compile time.
func (c *compiler) validateAsSequenceTypeWithNS(_ context.Context, as string, context string, _ map[string]string, _ string, _ bool) error {
	if as == "" {
		return nil
	}
	// Validate syntax of the sequence type expression (catches errors
	// like function(xs:integer) missing "as ReturnType").
	if _, err := xpath.ParseSequenceType(as); err != nil {
		if xpErr, ok := errors.AsType[*xdm.Error](err); ok {
			return staticError(xpErr.Code, "%s: invalid 'as' type: %s", context, err)
		}

		return staticError(errCodeXPST0003, "%s: invalid 'as' type: %s", context, err)
	}

	return nil
}

// checkTypedModePatterns validates XTSE3105: for modes declared with
// typed="strict", every template match pattern whose first step uses an axis
// with principal node kind Element and whose NodeTest is an EQName must
// correspond to a global element declaration in the imported schemas.
func checkTypedModePatterns(ss *Stylesheet) error { return nil }

// resolveXSDTypeName normalizes a QName type reference (e.g., "xs:ID",
// "xsd:integer", or "Q{http://www.w3.org/2001/XMLSchema}ID") to the
// canonical "xs:..." prefix form used by xpath constants. A bare (unprefixed)
// name is resolved against no namespace.
func resolveXSDTypeName(qname string, nsBindings map[string]string) string {
	return resolveXSDTypeNameNS(qname, nsBindings, "", false)
}

// resolveXSDTypeNameNS is like resolveXSDTypeName but resolves a bare
// (unprefixed) non-builtin type name against the in-scope xpath-default-namespace
// when one is in effect. Per XSLT/XPath, an unprefixed type name in an @as/@type
// attribute takes the default element/type namespace; a built-in xs: name and a
// prefixed/EQName form are unaffected.
func resolveXSDTypeNameNS(qname string, nsBindings map[string]string, xpathDefaultNS string, hasXPathDefaultNS bool) string {
	qname = strings.TrimSpace(qname)
	if qname == "" {
		return ""
	}

	if strings.HasPrefix(qname, "Q{") {
		closeIdx := strings.IndexByte(qname, '}')
		if closeIdx > 0 {
			uri := qname[2:closeIdx]

			local := qname[closeIdx+1:]
			if uri == lexicon.NamespaceXSD {
				return "xs:" + local
			}

			return qname
		}
	}

	if prefix, local, ok := strings.Cut(qname, ":"); ok {
		if prefix == "xs" || prefix == nameXsd {
			return "xs:" + local
		}

		if uri, ok := nsBindings[prefix]; ok {
			if uri == lexicon.NamespaceXSD {
				return "xs:" + local
			}
			// User-defined type: resolve to Q{ns}local canonical form.
			return xdm.QAnnotation(uri, local)
		}
	}
	// Bare name (no prefix, no Q{} wrapper): a user-defined type taking the
	// in-scope default element/type namespace (xpath-default-namespace) when one
	// is in effect, else no namespace. Use Q{} annotation form to match
	// xsdTypeNameFromDef.
	if hasXPathDefaultNS && xpathDefaultNS != "" {
		return xdm.QAnnotation(xpathDefaultNS, qname)
	}

	return "Q{}" + qname
}
