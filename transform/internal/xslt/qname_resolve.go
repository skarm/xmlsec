// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// nsResolver resolves a namespace prefix to its bound URI for the declaration
// site. It reports whether the prefix was bound. The xml prefix is handled by
// resolveSequenceTypeQName itself (predeclared), so a resolver need not special
// case it, though an explicit binding it returns takes precedence.
type nsResolver func(prefix string) (string, bool)

// resolveIntrospectionName expands an EQName supplied as a string argument.
// Unlike sequence-type syntax, these strings have no predeclared xs alias and
// strip only leading and trailing XML whitespace (XSLT 3.0 section 5.1.1).
func resolveIntrospectionName(name, defaultNS, code string, resolve nsResolver) (xdm.QNameValue, error) {
	name = strings.TrimFunc(name, xmlchar.IsSpace)
	if isValidEQName(name) {
		end := strings.IndexByte(name, '}')
		return xdm.QNameValue{URI: strings.Join(strings.FieldsFunc(name[2:end], xmlchar.IsSpace), " "), Local: name[end+1:]}, nil
	}

	if !xmlchar.IsValidQName(name) {
		return xdm.QNameValue{}, dynamicError(code, "%q is not a valid EQName", name)
	}

	if prefix, local, ok := strings.Cut(name, ":"); ok {
		uri, bound := resolvePrefixWithXML(prefix, resolve)
		if !bound || uri == "" {
			return xdm.QNameValue{}, dynamicError(code, "undeclared namespace prefix %q in %q", prefix, name)
		}

		return xdm.QNameValue{URI: uri, Local: local, Prefix: prefix}, nil
	}

	return xdm.QNameValue{URI: defaultNS, Local: name}, nil
}

func nsResolverFromMap(m map[string]string) nsResolver {
	return func(prefix string) (string, bool) {
		uri, ok := m[prefix]
		return uri, ok
	}
}

// qnameKind identifies the syntactic position of a QName inside a sequence-type
// item test. The expansion rules for an unprefixed name differ by position:
//
//   - qnameElementName  — the name argument of element() / schema-element() and
//     of document-node(element(...)). An unprefixed name takes the default
//     element namespace (xpath-default-namespace).
//   - qnameAttributeName — the name argument of attribute() / schema-attribute().
//     An unprefixed name is in NO namespace; the default element namespace NEVER
//     applies to an attribute name.
//   - qnameTypeName — the type argument (2nd arg) of element(name, type) and
//     attribute(name, type). An unprefixed built-in type resolves to the XSD
//     namespace, any other unprefixed name is in no namespace, and xs:/xsd:
//     prefixes are aliases for the XSD namespace. The default element namespace
//     never applies.
//
// In every position the xml prefix is predeclared to the XML namespace; an
// explicit declaration-site binding for any prefix overrides predeclaration.
type qnameKind int

const (
	qnameElementName qnameKind = iota
	qnameAttributeName
	qnameTypeName
)

// resolveSequenceTypeQName resolves a QName appearing in a sequence-type item
// test to its (localName, namespaceURI) pair, applying the position-specific
// rules described on qnameKind. This is the single canonical resolution path
// used by both @as validation and the XTSE3087 canonical-expansion so that an
// element name, attribute name, or type name is interpreted identically
// everywhere.
//
// qname may be a prefixed QName (prefix:local), an unprefixed NCName, or an
// EQName in Q{uri}local form. A wildcard ("*") or empty string is returned
// unchanged with an empty namespace.
func resolveSequenceTypeQName(qname string, kind qnameKind, resolve nsResolver, defaultElemNS string, hasDefaultElemNS bool) (local, ns string) {
	qname = strings.TrimSpace(qname)
	if qname == "" || qname == "*" {
		return qname, ""
	}

	// EQName form: Q{uri}local — already fully expanded.
	if strings.HasPrefix(qname, "Q{") {
		if closeIdx := strings.IndexByte(qname, '}'); closeIdx > 0 {
			return qname[closeIdx+1:], qname[2:closeIdx]
		}

		return "", ""
	}

	prefix, loc, prefixed := strings.Cut(qname, ":")
	if prefixed {
		// xs:/xsd: are conventional aliases for the XSD namespace when naming a
		// type; for element/attribute names they are ordinary prefixes resolved
		// through the binding map (so xsd: works only if declared).
		if kind == qnameTypeName && (prefix == "xs" || prefix == nameXsd) {
			return loc, lexicon.NamespaceXSD
		}
		// The xml prefix is predeclared everywhere; an explicit binding overrides.
		if uri, ok := resolvePrefixWithXML(prefix, resolve); ok {
			return loc, uri
		}

		return loc, ""
	}

	// Unprefixed name.
	switch kind {
	case qnameElementName:
		if hasDefaultElemNS {
			return qname, defaultElemNS
		}

		return qname, ""
	case qnameTypeName:
		// An unprefixed built-in type is in the XSD namespace; everything else
		// is in no namespace. The default element namespace is never applied.
		if isBuiltinXSDLocalName(qname) {
			return qname, lexicon.NamespaceXSD
		}

		return qname, ""
	default: // qnameAttributeName
		// An unprefixed attribute name is in no namespace.
		return qname, ""
	}
}

// resolvePrefixWithXML resolves a prefix through the given resolver, treating
// the xml prefix as predeclared to the XML namespace when the resolver has no
// explicit binding for it.
func resolvePrefixWithXML(prefix string, resolve nsResolver) (string, bool) {
	if resolve != nil {
		if uri, ok := resolve(prefix); ok {
			return uri, true
		}
	}

	if prefix == lexicon.PrefixXML {
		return lexicon.NamespaceXML, true
	}

	return "", false
}
