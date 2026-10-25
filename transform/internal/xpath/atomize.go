// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"fmt"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// --- NodeItem ---

// --- AtomicValue ---

// key: [2]string{actual,target} → bool

// --- Supporting Types ---

// --- FunctionItem ---

// --- MapItem ---

// --- ArrayItem ---

// --- Atomization ---

// AtomizeItem converts a single item to an atomic value per XPath 3.1 Section 2.6.2.
func AtomizeItem(item xdm.Item) (xdm.AtomicValue, error) {
	switch v := item.(type) {
	case xdm.AtomicValue:
		return v, nil
	case xdm.NodeItem:
		return atomizeItemNodeItem(&v)
	case xdm.ArrayItem:
		// XPath 3.1: atomizing an array atomizes each member and concatenates
		if v.Size() == 0 {
			return xdm.AtomicValue{}, &xdm.Error{
				Code:    lexicon.ErrFOTY0013,
				Message: "cannot atomize empty array to single atomic value",
			}
		}

		if v.Size() == 1 {
			member, _ := v.Get(1)
			if xdm.SequenceLen(member) == 1 {
				return AtomizeItem(member.Get(0))
			}
		}

		return xdm.AtomicValue{}, &xdm.Error{
			Code:    lexicon.ErrFOTY0013,
			Message: "cannot atomize array with multiple members to single atomic value",
		}
	default:
		return xdm.AtomicValue{}, &xdm.Error{
			Code:    lexicon.ErrFOTY0013,
			Message: fmt.Sprintf("cannot atomize %T", item),
		}
	}
}

// resolveQNameFromNode resolves a QName string (e.g., "my:brown-bear") using
// the in-scope namespaces of the given node.
func resolveQNameFromNode(s string, node xdm.Node, noDefaultNS bool) (xdm.QNameValue, error) {
	// The split kernel trims and splits at the first colon; this site does not
	// NCName-validate, so the validNC result is ignored.
	prefix, local, _, _ := xdm.SplitLexicalQName(s)

	var uri string

	scope := node
	if _, ok := scope.(*xdm.Element); !ok {
		scope = node.Parent()
	}

	if prefix == "xml" {
		// The "xml" prefix is predeclared (XML Namespaces) and need not be bound on
		// any node — matches xsd.resolveLexicalQName, so e.g. xml:lang atomizes as a
		// valid xs:QName in an assertion instead of failing with an undeclared prefix.
		uri = lexicon.NamespaceXML
	} else if prefix != "" {
		// prefix is non-empty here so an empty-URI binding cannot occur and the
		// first-match-wins helper matches the original skip-empty walk exactly.
		var found bool

		uri, found = xdm.LookupNSPrefixURI(scope, prefix)
		if !found {
			return xdm.QNameValue{}, fmt.Errorf("undeclared namespace prefix: %s", prefix)
		}
	} else if !noDefaultNS {
		// Default-namespace resolution keeps the skip-empty walk inline: an
		// ancestor xmlns="" must not stop the search for an outer default.
		for p := scope; p != nil; p = p.Parent() {
			pe, ok := p.(*xdm.Element)
			if !ok {
				continue
			}

			for _, ns := range pe.Namespaces() {
				if ns.Prefix() == "" {
					uri = ns.URI()
					break
				}
			}

			if uri != "" {
				break
			}
		}
	}

	return xdm.QNameValue{Prefix: prefix, Local: local, URI: uri}, nil
}

func atomizeItemNodeItem(v *xdm.NodeItem) (xdm.AtomicValue, error) {
	s := xdm.StringValue(v.Node)
	if returned0Value, matchedBranchBranch := atomizeItemNodeItemTypeAnnotation(v, s); matchedBranchBranch {
		return returned0Value, nil
	}

	if v.AtomizedType != "" && v.AtomizedType != xdm.TypeUntypedAtomic && v.AtomizedType != v.TypeAnnotation {
		cast, err := CastFromString(s, v.AtomizedType)
		if err == nil {
			// Preserve the user-defined type annotation so that
			// "instance of" checks match the original schema type.
			if v.TypeAnnotation != "" && !xdm.IsKnownXSDType(v.TypeAnnotation) {
				cast.BaseType = cast.TypeName
				cast.TypeName = v.TypeAnnotation
			}

			return cast, nil
		}
	}
	// Union types: try each member type until one succeeds.
	if len(v.UnionMemberTypes) > 0 {
		for _, memberType := range v.UnionMemberTypes {
			cast, err := CastFromString(s, memberType)
			if err == nil {
				cast.BaseType = cast.TypeName
				cast.TypeName = v.TypeAnnotation

				return cast, nil
			}
		}
	}
	// XPath 3.1 Section 2.6.2: typed value of PI, comment, and namespace nodes is xs:string
	if v.Node != nil {
		switch v.Node.Type() {
		case xdm.ProcessingInstructionNode, xdm.CommentNode, xdm.NamespaceNode:
			return xdm.AtomicValue{
				TypeName: xdm.TypeString,
				Value:    s,
			}, nil
		}
	}

	return xdm.AtomicValue{
		TypeName: xdm.TypeUntypedAtomic,
		Value:    s,
	}, nil
}

func atomizeItemNodeItemTypeAnnotation(v *xdm.NodeItem, s string) (returned0Value xdm.AtomicValue, matchedBranchBranch bool) {
	if v.TypeAnnotation != "" && v.TypeAnnotation != xdm.TypeUntypedAtomic {
		// QName-like types need namespace resolution from the node's scope.
		if v.TypeAnnotation == xdm.TypeQName || v.TypeAnnotation == xdm.TypeNOTATION ||
			v.AtomizedType == xdm.TypeQName || v.AtomizedType == xdm.TypeNOTATION {
			if qv, err := resolveQNameFromNode(s, v.Node, v.QNameNoDefaultNS); err == nil {
				typeName := v.TypeAnnotation
				if typeName == "" {
					typeName = v.AtomizedType
				}

				if typeName == "" {
					typeName = xdm.TypeQName
				}

				return xdm.AtomicValue{TypeName: typeName, Value: qv}, true
			}
		}

		cast, err := CastFromString(s, v.TypeAnnotation)
		if err == nil {
			return cast, true
		}
	}

	return
}

func atomizedTypeForAnnotation(annotation string, decls SchemaDeclarations) string {
	switch annotation {
	case "", xdm.TypeUntypedAtomic, xdm.TypeUntyped:
		return ""
	}

	if xdm.IsKnownXSDType(annotation) {
		return annotation
	}

	if decls == nil {
		return ""
	}

	// Check if this is a union type — if so, return the annotation itself
	// so that AtomizeItem can try member types via the SchemaDeclarations.
	members := decls.UnionMemberTypes(annotation)
	if len(members) > 0 {
		// For union types, find the first member type that resolves to a
		// concrete built-in type — this will be used for atomization.
		for _, m := range members {
			mType := atomizedTypeForAnnotation(m, decls)
			if mType != "" && mType != xdm.TypeAnySimpleType && mType != xdm.TypeAnyAtomicType {
				return mType
			}
		}

		return ""
	}

	current := annotation
	for range 32 {
		local, ns, ok := xdm.SchemaAnnotationParts(current)
		if !ok {
			return ""
		}

		baseType, ok := decls.LookupSchemaType(local, ns)
		if !ok || baseType == "" || baseType == current {
			return ""
		}

		switch baseType {
		case xdm.TypeUntypedAtomic, xdm.TypeUntyped:
			return ""
		}
		// xs:anySimpleType is not a useful atomized type — it means we
		// reached the top of the simple type hierarchy without finding a
		// concrete type (e.g. for union types). Return empty.
		if baseType == xdm.TypeAnySimpleType || baseType == xdm.TypeAnyAtomicType {
			return ""
		}

		if xdm.IsKnownXSDType(baseType) {
			return baseType
		}

		current = baseType
	}

	return ""
}
