// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

func lookupFunctionsQname(name string) (*builtinFunc, bool) {
	switch name {
	case nameQName:
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnQName}, true
	case "prefix-from-QName":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnPrefixFromQName}, true
	case "local-name-from-QName":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnLocalNameFromQName}, true
	case "namespace-uri-from-QName":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnNamespaceURIFromQName}, true
	case "namespace-uri-for-prefix":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnNamespaceURIForPrefix}, true
	case "in-scope-prefixes":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnInScopePrefixes}, true
	case "resolve-QName":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnResolveQName}, true
	}

	return nil, false
}

func fnQName(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	uri, err := coerceQNameString(args[0], true, "fn:QName namespace argument must be a string")
	if err != nil {
		return nil, err
	}

	qname, err := coerceQNameString(args[1], false, "fn:QName QName argument must be a string")
	if err != nil {
		return nil, err
	}

	prefix, local, err := parseLexicalQName(qname)
	if err != nil {
		return nil, err
	}
	// Validate: if there's a prefix, namespace must be non-empty
	if prefix != "" && uri == "" {
		return nil, &xdm.Error{Code: errCodeFOCA0002, Message: "namespace must not be empty when QName has a prefix"}
	}

	return xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: xdm.TypeQName,
		Value:    xdm.QNameValue{Prefix: prefix, Local: local, URI: uri},
	}), nil
}

// atomizeQNameArg atomizes a QName-accessor argument and enforces 0-or-1
// cardinality on the ATOMIZED result, so that a single array/list item that
// atomizes to multiple values is rejected as XPTY0004 (not FOTY0013). It
// stops atomization early once a second atom appears. The returned bool is
// true when the atomized sequence is empty (applicable result is the empty
// sequence); otherwise the returned AtomicValue is the single xs:QName.
func atomizeQNameArg(seq xdm.Sequence, fname string) (xdm.AtomicValue, bool, error) {
	var first xdm.AtomicValue

	count := 0

	err := atomizeStream(seq, func(av xdm.AtomicValue) (bool, error) {
		count++
		if count == 1 {
			first = av
			return true, nil
		}

		return false, nil
	})
	if err != nil {
		return xdm.AtomicValue{}, false, err
	}

	if count == 0 {
		return xdm.AtomicValue{}, true, nil
	}

	if count > 1 {
		return xdm.AtomicValue{}, false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fname + " expects a single QName"}
	}

	first = xdm.PromoteSchemaType(first)
	if first.TypeName != xdm.TypeQName {
		return xdm.AtomicValue{}, false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected QName"}
	}

	return first, false, nil
}

func fnPrefixFromQName(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, empty, err := atomizeQNameArg(args[0], "fn:prefix-from-QName")
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	qv := a.QNameVal()
	if qv.Prefix == "" {
		return nil, nil
	}

	return xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeNCName, Value: qv.Prefix}}, nil
}

func fnLocalNameFromQName(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, empty, err := atomizeQNameArg(args[0], "fn:local-name-from-QName")
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	return xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeNCName, Value: a.QNameVal().Local}}, nil
}

func fnNamespaceURIFromQName(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, empty, err := atomizeQNameArg(args[0], "fn:namespace-uri-from-QName")
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: a.QNameVal().URI}), nil
}

func fnNamespaceURIForPrefix(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// The element() second argument is required and must be exactly one
	// element() regardless of the first argument, so validate it FIRST.
	elem, err := requireSingleElement(args[1], "fn:namespace-uri-for-prefix")
	if err != nil {
		return nil, err
	}

	prefix, err := coerceQNameString(args[0], true, "fn:namespace-uri-for-prefix prefix argument must be a string")
	if err != nil {
		return nil, err
	}

	if ns := xdm.LookupNSByPrefix(elem, prefix); ns != nil && ns.URI() != "" {
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: ns.URI()}), nil
	}

	return nil, nil
}

// requireSingleElement validates a required element() argument: it must be
// exactly one node and that node must be a *xdm.Element. This is validated
// before any sibling argument is coerced so an invalid element() arg yields
// XPTY0004, and never an error from atomizing the other argument.
func requireSingleElement(seq xdm.Sequence, fname string) (*xdm.Element, error) {
	if xdm.SequenceLen(seq) != 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fname + ": expects a single element"}
	}

	ni, ok := seq.Get(0).(xdm.NodeItem)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fname + ": expected element node"}
	}

	elem, ok := ni.Node.(*xdm.Element)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fname + ": expected element node"}
	}

	return elem, nil
}

func fnResolveQName(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// The element() second argument is required and must be exactly one
	// element() regardless of whether $qname is empty, so validate it FIRST.
	elem, err := requireSingleElement(args[1], "resolve-QName")
	if err != nil {
		return nil, err
	}

	// Empty $qname yields the empty sequence (after the element() check). The
	// argument is atomized first so that a single empty array/list item (which
	// atomizes to the empty sequence) is treated as empty, while a literal ""
	// remains a non-empty lexical QName reaching parseLexicalQName.
	qnameStr, empty, err := coerceOptionalQNameString(args[0], "resolve-QName: QName argument must be a string")
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	prefix, local, err := parseLexicalQName(qnameStr)
	if err != nil {
		return nil, err
	}

	uri := ""

	if prefix != "" {
		ns := xdm.LookupNSByPrefix(elem, prefix)
		if ns == nil || ns.URI() == "" {
			return nil, &xdm.Error{Code: errCodeFONS0004, Message: "resolve-QName: no namespace binding for prefix " + prefix}
		}

		uri = ns.URI()
	} else {
		// Default namespace
		ns := xdm.LookupNSByPrefix(elem, "")
		if ns != nil {
			uri = ns.URI()
		}
	}

	return xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: xdm.TypeQName,
		Value:    xdm.QNameValue{Prefix: prefix, Local: local, URI: uri},
	}), nil
}

// parseLexicalQName splits a lexical QName WITHOUT trimming surrounding
// whitespace (fn:QName/fn:resolve-QName treat whitespace as significant here),
// so it deliberately does not route through xdm.SplitLexicalQName (which
// trims). It maps split/validate failures to FOCA0002.
func parseLexicalQName(qname string) (string, string, error) {
	prefix := ""

	local := qname
	if p, l, ok := strings.Cut(qname, ":"); ok {
		prefix = p
		local = l

		if prefix == "" {
			return "", "", &xdm.Error{Code: errCodeFOCA0002, Message: "invalid QName: " + qname}
		}
	}

	if prefix != "" && !xmlchar.IsValidNCName(prefix) {
		return "", "", &xdm.Error{Code: errCodeFOCA0002, Message: "invalid prefix in QName: " + prefix}
	}

	if !xmlchar.IsValidNCName(local) {
		return "", "", &xdm.Error{Code: errCodeFOCA0002, Message: "invalid local name in QName: " + local}
	}

	return strings.Clone(prefix), strings.Clone(local), nil
}

// coerceQNameString atomizes a QName string argument with streaming and a
// max-one cap on the ATOMIZED result, then enforces the string/anyURI/
// untypedAtomic rules. Atomizing first, in place of checking item cardinality
// up front, means a single array/list item that atomizes to multiple values is
// rejected as XPTY0004 (a cardinality error), not FOTY0013. Streaming stops
// once a second atom appears.
func coerceQNameString(seq xdm.Sequence, allowEmpty bool, message string) (string, error) {
	s, empty, err := coerceOptionalQNameString(seq, message)
	if err != nil {
		return "", err
	}

	if empty {
		if allowEmpty {
			return "", nil
		}

		return "", &xdm.Error{Code: lexicon.ErrXPTY0004, Message: message}
	}

	return s, nil
}

// coerceOptionalQNameString atomizes a QName string argument the same way as
// coerceQNameString but distinguishes an ATOMIZED-empty result (returning the
// empty bool) from a non-empty lexical value. A single empty array/list item
// that atomizes to the empty sequence yields empty=true (so callers may return
// the empty sequence), while a literal "" reaches the lexical path with
// empty=false. Streaming stops once a second atom appears.
func coerceOptionalQNameString(seq xdm.Sequence, message string) (string, bool, error) {
	var first xdm.AtomicValue

	count := 0

	err := atomizeStream(seq, func(av xdm.AtomicValue) (bool, error) {
		count++
		if count == 1 {
			first = av
			return true, nil
		}

		return false, nil
	})
	if err != nil {
		return "", false, err
	}

	if count == 0 {
		return "", true, nil
	}

	if count > 1 {
		return "", false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: message}
	}

	// Every QName-string parameter is typed xs:string?, so accept any xs:string
	// subtype (e.g. xs:NCName), xs:untypedAtomic, and xs:anyURI (which promotes
	// to xs:string under function conversion).
	first = xdm.PromoteSchemaType(first)
	switch {
	case xdm.IsAtomicSubtypeOf(first, xdm.TypeString):
	case first.TypeName == xdm.TypeUntypedAtomic:
	case first.TypeName == xdm.TypeAnyURI:
	default:
		return "", false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: message}
	}

	s, ok := first.Value.(string)
	if !ok {
		return "", false, fmt.Errorf("xpath: internal error: expected string for %s", first.TypeName)
	}

	return s, false, nil
}

func fnInScopePrefixes(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) != 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:in-scope-prefixes expects a single element"}
	}

	ni, ok := args[0].Get(0).(xdm.NodeItem)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected element node"}
	}

	elem, ok := ni.Node.(*xdm.Element)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected element node"}
	}

	// Walk from the context element outward so namespace undeclarations mask
	// ancestor bindings for the same prefix.
	prefixes := map[string]bool{lexicon.PrefixXML: true}
	resolved := map[string]struct{}{lexicon.PrefixXML: {}}

	for cur := elem; cur != nil; {
		for _, ns := range cur.Namespaces() {
			prefix := ns.Prefix()
			if _, ok := resolved[prefix]; ok {
				continue
			}

			prefixes[prefix] = ns.URI() != ""
			resolved[prefix] = struct{}{}
		}

		p := cur.Parent()
		if p == nil {
			break
		}

		if pe, ok := p.(*xdm.Element); ok {
			cur = pe
		} else {
			break
		}
	}

	// Collect active prefixes into a sorted slice to ensure deterministic
	// output order (the XPath 3.1 spec leaves order implementation-defined).
	sorted := make([]string, 0, len(prefixes))
	for prefix, active := range prefixes {
		if active {
			sorted = append(sorted, prefix)
		}
	}

	sort.Strings(sorted)

	result := make(xdm.ItemSlice, 0, len(sorted))
	for _, prefix := range sorted {
		result = append(result, xdm.AtomicValue{TypeName: xdm.TypeString, Value: prefix})
	}

	return result, nil
}
