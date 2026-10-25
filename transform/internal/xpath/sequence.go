// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// EBV computes the Effective Boolean Value of a sequence per XPath 3.1 Section 2.4.3.
func EBV(seq xdm.Sequence) (bool, error) {
	n := xdm.SequenceLen(seq)
	if n == 0 {
		return false, nil
	}

	first := seq.Get(0)
	// Sequence starting with a node → true
	if _, ok := first.(xdm.NodeItem); ok {
		return true, nil
	}

	if n == 1 {
		return ebvSingle(first)
	}

	return false, &xdm.Error{
		Code:    errCodeFORG0006,
		Message: "effective boolean value not defined for sequence of length > 1 starting with non-node",
	}
}

func ebvSingle(item xdm.Item) (bool, error) {
	switch v := item.(type) {
	case xdm.AtomicValue:
		return ebvAtomic(v)
	case xdm.NodeItem:
		return true, nil
	default:
		return false, &xdm.Error{
			Code:    errCodeFORG0006,
			Message: fmt.Sprintf("effective boolean value not defined for %T", item),
		}
	}
}

func ebvAtomic(v xdm.AtomicValue) (bool, error) {
	// Per XPath 3.1 §2.4.3, EBV is defined for: boolean, string, anyURI,
	// untypedAtomic, string-derived types, and numeric types only.
	switch v.TypeName {
	case xdm.TypeBoolean:
		return v.Value.(bool), nil //nolint:forcetypeassert
	case xdm.TypeString, xdm.TypeAnyURI, xdm.TypeUntypedAtomic:
		s, _ := v.Value.(string)
		return s != "", nil
	}

	if xdm.IsStringDerived(v.TypeName) {
		s, _ := v.Value.(string)
		return s != "", nil
	}

	if v.IsNumeric() {
		switch val := v.Value.(type) {
		case int64:
			return val != 0, nil
		case *big.Int:
			return val.Sign() != 0, nil
		case *big.Rat:
			return val.Sign() != 0, nil
		case *xdm.FloatValue, float64, float32:
			// Compute the magnitude from the effective-typed value so a
			// schema-derived xs:float (BaseType TypeFloat) is narrowed to single
			// precision before the zero/NaN test: e.g. my:float backed by 1e-50
			// underflows to 0.0 as xs:float and must yield EBV false. ToFloat64
			// honors BaseType-driven narrowing; the xs:double path is unaffected.
			f := v.ToFloat64()
			return f != 0 && !math.IsNaN(f), nil
		}
	}

	return false, &xdm.Error{
		Code:    errCodeFORG0006,
		Message: fmt.Sprintf("effective boolean value not defined for %s", v.TypeName),
	}
}

// AtomizeSequence atomizes all items in a sequence per XPath 3.1 Section 2.6.2.
func AtomizeSequence(seq xdm.Sequence) ([]xdm.AtomicValue, error) {
	if seq == nil {
		return nil, nil
	}

	result := make([]xdm.AtomicValue, 0, seq.Len())

	err := atomizeStream(seq, func(av xdm.AtomicValue) (bool, error) {
		result = append(result, av)
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FnAtomize applies typed atomization at an adapter function boundary, charging
// array edges, empty members and emitted atoms to the current invocation.
func FnAtomize(ctx context.Context, seq xdm.Sequence) ([]xdm.AtomicValue, error) {
	ec := getFnContext(ctx)

	var atoms []xdm.AtomicValue

	err := atomizeBounded(ctx, ec, seq, func(atom xdm.AtomicValue) (bool, error) {
		if len(atoms) >= fnMaxNodes(ec) {
			return false, ErrBudget
		}

		atoms = append(atoms, atom)

		return true, nil
	})

	return atoms, err
}

// atomizeBounded charges array traversal even when every leaf atomizes to ().
// The callback can stop before a later item, preserving cardinality error order.
func atomizeBounded(ctx context.Context, ec *evalContext, seq xdm.Sequence, yield func(xdm.AtomicValue) (bool, error)) error {
	check := typedValueItemCheckFor(ec)

	stack := []seqCursor{{members: []xdm.Sequence{seq}}}
	for len(stack) != 0 {
		item, ok, empty := stack[len(stack)-1].next()
		if err := fnCountOps(ctx, ec, empty+1); err != nil {
			return err
		}

		if !ok {
			stack = stack[:len(stack)-1]
			continue
		}

		if array, isArray := item.(xdm.ArrayItem); isArray {
			if len(stack) >= DepthLimit(ctx, 128) {
				return ErrBudget
			}

			stack = append(stack, seqCursor{members: array.MembersView()})

			continue
		}

		cont, err := atomizeStreamCont(xdm.ItemSlice{item}, check, func(atom xdm.AtomicValue) (bool, error) {
			if err := fnCountOp(ctx, ec); err != nil {
				return false, err
			}

			return yield(atom)
		})
		if err != nil || !cont {
			return err
		}
	}

	return nil
}

// atomizeStreamCont is the recursive worker behind atomizeStream. It returns
// (cont, err): cont is false once yield has requested a stop, so that recursive
// array-member atomization halts IMMEDIATELY and no further members (or items)
// are atomized. Propagating the stop is what lets a caller's bounded-work cap
// (e.g. a singleton-cardinality check) surface its own rejection, and never a
// later member's atomization error (e.g. FOTY0013 from a map).
//
// contentKindCheck, when non-nil (the fn:data / typed-value path only), is
// consulted for each non-array item in encounter order BEFORE that item is
// atomized, walking with the SAME order and array recursion as atomization. It
// returns an ACTION per XDM 3.1 §5.15: a NILLED element has no typed value and
// is SKIPPED (typed value ()); an element whose type annotation resolves to
// element-only complex content has no typed value and raises err:FOTY0012; one
// with empty complex content has typed value () and is SKIPPED (contributes no
// atoms); everything else atomizes normally. Because the check is interleaved
// with atomization, and never pre-scanned, the FIRST offending item wins — a
// map/function encountered earlier still raises FOTY0013 (from AtomizeItem)
// before a later element-only element is reached — and element-only / empty /
// nilled nodes nested inside arrays are handled too.
func atomizeStreamCont(seq xdm.Sequence, contentKindCheck atomizeItemCheck, yield func(xdm.AtomicValue) (bool, error)) (bool, error) {
	if seq == nil {
		return true, nil
	}

	// Keep indexed iteration and snapshot Len once at each recursion boundary.
	for i, size := 0, seq.Len(); i < size; i++ {
		cont, err := atomizeStreamItem(seq.Get(i), contentKindCheck, yield)
		if err != nil || !cont {
			return false, err
		}
	}

	return true, nil
}

func atomizeStreamItem(item xdm.Item, contentKindCheck atomizeItemCheck, yield func(xdm.AtomicValue) (bool, error)) (bool, error) {
	// Arrays flatten before content-kind checks, recursively in member order.
	if array, ok := item.(xdm.ArrayItem); ok {
		return atomizeArrayMembers(array, contentKindCheck, yield)
	}

	if contentKindCheck != nil {
		skip, err := contentKindCheck(item)
		if err != nil {
			return false, err
		}

		if skip {
			return true, nil
		}
	}

	if node, ok := item.(xdm.NodeItem); ok {
		if listItem := nodeListItemType(node); listItem != "" {
			return atomizeStreamList(node, listItem, yield)
		}

		if node.ActiveUnionMember != nil {
			if atoms, handled := atomizeUnionItems(node); handled {
				return yieldAtomizedValues(atoms, yield)
			}
		}
	}

	atom, err := AtomizeItem(item)
	if err != nil {
		return false, err
	}

	return yieldAtomizedValue(atom, yield)
}

func atomizeArrayMembers(array xdm.ArrayItem, contentKindCheck atomizeItemCheck, yield func(xdm.AtomicValue) (bool, error)) (bool, error) {
	for _, member := range array.MembersView() {
		cont, err := atomizeStreamCont(member, contentKindCheck, yield)
		if err != nil || !cont {
			return false, err
		}
	}

	return true, nil
}

func nodeListItemType(node xdm.NodeItem) string {
	if node.ListItemType != "" {
		return node.ListItemType
	}

	return builtinListItemType(node.TypeAnnotation)
}

func atomizeStreamList(node xdm.NodeItem, listItem string, yield func(xdm.AtomicValue) (bool, error)) (bool, error) {
	for i, token := range xsdListFields(xdm.StringValue(node.Node)) {
		atom, err := atomizeListTokenAt(i, token, listItem, node)
		if err != nil {
			return false, err
		}

		cont, err := yieldAtomizedValue(atom, yield)
		if err != nil || !cont {
			return false, err
		}
	}

	return true, nil
}

func yieldAtomizedValues(atoms []xdm.AtomicValue, yield func(xdm.AtomicValue) (bool, error)) (bool, error) {
	for _, atom := range atoms {
		cont, err := yieldAtomizedValue(atom, yield)
		if err != nil || !cont {
			return false, err
		}
	}

	return true, nil
}

func yieldAtomizedValue(atom xdm.AtomicValue, yield func(xdm.AtomicValue) (bool, error)) (bool, error) {
	cont, err := yield(atom)
	if err != nil {
		return false, err
	}

	return cont, nil
}

// atomizeListToken converts one XSD-whitespace-separated list token to an atomic
// value of the list's item type. A QName/NOTATION item type is resolved against
// the node's in-scope namespaces (CastFromString cannot resolve a prefix), so a
// list whose item type is xs:QName/xs:NOTATION — or a user type derived from
// either (whose built-in base is carried in ni.ListItemAtomized) — atomizes
// correctly in a schema-aware context, preserving the user/list-item type name.
// A non-QName USER-defined item type (a Q{...} name CastFromString cannot resolve)
// is cast through its built-in base (ni.ListItemAtomized) and typed as the user
// type with that built-in BaseType, so e.g. a list item type derived from xs:int
// atomizes to a numeric value usable by sum()/numeric comparison (matching $value).
func atomizeListToken(tok, listItem string, ni xdm.NodeItem) (xdm.AtomicValue, error) {
	if listItem == xdm.TypeQName || listItem == xdm.TypeNOTATION ||
		ni.ListItemAtomized == xdm.TypeQName || ni.ListItemAtomized == xdm.TypeNOTATION {
		qv, err := resolveQNameFromNode(tok, ni.Node, ni.QNameNoDefaultNS)
		if err != nil {
			return xdm.AtomicValue{}, &xdm.Error{
				Code:    errCodeFORG0001,
				Message: fmt.Sprintf("invalid QName list item %q: %v", tok, err),
			}
		}

		av := xdm.AtomicValue{TypeName: listItem, Value: qv}
		if !xdm.IsKnownXSDType(listItem) {
			base := ni.ListItemAtomized
			if base == "" {
				base = xdm.TypeQName
			}

			av.BaseType = base
		}

		return av, nil
	}

	cast, err := CastFromString(tok, listItem)
	if err == nil {
		return cast, nil
	}
	// User-defined item type (Q{ns}local): CastFromString does not know it, so cast
	// through its built-in base and carry the user type name with that base.
	if ni.ListItemAtomized != "" && ni.ListItemAtomized != listItem {
		base, berr := CastFromString(tok, ni.ListItemAtomized)
		if berr == nil {
			base.BaseType = base.TypeName
			base.TypeName = listItem

			return base, nil
		}
	}
	// Last resort: the value was already validated at construction; store it
	// verbatim under the user type name so atomization does not fail.
	if strings.HasPrefix(listItem, "Q{") {
		return xdm.AtomicValue{TypeName: listItem, Value: tok}, nil
	}

	return xdm.AtomicValue{}, err
}

// atomizeListTokenAt atomizes the i-th list token. When the list ITEM type is a
// UNION (ni.ListItemLeaves populated), it atomizes through that token's precomputed
// ACTIVE union member (resolved value-dependently in nodeItemFor), so a list of a
// union agrees with $value per token; otherwise it falls back to the static
// atomizeListToken on the declared item type.
func atomizeListTokenAt(i int, tok, listItem string, ni xdm.NodeItem) (xdm.AtomicValue, error) {
	if i < len(ni.ListItemLeaves) {
		if leaf := ni.ListItemLeaves[i]; leaf != nil {
			lni := xdm.NodeItem{Node: ni.Node, ListItemAtomized: leaf.Atomized, QNameNoDefaultNS: ni.QNameNoDefaultNS}
			return atomizeListToken(tok, leaf.TypeName, lni)
		}
	}

	return atomizeListToken(tok, listItem, ni)
}

// xsdListFields splits an xs:list value into items on runs of XSD whitespace ONLY
// (space, tab, CR, LF), matching XSD list tokenization and the validation / $value
// paths (internal/xsd/value.XSDFields). Unlike strings.Fields it does NOT split on
// NBSP or other Unicode whitespace, so a list item containing NBSP stays a single
// token (and is then rejected by per-item lexical validation), and is never
// silently split into two atoms.
func xsdListFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
}

// atomizeUnionItems atomizes a union-typed node through its precomputed ACTIVE
// member (ni.ActiveUnionMember, resolved by full schema-aware validation in
// nodeItemFor): a LIST active member yields its per-item atoms, an ATOMIC active
// member yields a single atom TYPED AS THE ACTIVE MEMBER (so data(@u) instance of
// the member type holds). handled is false only when no member resolved (the caller
// falls back to AtomizeItem). A QName/NOTATION value is resolved against the node's
// in-scope namespaces.
func atomizeUnionItems(ni xdm.NodeItem) ([]xdm.AtomicValue, bool) {
	if ni.ActiveUnionMember == nil {
		return nil, false
	}

	m := *ni.ActiveUnionMember

	s := xdm.StringValue(ni.Node)
	if m.ListItem != "" {
		tokens := xsdListFields(s)
		// When the active member's list item type is a UNION, m.ListItemLeaves carries
		// the per-token active leaves (resolved value-dependently in nodeItemFor), so each
		// token atomizes through its own active member — agreeing with $value — instead of
		// the single static m.ListItemAtom base; atomizeListTokenAt falls back to the
		// static path for a nil/absent leaf.
		lni := xdm.NodeItem{Node: ni.Node, ListItemAtomized: m.ListItemAtom, ListItemLeaves: m.ListItemLeaves, QNameNoDefaultNS: ni.QNameNoDefaultNS}

		atoms := make([]xdm.AtomicValue, 0, len(tokens))
		for i, tok := range tokens {
			av, err := atomizeListTokenAt(i, tok, m.ListItem, lni)
			if err != nil {
				return nil, false
			}

			atoms = append(atoms, av)
		}

		return atoms, true
	}

	av, err := atomizeUnionAtomicMember(s, m, ni)
	if err != nil {
		return nil, false
	}

	return []xdm.AtomicValue{av}, true
}

// atomizeUnionAtomicMember atomizes a union value through an ATOMIC active member,
// typing the result as that member (preserving a user type's annotation over its
// built-in base) so instance-of against the member type holds. A QName/NOTATION
// member resolves the value against the node's in-scope namespaces.
func atomizeUnionAtomicMember(s string, m xdm.NodeItemUnionMember, ni xdm.NodeItem) (xdm.AtomicValue, error) {
	if m.Atomized == xdm.TypeQName || m.Atomized == xdm.TypeNOTATION ||
		m.TypeName == xdm.TypeQName || m.TypeName == xdm.TypeNOTATION {
		qv, err := resolveQNameFromNode(s, ni.Node, ni.QNameNoDefaultNS)
		if err != nil {
			return xdm.AtomicValue{}, err
		}

		av := xdm.AtomicValue{TypeName: m.TypeName, Value: qv}
		if !xdm.IsKnownXSDType(m.TypeName) {
			base := m.Atomized
			if base == "" {
				base = xdm.TypeQName
			}

			av.BaseType = base
		}

		return av, nil
	}

	t := m.Atomized
	if t == "" {
		t = m.TypeName
	}

	cast, err := CastFromString(s, t)
	if err != nil {
		if strings.HasPrefix(m.TypeName, "Q{") {
			return xdm.AtomicValue{TypeName: m.TypeName, Value: s}, nil
		}

		return xdm.AtomicValue{}, err
	}

	if !xdm.IsKnownXSDType(m.TypeName) {
		cast.BaseType = cast.TypeName
		cast.TypeName = m.TypeName
	}

	return cast, nil
}

func builtinListItemType(typeName string) string {
	switch typeName {
	case xdm.TypeNMTOKENS:
		return xdm.TypeNMTOKEN
	case xdm.TypeIDREFS:
		return xdm.TypeIDREF
	case xdm.TypeENTITIES:
		return xdm.TypeENTITY
	}

	return ""
}

// atomizeStream atomizes a sequence per XPath 3.1 Section 2.6.2, invoking yield
// for each produced atomic value. If yield returns false, streaming stops early
// without error (used to bound work when a caller caps the number of atoms it
// will accept). A typed atomization error (e.g. FOTY0013 for function/map items,
// FORG0001 for an invalid list-member cast) propagates to the caller; this lets
// callers distinguish a genuine atomization failure from a plain cardinality
// rejection.
func atomizeStream(seq xdm.Sequence, yield func(xdm.AtomicValue) (bool, error)) error {
	_, err := atomizeStreamCont(seq, nil, yield)
	return err
}
