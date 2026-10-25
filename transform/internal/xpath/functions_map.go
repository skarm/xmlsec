// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func lookupFunctionsMap(name string) (*builtinFunc, bool) {
	switch name {
	case "merge":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnMapMerge}, true
	case "size":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMapSize}, true
	case "keys":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMapKeys}, true
	case fnNameContains:
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnMapContains}, true
	case "get":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnMapGet}, true
	case "put":
		return &builtinFunc{name: name, min: 3, max: 3, fn: fnMapPut}, true
	case "entry":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnMapEntry}, true
	case nameRemove:
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnMapRemove}, true
	case nameForEach:
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnMapForEach}, true
	case "find":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnMapFind}, true
	}

	return nil, false
}

func extractMap(seq xdm.Sequence) (xdm.MapItem, error) {
	if xdm.SequenceLen(seq) != 1 {
		return xdm.MapItem{}, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected single map"}
	}

	m, ok := seq.Get(0).(xdm.MapItem)
	if !ok {
		return xdm.MapItem{}, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("expected map, got %T", seq.Get(0))}
	}

	return m, nil
}

func fnMapMerge(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	duplicates := xdm.MergeUseFirst

	if len(args) > 1 {
		if xdm.SequenceLen(args[1]) == 0 {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "map:merge: options argument must be a map, got empty sequence"}
		}

		if xdm.SequenceLen(args[1]) > 1 {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "map:merge: options argument must be a single map"}
		}
		// The options map should contain "duplicates" key
		optMap, ok := args[1].Get(0).(xdm.MapItem)
		if !ok {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("map:merge: options argument must be a map, got %T", args[1].Get(0))}
		}

		key := xdm.AtomicValue{TypeName: xdm.TypeString, Value: nameDuplicates}
		if val, found := optMap.Get(key); found {
			// Per F&O 3.1 option conventions, the 'duplicates' value is type
			// xs:string and is converted with the function conversion rules.
			// So xs:string subtypes (xs:NCName, ...), xs:anyURI, xs:untypedAtomic,
			// and a single-item array all coerce to a string. An empty, multi-item,
			// or non-convertible value is a FOJS0005 error (not XPTY0004).
			s, convErr := coerceDuplicatesOption(ctx, val)
			if convErr != nil {
				return nil, convErr
			}

			switch s {
			case duplicatesUseFirst:
				duplicates = xdm.MergeUseFirst
			case nameUseLast:
				duplicates = xdm.MergeUseLast
			case "use-any":
				// use-any allows the implementation to pick any value;
				// reusing use-first behavior is conformant.
				duplicates = xdm.MergeUseFirst
			case duplicatesReject:
				duplicates = xdm.MergeReject
			case "combine":
				duplicates = xdm.MergeCombine
			default:
				return nil, &xdm.Error{Code: errCodeFOJS0005, Message: fmt.Sprintf("map:merge: invalid value for 'duplicates' option: %q", s)}
			}
		}
	}

	return mergeMapSequence(ctx, args[0], duplicates)
}

func mergeMapSequence(ctx context.Context, maps xdm.Sequence, duplicates xdm.MergePolicy) (xdm.Sequence, error) {
	ec := getFnContext(ctx)

	var combinedLengths map[xdm.MapKey]int
	if duplicates == xdm.MergeCombine {
		combinedLengths = make(map[xdm.MapKey]int)
	}

	builder := xdm.NewMapBuilder(duplicates, xdm.SequenceLen(maps))
	for item := range xdm.SequenceItems(maps) {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		m, ok := item.(xdm.MapItem)
		if !ok {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "map:merge requires sequence of maps"}
		}

		mergeErr := m.ForEachView(func(key xdm.AtomicValue, value xdm.Sequence) error {
			if err := fnCountOp(ctx, ec); err != nil {
				return err
			}

			if err := prepareMergedValue(ctx, ec, combinedLengths, key, value); err != nil {
				return err
			}

			if err := builder.Add(key, value); err != nil {
				return err
			}

			if builder.Size() > fnMaxNodes(ec) {
				return ErrBudget
			}

			return nil
		})
		if mergeErr != nil {
			return nil, mergeErr
		}
	}

	return xdm.ItemSlice{builder.Build()}, nil
}

// Combining duplicate values uses a builder-owned buffer with amortized append.
// Bound the accumulated size and charge incoming items before copying them.
func prepareMergedValue(ctx context.Context, ec *evalContext, lengths map[xdm.MapKey]int, key xdm.AtomicValue, value xdm.Sequence) error {
	if lengths == nil {
		return nil
	}

	normalized := xdm.NormalizeMapKey(key)
	previous := lengths[normalized]

	incoming := xdm.SequenceLen(value)
	if incoming > fnMaxNodes(ec)-previous {
		return ErrBudget
	}

	total := previous + incoming
	if err := fnCountOps(ctx, ec, max(1, incoming)); err != nil {
		return err
	}

	lengths[normalized] = total

	return nil
}

// coerceDuplicatesOption converts the 'duplicates' option value of map:merge to
// a string. The option is declared as xs:string, so only xs:untypedAtomic,
// xs:string (and subtypes), and xs:anyURI (and subtypes) are accepted; any other
// atomic type — even a custom type whose Go payload happens to be a string — is a
// FOJS0005 error, and is never silently accepted. A single-item array still
// flattens to its member via atomization. Atomization is ctx-aware: an
// element-only-typed node has no typed value, so it surfaces err:FOTY0012
// unchanged, masked as no FOJS0005 invalid-option error.
func coerceDuplicatesOption(ctx context.Context, val xdm.Sequence) (string, error) {
	var first xdm.AtomicValue

	count := 0

	_, err := atomizeStreamCont(val, typedValueItemCheck(ctx), func(av xdm.AtomicValue) (bool, error) {
		count++
		if count == 1 {
			first = av
			return true, nil
		}

		return false, nil
	})
	if err != nil {
		if isNoTypedValueError(err) {
			return "", err
		}

		return "", &xdm.Error{Code: errCodeFOJS0005, Message: fmt.Sprintf("map:merge: 'duplicates' option must be a single string: %s", err)}
	}

	if count != 1 {
		return "", &xdm.Error{Code: errCodeFOJS0005, Message: fmt.Sprintf("map:merge: 'duplicates' option must be a single string, got sequence of length %d", count)}
	}

	av := first
	if av.TypeName != xdm.TypeUntypedAtomic &&
		!xdm.IsAtomicSubtypeOf(av, xdm.TypeString) &&
		!xdm.IsAtomicSubtypeOf(av, xdm.TypeAnyURI) {
		return "", &xdm.Error{Code: errCodeFOJS0005, Message: fmt.Sprintf("map:merge: 'duplicates' option must be a string, got %s", av.TypeName)}
	}

	s, convErr := atomicToString(av)
	if convErr != nil {
		return "", &xdm.Error{Code: errCodeFOJS0005, Message: fmt.Sprintf("map:merge: 'duplicates' option must be a single string: %s", convErr)}
	}

	return s, nil
}

func fnMapSize(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	m, err := extractMap(args[0])
	if err != nil {
		return nil, err
	}

	return xdm.SingleInteger(int64(m.Size())), nil
}

func fnMapKeys(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	m, err := extractMap(args[0])
	if err != nil {
		return nil, err
	}

	keys := m.Keys()

	result := make(xdm.ItemSlice, len(keys))
	for i, k := range keys {
		result[i] = k
	}

	return result, nil
}

func fnMapContains(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	m, err := extractMap(args[0])
	if err != nil {
		return nil, err
	}

	ka, err := extractSingleAtomicArg(args[1], "map:contains")
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(m.Contains(ka)), nil
}

func fnMapGet(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	m, err := extractMap(args[0])
	if err != nil {
		return nil, err
	}

	if xdm.SequenceLen(args[1]) == 0 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "map:get requires a key argument"}
	}

	if xdm.SequenceLen(args[1]) > 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "map:get key must be a single atomic value"}
	}

	ka, err := AtomizeItem(args[1].Get(0))
	if err != nil {
		return nil, err
	}
	// Borrow the stored value WITHOUT cloning (get0), then drain it through
	// appendBoundedClonedSeq so maxNodes / OpLimit / cancellation fire BEFORE the
	// value is materialized. Public Get deep-clones by materializing eagerly,
	// which would defeat the bound for a borrowed lazy value (and panic if its
	// Materialize panics). Cloning each appended item keeps value semantics, so
	// mutating the result cannot reach the source map.
	val, ok := m.GetView(ka)
	if !ok {
		return nil, nil
	}

	ec := getFnContext(ctx)

	return appendBoundedClonedSeq(ctx, ec, nil, val, fnMaxNodes(ec))
}

func fnMapPut(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	m, err := extractMap(args[0])
	if err != nil {
		return nil, err
	}

	ka, err := extractSingleAtomicArg(args[1], "map:put key")
	if err != nil {
		return nil, err
	}

	return xdm.ItemSlice{m.Put(ka, args[2])}, nil
}

func fnMapEntry(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	ka, err := extractSingleAtomicArg(args[0], "map:entry key")
	if err != nil {
		return nil, err
	}

	return xdm.ItemSlice{xdm.SingleEntryMap(ka, args[1])}, nil
}

func fnMapRemove(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	m, err := extractMap(args[0])
	if err != nil {
		return nil, err
	}

	for item := range xdm.SequenceItems(args[1]) {
		ka, err := AtomizeItem(item)
		if err != nil {
			return nil, err
		}

		m = m.Remove(ka)
	}

	return xdm.ItemSlice{m}, nil
}

func fnMapForEach(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	m, err := extractMap(args[0])
	if err != nil {
		return nil, err
	}

	fi, err := extractFunctionItem(args[1])
	if err != nil {
		return nil, err
	}

	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)

	var result xdm.ItemSlice
	// Iterate without cloning (forEach0) so a borrowed lazy value is never
	// materialized by ForEach's clone before the bound/op guards run. For each
	// entry: bound the value length against maxNodes and charge the value's
	// length (min 1) of ops BEFORE cloning the key/value into the callback, so a
	// pathological lazy value is rejected, and never eagerly materialized.
	mapErr := m.ForEachView(func(k xdm.AtomicValue, v xdm.Sequence) error {
		vLen := xdm.SequenceLen(v)
		if maxNodes > 0 && vLen > maxNodes {
			return ErrNodeSetLimit
		}

		if err := fnCountOps(ctx, ec, max(vLen, 1)); err != nil {
			return err
		}

		r, err := fi.Invoke(ctx, []xdm.Sequence{xdm.ItemSlice{xdm.CloneMapKey(k)}, xdm.CloneSequence(v)})
		if err != nil {
			return err
		}

		result, err = appendBoundedSeq(ctx, ec, result, r, maxNodes)
		if err != nil {
			return err
		}

		return nil
	})
	if mapErr != nil {
		return nil, mapErr
	}

	return result, nil
}

func fnMapFind(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	ka, err := extractSingleAtomicArg(args[1], "map:find key")
	if err != nil {
		return nil, err
	}

	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)

	results, err := mapFindIter(ctx, ec, maxNodes, args[0], ka)
	if err != nil {
		return nil, err
	}

	return xdm.ItemSlice{xdm.NewArray(results)}, nil
}

// mapFindIter searches for a key in maps within items. Per XPath 3.1, map:find
// searches recursively through maps and arrays, in document order. The walk is
// performed iteratively with an explicit work stack, and never recursively, so
// a pathologically nested input cannot exhaust the goroutine stack when no op
// limit is set. The traversal charges an op per item and bounds the accumulated
// result item count so a deeply or widely nested input cannot exhaust resources.
//
// Each frame is a one-item-at-a-time cursor over a list of sequences: the root
// input, an array's members, or — for maps — the map's own entries accessed in
// place (so a wide map is never copied into a temporary []Sequence). Items are
// consumed via Sequence.Get so a lazy value/member sequence is never expanded
// into a temporary slice. A matched value is looked up without cloning (get0)
// and its length bound-checked before it is cloned, so a borrowed lazy value is
// rejected, and never materialized. The stack is LIFO, so on descending into a
// nested map/array the parent frame is left in place beneath the child frame,
// yielding document order.
func mapFindIter(ctx context.Context, ec *evalContext, maxNodes int, root xdm.Sequence, key xdm.AtomicValue) ([]xdm.Sequence, error) {
	var results []xdm.Sequence
	// total counts items already accumulated across all matched value sequences,
	// so a single huge (possibly lazy) matched value is bounded the same as many
	// small matches.
	total := 0

	stack := []seqCursor{{members: []xdm.Sequence{root}}}
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		item, ok, skippedEmpty := top.next()
		// Charge one op per empty value the cursor stepped past, so scanning N
		// empty map values costs ~N ops and trips OpLimit. Without this a map
		// with thousands of empty values is searched for free even when no key
		// matches.
		if skippedEmpty > 0 {
			if err := fnCountOps(ctx, ec, skippedEmpty); err != nil {
				return nil, err
			}
		}

		if !ok {
			stack = stack[:len(stack)-1]
			continue
		}

		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		switch v := item.(type) {
		case xdm.MapItem:
			// The map's own match comes before its descendants in document order.
			// Look the value up WITHOUT cloning (get0) and bound-check its length
			// before materializing: a borrowed lazy value (e.g. a huge integer
			// range stored via map:entry, which does not clone) must be rejected
			// with ErrNodeSetLimit, and never materialized by the clone in Get.
			if val, found := v.GetView(key); found {
				// Each matched value becomes one member of the result array.
				// appendArrayMember bounds both the member count (many empty
				// matches must not exceed maxNodes members) and the item count (a
				// borrowed lazy value must be rejected before NewArray clones it),
				// and charges max(valLen, 1) ops so empty matches still cost an op.
				// The borrowed (uncloned) value is appended; the single defensive
				// clone happens once in NewArray(results) at the call site.
				var aerr error

				results, total, aerr = appendArrayMember(ctx, ec, maxNodes, results, total, val)
				if aerr != nil {
					return nil, aerr
				}
			}
			// Then descend into the map's values, in insertion order, iterating
			// the entries in place so a wide map is not duplicated into a
			// temporary []Sequence before traversal.
			stack = append(stack, seqCursor{mapEntries: v.EntriesView()})
		case xdm.ArrayItem:
			stack = append(stack, seqCursor{members: v.MembersView()})
		}
	}

	return results, nil
}
