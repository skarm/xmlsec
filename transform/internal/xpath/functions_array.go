// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func lookupFunctionsArray(name string) (*builtinFunc, bool) {
	switch name {
	case "size":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnArraySize}, true
	case "get":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnArrayGet}, true
	case "put":
		return &builtinFunc{name: name, min: 3, max: 3, fn: fnArrayPut}, true
	case "append":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnArrayAppend}, true
	case "subarray":
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnArraySubarray}, true
	case nameRemove:
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnArrayRemove}, true
	case "insert-before":
		return &builtinFunc{name: name, min: 3, max: 3, fn: fnArrayInsertBefore}, true
	case fnNameHead:
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnArrayHead}, true
	case nameTail:
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnArrayTail}, true
	case nameReverse:
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnArrayReverse}, true
	case "join":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnArrayJoin}, true
	case "flatten":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnArrayFlatten}, true
	case "flat-map":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnArrayFlatMap, extension: true}, true
	case nameFilter:
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnArrayFilter}, true
	case nameFoldLeft:
		return &builtinFunc{name: name, min: 3, max: 3, fn: fnArrayFoldLeft}, true
	case nameFoldRight:
		return &builtinFunc{name: name, min: 3, max: 3, fn: fnArrayFoldRight}, true
	case nameForEach:
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnArrayForEach}, true
	case nameForEachPair:
		return &builtinFunc{name: name, min: 3, max: 3, fn: fnArrayForEachPair}, true
	case nameSort:
		return &builtinFunc{name: name, min: 1, max: 3, fn: fnArraySort}, true
	}

	return nil, false
}

func extractArray(seq xdm.Sequence) (xdm.ArrayItem, error) {
	if xdm.SequenceLen(seq) != 1 {
		return xdm.ArrayItem{}, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected single array"}
	}

	a, ok := seq.Get(0).(xdm.ArrayItem)
	if !ok {
		return xdm.ArrayItem{}, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("expected array, got %T", seq.Get(0))}
	}

	return a, nil
}

func fnArraySize(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	return xdm.SingleInteger(int64(a.Size())), nil
}

func fnArrayGet(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	idx, err := extractArrayIndex(args[1])
	if err != nil {
		return nil, err
	}

	return a.Get(idx)
}

// extractArrayIndex extracts a single xs:integer index from a sequence, validating
// that it is exactly one integer (not a decimal, sequence, etc.).
func extractArrayIndex(seq xdm.Sequence) (int, error) {
	return extractArrayInteger(seq, lexicon.ErrFOAY0001)
}

func extractArrayInteger(seq xdm.Sequence, negativeOverflowCode string) (int, error) {
	if xdm.SequenceLen(seq) != 1 {
		return 0, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "array index must be a single xs:integer"}
	}

	av, err := AtomizeItem(seq.Get(0))
	if err != nil {
		return 0, err
	}

	if !xdm.IsIntegerDerived(av.TypeName) {
		return 0, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("array index must be xs:integer, got %s", av.TypeName)}
	}

	iv, ok := av.Int64Val()
	if !ok {
		code := lexicon.ErrFOAY0001
		if av.BigInt().Sign() < 0 {
			code = negativeOverflowCode
		}

		return 0, &xdm.Error{Code: code, Message: textArrayIndexOutOfRange}
	}
	// On 64-bit platforms int(iv) is exact; on 32-bit, clamp out-of-int values
	// to the int extremes so the caller's 1..size bounds check still rejects
	// them (as out of range), wrapping into no valid-looking index.
	const maxInt = int(^uint(0) >> 1)
	if iv > int64(maxInt) {
		return maxInt, nil
	}

	if iv < int64(-maxInt-1) {
		return -maxInt - 1, nil
	}

	return int(iv), nil
}

func fnArrayPut(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	idx, err := extractArrayIndex(args[1])
	if err != nil {
		return nil, err
	}

	result, err := a.Put(idx, args[2])
	if err != nil {
		return nil, err
	}

	return xdm.ItemSlice{result}, nil
}

func fnArrayAppend(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	return xdm.ItemSlice{a.Append(args[1])}, nil
}

func fnArraySubarray(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	start, err := extractArrayIndex(args[1])
	if err != nil {
		return nil, err
	}

	length := a.Size() - start + 1
	if len(args) > 2 {
		// A negative length remains FOAY0002 even beyond the machine index
		// range; positive out-of-range lengths and positions use FOAY0001.
		length, err = extractArrayInteger(args[2], "FOAY0002")
		if err != nil {
			return nil, err
		}
	}

	sub, err := a.SubArray(start, length)
	if err != nil {
		return nil, err
	}

	return xdm.ItemSlice{sub}, nil
}

func fnArrayRemove(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}
	// args[1] is a sequence of positions to remove
	positions := make(map[int]struct{})
	size := a.Size()

	for item := range xdm.SequenceItems(args[1]) {
		av, err := AtomizeItem(item)
		if err != nil {
			return nil, err
		}

		if !xdm.IsIntegerDerived(av.TypeName) {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("array:remove position must be xs:integer, got %s", av.TypeName)}
		}

		iv, ok := av.Int64Val()
		if !ok {
			return nil, &xdm.Error{Code: lexicon.ErrFOAY0001, Message: "array:remove position out of range"}
		}
		// Range-check on int64 before converting so an out-of-int value cannot
		// wrap into a valid-looking position (e.g. on 32-bit platforms).
		if iv < 1 || iv > int64(size) {
			return nil, &xdm.Error{Code: lexicon.ErrFOAY0001, Message: fmt.Sprintf("array:remove: position %d out of range 1..%d", iv, size)}
		}

		positions[int(iv)] = struct{}{}
	}

	members := a.MembersView()

	var result []xdm.Sequence

	for i, m := range members {
		if _, skip := positions[i+1]; !skip {
			result = append(result, m)
		}
	}

	return xdm.ItemSlice{xdm.NewArray(result)}, nil
}

func fnArrayInsertBefore(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	pos, err := extractArrayIndex(args[1])
	if err != nil {
		return nil, err
	}

	members := a.MembersView()
	if pos < 1 || pos > len(members)+1 {
		return nil, &xdm.Error{Code: lexicon.ErrFOAY0001, Message: "array index out of bounds"}
	}

	result := make([]xdm.Sequence, 0, len(members)+1)
	result = append(result, members[:pos-1]...)
	result = append(result, args[2])
	result = append(result, members[pos-1:]...)

	return xdm.ItemSlice{xdm.NewArray(result)}, nil
}

func fnArrayHead(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	if a.Size() == 0 {
		return nil, &xdm.Error{Code: lexicon.ErrFOAY0001, Message: "array:head on empty array"}
	}

	return a.Get(1)
}

func fnArrayTail(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	if a.Size() == 0 {
		return nil, &xdm.Error{Code: lexicon.ErrFOAY0001, Message: "array:tail on empty array"}
	}

	sub, err := a.SubArray(2, a.Size()-1)
	if err != nil {
		return nil, err
	}

	return xdm.ItemSlice{sub}, nil
}

func fnArrayReverse(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	members := a.MembersView()

	reversed := make([]xdm.Sequence, len(members))
	for i, m := range members {
		reversed[len(members)-1-i] = m
	}

	return xdm.ItemSlice{xdm.NewArray(reversed)}, nil
}

func fnArrayJoin(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)

	var allMembers []xdm.Sequence
	// totalItems counts items already accumulated across all member sequences so
	// NewArray's per-member clone cannot materialize more than maxNodes items.
	totalItems := 0

	for item := range xdm.SequenceItems(args[0]) {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		a, ok := item.(xdm.ArrayItem)
		if !ok {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "array:join requires sequence of arrays"}
		}

		members := a.MembersView()
		for _, member := range members {
			// Both result-array bounds (member count and item count) plus the
			// per-member op charge are enforced by appendArrayMember.
			var err error

			allMembers, totalItems, err = appendArrayMember(ctx, ec, maxNodes, allMembers, totalItems, member)
			if err != nil {
				return nil, err
			}
		}
	}

	return xdm.ItemSlice{xdm.NewArray(allMembers)}, nil
}

func fnArrayFlatten(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)

	var result xdm.ItemSlice

	// Walk the (possibly deeply nested) array structure iteratively with an
	// explicit work stack, and never recursively, so a pathologically nested
	// input cannot exhaust the goroutine stack. The op-counter and node-set
	// limit bound the total work and output respectively.
	//
	// Each frame is a cursor over a list of member sequences (the array's
	// members, or the single top-level input) tracking the current member and
	// the current item within it. Items are consumed one at a time via
	// Sequence.Get so a lazy member sequence (e.g. a large integer range) is
	// never materialized into a temporary slice. The stack is LIFO, so on
	// descending into a nested array the parent frame is left in place beneath
	// the child frame, yielding document order.
	stack := []seqCursor{{members: []xdm.Sequence{args[0]}}}
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		item, ok, skippedEmpty := top.next()
		// Charge one op per empty member the cursor stepped past, so scanning N
		// empty array members costs ~N ops and trips OpLimit. Without this an
		// array of thousands of empty members is flattened for free.
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

		arr, isArr := item.(xdm.ArrayItem)
		if !isArr {
			// Deep-clone leaf items so pointer-backed atomics (*big.Int,
			// *big.Rat, *FloatValue, []byte) held in the array's internal
			// storage are not exposed to the caller; mutating the returned
			// sequence must not mutate the source array. Matches
			// ArrayItem.Flatten(). Nested arrays/maps are kept shared by
			// value (immutable, detached at ingress) to avoid O(N^2) work.
			var err error

			result, err = appendBounded(result, []xdm.Item{xdm.CloneItem(item)}, maxNodes)
			if err != nil {
				return nil, err
			}

			continue
		}
		// Descend into the nested array. The parent cursor was already advanced
		// past this item, so pushing the child frame on top processes the
		// array's contents before the parent's following items (document order).
		stack = append(stack, seqCursor{members: arr.MembersView()})
	}

	return result, nil
}

// seqCursor is a one-item-at-a-time cursor over a list of member sequences. It
// lets the iterative array/map walkers descend into nested structures without
// expanding any child sequence into a temporary slice: next() advances through
// the members in order, returning a single Item per call.
//
// The backing list of sequences is either an explicit []Sequence (array
// members or the single top-level input) or a map's entries, accessed in place
// via mapEntries so a wide map is never duplicated into a temporary []Sequence
// before traversal. memberAt/memberCount hide which backing is in use.
type seqCursor struct {
	members    []xdm.Sequence
	mapEntries []xdm.EntryView
	mi         int // current member index
	ii         int // current item index within member mi
}

func (c *seqCursor) memberCount() int {
	if c.mapEntries != nil {
		return len(c.mapEntries)
	}

	return len(c.members)
}

func (c *seqCursor) memberAt(i int) xdm.Sequence {
	if c.mapEntries != nil {
		return c.mapEntries[i].Value
	}

	return c.members[i]
}

// next advances the cursor by one item. The returned skippedEmpty count is the
// number of EMPTY member/value sequences the cursor stepped past to reach the
// returned item (or to exhaust the cursor). An empty member is one the cursor
// enters at item index 0 and finds has zero items, so it yields nothing. Callers
// MUST charge one op per skipped-empty member: otherwise a flood of empty array
// members or empty map values would advance the cursor for free and let
// array:flatten / map:find scan far more than OpLimit members without tripping
// the limit, since an empty member yields no item and so would never reach a
// per-item op charge. (A non-empty member is not counted: its op cost is charged
// once per item it yields by the caller's per-item op charge.)
func (c *seqCursor) next() (item xdm.Item, ok bool, skippedEmpty int) {
	for c.mi < c.memberCount() {
		m := c.memberAt(c.mi)
		if c.ii < xdm.SequenceLen(m) {
			it := m.Get(c.ii)
			c.ii++

			return it, true, skippedEmpty
		}

		if c.ii == 0 {
			// We entered this member at its start and it has no items: it is an
			// empty member, scanned for free unless the caller charges an op.
			skippedEmpty++
		}

		c.mi++
		c.ii = 0
	}

	return nil, false, skippedEmpty
}

func fnArrayFlatMap(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	fi, err := extractFunctionItem(args[1])
	if err != nil {
		return nil, err
	}

	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)

	var allMembers []xdm.Sequence
	// totalItems counts items already accumulated across all member sequences so
	// NewArray's per-member clone cannot materialize more than maxNodes items.
	totalItems := 0

	for _, m := range a.MembersView() {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		r, err := fi.Invoke(ctx, []xdm.Sequence{m})
		if err != nil {
			return nil, err
		}
		// Each result should be an array; collect members one at a time, checking
		// the limit before each append so neither a lazy callback result nor a
		// wide array member list can overshoot the limit before the check. Charge
		// one op per result item up front (even when the item is an empty array, so
		// many empty arrays cannot bypass OpLimit).
		for item := range xdm.SequenceItems(r) {
			if err := fnCountOp(ctx, ec); err != nil {
				return nil, err
			}

			if ra, ok := item.(xdm.ArrayItem); ok {
				for _, member := range ra.MembersView() {
					// Both result-array bounds (member count and item count) plus the
					// per-member op charge are enforced by appendArrayMember.
					allMembers, totalItems, err = appendArrayMember(ctx, ec, maxNodes, allMembers, totalItems, member)
					if err != nil {
						return nil, err
					}
				}

				continue
			}
			// A NON-array callback result becomes one scalar member. It must go
			// through the SAME bounds as array members: after maxNodes empty array
			// members the member count is already at the limit, so one scalar (item
			// count 1) would otherwise push the member count to maxNodes+1.
			allMembers, totalItems, err = appendArrayMember(ctx, ec, maxNodes, allMembers, totalItems, xdm.ItemSlice{item})
			if err != nil {
				return nil, err
			}
		}
	}

	return xdm.ItemSlice{xdm.NewArray(allMembers)}, nil
}

func fnArrayFilter(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	fi, err := extractFunctionItem(args[1])
	if err != nil {
		return nil, err
	}

	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)

	var result []xdm.Sequence
	// totalItems counts items already accumulated across all selected member
	// sequences so NewArray's per-member clone cannot materialize more than
	// maxNodes items: a single selected member with a huge lazy sequence must be
	// rejected before it is cloned, not just the member COUNT bounded.
	totalItems := 0

	for _, m := range a.MembersView() {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		r, err := fi.Invoke(ctx, []xdm.Sequence{m})
		if err != nil {
			return nil, err
		}
		// Per XPath 3.1, the callback must return exactly one xs:boolean
		if xdm.SequenceLen(r) != 1 {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "array:filter callback must return a single xs:boolean value"}
		}

		av, ok := r.Get(0).(xdm.AtomicValue)
		if !ok || av.TypeName != xdm.TypeBoolean {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "array:filter callback must return xs:boolean"}
		}

		if !av.BooleanVal() {
			continue
		}
		// A selected member must honor BOTH result-array bounds: the item count
		// (a selected member with a huge lazy sequence must be rejected before
		// NewArray clones it) AND the member count (selecting many EMPTY members,
		// each seqLen 0, must not build an array with more than maxNodes members).
		// appendArrayMember enforces both plus the per-member op charge.
		result, totalItems, err = appendArrayMember(ctx, ec, maxNodes, result, totalItems, m)
		if err != nil {
			return nil, err
		}
	}

	return xdm.ItemSlice{xdm.NewArray(result)}, nil
}

func fnArrayFoldLeft(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	acc := args[1]

	fi, err := extractFunctionItem(args[2])
	if err != nil {
		return nil, err
	}

	ec := getFnContext(ctx)

	maxNodes := fnMaxNodes(ec)
	for _, m := range a.MembersView() {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		acc, err = fi.Invoke(ctx, []xdm.Sequence{acc, m})
		if err != nil {
			return nil, err
		}
		// The accumulator can grow without bound across iterations; reject once
		// it would exceed the configured sequence/node-set limit.
		if maxNodes > 0 && xdm.SequenceLen(acc) > maxNodes {
			return nil, ErrNodeSetLimit
		}
	}

	return acc, nil
}

func fnArrayFoldRight(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	acc := args[1]

	fi, err := extractFunctionItem(args[2])
	if err != nil {
		return nil, err
	}

	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)

	members := a.MembersView()
	for _, v := range slices.Backward(members) {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		acc, err = fi.Invoke(ctx, []xdm.Sequence{v, acc})
		if err != nil {
			return nil, err
		}
		// The accumulator can grow without bound across iterations; reject once
		// it would exceed the configured sequence/node-set limit.
		if maxNodes > 0 && xdm.SequenceLen(acc) > maxNodes {
			return nil, ErrNodeSetLimit
		}
	}

	return acc, nil
}

func fnArrayForEach(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	fi, err := extractFunctionItem(args[1])
	if err != nil {
		return nil, err
	}

	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)

	var results []xdm.Sequence
	// total counts items across all callback results: NewArray clones each result,
	// so a callback returning one oversized lazy/borrowed sequence is still
	// materialized unless its length is bounded. Use an overflow-safe compare
	// (rLen > maxNodes-total) so total+rLen never overflows.
	total := 0

	for _, m := range a.MembersView() {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		r, err := fi.Invoke(ctx, []xdm.Sequence{m})
		if err != nil {
			return nil, err
		}
		// Each callback result becomes one array MEMBER. appendArrayMember bounds
		// both the member count and the item count and charges the per-member op.
		results, total, err = appendArrayMember(ctx, ec, maxNodes, results, total, r)
		if err != nil {
			return nil, err
		}
	}

	return xdm.ItemSlice{xdm.NewArray(results)}, nil
}

func fnArrayForEachPair(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a1, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	a2, err := extractArray(args[1])
	if err != nil {
		return nil, err
	}

	fi, err := extractFunctionItem(args[2])
	if err != nil {
		return nil, err
	}

	if fi.Arity >= 0 && fi.Arity != 2 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("array:for-each-pair callback must have arity 2, got %d", fi.Arity)}
	}

	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)
	size := min(a1.Size(), a2.Size())

	var results []xdm.Sequence
	// total counts items across all callback results (NewArray clones each), so a
	// callback returning one oversized lazy/borrowed sequence is bounded too. The
	// compare is overflow-safe (rLen > maxNodes-total).
	total := 0

	for i := 1; i <= size; i++ {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		m1, _ := a1.GetView(i)
		m2, _ := a2.GetView(i)

		r, err := fi.Invoke(ctx, []xdm.Sequence{m1, m2})
		if err != nil {
			return nil, err
		}
		// Each callback result becomes one array MEMBER. appendArrayMember bounds
		// both the member count and the item count and charges the per-member op.
		results, total, err = appendArrayMember(ctx, ec, maxNodes, results, total, r)
		if err != nil {
			return nil, err
		}
	}

	return xdm.ItemSlice{xdm.NewArray(results)}, nil
}

func fnArraySort(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	a, err := extractArray(args[0])
	if err != nil {
		return nil, err
	}

	src := a.MembersView()
	members := make([]xdm.Sequence, len(src))
	copy(members, src)

	coll, err := sortCollation(ctx, args)
	if err != nil {
		return nil, err
	}

	// Optional key function (3rd arg)
	var keyFn *xdm.FunctionItem

	if len(args) > 2 {
		fi, err := extractFunctionItem(args[2])
		if err != nil {
			return nil, err
		}

		keyFn = &fi
	}

	entries := make([]arraySortEntry, len(members))
	if err := populateArraySortKeys(ctx, members, keyFn, entries); err != nil {
		return nil, err
	}

	var sortErr error

	sort.SliceStable(entries, func(i, j int) bool {
		if sortErr != nil {
			return false
		}

		var less bool

		less, sortErr = sequenceSortKeyLess(ctx, entries[i].key, entries[j].key, coll)

		return less
	})

	if sortErr != nil {
		return nil, sortErr
	}

	sorted := make([]xdm.Sequence, len(entries))
	for i, e := range entries {
		sorted[i] = e.member
	}

	return xdm.ItemSlice{xdm.NewArray(sorted)}, nil
}

type arraySortEntry struct {
	member xdm.Sequence
	key    xdm.Sequence // atomized key sequence for comparison
}

func populateArraySortKeys(ctx context.Context, members []xdm.Sequence, keyFn *xdm.FunctionItem, entries []arraySortEntry) error {
	for i, member := range members {
		entries[i].member = member
		value := member

		if keyFn != nil {
			var err error

			value, err = keyFn.Invoke(ctx, []xdm.Sequence{member})
			if err != nil {
				return err
			}
		}

		key, err := atomizedSortKey(value)
		if err != nil {
			return err
		}

		entries[i].key = key
	}

	return nil
}
