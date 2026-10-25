// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"cmp"
	"context"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

const (
	sortOrderAscending  = "ascending"
	sortOrderDescending = "descending"
)

type sortKey struct {
	forwards10 bool

	Select    *xpath.Expression
	Body      []instruction // sequence constructor (when select is absent)
	Order     *avt          // "ascending" or "descending"
	DataType  *avt          // "text" or lexicon.TypeNumber
	CaseOrder *avt          // "upper-first" or "lower-first"
	Lang      *avt
	Collation *avt // collation URI
	Stable    *avt // "yes"/"no"/"true"/"false"/"1"/"0"
}

type sortValueKind uint8

const (
	sortValueText sortValueKind = iota
	sortValueNumber
	sortValueNaN
)

// sortValue is a pre-extracted, typed sort key. Numeric values are parsed
// once at extraction time; no string→float conversion happens during comparison.
type sortValue struct {
	kind     sortValueKind
	str      string
	num      float64
	precise  *big.Rat // exact numeric or temporal key; never used for data-type="number"
	typeName string   // original XSD type name (for XTDE1030 checking)
	// atom carries the original atomized value (when hasAtom is true) so the
	// XTDE1030 type-consistency check can probe true XPath comparability via
	// xpath.ValueCompare, comparing no raw type names. Numeric/date
	// pre-conversion to num is independent of this — atom always reflects the
	// untouched source type for the consistency gate.
	atom    xdm.AtomicValue
	hasAtom bool
}

type sortMode uint8

const (
	sortModeText sortMode = iota
	sortModeNumber
)

type resolvedLevel struct {
	compare   func(a, b string) int // collation comparator; nil = codepoint
	floatRank int                   // 0: exact, 1: xs:float, 2: xs:double
	mode      sortMode
	exact     bool
	desc      bool
}

// resolvedSort holds the fully resolved per-level sort configuration.
// Built once before sorting; no per-comparison avt evaluation needed.
type resolvedSort struct {
	levels []resolvedLevel
}

func (rs *resolvedSort) compareKeys(aKeys, bKeys []sortValue, aIdx, bIdx int) int {
	for i, level := range rs.levels {
		if c := compareSortValues(aKeys[i], bKeys[i], level); c != 0 {
			return c
		}
	}

	return cmp.Compare(aIdx, bIdx)
}

// keyed1 pairs a value with a single inline sort key and original index.
type keyed1[T any] struct {
	item  T
	key   sortValue
	index int
}

// keyedN pairs a value with pre-extracted typed sort keys and original index.
type keyedN[T any] struct {
	item  T
	keys  []sortValue
	index int
}

// keyedSlice is a named slice type for keyedN so that convertAutoNumeric
// can be defined once and passed to finalizeLevels.
type keyedSlice[T any] []keyedN[T]

func (ks keyedSlice[T]) convertAutoNumeric(level int, exact bool) int {
	rank := 0

	for j := range ks {
		sv := &ks[j].keys[level]

		rank = max(rank, sortFloatRank(sv.atom))
		if sv.kind == sortValueText {
			*sv = parseToNumericSortValue(sv.str)
		}
	}

	if exact && rank == 1 {
		for i := range ks {
			sv := &ks[i].keys[level]
			sv.num = sortFloat32(*sv)
		}
	}

	return rank
}

// --- Comparators ---

func compareSortValues(a, b sortValue, level resolvedLevel) int {
	var c int

	switch level.mode {
	case sortModeNumber:
		if level.exact && level.floatRank == 0 && a.precise != nil && b.precise != nil {
			c = a.precise.Cmp(b.precise)
		} else {
			c = compareFloat64(a, b)
		}
	default:
		if level.compare != nil {
			c = level.compare(a.str, b.str)
		} else {
			c = cmp.Compare(a.str, b.str)
		}
	}

	if level.desc {
		c = -c
	}

	return c
}

// sortFloat32 rounds exact keys directly, avoiding double rounding via float64.
// Finalization promotes each key once after determining the common numeric type.
func sortFloat32(value sortValue) float64 {
	if value.precise != nil {
		f, _ := value.precise.Float32()
		return float64(f)
	}

	return float64(float32(value.num))
}

func compareFloat64(a, b sortValue) int {
	aNaN := a.kind == sortValueNaN

	bNaN := b.kind == sortValueNaN
	if aNaN && bNaN {
		return 0
	}

	if aNaN {
		return -1
	}

	if bNaN {
		return 1
	}

	if a.num < b.num {
		return -1
	}

	if a.num > b.num {
		return 1
	}

	return 0
}

// dataTypeMode tracks whether a sort level's data type is explicit or auto-detected.
type dataTypeMode uint8

const (
	dataTypeAuto       dataTypeMode = iota // no explicit data-type attr; detect from first numeric result
	dataTypeText                           // explicit data-type="text"
	dataTypeNumber                         // explicit data-type=lexicon.TypeNumber
	dataTypeNumberAuto                     // auto-detected from first numeric/date value
)

func (ec *execContext) selectedSortValue(ctx context.Context, sk *sortKey, node xdm.Node, dtMode *dataTypeMode, evalState *xpath.EvalState) (sortValue, error) {
	result, err := ec.evaluateSortExpression(ctx, sk.Select, node, evalState)
	if err != nil {
		return sortValue{}, err
	}

	seq := result.Sequence()

	seqLen := 0
	if seq != nil {
		seqLen = xdm.SequenceLen(seq)
	}

	strVal := result.StringValue()
	// Backwards-compatible keys use the first item without raising XTTE1020.
	if seqLen > 1 && ec.isCompatExpr(sk.Select) {
		seq = xdm.ItemSlice{seq.Get(0)}
		strVal = stringifyItem(seq.Get(0))
		seqLen = 1
	}

	if seqLen > 1 {
		return sortValue{}, dynamicError(errCodeXTTE1020,
			"sort key value is a sequence of %d items; a single value is required", seqLen)
	}

	if ec.stylesheet.processorLanguage() == 10 {
		strVal, err = xpath.XPath10String(seq)
		if err != nil {
			return sortValue{}, err
		}

		if *dtMode == dataTypeNumber {
			return numericSortValue10(seq)
		}

		if *dtMode == dataTypeAuto {
			*dtMode = dataTypeText
		}
	}

	implicitTZ := ec.currentTime.Location()
	if *dtMode == dataTypeNumber {
		// Explicit numeric conversion uses number() semantics; dates become NaN.
		return extractNumericSortValue(seq, strVal, true, implicitTZ), nil
	}

	if *dtMode == dataTypeNumberAuto {
		sv := extractNumericSortValue(seq, strVal, false, implicitTZ)
		if seqLen == 1 {
			sv = applyNumberAutoSingleton(sv, seq.Get(0), implicitTZ)
		}

		return sv, nil
	}

	return textSortValue(seq, strVal, seqLen == 1, dtMode, implicitTZ), nil
}

func numericSortValue10(seq xdm.Sequence) (sortValue, error) {
	number, err := xpath.XPath10Number(seq)
	if err != nil {
		return sortValue{}, err
	}

	value := number.ToFloat64()
	if math.IsNaN(value) {
		return sortValue{kind: sortValueNaN}, nil
	}

	return sortValue{kind: sortValueNumber, num: value}, nil
}

// evaluateSortExpression reuses an evaluation state only for expressions that
// do not require XPath 1.0 compatibility, whose context is set by evalXPath.
func (ec *execContext) evaluateSortExpression(ctx context.Context, expr *xpath.Expression, node xdm.Node, evalState *xpath.EvalState) (xpath.Result, error) {
	if evalState != nil && !ec.isCompatExpr(expr) {
		if ec.contextItem != nil {
			evalState.SetContextItem(ec.contextItem)
		}

		return expr.EvaluateReuse(ctx, evalState, node)
	}

	result, err := ec.evalXPath(ctx, expr, node)
	if err != nil {
		return xpath.Result{}, err
	}

	return *result, nil
}

func (ec *execContext) bodySortValue(ctx context.Context, body []instruction, node xdm.Node, dtMode *dataTypeMode) (sortValue, error) {
	if len(body) == 0 {
		if *dtMode == dataTypeNumber || *dtMode == dataTypeNumberAuto {
			return sortValue{kind: sortValueNaN}, nil
		}

		return sortValue{}, nil
	}

	val, err := ec.evaluateSortBody(ctx, body, node)
	if err != nil {
		return sortValue{}, err
	}

	implicitTZ := ec.currentTime.Location()
	if *dtMode == dataTypeNumber {
		return extractNumericSortValue(val, stringifySequence(val), true, implicitTZ), nil
	}

	if *dtMode == dataTypeNumberAuto {
		sv := extractNumericSortValue(val, stringifySequence(val), false, implicitTZ)
		return autoNumericSortValue(sv, val, implicitTZ), nil
	}

	strVal := stringifySequence(val)

	return textSortValue(val, strVal, val != nil && xdm.SequenceLen(val) == 1, dtMode, implicitTZ), nil
}

// autoNumericSortValue promotes an atomized singleton while retaining its type
// for the XTDE1030 gate, including schema-typed date and duration node values.
func autoNumericSortValue(value sortValue, seq xdm.Sequence, implicitTZ *time.Location) sortValue {
	if seq != nil && xdm.SequenceLen(seq) == 1 {
		return applyNumberAutoSingleton(value, seq.Get(0), implicitTZ)
	}

	return value
}

func (ec *execContext) evaluateSortBody(ctx context.Context, body []instruction, node xdm.Node) (xdm.Sequence, error) {
	savedCurrent := ec.currentNode

	savedContext := ec.contextNode
	if node != nil {
		ec.currentNode = node
		ec.contextNode = node
	}

	ec.temporaryOutputDepth++
	val, err := ec.evaluateBody(ctx, body)
	ec.temporaryOutputDepth--
	ec.currentNode = savedCurrent
	ec.contextNode = savedContext

	return val, err
}

func (ec *execContext) execPerformSort(ctx context.Context, inst *performSortInst) error {
	seq, err := ec.performSortInput(ctx, inst)
	if err != nil {
		return err
	}
	// Validate sort key attributes even when the selected sequence is empty
	// (e.g. a bad collation must still raise XTDE1035). sortNodes/sortGroups
	// validate regardless of input; mirror that for the empty-input case here.
	for _, sk := range inst.Sort {
		if err := validateSortKeyAttrs(ctx, ec, sk); err != nil {
			return err
		}
	}

	if seq == nil || xdm.SequenceLen(seq) == 0 {
		return nil
	}

	// Try to extract nodes for node-based sorting
	nodes, allNodes := xdm.NodesFrom(seq)
	if allNodes && len(nodes) > 0 {
		return ec.outputSortedNodes(ctx, nodes, inst.Sort)
	}

	// Atomic sequence: sort by string value and output as text items
	if len(inst.Sort) > 0 {
		var err error

		seq, err = sortItems(ctx, ec, seq, inst.Sort)
		if err != nil {
			return err
		}
	}

	// In capture mode (e.g. inside xsl:function), push sorted items
	// directly so the caller receives a proper sequence of atomic values,
	// and no merged text nodes.
	out := ec.currentOutput()
	if out.captureItems && out.doc != nil && out.current == out.doc.DocumentElement() {
		out.captureSortedItems(seq)
		return nil
	}

	return ec.outputSortedAtomicItems(seq)
}

func sortItems(ctx context.Context, ec *execContext, items xdm.Sequence, sortKeys []*sortKey) (xdm.Sequence, error) {
	if len(sortKeys) == 0 || items == nil || xdm.SequenceLen(items) == 0 {
		return items, nil
	}

	if len(sortKeys) == 1 {
		return sortItems1(ctx, ec, items, sortKeys[0])
	}

	return sortItemsN(ctx, ec, items, sortKeys)
}

func sortItems1(ctx context.Context, ec *execContext, items xdm.Sequence, sk *sortKey) (xdm.Sequence, error) {
	dtMode, err := initDataTypeMode1(ctx, ec, sk)
	if err != nil {
		return nil, err
	}

	evalState := ec.sortXPathEvalState(ctx)
	// Set size/position/current() context for the FULL mixed sequence so
	// sort keys referencing position()/last()/current() compute correctly
	// (XSLT spec 13.1.4). Mirror the node-only path (sortNodes1).
	evalState.SetSize(xdm.SequenceLen(items))
	entries := make([]keyed1[xdm.Item], xdm.SequenceLen(items))

	savedItem := ec.contextItem

	savedCurrent := ec.currentNode
	defer func() {
		ec.contextItem = savedItem
		ec.currentNode = savedCurrent
	}()

	for i := range xdm.SequenceLen(items) {
		evalState.SetPosition(i + 1)
		item := items.Get(i)
		ec.contextItem = item

		var node xdm.Node
		if ni, ok := item.(xdm.NodeItem); ok {
			node = ni.Node
			ec.contextItem = nil
			// current() resolves via ec.currentNode for node items.
			ec.currentNode = node
		} else {
			// current() resolves via ec.contextItem for non-node items.
			ec.currentNode = nil
		}

		sv, err := evaluateSortKey(ctx, ec, sk, node, &dtMode, evalState)
		if err != nil {
			return nil, err
		}

		entries[i] = keyed1[xdm.Item]{item: item, key: sv, index: i}
	}

	// XTDE1030: check for heterogeneous sort key types that can't be compared.
	if err := validateSortKeyTypes1(entries, dtMode); err != nil {
		return nil, err
	}

	level, err := resolveLevel1(ctx, ec, sk)
	if err != nil {
		return nil, err
	}

	finalizeLevel1(&level, dtMode, entries)

	slices.SortFunc(entries, func(a, b keyed1[xdm.Item]) int {
		if c := compareSortValues(a.key, b.key, level); c != 0 {
			return c
		}

		return cmp.Compare(a.index, b.index)
	})

	result := make(xdm.ItemSlice, len(entries))
	for i, e := range entries {
		result[i] = e.item
	}

	return result, nil
}

func sortItemsN(ctx context.Context, ec *execContext, items xdm.Sequence, sortKeys []*sortKey) (xdm.Sequence, error) {
	dtModes, err := initDataTypeModes(ctx, ec, sortKeys)
	if err != nil {
		return nil, err
	}

	evalState := ec.sortXPathEvalState(ctx)
	// Set size/position/current() context for the FULL mixed sequence so
	// sort keys referencing position()/last()/current() compute correctly
	// (XSLT spec 13.1.4). Mirror the node-only path (sortNodesN).
	evalState.SetSize(xdm.SequenceLen(items))
	entries := make(keyedSlice[xdm.Item], xdm.SequenceLen(items))

	savedItem := ec.contextItem

	savedCurrent := ec.currentNode
	defer func() {
		ec.contextItem = savedItem
		ec.currentNode = savedCurrent
	}()

	for i := range xdm.SequenceLen(items) {
		evalState.SetPosition(i + 1)
		item := items.Get(i)
		ec.contextItem = item

		var node xdm.Node
		if ni, ok := item.(xdm.NodeItem); ok {
			node = ni.Node
			ec.contextItem = nil
			// current() resolves via ec.currentNode for node items.
			ec.currentNode = node
		} else {
			// current() resolves via ec.contextItem for non-node items.
			ec.currentNode = nil
		}

		keys, err := extractSortValues(ctx, ec, sortKeys, node, dtModes, evalState)
		if err != nil {
			return nil, err
		}

		entries[i] = keyedN[xdm.Item]{item: item, keys: keys, index: i}
	}

	// XTDE1030: validate each sort key's type consistency across the sequence.
	if err := validateSortKeyTypesN(entries, dtModes); err != nil {
		return nil, err
	}

	rs, err := buildResolvedSort(ctx, ec, sortKeys)
	if err != nil {
		return nil, err
	}

	finalizeLevels(&rs, dtModes, entries)

	slices.SortFunc(entries, func(a, b keyedN[xdm.Item]) int {
		return rs.compareKeys(a.keys, b.keys, a.index, b.index)
	})

	result := make(xdm.ItemSlice, len(entries))
	for i, e := range entries {
		result[i] = e.item
	}

	return result, nil
}

func (ec *execContext) outputSortedNodes(ctx context.Context, nodes []xdm.Node, keys []*sortKey) error {
	if len(keys) > 0 {
		var err error

		nodes, err = sortNodes(ctx, ec, nodes, keys)
		if err != nil {
			return err
		}
	}

	savedCurrent := ec.currentNode
	savedContext := ec.contextNode
	savedPos := ec.position
	savedSize := ec.size

	ec.size = len(nodes)
	defer func() {
		ec.currentNode = savedCurrent
		ec.contextNode = savedContext
		ec.position = savedPos
		ec.size = savedSize
	}()

	for _, node := range nodes {
		if err := ec.copyNodeToOutput(node); err != nil {
			return err
		}
	}

	return nil
}

// --- Public dispatch ---

func sortNodes(ctx context.Context, ec *execContext, nodes []xdm.Node, sortKeys []*sortKey) ([]xdm.Node, error) {
	// Validate sort key attributes even if there are no nodes (XTDE0030).
	for _, sk := range sortKeys {
		if err := validateSortKeyAttrs(ctx, ec, sk); err != nil {
			return nil, err
		}
	}

	if len(sortKeys) == 0 || len(nodes) == 0 {
		return nodes, nil
	}

	if len(sortKeys) == 1 {
		return sortNodes1(ctx, ec, nodes, sortKeys[0])
	}

	return sortNodesN(ctx, ec, nodes, sortKeys)
}

// --- Single-key sort paths ---

func sortNodes1(ctx context.Context, ec *execContext, nodes []xdm.Node, sk *sortKey) ([]xdm.Node, error) {
	dtMode, err := initDataTypeMode1(ctx, ec, sk)
	if err != nil {
		return nil, err
	}

	evalState := ec.sortXPathEvalState(ctx)
	evalState.SetSize(len(nodes))

	// Save and restore currentNode so current() works correctly
	// within sort key expressions (XSLT spec 13.1.4).
	savedCurrent := ec.currentNode
	defer func() { ec.currentNode = savedCurrent }()

	entries := make([]keyed1[xdm.Node], len(nodes))
	for i, node := range nodes {
		evalState.SetPosition(i + 1)

		ec.currentNode = node

		sv, err := evaluateSortKey(ctx, ec, sk, node, &dtMode, evalState)
		if err != nil {
			return nil, err
		}

		entries[i] = keyed1[xdm.Node]{item: node, key: sv, index: i}
	}

	// XTDE1030: check for incompatible or non-orderable sort key types.
	if err := validateSortKeyTypes1(entries, dtMode); err != nil {
		return nil, err
	}

	level, err := resolveLevel1(ctx, ec, sk)
	if err != nil {
		return nil, err
	}

	finalizeLevel1(&level, dtMode, entries)

	slices.SortFunc(entries, func(a, b keyed1[xdm.Node]) int {
		if c := compareSortValues(a.key, b.key, level); c != 0 {
			return c
		}

		return cmp.Compare(a.index, b.index)
	})

	for i, e := range entries {
		nodes[i] = e.item
	}

	return nodes, nil
}

// --- Multi-key sort paths ---

func sortNodesN(ctx context.Context, ec *execContext, nodes []xdm.Node, sortKeys []*sortKey) ([]xdm.Node, error) {
	dtModes, err := initDataTypeModes(ctx, ec, sortKeys)
	if err != nil {
		return nil, err
	}

	evalState := ec.sortXPathEvalState(ctx)
	evalState.SetSize(len(nodes))

	savedCurrent := ec.currentNode
	defer func() { ec.currentNode = savedCurrent }()

	entries := make(keyedSlice[xdm.Node], len(nodes))
	for i, node := range nodes {
		evalState.SetPosition(i + 1)

		ec.currentNode = node

		keys, err := extractSortValues(ctx, ec, sortKeys, node, dtModes, evalState)
		if err != nil {
			return nil, err
		}

		entries[i] = keyedN[xdm.Node]{item: node, keys: keys, index: i}
	}

	// XTDE1030: validate each sort key's type consistency across the sequence.
	if err := validateSortKeyTypesN(entries, dtModes); err != nil {
		return nil, err
	}

	rs, err := buildResolvedSort(ctx, ec, sortKeys)
	if err != nil {
		return nil, err
	}

	finalizeLevels(&rs, dtModes, entries)

	slices.SortFunc(entries, func(a, b keyedN[xdm.Node]) int {
		return rs.compareKeys(a.keys, b.keys, a.index, b.index)
	})

	for i, e := range entries {
		nodes[i] = e.item
	}

	return nodes, nil
}

func (ec *execContext) outputSortedAtomicItems(seq xdm.Sequence) error {
	// Output atomic items separated by spaces
	idx := 0
	for item := range xdm.SequenceItems(seq) {
		if idx > 0 {
			sep := ec.resultDoc.CreateText(" ")
			if err := ec.addNode(sep); err != nil {
				return err
			}
		}

		av, ok := item.(xdm.AtomicValue)
		if !ok {
			continue
		}

		s, err := xpath.AtomicToString(av)
		if err != nil {
			continue
		}

		text := ec.resultDoc.CreateText(s)
		if err := ec.addNode(text); err != nil {
			return err
		}

		idx++
	}

	return nil
}

// performSortInput evaluates a select or sequence constructor without forcing
// materialization before sort-attribute validation.
func (ec *execContext) performSortInput(ctx context.Context, inst *performSortInst) (xdm.Sequence, error) {
	if inst.Select != nil {
		result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
		if err != nil {
			return nil, err
		}

		return result.Sequence(), nil
	}

	if len(inst.Body) > 0 {
		return ec.evaluateBodyAsSequence(ctx, inst.Body)
	}

	return nil, nil
}

// --- Sort level resolution ---

// resolveSortOrder evaluates the order AVT (defaulting to ascending) and
// validates it, raising XTDE0030 for any value other than ascending/descending.
func resolveSortOrder(ctx context.Context, ec *execContext, sk *sortKey) (string, error) {
	order := sortOrderAscending

	if sk.Order != nil {
		var err error

		order, err = sk.Order.evaluate(ctx, ec.contextNode)
		if err != nil {
			return "", err
		}

		if order != sortOrderAscending && order != sortOrderDescending {
			if sk.forwards10 {
				return sortOrderAscending, nil
			}

			return "", dynamicError(errCodeXTDE0030,
				"invalid order %q in xsl:sort; must be \"ascending\" or \"descending\"", order)
		}
	}

	return order, nil
}

// buildResolvedSort evaluates AVTs for order once and builds a resolvedLevel per sort level.
func buildResolvedSort(ctx context.Context, ec *execContext, sortKeys []*sortKey) (resolvedSort, error) {
	levels := make([]resolvedLevel, len(sortKeys))
	for i, sk := range sortKeys {
		order, err := resolveSortOrder(ctx, ec, sk)
		if err != nil {
			return resolvedSort{}, err
		}

		levels[i] = resolvedLevel{
			desc: order == sortOrderDescending,
		}

		if sk.Collation != nil {
			uri, err := sk.Collation.evaluate(ctx, ec.contextNode)
			if err != nil {
				return resolvedSort{}, err
			}

			cmpFn, err := xpath.ResolveCollationCompareFunc(uri)
			if err != nil {
				return resolvedSort{}, dynamicError(errCodeXTDE1035,
					"unknown collation URI %q", uri)
			}

			levels[i].compare = cmpFn
		} else if sk.Lang != nil || sk.CaseOrder != nil {
			uri, err := buildImplicitCollationURI(ctx, ec, sk)
			if err != nil {
				return resolvedSort{}, err
			}

			if uri != "" {
				cmpFn, err := xpath.ResolveCollationCompareFunc(uri)
				if err == nil {
					levels[i].compare = cmpFn
				}
			}
		}
	}

	return resolvedSort{levels: levels}, nil
}

func resolveLevel1(ctx context.Context, ec *execContext, sk *sortKey) (resolvedLevel, error) {
	order, err := resolveSortOrder(ctx, ec, sk)
	if err != nil {
		return resolvedLevel{}, err
	}
	// XTDE0030: validate lang attribute value
	if sk.Lang != nil {
		lang, err := sk.Lang.evaluate(ctx, ec.contextNode)
		if err != nil {
			return resolvedLevel{}, err
		}

		if !isValidLanguageTag(lang) {
			return resolvedLevel{}, dynamicError(errCodeXTDE0030,
				"invalid language tag %q in xsl:sort", lang)
		}
	}

	rl := resolvedLevel{desc: order == sortOrderDescending}

	if sk.Collation != nil {
		uri, err := sk.Collation.evaluate(ctx, ec.contextNode)
		if err != nil {
			return resolvedLevel{}, err
		}

		cmpFn, err := xpath.ResolveCollationCompareFunc(uri)
		if err != nil {
			return resolvedLevel{}, dynamicError(errCodeXTDE1035,
				"unknown collation URI %q", uri)
		}

		rl.compare = cmpFn
	} else if sk.Lang != nil || sk.CaseOrder != nil {
		// Build a UCA collation from lang/case-order when no explicit collation.
		uri, err := buildImplicitCollationURI(ctx, ec, sk)
		if err != nil {
			return resolvedLevel{}, err
		}

		if uri != "" {
			cmpFn, err := xpath.ResolveCollationCompareFunc(uri)
			if err == nil {
				rl.compare = cmpFn
			}
		}
	}

	return rl, nil
}

// buildImplicitCollationURI constructs a UCA collation URI from lang and
// case-order attributes when no explicit collation is specified. An evaluated
// case-order that is neither "upper-first" nor "lower-first" raises XTDE0030.
func buildImplicitCollationURI(ctx context.Context, ec *execContext, sk *sortKey) (string, error) {
	var params []string

	if sk.Lang != nil {
		lang, err := sk.Lang.evaluate(ctx, ec.contextNode)
		if err != nil {
			return "", err
		}

		if lang != "" {
			params = append(params, "lang="+lang)
		}
	}

	if sk.CaseOrder != nil {
		co, err := sk.CaseOrder.evaluate(ctx, ec.contextNode)
		if err != nil {
			return "", err
		}

		switch co {
		case nameUpperFirst:
			params = append(params, "caseFirst=upper")
		case nameLowerFirst:
			params = append(params, "caseFirst=lower")
		default:
			if sk.forwards10 {
				break
			}

			return "", dynamicError(errCodeXTDE0030,
				"invalid case-order %q in xsl:sort; must be \"upper-first\" or \"lower-first\"", co)
		}
	}

	if len(params) == 0 {
		return "", nil
	}

	return "http://www.w3.org/2013/collation/UCA?" + strings.Join(params, ";"), nil
}

// validateSortKeyAttrs validates sort key attribute values (order, data-type,
// case-order, lang, collation, stable) regardless of whether there are nodes
// to sort.
func validateSortKeyAttrs(ctx context.Context, ec *execContext, sk *sortKey) error {
	if _, err := resolveSortOrder(ctx, ec, sk); err != nil {
		return err
	}

	if sk.DataType != nil {
		dt, err := sk.DataType.evaluate(ctx, ec.contextNode)
		if err != nil {
			return err
		}

		if !isValidSortDataType(dt) {
			return dynamicError(errCodeXTDE0030,
				"invalid data-type %q in xsl:sort; must be \"text\", \"number\", or a QName", dt)
		}
	}

	if sk.CaseOrder != nil {
		co, err := sk.CaseOrder.evaluate(ctx, ec.contextNode)
		if err != nil {
			return err
		}

		if co != nameUpperFirst && co != nameLowerFirst && !sk.forwards10 {
			return dynamicError(errCodeXTDE0030,
				"invalid case-order %q in xsl:sort; must be \"upper-first\" or \"lower-first\"", co)
		}
	}

	if sk.Lang != nil {
		lang, err := sk.Lang.evaluate(ctx, ec.contextNode)
		if err != nil {
			return err
		}

		if !isValidLanguageTag(lang) {
			return dynamicError(errCodeXTDE0030,
				"invalid language tag %q in xsl:sort", lang)
		}
	}

	if sk.Stable != nil {
		stable, err := sk.Stable.evaluate(ctx, ec.contextNode)
		if err != nil {
			return err
		}
		// helium always performs a stable sort; the evaluated value is
		// validated for conformance but does not change sort behavior
		// (honoring stable="no" via an unstable sort is out of scope).
		if _, ok := parseXSDBool(stable); !ok {
			return dynamicError(errCodeXTDE0030,
				"invalid stable %q in xsl:sort; must be a valid xs:boolean", stable)
		}
	}

	if sk.Collation != nil {
		uri, err := sk.Collation.evaluate(ctx, ec.contextNode)
		if err != nil {
			return err
		}

		if _, err := xpath.ResolveCollationCompareFunc(uri); err != nil {
			return dynamicError(errCodeXTDE1035,
				"unknown collation URI %q", uri)
		}
	}

	return nil
}

// sortKeyTypesComparable reports whether two atomic sort-key values are mutually
// ORDERABLE under XPath value-comparison semantics, reusing xpath.ValueCompare
// with the less-than operator (`lt`) as the orderability oracle instead of
// comparing raw type names. Sorting needs ordering, not just equality, so the
// gate must probe `lt`: two values are consistent only if `lt` is DEFINED
// between them. This honors the repo's XSD 1.1 model automatically — the numeric
// family, xs:dateTimeStamp ⊂ xs:dateTime, xs:anyURI/xs:string, and
// untypedAtomic-as-string are all mutually orderable — while equality-only
// families (e.g. mixed xs:yearMonthDuration + xs:dayTimeDuration, which define
// `eq` but raise XPTY0004 on `lt`) and genuinely incomparable families (e.g.
// xs:date vs xs:integer) are correctly rejected with XTDE1030.
func sortKeyTypesComparable(a, b xdm.AtomicValue) bool {
	_, err := xpath.ValueCompare(xpath.TokenLt, a, b)
	return err == nil
}

// validateSortLevelTypes is the SINGLE per-level XTDE1030 validation routine
// shared by both the single-key and multi-key sort paths. It raises XTDE1030
// when the values for one sort level have mutually incomparable atomic types.
//
// Levels with an explicit data-type="text" (every value is stringified) or
// data-type="number" (every value is cast to xs:double) make mixed original
// atomic types trivially comparable, so the check is skipped entirely for them.
// Only default-data-type levels (dataTypeAuto / dataTypeNumberAuto) compare
// values by their own atomic types and need the consistency check.
func validateSortLevelTypes(values []sortValue, mode dataTypeMode) error {
	if mode == dataTypeText || mode == dataTypeNumber {
		return nil
	}

	var ref *xdm.AtomicValue

	for i := range values {
		v := &values[i]
		if !v.hasAtom {
			continue
		}
		// xs:duration is only partially ordered and cannot be used as a sort key.
		if v.atom.TypeName == xdm.TypeDuration {
			return dynamicError(errCodeXTDE1030,
				"sort keys of type %s are only partially ordered", xdm.TypeDuration)
		}

		if ref == nil {
			ref = &v.atom
			continue
		}

		if !sortKeyTypesComparable(*ref, v.atom) {
			return dynamicError(errCodeXTDE1030,
				"sort keys have incompatible types: %s and %s", ref.TypeName, v.atom.TypeName)
		}
	}

	return nil
}

// validateSortKeyTypes1 routes a single-key sort's values through the shared
// per-level validator.
func validateSortKeyTypes1[T any](entries []keyed1[T], mode dataTypeMode) error {
	values := make([]sortValue, len(entries))
	for i := range entries {
		values[i] = entries[i].key
	}

	return validateSortLevelTypes(values, mode)
}

// validateSortKeyTypesN routes each level of a multi-key sort through the shared
// per-level validator.
func validateSortKeyTypesN[T any](entries keyedSlice[T], dtModes []dataTypeMode) error {
	values := make([]sortValue, len(entries))
	for level, m := range dtModes {
		for i := range entries {
			values[i] = entries[i].keys[level]
		}

		if err := validateSortLevelTypes(values, m); err != nil {
			return err
		}
	}

	return nil
}

// isValidSortDataType reports whether s is a permitted xsl:sort data-type
// value: "text", "number", or a QName denoting a non-absent namespace
// (a prefixed lexical QName or an EQName Q{uri}local). The effect of a QName
// data-type is implementation-defined; helium treats it as "text".
func isValidSortDataType(s string) bool {
	switch s {
	case methodText, lexicon.TypeNumber:
		return true
	}

	if isValidEQName(s) {
		return true
	}
	// A bare NCName has an absent namespace and is not permitted; require a
	// prefix so the QName denotes a non-absent namespace.
	if strings.IndexByte(s, ':') > 0 && xmlchar.IsValidQName(s) {
		return true
	}

	return false
}

// isValidLanguageTag checks if s is a plausible BCP47 language tag.
// Rejects obviously invalid values (empty, contains quotes, whitespace).
func isValidLanguageTag(s string) bool {
	if s == "" {
		return true // empty = implementation default
	}

	for _, r := range s {
		if r == '\'' || r == '"' || r == ' ' || r == '\t' || r == '\n' {
			return false
		}
	}

	return true
}

// --- Key evaluation ---

// fillSingletonSortValue records the atomized value of a singleton sort-key
// item on sv (so the XTDE1030 orderability gate can probe it via
// xpath.ValueCompare), applies auto data-type promotion, and rebuilds sv as a
// numeric value for orderable duration/date/time types. It returns the original
// atomized value and whether one was captured; callers MUST set sv.atom/hasAtom
// from the result LAST, because the duration/date rebuild replaces sv wholesale
// and would otherwise drop the atom. Shared by the select and body sort-key
// paths so both record the source atom identically.
func fillSingletonSortValue(sv *sortValue, item xdm.Item, dtMode *dataTypeMode, implicitTZ *time.Location) (xdm.AtomicValue, bool) {
	var av xdm.AtomicValue

	switch v := item.(type) {
	case xdm.AtomicValue:
		av = v
	case xdm.NodeItem:
		// Atomize to get the typed value. A schema/type-annotated node MUST then
		// flow through the SAME auto numeric/date/duration promotion an atomic
		// singleton receives, so a typed date/duration node sorts by its real
		// value, and never as text. Reuse this single atomized value for both
		// the comparison value and the XTDE1030 gate (don't atomize twice).
		atom, err := xpath.AtomizeItem(v)
		if err != nil {
			return xdm.AtomicValue{}, false
		}

		av = atom
	default:
		return xdm.AtomicValue{}, false
	}

	applyAutoSortPromotion(sv, av, dtMode, implicitTZ)

	return av, true
}

// applyAutoSortPromotion records av's type on sv and, for an auto-detect
// data-type level, rewrites sv as a numeric sortValue for orderable
// duration/date/time types (flipping the level to dataTypeNumberAuto). Shared by
// atomic and atomized-node singleton keys so both promote identically.
//
// Only an auto-detect level rewrites orderable duration/date/time keys into a
// numeric sortValue. An explicit data-type="text" level must keep the string
// value already stored in sv.str — a numeric rewrite there would blank str and
// make every such key compare as "" under text comparison. The atom is recorded
// by the caller either way so the XTDE1030 orderability gate still sees the true
// source type.
//
// The first numeric or temporal key is converted immediately so its exact value
// survives finalization, just like subsequent keys. Schema-derived types use
// the same primitive-type resolution as the XTDE1030 validation gate.
func applyAutoSortPromotion(sv *sortValue, av xdm.AtomicValue, dtMode *dataTypeMode, implicitTZ *time.Location) {
	sv.typeName = av.TypeName

	if *dtMode != dataTypeAuto {
		return
	}

	if nv, ok := atomicToNumericSortValue(av, implicitTZ); ok {
		*sv = nv
		*dtMode = dataTypeNumberAuto
	}
}

// evaluateSortKey evaluates a single sort key for one item and returns its typed value.
// Uses EvaluateReuse when evalState is non-nil to avoid per-item evalContext allocation.
func evaluateSortKey(ctx context.Context, ec *execContext, sk *sortKey, node xdm.Node, dtMode *dataTypeMode, evalState *xpath.EvalState) (sortValue, error) {
	savedInSort := ec.inSortKeyEval

	ec.inSortKeyEval = true
	defer func() { ec.inSortKeyEval = savedInSort }()

	if sk.Select != nil {
		return ec.selectedSortValue(ctx, sk, node, dtMode, evalState)
	}

	return ec.bodySortValue(ctx, sk.Body, node, dtMode)
}

// textSortValue records the atom after promotion so the XTDE1030 consistency
// gate sees the original type even when the comparison value becomes numeric.
func textSortValue(seq xdm.Sequence, text string, singleton bool, dtMode *dataTypeMode, implicitTZ *time.Location) sortValue {
	sv := sortValue{kind: sortValueText, str: text}
	if singleton {
		atom, haveAtom := fillSingletonSortValue(&sv, seq.Get(0), dtMode, implicitTZ)
		sv.atom = atom
		sv.hasAtom = haveAtom
	}

	return sv
}

func extractSortValues(ctx context.Context, ec *execContext, sortKeys []*sortKey, node xdm.Node, dtModes []dataTypeMode, evalState *xpath.EvalState) ([]sortValue, error) {
	keys := make([]sortValue, len(sortKeys))
	for i, sk := range sortKeys {
		sv, err := evaluateSortKey(ctx, ec, sk, node, &dtModes[i], evalState)
		if err != nil {
			return nil, err
		}

		keys[i] = sv
	}

	return keys, nil
}

// --- Numeric extraction helpers ---

// extractNumericSortValue converts a sort key sequence to a numeric sort value.
// A single atomic item is converted directly when orderable; when numericOnly
// is true (explicit data-type=lexicon.TypeNumber), only actual numeric types
// use direct conversion per number() semantics, so dates/durations fall through
// to the fallback string → double (producing NaN). Otherwise fallback is parsed.
func extractNumericSortValue(seq xdm.Sequence, fallback string, numericOnly bool, implicitTZ *time.Location) sortValue {
	if seq != nil && xdm.SequenceLen(seq) == 1 {
		if av, ok := seq.Get(0).(xdm.AtomicValue); ok && (!numericOnly || av.IsNumeric()) {
			if sv, ok := atomicToNumericSortValue(av, implicitTZ); ok {
				return sv
			}
		}
	}

	return parseToNumericSortValue(fallback)
}

// applyNumberAutoSingleton finalizes a dataTypeNumberAuto singleton sort value.
// It atomizes the singleton item (recording the atom for the XTDE1030
// orderability gate) and, when the atomized typed value is orderable, replaces
// the comparison value with the numeric value derived from that typed value.
// This makes a schema-typed date/duration NODE sort by value instead of the
// NaN that extractNumericSortValue's string fallback would otherwise yield; for
// an atomic singleton it reproduces the same value extractNumericSortValue
// already computed. If atomization fails, sv is returned unchanged.
func applyNumberAutoSingleton(sv sortValue, item xdm.Item, implicitTZ *time.Location) sortValue {
	av, err := xpath.AtomizeItem(item)
	if err != nil {
		return sv
	}

	if nv, ok := atomicToNumericSortValue(av, implicitTZ); ok {
		sv = nv
	} else {
		sv.typeName = av.TypeName
	}

	sv.atom = av
	sv.hasAtom = true

	return sv
}

// atomicToNumericSortValue converts an atomic value to a numeric sort value
// for types that support ordering: numeric, duration, date/time.
// implicitTZ is used for xs:time values that lack an explicit timezone;
// pass nil to fall back to the system local timezone.
//
// It is BaseType-AWARE: a schema-derived atomic (a user-defined TypeName whose
// built-in BaseType is a numeric/date/time/duration primitive) is converted by
// its typed value, not skipped. This keeps the comparison-value conversion
// consistent with the XTDE1030 validation gate, which accepts derived types via
// xpath.ValueCompare (itself promoting through PromoteSchemaType). The original
// av.TypeName is preserved on the returned sortValue so the gate still sees the
// untouched source type. Numerics are already BaseType-aware via IsNumeric/
// ToFloat64; the date/time/duration branches resolve the primitive type through
// PromoteSchemaType before switching on it.
func atomicToNumericSortValue(av xdm.AtomicValue, implicitTZ *time.Location) (sortValue, bool) {
	if av.IsNumeric() {
		f := av.ToFloat64()
		if math.IsNaN(f) {
			return sortValue{kind: sortValueNaN, typeName: av.TypeName}, true
		}

		sv := sortValue{kind: sortValueNumber, num: f, typeName: av.TypeName}

		prim := xdm.PromoteSchemaType(av)
		if xdm.IsIntegerDerived(prim.TypeName) {
			sv.precise = new(big.Rat).SetInt(prim.BigInt())
		} else if prim.TypeName == xdm.TypeDecimal {
			sv.precise = prim.BigRat()
		}

		return sv, true
	}
	// Resolve a schema-derived date/time/duration to its built-in primitive so the
	// switch matches a derived type, then preserve the original TypeName below.
	prim := xdm.PromoteSchemaType(av)
	switch prim.TypeName {
	case xdm.TypeYearMonthDuration:
		d := prim.DurationVal()

		f := float64(d.Months)
		if d.Negative {
			f = -f
		}

		precise := new(big.Rat).SetInt64(int64(d.Months))
		if d.Negative {
			precise.Neg(precise)
		}

		return sortValue{kind: sortValueNumber, num: f, precise: precise, typeName: av.TypeName}, true
	case xdm.TypeDayTimeDuration:
		d := prim.DurationVal()

		f := d.Seconds
		if d.Negative {
			f = -f
		}

		return sortValue{kind: sortValueNumber, num: f, typeName: av.TypeName}, true
	case xdm.TypeDateTime, xdm.TypeDateTimeStamp, xdm.TypeDate:
		t := prim.TimeVal()
		t = xpath.ApplyImplicitTZ(t, implicitTZ)
		// Use Unix seconds + fractional nanoseconds to avoid int64 overflow for large years
		f := float64(t.Unix()) + float64(t.Nanosecond())/1e9

		return temporalSortValue(av.TypeName, t, f), true
	case xdm.TypeTime:
		t := prim.TimeVal()
		// xs:time comparison uses reference date 1972-12-31 per F&O §10.4.4
		t = xpath.TimeToReferenceDateTime(xpath.ApplyImplicitTZ(t, implicitTZ))
		f := float64(t.Unix()) + float64(t.Nanosecond())/1e9

		return temporalSortValue(av.TypeName, t, f), true
	}

	return sortValue{}, false
}

func temporalSortValue(typeName string, t time.Time, approximate float64) sortValue {
	precise := new(big.Rat).SetInt64(t.Unix())
	precise.Add(precise, new(big.Rat).SetFrac64(int64(t.Nanosecond()), 1e9))

	return sortValue{kind: sortValueNumber, num: approximate, precise: precise, typeName: typeName}
}

// --- Data type mode resolution ---

func initDataTypeModes(ctx context.Context, ec *execContext, sortKeys []*sortKey) ([]dataTypeMode, error) {
	modes := make([]dataTypeMode, len(sortKeys))
	for i, sk := range sortKeys {
		if sk.DataType == nil {
			continue
		}

		dt, err := sk.DataType.evaluate(ctx, ec.contextNode)
		if err != nil {
			return nil, err
		}

		if dt == lexicon.TypeNumber {
			modes[i] = dataTypeNumber
		} else {
			modes[i] = dataTypeText
		}
	}

	return modes, nil
}

func initDataTypeMode1(ctx context.Context, ec *execContext, sk *sortKey) (dataTypeMode, error) {
	if sk.DataType == nil {
		return dataTypeAuto, nil
	}

	dt, err := sk.DataType.evaluate(ctx, ec.contextNode)
	if err != nil {
		return dataTypeAuto, err
	}

	if dt == lexicon.TypeNumber {
		return dataTypeNumber, nil
	}

	return dataTypeText, nil
}

// --- Finalization (auto-detect conversion) ---

func finalizeLevels(rs *resolvedSort, dtModes []dataTypeMode, entries interface {
	convertAutoNumeric(level int, exact bool) int
},
) {
	for i, m := range dtModes {
		switch m {
		case dataTypeNumber, dataTypeNumberAuto:
			rs.levels[i].mode = sortModeNumber
			rs.levels[i].floatRank = entries.convertAutoNumeric(i, m == dataTypeNumberAuto)
			rs.levels[i].exact = m == dataTypeNumberAuto
		default:
			rs.levels[i].mode = sortModeText
		}
	}
}

func finalizeLevel1[T any](level *resolvedLevel, dtMode dataTypeMode, entries []keyed1[T]) {
	switch dtMode {
	case dataTypeNumber, dataTypeNumberAuto:
		level.mode = sortModeNumber
		level.exact = dtMode == dataTypeNumberAuto

		for i := range entries {
			k := &entries[i].key

			level.floatRank = max(level.floatRank, sortFloatRank(k.atom))
			if k.kind == sortValueText {
				*k = parseToNumericSortValue(k.str)
			}
		}

		if level.exact && level.floatRank == 1 {
			for i := range entries {
				entries[i].key.num = sortFloat32(entries[i].key)
			}
		}
	default:
		level.mode = sortModeText
	}
}

func parseToNumericSortValue(s string) sortValue {
	f := parseNumber(s)
	if math.IsNaN(f) {
		return sortValue{kind: sortValueNaN}
	}

	return sortValue{kind: sortValueNumber, num: f}
}

// Numeric promotion applies to the entire sort level, including comparisons
// between two decimals when a third key is a float or double.
func sortFloatRank(atom xdm.AtomicValue) int {
	switch xdm.PromoteSchemaType(atom).TypeName {
	case xdm.TypeDouble:
		return 2
	case xdm.TypeFloat:
		return 1
	default:
		return 0
	}
}

func sortGroups(ctx context.Context, ec *execContext, groups []fegGroup, sortKeys []*sortKey, hasKey bool) ([]fegGroup, error) {
	for _, sk := range sortKeys {
		if err := validateSortKeyAttrs(ctx, ec, sk); err != nil {
			return nil, err
		}
	}

	if len(sortKeys) == 0 || len(groups) == 0 {
		return groups, nil
	}

	if len(sortKeys) == 1 {
		return sortGroups1(ctx, ec, groups, sortKeys[0], hasKey)
	}

	return sortGroupsN(ctx, ec, groups, sortKeys, hasKey)
}

func sortGroups1(ctx context.Context, ec *execContext, groups []fegGroup, sk *sortKey, hasKey bool) ([]fegGroup, error) {
	dtMode, err := initDataTypeMode1(ctx, ec, sk)
	if err != nil {
		return nil, err
	}

	entries := make([]keyed1[fegGroup], len(groups))
	if err := ec.withSortGroupContext(groups, hasKey, func(i int, node xdm.Node) error {
		sv, err := evaluateSortKey(ctx, ec, sk, node, &dtMode, nil)
		if err != nil {
			return err
		}

		entries[i] = keyed1[fegGroup]{item: groups[i], key: sv, index: i}

		return nil
	}); err != nil {
		return nil, err
	}

	// XTDE1030: check for incompatible or non-orderable sort key types.
	if err := validateSortKeyTypes1(entries, dtMode); err != nil {
		return nil, err
	}

	level, err := resolveLevel1(ctx, ec, sk)
	if err != nil {
		return nil, err
	}

	finalizeLevel1(&level, dtMode, entries)

	slices.SortFunc(entries, func(a, b keyed1[fegGroup]) int {
		if c := compareSortValues(a.key, b.key, level); c != 0 {
			return c
		}

		return cmp.Compare(a.index, b.index)
	})

	for i, e := range entries {
		groups[i] = e.item
	}

	return groups, nil
}

func sortGroupsN(ctx context.Context, ec *execContext, groups []fegGroup, sortKeys []*sortKey, hasKey bool) ([]fegGroup, error) {
	dtModes, err := initDataTypeModes(ctx, ec, sortKeys)
	if err != nil {
		return nil, err
	}

	entries := make(keyedSlice[fegGroup], len(groups))
	if err := ec.withSortGroupContext(groups, hasKey, func(i int, node xdm.Node) error {
		keys, err := extractSortValues(ctx, ec, sortKeys, node, dtModes, nil)
		if err != nil {
			return err
		}

		entries[i] = keyedN[fegGroup]{item: groups[i], keys: keys, index: i}

		return nil
	}); err != nil {
		return nil, err
	}

	// XTDE1030: validate each sort key's type consistency across the sequence.
	if err := validateSortKeyTypesN(entries, dtModes); err != nil {
		return nil, err
	}

	rs, err := buildResolvedSort(ctx, ec, sortKeys)
	if err != nil {
		return nil, err
	}

	finalizeLevels(&rs, dtModes, entries)

	slices.SortFunc(entries, func(a, b keyedN[fegGroup]) int {
		return rs.compareKeys(a.keys, b.keys, a.index, b.index)
	})

	for i, e := range entries {
		groups[i] = e.item
	}

	return groups, nil
}

func parseNumber(s string) float64 {
	s = strings.TrimSpace(s)

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return math.NaN()
	}

	return f
}

func (out *outputFrame) captureSortedItems(seq xdm.Sequence) {
	out.pendingItems = append(out.pendingItems, xdm.Materialize(seq)...)
	if seq != nil && xdm.SequenceLen(seq) > 0 {
		out.noteOutput()
	}
}
