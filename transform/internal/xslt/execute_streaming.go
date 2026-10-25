// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"math"
	"slices"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// Sentinel errors for xsl:break and xsl:next-iteration control flow.
var (
	errBreak    = errors.New("xsl:break")
	errNextIter = errors.New("xsl:next-iteration")
)

// mergeSourceItems holds the items from one merge source along with
// their pre-extracted sort keys and the source name.
type mergeSourceItems struct {
	name            string
	items           xdm.ItemSlice
	keys            [][]mergeKeyValue // keys[i] corresponds to items[i]
	sortBeforeMerge bool              // from parent mergeSource
	sourceIdx       int               // index into inst.Sources
}

// mergeKeyOrder tracks the descending flag for each key level.
type mergeKeyOrder struct {
	desc bool
}

// mergeKeyValue holds a single merge key as an XPath atomic value for
// type-aware comparison (dates, numbers, strings, etc.).
type mergeKeyValue struct {
	atom        xdm.AtomicValue       // the actual typed atomic value
	str         string                // string fallback (used when atom is zero)
	num         float64               // numeric value (used when numeric is true)
	numeric     bool                  // true when data-type="number" was applied
	isNaN       bool                  // true when numeric conversion produced NaN
	collCompare func(a, b string) int // collation compare function (nil = codepoint)
}

// execSourceDocument executes xsl:source-document by loading the referenced
// document into a DOM tree and executing the body with that document as context.
func (ec *execContext) execSourceDocument(ctx context.Context, inst *sourceDocumentInst) error {
	uri, err := inst.Href.evaluate(ctx, ec.contextNode)
	if err != nil {
		return err
	}

	docURI, fragment := splitURIFragment(uri)

	effectiveBase := inst.BaseURI
	if effectiveBase == "" {
		effectiveBase = ec.stylesheet.baseURI
	}

	resolvedURI := resolveAgainstBaseURI(docURI, effectiveBase)

	cacheKey := ec.docCacheKey(resolvedURI)
	if err := ec.CheckRead(ctx, resolvedURI); err != nil {
		return err
	}

	doc, ok := ec.docCache[cacheKey]
	if ok {
		if _, err := ec.existingDocumentRead(ctx, doc); err != nil {
			return err
		}
	}

	if !ok {
		reader, err := ec.retrieveDocumentReader(ctx, resolvedURI)
		if err != nil {
			if _, hostFailure := errors.AsType[*xdm.ResourceAccessError](err); hostFailure {
				return err
			}

			return dynamicErrorCause(errCodeFODC0002, err, "xsl:source-document cannot load %q: %v", uri, err)
		}

		doc, err = parseXMLResource(ctx, ec.inputParseOptions(), reader, resolvedURI, ec.resourceLimit())
		if err != nil {
			return dynamicErrorCause(errCodeFODC0002, err, "xsl:source-document cannot parse %q: %v", uri, err)
		}

		// Apply xsl:strip-space to the loaded document so that whitespace-only
		// text nodes are removed before XPath evaluation sees them.
		if len(ec.effectiveStripSpace()) > 0 {
			ec.stripWhitespaceFromDoc(doc)
		}

		if ec.docCache == nil {
			ec.docCache = make(map[string]*xdm.Document)
		}

		ec.docCache[cacheKey] = doc
	}

	// Apply input-type-annotations="strip": remove all type annotations so
	// elements are xs:untyped and attributes xs:untypedAtomic.
	if ec.stylesheet.inputTypeAnnotations == validationStrip && ec.typeAnnotations != nil {
		// Dropping annotations changes which nodes a typed count pattern matches.
		ec.numberMemos = nil
		ec.preserveIDAnnotations()

		for k := range ec.typeAnnotations {
			delete(ec.typeAnnotations, k)
		}
	}

	startNode := xdm.Node(doc)
	if fragment != "" {
		elem := doc.GetElementByID(fragment)
		if elem == nil {
			return dynamicError(errCodeFODC0002, "xsl:source-document fragment %q not found in %q", fragment, uri)
		}

		startNode = elem
	}

	if err := ec.prepareSourceDocumentAccumulators(ctx, inst, doc); err != nil {
		return err
	}

	// Save and restore source document, context nodes, and context item.
	savedSource := ec.sourceDoc
	savedContext := ec.contextNode
	savedCurrent := ec.currentNode
	savedItem := ec.contextItem
	savedPos := ec.position
	savedSize := ec.size
	savedActiveAccums := ec.activeAccumulators
	ec.sourceDoc = doc
	ec.contextNode = startNode
	ec.currentNode = startNode
	ec.contextItem = nil // document node is the context, not an atomic item
	ec.position = 1
	ec.size = 1

	ec.activeAccumulators = make(map[string]struct{}, len(inst.UseAccumulators))
	for _, name := range inst.UseAccumulators {
		ec.activeAccumulators[name] = struct{}{}
	}

	defer func() {
		ec.sourceDoc = savedSource
		ec.contextNode = savedContext
		ec.currentNode = savedCurrent
		ec.contextItem = savedItem
		ec.position = savedPos
		ec.size = savedSize
		ec.activeAccumulators = savedActiveAccums
	}()

	for _, child := range inst.Body {
		if err := ec.executeInstruction(ctx, child); err != nil {
			return err
		}
	}

	return nil
}

// execIterate executes xsl:iterate, processing each item in the selected
// sequence with mutable iteration parameters.
func (ec *execContext) execIterate(ctx context.Context, inst *iterateInst) error {
	result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
	if err != nil {
		return err
	}

	seq := result.Sequence()

	paramVals, paramTypes, err := ec.initializeIterateParams(ctx, inst.Params)
	if err != nil {
		return err
	}

	// Save and restore context.
	savedCurrent := ec.currentNode
	savedContext := ec.contextNode
	savedPos := ec.position
	savedSize := ec.size

	savedItem := ec.contextItem
	defer func() {
		ec.currentNode = savedCurrent
		ec.contextNode = savedContext
		ec.position = savedPos
		ec.size = savedSize
		ec.contextItem = savedItem
	}()

	ec.size = xdm.SequenceLen(seq)

	for i := range xdm.SequenceLen(seq) {
		if err := ctx.Err(); err != nil {
			return err
		}

		ec.setIterateContext(seq.Get(i), i+1)
		bodyErr := ec.executeIterateBody(ctx, inst.Body, paramVals)

		switch {
		case errors.Is(bodyErr, errBreak):
			return ec.outputIterateBreak()
		case errors.Is(bodyErr, errNextIter):
			if err := ec.updateIterateParams(ctx, paramVals, paramTypes); err != nil {
				return err
			}
		case bodyErr != nil:
			return bodyErr
		}
	}

	return ec.completeIterate(ctx, inst.OnCompletion, paramVals)
}

func (ec *execContext) initializeIterateParams(ctx context.Context, params []*iterateParam) (map[string]xdm.Sequence, map[string]string, error) {
	values := make(map[string]xdm.Sequence, len(params))
	types := make(map[string]string, len(params))

	for _, param := range params {
		if param.As != "" {
			types[param.Name] = param.As
		}

		value, err := ec.evaluateIterateParam(ctx, param)
		if err != nil {
			return nil, nil, err
		}

		values[param.Name] = value
	}

	return values, types, nil
}

func (ec *execContext) evaluateIterateParam(ctx context.Context, param *iterateParam) (xdm.Sequence, error) {
	value := xdm.EmptySequence()

	switch {
	case param.Select != nil:
		result, err := ec.evalXPath(ctx, param.Select, ec.contextNode)
		if err != nil {
			return nil, err
		}

		value = result.Sequence()
	case len(param.Body) > 0:
		ec.temporaryOutputDepth++
		result, err := ec.evaluateBody(ctx, param.Body)
		ec.temporaryOutputDepth--

		if err != nil {
			return nil, err
		}

		value = result
	}

	return ec.coerceIterateParam(ctx, value, param.As, "xsl:iterate parameter $"+param.Name)
}

func (ec *execContext) coerceIterateParam(ctx context.Context, value xdm.Sequence, asType, label string) (xdm.Sequence, error) {
	if asType == "" || value == nil || xdm.SequenceLen(value) == 0 {
		return value, nil
	}

	return checkSequenceType(ctx, value, parseSequenceType(asType), errCodeXTTE0570, label, ec)
}

func (ec *execContext) setIterateContext(item xdm.Item, position int) {
	ec.position = position
	if node, ok := item.(xdm.NodeItem); ok {
		ec.currentNode = node.Node
		ec.contextNode = node.Node
		ec.contextItem = nil
	} else {
		ec.contextItem = item
		ec.contextNode = nil
		ec.currentNode = nil
	}
}

func (ec *execContext) executeIterateBody(ctx context.Context, body []instruction, params map[string]xdm.Sequence) error {
	ec.pushVarScope()
	defer ec.popVarScope()

	for name, value := range params {
		ec.setVar(name, value)
	}

	for _, child := range body {
		if err := ec.executeInstruction(ctx, child); err != nil {
			return err
		}
	}

	return nil
}

func (ec *execContext) updateIterateParams(ctx context.Context, values map[string]xdm.Sequence, types map[string]string) error {
	for name, value := range ec.nextIterParams {
		coerced, err := ec.coerceIterateParam(ctx, value, types[name], "xsl:next-iteration parameter $"+name)
		if err != nil {
			return err
		}

		values[name] = coerced
	}

	ec.nextIterParams = nil

	return nil
}

func (ec *execContext) outputIterateBreak() error {
	if ec.breakValue == nil {
		return nil
	}

	out := ec.currentOutput()
	if out.captureItems {
		out.pendingItems = append(out.pendingItems, xdm.Materialize(ec.breakValue)...)
	} else if err := ec.outputSequence(ec.breakValue); err != nil {
		return err
	}

	ec.breakValue = nil

	return nil
}

func (ec *execContext) completeIterate(ctx context.Context, body []instruction, params map[string]xdm.Sequence) error {
	if len(body) == 0 {
		return nil
	}

	// on-completion has no context item, position or size.
	ec.contextNode = nil
	ec.currentNode = nil
	ec.contextItem = nil
	ec.position = 0
	ec.size = 0

	return ec.executeIterateBody(ctx, body, params)
}

// execFork executes xsl:fork by running each branch sequentially.
// In a true streaming implementation branches would run concurrently,
// but for the DOM-materialization strategy sequential execution is correct.
func (ec *execContext) execFork(ctx context.Context, inst *forkInst) error {
	for _, branch := range inst.Branches {
		for _, child := range branch {
			if err := ec.executeInstruction(ctx, child); err != nil {
				return err
			}
		}
	}

	return nil
}

// execBreak executes xsl:break, which terminates the enclosing xsl:iterate.
func (ec *execContext) execBreak(ctx context.Context, inst *breakInst) error {
	if inst.Select != nil {
		result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
		if err != nil {
			return err
		}

		ec.breakValue = result.Sequence()
	} else if len(inst.Body) > 0 {
		val, err := ec.evaluateBody(ctx, inst.Body)
		if err != nil {
			return err
		}

		ec.breakValue = val
	}

	return errBreak
}

// execNextIteration executes xsl:next-iteration, which signals the enclosing
// xsl:iterate to advance to the next item with updated parameter values.
func (ec *execContext) execNextIteration(ctx context.Context, inst *nextIterationInst) error {
	params := make(map[string]xdm.Sequence, len(inst.Params))
	for _, wp := range inst.Params {
		val, err := ec.evaluateWithParam(ctx, wp)
		if err != nil {
			return err
		}

		params[wp.Name] = val
	}

	ec.nextIterParams = params

	return errNextIter
}

// execMerge executes xsl:merge by loading, sorting, and merging items from
// multiple sources, then executing the merge-action for each group of items
// sharing the same key.
func (ec *execContext) execMerge(ctx context.Context, inst *mergeInst) error {
	sources, err := ec.gatherAllMergeSources(ctx, inst.Sources)
	if err != nil {
		return err
	}

	orders, err := ec.evaluateMergeOrders(ctx, inst.Sources[0].Keys)
	if err != nil {
		return err
	}

	dataTypes, err := ec.evaluateMergeDataTypes(ctx, inst.Sources)
	if err != nil {
		return err
	}

	if err := validateMergeDataTypes(dataTypes); err != nil {
		return err
	}

	if err := validateMergeSourceCollations(inst.Sources); err != nil {
		return err
	}

	collations, err := ec.resolveMergeCollations(ctx, inst.Sources[0].Keys)
	if err != nil {
		return err
	}

	if err := prepareMergeSourceOrder(sources, dataTypes, orders, collations); err != nil {
		return err
	}

	applyMergeComparisonTypes(sources, dataTypes[0], collations)

	groups, err := ec.nWayMerge(sources, orders)
	if err != nil {
		return err
	}

	return ec.executeMergeGroups(ctx, inst, groups)
}

// compareMergeKeysForVerify compares two merge key value arrays for
// sort-order verification (XTDE2220). It behaves like compareMergeKeyValues
// but, for a non-numeric key level with a declared collation, compares the
// keys' string values under that collation. Merge keys selected from untyped
// nodes atomize to xs:untypedAtomic and would otherwise compare by codepoint
// through compareSingleMergeKey, ignoring the declared collation — so data
// sorted for one collation and merged under another would be seen as sorted.
func compareMergeKeysForVerify(a, b []mergeKeyValue, orders []mergeKeyOrder, colls []func(x, y string) int) (int, error) {
	for i, ord := range orders {
		if i >= len(a) || i >= len(b) {
			break
		}

		var (
			c   int
			err error
		)
		if i < len(colls) && colls[i] != nil && mergeKeyStringLike(a[i]) && mergeKeyStringLike(b[i]) {
			c, err = compareMergeKeyStringsColl(a[i], b[i], colls[i])
		} else {
			c, err = compareSingleMergeKey(a[i], b[i])
		}

		if err != nil {
			return 0, err
		}

		if ord.desc {
			c = -c
		}

		if c != 0 {
			return c, nil
		}
	}

	return 0, nil
}

// compareMergeKeyStringsColl compares two merge key values as strings under
// the supplied collation compare function.
func compareMergeKeyStringsColl(a, b mergeKeyValue, coll func(x, y string) int) (int, error) {
	as, err := mergeKeyString(a)
	if err != nil {
		return 0, err
	}

	bs, err := mergeKeyString(b)
	if err != nil {
		return 0, err
	}

	return coll(as, bs), nil
}

// mergeKeyStringLike reports whether a merge key value should be compared as a
// string under a declared collation. A key selected from an untyped node
// (xs:untypedAtomic), a genuine xs:string/xs:anyURI, or a pure string fallback
// qualifies; a data-type="number" key or a genuinely-ordered non-string atom
// (numeric, date, boolean, …) does not — those keep their typed/codepoint
// ordering via compareSingleMergeKey, matching the n-way merge comparison and
// avoiding a spurious out-of-order verdict (e.g. "10" < "2").
func mergeKeyStringLike(mkv mergeKeyValue) bool {
	if mkv.numeric {
		return false
	}

	if mkv.atom.TypeName == "" {
		return true
	}

	switch mkv.atom.TypeName {
	case xdm.TypeString, xdm.TypeUntypedAtomic, xdm.TypeAnyURI:
		return true
	default:
		return false
	}
}

// mergeKeyString returns the string value of a merge key value, atomizing a
// typed atomic value when present and falling back to the recorded string.
func mergeKeyString(mkv mergeKeyValue) (string, error) {
	if mkv.atom.TypeName != "" {
		s, err := xpath.AtomicToString(mkv.atom)
		if err != nil {
			return "", err
		}

		return s, nil
	}

	return mkv.str, nil
}

// applyNumericMergeKey converts a merge key value to numeric mode.
// When data-type="number", the key's string value is parsed as a number.
// Non-numeric values become NaN, and two NaN values are treated as equal
// during comparison (per XSLT sort specification).
func applyNumericMergeKey(mkv *mergeKeyValue) {
	mkv.numeric = true

	// If we have a typed atomic value, try to extract its numeric value.
	if mkv.atom.TypeName != "" {
		if mkv.atom.IsNumeric() {
			f := mkv.atom.ToFloat64()
			if math.IsNaN(f) {
				mkv.isNaN = true
				return
			}

			mkv.num = f

			return
		}
		// Non-numeric atomic value: get string representation and parse.
		s, err := xpath.AtomicToString(mkv.atom)
		if err != nil {
			mkv.isNaN = true
			return
		}

		f := parseNumber(s)
		if math.IsNaN(f) {
			mkv.isNaN = true
			return
		}

		mkv.num = f

		return
	}

	// String fallback.
	f := parseNumber(mkv.str)
	if math.IsNaN(f) {
		mkv.isNaN = true
		return
	}

	mkv.num = f
}

func validateMergeDataTypes(perSourceDataTypes [][]string) error {
	// XTDE2210: detect inconsistent data-type between sources.
	// Per XSLT spec, if data-type differs between corresponding merge-key
	// elements for different merge sources, the processor may raise XTDE2210.
	if len(perSourceDataTypes) > 1 {
		first := perSourceDataTypes[0]
		for si := 1; si < len(perSourceDataTypes); si++ {
			for k := range first {
				if k < len(perSourceDataTypes[si]) && first[k] != perSourceDataTypes[si][k] {
					return dynamicError(errCodeXTDE2210, "merge sources have inconsistent data-type for merge key %d: %q vs %q", k+1, first[k], perSourceDataTypes[si][k])
				}
			}
		}
	}

	return nil
}

func validateMergeSourceCollations(sources []*mergeSource) error {
	// XTDE2210: detect inconsistent collation between sources.
	// If corresponding merge-key elements specify different collations,
	// lang, or case-order, raise XTDE2210.
	if len(sources) > 1 {
		firstKeys := sources[0].Keys
		for si := 1; si < len(sources); si++ {
			srcKeys := sources[si].Keys
			for k := range firstKeys {
				if k >= len(srcKeys) {
					break
				}

				if firstKeys[k].Collation != srcKeys[k].Collation {
					return dynamicError(errCodeXTDE2210, "merge sources have inconsistent collation for merge key %d: %q vs %q", k+1, firstKeys[k].Collation, srcKeys[k].Collation)
				}

				if firstKeys[k].Lang != srcKeys[k].Lang {
					return dynamicError(errCodeXTDE2210, "merge sources have inconsistent lang for merge key %d: %q vs %q", k+1, firstKeys[k].Lang, srcKeys[k].Lang)
				}

				if firstKeys[k].CaseOrder != srcKeys[k].CaseOrder {
					return dynamicError(errCodeXTDE2210, "merge sources have inconsistent case-order for merge key %d: %q vs %q", k+1, firstKeys[k].CaseOrder, srcKeys[k].CaseOrder)
				}
			}
		}
	}

	return nil
}

func prepareMergeSourceOrder(sources []mergeSourceItems, dataTypes [][]string, orders []mergeKeyOrder, collations []func(a, b string) int) error {
	for i := range sources {
		source := &sources[i]
		if len(source.items) <= 1 {
			continue
		}

		keys := mergeVerificationKeys(source.keys, dataTypes[source.sourceIdx])
		if source.sortBeforeMerge {
			if err := sortMergeSourceItems(source, keys, orders); err != nil {
				return err
			}
		} else if err := verifyMergeSourceKeys(keys, orders, collations); err != nil {
			return err
		}
	}

	return nil
}

func mergeVerificationKeys(keys [][]mergeKeyValue, dataTypes []string) [][]mergeKeyValue {
	verification := make([][]mergeKeyValue, len(keys))
	for i, key := range keys {
		copyKey := append([]mergeKeyValue(nil), key...)
		for k := range copyKey {
			if k < len(dataTypes) && dataTypes[k] == lexicon.TypeNumber {
				applyNumericMergeKey(&copyKey[k])
			}
		}

		verification[i] = copyKey
	}

	return verification
}

func sortMergeSourceItems(src *mergeSourceItems, verifyKeys [][]mergeKeyValue, orders []mergeKeyOrder) error {
	type indexedEntry struct {
		idx  int
		item xdm.Item
		keys []mergeKeyValue
	}

	// sort-before-merge="yes": sort the items by merge keys.
	entries := make([]indexedEntry, len(src.items))
	for i := range src.items {
		entries[i] = indexedEntry{idx: i, item: src.items[i], keys: verifyKeys[i]}
	}

	var sortErr error

	slices.SortStableFunc(entries, func(a, b indexedEntry) int {
		if sortErr != nil {
			return 0
		}

		c, err := compareMergeKeyValues(a.keys, b.keys, orders)
		if err != nil {
			sortErr = err
			return 0
		}

		return c
	})

	if sortErr != nil {
		return sortErr
	}
	// Rebuild items and keys in sorted order using a temporary copy
	// of the original keys to avoid in-place overwrite corruption.
	origKeys := make([][]mergeKeyValue, len(src.keys))
	copy(origKeys, src.keys)

	for i, e := range entries {
		src.items[i] = e.item
		src.keys[i] = origKeys[e.idx]
	}

	return nil
}

func verifyMergeSourceKeys(verifyKeys [][]mergeKeyValue, orders []mergeKeyOrder, keyCollations []func(a, b string) int) error {
	// Default: verify items are already sorted (XTDE2220). String
	// keys are compared under the declared collation (e.g. a UCA
	// collation with lang/case-order/alternate), so data sorted for
	// one collation but merged under another is detected as unsorted.
	for i := 1; i < len(verifyKeys); i++ {
		cmp, cmpErr := compareMergeKeysForVerify(verifyKeys[i-1], verifyKeys[i], orders, keyCollations)
		if cmpErr != nil {
			return cmpErr
		}

		if cmp > 0 {
			return dynamicError(errCodeXTDE2220, "merge input is not sorted according to the declared merge key")
		}
	}

	return nil
}

func applyMergeComparisonTypes(sources []mergeSourceItems, firstDTs []string, keyCollations []func(a, b string) int) {
	for si := range sources {
		src := &sources[si]
		for i := range src.keys {
			for k := range src.keys[i] {
				if k < len(firstDTs) && firstDTs[k] == lexicon.TypeNumber {
					applyNumericMergeKey(&src.keys[i][k])
				}

				if k < len(keyCollations) && keyCollations[k] != nil {
					src.keys[i][k].collCompare = keyCollations[k]
				}
			}
		}
	}
}

func (ec *execContext) gatherAllMergeSources(ctx context.Context, definitions []*mergeSource) ([]mergeSourceItems, error) {
	// 1. Gather items from all sources.
	var allSources []mergeSourceItems

	for srcIdx, src := range definitions {
		items, err := ec.gatherMergeSourceItems(ctx, src)
		if err != nil {
			return nil, err
		}

		// 2. Evaluate merge keys for items from this source using its own key defs.
		for i := range items {
			keys, err := ec.evaluateMergeKeys(ctx, &items[i], src.Keys)
			if err != nil {
				return nil, err
			}

			items[i].keys = keys
		}

		// Tag each mergeSourceItems with its source index for per-source
		// data-type resolution during sort verification.
		for i := range items {
			items[i].sourceIdx = srcIdx
		}

		allSources = append(allSources, items...)
	}

	return allSources, nil
}

func (ec *execContext) evaluateMergeOrders(ctx context.Context, keyDefs []*mergeKey) ([]mergeKeyOrder, error) {
	orders := make([]mergeKeyOrder, len(keyDefs))
	for i, mk := range keyDefs {
		orderStr := mk.Order
		if mk.OrderAVT != nil {
			evaluated, err := mk.OrderAVT.evaluate(ctx, ec.contextNode)
			if err != nil {
				return nil, err
			}

			orderStr = evaluated
		}

		orders[i] = mergeKeyOrder{desc: orderStr == lexicon.OutputDescending}
	}

	return orders, nil
}

func (ec *execContext) evaluateMergeDataTypes(ctx context.Context, sources []*mergeSource) ([][]string, error) {
	perSourceDataTypes := make([][]string, len(sources))
	for si, src := range sources {
		dts := make([]string, len(src.Keys))
		for k, mk := range src.Keys {
			dt := mk.DataType
			if mk.DataTypeAVT != nil {
				evaluated, err := mk.DataTypeAVT.evaluate(ctx, ec.contextNode)
				if err != nil {
					return nil, err
				}

				dt = evaluated
			}

			dts[k] = dt
		}

		perSourceDataTypes[si] = dts
	}

	return perSourceDataTypes, nil
}

func (ec *execContext) resolveMergeCollations(ctx context.Context, keyDefs []*mergeKey) ([]func(a, b string) int, error) {
	var keyCollations []func(a, b string) int

	for _, mk := range keyDefs {
		collFn, collErr := ec.resolveMergeKeyCollation(ctx, mk)
		if collErr != nil {
			return nil, collErr
		}

		keyCollations = append(keyCollations, collFn)
	}

	return keyCollations, nil
}

func (ec *execContext) installMergeFunctions(sources []*mergeSource) (*mergeActionState, func()) {
	ec.xsltFunctions()
	state := &mergeActionState{ec: ec, validSourceNames: make(map[string]struct{})}

	for _, source := range sources {
		if source.Name != "" {
			state.validSourceNames[source.Name] = struct{}{}
		}
	}

	savedGroup := ec.cachedFns[nameCurrentMergeGroup]
	savedKey := ec.cachedFns[nameCurrentMergeKey]
	ec.cachedFns[nameCurrentMergeGroup] = &xsltFunc{min: 0, max: 1, fn: state.currentGroup}
	ec.cachedFns[nameCurrentMergeKey] = &xsltFunc{min: 0, max: 0, fn: state.currentKey}

	return state, func() {
		if savedGroup != nil {
			ec.cachedFns[nameCurrentMergeGroup] = savedGroup
		} else {
			delete(ec.cachedFns, nameCurrentMergeGroup)
		}

		if savedKey != nil {
			ec.cachedFns[nameCurrentMergeKey] = savedKey
		} else {
			delete(ec.cachedFns, nameCurrentMergeKey)
		}
	}
}

func (ec *execContext) executeMergeGroups(ctx context.Context, inst *mergeInst, groups []mergeGroup) error {
	state, restoreFunctions := ec.installMergeFunctions(inst.Sources)
	defer restoreFunctions()

	// Save/restore context.
	savedCurrent := ec.currentNode
	savedContext := ec.contextNode
	savedPos := ec.position
	savedSize := ec.size
	savedInMerge := ec.inMergeAction

	ec.size = len(groups)
	defer func() {
		ec.currentNode = savedCurrent
		ec.contextNode = savedContext
		ec.position = savedPos
		ec.size = savedSize
		ec.inMergeAction = savedInMerge
	}()

	for i, g := range groups {
		ec.position = i + 1
		state.group = g

		// Context item is the first item in the group.
		if len(g.allItems) > 0 {
			if ni, ok := g.allItems[0].(xdm.NodeItem); ok {
				ec.currentNode = ni.Node
				ec.contextNode = ni.Node
			}
		}

		ec.inMergeAction = true
		ec.pushVarScope()

		for _, child := range inst.Action {
			if err := ec.executeInstruction(ctx, child); err != nil {
				ec.popVarScope()
				return err
			}
		}

		ec.popVarScope()
	}

	return nil
}

// gatherMergeSourceItems evaluates for-each-source or for-each-item and select
// for a single merge-source definition, returning one mergeSourceItems per
// source document/item. If for-each-source returns multiple URIs, each becomes
// a separate mergeSourceItems entry sharing the same source name.
func (ec *execContext) gatherMergeSourceItems(ctx context.Context, src *mergeSource) ([]mergeSourceItems, error) {
	switch {
	case src.ForEachSource != nil:
		return ec.gatherMergeDocuments(ctx, src)
	case src.ForEachItem != nil:
		return ec.gatherMergeItems(ctx, src)
	case src.Select != nil:
		result, err := ec.evalXPath(ctx, src.Select, ec.contextNode)
		if err != nil {
			return nil, err
		}

		source, err := ec.snapshotMergeSelection(ctx, src, result.Sequence())
		if err != nil {
			return nil, err
		}

		return []mergeSourceItems{source}, nil
	default:
		return nil, nil
	}
}

func (ec *execContext) gatherMergeDocuments(ctx context.Context, src *mergeSource) ([]mergeSourceItems, error) {
	uris, err := ec.evalXPath(ctx, src.ForEachSource, ec.contextNode)
	if err != nil {
		return nil, err
	}

	var sources []mergeSourceItems

	for item := range xdm.SequenceItems(uris.Sequence()) {
		source, err := ec.gatherMergeDocument(ctx, src, item)
		if err != nil {
			return nil, err
		}

		sources = append(sources, source)
	}

	return sources, nil
}

func (ec *execContext) gatherMergeDocument(ctx context.Context, src *mergeSource, uriItem xdm.Item) (mergeSourceItems, error) {
	atomic, err := xpath.AtomizeItem(uriItem)
	if err != nil {
		return mergeSourceItems{}, err
	}

	uri, err := xpath.AtomicToString(atomic)
	if err != nil {
		return mergeSourceItems{}, err
	}

	doc, err := ec.loadMergeDocument(ctx, uri, src.BaseURI)
	if err != nil {
		return mergeSourceItems{}, err
	}

	if err := ec.applyMergeSourceValidation(ctx, src, doc); err != nil {
		return mergeSourceItems{}, err
	}

	if err := ec.prepareMergeSourceAccumulators(ctx, src, doc); err != nil {
		return mergeSourceItems{}, err
	}

	selection, err := ec.evaluateMergeSelect(ctx, src, doc)
	if err != nil {
		return mergeSourceItems{}, err
	}

	return ec.snapshotMergeSelection(ctx, src, selection)
}

func (ec *execContext) gatherMergeItems(ctx context.Context, src *mergeSource) ([]mergeSourceItems, error) {
	items, err := ec.evalXPath(ctx, src.ForEachItem, ec.contextNode)
	if err != nil {
		return nil, err
	}

	var sources []mergeSourceItems

	for item := range xdm.SequenceItems(items.Sequence()) {
		selection, err := ec.selectMergeSourceItem(ctx, src, item)
		if err != nil {
			return nil, err
		}

		source, err := ec.snapshotMergeSelection(ctx, src, selection)
		if err != nil {
			return nil, err
		}

		sources = append(sources, source)
	}

	return sources, nil
}

func (ec *execContext) selectMergeSourceItem(ctx context.Context, src *mergeSource, item xdm.Item) (xdm.Sequence, error) {
	var node xdm.Node
	if value, ok := item.(xdm.NodeItem); ok {
		node = value.Node
		if err := ec.prepareMergeSourceAccumulators(ctx, src, node); err != nil {
			return nil, err
		}
	}

	if node == nil {
		return ec.evaluateMergeSelectOnItem(ctx, src, item)
	}

	return ec.evaluateMergeSelectOnNode(ctx, src, node)
}

func (ec *execContext) snapshotMergeSelection(ctx context.Context, src *mergeSource, selection xdm.Sequence) (mergeSourceItems, error) {
	items, err := ec.maybeSnapshotMergeItems(ctx, src, xdm.Materialize(selection))
	if err != nil {
		return mergeSourceItems{}, err
	}

	return mergeSourceItems{name: src.Name, items: items, sortBeforeMerge: src.SortBeforeMerge}, nil
}

// maybeSnapshotMergeItems replaces each selected node item of a streamable
// merge-source with its snapshot (XSLT 3.0 §18.2). A streaming merge only
// exposes a snapshot of each merged item — a deep copy of the item plus
// shallow copies of its ancestors — so a reverse-axis step (e.g.
// ancestor::record) from a merged item reaches the snapshot's ancestor shell,
// not the wider source tree. A non-streamable source keeps the live node so
// full-tree navigation works. Atomic items pass through unchanged.
func (ec *execContext) maybeSnapshotMergeItems(ctx context.Context, src *mergeSource, items xdm.ItemSlice) (xdm.ItemSlice, error) {
	if !src.StreamableAttr || len(items) == 0 {
		return items, nil
	}

	snapped := make(xdm.ItemSlice, 0, len(items))
	for _, item := range items {
		ni, ok := item.(xdm.NodeItem)
		if !ok {
			snapped = append(snapped, item)
			continue
		}

		node, err := ec.snapshotNode(ctx, ni.Node)
		if err != nil {
			return nil, err
		}
		// snapshotNode transfers the source node's PSVI type annotation onto
		// the copy (in ec.typeAnnotations); carry it onto the NodeItem too so
		// schema-aware tests (instance of schema-element(...), etc.) see it.
		ann := ni.TypeAnnotation
		if ann == "" {
			ann = ec.typeAnnotations[node]
		}

		snapped = append(snapped, xdm.NodeItem{Node: node, TypeAnnotation: ann})
	}

	return snapped, nil
}

func (ec *execContext) storeAccumulatorSnapshot(dst map[xdm.Node]map[string]xdm.Sequence, dstErr map[xdm.Node]map[string]error, node xdm.Node, state map[string]xdm.Sequence, stateErr map[string]error) {
	if node == nil {
		return
	}
	// Merge new state into existing snapshot (preserving values from
	// other packages' accumulators that were computed earlier).
	// Use package-scoped keys to isolate same-named accumulators.
	existing := dst[node]
	if existing == nil {
		existing = make(map[string]xdm.Sequence, len(state))
		dst[node] = existing
	}

	for k, v := range state {
		existing[ec.accumulatorStateKey(k)] = cloneXPathSequence(v)
	}

	if len(stateErr) > 0 {
		existingErr := dstErr[node]
		if existingErr == nil {
			existingErr = make(map[string]error, len(stateErr))
			dstErr[node] = existingErr
		}

		for k, v := range stateErr {
			existingErr[ec.accumulatorStateKey(k)] = v
		}
	}
}

func (ec *execContext) prepareMergeSourceAccumulators(ctx context.Context, src *mergeSource, node xdm.Node) error {
	if len(src.UseAccumulators) == 0 || len(ec.effectiveAccumulators()) == 0 || node == nil {
		return nil
	}

	doc := node.OwnerDocument()
	if docNode, ok := node.(*xdm.Document); ok {
		doc = docNode
	}

	if doc == nil {
		return nil
	}

	if ec.accumulatorBeforeByNode != nil {
		if _, ok := ec.accumulatorBeforeByNode[doc]; ok {
			return nil
		}
	}

	// Set activeAccumulators to restrict accumulator access (XTDE3362)
	// to only those declared in use-accumulators on the merge-source.
	savedActiveAccums := ec.activeAccumulators

	ec.activeAccumulators = make(map[string]struct{}, len(src.UseAccumulators))
	for _, name := range src.UseAccumulators {
		ec.activeAccumulators[name] = struct{}{}
	}

	defer func() { ec.activeAccumulators = savedActiveAccums }()

	names := append([]string(nil), ec.effectiveStylesheet().accumulatorOrder...)

	return ec.computeAccumulatorStates(ctx, doc, names)
}

func (ec *execContext) prepareSourceDocumentAccumulators(ctx context.Context, inst *sourceDocumentInst, doc xdm.Node) error {
	if len(inst.UseAccumulators) == 0 || len(ec.effectiveAccumulators()) == 0 || doc == nil {
		return nil
	}

	if ec.accumulatorBeforeByNode != nil {
		if _, ok := ec.accumulatorBeforeByNode[doc]; ok {
			return nil
		}
	}

	names := append([]string(nil), ec.effectiveStylesheet().accumulatorOrder...)

	return ec.computeAccumulatorStates(ctx, doc, names)
}

func (ec *execContext) computeAccumulatorStates(ctx context.Context, doc xdm.Node, names []string) error {
	if ec.accumulatorBeforeByNode == nil {
		ec.accumulatorBeforeByNode = make(map[xdm.Node]map[string]xdm.Sequence)
	}

	if ec.accumulatorAfterByNode == nil {
		ec.accumulatorAfterByNode = make(map[xdm.Node]map[string]xdm.Sequence)
	}

	if ec.accumulatorBeforeErrorByNode == nil {
		ec.accumulatorBeforeErrorByNode = make(map[xdm.Node]map[string]error)
	}

	if ec.accumulatorAfterErrorByNode == nil {
		ec.accumulatorAfterErrorByNode = make(map[xdm.Node]map[string]error)
	}

	state := make(map[string]xdm.Sequence, len(names))

	stateErr := make(map[string]error, len(names))
	for _, name := range names {
		def, ok := ec.effectiveAccumulators()[name]
		if !ok {
			continue
		}

		switch {
		case def.Initial != nil:
			result, err := ec.evalXPath(ctx, def.Initial, doc)
			if err != nil {
				stateErr[name] = err
				state[name] = xdm.EmptySequence()

				continue
			}

			checked, err := ec.checkAccumulatorType(ctx, def, result.Sequence())
			if err != nil {
				stateErr[name] = err
				state[name] = xdm.EmptySequence()

				continue
			}

			state[name] = cloneAccumulatorSequence(checked)
		case len(def.InitialBody) > 0:
			seq, err := ec.evaluateBodyAsSequence(ctx, def.InitialBody)
			if err != nil {
				stateErr[name] = err
				state[name] = xdm.EmptySequence()

				continue
			}

			checked, err := ec.checkAccumulatorType(ctx, def, seq)
			if err != nil {
				stateErr[name] = err
				state[name] = xdm.EmptySequence()

				continue
			}

			state[name] = cloneAccumulatorSequence(checked)
		default:
			state[name] = xdm.EmptySequence()
		}
	}

	savedState := ec.accumulatorState
	savedStateErr := ec.accumulatorStateError
	savedCurrent := ec.currentNode
	savedContext := ec.contextNode
	savedItem := ec.contextItem
	savedEval := ec.evaluatingAccumulator
	ec.accumulatorState = state
	ec.accumulatorStateError = stateErr
	ec.currentNode = doc
	ec.contextNode = doc
	ec.contextItem = nil

	ec.evaluatingAccumulator = true
	defer func() {
		ec.accumulatorState = savedState
		ec.accumulatorStateError = savedStateErr
		ec.currentNode = savedCurrent
		ec.contextNode = savedContext
		ec.contextItem = savedItem
		ec.evaluatingAccumulator = savedEval
	}()

	return ec.walkAccumulatorTree(ctx, doc, names)
}

func (ec *execContext) walkAccumulatorTree(ctx context.Context, node xdm.Node, names []string) error {
	// Fire start-phase rules first, then snapshot "before" state.
	// Per XSLT 3.0 §14.1, accumulator-before() returns the value AFTER start-phase
	// rules for the current node have fired (i.e., the value "before" descending into
	// the node's children), not the value before the node's own rules run.
	if err := ec.applyAccumulatorPhase(ctx, node, names, "start"); err != nil {
		return err
	}

	ec.storeAccumulatorSnapshot(ec.accumulatorBeforeByNode, ec.accumulatorBeforeErrorByNode, node, ec.accumulatorState, ec.accumulatorStateError)

	// Only XDM nodes take part: a DOCTYPE declaration or an entity reference
	// is not a child of its parent in XDM, and neither is anything under it.
	for child := range xdm.Children(node) {
		if !xdm.IsXDMChild(child) {
			continue
		}

		if err := ec.walkAccumulatorTree(ctx, child, names); err != nil {
			return err
		}
	}

	if err := ec.applyAccumulatorPhase(ctx, node, names, "end"); err != nil {
		return err
	}

	ec.storeAccumulatorSnapshot(ec.accumulatorAfterByNode, ec.accumulatorAfterErrorByNode, node, ec.accumulatorState, ec.accumulatorStateError)

	return nil
}

func (ec *execContext) applyAccumulatorPhase(ctx context.Context, node xdm.Node, names []string, phase string) error {
	savedCurrent := ec.currentNode
	savedContext := ec.contextNode
	savedItem := ec.contextItem
	ec.currentNode = node
	ec.contextNode = node

	ec.contextItem = nil
	defer func() {
		ec.currentNode = savedCurrent
		ec.contextNode = savedContext
		ec.contextItem = savedItem
	}()

	for _, name := range names {
		def, ok := ec.effectiveAccumulators()[name]
		if !ok {
			continue
		}

		if _, hasError := ec.accumulatorStateError[name]; hasError {
			continue
		}

		if err := ec.applyAccumulatorRules(ctx, node, name, def, phase); err != nil {
			return err
		}
	}

	return nil
}

func (ec *execContext) applyAccumulatorRules(ctx context.Context, node xdm.Node, name string, def *accumulatorDef, phase string) error {
	for _, rule := range def.Rules {
		if rule.Phase != phase || !rule.Match.matchPattern(ctx, ec, node) {
			continue
		}

		if def.CyclicDeps {
			return dynamicError(errCodeXTDE3400,
				"accumulator %q has a cyclic dependency on itself or other accumulators", def.Name)
		}

		value, err := ec.evaluateAccumulatorRule(ctx, node, name, rule)
		if err == nil {
			value, err = ec.checkAccumulatorType(ctx, def, value)
		}

		if err != nil {
			if ec.accumulatorStateError == nil {
				ec.accumulatorStateError = make(map[string]error)
			}

			ec.accumulatorStateError[name] = err

			break
		}

		ec.accumulatorState[name] = value
	}

	return nil
}

func (ec *execContext) evaluateAccumulatorRule(ctx context.Context, node xdm.Node, name string, rule *accumulatorRule) (xdm.Sequence, error) {
	currentValue := ec.accumulatorState[name]
	if rule.New {
		currentValue = xdm.EmptySequence()
	}

	ec.pushVarScope()
	ec.setVar("value", currentValue)
	ec.temporaryOutputDepth++

	defer func() {
		ec.temporaryOutputDepth--
		ec.popVarScope()
	}()

	switch {
	case rule.Select != nil:
		result, err := ec.evalXPath(ctx, rule.Select, node)
		if err != nil {
			return nil, err
		}

		return cloneAccumulatorSequence(result.Sequence()), nil
	case len(rule.Body) > 0:
		return ec.evaluateBodyAsSequence(ctx, rule.Body)
	default:
		return xdm.EmptySequence(), nil
	}
}

func (ec *execContext) checkAccumulatorType(ctx context.Context, def *accumulatorDef, seq xdm.Sequence) (xdm.Sequence, error) {
	if def == nil || def.As == "" {
		return seq, nil
	}

	return checkSequenceType(ctx, seq, parseSequenceType(def.As), "XPTY0004", "accumulator "+def.Name, ec)
}

// applyMergeSourceValidation applies xsl:merge-source/@validation and @type to
// a loaded merge document. A named @type or strict/lax validation validates the
// document against the imported schemas, annotating its nodes with their schema
// types and recording nilled elements, so downstream schema-aware expressions
// (e.g. "current-merge-group() instance of schema-element(X)*") see the PSVI
// type information. Mirrors xsl:source-document validation.
func (ec *execContext) applyMergeSourceValidation(ctx context.Context, src *mergeSource, doc *xdm.Document) error {
	return nil
}

// loadMergeDocument loads an XML document from a URI, resolving it relative
// to the given effective base URI (which accounts for xml:base).
func (ec *execContext) loadMergeDocument(ctx context.Context, uri string, effectiveBaseURI string) (*xdm.Document, error) {
	// Resolve URI relative to the effective base URI.
	effectiveBase := effectiveBaseURI
	if effectiveBase == "" {
		effectiveBase = ec.stylesheet.baseURI
	}

	resolvedURI := resolveAgainstBaseURI(uri, effectiveBase)

	mergeCacheKey := ec.docCacheKey(resolvedURI)
	if doc, ok := ec.docCache[mergeCacheKey]; ok {
		return ec.existingDocumentRead(ctx, doc)
	}

	reader, err := ec.retrieveDocumentReader(ctx, resolvedURI)
	if err != nil {
		if _, hostFailure := errors.AsType[*xdm.ResourceAccessError](err); hostFailure {
			return nil, err
		}

		return nil, dynamicErrorCause(errCodeFODC0002, err, "xsl:merge cannot load %q: %v", uri, err)
	}

	doc, err := parseXMLResource(ctx, ec.inputParseOptions(), reader, resolvedURI, ec.resourceLimit())
	if err != nil {
		return nil, dynamicErrorCause(errCodeFODC0002, err, "xsl:merge cannot parse %q: %v", uri, err)
	}

	// Apply xsl:strip-space.
	if len(ec.effectiveStripSpace()) > 0 {
		ec.stripWhitespaceFromDoc(doc)
	}

	if ec.docCache == nil {
		ec.docCache = make(map[string]*xdm.Document)
	}

	ec.docCache[mergeCacheKey] = doc

	return doc, nil
}

// evaluateMergeSelect evaluates the select expression of a merge source
// against a loaded document.
func (ec *execContext) evaluateMergeSelect(ctx context.Context, src *mergeSource, doc *xdm.Document) (xdm.Sequence, error) {
	if src.Select == nil {
		return xdm.ItemSlice{xdm.NodeItem{Node: doc}}, nil
	}

	savedSource := ec.sourceDoc
	savedContext := ec.contextNode
	savedCurrent := ec.currentNode
	ec.sourceDoc = doc
	ec.contextNode = doc

	ec.currentNode = doc
	defer func() {
		ec.sourceDoc = savedSource
		ec.contextNode = savedContext
		ec.currentNode = savedCurrent
	}()

	result, err := ec.evalXPath(ctx, src.Select, doc)
	if err != nil {
		return nil, err
	}

	return result.Sequence(), nil
}

// evaluateMergeSelectOnNode evaluates the select expression of a merge source
// against a specific node (used with for-each-item).
func (ec *execContext) evaluateMergeSelectOnNode(ctx context.Context, src *mergeSource, node xdm.Node) (xdm.Sequence, error) {
	if src.Select == nil {
		if node != nil {
			return xdm.ItemSlice{xdm.NodeItem{Node: node}}, nil
		}

		return xdm.EmptySequence(), nil
	}

	savedSource := ec.sourceDoc
	savedContext := ec.contextNode

	savedCurrent := ec.currentNode
	if doc, ok := node.(*xdm.Document); ok {
		ec.sourceDoc = doc
	}

	ec.contextNode = node

	ec.currentNode = node
	defer func() {
		ec.sourceDoc = savedSource
		ec.contextNode = savedContext
		ec.currentNode = savedCurrent
	}()

	result, err := ec.evalXPath(ctx, src.Select, node)
	if err != nil {
		return nil, err
	}

	return result.Sequence(), nil
}

// evaluateMergeSelectOnItem evaluates the select expression for a merge source
// with an atomic item as the context item (used with for-each-item when the
// items are not nodes).
func (ec *execContext) evaluateMergeSelectOnItem(ctx context.Context, src *mergeSource, item xdm.Item) (xdm.Sequence, error) {
	if src.Select == nil {
		return xdm.ItemSlice{item}, nil
	}

	savedItem := ec.contextItem

	ec.contextItem = item
	defer func() {
		ec.contextItem = savedItem
	}()

	result, err := ec.evalXPath(ctx, src.Select, nil)
	if err != nil {
		return nil, err
	}

	return result.Sequence(), nil
}

// evaluateMergeKeys evaluates the merge key expressions for all items in a source.
func (ec *execContext) evaluateMergeKeys(ctx context.Context, src *mergeSourceItems, keyDefs []*mergeKey) ([][]mergeKeyValue, error) {
	keys := make([][]mergeKeyValue, len(src.items))

	savedContext := ec.contextNode
	savedCurrent := ec.currentNode
	savedItem := ec.contextItem

	savedMergeKey := ec.evaluatingMergeKey
	defer func() {
		ec.contextNode = savedContext
		ec.currentNode = savedCurrent
		ec.contextItem = savedItem
		ec.evaluatingMergeKey = savedMergeKey
	}()

	for i, item := range src.items {
		itemKeys := make([]mergeKeyValue, len(keyDefs))

		var node xdm.Node

		if ni, ok := item.(xdm.NodeItem); ok {
			node = ni.Node
			ec.contextNode = node
			ec.currentNode = node
			ec.contextItem = nil
		} else {
			// Atomic item (e.g., string from unparsed-text-lines).
			ec.contextItem = item
		}

		for k, key := range keyDefs {
			value, err := ec.evaluateSingleMergeKey(ctx, key, node)
			if err != nil {
				return nil, err
			}

			itemKeys[k] = value
		}

		keys[i] = itemKeys
	}

	return keys, nil
}

func (ec *execContext) evaluateSingleMergeKey(ctx context.Context, mk *mergeKey, node xdm.Node) (mergeKeyValue, error) {
	if mk.Select == nil && len(mk.Body) == 0 {
		return mergeKeyValue{}, nil
	}

	seq, err := ec.evaluateMergeKeySequence(ctx, mk, node)
	if err != nil {
		return mergeKeyValue{}, err
	}

	return mergeKeyFromSequence(seq)
}

func mergeKeyFromSequence(seq xdm.Sequence) (mergeKeyValue, error) {
	atoms, err := xpath.AtomizeSequence(seq)
	if err != nil {
		return mergeKeyValue{}, err
	}

	// XTTE1020: cardinality is checked after atomization, including arrays.
	if len(atoms) > 1 {
		return mergeKeyValue{}, dynamicError(errCodeXTTE1020, "xsl:merge-key select expression must return a single atomic value, got %d items", len(atoms))
	}

	if len(atoms) == 1 {
		return mergeKeyValue{atom: atoms[0]}, nil
	}

	return mergeKeyValue{}, nil
}

func (ec *execContext) evaluateMergeKeySequence(ctx context.Context, mk *mergeKey, node xdm.Node) (xdm.Sequence, error) {
	var seq xdm.Sequence

	if mk.Select != nil {
		ec.evaluatingMergeKey = true
		result, err := ec.evalXPath(ctx, mk.Select, node)
		ec.evaluatingMergeKey = false

		if err != nil {
			return nil, err
		}

		seq = result.Sequence()
	} else {
		// Body evaluation: runs in temporary output state.
		ec.temporaryOutputDepth++
		bodySeq, err := ec.evaluateBodyAsSequence(ctx, mk.Body)
		ec.temporaryOutputDepth--

		if err != nil {
			return nil, err
		}

		seq = bodySeq
	}

	return seq, nil
}

// nWayMerge performs an n-way merge of pre-sorted sources, grouping items
// that share the same key values. Returns XTTE2230 if keys from different
// sources are not comparable.
func (ec *execContext) nWayMerge(sources []mergeSourceItems, orders []mergeKeyOrder) ([]mergeGroup, error) {
	cursors := make([]int, len(sources))

	var groups []mergeGroup

	for {
		keys, found, err := minimumMergeKeys(sources, cursors, orders)
		if err != nil {
			return nil, err
		}

		if !found {
			break
		}

		group, err := collectMergeGroup(sources, cursors, keys, orders)
		if err != nil {
			return nil, err
		}

		if len(keys) > 0 {
			group.key = mergeKeyValuesToSequence(keys)
		}

		groups = append(groups, group)
	}

	return groups, nil
}

func minimumMergeKeys(sources []mergeSourceItems, cursors []int, orders []mergeKeyOrder) ([]mergeKeyValue, bool, error) {
	// Find the minimum key across all sources at their current cursor.
	var minKeys []mergeKeyValue

	minFound := false

	for si, src := range sources {
		if cursors[si] >= len(src.items) {
			continue // exhausted
		}

		curKeys := src.keys[cursors[si]]
		if !minFound {
			minKeys = curKeys
			minFound = true
		} else {
			cmp, err := compareMergeKeyValues(curKeys, minKeys, orders)
			if err != nil {
				return nil, false, err
			}

			if cmp < 0 {
				minKeys = curKeys
			}
		}
	}

	return minKeys, minFound, nil
}

func collectMergeGroup(sources []mergeSourceItems, cursors []int, minKeys []mergeKeyValue, orders []mergeKeyOrder) (mergeGroup, error) {
	g := mergeGroup{
		byName: make(map[string]xdm.ItemSlice),
	}

	for si, src := range sources {
		for cursors[si] < len(src.items) {
			curKeys := src.keys[cursors[si]]

			cmp, err := compareMergeKeyValues(curKeys, minKeys, orders)
			if err != nil {
				return mergeGroup{}, err
			}

			if cmp != 0 {
				break
			}

			item := src.items[cursors[si]]

			g.allItems = append(g.allItems, item)
			if src.name != "" {
				g.byName[src.name] = append(g.byName[src.name], item)
			}

			cursors[si]++
		}
	}

	return g, nil
}

// mergeKeyValuesToSequence converts the merge key tuple to the XPath sequence
// exposed by current-merge-key().
func mergeKeyValuesToSequence(keys []mergeKeyValue) xdm.Sequence {
	seq := make(xdm.ItemSlice, 0, len(keys))
	for _, mkv := range keys {
		seq = append(seq, xdm.Materialize(mergeKeyValueToSequence(mkv))...)
	}

	return seq
}

func mergeKeyValueToSequence(mkv mergeKeyValue) xdm.Sequence {
	if mkv.atom.TypeName != "" {
		return xdm.SingleAtomic(mkv.atom)
	}

	if mkv.str != "" {
		return xdm.SingleString(mkv.str)
	}

	return xdm.EmptySequence()
}

// resolveMergeKeyCollation resolves the collation URI for a merge key
// definition at runtime. Returns nil compare function if no collation is
// specified or if the collation is the default codepoint collation.
// Raises XTDE2220 if the collation URI is not recognized.
func (ec *execContext) resolveMergeKeyCollation(ctx context.Context, mk *mergeKey) (func(a, b string) int, error) {
	cmpFn, _, err := ec.resolveMergeKeyCollationURI(ctx, mk)
	return cmpFn, err
}

// resolveMergeKeyCollationURI is like resolveMergeKeyCollation but also
// returns the resolved collation URI string for inspection.
func (ec *execContext) resolveMergeKeyCollationURI(ctx context.Context, mk *mergeKey) (func(a, b string) int, string, error) {
	collURI := mk.Collation
	if mk.CollationAVT != nil {
		evaluated, err := mk.CollationAVT.evaluate(ctx, ec.contextNode)
		if err != nil {
			return nil, "", err
		}

		collURI = evaluated
	}

	if collURI == "" {
		// No explicit collation — use lang/case-order to build a UCA URI.
		if mk.Lang != "" {
			collURI = "http://www.w3.org/2013/collation/UCA?lang=" + mk.Lang
			switch mk.CaseOrder {
			case nameUpperFirst:
				collURI += ";caseFirst=upper"
			case nameLowerFirst:
				collURI += ";caseFirst=lower"
			}
		}
	}

	if collURI == "" || collURI == "http://www.w3.org/2005/xpath-functions/collation/codepoint" {
		return nil, collURI, nil
	}

	cmpFn, err := xpath.ResolveCollationCompareFunc(collURI)
	if err != nil {
		return nil, collURI, dynamicError(errCodeXTDE2220, "unsupported collation URI %q: %v", collURI, err)
	}

	return cmpFn, collURI, nil
}

// compareMergeKeyValues compares two merge key value arrays using the
// specified orders. Returns -1, 0, or +1. Returns an error (XTTE2230)
// when keys from different sources have incompatible types.
func compareMergeKeyValues(a, b []mergeKeyValue, orders []mergeKeyOrder) (int, error) {
	for i, ord := range orders {
		if i >= len(a) || i >= len(b) {
			break
		}

		c, err := compareSingleMergeKey(a[i], b[i])
		if err != nil {
			return 0, err
		}

		if ord.desc {
			c = -c
		}

		if c != 0 {
			return c, nil
		}
	}

	return 0, nil
}

// compareSingleMergeKey compares two single merge key values.
// Returns XTTE2230 when the key types are incomparable.
func compareSingleMergeKey(a, b mergeKeyValue) (int, error) {
	// Numeric mode: use float64 comparison with NaN handling.
	if a.numeric || b.numeric {
		return compareNumericMergeKey(a, b), nil
	}

	// If both have typed atomic values, use XPath value comparison.
	if a.atom.TypeName != "" && b.atom.TypeName != "" {
		lt, err := xpath.ValueCompare(xpath.TokenLt, a.atom, b.atom)
		if err == nil {
			if lt {
				return -1, nil
			}

			eq, err2 := xpath.ValueCompare(xpath.TokenEq, a.atom, b.atom)
			if err2 == nil && eq {
				return 0, nil
			}

			return 1, nil
		}
		// Types are incomparable — raise XTTE2230.
		return 0, dynamicError(errCodeXTTE2230, "merge keys are not comparable: %s vs %s", a.atom.TypeName, b.atom.TypeName)
	}

	// Fall back to string comparison.
	aStr := a.str
	bStr := b.str

	if a.atom.TypeName != "" {
		s, err := xpath.AtomicToString(a.atom)
		if err == nil {
			aStr = s
		}
	}

	if b.atom.TypeName != "" {
		s, err := xpath.AtomicToString(b.atom)
		if err == nil {
			bStr = s
		}
	}
	// Use collation compare function if available.
	cmpFn := a.collCompare
	if cmpFn == nil {
		cmpFn = b.collCompare
	}

	if cmpFn != nil {
		return cmpFn(aStr, bStr), nil
	}

	if aStr < bStr {
		return -1, nil
	}

	if aStr > bStr {
		return 1, nil
	}

	return 0, nil
}

func compareNumericMergeKey(a, b mergeKeyValue) int {
	aNaN := a.isNaN

	bNaN := b.isNaN
	if aNaN && bNaN {
		return 0
	}

	if aNaN {
		return -1 // NaN sorts before non-NaN in ascending
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

func cloneAccumulatorSequence(seq xdm.Sequence) xdm.Sequence {
	if seq == nil || xdm.SequenceLen(seq) == 0 {
		return nil
	}

	return append(xdm.ItemSlice(nil), xdm.Materialize(seq)...)
}

// mergeGroup represents one group of items that share the same merge key tuple.
type mergeGroup struct {
	key      xdm.Sequence             // the merge key tuple for current-merge-key()
	allItems xdm.ItemSlice            // all items across all sources
	byName   map[string]xdm.ItemSlice // items per named source
}

type mergeActionState struct {
	ec               *execContext
	group            mergeGroup
	validSourceNames map[string]struct{}
}

func (state *mergeActionState) currentGroup(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if !state.ec.inMergeAction || xpath.IsDynamicCall(ctx) {
		return nil, dynamicError(errCodeXTDE3480, "current-merge-group() is not available outside the body of xsl:merge-action")
	}

	if len(args) == 0 || args[0] == nil || xdm.SequenceLen(args[0]) == 0 {
		return state.group.allItems, nil
	}

	atomic, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return nil, dynamicError(errCodeXTDE3490, "current-merge-group(): cannot atomize argument: %v", err)
	}

	name, err := xpath.AtomicToString(atomic)
	if err != nil {
		return nil, dynamicError(errCodeXTDE3490, "current-merge-group(): cannot convert argument to string: %v", err)
	}

	if _, ok := state.validSourceNames[name]; !ok {
		return nil, dynamicError(errCodeXTDE3490, "current-merge-group(%q): no xsl:merge-source with this name", name)
	}

	if items, ok := state.group.byName[name]; ok {
		return items, nil
	}

	return xdm.EmptySequence(), nil
}

func (state *mergeActionState) currentKey(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	if !state.ec.inMergeAction || xpath.IsDynamicCall(ctx) {
		return nil, dynamicError(errCodeXTDE3510, "current-merge-key() is not available outside the body of xsl:merge-action")
	}

	return state.group.key, nil
}

func cloneAccumulatorSnapshot(state map[string]xdm.Sequence) map[string]xdm.Sequence {
	if len(state) == 0 {
		return nil
	}

	snapshot := make(map[string]xdm.Sequence, len(state))
	for name, value := range state {
		snapshot[name] = cloneAccumulatorSequence(value)
	}

	return snapshot
}
