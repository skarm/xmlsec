// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type keyEntry struct {
	key  xdm.AtomicValue
	node xdm.Node
}

// compositeKeyEntry stores a composite key (sequence of atomic values) alongside
// the node it indexes.
type compositeKeyEntry struct {
	keys []xdm.AtomicValue
	node xdm.Node
}

type keyTable struct {
	defs           []*keyDef
	entries        map[string][]keyEntry          // canonicalKey -> entries (non-composite)
	compositeEntry map[string][]compositeKeyEntry // compositeCanonical -> entries (composite)
	collationKey   func(string) string            // collation key function (nil = codepoint)
	collationCmp   func(string, string) int       // collation compare function (nil = codepoint)
	compat         bool                           // any definition enables backwards-compatible processing
	building       bool
	built          bool
}

func newKeyTable(defs []*keyDef) (*keyTable, error) {
	table := &keyTable{
		defs: defs, entries: make(map[string][]keyEntry),
		compat: !defs[0].Composite && keyDefinitionsCompatible(defs), building: true,
	}
	if err := buildKeyTableCollation(defs, table); err != nil {
		return nil, err
	}

	if defs[0].Composite {
		table.compositeEntry = make(map[string][]compositeKeyEntry)
	}

	return table, nil
}

func keyDefinitionsCompatible(defs []*keyDef) bool {
	for _, def := range defs {
		if def.Compat {
			return true
		}
	}

	return false
}

func buildKeyTableCollation(defs []*keyDef, kt *keyTable) error {
	if defs[0].Collation != "" {
		keyFn, keyErr := xpath.ResolveCollationKeyFunc(defs[0].Collation)
		if keyErr != nil {
			return keyErr
		}

		cmpFn, cmpErr := xpath.ResolveCollationCompareFunc(defs[0].Collation)
		if cmpErr != nil {
			return cmpErr
		}

		kt.collationKey = keyFn
		kt.collationCmp = cmpFn
	}

	return nil
}

// keyCompatCast casts an atomized key value to xs:string for a
// backwards-compatible key (§16.3): both the indexed use value and the key()
// lookup value are compared as strings. A cast failure leaves the value
// unchanged so it simply fails to match.
func keyCompatCast(av xdm.AtomicValue, xpath10 bool) xdm.AtomicValue {
	if xpath10 {
		s, err := xpath.XPath10String(xdm.ItemSlice{av})
		if err == nil {
			return xdm.AtomicValue{TypeName: xdm.TypeString, Value: s}
		}

		return av
	}

	if s, err := xpath.CastAtomic(av, xdm.TypeString); err == nil {
		return s
	}

	return av
}

// collationCanonicalKey produces a canonical key using the collation key
// function for string/untypedAtomic types. Falls back to canonicalKey
// for non-string types.
func collationCanonicalKey(av xdm.AtomicValue, keyFn func(string) string) string {
	if keyFn == nil {
		return canonicalKey(av)
	}

	switch av.TypeName {
	case xdm.TypeUntypedAtomic, xdm.TypeString,
		xdm.TypeNormalizedString, xdm.TypeToken,
		xdm.TypeLanguage, xdm.TypeName, xdm.TypeNCName,
		xdm.TypeNMTOKEN, xdm.TypeNMTOKENS,
		xdm.TypeENTITY, xdm.TypeID, xdm.TypeIDREF, xdm.TypeIDREFS,
		xdm.TypeAnyURI:
		s, _ := xpath.AtomicToString(av)
		return "S:" + keyFn(s)
	default:
		return canonicalKey(av)
	}
}

// canonicalKey produces a hash key that groups potentially-equal values
// into the same bucket. Typed comparison refines matches within a bucket.
// Values that could be equal under XPath eq semantics (including
// untypedAtomic promotion) must share the same canonical key.
func canonicalKey(av xdm.AtomicValue) string {
	if qv, ok := canonicalQNameValue(av); ok {
		// QName equality is based on URI and local name, not lexical prefix.
		return xdm.TypeQName + ":" + qv.URI + "\x00" + qv.Local
	}

	// For date/time types, normalize to UTC so that equivalent instants
	// in different timezones share the same canonical key.
	switch av.TypeName {
	case xdm.TypeDateTime, xdm.TypeDateTimeStamp:
		if t, ok := av.Value.(time.Time); ok {
			return "DT:" + t.UTC().Format(time.RFC3339Nano)
		}
	case xdm.TypeDate:
		if t, ok := av.Value.(time.Time); ok {
			return "D:" + t.UTC().Format("2006-01-02Z07:00")
		}
	case xdm.TypeTime:
		if t, ok := av.Value.(time.Time); ok {
			return "T:" + t.UTC().Format("15:04:05.999999999Z07:00")
		}
	}

	s, _ := xpath.AtomicToString(av)
	// Group numerics together so integer 4 and double 4.0 can be
	// compared in the same bucket. The bucket deliberately loses precision;
	// typed comparison must refine collisions before a node is selected.
	if av.IsNumeric() {
		// Value comparison can promote either operand to xs:float. Keep all
		// potentially equal values together, then refine using their original types.
		f := float64(float32(av.ToFloat64()))
		if math.IsNaN(f) {
			return "N:NaN"
		}

		if f == 0 {
			return "N:0"
		}

		return "N:" + strconv.FormatFloat(f, 'g', -1, 64)
	}
	// Group untypedAtomic, string, and all string-derived types together
	// since untypedAtomic is promoted to string for eq comparison.
	switch av.TypeName {
	case xdm.TypeUntypedAtomic, xdm.TypeString,
		xdm.TypeNormalizedString, xdm.TypeToken,
		xdm.TypeLanguage, xdm.TypeName, xdm.TypeNCName,
		xdm.TypeNMTOKEN, xdm.TypeNMTOKENS,
		xdm.TypeENTITY, xdm.TypeID, xdm.TypeIDREF, xdm.TypeIDREFS,
		xdm.TypeAnyURI:
		return "S:" + s
	}

	return av.TypeName + ":" + s
}

func canonicalQNameValue(av xdm.AtomicValue) (xdm.QNameValue, bool) {
	if qv, ok := av.Value.(xdm.QNameValue); ok {
		return qv, true
	}

	promoted := xdm.PromoteSchemaType(av)

	qv, ok := promoted.Value.(xdm.QNameValue)
	if !ok || promoted.TypeName != xdm.TypeQName {
		return xdm.QNameValue{}, false
	}

	return qv, true
}

// compositeCanonicalKey produces a canonical key for a sequence of atomic values
// used as a composite key. Individual canonical keys are joined with NUL bytes.
// When keyFn is non-nil, string-like values use the collation key function.
func compositeCanonicalKey(avs []xdm.AtomicValue, keyFn func(string) string) string {
	parts := make([]string, len(avs))
	for i, av := range avs {
		parts[i] = collationCanonicalKey(av, keyFn)
	}

	return strings.Join(parts, "\x00")
}

// buildKeyTable builds or retrieves a key table for the given key name
// scoped to the given document root.
func (ec *execContext) buildKeyTable(ctx context.Context, name string, root xdm.Node) (*keyTable, error) {
	if ec.keyTables == nil {
		ec.keyTables = make(map[string]*keyTable)
	}

	// Isolate each key by document identity and owning package.
	cacheKey := fmt.Sprintf("%s@%p@%p", name, root, ec.currentPackage)

	table, err := ec.cachedKeyTable(cacheKey, name)
	if err != nil {
		return nil, err
	}

	if table != nil {
		return table, nil
	}

	defs, ok := ec.effectiveKeys()[name]
	if !ok || len(defs) == 0 {
		return nil, dynamicError(errCodeXTDE1260, "unknown key %q", name)
	}

	table, err = newKeyTable(defs)
	if err != nil {
		return nil, err
	}

	ec.keyTables[cacheKey] = table
	defer ec.pushAbsentGroupingContext()()

	ctx = xpath.WithoutDynamicCall(ctx)
	savedOutputURI := ec.currentOutputURI

	ec.currentOutputURI = ec.baseOutputURI
	defer func() { ec.currentOutputURI = savedOutputURI }()

	// A key declaration has global variable scope and singleton focus, with
	// no current template rule or inherited mode from the calling template.
	savedVars, savedTemplate := ec.localVars, ec.currentTemplate
	savedMode, savedModePackage := ec.currentMode, ec.currentModePackage
	savedPosition, savedSize := ec.position, ec.size
	ec.localVars = nil
	ec.localVarsVer++
	ec.setCurrentTemplate(nil)
	ec.currentMode, ec.currentModePackage = "", ec.effectiveStylesheet()

	ec.position, ec.size = 1, 1
	defer func() {
		ec.localVars = savedVars
		ec.localVarsVer++
		ec.setCurrentTemplate(savedTemplate)
		ec.currentMode, ec.currentModePackage = savedMode, savedModePackage
		ec.position, ec.size = savedPosition, savedSize
	}()

	// Restore all focus fields, including an outer atomic context item.
	savedContext, savedCurrent, savedItem := ec.contextNode, ec.currentNode, ec.contextItem
	defer func() {
		ec.contextNode, ec.currentNode, ec.contextItem = savedContext, savedCurrent, savedItem
	}()

	builder := keyIndexBuilder{
		ec: ec, table: table, composite: defs[0].Composite,
		seen: make(map[indexedKeyNode][][]xdm.AtomicValue),
	}

	err = indexKeyTree(ctx, root, keyDefinitionsMatchAttributes(defs), keyDefinitionsMatchNamespaces(defs), func(node xdm.Node) error {
		return builder.indexNode(ctx, node)
	})
	if err != nil {
		delete(ec.keyTables, cacheKey)

		return nil, err
	}

	table.building, table.built = false, true

	return table, nil
}

func keyDefinitionsMatchAttributes(defs []*keyDef) bool {
	for _, def := range defs {
		if def.Match.matchesAttributes() {
			return true
		}
	}

	return false
}

func keyDefinitionsMatchNamespaces(defs []*keyDef) bool {
	for _, def := range defs {
		if def.Match.matchesNamespaceNodes() {
			return true
		}
	}

	return false
}

// indexKeyTree calls indexNode on root and on each XDM descendant of root in
// document order, as the descendant-or-self axis selects them, and also on
// the attributes (needsAttrs) and in-scope namespace nodes (needsNSNodes) of
// each element right after the element. A cancelled context ends the walk
// with its error.
func indexKeyTree(ctx context.Context, root xdm.Node, needsAttrs, needsNSNodes bool, indexNode func(xdm.Node) error) error {
	stack := []xdm.Node{root}
	for len(stack) > 0 {
		last := len(stack) - 1
		node := stack[last]
		stack = stack[:last]

		if err := indexNode(node); err != nil {
			return err
		}

		if node.Type() == xdm.AttributeNode {
			continue
		}

		if elem, ok := node.(*xdm.Element); ok {
			if err := indexKeyElementNodes(elem, needsAttrs, needsNSNodes, indexNode); err != nil {
				return err
			}
		}

		var err error

		stack, err = xdm.PushXDMChildren(ctx, stack, node)
		if err != nil {
			return err
		}
	}

	return nil
}

func indexKeyElementNodes(elem *xdm.Element, needsAttrs, needsNSNodes bool, indexNode func(xdm.Node) error) error {
	if needsAttrs {
		for _, attr := range elem.Attributes() {
			if err := indexNode(attr); err != nil {
				return err
			}
		}
	}

	if needsNSNodes {
		// Include inherited namespaces, as selected by the XPath namespace axis.
		for _, namespace := range collectInScopeNSNodes(elem) {
			if err := indexNode(namespace); err != nil {
				return err
			}
		}
	}

	return nil
}

// collectInScopeNSNodes returns NamespaceNodeWrapper nodes for all in-scope
// namespaces of an element, including those inherited from ancestors.
// This matches XPath namespace axis semantics.
func collectInScopeNSNodes(elem *xdm.Element) []xdm.Node {
	seen := make(map[string]struct{})

	var result []xdm.Node

	// Walk from the element up through ancestors collecting namespace declarations.
	var cur xdm.Node = elem
	for cur != nil {
		if e, ok := cur.(*xdm.Element); ok {
			for _, ns := range e.Namespaces() {
				prefix := ns.Prefix()
				if _, exists := seen[prefix]; exists {
					continue
				}

				if ns.URI() == "" {
					seen[prefix] = struct{}{}
					continue
				}

				seen[prefix] = struct{}{}

				result = append(result, xdm.NewNamespaceNodeWrapper(ns, elem))
			}
		}

		cur = cur.Parent()
	}

	if _, exists := seen[lexicon.PrefixXML]; !exists {
		xmlNS := xdm.NewNamespace(lexicon.PrefixXML, lexicon.NamespaceXML)
		result = append(result, xdm.NewNamespaceNodeWrapper(xmlNS, elem))
	}

	return result
}

func (ec *execContext) cachedKeyTable(cacheKey, name string) (*keyTable, error) {
	table, found := ec.keyTables[cacheKey]
	if !found {
		return nil, nil
	}

	if table.built {
		return table, nil
	}

	if !table.building {
		return nil, nil
	}

	return nil, dynamicError(errCodeXTDE0640, "circular reference in key %q", name)
}

func (ec *execContext) evaluateKeyUse(ctx context.Context, def *keyDef, node xdm.Node) ([]xdm.Item, error) {
	ec.contextNode, ec.currentNode, ec.contextItem = node, node, nil

	if def.Use != nil {
		result, err := ec.evalXPath(ctx, def.Use, node)
		if err != nil {
			return nil, err
		}

		return xdm.Materialize(result.Sequence()), nil
	}

	if len(def.Body) == 0 {
		return nil, nil
	}

	seq, err := ec.evaluateKeyBody(ctx, def.Body)
	if err != nil {
		return nil, err
	}

	return xdm.Materialize(seq), nil
}

func (ec *execContext) evaluateKeyBody(ctx context.Context, body []instruction) (xdm.Sequence, error) {
	ec.temporaryOutputDepth++
	defer func() { ec.temporaryOutputDepth-- }()

	return ec.evaluateBodyAsSequence(ctx, body)
}

// lookupKey looks up nodes by key name and typed value in the given document root.
func (ec *execContext) lookupKey(ctx context.Context, name string, value xdm.AtomicValue, root xdm.Node) ([]xdm.Node, error) {
	kt, err := ec.buildKeyTable(ctx, name, root)
	if err != nil {
		return nil, err
	}

	// Backwards-compatible key: the lookup value is compared as a string.
	if kt.compat {
		value = keyCompatCast(value, ec.stylesheet.processorLanguage() == 10)
	}

	// NaN lookup never matches.
	if value.IsNaN() {
		return nil, nil
	}

	ck := collationCanonicalKey(value, kt.collationKey)
	if err := xpath.ChargeString(ctx, len(ck)); err != nil {
		return nil, err
	}

	candidates := kt.entries[ck]
	if len(candidates) == 0 {
		return nil, nil
	}

	// Filter candidates using typed eq comparison (collation-aware).
	var result []xdm.Node

	for _, entry := range candidates {
		if err := xpath.Charge(ctx, 1); err != nil {
			return nil, err
		}

		if collationAtomicEquals(value, entry.key, kt.collationCmp) {
			result = append(result, entry.node)
		}
	}

	return result, nil
}

func (ec *execContext) lookupKeyValues(ctx context.Context, name string, values []xdm.AtomicValue, root xdm.Node) ([]xdm.Node, error) {
	var nodes []xdm.Node

	seen := make(map[xdm.Node]struct{})

	for _, value := range values {
		found, err := ec.lookupKey(ctx, name, value, root)
		if err != nil {
			return nil, err
		}

		for _, node := range found {
			if err := xpath.Charge(ctx, 1); err != nil {
				return nil, err
			}

			if _, duplicate := seen[node]; !duplicate {
				seen[node] = struct{}{}
				nodes = append(nodes, node)
			}
		}
	}

	return nodes, nil
}

// lookupCompositeKey looks up nodes by composite key (sequence of values).
func (ec *execContext) lookupCompositeKey(ctx context.Context, name string, values []xdm.AtomicValue, root xdm.Node) ([]xdm.Node, error) {
	kt, err := ec.buildKeyTable(ctx, name, root)
	if err != nil {
		return nil, err
	}

	if kt.compositeEntry == nil {
		return nil, nil
	}

	ck := compositeCanonicalKey(values, kt.collationKey)
	if err := xpath.ChargeString(ctx, len(ck)); err != nil {
		return nil, err
	}

	candidates := kt.compositeEntry[ck]
	if len(candidates) == 0 {
		return nil, nil
	}

	var result []xdm.Node

	seen := make(map[xdm.Node]struct{})

	for _, entry := range candidates {
		if err := xpath.Charge(ctx, len(values)+1); err != nil {
			return nil, err
		}

		if compositeAtomicEquals(values, entry.keys, kt.collationCmp) {
			if _, duplicate := seen[entry.node]; !duplicate {
				seen[entry.node] = struct{}{}
				result = append(result, entry.node)
			}
		}
	}

	return result, nil
}

// compositeAtomicEquals tests whether two composite keys are equal element-by-element.
// When cmpFn is non-nil, string-like values use the collation compare function.
func compositeAtomicEquals(a, b []xdm.AtomicValue, cmpFn func(string, string) int) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if !(a[i].IsNaN() && b[i].IsNaN()) && !collationAtomicEquals(a[i], b[i], cmpFn) {
			return false
		}
	}

	return true
}

// collationAtomicEquals tests whether two atomic values are equal using
// the collation compare function for string/untypedAtomic types.
func collationAtomicEquals(a, b xdm.AtomicValue, cmpFn func(string, string) int) bool {
	if cmpFn == nil {
		return xpath.AtomicEquals(a, b)
	}
	// Only use collation for string-like types
	aIsStr := isStringLikeType(a.TypeName)

	bIsStr := isStringLikeType(b.TypeName)
	if aIsStr && bIsStr {
		sa, _ := xpath.AtomicToString(a)
		sb, _ := xpath.AtomicToString(b)

		return cmpFn(sa, sb) == 0
	}

	return xpath.AtomicEquals(a, b)
}

func isStringLikeType(tn string) bool {
	switch tn {
	case xdm.TypeUntypedAtomic, xdm.TypeString,
		xdm.TypeNormalizedString, xdm.TypeToken,
		xdm.TypeLanguage, xdm.TypeName, xdm.TypeNCName,
		xdm.TypeNMTOKEN, xdm.TypeNMTOKENS,
		xdm.TypeENTITY, xdm.TypeID, xdm.TypeIDREF, xdm.TypeIDREFS,
		xdm.TypeAnyURI:
		return true
	default:
		return false
	}
}

type indexedKeyNode struct {
	canonical string
	node      xdm.Node
}

type keyIndexBuilder struct {
	ec        *execContext
	table     *keyTable
	composite bool
	seen      map[indexedKeyNode][][]xdm.AtomicValue
}

func (b *keyIndexBuilder) indexNode(ctx context.Context, node xdm.Node) error {
	for _, def := range b.table.defs {
		if err := b.indexDefinition(ctx, def, node); err != nil {
			return err
		}
	}

	return nil
}

func (b *keyIndexBuilder) indexDefinition(ctx context.Context, def *keyDef, node xdm.Node) error {
	savedBase, savedPinned := b.ec.staticBaseURIOverride, b.ec.staticBaseURIPinned

	b.ec.staticBaseURIOverride, b.ec.staticBaseURIPinned = def.StaticBaseURI, true
	defer func() { b.ec.staticBaseURIOverride, b.ec.staticBaseURIPinned = savedBase, savedPinned }()

	if !def.Match.matchPattern(ctx, b.ec, node) {
		err := b.ec.patternMatchErr
		b.ec.patternMatchErr = nil

		return err
	}

	items, err := b.ec.evaluateKeyUse(ctx, def, node)
	if err != nil {
		return err
	}

	atoms, err := xpath.FnAtomize(ctx, xdm.ItemSlice(items))
	if err != nil {
		return err
	}

	if b.table.compat {
		for i, atom := range atoms {
			atoms[i] = keyCompatCast(atom, b.ec.stylesheet.processorLanguage() == 10)
		}
	}

	if b.composite {
		key := compositeCanonicalKey(atoms, b.table.collationKey)
		if record, err := b.record(ctx, key, node, atoms); err != nil {
			return err
		} else if record {
			b.table.compositeEntry[key] = append(b.table.compositeEntry[key], compositeKeyEntry{keys: atoms, node: node})
		}

		return nil
	}

	for _, atom := range atoms {
		if atom.IsNaN() {
			continue
		}

		key := collationCanonicalKey(atom, b.table.collationKey)
		if record, err := b.record(ctx, key, node, []xdm.AtomicValue{atom}); err != nil {
			return err
		} else if record {
			b.table.entries[key] = append(b.table.entries[key], keyEntry{key: atom, node: node})
		}
	}

	return nil
}

func (b *keyIndexBuilder) record(ctx context.Context, canonical string, node xdm.Node, atoms []xdm.AtomicValue) (bool, error) {
	if err := xpath.ChargeString(ctx, len(canonical), 32); err != nil {
		return false, err
	}

	key := indexedKeyNode{canonical: canonical, node: node}
	for _, previous := range b.seen[key] {
		if err := xpath.Charge(ctx, len(atoms)+1); err != nil {
			return false, err
		}
		// Cross-type numeric equality is not transitive: removing an equal
		// xs:float can lose a later integer match. Deduplicate equal types only.
		if sameKeyValueTypes(atoms, previous) && compositeAtomicEquals(atoms, previous, b.table.collationCmp) {
			return false, nil
		}
	}

	b.seen[key] = append(b.seen[key], atoms)

	return true, nil
}

func sameKeyValueTypes(a, b []xdm.AtomicValue) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i].TypeName != b[i].TypeName {
			return false
		}
	}

	return true
}
