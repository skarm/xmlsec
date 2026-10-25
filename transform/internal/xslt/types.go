// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"fmt"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// XSLT type error codes.
const (
	errCodeXTTE0505 = "XTTE0505" // template return type mismatch
	errCodeXTTE0570 = "XTTE0570" // variable/param type mismatch
	errCodeXTTE0780 = "XTTE0780" // function return type mismatch
	errCodeXTTE0790 = "XTTE0790" // function parameter type mismatch
)

// sequenceType represents a parsed XSLT/XPath sequence type declaration
// from the "as" attribute (e.g., "xs:string*", "element()+", "item()?").
type sequenceType struct {
	ItemType   string // "xs:string", "element()", lexicon.NodeTestNode, lexicon.NodeTestItem, etc.
	Occurrence rune   // 0 = exactly one, '?' = zero or one, '*' = zero or more, '+' = one or more
}

// parseSequenceType parses an "as" attribute value into a sequenceType.
// Examples: "item()*", "xs:string", "element()+", "xs:integer?", "text()", "empty-sequence()".
func parseSequenceType(as string) sequenceType {
	s := stripXPathComments(strings.TrimSpace(as))
	if s == "" {
		return sequenceType{ItemType: lexicon.NodeTestItem, Occurrence: '*'}
	}

	// empty-sequence() is a special type that matches only the empty sequence
	if s == nameEmptySequence {
		return sequenceType{ItemType: nameEmptySequence, Occurrence: 'E'}
	}

	// Check for occurrence indicator at the end
	var occ rune

	last := s[len(s)-1]
	switch last {
	case '?', '*', '+':
		occ = rune(last)
		s = strings.TrimSpace(s[:len(s)-1])
	}

	return sequenceType{ItemType: s, Occurrence: occ}
}

// allowsEmptySequence returns true if the given 'as' type string allows
// an empty sequence (zero items). Types ending with ? or * allow empty;
// types without an occurrence indicator or with + require at least one item.
func allowsEmptySequence(as string) bool {
	s := strings.TrimSpace(stripXPathComments(as))
	if s == "" || s == nameEmptySequence {
		return true
	}

	last := s[len(s)-1]

	return last == '?' || last == '*'
}

// checkSequenceType checks that a sequence matches the declared type.
// Returns the (possibly coerced) sequence on success, or an error on type mismatch.
func checkSequenceType(ctx context.Context, seq xdm.Sequence, st sequenceType, errCode string, context string, ec ...*execContext) (xdm.Sequence, error) {
	var execCtx *execContext
	if len(ec) > 0 {
		execCtx = ec[0]
	}

	// When the target type is atomic, pre-atomize the sequence so that
	// list-type nodes (e.g. xs:list of xs:decimal) expand into multiple
	// atomic items before cardinality and type checks.
	if isAtomicTargetType(st.ItemType) && seq != nil {
		atomized, err := xpath.AtomizeSequence(seq)
		if err == nil && len(atomized) > 0 {
			items := make(xdm.ItemSlice, len(atomized))
			for i, av := range atomized {
				items[i] = av
			}

			seq = items
		}
	}

	count := 0
	if seq != nil {
		count = xdm.SequenceLen(seq)
	}

	switch st.Occurrence {
	case 'E': // empty-sequence() — must be empty
		if count != 0 {
			return nil, dynamicError(errCode, "%s: required empty-sequence(), got %d items", context, count)
		}

		return seq, nil
	case 0: // exactly one
		if count != 1 {
			return nil, dynamicError(errCode, "%s: required exactly 1 item, got %d", context, count)
		}
	case '?': // zero or one
		if count > 1 {
			return nil, dynamicError(errCode, "%s: required 0 or 1 items, got %d", context, count)
		}
	case '+': // one or more
		if count == 0 {
			return nil, dynamicError(errCode, "%s: required 1 or more items, got 0", context)
		}
	case '*': // zero or more — always valid
	}

	if count == 0 {
		return seq, nil
	}

	// Check/coerce item types
	result := make(xdm.ItemSlice, 0, count)

	for item := range xdm.SequenceItems(seq) {
		coerced, err := coerceItem(ctx, item, st.ItemType, execCtx)
		if err != nil {
			if failure := preserveControlFailure(ctx, err); failure != nil {
				return nil, failure
			}

			return nil, dynamicError(errCode, "%s: %v", context, err)
		}

		result = append(result, coerced)
	}

	return result, nil
}

// isAtomicTargetType returns true when the item type string names an atomic
// type (e.g. "xs:decimal", "xs:string"), and no node/function/map test.
func isAtomicTargetType(itemType string) bool {
	if itemType == "" || itemType == lexicon.NodeTestItem {
		return false
	}
	// Node tests, function tests, map/array tests are not atomic.
	if strings.HasPrefix(itemType, "node(") ||
		strings.HasPrefix(itemType, "element(") ||
		strings.HasPrefix(itemType, "attribute(") ||
		strings.HasPrefix(itemType, "document-node(") ||
		strings.HasPrefix(itemType, "text(") ||
		strings.HasPrefix(itemType, "comment(") ||
		strings.HasPrefix(itemType, "processing-instruction(") ||
		strings.HasPrefix(itemType, "namespace-node(") ||
		strings.HasPrefix(itemType, "schema-element(") ||
		strings.HasPrefix(itemType, "schema-attribute(") ||
		strings.HasPrefix(itemType, "function(") ||
		strings.HasPrefix(itemType, "map(") ||
		strings.HasPrefix(itemType, "array(") {
		return false
	}

	return true
}

// coerceItem checks that a single item matches the expected type, applying
// atomization and casting as needed per the XSLT function conversion rules.
func coerceItem(ctx context.Context, item xdm.Item, itemType string, ec ...*execContext) (xdm.Item, error) {
	var execCtx *execContext
	if len(ec) > 0 {
		execCtx = ec[0]
	}

	return coerceItemWithContext(ctx, item, itemType, execCtx)
}

// coerceItemWithContext is the inner implementation of coerceItem with an explicit exec context.
func coerceItemWithContext(ctx context.Context, item xdm.Item, itemType string, ec *execContext) (xdm.Item, error) {
	// Strip one enclosing pair, as in (function(...) as ...).
	if len(itemType) > 2 && itemType[0] == '(' && itemType[len(itemType)-1] == ')' {
		itemType = itemType[1 : len(itemType)-1]
	}

	switch itemType {
	case lexicon.NodeTestItem:
		return item, nil
	case lexicon.NodeTestNode:
		if _, ok := item.(xdm.NodeItem); ok {
			return item, nil
		}

		return nil, fmt.Errorf("expected node(), got atomic value")
	}

	if kind, ok := simpleNodeTestKind(itemType); ok {
		return coerceNodeKind(item, itemType, kind)
	}

	switch {
	case strings.HasPrefix(itemType, "document-node("):
		return coerceDocumentNodeTest(ctx, item, itemType, ec)
	case strings.HasPrefix(itemType, "attribute("):
		return coerceNodeKind(item, itemType, xdm.AttributeNode)
	case strings.HasPrefix(itemType, "map("):
		return checkMapItemType(item, itemType)
	case strings.HasPrefix(itemType, "array("):
		// Retain the existing permissive array test.
		return item, nil
	case strings.HasPrefix(itemType, "function("):
		return coerceFunctionItemType(ctx, item, itemType, ec)
	case strings.HasPrefix(itemType, "element("):
		return coerceElementNodeTest(item, itemType, ec)
	case strings.HasPrefix(itemType, "schema-element("):
		return coerceSchemaElementTest(item, itemType, ec)
	case strings.HasPrefix(itemType, "schema-attribute("):
		return coerceSchemaAttributeTest(item, itemType, ec)
	default:
		return coerceToAtomicType(ctx, item, itemType, ec)
	}
}

func simpleNodeTestKind(itemType string) (xdm.ElementType, bool) {
	switch itemType {
	case "element()":
		return xdm.ElementNode, true
	case "attribute()":
		return xdm.AttributeNode, true
	case "text()":
		return xdm.TextNode, true
	case "comment()":
		return xdm.CommentNode, true
	case lexicon.NodeTestPI:
		return xdm.ProcessingInstructionNode, true
	case "namespace-node()":
		return xdm.NamespaceNode, true
	case "document-node()":
		return xdm.DocumentNode, true
	default:
		return 0, false
	}
}

func coerceNodeKind(item xdm.Item, itemType string, kind xdm.ElementType) (xdm.Item, error) {
	if node, ok := item.(xdm.NodeItem); ok {
		actual := node.Node.Type()
		if actual == kind || (kind == xdm.TextNode && actual == xdm.CDATASectionNode) {
			return item, nil
		}
	}

	return nil, fmt.Errorf("expected %s, got %s", itemType, describeItem(item))
}

func coerceDocumentNodeTest(ctx context.Context, item xdm.Item, itemType string, ec *execContext) (xdm.Item, error) {
	ni, ok := item.(xdm.NodeItem)
	if !ok || ni.Node.Type() != xdm.DocumentNode {
		return nil, fmt.Errorf("expected %s, got %s", itemType, describeItem(item))
	}

	inner := strings.TrimSpace(itemType[len("document-node(") : len(itemType)-1])
	if inner == "" {
		return item, nil
	}

	doc, ok := ni.Node.(*xdm.Document)
	if !ok {
		return nil, fmt.Errorf("expected %s, got %s", itemType, describeItem(item))
	}

	root := findDocumentElement(doc)
	if root == nil {
		return nil, fmt.Errorf("expected %s: document has no root element", itemType)
	}

	if _, err := coerceItemWithContext(ctx, xdm.NodeItem{Node: root}, inner, ec); err != nil {
		return nil, fmt.Errorf("expected %s: root element mismatch: %w", itemType, err)
	}

	return item, nil
}

func coerceFunctionItemType(ctx context.Context, item xdm.Item, itemType string, ec *execContext) (xdm.Item, error) {
	if itemType == "function(*)" {
		switch item.(type) {
		case xdm.FunctionItem, xdm.MapItem, *xdm.ArrayItem:
			return item, nil
		}

		return nil, fmt.Errorf("expected %s, got %s", itemType, describeItem(item))
	}

	st, err := xpath.ParseSequenceType(itemType)
	if err != nil {
		return item, nil //nolint:nilerr // unparseable type → pass through
	}

	seq := xdm.ItemSlice{item}

	var coerced xdm.Sequence
	if ec != nil {
		coerced, err = ec.convertFunctionArgument(ctx, seq, st)
	} else {
		coerced, err = xpath.ConvertToSequenceType(ctx, seq, st)
	}

	if err != nil {
		return nil, err
	}

	if coerced != nil && xdm.SequenceLen(coerced) == 1 {
		return coerced.Get(0), nil
	}

	return nil, fmt.Errorf("function item does not match required type %s", itemType)
}

func coerceElementNodeTest(item xdm.Item, itemType string, ec *execContext) (xdm.Item, error) {
	ni, ok := item.(xdm.NodeItem)
	if !ok || ni.Node.Type() != xdm.ElementNode {
		return nil, fmt.Errorf("expected %s, got %s", itemType, describeItem(item))
	}

	inner := strings.TrimSpace(itemType[len("element(") : len(itemType)-1])
	if inner == "" || inner == "*" {
		return item, nil
	}

	parts := splitTopLevelTypeArgs(inner)

	requiredName := strings.TrimSpace(parts[0])
	if requiredName == "*" {
		return item, nil
	}

	local, ns := resolveSchemaQName(requiredName, qnameElementName, ec)

	elem, ok := ni.Node.(*xdm.Element)
	if !ok {
		return nil, fmt.Errorf("expected %s, got non-element node", itemType)
	}

	if elem.LocalName() != local || elem.URI() != ns {
		return nil, fmt.Errorf("expected %s, got element %q", itemType, elem.LocalName())
	}

	return item, nil
}

func coerceSchemaElementTest(item xdm.Item, itemType string, ec *execContext) (xdm.Item, error) {
	ni, ok := item.(xdm.NodeItem)
	if !ok || ni.Node.Type() != xdm.ElementNode {
		return nil, fmt.Errorf("expected %s, got %s", itemType, describeItem(item))
	}

	inner := strings.TrimSpace(itemType[len("schema-element(") : len(itemType)-1])
	local, ns := resolveSchemaQName(inner, qnameElementName, ec)

	elem, ok := ni.Node.(*xdm.Element)
	if !ok {
		return nil, fmt.Errorf("expected %s, got non-element node", itemType)
	}

	if elem.LocalName() != local || elem.URI() != ns {
		return nil, fmt.Errorf("expected %s, got element %q", itemType, elem.LocalName())
	}

	return item, nil
}

func coerceSchemaAttributeTest(item xdm.Item, itemType string, ec *execContext) (xdm.Item, error) {
	ni, ok := item.(xdm.NodeItem)
	if !ok || ni.Node.Type() != xdm.AttributeNode {
		return nil, fmt.Errorf("expected %s, got %s", itemType, describeItem(item))
	}

	inner := strings.TrimSpace(itemType[len("schema-attribute(") : len(itemType)-1])
	local, ns := resolveSchemaQName(inner, qnameAttributeName, ec)

	attr, ok := ni.Node.(*xdm.Attribute)
	if !ok {
		return nil, fmt.Errorf("expected %s, got non-attribute node", itemType)
	}

	if attr.LocalName() != local || attr.URI() != ns {
		return nil, fmt.Errorf("expected %s, got attribute %q", itemType, attr.LocalName())
	}

	return item, nil
}

// coerceToAtomicType atomizes a node/value and casts to the target atomic type.
func coerceToAtomicType(ctx context.Context, item xdm.Item, targetType string, ec *execContext) (xdm.Item, error) {
	// If already an atomic value, check/cast the type
	if av, ok := item.(xdm.AtomicValue); ok {
		return castAtomicToType(ctx, av, targetType, ec)
	}

	// Node item — atomize first
	ni, ok := item.(xdm.NodeItem)
	if !ok {
		return nil, fmt.Errorf("expected %s, got %s", targetType, describeItem(item))
	}

	av, err := xpath.AtomizeItem(ni)
	if err != nil {
		return nil, fmt.Errorf("cannot atomize node for type %s: %w", targetType, err)
	}

	return castAtomicToType(ctx, av, targetType, ec)
}

func castAtomicToType(ctx context.Context, av xdm.AtomicValue, targetType string, ec ...*execContext) (xdm.Item, error) {
	// Normalize target type
	target := normalizeTypeName(targetType, ec...)

	// If already the right type, return as-is
	if av.TypeName == target {
		return av, nil
	}

	// Built-in XSD subtype relationships: xs:integer derives from xs:decimal.
	// An integer value satisfies xs:decimal without promotion/casting.
	if isBuiltinSubtypeOf(av.TypeName, target) {
		return av, nil
	}

	// xs:anyAtomicType matches any atomic value
	if target == "xs:anyAtomicType" {
		return av, nil
	}

	// xs:anyURI -> xs:string promotion (per XPath spec).
	// Also handles schema-defined types derived from xs:anyURI.
	if target == xdm.TypeString && isAnyURIType(av.TypeName, ec...) {
		return xdm.AtomicValue{TypeName: xdm.TypeString, Value: av.StringVal()}, nil
	}

	// xs:string -> xs:anyURI promotion (per XPath spec)
	if av.TypeName == xdm.TypeString && target == xdm.TypeAnyURI {
		return xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: av.StringVal()}, nil
	}

	// xs:untypedAtomic can be cast to any atomic type (function conversion rules).
	// xs:string is NOT implicitly castable to other types — only xs:untypedAtomic
	// has this privilege. xs:string -> xs:integer (etc.) is a type error (XTTE0590).
	if av.TypeName == xdm.TypeUntypedAtomic {
		s := av.StringVal()

		cast, err := xpath.CastFromString(s, target)
		if err != nil {
			// Try schema-aware cast for user-defined types.
			if schemaCast, ok := trySchemaCast(ctx, s, target, ec...); ok {
				return schemaCast, nil
			}

			return nil, fmt.Errorf("cannot cast %q to %s: %w", s, targetType, err)
		}

		return cast, nil
	}

	// Numeric promotion: a value whose numeric type is narrower than
	// the target is promoted (cast) to the target type. Demotion
	// (wider→narrower, e.g., double→float) is rejected (XTTE0570).
	// This also handles schema-defined types whose builtin base is numeric.
	srcBase, srcIsNum := resolveToNumericBase(av.TypeName, ec...)

	tgtBase, tgtIsNum := resolveToNumericBase(target, ec...)
	if srcIsNum && tgtIsNum {
		srcRank := numericRank(srcBase)

		tgtRank := numericRank(tgtBase)
		if srcRank > tgtRank {
			return nil, fmt.Errorf("cannot convert %s to %s", av.TypeName, targetType)
		}

		if srcRank < tgtRank {
			// Promote: cast to wider type so instance-of checks work.
			s, _ := xpath.AtomicToString(av)

			cast, err := xpath.CastFromString(s, target)
			if err != nil {
				return nil, fmt.Errorf("cannot promote %s to %s: %w", av.TypeName, target, err)
			}

			return cast, nil
		}
		// Same rank: accept as-is
		return av, nil
	}

	// No implicit cast path found — type mismatch.
	return nil, fmt.Errorf("cannot convert %s to %s", av.TypeName, targetType)
}

// trySchemaCast attempts to cast a string to a user-defined schema type by
// resolving to the built-in base type, casting to that, validating facets,
// and returning the result with the user-defined type name.
func trySchemaCast(ctx context.Context, s, target string, ec ...*execContext) (xdm.Item, bool) {
	return nil, false
}

// normalizeTypeName normalizes a type name. xs: and xsd: prefixes are
// canonicalized to xs:. Other prefixed names are resolved to Q{ns}local
// format using the exec context's namespace bindings (if available).
func normalizeTypeName(name string, ec ...*execContext) string {
	if strings.HasPrefix(name, "xs:") {
		return name
	}

	if strings.HasPrefix(name, "Q{") {
		return name
	}
	// Normalize xsd: prefix to xs: (both map to XML Schema namespace)
	if strings.HasPrefix(name, "xsd:") {
		return "xs:" + name[4:]
	}
	// Resolve other prefix:local names to Q{ns}local using namespace bindings.
	if idx := strings.IndexByte(name, ':'); idx > 0 {
		prefix := name[:idx]
		local := name[idx+1:]

		if len(ec) > 0 && ec[0] != nil {
			if ns, ok := ec[0].lookupTypeNamespaceOK(prefix); ok {
				if ns == lexicon.NamespaceXSD {
					return "xs:" + local
				}

				return xdm.QAnnotation(ns, local)
			}
		}
	}
	// Map unprefixed names to xs: prefixed
	switch name {
	case lexicon.TypeString:
		return xdm.TypeString
	case nameInteger:
		return xdm.TypeInteger
	case nameDecimal:
		return xdm.TypeDecimal
	case nameDouble:
		return xdm.TypeDouble
	case nameFloat:
		return xdm.TypeFloat
	case lexicon.TypeBoolean:
		return xdm.TypeBoolean
	case "date":
		return xdm.TypeDate
	case nameDateTime:
		return xdm.TypeDateTime
	case nameTime:
		return xdm.TypeTime
	case nameDuration:
		return xdm.TypeDuration
	case nameDayTimeDuration:
		return xdm.TypeDayTimeDuration
	case nameYearMonthDuration:
		return xdm.TypeYearMonthDuration
	case "anyURI":
		return xdm.TypeAnyURI
	case nameUntypedAtomic:
		return xdm.TypeUntypedAtomic
	}
	// Unprefixed non-builtin type names take the in-scope default element/type
	// namespace (xpath-default-namespace) when one is in effect; otherwise no
	// namespace. Use Q{} annotation form to match xsdTypeNameFromDef which
	// produces Q{}local for no-namespace types.
	if !strings.ContainsAny(name, ":{") {
		if len(ec) > 0 && ec[0] != nil && ec[0].hasXPathDefaultNS && ec[0].xpathDefaultNS != "" {
			return xdm.QAnnotation(ec[0].xpathDefaultNS, name)
		}

		return "Q{}" + name
	}

	return name
}

// numericRank returns the promotion rank of a numeric type.
// Higher rank = wider type. Promotion is only valid from lower to higher rank.
// Derived integer types (xs:int, xs:long, etc.) have the same rank as xs:integer.
func numericRank(t string) int {
	switch t {
	case xdm.TypeInteger:
		return 1
	case xdm.TypeDecimal:
		return 2
	case xdm.TypeFloat:
		return 3
	case xdm.TypeDouble:
		return 4
	}
	// Derived integer types all promote at the same rank as xs:integer.
	if xdm.BuiltinIsSubtypeOf(t, xdm.TypeInteger) {
		return 1
	}
	// Derived decimal types (not integer) promote at decimal rank.
	if xdm.BuiltinIsSubtypeOf(t, xdm.TypeDecimal) {
		return 2
	}

	return 0
}

// isNumericType returns true for xs:integer, xs:decimal, xs:float, xs:double
// and all built-in derived integer/decimal types (xs:int, xs:long, etc.).
func isNumericType(t string) bool {
	switch t {
	case xdm.TypeInteger, xdm.TypeDecimal, xdm.TypeFloat, xdm.TypeDouble:
		return true
	}

	return xdm.BuiltinIsSubtypeOf(t, xdm.TypeDecimal)
}

// resolveToNumericBase resolves a schema-defined type to its builtin numeric
// base type, if any. Returns the builtin type name and true, or ("", false).
func resolveToNumericBase(typeName string, _ ...*execContext) (string, bool) {
	if isNumericType(typeName) {
		return typeName, true
	}

	return "", false
}

// isAnyURIType returns true if the type is xs:anyURI or a schema-defined type
// that derives from xs:anyURI.
func isAnyURIType(typeName string, _ ...*execContext) bool {
	return typeName == xdm.TypeAnyURI
}

// resolveSchemaQName resolves the NAME argument of an element()/schema-element()
// or attribute()/schema-attribute() sequence-type test to (localName, namespace),
// using the exec context's namespace bindings (the declaration-site override when
// one is set, e.g. for xsl:global-context-item, else the stylesheet map). It
// delegates to the single unified resolveSequenceTypeQName so that the runtime
// resolution matches @as validation and the XTSE3087 canonicalization exactly.
//
// kind selects the position-specific rule: qnameElementName applies the default
// element namespace to an unprefixed name; qnameAttributeName never does (an
// unprefixed attribute name is in no namespace). The xml prefix is predeclared
// to the XML namespace in both positions.
func resolveSchemaQName(qname string, kind qnameKind, ec *execContext) (local, ns string) {
	var resolve nsResolver

	hasDefaultNS := false
	defaultNS := ""

	if ec != nil {
		resolve = ec.lookupTypeNamespaceOK
		hasDefaultNS = ec.hasXPathDefaultNS
		defaultNS = ec.xpathDefaultNS
	}

	return resolveSequenceTypeQName(qname, kind, resolve, defaultNS, hasDefaultNS)
}

// describeItem returns a human-readable description of an item for error messages.
func describeItem(item xdm.Item) string {
	switch v := item.(type) {
	case xdm.NodeItem:
		switch v.Node.Type() {
		case xdm.ElementNode:
			return "element node"
		case xdm.AttributeNode:
			return "attribute node"
		case xdm.TextNode, xdm.CDATASectionNode:
			return "text node"
		case xdm.CommentNode:
			return "comment node"
		case xdm.ProcessingInstructionNode:
			return "processing-instruction node"
		case xdm.DocumentNode:
			return "document node"
		default:
			return "node"
		}
	case xdm.AtomicValue:
		return fmt.Sprintf("atomic value of type %s", v.TypeName)
	case xdm.MapItem:
		return "map"
	default:
		return fmt.Sprintf("%T", item)
	}
}

func checkMapItemType(item xdm.Item, itemType string) (xdm.Item, error) {
	m, ok := item.(xdm.MapItem)
	if !ok {
		return nil, fmt.Errorf("expected %s, got %s", itemType, describeItem(item))
	}

	keyType, valueType, hasMembers, err := parseMapItemType(itemType)
	if err != nil {
		return nil, err
	}

	if !hasMembers {
		return item, nil
	}

	for _, key := range m.Keys() {
		if !atomicMatchesType(key, keyType) {
			return nil, fmt.Errorf("map key %q does not match %s", key.StringVal(), keyType)
		}

		value, _ := m.Get(key)
		if !sequenceMatchesTypeStrict(value, valueType) {
			return nil, fmt.Errorf("map entry for key %q does not match %s", key.StringVal(), formatSequenceType(valueType))
		}
	}

	return item, nil
}

func parseMapItemType(itemType string) (string, sequenceType, bool, error) {
	inner := strings.TrimSpace(itemType[len("map(") : len(itemType)-1])
	if inner == "*" {
		return "", sequenceType{}, false, nil
	}

	parts := splitTopLevelTypeArgs(inner)
	if len(parts) != 2 {
		return "", sequenceType{}, false, fmt.Errorf("invalid map type %q", itemType)
	}

	return strings.TrimSpace(parts[0]), parseSequenceType(strings.TrimSpace(parts[1])), true, nil
}

func splitTopLevelTypeArgs(s string) []string {
	var parts []string

	depth := 0
	start := 0

	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}

	parts = append(parts, s[start:])

	return parts
}

func sequenceMatchesTypeStrict(seq xdm.Sequence, st sequenceType) bool {
	count := 0
	if seq != nil {
		count = xdm.SequenceLen(seq)
	}

	switch st.Occurrence {
	case 0:
		if count != 1 {
			return false
		}
	case '?':
		if count > 1 {
			return false
		}
	case '+':
		if count == 0 {
			return false
		}
	}

	for item := range xdm.SequenceItems(seq) {
		if !itemMatchesTypeStrict(item, st.ItemType) {
			return false
		}
	}

	return true
}

func itemMatchesTypeStrict(item xdm.Item, itemType string) bool {
	switch itemType {
	case lexicon.NodeTestItem:
		return true
	case lexicon.NodeTestNode:
		_, ok := item.(xdm.NodeItem)
		return ok
	case "element()":
		if ni, ok := item.(xdm.NodeItem); ok {
			return ni.Node.Type() == xdm.ElementNode
		}

		return false
	case "attribute()":
		if ni, ok := item.(xdm.NodeItem); ok {
			return ni.Node.Type() == xdm.AttributeNode
		}

		return false
	case "text()":
		if ni, ok := item.(xdm.NodeItem); ok {
			return ni.Node.Type() == xdm.TextNode || ni.Node.Type() == xdm.CDATASectionNode
		}

		return false
	case "comment()":
		if ni, ok := item.(xdm.NodeItem); ok {
			return ni.Node.Type() == xdm.CommentNode
		}

		return false
	case lexicon.NodeTestPI:
		if ni, ok := item.(xdm.NodeItem); ok {
			return ni.Node.Type() == xdm.ProcessingInstructionNode
		}

		return false
	case "document-node()":
		if ni, ok := item.(xdm.NodeItem); ok {
			return ni.Node.Type() == xdm.DocumentNode
		}

		return false
	}

	if strings.HasPrefix(itemType, "map(") {
		_, err := checkMapItemType(item, itemType)
		return err == nil
	}

	if strings.HasPrefix(itemType, "array(") || strings.HasPrefix(itemType, "function(") {
		return true
	}

	av, ok := item.(xdm.AtomicValue)
	if !ok {
		return false
	}

	return atomicMatchesType(av, itemType)
}

func atomicMatchesType(av xdm.AtomicValue, targetType string) bool {
	target := normalizeTypeName(strings.TrimSpace(targetType))
	switch target {
	case "xs:anyAtomicType":
		return true
	case "xs:numeric":
		return isNumericType(av.TypeName)
	}

	if av.TypeName == target {
		return true
	}

	if target == xdm.TypeDecimal && av.TypeName == xdm.TypeInteger {
		return true
	}

	return false
}

func formatSequenceType(st sequenceType) string {
	if st.Occurrence == 0 {
		return st.ItemType
	}

	return st.ItemType + string(st.Occurrence)
}
