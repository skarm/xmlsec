// Copyright (c) 2026 xmlsec contributors.
// MIT License. Version boundaries were cross-checked against knroy/go-xml
// eb327e4c08420169c271e94708b5c803d58e91f9 (MIT, Komol Nath Roy).

package xpath

import (
	"context"
	"maps"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// Profile availability tables use standard function local names, with no
// namespace-prefix implication. Keep membership/order independent of dispatch.
const (
	fnNameInnermost                     = "innermost"
	fnNameOutermost                     = "outermost"
	fnNameAnalyzeString                 = "analyze-string"
	fnNameFormatInteger                 = "format-integer"
	fnNameFunctionName                  = "function-name"
	fnNameFunctionArity                 = "function-arity"
	fnNameFunctionLookup                = "function-lookup"
	fnNameEnvironmentVariable           = "environment-variable"
	fnNameAvailableEnvironmentVariables = "available-environment-variables"
	fnNameURICollection                 = "uri-collection"
	fnNameSerialize                     = "serialize"
	fnNameParseXML                      = "parse-xml"
	fnNameParseXMLFragment              = "parse-xml-fragment"
	fnNameParseJSON                     = "parse-json"
	fnNameJSONDoc                       = "json-doc"
	fnNameJSONToXML                     = "json-to-xml"
	fnNameXMLToJSON                     = "xml-to-json"
	fnNameTransform                     = "transform"
	fnNameDefaultLanguage               = "default-language"
	fnNameApply                         = "apply"
	fnNameCollationKey                  = "collation-key"
	fnNameContainsToken                 = "contains-token"
	fnNameParseIETFDate                 = "parse-ietf-date"
	fnNameRandomNumberGenerator         = "random-number-generator"
	fnNameTokenize                      = "tokenize"
	fnNameData                          = "data"
)

// Display labels describe XPath editions, not XML document versions. A negative
// arity denotes an AST node without a function call; the arities below select
// signatures introduced by particular language editions rather than limits.
const (
	xpathLabel10             = "1.0"
	xpathLabel20             = "2.0"
	xpathLabel30             = "3.0"
	xpathLabel31             = "3.1"
	unspecifiedFunctionArity = -1
	profileNullaryArity      = 0
	profileUnaryArity        = 1
	profileBinaryArity       = 2
	regexLiteralFlag         = "q"
	regexNoncapturingPrefix  = "(?:"
	profileKeywordIf         = "if"
	profileKeywordTypeSwitch = "typeswitch"
	profileKeywordSwitch     = "switch"
)

// CheckTypeLanguage applies the same version boundaries to standalone types.
func CheckTypeLanguage(st xdm.SequenceType, version int) error {
	return profileVisitor(func(node any) error {
		switch node.(type) {
		case xdm.FunctionTest:
			if version < xpathVersion30 {
				return profileError(lexicon.ErrXPST0003, "function types", version)
			}
		case xdm.MapTest, xdm.ArrayTest:
			if version < xpathVersion31 {
				return profileError(lexicon.ErrXPST0003, "map or array types", version)
			}
		}

		return nil
	}).walk(st)
}

// ValidNCName checks a prefix-free XML name used by the public API.
func ValidNCName(name string) bool { return xmlchar.IsValidNCName(name) }

// CheckStaticNamespaces rejects reserved namespace bindings in XPath 2.0+.
func CheckStaticNamespaces(namespaces map[string]string) error {
	for prefix, uri := range namespaces {
		if prefix == lexicon.PrefixXML && uri != lexicon.NamespaceXML ||
			prefix != "" && prefix != lexicon.PrefixXML && uri == lexicon.NamespaceXML ||
			prefix == lexicon.PrefixXMLNS || uri == lexicon.NamespaceXMLNS {
			return &xdm.Error{Code: errCodeXQST0070, Message: "invalid reserved namespace binding: " + prefix}
		}
	}

	return nil
}

// CheckStandaloneFunctions rejects unknown and non-standard static calls in
// the standalone API. XSLT supplies its own user functions and validates them
// through its compiler, so it does not use this check.
func CheckStandaloneFunctions(expr *Expression, namespaces map[string]string, extensions ...map[string]Function) error {
	return profileVisitor(func(node any) error {
		var prefix, name string

		arity := unspecifiedFunctionArity

		switch n := node.(type) {
		case FunctionCall:
			prefix, name, arity = n.Prefix, n.Name, len(n.Args)
		case NamedFunctionRef:
			prefix, name, arity = n.Prefix, n.Name, n.Arity
		case xdm.SchemaElementTest, xdm.SchemaAttributeTest:
			return &xdm.Error{Code: lexicon.ErrXPST0008, Message: "no schema declarations in the standalone static context"}
		}

		return checkStandaloneCall(expr.version, prefix, name, arity, namespaces, extensions)
	}).walk(expr.astExpr())
}

// Language pins the grammar and function library to XPath 1.0, 2.0, 3.0 or 3.1.
// Zero selects the engine default profile.
func (c Compiler) Language(version int, namespaces map[string]string) Compiler {
	cfg := compilerCfg{}
	if c.cfg != nil {
		cfg = *c.cfg
	}

	cfg.version, cfg.namespaces = version, maps.Clone(namespaces)

	return Compiler{cfg: &cfg}
}

// HostFunctions augments the selected library without changing its grammar.
// The host still validates declarations and arities in its own static context.
func (c Compiler) HostFunctions(available func(uri, name string, arity int) bool) Compiler {
	cfg := compilerCfg{}
	if c.cfg != nil {
		cfg = *c.cfg
	}

	cfg.hostFunction = available

	return Compiler{cfg: &cfg}
}

// BuiltinFunctionAvailable reports the selected language's standard function
// library, including version-specific arities, for host introspection.
func BuiltinFunctionAvailable(version int, uri, name string, arity int) bool {
	return functionVisible(version, uri, name, arity) && IsBuiltinFunctionNS(uri, name) &&
		(arity < finiteArityFloor || BuiltinFunctionAcceptsArity(uri, name, arity))
}

func profileError(code, feature string, version int) error {
	return &xdm.Error{Code: code, Message: feature + " is unavailable in XPath " + map[int]string{xpathVersion10: xpathLabel10, xpathVersion20: xpathLabel20, xpathVersion30: xpathLabel30, xpathVersion31: xpathLabel31}[version]}
}

func checkStandaloneCall(version int, prefix, name string, arity int, namespaces map[string]string, extensions []map[string]Function) error {
	if arity < finiteArityFloor {
		return nil
	}

	if prefix == "" {
		for _, registry := range extensions {
			if fn := registry[name]; fn != nil {
				return checkArity(fn, name, arity)
			}
		}
	}

	uri := NSFn
	if prefix != "" {
		uri = namespaces[prefix]
		if uri == "" {
			uri, _ = PredeclaredNamespace(prefix)
		}
	}

	if strings.HasPrefix(name, lexicon.EQNamePrefix) {
		if end := strings.IndexByte(name, '}'); end >= 0 {
			uri, name = name[2:end], name[end+1:]
		}
	}

	for _, registry := range extensions {
		if fn := registry[xdm.ClarkName(uri, name)]; fn != nil {
			if err := checkArity(fn, name, arity); err != nil {
				return &xdm.Error{Code: lexicon.ErrXPST0017, Message: "invalid application function arity: " + name, Cause: err}
			}

			return nil
		}
	}

	if version == xpathVersion10 && (prefix != "" || !xpath10FunctionArity(name, arity)) || !StandardFunctionAcceptsArity(uri, name, arity) {
		return &xdm.Error{Code: lexicon.ErrXPST0017, Message: "unknown function or arity: " + name}
	}

	// These functions belonged to the XSLT 2.0 host library before F&O 3.0
	// added them to standalone XPath. XSLT performs its own host checks.
	if version == xpathVersion20 && uri == NSFn {
		switch name {
		case fnNameUnparsedText, fnNameUnparsedTextAvailable, lexicon.FnFormatNumber, fnNameFormatDate, fnNameFormatDateTime, fnNameFormatTime:
			return profileError(lexicon.ErrXPST0017, name+" function", version)
		}
	}

	return nil
}

func validateVersionTokens(tokens []Token, version int) error {
	if version != xpathVersion10 && version != xpathVersion20 && version != xpathVersion30 && version != xpathVersion31 {
		return profileError(lexicon.ErrXPST0003, "language version", version)
	}

	for i, token := range tokens {
		if version == xpathVersion10 {
			if token.Type == TokenNumber && strings.ContainsAny(token.Value, floatExponentMarkers) {
				return profileError(lexicon.ErrXPST0003, "numeric literal", version)
			}

			if token.Value == nameProcessingInstruction && i+2 < len(tokens) && tokens[i+1].Type == TokenLParen && tokens[i+2].Type != TokenString && tokens[i+2].Type != TokenRParen {
				return profileError(lexicon.ErrXPST0003, "PI target must be a string literal", xpathVersion10)
			}
		}

		if version < xpathVersion31 && token.Type == TokenArrow {
			return profileError(lexicon.ErrXPST0003, "arrow operator", version)
		}

		if version < xpathVersion30 && token.Type != TokenString && strings.HasPrefix(token.Value, lexicon.EQNamePrefix) {
			return profileError(lexicon.ErrXPST0003, "URI-qualified names", version)
		}
	}

	return nil
}

func validateVersionExpr(ast Expr, version int, namespaces map[string]string, hostFunction func(string, string, int) bool) error {
	if version == xpathVersion10 {
		return validateXPath10Expr(ast)
	}

	return profileVisitor(func(node any) error {
		return validateProfileNode(node, version, namespaces, hostFunction)
	}).walk(ast)
}

func lookupXPath30Function(key string) (bool, bool) {
	switch key {
	case fnNameHead, nameTail, nameHasChildren, fnNameInnermost, fnNameOutermost, namePath, fnNameAnalyzeString, lexicon.FnGenerateID, fnNameFormatInteger, fnNameFunctionName, fnNameFunctionArity, fnNameFunctionLookup, nameForEach, nameFilter, nameFoldLeft, nameFoldRight, nameForEachPair, fnNameEnvironmentVariable, fnNameAvailableEnvironmentVariables, fnNameURICollection, fnNameSerialize, fnNameParseXML, fnNameParseXMLFragment, nameUnparsedTextLines:
		return true, true
	}

	var zero bool

	return zero, false
}

func functions30(key string) bool { value, _ := lookupXPath30Function(key); return value }

func lookupXPath31Function(key string) (bool, bool) {
	switch key {
	case fnNameParseJSON, fnNameJSONDoc, fnNameJSONToXML, fnNameXMLToJSON, fnNameTransform, fnNameDefaultLanguage, nameLoadXQueryModule, fnNameApply, fnNameCollationKey, fnNameContainsToken, fnNameParseIETFDate, fnNameRandomNumberGenerator, nameSort:
		return true, true
	}

	var zero bool

	return zero, false
}

func functions31(key string) bool { value, _ := lookupXPath31Function(key); return value }

func functionVisible(version int, uri, name string, arity int) bool {
	if version == xpathVersionDefault {
		return true
	}

	if version == xpathVersion10 {
		return uri == NSFn && xpath10FunctionArity(name, arity)
	}

	if (uri == NSMap || uri == NSArray) && version < xpathVersion31 {
		return false
	}

	if uri == NSMath && version < xpathVersion30 {
		return false
	}

	if uri == NSXS {
		return xsConstructorVisible(version, name)
	}

	if uri != NSFn {
		return true
	}

	if functions31(name) && version < xpathVersion31 {
		return false
	}

	if functions30(name) && version < xpathVersion30 {
		return false
	}

	if version < xpathVersion30 && (name == nameRound && arity == profileBinaryArity || name == fnNameStringJoin && arity == profileUnaryArity) {
		return false
	}

	if version < xpathVersion30 && arity == profileNullaryArity {
		switch name {
		case fnNameData, fnNameDocumentURI, fnNameNilled, nameNodeName:
			return false
		}
	}

	if version < xpathVersion31 && (name == fnNameTokenize && arity == profileUnaryArity || name == fnNameTrace && arity == profileUnaryArity) {
		return false
	}

	return true
}

func xsConstructorVisible(version int, name string) bool {
	if name == lexicon.TypeNumeric && version < xpathVersion31 {
		return false
	}

	return version != xpathVersion20 || !isBuiltinListLocalName(name) && name != lexicon.TypeError
}

func checkVersionRegex(ctx context.Context, pattern, flags string, version int) error {
	if version != xpathVersion20 {
		return nil
	}

	if strings.Contains(flags, regexLiteralFlag) {
		return &xdm.Error{Code: errCodeFORX0001, Message: "flag q requires XPath 3.0"}
	}

	if err := Charge(ctx, len(pattern)); err != nil {
		return err
	}

	if strings.ContainsRune(flags, regexFreeSpacingRune) {
		pattern = stripFreeSpacing(pattern)
	}

	// Character class subtraction may nest brackets. Escaped delimiters
	// and anything inside a class are literal to the group syntax check.
	classDepth := 0
	escaped := false

	for i, r := range pattern {
		if escaped {
			escaped = false
			continue
		}

		if r == '\\' {
			escaped = true
			continue
		}

		switch r {
		case '[':
			classDepth++
		case ']':
			classDepth = max(classDepth-1, 0)
		case '(':
			if classDepth == 0 && strings.HasPrefix(pattern[i:], regexNoncapturingPrefix) {
				return &xdm.Error{Code: lexicon.ErrFORX0002, Message: "non-capturing groups require XPath 3.0"}
			}
		}
	}

	return nil
}

func validateProfileNode(node any, version int, namespaces map[string]string, hostFunction func(string, string, int) bool) error {
	if err := validateFunctionSyntax(node, version, namespaces); err != nil {
		return err
	}

	switch node.(type) {
	case ConcatExpr, SimpleMapExpr, LetClause, NamedFunctionRef, DynamicFunctionCall, InlineFunctionExpr, PlaceholderExpr, xdm.FunctionTest, xdm.NamespaceNodeTest:
		if version < xpathVersion30 {
			return profileError(lexicon.ErrXPST0003, "XPath 3.0 construct", version)
		}
	case MapConstructorExpr, ArrayConstructorExpr, xdm.MapTest, xdm.ArrayTest, LookupExpr, UnaryLookupExpr:
		if version < xpathVersion31 {
			return profileError(lexicon.ErrXPST0003, "maps, arrays or lookup", version)
		}
	case TryCatchExpr:
		return &xdm.Error{Code: lexicon.ErrXPST0003, Message: "try/catch is XQuery syntax, not XPath"}
	}

	if flow, ok := node.(FLWORExpr); ok && len(flow.Clauses) > 1 {
		_, firstFor := flow.Clauses[0].(ForClause)
		for _, clause := range flow.Clauses[1:] {
			_, isFor := clause.(ForClause)
			if firstFor != isFor {
				return &xdm.Error{Code: lexicon.ErrXPST0003, Message: "mixed FLWOR clauses are XQuery syntax"}
			}
		}
	}

	if clause, ok := node.(ForClause); ok && clause.PosVar != "" {
		return &xdm.Error{Code: lexicon.ErrXPST0003, Message: "positional for variables are XQuery syntax"}
	}

	return validateProfileFunction(node, version, namespaces, hostFunction)
}

func validateProfileFunction(node any, version int, namespaces map[string]string, hostFunction func(string, string, int) bool) error {
	var prefix, name string

	arity := unspecifiedFunctionArity

	switch n := node.(type) {
	case FunctionCall:
		prefix, name, arity = n.Prefix, n.Name, len(n.Args)
	case NamedFunctionRef:
		prefix, name, arity = n.Prefix, n.Name, n.Arity
	}

	if arity >= finiteArityFloor {
		uri := NSFn

		if prefix != "" {
			var ok bool

			uri, ok = namespaces[prefix]
			if !ok {
				uri, _ = PredeclaredNamespace(prefix)
			}
		}

		if strings.HasPrefix(name, lexicon.EQNamePrefix) {
			if end := strings.IndexByte(name, '}'); end >= 0 {
				uri, name = name[2:end], name[end+1:]
			}
		}

		if !functionVisible(version, uri, name, arity) && (hostFunction == nil || !hostFunction(uri, name, arity)) {
			return profileError(lexicon.ErrXPST0017, name+" function", version)
		}
	}

	return nil
}

func validateFunctionSyntax(node any, version int, namespaces map[string]string) error {
	var prefix, name string

	switch n := node.(type) {
	case InlineFunctionExpr:
		if n.EmptyBody && version < xpathVersion31 {
			return profileError(lexicon.ErrXPST0003, "empty inline function body", version)
		}

		if err := checkInlineParameterNames(n.Params, namespaces); err != nil {
			return err
		}
	case NamedFunctionRef:
		prefix, name = n.Prefix, n.Name
	case FunctionCall:
		prefix, name = n.Prefix, n.Name
	}

	if prefix == "" && reservedFunctionName(name, version) {
		return profileError(lexicon.ErrXPST0003, "reserved unprefixed function name", version)
	}

	return nil
}

func checkInlineParameterNames(params []FunctionParam, namespaces map[string]string) error {
	seen := make(map[string]struct{}, len(params))
	for _, param := range params {
		key := VariableKey(param.Name, namespaces)
		if _, duplicate := seen[key]; duplicate {
			return &xdm.Error{Code: errCodeXQST0039, Message: "duplicate inline function parameter: " + param.Name}
		}

		seen[key] = struct{}{}
	}

	return nil
}

func reservedFunctionName(name string, version int) bool {
	switch name {
	case lexicon.KindAttribute, lexicon.KindComment, lexicon.KindDocumentNode, lexicon.KindElement, nameEmptySequence, profileKeywordIf, lexicon.KindItem, lexicon.KindNode, lexicon.KindPI, lexicon.KindSchemaAttribute, lexicon.KindSchemaElement, lexicon.KindText, profileKeywordTypeSwitch:
		return true
	case nameFunction, lexicon.KindNamespaceNode, profileKeywordSwitch:
		return version >= xpathVersion30
	case keywordArray, keywordMap:
		return version >= xpathVersion31
	}

	return false
}
