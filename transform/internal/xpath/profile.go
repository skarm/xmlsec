// Copyright (c) 2026 xmlsec contributors.
// MIT License. Version boundaries were cross-checked against knroy/go-xml
// eb327e4c08420169c271e94708b5c803d58e91f9 (MIT, Komol Nath Roy).

package xpath

import (
	"context"
	"maps"
	"reflect"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// CheckTypeLanguage applies the same version boundaries to standalone types.
func CheckTypeLanguage(st xdm.SequenceType, version int) error {
	return walkProfile(reflect.ValueOf(st), func(node any) error {
		switch node.(type) {
		case xdm.FunctionTest:
			if version < 30 {
				return profileError(errCodeXPST0003, "function types", version)
			}
		case xdm.MapTest, xdm.ArrayTest:
			if version < 31 {
				return profileError(errCodeXPST0003, "map or array types", version)
			}
		}

		return nil
	})
}

func profileError(code, feature string, version int) error {
	return &xdm.Error{Code: code, Message: feature + " is unavailable in XPath " + map[int]string{10: version10, 20: "2.0", 30: "3.0", 31: "3.1"}[version]}
}

// ValidNCName checks a prefix-free XML name used by the public API.
func ValidNCName(name string) bool { return xmlchar.IsValidNCName(name) }

// CheckStandaloneFunctions rejects unknown and non-standard static calls in
// the standalone API. XSLT supplies its own user functions and validates them
// through its compiler, so it does not use this check.
func CheckStandaloneFunctions(expr *Expression, namespaces map[string]string, extensions ...map[string]Function) error {
	return walkProfile(reflect.ValueOf(expr.astExpr()), func(node any) error {
		var prefix, name string

		arity := -1

		switch n := node.(type) {
		case FunctionCall:
			prefix, name, arity = n.Prefix, n.Name, len(n.Args)
		case NamedFunctionRef:
			prefix, name, arity = n.Prefix, n.Name, n.Arity
		}

		return checkStandaloneCall(expr.version, prefix, name, arity, namespaces, extensions)
	})
}

func checkStandaloneCall(version int, prefix, name string, arity int, namespaces map[string]string, extensions []map[string]Function) error {
	if arity < 0 {
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

	if strings.HasPrefix(name, "Q{") {
		if end := strings.IndexByte(name, '}'); end >= 0 {
			uri, name = name[2:end], name[end+1:]
		}
	}

	for _, registry := range extensions {
		if fn := registry[xdm.ClarkName(uri, name)]; fn != nil {
			if err := checkArity(fn, name, arity); err != nil {
				return &xdm.Error{Code: "XPST0017", Message: "invalid application function arity: " + name, Cause: err}
			}

			return nil
		}
	}

	if version == 10 && (prefix != "" || !xpath10FunctionArity(name, arity)) || !StandardFunctionAcceptsArity(uri, name, arity) {
		return &xdm.Error{Code: "XPST0017", Message: "unknown function or arity: " + name}
	}

	return nil
}

// Language pins the grammar and function library to XPath 1.0, 2.0, 3.0 or 3.1.
// Zero selects the engine default profile.
func (c Compiler) Language(version int, namespaces map[string]string) Compiler {
	return Compiler{cfg: &compilerCfg{version: version, namespaces: maps.Clone(namespaces)}}
}

func validateVersionTokens(tokens []Token, version int) error {
	if version != 10 && version != 20 && version != 30 && version != 31 {
		return profileError(errCodeXPST0003, "language version", version)
	}

	for i, token := range tokens {
		if version == 10 {
			if token.Type == TokenNumber && strings.ContainsAny(token.Value, "eE") || token.Type == TokenUnion {
				return profileError(errCodeXPST0003, "numeric literal or union keyword", version)
			}

			if token.Value == nameProcessingInstruction && i+2 < len(tokens) && tokens[i+1].Type == TokenLParen && tokens[i+2].Type != TokenString && tokens[i+2].Type != TokenRParen {
				return profileError(errCodeXPST0003, "PI target must be a string literal", 10)
			}
		}

		if version < 31 && token.Type == TokenArrow {
			return profileError(errCodeXPST0003, "arrow operator", version)
		}

		if version < 30 && token.Type != TokenString && strings.HasPrefix(token.Value, "Q{") {
			return profileError(errCodeXPST0003, "URI-qualified names", version)
		}
	}

	return nil
}

// walkProfile visits only exported AST fields, never literal payloads. The
// closed Expr/NodeTest interfaces keep this traversal exhaustive as new AST
// forms are added, including types nested inside function declarations.
func walkProfile(value reflect.Value, visit func(any) error) error {
	if !value.IsValid() {
		return nil
	}

	if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}

		return walkProfile(value.Elem(), visit)
	}

	switch value.Kind() {
	case reflect.Struct:
		if value.CanInterface() {
			if err := visit(value.Interface()); err != nil {
				return err
			}

			if _, ok := value.Interface().(LiteralExpr); ok {
				return nil
			}
		}

		for i := 0; i < value.NumField(); i++ {
			if value.Type().Field(i).IsExported() {
				if err := walkProfile(value.Field(i), visit); err != nil {
					return err
				}
			}
		}
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			if err := walkProfile(value.Index(i), visit); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateVersionExpr(ast Expr, version int, namespaces map[string]string) error {
	if version == 10 {
		return validateXPath10Expr(ast)
	}

	return walkProfile(reflect.ValueOf(ast), func(node any) error {
		return validateProfileNode(node, version, namespaces)
	})
}

func lookupfunctions30(key string) (bool, bool) {
	switch key {
	case fnNameHead, nameTail, nameHasChildren, "innermost", "outermost", namePath, "analyze-string", nameGenerateId, "format-integer", "function-name", "function-arity", "function-lookup", nameForEach, nameFilter, nameFoldLeft, nameFoldRight, nameForEachPair, "environment-variable", "available-environment-variables", "uri-collection", "serialize", "parse-xml", "parse-xml-fragment", "unparsed-text-lines":
		return true, true
	}

	var zero bool

	return zero, false
}

func functions30(key string) bool { value, _ := lookupfunctions30(key); return value }

func lookupfunctions31(key string) (bool, bool) {
	switch key {
	case "parse-json", "json-doc", "json-to-xml", "xml-to-json", "transform", "default-language", "load-xquery-module", "apply", "collation-key", "contains-token", "parse-ietf-date", "random-number-generator", nameSort:
		return true, true
	}

	var zero bool

	return zero, false
}

func functions31(key string) bool { value, _ := lookupfunctions31(key); return value }

func functionVisible(version int, uri, name string, arity int) bool {
	if version == 0 {
		return true
	}

	if version == 10 {
		return uri == NSFn && xpath10FunctionArity(name, arity)
	}

	if (uri == NSMap || uri == NSArray) && version < 31 {
		return false
	}

	if uri == NSMath && version < 30 {
		return false
	}

	if uri != NSFn {
		return true
	}

	if functions31(name) && version < 31 {
		return false
	}

	if functions30(name) && version < 30 {
		return false
	}

	if version < 30 && (name == nameRound && arity == 2 || name == "string-join" && arity == 1) {
		return false
	}

	if version < 31 && (name == "tokenize" && arity == 1 || name == "trace" && arity == 1) {
		return false
	}

	return true
}

func checkVersionRegex(ctx context.Context, pattern, flags string) error {
	ec := getFnContext(ctx)
	if ec == nil || ec.version != 20 {
		return nil
	}

	if strings.Contains(flags, "q") {
		return &xdm.Error{Code: "FORX0001", Message: "flag q requires XPath 3.0"}
	}
	// Escaped characters and character classes cannot start a non-capturing group.
	inClass, escaped := false, false
	for i, r := range pattern {
		if escaped {
			escaped = false
			continue
		}

		if r == '\\' {
			escaped = true
			continue
		}

		if r == '[' {
			inClass = true
		}

		if r == ']' {
			inClass = false
		}

		if !inClass && r == '(' && strings.HasPrefix(pattern[i:], "(?:") {
			return &xdm.Error{Code: "FORX0002", Message: "non-capturing groups require XPath 3.0"}
		}
	}

	return nil
}

func validateProfileNode(node any, version int, namespaces map[string]string) error {
	switch node.(type) {
	case ConcatExpr, SimpleMapExpr, LetClause, NamedFunctionRef, DynamicFunctionCall, InlineFunctionExpr, PlaceholderExpr, xdm.FunctionTest, xdm.NamespaceNodeTest:
		if version < 30 {
			return profileError(errCodeXPST0003, "XPath 3.0 construct", version)
		}
	case MapConstructorExpr, ArrayConstructorExpr, xdm.MapTest, xdm.ArrayTest, LookupExpr, UnaryLookupExpr:
		if version < 31 {
			return profileError(errCodeXPST0003, "maps, arrays or lookup", version)
		}
	case TryCatchExpr:
		return &xdm.Error{Code: errCodeXPST0003, Message: "try/catch is XQuery syntax, not XPath"}
	}

	if flow, ok := node.(FLWORExpr); ok && len(flow.Clauses) > 1 {
		_, firstFor := flow.Clauses[0].(ForClause)
		for _, clause := range flow.Clauses[1:] {
			_, isFor := clause.(ForClause)
			if firstFor != isFor {
				return &xdm.Error{Code: errCodeXPST0003, Message: "mixed FLWOR clauses are XQuery syntax"}
			}
		}
	}

	if clause, ok := node.(ForClause); ok && clause.PosVar != "" {
		return &xdm.Error{Code: errCodeXPST0003, Message: "positional for variables are XQuery syntax"}
	}

	var prefix, name string

	arity := -1

	switch n := node.(type) {
	case FunctionCall:
		prefix, name, arity = n.Prefix, n.Name, len(n.Args)
	case NamedFunctionRef:
		prefix, name, arity = n.Prefix, n.Name, n.Arity
	}

	if arity >= 0 {
		uri := NSFn

		if prefix != "" {
			var ok bool

			uri, ok = namespaces[prefix]
			if !ok {
				uri, _ = PredeclaredNamespace(prefix)
			}
		}

		if strings.HasPrefix(name, "Q{") {
			if end := strings.IndexByte(name, '}'); end >= 0 {
				uri, name = name[2:end], name[end+1:]
			}
		}

		if !functionVisible(version, uri, name, arity) {
			return profileError("XPST0017", name+" function", version)
		}
	}

	return nil
}
