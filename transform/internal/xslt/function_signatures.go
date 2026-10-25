package xslt

import (
	"context"
	"strings"
	"sync"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type functionTypeKey struct {
	name  string
	arity int
}
type functionTypes struct {
	params []xdm.SequenceType
	result *xdm.SequenceType
}

// XSLT-specific function type facts, bound independently of caller prefixes.
// https://www.w3.org/TR/2017/REC-xslt-30-20170608/#additional-functions
// F&O functions overridden by the host retain their core library signatures.
//
//nolint:gochecknoglobals // Immutable standard type data is shared across independent evaluations.
var xsltFunctionTypes = sync.OnceValue(func() map[functionTypeKey]functionTypes {
	result := make(map[functionTypeKey]functionTypes)
	namespaces := xpath.PredeclaredNamespaces()
	parse := func(source string) xdm.SequenceType {
		parsed, err := xpath.ParseSequenceType(source)
		if err != nil {
			panic(err)
		}

		bound, err := xpath.BindSequenceType(context.Background(), parsed, namespaces, "")
		if err != nil {
			panic(err)
		}

		return bound
	}

	for _, declaration := range []string{
		"current|item()",
		"document|node()*|item()*",
		"key|node()*|xs:string|xs:anyAtomicType*",
		"key|node()*|xs:string|xs:anyAtomicType*|node()",
		"document|node()*|item()*|node()",
		"unparsed-entity-uri|xs:anyURI|xs:string",
		"unparsed-entity-uri|xs:anyURI|xs:string|node()",
		"unparsed-entity-public-id|xs:string|xs:string",
		"unparsed-entity-public-id|xs:string|xs:string|node()",
		"current-group|item()*",
		"current-grouping-key|xs:anyAtomicType*",
		"accumulator-before|item()*|xs:string",
		"accumulator-after|item()*|xs:string",
		"copy-of|item()",
		"copy-of|item()*|item()*",
		"snapshot|item()",
		"snapshot|item()*|item()*",
		"regex-group|xs:string|xs:integer",
		"available-system-properties|xs:QName*",
		"stream-available|xs:boolean|xs:string?",
		"current-output-uri|xs:anyURI?",
		"current-merge-group|item()*",
		"current-merge-group|item()*|xs:string",
		"current-merge-key|xs:anyAtomicType*",
	} {
		fields := strings.Split(declaration, "|")

		value := functionTypes{params: make([]xdm.SequenceType, len(fields)-2)}
		for i, parameter := range fields[2:] {
			value.params[i] = parse(parameter)
		}

		returns := parse(fields[1])
		value.result = &returns
		result[functionTypeKey{fields[0], len(value.params)}] = value
	}

	return result
})
