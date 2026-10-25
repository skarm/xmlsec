package xslt

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

const fnNameUnparsedTextAvailable = "unparsed-text-available"

// legacyTextFunction retains the XSLT 2.0 host contract, before the text
// functions joined the F&O library with different signatures and error names.
type legacyTextFunction struct {
	xpath.TypedFunctionByArity
	name string
}

func newLegacyTextFunction(name string) xpath.Function {
	return &legacyTextFunction{TypedFunctionByArity: xpath.HostBuiltin(20, name), name: name}
}

func (f *legacyTextFunction) FuncParamTypesForArity(arity int) []xdm.SequenceType {
	params := f.TypedFunctionByArity.FuncParamTypesForArity(arity)
	if f.name == fnNameUnparsedTextAvailable && arity == 2 {
		params = slices.Clone(params)
		params[1].Occurrence = xdm.OccurrenceZeroOrOne
	}

	return params
}

func (f *legacyTextFunction) Call(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if f.name == fnNameUnparsedTextAvailable && len(args) == 2 && xdm.SequenceLen(args[1]) == 0 {
		args = args[:1]
	}

	result, err := f.TypedFunctionByArity.Call(ctx, args)
	if failure := preserveControlFailure(ctx, err); failure != nil {
		return nil, failure
	}

	if detail, ok := errors.AsType[*xdm.Error](err); ok && detail.CodeQName().URI == lexicon.NamespaceErr {
		code := ""

		switch detail.Code {
		case "FOUT1170":
			code = "XTDE1170"
		case "FOUT1190":
			code = "XTDE1190"
		case "FOUT1200":
			code = "XTDE1200"
		}

		if code != "" {
			return nil, dynamicErrorCause(code, err, "%s: %s", f.name, detail.Message)
		}
	}

	return result, err
}

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
