package xpath

import (
	"context"
	"strings"
	"sync"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// Standard function type facts from the published W3C F&O recommendations:
// 2.0: https://www.w3.org/TR/2010/REC-xpath-functions-20101214/
// 3.0: https://www.w3.org/TR/2014/REC-xpath-functions-30-20140408/
// 3.1: https://www.w3.org/TR/2017/REC-xpath-functions-31-20170321/
// Each declaration is name|result|parameters, with version bits 2.0/3.0/3.1.
// Operator mappings, constructors and variadic concat are handled separately.
// The 2.0 XML source's bare collation type "string" is qualified as xs:string,
// as in the published function signatures. "none" denotes a function that
// never returns, rather than the empty-sequence() type.
//
//nolint:gochecknoglobals // Immutable standard type data is shared across independent evaluations.
var standardFunctionDeclarations = [...]struct {
	versions  uint8
	signature string
}{
	{4, "array:append|array(*)|array(*)|item()*"},
	{4, "array:filter|array(*)|array(*)|function(item()*) as xs:boolean"},
	{4, "array:flatten|item()*|item()*"},
	{4, "array:fold-left|item()*|array(*)|item()*|function(item()*, item()*) as item()*"},
	{4, "array:fold-right|item()*|array(*)|item()*|function(item()*, item()*) as item()*"},
	{4, "array:for-each-pair|array(*)|array(*)|array(*)|function(item()*, item()*) as item()*"},
	{4, "array:for-each|array(*)|array(*)|function(item()*) as item()*"},
	{4, "array:get|item()*|array(*)|xs:integer"},
	{4, "array:head|item()*|array(*)"},
	{4, "array:insert-before|array(*)|array(*)|xs:integer|item()*"},
	{4, "array:join|array(*)|array(*)*"},
	{4, "array:put|array(*)|array(*)|xs:integer|item()*"},
	{4, "array:remove|array(*)|array(*)|xs:integer*"},
	{4, "array:reverse|array(*)|array(*)"},
	{4, "array:size|xs:integer|array(*)"},
	{4, "array:sort|array(*)|array(*)"},
	{4, "array:sort|array(*)|array(*)|xs:string?"},
	{4, "array:sort|array(*)|array(*)|xs:string?|function(item()*) as xs:anyAtomicType*"},
	{4, "array:subarray|array(*)|array(*)|xs:integer"},
	{4, "array:subarray|array(*)|array(*)|xs:integer|xs:integer"},
	{4, "array:tail|array(*)|array(*)"},
	{7, "fn:QName|xs:QName|xs:string?|xs:string"},
	{7, "fn:abs|xs:numeric?|xs:numeric?"},
	{7, "fn:adjust-date-to-timezone|xs:date?|xs:date?"},
	{7, "fn:adjust-date-to-timezone|xs:date?|xs:date?|xs:dayTimeDuration?"},
	{7, "fn:adjust-dateTime-to-timezone|xs:dateTime?|xs:dateTime?"},
	{7, "fn:adjust-dateTime-to-timezone|xs:dateTime?|xs:dateTime?|xs:dayTimeDuration?"},
	{7, "fn:adjust-time-to-timezone|xs:time?|xs:time?"},
	{7, "fn:adjust-time-to-timezone|xs:time?|xs:time?|xs:dayTimeDuration?"},
	{6, "fn:analyze-string|element(fn:analyze-string-result)|xs:string?|xs:string"},
	{6, "fn:analyze-string|element(fn:analyze-string-result)|xs:string?|xs:string|xs:string"},
	{4, "fn:apply|item()*|function(*)|array(*)"},
	{6, "fn:available-environment-variables|xs:string*"},
	{7, "fn:avg|xs:anyAtomicType?|xs:anyAtomicType*"},
	{7, "fn:base-uri|xs:anyURI?"},
	{7, "fn:base-uri|xs:anyURI?|node()?"},
	{7, "fn:boolean|xs:boolean|item()*"},
	{7, "fn:ceiling|xs:numeric?|xs:numeric?"},
	{7, "fn:codepoint-equal|xs:boolean?|xs:string?|xs:string?"},
	{7, "fn:codepoints-to-string|xs:string|xs:integer*"},
	{4, "fn:collation-key|xs:base64Binary|xs:string"},
	{4, "fn:collation-key|xs:base64Binary|xs:string|xs:string"},
	{4, "fn:collection|item()*"},
	{4, "fn:collection|item()*|xs:string?"},
	{3, "fn:collection|node()*"},
	{3, "fn:collection|node()*|xs:string?"},
	{7, "fn:compare|xs:integer?|xs:string?|xs:string?"},
	{7, "fn:compare|xs:integer?|xs:string?|xs:string?|xs:string"},
	{4, "fn:contains-token|xs:boolean|xs:string*|xs:string"},
	{4, "fn:contains-token|xs:boolean|xs:string*|xs:string|xs:string"},
	{7, "fn:contains|xs:boolean|xs:string?|xs:string?"},
	{7, "fn:contains|xs:boolean|xs:string?|xs:string?|xs:string"},
	{7, "fn:count|xs:integer|item()*"},
	{1, "fn:current-dateTime|xs:dateTime"},
	{6, "fn:current-dateTime|xs:dateTimeStamp"},
	{7, "fn:current-date|xs:date"},
	{7, "fn:current-time|xs:time"},
	{6, "fn:data|xs:anyAtomicType*"},
	{7, "fn:data|xs:anyAtomicType*|item()*"},
	{7, "fn:dateTime|xs:dateTime?|xs:date?|xs:time?"},
	{7, "fn:day-from-dateTime|xs:integer?|xs:dateTime?"},
	{7, "fn:day-from-date|xs:integer?|xs:date?"},
	{7, "fn:days-from-duration|xs:integer?|xs:duration?"},
	{7, "fn:deep-equal|xs:boolean|item()*|item()*"},
	{7, "fn:deep-equal|xs:boolean|item()*|item()*|xs:string"},
	{7, "fn:default-collation|xs:string"},
	{4, "fn:default-language|xs:language"},
	{7, "fn:distinct-values|xs:anyAtomicType*|xs:anyAtomicType*"},
	{7, "fn:distinct-values|xs:anyAtomicType*|xs:anyAtomicType*|xs:string"},
	{7, "fn:doc-available|xs:boolean|xs:string?"},
	{6, "fn:document-uri|xs:anyURI?"},
	{7, "fn:document-uri|xs:anyURI?|node()?"},
	{7, "fn:doc|document-node()?|xs:string?"},
	{7, "fn:element-with-id|element()*|xs:string*"},
	{7, "fn:element-with-id|element()*|xs:string*|node()"},
	{7, "fn:empty|xs:boolean|item()*"},
	{7, "fn:encode-for-uri|xs:string|xs:string?"},
	{7, "fn:ends-with|xs:boolean|xs:string?|xs:string?"},
	{7, "fn:ends-with|xs:boolean|xs:string?|xs:string?|xs:string"},
	{6, "fn:environment-variable|xs:string?|xs:string"},
	{7, "fn:error|none"},
	{3, "fn:error|none|xs:QName"},
	{4, "fn:error|none|xs:QName?"},
	{7, "fn:error|none|xs:QName?|xs:string"},
	{7, "fn:error|none|xs:QName?|xs:string|item()*"},
	{7, "fn:escape-html-uri|xs:string|xs:string?"},
	{7, "fn:exactly-one|item()|item()*"},
	{7, "fn:exists|xs:boolean|item()*"},
	{7, "fn:false|xs:boolean"},
	{6, "fn:filter|item()*|item()*|function(item()) as xs:boolean"},
	{7, "fn:floor|xs:numeric?|xs:numeric?"},
	{6, "fn:fold-left|item()*|item()*|item()*|function(item()*, item()) as item()*"},
	{2, "fn:fold-right|item()*|item()*|item()*|function(item()*, item()) as item()*"},
	{4, "fn:fold-right|item()*|item()*|item()*|function(item(), item()*) as item()*"},
	{6, "fn:for-each-pair|item()*|item()*|item()*|function(item(), item()) as item()*"},
	{6, "fn:for-each|item()*|item()*|function(item()) as item()*"},
	{6, "fn:format-dateTime|xs:string?|xs:dateTime?|xs:string"},
	{6, "fn:format-dateTime|xs:string?|xs:dateTime?|xs:string|xs:string?|xs:string?|xs:string?"},
	{6, "fn:format-date|xs:string?|xs:date?|xs:string"},
	{6, "fn:format-date|xs:string?|xs:date?|xs:string|xs:string?|xs:string?|xs:string?"},
	{6, "fn:format-integer|xs:string|xs:integer?|xs:string"},
	{6, "fn:format-integer|xs:string|xs:integer?|xs:string|xs:string?"},
	{6, "fn:format-number|xs:string|xs:numeric?|xs:string"},
	{6, "fn:format-number|xs:string|xs:numeric?|xs:string|xs:string?"},
	{6, "fn:format-time|xs:string?|xs:time?|xs:string"},
	{6, "fn:format-time|xs:string?|xs:time?|xs:string|xs:string?|xs:string?|xs:string?"},
	{6, "fn:function-arity|xs:integer|function(*)"},
	{6, "fn:function-lookup|function(*)?|xs:QName|xs:integer"},
	{6, "fn:function-name|xs:QName?|function(*)"},
	{6, "fn:generate-id|xs:string"},
	{6, "fn:generate-id|xs:string|node()?"},
	{6, "fn:has-children|xs:boolean"},
	{6, "fn:has-children|xs:boolean|node()?"},
	{6, "fn:head|item()?|item()*"},
	{7, "fn:hours-from-dateTime|xs:integer?|xs:dateTime?"},
	{7, "fn:hours-from-duration|xs:integer?|xs:duration?"},
	{7, "fn:hours-from-time|xs:integer?|xs:time?"},
	{7, "fn:idref|node()*|xs:string*"},
	{7, "fn:idref|node()*|xs:string*|node()"},
	{7, "fn:id|element()*|xs:string*"},
	{7, "fn:id|element()*|xs:string*|node()"},
	{7, "fn:implicit-timezone|xs:dayTimeDuration"},
	{7, "fn:in-scope-prefixes|xs:string*|element()"},
	{7, "fn:index-of|xs:integer*|xs:anyAtomicType*|xs:anyAtomicType"},
	{7, "fn:index-of|xs:integer*|xs:anyAtomicType*|xs:anyAtomicType|xs:string"},
	{6, "fn:innermost|node()*|node()*"},
	{7, "fn:insert-before|item()*|item()*|xs:integer|item()*"},
	{7, "fn:iri-to-uri|xs:string|xs:string?"},
	{4, "fn:json-doc|item()?|xs:string?"},
	{4, "fn:json-doc|item()?|xs:string?|map(*)"},
	{4, "fn:json-to-xml|document-node()?|xs:string?"},
	{4, "fn:json-to-xml|document-node()?|xs:string?|map(*)"},
	{7, "fn:lang|xs:boolean|xs:string?"},
	{7, "fn:lang|xs:boolean|xs:string?|node()"},
	{7, "fn:last|xs:integer"},
	{4, "fn:load-xquery-module|map(*)|xs:string"},
	{4, "fn:load-xquery-module|map(*)|xs:string|map(*)"},
	{7, "fn:local-name-from-QName|xs:NCName?|xs:QName?"},
	{7, "fn:local-name|xs:string"},
	{7, "fn:local-name|xs:string|node()?"},
	{7, "fn:lower-case|xs:string|xs:string?"},
	{7, "fn:matches|xs:boolean|xs:string?|xs:string"},
	{7, "fn:matches|xs:boolean|xs:string?|xs:string|xs:string"},
	{7, "fn:max|xs:anyAtomicType?|xs:anyAtomicType*"},
	{7, "fn:max|xs:anyAtomicType?|xs:anyAtomicType*|xs:string"},
	{7, "fn:minutes-from-dateTime|xs:integer?|xs:dateTime?"},
	{7, "fn:minutes-from-duration|xs:integer?|xs:duration?"},
	{7, "fn:minutes-from-time|xs:integer?|xs:time?"},
	{7, "fn:min|xs:anyAtomicType?|xs:anyAtomicType*"},
	{7, "fn:min|xs:anyAtomicType?|xs:anyAtomicType*|xs:string"},
	{7, "fn:month-from-dateTime|xs:integer?|xs:dateTime?"},
	{7, "fn:month-from-date|xs:integer?|xs:date?"},
	{7, "fn:months-from-duration|xs:integer?|xs:duration?"},
	{7, "fn:namespace-uri-for-prefix|xs:anyURI?|xs:string?|element()"},
	{7, "fn:namespace-uri-from-QName|xs:anyURI?|xs:QName?"},
	{7, "fn:namespace-uri|xs:anyURI"},
	{7, "fn:namespace-uri|xs:anyURI|node()?"},
	{7, "fn:name|xs:string"},
	{7, "fn:name|xs:string|node()?"},
	{2, "fn:nilled|xs:boolean"},
	{4, "fn:nilled|xs:boolean?"},
	{7, "fn:nilled|xs:boolean?|node()?"},
	{6, "fn:node-name|xs:QName?"},
	{7, "fn:node-name|xs:QName?|node()?"},
	{7, "fn:normalize-space|xs:string"},
	{7, "fn:normalize-space|xs:string|xs:string?"},
	{7, "fn:normalize-unicode|xs:string|xs:string?"},
	{7, "fn:normalize-unicode|xs:string|xs:string?|xs:string"},
	{7, "fn:not|xs:boolean|item()*"},
	{7, "fn:number|xs:double"},
	{7, "fn:number|xs:double|xs:anyAtomicType?"},
	{7, "fn:one-or-more|item()+|item()*"},
	{6, "fn:outermost|node()*|node()*"},
	{4, "fn:parse-ietf-date|xs:dateTime?|xs:string?"},
	{4, "fn:parse-json|item()?|xs:string?"},
	{4, "fn:parse-json|item()?|xs:string?|map(*)"},
	{6, "fn:parse-xml-fragment|document-node()?|xs:string?"},
	{6, "fn:parse-xml|document-node(element(*))?|xs:string?"},
	{6, "fn:path|xs:string?"},
	{6, "fn:path|xs:string?|node()?"},
	{7, "fn:position|xs:integer"},
	{7, "fn:prefix-from-QName|xs:NCName?|xs:QName?"},
	{4, "fn:random-number-generator|map(xs:string, item())"},
	{4, "fn:random-number-generator|map(xs:string, item())|xs:anyAtomicType?"},
	{7, "fn:remove|item()*|item()*|xs:integer"},
	{7, "fn:replace|xs:string|xs:string?|xs:string|xs:string"},
	{7, "fn:replace|xs:string|xs:string?|xs:string|xs:string|xs:string"},
	{7, "fn:resolve-QName|xs:QName?|xs:string?|element()"},
	{7, "fn:resolve-uri|xs:anyURI?|xs:string?"},
	{7, "fn:resolve-uri|xs:anyURI?|xs:string?|xs:string"},
	{7, "fn:reverse|item()*|item()*"},
	{7, "fn:root|node()"},
	{7, "fn:root|node()?|node()?"},
	{7, "fn:round-half-to-even|xs:numeric?|xs:numeric?"},
	{7, "fn:round-half-to-even|xs:numeric?|xs:numeric?|xs:integer"},
	{7, "fn:round|xs:numeric?|xs:numeric?"},
	{6, "fn:round|xs:numeric?|xs:numeric?|xs:integer"},
	{7, "fn:seconds-from-dateTime|xs:decimal?|xs:dateTime?"},
	{7, "fn:seconds-from-duration|xs:decimal?|xs:duration?"},
	{7, "fn:seconds-from-time|xs:decimal?|xs:time?"},
	{6, "fn:serialize|xs:string|item()*"},
	{2, "fn:serialize|xs:string|item()*|element(output:serialization-parameters)?"},
	{4, "fn:serialize|xs:string|item()*|item()?"},
	{4, "fn:sort|item()*|item()*"},
	{4, "fn:sort|item()*|item()*|xs:string?"},
	{4, "fn:sort|item()*|item()*|xs:string?|function(item()) as xs:anyAtomicType*"},
	{7, "fn:starts-with|xs:boolean|xs:string?|xs:string?"},
	{7, "fn:starts-with|xs:boolean|xs:string?|xs:string?|xs:string"},
	{7, "fn:static-base-uri|xs:anyURI?"},
	{4, "fn:string-join|xs:string|xs:anyAtomicType*"},
	{4, "fn:string-join|xs:string|xs:anyAtomicType*|xs:string"},
	{2, "fn:string-join|xs:string|xs:string*"},
	{3, "fn:string-join|xs:string|xs:string*|xs:string"},
	{7, "fn:string-length|xs:integer"},
	{7, "fn:string-length|xs:integer|xs:string?"},
	{7, "fn:string-to-codepoints|xs:integer*|xs:string?"},
	{7, "fn:string|xs:string"},
	{7, "fn:string|xs:string|item()?"},
	{7, "fn:subsequence|item()*|item()*|xs:double"},
	{7, "fn:subsequence|item()*|item()*|xs:double|xs:double"},
	{7, "fn:substring-after|xs:string|xs:string?|xs:string?"},
	{7, "fn:substring-after|xs:string|xs:string?|xs:string?|xs:string"},
	{7, "fn:substring-before|xs:string|xs:string?|xs:string?"},
	{7, "fn:substring-before|xs:string|xs:string?|xs:string?|xs:string"},
	{7, "fn:substring|xs:string|xs:string?|xs:double"},
	{7, "fn:substring|xs:string|xs:string?|xs:double|xs:double"},
	{7, "fn:sum|xs:anyAtomicType?|xs:anyAtomicType*|xs:anyAtomicType?"},
	{7, "fn:sum|xs:anyAtomicType|xs:anyAtomicType*"},
	{6, "fn:tail|item()*|item()*"},
	{7, "fn:timezone-from-dateTime|xs:dayTimeDuration?|xs:dateTime?"},
	{7, "fn:timezone-from-date|xs:dayTimeDuration?|xs:date?"},
	{7, "fn:timezone-from-time|xs:dayTimeDuration?|xs:time?"},
	{4, "fn:tokenize|xs:string*|xs:string?"},
	{7, "fn:tokenize|xs:string*|xs:string?|xs:string"},
	{7, "fn:tokenize|xs:string*|xs:string?|xs:string|xs:string"},
	{4, "fn:trace|item()*|item()*"},
	{7, "fn:trace|item()*|item()*|xs:string"},
	{4, "fn:transform|map(*)|map(*)"},
	{7, "fn:translate|xs:string|xs:string?|xs:string|xs:string"},
	{7, "fn:true|xs:boolean"},
	{7, "fn:unordered|item()*|item()*"},
	{6, "fn:unparsed-text-available|xs:boolean|xs:string?"},
	{6, "fn:unparsed-text-available|xs:boolean|xs:string?|xs:string"},
	{6, "fn:unparsed-text-lines|xs:string*|xs:string?"},
	{6, "fn:unparsed-text-lines|xs:string*|xs:string?|xs:string"},
	{6, "fn:unparsed-text|xs:string?|xs:string?"},
	{6, "fn:unparsed-text|xs:string?|xs:string?|xs:string"},
	{7, "fn:upper-case|xs:string|xs:string?"},
	{6, "fn:uri-collection|xs:anyURI*"},
	{6, "fn:uri-collection|xs:anyURI*|xs:string?"},
	{4, "fn:xml-to-json|xs:string?|node()?"},
	{4, "fn:xml-to-json|xs:string?|node()?|map(*)"},
	{7, "fn:year-from-dateTime|xs:integer?|xs:dateTime?"},
	{7, "fn:year-from-date|xs:integer?|xs:date?"},
	{7, "fn:years-from-duration|xs:integer?|xs:duration?"},
	{7, "fn:zero-or-one|item()?|item()*"},
	{4, "map:contains|xs:boolean|map(*)|xs:anyAtomicType"},
	{4, "map:entry|map(*)|xs:anyAtomicType|item()*"},
	{4, "map:find|array(*)|item()*|xs:anyAtomicType"},
	{4, "map:for-each|item()*|map(*)|function(xs:anyAtomicType, item()*) as item()*"},
	{4, "map:get|item()*|map(*)|xs:anyAtomicType"},
	{4, "map:keys|xs:anyAtomicType*|map(*)"},
	{4, "map:merge|map(*)|map(*)*"},
	{4, "map:merge|map(*)|map(*)*|map(*)"},
	{4, "map:put|map(*)|map(*)|xs:anyAtomicType|item()*"},
	{4, "map:remove|map(*)|map(*)|xs:anyAtomicType*"},
	{4, "map:size|xs:integer|map(*)"},
	{6, "math:acos|xs:double?|xs:double?"},
	{6, "math:asin|xs:double?|xs:double?"},
	{6, "math:atan2|xs:double|xs:double|xs:double"},
	{6, "math:atan|xs:double?|xs:double?"},
	{6, "math:cos|xs:double?|xs:double?"},
	{6, "math:exp10|xs:double?|xs:double?"},
	{6, "math:exp|xs:double?|xs:double?"},
	{6, "math:log10|xs:double?|xs:double?"},
	{6, "math:log|xs:double?|xs:double?"},
	{6, "math:pi|xs:double"},
	{6, "math:pow|xs:double?|xs:double?|xs:numeric"},
	{6, "math:sin|xs:double?|xs:double?"},
	{6, "math:sqrt|xs:double?|xs:double?"},
	{6, "math:tan|xs:double?|xs:double?"},
}

//nolint:gochecknoglobals // Immutable standard type data is shared across independent evaluations.
var standardFunctionCatalogs = sync.OnceValue(func() [3]map[sigKey]*functionSignature {
	var catalogs [3]map[sigKey]*functionSignature
	for i := range catalogs {
		catalogs[i] = make(map[sigKey]*functionSignature)
	}

	namespaces := PredeclaredNamespaces()
	namespaces["output"] = lexicon.NamespaceSerialization
	types := make(map[string]xdm.SequenceType)
	sequenceType := func(source string) xdm.SequenceType {
		if result, found := types[source]; found {
			return result
		}

		parsed, err := ParseSequenceType(source)
		if err != nil {
			panic(err)
		}

		bound, err := BindSequenceType(context.Background(), parsed, namespaces, "")
		if err != nil {
			panic(err)
		}

		types[source] = bound

		return bound
	}

	for _, declaration := range standardFunctionDeclarations {
		fields := strings.Split(declaration.signature, "|")
		prefix, name, _ := strings.Cut(fields[0], ":")

		signature := &functionSignature{ParamTypes: make([]xdm.SequenceType, len(fields)-2)}
		for i, parameter := range fields[2:] {
			signature.ParamTypes[i] = sequenceType(parameter)
		}

		if fields[1] != "none" {
			result := sequenceType(fields[1])
			signature.ReturnType = &result
		}

		key := sigKey{URI: namespaces[prefix], Name: name, Arity: len(signature.ParamTypes)}

		for i := range catalogs {
			if declaration.versions&(1<<i) != 0 {
				catalogs[i][key] = signature
			}
		}
	}

	return catalogs
})

// Catalog metadata is immutable and bound in the library's own static context.
func lookupStandardSignature(version int, key sigKey) *functionSignature {
	index := 2
	if version != 0 && version < 30 {
		index = 0
	} else if version == 30 {
		index = 1
	}

	return standardFunctionCatalogs()[index][key]
}
