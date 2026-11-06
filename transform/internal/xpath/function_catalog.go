package xpath

import (
	"context"
	"strings"
	"sync"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// Catalog slots follow XPath2.0/3.0/3.1 order. The untyped bits encode which
// editions share a standard declaration; combinations below retain that mask.
const (
	catalogXPath20Bit = 1 << iota
	catalogXPath30Bit
	catalogXPath31Bit
)

const (
	catalogXPath20Index = iota
	catalogXPath30Index
	catalogXPath31Index
	standardFunctionCatalogCount = 3
)

// Each declaration has name and result headers before its parameters. The
// sentinel denotes a function that never returns, not empty-sequence(). The
// serialization prefix belongs to this library's own signature static context.
const (
	catalogSignatureHeaderFields = 2
	catalogNeverReturnsType      = "none"
	catalogSerializationPrefix   = "output"
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
	{catalogXPath31Bit, "array:append|array(*)|array(*)|item()*"},
	{catalogXPath31Bit, "array:filter|array(*)|array(*)|function(item()*) as xs:boolean"},
	{catalogXPath31Bit, "array:flatten|item()*|item()*"},
	{catalogXPath31Bit, "array:fold-left|item()*|array(*)|item()*|function(item()*, item()*) as item()*"},
	{catalogXPath31Bit, "array:fold-right|item()*|array(*)|item()*|function(item()*, item()*) as item()*"},
	{catalogXPath31Bit, "array:for-each-pair|array(*)|array(*)|array(*)|function(item()*, item()*) as item()*"},
	{catalogXPath31Bit, "array:for-each|array(*)|array(*)|function(item()*) as item()*"},
	{catalogXPath31Bit, "array:get|item()*|array(*)|xs:integer"},
	{catalogXPath31Bit, "array:head|item()*|array(*)"},
	{catalogXPath31Bit, "array:insert-before|array(*)|array(*)|xs:integer|item()*"},
	{catalogXPath31Bit, "array:join|array(*)|array(*)*"},
	{catalogXPath31Bit, "array:put|array(*)|array(*)|xs:integer|item()*"},
	{catalogXPath31Bit, "array:remove|array(*)|array(*)|xs:integer*"},
	{catalogXPath31Bit, "array:reverse|array(*)|array(*)"},
	{catalogXPath31Bit, "array:size|xs:integer|array(*)"},
	{catalogXPath31Bit, "array:sort|array(*)|array(*)"},
	{catalogXPath31Bit, "array:sort|array(*)|array(*)|xs:string?"},
	{catalogXPath31Bit, "array:sort|array(*)|array(*)|xs:string?|function(item()*) as xs:anyAtomicType*"},
	{catalogXPath31Bit, "array:subarray|array(*)|array(*)|xs:integer"},
	{catalogXPath31Bit, "array:subarray|array(*)|array(*)|xs:integer|xs:integer"},
	{catalogXPath31Bit, "array:tail|array(*)|array(*)"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:QName|xs:QName|xs:string?|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:abs|xs:numeric?|xs:numeric?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:adjust-date-to-timezone|xs:date?|xs:date?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:adjust-date-to-timezone|xs:date?|xs:date?|xs:dayTimeDuration?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:adjust-dateTime-to-timezone|xs:dateTime?|xs:dateTime?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:adjust-dateTime-to-timezone|xs:dateTime?|xs:dateTime?|xs:dayTimeDuration?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:adjust-time-to-timezone|xs:time?|xs:time?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:adjust-time-to-timezone|xs:time?|xs:time?|xs:dayTimeDuration?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:analyze-string|element(fn:analyze-string-result)|xs:string?|xs:string"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:analyze-string|element(fn:analyze-string-result)|xs:string?|xs:string|xs:string"},
	{catalogXPath31Bit, "fn:apply|item()*|function(*)|array(*)"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:available-environment-variables|xs:string*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:avg|xs:anyAtomicType?|xs:anyAtomicType*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:base-uri|xs:anyURI?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:base-uri|xs:anyURI?|node()?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:boolean|xs:boolean|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:ceiling|xs:numeric?|xs:numeric?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:codepoint-equal|xs:boolean?|xs:string?|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:codepoints-to-string|xs:string|xs:integer*"},
	{catalogXPath31Bit, "fn:collation-key|xs:base64Binary|xs:string"},
	{catalogXPath31Bit, "fn:collation-key|xs:base64Binary|xs:string|xs:string"},
	{catalogXPath31Bit, "fn:collection|item()*"},
	{catalogXPath31Bit, "fn:collection|item()*|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit, "fn:collection|node()*"},
	{catalogXPath20Bit | catalogXPath30Bit, "fn:collection|node()*|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:compare|xs:integer?|xs:string?|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:compare|xs:integer?|xs:string?|xs:string?|xs:string"},
	{catalogXPath31Bit, "fn:contains-token|xs:boolean|xs:string*|xs:string"},
	{catalogXPath31Bit, "fn:contains-token|xs:boolean|xs:string*|xs:string|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:contains|xs:boolean|xs:string?|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:contains|xs:boolean|xs:string?|xs:string?|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:count|xs:integer|item()*"},
	{catalogXPath20Bit, "fn:current-dateTime|xs:dateTime"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:current-dateTime|xs:dateTimeStamp"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:current-date|xs:date"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:current-time|xs:time"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:data|xs:anyAtomicType*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:data|xs:anyAtomicType*|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:dateTime|xs:dateTime?|xs:date?|xs:time?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:day-from-dateTime|xs:integer?|xs:dateTime?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:day-from-date|xs:integer?|xs:date?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:days-from-duration|xs:integer?|xs:duration?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:deep-equal|xs:boolean|item()*|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:deep-equal|xs:boolean|item()*|item()*|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:default-collation|xs:string"},
	{catalogXPath31Bit, "fn:default-language|xs:language"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:distinct-values|xs:anyAtomicType*|xs:anyAtomicType*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:distinct-values|xs:anyAtomicType*|xs:anyAtomicType*|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:doc-available|xs:boolean|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:document-uri|xs:anyURI?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:document-uri|xs:anyURI?|node()?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:doc|document-node()?|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:element-with-id|element()*|xs:string*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:element-with-id|element()*|xs:string*|node()"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:empty|xs:boolean|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:encode-for-uri|xs:string|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:ends-with|xs:boolean|xs:string?|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:ends-with|xs:boolean|xs:string?|xs:string?|xs:string"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:environment-variable|xs:string?|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:error|none"},
	{catalogXPath20Bit | catalogXPath30Bit, "fn:error|none|xs:QName"},
	{catalogXPath31Bit, "fn:error|none|xs:QName?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:error|none|xs:QName?|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:error|none|xs:QName?|xs:string|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:escape-html-uri|xs:string|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:exactly-one|item()|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:exists|xs:boolean|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:false|xs:boolean"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:filter|item()*|item()*|function(item()) as xs:boolean"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:floor|xs:numeric?|xs:numeric?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:fold-left|item()*|item()*|item()*|function(item()*, item()) as item()*"},
	{catalogXPath30Bit, "fn:fold-right|item()*|item()*|item()*|function(item()*, item()) as item()*"},
	{catalogXPath31Bit, "fn:fold-right|item()*|item()*|item()*|function(item(), item()*) as item()*"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:for-each-pair|item()*|item()*|item()*|function(item(), item()) as item()*"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:for-each|item()*|item()*|function(item()) as item()*"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:format-dateTime|xs:string?|xs:dateTime?|xs:string"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:format-dateTime|xs:string?|xs:dateTime?|xs:string|xs:string?|xs:string?|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:format-date|xs:string?|xs:date?|xs:string"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:format-date|xs:string?|xs:date?|xs:string|xs:string?|xs:string?|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:format-integer|xs:string|xs:integer?|xs:string"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:format-integer|xs:string|xs:integer?|xs:string|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:format-number|xs:string|xs:numeric?|xs:string"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:format-number|xs:string|xs:numeric?|xs:string|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:format-time|xs:string?|xs:time?|xs:string"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:format-time|xs:string?|xs:time?|xs:string|xs:string?|xs:string?|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:function-arity|xs:integer|function(*)"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:function-lookup|function(*)?|xs:QName|xs:integer"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:function-name|xs:QName?|function(*)"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:generate-id|xs:string"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:generate-id|xs:string|node()?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:has-children|xs:boolean"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:has-children|xs:boolean|node()?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:head|item()?|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:hours-from-dateTime|xs:integer?|xs:dateTime?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:hours-from-duration|xs:integer?|xs:duration?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:hours-from-time|xs:integer?|xs:time?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:idref|node()*|xs:string*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:idref|node()*|xs:string*|node()"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:id|element()*|xs:string*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:id|element()*|xs:string*|node()"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:implicit-timezone|xs:dayTimeDuration"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:in-scope-prefixes|xs:string*|element()"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:index-of|xs:integer*|xs:anyAtomicType*|xs:anyAtomicType"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:index-of|xs:integer*|xs:anyAtomicType*|xs:anyAtomicType|xs:string"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:innermost|node()*|node()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:insert-before|item()*|item()*|xs:integer|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:iri-to-uri|xs:string|xs:string?"},
	{catalogXPath31Bit, "fn:json-doc|item()?|xs:string?"},
	{catalogXPath31Bit, "fn:json-doc|item()?|xs:string?|map(*)"},
	{catalogXPath31Bit, "fn:json-to-xml|document-node()?|xs:string?"},
	{catalogXPath31Bit, "fn:json-to-xml|document-node()?|xs:string?|map(*)"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:lang|xs:boolean|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:lang|xs:boolean|xs:string?|node()"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:last|xs:integer"},
	{catalogXPath31Bit, "fn:load-xquery-module|map(*)|xs:string"},
	{catalogXPath31Bit, "fn:load-xquery-module|map(*)|xs:string|map(*)"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:local-name-from-QName|xs:NCName?|xs:QName?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:local-name|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:local-name|xs:string|node()?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:lower-case|xs:string|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:matches|xs:boolean|xs:string?|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:matches|xs:boolean|xs:string?|xs:string|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:max|xs:anyAtomicType?|xs:anyAtomicType*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:max|xs:anyAtomicType?|xs:anyAtomicType*|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:minutes-from-dateTime|xs:integer?|xs:dateTime?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:minutes-from-duration|xs:integer?|xs:duration?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:minutes-from-time|xs:integer?|xs:time?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:min|xs:anyAtomicType?|xs:anyAtomicType*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:min|xs:anyAtomicType?|xs:anyAtomicType*|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:month-from-dateTime|xs:integer?|xs:dateTime?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:month-from-date|xs:integer?|xs:date?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:months-from-duration|xs:integer?|xs:duration?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:namespace-uri-for-prefix|xs:anyURI?|xs:string?|element()"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:namespace-uri-from-QName|xs:anyURI?|xs:QName?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:namespace-uri|xs:anyURI"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:namespace-uri|xs:anyURI|node()?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:name|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:name|xs:string|node()?"},
	{catalogXPath30Bit, "fn:nilled|xs:boolean"},
	{catalogXPath31Bit, "fn:nilled|xs:boolean?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:nilled|xs:boolean?|node()?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:node-name|xs:QName?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:node-name|xs:QName?|node()?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:normalize-space|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:normalize-space|xs:string|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:normalize-unicode|xs:string|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:normalize-unicode|xs:string|xs:string?|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:not|xs:boolean|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:number|xs:double"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:number|xs:double|xs:anyAtomicType?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:one-or-more|item()+|item()*"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:outermost|node()*|node()*"},
	{catalogXPath31Bit, "fn:parse-ietf-date|xs:dateTime?|xs:string?"},
	{catalogXPath31Bit, "fn:parse-json|item()?|xs:string?"},
	{catalogXPath31Bit, "fn:parse-json|item()?|xs:string?|map(*)"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:parse-xml-fragment|document-node()?|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:parse-xml|document-node(element(*))?|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:path|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:path|xs:string?|node()?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:position|xs:integer"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:prefix-from-QName|xs:NCName?|xs:QName?"},
	{catalogXPath31Bit, "fn:random-number-generator|map(xs:string, item())"},
	{catalogXPath31Bit, "fn:random-number-generator|map(xs:string, item())|xs:anyAtomicType?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:remove|item()*|item()*|xs:integer"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:replace|xs:string|xs:string?|xs:string|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:replace|xs:string|xs:string?|xs:string|xs:string|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:resolve-QName|xs:QName?|xs:string?|element()"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:resolve-uri|xs:anyURI?|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:resolve-uri|xs:anyURI?|xs:string?|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:reverse|item()*|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:root|node()"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:root|node()?|node()?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:round-half-to-even|xs:numeric?|xs:numeric?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:round-half-to-even|xs:numeric?|xs:numeric?|xs:integer"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:round|xs:numeric?|xs:numeric?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:round|xs:numeric?|xs:numeric?|xs:integer"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:seconds-from-dateTime|xs:decimal?|xs:dateTime?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:seconds-from-duration|xs:decimal?|xs:duration?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:seconds-from-time|xs:decimal?|xs:time?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:serialize|xs:string|item()*"},
	{catalogXPath30Bit, "fn:serialize|xs:string|item()*|element(output:serialization-parameters)?"},
	{catalogXPath31Bit, "fn:serialize|xs:string|item()*|item()?"},
	{catalogXPath31Bit, "fn:sort|item()*|item()*"},
	{catalogXPath31Bit, "fn:sort|item()*|item()*|xs:string?"},
	{catalogXPath31Bit, "fn:sort|item()*|item()*|xs:string?|function(item()) as xs:anyAtomicType*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:starts-with|xs:boolean|xs:string?|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:starts-with|xs:boolean|xs:string?|xs:string?|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:static-base-uri|xs:anyURI?"},
	{catalogXPath31Bit, "fn:string-join|xs:string|xs:anyAtomicType*"},
	{catalogXPath31Bit, "fn:string-join|xs:string|xs:anyAtomicType*|xs:string"},
	{catalogXPath30Bit, "fn:string-join|xs:string|xs:string*"},
	{catalogXPath20Bit | catalogXPath30Bit, "fn:string-join|xs:string|xs:string*|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:string-length|xs:integer"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:string-length|xs:integer|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:string-to-codepoints|xs:integer*|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:string|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:string|xs:string|item()?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:subsequence|item()*|item()*|xs:double"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:subsequence|item()*|item()*|xs:double|xs:double"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:substring-after|xs:string|xs:string?|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:substring-after|xs:string|xs:string?|xs:string?|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:substring-before|xs:string|xs:string?|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:substring-before|xs:string|xs:string?|xs:string?|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:substring|xs:string|xs:string?|xs:double"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:substring|xs:string|xs:string?|xs:double|xs:double"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:sum|xs:anyAtomicType?|xs:anyAtomicType*|xs:anyAtomicType?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:sum|xs:anyAtomicType|xs:anyAtomicType*"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:tail|item()*|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:timezone-from-dateTime|xs:dayTimeDuration?|xs:dateTime?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:timezone-from-date|xs:dayTimeDuration?|xs:date?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:timezone-from-time|xs:dayTimeDuration?|xs:time?"},
	{catalogXPath31Bit, "fn:tokenize|xs:string*|xs:string?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:tokenize|xs:string*|xs:string?|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:tokenize|xs:string*|xs:string?|xs:string|xs:string"},
	{catalogXPath31Bit, "fn:trace|item()*|item()*"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:trace|item()*|item()*|xs:string"},
	{catalogXPath31Bit, "fn:transform|map(*)|map(*)"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:translate|xs:string|xs:string?|xs:string|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:true|xs:boolean"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:unordered|item()*|item()*"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:unparsed-text-available|xs:boolean|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:unparsed-text-available|xs:boolean|xs:string?|xs:string"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:unparsed-text-lines|xs:string*|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:unparsed-text-lines|xs:string*|xs:string?|xs:string"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:unparsed-text|xs:string?|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:unparsed-text|xs:string?|xs:string?|xs:string"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:upper-case|xs:string|xs:string?"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:uri-collection|xs:anyURI*"},
	{catalogXPath30Bit | catalogXPath31Bit, "fn:uri-collection|xs:anyURI*|xs:string?"},
	{catalogXPath31Bit, "fn:xml-to-json|xs:string?|node()?"},
	{catalogXPath31Bit, "fn:xml-to-json|xs:string?|node()?|map(*)"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:year-from-dateTime|xs:integer?|xs:dateTime?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:year-from-date|xs:integer?|xs:date?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:years-from-duration|xs:integer?|xs:duration?"},
	{catalogXPath20Bit | catalogXPath30Bit | catalogXPath31Bit, "fn:zero-or-one|item()?|item()*"},
	{catalogXPath31Bit, "map:contains|xs:boolean|map(*)|xs:anyAtomicType"},
	{catalogXPath31Bit, "map:entry|map(*)|xs:anyAtomicType|item()*"},
	{catalogXPath31Bit, "map:find|array(*)|item()*|xs:anyAtomicType"},
	{catalogXPath31Bit, "map:for-each|item()*|map(*)|function(xs:anyAtomicType, item()*) as item()*"},
	{catalogXPath31Bit, "map:get|item()*|map(*)|xs:anyAtomicType"},
	{catalogXPath31Bit, "map:keys|xs:anyAtomicType*|map(*)"},
	{catalogXPath31Bit, "map:merge|map(*)|map(*)*"},
	{catalogXPath31Bit, "map:merge|map(*)|map(*)*|map(*)"},
	{catalogXPath31Bit, "map:put|map(*)|map(*)|xs:anyAtomicType|item()*"},
	{catalogXPath31Bit, "map:remove|map(*)|map(*)|xs:anyAtomicType*"},
	{catalogXPath31Bit, "map:size|xs:integer|map(*)"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:acos|xs:double?|xs:double?"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:asin|xs:double?|xs:double?"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:atan2|xs:double|xs:double|xs:double"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:atan|xs:double?|xs:double?"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:cos|xs:double?|xs:double?"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:exp10|xs:double?|xs:double?"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:exp|xs:double?|xs:double?"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:log10|xs:double?|xs:double?"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:log|xs:double?|xs:double?"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:pi|xs:double"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:pow|xs:double?|xs:double?|xs:numeric"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:sin|xs:double?|xs:double?"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:sqrt|xs:double?|xs:double?"},
	{catalogXPath30Bit | catalogXPath31Bit, "math:tan|xs:double?|xs:double?"},
}

//nolint:gochecknoglobals // Immutable standard type data is shared across independent evaluations.
var standardFunctionCatalogs = sync.OnceValue(func() [standardFunctionCatalogCount]map[sigKey]*functionSignature {
	var catalogs [standardFunctionCatalogCount]map[sigKey]*functionSignature
	for i := range catalogs {
		catalogs[i] = make(map[sigKey]*functionSignature)
	}

	namespaces := PredeclaredNamespaces()
	namespaces[catalogSerializationPrefix] = lexicon.NamespaceSerialization
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

		signature := &functionSignature{ParamTypes: make([]xdm.SequenceType, len(fields)-catalogSignatureHeaderFields)}
		for i, parameter := range fields[catalogSignatureHeaderFields:] {
			signature.ParamTypes[i] = sequenceType(parameter)
		}

		if fields[1] != catalogNeverReturnsType {
			result := sequenceType(fields[1])
			signature.ReturnType = &result
		}

		key := sigKey{URI: namespaces[prefix], Name: name, Arity: len(signature.ParamTypes)}

		for i := range catalogs {
			if declaration.versions&(catalogXPath20Bit<<i) != 0 {
				catalogs[i][key] = signature
			}
		}
	}

	return catalogs
})

// Catalog metadata is immutable and bound in the library's own static context.
func lookupStandardSignature(version int, key sigKey) *functionSignature {
	index := catalogXPath31Index
	if version != xpathVersionDefault && version < xpathVersion30 {
		index = catalogXPath20Index
	} else if version == xpathVersion30 {
		index = catalogXPath30Index
	}

	return standardFunctionCatalogs()[index][key]
}
