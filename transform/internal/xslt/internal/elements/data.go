// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package elements

import "github.com/skarm/xmlsec/transform/internal/xdm/lexicon"

// Lookup constructs metadata for one recognized XSLT element. Definitions are
// operation-owned; queries never construct the complete registry or share maps.
func Lookup(name string) (ElementInfo, bool) {
	for _, lookup := range []func(string) (ElementInfo, bool){
		lookupRootElement,
		lookupPackageElement,
		lookupDeclarationElement,
		lookupConstructorElement,
		lookupTemplateControlElement,
		lookupSequenceControlElement,
		lookupDynamicElement,
		lookupSerializationElement,
	} {
		if definition, ok := lookup(name); ok {
			return definition, true
		}
	}

	return ElementInfo{}, false
}

func lookupRootElement(name string) (ElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementStylesheet:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxRoot, Implemented: true,
		}, true
	case lexicon.XSLTElementTransform:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxRoot, Implemented: true,
		}, true
	case lexicon.XSLTElementPackage:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxRoot, Implemented: true,
		}, true
	}

	return ElementInfo{}, false
}

func lookupPackageElement(name string) (ElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementExpose:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("component", "names", "visibility"),
		}, true
	case lexicon.XSLTElementUsePackage:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("name", "package-version", "use-when"),
		}, true
	case lexicon.XSLTElementAccept:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("component", "names", "visibility"),
			Parents:      []string{"use-package"},
		}, true
	case lexicon.XSLTElementOverride:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxChildOnly, Implemented: true,
			Parents: []string{"use-package"},
		}, true
	}

	return ElementInfo{}, false
}

func lookupDeclarationElement(name string) (ElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementImport:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("href", "use-when"),
		}, true
	case lexicon.XSLTElementInclude:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("href", "use-when"),
		}, true
	case lexicon.XSLTElementTemplate:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("match", "name", "priority", "mode", "as", "visibility", "use-when"),
		}, true
	case lexicon.XSLTElementVariable:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxTopLevel | CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("name", "select", "as", "static", "visibility"),
		}, true
	case lexicon.XSLTElementParam:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxTopLevel | CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("name", "select", "as", "required", "tunnel", "static"),
			Parents:      []string{"template", "function", nameIterate},
		}, true
	case lexicon.XSLTElementKey:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("name", "match", "use", "collation", "composite", "use-when"),
		}, true
	case lexicon.XSLTElementStripSpace:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("elements"),
		}, true
	case lexicon.XSLTElementPreserveSpace:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("elements"),
		}, true
	case lexicon.XSLTElementFunction:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet(
				"name", "as", "visibility", "streamable",
				"streamability", "override-extension-function", "override",
				"identity-sensitive", "cache", "new-each-time", "use-when",
			),
		}, true
	case lexicon.XSLTElementDecimalFormat:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet(
				"name", "decimal-separator", "grouping-separator",
				"infinity", "minus-sign", "NaN", "percent",
				"per-mille", "zero-digit", "digit",
				"pattern-separator", "exponent-separator", "use-when",
			),
		}, true
	case lexicon.XSLTElementMode:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet(
				"name", "streamable", "on-no-match", "on-multiple-match",
				"warning-on-no-match", "warning-on-multiple-match",
				"typed", "visibility", "use-when", "use-accumulators",
			),
		}, true
	case lexicon.XSLTElementImportSchema:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("namespace", "schema-location", "use-when"),
		}, true
	case lexicon.XSLTElementAccumulator:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("name", "as", "initial-value", "streamable", "use-when"),
		}, true
	case lexicon.XSLTElementAttributeSet:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("name", "use-attribute-sets", "visibility", "streamable", "use-when"),
		}, true
	case lexicon.XSLTElementNamespaceAlias:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("stylesheet-prefix", "result-prefix", "use-when"),
		}, true
	case lexicon.XSLTElementGlobalContextItem:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("as", "use", "use-when"),
		}, true
	case lexicon.XSLTElementAccumulatorRule:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("match", "phase", "select", "new-value"),
			Parents:      []string{"accumulator"},
		}, true
	case lexicon.XSLTElementContextItem:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("as", "use"),
			Parents:      []string{"template"},
		}, true
	case lexicon.XSLTElementSchema:
		return ElementInfo{
			// Internal representation; not a standard XSLT instruction.
			MinVersion: lexicon.XSLTVersion10, Implemented: false,
		}, true
	}

	return ElementInfo{}, false
}

func lookupConstructorElement(name string) (ElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementValueOf:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select", "separator", "disable-output-escaping"),
		}, true
	case lexicon.XSLTElementText:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("disable-output-escaping"),
		}, true
	case lexicon.XSLTElementElement:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("name", "namespace", "inherit-namespaces", "use-attribute-sets", "type", "validation"),
		}, true
	case lexicon.XSLTElementAttribute:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("name", "namespace", "select", "separator", "type", "validation"),
		}, true
	case lexicon.XSLTElementComment:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select"),
		}, true
	case lexicon.XSLTElementProcessingInstruction:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("name", "select"),
		}, true
	case lexicon.XSLTElementCopy:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select", "copy-namespaces", "inherit-namespaces", "use-attribute-sets", "type", "validation"),
		}, true
	case lexicon.XSLTElementCopyOf:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select", "copy-namespaces", "copy-accumulators", "type", "validation"),
		}, true
	case lexicon.XSLTElementNumber:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("value", "select", "level", "count", "from", "format", "lang", "letter-value", "ordinal", "grouping-separator", "grouping-size"),
		}, true
	case lexicon.XSLTElementNamespace:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("name", "select"),
		}, true
	case lexicon.XSLTElementSequence:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select", "as"),
		}, true
	case lexicon.XSLTElementDocument:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("type", "validation"),
		}, true
	case lexicon.XSLTElementMap:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
		}, true
	case lexicon.XSLTElementMapEntry:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("key", "select"),
		}, true
	case lexicon.XSLTElementArray:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
		}, true
	}

	return ElementInfo{}, false
}

func lookupTemplateControlElement(name string) (ElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementApplyTemplates:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select", "mode"),
		}, true
	case lexicon.XSLTElementCallTemplate:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("name"),
		}, true
	case lexicon.XSLTElementIf:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("test"),
		}, true
	case lexicon.XSLTElementChoose:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
		}, true
	case lexicon.XSLTElementForEach:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select"),
		}, true
	case lexicon.XSLTElementNextMatch:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxInstruction, Implemented: true,
		}, true
	case lexicon.XSLTElementApplyImports:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
		}, true
	case lexicon.XSLTElementWhen:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("test"),
			Parents:      []string{"choose"},
		}, true
	case lexicon.XSLTElementOtherwise:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxChildOnly, Implemented: true,
			Parents: []string{"choose"},
		}, true
	case lexicon.XSLTElementWithParam:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("name", "select", "as", "tunnel"),
			Parents:      []string{"apply-templates", "call-template", "next-match", "apply-imports", "evaluate"},
		}, true
	}

	return ElementInfo{}, false
}

func lookupSequenceControlElement(name string) (ElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementPerformSort:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select"),
		}, true
	case lexicon.XSLTElementWherePopulated:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
		}, true
	case lexicon.XSLTElementOnEmpty:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
		}, true
	case lexicon.XSLTElementOnNonEmpty:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
		}, true
	case lexicon.XSLTElementForEachGroup:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select", "group-by", "group-adjacent", "group-starting-with", "group-ending-with", "composite", "collation"),
		}, true
	case lexicon.XSLTElementAnalyzeString:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select", "regex", "flags"),
		}, true
	case lexicon.XSLTElementIterate:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select"),
		}, true
	case lexicon.XSLTElementFork:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
		}, true
	case lexicon.XSLTElementMerge:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
		}, true
	case lexicon.XSLTElementSort:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("select", "order", "data-type", "case-order", "lang", "collation", "stable"),
			Parents:      []string{"apply-templates", "for-each", "for-each-group", "perform-sort"},
		}, true
	case lexicon.XSLTElementMatchingSubstring:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxChildOnly, Implemented: true,
			Parents: []string{"analyze-string"},
		}, true
	case lexicon.XSLTElementNonMatchingSubstring:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxChildOnly, Implemented: true,
			Parents: []string{"analyze-string"},
		}, true
	case lexicon.XSLTElementOnCompletion:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("select"),
			Parents:      []string{nameIterate},
		}, true
	case lexicon.XSLTElementMergeSource:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("name", "for-each-item", "for-each-source", "select", "streamable", "sort-before-merge", "use-accumulators", "validation"),
			Parents:      []string{"merge"},
		}, true
	case lexicon.XSLTElementMergeAction:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxChildOnly, Implemented: true,
			Parents: []string{"merge"},
		}, true
	case lexicon.XSLTElementMergeKey:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("select", "order", "collation", "lang", "data-type", "case-order"),
			Parents:      []string{"merge-source"},
		}, true
	case lexicon.XSLTElementBreak:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("select"),
			Parents:      []string{nameIterate},
		}, true
	case lexicon.XSLTElementNextIteration:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxChildOnly, Implemented: true,
			Parents: []string{nameIterate},
		}, true
	}

	return ElementInfo{}, false
}

func lookupDynamicElement(name string) (ElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementMessage:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select", "terminate", "error-code"),
		}, true
	case lexicon.XSLTElementTry:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("select", "rollback-output"),
		}, true
	case lexicon.XSLTElementAssert:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("test", "select", "error-code"),
		}, true
	case lexicon.XSLTElementEvaluate:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("xpath", "as", "base-uri", "namespace-context", "schema-aware"),
		}, true
	case lexicon.XSLTElementSourceDocument:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet("href", "streamable", "use-accumulators", "type", "validation"),
		}, true
	case lexicon.XSLTElementCatch:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion30, Context: CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("errors", "select"),
			Parents:      []string{"try"},
		}, true
	case lexicon.XSLTElementFallback:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxChildOnly, Implemented: true,
			// Parents is nil: fallback can appear inside any XSLT instruction
			// as a forwards-compatibility mechanism; validated at compile time.
		}, true
	}

	return ElementInfo{}, false
}

func lookupSerializationElement(name string) (ElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementOutput:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion10, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet(
				"name", "method", "version", "encoding",
				"omit-xml-declaration", "standalone", "doctype-public",
				"doctype-system", "cdata-section-elements", "indent",
				"media-type", "byte-order-mark", "escape-uri-attributes",
				"include-content-type", "normalization-form",
				"undeclare-prefixes", "use-character-maps",
				"suppress-indentation", "html-version",
				"item-separator", "json-node-output-method",
				"parameter-document", "build-tree",
				"allow-duplicate-names", "use-when",
			),
		}, true
	case lexicon.XSLTElementCharacterMap:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxTopLevel, Implemented: true,
			AllowedAttrs: attrSet("name", "use-character-maps", "use-when"),
		}, true
	case lexicon.XSLTElementResultDocument:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxInstruction, Implemented: true,
			AllowedAttrs: attrSet(
				"format", "href", "method", "version", "encoding",
				"omit-xml-declaration", "standalone", "doctype-public",
				"doctype-system", "cdata-section-elements", "indent",
				"media-type", "byte-order-mark", "escape-uri-attributes",
				"include-content-type", "normalization-form",
				"undeclare-prefixes", "use-character-maps",
				"output-version", "type", "validation",
				"allow-duplicate-names", "item-separator",
				"json-node-output-method", "parameter-document",
				"build-tree", "html-version", "suppress-indentation",
			),
		}, true
	case lexicon.XSLTElementOutputCharacter:
		return ElementInfo{
			MinVersion: lexicon.XSLTVersion20, Context: CtxChildOnly, Implemented: true,
			AllowedAttrs: attrSet("character", "string"),
			Parents:      []string{"character-map"},
		}, true
	}

	return ElementInfo{}, false
}

func attrSet(names ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}

	return m
}
