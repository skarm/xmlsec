// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import "github.com/skarm/xmlsec/internal/lexicon"

// lookupXSLTElementInfo constructs metadata for one recognized XSLT element. Definitions are
// operation-owned; queries never construct the complete registry or share maps.
func lookupXSLTElementInfo(name string) (xsltElementInfo, bool) {
	for _, lookup := range []func(string) (xsltElementInfo, bool){
		lookupRootElementInfo,
		lookupPackageElementInfo,
		lookupDeclarationElementInfo,
		lookupConstructorElementInfo,
		lookupTemplateControlElementInfo,
		lookupSequenceControlElementInfo,
		lookupDynamicElementInfo,
		lookupSerializationElementInfo,
	} {
		if definition, ok := lookup(name); ok {
			return definition, true
		}
	}

	return xsltElementInfo{}, false
}

func lookupRootElementInfo(name string) (xsltElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementStylesheet,
		lexicon.XSLTElementTransform:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementRoot, implemented: true,
		}, true
	case lexicon.XSLTElementPackage:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementRoot, implemented: true,
		}, true
	}

	return xsltElementInfo{}, false
}

func lookupPackageElementInfo(name string) (xsltElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementExpose,
		lexicon.XSLTElementUsePackage:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementAccept,
		lexicon.XSLTElementOverride:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementChildOnly, implemented: true,
		}, true
	}

	return xsltElementInfo{}, false
}

func lookupDeclarationElementInfo(name string) (xsltElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementImport,
		lexicon.XSLTElementInclude,
		lexicon.XSLTElementTemplate,
		lexicon.XSLTElementKey,
		lexicon.XSLTElementStripSpace,
		lexicon.XSLTElementPreserveSpace,
		lexicon.XSLTElementDecimalFormat,
		lexicon.XSLTElementAttributeSet,
		lexicon.XSLTElementNamespaceAlias:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementVariable:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementTopLevel | elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementParam:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementTopLevel | elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementFunction,
		lexicon.XSLTElementImportSchema:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementMode,
		lexicon.XSLTElementAccumulator,
		lexicon.XSLTElementGlobalContextItem:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementAccumulatorRule,
		lexicon.XSLTElementContextItem:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementSchema:
		return xsltElementInfo{
			// Internal representation; not a standard XSLT instruction.
			minVersion: lexicon.XSLTVersion10, implemented: false,
		}, true
	}

	return xsltElementInfo{}, false
}

func lookupConstructorElementInfo(name string) (xsltElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementValueOf,
		lexicon.XSLTElementText,
		lexicon.XSLTElementElement,
		lexicon.XSLTElementAttribute,
		lexicon.XSLTElementComment,
		lexicon.XSLTElementProcessingInstruction,
		lexicon.XSLTElementCopy,
		lexicon.XSLTElementCopyOf,
		lexicon.XSLTElementNumber:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementNamespace,
		lexicon.XSLTElementSequence,
		lexicon.XSLTElementDocument:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementMap,
		lexicon.XSLTElementMapEntry,
		lexicon.XSLTElementArray:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	}

	return xsltElementInfo{}, false
}

func lookupTemplateControlElementInfo(name string) (xsltElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementApplyTemplates,
		lexicon.XSLTElementCallTemplate,
		lexicon.XSLTElementIf,
		lexicon.XSLTElementChoose,
		lexicon.XSLTElementForEach,
		lexicon.XSLTElementApplyImports:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementNextMatch:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementWhen,
		lexicon.XSLTElementOtherwise,
		lexicon.XSLTElementWithParam:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementChildOnly, implemented: true,
		}, true
	}

	return xsltElementInfo{}, false
}

func lookupSequenceControlElementInfo(name string) (xsltElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementPerformSort,
		lexicon.XSLTElementForEachGroup,
		lexicon.XSLTElementAnalyzeString:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementWherePopulated,
		lexicon.XSLTElementOnEmpty,
		lexicon.XSLTElementOnNonEmpty,
		lexicon.XSLTElementIterate,
		lexicon.XSLTElementFork,
		lexicon.XSLTElementMerge:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementSort:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementMatchingSubstring,
		lexicon.XSLTElementNonMatchingSubstring:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementOnCompletion,
		lexicon.XSLTElementMergeSource,
		lexicon.XSLTElementMergeAction,
		lexicon.XSLTElementMergeKey,
		lexicon.XSLTElementBreak,
		lexicon.XSLTElementNextIteration:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementChildOnly, implemented: true,
		}, true
	}

	return xsltElementInfo{}, false
}

func lookupDynamicElementInfo(name string) (xsltElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementMessage:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementTry,
		lexicon.XSLTElementAssert,
		lexicon.XSLTElementEvaluate,
		lexicon.XSLTElementSourceDocument:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementCatch:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementFallback:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementChildOnly, implemented: true,
			// parents is nil: fallback can appear inside any XSLT instruction
			// as a forwards-compatibility mechanism; validated at compile time.
		}, true
	}

	return xsltElementInfo{}, false
}

func lookupSerializationElementInfo(name string) (xsltElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementOutput:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementCharacterMap:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementResultDocument:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementOutputCharacter:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementChildOnly, implemented: true,
		}, true
	}

	return xsltElementInfo{}, false
}
