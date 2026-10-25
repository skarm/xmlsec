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
	case lexicon.XSLTElementStylesheet:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementRoot, implemented: true,
		}, true
	case lexicon.XSLTElementTransform:
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
	case lexicon.XSLTElementExpose:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementUsePackage:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementAccept:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementOverride:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementChildOnly, implemented: true,
		}, true
	}

	return xsltElementInfo{}, false
}

func lookupDeclarationElementInfo(name string) (xsltElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementImport:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementInclude:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementTemplate:
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
	case lexicon.XSLTElementKey:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementStripSpace:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementPreserveSpace:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementFunction:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementDecimalFormat:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementMode:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementImportSchema:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementAccumulator:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementAttributeSet:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementNamespaceAlias:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementGlobalContextItem:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementTopLevel, implemented: true,
		}, true
	case lexicon.XSLTElementAccumulatorRule:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementContextItem:
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
	case lexicon.XSLTElementValueOf:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementText:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementElement:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementAttribute:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementComment:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementProcessingInstruction:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementCopy:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementCopyOf:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementNumber:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementNamespace:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementSequence:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementDocument:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementMap:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementMapEntry:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementArray:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	}

	return xsltElementInfo{}, false
}

func lookupTemplateControlElementInfo(name string) (xsltElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementApplyTemplates:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementCallTemplate:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementIf:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementChoose:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementForEach:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementNextMatch:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementApplyImports:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementWhen:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementOtherwise:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementWithParam:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementChildOnly, implemented: true,
		}, true
	}

	return xsltElementInfo{}, false
}

func lookupSequenceControlElementInfo(name string) (xsltElementInfo, bool) {
	switch name {
	case lexicon.XSLTElementPerformSort:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementWherePopulated:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementOnEmpty:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementOnNonEmpty:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementForEachGroup:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementAnalyzeString:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementIterate:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementFork:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementMerge:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementSort:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion10, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementMatchingSubstring:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementNonMatchingSubstring:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion20, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementOnCompletion:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementMergeSource:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementMergeAction:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementMergeKey:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementBreak:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementChildOnly, implemented: true,
		}, true
	case lexicon.XSLTElementNextIteration:
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
	case lexicon.XSLTElementTry:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementAssert:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementEvaluate:
		return xsltElementInfo{
			minVersion: lexicon.XSLTVersion30, context: elementInstruction, implemented: true,
		}, true
	case lexicon.XSLTElementSourceDocument:
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
