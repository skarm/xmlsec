// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// functionSignature stores the declared parameter and return types for a built-in function.
type functionSignature struct {
	ParamTypes      []xdm.SequenceType
	RepeatParamType bool
	ReturnType      *xdm.SequenceType
}

func newFunctionSignature(params []xdm.SequenceType, ret xdm.SequenceType) *functionSignature {
	return &functionSignature{ParamTypes: params, ReturnType: &ret}
}

type sigKey struct {
	URI   string
	Name  string
	Arity int
}

// seqType helpers for concise signature definitions
func stAtomic(typeName string, occ xdm.Occurrence) xdm.SequenceType {
	name := typeName
	if _, n, ok := strings.Cut(typeName, ":"); ok {
		name = n
	}

	// Standard function signatures name XSD types in their own static context.
	// A caller's rebinding of the lexical xs prefix cannot change those types.
	return xdm.SequenceType{ItemTest: xdm.AtomicOrUnionType{Name: xdm.QAnnotation(lexicon.NamespaceXSD, name)}, Occurrence: occ}
}

func stItem(occ xdm.Occurrence) xdm.SequenceType {
	return xdm.SequenceType{ItemTest: xdm.AnyItemTest{}, Occurrence: occ}
}

func stFunc(params []xdm.SequenceType, ret xdm.SequenceType) xdm.SequenceType {
	return xdm.SequenceType{
		ItemTest: xdm.FunctionTest{
			ParamTypes: params,
			ReturnType: ret,
		},
		Occurrence: xdm.OccurrenceExactlyOne,
	}
}

// lookupFunctionSignature returns metadata bound in the built-in library's context.
func lookupFunctionSignature(version int, uri, name string, arity int) *functionSignature {
	key := sigKey{URI: uri, Name: name, Arity: arity}
	if signature := lookupStandardSignature(version, key); signature != nil {
		return signature
	}

	if uri != NSFn {
		return nil
	}

	if name == nameConcat && arity >= 2 {
		signature := newFunctionSignature([]xdm.SequenceType{stAtomic(xdm.TypeAnyAtomicType, xdm.OccurrenceZeroOrOne)}, stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne))
		signature.RepeatParamType = true

		return signature
	}
	// XSLT 2.0 supplies these host functions before their adoption into F&O.
	switch name {
	case lexicon.FnFormatNumber:
		if arity == 2 || arity == 3 {
			params := []xdm.SequenceType{stAtomic(xdm.TypeNumeric, xdm.OccurrenceZeroOrOne), stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne)}
			if arity == 3 {
				params = append(params, stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne))
			}

			return newFunctionSignature(params, stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne))
		}
	case lexicon.FnGenerateID, fnNameFormatDate, fnNameFormatDateTime, fnNameFormatTime,
		fnNameUnparsedText, nameUnparsedTextLines, fnNameUnparsedTextAvailable:
		return lookupStandardSignature(31, key)
	}

	return nil
}
