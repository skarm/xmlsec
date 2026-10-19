// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// functionSignature stores the declared parameter and return types for a built-in function.
type functionSignature struct {
	ParamTypes []xdm.SequenceType
	ReturnType *xdm.SequenceType
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
	// typeName is like "xs:numeric" — split into prefix and name
	prefix := "xs"

	name := typeName
	if p, n, ok := strings.Cut(typeName, ":"); ok {
		prefix = p
		name = n
	}

	return xdm.SequenceType{ItemTest: xdm.AtomicOrUnionType{Prefix: prefix, Name: name}, Occurrence: occ}
}

func stNode(occ xdm.Occurrence) xdm.SequenceType { //nolint:unparam // always OccurrenceZeroOrOne but kept for signature symmetry with stAtomic/stItem
	return xdm.SequenceType{ItemTest: xdm.TypeTest{Kind: xdm.NodeKindNode}, Occurrence: occ}
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

func lookupNumericSignature(key sigKey) *functionSignature {
	numQQ := []xdm.SequenceType{stAtomic(xdm.TypeNumeric, xdm.OccurrenceZeroOrOne)}
	retNumQ := stAtomic(xdm.TypeNumeric, xdm.OccurrenceZeroOrOne)

	switch key {
	case sigKey{URI: NSFn, Name: "abs", Arity: 1}:
		return newFunctionSignature(numQQ, retNumQ)
	case sigKey{URI: NSFn, Name: nameCeiling, Arity: 1}:
		return newFunctionSignature(numQQ, retNumQ)
	case sigKey{URI: NSFn, Name: nameFloor, Arity: 1}:
		return newFunctionSignature(numQQ, retNumQ)
	case sigKey{URI: NSFn, Name: nameRound, Arity: 1}:
		return newFunctionSignature(numQQ, retNumQ)
	case sigKey{URI: NSFn, Name: nameRound, Arity: 2}:
		return newFunctionSignature([]xdm.SequenceType{stAtomic(xdm.TypeNumeric, xdm.OccurrenceZeroOrOne), stAtomic(xdm.TypeInteger, xdm.OccurrenceExactlyOne)}, retNumQ)
	case sigKey{URI: NSFn, Name: nameRoundHalfToEven, Arity: 1}:
		return newFunctionSignature(numQQ, retNumQ)
	case sigKey{URI: NSFn, Name: nameRoundHalfToEven, Arity: 2}:
		return newFunctionSignature([]xdm.SequenceType{stAtomic(xdm.TypeNumeric, xdm.OccurrenceZeroOrOne), stAtomic(xdm.TypeInteger, xdm.OccurrenceExactlyOne)}, retNumQ)
	}

	return nil
}

func lookupNodeSignature(key sigKey) *functionSignature {
	switch key {
	case sigKey{URI: NSFn, Name: nameName2, Arity: 0}:
		return newFunctionSignature(nil, stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameName2, Arity: 1}:
		return newFunctionSignature([]xdm.SequenceType{stNode(xdm.OccurrenceZeroOrOne)}, stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameLocalName, Arity: 0}:
		return newFunctionSignature(nil, stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameLocalName, Arity: 1}:
		return newFunctionSignature([]xdm.SequenceType{stNode(xdm.OccurrenceZeroOrOne)}, stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameNamespaceUri, Arity: 0}:
		return newFunctionSignature(nil, stAtomic(xdm.TypeAnyURI, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameNamespaceUri, Arity: 1}:
		return newFunctionSignature([]xdm.SequenceType{stNode(xdm.OccurrenceZeroOrOne)}, stAtomic(xdm.TypeAnyURI, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameNodeName, Arity: 0}:
		return newFunctionSignature(nil, stAtomic(xdm.TypeQName, xdm.OccurrenceZeroOrOne))
	case sigKey{URI: NSFn, Name: nameNodeName, Arity: 1}:
		return newFunctionSignature([]xdm.SequenceType{stNode(xdm.OccurrenceZeroOrOne)}, stAtomic(xdm.TypeQName, xdm.OccurrenceZeroOrOne))
	}

	return nil
}

func lookupStringSignature(key sigKey) *functionSignature {
	strQToStr := stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne)
	strQParam := []xdm.SequenceType{stAtomic(xdm.TypeString, xdm.OccurrenceZeroOrOne)}
	strQQBool := stAtomic(xdm.TypeBoolean, xdm.OccurrenceExactlyOne)
	strQQParams := []xdm.SequenceType{stAtomic(xdm.TypeString, xdm.OccurrenceZeroOrOne), stAtomic(xdm.TypeString, xdm.OccurrenceZeroOrOne)}

	switch key {
	case sigKey{URI: NSFn, Name: nameString, Arity: 0}:
		return newFunctionSignature(nil, stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameString, Arity: 1}:
		return newFunctionSignature([]xdm.SequenceType{stItem(xdm.OccurrenceZeroOrOne)}, stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameStringLength, Arity: 0}:
		return newFunctionSignature(nil, stAtomic(xdm.TypeInteger, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameStringLength, Arity: 1}:
		return newFunctionSignature(strQParam, stAtomic(xdm.TypeInteger, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: "upper-case", Arity: 1}:
		return newFunctionSignature(strQParam, strQToStr)
	case sigKey{URI: NSFn, Name: "lower-case", Arity: 1}:
		return newFunctionSignature(strQParam, strQToStr)
	case sigKey{URI: NSFn, Name: fnNameNormalizeSpace, Arity: 0}:
		return newFunctionSignature(nil, strQToStr)
	case sigKey{URI: NSFn, Name: fnNameNormalizeSpace, Arity: 1}:
		return newFunctionSignature(strQParam, strQToStr)
	case sigKey{URI: NSFn, Name: "normalize-unicode", Arity: 1}:
		return newFunctionSignature(strQParam, strQToStr)
	case sigKey{URI: NSFn, Name: "normalize-unicode", Arity: 2}:
		return newFunctionSignature([]xdm.SequenceType{stAtomic(xdm.TypeString, xdm.OccurrenceZeroOrOne), stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne)}, strQToStr)
	case sigKey{URI: NSFn, Name: nameConcat, Arity: 2}:
		return newFunctionSignature([]xdm.SequenceType{stItem(xdm.OccurrenceZeroOrMore), stItem(xdm.OccurrenceZeroOrMore)}, stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: fnNameContains, Arity: 2}:
		return newFunctionSignature(strQQParams, strQQBool)
	case sigKey{URI: NSFn, Name: fnNameStartsWith, Arity: 2}:
		return newFunctionSignature(strQQParams, strQQBool)
	case sigKey{URI: NSFn, Name: "ends-with", Arity: 2}:
		return newFunctionSignature(strQQParams, strQQBool)
	case sigKey{URI: NSFn, Name: fnNameSubstringBefore, Arity: 2}:
		return newFunctionSignature(strQQParams, strQToStr)
	case sigKey{URI: NSFn, Name: fnNameSubstringAfter, Arity: 2}:
		return newFunctionSignature(strQQParams, strQToStr)
	case sigKey{URI: NSFn, Name: "matches", Arity: 2}:
		return newFunctionSignature(strQQParams, strQQBool)
	case sigKey{URI: NSFn, Name: "matches", Arity: 3}:
		return newFunctionSignature([]xdm.SequenceType{stAtomic(xdm.TypeString, xdm.OccurrenceZeroOrOne), stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne), stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne)}, strQQBool)
	case sigKey{URI: NSFn, Name: "replace", Arity: 3}:
		return newFunctionSignature([]xdm.SequenceType{stAtomic(xdm.TypeString, xdm.OccurrenceZeroOrOne), stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne), stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne)}, strQToStr)
	case sigKey{URI: NSFn, Name: fnNameTranslate, Arity: 3}:
		return newFunctionSignature([]xdm.SequenceType{stAtomic(xdm.TypeString, xdm.OccurrenceZeroOrOne), stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne), stAtomic(xdm.TypeString, xdm.OccurrenceExactlyOne)}, strQToStr)
	case sigKey{URI: NSFn, Name: fnNameSubstring, Arity: 2}:
		return newFunctionSignature([]xdm.SequenceType{stAtomic(xdm.TypeString, xdm.OccurrenceZeroOrOne), stAtomic(xdm.TypeDouble, xdm.OccurrenceExactlyOne)}, strQToStr)
	case sigKey{URI: NSFn, Name: fnNameSubstring, Arity: 3}:
		return newFunctionSignature([]xdm.SequenceType{stAtomic(xdm.TypeString, xdm.OccurrenceZeroOrOne), stAtomic(xdm.TypeDouble, xdm.OccurrenceExactlyOne), stAtomic(xdm.TypeDouble, xdm.OccurrenceExactlyOne)}, strQToStr)
	}

	return nil
}

func lookupBooleanSignature(key sigKey) *functionSignature {
	switch key {
	case sigKey{URI: NSFn, Name: fnNameBoolean, Arity: 1}:
		return newFunctionSignature([]xdm.SequenceType{stItem(xdm.OccurrenceZeroOrMore)}, stAtomic(xdm.TypeBoolean, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: fnNameNot, Arity: 1}:
		return newFunctionSignature([]xdm.SequenceType{stItem(xdm.OccurrenceZeroOrMore)}, stAtomic(xdm.TypeBoolean, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameTrue, Arity: 0}:
		return newFunctionSignature(nil, stAtomic(xdm.TypeBoolean, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameFalse, Arity: 0}:
		return newFunctionSignature(nil, stAtomic(xdm.TypeBoolean, xdm.OccurrenceExactlyOne))
	}

	return nil
}

func lookupAggregateSignature(key sigKey) *functionSignature {
	switch key {
	case sigKey{URI: NSFn, Name: fnNameCount, Arity: 1}:
		return newFunctionSignature([]xdm.SequenceType{stItem(xdm.OccurrenceZeroOrMore)}, stAtomic(xdm.TypeInteger, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameSum, Arity: 1}:
		return newFunctionSignature([]xdm.SequenceType{stItem(xdm.OccurrenceZeroOrMore)}, stItem(xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: nameSum, Arity: 2}:
		return newFunctionSignature([]xdm.SequenceType{stItem(xdm.OccurrenceZeroOrMore), stItem(xdm.OccurrenceZeroOrMore)}, stItem(xdm.OccurrenceZeroOrMore))
	}

	return nil
}

func lookupSequenceSignature(key sigKey) *functionSignature {
	switch key {
	case sigKey{URI: NSFn, Name: "empty", Arity: 1}:
		return newFunctionSignature([]xdm.SequenceType{stItem(xdm.OccurrenceZeroOrMore)}, stAtomic(xdm.TypeBoolean, xdm.OccurrenceExactlyOne))
	case sigKey{URI: NSFn, Name: "exists", Arity: 1}:
		return newFunctionSignature([]xdm.SequenceType{stItem(xdm.OccurrenceZeroOrMore)}, stAtomic(xdm.TypeBoolean, xdm.OccurrenceExactlyOne))
	}

	return nil
}

func lookupHigherOrderSignature(key sigKey) *functionSignature {
	switch key {
	case sigKey{URI: NSFn, Name: nameFilter, Arity: 2}:
		return newFunctionSignature([]xdm.SequenceType{
			stItem(xdm.OccurrenceZeroOrMore),
			stFunc([]xdm.SequenceType{stItem(xdm.OccurrenceExactlyOne)}, stAtomic(xdm.TypeBoolean, xdm.OccurrenceExactlyOne)),
		}, stItem(xdm.OccurrenceZeroOrMore))
	case sigKey{URI: NSFn, Name: nameForEach, Arity: 2}:
		return newFunctionSignature([]xdm.SequenceType{
			stItem(xdm.OccurrenceZeroOrMore),
			stFunc([]xdm.SequenceType{stItem(xdm.OccurrenceExactlyOne)}, stItem(xdm.OccurrenceZeroOrMore)),
		}, stItem(xdm.OccurrenceZeroOrMore))
	case sigKey{URI: NSFn, Name: nameForEachPair, Arity: 3}:
		return newFunctionSignature([]xdm.SequenceType{
			stItem(xdm.OccurrenceZeroOrMore),
			stItem(xdm.OccurrenceZeroOrMore),
			stFunc([]xdm.SequenceType{stItem(xdm.OccurrenceExactlyOne), stItem(xdm.OccurrenceExactlyOne)}, stItem(xdm.OccurrenceZeroOrMore)),
		}, stItem(xdm.OccurrenceZeroOrMore))
	case sigKey{URI: NSFn, Name: nameFoldLeft, Arity: 3}:
		return newFunctionSignature([]xdm.SequenceType{
			stItem(xdm.OccurrenceZeroOrMore),
			stItem(xdm.OccurrenceZeroOrMore),
			stFunc([]xdm.SequenceType{stItem(xdm.OccurrenceZeroOrMore), stItem(xdm.OccurrenceExactlyOne)}, stItem(xdm.OccurrenceZeroOrMore)),
		}, stItem(xdm.OccurrenceZeroOrMore))
	case sigKey{URI: NSFn, Name: nameFoldRight, Arity: 3}:
		return newFunctionSignature([]xdm.SequenceType{
			stItem(xdm.OccurrenceZeroOrMore),
			stItem(xdm.OccurrenceZeroOrMore),
			stFunc([]xdm.SequenceType{stItem(xdm.OccurrenceExactlyOne), stItem(xdm.OccurrenceZeroOrMore)}, stItem(xdm.OccurrenceZeroOrMore)),
		}, stItem(xdm.OccurrenceZeroOrMore))
	case sigKey{URI: NSFn, Name: nameSort, Arity: 2}:
		return newFunctionSignature([]xdm.SequenceType{
			stItem(xdm.OccurrenceZeroOrMore),
			stAtomic(xdm.TypeString, xdm.OccurrenceZeroOrOne),
		}, stItem(xdm.OccurrenceZeroOrMore))
	}

	return nil
}

// lookupFunctionSignature constructs independent metadata for a built-in function.
func lookupFunctionSignature(uri, name string, arity int) *functionSignature {
	key := sigKey{URI: uri, Name: name, Arity: arity}
	for _, lookup := range [...]func(sigKey) *functionSignature{lookupNumericSignature, lookupNodeSignature, lookupStringSignature, lookupBooleanSignature, lookupAggregateSignature, lookupSequenceSignature, lookupHigherOrderSignature} {
		if sig := lookup(key); sig != nil {
			return sig
		}
	}

	return nil
}
