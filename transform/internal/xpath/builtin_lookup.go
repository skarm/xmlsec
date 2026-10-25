package xpath

// lookupBuiltin uses stateless function-family dispatch instead of package initialization.
func lookupBuiltin(qn QualifiedName) (Function, bool) {
	switch qn.URI {
	case NSArray:
		return lookupFunctionsArray(qn.Name)
	case NSFn:
		for _, lookup := range [...]func(string) (*builtinFunc, bool){lookupFunctions, lookupFunctions2, lookupFunctionsAggregate, lookupFunctionsDatetime, lookupFunctionsHof, lookupFunctionsJson, lookupFunctionsJsonXml, lookupFunctionsMisc, lookupFunctionsNode, lookupFunctionsNumeric, lookupFunctionsQname, lookupFunctionsSequence, lookupFunctionsSerialize, lookupFunctionsString, lookupFunctionsUnparsedText, lookupFunctionsUri, lookupParseIetfDate} {
			if fn, ok := lookup(qn.Name); ok {
				return fn, true
			}
		}
	case NSMap:
		return lookupFunctionsMap(qn.Name)
	case NSMath:
		return lookupFunctionsMath(qn.Name)
	case NSXS:
		return lookupConstructor(qn.Name)
	}

	return nil, false
}
