package main

import "flag"

func privateKeyFlagNames() []string {
	return []string{flagNameKeyFormat, flagNamePasswordFile, flagNameKeyMaxKDFWork, flagNameKeyMinIterations, flagNameKeyMaxIterations}
}

// commandFlags exposes only flags used by the selected operation. A typo or a
// signing option supplied to verification must fail instead of being ignored.
func commandFlags(fs *flag.FlagSet, signatures bool, specific ...string) *flag.FlagSet {
	allowed := map[string]struct{}{}
	for _, name := range specific {
		allowed[name] = struct{}{}
	}

	for _, name := range [...]string{
		flagNameMaxInputBytes, flagNameMaxOutputBytes, flagNameMaxDepth, flagNameMaxNodes,
		flagNameMaxAttributes, flagNameMaxNodeSetNodes, flagNameMaxNamespaces, flagNameTimeout,
	} {
		allowed[name] = struct{}{}
	}

	if signatures {
		for _, name := range [...]string{
			flagNameMaxReferences, flagNameMaxCanonicalBytes, flagNameMaxNodeVisits, flagNameMaxTransforms,
			flagNamePolicy, flagNameAllowedMethods, flagNameAllowedDigests, flagNameAllowedPrograms,
			flagNameMinRSABits, flagNameMaxRSABits, flagNameMinPSSSaltBytes, flagNameMaxPSSSaltBytes,
			flagNameMinHMACKeyBytes, flagNameMaxHMACKeyBytes, flagNameMinHMACOutputBits, flagNameAllowHMACTruncation,
		} {
			allowed[name] = struct{}{}
		}
	}

	result := flag.NewFlagSet(fs.Name(), flag.ContinueOnError)
	result.SetOutput(fs.Output())
	fs.VisitAll(func(f *flag.Flag) {
		if _, exists := allowed[f.Name]; exists {
			result.Var(f.Value, f.Name, f.Usage)
			result.Lookup(f.Name).DefValue = f.DefValue
		}
	})

	return result
}

func withoutFlags(fs *flag.FlagSet, names ...string) *flag.FlagSet {
	denied := map[string]struct{}{}
	for _, name := range names {
		denied[name] = struct{}{}
	}

	result := flag.NewFlagSet(fs.Name(), flag.ContinueOnError)
	result.SetOutput(fs.Output())
	fs.VisitAll(func(f *flag.Flag) {
		if _, exists := denied[f.Name]; !exists {
			result.Var(f.Value, f.Name, f.Usage)
			result.Lookup(f.Name).DefValue = f.DefValue
		}
	})

	return result
}
