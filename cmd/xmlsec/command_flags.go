package main

import (
	"flag"
	"strings"
)

const privateKeyFlagNames = " key-format password-file key-max-kdf-work key-min-iterations key-max-iterations"

// commandFlags exposes only flags used by the selected operation. A typo or a
// signing option supplied to verification must fail instead of being ignored.
func commandFlags(fs *flag.FlagSet, specific string, signatures bool) *flag.FlagSet {
	allowed := map[string]bool{}
	for name := range strings.FieldsSeq(specific + " max-input-bytes max-output-bytes max-depth max-nodes max-attributes max-nodeset-nodes max-namespaces timeout") {
		allowed[name] = true
	}

	if signatures {
		for name := range strings.FieldsSeq("max-references max-canonical-bytes max-node-visits max-transforms policy allowed-methods allowed-digests allowed-programs min-rsa-bits max-rsa-bits min-pss-salt-bytes max-pss-salt-bytes min-hmac-key-bytes max-hmac-key-bytes min-hmac-output-bits allow-hmac-truncation") {
			allowed[name] = true
		}
	}

	result := flag.NewFlagSet(fs.Name(), flag.ContinueOnError)
	result.SetOutput(fs.Output())
	fs.VisitAll(func(f *flag.Flag) {
		if allowed[f.Name] {
			result.Var(f.Value, f.Name, f.Usage)
			result.Lookup(f.Name).DefValue = f.DefValue
		}
	})

	return result
}

func withoutFlags(fs *flag.FlagSet, names string) *flag.FlagSet {
	denied := map[string]bool{}
	for name := range strings.FieldsSeq(names) {
		denied[name] = true
	}

	result := flag.NewFlagSet(fs.Name(), flag.ContinueOnError)
	result.SetOutput(fs.Output())
	fs.VisitAll(func(f *flag.Flag) {
		if !denied[f.Name] {
			result.Var(f.Value, f.Name, f.Usage)
			result.Lookup(f.Name).DefValue = f.DefValue
		}
	})

	return result
}
