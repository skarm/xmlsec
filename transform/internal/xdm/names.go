// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import (
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
)

// LocalName returns the element's local name, i.e. the part after the first
// ':' in its tag name, or the whole name when there is no prefix.
func LocalName(e *Element) string {
	name := e.Name()
	for i := range len(name) {
		if name[i] == ':' {
			return name[i+1:]
		}
	}

	return name
}

// XMLLangMatches walks the ancestor chain from n looking for an xml:lang
// attribute. langArg must already be lower-cased by the caller. It returns
// (matched, found): found is true once an xml:lang attribute is encountered,
// at which point matched reports whether its lower-cased value equals langArg
// or begins with langArg+"-". When no xml:lang is found, both are false.
func XMLLangMatches(n Node, langArg string) (matched, found bool) {
	for cur := n; cur != nil; cur = cur.Parent() {
		elem, ok := cur.(*Element)
		if !ok {
			continue
		}

		for _, attr := range elem.Attributes() {
			if attr.LocalName() == "lang" && attr.URI() == lexicon.NamespaceXML {
				val := strings.ToLower(attr.Value())
				if val == langArg || strings.HasPrefix(val, langArg+"-") {
					return true, true
				}

				return false, true
			}
		}
	}

	return false, false
}

// InScopeNamespaces collects all in-scope namespace bindings for e by walking
// the ancestor chain from the document root down to e, so that closer (inner)
// declarations override outer ones. The result is keyed by prefix. When
// dropXML is true the implicit "xml" prefix binding is removed.
func InScopeNamespaces(e *Element, dropXML bool) map[string]*Namespace {
	byPrefix := make(map[string]*Namespace)

	var chain []*Element

	for n := Node(e); n != nil; n = n.Parent() {
		if anc, ok := AsNode[*Element](n); ok {
			chain = append(chain, anc)
		}
	}

	// Outermost to innermost so the innermost binding wins.
	for _, anc := range slices.Backward(chain) {
		for _, ns := range anc.Namespaces() {
			byPrefix[ns.Prefix()] = ns
		}

		if ns := anc.Namespace(); ns != nil {
			if _, ok := byPrefix[ns.Prefix()]; !ok {
				byPrefix[ns.Prefix()] = ns
			}
		}
	}

	if dropXML {
		delete(byPrefix, lexicon.PrefixXML)
	}

	return byPrefix
}

// LookupNSPrefixURI walks start and its ancestors for a namespace declaration
// matching prefix, returning the bound URI. Unlike LookupNSByPrefix it
// does NOT predeclare the "xml" prefix — it replicates the bare ancestor walk
// used by several call sites that intentionally omit that predeclaration. The
// bool reports whether a binding was found. start may be any node (or nil);
// non-element nodes in the chain are skipped.
func LookupNSPrefixURI(start Node, prefix string) (string, bool) {
	for n := start; n != nil; n = n.Parent() {
		if e, ok := n.(*Element); ok {
			for i := 0; ; i++ {
				ns, ok := NamespaceDeclarationAt(e, i)
				if !ok {
					break
				}

				if ns.Prefix() == prefix {
					return ns.URI(), true
				}
			}
		}
	}

	return "", false
}

func LookupNSURI(start Node, uri string) (*Namespace, bool) {
	for n := start; n != nil; n = n.Parent() {
		if e, ok := n.(*Element); ok {
			for i := 0; ; i++ {
				ns, ok := NamespaceDeclarationAt(e, i)
				if !ok {
					break
				}

				if ns.URI() == uri {
					return ns, true
				}
			}
		}
	}

	return nil, false
}

// SplitLexicalQName trims surrounding whitespace from s, splits it at the first
// ':' into prefix and local, and validates each part as an NCName. It is
// error-code free: callers map a failure to whatever XPath error code
// (FORG0001, FOCA0002, ...) applies in their context. hadColon reports whether
// a ':' was present (so callers can flag a leading colon, where hadColon is
// true but prefix is empty). validNC reports whether prefix (when present) and
// local are both valid NCNames.
func SplitLexicalQName(s string) (prefix, local string, hadColon, validNC bool) {
	s = strings.TrimSpace(s)
	prefix = ""

	local = s
	if p, l, found := strings.Cut(s, ":"); found {
		prefix = p
		local = l
		hadColon = true
	}

	validNC = xmlchar.IsValidNCName(local) && (prefix == "" || xmlchar.IsValidNCName(prefix))

	return strings.Clone(prefix), strings.Clone(local), hadColon, validNC
}
