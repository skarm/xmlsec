package tree

import (
	"slices"

	"github.com/skarm/xmlsec/internal/lexicon"
)

// ImportSubtree copies an element header for insertion into a private draft.
// It preserves the source's complete in-scope namespace context, including an
// absent default namespace, without renaming prefixes used in QName values or
// XPath/XSLT. Descendants and attributes are borrowed read-only until Reparse;
// callers may change only the returned header and its parent.
func ImportSubtree(node *Node) *Node {
	return copySubtreeContext(node, true)
}

// ExtractSubtree copies a header for an independent document. It preserves
// explicit declarations and inherited bindings, but does not add an empty
// default declaration merely to guard against a future destination parent.
// Ownership and mutation rules are the same as for ImportSubtree.
func ExtractSubtree(node *Node) *Node {
	return copySubtreeContext(node, false)
}

func copySubtreeContext(node *Node, insertion bool) *Node {
	if node == nil {
		return nil
	}

	out := *node
	out.Parent = nil

	scope := namespaceScope(node)
	if _, exists := scope[""]; !exists && insertion {
		scope[""] = ""
	}
	// The XPath namespace axis has no empty default node. Preserve an explicit
	// local reset, while avoiding a synthetic reset on a standalone document.
	if !insertion && scope[""] == "" && !slices.ContainsFunc(node.NS, func(ns Namespace) bool { return ns.Prefix == "" }) {
		delete(scope, "")
	}

	prefixes := make([]string, 0, len(scope))
	for prefix := range scope {
		if prefix != lexicon.PrefixXML {
			prefixes = append(prefixes, prefix)
		}
	}

	slices.Sort(prefixes)

	out.NS = make([]Namespace, 0, len(prefixes))
	for _, prefix := range prefixes {
		out.NS = append(out.NS, Namespace{Prefix: prefix, URI: scope[prefix]})
	}

	return &out
}

type namespaceUndo struct {
	prefix   string
	previous string
	existed  bool
}

// namespaceContext maintains source bindings during a depth-first walk. Undo
// records restore shadowed prefixes without copying or rescanning ancestors.
// It is operation-local and must not be confused with C14N's rendered bindings.
type namespaceContext struct {
	bindings map[string]string
	undo     []namespaceUndo
}

func newNamespaceContext(parent *Node) namespaceContext {
	return namespaceContext{bindings: namespaceScope(parent)}
}

func (s *namespaceContext) push(declarations []Namespace) int {
	mark := len(s.undo)
	for _, ns := range declarations {
		previous, existed := s.bindings[ns.Prefix]
		if existed && previous == ns.URI {
			continue
		}

		s.undo = append(s.undo, namespaceUndo{ns.Prefix, previous, existed})
		s.bindings[ns.Prefix] = ns.URI
	}

	return mark
}

func (s *namespaceContext) pop(mark int) {
	for i := len(s.undo) - 1; i >= mark; i-- {
		u := s.undo[i]
		if u.existed {
			s.bindings[u.prefix] = u.previous
		} else {
			delete(s.bindings, u.prefix)
		}

		s.undo[i] = namespaceUndo{}
	}

	s.undo = s.undo[:mark]
}

func (s *namespaceContext) resolve(prefix string) (string, bool) {
	uri, ok := s.bindings[prefix]
	return uri, ok || prefix == ""
}

func (s *namespaceContext) size() int {
	n := len(s.bindings)
	if uri, ok := s.bindings[""]; ok && uri == "" {
		n--
	}

	return n
}
