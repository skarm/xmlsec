package tree

type namespaceUndo struct {
	prefix, previous string
	existed          bool
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
