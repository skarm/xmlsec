package tree

// NodeBase returns the retained retrieval base for a private node, or empty when none is
// recorded.
func NodeBase(d *Document, node *Node) string { return d.nodeBases[node] }

// CopyUnparsedEntities retains immutable declaration metadata from source on the
// destination draft d. Callers must not mutate published snapshots.
func CopyUnparsedEntities(d, source *Document) {
	d.unparsedEntities = source.unparsedEntities
}

// SetNodeBase changes retrieval metadata on an internal draft. An empty base removes the
// entry. Callers must not mutate published snapshots.
func SetNodeBase(d *Document, node *Node, base string) {
	if base == "" {
		delete(d.nodeBases, node)
		return
	}

	if d.nodeBases == nil {
		d.nodeBases = make(map[*Node]string)
	}

	d.nodeBases[node] = base
}

// AttributeDTDType returns the retained DTD ID or IDREF classification, or DTDNoType
// when absent.
func AttributeDTDType(d *Document, node *Node, name Name) DTDAttributeType {
	return d.dtdTypes[dtdAttributeKey{node, name}]
}

// SetAttributeDTDType changes DTD metadata on an internal draft. DTDNoType removes the
// entry. Callers must not mutate published snapshots.
func SetAttributeDTDType(d *Document, node *Node, name Name, kind DTDAttributeType) {
	key := dtdAttributeKey{node, name}

	if kind == DTDNoType {
		delete(d.dtdTypes, key)
		return
	}

	if d.dtdTypes == nil {
		d.dtdTypes = make(map[dtdAttributeKey]DTDAttributeType)
	}

	d.dtdTypes[key] = kind
}

// LookupUnparsedEntity returns a retained unparsed entity declaration and reports whether it
// exists. It performs no resource retrieval.
func LookupUnparsedEntity(d *Document, name string) (UnparsedEntity, bool) {
	entity, ok := d.unparsedEntities[name]
	return entity, ok
}
