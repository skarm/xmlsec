package xdm

// Doctype is an explicit output declaration. It is not an XDM node and cannot
// introduce input DTDs, entity declarations, or children into a document.
type Doctype struct {
	// Name is the document type name to emit.
	Name string
	// PublicID is the optional public external identifier.
	PublicID string
	// SystemID is the optional system external identifier. Serialization does not
	// retrieve it.
	SystemID string
}

// CopyDoctype preserves output metadata without sharing mutable declarations.
func CopyDoctype(src, dst *Document) {
	if src.Doctype != nil {
		declaration := *src.Doctype
		dst.Doctype = &declaration
	}
}

// CopyUnparsedEntities copies the XDM document property without retrieving
// entities or adding a serialized output declaration.
func CopyUnparsedEntities(src, dst *Document) {
	dst.native.CopyUnparsedEntities(src.native)
}

// SetDoctype records output metadata without changing the XML tree.
func (d *Document) SetDoctype(name, publicID, systemID string) {
	d.Doctype = &Doctype{Name: name, PublicID: publicID, SystemID: systemID}
}
