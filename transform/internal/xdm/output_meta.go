package xdm

// Doctype is an explicit output declaration. It is not an XDM node and cannot
// introduce input DTDs, entity declarations, or children into a document.
type Doctype struct {
	Name, PublicID, SystemID string
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
