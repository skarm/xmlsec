package xdm

// AttributeIDType supplies ID/IDREF semantics for XPath and XSLT attributes.
// Input DTD declaration types are outside the document model.
type AttributeIDType uint8

const (
	UntypedAttribute AttributeIDType = iota
	IDAttribute
	IDRefAttribute
	IDRefsAttribute
)
