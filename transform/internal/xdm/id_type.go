package xdm

// AttributeIDType supplies ID/IDREF semantics for XPath and XSLT attributes.
// DTD declarations supply these flags without adding schema type annotations.
type AttributeIDType uint8

const (
	UntypedAttribute AttributeIDType = iota
	IDAttribute
	IDRefAttribute
	IDRefsAttribute
)
