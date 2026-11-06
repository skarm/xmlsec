package metadata

// Decoded DER byte ceiling shared by metadata construction and certificate parsing; metadata trust does not imply PKIX certificate validation.
const (
	maximumCertificateBytes = 32 << 10
)

// Metadata vocabulary local name shared by builder and parser; callers must still check the metadata or extension namespace.
const (
	xmlNameAuthnRequestsSigned        = "AuthnRequestsSigned"
	xmlNameBinding                    = "Binding"
	xmlNameEntityDescriptor           = "EntityDescriptor"
	xmlNameEntityID                   = "entityID"
	xmlNameIndex                      = "index"
	xmlNameIsDefault                  = "isDefault"
	xmlNameKeyDescriptor              = "KeyDescriptor"
	xmlNameLocation                   = "Location"
	xmlNameProtocolSupportEnumeration = "protocolSupportEnumeration"
	xmlNameResponseLocation           = "ResponseLocation"
	xmlNameWantAssertionsSigned       = "WantAssertionsSigned"
	xmlNameWantAuthnRequestsSigned    = "WantAuthnRequestsSigned"
)

const (
	// Role declaration element in the metadata namespace; supported formats
	// are exact URIs, independently of the syntax of an assertion's NameID.
	nameNameIDFormat = "NameIDFormat"
	// Relative metadata freshness bound, interpreted as the supported XSD
	// day/time duration subset rather than as an absolute timestamp.
	nameCacheDuration = "cacheDuration"
)

const (
	// Explicit absolute expiry is presence-sensitive: even the Go zero instant
	// is an expiry when the XML attribute is present, not an omitted limit.
	nameValidUntil = "validUntil"
)
