package keyinfo

import "github.com/skarm/xmlsec/internal/lexicon"

const (
	nameDEREncodedKeyValue = "DEREncodedKeyValue"
	nameDSAKeyValue        = "DSAKeyValue"
	nameECKeyValue         = "ECKeyValue"
	nameKeyInfoReference   = "KeyInfoReference"
	nameRSAKeyValue        = "RSAKeyValue"
	nameX509Data           = lexicon.DSigElementX509Data
	nameX509Certificate    = lexicon.DSigElementX509Certificate
	nameX509CRL            = lexicon.DSigElementX509CRL
	nameX509SKI            = "X509SKI"
)
