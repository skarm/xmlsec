package keyinfo

import "github.com/skarm/xmlsec/internal/lexicon"

const (
	// Names the RSA public exponent in XMLDSig KeyValue encoding.
	nameExponent = "Exponent"
	// Names the DSA generator in XMLDSig KeyValue encoding.
	nameG = "G"
	// Names the RSA modulus in XMLDSig KeyValue encoding.
	nameModulus = "Modulus"
	// Names the DSA prime modulus in XMLDSig KeyValue encoding.
	nameP = "P"
	// Names the DSA subgroup order in XMLDSig KeyValue encoding.
	nameQ = "Q"
	// Names the DSA public value in XMLDSig KeyValue encoding.
	nameY = "Y"
)

const (
	// XMLDSig 1.1 representation carrying the DER SubjectPublicKeyInfo bytes of a public key.
	nameDEREncodedKeyValue = "DEREncodedKeyValue"
	// XMLDSig representation of legacy DSA public parameters.
	nameDSAKeyValue = "DSAKeyValue"
	// XMLDSig 1.1 representation combining a named curve and an encoded EC point.
	nameECKeyValue = lexicon.DSigElementECKeyValue
	// XMLDSig 1.1 reference to a separately resolved KeyInfo element.
	nameKeyInfoReference = "KeyInfoReference"
	// XMLDSig representation of an RSA public modulus and exponent.
	nameRSAKeyValue = "RSAKeyValue"
	// Groups certificate/CRL encodings and untrusted certificate selectors within KeyInfo.
	nameX509Data = lexicon.DSigElementX509Data
	// Carries one DER certificate within an X509Data group.
	nameX509Certificate = lexicon.DSigElementX509Certificate
	// Carries one DER CRL within an X509Data group.
	nameX509CRL = lexicon.DSigElementX509CRL
	// Carries raw subject-key-identifier bytes used for certificate selection.
	nameX509SKI = "X509SKI"
)
