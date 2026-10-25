package lexicon

// Shared security protocol identifiers; policy remains with each consumer.
const (
	// NamespaceSAMLAssertion is the SAML 2.0 assertion namespace URI.
	NamespaceSAMLAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	// NamespaceSAMLProtocol is the SAML 2.0 protocol namespace URI.
	NamespaceSAMLProtocol = "urn:oasis:names:tc:SAML:2.0:protocol"
	// NamespaceSAMLMetadata is the SAML 2.0 metadata namespace URI.
	NamespaceSAMLMetadata = "urn:oasis:names:tc:SAML:2.0:metadata"
	// SAMLBindingHTTPPost is the SAML HTTP-POST binding URI.
	SAMLBindingHTTPPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	// SAMLBindingHTTPRedirect is the SAML HTTP-Redirect binding URI.
	SAMLBindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	// SAMLBindingHTTPArtifact is the SAML HTTP-Artifact binding URI; artifact processing is unsupported.
	SAMLBindingHTTPArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
	// SAMLBindingSOAP is the SAML SOAP binding URI; SOAP processing is unsupported.
	SAMLBindingSOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
	// DigestSHA1 is the SHA-1 digest algorithm URI.
	DigestSHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
	// DigestSHA224 is the SHA-224 digest algorithm URI.
	DigestSHA224 = "http://www.w3.org/2001/04/xmldsig-more#sha224"
	// DigestSHA256 is the SHA-256 digest algorithm URI.
	DigestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	// DigestSHA384 is the SHA-384 digest algorithm URI.
	DigestSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	// DigestSHA512 is the SHA-512 digest algorithm URI.
	DigestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
	// TransformEnvelopedSignature is the XMLDSig enveloped-signature transform URI.
	TransformEnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

// XMLDSig 1.1 named-curve identifiers are shared by signing and agreement.
const (
	// CurveP256 identifies the NIST P-256 prime curve.
	CurveP256 = "urn:oid:1.2.840.10045.3.1.7"
	// CurveP384 identifies the NIST P-384 prime curve.
	CurveP384 = "urn:oid:1.3.132.0.34"
	// CurveP521 identifies the NIST P-521 prime curve.
	CurveP521 = "urn:oid:1.3.132.0.35"
)

// XMLDSig element local names. Consumers must also check NamespaceDSig.
const (
	// DSigElementSignature names the XMLDSig Signature element.
	DSigElementSignature = "Signature"
	// DSigElementSignedInfo names the XMLDSig SignedInfo element.
	DSigElementSignedInfo = "SignedInfo"
	// DSigElementSignatureValue names the XMLDSig SignatureValue element.
	DSigElementSignatureValue = "SignatureValue"
	// DSigElementCanonicalizationMethod names the XMLDSig CanonicalizationMethod element.
	DSigElementCanonicalizationMethod = "CanonicalizationMethod"
	// DSigElementSignatureMethod names the XMLDSig SignatureMethod element.
	DSigElementSignatureMethod = "SignatureMethod"
	// DSigElementReference names the XMLDSig Reference element.
	DSigElementReference = "Reference"
	// DSigElementTransforms names the XMLDSig Transforms element.
	DSigElementTransforms = "Transforms"
	// DSigElementTransform names the XMLDSig Transform element.
	DSigElementTransform = "Transform"
	// DSigElementDigestMethod names the XMLDSig DigestMethod element.
	DSigElementDigestMethod = "DigestMethod"
	// DSigElementDigestValue names the XMLDSig DigestValue element.
	DSigElementDigestValue = "DigestValue"
	// DSigElementKeyInfo names the XMLDSig KeyInfo element.
	DSigElementKeyInfo = "KeyInfo"
	// DSigElementKeyName names the XMLDSig KeyName element.
	DSigElementKeyName = "KeyName"
	// DSigElementKeyValue names the XMLDSig KeyValue element.
	DSigElementKeyValue = "KeyValue"
	// DSigElementX509Data names the XMLDSig X509Data element.
	DSigElementX509Data = "X509Data"
	// DSigElementX509Certificate names the XMLDSig X509Certificate element.
	DSigElementX509Certificate = "X509Certificate"
	// DSigElementX509CRL names the XMLDSig X509CRL element.
	DSigElementX509CRL = "X509CRL"
)

// SAML metadata endpoint names are keys in role endpoint collections.
const (
	// SAMLAssertionConsumerService identifies an assertion consumer endpoint.
	SAMLAssertionConsumerService = "AssertionConsumerService"
	// SAMLSingleSignOnService identifies an IdP sign-on endpoint.
	SAMLSingleSignOnService = "SingleSignOnService"
	// SAMLSingleLogoutService identifies a logout endpoint declaration.
	SAMLSingleLogoutService = "SingleLogoutService"
	// SAMLArtifactResolutionService identifies an artifact resolution endpoint declaration.
	SAMLArtifactResolutionService = "ArtifactResolutionService"
	// SAMLManageNameIDService identifies a name identifier management endpoint declaration.
	SAMLManageNameIDService = "ManageNameIDService"
	// SAMLNameIDMappingService identifies a name identifier mapping endpoint declaration.
	SAMLNameIDMappingService = "NameIDMappingService"
)
