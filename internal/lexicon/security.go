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
