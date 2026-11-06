package lexicon

// RevocationReasonCertificateHold is the signed CRLReason ENUMERATED value for
// temporary certificate suspension. It is not a ReasonFlags bit position.
const RevocationReasonCertificateHold = 6

// GeneralName CHOICE tags identify context-specific X.509 name forms shared by
// certificate, CRL and TSA-name processing. They are not universal ASN.1 tags.
const (
	// GeneralNameOtherName wraps a type OID and its explicitly tagged value.
	GeneralNameOtherName = 0
	// GeneralNameRFC822 carries an IA5 mailbox name.
	GeneralNameRFC822 = 1
	// GeneralNameDNS carries an IA5 DNS name.
	GeneralNameDNS = 2
	// GeneralNameX400 carries a constructed X.400 address.
	GeneralNameX400 = 3
	// GeneralNameDirectory wraps an X.501 distinguished name.
	GeneralNameDirectory = 4
	// GeneralNameEDI carries a constructed EDI party name.
	GeneralNameEDI = 5
	// GeneralNameURI carries an IA5 uniform resource identifier.
	GeneralNameURI = 6
	// GeneralNameIP carries address octets, rather than a textual IP address.
	GeneralNameIP = 7
	// GeneralNameRegisteredID carries an implicitly tagged object identifier.
	GeneralNameRegisteredID = 8
)

// PEM labels shared by key parsing and export. The label identifies the encoded
// ASN.1 container, so a different key container requires its own label.
const (
	// PEMPrivateKey identifies an unencrypted PKCS#8 PrivateKeyInfo.
	PEMPrivateKey = "PRIVATE KEY"
	// PEMEncryptedPrivateKey identifies a PKCS#8 EncryptedPrivateKeyInfo.
	PEMEncryptedPrivateKey = "ENCRYPTED PRIVATE KEY"
	// PEMPublicKey identifies a SubjectPublicKeyInfo encoding.
	PEMPublicKey = "PUBLIC KEY"
)

const (
	// HeaderContentType is the canonical HTTP field name used for XML and evidence media types.
	HeaderContentType = "Content-Type"
	// MediaTypePAOS identifies PAOS content for SAML enhanced client/proxy exchanges.
	MediaTypePAOS = "application/vnd.paos+xml"
	// MediaTypeSOAP identifies the text/xml media type used by SOAP 1.1 bindings and proof parsing.
	MediaTypeSOAP = "text/xml"
	// MediaTypeXML identifies generic XML content accepted by the XML/SAML resource adapters.
	MediaTypeXML = "application/xml"
	// NamespaceSAMLChannelBinding identifies the channel-binding extension shared by metadata and
	// protocol processing.
	NamespaceSAMLChannelBinding = "urn:oasis:names:tc:SAML:protocol:ext:channel-binding"
	// SAMLAttrID names the case-sensitive, unqualified ID attribute of SAML messages and assertions.
	SAMLAttrID = "ID"
	// SAMLBindingPAOS identifies the SAML 2.0 PAOS binding; callers select the supported ECP profile.
	SAMLBindingPAOS = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"
	// SAMLElementArtifactResolve names a SAML protocol message; match NamespaceSAMLProtocol when using
	// it.
	SAMLElementArtifactResolve = "ArtifactResolve"
	// SAMLElementArtifactResponse names a SAML protocol message; match NamespaceSAMLProtocol when
	// using it.
	SAMLElementArtifactResponse = "ArtifactResponse"
	// SAMLElementAssertionIDRequest names a SAML protocol message; match NamespaceSAMLProtocol when
	// using it.
	SAMLElementAssertionIDRequest = "AssertionIDRequest"
	// SAMLElementAttributeQuery names a SAML protocol message; match NamespaceSAMLProtocol when using
	// it.
	SAMLElementAttributeQuery = "AttributeQuery"
	// SAMLElementAuthnQuery names a SAML protocol message; match NamespaceSAMLProtocol when using it.
	SAMLElementAuthnQuery = "AuthnQuery"
	// SAMLElementAuthnRequest names a SAML protocol message; match NamespaceSAMLProtocol when using
	// it.
	SAMLElementAuthnRequest = "AuthnRequest"
	// SAMLElementAuthzDecisionQuery names a SAML protocol message; match NamespaceSAMLProtocol when
	// using it.
	SAMLElementAuthzDecisionQuery = "AuthzDecisionQuery"
	// SAMLElementLogoutRequest names a SAML protocol message; match NamespaceSAMLProtocol when using
	// it.
	SAMLElementLogoutRequest = "LogoutRequest"
	// SAMLElementLogoutResponse names a SAML protocol message; match NamespaceSAMLProtocol when using
	// it.
	SAMLElementLogoutResponse = "LogoutResponse"
	// SAMLElementManageNameIDRequest names a SAML protocol message; match NamespaceSAMLProtocol when
	// using it.
	SAMLElementManageNameIDRequest = "ManageNameIDRequest"
	// SAMLElementManageNameIDResponse names a SAML protocol message; match NamespaceSAMLProtocol when
	// using it.
	SAMLElementManageNameIDResponse = "ManageNameIDResponse"
	// SAMLElementNameIDMappingRequest names a SAML protocol message; match NamespaceSAMLProtocol when
	// using it.
	SAMLElementNameIDMappingRequest = "NameIDMappingRequest"
	// SAMLElementNameIDMappingResponse names a SAML protocol message; match NamespaceSAMLProtocol when
	// using it.
	SAMLElementNameIDMappingResponse = "NameIDMappingResponse"
	// SAMLElementResponse names a SAML protocol message; match NamespaceSAMLProtocol when using it.
	SAMLElementResponse = "Response"
	// SAMLNameIDFormatEntity selects the NameID format for a SAML entity identifier, including ECP
	// issuers.
	SAMLNameIDFormatEntity = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	// C14NAttrPrefixList names the Exclusive C14N inclusive-prefix list attribute.
	C14NAttrPrefixList = "PrefixList"
	// C14NDefaultPrefixToken denotes the default namespace in an Exclusive C14N
	// PrefixList. It does not name an XSLT processing mode.
	C14NDefaultPrefixToken = "#default"
	// C14NElementInclusiveNamespaces names the Exclusive C14N parameter element; match its
	// canonicalization namespace.
	C14NElementInclusiveNamespaces = "InclusiveNamespaces"
	// DSigElementECKeyValue names the XMLDSig 1.1 representation combining a named curve and an
	// encoded EC point.
	DSigElementECKeyValue = "ECKeyValue"
	// DSigElementNamedCurve names the curve-identifier element inside an XMLDSig 1.1 ECKeyValue.
	DSigElementNamedCurve = "NamedCurve"
	// DSigElementObject names an XMLDSig element; match the namespace required by that element's
	// schema.
	DSigElementObject = "Object"
	// DSigElementPublicKey names the element carrying an encoded EC public point in XMLDSig 1.1.
	DSigElementPublicKey = "PublicKey"
	// DSigElementRetrievalMethod names a KeyInfo resource link; external retrieval follows explicit
	// caller permissions.
	DSigElementRetrievalMethod = "RetrievalMethod"
	// PrefixDSig is the suggested prefix for generated XMLDSig elements; their namespace URI
	// determines identity.
	PrefixDSig = "ds"
	// PrefixDSig11 is the suggested prefix for generated XMLDSig 1.1 elements; their namespace URI
	// determines identity.
	PrefixDSig11 = "dsig11"
	// PrefixExclusiveC14N is the suggested prefix for Exclusive C14N parameter elements.
	PrefixExclusiveC14N = "ec"
	// SecurityAttrAlgorithm names the unqualified Algorithm attribute carrying an algorithm URI.
	SecurityAttrAlgorithm = "Algorithm"
	// SecurityAttrEncoding names the unqualified Encoding attribute describing a value encoding.
	SecurityAttrEncoding = "Encoding"
	// SecurityAttrID names the case-sensitive, unqualified Id attribute of XML security elements.
	SecurityAttrID = "Id"
	// SecurityAttrMimeType names the unqualified MimeType attribute declaring a resource media type.
	SecurityAttrMimeType = "MimeType"
	// SecurityAttrTarget names the unqualified Target attribute linking properties to their target.
	SecurityAttrTarget = "Target"
	// SecurityAttrType names the unqualified Type attribute describing a resource representation.
	SecurityAttrType = "Type"
	// SecurityAttrURI names the unqualified URI attribute used by signature, encryption and XAdES
	// links.
	SecurityAttrURI = "URI"
	// ASN1GeneralizedTimeLayout is the canonical UTC seconds-only DER GeneralizedTime layout.
	ASN1GeneralizedTimeLayout = "20060102150405Z"
	// ASN1UTCTimeLayout is the canonical UTC seconds-only DER UTCTime layout.
	ASN1UTCTimeLayout = "060102150405Z"
	// HistoricalCodeChainConstraintsFailure is the shared sub-indication for a certificate chain
	// outside the selected constraints.
	HistoricalCodeChainConstraintsFailure = "CHAIN_CONSTRAINTS_FAILURE"
	// HistoricalCodeSigCryptoFailure is the shared sub-indication for a failed cryptographic signature
	// check.
	HistoricalCodeSigCryptoFailure = "SIG_CRYPTO_FAILURE"
	// SignatureFamilyECDSA selects the parsed ECDSA signature family in internal algorithm dispatch.
	SignatureFamilyECDSA = "ecdsa"
	// SignatureFamilyRSA selects the parsed RSA PKCS#1 v1.5 signature family in internal algorithm
	// dispatch.
	SignatureFamilyRSA = "rsa"
	// SignatureFamilyRSAPSS selects the parsed RSA-PSS signature family in internal algorithm
	// dispatch.
	SignatureFamilyRSAPSS = "pss"
	// X509OIDCertificateIssuer identifies the CRL-entry extension that specifies the certificate
	// issuer.
	X509OIDCertificateIssuer = "2.5.29.29"
	// X509OIDDeltaCRLIndicator identifies the extension carrying the base CRL number of a delta CRL.
	X509OIDDeltaCRLIndicator = "2.5.29.27"
	// X509OIDIssuingDistributionPoint identifies the CRL extension that describes distribution-point
	// scope.
	X509OIDIssuingDistributionPoint = "2.5.29.28"
)

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
	// SAMLBindingHTTPArtifact is the SAML HTTP-Artifact binding URI.
	SAMLBindingHTTPArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
	// SAMLBindingSOAP is the SAML SOAP binding URI.
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
