package xades

const (
	// Unqualified attribute that binds signed format metadata to an exact ds:Reference.
	attrObjectReference = "ObjectReference"
	// Timestamp property covering all selected signed data objects. Match the applicable XAdES
	// namespace at use sites.
	nameAllDataObjectsTimeStamp = "AllDataObjectsTimeStamp"
	// Archive timestamp property used by preservation and historical validation. Match the applicable
	// XAdES namespace at use sites.
	nameArchiveTimeStamp = "ArchiveTimeStamp"
	// One digest-qualified signing-certificate reference inside SigningCertificateV2. Match the
	// applicable XAdES namespace at use sites.
	nameCert = "Cert"
	// Digest binding for a certificate selected by an XAdES property. Match the applicable XAdES
	// namespace at use sites.
	nameCertDigest = "CertDigest"
	// Certificate evidence container; trust is established by subsequent certificate validation. Match
	// the applicable XAdES namespace at use sites.
	nameCertificateValues = "CertificateValues"
	// Signed commitment claim associated with referenced data objects. Match the applicable XAdES
	// namespace at use sites.
	nameCommitmentTypeIndication = "CommitmentTypeIndication"
	// Unsigned property containing a separate signature over the owning SignatureValue. Match the
	// applicable XAdES namespace at use sites.
	nameCounterSignature = "CounterSignature"
	// Signed format metadata linked to a Reference by ObjectReference. Match the applicable XAdES
	// namespace at use sites.
	nameDataObjectFormat = "DataObjectFormat"
	// Original CRL bytes carried inside RevocationValues. Match the applicable XAdES namespace at use
	// sites.
	nameEncapsulatedCRLValue = "EncapsulatedCRLValue"
	// Original OCSP response bytes carried inside RevocationValues. Match the applicable XAdES
	// namespace at use sites.
	nameEncapsulatedOCSPValue = "EncapsulatedOCSPValue"
	// Encoded RFC 3161 token carried by an XAdES timestamp property. Match the applicable XAdES
	// namespace at use sites.
	nameEncapsulatedTimeStamp = "EncapsulatedTimeStamp"
	// Original DER certificate bytes carried by CertificateValues. Match the applicable XAdES
	// namespace at use sites.
	nameEncapsulatedX509Certificate = "EncapsulatedX509Certificate"
	// Timestamp property covering explicitly listed signed data-object references. Match the
	// applicable XAdES namespace at use sites.
	nameIndividualDataObjectsTimeStamp = "IndividualDataObjectsTimeStamp"
	// Root XAdES property container bound to the selected XML signature. Match the applicable XAdES
	// namespace at use sites.
	nameQualifyingProperties = "QualifyingProperties"
	// Container for original CRL and OCSP evidence encodings. Match the applicable XAdES namespace at
	// use sites.
	nameRevocationValues = "RevocationValues"
	// Signed choice of an explicit or implied signature policy. Match the applicable XAdES namespace
	// at use sites.
	nameSignaturePolicyIdentifier = "SignaturePolicyIdentifier"
	// Timestamp property covering the owning ds:SignatureValue. Match the applicable XAdES namespace
	// at use sites.
	nameSignatureTimeStamp = "SignatureTimeStamp"
	// Authenticated data-object property container under SignedProperties. Match the applicable XAdES
	// namespace at use sites.
	nameSignedDataObjectProperties = "SignedDataObjectProperties"
	// Properties node covered by an explicit SignedInfo reference. Match the applicable XAdES
	// namespace at use sites.
	nameSignedProperties = "SignedProperties"
	// Authenticated properties about the signature and signing identity. Match the applicable XAdES
	// namespace at use sites.
	nameSignedSignatureProperties = "SignedSignatureProperties"
	// Signed role claims whose authorization meaning is selected by application policy. Match the
	// applicable XAdES namespace at use sites.
	nameSignerRoleV2 = "SignerRoleV2"
	// Digest-qualified signing-certificate binding for the selected signature. Match the applicable
	// XAdES namespace at use sites.
	nameSigningCertificateV2 = "SigningCertificateV2"
	// Claimed signing time; trusted time comes from timestamp verification. Match the applicable XAdES
	// namespace at use sites.
	nameSigningTime = "SigningTime"
	// Evidence association for a timestamp in the XAdES 1.4.1 namespace. Match the applicable XAdES
	// namespace at use sites.
	nameTimeStampValidationData = "TimeStampValidationData"
	// Unsigned properties associated with signed data objects. Match the applicable XAdES namespace at
	// use sites.
	nameUnsignedDataObjectProperties = "UnsignedDataObjectProperties"
	// Root container for timestamp and preservation properties. Match the applicable XAdES namespace
	// at use sites.
	nameUnsignedProperties = "UnsignedProperties"
	// Unsigned properties attached to the selected signature. Match the applicable XAdES namespace at
	// use sites.
	nameUnsignedSignatureProperties = "UnsignedSignatureProperties"
)

const (
	// Suggested prefix for generated qualifying properties; the XAdES namespace URI determines
	// identity.
	prefixXAdES = "xades"
)
