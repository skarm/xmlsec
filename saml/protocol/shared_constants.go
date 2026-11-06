package protocol

import "github.com/skarm/xmlsec/internal/lexicon"

// Local SAML vocabulary tokens shared by protocol producers and parsers. Each call site still verifies the assertion/protocol namespace or resolves the QName prefix.
const (
	xmlNameAction                  = "Action"
	xmlNameAdvice                  = "Advice"
	xmlNameAllowCreate             = "AllowCreate"
	xmlNameAttribute               = "Attribute"
	xmlNameAttributeStatement      = "AttributeStatement"
	xmlNameAttributeValue          = "AttributeValue"
	xmlNameAudience                = "Audience"
	xmlNameAudienceRestriction     = "AudienceRestriction"
	xmlNameAuthenticatingAuthority = "AuthenticatingAuthority"
	xmlNameAuthnContext            = "AuthnContext"
	xmlNameAuthnContextClassRef    = "AuthnContextClassRef"
	xmlNameAuthnContextDeclRef     = "AuthnContextDeclRef"
	xmlNameAuthnInstant            = "AuthnInstant"
	xmlNameAuthnStatement          = "AuthnStatement"
	xmlNameAuthzDecisionStatement  = "AuthzDecisionStatement"
	xmlNameComparison              = "Comparison"
	xmlNameConditions              = "Conditions"
	xmlNameEncryptedAssertion      = "EncryptedAssertion"
	xmlNameEncryptedAttribute      = "EncryptedAttribute"
	xmlNameEncryptedID             = "EncryptedID"
	xmlNameEvidence                = "Evidence"
	xmlNameExtensions              = "Extensions"
	xmlNameFriendlyName            = "FriendlyName"
	xmlNameIssuer                  = "Issuer"
	xmlNameNameFormat              = "NameFormat"
	xmlNameNameID                  = "NameID"
	xmlNameNameIDPolicy            = "NameIDPolicy"
	xmlNameNewEncryptedID          = "NewEncryptedID"
	xmlNameNewID                   = "NewID"
	xmlNameOneTimeUse              = "OneTimeUse"
	xmlNameRequestedAuthnContext   = "RequestedAuthnContext"
	xmlNameResource                = "Resource"
	xmlNameSessionIndex            = "SessionIndex"
	xmlNameStatus                  = "Status"
	xmlNameStatusCode              = "StatusCode"
	xmlNameSubject                 = "Subject"
	xmlNameSubjectConfirmation     = "SubjectConfirmation"
	xmlNameSubjectConfirmationData = "SubjectConfirmationData"
	xmlNameValue                   = "Value"
)

// Fixed profile ceilings shared by producers and parsers. Text limits count
// UTF-8 bytes; key and child limits count alternatives or direct XML children.
// None of these values is a configurable zero-value default.
const (
	maximumAttributeNameBytes       = 1024
	maximumFriendlyNameBytes        = 1024
	maximumNameQualifierBytes       = 2048
	maximumRedirectVerificationKeys = 16
	maximumSubjectChildren          = 9
	maximumURITextBytes             = 2048
	minimumSubjectChildren          = 2
)

// XML child offsets after the mandatory issuer; a direct XML signature adds one child. These widths describe syntax, not authority to bypass authentication.
const (
	signedMessagePrefixChildren   = 2
	unsignedMessagePrefixChildren = 1
)

// SAML 2.0 header and confirmation attributes are unqualified XML names.
// The version token is a wire value, independent of the namespace declarations.
const (
	version20           = "2.0"
	nameDestination     = "Destination"
	nameMethod          = "Method"
	nameRecipient       = "Recipient"
	nameAddress         = "Address"
	nameNotBefore       = "NotBefore"
	nameSPNameQualifier = "SPNameQualifier"
)

// Correlation and issue-time attributes are shared across the request families.
const (
	nameInResponseTo = "InResponseTo"
	nameIssueInstant = "IssueInstant"
)

// Version is the unqualified attribute carrying version20 on protocol messages.
const (
	nameVersion = "Version"
)

// Identifier qualifiers and expiry names are shared by assertion and protocol
// producers/parsers. Prefixes are serialization choices, never namespace trust.
const (
	nameFormat        = "Format"
	nameNameQualifier = "NameQualifier"
	nameNotOnOrAfter  = "NotOnOrAfter"
	nameSPProvidedID  = "SPProvidedID"
	prefixAssertion   = "saml"
	prefixProtocol    = "samlp"
	prefixSOAP        = "env"
	// LogoutResponse is the SAML logout response element local name.
	LogoutResponse = lexicon.SAMLElementLogoutResponse
	// ManageNameIDResponse is the SAML name management response element local name.
	ManageNameIDResponse = lexicon.SAMLElementManageNameIDResponse
	// ArtifactResponse is the SAML artifact response element local name.
	ArtifactResponse = lexicon.SAMLElementArtifactResponse
)

// These names and the exact-comparison selector are reused by web and query
// assertion paths; their surrounding assertion/protocol namespaces remain explicit.
const (
	nameAttributeName       = "Name"
	contextExact            = "exact"
	nameSessionNotOnOrAfter = "SessionNotOnOrAfter"
	nameAssertion           = "Assertion"
)
