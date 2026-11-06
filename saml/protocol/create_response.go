package protocol

import (
	"context"
	"crypto"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

// AssertionData supplies identity claims for an assertion. The application must
// establish these claims through its authentication and authorization decisions;
// constructing this value does not authenticate a user.
type AssertionData struct {
	// ID is the required assertion XML ID. It must differ from the response ID.
	ID string
	// NameID is the nonempty subject identifier established by the application.
	NameID string
	// NameIDFormat is the identifier format URI. Empty selects NameIDUnspecified.
	NameIDFormat string
	// NameQualifier, SPNameQualifier and SPProvidedID retain the identifier
	// established by name identifier management, including the SP's current alias.
	NameQualifier, SPNameQualifier, SPProvidedID string
	// NotBefore is the required inclusive start of assertion validity.
	NotBefore time.Time
	// NotOnOrAfter is the required exclusive end of assertion validity.
	NotOnOrAfter time.Time
	// AuthnInstant is the required time at which the subject was authenticated.
	AuthnInstant time.Time
	// AuthnContext is the required authentication context class URI.
	AuthnContext string
	// SessionIndex is an optional identifier for the authenticated session.
	SessionIndex string
	// SessionNotOnOrAfter is the optional exclusive end of session validity. Zero omits it.
	SessionNotOnOrAfter time.Time
	// Attributes contains application-authorized string attributes for the subject.
	Attributes []Attribute
	// ChannelBindings signals IdP verification of the matching signed request's
	// transport bindings. Only set this after the ECP comparison succeeded.
	ChannelBindings []ChannelBinding
	// HolderOfKeyCertificate selects HoK instead of bearer confirmation. The
	// application must establish possession and its association with the subject.
	HolderOfKeyCertificate []byte
}

// Response supplies the envelope and assertion for a successful solicited SAML
// response.
type Response struct {
	// ID is the required response XML ID.
	ID string
	// Issuer is the issuing identity provider's entity identifier URI.
	Issuer string
	// Audience is the intended service provider's entity identifier URI.
	Audience string
	// Destination is the trusted assertion consumer endpoint URL.
	Destination string
	// InResponseTo is the XML ID of the soliciting authentication request.
	InResponseTo string
	// IssueInstant is the required issuance time for the response and assertion.
	IssueInstant time.Time
	// Assertion supplies the authenticated identity claims to sign.
	Assertion AssertionData
	// Limits bounds assertion times and attributes during creation and self-verification.
	Limits Limits
	// Encryption selects encrypted assertion, identifier and/or attributes.
	// Nil produces the existing signed plaintext response.
	Encryption *EncryptionOptions
	// SOAPContext signs the assertion in the SOAP envelope namespace context.
	// Set this before signing when the response will be carried by SOAP/PAOS,
	// especially for Inclusive C14N. It does not itself wrap the response.
	SOAPContext bool
}

// SignResponse signs the Assertion, then the enclosing Response, and verifies
// both again. No envelope-only POST assertion is generated.
func SignResponse(ctx context.Context, s Response, key SigningKey) (*document.Document, error) {
	k, e := signing(key)
	if e != nil {
		return nil, e
	}

	if ctx == nil || !profile.ID(s.ID) || !profile.ID(s.Assertion.ID) || s.ID == s.Assertion.ID || !profile.ID(s.InResponseTo) || !profile.URI(s.Issuer) || !profile.URI(s.Audience) || !profile.Endpoint(s.Destination, true) || s.IssueInstant.IsZero() {
		return nil, ErrProfile
	}

	root := xmlutil.Node(prefixProtocol, ProtocolNamespace, lexicon.SAMLElementResponse)

	root.NS = []tree.Namespace{{Prefix: prefixProtocol, URI: ProtocolNamespace}, {Prefix: prefixAssertion, URI: AssertionNamespace}, {Prefix: lexicon.PrefixDSig, URI: xmlutil.DS}}
	if s.SOAPContext {
		root.NS = append(root.NS, tree.Namespace{Prefix: prefixSOAP, URI: binding.SOAPNamespace})
	}

	for _, v := range [][2]string{{lexicon.SAMLAttrID, s.ID}, {nameVersion, version20}, {nameIssueInstant, profile.Time(s.IssueInstant)}, {nameDestination, s.Destination}, {nameInResponseTo, s.InResponseTo}} {
		xmlutil.Set(root, v[0], v[1])
	}

	issue := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameIssuer)
	xmlutil.Text(issue, s.Issuer)
	xmlutil.Add(root, issue)

	status := xmlutil.Node(prefixProtocol, ProtocolNamespace, xmlNameStatus)
	code := xmlutil.Node(prefixProtocol, ProtocolNamespace, xmlNameStatusCode)
	xmlutil.Set(code, xmlNameValue, Success)
	xmlutil.Add(status, code)
	xmlutil.Add(root, status)

	a, e := assertionNode(s)
	if e != nil {
		return nil, e
	}

	xmlutil.Add(root, a)

	d, e := xmlutil.Document(ctx, root)
	if e != nil {
		return nil, e
	}

	encryption, e := CloneEncryption(s.Encryption)
	if e != nil || encryption != nil && encryption.Recipient == nil {
		return nil, ErrEncryption
	}
	// Check the same semantic rules before encryption makes fields opaque to
	// the producer. Signature generation independently self-verifies its bytes.
	if e := validateProducedAssertion(d, s); e != nil {
		return nil, e
	}

	if encryption != nil {
		d, e = encryptAssertionContents(ctx, d, encryption)
		if e != nil {
			return nil, e
		}
	}

	target, e := xmlutil.Direct(d.Root(), xmlutil.Name(AssertionNamespace, nameAssertion))
	if e != nil {
		return nil, e
	}

	d, e = xmlsig.Sign(ctx, d, target, k, true)
	if e != nil {
		return nil, e
	}

	if encryption != nil && encryption.Targets&EncryptAssertion != 0 {
		target, e = xmlutil.Direct(d.Root(), xmlutil.Name(AssertionNamespace, nameAssertion))
		if e != nil {
			return nil, e
		}

		d, e = encryptSAML(ctx, d, target, xmlNameEncryptedAssertion, encryption)
		if e != nil {
			return nil, e
		}
	}

	d, e = xmlsig.Sign(ctx, d, d.Root(), k, true)
	if e != nil {
		return nil, e
	}

	if encryption == nil {
		_, e = VerifyResponse(ctx, d, []crypto.PublicKey{verificationKey(key)}, ResponseOptions{Issuer: s.Issuer, Audience: s.Audience, Destination: s.Destination, ExpectedRequestID: s.InResponseTo, At: s.IssueInstant, Limits: s.Limits, Policy: key.Policy, producedCertificate: s.Assertion.HolderOfKeyCertificate})
		if e != nil {
			return nil, e
		}
	}

	return d, nil
}

func assertionNode(s Response) (*tree.Node, error) {
	a := s.Assertion

	l, err := normalize(s.Limits)
	if err != nil {
		return nil, err
	}

	if len(a.NameID) == 0 || len(a.NameID) > l.MaxValueBytes || a.NotBefore.IsZero() || a.NotOnOrAfter.IsZero() || a.AuthnInstant.IsZero() || !profile.URI(a.AuthnContext) || timeWindow(a.NotBefore, a.NotOnOrAfter, s.IssueInstant, l) != nil || len(a.Attributes) > l.MaxAttributes {
		return nil, ErrProfile
	}

	if a.NameIDFormat == "" {
		a.NameIDFormat = NameIDUnspecified
	}

	if !profile.URI(a.NameIDFormat) {
		return nil, ErrProfile
	}

	if err := (NameIdentifier{Value: a.NameID, Format: a.NameIDFormat, NameQualifier: a.NameQualifier, SPNameQualifier: a.SPNameQualifier, SPProvidedID: a.SPProvidedID}).Validate(); err != nil {
		return nil, err
	}

	node := xmlutil.Node(prefixAssertion, AssertionNamespace, nameAssertion)
	xmlutil.Set(node, lexicon.SAMLAttrID, a.ID)
	xmlutil.Set(node, nameVersion, version20)
	xmlutil.Set(node, nameIssueInstant, profile.Time(s.IssueInstant))

	issuer := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameIssuer)
	xmlutil.Text(issuer, s.Issuer)
	xmlutil.Add(node, issuer)

	subject := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameSubject)
	name := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameNameID)
	xmlutil.Set(name, nameFormat, a.NameIDFormat)

	appendNameQualifiers(name, a)
	xmlutil.Text(name, a.NameID)
	xmlutil.Add(subject, name)

	conf, err := confirmationNode(s)
	if err != nil {
		return nil, err
	}

	xmlutil.Add(subject, conf)
	xmlutil.Add(node, subject)

	conditions := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameConditions)
	xmlutil.Set(conditions, nameNotBefore, profile.Time(a.NotBefore))
	xmlutil.Set(conditions, nameNotOnOrAfter, profile.Time(a.NotOnOrAfter))

	restriction := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameAudienceRestriction)
	audience := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameAudience)
	xmlutil.Text(audience, s.Audience)
	xmlutil.Add(restriction, audience)
	xmlutil.Add(conditions, restriction)
	xmlutil.Add(node, conditions)

	if err := appendChannelContainer(node, xmlNameAdvice, a.ChannelBindings, true); err != nil {
		return nil, err
	}

	auth := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameAuthnStatement)
	xmlutil.Set(auth, xmlNameAuthnInstant, profile.Time(a.AuthnInstant))

	if a.SessionIndex != "" {
		xmlutil.Set(auth, xmlNameSessionIndex, a.SessionIndex)
	}

	if !a.SessionNotOnOrAfter.IsZero() {
		xmlutil.Set(auth, nameSessionNotOnOrAfter, profile.Time(a.SessionNotOnOrAfter))
	}

	ac := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameAuthnContext)
	ref := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameAuthnContextClassRef)
	xmlutil.Text(ref, a.AuthnContext)
	xmlutil.Add(ac, ref)
	xmlutil.Add(auth, ac)
	xmlutil.Add(node, auth)

	if len(a.Attributes) > 0 {
		statement := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameAttributeStatement)
		seen := map[[2]string]struct{}{}

		for _, v := range a.Attributes {
			format := v.NameFormat
			if format == "" {
				format = AttributeUnspecified
			}

			if _, exists := seen[[2]string{v.Name, format}]; v.Name == "" || len(v.Name) > maximumAttributeNameBytes || !profile.URI(format) || len(v.FriendlyName) > maximumFriendlyNameBytes || len(v.Values) < 1 || len(v.Values) > l.MaxValuesPerAttribute || exists {
				return nil, ErrProfile
			}

			seen[[2]string{v.Name, format}] = struct{}{}
			attr := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameAttribute)
			xmlutil.Set(attr, nameAttributeName, v.Name)
			xmlutil.Set(attr, xmlNameNameFormat, format)

			if v.FriendlyName != "" {
				xmlutil.Set(attr, xmlNameFriendlyName, v.FriendlyName)
			}

			for _, s := range v.Values {
				if len(s) > l.MaxValueBytes {
					return nil, ErrProfile
				}

				value := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameAttributeValue)
				xmlutil.Text(value, s)
				xmlutil.Add(attr, value)
			}

			xmlutil.Add(statement, attr)
		}

		xmlutil.Add(node, statement)
	}

	return node, nil
}

func validateProducedAssertion(d *document.Document, s Response) error {
	plain, e := xmlutil.Direct(d.Root(), xmlutil.Name(AssertionNamespace, nameAssertion))
	if e != nil {
		return e
	}

	l, e := normalize(s.Limits)
	if e != nil {
		return e
	}

	if _, e = parseAssertion(plain, ResponseOptions{Issuer: s.Issuer, Audience: s.Audience, Destination: s.Destination, ExpectedRequestID: s.InResponseTo, At: s.IssueInstant, AllowUnsignedAssertion: true, producedCertificate: s.Assertion.HolderOfKeyCertificate}, l); e != nil {
		return e
	}

	return nil
}

func appendNameQualifiers(name *tree.Node, a AssertionData) {
	for _, attr := range [][2]string{{nameNameQualifier, a.NameQualifier}, {nameSPNameQualifier, a.SPNameQualifier}, {nameSPProvidedID, a.SPProvidedID}} {
		if attr[1] != "" {
			xmlutil.Set(name, attr[0], attr[1])
		}
	}
}
