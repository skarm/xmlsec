package protocol

import (
	"context"
	"crypto"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
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
}

// SignResponse signs the Assertion, then the enclosing Response, and verifies
// both again. No envelope-only POST assertion is generated.
func SignResponse(ctx context.Context, s Response, key SigningKey) (*document.Document, error) {
	k, e := signing(key)
	if e != nil {
		return nil, e
	}

	if ctx == nil || !xmlutil.ID(s.ID) || !xmlutil.ID(s.Assertion.ID) || s.ID == s.Assertion.ID || !xmlutil.ID(s.InResponseTo) || !xmlutil.URI(s.Issuer) || !xmlutil.URI(s.Audience) || !xmlutil.Endpoint(s.Destination, true) || s.IssueInstant.IsZero() {
		return nil, ErrProfile
	}

	root := xmlutil.Node("samlp", ProtocolNamespace, "Response")

	root.NS = []tree.Namespace{{Prefix: "samlp", URI: ProtocolNamespace}, {Prefix: "saml", URI: AssertionNamespace}, {Prefix: "ds", URI: xmlutil.DS}}
	for _, v := range [][2]string{{"ID", s.ID}, {nameVersion, version20}, {nameIssueInstant, xmlutil.Time(s.IssueInstant)}, {nameDestination, s.Destination}, {nameInResponseTo, s.InResponseTo}} {
		xmlutil.Set(root, v[0], v[1])
	}

	issue := xmlutil.Node("saml", AssertionNamespace, "Issuer")
	xmlutil.Text(issue, s.Issuer)
	xmlutil.Add(root, issue)

	status := xmlutil.Node("samlp", ProtocolNamespace, "Status")
	code := xmlutil.Node("samlp", ProtocolNamespace, "StatusCode")
	xmlutil.Set(code, "Value", Success)
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

	target, e := xmlutil.Direct(d.Root(), xmlutil.Name(AssertionNamespace, "Assertion"))
	if e != nil {
		return nil, e
	}

	d, e = xmlsig.Sign(ctx, d, target, k, true)
	if e != nil {
		return nil, e
	}

	d, e = xmlsig.Sign(ctx, d, d.Root(), k, true)
	if e != nil {
		return nil, e
	}

	_, e = VerifyResponse(ctx, d, []crypto.PublicKey{key.Key.Public()}, ResponseOptions{Issuer: s.Issuer, Audience: s.Audience, Destination: s.Destination, ExpectedRequestID: s.InResponseTo, At: s.IssueInstant, Limits: s.Limits, Policy: key.Policy})
	if e != nil {
		return nil, e
	}

	return d, nil
}

func assertionNode(s Response) (*tree.Node, error) {
	a := s.Assertion

	l, err := normalize(s.Limits)
	if err != nil {
		return nil, err
	}

	if len(a.NameID) == 0 || len(a.NameID) > l.MaxValueBytes || a.NotBefore.IsZero() || a.NotOnOrAfter.IsZero() || a.AuthnInstant.IsZero() || !xmlutil.URI(a.AuthnContext) || timeWindow(a.NotBefore, a.NotOnOrAfter, s.IssueInstant, l) != nil || len(a.Attributes) > l.MaxAttributes {
		return nil, ErrProfile
	}

	if a.NameIDFormat == "" {
		a.NameIDFormat = NameIDUnspecified
	}

	if !xmlutil.URI(a.NameIDFormat) {
		return nil, ErrProfile
	}

	node := xmlutil.Node("saml", AssertionNamespace, "Assertion")
	xmlutil.Set(node, "ID", a.ID)
	xmlutil.Set(node, nameVersion, version20)
	xmlutil.Set(node, nameIssueInstant, xmlutil.Time(s.IssueInstant))

	issuer := xmlutil.Node("saml", AssertionNamespace, "Issuer")
	xmlutil.Text(issuer, s.Issuer)
	xmlutil.Add(node, issuer)

	subject := xmlutil.Node("saml", AssertionNamespace, "Subject")
	name := xmlutil.Node("saml", AssertionNamespace, "NameID")
	xmlutil.Set(name, "Format", a.NameIDFormat)
	xmlutil.Text(name, a.NameID)
	xmlutil.Add(subject, name)

	conf := xmlutil.Node("saml", AssertionNamespace, "SubjectConfirmation")
	xmlutil.Set(conf, "Method", Bearer)

	data := xmlutil.Node("saml", AssertionNamespace, "SubjectConfirmationData")
	xmlutil.Set(data, "Recipient", s.Destination)
	xmlutil.Set(data, nameInResponseTo, s.InResponseTo)
	xmlutil.Set(data, "NotOnOrAfter", xmlutil.Time(a.NotOnOrAfter))
	xmlutil.Add(conf, data)
	xmlutil.Add(subject, conf)
	xmlutil.Add(node, subject)

	conditions := xmlutil.Node("saml", AssertionNamespace, "Conditions")
	xmlutil.Set(conditions, "NotBefore", xmlutil.Time(a.NotBefore))
	xmlutil.Set(conditions, "NotOnOrAfter", xmlutil.Time(a.NotOnOrAfter))

	restriction := xmlutil.Node("saml", AssertionNamespace, "AudienceRestriction")
	audience := xmlutil.Node("saml", AssertionNamespace, "Audience")
	xmlutil.Text(audience, s.Audience)
	xmlutil.Add(restriction, audience)
	xmlutil.Add(conditions, restriction)
	xmlutil.Add(node, conditions)

	auth := xmlutil.Node("saml", AssertionNamespace, "AuthnStatement")
	xmlutil.Set(auth, "AuthnInstant", xmlutil.Time(a.AuthnInstant))

	if a.SessionIndex != "" {
		xmlutil.Set(auth, "SessionIndex", a.SessionIndex)
	}

	if !a.SessionNotOnOrAfter.IsZero() {
		xmlutil.Set(auth, "SessionNotOnOrAfter", xmlutil.Time(a.SessionNotOnOrAfter))
	}

	ac := xmlutil.Node("saml", AssertionNamespace, "AuthnContext")
	ref := xmlutil.Node("saml", AssertionNamespace, "AuthnContextClassRef")
	xmlutil.Text(ref, a.AuthnContext)
	xmlutil.Add(ac, ref)
	xmlutil.Add(auth, ac)
	xmlutil.Add(node, auth)

	if len(a.Attributes) > 0 {
		statement := xmlutil.Node("saml", AssertionNamespace, "AttributeStatement")
		seen := map[[2]string]struct{}{}

		for _, v := range a.Attributes {
			format := v.NameFormat
			if format == "" {
				format = AttributeUnspecified
			}

			if _, exists := seen[[2]string{v.Name, format}]; v.Name == "" || len(v.Name) > 1024 || !xmlutil.URI(format) || len(v.FriendlyName) > 1024 || len(v.Values) < 1 || len(v.Values) > l.MaxValuesPerAttribute || exists {
				return nil, ErrProfile
			}

			seen[[2]string{v.Name, format}] = struct{}{}
			attr := xmlutil.Node("saml", AssertionNamespace, "Attribute")
			xmlutil.Set(attr, "Name", v.Name)
			xmlutil.Set(attr, "NameFormat", format)

			if v.FriendlyName != "" {
				xmlutil.Set(attr, "FriendlyName", v.FriendlyName)
			}

			for _, s := range v.Values {
				if len(s) > l.MaxValueBytes {
					return nil, ErrProfile
				}

				value := xmlutil.Node("saml", AssertionNamespace, "AttributeValue")
				xmlutil.Text(value, s)
				xmlutil.Add(attr, value)
			}

			xmlutil.Add(statement, attr)
		}

		xmlutil.Add(node, statement)
	}

	return node, nil
}
