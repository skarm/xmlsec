package protocol

import (
	"context"
	"crypto"
	"net"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/saml/proof"
	"github.com/skarm/xmlsec/xmldsig"
)

// ResponseOptions supplies relying-party policy for a solicited POST response.
// The application must obtain ExpectedRequestID, assertion consumer endpoint,
// audience and issuer from trusted configuration and pending state. Values from
// the received response cannot replace those expectations.
type ResponseOptions struct {
	// Issuer is the expected identity provider's entity identifier from trusted
	// configuration.
	Issuer string
	// Audience is the expected service provider's entity identifier.
	Audience string
	// Destination is the trusted assertion consumer endpoint URL.
	Destination string
	// ExpectedRequestID is the soliciting request ID retained in trusted pending state.
	ExpectedRequestID string
	// At is the explicit trusted verification time.
	At time.Time
	// RequestIssueInstant is required with ForceAuthn and binds freshness to the original request.
	RequestIssueInstant time.Time
	// Limits bounds message age, assertion lifetime and attribute values.
	Limits Limits
	// Policy sets response and assertion signature algorithms and key limits.
	Policy xmldsig.Policy
	// AllowUnsignedResponse permits a Response without an envelope signature. The
	// Assertion signature remains required. Unsigned envelope fields are unauthenticated.
	AllowUnsignedResponse bool
	// AllowUnsignedAssertion accepts an unsigned assertion only when the Response
	// envelope has been authenticated. A present assertion signature is always
	// checked. The default continues to require both signatures.
	AllowUnsignedAssertion bool
	// Decryption supplies the explicit recipient key ring and exact cipher policy.
	Decryption *DecryptionOptions
	// RequireEncryption rejects plaintext at the selected positions. Attributes
	// means every present Attribute; an absent AttributeStatement is allowed.
	RequireEncryption EncryptionTargets
	// AllowedNameIDFormats restricts subject identifier formats to exact URIs. Empty
	// disables this membership check.
	AllowedNameIDFormats []string
	// ExpectedAuthnContexts restricts authentication contexts to exact URIs. Empty
	// disables this membership check.
	ExpectedAuthnContexts []string
	// ForceAuthn requires authentication no earlier than RequestIssueInstant,
	// subject to the configured clock skew.
	ForceAuthn bool
	// ExpectedAddress supplies the trusted client address to require when subject
	// confirmation includes Address.
	ExpectedAddress string
	// ExpectedChannelBindings requires authenticated Advice confirming at least
	// one of the bindings retained with the soliciting ECP request.
	ExpectedChannelBindings []ChannelBinding
	// Proof is verified possession for this exact SOAP payload, never a peer
	// certificate supplied independently of the received message.
	// Supplying it selects HoK and never falls back to bearer confirmation.
	Proof *proof.Verified
	// RequireHolderOfKey rejects a bearer downgrade when HoK was requested.
	RequireHolderOfKey  bool
	producedCertificate []byte
}

// Attribute is a SAML attribute and its string values.
type Attribute struct {
	// Name is the required attribute name.
	Name string
	// NameFormat optionally identifies the naming scheme by URI.
	NameFormat string
	// FriendlyName is an optional human-readable attribute label.
	FriendlyName string
	// Values contains the attribute's string values.
	Values []string
}

// VerifiedAssertion exposes values from the verified Assertion snapshot.
// It does not consume replay state or create an application session. Package
// saml/sp atomically consumes request, assertion and response identifiers after
// protocol and browser-correlation checks.
type VerifiedAssertion struct {
	assertion      document.Element
	responseID     string
	assertionID    string
	issuer         string
	audience       string
	recipient      string
	requestID      string
	nameID         string
	nameIDFormat   string
	identifier     NameIdentifier
	sessionIndex   string
	contextClass   string
	instant        time.Time
	authnInstant   time.Time
	expires        time.Time
	sessionExpires time.Time
	attributes     []Attribute
	responseSigned bool
	encryption     EncryptionTargets
	channels       []ChannelBinding
	confirmation   string
	hokCertificate []byte
}

// VerifyResponse authenticates and validates a solicited response and its signed assertion
// under explicit expectations.
func VerifyResponse(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o ResponseOptions) (*VerifiedAssertion, error) {
	const (
		minimumWebResponseChildren = 2
	)

	if o.Proof != nil && !o.Proof.Covers(d) {
		return nil, ErrConditions
	}

	l, e := normalize(o.Limits)
	if e != nil {
		return nil, e
	}

	if e := validateResponseOptions(ctx, d, o); e != nil {
		return nil, e
	}

	if !validEncryptionTargets(o.RequireEncryption) || o.RequireEncryption != 0 && o.Decryption == nil {
		return nil, ErrEncryption
	}

	decryption, e := newDecryptionState(o.Decryption)
	if e != nil {
		return nil, e
	}

	if e = ctx.Err(); e != nil {
		return nil, e
	}

	root := d.Root()
	if xmlutil.Attrs(root, []string{lexicon.SAMLAttrID, nameVersion, nameIssueInstant, nameDestination, nameInResponseTo}, nil) != nil {
		return nil, ErrProfile
	}

	responseID, _, e := header(root, lexicon.SAMLElementResponse, o.At, l)
	if e != nil {
		return nil, e
	}

	if xmlutil.Attr(root, nameDestination) != o.Destination || xmlutil.Attr(root, nameInResponseTo) != o.ExpectedRequestID {
		return nil, ErrCorrelation
	}

	children, e := xmlutil.Children(root)
	if e != nil || len(children) < minimumWebResponseChildren || issuer(children[0], o.Issuer) != nil {
		return nil, ErrProfile
	}

	pos := 1
	responseSigned := false

	if children[pos].Name() == xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature) {
		if e = targetSignature(ctx, d, root, keys, o.Policy); e != nil {
			return nil, e
		}

		responseSigned = true
		pos++
	} else if !o.AllowUnsignedResponse {
		return nil, ErrSignature
	}

	if pos >= len(children) || children[pos].Name() != xmlutil.Name(ProtocolNamespace, xmlNameStatus) {
		return nil, ErrProfile
	}

	status := children[pos]
	pos++

	parsedStatus, e := readStatus(status)
	if e != nil {
		return nil, e
	}

	if parsedStatus.Code != Success {
		if !responseSigned || pos != len(children) || signingCount(d, 1) != nil {
			return nil, ErrProfile
		}

		return nil, &StatusError{Code: parsedStatus.Code, Subcodes: parsedStatus.Subcodes, Message: parsedStatus.Message}
	}

	if pos+1 != len(children) {
		return nil, ErrProfile
	}

	return verifyAssertionPayload(ctx, d, children[pos], keys, o, l, decryption, responseID, responseSigned)
}

func verifyAssertionPayload(ctx context.Context, d *document.Document, payload document.Element, keys []crypto.PublicKey, o ResponseOptions, l Limits, decryption *decryptionState, responseID string, responseSigned bool) (*VerifiedAssertion, error) {
	var (
		e         error
		encrypted EncryptionTargets
	)

	if payload.Name() == xmlutil.Name(AssertionNamespace, xmlNameEncryptedAssertion) {
		d, e = decryption.decryptSAML(ctx, d, payload, nameAssertion, responseSigned)
		if e != nil {
			return nil, e
		}

		encrypted |= EncryptAssertion

		payload, e = xmlutil.Direct(d.Root(), xmlutil.Name(AssertionNamespace, nameAssertion))
		if e != nil {
			return nil, e
		}
	} else if o.RequireEncryption&EncryptAssertion != 0 {
		return nil, ErrEncryption
	}

	if payload.Name() != xmlutil.Name(AssertionNamespace, nameAssertion) {
		return nil, ErrProfile
	}

	assertion := payload

	assertionSigned := false
	for _, child := range assertion.Children() {
		assertionSigned = assertionSigned || child.Name() == xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature)
	}

	expectedCount := 0
	if assertionSigned {
		expectedCount++

		if e = targetSignature(ctx, d, assertion, keys, o.Policy); e != nil {
			return nil, e
		}
	} else if !o.AllowUnsignedAssertion || !responseSigned {
		return nil, ErrSignature
	}

	if responseSigned {
		expectedCount++
	}

	if signingCount(d, expectedCount) != nil {
		return nil, ErrProfile
	}

	signedAssertion := assertion

	d, innerEncryption, e := decryptAssertionContents(ctx, d, decryption, o.RequireEncryption, assertionSigned || responseSigned, l)
	if e != nil {
		return nil, e
	}

	encrypted |= innerEncryption

	assertion, e = xmlutil.Direct(d.Root(), xmlutil.Name(AssertionNamespace, nameAssertion))
	if e != nil {
		return nil, e
	}

	result, e := parseAssertion(assertion, o, l)
	if e != nil {
		return nil, e
	}

	result.responseID = responseID
	result.responseSigned = responseSigned
	result.assertion = signedAssertion
	result.encryption = encrypted

	if e = ctx.Err(); e != nil {
		return nil, e
	}

	return result, nil
}

// Encryption reports which SAML positions were successfully decrypted and
// authenticated. It does not infer confidentiality of transport or other fields.
func (r *VerifiedAssertion) Encryption() EncryptionTargets {
	if r == nil {
		return 0
	}

	return r.encryption
}

// AssertionID returns the authenticated assertion identifier.
func (r *VerifiedAssertion) AssertionID() string {
	if r == nil {
		return ""
	}

	return r.assertionID
}

// ResponseID returns the response identifier.
func (r *VerifiedAssertion) ResponseID() string {
	if r == nil {
		return ""
	}

	return r.responseID
}

// Issuer returns the authenticated issuer identifier.
func (r *VerifiedAssertion) Issuer() string {
	if r == nil {
		return ""
	}

	return r.issuer
}

// Audience returns the accepted audience identifier.
func (r *VerifiedAssertion) Audience() string {
	if r == nil {
		return ""
	}

	return r.audience
}

// Recipient returns the accepted subject-confirmation recipient.
func (r *VerifiedAssertion) Recipient() string {
	if r == nil {
		return ""
	}

	return r.recipient
}

// InResponseTo returns the correlated request identifier.
func (r *VerifiedAssertion) InResponseTo() string {
	if r == nil {
		return ""
	}

	return r.requestID
}

// NameID returns the authenticated subject identifier.
func (r *VerifiedAssertion) NameID() string {
	if r == nil {
		return ""
	}

	return r.nameID
}

// NameIDFormat returns the accepted NameID format URI.
func (r *VerifiedAssertion) NameIDFormat() string {
	if r == nil {
		return ""
	}

	return r.nameIDFormat
}

// Identifier returns the complete authenticated NameID including its qualifiers
// and current SPProvidedID. Retain this value for logout and name management.
func (r *VerifiedAssertion) Identifier() NameIdentifier { return r.identifier }

// SessionIndex returns the authenticated session identifier.
func (r *VerifiedAssertion) SessionIndex() string {
	if r == nil {
		return ""
	}

	return r.sessionIndex
}

// AuthnContext returns the accepted authentication context URI.
func (r *VerifiedAssertion) AuthnContext() string {
	if r == nil {
		return ""
	}

	return r.contextClass
}

// IssueInstant returns the message issue instant.
func (r *VerifiedAssertion) IssueInstant() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.instant
}

// AuthnInstant returns the authenticated authentication instant.
func (r *VerifiedAssertion) AuthnInstant() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.authnInstant
}

// NotOnOrAfter returns the exclusive assertion expiration boundary.
func (r *VerifiedAssertion) NotOnOrAfter() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.expires
}

// SessionNotOnOrAfter returns the exclusive session expiration boundary, or zero when
// absent.
func (r *VerifiedAssertion) SessionNotOnOrAfter() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.sessionExpires
}

// Attributes returns owned copies of the authenticated attribute values.
func (r *VerifiedAssertion) Attributes() []Attribute {
	if r == nil {
		return nil
	}

	return copyAttributes(r.attributes)
}

// ResponseAuthenticated returns whether the response envelope itself was authenticated.
func (r *VerifiedAssertion) ResponseAuthenticated() bool { return r != nil && r.responseSigned }

// StatusError reports an authenticated non-success response. It does not indicate
// login success. Remote StatusMessage and StatusDetail are not exposed as trusted
// text.
type StatusError struct {
	// Subcodes are authenticated nested status codes, outermost first.
	Subcodes []string
	// Message is bounded authenticated remote diagnostic text, not a trust decision.
	Message string
	// Code is the authenticated non-success SAML status code URI.
	Code string
}

// Error returns the diagnostic error message.
func (e *StatusError) Error() string { return "SAML response status: " + e.Code }

// ValidatePolicy checks a reusable policy before a stateful SP/IdP accepts it.
func ValidatePolicy(l Limits) error { _, e := normalize(l); return e }

// AcceptanceWindow returns normalized, immutable timing limits to wrappers.
func AcceptanceWindow(l Limits) (messageAge, assertionLifetime, skew time.Duration, err error) {
	n, e := normalize(l)
	if e != nil {
		return 0, 0, 0, e
	}

	return n.MaxMessageAge, n.MaxAssertionLifetime, n.ClockSkew, nil
}

func validateResponseOptions(ctx context.Context, d *document.Document, o ResponseOptions) error {
	const (
		maximumAllowedNameIDFormats  = 16
		maximumExpectedAuthnContexts = 16
	)

	if ctx == nil || d == nil || o.At.IsZero() || !profile.URI(o.Issuer) || !profile.URI(o.Audience) || !profile.Endpoint(o.Destination, true) || !profile.ID(o.ExpectedRequestID) || len(o.AllowedNameIDFormats) > maximumAllowedNameIDFormats || len(o.ExpectedAuthnContexts) > maximumExpectedAuthnContexts || o.ForceAuthn && o.RequestIssueInstant.IsZero() {
		return ErrProfile
	}

	return nil
}

func parseAssertion(a document.Element, o ResponseOptions, l Limits) (*VerifiedAssertion, error) {
	const (
		maximumWebAssertionChildren         = 7
		minimumWebAssertionChildren         = 4
		requiredWebAssertionPayloadChildren = 3
	)

	if xmlutil.Attrs(a, []string{lexicon.SAMLAttrID, nameVersion, nameIssueInstant}, nil) != nil || xmlutil.Attr(a, nameVersion) != version20 || !profile.ID(xmlutil.Attr(a, lexicon.SAMLAttrID)) {
		return nil, ErrProfile
	}

	instant, e := profile.ParseTime(xmlutil.Attr(a, nameIssueInstant))
	if e != nil || instant.After(o.At.Add(l.ClockSkew)) || instant.Before(o.At.Add(-l.MaxMessageAge-l.ClockSkew)) {
		return nil, ErrConditions
	}

	cs, e := xmlutil.Children(a)
	if e != nil || len(cs) < minimumWebAssertionChildren || len(cs) > maximumWebAssertionChildren || issuer(cs[0], o.Issuer) != nil {
		return nil, ErrProfile
	}

	pos := 1
	if cs[pos].Name() == xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature) {
		pos++
	} else if !o.AllowUnsignedAssertion {
		return nil, ErrSignature
	}

	if len(cs) < pos+requiredWebAssertionPayloadChildren || cs[pos].Name() != xmlutil.Name(AssertionNamespace, xmlNameSubject) || cs[pos+1].Name() != xmlutil.Name(AssertionNamespace, xmlNameConditions) {
		return nil, ErrProfile
	}

	r := &VerifiedAssertion{assertion: a, assertionID: xmlutil.Attr(a, lexicon.SAMLAttrID), issuer: o.Issuer, audience: o.Audience, recipient: o.Destination, requestID: o.ExpectedRequestID, instant: instant}
	if e = parseSubject(cs[pos], o, l, r); e != nil {
		return nil, e
	}

	expiry, e := parseConditions(cs[pos+1], o, l)
	if e != nil {
		return nil, e
	}

	r.expires = minTime(expiry, r.expires)

	pos += 2
	if cs[pos].Name() == xmlutil.Name(AssertionNamespace, xmlNameAdvice) {
		r.channels, e = readChannelContainer(cs[pos], true)
		if e != nil {
			return nil, e
		}

		pos++
	}

	if e := requireChannelAdvice(r.channels, o.ExpectedChannelBindings); e != nil {
		return nil, e
	}

	if pos >= len(cs) || cs[pos].Name() != xmlutil.Name(AssertionNamespace, xmlNameAuthnStatement) {
		return nil, ErrProfile
	}

	if e = parseAuthn(cs[pos], o, l, r); e != nil {
		return nil, e
	}

	pos++
	if pos < len(cs) {
		if pos+1 != len(cs) || cs[pos].Name() != xmlutil.Name(AssertionNamespace, xmlNameAttributeStatement) {
			return nil, ErrProfile
		}

		r.attributes, e = parseAttributes(cs[pos], l)
		if e != nil {
			return nil, e
		}
	}

	return r, nil
}

func parseSubject(s document.Element, o ResponseOptions, l Limits, r *VerifiedAssertion) error {
	if xmlutil.Attrs(s, nil, nil) != nil {
		return ErrProfile
	}

	cs, e := xmlutil.Children(s)
	if e != nil || len(cs) < minimumSubjectChildren || len(cs) > maximumSubjectChildren || cs[0].Name() != xmlutil.Name(AssertionNamespace, xmlNameNameID) {
		return ErrProfile
	}

	if e := parseSubjectNameID(cs[0], o, l, r); e != nil {
		return e
	}

	for _, conf := range cs[1:] {
		if conf.Name() != xmlutil.Name(AssertionNamespace, xmlNameSubjectConfirmation) || xmlutil.Attrs(conf, []string{nameMethod}, nil) != nil {
			return ErrProfile
		}
	}

	wantHoK := o.RequireHolderOfKey || o.Proof != nil || len(o.producedCertificate) != 0
	lastErr := ErrConditions

	for _, conf := range cs[1:] {
		candidate := *r
		if wantHoK && xmlutil.Attr(conf, nameMethod) == HolderOfKey {
			lastErr = parseHoKConfirmation(conf, o, l, &candidate)
		} else if !wantHoK && xmlutil.Attr(conf, nameMethod) == Bearer {
			candidate.confirmation = Bearer
			lastErr = parseBearerConfirmation(conf, o, l, &candidate)
		} else {
			continue
		}

		if lastErr == nil {
			*r = candidate
			return nil
		}
	}

	return lastErr
}

func parseSubjectNameID(id document.Element, o ResponseOptions, l Limits, r *VerifiedAssertion) error {
	if xmlutil.Attrs(id, nil, []string{nameFormat, nameNameQualifier, nameSPNameQualifier, nameSPProvidedID}) != nil || len(id.Children()) != 0 {
		return ErrProfile
	}

	value, err := xmlutil.SimpleText(id, l.MaxValueBytes)
	if err != nil || value == "" {
		return ErrProfile
	}

	r.nameID = value

	r.nameIDFormat = xmlutil.Attr(id, nameFormat)
	if r.nameIDFormat == "" {
		r.nameIDFormat = NameIDUnspecified
	}

	if !profile.URI(r.nameIDFormat) || r.nameIDFormat == NameIDEncrypted || len(o.AllowedNameIDFormats) > 0 && !allowed(r.nameIDFormat, o.AllowedNameIDFormats) {
		return ErrProfile
	}

	if q, ok := id.Attribute(document.Name{Local: nameNameQualifier}); ok && q != o.Issuer {
		return ErrProfile
	}

	if q, ok := id.Attribute(document.Name{Local: nameSPNameQualifier}); ok && q != o.Audience {
		return ErrProfile
	}

	alias := xmlutil.Attr(id, nameSPProvidedID)
	if len(alias) > l.MaxValueBytes {
		return ErrProfile
	}

	r.identifier = NameIdentifier{Value: r.nameID, Format: r.nameIDFormat, NameQualifier: xmlutil.Attr(id, nameNameQualifier), SPNameQualifier: xmlutil.Attr(id, nameSPNameQualifier), SPProvidedID: alias}
	if err := r.identifier.Validate(); err != nil {
		return err
	}

	return nil
}

func parseBearerConfirmation(c document.Element, o ResponseOptions, l Limits, r *VerifiedAssertion) error {
	if xmlutil.Attrs(c, []string{nameMethod}, nil) != nil || xmlutil.Attr(c, nameMethod) != Bearer {
		return ErrProfile
	}

	ds, e := xmlutil.Children(c)
	if e != nil || len(ds) != 1 || ds[0].Name() != xmlutil.Name(AssertionNamespace, xmlNameSubjectConfirmationData) {
		return ErrProfile
	}

	data := ds[0]
	// Web Browser SSO bearer confirmation MUST NOT contain NotBefore.
	if xmlutil.Attrs(data, []string{nameRecipient, nameInResponseTo, nameNotOnOrAfter}, []string{nameAddress}) != nil || !xmlutil.EmptyContent(data) {
		return ErrProfile
	}

	if xmlutil.Attr(data, nameRecipient) != o.Destination || xmlutil.Attr(data, nameInResponseTo) != o.ExpectedRequestID {
		return ErrCorrelation
	}

	end, e := profile.ParseTime(xmlutil.Attr(data, nameNotOnOrAfter))
	if e != nil || !o.At.Add(-l.ClockSkew).Before(end) || end.After(o.At.Add(l.MaxAssertionLifetime+l.ClockSkew)) {
		return ErrConditions
	}

	r.expires = end

	if addr, ok := data.Attribute(document.Name{Local: nameAddress}); ok {
		actual := net.ParseIP(addr)

		expected := net.ParseIP(o.ExpectedAddress)
		if actual == nil || expected == nil || !actual.Equal(expected) {
			return ErrConditions
		}
	}

	return nil
}

func parseConditions(c document.Element, o ResponseOptions, l Limits) (time.Time, error) {
	const (
		maximumWebConditionsChildren = 17
	)

	if xmlutil.Attrs(c, []string{nameNotBefore, nameNotOnOrAfter}, nil) != nil {
		return time.Time{}, ErrProfile
	}

	start, e := profile.ParseTime(xmlutil.Attr(c, nameNotBefore))
	if e != nil {
		return time.Time{}, ErrConditions
	}

	end, e := profile.ParseTime(xmlutil.Attr(c, nameNotOnOrAfter))
	if e != nil || timeWindow(start, end, o.At, l) != nil {
		return time.Time{}, ErrConditions
	}

	cs, e := xmlutil.Children(c)
	if e != nil || len(cs) < 1 || len(cs) > maximumWebConditionsChildren {
		return time.Time{}, ErrProfile
	}

	groups := 0
	once := false

	for _, child := range cs {
		if xmlutil.Attrs(child, nil, nil) != nil {
			return time.Time{}, ErrProfile
		}

		switch child.Name() {
		case xmlutil.Name(AssertionNamespace, xmlNameAudienceRestriction):
			if e := validateAudienceRestriction(child, o.Audience); e != nil {
				return time.Time{}, e
			}

			groups++
		case xmlutil.Name(AssertionNamespace, xmlNameOneTimeUse):
			if once || !xmlutil.EmptyContent(child) {
				return time.Time{}, ErrProfile
			}

			once = true
		default:
			return time.Time{}, ErrProfile
		}
	}

	if groups == 0 {
		return time.Time{}, ErrConditions
	}

	return end, nil
}

func validateAudienceRestriction(child document.Element, expected string) error {
	const (
		maximumAudienceAlternatives = 16
	)

	audiences, e := xmlutil.Children(child)
	if e != nil || len(audiences) < 1 || len(audiences) > maximumAudienceAlternatives {
		return ErrProfile
	}

	match := false

	for _, a := range audiences {
		if a.Name() != xmlutil.Name(AssertionNamespace, xmlNameAudience) {
			return ErrProfile
		}

		s, e := xmlutil.Simple(a, maximumURITextBytes)
		if e != nil || !profile.URI(s) {
			return ErrProfile
		}

		if s == expected {
			match = true
		}
	}

	if !match {
		return ErrConditions
	}

	return nil
}

func parseAuthn(a document.Element, o ResponseOptions, l Limits, r *VerifiedAssertion) error {
	const (
		maximumAuthnSessionIndexBytes  = 1024
		maximumWebAuthnContextChildren = 9
	)

	if xmlutil.Attrs(a, []string{xmlNameAuthnInstant}, []string{xmlNameSessionIndex, nameSessionNotOnOrAfter}) != nil {
		return ErrProfile
	}

	t, e := profile.ParseTime(xmlutil.Attr(a, xmlNameAuthnInstant))
	if e != nil || t.After(o.At.Add(l.ClockSkew)) || t.After(r.instant.Add(l.ClockSkew)) {
		return ErrConditions
	}

	if o.ForceAuthn && t.Before(o.RequestIssueInstant.Add(-l.ClockSkew)) {
		return ErrConditions
	}

	r.authnInstant = t

	r.sessionIndex = xmlutil.Attr(a, xmlNameSessionIndex)
	if len(r.sessionIndex) > maximumAuthnSessionIndexBytes {
		return ErrProfile
	}

	if s, ok := a.Attribute(document.Name{Local: nameSessionNotOnOrAfter}); ok {
		end, e := profile.ParseTime(s)
		if e != nil || !t.Before(end) || !o.At.Add(-l.ClockSkew).Before(end) {
			return ErrConditions
		}

		r.sessionExpires = end
		r.expires = minTime(r.expires, end)
	}

	cs, e := xmlutil.Children(a)
	if e != nil || len(cs) != 1 || cs[0].Name() != xmlutil.Name(AssertionNamespace, xmlNameAuthnContext) || xmlutil.Attrs(cs[0], nil, nil) != nil {
		return ErrProfile
	}

	ac, e := xmlutil.Children(cs[0])
	if e != nil || len(ac) < 1 || len(ac) > maximumWebAuthnContextChildren || ac[0].Name() != xmlutil.Name(AssertionNamespace, xmlNameAuthnContextClassRef) {
		return ErrProfile
	}

	class, e := xmlutil.Simple(ac[0], maximumURITextBytes)
	if e != nil || !profile.URI(class) || len(o.ExpectedAuthnContexts) > 0 && !allowed(class, o.ExpectedAuthnContexts) {
		return ErrConditions
	}

	r.contextClass = class

	for _, x := range ac[1:] {
		if x.Name() != xmlutil.Name(AssertionNamespace, xmlNameAuthenticatingAuthority) {
			return ErrProfile
		}

		s, e := xmlutil.Simple(x, maximumURITextBytes)
		if e != nil || !profile.URI(s) {
			return ErrProfile
		}
	}

	return nil
}

func parseAttributes(a document.Element, l Limits) ([]Attribute, error) {
	if xmlutil.Attrs(a, nil, nil) != nil {
		return nil, ErrProfile
	}

	cs, e := xmlutil.Children(a)
	if e != nil || len(cs) < 1 || len(cs) > l.MaxAttributes {
		return nil, ErrProfile
	}

	seen := map[[2]string]struct{}{}

	out := make([]Attribute, 0, len(cs))
	for _, c := range cs {
		v, e := parseAttribute(c, l, seen)
		if e != nil {
			return nil, e
		}

		out = append(out, v)
	}

	return out, nil
}

func parseAttribute(c document.Element, l Limits, seen map[[2]string]struct{}) (Attribute, error) {
	if c.Name() != xmlutil.Name(AssertionNamespace, xmlNameAttribute) || xmlutil.Attrs(c, []string{nameAttributeName}, []string{xmlNameNameFormat, xmlNameFriendlyName}) != nil {
		return Attribute{}, ErrProfile
	}

	name := xmlutil.Attr(c, nameAttributeName)

	format := xmlutil.Attr(c, xmlNameNameFormat)
	if format == "" {
		format = AttributeUnspecified
	}

	friendly := xmlutil.Attr(c, xmlNameFriendlyName)
	if _, exists := seen[[2]string{name, format}]; len(name) == 0 || len(name) > maximumAttributeNameBytes || !profile.URI(format) || len(friendly) > maximumFriendlyNameBytes || exists {
		return Attribute{}, ErrProfile
	}

	seen[[2]string{name, format}] = struct{}{}

	values, e := xmlutil.Children(c)
	if e != nil || len(values) < 1 || len(values) > l.MaxValuesPerAttribute {
		return Attribute{}, ErrProfile
	}

	v := Attribute{Name: name, NameFormat: format, FriendlyName: friendly}

	for _, x := range values {
		s, e := parseAttributeValue(x, l)
		if e != nil {
			return Attribute{}, e
		}

		v.Values = append(v.Values, s)
	}

	return v, nil
}

func parseAttributeValue(x document.Element, l Limits) (string, error) {
	const (
		maximumAttributeTypeNameBytes = 256
	)

	if x.Name() != xmlutil.Name(AssertionNamespace, xmlNameAttributeValue) || len(x.Children()) != 0 {
		return "", ErrProfile
	}

	for _, attr := range x.Attributes() {
		if attr.Name != (document.Name{Space: lexicon.NamespaceXSI, Local: lexicon.AttrType}) || len(attr.Value) > maximumAttributeTypeNameBytes {
			return "", ErrProfile
		}
	}

	s, err := xmlutil.SimpleText(x, l.MaxValueBytes)
	if err != nil {
		return "", ErrProfile
	}

	return s, nil
}

func copyAttributes(a []Attribute) []Attribute {
	out := make([]Attribute, len(a))
	for i, x := range a {
		out[i] = x
		out[i].Values = append([]string(nil), x.Values...)
	}

	return out
}
