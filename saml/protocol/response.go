package protocol

import (
	"context"
	"crypto"
	"net"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/xmldsig"
)

// ResponseOptions is a relying party policy for a SOLICITED POST response.
// ExpectedRequestID and trusted ACS/audience/issuer are never read from the
// untrusted response as a substitute for stored request state.
type ResponseOptions struct {
	Issuer, Audience, Destination, ExpectedRequestID string
	// At is the explicit trusted verification time.
	At time.Time
	// RequestIssueInstant is required with ForceAuthn and binds freshness to the original request.
	RequestIssueInstant time.Time
	Limits              Limits
	Policy              xmldsig.Policy
	// AllowUnsignedResponse permits an unsigned Response envelope. An Assertion
	// signature remains required; unsigned envelope fields are not authenticated.
	AllowUnsignedResponse bool
	// AllowedNameIDFormats restricts exact format URIs; empty disables this membership check.
	AllowedNameIDFormats []string
	// ExpectedAuthnContexts restricts exact context URIs; empty disables this membership check.
	ExpectedAuthnContexts []string
	// ForceAuthn requires authentication no earlier than RequestIssueInstant,
	// subject to the configured clock skew.
	ForceAuthn bool
	// ExpectedAddress is the trusted client address, checked when a confirmation carries Address.
	ExpectedAddress string
}

// Attribute is a SAML attribute and its string values.
type Attribute struct {
	Name, NameFormat, FriendlyName string
	Values                         []string
}

// VerifiedAssertion contains only values extracted from the verified Assertion
// snapshot. It does not itself consume replay state or create an application
// session. saml/sp performs the atomic request/assertion/response consumption.
type VerifiedAssertion struct {
	assertion                                                       document.Element
	responseID, assertionID, issuer, audience, recipient, requestID string
	nameID, nameIDFormat, sessionIndex, contextClass                string
	instant, authnInstant, expires, sessionExpires                  time.Time
	attributes                                                      []Attribute
	responseSigned                                                  bool
}

// VerifyResponse authenticates and validates a solicited response and its signed assertion
// under explicit expectations.
func VerifyResponse(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o ResponseOptions) (*VerifiedAssertion, error) {
	l, e := normalize(o.Limits)
	if e != nil {
		return nil, e
	}

	if e := validateResponseOptions(ctx, d, o); e != nil {
		return nil, e
	}

	if e = ctx.Err(); e != nil {
		return nil, e
	}

	root := d.Root()
	if xmlutil.Attrs(root, []string{"ID", nameVersion, nameIssueInstant, nameDestination, nameInResponseTo}, nil) != nil {
		return nil, ErrProfile
	}

	responseID, _, e := header(root, "Response", o.At, l)
	if e != nil {
		return nil, e
	}

	if xmlutil.Attr(root, nameDestination) != o.Destination || xmlutil.Attr(root, nameInResponseTo) != o.ExpectedRequestID {
		return nil, ErrCorrelation
	}

	children, e := xmlutil.Children(root)
	if e != nil || len(children) < 2 || issuer(children[0], o.Issuer) != nil {
		return nil, ErrProfile
	}

	pos := 1
	responseSigned := false

	if children[pos].Name() == xmlutil.Name(xmlutil.DS, "Signature") {
		if e = targetSignature(ctx, d, root, keys, o.Policy); e != nil {
			return nil, e
		}

		responseSigned = true
		pos++
	} else if !o.AllowUnsignedResponse {
		return nil, ErrSignature
	}

	if pos >= len(children) || children[pos].Name() != xmlutil.Name(ProtocolNamespace, "Status") {
		return nil, ErrProfile
	}

	status := children[pos]
	pos++

	code, e := parseResponseStatus(status)
	if e != nil {
		return nil, e
	}

	if code != Success {
		if !responseSigned || pos != len(children) || signingCount(d, 1) != nil {
			return nil, ErrProfile
		}

		return nil, &StatusError{Code: code}
	}

	if pos+1 != len(children) || children[pos].Name() != xmlutil.Name(AssertionNamespace, "Assertion") {
		return nil, ErrProfile
	}

	assertion := children[pos]

	expectedCount := 1
	if responseSigned {
		expectedCount = 2
	}

	if signingCount(d, expectedCount) != nil {
		return nil, ErrProfile
	}

	if e = targetSignature(ctx, d, assertion, keys, o.Policy); e != nil {
		return nil, e
	}

	result, e := parseAssertion(assertion, o, l)
	if e != nil {
		return nil, e
	}

	result.responseID = responseID
	result.responseSigned = responseSigned

	if e = ctx.Err(); e != nil {
		return nil, e
	}

	return result, nil
}

func validateResponseOptions(ctx context.Context, d *document.Document, o ResponseOptions) error {
	if ctx == nil || d == nil || o.At.IsZero() || !xmlutil.URI(o.Issuer) || !xmlutil.URI(o.Audience) || !xmlutil.Endpoint(o.Destination, true) || !xmlutil.ID(o.ExpectedRequestID) || len(o.AllowedNameIDFormats) > 16 || len(o.ExpectedAuthnContexts) > 16 || o.ForceAuthn && o.RequestIssueInstant.IsZero() {
		return ErrProfile
	}

	return nil
}

func parseResponseStatus(status document.Element) (string, error) {
	if xmlutil.Attrs(status, nil, nil) != nil {
		return "", ErrProfile
	}

	sc, e := xmlutil.Children(status)
	if e != nil || len(sc) != 1 || sc[0].Name() != xmlutil.Name(ProtocolNamespace, "StatusCode") || xmlutil.Attrs(sc[0], []string{"Value"}, nil) != nil || !xmlutil.EmptyContent(sc[0]) {
		return "", ErrProfile
	}

	code := xmlutil.Attr(sc[0], "Value")
	if !xmlutil.URI(code) {
		return "", ErrProfile
	}

	return code, nil
}

func parseAssertion(a document.Element, o ResponseOptions, l Limits) (*VerifiedAssertion, error) {
	if xmlutil.Attrs(a, []string{"ID", nameVersion, nameIssueInstant}, nil) != nil || xmlutil.Attr(a, nameVersion) != version20 || !xmlutil.ID(xmlutil.Attr(a, "ID")) {
		return nil, ErrProfile
	}

	instant, e := xmlutil.ParseTime(xmlutil.Attr(a, nameIssueInstant))
	if e != nil || instant.After(o.At.Add(l.ClockSkew)) || instant.Before(o.At.Add(-l.MaxMessageAge-l.ClockSkew)) {
		return nil, ErrConditions
	}

	cs, e := xmlutil.Children(a)
	if e != nil || len(cs) < 5 || len(cs) > 6 || issuer(cs[0], o.Issuer) != nil || cs[1].Name() != xmlutil.Name(xmlutil.DS, "Signature") || cs[2].Name() != xmlutil.Name(AssertionNamespace, "Subject") || cs[3].Name() != xmlutil.Name(AssertionNamespace, "Conditions") || cs[4].Name() != xmlutil.Name(AssertionNamespace, "AuthnStatement") {
		return nil, ErrProfile
	}

	r := &VerifiedAssertion{assertion: a, assertionID: xmlutil.Attr(a, "ID"), issuer: o.Issuer, audience: o.Audience, recipient: o.Destination, requestID: o.ExpectedRequestID, instant: instant}
	if e = parseSubject(cs[2], o, l, r); e != nil {
		return nil, e
	}

	expiry, e := parseConditions(cs[3], o, l)
	if e != nil {
		return nil, e
	}

	r.expires = minTime(expiry, r.expires)
	if e = parseAuthn(cs[4], o, l, r); e != nil {
		return nil, e
	}

	if len(cs) == 6 {
		if cs[5].Name() != xmlutil.Name(AssertionNamespace, "AttributeStatement") {
			return nil, ErrProfile
		}

		r.attributes, e = parseAttributes(cs[5], l)
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
	if e != nil || len(cs) != 2 || cs[0].Name() != xmlutil.Name(AssertionNamespace, "NameID") || cs[1].Name() != xmlutil.Name(AssertionNamespace, "SubjectConfirmation") {
		return ErrProfile
	}

	if e := parseSubjectNameID(cs[0], o, l, r); e != nil {
		return e
	}

	return parseBearerConfirmation(cs[1], o, l, r)
}

func parseSubjectNameID(id document.Element, o ResponseOptions, l Limits, r *VerifiedAssertion) error {
	if xmlutil.Attrs(id, nil, []string{"Format", "NameQualifier", nameSPNameQualifier}) != nil || len(id.Children()) != 0 {
		return ErrProfile
	}

	value, err := xmlutil.SimpleText(id, l.MaxValueBytes)
	if err != nil || value == "" {
		return ErrProfile
	}

	r.nameID = value

	r.nameIDFormat = xmlutil.Attr(id, "Format")
	if r.nameIDFormat == "" {
		r.nameIDFormat = NameIDUnspecified
	}

	if !xmlutil.URI(r.nameIDFormat) || len(o.AllowedNameIDFormats) > 0 && !allowed(r.nameIDFormat, o.AllowedNameIDFormats) {
		return ErrProfile
	}

	if q, ok := id.Attribute(document.Name{Local: "NameQualifier"}); ok && q != o.Issuer {
		return ErrProfile
	}

	if q, ok := id.Attribute(document.Name{Local: nameSPNameQualifier}); ok && q != o.Audience {
		return ErrProfile
	}

	return nil
}

func parseBearerConfirmation(c document.Element, o ResponseOptions, l Limits, r *VerifiedAssertion) error {
	if xmlutil.Attrs(c, []string{"Method"}, nil) != nil || xmlutil.Attr(c, "Method") != Bearer {
		return ErrProfile
	}

	ds, e := xmlutil.Children(c)
	if e != nil || len(ds) != 1 || ds[0].Name() != xmlutil.Name(AssertionNamespace, "SubjectConfirmationData") {
		return ErrProfile
	}

	data := ds[0]
	// Web Browser SSO bearer confirmation MUST NOT contain NotBefore.
	if xmlutil.Attrs(data, []string{"Recipient", nameInResponseTo, "NotOnOrAfter"}, []string{"Address"}) != nil || !xmlutil.EmptyContent(data) {
		return ErrProfile
	}

	if xmlutil.Attr(data, "Recipient") != o.Destination || xmlutil.Attr(data, nameInResponseTo) != o.ExpectedRequestID {
		return ErrCorrelation
	}

	end, e := xmlutil.ParseTime(xmlutil.Attr(data, "NotOnOrAfter"))
	if e != nil || !o.At.Add(-l.ClockSkew).Before(end) || end.After(o.At.Add(l.MaxAssertionLifetime+l.ClockSkew)) {
		return ErrConditions
	}

	r.expires = end

	if addr, ok := data.Attribute(document.Name{Local: "Address"}); ok {
		actual := net.ParseIP(addr)

		expected := net.ParseIP(o.ExpectedAddress)
		if actual == nil || expected == nil || !actual.Equal(expected) {
			return ErrConditions
		}
	}

	return nil
}

func parseConditions(c document.Element, o ResponseOptions, l Limits) (time.Time, error) {
	if xmlutil.Attrs(c, []string{"NotBefore", "NotOnOrAfter"}, nil) != nil {
		return time.Time{}, ErrProfile
	}

	start, e := xmlutil.ParseTime(xmlutil.Attr(c, "NotBefore"))
	if e != nil {
		return time.Time{}, ErrConditions
	}

	end, e := xmlutil.ParseTime(xmlutil.Attr(c, "NotOnOrAfter"))
	if e != nil || timeWindow(start, end, o.At, l) != nil {
		return time.Time{}, ErrConditions
	}

	cs, e := xmlutil.Children(c)
	if e != nil || len(cs) < 1 || len(cs) > 17 {
		return time.Time{}, ErrProfile
	}

	groups := 0
	once := false

	for _, child := range cs {
		if xmlutil.Attrs(child, nil, nil) != nil {
			return time.Time{}, ErrProfile
		}

		switch child.Name() {
		case xmlutil.Name(AssertionNamespace, "AudienceRestriction"):
			if e := validateAudienceRestriction(child, o.Audience); e != nil {
				return time.Time{}, e
			}

			groups++
		case xmlutil.Name(AssertionNamespace, "OneTimeUse"):
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
	audiences, e := xmlutil.Children(child)
	if e != nil || len(audiences) < 1 || len(audiences) > 16 {
		return ErrProfile
	}

	match := false

	for _, a := range audiences {
		if a.Name() != xmlutil.Name(AssertionNamespace, "Audience") {
			return ErrProfile
		}

		s, e := xmlutil.Simple(a, 2048)
		if e != nil || !xmlutil.URI(s) {
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
	if xmlutil.Attrs(a, []string{"AuthnInstant"}, []string{"SessionIndex", "SessionNotOnOrAfter"}) != nil {
		return ErrProfile
	}

	t, e := xmlutil.ParseTime(xmlutil.Attr(a, "AuthnInstant"))
	if e != nil || t.After(o.At.Add(l.ClockSkew)) || t.After(r.instant.Add(l.ClockSkew)) {
		return ErrConditions
	}

	if o.ForceAuthn && t.Before(o.RequestIssueInstant.Add(-l.ClockSkew)) {
		return ErrConditions
	}

	r.authnInstant = t

	r.sessionIndex = xmlutil.Attr(a, "SessionIndex")
	if len(r.sessionIndex) > 1024 {
		return ErrProfile
	}

	if s, ok := a.Attribute(document.Name{Local: "SessionNotOnOrAfter"}); ok {
		end, e := xmlutil.ParseTime(s)
		if e != nil || !t.Before(end) || !o.At.Add(-l.ClockSkew).Before(end) {
			return ErrConditions
		}

		r.sessionExpires = end
		r.expires = minTime(r.expires, end)
	}

	cs, e := xmlutil.Children(a)
	if e != nil || len(cs) != 1 || cs[0].Name() != xmlutil.Name(AssertionNamespace, "AuthnContext") || xmlutil.Attrs(cs[0], nil, nil) != nil {
		return ErrProfile
	}

	ac, e := xmlutil.Children(cs[0])
	if e != nil || len(ac) < 1 || len(ac) > 9 || ac[0].Name() != xmlutil.Name(AssertionNamespace, "AuthnContextClassRef") {
		return ErrProfile
	}

	class, e := xmlutil.Simple(ac[0], 2048)
	if e != nil || !xmlutil.URI(class) || len(o.ExpectedAuthnContexts) > 0 && !allowed(class, o.ExpectedAuthnContexts) {
		return ErrConditions
	}

	r.contextClass = class

	for _, x := range ac[1:] {
		if x.Name() != xmlutil.Name(AssertionNamespace, "AuthenticatingAuthority") {
			return ErrProfile
		}

		s, e := xmlutil.Simple(x, 2048)
		if e != nil || !xmlutil.URI(s) {
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

	seen := map[[2]string]bool{}

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

func parseAttribute(c document.Element, l Limits, seen map[[2]string]bool) (Attribute, error) {
	if c.Name() != xmlutil.Name(AssertionNamespace, "Attribute") || xmlutil.Attrs(c, []string{"Name"}, []string{"NameFormat", "FriendlyName"}) != nil {
		return Attribute{}, ErrProfile
	}

	name := xmlutil.Attr(c, "Name")

	format := xmlutil.Attr(c, "NameFormat")
	if format == "" {
		format = AttributeUnspecified
	}

	friendly := xmlutil.Attr(c, "FriendlyName")
	if len(name) == 0 || len(name) > 1024 || !xmlutil.URI(format) || len(friendly) > 1024 || seen[[2]string{name, format}] {
		return Attribute{}, ErrProfile
	}

	seen[[2]string{name, format}] = true

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
	if x.Name() != xmlutil.Name(AssertionNamespace, "AttributeValue") || len(x.Children()) != 0 {
		return "", ErrProfile
	}

	for _, attr := range x.Attributes() {
		if attr.Name != (document.Name{Space: "http://www.w3.org/2001/XMLSchema-instance", Local: "type"}) || len(attr.Value) > 256 {
			return "", ErrProfile
		}
	}

	s, err := xmlutil.SimpleText(x, l.MaxValueBytes)
	if err != nil {
		return "", ErrProfile
	}

	return s, nil
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

func copyAttributes(a []Attribute) []Attribute {
	out := make([]Attribute, len(a))
	for i, x := range a {
		out[i] = x
		out[i].Values = append([]string(nil), x.Values...)
	}

	return out
}

// ResponseAuthenticated returns whether the response envelope itself was authenticated.
func (r *VerifiedAssertion) ResponseAuthenticated() bool { return r != nil && r.responseSigned }

// StatusError denotes an authenticated non-success Response, never a login.
// Detailed remote StatusMessage/StatusDetail are not surfaced as trusted text.
type StatusError struct{ Code string }

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
