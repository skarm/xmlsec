package protocol

import (
	"context"
	"crypto"
	"slices"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/xmldsig"
)

// Profile bound shared by these producer/parser paths; byte/count/time units follow the name, and default values apply only to zero options.
const (
	maximumAuthorityStatements = 128
)

// MaxQueryAssertions bounds a response to the shared 64-signature budget.
const MaxQueryAssertions = xmlsig.MaxMessageSignatures - 1

// AuthorityAssertion describes an assertion independent of WebSSO. Statements
// are complete AuthnStatement, AttributeStatement or AuthzDecisionStatement XML
// documents. This retains complex attribute values, authentication declarations
// and authorization evidence without converting them to lossy string claims.
type AuthorityAssertion struct {
	// ID is the assertion's XML identifier.
	ID string
	// Issuer is the assertion issuer's entity ID.
	Issuer string
	// Limits bounds XML attribute values, including their markup and type annotations.
	Limits Limits
	// IssueInstant is the assertion creation time.
	IssueInstant time.Time
	// Subject is an optional complete saml:Subject document.
	Subject *document.Document
	// Conditions is an optional complete saml:Conditions document.
	Conditions *document.Document
	// Advice is optional saml:Advice XML; its contents grant no trust by
	// themselves.
	Advice *document.Document
	// Statements contains complete supported SAML statement documents.
	Statements []*document.Document
	// Encryption optionally encrypts selected assertion contents before signing and
	// the whole assertion afterward.
	Encryption *EncryptionOptions
}

// AssertionOptions fixes the assertion issuer independently of the response
// issuer (Profiles 6.4.2). Unknown conditions fail closed. Audience restrictions
// are ANDed; audience values within each restriction are ORed (Errata E46).
type AssertionOptions struct {
	// Issuer is the expected assertion issuer, independently of the response
	// issuer.
	Issuer string
	// Audience is the local relying party checked against audience restrictions.
	Audience string
	// At is the explicit, nonzero assertion verification time.
	At time.Time
	// Limits bounds assertion structure, values and validity windows.
	Limits Limits
	// Policy restricts assertion signature and reference algorithms.
	Policy xmldsig.Policy
	// Decryption supplies keys and policy for encrypted assertion data. Nil
	// supplies no decryption keys.
	Decryption *DecryptionOptions
}

// QueryMatchOptions provides application-defined semantics explicitly. Context
// must implement minimum/maximum/better according to the authority's ordering,
// including maximum's strongest-available rule. Exact URI comparison is built in.
// Confirm must establish Core 3.3.4 strong confirmation matching, not merely
// equality of method names. Missing callbacks reject requests needing them.
// EqualValue optionally implements an attribute profile's value equality rules;
// otherwise the identical canonical XML representation is required.
type QueryMatchOptions struct {
	// Context compares a statement's authentication context with the requested
	// context when application-defined ordering is needed.
	Context func(context.Context, document.Element, RequestedContext) (bool, error)
	// Confirm checks strong matching between requested and returned
	// SubjectConfirmation elements.
	Confirm func(context.Context, document.Element, document.Element) (bool, error)
	// EqualValue optionally compares requested and returned attribute values. Nil
	// requires identical canonical XML.
	EqualValue func(context.Context, document.Element, document.Element) (bool, error)
}

// VerifiedAuthorityAssertion contains authenticated XML, not an application login
// or authorization grant. OneTimeUse requires atomic consumption by the relying
// application; saml/authority's client performs it before returning the result.
type VerifiedAuthorityAssertion struct {
	document   *document.Document
	signed     *document.Document
	id, issuer string
	subject    document.Element
	statements []document.Element
	oneTime    bool
	expires    time.Time
}

// Document returns the immutable authenticated, decrypted assertion.
func (a *VerifiedAuthorityAssertion) Document() *document.Document { return a.document }

// ID returns the assertion ID.
func (a *VerifiedAuthorityAssertion) ID() string { return a.id }

// Issuer returns the separately authenticated assertion issuer.
func (a *VerifiedAuthorityAssertion) Issuer() string { return a.issuer }

// Subject returns the authenticated subject, which can be absent for an ID request.
func (a *VerifiedAuthorityAssertion) Subject() document.Element { return a.subject }

// Statements returns an owned list of immutable authenticated statements.
func (a *VerifiedAuthorityAssertion) Statements() []document.Element {
	return slices.Clone(a.statements)
}

// OneTimeUse reports the assertion's one-time-use restriction.
func (a *VerifiedAuthorityAssertion) OneTimeUse() bool { return a.oneTime }

// NotOnOrAfter returns the assertion expiry, or zero when not supplied.
func (a *VerifiedAuthorityAssertion) NotOnOrAfter() time.Time { return a.expires }

// EncryptAuthorityAssertion encrypts an authenticated assertion for a recipient.
// Only whole-assertion encryption can be applied after its signature; encrypting
// inner identifiers/attributes must be done before signing the assertion.
func EncryptAuthorityAssertion(ctx context.Context, a *VerifiedAuthorityAssertion, o *EncryptionOptions) (*document.Document, error) {
	if a == nil || o == nil || o.Targets != EncryptAssertion {
		return nil, ErrEncryption
	}

	p, err := CloneEncryption(o)
	if err != nil || p.Recipient == nil {
		return nil, ErrEncryption
	}

	return encryptSAML(ctx, a.signed, a.signed.Root(), xmlNameEncryptedAssertion, p)
}

// SignAuthorityAssertion builds and signs an assertion in SOAP-compatible
// namespace context. Application code supplies statements about established
// facts or decisions; an AuthnQuery must never trigger a new authentication.
func SignAuthorityAssertion(ctx context.Context, s AuthorityAssertion, key SigningKey) (*document.Document, error) {
	if ctx == nil {
		return nil, ErrProfile
	}

	n, err := authorityAssertionNode(s)
	if err != nil {
		return nil, err
	}

	d, err := xmlutil.Document(ctx, n)
	if err != nil {
		return nil, err
	}

	l, err := normalize(s.Limits)
	if err != nil {
		return nil, err
	}

	if err = authorityAttributeBudget(ctx, d, l); err != nil {
		return nil, err
	}

	if s.Encryption != nil {
		d, err = encryptAuthorityContents(ctx, d, s.Encryption)
		if err != nil {
			return nil, err
		}
	}

	key = namespaceSigningKey(d.Root(), key)

	k, err := signing(key)
	if err != nil {
		return nil, err
	}

	d, err = xmlsig.Sign(ctx, d, d.Root(), k, true)
	if err != nil {
		return nil, err
	}

	if s.Encryption != nil && s.Encryption.Targets&EncryptAssertion != 0 {
		return encryptSAML(ctx, d, d.Root(), xmlNameEncryptedAssertion, s.Encryption)
	}

	return d, nil
}

// VerifyAuthorityAssertion verifies a standalone assertion, including the
// unencrypted or encrypted representation returned by the URI binding.
func VerifyAuthorityAssertion(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o AssertionOptions) (*VerifiedAuthorityAssertion, error) {
	if ctx == nil || d == nil || o.At.IsZero() || !profile.URI(o.Issuer) {
		return nil, ErrProfile
	}

	l, err := normalize(o.Limits)
	if err != nil {
		return nil, err
	}

	state, err := newDecryptionState(o.Decryption)
	if err != nil {
		return nil, err
	}

	return verifyAuthorityAssertion(ctx, d, keys, o, l, state)
}

func verifyAuthorityAssertion(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o AssertionOptions, l Limits, state *decryptionState) (*VerifiedAuthorityAssertion, error) {
	if ctx == nil || d == nil || o.At.IsZero() || !profile.URI(o.Issuer) {
		return nil, ErrProfile
	}

	var err error
	if d.Root().Name() == xmlutil.Name(AssertionNamespace, xmlNameEncryptedAssertion) {
		d, err = state.decryptSAML(ctx, d, d.Root(), nameAssertion, false)
		if err != nil {
			return nil, err
		}
	}

	if d.Root().Name() != xmlutil.Name(AssertionNamespace, nameAssertion) {
		return nil, ErrProfile
	}

	if err := targetSignature(ctx, d, d.Root(), keys, o.Policy); err != nil {
		return nil, err
	}

	return parseAuthorityAssertion(ctx, d, o, l, state)
}

func parseAuthorityAssertion(ctx context.Context, d *document.Document, o AssertionOptions, l Limits, state *decryptionState) (*VerifiedAuthorityAssertion, error) {
	signed := d

	r := d.Root()
	if xmlutil.Attrs(r, []string{lexicon.SAMLAttrID, nameVersion, nameIssueInstant}, nil) != nil || !profile.ID(xmlutil.Attr(r, lexicon.SAMLAttrID)) || xmlutil.Attr(r, nameVersion) != version20 {
		return nil, ErrProfile
	}

	t, err := profile.ParseTime(xmlutil.Attr(r, nameIssueInstant))
	if err != nil || t.After(o.At.Add(l.ClockSkew)) {
		return nil, ErrConditions
	}

	cs, err := xmlutil.Children(r)
	if err != nil || len(cs) < signedMessagePrefixChildren || issuer(cs[0], o.Issuer) != nil || cs[1].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature) {
		return nil, ErrProfile
	}

	d, err = decryptAuthorityContents(ctx, d, state)
	if err != nil {
		return nil, err
	}

	r = d.Root()

	cs, err = xmlutil.Children(r)
	if err != nil {
		return nil, err
	}

	a := &VerifiedAuthorityAssertion{document: d, signed: signed, id: xmlutil.Attr(r, lexicon.SAMLAttrID), issuer: o.Issuer}

	i := signedMessagePrefixChildren
	if i < len(cs) && cs[i].Name() == xmlutil.Name(AssertionNamespace, xmlNameSubject) {
		sub, err := tree.ScopeDocument(d, cs[i])
		if err != nil {
			return nil, err
		}

		if err = validateQuerySubject(sub); err != nil {
			return nil, err
		}

		a.subject = cs[i]
		i++
	}

	if i < len(cs) && cs[i].Name() == xmlutil.Name(AssertionNamespace, xmlNameConditions) {
		if err := authorityConditions(cs[i], o, l, a); err != nil {
			return nil, err
		}

		i++
	}

	if i < len(cs) && cs[i].Name() == xmlutil.Name(AssertionNamespace, xmlNameAdvice) {
		if err := validateAdvice(cs[i]); err != nil {
			return nil, err
		}

		i++
	}

	if len(cs)-i > maximumAuthorityStatements {
		return nil, ErrProfile
	}

	for _, st := range cs[i:] {
		if err := validateAuthorityStatement(st); err != nil {
			return nil, err
		}

		a.statements = append(a.statements, st)
	}

	if len(a.statements) > 0 && !a.subject.Valid() {
		return nil, ErrProfile
	}

	if err := authorityAttributeBudget(ctx, d, l); err != nil {
		return nil, err
	}

	return a, ctx.Err()
}

func authorityConditions(e document.Element, o AssertionOptions, l Limits, a *VerifiedAuthorityAssertion) error {
	const (
		maximumAuthorityConditions = 128
		xmlNameProxyRestriction    = "ProxyRestriction"
	)

	if err := authorityTimeWindow(e, o, l, a); err != nil {
		return err
	}

	cs, err := xmlutil.Children(e)
	if err != nil || len(cs) > maximumAuthorityConditions {
		return ErrConditions
	}

	proxy := false

	for _, c := range cs {
		if c.Name().Space != AssertionNamespace {
			return ErrConditions
		}

		switch c.Name().Local {
		case xmlNameAudienceRestriction:
			if err := authorityAudience(c, o.Audience); err != nil {
				return err
			}
		case xmlNameOneTimeUse:
			if a.oneTime || xmlutil.Attrs(c, nil, nil) != nil || !xmlutil.EmptyContent(c) {
				return ErrConditions
			}

			a.oneTime = true
		case xmlNameProxyRestriction:
			if proxy {
				return ErrConditions
			}

			proxy = true

			if err := authorityProxy(c); err != nil {
				return err
			}
		default:
			return ErrConditions
		}
	}

	return nil
}

// QueryResponse is a correlated result with zero or more signed assertions.
// Assertion issuers may differ from the response issuer. Empty success is a
// valid no-match result; failures carry no assertions.
type QueryResponse struct {
	MessageHeader
	// InResponseTo identifies the query or assertion-ID request being answered.
	InResponseTo string
	// Status is the signed query outcome; a successful response may contain no
	// assertions.
	Status Status
	// Assertions contains already signed assertions or encrypted assertions.
	// Failure responses must leave it empty.
	Assertions []*document.Document
}

// VerifiedQueryResponse retains authenticated protocol data, including an empty
// successful result. It is not a WebSSO response and must not create a login.
type VerifiedQueryResponse struct {
	header     MessageHeader
	status     Status
	assertions []*VerifiedAuthorityAssertion
}

// Header returns the authenticated response header.
func (r *VerifiedQueryResponse) Header() MessageHeader { return r.header }

// Status returns the authenticated status.
func (r *VerifiedQueryResponse) Status() Status {
	s := r.status
	s.Subcodes = slices.Clone(s.Subcodes)

	return s
}

// Assertions returns an owned list of verified assertions.
func (r *VerifiedQueryResponse) Assertions() []*VerifiedAuthorityAssertion {
	return slices.Clone(r.assertions)
}

// QueryResponseOptions combines envelope and independently trusted assertion
// policies. AssertionTrust must authorize each assertion issuer; omission trusts
// only the response issuer with the supplied response keys. Matcher supplies
// context/confirmation semantics required by the particular query.
type QueryResponseOptions struct {
	ExchangeOptions
	// Audience is the local relying party required by assertion audience
	// restrictions.
	Audience string
	// AssertionTrust optionally resolves trusted keys for each assertion issuer
	// independently of the response signer.
	// Nil requires the response issuer and uses the response verification keys.
	AssertionTrust func(context.Context, string) ([]crypto.PublicKey, error)
	// Matcher supplies application semantics for matching assertions to the
	// original query.
	Matcher QueryMatchOptions
}

// SignQueryResponse signs the whole response. Each supplied assertion must
// already be signed in SOAP-compatible context, or be an encrypted assertion.
func SignQueryResponse(ctx context.Context, s QueryResponse, key SigningKey) (*document.Document, error) {
	if !profile.ID(s.InResponseTo) || len(s.Assertions) > MaxQueryAssertions || s.Status.Code != "" && s.Status.Code != Success && len(s.Assertions) > 0 {
		return nil, ErrProfile
	}

	n, err := soapExchangeRoot(s.MessageHeader, lexicon.SAMLElementResponse)
	if err != nil {
		return nil, err
	}

	n.NS = append(n.NS, tree.Namespace{Prefix: prefixSOAP, URI: binding.SOAPNamespace})
	xmlutil.Set(n, nameInResponseTo, s.InResponseTo)

	st, err := statusNode(s.Status)
	if err != nil {
		return nil, err
	}

	xmlutil.Add(n, st)

	seen := map[string]bool{s.ID: true}
	for _, a := range s.Assertions {
		if a == nil || a.Root().Name().Space != AssertionNamespace || !slices.Contains([]string{nameAssertion, xmlNameEncryptedAssertion}, a.Root().Name().Local) {
			return nil, ErrProfile
		}

		if a.Root().Name().Local == nameAssertion {
			id := xmlutil.Attr(a.Root(), lexicon.SAMLAttrID)
			if !profile.ID(id) || seen[id] {
				return nil, ErrProfile
			}

			seen[id] = true
		}

		appendDocument(n, a)
	}

	return signRichExchange(ctx, n, key, nil)
}

// VerifyQueryResponse checks signatures, issuer trust, correlation, conditions
// and Core query constraints before returning any assertions.
func VerifyQueryResponse(ctx context.Context, d *document.Document, keys []crypto.PublicKey, q Query, o QueryResponseOptions) (*VerifiedQueryResponse, error) {
	if err := validateQuery(ctx, q); err != nil {
		return nil, err
	}

	if q.ID == "" || o.ExpectedRequestID != q.ID {
		return nil, ErrCorrelation
	}

	h, cs, err := verifyExchange(ctx, d, lexicon.SAMLElementResponse, keys, o.ExchangeOptions, nil, true)
	if err != nil {
		return nil, err
	}

	if xmlutil.Attr(d.Root(), nameInResponseTo) != q.ID {
		return nil, ErrCorrelation
	}

	if len(cs) < 1 || len(cs) > MaxQueryAssertions+1 {
		return nil, ErrProfile
	}

	status, err := readStatus(cs[0])
	if err != nil {
		return nil, err
	}

	result := &VerifiedQueryResponse{header: h, status: status}
	if status.Code != Success {
		if len(cs) != 1 {
			return nil, ErrProfile
		}

		return result, nil
	}

	state, err := newDecryptionState(o.Decryption)
	if err != nil {
		return nil, err
	}

	l, err := normalize(o.Limits)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{h.ID: true}

	for _, payload := range cs[1:] {
		a, err := verifyResponseAssertion(ctx, d, payload, keys, o, l, state)
		if err != nil {
			return nil, err
		}

		if seen[a.id] {
			return nil, ErrProfile
		}

		seen[a.id] = true
		result.assertions = append(result.assertions, a)
	}

	if err := MatchQueryResponse(ctx, q, result.assertions, o.Matcher); err != nil {
		return nil, err
	}

	return result, ctx.Err()
}

// MatchQueryResponse enforces the query's subject and result filters across the
// complete returned set. It is also used by authorities before signing output.
func MatchQueryResponse(ctx context.Context, q Query, as []*VerifiedAuthorityAssertion, o QueryMatchOptions) error {
	if err := validateQuery(ctx, q); err != nil {
		return err
	}

	if len(as) == 0 {
		return nil
	}

	session, contextMatch := q.SessionIndex == "", q.Context == nil

	for _, a := range as {
		if a == nil {
			return ErrProfile
		}

		if q.Kind == AssertionRequest {
			if !slices.Contains(q.AssertionIDs, a.id) {
				return ErrCorrelation
			}

			continue
		}

		if err := strongSubject(ctx, a.subject, q.Subject.Root(), o); err != nil {
			return err
		}

		matched, s, c, err := matchAssertionStatements(ctx, a, q, o)
		if err != nil {
			return err
		}

		if !matched {
			return ErrProfile
		}

		session = session || s
		contextMatch = contextMatch || c
	}

	if q.Kind == AuthenticationQuery {
		if !contextMatch {
			return &StatusError{Code: Responder, Subcodes: []string{NoAuthnContext}}
		}

		if !session {
			return ErrCorrelation
		}
	}

	return ctx.Err()
}

func strongSubject(ctx context.Context, a, b document.Element, o QueryMatchOptions) error {
	if !a.Valid() {
		return ErrCorrelation
	}

	ac, bc := a.Children(), b.Children()
	if len(bc) > 0 && bc[0].Name() == xmlutil.Name(AssertionNamespace, xmlNameNameID) {
		if len(ac) == 0 || ac[0].Name() != bc[0].Name() {
			return ErrCorrelation
		}

		x, err := readNameID(ac[0])
		if err != nil {
			return err
		}

		y, err := readNameID(bc[0])
		if err != nil || x != y {
			return ErrCorrelation
		}
		// Empty and explicitly present attributes are distinct for strong matching.
		if !sameAttributes(ac[0], bc[0]) {
			return ErrCorrelation
		}

		bc = bc[1:]
	}

	if len(bc) == 0 {
		return nil
	}

	if o.Confirm == nil {
		return ErrConditions
	}

	for _, want := range bc {
		for _, have := range ac {
			if have.Name() != xmlutil.Name(AssertionNamespace, xmlNameSubjectConfirmation) {
				continue
			}

			ok, err := o.Confirm(ctx, have, want)
			if err != nil {
				return err
			}

			if ok {
				return nil
			}
		}
	}

	return ErrConditions
}

func sameAttributes(a, b document.Element) bool {
	if len(a.Attributes()) != len(b.Attributes()) {
		return false
	}

	for _, attr := range a.Attributes() {
		v, ok := b.Attribute(attr.Name)
		if !ok || v != attr.Value {
			return false
		}
	}

	return true
}

func actionEqual(a, b Action) bool {
	const defaultNamespace = "urn:oasis:names:tc:SAML:1.0:action:rwedc-negation"
	if a.Namespace == "" {
		a.Namespace = defaultNamespace
	}

	if b.Namespace == "" {
		b.Namespace = defaultNamespace
	}

	return a == b
}

func matchContext(ctx context.Context, st document.Element, w RequestedContext, o QueryMatchOptions) (bool, error) {
	ac, err := xmlutil.Direct(st, xmlutil.Name(AssertionNamespace, xmlNameAuthnContext))
	if err != nil {
		return false, err
	}

	if w.Comparison != "" && w.Comparison != contextExact {
		if o.Context == nil {
			return false, ErrConditions
		}

		return o.Context(ctx, ac, w)
	}

	for _, c := range ac.Children() {
		s, err := xmlutil.SimpleText(c, maximumURITextBytes)
		if err != nil {
			continue
		}

		if c.Name() == xmlutil.Name(AssertionNamespace, xmlNameAuthnContextClassRef) && slices.Contains(w.Classes, s) || c.Name() == xmlutil.Name(AssertionNamespace, xmlNameAuthnContextDeclRef) && slices.Contains(w.Declarations, s) {
			return true, nil
		}
	}

	return false, nil
}

func matchAttributes(ctx context.Context, st document.Element, wants []*document.Document, o QueryMatchOptions) error {
	if len(wants) == 0 {
		return nil
	}

	for _, a := range st.Children() {
		key, err := queryAttribute(a)
		if err != nil {
			return err
		}

		want := findRequestedAttribute(wants, key)
		if want == nil {
			return ErrCorrelation
		}

		if err := matchAttributeValues(ctx, a, want.Root().Children(), o); err != nil {
			return err
		}
	}

	return nil
}

func authorityAssertionNode(s AuthorityAssertion) (*tree.Node, error) {
	if !profile.ID(s.ID) || !profile.URI(s.Issuer) || s.IssueInstant.IsZero() || len(s.Statements) > maximumAuthorityStatements {
		return nil, ErrProfile
	}

	n := xmlutil.Node(prefixAssertion, AssertionNamespace, nameAssertion)
	n.NS = []tree.Namespace{{Prefix: prefixAssertion, URI: AssertionNamespace}, {Prefix: prefixProtocol, URI: ProtocolNamespace}, {Prefix: lexicon.PrefixDSig, URI: xmlutil.DS}, {Prefix: prefixSOAP, URI: binding.SOAPNamespace}}
	xmlutil.Set(n, lexicon.SAMLAttrID, s.ID)
	xmlutil.Set(n, nameVersion, version20)
	xmlutil.Set(n, nameIssueInstant, profile.Time(s.IssueInstant))

	i := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameIssuer)
	xmlutil.Text(i, s.Issuer)
	xmlutil.Add(n, i)

	if s.Subject != nil {
		if err := validateQuerySubject(s.Subject); err != nil {
			return nil, err
		}

		appendDocument(n, s.Subject)
	} else if len(s.Statements) > 0 {
		return nil, ErrProfile
	}

	if s.Conditions != nil {
		if s.Conditions.Root().Name() != xmlutil.Name(AssertionNamespace, xmlNameConditions) {
			return nil, ErrProfile
		}

		appendDocument(n, s.Conditions)
	}

	if s.Advice != nil {
		if err := validateAdvice(s.Advice.Root()); err != nil {
			return nil, err
		}

		appendDocument(n, s.Advice)
	}

	for _, stmt := range s.Statements {
		if stmt == nil {
			return nil, ErrProfile
		}

		if err := validateAuthorityStatement(stmt.Root()); err != nil {
			return nil, err
		}

		appendDocument(n, stmt)
	}

	return n, nil
}

func encryptAuthorityContents(ctx context.Context, d *document.Document, options *EncryptionOptions) (*document.Document, error) {
	o, err := CloneEncryption(options)
	if err != nil || o.Recipient == nil {
		return nil, ErrEncryption
	}

	if o.Targets&EncryptNameID != 0 {
		d, err = encryptSubjectIdentifiers(ctx, d, o)
		if err != nil {
			return nil, err
		}
	}

	if o.Targets&EncryptAttributes != 0 {
		for {
			target := authorityAttributeChild(d, xmlNameAttribute)
			if !target.Valid() {
				break
			}

			d, err = encryptSAML(ctx, d, target, xmlNameEncryptedAttribute, o)
			if err != nil {
				return nil, err
			}
		}
	}

	return d, nil
}

func authoritySubjectChild(d *document.Document, local string) document.Element {
	for _, c := range d.Root().Children() {
		if c.Name() == xmlutil.Name(AssertionNamespace, xmlNameSubject) {
			return subjectChild(c, local)
		}
	}

	return document.Element{}
}

func authorityAttributeChild(d *document.Document, local string) document.Element {
	for _, st := range d.Root().Children() {
		if st.Name() != xmlutil.Name(AssertionNamespace, xmlNameAttributeStatement) {
			continue
		}

		for _, a := range st.Children() {
			if a.Name() == xmlutil.Name(AssertionNamespace, local) {
				return a
			}
		}
	}

	return document.Element{}
}

func decryptAuthorityContents(ctx context.Context, d *document.Document, state *decryptionState) (*document.Document, error) {
	for {
		target := authoritySubjectChild(d, xmlNameEncryptedID)
		plain := xmlNameNameID

		if !target.Valid() {
			target = authorityAttributeChild(d, xmlNameEncryptedAttribute)
			plain = xmlNameAttribute
		}

		if !target.Valid() {
			return d, nil
		}

		var err error

		d, err = state.decryptSAML(ctx, d, target, plain, true)
		if err != nil {
			return nil, err
		}
	}
}

func authorityTimeWindow(e document.Element, o AssertionOptions, l Limits, a *VerifiedAuthorityAssertion) error {
	if xmlutil.Attrs(e, nil, []string{nameNotBefore, nameNotOnOrAfter}) != nil {
		return ErrConditions
	}

	var start, end time.Time

	startValue, hasStart := e.Attribute(document.Name{Local: nameNotBefore})
	if hasStart {
		t, err := profile.ParseTime(startValue)
		if err != nil || o.At.Add(l.ClockSkew).Before(t) {
			return ErrConditions
		}

		start = t
	}

	endValue, hasEnd := e.Attribute(document.Name{Local: nameNotOnOrAfter})
	if hasEnd {
		t, err := profile.ParseTime(endValue)
		if err != nil || !o.At.Add(-l.ClockSkew).Before(t) {
			return ErrConditions
		}

		end = t
		a.expires = t
	}

	if hasStart && hasEnd && (!start.Before(end) || end.Sub(start) > l.MaxAssertionLifetime) {
		return ErrConditions
	}

	return nil
}

func authorityAudience(e document.Element, audience string) error {
	if xmlutil.Attrs(e, nil, nil) != nil {
		return ErrConditions
	}

	values, err := xmlutil.Children(e)
	if err != nil || len(values) == 0 {
		return ErrConditions
	}

	match := false

	for _, v := range values {
		if v.Name() != xmlutil.Name(AssertionNamespace, xmlNameAudience) {
			return ErrConditions
		}

		s, err := xmlutil.Simple(v, maximumURITextBytes)
		if err != nil || !profile.URI(s) {
			return ErrConditions
		}

		match = match || s == audience
	}

	if !match {
		return ErrConditions
	}

	return nil
}

func authorityProxy(e document.Element) error {
	const (
		xmlNameCount = "Count"
	)

	if xmlutil.Attrs(e, nil, []string{xmlNameCount}) != nil {
		return ErrConditions
	}

	if s, ok := e.Attribute(document.Name{Local: xmlNameCount}); ok {
		if !nonNegativeInteger(s) {
			return ErrConditions
		}
	}

	cs, err := xmlutil.Children(e)
	if err != nil {
		return ErrConditions
	}

	for _, v := range cs {
		if v.Name() != xmlutil.Name(AssertionNamespace, xmlNameAudience) || !simpleURI(v) {
			return ErrConditions
		}
	}

	return nil
}

func nonNegativeInteger(s string) bool {
	const (
		maximumProxyCountLexicalBytes = 4096
	)

	s = strings.Trim(s, lexicon.XMLWhitespace)

	negative := false
	if len(s) > 0 && (s[0] == '+' || s[0] == '-') {
		negative = s[0] == '-'
		s = s[1:]
	}

	if s == "" || len(s) > maximumProxyCountLexicalBytes {
		return false
	}

	for _, c := range s {
		if c < '0' || c > '9' || negative && c != '0' {
			return false
		}
	}

	return true
}

func verifyResponseAssertion(ctx context.Context, d *document.Document, payload document.Element, keys []crypto.PublicKey, o QueryResponseOptions, l Limits, state *decryptionState) (*VerifiedAuthorityAssertion, error) {
	ad, err := tree.ScopeDocument(d, payload)
	if err != nil {
		return nil, err
	}

	if payload.Name() == xmlutil.Name(AssertionNamespace, xmlNameEncryptedAssertion) {
		ad, err = state.decryptSAML(ctx, ad, ad.Root(), nameAssertion, true)
		if err != nil {
			return nil, err
		}
	}

	if ad.Root().Name() != xmlutil.Name(AssertionNamespace, nameAssertion) {
		return nil, ErrProfile
	}

	children := ad.Root().Children()
	if len(children) == 0 {
		return nil, ErrProfile
	}

	who, err := xmlutil.SimpleText(children[0], maximumURITextBytes)
	if err != nil || !profile.URI(who) {
		return nil, ErrProfile
	}

	trusted := keys
	if o.AssertionTrust != nil {
		trusted, err = o.AssertionTrust(ctx, who)
		if err != nil {
			return nil, err
		}
	} else if who != o.Issuer {
		return nil, ErrSignature
	}

	if err := targetSignature(ctx, ad, ad.Root(), trusted, o.Policy); err != nil {
		return nil, err
	}

	return parseAuthorityAssertion(ctx, ad, AssertionOptions{Issuer: who, Audience: o.Audience, At: o.At, Limits: o.Limits, Policy: o.Policy, Decryption: o.Decryption}, l, state)
}

func matchAssertionStatements(ctx context.Context, a *VerifiedAuthorityAssertion, q Query, o QueryMatchOptions) (matched, session, contextMatch bool, err error) {
	for _, st := range a.statements {
		yes, s, c, e := matchStatement(ctx, st, q, o)
		if e != nil {
			return false, false, false, e
		}

		matched = matched || yes
		session = session || s
		contextMatch = contextMatch || c
	}

	return
}

func matchStatement(ctx context.Context, st document.Element, q Query, o QueryMatchOptions) (bool, bool, bool, error) {
	switch q.Kind {
	case AuthenticationQuery:
		if st.Name() != xmlutil.Name(AssertionNamespace, xmlNameAuthnStatement) {
			return false, false, false, nil
		}

		contextMatch := true

		if q.Context != nil {
			var err error

			contextMatch, err = matchContext(ctx, st, *q.Context, o)
			if err != nil {
				return false, false, false, err
			}
		}

		return true, xmlutil.Attr(st, xmlNameSessionIndex) == q.SessionIndex, contextMatch, nil
	case AttributeQuery:
		if st.Name() != xmlutil.Name(AssertionNamespace, xmlNameAttributeStatement) {
			return false, false, false, nil
		}

		return true, false, false, matchAttributes(ctx, st, q.Attributes, o)
	case AuthorizationQuery:
		if st.Name() != xmlutil.Name(AssertionNamespace, xmlNameAuthzDecisionStatement) {
			return false, false, false, nil
		}

		return true, false, false, matchAuthorization(st, q)
	default:
		return false, false, false, ErrProfile
	}
}

func matchAuthorization(st document.Element, q Query) error {
	if xmlutil.Attr(st, xmlNameResource) != q.Resource {
		return ErrCorrelation
	}

	for _, v := range st.Children() {
		if v.Name() != xmlutil.Name(AssertionNamespace, xmlNameAction) {
			continue
		}

		a, err := readAction(v)
		if err != nil {
			return err
		}

		matched := false
		for _, want := range q.Actions {
			matched = matched || actionEqual(a, want)
		}

		if !matched {
			return ErrCorrelation
		}
	}

	return nil
}

func findRequestedAttribute(wants []*document.Document, key [2]string) *document.Document {
	for _, w := range wants {
		wk, _ := queryAttribute(w.Root())
		if wk == key {
			return w
		}
	}

	return nil
}

func matchAttributeValues(ctx context.Context, attribute document.Element, values []document.Element, o QueryMatchOptions) error {
	if len(values) == 0 {
		return nil
	}

	for _, v := range attribute.Children() {
		match := false

		for _, allowed := range values {
			var (
				ok  bool
				err error
			)
			if o.EqualValue != nil {
				ok, err = o.EqualValue(ctx, v, allowed)
			} else {
				ok, err = sameXML(ctx, v, allowed)
			}

			if err != nil {
				return err
			}

			match = match || ok
		}

		if !match {
			return ErrCorrelation
		}
	}

	return nil
}
