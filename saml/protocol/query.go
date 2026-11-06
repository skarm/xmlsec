package protocol

import (
	"bytes"
	"context"
	"crypto"
	"slices"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

// Local SAML vocabulary tokens shared by protocol producers and parsers. Each call site still verifies the assertion/protocol namespace or resolves the QName prefix.
const (
	xmlNameAssertionIDRef = "AssertionIDRef"
	xmlNameNamespace      = "Namespace"
)

// Profile bound shared by these producer/parser paths; byte/count/time units follow the name, and default values apply only to zero options.
const (
	maximumActionValueBytes = 4096
)

// QueryKind identifies a Core 3.3 query or assertion request.
type QueryKind string

const (
	// AuthenticationQuery requests statements about past authentication, not login.
	AuthenticationQuery QueryKind = lexicon.SAMLElementAuthnQuery
	// AttributeQuery requests attributes, optionally constrained by values.
	AttributeQuery QueryKind = lexicon.SAMLElementAttributeQuery
	// AuthorizationQuery requests authorization decisions for actions on a resource.
	AuthorizationQuery QueryKind = lexicon.SAMLElementAuthzDecisionQuery
	// AssertionRequest requests existing assertions by their exact XML IDs.
	AssertionRequest QueryKind = lexicon.SAMLElementAssertionIDRequest
)

// RequestedContext preserves references and their comparison rule. AuthnQuery
// does not impose preference ordering (Approved Errata E45). Exactly one of
// Classes and Declarations is required. Empty Comparison is exact.
type RequestedContext struct {
	// Classes lists authentication context class URIs. Exactly one of Classes and
	// Declarations must be nonempty.
	Classes []string
	// Declarations lists authentication context declaration URIs.
	Declarations []string
	// Comparison selects exact, minimum, maximum or better comparison. Empty
	// selects exact.
	Comparison string
}

// Action is a Core 2.7.4.2 action. An omitted Namespace has the SAML default
// rwedc-negation semantics; it is not an arbitrary application namespace.
type Action struct {
	// Namespace identifies the action vocabulary. Empty selects the SAML
	// rwedc-negation vocabulary.
	Namespace string
	// Value is the action text interpreted according to Namespace.
	Value string
}

// Query represents a complete query payload. Subject is a saml:Subject document;
// Attributes are saml:Attribute documents, retaining arbitrary XML values and
// xsi:type/nil annotations. Evidence is an optional saml:Evidence document and
// remains untrusted until independently validated by the authorization backend.
// The optional Encryption must select EncryptNameID and encrypts the subject ID.
type Query struct {
	MessageHeader
	// Limits bounds producer-side attribute filters; verification uses the receiver's limits.
	Limits Limits
	// Kind selects the query or assertion-ID request form.
	Kind QueryKind
	// Subject is the complete saml:Subject document required by subject queries and
	// absent from assertion-ID requests.
	Subject *document.Document
	// SessionIndex optionally restricts an authentication query to one session.
	SessionIndex string
	// Context optionally restricts an authentication query's authentication
	// context.
	Context *RequestedContext
	// Attributes contains the requested saml:Attribute filters for an attribute
	// query. Empty requests all attributes allowed by authority policy.
	Attributes []*document.Document
	// Resource is the resource URI for an authorization decision query.
	Resource string
	// Actions lists the actions requested by an authorization decision query.
	Actions []Action
	// Evidence is optional saml:Evidence for an authorization query. The backend
	// must validate it independently.
	Evidence *document.Document
	// AssertionIDs lists exact XML IDs for an assertion-ID request.
	AssertionIDs []string
	// Encryption optionally encrypts the subject identifier and must select
	// EncryptNameID.
	Encryption *EncryptionOptions
}

// VerifiedQuery contains a validated signed request. It neither authorizes
// disclosure nor verifies embedded Evidence. Those are separate application duties.
type VerifiedQuery struct{ query Query }

// Query returns an owned copy; immutable XML snapshots may safely be shared.
func (q *VerifiedQuery) Query() Query { return cloneQuery(q.query) }

// NewSubject creates a subject with a NameID. Subject confirmations, when needed,
// can instead be supplied in an application-built immutable Subject document.
func NewSubject(ctx context.Context, id NameIdentifier) (*document.Document, error) {
	n, err := nameIDNode(id)
	if err != nil {
		return nil, err
	}

	s := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameSubject)
	s.NS = []tree.Namespace{{Prefix: prefixAssertion, URI: AssertionNamespace}}
	xmlutil.Add(s, n)

	return xmlutil.Document(ctx, s)
}

// SignQuery signs a Core query. SOAP delivery must use SignSOAP so inclusive
// canonicalization is evaluated in the final namespace context.
func SignQuery(ctx context.Context, q Query, key SigningKey) (*document.Document, error) {
	if ctx == nil {
		return nil, ErrProfile
	}

	q = cloneQuery(q)

	n, err := soapExchangeRoot(q.MessageHeader, string(q.Kind))
	if err != nil {
		return nil, err
	}

	if err = validateQuery(ctx, q); err != nil {
		return nil, err
	}

	if q.Subject != nil {
		appendDocument(n, q.Subject)
	}

	switch q.Kind {
	case AuthenticationQuery:
		if q.SessionIndex != "" {
			xmlutil.Set(n, xmlNameSessionIndex, q.SessionIndex)
		}

		if q.Context != nil {
			c, _ := requestedContextNode(*q.Context)
			xmlutil.Add(n, c)
		}
	case AttributeQuery:
		for _, a := range q.Attributes {
			appendDocument(n, a)
		}
	case AuthorizationQuery:
		xmlutil.Set(n, xmlNameResource, q.Resource)

		for _, a := range q.Actions {
			c, _ := actionNode(a)
			xmlutil.Add(n, c)
		}

		if q.Evidence != nil {
			appendDocument(n, q.Evidence)
		}
	case AssertionRequest:
		for _, id := range q.AssertionIDs {
			c := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameAssertionIDRef)
			xmlutil.Text(c, id)
			xmlutil.Add(n, c)
		}
	}

	d, err := xmlutil.Document(ctx, n)
	if err != nil {
		return nil, err
	}

	if q.Encryption != nil {
		o, err := CloneEncryption(q.Encryption)
		if err != nil || o.Targets != EncryptNameID || o.Recipient == nil {
			return nil, ErrEncryption
		}

		d, err = encryptSubjectIdentifiers(ctx, d, o)
		if err != nil {
			return nil, err
		}
	}

	key = namespaceSigningKey(d.Root(), key)

	k, err := signing(key)
	if err != nil {
		return nil, err
	}

	return xmlsig.Sign(ctx, d, d.Root(), k, true)
}

// VerifyQuery authenticates the complete query before decrypting its subject.
// ExchangeOptions.Binding should be SOAP for a synchronous SOAP exchange.
func VerifyQuery(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o ExchangeOptions) (*VerifiedQuery, error) {
	if d == nil {
		return nil, ErrProfile
	}

	kind := QueryKind(d.Root().Name().Local)

	attrs := []string{}
	if kind == AuthenticationQuery {
		attrs = append(attrs, xmlNameSessionIndex)
	}

	if kind == AuthorizationQuery {
		attrs = append(attrs, xmlNameResource)
	}

	h, cs, err := verifyExchange(ctx, d, string(kind), keys, o, attrs, false)
	if err != nil {
		return nil, err
	}

	q := Query{MessageHeader: h, Kind: kind, Limits: o.Limits}
	if kind != AssertionRequest {
		d, q.Subject, err = readQuerySubject(ctx, d, cs, o.Decryption)
		if err != nil {
			return nil, err
		}

		cs, err = controlChildren(d, false)
		if err != nil {
			return nil, err
		}

		cs = cs[1:]
	}

	if err = readQueryBody(d, cs, &q); err != nil {
		return nil, err
	}

	if err = validateQuery(ctx, q); err != nil {
		return nil, err
	}

	return &VerifiedQuery{query: q}, ctx.Err()
}

func validateQuery(ctx context.Context, q Query) error {
	const (
		maximumAssertionIDReferences = 128
	)

	if ctx == nil {
		return ErrProfile
	}

	if q.Kind == AssertionRequest {
		if q.Subject != nil || len(q.AssertionIDs) < 1 || len(q.AssertionIDs) > maximumAssertionIDReferences {
			return ErrProfile
		}

		for _, id := range q.AssertionIDs {
			if !profile.ID(id) {
				return ErrProfile
			}
		}
	} else {
		if err := validateQuerySubject(q.Subject); err != nil {
			return err
		}

		if len(q.AssertionIDs) > 0 {
			return ErrProfile
		}
	}

	if q.Kind != AuthenticationQuery && (q.SessionIndex != "" || q.Context != nil) || q.Kind != AttributeQuery && len(q.Attributes) != 0 || q.Kind != AuthorizationQuery && (q.Resource != "" || len(q.Actions) != 0 || q.Evidence != nil) {
		return ErrProfile
	}

	if err := validateQueryBody(q); err != nil {
		return err
	}

	l, err := normalize(q.Limits)
	if err != nil {
		return err
	}

	if len(q.Attributes) > l.MaxAttributes {
		return ErrProfile
	}

	for _, a := range q.Attributes {
		if err := attributeBudget(ctx, a.Root(), l); err != nil {
			return err
		}
	}

	return ctx.Err()
}

func cloneQuery(q Query) Query {
	q.Attributes = slices.Clone(q.Attributes)
	q.Actions = slices.Clone(q.Actions)

	q.AssertionIDs = slices.Clone(q.AssertionIDs)
	if q.Context != nil {
		c := *q.Context
		c.Classes = slices.Clone(c.Classes)
		c.Declarations = slices.Clone(c.Declarations)
		q.Context = &c
	}

	return q
}

func appendDocument(n *tree.Node, d *document.Document) {
	_, child := tree.Unwrap(d.Root())
	xmlutil.Add(n, tree.ImportSubtree(child))
}

func validateQuerySubject(d *document.Document) error {
	const (
		maximumQuerySubjectChildren = 65
	)

	if d == nil || d.Root().Name() != xmlutil.Name(AssertionNamespace, xmlNameSubject) || xmlutil.Attrs(d.Root(), nil, nil) != nil {
		return ErrProfile
	}

	cs, err := xmlutil.Children(d.Root())
	if err != nil || len(cs) == 0 || len(cs) > maximumQuerySubjectChildren {
		return ErrProfile
	}

	i := 0

	if cs[0].Name() == xmlutil.Name(AssertionNamespace, xmlNameNameID) {
		if _, err := readNameID(cs[0]); err != nil {
			return err
		}

		i++
	}

	for _, c := range cs[i:] {
		if err := validateQueryConfirmation(c); err != nil {
			return err
		}
	}

	return nil
}

func requestedContextNode(c RequestedContext) (*tree.Node, error) {
	const (
		contextBetter                     = "better"
		contextMaximum                    = "maximum"
		contextMinimum                    = "minimum"
		maximumRequestedContextReferences = 128
	)

	if (len(c.Classes) == 0) == (len(c.Declarations) == 0) || len(c.Classes)+len(c.Declarations) > maximumRequestedContextReferences || !slices.Contains([]string{"", contextExact, contextMinimum, contextMaximum, contextBetter}, c.Comparison) {
		return nil, ErrProfile
	}

	n := xmlutil.Node(prefixProtocol, ProtocolNamespace, xmlNameRequestedAuthnContext)
	if c.Comparison != "" {
		xmlutil.Set(n, xmlNameComparison, c.Comparison)
	}

	name, refs := xmlNameAuthnContextClassRef, c.Classes
	if len(c.Declarations) > 0 {
		name, refs = xmlNameAuthnContextDeclRef, c.Declarations
	}

	for _, v := range refs {
		if !profile.URI(v) {
			return nil, ErrProfile
		}

		e := xmlutil.Node(prefixAssertion, AssertionNamespace, name)
		xmlutil.Text(e, v)
		xmlutil.Add(n, e)
	}

	return n, nil
}

func readRequestedContext(e document.Element) (*RequestedContext, error) {
	if e.Name() != xmlutil.Name(ProtocolNamespace, xmlNameRequestedAuthnContext) || xmlutil.Attrs(e, nil, []string{xmlNameComparison}) != nil {
		return nil, ErrProfile
	}

	c := &RequestedContext{Comparison: xmlutil.Attr(e, xmlNameComparison)}

	cs, err := xmlutil.Children(e)
	if err != nil {
		return nil, err
	}

	for _, r := range cs {
		v, err := xmlutil.Simple(r, maximumURITextBytes)
		if err != nil {
			return nil, err
		}

		switch r.Name() {
		case xmlutil.Name(AssertionNamespace, xmlNameAuthnContextClassRef):
			c.Classes = append(c.Classes, v)
		case xmlutil.Name(AssertionNamespace, xmlNameAuthnContextDeclRef):
			c.Declarations = append(c.Declarations, v)
		default:
			return nil, ErrProfile
		}
	}

	_, err = requestedContextNode(*c)

	return c, err
}

func actionNode(a Action) (*tree.Node, error) {
	if !uriReference(a.Namespace) || a.Value == "" || len(a.Value) > maximumActionValueBytes {
		return nil, ErrProfile
	}

	n := xmlutil.Node(prefixAssertion, AssertionNamespace, xmlNameAction)
	if a.Namespace != "" {
		xmlutil.Set(n, xmlNameNamespace, a.Namespace)
	}

	xmlutil.Text(n, a.Value)

	return n, nil
}

func readAction(e document.Element) (Action, error) {
	a := Action{Namespace: xmlutil.Attr(e, xmlNameNamespace)}
	if e.Name() != xmlutil.Name(AssertionNamespace, xmlNameAction) || xmlutil.Attrs(e, nil, []string{xmlNameNamespace}) != nil {
		return a, ErrProfile
	}

	v, err := xmlutil.SimpleText(e, maximumActionValueBytes)
	if err != nil {
		return a, err
	}

	a.Value = v
	_, err = actionNode(a)

	return a, err
}

func queryAttribute(e document.Element) ([2]string, error) {
	const (
		maximumQueryAttributeNameBytes = 4096
		maximumQueryAttributeValues    = 128
	)

	k := [2]string{xmlutil.Attr(e, nameAttributeName), xmlutil.Attr(e, xmlNameNameFormat)}
	if k[1] == "" {
		k[1] = AttributeUnspecified
	}

	if e.Name() != xmlutil.Name(AssertionNamespace, xmlNameAttribute) || attributeAttributes(e) != nil || k[0] == "" || len(k[0]) > maximumQueryAttributeNameBytes || !profile.URI(k[1]) {
		return k, ErrProfile
	}

	cs, err := xmlutil.Children(e)
	if err != nil || len(cs) > maximumQueryAttributeValues {
		return k, ErrProfile
	}

	for _, v := range cs {
		if v.Name() != xmlutil.Name(AssertionNamespace, xmlNameAttributeValue) {
			return k, ErrProfile
		}

		if err := attributeValueType(v); err != nil {
			return k, err
		}
	}

	return k, nil
}

func validateEvidence(e document.Element) error {
	if e.Name() != xmlutil.Name(AssertionNamespace, xmlNameEvidence) || xmlutil.Attrs(e, nil, nil) != nil {
		return ErrProfile
	}

	return validateAssertionReferences(e, false)
}

func validateAdvice(e document.Element) error {
	if e.Name() != xmlutil.Name(AssertionNamespace, xmlNameAdvice) || xmlutil.Attrs(e, nil, nil) != nil {
		return ErrProfile
	}

	return validateAssertionReferences(e, true)
}

func validateAssertionReferences(e document.Element, allowForeign bool) error {
	const (
		maximumAssertionReferences = 128
		xmlNameAssertionURIRef     = "AssertionURIRef"
	)

	cs, err := xmlutil.Children(e)
	if err != nil || !allowForeign && len(cs) == 0 || len(cs) > maximumAssertionReferences {
		return ErrProfile
	}

	for _, v := range cs {
		if v.Name().Space != AssertionNamespace {
			if allowForeign && v.Name().Space != "" {
				continue
			}

			return ErrProfile
		}

		switch v.Name().Local {
		case xmlNameAssertionIDRef, xmlNameAssertionURIRef:
			ref, err := xmlutil.Simple(v, maximumURITextBytes)
			if err != nil || ref == "" || v.Name().Local == xmlNameAssertionIDRef && !profile.ID(ref) || v.Name().Local == xmlNameAssertionURIRef && !uriReference(ref) {
				return ErrProfile
			}
		case nameAssertion, xmlNameEncryptedAssertion:
			// Embedded assertions remain untrusted until independently verified.
		default:
			return ErrProfile
		}
	}

	return nil
}

func sameXML(ctx context.Context, a, b document.Element) (bool, error) {
	var x, y bytes.Buffer

	prefixes := valuePrefixes(a, b)
	if err := c14n.WriteElement(ctx, &x, a, c14n.Options{Algorithm: c14n.ExclusiveWithComments, InclusivePrefixes: prefixes}); err != nil {
		return false, err
	}

	if err := c14n.WriteElement(ctx, &y, b, c14n.Options{Algorithm: c14n.ExclusiveWithComments, InclusivePrefixes: prefixes}); err != nil {
		return false, err
	}

	return bytes.Equal(x.Bytes(), y.Bytes()), nil
}

func uriReference(s string) bool { return logoutReason(s) }

func readQuerySubject(ctx context.Context, d *document.Document, cs []document.Element, o *DecryptionOptions) (*document.Document, *document.Document, error) {
	if len(cs) == 0 || cs[0].Name() != xmlutil.Name(AssertionNamespace, xmlNameSubject) {
		return nil, nil, ErrProfile
	}

	state, err := newDecryptionState(o)
	if err != nil {
		return nil, nil, err
	}

	for {
		sub, err := xmlutil.Direct(d.Root(), xmlutil.Name(AssertionNamespace, xmlNameSubject))
		if err != nil {
			return nil, nil, err
		}

		target := subjectChild(sub, xmlNameEncryptedID)
		if !target.Valid() {
			scope, err := tree.ScopeDocument(d, sub)
			return d, scope, err
		}

		d, err = state.decryptSAML(ctx, d, target, xmlNameNameID, true)
		if err != nil {
			return nil, nil, err
		}
	}
}

func readQueryBody(d *document.Document, cs []document.Element, q *Query) error {
	const (
		maximumAssertionReferenceBytes = 1024
	)

	switch q.Kind {
	case AuthenticationQuery:
		q.SessionIndex = xmlutil.Attr(d.Root(), xmlNameSessionIndex)

		if len(cs) > 1 {
			return ErrProfile
		}

		if len(cs) == 1 {
			var err error

			q.Context, err = readRequestedContext(cs[0])

			return err
		}
	case AttributeQuery:
		for _, a := range cs {
			v, err := tree.ScopeDocument(d, a)
			if err != nil {
				return err
			}

			q.Attributes = append(q.Attributes, v)
		}
	case AuthorizationQuery:
		q.Resource = xmlutil.Attr(d.Root(), xmlNameResource)

		if len(cs) > 0 && cs[len(cs)-1].Name() == xmlutil.Name(AssertionNamespace, xmlNameEvidence) {
			var err error

			q.Evidence, err = tree.ScopeDocument(d, cs[len(cs)-1])
			if err != nil {
				return err
			}

			cs = cs[:len(cs)-1]
		}

		for _, a := range cs {
			v, err := readAction(a)
			if err != nil {
				return err
			}

			q.Actions = append(q.Actions, v)
		}
	case AssertionRequest:
		for _, c := range cs {
			if c.Name() != xmlutil.Name(AssertionNamespace, xmlNameAssertionIDRef) {
				return ErrProfile
			}

			v, err := xmlutil.Simple(c, maximumAssertionReferenceBytes)
			if err != nil {
				return err
			}

			q.AssertionIDs = append(q.AssertionIDs, v)
		}
	default:
		return ErrProfile
	}

	return nil
}

func validateQueryBody(q Query) error {
	const (
		maximumQueryActions           = 128
		maximumQuerySessionIndexBytes = 4096
	)

	switch q.Kind {
	case AuthenticationQuery:
		if len(q.SessionIndex) > maximumQuerySessionIndexBytes {
			return ErrProfile
		}

		if q.Context != nil {
			_, err := requestedContextNode(*q.Context)
			return err
		}
	case AttributeQuery:
		return validateQueryAttributes(q.Attributes)
	case AuthorizationQuery:
		if !uriReference(q.Resource) || len(q.Actions) < 1 || len(q.Actions) > maximumQueryActions {
			return ErrProfile
		}

		for _, a := range q.Actions {
			if _, err := actionNode(a); err != nil {
				return err
			}
		}

		if q.Evidence != nil {
			return validateEvidence(q.Evidence.Root())
		}
	case AssertionRequest:
	default:
		return ErrProfile
	}

	return nil
}

func validateQueryAttributes(attributes []*document.Document) error {
	const (
		maximumQueryAttributes = 512
	)

	if len(attributes) > maximumQueryAttributes {
		return ErrProfile
	}

	seen := map[[2]string]bool{}

	for _, a := range attributes {
		if a == nil {
			return ErrProfile
		}

		name, err := queryAttribute(a.Root())
		if err != nil || seen[name] {
			return ErrProfile
		}

		seen[name] = true
	}

	return nil
}

func subjectChild(subject document.Element, local string) document.Element {
	for _, c := range subject.Children() {
		if c.Name() == xmlutil.Name(AssertionNamespace, local) {
			return c
		}

		if c.Name() == xmlutil.Name(AssertionNamespace, xmlNameSubjectConfirmation) {
			for _, id := range c.Children() {
				if id.Name() == xmlutil.Name(AssertionNamespace, local) {
					return id
				}
			}
		}
	}

	return document.Element{}
}
