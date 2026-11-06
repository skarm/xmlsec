package protocol

import (
	"context"
	"crypto"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

// Mapping payloads contain the original identifier and policy/result identifier
// after the common issuer/signature prefix has been removed.
const (
	mappingPayloadChildren = 2
)

const (
	// InvalidNameIDPolicy indicates that the requested identifier policy cannot be satisfied.
	InvalidNameIDPolicy = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
	// NoAuthnContext indicates that no requested authentication context can be satisfied.
	NoAuthnContext = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"
)

// NameIDPolicy selects the desired identifier format, target federation namespace
// and permission to establish a new identifier. It does not authorize disclosure.
type NameIDPolicy struct {
	// Format is the requested identifier format URI.
	Format string
	// SPNameQualifier identifies the target service provider or affiliation
	// namespace.
	SPNameQualifier string
	// AllowCreate permits creation of an identifier subject to application policy.
	AllowCreate bool
}

// NameIDMappingRequest maps an existing principal identifier into another format
// or federation namespace. Encryption, if present, encrypts the input identifier
// for the identity provider. It must select EncryptNameID.
type NameIDMappingRequest struct {
	MessageHeader
	// NameID is the existing principal identifier to map.
	NameID NameIdentifier
	// Policy selects the desired identifier format and target namespace.
	Policy NameIDPolicy
	// Encryption optionally encrypts the input identifier and must select
	// EncryptNameID.
	Encryption *EncryptionOptions
}

// VerifiedNameIDMappingRequest contains an authenticated mapping request.
type VerifiedNameIDMappingRequest struct {
	request            NameIDMappingRequest
	originalIdentifier *document.Document
}

// Request returns the authenticated plaintext input and requested policy.
func (r *VerifiedNameIDMappingRequest) Request() NameIDMappingRequest { return r.request }

// ErrorIdentifier returns the original identifier representation for an error
// response. Core's NameIDMappingResponse schema requires an identifier even on
// error. Echoing the original EncryptedID preserves its confidentiality and does
// not assert a successful mapping. Error results never expose a mapped identifier.
func (r *VerifiedNameIDMappingRequest) ErrorIdentifier() *document.Document {
	return r.originalIdentifier
}

// NameIDMappingResponse contains either a plaintext NameID or an opaque
// EncryptedID for the target provider. The requester need not hold its decryption
// key: Core 3.8 permits forwarding the encrypted identifier to another provider.
// Encryption encrypts a plaintext NameID for that target and must select EncryptNameID.
type NameIDMappingResponse struct {
	MessageHeader
	// InResponseTo identifies the mapping request being answered.
	InResponseTo string
	// Status records whether mapping succeeded.
	Status Status
	// Identifier contains the mapped NameID or opaque EncryptedID. Error responses
	// carry the original identifier representation.
	Identifier *document.Document
	// Encryption optionally encrypts a plaintext result for the target provider and
	// must select EncryptNameID.
	Encryption *EncryptionOptions
}

// VerifiedNameIDMappingResponse authenticates the mapping result. An EncryptedID
// is not decrypted or promoted to a local principal merely by verifying its envelope.
type VerifiedNameIDMappingResponse struct {
	header     MessageHeader
	requestID  string
	status     Status
	identifier *document.Document
}

// Header returns the authenticated envelope header.
func (r *VerifiedNameIDMappingResponse) Header() MessageHeader { return r.header }

// InResponseTo returns the authenticated request correlation.
func (r *VerifiedNameIDMappingResponse) InResponseTo() string { return r.requestID }

// Status returns a copy of the authenticated status.
func (r *VerifiedNameIDMappingResponse) Status() Status {
	s := r.status
	s.Subcodes = append([]string(nil), s.Subcodes...)

	return s
}

// Identifier returns the immutable NameID or opaque EncryptedID, or nil on error.
func (r *VerifiedNameIDMappingResponse) Identifier() *document.Document { return r.identifier }

// NameIDDocument builds an immutable identifier document for mapping responses.
func NameIDDocument(ctx context.Context, id NameIdentifier) (*document.Document, error) {
	n, err := nameIDNode(id)
	if err != nil {
		return nil, err
	}

	n.NS = []tree.Namespace{{Prefix: prefixAssertion, URI: AssertionNamespace}}

	return xmlutil.Document(ctx, n)
}

// EncryptMappedIdentifier encrypts a plaintext NameID for the target provider.
func EncryptMappedIdentifier(ctx context.Context, d *document.Document, o *EncryptionOptions) (*document.Document, error) {
	if ctx == nil || d == nil || o == nil || o.Targets != EncryptNameID {
		return nil, ErrEncryption
	}

	if _, err := readNameID(d.Root()); err != nil {
		return nil, err
	}

	p, err := CloneEncryption(o)
	if err != nil || p.Recipient == nil {
		return nil, ErrEncryption
	}

	return encryptSAML(ctx, d, d.Root(), xmlNameEncryptedID, p)
}

// EncryptMappedAssertion implements Profiles 7.4.2.1: a signed statement-free
// assertion carries the identifier with conditions limiting use at the target.
func EncryptMappedAssertion(ctx context.Context, a *VerifiedAuthorityAssertion, o *EncryptionOptions) (*document.Document, error) {
	if a == nil || !a.subject.Valid() || len(a.statements) != 0 || o == nil || o.Targets != EncryptNameID {
		return nil, ErrEncryption
	}

	p, err := CloneEncryption(o)
	if err != nil || p.Recipient == nil {
		return nil, ErrEncryption
	}

	return encryptSAML(ctx, a.signed, a.signed.Root(), xmlNameEncryptedID, p)
}

// DecryptMappedAssertion verifies the signed, limited-use assertion carried by
// an EncryptedID. Its conditions and subject remain distinct from a bare NameID.
func DecryptMappedAssertion(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o AssertionOptions) (*VerifiedAuthorityAssertion, error) {
	return decryptMappedAssertion(ctx, d, keys, o, false)
}

// DecryptAssertion opens the exact authenticated mapping result and verifies its
// limited-use assertion. All private-key attempts share one decryption budget.
func (r *VerifiedNameIDMappingResponse) DecryptAssertion(ctx context.Context, keys []crypto.PublicKey, o AssertionOptions) (*VerifiedAuthorityAssertion, error) {
	if r == nil || r.identifier == nil {
		return nil, ErrProfile
	}

	return decryptMappedAssertion(ctx, r.identifier, keys, o, true)
}

func decryptMappedAssertion(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o AssertionOptions, authenticated bool) (*VerifiedAuthorityAssertion, error) {
	if ctx == nil || d == nil || d.Root().Name() != xmlutil.Name(AssertionNamespace, xmlNameEncryptedID) {
		return nil, ErrEncryption
	}

	s, err := newDecryptionState(o.Decryption)
	if err != nil {
		return nil, err
	}

	plain, err := s.decryptSAML(ctx, d, d.Root(), nameAssertion, authenticated)
	if err != nil {
		return nil, err
	}

	l, err := normalize(o.Limits)
	if err != nil {
		return nil, err
	}

	a, err := verifyAuthorityAssertion(ctx, plain, keys, o, l, s)
	if err != nil {
		return nil, err
	}

	if !a.subject.Valid() || len(a.statements) != 0 {
		return nil, ErrProfile
	}

	return a, nil
}

// SignNameIDMappingRequest authenticates the input identifier and target policy.
func SignNameIDMappingRequest(ctx context.Context, s NameIDMappingRequest, key SigningKey) (*document.Document, error) {
	n, err := soapExchangeRoot(s.MessageHeader, lexicon.SAMLElementNameIDMappingRequest)
	if err != nil {
		return nil, err
	}

	id, err := nameIDNode(s.NameID)
	if err != nil {
		return nil, err
	}

	xmlutil.Add(n, id)

	p, err := mappingPolicyNode(s.Policy)
	if err != nil {
		return nil, err
	}

	xmlutil.Add(n, p)

	return signRichExchange(ctx, n, key, s.Encryption)
}

// VerifyNameIDMappingRequest authenticates before decrypting an existing ID.
func VerifyNameIDMappingRequest(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o ExchangeOptions) (*VerifiedNameIDMappingRequest, error) {
	h, cs, err := verifyExchange(ctx, d, lexicon.SAMLElementNameIDMappingRequest, keys, o, nil, false)
	if err != nil {
		return nil, err
	}

	if len(cs) != mappingPayloadChildren {
		return nil, ErrProfile
	}

	original, err := tree.ScopeDocument(d, cs[0])
	if err != nil {
		return nil, err
	}

	d, err = decryptControl(ctx, d, cs, o.Decryption)
	if err != nil {
		return nil, err
	}

	cs, err = controlChildren(d, false)
	if err != nil || len(cs) != mappingPayloadChildren {
		return nil, ErrProfile
	}

	id, err := readNameID(cs[0])
	if err != nil {
		return nil, err
	}

	p, err := readMappingPolicy(cs[1])
	if err != nil {
		return nil, err
	}

	return &VerifiedNameIDMappingRequest{request: NameIDMappingRequest{MessageHeader: h, NameID: id, Policy: p}, originalIdentifier: original}, ctx.Err()
}

// SignNameIDMappingResponse signs success or error. Core 3.8.2 requires exactly
// one identifier in both cases. For an error, use the request's ErrorIdentifier;
// consumers do not interpret it as a mapped identity.
func SignNameIDMappingResponse(ctx context.Context, s NameIDMappingResponse, key SigningKey) (*document.Document, error) {
	if !profile.ID(s.InResponseTo) {
		return nil, ErrProfile
	}

	n, err := soapExchangeRoot(s.MessageHeader, lexicon.SAMLElementNameIDMappingResponse)
	if err != nil {
		return nil, err
	}

	xmlutil.Set(n, nameInResponseTo, s.InResponseTo)

	status, err := statusNode(s.Status)
	if err != nil {
		return nil, err
	}

	xmlutil.Add(n, status)

	success := s.Status.Code == "" || s.Status.Code == Success
	if s.Identifier == nil || !success && s.Encryption != nil {
		return nil, ErrProfile
	}

	if err := mappedIdentifier(s.Identifier.Root()); err != nil {
		return nil, err
	}

	appendDocument(n, s.Identifier)

	return signRichExchange(ctx, n, key, s.Encryption)
}

// VerifyNameIDMappingResponse validates the peer, signature, time and request
// correlation. Opaque encrypted output can be forwarded without decrypting it.
func VerifyNameIDMappingResponse(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o ExchangeOptions) (*VerifiedNameIDMappingResponse, error) {
	if !profile.ID(o.ExpectedRequestID) {
		return nil, ErrProfile
	}

	h, cs, err := verifyExchange(ctx, d, lexicon.SAMLElementNameIDMappingResponse, keys, o, nil, true)
	if err != nil {
		return nil, err
	}

	if xmlutil.Attr(d.Root(), nameInResponseTo) != o.ExpectedRequestID {
		return nil, ErrCorrelation
	}

	if len(cs) != mappingPayloadChildren {
		return nil, ErrProfile
	}

	s, err := readStatus(cs[0])
	if err != nil {
		return nil, err
	}

	r := &VerifiedNameIDMappingResponse{header: h, requestID: o.ExpectedRequestID, status: s}
	if s.Code == Success {
		if err := mappedIdentifier(cs[1]); err != nil {
			return nil, err
		}

		r.identifier, err = tree.ScopeDocument(d, cs[1])
	} else if err := mappedIdentifier(cs[1]); err != nil {
		return nil, err
	}

	return r, err
}

// DecryptMappedNameID opens an identifier only with the target's explicit keys.
// Assertion-wrapped limited-use identifiers must instead be processed under
// the target application's assertion/condition policy; they are not bare names.
func DecryptMappedNameID(ctx context.Context, d *document.Document, o *DecryptionOptions) (NameIdentifier, error) {
	return decryptMappedNameID(ctx, d, o, false)
}

// DecryptNameID opens this exact authenticated mapping result. Its verified
// envelope also permits explicitly authorized legacy CBC/RSA-v1.5 policies.
func (r *VerifiedNameIDMappingResponse) DecryptNameID(ctx context.Context, o *DecryptionOptions) (NameIdentifier, error) {
	if r == nil || r.identifier == nil {
		return NameIdentifier{}, ErrProfile
	}

	return decryptMappedNameID(ctx, r.identifier, o, true)
}

func decryptMappedNameID(ctx context.Context, d *document.Document, o *DecryptionOptions, authenticated bool) (NameIdentifier, error) {
	if ctx == nil || d == nil {
		return NameIdentifier{}, ErrProfile
	}

	if d.Root().Name() == xmlutil.Name(AssertionNamespace, xmlNameNameID) {
		return readNameID(d.Root())
	}

	if d.Root().Name() != xmlutil.Name(AssertionNamespace, xmlNameEncryptedID) {
		return NameIdentifier{}, ErrProfile
	}

	state, err := newDecryptionState(o)
	if err != nil {
		return NameIdentifier{}, err
	}

	d, err = state.decryptSAML(ctx, d, d.Root(), xmlNameNameID, authenticated)
	if err != nil {
		return NameIdentifier{}, err
	}

	return readNameID(d.Root())
}

func mappedIdentifier(e document.Element) error {
	switch e.Name() {
	case xmlutil.Name(AssertionNamespace, xmlNameNameID):
		_, err := readNameID(e)
		return err
	case xmlutil.Name(AssertionNamespace, xmlNameEncryptedID):
		if xmlutil.Attrs(e, nil, nil) != nil {
			return ErrProfile
		}

		_, _, err := encryptedSAMLRecipients(e)

		return err
	default:
		return ErrProfile
	}
}

func mappingPolicyNode(p NameIDPolicy) (*tree.Node, error) {
	if p.Format != "" && !profile.URI(p.Format) || len(p.SPNameQualifier) > maximumNameQualifierBytes {
		return nil, ErrProfile
	}

	n := xmlutil.Node(prefixProtocol, ProtocolNamespace, xmlNameNameIDPolicy)
	if p.Format != "" {
		xmlutil.Set(n, nameFormat, p.Format)
	}

	if p.SPNameQualifier != "" {
		xmlutil.Set(n, nameSPNameQualifier, p.SPNameQualifier)
	}

	if p.AllowCreate {
		xmlutil.Set(n, xmlNameAllowCreate, lexicon.ValueTrue)
	}

	return n, nil
}

func readMappingPolicy(e document.Element) (NameIDPolicy, error) {
	p := NameIDPolicy{Format: xmlutil.Attr(e, nameFormat), SPNameQualifier: xmlutil.Attr(e, nameSPNameQualifier)}
	if e.Name() != xmlutil.Name(ProtocolNamespace, xmlNameNameIDPolicy) || xmlutil.Attrs(e, nil, []string{nameFormat, nameSPNameQualifier, xmlNameAllowCreate}) != nil || !xmlutil.EmptyContent(e) {
		return p, ErrProfile
	}

	v, err := xmlutil.BoolAttr(e, xmlNameAllowCreate)
	if err != nil {
		return p, err
	}

	p.AllowCreate = v
	_, err = mappingPolicyNode(p)

	return p, err
}

// CheckMappedPolicy checks plaintext output against the requested format and
// federation. For opaque EncryptedID the authoritative backend must enforce the
// policy before encrypting; the requesting entity may not hold the target's key.
func CheckMappedPolicy(ctx context.Context, d *document.Document, p NameIDPolicy) error {
	if ctx == nil || d == nil {
		return ErrProfile
	}

	if err := mappedIdentifier(d.Root()); err != nil {
		return err
	}

	if d.Root().Name().Local == xmlNameEncryptedID {
		return ctx.Err()
	}

	id, err := readNameID(d.Root())
	if err != nil {
		return err
	}

	if p.Format == NameIDEncrypted {
		return ErrEncryption
	}

	if p.Format != "" && p.Format != NameIDUnspecified && id.Format != p.Format || p.SPNameQualifier != "" && id.SPNameQualifier != p.SPNameQualifier {
		return ErrConditions
	}

	return ctx.Err()
}
