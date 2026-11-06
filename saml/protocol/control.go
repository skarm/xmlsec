package protocol

import (
	"context"
	"crypto"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

// Local SAML vocabulary tokens shared by protocol producers and parsers. Each call site still verifies the assertion/protocol namespace or resolves the QName prefix.
const (
	xmlNameArtifact  = "Artifact"
	xmlNameReason    = "Reason"
	xmlNameTerminate = "Terminate"
)

// Control-message text is bounded in UTF-8 bytes in both producers and parsers.
// Equal ceilings remain independent for artifacts, identifier updates and sessions.
const (
	maximumArtifactTextBytes  = 4096
	maximumNewIdentifierBytes = 4096
	maximumSessionIndexBytes  = 4096
)

// LogoutRequest terminates the named sessions. With no SessionIndexes all
// sessions for this provider and identifier are selected (Core 3.7.3.1).
type LogoutRequest struct {
	MessageHeader
	// NameID identifies the subject whose peer sessions are selected.
	NameID NameIdentifier
	// SessionIndexes selects exact peer session indices. Empty selects all sessions
	// for this provider and identifier.
	SessionIndexes []string
	// Reason is an optional URI describing the logout reason.
	Reason string
	// NotOnOrAfter is the optional exclusive request expiration time.
	NotOnOrAfter time.Time
	// Encryption, when set, must select EncryptNameID.
	Encryption *EncryptionOptions
}

// VerifiedLogoutRequest contains an authenticated request, never caller-supplied
// claims. Replay protection and application session termination remain necessary.
type VerifiedLogoutRequest struct{ request LogoutRequest }

// Request returns an owned copy of the authenticated plaintext request.
func (r *VerifiedLogoutRequest) Request() LogoutRequest {
	s := r.request
	s.SessionIndexes = slices.Clone(s.SessionIndexes)

	return s
}

// ManageNameIDRequest changes an identifier value or ends its use between two
// providers. Exactly one of NewID and Terminate must be selected. For an SP
// requester NewID changes SPProvidedID; for an IdP it changes NameID content.
type ManageNameIDRequest struct {
	MessageHeader
	// NameID is the current complete identifier binding.
	NameID NameIdentifier
	// NewID is the replacement NameID value for an IdP requester or SPProvidedID
	// for an SP requester. It must be empty when Terminate is true.
	NewID string
	// Terminate ends the identifier binding instead of assigning NewID.
	Terminate bool
	// Encryption encrypts both the existing NameID and NewID, when present.
	Encryption *EncryptionOptions
}

// VerifiedManageNameIDRequest contains an authenticated identifier change.
type VerifiedManageNameIDRequest struct{ request ManageNameIDRequest }

// Request returns the authenticated plaintext request.
func (r *VerifiedManageNameIDRequest) Request() ManageNameIDRequest { return r.request }

// ArtifactResolve requests a protocol message represented by an opaque artifact.
type ArtifactResolve struct {
	MessageHeader
	// Artifact is the base64-encoded artifact to resolve.
	Artifact string
}

// VerifiedArtifactResolve contains an authenticated artifact resolution request.
type VerifiedArtifactResolve struct{ request ArtifactResolve }

// Request returns the authenticated request.
func (r *VerifiedArtifactResolve) Request() ArtifactResolve { return r.request }

// SignLogoutRequest signs a logout request, encrypting its identifier first when
// requested. Session order is retained and duplicate indices are rejected.
func SignLogoutRequest(ctx context.Context, s LogoutRequest, key SigningKey) (*document.Document, error) {
	const (
		maximumLogoutSessionIndexes = 128
	)

	if len(s.SessionIndexes) > maximumLogoutSessionIndexes || !logoutReason(s.Reason) || !s.NotOnOrAfter.IsZero() && !s.IssueInstant.Before(s.NotOnOrAfter) {
		return nil, ErrProfile
	}

	n, err := exchangeRoot(s.MessageHeader, lexicon.SAMLElementLogoutRequest)
	if err != nil {
		return nil, err
	}

	if s.Reason != "" {
		xmlutil.Set(n, xmlNameReason, s.Reason)
	}

	if !s.NotOnOrAfter.IsZero() {
		xmlutil.Set(n, nameNotOnOrAfter, profile.Time(s.NotOnOrAfter))
	}

	id, err := nameIDNode(s.NameID)
	if err != nil {
		return nil, err
	}

	xmlutil.Add(n, id)

	seen := map[string]bool{}
	for _, index := range s.SessionIndexes {
		if index == "" || len(index) > maximumSessionIndexBytes || seen[index] {
			return nil, ErrProfile
		}

		seen[index] = true
		c := xmlutil.Node(prefixProtocol, ProtocolNamespace, xmlNameSessionIndex)
		xmlutil.Text(c, index)
		xmlutil.Add(n, c)
	}

	return signExchange(ctx, n, key, s.Encryption)
}

// VerifyLogoutRequest authenticates and validates a logout message before any
// encrypted identifier is processed or application session is invalidated.
func VerifyLogoutRequest(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o ExchangeOptions) (*VerifiedLogoutRequest, error) {
	const (
		maximumLogoutPayloadChildren = 129
	)

	h, cs, err := verifyExchange(ctx, d, lexicon.SAMLElementLogoutRequest, keys, o, []string{xmlNameReason, nameNotOnOrAfter}, false)
	if err != nil {
		return nil, err
	}

	s := LogoutRequest{MessageHeader: h, Reason: xmlutil.Attr(d.Root(), xmlNameReason)}
	if !logoutReason(s.Reason) {
		return nil, ErrProfile
	}

	if value, present := d.Root().Attribute(document.Name{Local: nameNotOnOrAfter}); present {
		s.NotOnOrAfter, err = profile.ParseTime(value)
		if err != nil || !h.IssueInstant.Before(s.NotOnOrAfter) || !o.At.Add(-o.Limits.ClockSkew).Before(s.NotOnOrAfter) {
			return nil, ErrConditions
		}
	}

	if len(cs) < 1 || len(cs) > maximumLogoutPayloadChildren {
		return nil, ErrProfile
	}

	d, err = decryptControl(ctx, d, cs, o.Decryption)
	if err != nil {
		return nil, err
	}

	cs, err = controlChildren(d, o.redirect)
	if err != nil {
		return nil, err
	}

	s.NameID, err = readNameID(cs[0])
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}

	for _, c := range cs[1:] {
		if c.Name() != xmlutil.Name(ProtocolNamespace, xmlNameSessionIndex) {
			return nil, ErrProfile
		}

		v, err := xmlutil.Simple(c, maximumSessionIndexBytes)
		if err != nil || v == "" || seen[v] {
			return nil, ErrProfile
		}

		seen[v] = true
		s.SessionIndexes = append(s.SessionIndexes, v)
	}

	return &VerifiedLogoutRequest{request: s}, ctx.Err()
}

// VerifyRedirectLogoutRequest validates a signed HTTP-Redirect logout request.
func VerifyRedirectLogoutRequest(ctx context.Context, query string, keys []crypto.PublicKey, o ExchangeOptions, limits binding.Options) (*VerifiedLogoutRequest, *string, error) {
	d, relay, err := exchangeRedirect(ctx, query, keys, o, limits, binding.Request)
	if err != nil {
		return nil, nil, err
	}

	o.redirect = true
	r, err := VerifyLogoutRequest(ctx, d, nil, o)

	return r, relay, err
}

// SignManageNameIDRequest signs the identifier update or termination.
func SignManageNameIDRequest(ctx context.Context, s ManageNameIDRequest, key SigningKey) (*document.Document, error) {
	if s.Terminate == (s.NewID != "") || len(s.NewID) > maximumNewIdentifierBytes || s.NameID.Format == NameIDTransient {
		return nil, ErrProfile
	}

	n, err := exchangeRoot(s.MessageHeader, lexicon.SAMLElementManageNameIDRequest)
	if err != nil {
		return nil, err
	}

	id, err := nameIDNode(s.NameID)
	if err != nil {
		return nil, err
	}

	xmlutil.Add(n, id)

	kind := xmlNameNewID
	if s.Terminate {
		kind = xmlNameTerminate
	}

	c := xmlutil.Node(prefixProtocol, ProtocolNamespace, kind)
	if !s.Terminate {
		xmlutil.Text(c, s.NewID)
	}

	xmlutil.Add(n, c)

	return signExchange(ctx, n, key, s.Encryption)
}

// VerifyManageNameIDRequest authenticates the request before decrypting names.
func VerifyManageNameIDRequest(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o ExchangeOptions) (*VerifiedManageNameIDRequest, error) {
	const (
		managePayloadChildren = 2
	)

	h, cs, err := verifyExchange(ctx, d, lexicon.SAMLElementManageNameIDRequest, keys, o, nil, false)
	if err != nil {
		return nil, err
	}

	if len(cs) != managePayloadChildren {
		return nil, ErrProfile
	}

	d, err = decryptControl(ctx, d, cs, o.Decryption)
	if err != nil {
		return nil, err
	}

	cs, err = controlChildren(d, o.redirect)
	if err != nil {
		return nil, err
	}

	s := ManageNameIDRequest{MessageHeader: h}

	s.NameID, err = readNameID(cs[0])
	if err != nil {
		return nil, err
	}

	if s.NameID.Format == NameIDTransient {
		return nil, ErrProfile
	}

	switch cs[1].Name() {
	case xmlutil.Name(ProtocolNamespace, xmlNameNewID):
		s.NewID, err = xmlutil.Simple(cs[1], maximumNewIdentifierBytes)
		if err != nil || s.NewID == "" {
			return nil, ErrProfile
		}
	case xmlutil.Name(ProtocolNamespace, xmlNameTerminate):
		if xmlutil.Attrs(cs[1], nil, nil) != nil || !xmlutil.EmptyContent(cs[1]) {
			return nil, ErrProfile
		}

		s.Terminate = true
	default:
		return nil, ErrProfile
	}

	return &VerifiedManageNameIDRequest{request: s}, ctx.Err()
}

// VerifyRedirectManageNameIDRequest validates the exact Redirect signature.
func VerifyRedirectManageNameIDRequest(ctx context.Context, query string, keys []crypto.PublicKey, o ExchangeOptions, limits binding.Options) (*VerifiedManageNameIDRequest, *string, error) {
	d, relay, err := exchangeRedirect(ctx, query, keys, o, limits, binding.Request)
	if err != nil {
		return nil, nil, err
	}

	o.redirect = true
	r, err := VerifyManageNameIDRequest(ctx, d, nil, o)

	return r, relay, err
}

// SignArtifactResolve signs a resolution request. Artifact syntax is validated by
// the selected artifact binding; Core permits artifact formats defined elsewhere.
func SignArtifactResolve(ctx context.Context, s ArtifactResolve, key SigningKey) (*document.Document, error) {
	if len(s.Artifact) > maximumArtifactTextBytes {
		return nil, ErrProfile
	}

	n, err := exchangeRoot(s.MessageHeader, lexicon.SAMLElementArtifactResolve)
	if err != nil {
		return nil, err
	}

	c := xmlutil.Node(prefixProtocol, ProtocolNamespace, xmlNameArtifact)
	xmlutil.Text(c, s.Artifact)
	xmlutil.Add(n, c)

	return signExchange(ctx, n, key, nil)
}

// VerifyArtifactResolve authenticates and validates an artifact resolution.
func VerifyArtifactResolve(ctx context.Context, d *document.Document, keys []crypto.PublicKey, o ExchangeOptions) (*VerifiedArtifactResolve, error) {
	h, cs, err := verifyExchange(ctx, d, lexicon.SAMLElementArtifactResolve, keys, o, nil, false)
	if err != nil {
		return nil, err
	}

	if len(cs) != 1 || cs[0].Name() != xmlutil.Name(ProtocolNamespace, xmlNameArtifact) {
		return nil, ErrProfile
	}

	v, err := xmlutil.Simple(cs[0], maximumArtifactTextBytes)
	if err != nil {
		return nil, ErrProfile
	}

	return &VerifiedArtifactResolve{request: ArtifactResolve{MessageHeader: h, Artifact: v}}, nil
}

func controlChildren(d *document.Document, redirect bool) ([]document.Element, error) {
	cs, err := xmlutil.Children(d.Root())

	offset := signedMessagePrefixChildren
	if redirect {
		offset = unsignedMessagePrefixChildren
	}

	if err != nil || len(cs) <= offset {
		return nil, ErrProfile
	}

	if cs[offset].Name() == xmlutil.Name(ProtocolNamespace, xmlNameExtensions) {
		offset++
	}

	return cs[offset:], nil
}

func decryptControl(ctx context.Context, d *document.Document, cs []document.Element, options *DecryptionOptions) (*document.Document, error) {
	var state *decryptionState

	for _, c := range cs {
		var expected document.Name

		switch c.Name() {
		case xmlutil.Name(AssertionNamespace, xmlNameEncryptedID):
			expected = xmlutil.Name(AssertionNamespace, xmlNameNameID)
		case xmlutil.Name(ProtocolNamespace, xmlNameNewEncryptedID):
			expected = xmlutil.Name(ProtocolNamespace, xmlNameNewID)
		default:
			continue
		}

		if state == nil {
			var err error

			state, err = newDecryptionState(options)
			if err != nil {
				return nil, err
			}
		}
		// A previous replacement changed ownership. Re-select from the current
		// immutable snapshot rather than using stale elements.
		selected, err := xmlutil.Direct(d.Root(), c.Name())
		if err != nil {
			return nil, ErrProfile
		}

		d, err = state.decryptSAMLName(ctx, d, selected, expected, true)
		if err != nil {
			return nil, err
		}
	}

	return d, nil
}

func logoutReason(value string) bool {
	if len(value) > maximumURITextBytes || strings.ContainsAny(value, lexicon.XMLWhitespace) {
		return false
	}

	_, err := url.Parse(value)

	return err == nil
}
