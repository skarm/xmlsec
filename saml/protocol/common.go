package protocol

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	// AssertionNamespace is the SAML 2.0 assertion namespace URI.
	AssertionNamespace = xmlutil.Assertion
	// ProtocolNamespace is the SAML 2.0 protocol namespace URI.
	ProtocolNamespace = xmlutil.Protocol
	// Bearer is the SAML bearer subject-confirmation method URI.
	Bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer" // #nosec G101 -- This standard namespace URI is not a credential.
	// NameIDUnspecified is the unspecified SAML NameID format URI.
	NameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	// NameIDPersistent is the persistent SAML NameID format URI.
	NameIDPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	// NameIDTransient is the transient SAML NameID format URI.
	NameIDTransient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	// AttributeUnspecified is the SAML unspecified attribute name format URI.
	AttributeUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
	// Success is the SAML successful response status URI.
	Success = "urn:oasis:names:tc:SAML:2.0:status:Success"
)

// NameIDEmail is the email-address SAML NameID format URI.
const NameIDEmail = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

var (
	// ErrProfile reports SAML profile rejected.
	ErrProfile = errors.New("SAML profile rejected")
	// ErrSignature reports SAML signature rejected.
	ErrSignature = errors.New("SAML signature rejected")
	// ErrConditions reports SAML conditions rejected.
	ErrConditions = errors.New("SAML conditions rejected")
	// ErrCorrelation reports SAML request correlation rejected.
	ErrCorrelation = errors.New("SAML request correlation rejected")
)

// Limits bounds message age, assertion lifetime and attribute values. Zero fields
// select profile defaults.
type Limits struct {
	// MaxMessageAge bounds response and request age; zero selects five minutes.
	MaxMessageAge time.Duration
	// MaxAssertionLifetime bounds assertion validity; zero selects ten minutes.
	MaxAssertionLifetime time.Duration
	// ClockSkew permits time tolerance; zero permits none, with a five-minute maximum.
	ClockSkew time.Duration
	// MaxAttributes bounds assertion attributes; zero selects 64, with a maximum of 512.
	MaxAttributes int
	// MaxValuesPerAttribute bounds values in one attribute; zero selects 32, with a maximum of 128.
	MaxValuesPerAttribute int
	// MaxValueBytes bounds each attribute value; zero selects 4096, with a 64 KiB maximum.
	MaxValueBytes int
}

// SigningKey pairs a local signer with its matching DER certificate and XML signature
// policy.
type SigningKey struct {
	// Key is the local signing key. Its public key must match CertificateDER.
	Key crypto.Signer
	// CertificateDER is the matching DER certificate included as a key description.
	CertificateDER []byte
	// SignatureMethod selects the XML signature algorithm. Empty selects RSA-SHA256
	// for RSA keys or ECDSA-SHA256 for ECDSA keys.
	SignatureMethod string
	// Policy sets signature algorithms and key limits. Zero selects xmldsig.DefaultPolicy.
	Policy xmldsig.Policy
}

func normalize(l Limits) (Limits, error) {
	if l.MaxMessageAge == 0 {
		l.MaxMessageAge = 5 * time.Minute
	}

	if l.MaxAssertionLifetime == 0 {
		l.MaxAssertionLifetime = 10 * time.Minute
	}

	if l.MaxAttributes == 0 {
		l.MaxAttributes = 64
	}

	if l.MaxValuesPerAttribute == 0 {
		l.MaxValuesPerAttribute = 32
	}

	if l.MaxValueBytes == 0 {
		l.MaxValueBytes = 4096
	}

	if l.MaxMessageAge <= 0 || l.MaxMessageAge > time.Hour || l.MaxAssertionLifetime <= 0 || l.MaxAssertionLifetime > time.Hour || l.ClockSkew < 0 || l.ClockSkew > 5*time.Minute || l.MaxAttributes < 1 || l.MaxAttributes > 512 || l.MaxValuesPerAttribute < 1 || l.MaxValuesPerAttribute > 128 || l.MaxValueBytes < 1 || l.MaxValueBytes > 64<<10 {
		return l, ErrProfile
	}

	return l, nil
}

func header(e document.Element, local string, at time.Time, l Limits) (string, time.Time, error) {
	if e.Name() != xmlutil.Name(ProtocolNamespace, local) || xmlutil.Attr(e, nameVersion) != version20 || !profile.ID(xmlutil.Attr(e, "ID")) {
		return "", time.Time{}, ErrProfile
	}

	t, err := profile.ParseTime(xmlutil.Attr(e, nameIssueInstant))
	if err != nil || t.After(at.Add(l.ClockSkew)) || t.Before(at.Add(-l.MaxMessageAge-l.ClockSkew)) {
		return "", time.Time{}, ErrConditions
	}

	return xmlutil.Attr(e, "ID"), t, nil
}

func issuer(e document.Element, expected string) error {
	if e.Name() != xmlutil.Name(AssertionNamespace, "Issuer") {
		return ErrProfile
	}

	s, er := xmlutil.Simple(e, 2048)
	if er != nil || s != expected {
		return ErrProfile
	}

	return nil
}

func targetSignature(ctx context.Context, d *document.Document, n document.Element, keys []crypto.PublicKey, p xmldsig.Policy) error {
	if _, e := xmlsig.Verify(ctx, d, n, keys, p); e != nil {
		return fmt.Errorf("%w: %w", ErrSignature, e)
	}

	return nil
}

func allowed(s string, set []string) bool {
	return slices.Contains(set, s)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}

	return b
}

func timeWindow(start, end, at time.Time, l Limits) error {
	if start.IsZero() || end.IsZero() || !start.Before(end) || end.Sub(start) > l.MaxAssertionLifetime || at.Add(l.ClockSkew).Before(start) || !at.Add(-l.ClockSkew).Before(end) {
		return ErrConditions
	}

	return nil
}

func signing(k SigningKey) (xmlsig.SigningKey, error) {
	if nilcheck.IsNil(k.Key) {
		return xmlsig.SigningKey{}, ErrSignature
	}

	if e := signature.Key(k.Key.Public()); e != nil {
		return xmlsig.SigningKey{}, e
	}

	method := k.SignatureMethod
	if method == "" {
		switch k.Key.Public().(type) {
		case *rsa.PublicKey:
			method = xmldsig.RSASHA256
		case *ecdsa.PublicKey:
			method = xmldsig.ECDSASHA256
		default:
			return xmlsig.SigningKey{}, ErrSignature
		}
	}

	return xmlsig.SigningKey{Key: k.Key, CertificateDER: k.CertificateDER, Method: method, Policy: k.Policy}, nil
}

func signingCount(d *document.Document, n int) error {
	if len(xmldsig.Signatures(d)) != n {
		return ErrProfile
	}

	return nil
}
