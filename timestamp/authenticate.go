package timestamp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/pki"
)

// AuthenticatedToken binds an RFC 3161 assertion to a cryptographically checked
// CMS signature, ESS certificate and caller-selected imprint. It deliberately
// contains NO PKIX, revocation or historical trust result. A zero value is invalid.
// Only a complete validation workflow may promote this assertion to trusted PoE.
type AuthenticatedToken struct {
	token       *Token
	certificate []byte
	hash        crypto.Hash
	algorithm   string
	digest      [32]byte
	valid       bool
}

// Valid reports cryptographic authentication ONLY, never trust or existence.
func (a *AuthenticatedToken) Valid() bool { return a != nil && a.valid && a.token != nil }

// Token returns the immutable cryptographically authenticated token.
func (a *AuthenticatedToken) Token() *Token {
	if !a.Valid() {
		return nil
	}

	return a.token
}

// Info returns authenticated TSA claims whose trust is still to be established.
func (a *AuthenticatedToken) Info() Info {
	if !a.Valid() {
		return Info{}
	}

	return a.token.info
}

// CertificateDER returns an owned copy of the ESS-bound TSA certificate.
func (a *AuthenticatedToken) CertificateDER() []byte {
	if !a.Valid() {
		return nil
	}

	return bytes.Clone(a.certificate)
}

// TokenSHA256 identifies the exact token encoding, without changing its DER.
func (a *AuthenticatedToken) TokenSHA256() [32]byte {
	if !a.Valid() {
		return [32]byte{}
	}

	return a.digest
}

// SignatureHash returns the authenticated CMS hash algorithm.
func (a *AuthenticatedToken) SignatureHash() crypto.Hash {
	if !a.Valid() {
		return 0
	}

	return a.hash
}

// SignatureAlgorithmOID returns the normalized authenticated CMS signature OID.
func (a *AuthenticatedToken) SignatureAlgorithmOID() string {
	if !a.Valid() {
		return ""
	}

	return a.algorithm
}

// Authenticate checks format, exact imprint/nonce/policy bindings, TSA name,
// critical timeStamping-only EKU, certificate validity at GenTime and the CMS
// signature. at is the explicit current time used for configured age/future
// constraints. No certificate path, revocation check or time backdating occurs.
func (v *Verifier) Authenticate(ctx context.Context, token *Token, want Expectation, at time.Time) (*AuthenticatedToken, error) {
	if v == nil || v.trust == nil || ctx == nil || token == nil || token.signed == nil || token.Size() == 0 || token.Size() > v.maxBytes || at.IsZero() || !validImprint(want.Imprint) {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if want.Nonce != nil && (want.Nonce.Sign() <= 0 || want.Nonce.BitLen() > 256) {
		return nil, ErrPolicy
	}

	chosen, err := v.selectTSASigner(token.signed, token.signed.Certificates())
	if err != nil {
		return nil, err
	}

	certificate, err := x509cert.ParseDefault(chosen)
	if err != nil {
		return nil, ErrTrust
	}

	if err := v.validateTokenInfo(ctx, token.info, want, certificate, at); err != nil {
		return nil, err
	}

	checked, err := token.signed.Verify(ctx, [][]byte{chosen}, cms.VerifyOptions{
		ExpectedContentType: tstOID(), RequireCertificateBinding: true,
		AllowLegacyESSCertID: v.legacy, DiscardContent: true, RequireUnrestrictedCertificatePath: true,
	})
	if err != nil {
		return nil, err
	}

	signer := checked.Signers()[0]
	digest := sha256.New()

	if _, err := token.WriterTo(ctx).WriteTo(digest); err != nil {
		return nil, err
	}

	var fingerprint [32]byte
	copy(fingerprint[:], digest.Sum(nil))

	return &AuthenticatedToken{
		token:       token,
		certificate: bytes.Clone(chosen),
		hash:        signer.SignatureHash(),
		algorithm:   signer.SignatureAlgorithmOID(),
		digest:      fingerprint,
		valid:       true,
	}, nil
}

// NewHistoricalSession creates a separate operation using this verifier's exact
// immutable TSA roots, usages and responder policy. It does not validate a token
// or grant PoE. Configured lookup certificates remain untrusted intermediates.
func (v *Verifier) NewHistoricalSession(ctx context.Context, options pki.HistoricalOptions, now time.Time, evidence pki.Evidence) (*pki.HistoricalSession, error) {
	if v == nil || v.trust == nil {
		return nil, ErrPolicy
	}

	evidence.Intermediates = append([][]byte(nil), evidence.Intermediates...)

	for _, certificate := range v.certificates {
		found := false

		for _, existing := range evidence.Intermediates {
			if bytes.Equal(existing, certificate) {
				found = true
				break
			}
		}

		if !found {
			evidence.Intermediates = append(evidence.Intermediates, certificate)
		}
	}

	return v.trust.NewHistoricalSession(ctx, options, now, evidence)
}
