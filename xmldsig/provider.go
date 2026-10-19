package xmldsig

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
)

// ContextSigner uses crypto.Signer's input and output conventions: hashed input
// for nonzero HashFunc, full message for pure Ed25519 (HashFunc==0), ECDSA output
// encoded as ASN.1 DER. Providers must honor cancellation themselves. The XMLDSig
// layer checks their output with the supplied public key before releasing it.
type ContextSigner interface {
	// Public returns the public key corresponding to the signing key.
	Public() crypto.PublicKey
	// Sign follows crypto.Signer conventions for input, randomness, options and
	// output, and must honor cancellation.
	Sign(context.Context, io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

// AdaptContextSigner adapts a trusted context-aware provider while preserving cancellation
// and optional PSS support. The adapter passes operation contexts in XMLDSig,
// CMS, PKI and timestamp signing. Calls through crypto.Signer.Sign use a background context.
func AdaptContextSigner(provider ContextSigner) (crypto.Signer, error) {
	if nilcheck.IsNil(provider) {
		return nil, ErrKey
	}

	base := signature.SignerAdapter{Provider: provider}
	if extended, ok := provider.(ParameterizedPSSSigner); ok {
		return parameterizedContextSignerAdapter{SignerAdapter: base, pss: extended}, nil
	}

	return base, nil
}

// SignMessage applies an explicitly selected XMLDSig SignatureMethod to exact
// message bytes. It does NOT parse or validate XML or establish application trust.
// This primitive is useful for protocol bindings that sign something other than
// SignedInfo (e.g. SAML HTTP-Redirect). ECDSA output is XMLDSig r||s, not DER.
func SignMessage(ctx context.Context, message []byte, signer crypto.Signer, method string, policy Policy) ([]byte, error) {
	return SignMessageReader(ctx, bytes.NewBuffer(message), signer, method, policy)
}

// SignMessageReader signs exact bytes from src, retaining only a digest for
// RSA/ECDSA/Ed25519ph and the complete bounded message for pure Ed25519.
// It leaves src open.
func SignMessageReader(ctx context.Context, src io.Reader, signer crypto.Signer, method string, policy Policy) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrPolicy)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if nilcheck.IsNil(signer) {
		return nil, ErrKey
	}

	p, err := normalizePolicy(policy)
	if err != nil {
		return nil, err
	}

	if !permits(p.AllowedSignatureMethods, method) || nilcheck.IsNil(src) {
		return nil, fmt.Errorf("%w: message signing policy", ErrPolicy)
	}

	key := signer.Public()
	if err := validateKey(key, p); err != nil {
		return nil, err
	}

	if _, mac := macHash(method); mac || method == RSAPSS {
		return nil, ErrAlgorithm
	}

	if err := matchKeyAlgorithm(method, key); err != nil {
		return nil, err
	}

	credential := signatureCredential{public: key, signer: signer}
	spec := signatureSpec{algorithm: method}

	digest, err := credential.readInput(ctx, spec, src, p.MaxCanonicalBytes)
	if err != nil {
		return nil, err
	}

	return credential.signPrepared(ctx, spec, digest)
}

// VerifyMessage validates only a signature over exact message bytes, not XML,
// certificates, replay state or protocol semantics. The key is caller-trusted.
func VerifyMessage(ctx context.Context, message, value []byte, key crypto.PublicKey, method string, policy Policy) error {
	return VerifyMessageReader(ctx, bytes.NewBuffer(message), value, key, method, policy)
}

// VerifyMessageReader verifies exact src bytes, hashing RSA/ECDSA/Ed25519ph input
// incrementally. Pure Ed25519 retains the complete bounded message. It leaves src open.
func VerifyMessageReader(ctx context.Context, src io.Reader, value []byte, key crypto.PublicKey, method string, policy Policy) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrPolicy)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	p, err := normalizePolicy(policy)
	if err != nil {
		return err
	}

	if !permits(p.AllowedSignatureMethods, method) || nilcheck.IsNil(src) {
		return fmt.Errorf("%w: message verification policy", ErrPolicy)
	}

	if err := validateKey(key, p); err != nil {
		return err
	}

	if _, mac := macHash(method); mac || method == RSAPSS {
		return ErrAlgorithm
	}

	if err := matchKeyAlgorithm(method, key); err != nil {
		return err
	}

	credential := signatureCredential{public: key}
	spec := signatureSpec{algorithm: method}

	digest, err := credential.readInput(ctx, spec, src, p.MaxCanonicalBytes)
	if err != nil {
		return err
	}

	if err := credential.verifyPrepared(spec, digest, value); err != nil {
		return err
	}

	return ctx.Err()
}

// The adapter advertises the extended capability only when the provider has it.
type parameterizedContextSignerAdapter struct {
	signature.SignerAdapter
	pss ParameterizedPSSSigner
}

func (a parameterizedContextSignerAdapter) SignPSS(ctx context.Context, r io.Reader, digest []byte, p PSSParameters) ([]byte, error) {
	return a.pss.SignPSS(ctx, r, digest, p)
}
