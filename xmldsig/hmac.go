package xmldsig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
)

// HMACResult authenticates references with a shared secret. Every holder of the
// secret can produce the same MAC; it does NOT identify a unique signer or
// provide non-repudiation. No key fingerprint, key bytes or key-derived identifier
// is exposed. Like SignatureResult, it exists only after ALL required checks.
type HMACResult struct{ checked *SignatureResult }

// VerifyHMACSignature never obtains a secret from KeyInfo, a certificate or an
// embedded KeyName. Caller policy must explicitly allow HMAC (e.g. HMACPolicy).
func VerifyHMACSignature(ctx context.Context, doc *document.Document, selected document.Element, secret []byte, opt SignatureOptions) (*HMACResult, error) {
	result, _, err := VerifyHMACSignatureDetailed(ctx, doc, selected, secret, opt)
	return result, err
}

// VerifyHMACSignatureDetailed verifies a selected HMAC signature and all required
// references, returning diagnostic checks on failure.
func VerifyHMACSignatureDetailed(ctx context.Context, doc *document.Document, selected document.Element, secret []byte, opt SignatureOptions) (*HMACResult, *VerificationReport, error) {
	if ctx == nil {
		return nil, nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	key, err := copySecret(secret)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)

	r, report, err := verifySignatureDetailed(ctx, doc, selected, signatureCredential{mac: true, secret: key}, opt)
	if err != nil {
		return nil, report, err
	}

	return &HMACResult{checked: r}, report, nil
}

// Signature returns the MAC-validated Signature element in the verified snapshot.
func (r *HMACResult) Signature() document.Element {
	if r == nil {
		return document.Element{}
	}

	return r.checked.Signature()
}

// SignatureMethod returns the authenticated signature algorithm URI.
func (r *HMACResult) SignatureMethod() string {
	if r == nil {
		return ""
	}

	return r.checked.SignatureMethod()
}

// OutputLength returns the HMACOutputLength parameter in bits; zero denotes the full digest.
func (r *HMACResult) OutputLength() int {
	if r == nil || r.checked == nil {
		return 0
	}

	return r.checked.parameters.HMACOutputLength
}

// References returns an owned slice of immutable validated reference results.
func (r *HMACResult) References() []ReferenceResult {
	if r == nil {
		return nil
	}

	return r.checked.References()
}

// Manifests returns an owned slice of immutable validated Manifest results.
func (r *HMACResult) Manifests() []ManifestResult {
	if r == nil {
		return nil
	}

	return r.checked.Manifests()
}

// CoversElement reports whether a validated reference authenticates the complete element
// under its coverage rules.
func (r *HMACResult) CoversElement(e document.Element) bool {
	if r == nil {
		return false
	}

	return r.checked.CoversElement(e)
}

// SignHMACTemplate fills the selected template with an HMAC, never a public-key
// signature. Reference processing, preservation, resource replay and serialized
// self-verification are shared with SignTemplate. Owned key copies are cleared
// when the operation returns; Go does not provide a complete secure-memory API.
func SignHMACTemplate(ctx context.Context, doc *document.Document, selected document.Element, secret []byte, opt TemplateSignOptions) (*document.Document, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	key, err := copySecret(secret)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	return signTemplate(ctx, doc, selected, signatureCredential{mac: true, secret: key}, opt)
}

// ComputeHMAC and VerifyHMAC operate on exact bytes, not XML or certificates.
// outputBits=0 requests the full tag. Truncation requires explicit policy opt-in.
func ComputeHMAC(ctx context.Context, message, secret []byte, method string, outputBits int, policy Policy) ([]byte, error) {
	return ComputeHMACReader(ctx, bytes.NewReader(message), secret, method, outputBits, policy)
}

// ComputeHMACReader authenticates src incrementally with bounded working storage.
// It snapshots the secret, enforces the input budget and leaves src open.
func ComputeHMACReader(ctx context.Context, src io.Reader, secret []byte, method string, outputBits int, policy Policy) ([]byte, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p, err := normalizePolicy(policy)
	if err != nil {
		return nil, err
	}

	s, err := normalizeSignatureSpec(method, SignatureParameters{HMACOutputLength: outputBits})
	if err != nil {
		return nil, err
	}

	if err = s.validatePolicy(p); err != nil {
		return nil, err
	}

	if nilcheck.IsNil(src) {
		return nil, ErrPolicy
	}

	c := signatureCredential{secret: secret, mac: true}
	if err = c.validate(s, p); err != nil {
		return nil, err
	}

	owned, err := copySecret(secret)
	if err != nil {
		return nil, err
	}
	defer clear(owned)

	c.secret = owned

	tag, err := c.readInput(ctx, s, src, p.MaxCanonicalBytes)
	if err != nil {
		return nil, err
	}

	if err = ctx.Err(); err != nil {
		clear(tag)
		return nil, err
	}

	return tag, nil
}

// VerifyHMAC authenticates a message using the explicit HMAC algorithm and policy-approved
// output length.
func VerifyHMAC(ctx context.Context, message, value, secret []byte, method string, outputBits int, policy Policy) error {
	return VerifyHMACReader(ctx, bytes.NewReader(message), value, secret, method, outputBits, policy)
}

// VerifyHMACReader authenticates src incrementally without retaining the message.
// The reader remains caller-owned.
func VerifyHMACReader(ctx context.Context, src io.Reader, value, secret []byte, method string, outputBits int, policy Policy) error {
	expected, err := ComputeHMACReader(ctx, src, secret, method, outputBits, policy)
	if err != nil {
		return err
	}
	defer clear(expected)

	if !hmac.Equal(expected, value) {
		return fmt.Errorf("%w: HMAC", ErrSignature)
	}

	return ctx.Err()
}

// Internal credential modes are selected only by distinct public APIs. A byte
// slice passed as crypto.PublicKey cannot become an HMAC secret.
type signatureCredential struct {
	public crypto.PublicKey
	signer crypto.Signer
	secret []byte
	mac    bool
}

func (c signatureCredential) validate(s signatureSpec, p Policy) error {
	if c.mac {
		if _, ok := macHash(s.algorithm); !ok {
			return fmt.Errorf("%w: shared-secret API requires HMAC", ErrKey)
		}

		if len(c.secret) < p.MinHMACKeyBytes || len(c.secret) > p.MaxHMACKeyBytes {
			return fmt.Errorf("%w: HMAC key length outside policy", ErrKey)
		}

		return nil
	}

	return s.validatePublicKey(c.public, p)
}

func (c signatureCredential) validateSigner(s signatureSpec) error {
	if c.mac {
		return nil
	}

	if nilcheck.IsNil(c.signer) {
		return ErrKey
	}

	return s.validateSigner(c.signer)
}

func (c signatureCredential) prepareInput(ctx context.Context, s signatureSpec, emit func(io.Writer) error) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if c.mac {
		h, _ := macHash(s.algorithm)

		mac := hmac.New(h.New, c.secret)
		if err := emit(mac); err != nil {
			return nil, err
		}

		full := mac.Sum(nil)
		n := s.hmacBits / 8
		clear(full[n:])

		return full[:n:n], ctx.Err()
	}

	if s.pss == nil {
		if _, mac := macHash(s.algorithm); mac || s.algorithm == RSAPSS {
			return nil, ErrAlgorithm
		}

		if err := matchKeyAlgorithm(s.algorithm, c.public); err != nil {
			return nil, err
		}
	}

	if s.algorithm == Ed25519 {
		var message bytes.Buffer
		// Keep copies chunked: Buffer.ReadFrom otherwise reserves more storage
		// merely to probe EOF after a message exactly fills its capacity.
		if err := emit(struct{ io.Writer }{&message}); err != nil {
			return nil, err
		}

		return message.Bytes(), ctx.Err()
	}

	digest := s.hash().New()
	if err := emit(digest); err != nil {
		return nil, err
	}

	return digest.Sum(nil), ctx.Err()
}

func (c signatureCredential) readInput(ctx context.Context, s signatureSpec, src io.Reader, maximum int) ([]byte, error) {
	// Pure Ed25519 consumes the complete message. Borrow already resident bytes
	// rather than copying them through a second buffer. SignDigest isolates
	// external providers; the standard Ed25519 implementation does not mutate input.
	if buffer, ok := src.(*bytes.Buffer); ok && s.algorithm == Ed25519 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if buffer.Len() > maximum {
			return nil, ErrPolicy
		}

		return buffer.Next(buffer.Len()), nil
	}

	return c.prepareInput(ctx, s, func(dst io.Writer) error {
		_, err := io.Copy(dst, &streamio.Reader{Context: ctx, Source: src, Limit: int64(maximum), LimitError: ErrPolicy})
		return err
	})
}

func (c signatureCredential) verifyPrepared(s signatureSpec, digest, value []byte) error {
	if c.mac {
		if !hmac.Equal(digest, value) {
			return fmt.Errorf("%w: HMAC", ErrSignature)
		}

		return nil
	}

	return s.verifyPrepared(c.public, digest, value)
}

func (c signatureCredential) signPrepared(ctx context.Context, s signatureSpec, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if c.mac {
		return digest, nil
	}

	return s.signPrepared(ctx, c.signer, c.public, digest)
}

// hash selects the content digest; zero means Ed25519's complete message.
func (s signatureSpec) hash() crypto.Hash {
	if s.pss != nil {
		return s.pss.Hash
	}

	h, _, _ := signatureAlgorithm(s.algorithm)

	return h
}

// copySecret bounds allocation before cloning, independently of caller policy.
// Key length is not a test of entropy. Applications must generate random secrets.
func copySecret(secret []byte) ([]byte, error) {
	if len(secret) < 32 || len(secret) > 1<<20 {
		return nil, fmt.Errorf("%w: HMAC secret length", ErrKey)
	}

	return bytes.Clone(secret), nil
}

func verifyRequirement(ctx context.Context, doc *document.Document, selected document.Element, req SignatureRequirement, opt SignatureOptions) error {
	if req.SharedSecret != nil {
		if !nilcheck.IsNil(req.PublicKey) {
			return fmt.Errorf("%w: preservation must choose exactly one trust model", ErrPolicy)
		}

		_, err := VerifyHMACSignature(ctx, doc, selected, req.SharedSecret, opt)

		return err
	}

	_, err := VerifySignature(ctx, doc, selected, req.PublicKey, opt)

	return err
}
