package cms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/pki"
)

// VerifyOptions binds content interpretation to the caller's expectation.
// Certificate binding checks ESS, independently of PKIX trust.
type VerifyOptions struct {
	// ExpectedContentType is required and must match the encapsulated content type.
	ExpectedContentType asn1.ObjectIdentifier
	// DetachedContent is required for detached data and must be nil for embedded data.
	// A pointer to an empty slice supplies an empty detached message.
	// VerifyReader takes its detached reader separately; leave this field nil there.
	DetachedContent *[]byte
	// DiscardContent omits message bytes from Result while retaining ContentSize.
	// Verification still authenticates the complete embedded or detached message.
	DiscardContent bool
	// RequireCertificateBinding requires an authenticated ESS certificate binding,
	// independently of PKIX trust.
	RequireCertificateBinding bool
	// AllowLegacyESSCertID permits the SHA-1 ESSCertID certificate identifier.
	// It does not enable SHA-1 CMS signatures.
	AllowLegacyESSCertID bool
}

// SignerResult authenticates one caller-selected certificate and signed
// attributes. It does not establish a certificate path or a trusted signing time.
type SignerResult struct {
	certificate []byte
	signed      []Attribute
	bound       bool
	trust       *pki.Result
}

// CertificateDER returns an owned copy of the certificate DER.
func (r SignerResult) CertificateDER() []byte { return bytes.Clone(r.certificate) }

// SignedAttributes returns an owned copy of the authenticated signed attributes.
func (r SignerResult) SignedAttributes() []Attribute { return cloneAttributes(r.signed) }

// CertificateBound returns whether signed ESS attributes bind the exact signer
// certificate.
func (r SignerResult) CertificateBound() bool { return r.bound }

// Result is returned only after every signer and the content have been checked.
// Accessors return copies; a Result alone makes no claim about PKIX trust.
type Result struct {
	content     []byte
	contentSize int64
	contentType asn1.ObjectIdentifier
	signers     []SignerResult
}

// Content returns an owned copy of retained authenticated content. A detached
// VerifyReader result does not retain the message and returns nil.
func (r *Result) Content() []byte {
	if r == nil {
		return nil
	}

	return bytes.Clone(r.content)
}

// ContentSize returns the number of authenticated message bytes, including
// detached content consumed by VerifyReader.
func (r *Result) ContentSize() int64 {
	if r == nil {
		return 0
	}

	return r.contentSize
}

// ContentType returns an owned copy of the content-type object identifier.
func (r *Result) ContentType() asn1.ObjectIdentifier {
	if r == nil {
		return nil
	}

	return append(asn1.ObjectIdentifier(nil), r.contentType...)
}

// Signers returns an owned slice of immutable signer results.
func (r *Result) Signers() []SignerResult {
	if r == nil {
		return nil
	}

	return append([]SignerResult(nil), r.signers...)
}

// Verify authenticates ALL signers against exactly the caller-selected certs.
// It does not infer trust, perform PKIX or interpret unknown attribute semantics.
func (s *SignedData) Verify(ctx context.Context, expected [][]byte, opt VerifyOptions) (*Result, error) {
	var source io.Reader
	if opt.DetachedContent != nil {
		source = bytes.NewReader(*opt.DetachedContent)
	}

	options := opt
	options.DetachedContent = nil

	result, err := s.VerifyReader(ctx, source, expected, options)
	if err == nil && s.detached && !opt.DiscardContent {
		result.content = bytes.Clone(*opt.DetachedContent)
	}

	return result, err
}

// VerifyReader authenticates all signers while reading detached content once
// without retaining it. For embedded content src must be nil; the stored content
// is hashed directly. opt.DetachedContent must be nil. It leaves src open and
// returns no Result after a read, cancellation, budget or authentication failure.
func (s *SignedData) VerifyReader(ctx context.Context, src io.Reader, expected [][]byte, opt VerifyOptions) (*Result, error) {
	if s == nil || ctx == nil || len(s.signers) == 0 || len(s.raw) == 0 || len(expected) != len(s.signers) || !s.contentType.Equal(opt.ExpectedContentType) || opt.DetachedContent != nil {
		return nil, ErrPolicy
	}

	if s.detached == nilcheck.IsNil(src) {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	certs, err := parseVerificationCertificates(ctx, expected)
	if err != nil {
		return nil, err
	}

	if !s.detached {
		src = bytes.NewReader(s.content)
	}

	hashes := make([]crypto.Hash, 0, len(s.signers))
	for _, signer := range s.signers {
		h, err := signature.Hash(signer.digest, false)
		if err != nil {
			return nil, ErrPolicy
		}

		hashes = append(hashes, h)
	}

	digests, size, err := hashContent(ctx, src, hashes, s.limits.MaxContentBytes, nil)
	if err != nil {
		return nil, err
	}

	return s.verifyDigests(ctx, certs, opt, digests, size)
}

func parseVerificationCertificates(ctx context.Context, expected [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(expected))
	seen := certificateSet{}

	for _, raw := range expected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if len(raw) > 1<<20 || !seen.add(raw) {
			return nil, ErrCertificate
		}

		certificate, err := x509cert.ParseDefault(bytes.Clone(raw))
		if err != nil {
			return nil, ErrCertificate
		}

		if err := signature.Key(certificate.PublicKey); err != nil {
			return nil, err
		}

		certs = append(certs, certificate)
	}

	return certs, nil
}

func (s *SignedData) verifyDigests(ctx context.Context, certs []*x509.Certificate, opt VerifyOptions, digests map[crypto.Hash][]byte, size int64) (*Result, error) {
	signers, err := s.verifySigners(ctx, certs, opt, digests)
	if err != nil {
		return nil, err
	}

	result := &Result{contentSize: size, contentType: append(asn1.ObjectIdentifier(nil), s.contentType...), signers: signers}
	for i := range result.signers {
		result.signers[i].signed = cloneAttributes(result.signers[i].signed)
	}
	// Do not keep a larger container alive through a subslice in a Result.
	if !opt.DiscardContent {
		result.content = bytes.Clone(s.content)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func (s *SignedData) verifySigners(ctx context.Context, certs []*x509.Certificate, opt VerifyOptions, digests map[crypto.Hash][]byte) ([]SignerResult, error) {
	var signers []SignerResult

	used := make([]bool, len(certs))

	for _, p := range s.signers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		index, err := signerCertificateIndex(ctx, p, certs)
		if err != nil {
			return nil, err
		}

		if used[index] {
			return nil, ErrCertificate
		}

		used[index] = true

		signer, err := s.verifySigner(ctx, p, certs[index], digests, opt)
		if err != nil {
			return nil, err
		}

		signers = append(signers, signer)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return signers, nil
}

func signerCertificateIndex(ctx context.Context, p parsedSigner, certs []*x509.Certificate) (int, error) {
	index := -1

	for i, certificate := range certs {
		matched, err := certificateMatch(ctx, p, certificate)
		if err != nil {
			return -1, err
		}

		if !matched {
			continue
		}

		if index != -1 {
			return -1, ErrCertificate
		}

		index = i
	}

	if index < 0 {
		return -1, ErrCertificate
	}

	return index, nil
}

func (s *SignedData) verifySigner(ctx context.Context, p parsedSigner, cert *x509.Certificate, digests map[crypto.Hash][]byte, opt VerifyOptions) (SignerResult, error) {
	h, err := signature.Hash(p.digest, false)
	if err != nil {
		return SignerResult{}, ErrPolicy
	}

	algorithm, err := normalizeSignature(p.alg, h)
	if err != nil {
		return SignerResult{}, err
	}

	if len(p.signed) == 0 {
		if !s.contentType.Equal(oidData()) {
			return SignerResult{}, ErrSyntax
		}

		err = signature.VerifyDigest(cert.PublicKey, algorithm, digests[h], p.sig)
	} else {
		if err = verifyContentDigest(p.signed, s.contentType, digests[h]); err != nil {
			return SignerResult{}, err
		}

		if err = verifyProtection(p.signed, p.alg, h); err != nil {
			return SignerResult{}, err
		}

		state := h.New()
		_, _ = state.Write([]byte{0x31})

		writer := &streamio.Writer{Context: ctx, Target: state, Limit: int64(s.limits.MaxBytes), LimitError: ErrPolicy}
		if err := writeDERPart(writer, p.signedInput[1:]); err != nil {
			return SignerResult{}, err
		}

		err = signature.VerifyDigest(cert.PublicKey, algorithm, state.Sum(nil), p.sig)
	}

	if err != nil {
		return SignerResult{}, fmt.Errorf("%w: %w", ErrSignature, err)
	}

	bound, err := verifyESS(ctx, p.signed, cert, opt.AllowLegacyESSCertID)
	if err != nil {
		return SignerResult{}, err
	}

	if opt.RequireCertificateBinding && !bound {
		return SignerResult{}, ErrCertificate
	}

	return SignerResult{certificate: cert.Raw, signed: p.signed, bound: bound}, nil
}

func normalizeSignature(aid pkix.AlgorithmIdentifier, h crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	if aid.Algorithm.Equal(signature.RSA()) {
		if !signature.NullOrAbsent(aid.Parameters) {
			return aid, ErrPolicy
		}

		n := 11

		switch h {
		case crypto.SHA256:
		case crypto.SHA384:
			n = 12
		case crypto.SHA512:
			n = 13
		default:
			return aid, ErrPolicy
		}

		return pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, n}, Parameters: asn1.NullRawValue}, nil
	}

	actual, _, e := signature.Details(aid)
	if e != nil || actual != h {
		return aid, ErrPolicy
	}

	return aid, nil
}

func verifyContentDigest(attrs []Attribute, contentType asn1.ObjectIdentifier, want []byte) error {
	ct, ok, err := attributeValue(attrs, oidContentType())
	if err != nil || !ok {
		return ErrSyntax
	}

	var oid asn1.ObjectIdentifier
	if der.Unmarshal(ct, &oid) != nil || !oid.Equal(contentType) {
		return ErrSignature
	}

	md, ok, err := attributeValue(attrs, oidMessageDigest())
	if err != nil || !ok {
		return ErrSyntax
	}

	var digest []byte
	if der.Unmarshal(md, &digest) != nil {
		return ErrSyntax
	}

	if !bytes.Equal(digest, want) {
		return ErrSignature
	}

	return nil
}
