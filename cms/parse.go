package cms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/streamio"
)

// SignedData is an immutable parsed container. Parsing does not authenticate
// content or embedded certificates; use Verify with caller-selected certificates.
type SignedData struct {
	raw, content []byte
	contentType  asn1.ObjectIdentifier
	detached     bool
	signers      []parsedSigner
	certificates [][]byte
	limits       Limits
}

type parsedSigner struct {
	issuer           []byte
	serial           *big.Int
	ski              []byte
	digest, alg      pkix.AlgorithmIdentifier
	signed, unsigned []Attribute
	signedInput, sig []byte
}

// Parse copies a bounded definite-length container and validates supported DER
// structure and attribute placement. It performs no trust or signature checks.
func Parse(ctx context.Context, b []byte, l Limits) (*SignedData, error) {
	return ParseReader(ctx, bytes.NewReader(b), l)
}

// ParseReader reads one bounded DER container into owned storage and validates
// its structure. The complete container and embedded content remain resident;
// use detached content with VerifyReader for large messages. It leaves src open.
func ParseReader(ctx context.Context, src io.Reader, l Limits) (*SignedData, error) {
	if ctx == nil || nilcheck.IsNil(src) {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l, e := normalize(l)
	if e != nil {
		return nil, e
	}

	v, e := der.ReadSequence(ctx, src, l.MaxBytes)
	if e != nil {
		if errors.Is(e, der.ErrLimit) {
			return nil, fmt.Errorf("%w: %w", ErrPolicy, e)
		}

		return nil, fmt.Errorf("%w: %w", ErrSyntax, e)
	}

	b := v.FullBytes

	ci, e := der.Sequence(v, 2, 2)
	if e != nil || !der.OIDEqual(ci[0], oidSignedData()) {
		return nil, ErrSyntax
	}

	sd, e := der.Explicit(ci[1], 0)
	if e != nil {
		return nil, ErrSyntax
	}

	f, e := der.Sequence(sd, 4, 6)
	if e != nil {
		return nil, ErrSyntax
	}

	var version int
	if der.Decode(f[0], &version) != nil {
		return nil, ErrSyntax
	}

	digests, e := parseDigestAlgorithms(f[1], l)
	if e != nil {
		return nil, e
	}

	ec, e := der.Sequence(f[2], 1, 2)
	if e != nil {
		return nil, ErrSyntax
	}

	s := &SignedData{raw: b, limits: l, detached: len(ec) == 1}
	if der.Decode(ec[0], &s.contentType) != nil {
		return nil, ErrSyntax
	}

	if !s.detached {
		x, e := der.Explicit(ec[1], 0)
		if e != nil || !der.Is(x, 0, 4, false) || len(x.Bytes) > l.MaxContentBytes {
			return nil, ErrSyntax
		}
	}

	if !s.detached {
		x, _ := der.Explicit(ec[1], 0)
		s.content = x.Bytes
	}

	i := 3
	if i < len(f) && der.Is(f[i], 2, 0, true) {
		certificates, e := parseCertificateBag(ctx, f[i], l)
		if e != nil {
			return nil, e
		}

		s.certificates = certificates

		i++
	}
	// CMS revocationInfoChoices and attribute certificates are not implemented.
	if i+1 != len(f) {
		return nil, ErrSyntax
	}

	if e := s.parseSigners(ctx, f[i], digests, version); e != nil {
		return nil, e
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return s, nil
}

func parseDigestAlgorithms(value asn1.RawValue, l Limits) (map[crypto.Hash]bool, error) {
	ds, e := der.SetFields(value, 0, asn1.TagSet, l.MaxSigners)
	if e != nil || len(ds) == 0 {
		return nil, ErrSyntax
	}

	digests := map[crypto.Hash]bool{}

	for _, rv := range ds {
		a, e := signature.Algorithm(rv)
		if e != nil {
			return nil, ErrSyntax
		}

		h, e := signature.Hash(a, false)
		if e != nil || digests[h] {
			return nil, ErrPolicy
		}

		digests[h] = true
	}

	return digests, nil
}

func parseCertificateBag(ctx context.Context, value asn1.RawValue, l Limits) ([][]byte, error) {
	var certificates [][]byte
	// OpenSSL emits a definite-length BER CertificateSet in insertion order. Only
	// this untrusted certificate bag may be unsorted; signedAttrs remain strict DER.
	cs, e := der.Children(value)
	if e != nil || len(cs) == 0 || len(cs) > l.MaxCertificates {
		return nil, ErrSyntax
	}

	seen := certificateSet{}

	for _, rv := range cs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if !der.Is(rv, 0, asn1.TagSequence, true) {
			return nil, ErrSyntax
		}

		c, e := x509.ParseCertificate(rv.FullBytes)
		if e != nil || !seen.add(c.Raw) {
			return nil, ErrSyntax
		}

		certificates = append(certificates, c.Raw)
	}

	return certificates, nil
}

// DER returns an owned copy of the original DER encoding.
func (s *SignedData) DER() []byte {
	if s == nil {
		return nil
	}

	return bytes.Clone(s.raw)
}

// Size returns the size of the complete DER container in bytes.
func (s *SignedData) Size() int {
	if s == nil {
		return 0
	}

	return len(s.raw)
}

// WriterTo returns an io.WriterTo that emits the original DER without copying
// the container. It checks ctx and may leave partial output on destination error.
func (s *SignedData) WriterTo(ctx context.Context) io.WriterTo {
	return signedDataWriter{source: s, ctx: ctx}
}

// Detached returns whether the CMS content is detached.
func (s *SignedData) Detached() bool { return s != nil && s.detached }

// ContentType returns an owned copy of the content-type object identifier.
func (s *SignedData) ContentType() asn1.ObjectIdentifier {
	if s == nil {
		return nil
	}

	return append(asn1.ObjectIdentifier(nil), s.contentType...)
}

// UnverifiedContent returns an owned copy of unauthenticated content; verification is
// required before accepting it.
func (s *SignedData) UnverifiedContent() []byte {
	if s == nil {
		return nil
	}

	return bytes.Clone(s.content)
}

// SignerCount returns the number of parsed CMS signers.
func (s *SignedData) SignerCount() int {
	if s == nil {
		return 0
	}

	return len(s.signers)
}

// Certificates returns UNTRUSTED path-building candidates, never trust anchors.
func (s *SignedData) Certificates() [][]byte {
	if s == nil {
		return nil
	}

	var r [][]byte
	for _, b := range s.certificates {
		r = append(r, bytes.Clone(b))
	}

	return r
}

// MatchesSigner checks only a SignerIdentifier, not a signature or PKIX trust.
func (s *SignedData) MatchesSigner(index int, raw []byte) bool {
	if s == nil || index < 0 || index >= len(s.signers) || len(raw) > 1<<20 {
		return false
	}

	c, e := x509.ParseCertificate(raw)

	return e == nil && certificateMatch(s.signers[index], c)
}

func certificateMatch(p parsedSigner, c *x509.Certificate) bool {
	if len(p.ski) > 0 {
		return len(c.SubjectKeyId) > 0 && bytes.Equal(p.ski, c.SubjectKeyId)
	}

	return p.serial.Cmp(c.SerialNumber) == 0 && bytes.Equal(p.issuer, c.RawIssuer)
}

func (s *SignedData) parseSigners(ctx context.Context, value asn1.RawValue, digests map[crypto.Hash]bool, version int) error {
	si, e := der.SetFields(value, 0, asn1.TagSet, s.limits.MaxSigners)
	if e != nil || len(si) == 0 {
		return ErrSyntax
	}

	wanted := 1
	if !s.contentType.Equal(oidData()) {
		wanted = 3
	}

	for _, rv := range si {
		if err := ctx.Err(); err != nil {
			return err
		}

		p, e := parseSigner(rv, s.limits)
		if e != nil {
			return e
		}

		h, e := signature.Hash(p.digest, false)
		if e != nil || !digests[h] {
			return ErrPolicy
		}

		if len(p.ski) > 0 {
			wanted = 3
		}

		s.signers = append(s.signers, p)
	}

	if version != wanted {
		return fmt.Errorf("%w: version", ErrSyntax)
	}

	return nil
}

func parseSigner(v asn1.RawValue, l Limits) (parsedSigner, error) {
	f, e := der.Sequence(v, 5, 7)
	if e != nil {
		return parsedSigner{}, ErrSyntax
	}

	var version int
	if der.Decode(f[0], &version) != nil {
		return parsedSigner{}, ErrSyntax
	}

	p := parsedSigner{}

	if der.Is(f[1], 2, 0, false) {
		if version != 3 || len(f[1].Bytes) < 1 || len(f[1].Bytes) > 128 {
			return p, ErrSyntax
		}

		p.ski = f[1].Bytes
	} else {
		x, e := der.Sequence(f[1], 2, 2)
		if e != nil || version != 1 || !der.Is(x[0], 0, asn1.TagSequence, true) || der.Decode(x[1], &p.serial) != nil || p.serial == nil || p.serial.Sign() <= 0 || p.serial.BitLen() > 160 {
			return p, ErrSyntax
		}

		p.issuer = x[0].FullBytes
	}

	p.digest, e = signature.Algorithm(f[2])
	if e != nil {
		return p, ErrSyntax
	}

	i := 3
	if der.Is(f[i], 2, 0, true) {
		p.signed, e = parseAttributes(f[i], 0, l.MaxAttributes)
		if e != nil {
			return p, e
		}

		// Verification substitutes the universal SET tag while hashing; the
		// rest of the signed-attribute encoding can borrow owned container bytes.
		p.signedInput = f[i].FullBytes
		i++
	}

	if i+1 >= len(f) {
		return p, ErrSyntax
	}

	p.alg, e = signature.Algorithm(f[i])
	if e != nil {
		return p, ErrSyntax
	}

	i++
	if der.Decode(f[i], &p.sig) != nil || len(p.sig) == 0 || len(p.sig) > 2048 {
		return p, ErrSyntax
	}

	i++
	if i < len(f) {
		p.unsigned, e = parseAttributes(f[i], 1, l.MaxAttributes)
		if e != nil {
			return p, e
		}

		i++
	}

	if i != len(f) {
		return p, ErrSyntax
	}

	return p, nil
}

// certificateSet keeps exact duplicate checks without copying DER into string keys.
type certificateSet map[[sha256.Size]byte][][]byte

func (s certificateSet) add(raw []byte) bool {
	hash := sha256.Sum256(raw)
	for _, previous := range s[hash] {
		if bytes.Equal(previous, raw) {
			return false
		}
	}

	s[hash] = append(s[hash], raw)

	return true
}

type signedDataWriter struct {
	source *SignedData
	ctx    context.Context
}

func (w signedDataWriter) WriteTo(dst io.Writer) (int64, error) {
	if w.ctx == nil || w.source == nil || len(w.source.raw) == 0 || nilcheck.IsNil(dst) {
		return 0, ErrPolicy
	}

	out := &streamio.Writer{Context: w.ctx, Target: dst, Limit: int64(len(w.source.raw)), LimitError: ErrPolicy}
	err := writeDERPart(out, w.source.raw)

	return out.Written, errors.Join(err, w.ctx.Err())
}
