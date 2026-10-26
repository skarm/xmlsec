package cms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"sort"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/x509cert"
)

// Signer supplies a signing key, its matching certificate and additional signed
// attributes.
type Signer struct {
	// Key must match CertificateDER. Standard and adapted context-aware signers are accepted.
	Key crypto.Signer
	// CertificateDER is the signer's DER certificate. Embedding it does not establish
	// trust.
	CertificateDER []byte
	// Attributes adds signed attributes without replacing generated content,
	// digest, certificate or algorithm bindings.
	Attributes []Attribute
	// Hash defaults to SHA-256.
	Hash crypto.Hash
	// RSAPSS selects fixed-parameter RSA-PSS for an RSA key.
	RSAPSS bool
	// SubjectKeyIdentifier selects the certificate's nonempty SKI as signer identifier.
	// False selects issuer and serial number.
	SubjectKeyIdentifier bool
	// OmitCertificateBinding omits the generated ESS signing-certificate binding.
	OmitCertificateBinding bool
}

// SignOptions selects CMS content placement, embedded certificates and processing
// limits.
type SignOptions struct {
	// ContentType defaults to id-data.
	ContentType asn1.ObjectIdentifier
	// ExtraCertificates embeds untrusted path-building candidates.
	ExtraCertificates [][]byte
	// Limits bounds content, certificates and container processing. Zero fields select
	// defaults.
	Limits Limits
	// Detached omits content from the container while still signing it.
	Detached bool
	// OmitCertificates omits all embedded certificates and cannot be combined
	// with ExtraCertificates.
	OmitCertificates bool
}

// Sign returns a complete DER SignedData container. It collects SignReader's
// writer output and returns no partial bytes on failure.
func Sign(ctx context.Context, content []byte, signers []Signer, o SignOptions) ([]byte, error) {
	var out bytes.Buffer
	if _, err := SignReader(ctx, &out, bytes.NewBuffer(content), signers, o); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// SignReader signs src once and writes definite-length DER to dst. Detached
// content is hashed with bounded working storage. Embedded content is retained
// until its length and signatures are known; no full encoded container is built.
// Output starts only after src reaches EOF and the generated signatures and
// metadata have been verified. Bounded hashing does not imply early output.
// The streams remain caller-owned; a destination error may leave partial output.
func SignReader(ctx context.Context, dst io.Writer, src io.Reader, signers []Signer, o SignOptions) (int64, error) {
	if ctx == nil || nilcheck.IsNil(src) || nilcheck.IsNil(dst) {
		return 0, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	l, err := normalize(o.Limits)
	if err != nil {
		return 0, err
	}

	if len(signers) < 1 || len(signers) > l.MaxSigners || len(o.ExtraCertificates) > l.MaxCertificates || o.OmitCertificates && len(o.ExtraCertificates) > 0 {
		return 0, ErrPolicy
	}

	if len(o.ContentType) == 0 {
		o.ContentType = DataOID()
	}

	ct := der.OID(o.ContentType)
	if len(ct) == 0 {
		return 0, ErrPolicy
	}

	encoder := signedDataEncoder{contentType: ct, limits: l, certSeen: certificateSet{}, digestSeen: map[crypto.Hash]struct{}{}, version: 1}
	if !o.ContentType.Equal(oidData()) {
		encoder.version = 3
	}

	certificates, hashes, err := encoder.prepareSigners(ctx, signers)
	if err != nil {
		return 0, err
	}

	if err := encoder.addCertificates(ctx, o.ExtraCertificates); err != nil {
		return 0, err
	}

	var (
		embedded bytes.Buffer
		retain   io.Writer
	)
	if !o.Detached {
		retain = &embedded
		// Already resident content can be hashed and emitted without a second
		// full buffer. External signers receive signed attributes, not this data.
		if buffer, ok := src.(*bytes.Buffer); ok {
			encoder.content = buffer.Bytes()
			retain = nil
		}
	}

	contentLimit := l.MaxContentBytes
	if !o.Detached {
		contentLimit = min(contentLimit, l.MaxBytes)
	}

	digests, _, err := hashContent(ctx, src, hashes, contentLimit, retain)
	if err != nil {
		return 0, err
	}

	if retain != nil {
		encoder.content = embedded.Bytes()
	}

	encoder.contentDigests = digests
	for i, s := range signers {
		if err := encoder.addSigner(ctx, s, certificates[i]); err != nil {
			return 0, err
		}
	}

	if len(encoder.certs) > l.MaxCertificates {
		return 0, ErrPolicy
	}
	// Verify generated metadata and signatures against the digests already read.
	detached := o
	detached.Detached = true
	detached.OmitCertificates = true

	sort.Slice(encoder.certs, func(i, j int) bool { return bytes.Compare(encoder.certs[i], encoder.certs[j]) < 0 })
	sort.Slice(encoder.infos, func(i, j int) bool { return bytes.Compare(encoder.infos[i], encoder.infos[j]) < 0 })

	var metadata bytes.Buffer

	err = encoder.encodeTo(&metadata, detached)
	if err != nil {
		return 0, err
	}

	parsed, err := ParseReader(ctx, bytes.NewReader(metadata.Bytes()), l)
	if err != nil {
		return 0, err
	}

	if _, err = parsed.verifySigners(ctx, certificates, VerifyOptions{ExpectedContentType: o.ContentType}, digests); err != nil {
		return 0, err
	}

	writer := &streamio.Writer{Context: ctx, Target: dst, Limit: int64(l.MaxBytes), LimitError: ErrPolicy}
	err = encoder.encodeTo(writer, o)

	return writer.Written, errors.Join(err, ctx.Err())
}

type signedDataEncoder struct {
	content        []byte
	contentType    []byte
	contentDigests map[crypto.Hash][]byte
	limits         Limits
	infos          [][]byte
	certs          [][]byte
	digests        [][]byte
	certSeen       certificateSet
	digestSeen     map[crypto.Hash]struct{}
	version        int
}

func (e *signedDataEncoder) addSigner(ctx context.Context, s Signer, c *x509.Certificate) error {
	if e.certSeen.add(c.Raw) {
		e.certs = append(e.certs, c.Raw)
	}

	if s.Hash == 0 {
		s.Hash = crypto.SHA256
	}

	da, err := signature.DigestAlgorithm(s.Hash)
	if err != nil {
		return err
	}

	if _, err = signature.Hash(da, false); err != nil {
		return err
	}

	alg, err := signature.Select(c.PublicKey, s.Hash, s.RSAPSS)
	if err != nil {
		return err
	}

	digestAI, algAI := signature.EncAlgorithm(da), signature.EncAlgorithm(alg)

	signed, err := e.signedAttributes(s, c, digestAI, algAI)
	if err != nil {
		return err
	}

	value, err := signature.Sign(ctx, s.Key, alg, signed)
	if err != nil {
		return err
	}

	// The IMPLICIT [0] tag preserves the authenticated SET length and contents.
	signed[0] = 0xa0

	sid, sidVersion, err := signerIdentifier(s, c)
	if err != nil {
		return err
	}

	if sidVersion == 3 {
		e.version = 3
	}

	e.infos = append(e.infos, der.Seq(der.Int(sidVersion), sid, digestAI, signed, algAI, der.Octets(value)))
	if _, exists := e.digestSeen[s.Hash]; !exists {
		e.digests = append(e.digests, digestAI)
		e.digestSeen[s.Hash] = struct{}{}
	}

	return nil
}

func (e *signedDataEncoder) signerCertificate(s Signer) (*x509.Certificate, error) {
	if nilcheck.IsNil(s.Key) || len(s.CertificateDER) > 1<<20 || len(s.Attributes) > e.limits.MaxAttributes {
		return nil, ErrPolicy
	}

	c, err := x509cert.ParseDefault(bytes.Clone(s.CertificateDER))
	if err != nil || c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 || c.SerialNumber.BitLen() > 160 {
		return nil, ErrCertificate
	}

	if err := signature.MatchCertificate(s.Key, c); err != nil {
		return nil, err
	}

	return c, nil
}

func (e *signedDataEncoder) signedAttributes(s Signer, c *x509.Certificate, digestAI, algAI []byte) ([]byte, error) {
	d := e.contentDigests[s.Hash]
	attrs := []Attribute{{oidContentType(), [][]byte{e.contentType}}, {oidMessageDigest(), [][]byte{der.Octets(d)}}}

	if !s.OmitCertificateBinding {
		a, err := CertificateBindingAttribute(c.Raw)
		if err != nil {
			return nil, err
		}

		attrs = append(attrs, a)
	}

	av, _ := der.Read(algAI, 4096)
	protect := der.Seq(digestAI, der.Wrap(2, 1, true, av.Bytes))

	attrs = append(attrs, Attribute{oidAlgorithmProtect(), [][]byte{protect}})
	for _, a := range s.Attributes {
		if a.OID.Equal(oidContentType()) || a.OID.Equal(oidMessageDigest()) || a.OID.Equal(oidSigningCertificate()) || a.OID.Equal(oidSigningCertificateV2()) || a.OID.Equal(oidAlgorithmProtect()) {
			return nil, ErrPolicy
		}

		attrs = append(attrs, a)
	}

	return encodeAttributes(attrs, e.limits.MaxAttributes)
}

func (e *signedDataEncoder) addCertificates(ctx context.Context, extra [][]byte) error {
	for _, b := range extra {
		if err := ctx.Err(); err != nil {
			return err
		}

		if len(b) > 1<<20 {
			return ErrPolicy
		}

		c, err := x509cert.ParseDefault(bytes.Clone(b))
		if err != nil {
			return ErrCertificate
		}

		if e.certSeen.add(c.Raw) {
			e.certs = append(e.certs, c.Raw)
		}
	}

	return nil
}

// encodeTo emits headers and retained payload separately. Only metadata is
// assembled with the small DER helpers; content is never copied into nested DER.
func (e *signedDataEncoder) encodeTo(dst io.Writer, o SignOptions) error {
	certificateLength, infosLength, err := e.metadataSizes(o.OmitCertificates)
	if err != nil {
		return err
	}

	certificateSize := 0
	if !o.OmitCertificates {
		certificateSize = derSize(certificateLength)
	}

	version, digests := der.Int(e.version), der.Set(e.digests...)

	oid := der.OID(oidSignedData())

	contentLength := len(e.contentType)
	if !o.Detached {
		contentLength += derSize(derSize(len(e.content)))
	}

	encapLength := derSize(contentLength)
	signedLength := len(version) + len(digests) + encapLength + certificateSize + derSize(infosLength)

	outerLength := len(oid) + derSize(derSize(signedLength))
	if derSize(outerLength) > e.limits.MaxBytes {
		return ErrPolicy
	}
	// ContentInfo, SignedData and EncapsulatedContentInfo nesting is definite-length.
	for _, part := range [][]byte{der.Header(0x30, outerLength), oid, der.Header(0xa0, derSize(signedLength)), der.Header(0x30, signedLength), version, digests, der.Header(0x30, contentLength), e.contentType} {
		if err := writeDERPart(dst, part); err != nil {
			return err
		}
	}

	if !o.Detached {
		for _, part := range [][]byte{der.Header(0xa0, derSize(len(e.content))), der.Header(4, len(e.content)), e.content} {
			if err := writeDERPart(dst, part); err != nil {
				return err
			}
		}
	}

	if !o.OmitCertificates {
		if err := writeDERPart(dst, der.Header(0xa0, certificateLength)); err != nil {
			return err
		}

		for _, certificate := range e.certs {
			if err := writeDERPart(dst, certificate); err != nil {
				return err
			}
		}
	}

	if err := writeDERPart(dst, der.Header(0x31, infosLength)); err != nil {
		return err
	}

	for _, info := range e.infos {
		if err := writeDERPart(dst, info); err != nil {
			return err
		}
	}

	return nil
}

func (e *signedDataEncoder) prepareSigners(ctx context.Context, signers []Signer) ([]*x509.Certificate, []crypto.Hash, error) {
	hashes := make([]crypto.Hash, 0, len(signers))

	certificates := make([]*x509.Certificate, 0, len(signers))
	for _, s := range signers {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		c, err := e.signerCertificate(s)
		if err != nil {
			return nil, nil, err
		}

		h := s.Hash
		if h == 0 {
			h = crypto.SHA256
		}

		if _, err := signature.Select(c.PublicKey, h, s.RSAPSS); err != nil {
			return nil, nil, err
		}

		for _, previous := range certificates {
			if bytes.Equal(previous.Raw, c.Raw) {
				return nil, nil, ErrPolicy
			}
		}

		certificates = append(certificates, c)
		hashes = append(hashes, h)
	}

	return certificates, hashes, nil
}

func (e *signedDataEncoder) metadataSizes(omitCertificates bool) (int, int, error) {
	certificateLength := 0

	if !omitCertificates {
		for _, cert := range e.certs {
			if len(cert) > e.limits.MaxBytes-certificateLength {
				return 0, 0, ErrPolicy
			}

			certificateLength += len(cert)
		}
	}

	infosLength := 0
	for _, info := range e.infos {
		if len(info) > e.limits.MaxBytes-infosLength {
			return 0, 0, ErrPolicy
		}

		infosLength += len(info)
	}

	return certificateLength, infosLength, nil
}

func signerIdentifier(s Signer, c *x509.Certificate) ([]byte, int, error) {
	serial, _ := asn1.Marshal(c.SerialNumber)

	sid := der.Seq(c.RawIssuer, serial)
	if !s.SubjectKeyIdentifier {
		return sid, 1, nil
	}

	if len(c.SubjectKeyId) < 1 || len(c.SubjectKeyId) > 128 {
		return nil, 0, ErrCertificate
	}

	return der.Wrap(2, 0, false, c.SubjectKeyId), 3, nil
}

func derSize(length int) int { return len(der.Header(0, length)) + length }

func writeDERPart(dst io.Writer, value []byte) error {
	for len(value) > 0 {
		chunk := value[:min(len(value), 32<<10)]

		n, err := dst.Write(chunk)
		if err != nil {
			return err
		}

		if n != len(chunk) {
			return io.ErrShortWrite
		}

		value = value[n:]
	}

	return nil
}
