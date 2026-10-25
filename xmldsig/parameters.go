package xmldsig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
)

const (
	// PSSNamespace is the namespace for parameterized RSA-PSS and MGF1 identifiers.
	PSSNamespace = "http://www.w3.org/2007/05/xmldsig-more#"
	// RSAPSS is the XMLDSig RSA-PSS URI with explicit algorithm parameters.
	RSAPSS = PSSNamespace + "rsa-pss"
	// MGF1 is the generic MGF1 mask-generation URI.
	MGF1 = PSSNamespace + "MGF1"
	// HMACSHA1 is the legacy HMAC-SHA1 URI. It requires LegacyHMACPolicy or an explicit allowlist.
	HMACSHA1 = Namespace + "hmac-sha1"
	// HMACSHA256 is the HMAC-SHA-256 algorithm URI.
	HMACSHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
	// HMACSHA384 is the HMAC-SHA-384 algorithm URI.
	HMACSHA384 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384"
	// HMACSHA512 is the HMAC-SHA-512 algorithm URI.
	HMACSHA512 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"
)

// PSSParameters describes RFC 9231 parameterized RSA-PSS using SHA-2,
// MGF1 and trailer field 1. Salt length is exact, including zero.
type PSSParameters struct {
	// Hash selects SHA-256, SHA-384 or SHA-512; zero selects SHA-256.
	Hash crypto.Hash
	// MGFHash selects the MGF1 hash; zero uses Hash.
	MGFHash crypto.Hash
	// SaltLength is exact: zero means zero salt, not rsa.PSSSaltLengthAuto.
	SaltLength int
	// TrailerField accepts 1; zero in this Go API selects 1.
	// An explicitly encoded XML zero is invalid.
	TrailerField int
}

// SignatureParameters holds parameters for a single SignatureMethod.
// Fixed-method URIs do not accept parameters.
type SignatureParameters struct {
	// PSS applies to the generic RSAPSS method. Nil selects the RFC 9231
	// defaults: SHA-256, MGF1-SHA256, 32-byte salt and trailer 1.
	PSS *PSSParameters
	// HMACOutputLength is the tag length in bits. Zero omits the XML parameter
	// and selects a full tag; an explicitly encoded XML zero is invalid.
	HMACOutputLength int
}

// ParameterizedPSSSigner is an optional capability of a crypto.Signer. It is
// needed for a different MGF1 hash or exact zero salt, which crypto.SignerOpts
// cannot express unambiguously. digest is already hashed. Implementations must
// honor EVERY normalized parameter. Returned signatures are verified locally.
// This interface is not an HSM driver or a private-key RSA implementation.
type ParameterizedPSSSigner interface {
	// SignPSS signs a prehashed digest using every normalized PSS parameter and
	// must honor cancellation. The reader supplies randomness when needed.
	SignPSS(context.Context, io.Reader, []byte, PSSParameters) ([]byte, error)
}

// SignMessageWithParameters signs exact bytes with a parameterized public-key
// SignatureMethod. This is not XML processing, PKIX validation or SAML validation.
func SignMessageWithParameters(ctx context.Context, message []byte, signer crypto.Signer, method string, params SignatureParameters, policy Policy) ([]byte, error) {
	return SignMessageWithParametersReader(ctx, bytes.NewBuffer(message), signer, method, params, policy)
}

// SignMessageWithParametersReader signs src incrementally with explicit signature
// parameters. Pure Ed25519 retains the complete message; other methods retain only
// a digest. It leaves src open.
func SignMessageWithParametersReader(ctx context.Context, src io.Reader, signer crypto.Signer, method string, params SignatureParameters, policy Policy) ([]byte, error) {
	if ctx == nil {
		return nil, ErrPolicy
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

	s, err := normalizeSignatureSpec(method, params)
	if err != nil {
		return nil, err
	}

	if err = s.validatePolicy(p); err != nil {
		return nil, err
	}

	if nilcheck.IsNil(src) {
		return nil, ErrPolicy
	}

	key := signer.Public()
	if err = s.validatePublicKey(key, p); err != nil {
		return nil, err
	}

	credential := signatureCredential{public: key, signer: signer}
	if err := credential.validateSigner(s); err != nil {
		return nil, err
	}

	digest, err := credential.readInput(ctx, s, src, p.MaxCanonicalBytes)
	if err != nil {
		return nil, err
	}

	return credential.signPrepared(ctx, s, digest)
}

// VerifyMessageWithParameters verifies a raw message with explicit signature parameters
// and algorithm policy.
func VerifyMessageWithParameters(ctx context.Context, message, value []byte, key crypto.PublicKey, method string, params SignatureParameters, policy Policy) error {
	return VerifyMessageWithParametersReader(ctx, bytes.NewBuffer(message), value, key, method, params, policy)
}

// VerifyMessageWithParametersReader verifies src with explicit parameters and
// bounded input. Only pure Ed25519 requires complete message storage; src remains open.
func VerifyMessageWithParametersReader(ctx context.Context, src io.Reader, value []byte, key crypto.PublicKey, method string, params SignatureParameters, policy Policy) error {
	if ctx == nil {
		return ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	p, err := normalizePolicy(policy)
	if err != nil {
		return err
	}

	s, err := normalizeSignatureSpec(method, params)
	if err != nil {
		return err
	}

	if err = s.validatePolicy(p); err != nil {
		return err
	}

	if nilcheck.IsNil(src) {
		return ErrPolicy
	}

	if err = s.validatePublicKey(key, p); err != nil {
		return err
	}

	digest, err := (signatureCredential{public: key}).readInput(ctx, s, src, p.MaxCanonicalBytes)
	if err != nil {
		return err
	}

	if err = s.verifyPrepared(key, digest, value); err != nil {
		return err
	}

	return ctx.Err()
}

type signatureSpec struct {
	algorithm string
	pss       *PSSParameters
	hmacBits  int
}

func (s signatureSpec) parameters() SignatureParameters {
	return copySignatureParameters(SignatureParameters{PSS: s.pss, HMACOutputLength: s.hmacBits})
}

func copySignatureParameters(p SignatureParameters) SignatureParameters {
	if p.PSS != nil {
		cp := *p.PSS
		p.PSS = &cp
	}

	return p
}

func (s signatureSpec) validatePolicy(p Policy) error {
	if !permits(p.AllowedSignatureMethods, s.algorithm) {
		return fmt.Errorf("%w: signature algorithm", ErrPolicy)
	}

	if s.pss != nil {
		for _, h := range []crypto.Hash{s.pss.Hash, s.pss.MGFHash} {
			u, _ := digestURI(h)
			if !permits(p.AllowedDigestMethods, u) {
				return fmt.Errorf("%w: PSS hash/MGF digest", ErrPolicy)
			}
		}

		if s.pss.SaltLength < p.MinPSSSaltBytes || s.pss.SaltLength > p.MaxPSSSaltBytes {
			return fmt.Errorf("%w: PSS salt length", ErrPolicy)
		}
	}

	if h, ok := macHash(s.algorithm); ok {
		u, _ := digestURI(h)
		if !permits(p.AllowedDigestMethods, u) {
			return fmt.Errorf("%w: HMAC hash", ErrPolicy)
		}

		if s.hmacBits < p.MinHMACOutputBits || (!p.AllowHMACTruncation && s.hmacBits != h.Size()*8) {
			return fmt.Errorf("%w: HMAC truncation", ErrPolicy)
		}
	}

	return nil
}

func (s signatureSpec) validatePublicKey(key crypto.PublicKey, p Policy) error {
	if _, ok := macHash(s.algorithm); ok {
		return fmt.Errorf("%w: HMAC requires the shared-secret API", ErrKey)
	}

	if err := validateKey(key, p); err != nil {
		return err
	}

	if err := matchKeyAlgorithm(s.algorithm, key); err != nil {
		return err
	}

	if s.pss != nil {
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrKey
		}

		emLen := (k.N.BitLen() - 1 + 7) / 8
		if s.pss.SaltLength > emLen-s.pss.Hash.Size()-2 {
			return fmt.Errorf("%w: PSS salt does not fit the RSA modulus", ErrPolicy)
		}
	}

	return nil
}

func (s signatureSpec) validateSigner(signer crypto.Signer) error {
	if s.algorithm == DSASHA1 || s.algorithm == RSASHA1 {
		return fmt.Errorf("%w: legacy signature generation is disabled", ErrPolicy)
	}

	if s.pss != nil && (s.pss.Hash != s.pss.MGFHash || s.pss.SaltLength == 0) {
		if _, ok := signer.(ParameterizedPSSSigner); !ok {
			return fmt.Errorf("%w: parameters require ParameterizedPSSSigner (different MGF hash or exact zero salt)", ErrAlgorithm)
		}
	}

	return nil
}

func (s signatureSpec) verifyPrepared(key crypto.PublicKey, digest, value []byte) error {
	if s.pss == nil {
		return verifyPreparedValue(s.algorithm, key, s.hash(), digest, value)
	}

	k, ok := key.(*rsa.PublicKey)
	if !ok {
		return ErrKey
	}

	return verifyParameterizedPSS(k, digest, value, *s.pss)
}

// verifyParameterizedPSS implements the PUBLIC-key verification portion of
// RFC 8017 8.1.2 and 9.1.2, with explicit independent MGF1 hash and exact salt.
// It does not perform private-key math. Inputs have already passed key/policy
// validation; bounds are rechecked here before slicing or allocating.
func verifyParameterizedPSS(k *rsa.PublicKey, digest, signature []byte, p PSSParameters) error {
	invalid := func() error { return fmt.Errorf("%w: RSA-PSS", ErrSignature) }
	if k == nil || k.N == nil || k.N.Sign() <= 0 || k.E < 3 || len(signature) != (k.N.BitLen()+7)/8 {
		return invalid()
	}

	emBits := k.N.BitLen() - 1
	emLen := (emBits + 7) / 8

	hLen := p.Hash.Size()
	if p.SaltLength < 0 || emLen < hLen+p.SaltLength+2 {
		return invalid()
	}
	// Delegate the ordinary representable case to the standard library.
	// The public-key decoder below is only needed for exact zero salt or an
	// independent MGF1 hash, not expressible by Go's PSS verification options.
	if p.Hash == p.MGFHash && p.SaltLength > 0 {
		if err := rsa.VerifyPSS(k, p.Hash, digest, signature, &rsa.PSSOptions{Hash: p.Hash, SaltLength: p.SaltLength}); err != nil {
			return invalid()
		}

		return nil
	}

	sig := new(big.Int).SetBytes(signature)
	if sig.Cmp(k.N) >= 0 {
		return invalid()
	}

	m := new(big.Int).Exp(sig, big.NewInt(int64(k.E)), k.N)
	if m.BitLen() > emLen*8 {
		return invalid()
	}

	em := make([]byte, emLen)
	m.FillBytes(em)

	if em[emLen-1] != 0xbc {
		return invalid()
	}

	dbLen := emLen - hLen - 1

	unused := uint(8*emLen - emBits)
	if em[0] & ^byte(0xff>>unused) != 0 {
		return invalid()
	}

	H := em[dbLen : dbLen+hLen]
	db := make([]byte, dbLen)
	copy(db, em[:dbLen])

	mask := p.MGFHash.New()

	var counter [4]byte

	off := 0
	for i := uint32(0); off < dbLen; i++ {
		binary.BigEndian.PutUint32(counter[:], i)
		mask.Reset()
		_, _ = mask.Write(H)
		_, _ = mask.Write(counter[:])

		block := mask.Sum(nil)
		for _, b := range block {
			if off == dbLen {
				break
			}

			db[off] ^= b
			off++
		}
	}

	db[0] &= 0xff >> unused
	psLen := dbLen - p.SaltLength - 1

	bad := byte(0)
	for _, b := range db[:psLen] {
		bad |= b
	}

	if bad != 0 || db[psLen] != 1 {
		return invalid()
	}

	hash := p.Hash.New()
	_, _ = hash.Write(make([]byte, 8))
	_, _ = hash.Write(digest)

	_, _ = hash.Write(db[psLen+1:])
	if subtle.ConstantTimeCompare(H, hash.Sum(nil)) != 1 {
		return invalid()
	}

	return nil
}

func (s signatureSpec) signPrepared(ctx context.Context, signer crypto.Signer, key crypto.PublicKey, digest []byte) ([]byte, error) {
	if s.pss == nil {
		return signPreparedValue(ctx, s.algorithm, signer, key, s.hash(), digest)
	}

	if err := s.validateSigner(signer); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var (
		raw []byte
		err error
	)
	if provider, ok := signer.(ParameterizedPSSSigner); ok {
		raw, err = provider.SignPSS(ctx, rand.Reader, bytes.Clone(digest), *s.pss)
	} else {
		opts := &rsa.PSSOptions{SaltLength: s.pss.SaltLength, Hash: s.pss.Hash}
		raw, err = signature.SignDigest(ctx, signer, rand.Reader, digest, opts)
	}

	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}

	if err = ctx.Err(); err != nil {
		return nil, err
	}

	if err = s.verifyPrepared(key, digest, raw); err != nil {
		return nil, fmt.Errorf("signer output: %w", err)
	}

	return append([]byte(nil), raw...), nil
}

func macHash(method string) (crypto.Hash, bool) {
	switch method {
	case HMACSHA1:
		return crypto.SHA1, true
	case HMACSHA256:
		return crypto.SHA256, true
	case HMACSHA384:
		return crypto.SHA384, true
	case HMACSHA512:
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

func digestURI(h crypto.Hash) (string, error) {
	switch h {
	case crypto.SHA1:
		return SHA1, nil
	case crypto.SHA256:
		return SHA256, nil
	case crypto.SHA384:
		return SHA384, nil
	case crypto.SHA512:
		return SHA512, nil
	default:
		return "", fmt.Errorf("%w: unsupported digest", ErrAlgorithm)
	}
}

func normalizeSignatureSpec(method string, params SignatureParameters) (signatureSpec, error) {
	s := signatureSpec{algorithm: method}
	if method == RSAPSS {
		if params.HMACOutputLength != 0 {
			return s, fmt.Errorf("%w: HMAC parameter on RSA-PSS", ErrStructure)
		}

		p := PSSParameters{Hash: crypto.SHA256, MGFHash: crypto.SHA256, SaltLength: 32, TrailerField: 1}
		normalizeSignatureSpecPSS(&params, &p)

		if p.Hash == crypto.SHA1 || p.MGFHash == crypto.SHA1 {
			return s, fmt.Errorf("%w: parameterized PSS requires SHA-2", ErrAlgorithm)
		}

		if _, err := digestURI(p.Hash); err != nil {
			return s, err
		}

		if _, err := digestURI(p.MGFHash); err != nil {
			return s, err
		}

		if p.TrailerField != 1 {
			return s, fmt.Errorf("%w: PSS trailer must be 1", ErrAlgorithm)
		}

		if p.SaltLength < 0 || p.SaltLength > 2048 {
			return s, fmt.Errorf("%w: PSS salt bounds", ErrPolicy)
		}

		s.pss = &p

		return s, nil
	}

	if h, ok := macHash(method); ok {
		if params.PSS != nil {
			return s, fmt.Errorf("%w: PSS parameters on HMAC", ErrStructure)
		}

		bits := params.HMACOutputLength
		if bits == 0 {
			bits = h.Size() * 8
		}
		// XMLDSig 1.1 sections 4.4.2 and 6.3.1: whole bytes, >= half
		// the hash output and >=80 bits, never longer than the hash output.
		if bits%8 != 0 || bits < h.Size()*4 || bits < 80 || bits > h.Size()*8 {
			return s, fmt.Errorf("%w: invalid HMAC output length", ErrPolicy)
		}

		s.hmacBits = bits

		return s, nil
	}

	if params.PSS != nil || params.HMACOutputLength != 0 {
		return s, fmt.Errorf("%w: parameters on a fixed SignatureMethod", ErrStructure)
	}

	_, _, err := signatureAlgorithm(method)

	return s, err
}

func normalizeSignatureSpecPSS(params *SignatureParameters, p *PSSParameters) {
	if params.PSS != nil {
		(*p) = *params.PSS
		if p.Hash == 0 {
			p.Hash = crypto.SHA256
		}

		if p.MGFHash == 0 {
			p.MGFHash = p.Hash
		}

		if p.TrailerField == 0 {
			p.TrailerField = 1
		}
	}
}
