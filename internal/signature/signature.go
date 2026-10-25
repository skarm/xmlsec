package signature

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" // #nosec G505 -- Legacy digests require explicit profile permission.
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/ecdsakey"
	"github.com/skarm/xmlsec/internal/nilcheck"
)

const (
	namePss = "pss"
)

// Err reports unsupported or invalid ASN.1 signature.
var Err = errors.New("unsupported or invalid ASN.1 signature")

// SignerProvider follows crypto.Signer conventions with a caller context.
type SignerProvider interface {
	Public() crypto.PublicKey
	Sign(context.Context, io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

// SignerAdapter bridges a context-aware provider to crypto.Signer. It can be
// embedded in an adapter that exposes additional signing capabilities.
type SignerAdapter struct {
	Provider SignerProvider
}

// Public returns the provider's public key.
func (a SignerAdapter) Public() crypto.PublicKey { return a.Provider.Public() }

// Sign implements crypto.Signer for callers without an operation context.
func (a SignerAdapter) Sign(r io.Reader, input []byte, opt crypto.SignerOpts) ([]byte, error) {
	return a.Provider.Sign(context.Background(), r, input, opt)
}

func (a SignerAdapter) sign(ctx context.Context, r io.Reader, input []byte, opt crypto.SignerOpts) ([]byte, error) {
	return a.Provider.Sign(ctx, r, input, opt)
}

// SHA1 returns a caller-owned SHA-1 object identifier.
func SHA1() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26} }

// SHA256 returns a caller-owned ASN.1 object identifier.
func SHA256() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1} }

// SHA384 returns a caller-owned ASN.1 object identifier.
func SHA384() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2} }

// SHA512 returns a caller-owned ASN.1 object identifier.
func SHA512() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3} }

// RSA returns a caller-owned ASN.1 object identifier.
func RSA() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1} }

// PSS returns a caller-owned ASN.1 object identifier.
func PSS() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10} }

// MGF1 returns a caller-owned ASN.1 object identifier.
func MGF1() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8} }

// Key checks the supported public-key type and minimum key strength.
func Key(k crypto.PublicKey) error {
	switch p := k.(type) {
	case *rsa.PublicKey:
		if p == nil || p.N == nil || p.N.BitLen() < 2048 || p.N.BitLen() > 16384 || p.N.Sign() <= 0 || p.E < 3 || p.E%2 == 0 {
			return Err
		}
	case *ecdsa.PublicKey:
		if p == nil || (p.Curve != elliptic.P256() && p.Curve != elliptic.P384() && p.Curve != elliptic.P521()) {
			return Err
		}

		if _, err := ecdsakey.PublicBytes(p); err != nil {
			return Err
		}
	case ed25519.PublicKey:
		if len(p) != ed25519.PublicKeySize {
			return Err
		}
	default:
		return Err
	}

	return nil
}

// HashOID returns a caller-owned OID for a supported digest algorithm.
func HashOID(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA1:
		return SHA1(), nil
	case crypto.SHA256:
		return SHA256(), nil
	case crypto.SHA384:
		return SHA384(), nil
	case crypto.SHA512:
		return SHA512(), nil
	}

	return nil, Err
}

// DigestAlgorithm constructs a supported digest AlgorithmIdentifier.
func DigestAlgorithm(h crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	o, e := HashOID(h)
	return pkix.AlgorithmIdentifier{Algorithm: append(asn1.ObjectIdentifier(nil), o...), Parameters: asn1.NullRawValue}, e
}

// NullOrAbsent reports whether ASN.1 parameters are NULL or omitted.
func NullOrAbsent(v asn1.RawValue) bool {
	return len(v.FullBytes) == 0 && len(v.Bytes) == 0 && v.Tag == 0 || der.Is(v, 0, asn1.TagNull, false) && len(v.Bytes) == 0
}

// Hash decodes a supported digest identifier; SHA-1 requires explicit permission.
func Hash(a pkix.AlgorithmIdentifier, allowSHA1 bool) (crypto.Hash, error) {
	if !NullOrAbsent(a.Parameters) {
		return 0, Err
	}

	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA1} {
		o, _ := HashOID(h)
		if a.Algorithm.Equal(o) {
			if h == crypto.SHA1 && !allowSHA1 {
				return 0, Err
			}

			return h, nil
		}
	}

	return 0, Err
}

// Sum hashes bytes using the supplied supported algorithm.
func Sum(h crypto.Hash, b []byte) ([]byte, error) {
	if !h.Available() {
		return nil, Err
	}

	d := h.New()
	_, _ = d.Write(b)

	return d.Sum(nil), nil
}

// Algorithm decodes a complete AlgorithmIdentifier.
func Algorithm(v asn1.RawValue) (pkix.AlgorithmIdentifier, error) {
	f, e := der.Sequence(v, 1, 2)
	if e != nil {
		return pkix.AlgorithmIdentifier{}, e
	}

	var o asn1.ObjectIdentifier
	if der.Decode(f[0], &o) != nil {
		return pkix.AlgorithmIdentifier{}, Err
	}

	a := pkix.AlgorithmIdentifier{Algorithm: o}
	if len(f) == 2 {
		a.Parameters = f[1]
	}

	return a, nil
}

// EncAlgorithm encodes an AlgorithmIdentifier.
func EncAlgorithm(a pkix.AlgorithmIdentifier) []byte {
	p := [][]byte{der.OID(a.Algorithm)}
	if len(a.Parameters.FullBytes) > 0 {
		p = append(p, a.Parameters.FullBytes)
	} else if a.Parameters.Tag != 0 || a.Parameters.Class != 0 || len(a.Parameters.Bytes) > 0 {
		b, _ := asn1.Marshal(a.Parameters)
		p = append(p, b)
	}

	return der.Seq(p...)
}

// Select selects a supported signature identifier for the explicit key, digest and PSS
// flag.
func Select(k crypto.PublicKey, h crypto.Hash, pss bool) (pkix.AlgorithmIdentifier, error) {
	if e := Key(k); e != nil {
		return pkix.AlgorithmIdentifier{}, e
	}

	i := 0

	switch h {
	case crypto.SHA256:
	case crypto.SHA384:
		i = 1
	case crypto.SHA512:
		i = 2
	default:
		return pkix.AlgorithmIdentifier{}, Err
	}

	switch k.(type) {
	case *rsa.PublicKey:
		if pss {
			da, _ := DigestAlgorithm(h)
			d := EncAlgorithm(da)
			params := der.Seq(der.Ctx(0, d), der.Ctx(1, der.Seq(der.OID(MGF1()), d)), der.Ctx(2, der.Int(h.Size())))

			return pkix.AlgorithmIdentifier{Algorithm: PSS(), Parameters: asn1.RawValue{FullBytes: params}}, nil
		}

		return pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11 + i}, Parameters: asn1.NullRawValue}, nil
	case *ecdsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2 + i}}, nil
	}

	return pkix.AlgorithmIdentifier{}, Err
}

// Details validates a signature identifier and returns its digest and signature family.
func Details(a pkix.AlgorithmIdentifier) (crypto.Hash, string, error) {
	if a.Algorithm.Equal(PSS()) {
		raw := a.Parameters
		if len(raw.FullBytes) > 0 {
			var e error

			raw, e = der.Read(raw.FullBytes, 4096)
			if e != nil {
				return 0, "", Err
			}
		}

		f, e := der.Sequence(raw, 3, 3)
		if e != nil {
			return 0, "", Err
		}

		x, e := der.Explicit(f[0], 0)
		if e != nil {
			return 0, "", Err
		}

		ha, e := Algorithm(x)
		if e != nil {
			return 0, "", Err
		}

		h, e := Hash(ha, false)
		if e != nil {
			return 0, "", Err
		}

		x, e = der.Explicit(f[1], 1)
		if e != nil {
			return 0, "", Err
		}

		m, e := Algorithm(x)
		if e != nil || !m.Algorithm.Equal(MGF1()) {
			return 0, "", Err
		}

		mh, e := Algorithm(m.Parameters)
		if e != nil {
			return 0, "", Err
		}

		hh, e := Hash(mh, false)
		if e != nil || hh != h {
			return 0, "", Err
		}

		x, e = der.Explicit(f[2], 2)

		var salt int
		if e != nil || der.Decode(x, &salt) != nil || salt != h.Size() {
			return 0, "", Err
		}

		return h, namePss, nil
	}

	if returned0, returned1, matched := detailsEntries(&a); matched {
		return returned0, returned1, nil
	}

	return 0, "", Err
}

func detailsEntries(a *pkix.AlgorithmIdentifier) (returned0 crypto.Hash, returned1 string, matched bool) {
	for i, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		if a.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11 + i}) && NullOrAbsent(a.Parameters) {
			return h, "rsa", true
		}

		if a.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2 + i}) && len(a.Parameters.FullBytes) == 0 && a.Parameters.Tag == 0 {
			return h, "ecdsa", true
		}
	}

	return
}

type contextual interface {
	sign(context.Context, io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

// SignDigest sends the caller context to adapted providers. Plain crypto.Signer
// implementations keep their standard signing contract. External providers
// receive an owned copy; the standard Ed25519 key reads input without copying it.
func SignDigest(ctx context.Context, s crypto.Signer, r io.Reader, digest []byte, opt crypto.SignerOpts) ([]byte, error) {
	switch s.(type) {
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return s.Sign(r, digest, opt)
	}

	if cs, ok := s.(contextual); ok {
		return cs.sign(ctx, r, bytes.Clone(digest), opt)
	}

	return s.Sign(r, bytes.Clone(digest), opt)
}

// Sign signs a message under a supported signature identifier with cancellation checks.
func Sign(ctx context.Context, s crypto.Signer, a pkix.AlgorithmIdentifier, message []byte) ([]byte, error) {
	if ctx == nil || nilcheck.IsNil(s) {
		return nil, Err
	}

	if e := ctx.Err(); e != nil {
		return nil, e
	}

	h, mode, e := Details(a)
	if e != nil {
		return nil, e
	}

	if e = Key(s.Public()); e != nil {
		return nil, e
	}

	digest, e := Sum(h, message)
	if e != nil {
		return nil, e
	}

	var opt crypto.SignerOpts = h
	if mode == namePss {
		opt = &rsa.PSSOptions{SaltLength: h.Size(), Hash: h}
	}

	value, e := SignDigest(ctx, s, rand.Reader, digest, opt)
	if e != nil {
		return nil, e
	}

	if e = ctx.Err(); e != nil {
		return nil, e
	}

	if e = Verify(s.Public(), a, message, value); e != nil {
		return nil, fmt.Errorf("%w: provider output: %w", Err, e)
	}

	return bytes.Clone(value), nil
}

// Verify checks a message signature using an explicitly supplied public key.
func Verify(k crypto.PublicKey, a pkix.AlgorithmIdentifier, message, value []byte) error {
	if e := Key(k); e != nil {
		return e
	}

	h, _, e := Details(a)
	if e != nil {
		return e
	}

	digest, e := Sum(h, message)
	if e != nil {
		return e
	}

	return VerifyDigest(k, a, digest, value)
}

// VerifyDigest checks an already computed digest using the signature algorithm's
// exact hash and parameter constraints.
func VerifyDigest(k crypto.PublicKey, a pkix.AlgorithmIdentifier, digest, value []byte) error {
	if e := Key(k); e != nil {
		return e
	}

	h, mode, e := Details(a)
	if e != nil {
		return e
	}

	if len(digest) != h.Size() {
		return Err
	}

	switch p := k.(type) {
	case *rsa.PublicKey:
		switch mode {
		case "rsa":
			e = rsa.VerifyPKCS1v15(p, h, digest, value)
		case namePss:
			e = rsa.VerifyPSS(p, h, digest, value, &rsa.PSSOptions{SaltLength: h.Size(), Hash: h})
		default:
			return Err
		}
	case *ecdsa.PublicKey:
		if mode != "ecdsa" {
			return Err
		}

		if _, e := der.Read(value, 256); e != nil {
			return e
		}

		if !ecdsa.VerifyASN1(p, digest, value) {
			return Err
		}
	default:
		return Err
	}

	if e != nil {
		return fmt.Errorf("%w: %w", Err, e)
	}

	return nil
}

// MatchCertificate checks that a signer and certificate identify the same public key.
func MatchCertificate(s crypto.Signer, c *x509.Certificate) error {
	if nilcheck.IsNil(s) || c == nil {
		return Err
	}

	if e := Key(s.Public()); e != nil {
		return e
	}

	b, e := x509.MarshalPKIXPublicKey(s.Public())
	if e != nil || !bytes.Equal(b, c.RawSubjectPublicKeyInfo) {
		return Err
	}

	return nil
}
