package xmldsig

import (
	"bytes"
	"context"
	"crypto"

	// #nosec G406 -- Explicit bounded legacy compatibility only.
	"crypto/dsa" //nolint:staticcheck // XMLDSig 1.1 requires legacy DSA verification; generation is disabled.
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" // #nosec G505 -- Explicit legacy policy only; disabled in FIPS mode.
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/skarm/xmlsec/internal/ecdsakey"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/signature"
)

const (
	// Namespace is the XMLDSig 1.0 namespace URI.
	Namespace = lexicon.NamespaceDSig
	// EnvelopedSignature identifies the transform that removes its containing Signature.
	EnvelopedSignature = lexicon.TransformEnvelopedSignature
	// SHA1 is the legacy SHA-1 digest URI. It requires an explicit compatibility policy.
	SHA1 = lexicon.DigestSHA1
	// DSASHA1 is the legacy DSA-SHA1 URI, supported for verification only.
	DSASHA1 = Namespace + "dsa-sha1"
	// RSASHA1 is the legacy RSA-SHA1 URI, supported for verification only.
	RSASHA1 = Namespace + "rsa-sha1"
	// SHA256 is the SHA-256 digest algorithm URI.
	SHA256 = lexicon.DigestSHA256
	// SHA384 is the SHA-384 digest algorithm URI.
	SHA384 = lexicon.DigestSHA384
	// SHA512 is the SHA-512 digest algorithm URI.
	SHA512 = lexicon.DigestSHA512
	// RSASHA256 is the RSA PKCS#1 v1.5 with SHA-256 signature URI.
	RSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	// RSASHA384 is the RSA PKCS#1 v1.5 with SHA-384 signature URI.
	RSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	// RSASHA512 is the RSA PKCS#1 v1.5 with SHA-512 signature URI.
	RSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	// ECDSASHA256 is the ECDSA with SHA-256 signature URI.
	ECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	// ECDSASHA384 is the ECDSA with SHA-384 signature URI.
	ECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	// ECDSASHA512 is the ECDSA with SHA-512 signature URI.
	ECDSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	// RSAPSSSHA256 is the fixed-parameter RSA-PSS with SHA-256 signature URI.
	// RFC 9231 section 2.3.10 requires MGF1-SHA256 and a 32-byte salt.
	RSAPSSSHA256 = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
	// RSAPSSSHA384 is the fixed-parameter RSA-PSS with SHA-384 signature URI.
	RSAPSSSHA384 = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1"
	// RSAPSSSHA512 is the fixed-parameter RSA-PSS with SHA-512 signature URI.
	RSAPSSSHA512 = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1"
	// Ed25519 identifies pure Ed25519, without the ph or ctx variants.
	// SignedInfo bytes are not prehashed.
	Ed25519 = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"
	// Ed25519ph identifies Ed25519 with a SHA-512 prehash and an empty context.
	// It is distinct from pure Ed25519 and hashes message input incrementally.
	Ed25519ph = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519ph"
)

var (
	// ErrStructure reports invalid XMLDSig structure.
	ErrStructure = errors.New("invalid XMLDSig structure")
	// ErrPolicy reports XMLDSig policy violation.
	ErrPolicy = errors.New("XMLDSig policy violation")
	// ErrAlgorithm reports unsupported XMLDSig algorithm.
	ErrAlgorithm = errors.New("unsupported XMLDSig algorithm")
	// ErrReference reports invalid XMLDSig reference.
	ErrReference = errors.New("invalid XMLDSig reference")
	// ErrSignature reports invalid XMLDSig signature value.
	ErrSignature = errors.New("invalid XMLDSig signature value")
	// ErrDigest reports XMLDSig reference digest mismatch.
	ErrDigest = errors.New("XMLDSig reference digest mismatch")
	// ErrKey reports invalid or missing trusted key.
	ErrKey = errors.New("invalid or missing trusted key")
)

func hashForDigest(uri string) (crypto.Hash, error) {
	switch uri {
	case SHA1:
		if fips140.Enabled() {
			return 0, fmt.Errorf("%w: legacy SHA-1 is disabled in FIPS mode", ErrPolicy)
		}

		return crypto.SHA1, nil
	case SHA256:
		return crypto.SHA256, nil
	case SHA384:
		return crypto.SHA384, nil
	case SHA512:
		return crypto.SHA512, nil
	}

	return 0, fmt.Errorf("%w: digest %q", ErrAlgorithm, uri)
}

func signatureAlgorithm(uri string) (crypto.Hash, bool, error) {
	switch uri {
	case DSASHA1, RSASHA1, HMACSHA1:
		if fips140.Enabled() {
			return 0, false, fmt.Errorf("%w: legacy methods are disabled in FIPS mode", ErrPolicy)
		}

		return crypto.SHA1, false, nil
	case Ed25519:
		return 0, false, nil
	case RSASHA256, RSAPSSSHA256, RSAPSS, HMACSHA256:
		return crypto.SHA256, false, nil
	case RSASHA384, RSAPSSSHA384, HMACSHA384:
		return crypto.SHA384, false, nil
	case RSASHA512, RSAPSSSHA512, HMACSHA512, Ed25519ph:
		return crypto.SHA512, false, nil
	case ECDSASHA256:
		return crypto.SHA256, true, nil
	case ECDSASHA384:
		return crypto.SHA384, true, nil
	case ECDSASHA512:
		return crypto.SHA512, true, nil
	}

	return 0, false, fmt.Errorf("%w: signature %q", ErrAlgorithm, uri)
}

func defaultSignature(key crypto.PublicKey) string {
	if _, ok := key.(ed25519.PublicKey); ok {
		return Ed25519
	}

	if k, ok := key.(*ecdsa.PublicKey); ok && k != nil {
		switch k.Curve {
		case elliptic.P384():
			return ECDSASHA384
		case elliptic.P521():
			return ECDSASHA512
		default:
			return ECDSASHA256
		}
	}

	return RSASHA256
}

func validateKey(key crypto.PublicKey, p Policy) error {
	switch k := key.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil || k.N.Sign() <= 0 || k.N.BitLen() < p.MinRSABits || k.N.BitLen() > p.MaxRSABits || k.N.Bit(0) == 0 || k.E < 3 || k.E%2 == 0 || k.E > 0x7fffffff {
			return fmt.Errorf("%w: RSA key outside policy", ErrKey)
		}
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil {
			return fmt.Errorf("%w: incomplete ECDSA key", ErrKey)
		}

		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return fmt.Errorf("%w: unsupported ECDSA curve", ErrKey)
		}

		if _, err := ecdsakey.PublicBytes(k); err != nil {
			return fmt.Errorf("%w: point not on curve", ErrKey)
		}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: Ed25519 public key size", ErrKey)
		}
	case *dsa.PublicKey:
		if fips140.Enabled() {
			return fmt.Errorf("%w: legacy DSA is disabled in FIPS mode", ErrPolicy)
		}

		if err := signature.LegacyDSAKey(k); err != nil {
			return fmt.Errorf("%w: invalid legacy DSA public key", ErrKey)
		}
	default:
		return fmt.Errorf("%w: unsupported public key type", ErrKey)
	}

	return nil
}

func matchKeyAlgorithm(uri string, key crypto.PublicKey) error {
	_, ec, err := signatureAlgorithm(uri)
	if err != nil {
		return err
	}

	ok := false
	if uri == Ed25519 || uri == Ed25519ph {
		_, ok = key.(ed25519.PublicKey)
	} else if uri == DSASHA1 {
		_, ok = key.(*dsa.PublicKey)
	} else if ec {
		_, ok = key.(*ecdsa.PublicKey)
	} else {
		_, ok = key.(*rsa.PublicKey)
	}

	if !ok {
		return fmt.Errorf("%w: algorithm/key mismatch", ErrKey)
	}

	return nil
}

func isPSS(uri string) bool { return uri == RSAPSSSHA256 || uri == RSAPSSSHA384 || uri == RSAPSSSHA512 }

func signPreparedValue(ctx context.Context, uri string, signer crypto.Signer, pub crypto.PublicKey, h crypto.Hash, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if uri == DSASHA1 || uri == RSASHA1 {
		return nil, fmt.Errorf("%w: legacy signature generation is disabled", ErrPolicy)
	}

	var opts crypto.SignerOpts = h
	if isPSS(uri) {
		opts = &rsa.PSSOptions{SaltLength: h.Size(), Hash: h}
	}

	raw, err := signature.SignDigest(ctx, signer, rand.Reader, digest, opts)
	if err == nil {
		err = ctx.Err()
	}

	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}

	if len(raw) > 2048 {
		return nil, fmt.Errorf("%w: signer output size", ErrSignature)
	}

	if k, ok := pub.(*ecdsa.PublicKey); ok {
		var pair struct{ R, S *big.Int }

		rest, err := asn1.Unmarshal(raw, &pair)
		if err != nil || len(rest) != 0 || pair.R == nil || pair.S == nil || pair.R.Sign() <= 0 || pair.S.Sign() <= 0 || pair.R.Cmp(k.Params().N) >= 0 || pair.S.Cmp(k.Params().N) >= 0 {
			return nil, fmt.Errorf("%w: signer returned invalid ECDSA DER", ErrSignature)
		}

		n := (k.Params().BitSize + 7) / 8
		raw = make([]byte, 2*n)
		pair.R.FillBytes(raw[:n])
		pair.S.FillBytes(raw[n:])
	}
	// Do not release a document if an external signer returned a mismatched key,
	// algorithm, or malformed signature. This check is deliberately unconditional.
	if err := verifyPreparedValue(uri, pub, h, digest, raw); err != nil {
		return nil, fmt.Errorf("signer output: %w", err)
	}

	return bytes.Clone(raw), nil
}

func verifyPreparedValue(uri string, pub crypto.PublicKey, h crypto.Hash, digest, sig []byte) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		var err error
		if isPSS(uri) {
			err = rsa.VerifyPSS(k, h, digest, sig, &rsa.PSSOptions{SaltLength: h.Size(), Hash: h})
		} else {
			err = rsa.VerifyPKCS1v15(k, h, digest, sig)
		}

		if err != nil {
			return fmt.Errorf("%w: RSA", ErrSignature)
		}
	case ed25519.PublicKey:
		if err := ed25519.VerifyWithOptions(k, digest, sig, &ed25519.Options{Hash: h}); err != nil {
			return fmt.Errorf("%w: Ed25519", ErrSignature)
		}
	case *ecdsa.PublicKey:
		n := (k.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return fmt.Errorf("%w: ECDSA must be fixed-width r || s", ErrSignature)
		}

		r, s := new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(k, digest, r, s) {
			return fmt.Errorf("%w: ECDSA", ErrSignature)
		}
	case *dsa.PublicKey:
		if uri != DSASHA1 || h != crypto.SHA1 || len(digest) != 20 || len(sig) != 40 {
			return fmt.Errorf("%w: DSA-SHA1 requires fixed-width r || s", ErrSignature)
		}

		if !dsa.Verify(k, digest, new(big.Int).SetBytes(sig[:20]), new(big.Int).SetBytes(sig[20:])) {
			return fmt.Errorf("%w: DSA", ErrSignature)
		}
	default:
		return ErrKey
	}

	return nil
}
