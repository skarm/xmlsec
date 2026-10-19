package pki

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
)

// OCSPOptions configures offline evidence checks at the supplied verification
// time; it does not authenticate the issuer itself. SHA-1 CertID/ResponderID
// values are identifiers, not signature algorithms.
type OCSPOptions struct {
	// ExpectedNonce requires an exact response nonce match when nonempty.
	// At most 128 bytes are accepted.
	ExpectedNonce []byte
	// MaxAge bounds evidence age; zero selects 24 hours, with a 30-day maximum.
	MaxAge time.Duration
	// ClockSkew permits time tolerance; zero permits none. Negative values and
	// values greater than ten minutes are rejected.
	ClockSkew time.Duration
	// MaxBytes bounds response DER; zero selects 1 MiB, with an 8 MiB maximum.
	MaxBytes int
	// ResponderCRLs supplies offline revocation evidence for delegated responders.
	// At most 32 CRLs totaling 8 MiB are accepted; nothing is fetched automatically.
	ResponderCRLs [][]byte
}

// OCSPStatus is the status asserted for a certificate by an authenticated OCSP response.
type OCSPStatus string

const (
	// OCSPGood identifies an authenticated good certificate-status assertion.
	OCSPGood OCSPStatus = "good"
	// OCSPRevoked identifies an authenticated revocation assertion.
	OCSPRevoked OCSPStatus = "revoked"
	// OCSPUnknown identifies an unknown certificate-status assertion.
	OCSPUnknown OCSPStatus = "unknown"
)

// OCSPReport records OCSP signature, freshness and certificate-status checks.
type OCSPReport struct {
	Signature              Status     `json:"signature"`
	Status                 OCSPStatus `json:"certificate_status,omitempty"`
	ProducedAt, RevokedAt  time.Time
	ThisUpdate, NextUpdate time.Time
	RevocationReason       int
	Delegated              bool
	Error                  string `json:"error,omitempty"`
}

// OCSPResult is an immutable authenticated OCSP response and responder certificate.
type OCSPResult struct {
	response, responder []byte
	report              OCSPReport
}

// DER returns an owned copy of the original DER encoding.
func (r *OCSPResult) DER() []byte {
	if r == nil {
		return nil
	}

	return bytes.Clone(r.response)
}

// ResponderDER returns an owned copy of the authenticated responder certificate DER.
func (r *OCSPResult) ResponderDER() []byte {
	if r == nil {
		return nil
	}

	return bytes.Clone(r.responder)
}

// Report returns the verification diagnostics.
func (r *OCSPResult) Report() OCSPReport {
	if r == nil {
		return OCSPReport{Signature: NotChecked}
	}

	return r.report
}

// OCSPRequest is one unsigned request. Unsupported extensions/signed requests
// and requestorName are rejected, rather than silently dropping their meaning.
type OCSPRequest struct {
	id         certID
	nonce, raw []byte
}

// ParseOCSPRequest parses one complete bounded OCSP request without authenticating its
// origin.
func ParseOCSPRequest(b []byte) (*OCSPRequest, error) {
	if len(b) > 1<<16 {
		return nil, ErrEvidence
	}

	b = bytes.Clone(b)

	v, e := der.Read(b, 1<<16)
	if e != nil {
		return nil, ErrEvidence
	}

	f, e := der.Sequence(v, 1, 1)
	if e != nil {
		return nil, ErrUnsupported
	}

	t, e := der.Sequence(f[0], 1, 2)
	if e != nil {
		return nil, ErrEvidence
	}

	list, e := der.Sequence(t[0], 1, 1)
	if e != nil {
		return nil, ErrUnsupported
	}

	entry, e := der.Sequence(list[0], 1, 1)
	if e != nil {
		return nil, ErrUnsupported
	}

	id, e := parseCertID(entry[0])
	if e != nil {
		return nil, e
	}

	r := &OCSPRequest{id: id, raw: b}

	if len(t) > 1 {
		x, e := der.Explicit(t[1], 2)
		if e != nil {
			return nil, ErrEvidence
		}

		ext, e := extensions(x)
		if e != nil {
			return nil, e
		}

		for _, x := range ext {
			if !x.Id.Equal(oidOCSPNonce()) {
				return nil, ErrUnsupported
			}
		}

		r.nonce, e = nonceFrom(ext, true)
		if e != nil {
			return nil, e
		}
	}

	return r, nil
}

func parseCertID(v asn1.RawValue) (certID, error) {
	f, e := der.Sequence(v, 4, 4)
	if e != nil {
		return certID{}, ErrEvidence
	}

	a, e := signature.Algorithm(f[0])
	if e != nil {
		return certID{}, ErrEvidence
	}

	h, e := signature.Hash(a, true)
	if e != nil {
		return certID{}, ErrUnsupported
	}

	var (
		n, k []byte
		s    *big.Int
	)
	if der.Decode(f[1], &n) != nil || der.Decode(f[2], &k) != nil || der.Decode(f[3], &s) != nil || s == nil || s.Sign() <= 0 || s.BitLen() > 160 || len(n) != h.Size() || len(k) != h.Size() {
		return certID{}, ErrEvidence
	}

	return certID{a, n, k, s}, nil
}

func extensions(v asn1.RawValue) ([]pkix.Extension, error) {
	fields, e := der.Sequence(v, 1, 32)
	if e != nil {
		return nil, ErrEvidence
	}

	var out []pkix.Extension

	seen := map[string]bool{}

	for _, field := range fields {
		f, e := der.Sequence(field, 2, 3)
		if e != nil {
			return nil, ErrEvidence
		}

		var oid asn1.ObjectIdentifier
		if der.Decode(f[0], &oid) != nil || seen[oid.String()] {
			return nil, ErrEvidence
		}

		seen[oid.String()] = true
		x := pkix.Extension{Id: oid}
		i := 1

		if len(f) == 3 {
			if der.Decode(f[1], &x.Critical) != nil || !x.Critical {
				return nil, ErrEvidence
			}

			i++
		}

		if !der.Is(f[i], 0, asn1.TagOctetString, false) {
			return nil, ErrEvidence
		}

		x.Value = f[i].Bytes

		out = append(out, x)
	}

	return out, nil
}

func nonceFrom(exts []pkix.Extension, allow bool) ([]byte, error) {
	var nonce []byte

	for _, e := range exts {
		if e.Id.Equal(oidOCSPNonce()) {
			if !allow || e.Critical {
				return nil, ErrUnsupported
			}

			if der.Unmarshal(e.Value, &nonce) != nil || len(nonce) < 1 || len(nonce) > 128 {
				return nil, ErrEvidence
			}
		} else if e.Critical {
			return nil, fmt.Errorf("%w: critical OCSP extension %s", ErrUnsupported, e.Id)
		}
	}

	return nonce, nil
}

// DER returns an owned copy of the original DER encoding.
func (r *OCSPRequest) DER() []byte {
	if r == nil {
		return nil
	}

	return bytes.Clone(r.raw)
}

// Nonce returns an owned copy of the nonce, or nil when absent.
func (r *OCSPRequest) Nonce() []byte {
	if r == nil {
		return nil
	}

	return bytes.Clone(r.nonce)
}

// Hash returns the request hash algorithm.
func (r *OCSPRequest) Hash() crypto.Hash {
	if r == nil {
		return 0
	}

	h, _ := signature.Hash(r.id.alg, true)

	return h
}

// CreateOCSPRequest encodes a single-certificate OCSP request for the explicit issuer,
// hash and optional nonce. A supplied nonce must contain 32--128 bytes generated
// by a cryptographically strong random source (RFC 9654 section 2.1). Incoming
// requests retain support for legacy 1--31 byte nonces.
func CreateOCSPRequest(certificateDER, issuerDER []byte, h crypto.Hash, nonce []byte) ([]byte, error) {
	if len(nonce) > 0 && len(nonce) < 32 || len(nonce) > 128 {
		return nil, ErrPolicy
	}

	c, e := parseBorrowedCertificate(certificateDER)
	if e != nil {
		return nil, e
	}

	issuer, e := parseBorrowedCertificate(issuerDER)
	if e != nil {
		return nil, e
	}

	id, e := makeCertID(c, issuer, h)
	if e != nil {
		return nil, e
	}

	f := [][]byte{der.Seq(der.Seq(encodeCertID(id)))}
	if len(nonce) > 0 {
		f = append(f, der.Ctx(2, nonceExtensions(nonce)))
	}

	return der.Seq(der.Seq(f...)), nil
}

func publicBits(c *x509.Certificate) ([]byte, error) {
	v, e := der.Read(c.RawSubjectPublicKeyInfo, 1<<20)
	if e != nil {
		return nil, e
	}

	f, e := der.Sequence(v, 2, 2)
	if e != nil {
		return nil, e
	}

	var b asn1.BitString
	if der.Decode(f[1], &b) != nil || b.BitLength%8 != 0 {
		return nil, ErrCertificate
	}

	return b.Bytes, nil
}

func makeCertID(c, issuer *x509.Certificate, h crypto.Hash) (certID, error) {
	if h == 0 {
		h = crypto.SHA256
	}

	a, e := signature.DigestAlgorithm(h)
	if e != nil {
		return certID{}, ErrPolicy
	}

	if c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 || c.SerialNumber.BitLen() > 160 || !bytes.Equal(c.RawIssuer, issuer.RawSubject) || c.CheckSignatureFrom(issuer) != nil {
		return certID{}, ErrCertificate
	}

	bits, e := publicBits(issuer)
	if e != nil {
		return certID{}, e
	}

	n, _ := signature.Sum(h, issuer.RawSubject)
	k, _ := signature.Sum(h, bits)

	return certID{a, n, k, new(big.Int).Set(c.SerialNumber)}, nil
}

func encodeCertID(c certID) []byte {
	s, _ := asn1.Marshal(c.serial)
	return der.Seq(signature.EncAlgorithm(c.alg), der.Octets(c.name), der.Octets(c.key), s)
}

func nonceExtensions(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}

	return der.Seq(der.Seq(der.OID(oidOCSPNonce()), der.Octets(der.Octets(b))))
}

func oidOCSPBasic() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
}

func oidOCSPNonce() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
}

func oidOCSPNoCheck() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
}

type certID struct {
	alg       pkix.AlgorithmIdentifier
	name, key []byte
	serial    *big.Int
}

func sameCertID(a, b certID) bool {
	ha, ea := signature.Hash(a.alg, true)
	hb, eb := signature.Hash(b.alg, true)

	return ea == nil && eb == nil && ha == hb && a.serial.Cmp(b.serial) == 0 && subtle.ConstantTimeCompare(a.name, b.name) == 1 && subtle.ConstantTimeCompare(a.key, b.key) == 1
}
