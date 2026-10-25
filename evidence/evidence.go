// Package evidence records owned, untrusted observations for later offline
// verification. Transport provenance and retrieval time are never authentication
// or proof of existence. The pki and timestamp packages produce their own opaque
// authenticated facts after checking the relevant signatures and bindings.
package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	// ErrInput reports malformed observation metadata or collector configuration.
	ErrInput = errors.New("evidence: invalid input")
	// ErrLimit reports an exceeded evidence collection or storage budget.
	ErrLimit = errors.New("evidence: resource limit exceeded")
	// ErrPolicy reports a request outside the explicitly configured collection policy.
	ErrPolicy = errors.New("evidence: disallowed resource")
	// ErrResource reports a collection failure, preserving its underlying cause.
	ErrResource = errors.New("evidence: unavailable resource")
)

// Kind identifies the intended offline parser, without asserting valid content.
type Kind string

const (
	// Certificate identifies an untrusted DER certificate observation.
	Certificate Kind = "certificate"
	// CRL identifies an untrusted DER certificate revocation list observation.
	CRL Kind = "crl"
	// OCSP identifies an untrusted DER OCSP response observation.
	OCSP Kind = "ocsp"
	// Timestamp identifies an untrusted timestamp token or response observation.
	Timestamp Kind = "timestamp"
)

// Provenance describes how bytes were obtained. All fields are untrusted host
// metadata. In particular, RetrievedAt cannot establish a historical signing
// time or proof of existence, even after the bytes authenticate successfully.
type Provenance struct {
	// URI is the original absolute source URI, or empty for an unnamed source.
	URI string
	// Redirects lists the followed absolute URIs, in order, excluding URI.
	Redirects []string
	// RetrievedAt is a host observation time; zero means unknown.
	RetrievedAt time.Time
	// RequestSHA256 optionally identifies an accompanying request, such as OCSP.
	// Offline verification must independently bind any expected nonce or CertID.
	RequestSHA256 [32]byte
}

// Observation owns raw bytes and their digest. The zero value is invalid.
// Accessors return fresh copies of all mutable data and support concurrent use.
type Observation struct {
	kind       Kind
	data       []byte
	digest     [32]byte
	provenance Provenance
}

// NewObservation snapshots at most 64 MiB and ten redirect URIs. Input bytes
// must remain unchanged during the call. It performs no format validation,
// authentication, network access or certificate-path processing.
func NewObservation(ctx context.Context, kind Kind, data []byte, provenance Provenance) (*Observation, error) {
	if ctx == nil || !ValidKind(kind) || len(data) == 0 {
		return nil, ErrInput
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(data) > 64<<20 || len(provenance.Redirects) > 10 {
		return nil, ErrLimit
	}

	if provenance.URI != "" && !validProvenanceURI(provenance.URI) {
		return nil, ErrInput
	}

	for _, uri := range provenance.Redirects {
		if !validProvenanceURI(uri) {
			return nil, ErrInput
		}
	}

	provenance.Redirects = append([]string(nil), provenance.Redirects...)
	if !provenance.RetrievedAt.IsZero() {
		provenance.RetrievedAt = provenance.RetrievedAt.UTC()
	}

	owned := bytes.Clone(data)

	digest := sha256.Sum256(owned)
	if err := ctx.Err(); err != nil {
		clear(owned)
		return nil, err
	}

	return &Observation{kind: kind, data: owned, digest: digest, provenance: provenance}, nil
}

// ValidKind reports whether kind names a supported observation category.
func ValidKind(kind Kind) bool {
	return kind == Certificate || kind == CRL || kind == OCSP || kind == Timestamp
}

func validProvenanceURI(raw string) bool {
	if len(raw) > 8192 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\x00\r\n") {
		return false
	}

	u, err := url.Parse(raw)

	return err == nil && u.IsAbs() && u.User == nil
}

// Valid reports that this observation owns a nonempty byte snapshot.
func (o *Observation) Valid() bool { return o != nil && len(o.data) != 0 }

// Size returns the original byte count without allocating a copy; invalid is zero.
func (o *Observation) Size() int {
	if !o.Valid() {
		return 0
	}

	return len(o.data)
}

// Kind returns the intended parser category, or an empty value when invalid.
func (o *Observation) Kind() Kind {
	if !o.Valid() {
		return ""
	}

	return o.kind
}

// Bytes returns an owned copy of the original, unverified bytes.
func (o *Observation) Bytes() []byte {
	if !o.Valid() {
		return nil
	}

	return bytes.Clone(o.data)
}

// DigestSHA256 returns the digest of the original byte snapshot.
func (o *Observation) DigestSHA256() [32]byte {
	if !o.Valid() {
		return [32]byte{}
	}

	return o.digest
}

// FingerprintSHA256 returns the original byte digest in lowercase hexadecimal.
func (o *Observation) FingerprintSHA256() string {
	if !o.Valid() {
		return ""
	}

	return hex.EncodeToString(o.digest[:])
}

// Provenance returns an owned copy of untrusted source metadata.
func (o *Observation) Provenance() Provenance {
	if !o.Valid() {
		return Provenance{}
	}

	p := o.provenance
	p.Redirects = append([]string(nil), p.Redirects...)

	return p
}
