package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"sort"
	"time"
)

func safeMarshalPublic(public crypto.PublicKey) ([]byte, error) {
	switch k := public.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil || k.N.Sign() <= 0 || k.E < 3 {
			return nil, ErrCertificate
		}
	case *ecdsa.PublicKey:
		if k == nil || k.X == nil || k.Y == nil { //nolint:staticcheck // Bytes panics on nil legacy coordinates; reject malformed caller keys first.
			return nil, ErrCertificate
		}

		if _, err := k.Bytes(); err != nil {
			return nil, ErrCertificate
		}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, ErrCertificate
		}
	default:
		return nil, ErrCertificate
	}

	return x509.MarshalPKIXPublicKey(public)
}

func oidEqual(o asn1.ObjectIdentifier, s string) bool { return o.String() == s }

func parseCRLs(ctx context.Context, ders [][]byte) ([]*x509.RevocationList, error) {
	lists := make([]*x509.RevocationList, 0, len(ders))
	for _, der := range ders {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Evidence is borrowed only during this operation, never retained in a
		// result. x509 parsing and signature checking do not modify its bytes.
		list, err := x509.ParseRevocationList(der)
		if err != nil {
			return nil, fmt.Errorf("%w: CRL DER: %w", ErrEvidence, err)
		}

		if err := validateCRLMetadata(list); err != nil {
			return nil, err
		}

		if err := validateCRLExtensions(list); err != nil {
			return nil, err
		}

		if err := validateCRLEntries(ctx, list.RevokedCertificateEntries); err != nil {
			return nil, err
		}

		lists = append(lists, list)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return lists, nil
}

func validateCRLEntries(ctx context.Context, entries []x509.RevocationListEntry) error {
	serials := make(map[string]struct{})

	for i, entry := range entries {
		if i&255 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}

		if entry.SerialNumber == nil || entry.SerialNumber.Sign() < 0 || entry.RevocationTime.IsZero() {
			return ErrEvidence
		}

		serial := entry.SerialNumber.String()
		if _, ok := serials[serial]; ok {
			return fmt.Errorf("%w: duplicate CRL serial", ErrEvidence)
		}

		serials[serial] = struct{}{}

		if entry.ReasonCode == 8 {
			return fmt.Errorf("%w: removeFromCRL requires delta processing", ErrUnsupported)
		}

		if entry.ReasonCode < 0 || entry.ReasonCode > 10 || entry.ReasonCode == 7 {
			return ErrEvidence
		}

		if err := validateCRLEntryExtensions(entry); err != nil {
			return err
		}
	}

	return nil
}

func validateCRLEntryExtensions(entry x509.RevocationListEntry) error {
	seen := make(map[string]struct{})

	for _, ext := range entry.Extensions {
		name := ext.Id.String()
		if _, ok := seen[name]; ok {
			return ErrEvidence
		}

		seen[name] = struct{}{}

		if oidEqual(ext.Id, "2.5.29.29") {
			return fmt.Errorf("%w: indirect CRL entry", ErrUnsupported)
		}

		if ext.Critical && name == "2.5.29.21" {
			return fmt.Errorf("%w: CRL reasonCode must be non-critical", ErrEvidence)
		}

		if ext.Critical {
			return fmt.Errorf("%w: critical CRL entry extension", ErrUnsupported)
		}
	}

	return nil
}

func checkChainCRLs(ctx context.Context, chain []*x509.Certificate, lists []*x509.RevocationList, at time.Time) error {
	for i := 0; i+1 < len(chain); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		cert, issuer := chain[i], chain[i+1]

		chosen, err := selectCRL(ctx, issuer, lists, at)
		if err != nil {
			return err
		}

		if chosen == nil {
			return fmt.Errorf("%w: certificate at chain index %d", ErrUnavailable, i)
		}

		for j, entry := range chosen.RevokedCertificateEntries {
			if j&255 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}

			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 && !entry.RevocationTime.After(at) {
				return fmt.Errorf("%w: chain index %d", ErrRevoked, i)
			}
		}
	}

	return nil
}

// selectCRL authenticates the complete, direct-issuer evidence before choosing
// the newest list. Conflicts in older evidence must not disappear merely because
// a newer list occurs first in the caller's slice (RFC 5280 section 5.2.3).
func selectCRL(ctx context.Context, issuer *x509.Certificate, lists []*x509.RevocationList, at time.Time) (*x509.RevocationList, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// RFC 10007 updates RFC 5280: a v3 issuer must explicitly authorize CRL
	// signing. x509.CheckSignatureFrom also accepts an absent keyUsage.
	if issuer.Version == 3 && issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, nil
	}

	var valid []*x509.RevocationList

	byNumber := make(map[string]*x509.RevocationList)

	for _, list := range lists {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Conservative direct-issuer matching; generalized DN equivalence,
		// indirect and distribution-point scoped CRLs are not implemented.
		if !bytes.Equal(list.RawIssuer, issuer.RawSubject) {
			continue
		}

		if len(list.AuthorityKeyId) > 0 && !bytes.Equal(list.AuthorityKeyId, issuer.SubjectKeyId) {
			continue
		}

		if list.ThisUpdate.After(at) || !at.Before(list.NextUpdate) {
			continue
		}

		if !allowedSignature(list.SignatureAlgorithm) {
			continue
		}

		if err := list.CheckSignatureFrom(issuer); err != nil {
			continue
		}

		number := list.Number.String()
		if previous := byNumber[number]; previous != nil {
			if !bytes.Equal(previous.RawTBSRevocationList, list.RawTBSRevocationList) {
				return nil, fmt.Errorf("%w: conflicting CRLs with the same number", ErrEvidence)
			}

			continue
		}

		byNumber[number] = list
		valid = append(valid, list)
	}

	sort.Slice(valid, func(i, j int) bool {
		if valid[i].ThisUpdate.Equal(valid[j].ThisUpdate) {
			return valid[i].Number.Cmp(valid[j].Number) < 0
		}

		return valid[i].ThisUpdate.Before(valid[j].ThisUpdate)
	})

	for i := 1; i < len(valid); i++ {
		if valid[i].Number.Cmp(valid[i-1].Number) <= 0 {
			return nil, fmt.Errorf("%w: non-monotonic CRL numbers", ErrEvidence)
		}
	}

	if len(valid) == 0 {
		return nil, nil
	}

	return valid[len(valid)-1], nil
}

func validateCRLExtensions(list *x509.RevocationList) error {
	seen := make(map[string]bool)

	for _, ext := range list.Extensions {
		name := ext.Id.String()
		if seen[name] {
			return fmt.Errorf("%w: duplicate CRL extension", ErrEvidence)
		}

		seen[name] = true
		switch name {
		case "2.5.29.27", "2.5.29.28":
			return fmt.Errorf("%w: delta/scoped/indirect CRL", ErrUnsupported)
		case "2.5.29.20", "2.5.29.35": // number and authorityKeyIdentifier parsed by x509
			if ext.Critical {
				return fmt.Errorf("%w: CRL number/authorityKeyIdentifier must be non-critical", ErrEvidence)
			}
		default:
			if ext.Critical {
				return fmt.Errorf("%w: critical CRL extension %s", ErrUnsupported, name)
			}
		}
	}

	return nil
}

// validateCRLMetadata checks the complete-CRL header before extensions or entries.
func validateCRLMetadata(list *x509.RevocationList) error {
	if list.Number == nil || list.Number.Sign() < 0 || list.ThisUpdate.IsZero() || !list.NextUpdate.After(list.ThisUpdate) || len(list.RevokedCertificateEntries) > 100000 {
		return fmt.Errorf("%w: CRL number, dates or entry count", ErrEvidence)
	}

	return nil
}
