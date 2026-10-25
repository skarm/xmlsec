package pki

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/x509crl"
)

type parsedCRL struct {
	work               *crlWorkBudget
	authentication     map[crlAuthenticationKey]*x509.Certificate
	sources            []*evidence.Observation
	authenticated      []*VerifiedEvidence
	used               []*VerifiedEvidence
	ownedRaw           []byte
	raw                []byte
	tbs                []byte
	issuer             []byte
	signature          []byte
	issuerKey          string
	algorithm          pkix.AlgorithmIdentifier
	version            int
	signatureAlgorithm x509.SignatureAlgorithm
	retainedFrom       time.Time
	this               time.Time
	next               time.Time
	number             *big.Int
	base               *big.Int
	authorityKeyID     []byte
	authorityIssuers   []crlGeneralName
	authoritySerial    *big.Int
	scope              crlScope
	entries            []crlEntry
	freshest           []crlDistributionPoint
	candidates         [][]byte
}

type crlEntry struct {
	serial     *big.Int
	revoked    time.Time
	invalidity time.Time
	reason     int
	issuers    []crlGeneralName
}

func parseCRL(ctx context.Context, raw []byte) (*parsedCRL, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	view, err := x509crl.ParseEvidence(raw, 64<<20)
	if err != nil {
		if errors.Is(err, x509crl.ErrLimit) {
			return nil, fmt.Errorf("%w: %w: %w", ErrPolicy, ErrLimit, err)
		}

		return nil, fmt.Errorf("%w: CRL DER: %w", ErrEvidence, err)
	}

	source := view.CRL
	list := &parsedCRL{
		raw:                source.Raw,
		tbs:                source.RawTBSRevocationList,
		issuer:             source.RawIssuer,
		signature:          source.Signature,
		algorithm:          view.Algorithm,
		version:            view.Version,
		signatureAlgorithm: source.SignatureAlgorithm,
		this:               source.ThisUpdate,
		next:               source.NextUpdate,
		scope:              crlScope{crlDistributionPoint: crlDistributionPoint{reasons: allCRLReasons}},
	}

	if !list.next.IsZero() && !list.next.After(list.this) {
		return nil, ErrEvidence
	}

	if err := list.parseExtensions(ctx, source.Extensions); err != nil {
		return nil, err
	}

	if list.version == 1 && list.number == nil || list.base != nil && (list.number == nil || list.number.Cmp(list.base) <= 0) {
		return nil, ErrEvidence
	}

	issuerName, err := crlDirectoryName(ctx, list.issuer)
	if err != nil {
		return nil, err
	}

	list.issuerKey = issuerName.key
	if err := list.parseEntries(ctx, source.RevokedCertificateEntries, issuerName); err != nil {
		return nil, err
	}

	return list, ctx.Err()
}

func (l *parsedCRL) parseEntries(ctx context.Context, entries []x509.RevocationListEntry, issuerName crlGeneralName) error {
	currentIssuer := []crlGeneralName{issuerName}

	seen := make(map[string]struct{}, len(entries))

	l.entries = make([]crlEntry, 0, len(entries))
	for index, parsed := range entries {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}

		if parsed.SerialNumber == nil || parsed.SerialNumber.Sign() < 0 || parsed.SerialNumber.BitLen() > 160 {
			return ErrEvidence
		}

		entry := crlEntry{serial: parsed.SerialNumber, revoked: parsed.RevocationTime, issuers: currentIssuer}
		if err := l.parseEntryExtensions(ctx, &entry, parsed.Extensions); err != nil {
			return err
		}

		currentIssuer = entry.issuers

		if err := reserveCRLEntryNames(seen, &entry); err != nil {
			return err
		}

		if entry.reason == 8 && l.base == nil {
			return ErrEvidence
		}

		l.entries = append(l.entries, entry)
	}

	return ctx.Err()
}

func crlNumber(raw []byte) (*big.Int, error) {
	var number *big.Int
	if der.Unmarshal(raw, &number) != nil || number == nil || number.Sign() < 0 || number.BitLen() > 160 {
		return nil, ErrEvidence
	}

	return number, nil
}

func (l *parsedCRL) parseExtensions(ctx context.Context, list []pkix.Extension) error {
	if err := uniqueCRLExtensions(list); err != nil {
		return err
	}

	for _, ext := range list {
		if err := l.parseExtension(ctx, ext); err != nil {
			return err
		}
	}

	if l.base != nil && len(l.freshest) != 0 {
		return ErrEvidence
	}

	return nil
}

func (l *parsedCRL) parseExtension(ctx context.Context, ext pkix.Extension) error {
	switch ext.Id.String() {
	case "2.5.29.20":
		if ext.Critical {
			return ErrEvidence
		}

		var err error

		l.number, err = crlNumber(ext.Value)
		if err != nil {
			return err
		}
	case "2.5.29.27":
		if !ext.Critical {
			return ErrEvidence
		}

		var err error

		l.base, err = crlNumber(ext.Value)
		if err != nil {
			return err
		}
	case "2.5.29.28":
		if !ext.Critical {
			return ErrEvidence
		}

		var err error

		l.scope, err = parseCRLScope(ctx, ext.Value)
		if err != nil {
			return err
		}
	case "2.5.29.35":
		if ext.Critical {
			return ErrEvidence
		}

		id, err := parseCRLAuthority(ctx, ext.Value)
		if err != nil {
			return err
		}

		l.authorityKeyID = id.keyID
		l.authorityIssuers = id.issuers
		l.authoritySerial = id.serial
	case "2.5.29.60":
		retained, err := parseExpiredCRLRetention(ext, l.this)
		l.retainedFrom = retained

		return err
	case "2.5.29.46":
		if ext.Critical {
			return ErrEvidence
		}

		return l.parseFreshest(ctx, ext.Value)

	case "2.5.29.18":
		value, err := der.Read(ext.Value, 1<<20)
		if err != nil {
			return ErrEvidence
		}

		if _, err := parseGeneralNames(ctx, value, false); err != nil {
			return err
		}
	default:
		if ext.Critical {
			return ErrUnsupported
		}
	}

	return nil
}

type crlAuthority struct {
	keyID   []byte
	issuers []crlGeneralName
	serial  *big.Int
}

func parseCRLAuthority(ctx context.Context, raw []byte) (crlAuthority, error) {
	out := crlAuthority{}

	value, err := der.Read(raw, 1<<20)
	if err != nil {
		return out, ErrEvidence
	}

	fields, err := der.Sequence(value, 1, 3)
	if err != nil {
		return out, ErrEvidence
	}

	previous := -1
	for _, field := range fields {
		if field.Class != 2 || field.Tag <= previous {
			return out, ErrEvidence
		}

		previous = field.Tag
		switch field.Tag {
		case 0:
			if field.IsCompound || len(field.Bytes) == 0 {
				return out, ErrEvidence
			}

			out.keyID = field.Bytes
		case 1:
			out.issuers, err = parseGeneralNames(ctx, field, true)
			if err != nil {
				return out, err
			}
		case 2:
			if field.IsCompound {
				return out, ErrEvidence
			}

			out.serial, err = crlNumber(der.Wrap(0, asn1.TagInteger, false, field.Bytes))
			if err != nil {
				return out, err
			}
		default:
			return out, ErrEvidence
		}
	}

	if (len(out.issuers) != 0) != (out.serial != nil) {
		return out, ErrEvidence
	}

	return out, nil
}

func (l *parsedCRL) parseEntryExtensions(ctx context.Context, entry *crlEntry, extensions []pkix.Extension) error {
	if err := uniqueCRLExtensions(extensions); err != nil {
		return err
	}

	for _, ext := range extensions {
		if err := l.parseEntryExtension(ctx, entry, ext); err != nil {
			return err
		}
	}

	return nil
}

func (l *parsedCRL) parseEntryExtension(ctx context.Context, entry *crlEntry, ext pkix.Extension) error {
	switch ext.Id.String() {
	case "2.5.29.21":
		var reason asn1.Enumerated
		if ext.Critical || der.Unmarshal(ext.Value, &reason) != nil || !validReason(int(reason)) {
			return ErrEvidence
		}

		entry.reason = int(reason)
	case "2.5.29.24":
		if ext.Critical {
			return ErrEvidence
		}

		v, err := der.Read(ext.Value, 64)
		if err != nil {
			return ErrEvidence
		}

		entry.invalidity, err = generalized(v)
		if err != nil {
			return err
		}
	case "2.5.29.29":
		if !ext.Critical || !l.scope.indirect {
			return ErrEvidence
		}

		names, err := parseCRLCertificateIssuer(ctx, ext.Value)
		if err != nil {
			return err
		}

		entry.issuers = names

	default:
		if ext.Critical {
			return ErrUnsupported
		}
	}

	return nil
}

func (l *parsedCRL) verifySignature(public crypto.PublicKey) error {
	if err := allowedPublicKey(public); err != nil {
		return err
	}

	if l.algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}) {
		key, ok := public.(ed25519.PublicKey)
		if !ok || len(l.algorithm.Parameters.FullBytes) != 0 || !ed25519.Verify(key, l.tbs, l.signature) {
			return ErrEvidence
		}

		return nil
	}

	return signature.Verify(public, l.algorithm, l.tbs, l.signature)
}

func uniqueCRLExtensions(extensions []pkix.Extension) error {
	if len(extensions) > 32 {
		return fmt.Errorf("%w: %w: CRL extension count", ErrPolicy, ErrLimit)
	}

	seen := make(map[string]struct{}, len(extensions))
	for _, extension := range extensions {
		name := extension.Id.String()
		if _, exists := seen[name]; exists {
			return ErrEvidence
		}

		seen[name] = struct{}{}
	}

	return nil
}

func reserveCRLEntryNames(seen map[string]struct{}, entry *crlEntry) error {
	names := make(map[string]struct{}, len(entry.issuers))
	for _, name := range entry.issuers {
		if name.tag != 4 {
			continue
		}

		key := name.key + "/" + entry.serial.String()
		if _, exists := names[key]; exists {
			continue
		}

		names[key] = struct{}{}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate CRL issuer/serial", ErrEvidence)
		}

		seen[key] = struct{}{}
	}

	return nil
}

func (l *parsedCRL) parseFreshest(ctx context.Context, raw []byte) error {
	points, err := parseCRLDistributionPoints(ctx, raw)
	if err != nil {
		return err
	}

	for _, point := range points {
		if point.reasonsPresent || len(point.issuer) != 0 {
			return ErrEvidence
		}
	}

	l.freshest = points

	return nil
}

func parseCRLCertificateIssuer(ctx context.Context, raw []byte) ([]crlGeneralName, error) {
	value, err := der.Read(raw, 1<<20)
	if err != nil {
		return nil, ErrEvidence
	}

	names, err := parseGeneralNames(ctx, value, false)
	if err != nil {
		return nil, err
	}

	for _, name := range names {
		if name.tag == 4 {
			return names, nil
		}
	}

	return nil, ErrEvidence
}

func parseExpiredCRLRetention(extension pkix.Extension, issued time.Time) (time.Time, error) {
	if extension.Critical {
		return time.Time{}, ErrEvidence
	}

	value, err := der.Read(extension.Value, 64)
	if err != nil {
		return time.Time{}, ErrEvidence
	}

	retained, err := generalized(value)
	if err != nil || retained.After(issued) {
		return time.Time{}, ErrEvidence
	}

	return retained, nil
}
