package cms

import (
	"encoding/asn1"
	"errors"
)

var (
	// ErrSyntax reports invalid or unsupported CMS SignedData.
	ErrSyntax = errors.New("invalid or unsupported CMS SignedData")
	// ErrPolicy reports CMS policy violation.
	ErrPolicy = errors.New("CMS policy violation")
	// ErrSignature reports CMS signature or content digest mismatch.
	ErrSignature = errors.New("CMS signature or content digest mismatch")
	// ErrCertificate reports CMS signer certificate binding mismatch.
	ErrCertificate = errors.New("CMS signer certificate binding mismatch")
)

// Limits bounds DER parsing and CMS collections. Zero fields select defaults;
// invalid or excessive limits return [ErrPolicy].
type Limits struct {
	// MaxBytes bounds the DER container; zero selects 16 MiB, with a 64 MiB maximum.
	MaxBytes int
	// MaxContentBytes bounds content independently of the DER container size.
	// Zero selects the smaller of 12 MiB and MaxBytes.
	MaxContentBytes int
	// MaxCertificates bounds embedded certificates; zero selects 32, with a maximum of 128.
	MaxCertificates int
	// MaxSigners bounds signer infos; zero selects 16, with a maximum of 32.
	MaxSigners int
	// MaxAttributes bounds each attribute set; zero selects 64, with a maximum of 128.
	MaxAttributes int
}

// DefaultLimits returns a fresh value containing the default resource budgets.
func DefaultLimits() Limits { return Limits{16 << 20, 12 << 20, 32, 16, 64} }

// DataOID returns an owned copy of the CMS id-data object identifier.
func DataOID() asn1.ObjectIdentifier { return append(asn1.ObjectIdentifier(nil), oidData()...) }

func oidData() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1} }

func oidSignedData() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2} }

func oidContentType() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3} }

func oidSigningTime() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5} }

func oidCountersignature() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
}

func oidMessageDigest() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
}

func oidSigningCertificate() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
}

func oidSigningCertificateV2() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
}

func oidAlgorithmProtect() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 52}
}

func normalize(l Limits) (Limits, error) {
	d := DefaultLimits()
	if l.MaxBytes == 0 {
		l.MaxBytes = d.MaxBytes
	}

	if l.MaxContentBytes == 0 {
		l.MaxContentBytes = min(l.MaxBytes, d.MaxContentBytes)
	}

	if l.MaxCertificates == 0 {
		l.MaxCertificates = d.MaxCertificates
	}

	if l.MaxSigners == 0 {
		l.MaxSigners = d.MaxSigners
	}

	if l.MaxAttributes == 0 {
		l.MaxAttributes = d.MaxAttributes
	}

	if l.MaxBytes < 1 || l.MaxBytes > 64<<20 || l.MaxContentBytes < 1 || l.MaxCertificates < 1 || l.MaxCertificates > 128 || l.MaxSigners < 1 || l.MaxSigners > 32 || l.MaxAttributes < 2 || l.MaxAttributes > 128 {
		return l, ErrPolicy
	}

	return l, nil
}
