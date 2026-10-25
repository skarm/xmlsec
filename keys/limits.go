package keys

import (
	"encoding/asn1"
	"errors"

	"github.com/skarm/xmlsec/internal/der"
)

// Limits bounds key-material processing. Each zero field selects its default;
// negative values are rejected. Budgets are independent of algorithm strength
// and certificate trust policy. Parsing and export use the same limits.
type Limits struct {
	// MaxInputBytes bounds the complete encoded input, including PEM framing,
	// whitespace and Base64. Zero selects 32 MiB.
	MaxInputBytes int
	// MaxKeyBytes bounds one decoded, unencrypted DER key; zero selects 64 KiB.
	MaxKeyBytes int
	// MaxCertificateBytes bounds one DER certificate; zero selects 1 MiB.
	MaxCertificateBytes int
	// MaxCRLBytes bounds one DER revocation list; zero selects 16 MiB.
	MaxCRLBytes int
	// MaxContainerBytes bounds encrypted PKCS#8, PKCS#12 and their intermediate
	// encoded contents, including exported DER. Zero selects 16 MiB.
	MaxContainerBytes int
	// MaxASN1Depth bounds nested DER or explicitly enabled BER values, counting the root at depth one;
	// zero selects 32. OCTET STRING payloads are checked separately when decoded.
	MaxASN1Depth int
	// MaxASN1Nodes bounds DER values in each decoded structure; zero selects 1000000.
	MaxASN1Nodes int
	// MaxRSABits bounds RSA modulus and private integer components before private-key
	// validation; zero selects 16384. It does not set a minimum key strength.
	MaxRSABits int
	// MaxRSAPrimes bounds RSA private factors; zero selects 8. Values below two are invalid.
	MaxRSAPrimes int
	// MaxCertificates bounds all PKCS#12 certificate bags; zero selects 16.
	MaxCertificates int
	// MaxBags bounds all PKCS#12 safe bags, including enabled nested containers;
	// zero selects 32. Nested SafeContents also obey MaxASN1Depth.
	MaxBags int
	// MaxContentInfos bounds PKCS#12 authenticated-safe content infos; zero selects 8.
	MaxContentInfos int
	// MaxCRLEntries bounds revoked-certificate entries before X.509 allocation;
	// zero selects 100000.
	MaxCRLEntries int
	// MaxPasswordBytes bounds password bytes before copying or conversion; zero selects 1024.
	MaxPasswordBytes int
	// MinIterations enforces an import/storage-policy floor; zero selects 1000.
	MinIterations int
	// MaxIterations bounds each KDF; zero selects 1000000.
	MaxIterations int
	// MaxKDFWork bounds aggregate PRF/hash iterations per operation. Each PBKDF2
	// output block costs its iteration count. Zero selects 3000000.
	MaxKDFWork int
}

// DefaultLimits returns independent resource budgets for key material, containers and KDFs.
func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes:       32 << 20,
		MaxKeyBytes:         64 << 10,
		MaxCertificateBytes: 1 << 20,
		MaxCRLBytes:         16 << 20,
		MaxContainerBytes:   16 << 20,
		MaxASN1Depth:        32,
		MaxASN1Nodes:        1000000,
		MaxRSABits:          16384,
		MaxRSAPrimes:        8,
		MaxCertificates:     16,
		MaxBags:             32,
		MaxContentInfos:     8,
		MaxCRLEntries:       100000,
		MaxPasswordBytes:    1024,
		MinIterations:       1000,
		MaxIterations:       1000000,
		MaxKDFWork:          3000000,
	}
}

func normalizeLimits(l Limits) (Limits, error) {
	d := DefaultLimits()
	fields := []struct {
		value    *int
		fallback int
	}{
		{value: &l.MaxInputBytes, fallback: d.MaxInputBytes},
		{value: &l.MaxKeyBytes, fallback: d.MaxKeyBytes},
		{value: &l.MaxCertificateBytes, fallback: d.MaxCertificateBytes},
		{value: &l.MaxCRLBytes, fallback: d.MaxCRLBytes},
		{value: &l.MaxContainerBytes, fallback: d.MaxContainerBytes},
		{value: &l.MaxASN1Depth, fallback: d.MaxASN1Depth},
		{value: &l.MaxASN1Nodes, fallback: d.MaxASN1Nodes},
		{value: &l.MaxRSABits, fallback: d.MaxRSABits},
		{value: &l.MaxRSAPrimes, fallback: d.MaxRSAPrimes},
		{value: &l.MaxCertificates, fallback: d.MaxCertificates},
		{value: &l.MaxBags, fallback: d.MaxBags},
		{value: &l.MaxContentInfos, fallback: d.MaxContentInfos},
		{value: &l.MaxCRLEntries, fallback: d.MaxCRLEntries},
		{value: &l.MaxPasswordBytes, fallback: d.MaxPasswordBytes},
		{value: &l.MinIterations, fallback: d.MinIterations},
		{value: &l.MaxIterations, fallback: d.MaxIterations},
		{value: &l.MaxKDFWork, fallback: d.MaxKDFWork},
	}

	for _, field := range fields {
		if *field.value < 0 {
			return l, ErrPolicy
		}

		if *field.value == 0 {
			*field.value = field.fallback
		}
	}

	if l.MinIterations > l.MaxIterations || l.MaxRSAPrimes < 2 {
		return l, ErrPolicy
	}

	return l, nil
}

func readDER(raw []byte, maximum int, limits Limits) (asn1.RawValue, error) {
	v, err := der.ReadLimits(raw, maximum, limits.MaxASN1Depth, limits.MaxASN1Nodes)
	if err != nil {
		return asn1.RawValue{}, derError(err)
	}

	return v, nil
}

func derError(err error) error {
	if errors.Is(err, der.ErrLimit) {
		return ErrLimit
	}

	return ErrFormat
}
