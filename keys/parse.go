package keys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/bits"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/internal/x509crl"
)

const certificatePEMType = "CERTIFICATE"

var (
	// ErrFormat reports malformed, ambiguous or unsupported key material.
	ErrFormat = errors.New("invalid or unsupported key material")
	// ErrLimit reports input, key components or KDF work exceeding a resource budget.
	ErrLimit = errors.New("key material limit exceeded")
)

// ParsePrivate parses exactly one unencrypted PKCS#8, RSA PKCS#1 or EC SEC1
// private key in PEM or DER. PEM labels are authoritative. The returned signer
// owns its data; input bytes are never modified. RSA resource limits are checked
// before crypto/x509 performs private-key validation. Zero limits select defaults.
// Applications must separately apply an operation's algorithm/key-strength policy.
func ParsePrivate(data []byte, limits Limits) (crypto.Signer, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}

	decoded, err := material(context.Background(), data, limits.MaxKeyBytes, limits)
	if err != nil {
		return nil, err
	}
	defer decoded.clear()

	return parsePrivateDER(decoded.label, decoded.der, limits)
}

func parsePrivateDER(label string, raw []byte, limits Limits) (crypto.Signer, error) {
	if err := privateBudget(raw, limits); err != nil {
		return nil, err
	}

	var (
		key any
		err error
	)

	switch label {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(raw)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(raw)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(raw)
	case "":
		key, err = x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			key, err = x509.ParsePKCS1PrivateKey(raw)
		}

		if err != nil {
			key, err = x509.ParseECPrivateKey(raw)
		}
	default:
		return nil, ErrFormat
	}

	if err != nil {
		return nil, fmt.Errorf("%w: private key: %w", ErrFormat, err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: private key is not a signer", ErrFormat)
	}

	if err := validatePrivateStructure(raw, signer, limits); err != nil {
		return nil, err
	}

	return signer, nil
}

// Bound private RSA integers before x509 validates primes and builds CRT values.
// PKCS#8 carries a nested DER key inside its privateKey OCTET STRING.
func privateBudget(raw []byte, limits Limits) error {
	v, err := readDER(raw, limits.MaxKeyBytes, limits)
	if err != nil {
		return err
	}

	fields, err := der.Sequence(v, 2, 16)
	if err != nil {
		return derError(err)
	}

	if len(fields) >= 3 && der.Is(fields[1], 0, asn1.TagSequence, true) && der.Is(fields[2], 0, asn1.TagOctetString, false) {
		v, err = readDER(fields[2].Bytes, limits.MaxKeyBytes, limits)
		if err != nil {
			return err
		}
		// Ed25519's inner value is an OCTET STRING; EC SEC1 has an OCTET STRING second field.
		if !der.Is(v, 0, asn1.TagSequence, true) {
			return nil
		}

		fields, err = der.Sequence(v, 2, 16)
		if err != nil {
			return derError(err)
		}
	}

	if der.Is(fields[0], 0, asn1.TagInteger, false) && der.Is(fields[1], 0, asn1.TagInteger, false) {
		return integerBudget(v, limits)
	}

	return nil
}

func integerBudget(v asn1.RawValue, limits Limits) error {
	if der.Is(v, 0, asn1.TagInteger, false) {
		if !integerWithinBits(v.Bytes, limits.MaxRSABits) {
			return ErrLimit
		}
	}

	if v.IsCompound {
		children, err := der.ChildrenLimit(v, limits.MaxASN1Nodes)
		if err != nil {
			return ErrFormat
		}
		// PKCS#1's additional primes otherwise allow an attacker to multiply a
		// large collection during x509 validation despite bounded components.
		if der.Is(v, 0, asn1.TagSequence, true) && len(children) >= 9 && der.Is(children[0], 0, asn1.TagInteger, false) && der.Is(children[1], 0, asn1.TagInteger, false) && der.Is(children[2], 0, asn1.TagInteger, false) {
			if len(children) > 10 {
				return ErrFormat
			}

			if len(children) == 10 {
				if _, err := der.Sequence(children[9], 0, limits.MaxRSAPrimes-2); err != nil {
					return ErrLimit
				}
			}
		}

		for _, child := range children {
			if err := integerBudget(child, limits); err != nil {
				return err
			}
		}
	}

	return nil
}

func integerWithinBits(value []byte, maximum int) bool {
	if len(value) > 0 && value[0] == 0 {
		value = value[1:]
	}

	if len(value) == 0 {
		return true
	}

	if len(value)-1 > maximum/8 {
		return false
	}

	return (len(value)-1)*8+bits.Len8(value[0]) <= maximum
}

// ParsePublic parses exactly one SPKI or RSA PKCS#1 public key, or extracts the
// public key from one X.509 certificate, in PEM or DER. It does not validate
// certificate trust, lifetime or revocation. Returned data does not alias input.
func ParsePublic(data []byte, limits Limits) (crypto.PublicKey, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}

	decoded, err := material(context.Background(), data, max(limits.MaxKeyBytes, limits.MaxCertificateBytes), limits)
	if err != nil {
		return nil, err
	}

	label, raw := decoded.label, decoded.der

	// A certificate has three outer fields; SPKI and PKCS#1 public keys have two.
	value, err := readDER(raw, max(limits.MaxKeyBytes, limits.MaxCertificateBytes), limits)
	if err != nil {
		return nil, err
	}

	fields, err := der.Sequence(value, 2, 3)
	if err != nil {
		return nil, derError(err)
	}

	certificate := label == certificatePEMType || label == "" && len(fields) == 3
	if !certificate && len(raw) > limits.MaxKeyBytes {
		return nil, ErrLimit
	}

	if !certificate && !decoded.owned {
		// Some x509 public-key models borrow SPKI bytes. Keep that small key
		// encoding owned, while certificate extraction owns only its SPKI.
		raw = bytes.Clone(raw)
	}

	var key any

	switch label {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(raw)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(raw)
	case certificatePEMType:
		return certificateKey(raw, limits)
	case "":
		key, err = x509.ParsePKIXPublicKey(raw)
		if err != nil {
			key, err = x509.ParsePKCS1PublicKey(raw)
		}

		if err != nil {
			return certificateKey(raw, limits)
		}
	default:
		return nil, ErrFormat
	}

	if err != nil {
		return nil, fmt.Errorf("%w: public key: %w", ErrFormat, err)
	}

	if err := publicBudget(key, limits); err != nil {
		return nil, err
	}

	return key, nil
}

func certificateKey(raw []byte, limits Limits) (crypto.PublicKey, error) {
	if len(raw) > limits.MaxCertificateBytes {
		return nil, ErrLimit
	}

	cert, err := x509cert.Parse(raw, x509cert.Limits{Bytes: limits.MaxCertificateBytes, Depth: limits.MaxASN1Depth, Nodes: limits.MaxASN1Nodes})
	if err != nil {
		return nil, fmt.Errorf("%w: certificate: %w", ErrFormat, err)
	}

	if err := publicBudget(cert.PublicKey, limits); err != nil {
		return nil, err
	}

	// Ed25519 and future public-key parsers may borrow their encoded key bytes.
	// Own only SPKI, rather than keeping or copying the entire certificate.
	key, err := x509.ParsePKIXPublicKey(bytes.Clone(cert.RawSubjectPublicKeyInfo))
	if err != nil {
		return nil, fmt.Errorf("%w: public key: %w", ErrFormat, err)
	}

	return key, nil
}

// ParseCertificate parses exactly one X.509 certificate in PEM or DER into an
// owned object. A successful parse is not a certificate validation or trust decision.
func ParseCertificate(data []byte, limits Limits) (*x509.Certificate, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}

	decoded, err := material(context.Background(), data, limits.MaxCertificateBytes, limits)
	if err != nil {
		return nil, err
	}

	if decoded.label != "" && decoded.label != certificatePEMType {
		return nil, ErrFormat
	}

	cert, err := x509cert.Parse(decoded.ownedDER(), x509cert.Limits{Bytes: limits.MaxCertificateBytes, Depth: limits.MaxASN1Depth, Nodes: limits.MaxASN1Nodes})
	if err != nil {
		return nil, fmt.Errorf("%w: certificate: %w", ErrFormat, err)
	}

	if err := publicBudget(cert.PublicKey, limits); err != nil {
		return nil, err
	}

	return cert, nil
}

// ParseCRL parses exactly one X.509 CRL in PEM or DER into an owned object.
// It does not validate the issuer, signature, times or revocation applicability.
func ParseCRL(data []byte, limits Limits) (*x509.RevocationList, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}

	decoded, err := material(context.Background(), data, limits.MaxCRLBytes, limits)
	if err != nil {
		return nil, err
	}

	if decoded.label != "" && decoded.label != "X509 CRL" {
		return nil, ErrFormat
	}

	if err := crlBudget(decoded.der, limits); err != nil {
		return nil, err
	}

	view, err := x509crl.Parse(decoded.ownedDER(), x509crl.Limits{Bytes: limits.MaxCRLBytes, Depth: limits.MaxASN1Depth, Nodes: limits.MaxASN1Nodes, Entries: limits.MaxCRLEntries})
	if err != nil {
		return nil, fmt.Errorf("%w: CRL: %w", ErrFormat, err)
	}

	return view.CRL, nil
}

func crlBudget(raw []byte, limits Limits) error {
	value, err := readDER(raw, limits.MaxCRLBytes, limits)
	if err != nil {
		return err
	}

	fields, err := der.Sequence(value, 3, 3)
	if err != nil {
		return derError(err)
	}

	body, err := der.Sequence(fields[0], 3, 7)
	if err != nil {
		return derError(err)
	}

	index := 0
	if der.Is(body[0], 0, asn1.TagInteger, false) {
		index++
	}
	// Signature algorithm, issuer and thisUpdate precede optional nextUpdate.
	index += 3
	if index < len(body) && (der.Is(body[index], 0, asn1.TagUTCTime, false) || der.Is(body[index], 0, asn1.TagGeneralizedTime, false)) {
		index++
	}

	if index < len(body) && der.Is(body[index], 0, asn1.TagSequence, true) {
		contents := body[index].Bytes
		for count := 0; len(contents) > 0; count++ {
			if count >= limits.MaxCRLEntries {
				return ErrLimit
			}

			var entry asn1.RawValue

			rest, err := asn1.Unmarshal(contents, &entry)
			if err != nil {
				return ErrFormat
			}

			contents = rest
		}
	}

	return nil
}

func publicBudget(key crypto.PublicKey, limits Limits) error {
	if key, ok := key.(*rsa.PublicKey); ok && key.N.BitLen() > limits.MaxRSABits {
		return ErrLimit
	}

	return nil
}

type decodedMaterial struct {
	label string
	der   []byte
	owned bool
}

func (m decodedMaterial) clear() {
	if m.owned {
		clear(m.der)
	}
}

func (m decodedMaterial) ownedDER() []byte {
	if m.owned {
		return m.der
	}

	return bytes.Clone(m.der)
}

func material(ctx context.Context, data []byte, maximum int, limits Limits) (decodedMaterial, error) {
	if len(data) > limits.MaxInputBytes {
		return decodedMaterial{}, ErrLimit
	}

	trimmed := bytes.TrimSpace(data)

	m := decodedMaterial{}

	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		var err error

		m, err = decodePEM(ctx, trimmed, maximum)
		if err != nil {
			return decodedMaterial{}, err
		}
	} else {
		// A final DER byte equal to ASCII whitespace is still data.
		if len(data) > maximum {
			return decodedMaterial{}, ErrLimit
		}

		m.der = data
	}

	if _, err := readDER(m.der, maximum, limits); err != nil {
		m.clear()
		return decodedMaterial{}, err
	}

	return m, nil
}

// decodePEM frames exactly one header-free block and budgets decoded bytes
// before allocation. Base64 whitespace is skipped without copying encoded text.
func decodePEM(ctx context.Context, data []byte, maximum int) (decodedMaterial, error) {
	line, body, ok := pemLine(data)
	if !ok || !bytes.HasSuffix(line, []byte("-----")) || len(line) < 16 || bytes.Count(data, []byte("-----BEGIN ")) != 1 {
		return decodedMaterial{}, ErrFormat
	}

	label := line[11 : len(line)-5]
	if len(label) == 0 || len(label) > 64 {
		return decodedMaterial{}, ErrFormat
	}

	end := bytes.Index(body, []byte("\n-----END "))
	if end < 0 {
		return decodedMaterial{}, ErrFormat
	}

	trailer, rest, _ := pemLine(body[end+1:])
	if len(trailer) != 9+len(label)+5 || !bytes.Equal(trailer[9:len(trailer)-5], label) || !bytes.HasSuffix(trailer, []byte("-----")) || len(bytes.TrimSpace(rest)) != 0 {
		return decodedMaterial{}, ErrFormat
	}

	body = body[:end]

	size, err := pemDecodedSize(ctx, body, maximum)
	if err != nil {
		return decodedMaterial{}, err
	}

	output := make([]byte, size)

	decoder := base64.NewDecoder(base64.StdEncoding, &pemBodyReader{ctx: ctx, data: body})
	if _, err := io.ReadFull(decoder, output); err != nil {
		clear(output)
		return decodedMaterial{}, errors.Join(ErrFormat, err)
	}

	var probe [1]byte
	if n, err := decoder.Read(probe[:]); n != 0 || err != io.EOF {
		clear(output)
		return decodedMaterial{}, errors.Join(ErrFormat, err)
	}

	if err := ctx.Err(); err != nil {
		clear(output)
		return decodedMaterial{}, err
	}

	return decodedMaterial{label: string(label), der: output, owned: true}, nil
}

func pemSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

func pemLine(data []byte) ([]byte, []byte, bool) {
	line, rest, newline := bytes.Cut(data, []byte{'\n'})
	if newline && len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}

	return bytes.TrimRight(line, " \t"), rest, newline
}

func pemDecodedSize(ctx context.Context, data []byte, maximum int) (int, error) {
	count, padding := 0, 0

	for i, c := range data {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}

		if pemSpace(c) {
			continue
		}

		count++

		if c == '=' {
			padding++
		} else if padding > 0 || !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
			return 0, ErrFormat
		}
	}

	if count%4 != 0 || padding > 2 || count == 0 {
		return 0, ErrFormat
	}

	size := count/4*3 - padding
	if size > maximum {
		return 0, ErrLimit
	}

	return size, nil
}

type pemBodyReader struct {
	ctx  context.Context
	data []byte
}

func (r *pemBodyReader) Read(dst []byte) (int, error) {
	used := 0
	for len(r.data) > 0 && used < len(dst) {
		if err := r.ctx.Err(); err != nil {
			return used, err
		}

		span := r.data[:min(len(r.data), 4096)]

		taken := 0
		for taken < len(span) && used < len(dst) {
			c := span[taken]
			taken++

			if !pemSpace(c) {
				dst[used] = c
				used++
			}
		}

		r.data = r.data[taken:]
	}

	if used == 0 && len(dst) > 0 {
		return 0, io.EOF
	}

	return used, nil
}
