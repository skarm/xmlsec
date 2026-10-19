package keys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
)

// PKCS12Identity contains owned, mutable objects from a password-authenticated
// container. Certificate matches PrivateKey by SPKI. ExtraCertificates are
// unordered untrusted evidence, not a verified chain or trust anchors.
// The container MAC proves password integrity, not sender identity or PKIX trust.
type PKCS12Identity struct {
	PrivateKey        crypto.Signer
	Certificate       *x509.Certificate
	ExtraCertificates []*x509.Certificate
}

// ParsePKCS12 imports one complete DER PFX version 3 with mandatory password
// integrity and exactly one private key with one matching certificate. It accepts
// PBMAC1/PBKDF2 or traditional SHA-2 MAC, and PBES2/AES-CBC encrypted SafeContents
// and shrouded keys. UTF-8 password bytes are passed unchanged to PBKDF2; classic
// MAC converts a BMP-only password to big-endian BMP with a terminal zero pair.
// Limits apply across all KDFs; the MAC is verified before decrypting any bags.
// Limits also bound ContentInfos, flat bags and certificate objects.
// Unknown/nested bags, attributes other than localKeyId/friendlyName, conflicting
// identifiers and ambiguous identities are rejected. No partial identity is
// returned on error, and no I/O or certificate trust validation is performed.
func ParsePKCS12(ctx context.Context, data, password []byte, limits Limits) (*PKCS12Identity, error) {
	state, err := newPasswordState(ctx, password, limits)
	if err != nil {
		return nil, err
	}
	defer state.close()

	if !validPKCS12Password(state.password) {
		return nil, ErrPolicy
	}

	if len(data) > state.limits.MaxInputBytes || len(data) > state.limits.MaxContainerBytes {
		return nil, ErrLimit
	}

	// The container is borrowed for this call. Keys are decoded into independent
	// objects, and certificates get their own DER before plaintext is cleared.
	v, err := readDER(data, state.limits.MaxContainerBytes, state.limits)
	if err != nil {
		return nil, err
	}

	f, err := der.Sequence(v, 3, 3) // MacData is mandatory in this profile.
	if err != nil {
		return nil, ErrFormat
	}

	version, err := integer(f[0])
	if err != nil || version != 3 {
		return nil, ErrFormat
	}

	oid, authSafe, err := contentInfo(f[1])
	if err != nil || !oid.Equal(oidData()) || !der.Is(authSafe, 0, asn1.TagOctetString, false) {
		return nil, ErrFormat
	}

	if err := verifyPKCS12MAC(state, f[2], authSafe.Bytes); err != nil {
		return nil, err
	}

	v, err = readDER(authSafe.Bytes, state.limits.MaxContainerBytes, state.limits)
	if err != nil {
		return nil, err
	}

	infos, err := der.Sequence(v, 1, state.limits.MaxContentInfos)
	if err != nil {
		return nil, derError(err)
	}

	parser := identityParser{state: state}

	if returned1, matchedBranch := parsePKCS12Infos(infos, &parser, state); matchedBranch {
		return nil, returned1
	}

	if parser.private == nil || len(parser.certs) == 0 {
		return nil, ErrFormat
	}

	identity, err := matchIdentity(parser.private, parser.certs, parser.keyID, parser.certIDs)
	if err != nil {
		return nil, err
	}

	if err := state.ctx.Err(); err != nil {
		return nil, err
	}

	return identity, nil
}

func contentInfo(v asn1.RawValue) (asn1.ObjectIdentifier, asn1.RawValue, error) {
	f, err := der.Sequence(v, 2, 2)
	if err != nil {
		return nil, asn1.RawValue{}, ErrFormat
	}

	var oid asn1.ObjectIdentifier
	if !der.Is(f[0], 0, asn1.TagOID, false) || der.Decode(f[0], &oid) != nil {
		return nil, asn1.RawValue{}, ErrFormat
	}

	content, err := der.Explicit(f[1], 0)
	if err != nil {
		return nil, asn1.RawValue{}, ErrFormat
	}

	return oid, content, nil
}

func decryptSafeContents(state *passwordState, v asn1.RawValue) ([]byte, error) {
	f, err := der.Sequence(v, 2, 2)
	if err != nil {
		return nil, ErrFormat
	}

	version, err := integer(f[0])
	if err != nil || version != 0 {
		return nil, ErrFormat
	}

	info, err := der.Sequence(f[1], 3, 3)
	if err != nil || !der.OIDEqual(info[0], oidData()) || !der.Is(info[2], 2, 0, false) {
		return nil, ErrFormat
	}

	return decryptPBES2(state, info[1], info[2].Bytes, state.limits.MaxContainerBytes)
}

func parsePKCS12Infos(infos []asn1.RawValue, parser *identityParser, state *passwordState) (returned1 error, matchedBranch bool) {
	for _, info := range infos {
		oid, content, err := contentInfo(info)
		if err != nil {
			return err, true
		}

		switch {
		case oid.Equal(oidData()):
			if !der.Is(content, 0, asn1.TagOctetString, false) {
				return ErrFormat, true
			}

			if err := parser.safeContents(content.Bytes); err != nil {
				return err, true
			}
		case oid.Equal(oidEncryptedData()):
			plain, err := decryptSafeContents(state, content)
			if err != nil {
				return err, true
			}

			err = parser.safeContents(plain)
			clear(plain[:cap(plain)])

			if err != nil {
				return err, true
			}
		default:
			return ErrPolicy, true
		}
	}

	return returned1, matchedBranch
}

// PKCS12Options selects encryption and integrity for DER PKCS#12 output.
// Both integrity modes require a MAC and use independently generated salts.
// No RC2, 3DES, SHA-1, BER or MAC-less output is supported. Password bytes are
// UTF-8; empty passwords are import-only.
type PKCS12Options struct {
	Encryption EncryptionOptions
	// ClassicMAC selects RFC 7292 SHA-2 integrity and requires a BMP-only password.
	// False selects RFC 9879 PBMAC1 with UTF-8 passwords.
	ClassicMAC bool
}

// MarshalPKCS12 exports one private key, its matching certificate and optional
// additional certificates to a password-authenticated DER PFX. It encrypts both
// certificate SafeContents and the PKCS#8 key with separate PBES2 salts/IVs;
// the MAC is mandatory. Zero options use RFC 9879 PBMAC1. ClassicMAC explicitly
// selects RFC 7292 SHA-2 integrity for older readers. Certificate objects are
// parsed from their Raw DER, ownership is copied and no trust is inferred.
// Password must be nonempty UTF-8. It performs no file/network I/O.
func MarshalPKCS12(ctx context.Context, identity PKCS12Identity, password []byte, options PKCS12Options, limits Limits) ([]byte, error) {
	parts, err := preparePKCS12(ctx, identity, password, options, limits)
	if err != nil {
		return nil, err
	}

	return parts.bytes(ctx)
}

// WritePKCS12 exports a password-authenticated PFX directly to dst. It retains
// certificate snapshots and ciphertext but does not build a complete PFX or
// repeated nested DER buffers. Limits and KDF work are checked before output.
// The destination stays open and may contain partial output on error.
func WritePKCS12(ctx context.Context, dst io.Writer, identity PKCS12Identity, password []byte, options PKCS12Options, limits Limits) (int64, error) {
	if nilcheck.IsNil(dst) {
		return 0, ErrPolicy
	}

	parts, err := preparePKCS12(ctx, identity, password, options, limits)
	if err != nil {
		return 0, err
	}

	return parts.write(ctx, dst)
}

func oidData() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1} }

func oidEncryptedData() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
}

func oidShroudedKeyBag() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
}

func oidCertBag() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
}

func oidX509Cert() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
}

func oidLocalKeyID() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21} }

type identityParser struct {
	state   *passwordState
	private crypto.Signer
	keyID   []byte
	certs   []*x509.Certificate
	certIDs [][]byte
	bags    int
}

func (p *identityParser) safeContents(raw []byte) error {
	if err := p.state.ctx.Err(); err != nil {
		return err
	}

	v, err := readDER(raw, p.state.limits.MaxContainerBytes, p.state.limits)
	if err != nil {
		return err
	}

	bags, err := der.Sequence(v, 0, p.state.limits.MaxBags)
	if err != nil {
		return ErrLimit
	}

	if len(bags) > p.state.limits.MaxBags-p.bags {
		return ErrLimit
	}

	p.bags += len(bags)
	for _, bag := range bags {
		if err := p.parseSafeBag(bag); err != nil {
			return err
		}
	}

	return p.state.ctx.Err()
}

func (p *identityParser) parseSafeBag(bag asn1.RawValue) error {
	f, err := der.Sequence(bag, 2, 3)
	if err != nil {
		return ErrFormat
	}

	value, err := der.Explicit(f[1], 0)
	if err != nil {
		return ErrFormat
	}

	var id []byte
	if len(f) == 3 {
		id, err = bagID(f[2])
		if err != nil {
			return err
		}
	}

	switch {
	case der.OIDEqual(f[0], oidShroudedKeyBag()), der.OIDEqual(f[0], oidKeyBag()):
		if p.private != nil {
			return ErrFormat
		}

		if der.OIDEqual(f[0], oidShroudedKeyBag()) {
			p.private, err = decryptPrivateInfo(p.state, value.FullBytes)
		} else {
			p.private, err = parseDecryptedPrivate(p.state, value.FullBytes)
		}

		if err != nil {
			return err
		}

		p.keyID = id
	case der.OIDEqual(f[0], oidCertBag()):
		if len(p.certs) >= p.state.limits.MaxCertificates {
			return ErrLimit
		}

		cert, err := der.Sequence(value, 2, 2)
		if err != nil || !der.OIDEqual(cert[0], oidX509Cert()) {
			return ErrFormat
		}

		data, err := der.Explicit(cert[1], 0)
		if err != nil || !der.Is(data, 0, asn1.TagOctetString, false) {
			return ErrFormat
		}

		c, err := ParseCertificate(data.Bytes, p.state.limits)
		if err != nil {
			return err
		}

		for _, prior := range p.certs {
			if bytes.Equal(prior.Raw, c.Raw) {
				return ErrFormat
			}
		}

		p.certs = append(p.certs, c)
		p.certIDs = append(p.certIDs, id)
	default:
		return ErrPolicy
	}

	return nil
}

func oidKeyBag() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
}

func oidFriendlyName() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
}

func bagID(attributes asn1.RawValue) ([]byte, error) {
	fields, err := der.SetFields(attributes, 0, asn1.TagSet, 2)
	if err != nil {
		return nil, ErrFormat
	}

	var id []byte

	nameSeen, idSeen := false, false

	for _, attr := range fields {
		f, err := der.Sequence(attr, 2, 2)
		if err != nil {
			return nil, ErrFormat
		}

		values, err := der.SetFields(f[1], 0, asn1.TagSet, 1)
		if err != nil || len(values) != 1 {
			return nil, ErrFormat
		}

		value := values[0]

		switch {
		case der.OIDEqual(f[0], oidLocalKeyID()):
			if idSeen || !der.Is(value, 0, asn1.TagOctetString, false) || len(value.Bytes) == 0 || len(value.Bytes) > 64 {
				return nil, ErrFormat
			}

			idSeen = true
			id = bytes.Clone(value.Bytes)
		case der.OIDEqual(f[0], oidFriendlyName()):
			if nameSeen || !der.Is(value, 0, asn1.TagBMPString, false) || len(value.Bytes) > 512 || len(value.Bytes)%2 != 0 {
				return nil, ErrFormat
			}

			for i := 0; i < len(value.Bytes); i += 2 {
				r := uint16(value.Bytes[i])<<8 | uint16(value.Bytes[i+1])
				if r >= 0xd800 && r <= 0xdfff {
					return nil, ErrFormat
				}
			}

			nameSeen = true
		default:
			return nil, ErrPolicy
		}
	}

	return id, nil
}

func matchIdentity(key crypto.Signer, certs []*x509.Certificate, keyID []byte, certIDs [][]byte) (*PKCS12Identity, error) {
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, ErrFormat
	}

	out := &PKCS12Identity{PrivateKey: key}

	for i, c := range certs {
		certificatePublic, err := x509.MarshalPKIXPublicKey(c.PublicKey)
		if err != nil {
			return nil, ErrFormat
		}

		matches := bytes.Equal(public, certificatePublic)

		idMatches := len(keyID) > 0 && len(certIDs[i]) > 0 && bytes.Equal(keyID, certIDs[i])
		if idMatches && !matches {
			return nil, ErrFormat
		}

		if matches {
			if out.Certificate != nil || len(keyID) > 0 && len(certIDs[i]) > 0 && !idMatches {
				return nil, ErrFormat
			}

			out.Certificate = c
		} else {
			out.ExtraCertificates = append(out.ExtraCertificates, c)
		}
	}

	if out.Certificate == nil {
		return nil, ErrFormat
	}

	return out, nil
}

func dataInfo(contents []byte) []byte {
	return der.Seq(der.OID(oidData()), der.Ctx(0, der.Octets(contents)))
}

func safeBag(oid asn1.ObjectIdentifier, value, attributes []byte) []byte {
	parts := [][]byte{der.OID(oid), der.Ctx(0, value)}
	if attributes != nil {
		parts = append(parts, attributes)
	}

	return der.Seq(parts...)
}

func preparePKCS12(ctx context.Context, identity PKCS12Identity, password []byte, options PKCS12Options, limits Limits) (derParts, error) {
	if len(password) == 0 {
		return nil, ErrPolicy
	}

	var err error

	options.Encryption, err = normalizeEncryption(options.Encryption)
	if err != nil {
		return nil, err
	}

	state, err := newPasswordState(ctx, password, limits)
	if err != nil {
		return nil, err
	}
	defer state.close()

	if !validPKCS12Password(state.password) {
		return nil, ErrPolicy
	}

	if options.ClassicMAC {
		bmp, err := bmpPassword(state.password)
		clear(bmp)

		if err != nil {
			return nil, err
		}
	}

	if identity.Certificate == nil {
		return nil, ErrPolicy
	}

	if len(identity.ExtraCertificates) >= state.limits.MaxCertificates || len(identity.ExtraCertificates) > state.limits.MaxBags-2 || state.limits.MaxContentInfos < 2 {
		return nil, ErrLimit
	}

	private, key, err := privateEncoding(identity.PrivateKey, state.limits)
	if err != nil {
		return nil, err
	}
	defer clear(private)

	certs := make([]*x509.Certificate, 0, 1+len(identity.ExtraCertificates))
	seen := make(map[[32]byte]bool)
	totalBytes := len(private)
	certificateLimits := state.limits
	certificateLimits.MaxInputBytes = state.limits.MaxCertificateBytes

	for _, c := range append([]*x509.Certificate{identity.Certificate}, identity.ExtraCertificates...) {
		if c == nil {
			return nil, ErrPolicy
		}

		if len(c.Raw) > state.limits.MaxContainerBytes-totalBytes {
			return nil, ErrLimit
		}

		totalBytes += len(c.Raw)

		parsed, err := ParseCertificate(c.Raw, certificateLimits)
		if err != nil {
			return nil, err
		}

		fingerprint := sha256.Sum256(parsed.Raw)

		if seen[fingerprint] {
			return nil, ErrFormat
		}

		seen[fingerprint] = true

		certs = append(certs, parsed)
	}

	matched, err := matchIdentity(key, certs, nil, make([][]byte, len(certs)))
	if err != nil || matched.Certificate != certs[0] {
		return nil, ErrFormat
	}

	id := sha256.Sum256(certs[0].Raw)
	attributes := der.Set(der.Seq(der.OID(oidLocalKeyID()), der.Set(der.Octets(id[:]))))

	var certBags []derParts

	for i, c := range certs {
		var attrs []byte
		if i == 0 {
			attrs = attributes
		}

		value := frameDER(0x30, derParts{der.OID(oidX509Cert())}, frameDER(0xa0, frameDER(4, derParts{c.Raw})))
		certBags = append(certBags, frameDER(0x30, derParts{der.OID(oidCertBag())}, frameDER(0xa0, value), derParts{attrs}))
	}

	certContents := frameDER(0x30, certBags...)

	certAlg, certCipher, err := encryptPBES2Parts(state, certContents, options.Encryption)
	if err != nil {
		return nil, err
	}

	certInfo := frameDER(0x30, derParts{der.OID(oidEncryptedData())}, frameDER(0xa0, frameDER(0x30, derParts{der.Int(0)}, frameDER(0x30, derParts{der.OID(oidData()), certAlg}, frameDER(0x80, derParts{certCipher})))))

	keyAlg, keyCipher, err := encryptPBES2(state, private, options.Encryption)
	if err != nil {
		return nil, err
	}

	keyInfo := frameDER(0x30, derParts{keyAlg}, frameDER(4, derParts{keyCipher}))
	keyBag := frameDER(0x30, derParts{der.OID(oidShroudedKeyBag())}, frameDER(0xa0, keyInfo), derParts{attributes})
	keyContents := frameDER(0x30, keyBag)
	keyContentInfo := frameDER(0x30, derParts{der.OID(oidData())}, frameDER(0xa0, frameDER(4, keyContents)))
	authSafe := frameDER(0x30, certInfo, keyContentInfo)

	mac, err := encodePKCS12MACParts(state, authSafe, options)
	if err != nil {
		return nil, err
	}

	out := frameDER(0x30, derParts{der.Int(3)}, frameDER(0x30, derParts{der.OID(oidData())}, frameDER(0xa0, frameDER(4, authSafe))), derParts{mac})
	if out.size() > state.limits.MaxContainerBytes {
		return nil, ErrLimit
	}

	if err := state.ctx.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

// derParts holds a small list of DER headers and borrowed payload segments.
// It is operation-local; only complete returned byte slices own a flat encoding.
type derParts [][]byte

func (p derParts) size() int {
	length := 0
	for _, part := range p {
		length += len(part)
	}

	return length
}

func (p derParts) write(ctx context.Context, dst io.Writer) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	if buffer, ok := dst.(*bytes.Buffer); ok {
		buffer.Grow(p.size())
	}

	writer := &streamio.Writer{Context: ctx, Target: dst, Limit: int64(p.size()), LimitError: ErrLimit}
	for _, part := range p {
		for len(part) > 0 {
			chunk := part[:min(len(part), 32<<10)]
			if _, err := writer.Write(chunk); err != nil {
				return writer.Written, errors.Join(err, ctx.Err())
			}

			part = part[len(chunk):]
		}
	}

	return writer.Written, ctx.Err()
}

func (p derParts) bytes(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	output := bytes.NewBuffer(make([]byte, 0, p.size()))
	if _, err := p.write(ctx, output); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

func frameDER(tag byte, values ...derParts) derParts {
	var parts derParts
	for _, value := range values {
		parts = append(parts, value...)
	}

	return append(derParts{der.Header(tag, parts.size())}, parts...)
}
