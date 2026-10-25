package keys

import (
	"bytes"
	"encoding/asn1"
	"errors"

	"github.com/skarm/xmlsec/internal/ber"
	"github.com/skarm/xmlsec/internal/der"
)

type pkcs12Form byte

const (
	pfxForm pkcs12Form = iota
	authenticatedForm
	safeContentsForm
)

func oidSafeContentsBag() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
}

// Normalization never traverses the ASN.1 held inside data OCTET STRINGs.
// In particular, the original AuthenticatedSafe octets authenticate before its
// own wrappers are interpreted. Certificate and private-key bytes stay opaque.
func normalizePKCS12BER(state *passwordState, input []byte, form pkcs12Form) ([]byte, error) {
	root, err := ber.Read(state.ctx, input, ber.Limits{MaxBytes: state.limits.MaxContainerBytes, MaxDepth: state.limits.MaxASN1Depth, MaxNodes: state.limits.MaxASN1Nodes})
	if err != nil {
		return nil, pkcs12BERError(err)
	}

	if root.Tag != 0x30 {
		return nil, ErrFormat
	}

	var result []byte

	switch form {
	case pfxForm:
		if len(root.Children) != 3 {
			return nil, ErrFormat
		}

		info, err := pkcs12BERInfo(state, root.Children[1], false)
		if err != nil {
			return nil, err
		}
		defer clear(info)

		result = der.Seq(root.Children[0].Full, info, root.Children[2].Full)
	case authenticatedForm:
		if len(root.Children) == 0 || len(root.Children) > state.limits.MaxContentInfos {
			return nil, ErrLimit
		}

		parts := make([][]byte, 0, len(root.Children))
		defer func() {
			for _, part := range parts {
				clear(part)
			}
		}()

		for _, child := range root.Children {
			info, err := pkcs12BERInfo(state, child, true)
			if err != nil {
				return nil, err
			}

			parts = append(parts, info)
		}

		result = der.Seq(parts...)
	case safeContentsForm:
		result, err = pkcs12BERSafe(state, root)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrPolicy
	}

	if len(result) > state.limits.MaxContainerBytes {
		clear(result)
		return nil, ErrLimit
	}

	if err := state.ctx.Err(); err != nil {
		clear(result)
		return nil, err
	}

	return result, nil
}

func pkcs12BERInfo(state *passwordState, info ber.Value, encrypted bool) ([]byte, error) {
	if info.Tag != 0x30 || len(info.Children) != 2 {
		return nil, ErrFormat
	}

	oid, err := readDER(info.Children[0].Full, state.limits.MaxContainerBytes, state.limits)
	if err != nil {
		return nil, err
	}

	explicit := info.Children[1]
	if explicit.Tag != 0xa0 || len(explicit.Children) != 1 {
		return nil, ErrFormat
	}

	content := explicit.Children[0]

	var value []byte

	switch {
	case der.OIDEqual(oid, oidData()):
		var output bytes.Buffer
		defer func() { clear(output.Bytes()) }()

		if err := ber.AppendOctets(state.ctx, content, &output, state.limits.MaxContainerBytes); err != nil {
			return nil, pkcs12BERError(err)
		}

		value = der.Octets(output.Bytes())
	case encrypted && der.OIDEqual(oid, oidEncryptedData()):
		value, err = pkcs12BEREncrypted(state, content)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrPolicy
	}

	defer clear(value)

	return der.Seq(oid.FullBytes, der.Ctx(0, value)), nil
}

func pkcs12BEREncrypted(state *passwordState, content ber.Value) ([]byte, error) {
	if content.Tag != 0x30 || len(content.Children) != 2 {
		return nil, ErrFormat
	}

	info := content.Children[1]
	if info.Tag != 0x30 || len(info.Children) != 3 {
		return nil, ErrFormat
	}

	cipher := info.Children[2]
	if cipher.Tag != 0x80 && cipher.Tag != 0xa0 {
		return nil, ErrFormat
	}
	// The implicit OCTET STRING has universal OCTET STRING segments when
	// constructed. Flatten only its string encoding, never ciphertext bytes.
	cipher.Tag = (cipher.Tag & 0x20) | 4

	var output bytes.Buffer
	if err := ber.AppendOctets(state.ctx, cipher, &output, state.limits.MaxContainerBytes); err != nil {
		return nil, pkcs12BERError(err)
	}

	return der.Seq(content.Children[0].Full, der.Seq(info.Children[0].Full, info.Children[1].Full, der.Wrap(2, 0, false, output.Bytes()))), nil
}

func pkcs12BERSafe(state *passwordState, contents ber.Value) ([]byte, error) {
	if contents.Tag != 0x30 {
		return nil, ErrFormat
	}

	if len(contents.Children) > state.limits.MaxBags {
		return nil, ErrLimit
	}

	parts := make([][]byte, 0, len(contents.Children))
	defer func() {
		for _, part := range parts {
			clear(part)
		}
	}()

	for _, bag := range contents.Children {
		if err := state.ctx.Err(); err != nil {
			return nil, err
		}

		if bag.Tag != 0x30 || len(bag.Children) < 2 || len(bag.Children) > 3 {
			return nil, ErrFormat
		}

		oid, err := readDER(bag.Children[0].Full, state.limits.MaxContainerBytes, state.limits)
		if err != nil {
			return nil, err
		}

		explicit := bag.Children[1]
		if explicit.Tag != 0xa0 || len(explicit.Children) != 1 {
			return nil, ErrFormat
		}

		value := explicit.Children[0].Full
		ownedValue := false

		if der.OIDEqual(oid, oidSafeContentsBag()) {
			value, err = pkcs12BERSafe(state, explicit.Children[0])
			if err != nil {
				return nil, err
			}

			ownedValue = true
		} else if der.OIDEqual(oid, oidCertBag()) {
			value, err = pkcs12BERCertificate(state, explicit.Children[0])
			if err != nil {
				return nil, err
			}

			ownedValue = true
		}

		fields := [][]byte{oid.FullBytes, der.Ctx(0, value)}
		if ownedValue {
			clear(value)
		}

		if len(bag.Children) == 3 {
			fields = append(fields, bag.Children[2].Full)
		}

		parts = append(parts, der.Seq(fields...))
		clear(fields[1])
	}

	return der.Seq(parts...), nil
}

func pkcs12BERCertificate(state *passwordState, value ber.Value) ([]byte, error) {
	if value.Tag != 0x30 || len(value.Children) != 2 {
		return nil, ErrFormat
	}

	explicit := value.Children[1]
	if explicit.Tag != 0xa0 || len(explicit.Children) != 1 {
		return nil, ErrFormat
	}

	var output bytes.Buffer
	if err := ber.AppendOctets(state.ctx, explicit.Children[0], &output, state.limits.MaxCertificateBytes); err != nil {
		return nil, pkcs12BERError(err)
	}

	return der.Seq(value.Children[0].Full, der.Ctx(0, der.Octets(output.Bytes()))), nil
}

func pkcs12BERError(err error) error {
	if errors.Is(err, ber.ErrLimit) {
		return errors.Join(ErrLimit, err)
	}

	if errors.Is(err, ber.ErrSyntax) {
		return errors.Join(ErrFormat, err)
	}

	return err
}
