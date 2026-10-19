package xmlenc

import (
	"context"
	"crypto/cipher"
	"crypto/rsa"

	"github.com/skarm/xmlsec/document"
)

const (
	gcmNonceBytes = 12
	gcmTagBytes   = 16
	gcmOverhead   = gcmNonceBytes + gcmTagBytes
)

type keyTransport struct {
	algorithm    string
	wrappedBytes int
	wrap         func([]byte) ([]byte, error)
	unwrap       func(context.Context, []byte) ([]byte, error)
	oaep         OAEPParameters
}

type profile struct {
	options   Options
	keyBytes  int
	transport keyTransport
	direct    cipher.AEAD
	keyName   string
}

func normalize(ctx context.Context, options Options) (profile, error) {
	if ctx == nil {
		return profile{}, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return profile{}, err
	}

	if options.DataAlgorithm == "" {
		options.DataAlgorithm = AES256GCM
	}

	var keyBytes int

	switch options.DataAlgorithm {
	case AES128GCM:
		keyBytes = 16
	case AES192GCM:
		keyBytes = 24
	case AES256GCM:
		keyBytes = 32
	default:
		return profile{}, ErrPolicy
	}

	if options.MaxPlaintextBytes == 0 {
		options.MaxPlaintextBytes = 8 << 20
	}

	if options.MaxPlaintextBytes < 1 || options.MaxPlaintextBytes > 32<<20 {
		return profile{}, ErrPolicy
	}

	if options.XMLLimits == (document.Limits{}) {
		options.XMLLimits = document.DefaultLimits()
	}

	if options.XMLLimits.MaxBytes > options.MaxPlaintextBytes {
		options.XMLLimits.MaxBytes = options.MaxPlaintextBytes
	}

	if err := options.XMLLimits.Validate(); err != nil {
		return profile{}, err
	}

	if options.External != nil {
		external, err := normalizeExternal(*options.External, options.MaxPlaintextBytes+gcmOverhead)
		if err != nil {
			return profile{}, err
		}

		options.External = &external
	}

	return profile{options: options, keyBytes: keyBytes}, nil
}

func validateRSAKey(key *rsa.PublicKey) error {
	if key == nil || key.N == nil || key.N.Sign() <= 0 || key.N.Bit(0) == 0 || key.N.BitLen() < 2048 || key.N.BitLen() > 16384 || key.E < 3 || key.E%2 == 0 || key.E > 0x7fffffff {
		return ErrPolicy
	}

	return nil
}
