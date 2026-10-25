package xmlenc

import (
	"context"
	"crypto/cipher"
	"crypto/rsa"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

const (
	gcmNonceBytes = 12
	gcmTagBytes   = 16
)

type keyTransport struct {
	algorithm    string
	wrappedBytes int
	keyBits      int
	wrap         func([]byte) ([]byte, error)
	unwrap       func(context.Context, []byte) ([]byte, error)
	oaep         OAEPParameters
	keyInfo      *tree.Node
	checkKeyInfo func(context.Context, document.Element) error
}

type profile struct {
	options   Options
	keyBytes  int
	transport keyTransport
	direct    cipher.Block
	data      dataCipher
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

	data, err := dataAlgorithm(options.DataAlgorithm, options.AllowLegacy)
	if err != nil {
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
		external, err := normalizeExternal(*options.External, options.MaxPlaintextBytes+data.overhead())
		if err != nil {
			return profile{}, err
		}

		options.External = &external
	}

	return profile{options: options, keyBytes: data.keyBytes, data: data}, nil
}

func validateRSAKey(key *rsa.PublicKey) error {
	if key == nil || key.N == nil || key.N.Sign() <= 0 || key.N.Bit(0) == 0 || key.N.BitLen() < 2048 || key.N.BitLen() > 16384 || key.E < 3 || key.E%2 == 0 || key.E > 0x7fffffff {
		return ErrPolicy
	}

	return nil
}
