package xmlenc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"io"

	"github.com/skarm/xmlsec/internal/nilcheck"
)

// ContextDecrypter allows a key provider to receive cancellation and deadlines.
type ContextDecrypter interface {
	// Public returns the public key corresponding to the decryption key.
	Public() crypto.PublicKey
	// Decrypt follows crypto.Decrypter conventions for ciphertext, randomness,
	// options and plaintext, and must honor cancellation.
	Decrypt(context.Context, io.Reader, []byte, crypto.DecrypterOpts) ([]byte, error)
}

// AdaptContextDecrypter adapts a provider to crypto.Decrypter. The xmlenc
// decrypt entry points pass the caller's context to the provider.
func AdaptContextDecrypter(provider ContextDecrypter) (crypto.Decrypter, error) {
	if nilcheck.IsNil(provider) {
		return nil, ErrPolicy
	}

	return &contextAdapter{provider}, nil
}

type contextAdapter struct{ ContextDecrypter }

func (a *contextAdapter) Decrypt(r io.Reader, ciphertext []byte, options crypto.DecrypterOpts) ([]byte, error) {
	return a.ContextDecrypter.Decrypt(context.Background(), r, ciphertext, options)
}

func (a *contextAdapter) decrypt(ctx context.Context, r io.Reader, ciphertext []byte, options crypto.DecrypterOpts) ([]byte, error) {
	return a.ContextDecrypter.Decrypt(ctx, r, ciphertext, options)
}

func rsaEncryptProfile(ctx context.Context, options Options, recipient *rsa.PublicKey) (profile, error) {
	p, err := normalize(ctx, options)
	if err != nil {
		return profile{}, err
	}

	if err := validateRSAKey(recipient); err != nil {
		return profile{}, err
	}

	oaep, err := normalizeOAEP(options.OAEP)
	if err != nil {
		return profile{}, err
	}

	p.transport = keyTransport{
		algorithm: RSAOAEP, wrappedBytes: recipient.Size(),
		oaep: oaep,
		wrap: func(key []byte) ([]byte, error) {
			return rsa.EncryptOAEP(oaep.Hash.New(), rand.Reader, recipient, key, oaep.Label)
		},
	}

	return p, nil
}

type contextualDecrypter interface {
	decrypt(context.Context, io.Reader, []byte, crypto.DecrypterOpts) ([]byte, error)
}

func rsaDecryptProfile(ctx context.Context, options Options, recipient crypto.Decrypter) (profile, error) {
	p, err := normalize(ctx, options)
	if err != nil {
		return profile{}, err
	}

	if nilcheck.IsNil(recipient) {
		return profile{}, ErrPolicy
	}

	public, ok := recipient.Public().(*rsa.PublicKey)
	if !ok || validateRSAKey(public) != nil {
		return profile{}, ErrPolicy
	}

	oaep, err := normalizeOAEP(options.OAEP)
	if err != nil {
		return profile{}, err
	}

	p.transport = keyTransport{
		algorithm: RSAOAEP, wrappedBytes: public.Size(),
		oaep: oaep,
		unwrap: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
			options := &rsa.OAEPOptions{Hash: oaep.Hash, MGFHash: oaep.Hash, Label: bytes.Clone(oaep.Label)}
			if provider, ok := recipient.(contextualDecrypter); ok {
				return provider.decrypt(ctx, rand.Reader, ciphertext, options)
			}

			return recipient.Decrypt(rand.Reader, ciphertext, options)
		},
	}

	return p, nil
}
