// Command keyprobe is a private key-container interoperability adapter.
// It accepts paths and public test passwords from the local harness only.
package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/skarm/xmlsec/keys"
)

type task struct {
	Mode        string
	Input       string
	Key         string
	Certificate string
	Extras      []string
	Password    []byte
	Hash        int
	KeyBits     int
	Iterations  int
	ClassicMAC  bool
}

type output struct {
	Data        []byte `json:"data,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Extras      int    `json:"extras,omitempty"`
	Error       string `json:"error,omitempty"`
}

func main() {
	var t task

	d := json.NewDecoder(os.Stdin)
	d.DisallowUnknownFields()

	o := output{}
	if err := d.Decode(&t); err != nil {
		o.Error = err.Error()
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		var err error

		o, err = process(ctx, t)

		cancel()

		if err != nil {
			o.Error = err.Error()
		}
	}

	clear(t.Password)

	if err := json.NewEncoder(os.Stdout).Encode(o); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

func process(ctx context.Context, t task) (output, error) {
	var (
		o        output
		signer   crypto.Signer
		identity *keys.PKCS12Identity
		err      error
	)

	if t.Mode == "parse-pkcs8" || t.Mode == "parse-pkcs12" {
		raw, readErr := os.ReadFile(t.Input)
		if readErr != nil {
			return o, readErr
		}
		defer clear(raw)

		if t.Mode == "parse-pkcs8" {
			signer, err = keys.ParseEncryptedPrivate(ctx, raw, t.Password, keys.Limits{})
		} else {
			identity, err = keys.ParsePKCS12(ctx, raw, t.Password, keys.Limits{})
			if err == nil {
				signer = identity.PrivateKey
			}
		}
	} else {
		raw, readErr := os.ReadFile(t.Key)
		if readErr != nil {
			return o, readErr
		}

		signer, err = keys.ParsePrivate(raw, keys.Limits{})
		clear(raw)

		if err != nil {
			return o, err
		}

		hash := crypto.SHA256

		switch t.Hash {
		case 0, 256:
		case 384:
			hash = crypto.SHA384
		case 512:
			hash = crypto.SHA512
		default:
			return o, errors.New("hash")
		}

		options := keys.EncryptionOptions{Hash: hash, KeyBits: t.KeyBits, Iterations: t.Iterations}
		switch t.Mode {
		case "marshal-pkcs8":
			o.Data, err = keys.MarshalEncryptedPrivate(ctx, signer, t.Password, options, keys.Limits{})
		case "marshal-pkcs12":
			identity, err = identityForExport(t, signer)
			if err != nil {
				return o, err
			}

			o.Data, err = keys.MarshalPKCS12(ctx, *identity, t.Password, keys.PKCS12Options{Encryption: options, ClassicMAC: t.ClassicMAC}, keys.Limits{})
		default:
			return o, errors.New("mode")
		}
	}

	if err != nil {
		return output{}, err
	}

	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return output{}, err
	}

	o.Fingerprint = digest(public)
	if identity != nil {
		o.Certificate = digest(identity.Certificate.Raw)
		o.Extras = len(identity.ExtraCertificates)
	}

	return o, nil
}

func identityForExport(t task, signer crypto.Signer) (*keys.PKCS12Identity, error) {
	raw, err := os.ReadFile(t.Certificate)
	if err != nil {
		return nil, err
	}

	certificate, err := keys.ParseCertificate(raw, keys.Limits{})
	if err != nil {
		return nil, err
	}

	identity := &keys.PKCS12Identity{PrivateKey: signer, Certificate: certificate}
	if err := appendIdentityCertificates(identity, t.Extras); err != nil {
		return identity, err
	}

	return identity, nil
}

func appendIdentityCertificates(identity *keys.PKCS12Identity, paths []string) error {
	for _, path := range paths {
		raw, err := os.ReadFile(path) // #nosec G304 -- The local interoperability harness supplies fixture paths.
		if err != nil {
			return err
		}

		c, err := keys.ParseCertificate(raw, keys.Limits{})
		if err != nil {
			return err
		}

		identity.ExtraCertificates = append(identity.ExtraCertificates, c)
	}

	return nil
}
