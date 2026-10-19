// Command keys demonstrates password-protected key containers with explicit limits.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/skarm/xmlsec/examples/internal/democert"
	"github.com/skarm/xmlsec/keys"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	c, err := democert.New(time.Now().UTC())
	if err != nil {
		return err
	}
	// This public password protects only disposable demonstration keys.
	// Obtain production passwords through application-controlled secret storage.
	password := []byte("public example пароль 😀")
	defer clear(password)

	private, err := keys.MarshalEncryptedPrivate(ctx, c.SignerKey, password, keys.EncryptionOptions{}, keys.Limits{})
	if err != nil {
		return err
	}

	parsed, err := keys.ParseEncryptedPrivate(ctx, private, password, keys.Limits{})
	if err != nil {
		return err
	}

	if !c.SignerKey.PublicKey.Equal(parsed.Public()) {
		return errors.New("unexpected PKCS#8 key")
	}

	container, err := keys.MarshalPKCS12(ctx, keys.PKCS12Identity{
		PrivateKey: c.SignerKey, Certificate: c.Signer, ExtraCertificates: []*x509.Certificate{c.Root},
	}, password, keys.PKCS12Options{}, keys.Limits{})
	if err != nil {
		return err
	}

	identity, err := keys.ParsePKCS12(ctx, container, password, keys.Limits{})
	if err != nil {
		return err
	}
	// The MAC authenticates this container under the password. The additional
	// certificate remains untrusted evidence; use explicit roots/time in pki.
	fmt.Printf("PKCS#8 key restored; PKCS#12 certificate %q, %d extra certificate\n",
		identity.Certificate.Subject.CommonName, len(identity.ExtraCertificates))

	return nil
}
