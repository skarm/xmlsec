package keys_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/keys"
)

func ExampleParsePrivate() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}

	parsed, err := keys.ParsePrivate(der, keys.Limits{})
	if err != nil {
		panic(err)
	}

	fmt.Println(key.PublicKey.Equal(parsed.Public()))
	// Output: true
}

func ExampleMarshalEncryptedPrivate() {
	ctx := context.Background()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	// This public password is only for a disposable example key.
	// Obtain production passwords from application-controlled secret storage.
	password := []byte("example password for disposable key")
	defer clear(password)

	encrypted, err := keys.MarshalEncryptedPrivate(ctx, key, password, keys.EncryptionOptions{}, keys.Limits{})
	if err != nil {
		panic(err)
	}

	restored, err := keys.ParseEncryptedPrivate(ctx, encrypted, password, keys.Limits{})
	if err != nil {
		panic(err)
	}

	// Encrypted PKCS#8 uses AES-CBC without a MAC; parsing establishes no trust.
	fmt.Println(key.PublicKey.Equal(restored.Public()))
	// Output: true
}

func ExampleMarshalPKCS12() {
	ctx := context.Background()
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example signer"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		panic(err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	password := []byte("public password for disposable PFX")
	defer clear(password)

	pfx, err := keys.MarshalPKCS12(ctx, keys.PKCS12Identity{
		PrivateKey: key, Certificate: certificate,
	}, password, keys.PKCS12Options{}, keys.Limits{})
	if err != nil {
		panic(err)
	}

	identity, err := keys.ParsePKCS12(ctx, pfx, password, keys.Limits{})
	if err != nil {
		panic(err)
	}

	// The mandatory MAC protects the container under the password, not PKIX trust.
	fmt.Println(identity.Certificate.Subject.CommonName)
	fmt.Println(key.PublicKey.Equal(identity.PrivateKey.Public()))
	// Output:
	// example signer
	// true
}
