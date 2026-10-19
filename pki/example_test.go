package pki_test

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

	"github.com/skarm/xmlsec/pki"
)

func ExampleVerifier_Verify() {
	ctx := context.Background()
	// Use a fixed clock only to make this example reproducible. An application
	// supplies its trusted evaluation time, not a document's claimed signing time.
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example CA"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		panic(err)
	}

	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		panic(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "document signer"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, leafKey.Public(), caKey)
	if err != nil {
		panic(err)
	}

	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Hour),
	}, root, caKey)
	if err != nil {
		panic(err)
	}

	// Trust this root explicitly and require offline revocation evidence.
	verifier, err := pki.NewVerifier(pki.Config{
		Roots: [][]byte{rootDER}, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		Revocation: pki.RequireCRL,
	})
	if err != nil {
		panic(err)
	}

	result, report, err := verifier.Verify(ctx, leafDER, at, pki.Evidence{CRLs: [][]byte{crl}})
	if err != nil {
		panic(err)
	}

	fmt.Println(report.Chain, result.RevocationStatus(), len(result.ChainDER()))
	// Output: valid valid 2
}
