// Command trust demonstrates the corresponding XML security API.
// An explicit composition: offline PKIX+CRL trust, basic XAdES signing, and
// XML Encryption. This is NOT XAdES B-T/LT/LTA or historical validation.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
	"github.com/skarm/xmlsec/xmlenc"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}

	rootDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, issuer.Public(), issuer)
	if err != nil {
		return err
	}

	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return err
	}

	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Example signer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, BasicConstraintsValid: true}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, signingKey.Public(), issuer)
	if err != nil {
		return err
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, root, issuer)
	if err != nil {
		return err
	}

	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{rootDER}, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, Revocation: pki.RequireCRL})
	if err != nil {
		return err
	}
	// Use the actual evaluation time and explicit evidence, NEVER SigningTime.
	_, trustReport, err := verifier.Verify(ctx, leafDER, now, pki.Evidence{CRLs: [][]byte{crlDER}})
	if err != nil {
		return err
	}

	source, err := document.Parse(ctx, []byte(`<invoice ID="invoice"><amount currency="EUR">42.00</amount></invoice>`), document.DefaultLimits())
	if err != nil {
		return err
	}

	signed, _, err := xades.SignBasicEnveloped(ctx, source, signingKey, leafDER, xades.SignOptions{SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: now})
	if err != nil {
		return err
	}

	recipient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	encrypted, err := xmlenc.EncryptDocument(ctx, signed, &recipient.PublicKey, xmlenc.Options{})
	if err != nil {
		return err
	}

	transport, err := encrypted.XML(ctx)
	if err != nil {
		return err
	}

	received, err := document.Parse(ctx, transport, document.DefaultLimits())
	if err != nil {
		return err
	}

	decrypted, err := xmlenc.DecryptDocument(ctx, received, recipient, xmlenc.Options{})
	if err != nil {
		return err
	}
	// Decryption authenticates ciphertext integrity, NOT who sent the message.
	selections := xmldsig.Signatures(decrypted)
	if len(selections) != 1 {
		return errors.New("expected exactly one XAdES signature")
	}

	result, err := xades.VerifyBasicEnveloped(ctx, decrypted, selections[0], leafDER, xades.VerifyOptions{})
	if err != nil {
		return err
	}

	fmt.Printf("chain=%s revocation=%s xades-root-covered=%t encryption=authenticated-ciphertext\n", trustReport.Chain, trustReport.Revocation, result.Signature().CoversElement(decrypted.Root()))
	fmt.Printf("claimed-signing-time=%s (not a trusted timestamp)\n", result.ClaimedSigningTime().Format(time.RFC3339))

	return nil
}
