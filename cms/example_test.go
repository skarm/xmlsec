package cms_test

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

	"github.com/skarm/xmlsec/cms"
)

func ExampleSign() {
	ctx := context.Background()
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "CMS example"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		panic(err)
	}

	content := []byte("invoice 42")

	encoded, err := cms.Sign(ctx, content, []cms.Signer{
		{Key: key, CertificateDER: certificateDER},
	}, cms.SignOptions{Detached: true})
	if err != nil {
		panic(err)
	}

	parsed, err := cms.Parse(ctx, encoded, cms.DefaultLimits())
	if err != nil {
		panic(err)
	}
	// Select certificates through application policy, not from the container.
	// This example pins its freshly generated certificate; PKIX is separate.
	result, err := parsed.Verify(ctx, [][]byte{certificateDER}, cms.VerifyOptions{
		ExpectedContentType: cms.DataOID(), DetachedContent: &content,
		RequireCertificateBinding: true,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(string(result.Content()), result.Signers()[0].CertificateBound())
	// Output: invoice 42 true
}
