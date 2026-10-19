package xades_test

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

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

func ExampleSignBasicEnveloped() {
	ctx := context.Background()
	claimedTime := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "XAdES example"},
		NotBefore: claimedTime.Add(-time.Hour), NotAfter: claimedTime.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		panic(err)
	}

	doc, err := document.Parse(ctx, []byte(`<invoice ID="invoice-1"><amount>42</amount></invoice>`), document.DefaultLimits())
	if err != nil {
		panic(err)
	}

	signed, _, err := xades.SignBasicEnveloped(ctx, doc, key, certDER, xades.SignOptions{
		SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: claimedTime,
	})
	if err != nil {
		panic(err)
	}

	signatures := xmldsig.Signatures(signed)
	if len(signatures) != 1 {
		panic("expected one signature")
	}
	// This certificate is explicitly pinned for the example. Basic validation
	// does not establish PKIX trust, revocation status or trusted signing time.
	result, err := xades.VerifyBasicEnveloped(ctx, signed, signatures[0], certDER, xades.VerifyOptions{})
	if err != nil {
		panic(err)
	}

	fmt.Println(result.Signature().CoversElement(signed.Root()))
	fmt.Println(result.ClaimedSigningTime().Format(time.RFC3339))
	// Output:
	// true
	// 2026-10-19T12:00:00Z
}
