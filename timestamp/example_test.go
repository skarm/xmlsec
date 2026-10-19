package timestamp_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

func ExampleCreateRequest() {
	request, err := timestamp.CreateRequest(context.Background(), []byte("invoice 42"), timestamp.RequestOptions{
		Policy: asn1.ObjectIdentifier{1, 2, 3, 4, 1},
	})
	if err != nil {
		panic(err)
	}

	parsed, err := timestamp.ParseRequest(request.DER())
	if err != nil {
		panic(err)
	}

	// Keep request to bind the eventual response to its imprint, nonce and policy.
	fmt.Println(parsed.Nonce() != nil, parsed.CertificatesRequested())
	fmt.Println(parsed.Policy())
	// Output:
	// true true
	// 1.2.3.4.1
}

func ExampleVerifier_Fetch() {
	ctx := context.Background()
	// This is a local TSA demonstration, with an explicit reproducible clock.
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	tsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	issue := func(template, parent *x509.Certificate, key, issuer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), issuer)
		if err != nil {
			panic(err)
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			panic(err)
		}

		return cert
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example TSA root"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
	root := issue(ca, ca, rootKey, rootKey)
	// This profile requires a critical EKU containing only timeStamping.
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		panic(err)
	}

	tsa := issue(&x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "example TSA"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}},
	}, root, tsaKey, rootKey)

	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Hour),
	}, root, rootKey)
	if err != nil {
		panic(err)
	}

	policy := asn1.ObjectIdentifier{1, 2, 3, 4, 1}

	verifier, err := timestamp.NewVerifier(timestamp.Config{
		PKI:             pki.Config{Roots: [][]byte{root.Raw}, Revocation: pki.RequireCRL},
		AllowedPolicies: []asn1.ObjectIdentifier{policy},
	})
	if err != nil {
		panic(err)
	}

	request, err := timestamp.CreateRequest(context.Background(), []byte("invoice 42"), timestamp.RequestOptions{Policy: policy})
	if err != nil {
		panic(err)
	}
	// No network is used here. A production Transport owns the trusted endpoint,
	// TLS policy and cancellation; a real TSA owns its clock and serial allocation.
	transport := timestamp.TransportFunc(func(ctx context.Context, requestDER []byte) (io.ReadCloser, error) {
		response, err := timestamp.IssueResponse(ctx, requestDER, tsaKey, tsa.Raw, timestamp.IssueOptions{
			Policy: policy, SerialNumber: big.NewInt(1), GenTime: at,
		})
		if err != nil {
			return nil, err
		}

		return io.NopCloser(bytes.NewReader(response)), nil
	})

	result, err := verifier.Fetch(ctx, transport, request, at.Add(time.Second), pki.Evidence{CRLs: [][]byte{crl}})
	if err != nil {
		panic(err)
	}

	fmt.Println(result.Info().Policy(), result.Trust().RevocationStatus())
	fmt.Println(result.Info().GenTime().Format(time.RFC3339))
	// Output:
	// 1.2.3.4.1 valid
	// 2026-10-19T12:00:00Z
}
