package testcert_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestChainAndRevocationFixtures(t *testing.T) {
	chain := testcert.New(t)
	for _, cert := range []*x509.Certificate{chain.Leaf, chain.TSA, chain.Responder} {
		if err := cert.CheckSignatureFrom(chain.Root); err != nil || !cert.NotBefore.Before(testcert.Now()) || !cert.NotAfter.After(testcert.Now()) {
			t.Fatalf("invalid leaf fixture %q: %v", cert.Subject.CommonName, err)
		}
	}

	if !chain.LeafKey.PublicKey.Equal(chain.Leaf.PublicKey) || len(chain.TSA.ExtKeyUsage) != 1 || chain.TSA.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(chain.Responder.ExtKeyUsage) != 1 || chain.Responder.ExtKeyUsage[0] != x509.ExtKeyUsageOCSPSigning {
		t.Fatal("fixture identity roles changed")
	}

	raw := testcert.CRL(t, chain, chain.Leaf, chain.TSA)
	list, err := x509.ParseRevocationList(raw)
	if err != nil {
		t.Fatal(err)
	}

	if err := list.CheckSignatureFrom(chain.Root); err != nil || len(list.RevokedCertificateEntries) != 2 || list.RevokedCertificateEntries[0].SerialNumber.Cmp(chain.Leaf.SerialNumber) != 0 || list.RevokedCertificateEntries[1].SerialNumber.Cmp(chain.TSA.SerialNumber) != 0 {
		t.Fatal("CRL fixture lost requested revocations or issuer:", err)
	}

	legacy, err := x509.ParseCRL(testcert.CRLV1(t, chain, chain.Leaf)) //nolint:staticcheck // The v1 fixture needs the standard library's legacy CRL parser.
	if err != nil {
		t.Fatal(err)
	}

	if legacy.TBSCertList.Version != 0 || len(legacy.TBSCertList.Extensions) != 0 || len(legacy.TBSCertList.RevokedCertificates) != 1 || chain.Root.CheckCRLSignature(legacy) != nil { //nolint:staticcheck // Authenticate the original v1 view with the standard-library verifier.
		t.Fatal("legacy fixture is not an original signed v1 list")
	}

	encodings := testcert.CertificateEncodings(t, chain)
	if len(encodings) != 5 {
		t.Fatal("missing certificate syntax controls")
	}

	for i, encoding := range encodings {
		if encoding.Valid != (i < 3) || len(encoding.DER) == 0 || i > 0 && bytes.Equal(encoding.DER, chain.Leaf.Raw) {
			t.Fatalf("ineffective certificate control: %s", encoding.Name)
		}

		var signed struct {
			TBS       asn1.RawValue
			Algorithm pkix.AlgorithmIdentifier
			Signature asn1.BitString
		}

		rest, err := asn1.Unmarshal(encoding.DER, &signed)
		if err != nil || len(rest) != 0 || signed.Signature.BitLength != 8*len(signed.Signature.Bytes) || !signed.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}) {
			t.Fatalf("invalid signed control envelope %q: %v", encoding.Name, err)
		}

		if err := chain.Root.CheckSignature(x509.ECDSAWithSHA256, signed.TBS.FullBytes, signed.Signature.Bytes); err != nil {
			t.Fatalf("control %q is not signed over its actual bytes: %v", encoding.Name, err)
		}
	}
}

func TestIssueReportsSignerError(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	signErr := errors.New("test signer unavailable")
	err := captureFixtureFatal(t, func(tb testing.TB) {
		testcert.Issue(tb, chain.Leaf, chain.Root, chain.Leaf.PublicKey, unavailableSigner{chain.RootKey, signErr})
	})
	if !errors.Is(err, signErr) {
		t.Errorf("Issue failed with %v, want signer error %v", err, signErr)
	}
}

type unavailableSigner struct {
	crypto.Signer
	err error
}

func (s unavailableSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, s.err
}

func TestCRLReportsMissingIssuer(t *testing.T) {
	t.Parallel()

	chain := testcert.Chain{RootKey: testcert.Key(t)}
	err := captureFixtureFatal(t, func(tb testing.TB) { testcert.CRL(tb, chain) })
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("CRL failed with %v, want a missing issuer diagnostic", err)
	}
}

func TestCertificateEncodingsReportsInvalidLeaf(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"truncated_certificate", []byte{0x30, 0x02, 0x05}},
		{"wrong_outer_shape", []byte{0x30, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain := testcert.Chain{Leaf: &x509.Certificate{Raw: tc.der}}
			err := captureFixtureFatal(t, func(tb testing.TB) { testcert.CertificateEncodings(tb, chain) })
			if !errors.Is(err, der.ErrInvalidDER) {
				t.Errorf("CertificateEncodings failed with %v, want %v", err, der.ErrInvalidDER)
			}
		})
	}
}

func TestCertificateEncodingsRequiresNoncriticalExtension(t *testing.T) {
	t.Parallel()

	key := testcert.Key(t)
	at := testcert.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "key usage fixture"},
		NotBefore:    at.Add(-time.Hour),
		NotAfter:     at.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leaf := testcert.Issue(t, template, template, key.Public(), key)
	if len(leaf.Extensions) != 1 || !leaf.Extensions[0].Critical {
		t.Fatalf("fixture has extensions %v, want a single critical key usage", leaf.Extensions)
	}
	chain := testcert.Chain{Leaf: leaf, RootKey: key}
	err := captureFixtureFatal(t, func(tb testing.TB) { testcert.CertificateEncodings(tb, chain) })
	if !strings.Contains(err.Error(), "noncritical extension") {
		t.Errorf("CertificateEncodings failed with %v, want a missing noncritical extension diagnostic", err)
	}
}
