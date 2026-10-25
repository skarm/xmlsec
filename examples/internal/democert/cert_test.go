package democert_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/skarm/xmlsec/examples/internal/democert"
)

func TestExplicitTimeAndChain(t *testing.T) {
	if _, err := democert.New(time.Time{}); err == nil {
		t.Fatal("zero example time accepted")
	}

	at := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	chain, err := democert.New(at)
	if err != nil {
		t.Fatal(err)
	}

	if !chain.Root.IsCA || chain.Root.KeyUsage&x509.KeyUsageCRLSign == 0 || chain.Root.CheckSignatureFrom(chain.Root) != nil {
		t.Fatal("demonstration root cannot authorize its chain/CRL")
	}

	for _, cert := range []*x509.Certificate{chain.Signer, chain.TSA, chain.Peer} {
		if err := cert.CheckSignatureFrom(chain.Root); err != nil || !cert.NotBefore.Before(at) || !cert.NotAfter.After(at) || cert.IsCA {
			t.Fatalf("invalid demonstration leaf %q: %v", cert.Subject.CommonName, err)
		}
	}

	if !chain.SignerKey.PublicKey.Equal(chain.Signer.PublicKey) {
		t.Fatal("signer certificate and private key differ")
	}

	if len(chain.TSA.ExtKeyUsage) != 1 || chain.TSA.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping {
		t.Fatal("TSA usage was not restricted to timestamping")
	}

	critical := false
	for _, extension := range chain.TSA.Extensions {
		if extension.Id.String() == "2.5.29.37" {
			critical = extension.Critical
		}
	}

	if !critical {
		t.Fatal("TSA extended key usage is not critical")
	}

	list, err := x509.ParseRevocationList(chain.CRL)
	if err != nil || list.CheckSignatureFrom(chain.Root) != nil || !list.ThisUpdate.Before(at) || !list.NextUpdate.After(at) || len(list.RevokedCertificateEntries) != 0 {
		t.Fatal("invalid complete example CRL:", err)
	}
}
