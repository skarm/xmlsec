package testcert_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestPublicFixtureSelection(t *testing.T) {
	dir := t.TempDir()
	manifest := `[{"name":"first","at":"2020-01-01T00:00:00Z","certificate":"wrong.der","nonce":"00"},{"name":"selected","at":"2026-10-25T12:30:00.123Z","certificate":"certificate.der","nonce":"0102ff"}]`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "certificate.der"), []byte{1, 2, 3, 4}, 0o600); err != nil {
		t.Fatal(err)
	}

	fixture := testcert.LoadFixture(t, dir, "selected")
	wantTime := time.Date(2026, 10, 25, 12, 30, 0, 123000000, time.UTC)
	if fixture.Certificate != "certificate.der" || !fixture.At.Equal(wantTime) || !bytes.Equal(fixture.Nonce, []byte{1, 2, 255}) || !bytes.Equal(fixture.Read(t, fixture.Certificate), []byte{1, 2, 3, 4}) {
		t.Fatalf("selected fixture metadata/bytes differ: %+v", fixture)
	}
}
