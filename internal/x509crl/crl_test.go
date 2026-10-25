package x509crl_test

import (
	"bytes"
	"crypto/x509"
	"errors"
	"math/big"
	"strconv"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/x509crl"
)

func TestParseVersionsOriginalBytesAndLimits(t *testing.T) {
	chain := testcert.New(t)
	for _, version := range []int{0, 1} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			raw := testcert.CRL(t, chain, chain.Leaf, chain.Responder)
			if version == 0 {
				raw = testcert.CRLV1(t, chain, chain.Leaf, chain.Responder)
			}
			before := bytes.Clone(raw)
			limits := x509crl.Limits{Bytes: len(raw), Depth: 33, Nodes: 1000000, Entries: 2}
			view, err := x509crl.Parse(raw, limits)
			if err != nil {
				t.Fatal(err)
			}
			if view.Version != version || !bytes.Equal(view.CRL.Raw, before) || !bytes.Equal(raw, before) || len(view.CRL.RevokedCertificateEntries) != 2 || view.CRL.RevokedCertificateEntries[0].SerialNumber.Cmp(chain.Leaf.SerialNumber) != 0 {
				t.Fatal("CRL version/entries/original bytes changed")
			}
			if err := view.CRL.CheckSignatureFrom(chain.Root); err != nil {
				t.Fatal("original CRL signature lost", err)
			}
			limits.Entries = 1
			if result, err := x509crl.Parse(raw, limits); result != nil || !errors.Is(err, x509crl.ErrLimit) {
				t.Fatal("entry cap", result, err)
			}
			limits.Entries = 2
			limits.Bytes--
			if result, err := x509crl.Parse(raw, limits); result != nil || !errors.Is(err, x509crl.ErrLimit) {
				t.Fatal("byte cap", result, err)
			}
			limits.Bytes++
			limits.Depth = 1
			if result, err := x509crl.Parse(raw, limits); result != nil || !errors.Is(err, x509crl.ErrLimit) {
				t.Fatal("depth cap", result, err)
			}
			limits.Depth = 33
			limits.Nodes = 1
			if result, err := x509crl.Parse(raw, limits); result != nil || !errors.Is(err, x509crl.ErrLimit) {
				t.Fatal("node cap", result, err)
			}
		})
	}
}

func TestCRLParsingDoesNotAuthenticateOrIgnoreTrailingInput(t *testing.T) {
	chain := testcert.New(t)
	raw := testcert.CRL(t, chain)
	if got, err := x509crl.ParseEvidence(append(bytes.Clone(raw), 0), 1<<20); got != nil || err == nil {
		t.Fatal("trailing DER accepted", got, err)
	}
	changed := bytes.Clone(raw)
	changed[len(changed)-1] ^= 1
	view, err := x509crl.ParseEvidence(changed, 1<<20)
	if err != nil {
		t.Fatal("structural parsing conflated with signature verification", err)
	}
	if err := view.CRL.CheckSignatureFrom(chain.Root); err == nil {
		t.Fatal("changed signed encoding authenticated")
	}
}

func BenchmarkParseCRL(b *testing.B) {
	chain := testcert.New(b)
	for _, count := range []int{0, 1024} {
		revoked := make([]*x509.Certificate, count)
		for i := range revoked {
			revoked[i] = &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1000))}
		}
		raw := testcert.CRL(b, chain, revoked...)
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := x509crl.ParseEvidence(raw, 64<<20); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
