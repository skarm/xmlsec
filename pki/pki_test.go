package pki_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
)

func TestPKIXAndCRL(t *testing.T) {
	c := makeChain(t)
	fresh := makeCRL(t, c, false, nil)
	revoked := makeCRL(t, c, true, nil)
	tests := []struct {
		name string
		crls [][]byte
		at   time.Time
		want error
	}{
		{"fresh", [][]byte{fresh}, verificationTime(), nil}, {"missing", nil, verificationTime(), pki.ErrUnavailable}, {"revoked", [][]byte{revoked}, verificationTime(), pki.ErrRevoked}, {"expired CRL", [][]byte{fresh}, verificationTime().Add(2 * time.Minute), pki.ErrUnavailable}, {"expired certificate", [][]byte{fresh}, verificationTime().Add(2 * time.Hour), pki.ErrCertificate}, {"malformed", [][]byte{{1, 2, 3}}, verificationTime(), pki.ErrEvidence},
	}

	v, e := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
	if e != nil {
		t.Fatal(e)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, report, e := v.Verify(t.Context(), c.leaf.Raw, tc.at, pki.Evidence{CRLs: tc.crls})
			if tc.want == nil {
				if e != nil || r == nil || report.Chain != pki.Valid || report.Revocation != pki.Valid {
					t.Fatalf("%v %+v", e, report)
				}

				snapshot := r.ChainDER()
				snapshot[0][0] ^= 255

				if _, e = x509.ParseCertificate(r.ChainDER()[0]); e != nil {
					t.Fatal("mutable result")
				}

				if _, e = r.PublicKey(); e != nil {
					t.Fatal(e)
				}
			} else if r != nil || !errors.Is(e, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, e)
			}
		})
	}
}

func TestPKIDistinctTrustModels(t *testing.T) {
	c := makeChain(t)
	if _, e := pki.NewVerifier(pki.Config{}); !errors.Is(e, pki.ErrPolicy) {
		t.Fatal("implicit system roots")
	}

	v, e := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}})
	if e != nil {
		t.Fatal(e)
	}

	r, report, e := v.Verify(t.Context(), c.leaf.Raw, verificationTime(), pki.Evidence{})
	if e != nil || r == nil || report.Revocation != pki.NotChecked {
		t.Fatalf("%v %+v", e, report)
	}

	pin, e := pki.NewKeyPin(&c.leafKey.PublicKey)
	if e != nil {
		t.Fatal(e)
	}

	if e = pin.MatchCertificate(c.leaf.Raw); e != nil {
		t.Fatal(e)
	}

	if e = pin.MatchCertificate(c.root.Raw); !errors.Is(e, pki.ErrCertificate) {
		t.Fatal("wrong key matched")
	}

	other := makeChain(t)

	untrusted, e := pki.NewVerifier(pki.Config{Roots: [][]byte{other.root.Raw}})
	if e != nil {
		t.Fatal(e)
	}

	if r, _, e = untrusted.Verify(t.Context(), c.leaf.Raw, verificationTime(), pki.Evidence{}); r != nil || !errors.Is(e, pki.ErrCertificate) {
		t.Fatal("untrusted chain accepted")
	}

	noEKU, e := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}})
	if e != nil {
		t.Fatal(e)
	}

	if r, _, e = noEKU.Verify(t.Context(), c.leaf.Raw, verificationTime(), pki.Evidence{}); r != nil || !errors.Is(e, pki.ErrCertificate) {
		t.Fatal("wrong EKU accepted")
	}
}

func TestCRLRejectsUnsupportedAndWrongSignature(t *testing.T) {
	c := makeChain(t)
	other := makeChain(t)

	v, e := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
	if e != nil {
		t.Fatal(e)
	}

	delta := makeCRL(t, c, false, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: verificationTime().Add(-time.Minute), NextUpdate: verificationTime().Add(time.Minute), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{2, 1, 1}}}})

	r, _, e := v.Verify(t.Context(), c.leaf.Raw, verificationTime(), pki.Evidence{CRLs: [][]byte{delta}})
	if r != nil || !errors.Is(e, pki.ErrUnavailable) {
		t.Fatalf("recognized delta without base treated as full: %v", e)
	}

	wrong := makeCRL(t, other, false, nil)

	r, _, e = v.Verify(t.Context(), c.leaf.Raw, verificationTime(), pki.Evidence{CRLs: [][]byte{wrong}})
	if r != nil || !errors.Is(e, pki.ErrUnavailable) {
		t.Fatalf("wrong CRL signer: %v", e)
	}
}

func TestPKIConcurrentAndCancellation(t *testing.T) {
	c := makeChain(t)

	v, e := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}})
	if e != nil {
		t.Fatal(e)
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, _, e := v.Verify(t.Context(), c.leaf.Raw, verificationTime(), pki.Evidence{}); e != nil {
				t.Error(e)
			}
		})
	}

	wg.Wait()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, _, e = v.Verify(ctx, c.leaf.Raw, verificationTime(), pki.Evidence{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestPythonCRLFixtures(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()

		b, e := os.ReadFile("../testdata/next/pki-" + name)
		if e != nil {
			t.Fatal(e)
		}

		return b
	}
	root, leaf := read("root.der"), read("leaf.der")

	v, e := pki.NewVerifier(pki.Config{Roots: [][]byte{root}, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, Revocation: pki.RequireCRL})
	if e != nil {
		t.Fatal(e)
	}

	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name   string
		status pki.Status
	}{{"fresh", pki.Valid}, {"revoked", pki.Invalid}, {"stale", pki.Indeterminate}} {
		t.Run(tc.name, func(t *testing.T) {
			r, report, e := v.Verify(t.Context(), leaf, at, pki.Evidence{CRLs: [][]byte{read(tc.name + ".crl.der")}})
			if report.Chain != pki.Valid || report.Revocation != tc.status {
				t.Fatalf("%v %+v", e, report)
			}

			if (e == nil) != (tc.status == pki.Valid) || (r != nil) != (tc.status == pki.Valid) {
				t.Fatalf("%v", e)
			}
		})
	}
}

func FuzzCRL(f *testing.F) {
	root, e := os.ReadFile("../testdata/next/pki-root.der")
	if e != nil {
		f.Fatal(e)
	}

	leaf, e := os.ReadFile("../testdata/next/pki-leaf.der")
	if e != nil {
		f.Fatal(e)
	}

	crl, e := os.ReadFile("../testdata/next/pki-fresh.crl.der")
	if e != nil {
		f.Fatal(e)
	}

	v, e := pki.NewVerifier(pki.Config{Roots: [][]byte{root}, Revocation: pki.RequireCRL, MaxEvidenceBytes: 64 << 10})
	if e != nil {
		f.Fatal(e)
	}

	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

	f.Add(crl)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			return
		}

		_, _, _ = v.Verify(t.Context(), leaf, at, pki.Evidence{CRLs: [][]byte{b}})
	})
}

func BenchmarkVerifyCRL(b *testing.B) {
	c := testcert.New(b)

	v, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		b.Fatal(err)
	}

	e := pki.Evidence{CRLs: [][]byte{testcert.CRL(b, c)}}
	b.ReportAllocs()

	for b.Loop() {
		if _, _, err := v.Verify(b.Context(), c.Leaf.Raw, testcert.Now(), e); err != nil {
			b.Fatal(err)
		}
	}
}

func verificationTime() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) }

type chainData struct {
	root    *x509.Certificate
	leaf    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	leafKey *ecdsa.PrivateKey
}

func makeChain(t *testing.T) chainData {
	t.Helper()

	rk, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	lk, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: verificationTime().Add(-24 * time.Hour), NotAfter: verificationTime().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3}}

	der, e := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	if e != nil {
		t.Fatal(e)
	}

	root, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}

	lt := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "signer"}, NotBefore: verificationTime().Add(-time.Hour), NotAfter: verificationTime().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}

	der, e = x509.CreateCertificate(rand.Reader, lt, root, &lk.PublicKey, rk)
	if e != nil {
		t.Fatal(e)
	}

	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}

	return chainData{root, leaf, rk, lk}
}

func makeCRL(t *testing.T, c chainData, revoked bool, template *x509.RevocationList) []byte {
	t.Helper()

	if template == nil {
		template = &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: verificationTime().Add(-time.Minute), NextUpdate: verificationTime().Add(time.Minute)}
	}

	if revoked {
		template.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: c.leaf.SerialNumber, RevocationTime: verificationTime().Add(-time.Minute)}}
	}

	der, e := x509.CreateRevocationList(rand.Reader, template, c.root, c.rootKey)
	if e != nil {
		t.Fatal(e)
	}

	return der
}

// BenchmarkVerifyLargeCRL includes strict DER parsing, duplicate detection and
// all authenticated lookup passes; setup and CRL signing are outside the timer.
func BenchmarkVerifyLargeCRL(b *testing.B) {
	for _, count := range []int{1, 1024, 65536} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			c := testcert.New(b)
			revoked := make([]*x509.Certificate, count)
			for i := range revoked {
				revoked[i] = &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1000))}
			}
			raw := testcert.CRL(b, c, revoked...)
			v, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL})
			if err != nil {
				b.Fatal(err)
			}
			e := pki.Evidence{CRLs: [][]byte{raw}}
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			for b.Loop() {
				if _, _, err := v.Verify(b.Context(), c.Leaf.Raw, testcert.Now(), e); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerifyMalformedLargeCRL(b *testing.B) {
	for _, count := range []int{1024, 65536} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			c := testcert.New(b)
			for _, early := range []bool{true, false} {
				b.Run(strconv.FormatBool(early), func(b *testing.B) {
					revoked := make([]*x509.Certificate, count)
					for i := range revoked {
						revoked[i] = &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1000))}
					}
					if early {
						revoked[1] = revoked[0]
					} else {
						revoked[count-1] = revoked[0]
					}
					raw := testcert.CRL(b, c, revoked...)
					verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL})
					if err != nil {
						b.Fatal(err)
					}
					input := pki.Evidence{CRLs: [][]byte{raw}}
					b.ReportAllocs()
					b.SetBytes(int64(len(raw)))
					for b.Loop() {
						if result, _, err := verifier.Verify(b.Context(), c.Leaf.Raw, testcert.Now(), input); result != nil || !errors.Is(err, pki.ErrEvidence) {
							b.Fatal(result, err)
						}
					}
				})
			}
		})
	}
}
