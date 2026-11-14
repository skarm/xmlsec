//go:build interop

package interop_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/keys"
	"github.com/skarm/xmlsec/pki"
)

func TestCRLFixtures(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	base := filepath.Join(fixture.root, "testdata/next")
	leaf := filepath.Join(base, "pki-leaf.der")
	rootDER := filepath.Join(base, "pki-root.der")
	rootPEM := write(t, filepath.Join(dir, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: read(t, rootDER)}))

	leafPEM := write(t, filepath.Join(dir, "leaf.pem"), pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: read(t, leaf)}))
	for _, mode := range []string{nameFresh, "revoked", "stale"} {
		crl := filepath.Join(base, "pki-"+mode+".crl.der")
		probe(t, fixture, "nextprobe", map[string]any{nameMode: "pki-verify", nameInput: leaf, "Root": rootDER, "CRL": crl, "At": "2026-10-07T12:00:00Z"}, mode == nameFresh)
		crlPEM := write(t, filepath.Join(dir, "crl.pem"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: read(t, crl)}))
		command(t, fixture, mode == nameFresh, nil, "openssl", nameVerify, "-CAfile", rootPEM, "-CRLfile", crlPEM, "-crl_check", "-attime", "1791374400", leafPEM)
	}
}

func TestCRLCompositionsOpenSSL(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "portable")
	c := testcert.New(t)
	at := testcert.Now()
	point := func(uri string) []byte { return der.Ctx(0, der.Wrap(2, 0, true, der.Wrap(2, 6, false, []byte(uri)))) }
	freshest := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 46}, Value: der.Seq(der.Seq(point("urn:offline:delta")))}
	list := func(number int64, this, next time.Time, base int64, scope []byte, entries []x509.RevocationListEntry, extras ...pkix.Extension) []byte {
		template := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: this, NextUpdate: next, RevokedCertificateEntries: entries, ExtraExtensions: extras}
		if base >= 0 {
			value, _ := asn1.Marshal(big.NewInt(base))
			template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: value})
		}
		if scope != nil {
			template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: scope})
		}
		raw, err := x509.CreateRevocationList(rand.Reader, template, c.Root, c.RootKey)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	entry := func(reason int) []x509.RevocationListEntry {
		return []x509.RevocationListEntry{{SerialNumber: c.Leaf.SerialNumber, RevocationTime: at.Add(-time.Hour), ReasonCode: reason}}
	}
	base := list(1, at.Add(-2*time.Minute), at.Add(time.Hour), -1, nil, nil, freshest)
	held := list(1, at.Add(-2*time.Minute), at.Add(time.Hour), -1, nil, entry(6), freshest)
	delta := func(entries []x509.RevocationListEntry) []byte {
		return list(2, at.Add(-time.Minute), at.Add(time.Hour), 1, nil, entries)
	}
	expired := list(1, at.Add(-2*time.Hour), at.Add(-time.Hour), -1, nil, nil, freshest)
	leafDP := func(encoded []byte) *x509.Certificate {
		template := *c.Leaf
		template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: encoded}}
		raw, err := x509.CreateCertificate(rand.Reader, &template, c.Root, c.LeafKey.Public(), c.RootKey)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := keys.ParseCertificate(raw, keys.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	scope := func(mask byte) []byte {
		return der.Seq(point("urn:offline:partition"), der.Wrap(2, 3, false, []byte{0, mask}))
	}
	scopedLeaf := leafDP(der.Seq(der.Seq(point("urn:offline:partition"))))
	relative := func(value string) []byte {
		return der.Ctx(0, der.Wrap(2, 1, true, der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 4, 3}), der.Wrap(0, asn1.TagUTF8String, false, []byte(value)))))
	}
	relativeLeaf := leafDP(der.Seq(der.Seq(relative("partition"))))
	type composition struct {
		name  string
		leaf  *x509.Certificate
		lists [][]byte
		want  error
	}
	tests := make([]composition, 0, 13)
	tests = append(tests, []composition{
		{"complete v1 good", c.Leaf, [][]byte{testcert.CRLV1(t, c)}, nil},
		{"complete v1 revoked", c.Leaf, [][]byte{testcert.CRLV1(t, c, c.Leaf)}, pki.ErrRevoked},
		{"complete v2 good", c.Leaf, [][]byte{testcert.CRL(t, c)}, nil},
		{"complete v2 revoked", c.Leaf, [][]byte{testcert.CRL(t, c, c.Leaf)}, pki.ErrRevoked},
		{"expired complete", c.Leaf, [][]byte{list(1, at.Add(-2*time.Hour), at.Add(-time.Hour), -1, nil, nil)}, pki.ErrUnavailable},
		{"delta adds revocation", c.Leaf, [][]byte{base, delta(entry(1))}, pki.ErrRevoked},
		{"delta releases hold", c.Leaf, [][]byte{held, delta(entry(8))}, nil},
		{"expired base current delta", c.Leaf, [][]byte{expired, delta(nil)}, nil},
		{"scoped all reasons", scopedLeaf, [][]byte{list(1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope(0x78), nil), list(1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope(0x07), nil), list(1, at.Add(-time.Minute), at.Add(time.Hour), -1, der.Seq(point("urn:offline:partition"), der.Wrap(2, 3, false, []byte{7, 0, 128})), nil)}, nil},
		{"scoped incomplete reasons", scopedLeaf, [][]byte{list(1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope(0x78), nil)}, pki.ErrUnavailable},
		{"relative distribution point", relativeLeaf, [][]byte{list(1, at.Add(-time.Minute), at.Add(time.Hour), -1, der.Seq(relative("PARTITION")), nil)}, nil},
	}...)

	delegateKey := testcert.Key(t)
	delegate := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(17), Subject: pkix.Name{CommonName: "non-CA CRL delegate"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageCRLSign, SubjectKeyId: []byte{9, 7, 5}}, c.Root, delegateKey.Public(), c.RootKey)
	indirectLeaf := leafDP(der.Seq(der.Seq(point("urn:offline:indirect"), der.Wrap(2, 2, true, der.Ctx(4, delegate.RawSubject)))))
	indirectScope := der.Seq(point("urn:offline:indirect"), der.Wrap(2, 4, false, []byte{255}))
	for _, revoked := range []bool{false, true} {
		template := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: indirectScope}}}
		name := "indirect non-CA good"
		var want error
		if revoked {
			name = "indirect non-CA revoked"
			want = pki.ErrRevoked
			template.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: indirectLeaf.SerialNumber, RevocationTime: at.Add(-time.Hour), ReasonCode: 1, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 29}, Critical: true, Value: der.Seq(der.Ctx(4, c.Root.RawSubject))}}}}
		}
		raw, err := x509.CreateRevocationList(rand.Reader, template, delegate, delegateKey)
		if err != nil {
			t.Fatal(err)
		}
		tests = append(tests, composition{name, indirectLeaf, [][]byte{raw}, want})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL})
			if err != nil {
				t.Fatal(err)
			}
			input := pki.Evidence{CRLs: test.lists}
			if strings.HasPrefix(test.name, "indirect ") {
				input.Intermediates = [][]byte{delegate.Raw}
			}
			result, _, err := verifier.Verify(t.Context(), test.leaf.Raw, at, input)
			if test.want == nil {
				if err != nil || result == nil {
					t.Fatal(result != nil, err)
				}
			} else if result != nil || !errors.Is(err, test.want) {
				t.Fatal(result != nil, err)
			}
			directory := t.TempDir()
			root := write(t, filepath.Join(directory, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Root.Raw}))
			leaf := write(t, filepath.Join(directory, "leaf.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: test.leaf.Raw}))
			var bundle bytes.Buffer
			for _, raw := range test.lists {
				if err := pem.Encode(&bundle, &pem.Block{Type: "X509 CRL", Bytes: raw}); err != nil {
					t.Fatal(err)
				}
			}
			crls := write(t, filepath.Join(directory, "crls.pem"), bundle.Bytes())

			args := []string{"verify", "-CAfile", root, "-CRLfile", crls, "-crl_check", "-extended_crl", "-use_deltas", "-attime", strconv.FormatInt(at.Unix(), 10)}
			if strings.HasPrefix(test.name, "indirect ") {
				untrusted := write(t, filepath.Join(directory, "delegate.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: delegate.Raw}))
				args = append(args, "-untrusted", untrusted)
			}
			args = append(args, leaf)
			output, diagnostic := command(t, fixture, test.want == nil, nil, "openssl", args...)
			if test.want == nil && !bytes.Contains(output, []byte(": OK")) {
				t.Fatal(string(output), string(diagnostic))
			}
			if test.want != nil {
				expected := "unable to get certificate CRL"
				if errors.Is(test.want, pki.ErrRevoked) {
					expected = "certificate revoked"
				}
				if test.name == "expired complete" {
					expected = "CRL has expired"
				}
				if !bytes.Contains(diagnostic, []byte(expected)) {
					t.Fatal(string(output), string(diagnostic))
				}
			}
		})
	}
}
