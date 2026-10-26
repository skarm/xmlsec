package x509cert_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/x509cert"
)

func TestParsePreservesOriginalSignedCertificate(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	cn := der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 4, 3}), der.Wrap(0, asn1.TagUTF8String, false, []byte("relative crl")))
	relative := der.Seq(der.Seq(der.Ctx(0, der.Ctx(1, cn))))
	template := *chain.Leaf
	template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: relative}}
	encoded, err := x509.CreateCertificate(rand.Reader, &template, chain.Root, chain.LeafKey.Public(), chain.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(encoded)
	parsed, err := x509cert.ParseDefault(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, before) || !bytes.Equal(parsed.Raw, encoded) || !bytes.Equal(parsed.RawIssuer, chain.Leaf.RawIssuer) || len(parsed.CRLDistributionPoints) != 0 {
		t.Fatal("private parsing view changed original DER or invented a URI")
	}
	if err := parsed.CheckSignatureFrom(chain.Root); err != nil {
		t.Fatal("original signed TBS was not restored", err)
	}
	var found bool
	for _, extension := range parsed.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}) {
			found = bytes.Equal(extension.Value, relative)
		}
	}
	if !found {
		t.Fatal("original relative distribution point was replaced")
	}
}

func TestParseBoundsAndNoAuthentication(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	raw := chain.Leaf.Raw
	for _, tc := range []struct {
		name   string
		limits x509cert.Limits
	}{
		{"bytes", x509cert.Limits{Bytes: len(raw) - 1, Depth: 33, Nodes: 100000}},
		{"depth", x509cert.Limits{Bytes: len(raw), Depth: 1, Nodes: 100000}},
		{"nodes", x509cert.Limits{Bytes: len(raw), Depth: 33, Nodes: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got, err := x509cert.Parse(raw, tc.limits); got != nil || !errors.Is(err, der.ErrLimit) {
				t.Fatal(got, err)
			}
		})
	}
	exact, err := x509cert.ParseWithMaxBytes(raw, len(raw))
	if err != nil || !bytes.Equal(exact.RawTBSCertificate, chain.Leaf.RawTBSCertificate) {
		t.Fatal("exact byte bound", err)
	}
	for _, invalid := range [][]byte{nil, {0x30, 0}, append(bytes.Clone(raw), 0)} {
		if got, err := x509cert.ParseDefault(invalid); got != nil || err == nil {
			t.Fatal("malformed certificate accepted", got, err)
		}
	}
	changed := bytes.Clone(raw)
	changed[len(changed)-1] ^= 1
	parsed, err := x509cert.ParseDefault(changed)
	if err != nil {
		t.Fatal("a parser must not claim signature authentication", err)
	}
	if err := parsed.CheckSignatureFrom(chain.Root); err == nil {
		t.Fatal("corrupted signature passed independent signature check")
	}
}

func BenchmarkParseCertificate(b *testing.B) {
	chain := testcert.New(b)
	for _, size := range []int{0, 64 << 10} {
		raw := chain.Leaf.Raw
		name := "ordinary"
		if size != 0 {
			template := *chain.Leaf
			template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: der.Octets(bytes.Repeat([]byte("x"), size))}}
			var err error
			raw, err = x509.CreateCertificate(rand.Reader, &template, chain.Root, chain.LeafKey.Public(), chain.RootKey)
			if err != nil {
				b.Fatal(err)
			}
			name = "large-extension"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			for b.Loop() {
				if _, err := x509cert.ParseDefault(raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
