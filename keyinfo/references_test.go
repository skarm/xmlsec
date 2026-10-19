package keyinfo_test

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/keyinfo"
)

const uriUrnKey = "urn:key"

func TestRetrievalTypesAndPreflight(t *testing.T) {
	k := ec(t, elliptic.P256())
	full := parseXML(t, wrap(derXML(t, &k.PublicKey)))
	xml := asXML(t, full)
	// Pull a DEREncodedKeyValue out with a root namespace declaration, not a KeyInfo wrapper.
	remote := `<k:DEREncodedKeyValue xmlns:k="` + ns11 + `">` + enc(mustSPKI(t, &k.PublicKey)) + `</k:DEREncodedKeyValue>`
	for _, test := range []struct {
		name, typ string
		err       error
	}{{"typed", ns11 + "DEREncodedKeyValue", nil}, {"inferred", "", nil}, {"mismatch", ns + "X509Data", keyinfo.ErrInput}} {
		t.Run(test.name, func(t *testing.T) {
			d := parseXML(t, wrap(`<ds:RetrievalMethod URI="urn:key" Type="`+test.typ+`"/>`))
			o := keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(remote)), nil
			})}}

			r, e := keyinfo.Parse(context.Background(), d, d.Root(), o)
			if test.err != nil {
				if r != nil || !errors.Is(e, test.err) {
					t.Fatal(e)
				}

				return
			}

			if e != nil || len(r.Candidates()) != 1 {
				t.Fatal(e)
			}
		})
	}

	calls := 0
	o := keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return io.NopCloser(strings.NewReader(xml)), nil
	})}}
	requireErr(t, wrap(`<ds:RetrievalMethod URI="urn:key"><ds:Transforms><ds:Transform Algorithm="urn:unsupported"/></ds:Transforms></ds:RetrievalMethod>`), o, keyinfo.ErrUnsupported)

	if calls != 0 {
		t.Fatal("resource fetched before transform preflight")
	}
}

func mustSPKI(t testing.TB, k any) []byte {
	t.Helper()

	b, e := x509.MarshalPKIXPublicKey(k)
	if e != nil {
		t.Fatal(e)
	}

	return b
}

func TestDirectCRLRetainedWithoutTrust(t *testing.T) {
	key := ec(t, elliptic.P256())
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	ca := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "test"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}

	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}

	issuer, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}

	crl, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour)}, issuer, key)
	if e != nil {
		t.Fatal(e)
	}

	r := parseInfo(t, wrap(`<ds:X509Data><ds:X509CRL>`+enc(crl)+`</ds:X509CRL></ds:X509Data>`))

	g := r.X509Groups()[0]
	if len(r.Candidates()) != 0 || !g.Source().Valid() {
		t.Fatal("CRL became key")
	}

	g.CRLsDER()[0][0] ^= 255
	if !bytes.Equal(g.CRLsDER()[0], crl) {
		t.Fatal("CRL not owned")
	}
}

func TestLocalAndRemoteBudgets(t *testing.T) {
	requireErr(t, wrap(`<ds:KeyName>12345</ds:KeyName>`), keyinfo.Options{Limits: keyinfo.Limits{MaxBlobBytes: 4}}, keyinfo.ErrLimit)
	requireErr(t, wrap(`<ds:KeyName>x</ds:KeyName><ds:KeyName>x</ds:KeyName>`), keyinfo.Options{Limits: keyinfo.Limits{MaxElements: 2}}, keyinfo.ErrLimit)
	requireErr(t, wrap(`<k:DEREncodedKeyValue>`+strings.Repeat("A", 80)+`</k:DEREncodedKeyValue>`), keyinfo.Options{Limits: keyinfo.Limits{MaxBlobBytes: 4}}, keyinfo.ErrLimit)

	ctx, cancel := context.WithCancel(context.Background())
	r := &reader{read: func([]byte) (int, error) { cancel(); return 0, nil }}
	d := parseXML(t, wrap(`<k:KeyInfoReference URI="urn:key"/>`))

	result, e := keyinfo.Parse(ctx, d, d.Root(), keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) { return r, nil })}})
	if result != nil || !errors.Is(e, context.Canceled) || !r.closed {
		t.Fatal("cancellation/close", e)
	}
}

func TestRawCertificateRetainsFinalReadError(t *testing.T) {
	key := ec(t, elliptic.P256())
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}

	certificate, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	input := bytes.NewReader(certificate)
	failure := errors.New("final read failed")
	source := &reader{read: func(dst []byte) (int, error) {
		n, err := input.Read(dst)
		if n > 0 && input.Len() == 0 {
			err = failure
		}

		return n, err
	}}
	doc := parseXML(t, wrap(`<ds:RetrievalMethod URI="urn:key" Type="`+keyinfo.RawX509Certificate+`"/>`))

	options := keyinfo.Options{External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) { return source, nil })}}
	if result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), options); result != nil || !errors.Is(err, failure) || !source.closed {
		t.Fatal("resource failure yielded key candidates", result, err, source.closed)
	}
}
