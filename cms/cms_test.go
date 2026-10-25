package cms_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestCMSIndependentFixtures(t *testing.T) {
	paths, err := filepath.Glob("../testdata/evidence/cms-*/signature.der")
	if err != nil || len(paths) == 0 {
		t.Fatal(paths, err)
	}

	for _, path := range paths {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) { testCMSIndependentFixture(t, path) })
	}
}

func testCMSIndependentFixture(t *testing.T, path string) {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := os.ReadFile(filepath.Join(filepath.Dir(path), "signer.der"))
	if err != nil {
		t.Fatal(err)
	}

	message, err := os.ReadFile(filepath.Join(filepath.Dir(path), "content.bin"))
	if err != nil {
		t.Fatal(err)
	}

	signed, err := cms.ParseReader(t.Context(), bytes.NewReader(raw), cms.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	options := cms.VerifyOptions{ExpectedContentType: cms.DataOID()}
	if signed.Detached() {
		options.DetachedContent = &message
	}

	for _, discard := range []bool{false, true} {
		options.DiscardContent = discard

		result, err := signed.Verify(t.Context(), [][]byte{certificate}, options)
		if err != nil {
			t.Fatal(err)
		}

		if result.ContentSize() != int64(len(message)) || (!discard && !bytes.Equal(result.Content(), message)) || (discard && result.Content() != nil) {
			t.Fatal("content retention", discard)
		}
	}

	var output bytes.Buffer
	if n, err := signed.WriterTo(t.Context()).WriteTo(&output); err != nil || n != int64(len(raw)) || !bytes.Equal(output.Bytes(), raw) {
		t.Fatal("DER replay", n, err)
	}
}

func TestCMSRejectsMalformedAttributeValues(t *testing.T) {
	c := testcert.New(t)
	for _, value := range [][]byte{
		{12, 1, 255},
		{19, 1, '@'},
		{22, 1, 255},
		{30, 2, 0xd8, 0},
		der.Wrap(0, asn1.TagGeneralizedTime, false, []byte("20261019010203.10Z")),
	} {
		signer := cms.Signer{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Attributes: []cms.Attribute{{OID: asn1.ObjectIdentifier{1, 2, 3, 4}, ValuesDER: [][]byte{value}}}}
		if raw, err := cms.Sign(t.Context(), nil, []cms.Signer{signer}, cms.SignOptions{}); raw != nil || !errors.Is(err, cms.ErrPolicy) {
			t.Fatalf("invalid attribute %x: output=%t, error=%v", value, raw != nil, err)
		}
	}
}

func TestCMSAttributeSetOrdering(t *testing.T) {
	c := testcert.New(t)
	// A custom attribute containing SET { SEQUENCE {}, IA5String }.
	value := []byte{0x31, 5, 0x30, 0, 0x16, 1, 'a'}
	signer := cms.Signer{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Attributes: []cms.Attribute{{OID: asn1.ObjectIdentifier{1, 2, 3, 4}, ValuesDER: [][]byte{value}}}}

	raw, err := cms.Sign(t.Context(), []byte("content"), []cms.Signer{signer}, cms.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := cms.Parse(t.Context(), raw, cms.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := parsed.Verify(t.Context(), [][]byte{c.Leaf.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID()}); err != nil {
		t.Fatal(err)
	}
}

func TestCMSSignedAttributesBorrowOwnedDER(t *testing.T) {
	c := testcert.New(t)

	value, err := asn1.Marshal(bytes.Repeat([]byte{7}, 512<<10))
	if err != nil {
		t.Fatal(err)
	}

	raw, err := cms.Sign(t.Context(), []byte("content"), []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Attributes: []cms.Attribute{{OID: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, ValuesDER: [][]byte{value}}}}}, cms.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}

	var before, after runtime.MemStats

	allocated := ^uint64(0)

	for range 3 {
		runtime.ReadMemStats(&before)

		parsed, err := cms.Parse(t.Context(), raw, cms.Limits{})

		runtime.ReadMemStats(&after)

		if err != nil {
			t.Fatal(err)
		}

		allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)

		result, err := parsed.Verify(t.Context(), [][]byte{c.Leaf.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID(), DiscardContent: true})
		if err != nil || len(result.Signers()) != 1 {
			t.Fatal(result, err)
		}
	}

	if allocated > uint64(len(raw))+(128<<10) {
		t.Fatalf("CMS parsing copied signed attributes: %d allocated for %d DER bytes", allocated, len(raw))
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	parsed, err := cms.Parse(t.Context(), raw, cms.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	if n, err := parsed.WriterTo(ctx).WriteTo(io.Discard); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal(n, err)
	}
}

func TestCMSRoundTrip(t *testing.T) {
	c := testcert.New(t)

	rk, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}

	rc := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(15), Subject: pkix.Name{CommonName: "RSA"}, NotBefore: testcert.Now().Add(-time.Hour), NotAfter: testcert.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}, c.Root, &rk.PublicKey, c.RootKey)
	for _, tc := range []struct {
		name     string
		key      crypto.Signer
		cert     []byte
		h        crypto.Hash
		pss, ski bool
	}{{"ECDSA256", c.LeafKey, c.Leaf.Raw, crypto.SHA256, false, false}, {"ECDSA384 SKI", c.LeafKey, c.Leaf.Raw, crypto.SHA384, false, true}, {"ECDSA512", c.LeafKey, c.Leaf.Raw, crypto.SHA512, false, false}, {"RSA", rk, rc.Raw, crypto.SHA256, false, false}, {"PSS256", rk, rc.Raw, crypto.SHA256, true, false}, {"PSS384", rk, rc.Raw, crypto.SHA384, true, false}, {"PSS512", rk, rc.Raw, crypto.SHA512, true, false}} {
		for _, detached := range []bool{false, true} {
			suffix := " attached"
			if detached {
				suffix = " detached"
			}

			t.Run(tc.name+suffix, func(t *testing.T) { testCMSRoundTripCase(t, &tc, &detached, &c) })
		}
	}
}

func testCMSRoundTripCase(t *testing.T, tc *struct {
	name string
	key  crypto.Signer
	cert []byte
	h    crypto.Hash
	pss  bool
	ski  bool
}, detached *bool, c *testcert.Chain,
) {
	m := []byte("exact\x00binary\r\ncontent")

	raw, e := cms.Sign(context.Background(), m, []cms.Signer{{Key: tc.key, CertificateDER: tc.cert, Hash: tc.h, RSAPSS: tc.pss, SubjectKeyIdentifier: tc.ski}}, cms.SignOptions{Detached: *detached, ExtraCertificates: [][]byte{c.Root.Raw}})
	if e != nil {
		t.Fatal(e)
	}

	s, e := cms.Parse(t.Context(), raw, cms.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	o := cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true}
	if *detached {
		o.DetachedContent = &m
	}

	r, e := s.Verify(context.Background(), [][]byte{tc.cert}, o)
	if e != nil || r == nil || !bytes.Equal(r.Content(), m) || !r.Signers()[0].CertificateBound() {
		t.Fatal(e)
	}

	r.Content()[0] ^= 1

	r.Signers()[0].CertificateDER()[0] ^= 1
	if !bytes.Equal(r.Content(), m) {
		t.Fatal("mutable")
	}

	if _, e = s.Verify(context.Background(), [][]byte{tc.cert}, o); e != nil {
		t.Fatal(e)
	}

	if *detached {
		wrong := []byte("other")

		o.DetachedContent = &wrong
		if r, e := s.Verify(context.Background(), [][]byte{tc.cert}, o); r != nil || !errors.Is(e, cms.ErrSignature) {
			t.Fatal(e)
		}
	} else {
		o.DetachedContent = &m
		if r, e := s.Verify(context.Background(), [][]byte{tc.cert}, o); r != nil || !errors.Is(e, cms.ErrPolicy) {
			t.Fatal(e)
		}
	}
}

func TestCMSMultiplePolicyAndMutation(t *testing.T) {
	c := testcert.New(t)
	signers := []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}, {Key: c.TSAKey, CertificateDER: c.TSA.Raw}}

	raw, e := cms.Sign(context.Background(), []byte("unique payload here"), signers, cms.SignOptions{})
	if e != nil {
		t.Fatal(e)
	}

	s, e := cms.Parse(t.Context(), raw, cms.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	if _, e = s.Verify(context.Background(), [][]byte{c.TSA.Raw, c.Leaf.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID()}); e != nil {
		t.Fatal(e)
	}

	for _, cs := range [][][]byte{{c.Leaf.Raw}, {c.Leaf.Raw, c.Leaf.Raw}, {c.Root.Raw, c.TSA.Raw}} {
		if r, e := s.Verify(context.Background(), cs, cms.VerifyOptions{ExpectedContentType: cms.DataOID()}); r != nil || e == nil {
			t.Fatal("partial/wrong signers")
		}
	}

	for _, b := range [][]byte{nil, {0x30, 0}, raw[:len(raw)-1], append(bytes.Clone(raw), 0)} {
		if _, e = cms.Parse(t.Context(), b, cms.DefaultLimits()); e == nil {
			t.Fatal("invalid DER")
		}
	}

	mutated := bytes.Replace(raw, []byte("unique payload here"), []byte("unique payload evil"), 1)

	s, e = cms.Parse(t.Context(), mutated, cms.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	if r, e := s.Verify(context.Background(), [][]byte{c.Leaf.Raw, c.TSA.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID()}); r != nil || !errors.Is(e, cms.ErrSignature) {
		t.Fatal("content", e)
	}

	for _, oid := range []asn1.ObjectIdentifier{{1, 2, 840, 113549, 1, 9, 3}, {1, 2, 840, 113549, 1, 9, 4}, {1, 2, 840, 113549, 1, 9, 52}} {
		x := signers[0]

		x.Attributes = []cms.Attribute{{OID: oid, ValuesDER: [][]byte{{5, 0}}}}
		if _, e = cms.Sign(context.Background(), nil, []cms.Signer{x}, cms.SignOptions{}); !errors.Is(e, cms.ErrPolicy) {
			t.Fatal("reserved", e)
		}
	}

	x := signers[0]
	x.OmitCertificateBinding = true

	raw, e = cms.Sign(context.Background(), nil, []cms.Signer{x}, cms.SignOptions{})
	if e != nil {
		t.Fatal(e)
	}

	s, e = cms.Parse(t.Context(), raw, cms.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	if r, e := s.Verify(context.Background(), [][]byte{c.Leaf.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true}); r != nil || !errors.Is(e, cms.ErrCertificate) {
		t.Fatal("ESS required", e)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, e = s.Verify(ctx, [][]byte{c.Leaf.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID()}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func FuzzParse(f *testing.F) {
	fixture := testcert.LoadFixture(f, "../testdata/evidence", "cms-ecdsa-256-attached")
	raw := fixture.Read(f, "cms-ecdsa-256-attached/signature.der")
	certificate := fixture.Read(f, "cms-ecdsa-256-attached/signer.der")
	options := cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true}

	seed, e := cms.Parse(context.Background(), raw, cms.DefaultLimits())
	if e != nil {
		f.Fatal(e)
	}

	result, e := seed.Verify(context.Background(), [][]byte{certificate}, options)
	if e != nil || result == nil || !bytes.Equal(result.Content(), fixture.Read(f, "cms-ecdsa-256-attached/content.bin")) {
		f.Fatalf("invalid positive CMS fixture: %v", e)
	}

	f.Add(raw)
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}

		s, e := cms.Parse(t.Context(), b, cms.DefaultLimits())
		if e == nil {
			result, e := s.Verify(context.Background(), [][]byte{certificate}, options)
			if e != nil && result != nil || e == nil && (result == nil || len(result.Signers()) != 1 || !result.Signers()[0].CertificateBound()) {
				t.Fatal("inconsistent CMS verification result")
			}
		}
	})
}

func BenchmarkCMS(b *testing.B) {
	c := testcert.New(b)

	raw, err := cms.Sign(context.Background(), make([]byte, 4096), []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}}, cms.SignOptions{})
	if err != nil {
		b.Fatal(err)
	}

	s, err := cms.Parse(b.Context(), raw, cms.DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}

	b.Run("Parse", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			if _, err := cms.Parse(b.Context(), raw, cms.DefaultLimits()); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Verify", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			if _, err := s.Verify(context.Background(), [][]byte{c.Leaf.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestCMSRejectsEmptySignedData(t *testing.T) {
	for _, s := range []*cms.SignedData{nil, new(cms.SignedData)} {
		result, err := s.Verify(context.Background(), nil, cms.VerifyOptions{})
		if result != nil || !errors.Is(err, cms.ErrPolicy) {
			t.Fatalf("unsigned zero value: result=%v error=%v", result != nil, err)
		}
	}
}

func TestCMSAlgorithmProtectionPreservesIdentifier(t *testing.T) {
	c := testcert.New(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	cert := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "RSA signer"}, NotBefore: testcert.Now().Add(-time.Hour), NotAfter: testcert.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}, c.Root, &key.PublicKey, c.RootKey)

	raw, err := cms.Sign(context.Background(), []byte("protected algorithms"), []cms.Signer{{Key: key, CertificateDER: cert.Raw}}, cms.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		algorithm asn1.ObjectIdentifier
		want      error
	}{
		{"same OID absent NULL", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, nil},
		{"different RSA OID", signature.RSA(), cms.ErrSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := rewriteSigner(t, raw, func(f []asn1.RawValue) [][]byte {
				b := signerBytes(f)
				b[4] = der.Seq(der.OID(tc.algorithm))

				return b
			})

			s, err := cms.Parse(t.Context(), modified, cms.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}

			result, err := s.Verify(context.Background(), [][]byte{cert.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID()})
			if tc.want == nil && (err != nil || result == nil) || tc.want != nil && (result != nil || !errors.Is(err, tc.want)) {
				t.Fatalf("result=%v error=%v want=%v", result != nil, err, tc.want)
			}
		})
	}
}

func TestCMSRejectsAttributesInWrongSection(t *testing.T) {
	c := testcert.New(t)

	raw, err := cms.Sign(context.Background(), []byte("payload"), []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}}, cms.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for _, suffix := range [][]int{{3}, {4}, {5}, {52}, {16, 2, 12}, {16, 2, 47}} {
		oid := append(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9}, suffix...)
		t.Run(oid.String(), func(t *testing.T) {
			modified := rewriteSigner(t, raw, func(f []asn1.RawValue) [][]byte {
				attrs, err := der.Read(der.Set(der.Seq(der.OID(oid), der.Set(der.Octets(nil)))), 4096)
				if err != nil {
					t.Fatal(err)
				}

				return append(signerBytes(f), der.Wrap(2, 1, true, attrs.Bytes))
			})
			if s, err := cms.Parse(t.Context(), modified, cms.DefaultLimits()); s != nil || !errors.Is(err, cms.ErrSyntax) {
				t.Fatalf("wrong section accepted: parsed=%v error=%v", s != nil, err)
			}
		})
	}

	_, err = cms.Sign(context.Background(), nil, []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Attributes: []cms.Attribute{{OID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}, ValuesDER: [][]byte{der.Seq()}}}}}, cms.SignOptions{})
	if !errors.Is(err, cms.ErrPolicy) {
		t.Fatalf("signed countersignature: %v", err)
	}
}

func TestCMSSigningTimeSyntax(t *testing.T) {
	c := testcert.New(t)
	for _, tc := range []struct {
		text  string
		tag   int
		valid bool
	}{
		{"261008120000Z", asn1.TagUTCTime, true},
		{"491231235959Z", asn1.TagUTCTime, true},
		{"20500101000000Z", asn1.TagGeneralizedTime, true},
		{"19491231235959Z", asn1.TagGeneralizedTime, true},
		{"20261008120000Z", asn1.TagGeneralizedTime, false},
		{"2610081200Z", asn1.TagUTCTime, false},
		{"261008140000+0200", asn1.TagUTCTime, false},
		{"20500101000000.1Z", asn1.TagGeneralizedTime, false},
		{"20500230000000Z", asn1.TagGeneralizedTime, false},
	} {
		t.Run(tc.text, func(t *testing.T) {
			a := cms.Attribute{OID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}, ValuesDER: [][]byte{der.Wrap(0, tc.tag, false, []byte(tc.text))}}

			raw, err := cms.Sign(context.Background(), nil, []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Hash: crypto.SHA256, Attributes: []cms.Attribute{a}}}, cms.SignOptions{})
			if tc.valid && (raw == nil || err != nil) || !tc.valid && (raw != nil || !errors.Is(err, cms.ErrPolicy)) {
				t.Fatalf("valid=%v output=%v error=%v", tc.valid, raw != nil, err)
			}
		})
	}
}

// Rebuild just the unsigned container, leaving the signed attributes and
// cryptographic signature intact. The negative cases are valid DER.
func rewriteSigner(t *testing.T, raw []byte, change func([]asn1.RawValue) [][]byte) []byte {
	t.Helper()

	v, err := der.Read(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}

	ci, err := der.Sequence(v, 2, 2)
	if err != nil {
		t.Fatal(err)
	}

	sd, err := der.Explicit(ci[1], 0)
	if err != nil {
		t.Fatal(err)
	}

	f, err := der.Sequence(sd, 4, 6)
	if err != nil {
		t.Fatal(err)
	}

	si, err := der.SetFields(f[len(f)-1], 0, asn1.TagSet, 1)
	if err != nil || len(si) != 1 {
		t.Fatal(err)
	}

	fields, err := der.Sequence(si[0], 5, 7)
	if err != nil {
		t.Fatal(err)
	}

	parts := make([][]byte, len(f))
	for i := range f {
		parts[i] = f[i].FullBytes
	}

	parts[len(parts)-1] = der.Set(der.Seq(change(fields)...))

	return der.Seq(ci[0].FullBytes, der.Ctx(0, der.Seq(parts...)))
}

func signerBytes(f []asn1.RawValue) [][]byte {
	b := make([][]byte, len(f))
	for i := range f {
		b[i] = f[i].FullBytes
	}

	return b
}
