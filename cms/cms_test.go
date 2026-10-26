package cms_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
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

func TestCMSBERConstructedContent(t *testing.T) {
	fixture := testcert.LoadFixture(t, "../testdata/evidence", "cms-ecdsa-256-attached")
	raw := fixture.Read(t, "cms-ecdsa-256-attached/signature.der")
	certificate := fixture.Read(t, "cms-ecdsa-256-attached/signer.der")
	content := fixture.Read(t, "cms-ecdsa-256-attached/content.bin")
	mid := len(content) / 2

	chunks := [][]byte{der.Octets(content[:mid]), der.Octets(nil), der.Octets(content[mid:])}
	for _, encoded := range [][]byte{
		raw,
		cmsBEREnvelope(t, raw, der.Octets(content)),
		cmsBEREnvelope(t, raw, der.Wrap(0, asn1.TagOctetString, true, bytes.Join(chunks, nil))),
		cmsBEREnvelope(t, raw, indefiniteBER(0x24, chunks...)),
		cmsBEREnvelope(t, raw, indefiniteBER(0x24, chunks[0], indefiniteBER(0x24, chunks[1:]...))),
	} {
		parsed, err := cms.ParseBERReader(t.Context(), bytes.NewReader(encoded), cms.Limits{})
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(parsed.DER(), raw) || parsed.Size() != len(raw) {
			t.Fatal("BER changed signed fields or normalized encoding")
		}

		result, err := parsed.Verify(t.Context(), [][]byte{certificate}, cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true})
		if err != nil || !bytes.Equal(result.Content(), content) {
			t.Fatal("independent signature did not survive BER normalization", err)
		}

		if !bytes.Equal(encoded, raw) {
			if got, err := cms.Parse(t.Context(), encoded, cms.Limits{}); got != nil || !errors.Is(err, cms.ErrSyntax) {
				t.Fatal("strict Parse silently enabled BER", err)
			}
		}

		var output bytes.Buffer
		if n, err := parsed.WriterTo(t.Context()).WriteTo(&output); err != nil || n != int64(len(raw)) || !bytes.Equal(output.Bytes(), raw) {
			t.Fatal("normalized replay", n, err)
		}
	}
	// BER permits leading zero length octets on the selected envelope wrappers.
	root, err := der.Read(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}

	wide := make([]byte, 0, 6+len(root.Bytes))
	wide = append(wide, 0x30, 0x84, byte(len(root.Bytes)>>24), byte(len(root.Bytes)>>16), byte(len(root.Bytes)>>8), byte(len(root.Bytes)))
	wide = append(wide, root.Bytes...)

	parsed, err := cms.ParseBER(t.Context(), wide, cms.Limits{})
	if err != nil || !bytes.Equal(parsed.DER(), raw) {
		t.Fatal("BER length normalization", err)
	}

	clear(wide)

	if !bytes.Equal(parsed.DER(), raw) {
		t.Fatal("normalized model borrowed caller bytes")
	}
	// EOC octets inside a primitive value are content, not wrapper terminators.
	parsed, err = cms.ParseBER(t.Context(), cmsBEREnvelope(t, raw, der.Octets([]byte{0, 0})), cms.Limits{})
	if err != nil || !bytes.Equal(parsed.UnverifiedContent(), []byte{0, 0}) {
		t.Fatal("primitive content confused with EOC", err)
	}

	if result, err := parsed.Verify(t.Context(), [][]byte{certificate}, cms.VerifyOptions{ExpectedContentType: cms.DataOID()}); result != nil || !errors.Is(err, cms.ErrSignature) {
		t.Fatal("changed BER content authenticated", err)
	}
}

func TestCMSBERDetached(t *testing.T) {
	fixture := testcert.LoadFixture(t, "../testdata/evidence", "cms-rsa-256-detached")
	raw := fixture.Read(t, "cms-rsa-256-detached/signature.der")
	content := fixture.Read(t, "cms-rsa-256-detached/content.bin")
	certificate := fixture.Read(t, "cms-rsa-256-detached/signer.der")

	parsed, err := cms.ParseBER(t.Context(), cmsBEREnvelope(t, raw, nil), cms.Limits{})
	if err != nil || !parsed.Detached() || !bytes.Equal(parsed.DER(), raw) {
		t.Fatal("detached BER", err)
	}

	result, err := parsed.Verify(t.Context(), [][]byte{certificate}, cms.VerifyOptions{ExpectedContentType: cms.DataOID(), DetachedContent: &content})
	if err != nil || !bytes.Equal(result.Content(), content) {
		t.Fatal("detached binding changed", err)
	}
}

func TestCMSBERLimitsAndSyntax(t *testing.T) {
	fixture := testcert.LoadFixture(t, "../testdata/evidence", "cms-ecdsa-256-attached")
	raw := fixture.Read(t, "cms-ecdsa-256-attached/signature.der")
	content := fixture.Read(t, "cms-ecdsa-256-attached/content.bin")

	valid := cmsBEREnvelope(t, raw, indefiniteBER(0x24, der.Octets(content)))
	for _, bad := range [][]byte{
		valid[:len(valid)-1], append(bytes.Clone(valid), 0),
		{0x30, 0x88, 255, 255, 255, 255, 255, 255, 255, 255},
		{0x30, 0x80, 0, 0, 0, 0},
		cmsBEREnvelope(t, raw, []byte{4, 128, 0, 0}),
		cmsBEREnvelope(t, raw, indefiniteBER(0x24, der.Int(1))),
		cmsBEREnvelope(t, raw, der.Wrap(0, 4, true, []byte{0, 0})),
	} {
		if got, err := cms.ParseBER(t.Context(), bad, cms.Limits{}); got != nil || !errors.Is(err, cms.ErrSyntax) {
			t.Fatalf("bad BER %x: %v", bad[:min(len(bad), 12)], err)
		}
	}

	for _, limits := range []cms.Limits{{MaxBytes: len(valid) - 1}, {MaxContentBytes: len(content) - 1}} {
		if got, err := cms.ParseBER(t.Context(), valid, limits); got != nil || !errors.Is(err, cms.ErrPolicy) {
			t.Fatal("BER budget ignored", err)
		}
	}

	deep := der.Octets(content)
	for range 27 { // Root/explicit/SignedData/encap/explicit + 27 constructed levels + leaf = 33.
		deep = indefiniteBER(0x24, deep)
	}

	if got, err := cms.ParseBER(t.Context(), cmsBEREnvelope(t, raw, deep), cms.Limits{MaxContentBytes: len(content)}); got == nil || err != nil {
		t.Fatal("exact BER depth/content limits rejected", err)
	}

	deep = indefiniteBER(0x24, deep)

	wide := indefiniteBER(0x24, bytes.Repeat(der.Octets(nil), 100001))
	for _, encoded := range [][]byte{cmsBEREnvelope(t, raw, deep), cmsBEREnvelope(t, raw, wide)} {
		if got, err := cms.ParseBER(t.Context(), encoded, cms.Limits{}); got != nil || !errors.Is(err, cms.ErrPolicy) {
			t.Fatal("BER structural budget ignored", err)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if got, err := cms.ParseBER(ctx, valid, cms.Limits{}); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("BER cancellation ignored", err)
	}

	if got, err := cms.ParseBERReader(t.Context(), nil, cms.Limits{}); got != nil || !errors.Is(err, cms.ErrPolicy) {
		t.Fatal("nil BER source accepted", err)
	}
}

func TestCMSBERPreservesDERAttributes(t *testing.T) {
	fixture := testcert.LoadFixture(t, "../testdata/evidence", "cms-ecdsa-256-attached")

	raw := fixture.Read(t, "cms-ecdsa-256-attached/signature.der")
	for _, indefinite := range []bool{false, true} {
		bad := rewriteSigner(t, raw, func(fields []asn1.RawValue) [][]byte {
			parts := signerBytes(fields)
			if fields[3].Class != 2 || fields[3].Tag != 0 {
				t.Fatal("missing signed attributes")
			}

			if indefinite {
				parts[3] = indefiniteBER(0xa0, fields[3].Bytes)
			} else {
				attrs, err := der.Children(fields[3])
				if err != nil || len(attrs) < 2 {
					t.Fatal("invalid attribute fixture", err)
				}

				encoded := signerBytes(attrs)
				encoded[0], encoded[len(encoded)-1] = encoded[len(encoded)-1], encoded[0]
				parts[3] = der.Wrap(2, 0, true, bytes.Join(encoded, nil))
			}

			return parts
		})
		if got, err := cms.ParseBER(t.Context(), bad, cms.Limits{}); got != nil || !errors.Is(err, cms.ErrSyntax) {
			t.Fatal("BER parser repaired invalid signed-attribute encoding", err)
		}
	}
}

func TestCMSBERNormalizedBudget(t *testing.T) {
	fixture := testcert.LoadFixture(t, "../testdata/evidence", "cms-ecdsa-256-attached")
	raw := fixture.Read(t, "cms-ecdsa-256-attached/signature.der")
	encoded := cmsBEREnvelope(t, raw, der.Octets(make([]byte, 1<<16)))

	parsed, err := cms.ParseBER(t.Context(), encoded, cms.Limits{})
	if err != nil || parsed.Size() <= len(encoded) {
		t.Fatal("ineffective normalized-size boundary case", err)
	}

	if got, err := cms.ParseBER(t.Context(), encoded, cms.Limits{MaxBytes: len(encoded)}); got != nil || !errors.Is(err, cms.ErrPolicy) {
		t.Fatal("normalized encoding exceeded container budget", err)
	}

	if got, err := cms.ParseBER(t.Context(), encoded, cms.Limits{MaxBytes: parsed.Size()}); got == nil || err != nil {
		t.Fatal("exact normalized byte limit rejected", err)
	}

	for _, reader := range []io.Reader{nil, (*bytes.Reader)(nil)} {
		if got, err := cms.ParseBERReader(t.Context(), reader, cms.Limits{}); got != nil || !errors.Is(err, cms.ErrPolicy) {
			t.Fatal("nil source accepted", err)
		}
	}

	if got, err := cms.ParseBER(nil, encoded, cms.Limits{}); got != nil || !errors.Is(err, cms.ErrPolicy) {
		t.Fatal("nil context accepted", err)
	}
}

func indefiniteBER(tag byte, parts ...[]byte) []byte {
	return append(append([]byte{tag, 128}, bytes.Join(parts, nil)...), 0, 0)
}

func cmsBEREnvelope(t testing.TB, raw, octets []byte) []byte {
	t.Helper()
	ci, fields := cmsEnvelopeFields(t, raw)

	ec, err := der.Sequence(fields[2], 1, 2)
	if err != nil {
		t.Fatal(err)
	}

	encap := ec[0].FullBytes
	if len(ec) == 2 {
		encap = append(bytes.Clone(encap), indefiniteBER(0xa0, octets)...)
	}

	parts := signerBytes(fields)
	parts[2] = indefiniteBER(0x30, encap)

	return indefiniteBER(0x30, ci[0].FullBytes, indefiniteBER(0xa0, indefiniteBER(0x30, parts...)))
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
		name string
		key  crypto.Signer
		cert []byte
		h    crypto.Hash
		pss  bool
		ski  bool
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

	raw, e := cms.Sign(t.Context(), m, []cms.Signer{{Key: tc.key, CertificateDER: tc.cert, Hash: tc.h, RSAPSS: tc.pss, SubjectKeyIdentifier: tc.ski}}, cms.SignOptions{Detached: *detached, ExtraCertificates: [][]byte{c.Root.Raw}})
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

	r, e := s.Verify(t.Context(), [][]byte{tc.cert}, o)
	if e != nil || r == nil || !bytes.Equal(r.Content(), m) || !r.Signers()[0].CertificateBound() {
		t.Fatal(e)
	}

	r.Content()[0] ^= 1

	r.Signers()[0].CertificateDER()[0] ^= 1
	if !bytes.Equal(r.Content(), m) {
		t.Fatal("mutable")
	}

	if _, e = s.Verify(t.Context(), [][]byte{tc.cert}, o); e != nil {
		t.Fatal(e)
	}

	if *detached {
		wrong := []byte("other")

		o.DetachedContent = &wrong
		if r, e := s.Verify(t.Context(), [][]byte{tc.cert}, o); r != nil || !errors.Is(e, cms.ErrSignature) {
			t.Fatal(e)
		}
	} else {
		o.DetachedContent = &m
		if r, e := s.Verify(t.Context(), [][]byte{tc.cert}, o); r != nil || !errors.Is(e, cms.ErrPolicy) {
			t.Fatal(e)
		}
	}
}

func TestCMSMultiplePolicyAndMutation(t *testing.T) {
	c := testcert.New(t)
	signers := []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}, {Key: c.TSAKey, CertificateDER: c.TSA.Raw}}

	raw, e := cms.Sign(t.Context(), []byte("unique payload here"), signers, cms.SignOptions{})
	if e != nil {
		t.Fatal(e)
	}

	s, e := cms.Parse(t.Context(), raw, cms.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	if _, e = s.Verify(t.Context(), [][]byte{c.TSA.Raw, c.Leaf.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID()}); e != nil {
		t.Fatal(e)
	}

	for _, cs := range [][][]byte{{c.Leaf.Raw}, {c.Leaf.Raw, c.Leaf.Raw}, {c.Root.Raw, c.TSA.Raw}} {
		if r, e := s.Verify(t.Context(), cs, cms.VerifyOptions{ExpectedContentType: cms.DataOID()}); r != nil || e == nil {
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

	if r, e := s.Verify(t.Context(), [][]byte{c.Leaf.Raw, c.TSA.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID()}); r != nil || !errors.Is(e, cms.ErrSignature) {
		t.Fatal("content", e)
	}

	for _, oid := range []asn1.ObjectIdentifier{{1, 2, 840, 113549, 1, 9, 3}, {1, 2, 840, 113549, 1, 9, 4}, {1, 2, 840, 113549, 1, 9, 52}} {
		x := signers[0]

		x.Attributes = []cms.Attribute{{OID: oid, ValuesDER: [][]byte{{5, 0}}}}
		if _, e = cms.Sign(t.Context(), nil, []cms.Signer{x}, cms.SignOptions{}); !errors.Is(e, cms.ErrPolicy) {
			t.Fatal("reserved", e)
		}
	}

	x := signers[0]
	x.OmitCertificateBinding = true

	raw, e = cms.Sign(t.Context(), nil, []cms.Signer{x}, cms.SignOptions{})
	if e != nil {
		t.Fatal(e)
	}

	s, e = cms.Parse(t.Context(), raw, cms.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	if r, e := s.Verify(t.Context(), [][]byte{c.Leaf.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true}); r != nil || !errors.Is(e, cms.ErrCertificate) {
		t.Fatal("ESS required", e)
	}

	ctx, cancel := context.WithCancel(t.Context())
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

	seed, e := cms.Parse(f.Context(), raw, cms.DefaultLimits())
	if e != nil {
		f.Fatal(e)
	}

	result, e := seed.Verify(f.Context(), [][]byte{certificate}, options)
	if e != nil || result == nil || !bytes.Equal(result.Content(), fixture.Read(f, "cms-ecdsa-256-attached/content.bin")) {
		f.Fatalf("invalid positive CMS fixture: %v", e)
	}

	f.Add(raw)
	f.Add(cmsBEREnvelope(f, raw, indefiniteBER(0x24, der.Octets(fixture.Read(f, "cms-ecdsa-256-attached/content.bin")))))
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}

		for _, parse := range []func(context.Context, []byte, cms.Limits) (*cms.SignedData, error){cms.Parse, cms.ParseBER} {
			s, e := parse(t.Context(), b, cms.DefaultLimits())
			if e != nil {
				continue
			}

			result, e := s.Verify(t.Context(), [][]byte{certificate}, options)
			if e != nil && result != nil || e == nil && (result == nil || len(result.Signers()) != 1 || !result.Signers()[0].CertificateBound()) {
				t.Fatal("inconsistent CMS verification result")
			}
		}
	})
}

func BenchmarkCMS(b *testing.B) {
	c := testcert.New(b)

	raw, err := cms.Sign(b.Context(), make([]byte, 4096), []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}}, cms.SignOptions{})
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
			if _, err := s.Verify(b.Context(), [][]byte{c.Leaf.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestCMSRejectsEmptySignedData(t *testing.T) {
	for _, s := range []*cms.SignedData{nil, new(cms.SignedData)} {
		result, err := s.Verify(t.Context(), nil, cms.VerifyOptions{})
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

	raw, err := cms.Sign(t.Context(), []byte("protected algorithms"), []cms.Signer{{Key: key, CertificateDER: cert.Raw}}, cms.SignOptions{})
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

			result, err := s.Verify(t.Context(), [][]byte{cert.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID()})
			if tc.want == nil && (err != nil || result == nil) || tc.want != nil && (result != nil || !errors.Is(err, tc.want)) {
				t.Fatalf("result=%v error=%v want=%v", result != nil, err, tc.want)
			}
		})
	}
}

func TestCMSRejectsAttributesInWrongSection(t *testing.T) {
	c := testcert.New(t)

	raw, err := cms.Sign(t.Context(), []byte("payload"), []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}}, cms.SignOptions{})
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

	_, err = cms.Sign(t.Context(), nil, []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Attributes: []cms.Attribute{{OID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}, ValuesDER: [][]byte{der.Seq()}}}}}, cms.SignOptions{})
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

			raw, err := cms.Sign(t.Context(), nil, []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Hash: crypto.SHA256, Attributes: []cms.Attribute{a}}}, cms.SignOptions{})
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
	ci, f := cmsEnvelopeFields(t, raw)

	si, err := der.SetFields(f[len(f)-1], 0, asn1.TagSet, 1)
	if err != nil || len(si) != 1 {
		t.Fatal(err)
	}

	fields, err := der.Sequence(si[0], 5, 7)
	if err != nil {
		t.Fatal(err)
	}

	parts := signerBytes(f)
	parts[len(parts)-1] = der.Set(der.Seq(change(fields)...))

	return der.Seq(ci[0].FullBytes, der.Ctx(0, der.Seq(parts...)))
}

func cmsEnvelopeFields(t testing.TB, raw []byte) ([]asn1.RawValue, []asn1.RawValue) {
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

	return ci, f
}

func signerBytes(f []asn1.RawValue) [][]byte {
	b := make([][]byte, len(f))
	for i := range f {
		b[i] = f[i].FullBytes
	}

	return b
}

func TestCMSTrustBinding(t *testing.T) {
	chain := testcert.New(t)
	content := []byte("authenticated content and explicit trust")
	raw, err := cms.Sign(t.Context(), content, []cms.Signer{{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw}}, cms.SignOptions{ExtraCertificates: [][]byte{chain.Root.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cms.Parse(t.Context(), raw, cms.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	opt := cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true}
	plain, err := signed.Verify(t.Context(), [][]byte{chain.Leaf.Raw}, opt)
	if err != nil || plain.TrustChecked() || plain.Signers()[0].Trust() != nil {
		t.Fatal("cryptographic verification asserted trust", err)
	}
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	good := pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain)}}
	options := cms.TrustOptions{Verifier: verifier, VerificationTime: testcert.Now(), Evidence: good}
	trusted, err := signed.VerifyWithTrust(t.Context(), [][]byte{chain.Leaf.Raw}, opt, options)
	if err != nil || !trusted.TrustChecked() || trusted.Signers()[0].Trust().RevocationStatus() != pki.Valid || !bytes.Equal(trusted.Content(), content) {
		t.Fatal("complete CMS trust", err)
	}
	if trusted.Signers()[0].Trust().VerificationTime() != testcert.Now() {
		t.Fatal("signing time replaced explicit trust time")
	}
	for _, kind := range []string{"missing revocation", "revoked", "wrong root", "missing verifier", "missing time", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			policy := options
			ctx := t.Context()
			want := cms.ErrTrust
			switch kind {
			case "missing revocation":
				policy.Evidence = pki.Evidence{}
			case "revoked":
				policy.Evidence = pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain, chain.Leaf)}}
			case "wrong root":
				other := testcert.New(t)
				policy.Verifier, err = pki.NewVerifier(pki.Config{Roots: [][]byte{other.Root.Raw}})
				if err != nil {
					t.Fatal(err)
				}
			case "missing verifier":
				policy.Verifier = nil
				want = cms.ErrPolicy
			case "missing time":
				policy.VerificationTime = time.Time{}
				want = cms.ErrPolicy
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			}
			if got, err := signed.VerifyWithTrust(ctx, [][]byte{chain.Leaf.Raw}, opt, policy); got != nil || !errors.Is(err, want) {
				t.Fatal("partial CMS trust returned success", kind, err)
			}
		})
	}
	unchecked, err := pki.NewVerifier(pki.Config{Roots: [][]byte{chain.Root.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	options.Verifier = unchecked
	options.Evidence = pki.Evidence{}
	result, err := signed.VerifyWithTrust(t.Context(), [][]byte{chain.Leaf.Raw}, opt, options)
	if err != nil || !result.TrustChecked() || result.Signers()[0].Trust().RevocationStatus() != pki.NotChecked {
		t.Fatal("unchecked revocation reported valid", err)
	}
}

func TestCMSTrustAllSignersAndDetachedReader(t *testing.T) {
	chain := testcert.New(t)
	content := []byte("all signers and one-pass detached content")
	raw, err := cms.Sign(t.Context(), content, []cms.Signer{{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw}, {Key: chain.TSAKey, CertificateDER: chain.TSA.Raw}}, cms.SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cms.Parse(t.Context(), raw, cms.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	policy := cms.TrustOptions{Verifier: verifier, VerificationTime: testcert.Now(), Evidence: pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain)}}}
	opt := cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true}
	result, err := signed.VerifyReaderWithTrust(t.Context(), bytes.NewReader(content), [][]byte{chain.Leaf.Raw, chain.TSA.Raw}, opt, policy)
	if err != nil || !result.TrustChecked() || len(result.Signers()) != 2 || result.Content() != nil || result.ContentSize() != int64(len(content)) {
		t.Fatal("detached trusted verification", err)
	}
	policy.Evidence = pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain, chain.TSA)}}
	if got, err := signed.VerifyReaderWithTrust(t.Context(), bytes.NewReader(content), [][]byte{chain.Leaf.Raw, chain.TSA.Raw}, opt, policy); got != nil || !errors.Is(err, cms.ErrTrust) || !errors.Is(err, pki.ErrRevoked) {
		t.Fatal("one valid signer hid revoked signer", err)
	}
	bad := bytes.Clone(content)
	bad[0] ^= 1
	if got, err := signed.VerifyReaderWithTrust(t.Context(), bytes.NewReader(bad), [][]byte{chain.Leaf.Raw, chain.TSA.Raw}, opt, policy); got != nil || !errors.Is(err, cms.ErrSignature) {
		t.Fatal("trust hid content binding failure", err)
	}
}

func TestCMSTrustEvidenceBounds(t *testing.T) {
	chain := testcert.New(t)
	raw, err := cms.Sign(t.Context(), nil, []cms.Signer{{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw}}, cms.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cms.Parse(t.Context(), raw, cms.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	checker, err := pki.NewVerifier(pki.Config{Roots: [][]byte{chain.Root.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	for _, evidence := range []pki.Evidence{{Intermediates: make([][]byte, 65)}, {CRLs: make([][]byte, 257)}, {OCSPResponses: make([][]byte, 257)}, {Intermediates: [][]byte{make([]byte, (1<<20)+1)}}} {
		if got, err := signed.VerifyWithTrust(t.Context(), [][]byte{chain.Leaf.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID()}, cms.TrustOptions{Verifier: checker, VerificationTime: testcert.Now(), Evidence: evidence}); got != nil || !errors.Is(err, cms.ErrPolicy) {
			t.Fatal("unbounded CMS trust evidence accepted", err)
		}
	}
}

func TestCMSTrustEvidenceBindings(t *testing.T) {
	chain := testcert.New(t)
	raw, err := cms.Sign(t.Context(), []byte("shared issuer evidence"), []cms.Signer{{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw}, {Key: chain.TSAKey, CertificateDER: chain.TSA.Raw}}, cms.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cms.Parse(t.Context(), raw, cms.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	expected := [][]byte{chain.Leaf.Raw, chain.TSA.Raw}
	cryptoOnly, err := signed.Verify(t.Context(), expected, cms.VerifyOptions{ExpectedContentType: cms.DataOID()})
	if err != nil || cryptoOnly.Evidence() != nil {
		t.Fatal("crypto-only result minted trust evidence", err)
	}
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	crl := testcert.CRL(t, chain)
	result, err := signed.VerifyWithTrust(t.Context(), expected, cms.VerifyOptions{ExpectedContentType: cms.DataOID()}, cms.TrustOptions{Verifier: verifier, VerificationTime: testcert.Now(), Evidence: pki.Evidence{CRLs: [][]byte{crl}}})
	if err != nil {
		t.Fatal(err)
	}
	assertions := result.Evidence()
	if len(assertions) != 2 {
		t.Fatal("shared CRL lost distinct signer certificate bindings", len(assertions))
	}
	fingerprint := sha256.Sum256(crl)
	targets := map[string]struct{}{}
	for _, certificate := range expected {
		sum := sha256.Sum256(certificate)
		targets[hex.EncodeToString(sum[:])] = struct{}{}
	}
	for _, assertion := range assertions {
		if _, exists := targets[assertion.TargetCertificateSHA256()]; assertion.AuthenticationStatus() != pki.Valid || assertion.FingerprintSHA256() != hex.EncodeToString(fingerprint[:]) || !exists || assertion.IssuerScopeBinding() == "" || assertion.ValidationTime() != testcert.Now() {
			t.Fatal("wrong authenticated CMS evidence binding")
		}
		delete(targets, assertion.TargetCertificateSHA256())
		owned := assertion.DER()
		owned[0] ^= 1
		if !bytes.Equal(assertion.DER(), crl) {
			t.Fatal("mutable evidence DER accessor")
		}
	}
	assertions[0] = nil
	if len(targets) != 0 || result.Evidence()[0] == nil {
		t.Fatal("mutable/dropped CMS evidence binding")
	}
	var absent *cms.Result
	if absent.Evidence() != nil || absent.TrustChecked() {
		t.Fatal("nil result claimed trust")
	}
}

func TestCMSSemanticIssuerBindings(t *testing.T) {
	chain := testcert.New(t)
	alternative, _ := asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("  ITERATION  6 TEST ROOT  ")}}}})
	raw, err := cms.Sign(t.Context(), []byte("semantic issuer binding"), []cms.Signer{{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw}}, cms.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"sid", "ess", "wrong-name", "wrong-serial", "wrong-hash", "explicit default hash", "wrong-extra-issuer-uri", "wrong-extra-issuer-dn"} {
		t.Run(kind, func(t *testing.T) {
			changed := rewriteSigner(t, raw, func(fields []asn1.RawValue) [][]byte {
				parts := signerBytes(fields)
				serial, _ := asn1.Marshal(chain.Leaf.SerialNumber)
				name := alternative
				if kind == "wrong-name" {
					name, _ = asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "unrelated"}}})
				}
				if kind == "sid" || kind == "wrong-name" {
					parts[1] = der.Seq(name, serial)
					return parts
				}
				if kind == "wrong-serial" {
					serial = der.Int(38)
				}
				sum := sha256.Sum256(chain.Leaf.Raw)
				if kind == "wrong-hash" {
					sum[0] ^= 1
				}
				idParts := [][]byte{der.Octets(sum[:]), der.Seq(der.Seq(der.Ctx(4, name)), serial)}
				if strings.HasPrefix(kind, "wrong-extra-issuer") {
					extra := der.Wrap(2, 6, false, []byte("https://unrelated.test/"))
					if kind == "wrong-extra-issuer-dn" {
						extra = der.Ctx(4, chain.Leaf.RawSubject)
					}
					idParts[1] = der.Seq(der.Seq(der.Ctx(4, name), extra), serial)
				}

				if kind == "explicit default hash" {
					idParts = append([][]byte{der.Seq(der.OID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}))}, idParts...)
				}
				attribute := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}), der.Set(der.Seq(der.Seq(der.Seq(idParts...)))))
				values, err := der.Children(fields[3])
				if err != nil {
					t.Fatal(err)
				}
				attrs := make([][]byte, 0, len(values))
				for _, value := range values {
					f, _ := der.Sequence(value, 2, 2)
					var oid asn1.ObjectIdentifier
					if der.Decode(f[0], &oid) != nil {
						t.Fatal("attribute OID")
					}
					if oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}) {
						attrs = append(attrs, attribute)
					} else {
						attrs = append(attrs, value.FullBytes)
					}
				}
				set := der.Set(attrs...)
				parsed, err := der.Read(set, len(set))
				if err != nil {
					t.Fatal(err)
				}
				parts[3] = der.Wrap(2, 0, true, parsed.Bytes)
				alg, err := signature.Algorithm(fields[4])
				if err != nil {
					t.Fatal(err)
				}
				sig, err := signature.Sign(t.Context(), chain.LeafKey, alg, set)
				if err != nil {
					t.Fatal(err)
				}
				parts[5] = der.Octets(sig)
				return parts
			})
			parsed, err := cms.Parse(t.Context(), changed, cms.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			result, err := parsed.Verify(t.Context(), [][]byte{chain.Leaf.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true})
			if kind == "explicit default hash" {
				if result != nil || !errors.Is(err, cms.ErrSyntax) {
					t.Fatal("explicit SHA256 DEFAULT accepted", err)
				}
			} else if strings.HasPrefix(kind, "wrong") {
				if result != nil || !errors.Is(err, cms.ErrCertificate) {
					t.Fatal("incorrect issuer/hash/serial binding accepted", err)
				}
			} else if result == nil || err != nil || !parsed.MatchesSigner(0, chain.Leaf.Raw) {
				t.Fatal("equivalent issuer rejected", err)
			}
		})
	}
}

func TestCMSTrustRejectsUnevaluatedESSPathRestrictions(t *testing.T) {
	chain := testcert.New(t)
	raw, err := cms.Sign(t.Context(), []byte("restricted path"), []cms.Signer{{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw}}, cms.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	changed := rewriteSigner(t, raw, func(fields []asn1.RawValue) [][]byte {
		return addESSPathRestriction(t, fields, chain.Root.Raw, chain.LeafKey)
	})
	parsed, err := cms.Parse(t.Context(), changed, cms.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	options := cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true}
	cryptoOnly, err := parsed.Verify(t.Context(), [][]byte{chain.Leaf.Raw}, options)
	if err != nil || cryptoOnly == nil || !cryptoOnly.Signers()[0].CertificateBound() || cryptoOnly.TrustChecked() {
		t.Fatal("first signer binding damaged", err)
	}
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	if trusted, err := parsed.VerifyWithTrust(t.Context(), [][]byte{chain.Leaf.Raw}, options, cms.TrustOptions{Verifier: verifier, VerificationTime: testcert.Now(), Evidence: pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain)}}}); trusted != nil || !errors.Is(err, cms.ErrUnsupported) {
		t.Fatal("unevaluated signed path restriction became trusted", err)
	}
}

func addESSPathRestriction(t *testing.T, fields []asn1.RawValue, extra []byte, key crypto.Signer) [][]byte {
	t.Helper()
	binding, err := cms.CertificateBindingAttribute(extra)
	if err != nil {
		t.Fatal(err)
	}
	extraValue, _ := der.Read(binding.ValuesDER[0], 1<<20)
	extraTop, _ := der.Sequence(extraValue, 1, 2)
	extraIDs, _ := der.Sequence(extraTop[0], 1, 32)
	values, err := der.Children(fields[3])
	if err != nil {
		t.Fatal(err)
	}
	attrs := make([][]byte, 0, len(values))
	for _, value := range values {
		attr, _ := der.Sequence(value, 2, 2)
		var oid asn1.ObjectIdentifier
		if der.Decode(attr[0], &oid) != nil {
			t.Fatal("attribute OID")
		}
		if oid.Equal(binding.OID) {
			singleton, _ := der.SetFields(attr[1], 0, asn1.TagSet, 1)
			top, _ := der.Sequence(singleton[0], 1, 2)
			ids, _ := der.Sequence(top[0], 1, 32)
			idParts := signerBytes(ids)
			idParts = append(idParts, extraIDs[0].FullBytes)
			topParts := signerBytes(top)
			topParts[0] = der.Seq(idParts...)
			attrs = append(attrs, der.Seq(attr[0].FullBytes, der.Set(der.Seq(topParts...))))
		} else {
			attrs = append(attrs, value.FullBytes)
		}
	}
	set := der.Set(attrs...)
	value, _ := der.Read(set, len(set))
	parts := signerBytes(fields)
	parts[3] = der.Wrap(2, 0, true, value.Bytes)
	algorithm, err := signature.Algorithm(fields[4])
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signature.Sign(t.Context(), key, algorithm, set)
	if err != nil {
		t.Fatal(err)
	}
	parts[5] = der.Octets(signed)
	return parts
}

func TestCMSSchemaCertificateDefaults(t *testing.T) {
	c := testcert.New(t)
	original, err := cms.Sign(t.Context(), []byte("certificate schema defaults"), []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}}, cms.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"explicit v1", "critical false"} {
		t.Run(name, func(t *testing.T) {
			raw := cmsCertificateDefaultVariant(t, c.Leaf.Raw, c.RootKey, name == "explicit v1")
			if output, err := cms.Sign(t.Context(), nil, []cms.Signer{{Key: c.LeafKey, CertificateDER: raw}}, cms.SignOptions{}); output != nil || !errors.Is(err, cms.ErrCertificate) {
				t.Fatal("schema-invalid signer certificate accepted", err)
			}
			if _, err := cms.CertificateBindingAttribute(raw); !errors.Is(err, cms.ErrCertificate) {
				t.Fatal("schema-invalid certificate binding accepted", err)
			}
			ci, fields := cmsEnvelopeFields(t, original)
			parts := signerBytes(fields)
			replaced := false
			for i, field := range fields {
				if der.Is(field, 2, 0, true) {
					parts[i] = der.Ctx(0, raw)
					replaced = true
				}
			}
			if !replaced {
				t.Fatal("missing certificate bag")
			}
			if parsed, err := cms.Parse(t.Context(), der.Seq(ci[0].FullBytes, der.Ctx(0, der.Seq(parts...))), cms.Limits{}); parsed != nil || !errors.Is(err, cms.ErrSyntax) {
				t.Fatal("schema-invalid embedded certificate accepted", err)
			}
		})
	}
}

func cmsCertificateDefaultVariant(t *testing.T, raw []byte, key crypto.Signer, v1 bool) []byte {
	t.Helper()
	value, _ := der.Read(raw, len(raw))
	outer, _ := der.Sequence(value, 3, 3)
	fields, _ := der.Sequence(outer[0], 7, 10)
	parts := signerBytes(fields)
	if v1 {
		parts = append([][]byte{der.Ctx(0, der.Int(0))}, parts[1:len(parts)-1]...)
	} else {
		extensions, _ := der.Explicit(fields[len(fields)-1], 3)
		values, _ := der.Sequence(extensions, 1, 32)
		encoded := signerBytes(values)
		changed := false
		for i, extension := range values {
			f, _ := der.Sequence(extension, 2, 3)
			if len(f) == 2 && !changed {
				encoded[i] = der.Seq(f[0].FullBytes, []byte{1, 1, 0}, f[1].FullBytes)
				changed = true
			}
		}
		if !changed {
			t.Fatal("no omitted DEFAULT FALSE")
		}
		parts[len(parts)-1] = der.Ctx(3, der.Seq(encoded...))
	}
	tbs := der.Seq(parts...)
	algorithm, _ := signature.Algorithm(outer[1])
	signed, err := signature.Sign(t.Context(), key, algorithm, tbs)
	if err != nil {
		t.Fatal(err)
	}
	bits, _ := asn1.Marshal(asn1.BitString{Bytes: signed, BitLength: len(signed) * 8})
	return der.Seq(tbs, outer[1].FullBytes, bits)
}

// BenchmarkCMSBER measures normalization separately from signature verification.
func BenchmarkCMSBER(b *testing.B) { benchmarkCMSBER(b, false) }

func BenchmarkCMSBERReader(b *testing.B) { benchmarkCMSBER(b, true) }

func benchmarkCMSBER(b *testing.B, reader bool) {
	c := testcert.New(b)
	for _, size := range []int{16 << 10, 1 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			content := bytes.Repeat([]byte("a"), size)
			raw, err := cms.Sign(b.Context(), content, []cms.Signer{{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}}, cms.SignOptions{})
			if err != nil {
				b.Fatal(err)
			}
			encoded := cmsBEREnvelope(b, raw, indefiniteBER(0x24, der.Octets(content[:size/2]), der.Octets(content[size/2:])))
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				var parsed *cms.SignedData
				var err error
				if reader {
					parsed, err = cms.ParseBERReader(b.Context(), bytes.NewReader(encoded), cms.Limits{})
				} else {
					parsed, err = cms.ParseBER(b.Context(), encoded, cms.Limits{})
				}
				if err != nil || parsed.Size() != len(raw) {
					b.Fatal(err)
				}
			}
		})
	}
}
