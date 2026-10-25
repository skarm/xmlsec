package xades_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestWithTimeExpiredSignerAndCurrentProfile(t *testing.T) {
	c := expiredChain(t)
	proof := testcert.Now().Add(-2 * time.Hour)
	d := timedPastDocument(t, c, proof, nil)
	v := timeValidator(t, c)
	evidence := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{datedCRL(t, c, proof, 1)}}, TSA: timeOptions(t, c).Evidence}

	r, report, e := v.ValidateEnveloped(context.Background(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), evidence)
	if e != nil || r == nil || report.Indication() != xades.Passed || !r.ProofTime().Equal(proof) || !r.SignerTrust().VerificationTime().Equal(proof) || !r.Basic().Signature().CoversElement(d.Root()) {
		t.Fatal(report, e)
	}

	if !r.VerificationTime().Equal(testcert.Now()) || r.Profile() != "xmlsec-enveloped-with-time-v1" {
		t.Fatal("profile/time")
	}

	r.Timestamps()[0] = nil
	if r.Timestamps()[0] == nil {
		t.Fatal("mutable tokens")
	}

	current, e := xades.NewValidator(xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, TSA: timeOptions(t, c).TSA, MinimumLevel: xades.LevelBT})
	if e != nil {
		t.Fatal(e)
	}

	if r, e := current.ValidateEnveloped(context.Background(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), evidence); r != nil || !errors.Is(e, pki.ErrCertificate) {
		t.Fatal("current validator implicitly backdated", e)
	}

	var zero xades.WithTimeReport
	if zero.Indication() != xades.Indeterminate || zero.ProofTime() != (time.Time{}) {
		t.Fatal("zero reads valid")
	}
	// One immutable validator supports independent concurrent proofs/evidence.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			r, report, e := v.ValidateEnveloped(context.Background(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), evidence)
			if e != nil || r == nil || report.Indication() != xades.Passed {
				t.Error(e)
			}
		})
	}

	wg.Wait()
}

func TestWithTimeNoUntrustedRecovery(t *testing.T) {
	c := expiredChain(t)
	proof := testcert.Now().Add(-2 * time.Hour)
	d := timedPastDocument(t, c, proof, nil)
	v := timeValidator(t, c)
	good := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{datedCRL(t, c, proof, 1)}}, TSA: timeOptions(t, c).Evidence}
	assertReject := func(name string, doc *document.Document, evidence xades.ValidationEvidence, want error, status xades.Indication) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			r, report, e := v.ValidateEnveloped(context.Background(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now(), evidence)
			if r != nil || e == nil || report.Indication() != status || want != nil && !errors.Is(e, want) {
				t.Fatal(r, report.Indication(), e)
			}
		})
	}
	assertReject("claimed SigningTime alone", basicDocument(t, c), good, xades.ErrTimestamp, xades.Indeterminate)
	missing := good
	missing.Signer = pki.Evidence{}
	assertReject("no fresh historical evidence", d, missing, pki.ErrUnavailable, xades.Indeterminate)
	missing = good
	missing.TSA = pki.Evidence{}
	assertReject("no current TSA evidence", d, missing, nil, xades.Indeterminate)

	revoked := good
	revoked.Signer.CRLs = [][]byte{datedCRL(t, c, proof, 1, x509.RevocationListEntry{SerialNumber: c.Leaf.SerialNumber, RevocationTime: proof.Add(-time.Hour), ReasonCode: 1})}
	assertReject("revoked at proof", d, revoked, pki.ErrRevoked, xades.Failed)
	revoked = good
	revoked.Signer.CRLs = append(append([][]byte(nil), good.Signer.CRLs...), datedCRL(t, c, testcert.Now(), 2, x509.RevocationListEntry{SerialNumber: c.Leaf.SerialNumber, RevocationTime: proof.Add(time.Minute), ReasonCode: 1}))
	assertReject("no later compromise recovery", d, revoked, xades.ErrLevel, xades.Indeterminate)
	for _, version1 := range []bool{false, true} {
		future := revoked.Signer.CRLs[1]
		if version1 {
			future = testcert.CRLV1(t, c, c.Leaf)
		}

		for _, folded := range []bool{false, true} {
			issuer := c.Root.Subject.CommonName
			if folded {
				issuer = strings.ToUpper(issuer)
			}

			changed := withTimeCRLIssuerEncoding(t, future, c, issuer, false)
			additional := good
			additional.Signer.CRLs = append(append([][]byte(nil), good.Signer.CRLs...), changed)
			name := "no later compromise recovery/" + map[bool]string{false: "v2", true: "v1"}[version1] + "/" + map[bool]string{false: "original issuer", true: "same issuer different case"}[folded]
			assertReject(name, d, additional, xades.ErrLevel, xades.Indeterminate)
		}
	}
	raw, _ := d.XML(t.Context())

	bad, e := document.Parse(t.Context(), bytes.Replace(raw, []byte(">123<"), []byte(">999<"), 1), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	if bytes.Equal(raw, mustXML(t, bad)) {
		t.Fatal("test mutation not applied")
	}

	assertReject("bad signed data", bad, good, xmldsig.ErrDigest, xades.Failed)
	// Corrupt a token rather than the signed XML: unsigned evidence cannot pass.
	text := string(raw)
	marker := "<xades:EncapsulatedTimeStamp"

	start := strings.Index(text, marker)
	if start < 0 {
		t.Fatal("timestamp marker")
	}

	start += strings.Index(text[start:], ">") + 1
	end := start + strings.Index(text[start:], "</")

	token, e := base64.StdEncoding.DecodeString(text[start:end])
	if e != nil {
		t.Fatal(e)
	}

	token[len(token)-1] ^= 1

	bad, e = document.Parse(t.Context(), []byte(text[:start]+base64.StdEncoding.EncodeToString(token)+text[end:]), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	assertReject("bad unsigned timestamp", bad, good, nil, xades.Indeterminate)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if r, report, e := v.ValidateEnveloped(ctx, d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), good); r != nil || !errors.Is(e, context.Canceled) || report.Indication() == xades.Passed {
		t.Fatal(e)
	}
}

func mustXML(t testing.TB, d *document.Document) []byte {
	t.Helper()

	raw, e := d.XML(t.Context())
	if e != nil {
		t.Fatal(e)
	}

	return raw
}

func TestWithTimeAccuracyAndEarliestProof(t *testing.T) {
	c := expiredChain(t)
	gen := c.Leaf.NotAfter.Add(-time.Second)
	accuracy := 2 * time.Second
	d := timedPastDocument(t, c, gen, &accuracy)
	evidence := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{datedCRL(t, c, gen, 1)}}, TSA: timeOptions(t, c).Evidence}

	v := timeValidator(t, c)
	if r, report, e := v.ValidateEnveloped(context.Background(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), evidence); r != nil || !errors.Is(e, xades.ErrLevel) || report.Indication() != xades.Indeterminate || !report.ProofTime().Equal(gen.Add(accuracy)) {
		t.Fatal("accuracy ignored", e)
	}

	early := testcert.Now().Add(-2 * time.Hour)
	d = timedPastDocument(t, c, early.Add(time.Minute), nil)

	d, _, e := xades.AddSignatureTimestamp(context.Background(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, datedTSA{chain: c, gen: early}, xades.AddTimestampOptions{Validation: timeOptions(t, c), Request: timestamp.RequestOptions{Policy: tsaPolicy()}})
	if e != nil {
		t.Fatal(e)
	}

	evidence.Signer.CRLs = [][]byte{datedCRL(t, c, early, 1)}

	r, report, e := v.ValidateEnveloped(context.Background(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), evidence)
	if e != nil || r == nil || !report.ProofTime().Equal(early) || len(r.Timestamps()) != 2 {
		t.Fatal("earliest POE changed", e)
	}

	if _, e := xades.NewWithTimeValidator(xades.WithTimeConfig{}); e == nil {
		t.Fatal("unchecked configuration")
	}
}

type datedTSA struct {
	chain    testcert.Chain
	gen      time.Time
	accuracy *time.Duration
}

func (s datedTSA) RoundTrip(ctx context.Context, raw []byte) (io.ReadCloser, error) {
	b, e := timestamp.IssueResponse(ctx, raw, s.chain.TSAKey, s.chain.TSA.Raw, timestamp.IssueOptions{Policy: tsaPolicy(), SerialNumber: big.NewInt(101), GenTime: s.gen, Accuracy: s.accuracy, ExtraCertificates: [][]byte{s.chain.Root.Raw}})
	return io.NopCloser(bytes.NewReader(b)), e
}

func datedCRL(t testing.TB, c testcert.Chain, at time.Time, number int64, entries ...x509.RevocationListEntry) []byte {
	t.Helper()

	b, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Hour), RevokedCertificateEntries: entries}, c.Root, c.RootKey)
	if e != nil {
		t.Fatal(e)
	}

	return b
}

func timeValidator(t testing.TB, c testcert.Chain) *xades.WithTimeValidator {
	t.Helper()
	o := timeOptions(t, c)

	v, e := xades.NewWithTimeValidator(xades.WithTimeConfig{SignerPKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, TSA: o.TSA})
	if e != nil {
		t.Fatal(e)
	}

	return v
}

func timedPastDocument(t *testing.T, c testcert.Chain, gen time.Time, accuracy *time.Duration) *document.Document {
	t.Helper()
	base := basicDocument(t, c)

	d, _, e := xades.AddSignatureTimestamp(context.Background(), base, xmldsig.Signatures(base)[0], c.Leaf.Raw, datedTSA{c, gen, accuracy}, xades.AddTimestampOptions{Validation: timeOptions(t, c), Request: timestamp.RequestOptions{Policy: tsaPolicy()}})
	if e != nil {
		t.Fatal(e)
	}

	return d
}

func expiredChain(t testing.TB) testcert.Chain {
	t.Helper()
	c := testcert.New(t)
	leaf := *c.Leaf
	leaf.NotAfter = testcert.Now().Add(-time.Hour)
	c.Leaf = testcert.Issue(t, &leaf, c.Root, &c.LeafKey.PublicKey, c.RootKey)

	return c
}

func TestWithTimeRelativeDistributionPointCertificate(t *testing.T) {
	chain := testcert.New(t)
	var relative []byte
	for _, test := range testcert.CertificateEncodings(t, chain) {
		if test.Name == "relative distribution point" {
			relative = test.DER
			break
		}
	}
	if len(relative) == 0 {
		t.Fatal("relative certificate fixture missing")
	}
	leaf := *chain.Leaf
	leaf.Raw = relative
	chain.Leaf = &leaf
	proof := testcert.Now().Add(-time.Hour)
	doc := timedPastDocument(t, chain, proof, nil)
	validator := timeValidator(t, chain)
	evidence := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{datedCRL(t, chain, proof, 1)}}, TSA: timeOptions(t, chain).Evidence}
	result, report, err := validator.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], relative, testcert.Now(), evidence)
	if err != nil || result == nil || report.Indication() != xades.Passed || !bytes.Equal(result.Basic().CertificateDER(), relative) {
		t.Fatal("with-time private certificate reparsing lost valid original DER", report, err)
	}
}

func withTimeCRLIssuerEncoding(t *testing.T, raw []byte, c testcert.Chain, commonName string, version1 bool) []byte {
	t.Helper()
	value, err := der.Read(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}
	outer, err := der.Sequence(value, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	body, err := der.Sequence(outer[0], 3, 7)
	if err != nil {
		t.Fatal(err)
	}
	issuerIndex := 1
	if body[0].Tag == asn1.TagInteger {
		issuerIndex++
	}
	name, err := asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: commonName}}})
	if err != nil {
		t.Fatal(err)
	}
	parts := make([][]byte, 0, len(body))
	for i, field := range body {
		if version1 && (i == 0 && issuerIndex == 2 || field.Class == 2 && field.Tag == 0) {
			continue
		}
		if i == issuerIndex {
			parts = append(parts, name)
		} else {
			parts = append(parts, field.FullBytes)
		}
	}
	tbs := der.Seq(parts...)
	algorithm, err := signature.Algorithm(outer[1])
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signature.Sign(t.Context(), c.RootKey, algorithm, tbs)
	if err != nil {
		t.Fatal(err)
	}
	bits, err := asn1.Marshal(asn1.BitString{Bytes: signed, BitLength: len(signed) * 8})
	if err != nil {
		t.Fatal(err)
	}
	return der.Seq(tbs, outer[1].FullBytes, bits)
}

func TestWithTimeV1CRLEvidence(t *testing.T) {
	c := expiredChain(t)
	proof := testcert.Now().Add(-2 * time.Hour)
	doc := timedPastDocument(t, c, proof, nil)
	validator := timeValidator(t, c)
	raw := withTimeCRLIssuerEncoding(t, datedCRL(t, c, proof, 1), c, strings.ToUpper(c.Root.Subject.CommonName), true)
	evidence := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{raw}}, TSA: timeOptions(t, c).Evidence}
	result, report, err := validator.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now(), evidence)
	if err != nil || result == nil || report.Indication() != xades.Passed {
		t.Fatal("already validated v1 CRL rejected during with-time reparse", report, err)
	}
}

func TestWithTimeAdvancedCRLInputScope(t *testing.T) {
	for _, kind := range []string{"delta", "indirect", "scoped"} {
		t.Run(kind, func(t *testing.T) {
			c := testcert.New(t)
			proof := testcert.Now().Add(-time.Hour)
			signer := *c.Root
			signerKey := c.RootKey
			var scope []byte
			pointName := func() []byte {
				return der.Ctx(0, der.Wrap(2, 0, true, der.Wrap(2, 6, false, []byte("urn:delegated-crl"))))
			}
			evidence := xades.ValidationEvidence{TSA: timeOptions(t, c).Evidence}
			if kind == "indirect" {
				template := &x509.Certificate{SerialNumber: big.NewInt(50), Subject: pkix.Name{CommonName: "delegated CRL signer"}, NotBefore: testcert.Now().Add(-24 * time.Hour), NotAfter: testcert.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCRLSign, SubjectKeyId: []byte{50, 51, 52}, BasicConstraintsValid: true}
				raw, e := x509.CreateCertificate(rand.Reader, template, c.Root, c.ResponderKey.Public(), c.RootKey)
				if e != nil {
					t.Fatal(e)
				}
				parsed, e := x509.ParseCertificate(raw)
				if e != nil {
					t.Fatal(e)
				}
				signer = *parsed
				signerKey = c.ResponderKey
				evidence.Signer.Intermediates = [][]byte{raw}
				leaf := *c.Leaf
				leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: der.Seq(der.Seq(pointName(), der.Wrap(2, 2, true, der.Ctx(4, signer.RawSubject))))}}
				raw, e = x509.CreateCertificate(rand.Reader, &leaf, c.Root, c.LeafKey.Public(), c.RootKey)
				if e != nil {
					t.Fatal(e)
				}
				c.Leaf, e = x509.ParseCertificate(raw)
				if e != nil {
					t.Fatal(e)
				}
				scope = der.Seq(pointName(), der.Wrap(2, 4, false, []byte{255}))
			}
			if kind == "scoped" {
				scope = der.Seq(der.Wrap(2, 1, false, []byte{255}))
			}
			makeList := func(number int64, at time.Time, revoke bool) []byte {
				template := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: at.Add(-time.Minute), NextUpdate: testcert.Now().Add(time.Hour)}
				if scope != nil {
					template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: scope})
				}
				if kind == "delta" && number == 2 {
					template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: der.Int(1)})
				}
				if revoke {
					entry := x509.RevocationListEntry{SerialNumber: c.Leaf.SerialNumber, RevocationTime: proof.Add(time.Minute), ReasonCode: 1}
					if kind == "indirect" {
						entry.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 29}, Critical: true, Value: der.Seq(der.Ctx(4, c.Root.RawSubject))}}
					}
					template.RevokedCertificateEntries = []x509.RevocationListEntry{entry}
				}
				raw, e := x509.CreateRevocationList(rand.Reader, template, &signer, signerKey)
				if e != nil {
					t.Fatal(e)
				}
				return raw
			}
			evidence.Signer.CRLs = [][]byte{makeList(1, proof, false), makeList(2, testcert.Now(), true)}
			policy := pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}
			current, e := pki.NewVerifier(policy)
			if e != nil {
				t.Fatal(e)
			}
			r, _, e := current.Verify(t.Context(), c.Leaf.Raw, testcert.Now(), evidence.Signer)
			if r != nil || !errors.Is(e, pki.ErrRevoked) {
				t.Fatal("current-time PKI lost authenticated future revocation", r, e)
			}
			r, _, e = current.Verify(t.Context(), c.Leaf.Raw, proof, evidence.Signer)
			if r == nil || e != nil {
				t.Fatal("proof-time fixture did not establish its old good status", r, e)
			}
			doc := timedPastDocument(t, c, proof, nil)
			v := timeValidator(t, c)
			result, report, e := v.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now(), evidence)
			if result != nil || !errors.Is(e, xades.ErrProfile) || report.Indication() != xades.Indeterminate {
				t.Fatal("broader current PKI input silently enabled historical recovery", result, report, e)
			}
			// Removing only the advanced future list leaves the direct base supported.
			// Scoped/indirect historical bases remain explicitly outside this B-T profile.
			evidence.Signer.CRLs = evidence.Signer.CRLs[:1]
			result, report, e = v.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now(), evidence)
			if kind == "delta" {
				if result == nil || e != nil || report.Indication() != xades.Passed {
					t.Fatal("ordinary direct complete proof input changed", result, report, e)
				}
			} else if result != nil || !errors.Is(e, xades.ErrProfile) {
				t.Fatal("historical scoped/indirect input escaped the closed profile", result, e)
			}
		})
	}
}

func TestWithTimeDirectCRLFreshestAdvertisementPolicy(t *testing.T) {
	c := testcert.New(t)
	proof := testcert.Now().Add(-time.Hour)
	point := der.Seq(der.Ctx(0, der.Wrap(2, 0, true, der.Wrap(2, 6, false, []byte("urn:delta-advertisement")))))
	template := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: proof.Add(-time.Minute), NextUpdate: testcert.Now().Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 46}, Value: der.Seq(point)}}}
	raw, err := x509.CreateRevocationList(rand.Reader, template, c.Root, c.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	doc := timedPastDocument(t, c, proof, nil)
	evidence := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{raw}}, TSA: timeOptions(t, c).Evidence}
	for _, disable := range []bool{false, true} {
		validator, err := xades.NewWithTimeValidator(xades.WithTimeConfig{SignerPKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL, CRL: pki.CRLOptions{DisableDeltaCRLs: disable}}, TSA: timeOptions(t, c).TSA})
		if err != nil {
			t.Fatal(err)
		}
		result, report, err := validator.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now(), evidence)
		if disable {
			if err != nil || result == nil || report.Indication() != xades.Passed {
				t.Fatal("unused advertisement changed the direct complete input scope", report, err)
			}
		} else if result != nil || !errors.Is(err, pki.ErrUnavailable) {
			t.Fatal("wrapper ignored PKI use-deltas policy", result, err)
		}
	}
}
