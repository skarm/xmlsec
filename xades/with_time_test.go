package xades_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
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
