package historical

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
)

func TestPastEvaluationRequiresIssuerAndIndependentMaterialProofs(t *testing.T) { //nolint:tparallel // Subtests share one operation-scoped PKI session and its resource accounting.
	t.Parallel()

	chain := testcert.New(t)
	crl := testcert.CRL(t, chain)
	now := testcert.Now()
	cutoff := now.Add(-30 * time.Second)
	proofAt := cutoff.Add(-time.Second)
	options := pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: cutoff}}}
	session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, HistoricalOptions: options}, now, pki.Evidence{CRLs: [][]byte{crl}})
	if err != nil {
		t.Fatal(err)
	}
	signature := sha256.Sum256([]byte("authenticated signature encoding"))
	reference := sha256.Sum256([]byte("separately hashed signed reference"))
	source := sha256.Sum256([]byte("independent authenticated archive timestamp"))
	for _, test := range []struct {
		name         string
		issuer       bool
		referenceAt  time.Time
		current, sub string
	}{
		{"no-chain recovery", true, proofAt, noChain, ""},
		{"crypto recovery", true, proofAt, cryptoFailure, ""},
		{"freshness recovery", true, proofAt, tryLater, ""},
		{"issuer proof is independent", false, proofAt, noChain, revocationBounds},
		{"reference hash cutoff equality", true, cutoff, noChain, cryptoFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := []historicalproof.Fact{
				{Digest: signature, Source: source, At: proofAt, Kind: historicalproof.Signature},
				{Digest: reference, Source: source, At: test.referenceAt, Kind: historicalproof.Data},
				{Digest: sha256.Sum256(chain.Leaf.Raw), Source: source, At: proofAt, Kind: historicalproof.Certificate},
				{Digest: sha256.Sum256(crl), Source: source, At: proofAt, Kind: historicalproof.CRL},
			}
			if test.issuer {
				facts = append(facts, historicalproof.Fact{Digest: sha256.Sum256(chain.Root.Raw), Source: source, At: proofAt, Kind: historicalproof.Certificate})
			}
			proofs := newProofSet(t, facts...)
			material := signedMaterial{digest: signature, certificate: chain.Leaf.Raw, algorithm: x509.ECDSAWithSHA256, uses: []MaterialUse{{Object: reference, Hash: crypto.SHA256}}}
			out := pastSignature(t.Context(), session, material, test.current, proofs, options)
			if test.sub != "" {
				if out.indication == Passed || out.result != nil || out.sub != test.sub || !errors.Is(out.err, ErrValidation) {
					t.Fatal("missing independent proof accepted", out)
				}
				return
			}
			if out.indication != Passed || out.err != nil || out.sub != "" || out.result == nil || out.result.ValidationTime() != cutoff || out.best != proofAt {
				t.Fatal("past recovery failed", out)
			}
			if len(out.steps) != 2 || out.steps[0].Object != sha256.Sum256(chain.Leaf.Raw) || out.steps[0].Before != now || out.steps[0].After != cutoff || out.steps[1].Action != "past-signature-validation" || out.steps[1].Object != signature {
				t.Fatal("past transition trace lost exact object or bound", out.steps)
			}
		})
	}
}

func TestAuthenticatedRevocationClaimsControlFreshnessAndSuspension(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	now := testcert.Now()
	for _, suspendedLeaf := range []bool{false, true} {
		list := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
		if suspendedLeaf {
			list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: chain.Leaf.SerialNumber, RevocationTime: now.Add(-time.Hour), ReasonCode: 6}}
		}
		raw, err := x509.CreateRevocationList(rand.Reader, list, chain.Root, chain.RootKey)
		if err != nil {
			t.Fatal(err)
		}
		session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}}, now, pki.Evidence{CRLs: [][]byte{raw}})
		if err != nil {
			t.Fatal(err)
		}
		paths, err := session.Paths(t.Context(), chain.Leaf.Raw)
		if err != nil || len(paths) != 1 {
			t.Fatal("real certificate path unavailable", paths, err)
		}
		claims, err := session.AuthenticateEvidence(t.Context(), paths[0])
		if err != nil || len(claims) != 1 || claims[0].AuthenticationStatus() != pki.Valid {
			t.Fatal("signed CRL was not authenticated", claims, err)
		}
		if suspended(chain.Leaf.Raw, claims) != suspendedLeaf || suspended(chain.TSA.Raw, claims) {
			t.Fatal("suspension status borrowed across target certificates")
		}
		for _, test := range []struct {
			maximum *time.Duration
			want    bool
		}{{nil, true}, {new(2 * time.Minute), true}, {new(time.Minute), false}, {new(time.Minute + time.Nanosecond), true}, {new(-time.Second), false}} {
			if got := freshForSignature(chain.Leaf.Raw, claims, now, test.maximum); got != test.want {
				t.Fatal("freshness did not retain strict boundary", test.maximum, got)
			}
		}
		if freshForSignature(chain.TSA.Raw, claims, now, nil) || freshForSignature(chain.Leaf.Raw, nil, now, nil) {
			t.Fatal("unrelated or absent evidence established freshness")
		}
	}
}
