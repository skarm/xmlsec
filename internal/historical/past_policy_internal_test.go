package historical

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
)

func TestPastSignatureRecoveryHasBranchSpecificCertificateBounds(t *testing.T) {
	t.Parallel()

	start := testcert.Now().Add(-time.Hour)
	end := testcert.Now().Add(-time.Minute)
	certificate := &x509.Certificate{NotBefore: start, NotAfter: end}
	for _, current := range []string{noChain, outOfBounds, outNotRevoked, revoked, revocationBounds} {
		for _, test := range []struct {
			name string
			at   time.Time
		}{
			{"before issuance", start.Add(-time.Nanosecond)}, {"issuance equality", start}, {"inside", start.Add(time.Nanosecond)}, {"expiry equality", end}, {"after expiry", end.Add(time.Nanosecond)},
		} {
			t.Run(current+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				out := pastOutcome{best: test.at, sub: current}
				evaluation := pastSignatureEvaluation{current: current, certificate: certificate}
				accepted, terminal := evaluation.signatureProofRecovery(&out, nil)
				wantTerminal := test.at.Before(start)
				strict := current == outOfBounds || current == outNotRevoked
				wantAccepted := !test.at.Before(start) && !test.at.After(end)
				if strict {
					wantAccepted = test.at.After(start) && test.at.Before(end)
				}
				if accepted != wantAccepted || terminal != wantTerminal {
					t.Fatalf("recovery = %v,%v; want %v,%v", accepted, terminal, wantAccepted, wantTerminal)
				}
				if wantTerminal && (out.indication != Failed || out.sub != "NOT_YET_VALID") {
					t.Fatal("before-issuance failure was not terminal", out)
				}
				if test.at.After(end) && current == noChain && out.sub != outOfBounds {
					t.Fatal("missing-chain expiry classification", out.sub)
				}
				if test.at.After(end) && (current == revoked || current == revocationBounds) && out.sub != outNotRevoked {
					t.Fatal("revocation recovery expiry classification", out.sub)
				}
			})
		}
	}
	if accept, terminal := (&pastSignatureEvaluation{current: revokedCA, certificate: certificate}).signatureProofRecovery(&pastOutcome{best: start.Add(time.Second)}, nil); accept || terminal {
		t.Fatal("CA revocation recovered without authenticated CA evidence")
	}
	if accept, terminal := (&pastSignatureEvaluation{current: cryptoFailure, certificate: certificate}).signatureProofRecovery(&pastOutcome{best: start.Add(time.Second)}, nil); accept || terminal {
		t.Fatal("unrelated recovery branch was accepted")
	}
}

func TestPastSignatureRejectsMissingProofsBeforePathProcessing(t *testing.T) {
	t.Parallel()

	signature := sha256.Sum256([]byte("signature"))
	material := signedMaterial{digest: signature}
	for _, test := range []struct {
		current string
		proofs  *historicalproof.Set
	}{
		{noChain, nil}, {noChain, &historicalproof.Set{}}, {noChain, newProofSet(t)}, {"permanent failure", newProofSet(t)},
	} {
		out := pastSignature(t.Context(), nil, material, test.current, test.proofs, pki.HistoricalOptions{})
		if out.indication != Indeterminate || out.sub != test.current || !out.best.IsZero() || out.result != nil || !errors.Is(out.err, ErrValidation) {
			t.Fatal("missing PoE produced past acceptance", out)
		}
	}
}

func TestRecoverableIndications(t *testing.T) {
	t.Parallel()

	for _, current := range []string{noChain, outOfBounds, outNotRevoked, revoked, revokedCA, revocationBounds, cryptoFailure, tryLater} {
		if !recoverable(current) {
			t.Fatal("recoverable indication omitted", current)
		}
	}
	for _, current := range []string{"", "SIG_CRYPTO_FAILURE", "HASH_FAILURE", "CHAIN_CONSTRAINTS_FAILURE"} {
		if recoverable(current) {
			t.Fatal("non-recoverable failure accepted", current)
		}
	}
}

func TestPastSignatureRejectsMalformedCertificateAndCancellation(t *testing.T) {
	t.Parallel()

	signature := sha256.Sum256([]byte("signature"))
	material := signedMaterial{digest: signature, certificate: []byte{1, 2, 3}}
	source := sha256.Sum256([]byte("authenticated archive source"))
	proofs := newProofSet(t, historicalproof.Fact{Digest: signature, Source: source, At: testcert.Now().Add(-time.Hour), Kind: historicalproof.Signature})
	out := pastSignature(t.Context(), nil, material, noChain, proofs, pki.HistoricalOptions{})
	if out.err == nil || out.result != nil || out.best.IsZero() || out.indication == Passed {
		t.Fatal("malformed certificate recovered", out)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	chain := testcert.New(t)
	material.certificate = chain.Leaf.Raw
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	session, err := verifier.NewHistoricalSession(t.Context(), pki.HistoricalOptions{}, testcert.Now(), pki.Evidence{})
	if err != nil {
		t.Fatal(err)
	}
	out = pastSignature(ctx, session, material, noChain, proofs, pki.HistoricalOptions{})
	if !errors.Is(out.err, context.Canceled) || out.result != nil || out.indication == Passed {
		t.Fatal("canceled past validation returned trust", out)
	}
}

func TestDiagnosticDigestRequiresAllHexBytes(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "00", "000000000000000000000000000000000000000000000000000000000000000g"} {
		if got := decodeDigest(value); got != ([32]byte{}) {
			t.Fatal("malformed diagnostic fingerprint accepted", got)
		}
	}
	if got := decodeDigest("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"); got != ([32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}) {
		t.Fatal("diagnostic fingerprint changed", got)
	}
}
