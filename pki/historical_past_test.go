package pki //nolint:testpackage // Exercises historical evidence boundaries and exact archive-time evaluation.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/pkipast"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestValidateArchiveUsesExactTimeAndRetainsCause(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	now := testcert.Now()
	goodCRL := testcert.CRL(t, chain)
	revokedCRL := testcert.CRL(t, chain, chain.Leaf)
	issued := now.Add(-time.Minute)
	at := now.Add(-30 * time.Second)
	source := sha256.Sum256([]byte("test archive timestamp"))

	for _, tc := range []struct {
		name      string
		target    time.Time
		proofTime time.Time
		crl       []byte
		wantSub   string
		wantErr   error
	}{
		{"fresh_evidence", at, issued, goodCRL, "", nil},
		{"at_observation_time", now, issued, goodCRL, "NO_POE", ErrPolicy},
		{"before_certificate_validity", chain.Leaf.NotBefore.Add(-time.Second), issued, goodCRL, "CERTIFICATE_CHAIN_GENERAL_FAILURE", ErrCertificate},
		{"before_certificate_proof", at, now, goodCRL, "NO_POE", ErrUnavailable},
		{"revoked_at_archive_time", at, issued, revokedCRL, "REVOKED", ErrRevoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			config := HistoricalConfig{PKI: Config{Roots: [][]byte{chain.Root.Raw}, Revocation: RequireCRL}}
			session, err := NewHistoricalSession(t.Context(), config, now, Evidence{CRLs: [][]byte{tc.crl}})
			if err != nil {
				t.Fatal(err)
			}
			proofs, err := historicalproof.New(t.Context(), now, []historicalproof.Fact{
				{Kind: historicalproof.Certificate, Digest: sha256.Sum256(chain.Leaf.Raw), Source: source, At: tc.proofTime},
				{Kind: historicalproof.CRL, Digest: sha256.Sum256(tc.crl), Source: source, At: issued},
			})
			if err != nil {
				t.Fatal(err)
			}

			result, report, err := pkipast.ValidateArchive(t.Context(), session, chain.Leaf.Raw, proofs, tc.target)
			if !errors.Is(err, tc.wantErr) || (result == nil) != (tc.wantErr != nil) {
				t.Fatalf("ValidateArchive(%v) = result present %t, error %v, want %v", tc.target, result != nil, err, tc.wantErr)
			}
			if report.SubIndication() != tc.wantSub || !errors.Is(report.Cause(), tc.wantErr) {
				t.Errorf("archive diagnostics = %q, %v, want %q, %v", report.SubIndication(), report.Cause(), tc.wantSub, tc.wantErr)
			}
			if result != nil {
				if !result.ValidationTime().Equal(tc.target) || len(report.Transitions()) != 0 {
					t.Errorf("archive time = %v with %d transitions, want %v with no transitions", result.ValidationTime(), len(report.Transitions()), tc.target)
				}
				if used := result.Evidence(); len(used) != 1 || !bytes.Equal(used[0].DER(), tc.crl) {
					t.Errorf("result evidence has %d assertions, want the original CRL", len(used))
				}
			}
		})
	}
}

func TestCheckArchiveStatusTimeEnforcesEvidenceWindow(t *testing.T) {
	t.Parallel()

	at := testcert.Now()
	before := at.Add(-time.Second)
	after := at.Add(time.Second)
	explicitFreshness := time.Minute
	e := pastEvaluation{session: &HistoricalSession{
		options: HistoricalOptions{RevocationFreshness: &explicitFreshness},
		verifier: &Verifier{
			crlOptions:  CRLOptions{MaxAge: 10 * time.Second},
			ocspOptions: OCSPOptions{MaxAge: 10 * time.Second, ClockSkew: time.Minute},
		},
	}}

	for _, tc := range []struct {
		name       string
		issued     time.Time
		this       time.Time
		next       time.Time
		dependency bool
		ocsp       bool
		want       error
	}{
		{"published_at_validation_time", at, before, after, false, false, nil},
		{"published_after_validation_time", after, before, after, false, false, ErrUnavailable},
		{"dependency_needs_no_status_freshness", before, at.Add(-time.Hour), before, true, false, nil},
		{"next_update_is_exclusive", before, before, at, false, false, ErrUnavailable},
		{"configured_freshness_is_exclusive", before, at.Add(-time.Minute), after, false, false, ErrUnavailable},
		{"crl_missing_next_update_within_max_age", before, at.Add(-9 * time.Second), time.Time{}, false, false, nil},
		{"crl_missing_next_update_at_max_age", before, at.Add(-10 * time.Second), time.Time{}, false, false, ErrUnavailable},
		{"ocsp_produced_before_this_update", before, at, after, false, true, ErrUnavailable},
		{"ocsp_produced_at_this_update", before, before, after, false, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			claim := historicalClaim{
				fact: &VerifiedEvidence{issued: tc.issued, this: tc.this, next: tc.next}, dependency: tc.dependency,
			}
			if tc.ocsp {
				claim.ocsp = &singleResponse{status: OCSPGood, this: tc.this, next: tc.next}
			}
			if got := e.checkArchiveStatusTime(claim, at); !errors.Is(got, tc.want) {
				t.Errorf("checkArchiveStatusTime = %v, want %v", got, tc.want)
			}
		})
	}
}
