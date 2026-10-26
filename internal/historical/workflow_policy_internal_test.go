package historical

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

func TestTimestampDelayUsesExclusiveBoundaryAndExactAdapterComparison(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	stamp := issuer.issueStamp(t, 1, testcert.Now().Add(-time.Minute), nil, false, []byte("signature"))
	delay := 5 * time.Minute
	best := testcert.Now().Add(-time.Hour)
	for _, test := range []struct {
		name    string
		claimed time.Time
		want    bool
	}{
		{"just inside", best.Add(-delay + time.Nanosecond), true},
		{"equality", best.Add(-delay), false},
		{"before", best.Add(-delay - time.Nanosecond), false},
		{"missing claimed time", time.Time{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			workflow := validationWorkflow{config: Config{TimestampDelay: &delay}, input: Input{Timestamps: []Candidate{stamp.candidate}, ClaimedTime: test.claimed}, report: &Report{Best: best}}
			err := workflow.verifyDelay()
			if test.want && err != nil || !test.want && !errors.Is(err, ErrValidation) {
				t.Fatal("timestamp delay boundary", err)
			}
			if !test.want && workflow.report.SubIndication != signatureConstraintsFailure {
				t.Fatal("delay refusal did not preserve its indication", workflow.report.SubIndication)
			}
		})
	}
	for _, flags := range []struct{ archive, content bool }{{true, false}, {false, true}, {false, false}} {
		candidate := stamp.candidate
		candidate.Archive = flags.archive
		candidate.Content = flags.content
		called := false
		workflow := validationWorkflow{config: Config{TimestampDelay: &delay}, input: Input{Timestamps: []Candidate{candidate}, ClaimedTimeAfter: func(at time.Time) (bool, error) {
			called = true
			if at != best.Add(-delay) {
				t.Fatal("exact comparison threshold changed", at)
			}
			return true, nil
		}}, report: &Report{Best: best}}
		if err := workflow.verifyDelay(); err != nil || called != (!flags.archive && !flags.content) {
			t.Fatal("wrong timestamp class used for signature-delay policy", called, err)
		}
	}
	failure := errors.New("adapter comparison failed")
	workflow := validationWorkflow{config: Config{TimestampDelay: &delay}, input: Input{Timestamps: []Candidate{stamp.candidate}, ClaimedTime: best, ClaimedTimeAfter: func(time.Time) (bool, error) { return false, failure }}, report: &Report{Best: best}}
	if err := workflow.verifyDelay(); !errors.Is(err, failure) {
		t.Fatal("exact adapter error was replaced", err)
	}
	workflow.input.ClaimedTimeAfter = func(time.Time) (bool, error) { return false, nil }
	if err := workflow.verifyDelay(); !errors.Is(err, ErrValidation) {
		t.Fatal("false exact comparison ignored", err)
	}
	workflow.config.TimestampDelay = nil
	workflow.input.ClaimedTimeAfter = func(time.Time) (bool, error) { t.Fatal("disabled delay invoked adapter"); return false, failure }
	if err := workflow.verifyDelay(); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentSubIndicationPreservesCertificateBoundsAndFailureClass(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	certificate := chain.Leaf
	for _, test := range []struct {
		name  string
		at    time.Time
		cause error
		want  string
	}{
		{"not yet valid outranks error class", certificate.NotBefore.Add(-time.Nanosecond), pki.ErrRevoked, outOfBounds},
		{"expired outranks error class", certificate.NotAfter.Add(time.Nanosecond), pki.ErrUnavailable, outOfBounds},
		{"issuance equality", certificate.NotBefore, pki.ErrCertificate, noChain},
		{"expiry equality", certificate.NotAfter, pki.ErrCertificate, noChain},
		{"leaf revoked", testcert.Now(), pki.ErrRevoked, revoked},
		{"unavailable", testcert.Now(), errors.Join(errors.New("offline lookup"), pki.ErrUnavailable), tryLater},
		{"timestamp trust", testcert.Now(), timestamp.ErrTrust, noChain},
		{"unclassified chain error", testcert.Now(), errors.New("invalid chain"), "CHAIN_CONSTRAINTS_FAILURE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := currentSubIndication(test.cause, pki.Report{}, certificate, test.at); got != test.want {
				t.Fatalf("sub-indication = %s; want %s", got, test.want)
			}
		})
	}
}

func TestTimestampPreparationChecksAccuracyWithoutGrantingHistoricalTrust(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	for _, test := range []struct {
		name              string
		accuracy, assumed *time.Duration
		delta             time.Duration
		want              bool
	}{
		{"missing refuses assumed precision", nil, nil, -time.Minute, false},
		{"explicit zero accuracy", new(time.Duration(0)), nil, 0, true},
		{"configured missing accuracy", nil, new(time.Minute), -time.Minute, true},
		{"upper equality", new(time.Minute), nil, -time.Minute, true},
		{"upper in the future", new(time.Minute + time.Microsecond), nil, -time.Minute, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stamp := issuer.issueStamp(t, 1, testcert.Now().Add(test.delta), test.accuracy, false, []byte("timestamp input"))
			workflow := validationWorkflow{ctx: t.Context(), now: testcert.Now(), config: Config{TSA: issuer.verifier, MissingAccuracy: test.assumed, RequireAllTimestamps: true}, report: &Report{}}
			prepared, err := workflow.prepareTimestamp(stamp.candidate)
			if !test.want {
				if prepared != nil || !errors.Is(err, ErrValidation) || workflow.report.SubIndication != signatureConstraintsFailure || len(workflow.report.Stamps) != 1 || workflow.report.Stamps[0].SubIndication != "TIMESTAMP_CONSTRAINTS_FAILURE" {
					t.Fatal("timestamp precision constraint was bypassed", prepared, err, workflow.report)
				}
				return
			}
			if err != nil || prepared == nil || prepared.upper != testcert.Now() || !prepared.assertion.Valid() || prepared.certificate == nil || len(workflow.report.Stamps) != 0 {
				t.Fatal("valid timestamp preparation failed", prepared, err)
			}
			if workflow.report.Indication != Indeterminate || workflow.report.Proofs != nil {
				t.Fatal("cryptographic preparation granted historical trust")
			}
		})
	}
}

func TestTimestampRejectionPreservesCauseAndRequiredPolicy(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	stamp := issuer.issueStamp(t, 1, testcert.Now().Add(-time.Minute), nil, false, []byte("input"))
	for _, test := range []struct {
		cause      error
		indication Indication
		sub        string
	}{
		{cms.ErrSignature, Failed, "SIG_CRYPTO_FAILURE"}, {timestamp.ErrBinding, Failed, "HASH_FAILURE"}, {timestamp.ErrPolicy, Indeterminate, signatureConstraintsFailure},
	} {
		for _, required := range []bool{false, true} {
			workflow := validationWorkflow{ctx: t.Context(), config: Config{RequireAllTimestamps: required}, report: &Report{}}
			err := workflow.rejectTimestampAuthentication(stamp.candidate, test.cause)
			if required && (!errors.Is(err, ErrValidation) || !errors.Is(err, test.cause)) || !required && err != nil {
				t.Fatal("required/optional timestamp rejection", required, err)
			}
			if len(workflow.report.Stamps) != 1 || workflow.report.Stamps[0].Token != stamp.assertion.TokenSHA256() || workflow.report.Stamps[0].Indication != test.indication || workflow.report.Stamps[0].SubIndication != test.sub {
				t.Fatal("timestamp rejection diagnostics lost", workflow.report.Stamps)
			}
			if required && (workflow.report.Indication != test.indication || workflow.report.SubIndication != test.sub) {
				t.Fatal("required timestamp failure not propagated", workflow.report)
			}
		}
	}
	workflow := validationWorkflow{ctx: t.Context(), report: &Report{}}
	if err := workflow.rejectTimestampAuthentication(stamp.candidate, pki.ErrLimit); !errors.Is(err, pki.ErrLimit) {
		t.Fatal("optional timestamp swallowed aggregate limit", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	workflow.ctx = ctx
	if err := workflow.rejectTimestampAuthentication(stamp.candidate, context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("optional timestamp swallowed cancellation", err)
	}
}

func TestRemoveTimestampSourcesRequiresAdmittedTokensAndPreservesOtherEvidence(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	stamp := issuer.issueStamp(t, 1, testcert.Now().Add(-time.Minute), nil, false, []byte("input"))
	observation := func(kind evidence.Kind, data []byte) *evidence.Observation {
		value, err := evidence.NewObservation(t.Context(), kind, data, evidence.Provenance{RetrievedAt: testcert.Now().Add(-time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	ts := observation(evidence.Timestamp, stamp.candidate.Token.DER())
	crl := observation(evidence.CRL, []byte("untrusted revocation bytes"))
	input := Input{Timestamps: []Candidate{stamp.candidate}}
	first := pki.Evidence{Sources: []*evidence.Observation{ts, crl}, CRLs: [][]byte{[]byte("retained input")}}
	second := pki.Evidence{Sources: []*evidence.Observation{ts}}
	a, b, err := removeTimestampSources(input, first, second)
	if err != nil || !slices.Equal(a.Sources, []*evidence.Observation{crl}) || len(b.Sources) != 0 || len(first.Sources) != 2 || first.Sources[0] != ts || len(a.CRLs) != 1 {
		t.Fatal("observation filtering changed independent evidence or caller input", a, b, err)
	}
	for _, invalid := range []*evidence.Observation{nil, {}, observation(evidence.Timestamp, []byte("unlisted token encoding"))} {
		if a, b, err := removeTimestampSources(input, pki.Evidence{Sources: []*evidence.Observation{invalid}}, second); !errors.Is(err, ErrInput) || len(a.Sources) != 0 || len(b.Sources) != 0 {
			t.Fatal("unadmitted timestamp provenance accepted", a, b, err)
		}
	}
}

func TestCurrentWorkflowKeepsObservationTimeSeparateFromAuthenticatedPoE(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	signer, err := pki.NewVerifier(pki.Config{Roots: [][]byte{issuer.chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Signer: signer, TSA: issuer.verifier}
	signatureBytes := []byte("exact signature bytes supplied by the already-authenticated format adapter")
	signature := sha256.Sum256(signatureBytes)
	crl := testcert.CRL(t, issuer.chain)
	for _, stamped := range []bool{false, true} {
		input := Input{Signature: signature, Certificate: issuer.chain.Leaf.Raw, SignatureMethod: issuer.chain.Leaf.SignatureAlgorithm, Hashes: []crypto.Hash{crypto.SHA256}, Objects: []Object{{Bytes: signatureBytes, Kind: historicalproof.Signature}}, ClaimedTime: testcert.Now().Add(-time.Hour)}
		wantBest := testcert.Now()
		var token [32]byte
		if stamped {
			zero := time.Duration(0)
			stamp := issuer.issueStamp(t, 1, testcert.Now().Add(-30*time.Second), &zero, false, signatureBytes)
			stamp.candidate.Covered = [][32]byte{signature}
			input.Timestamps = []Candidate{stamp.candidate}
			wantBest = stamp.upper
			token = stamp.assertion.TokenSHA256()
		}
		report, err := Validate(t.Context(), config, input, testcert.Now(), pki.Evidence{CRLs: [][]byte{crl}}, pki.Evidence{CRLs: [][]byte{crl}})
		if err != nil || report == nil || report.Indication != Passed || report.Cause != nil || report.Current == nil || report.Past != nil || report.Best != wantBest || report.Validation != testcert.Now() || report.Proofs == nil {
			t.Fatal("valid current workflow failed or borrowed claimed SigningTime", stamped, report, err)
		}
		if at, ok := report.Proofs.Earliest(signature); !ok || at != wantBest {
			t.Fatal("signature proof bound wrong", at, ok)
		}
		if at, ok := report.Proofs.Earliest(sha256.Sum256(crl)); !ok || at != testcert.Now() {
			t.Fatal("uncovered revocation bytes backdated", at, ok)
		}
		if stamped {
			if at, ok := report.Proofs.Earliest(token); !ok || at != testcert.Now() {
				t.Fatal("token used its own generation time as proof of its encoding", at, ok)
			}
			if len(report.Stamps) != 1 || report.Stamps[0].Indication != Passed || report.Stamps[0].Upper != wantBest {
				t.Fatal("timestamp acceptance diagnostic missing", report.Stamps)
			}
		}
		if step := report.Steps[len(report.Steps)-1]; step.Action != "return-passed" || step.Object != signature {
			t.Fatal("workflow omitted final successful signature decision", step)
		}
	}
}

func TestWorkflowTimestampFailureHonorsOptionalPolicyWithoutExtractingProofs(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	signer, err := pki.NewVerifier(pki.Config{Roots: [][]byte{issuer.chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	crl := testcert.CRL(t, issuer.chain)
	signatureBytes := []byte("format-authenticated signature encoding")
	signature := sha256.Sum256(signatureBytes)
	for _, failure := range []string{"binding", "missing accuracy", "expired TSA hash"} {
		for _, required := range []bool{false, true} {
			t.Run(failure+"/"+map[bool]string{false: "optional", true: "required"}[required], func(t *testing.T) {
				t.Parallel()

				config := Config{Signer: signer, TSA: issuer.verifier, RequireAllTimestamps: required}
				accuracy := new(time.Duration(0))
				if failure == "missing accuracy" {
					accuracy = nil
				}
				stamp := issuer.issueStamp(t, 1, testcert.Now().Add(-30*time.Second), accuracy, false, signatureBytes)
				stamp.candidate.Covered = [][32]byte{signature}
				wantIndication, wantSub := Indeterminate, signatureConstraintsFailure
				if failure == "binding" {
					stamp.candidate.Imprint.Digest = make([]byte, crypto.SHA256.Size())
					wantIndication, wantSub = Failed, "HASH_FAILURE"
				}
				if failure == "missing accuracy" {
					wantSub = "TIMESTAMP_CONSTRAINTS_FAILURE"
				}
				if failure == "expired TSA hash" {
					config.TSAHistory.CryptoConstraints = []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: testcert.Now().Add(-time.Second)}}
					wantSub = cryptoFailure
				}
				input := Input{Signature: signature, Certificate: issuer.chain.Leaf.Raw, SignatureMethod: issuer.chain.Leaf.SignatureAlgorithm, Hashes: []crypto.Hash{crypto.SHA256}, Objects: []Object{{Bytes: signatureBytes, Kind: historicalproof.Signature}}, Timestamps: []Candidate{stamp.candidate}}
				report, err := Validate(t.Context(), config, input, testcert.Now(), pki.Evidence{CRLs: [][]byte{crl}}, pki.Evidence{CRLs: [][]byte{crl}})
				if report == nil || len(report.Stamps) != 1 || report.Stamps[0].Indication != wantIndication || report.Stamps[0].SubIndication != wantSub || report.Best != testcert.Now() {
					t.Fatal("rejected timestamp changed bound or lost diagnostic", report, err)
				}
				if required {
					if !errors.Is(err, ErrValidation) || !errors.Is(report.Cause, err) || report.Indication == Passed || report.Current != nil || report.Past != nil {
						t.Fatal("required timestamp did not stop signer acceptance", report, err)
					}
					return
				}
				if err != nil || report.Indication != Passed || report.Current == nil || report.Cause != nil {
					t.Fatal("optional timestamp stopped otherwise valid signature", report, err)
				}
				if at, ok := report.Proofs.Earliest(signature); !ok || at != testcert.Now() {
					t.Fatal("rejected timestamp minted a past proof", at, ok)
				}
			})
		}
	}
}

func TestWorkflowRejectsContentChronologyEvenWhenTimestampsAreOptional(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	signer, err := pki.NewVerifier(pki.Config{Roots: [][]byte{issuer.chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	crl := testcert.CRL(t, issuer.chain)
	signatureBytes, contentBytes := []byte("authenticated signature"), []byte("authenticated signed content")
	signature, content := sha256.Sum256(signatureBytes), sha256.Sum256(contentBytes)
	for _, contentDelta := range []time.Duration{-time.Second, 0} {
		at := testcert.Now().Add(-time.Minute)
		sigStamp := issuer.issueStamp(t, 1, at, new(time.Duration(0)), false, signatureBytes)
		sigStamp.candidate.Covered = [][32]byte{signature}
		contentStamp := issuer.issueStamp(t, 2, at.Add(contentDelta), new(time.Duration(0)), false, contentBytes)
		contentStamp.candidate.Content = true
		contentStamp.candidate.Covered = [][32]byte{content}
		input := Input{Signature: signature, Certificate: issuer.chain.Leaf.Raw, SignatureMethod: issuer.chain.Leaf.SignatureAlgorithm, Hashes: []crypto.Hash{crypto.SHA256}, Objects: []Object{{Bytes: signatureBytes, Kind: historicalproof.Signature}, {Bytes: contentBytes, Kind: historicalproof.Data}}, Timestamps: []Candidate{contentStamp.candidate, sigStamp.candidate}}
		report, err := Validate(t.Context(), Config{Signer: signer, TSA: issuer.verifier}, input, testcert.Now(), pki.Evidence{CRLs: [][]byte{crl}}, pki.Evidence{CRLs: [][]byte{crl}})
		if contentDelta < 0 {
			if err != nil || report.Indication != Passed || len(report.Stamps) != 2 || report.Stamps[0].Indication != Passed || report.Stamps[1].Indication != Passed {
				t.Fatal("strictly earlier content timestamp refused", report, err)
			}
			continue
		}
		if !errors.Is(err, ErrValidation) || report.Indication == Passed || report.SubIndication != timestampOrderFailure || len(report.Stamps) != 2 || report.Stamps[1].SubIndication != timestampOrderFailure || report.Stamps[1].Indication != Indeterminate || report.Current != nil {
			t.Fatal("incoherent content chronology accepted as optional", report, err)
		}
	}
}

func TestWorkflowPastRecoveryRequiresTimestampedCertificateAndRevocationBytes(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	signer, err := pki.NewVerifier(pki.Config{Roots: [][]byte{issuer.chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	crl := testcert.CRL(t, issuer.chain)
	signatureBytes := []byte("authenticated format signature encoding")
	signature := sha256.Sum256(signatureBytes)
	cutoff := testcert.Now().Add(-30 * time.Second)
	config := Config{Signer: signer, TSA: issuer.verifier, SignerHistory: pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: cutoff}}}}
	for _, fullCoverage := range []bool{false, true} {
		protected := [][]byte{signatureBytes}
		if fullCoverage {
			protected = append(protected, issuer.chain.Leaf.Raw, issuer.chain.Root.Raw, crl)
		}
		// Every Covered encoding is literally included in this timestamp input.
		stamp := issuer.issueStamp(t, 1, cutoff.Add(-time.Second), new(time.Duration(0)), false, bytes.Join(protected, nil))
		for _, raw := range protected {
			stamp.candidate.Covered = append(stamp.candidate.Covered, sha256.Sum256(raw))
		}
		input := Input{Signature: signature, Certificate: issuer.chain.Leaf.Raw, SignatureMethod: issuer.chain.Leaf.SignatureAlgorithm, Hashes: []crypto.Hash{crypto.SHA256}, Objects: []Object{{Bytes: signatureBytes, Kind: historicalproof.Signature}}, Timestamps: []Candidate{stamp.candidate}}
		report, err := Validate(t.Context(), config, input, testcert.Now(), pki.Evidence{CRLs: [][]byte{crl}}, pki.Evidence{CRLs: [][]byte{crl}})
		if !fullCoverage {
			if !errors.Is(err, ErrValidation) || report.Indication == Passed || report.Past != nil {
				t.Fatal("signature proof alone repaired expired certificate/evidence hashes", report, err)
			}
			continue
		}
		if err != nil || report.Indication != Passed || report.Current != nil || report.Past == nil || report.Path == nil || report.Validation != cutoff || report.Best != stamp.upper {
			t.Fatal("past recovery failed with independently protected exact encodings", report, err)
		}
		if !slices.ContainsFunc(report.Steps, func(step Step) bool {
			return step.Action == "past-signature-validation" && step.Object == signature && step.After.Equal(cutoff)
		}) {
			t.Fatal("past signer decision was not propagated to workflow trace", report.Steps)
		}
	}
}
