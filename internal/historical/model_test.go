package historical //nolint:testpackage // Shares the signed timestamp fixture with the workflow tests.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
)

func TestValidateReportsInputAndSessionFailures(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	config := workflowConfigForIssuer(t, issuer)
	now := testcert.Now()
	signature := []byte("signature bytes")
	key := sha256.Sum256(signature)
	input := Input{
		Signature:       key,
		Certificate:     issuer.chain.Leaf.Raw,
		SignatureMethod: x509.ECDSAWithSHA256,
		Hashes:          []crypto.Hash{crypto.SHA256},
		Objects:         []Object{{Bytes: signature, Kind: historicalproof.Signature}},
	}
	for _, tc := range []struct {
		name   string
		change func(*Config, *Input, *time.Time)
		want   error
	}{
		{"missing_validation_time", func(_ *Config, _ *Input, at *time.Time) { *at = time.Time{} }, ErrInput},
		{"invalid_workflow_limits", func(c *Config, _ *Input, _ *time.Time) { c.MaxEdges = -1 }, ErrLimit},
		{"invalid_certificate", func(_ *Config, i *Input, _ *time.Time) { i.Certificate = []byte("not DER") }, ErrInput},
		{"missing_signature_method", func(_ *Config, i *Input, _ *time.Time) { i.SignatureMethod = x509.UnknownSignatureAlgorithm }, ErrInput},
		{"invalid_signature_hash", func(_ *Config, i *Input, _ *time.Time) { i.Hashes = []crypto.Hash{0} }, ErrInput},
		{"signature_hash_budget", func(_ *Config, i *Input, _ *time.Time) { i.Hashes = make([]crypto.Hash, 129) }, ErrLimit},
		{"invalid_signer_model", func(c *Config, _ *Input, _ *time.Time) { c.SignerHistory.Model = "other" }, pki.ErrPolicy},
		{"invalid_tsa_model", func(c *Config, _ *Input, _ *time.Time) { c.TSAHistory.Model = "other" }, pki.ErrPolicy},
		{"missing_signature_object", func(_ *Config, i *Input, _ *time.Time) { i.Objects = nil }, ErrInput},
		{"unknown_protected_material", func(_ *Config, i *Input, _ *time.Time) {
			i.Uses = []MaterialUse{{Object: sha256.Sum256([]byte("missing")), Hash: crypto.SHA256}}
		}, ErrInput},
		{"invalid_protected_material_hash", func(_ *Config, i *Input, _ *time.Time) {
			i.Uses = []MaterialUse{{Object: key, Hash: 0}}
		}, ErrInput},
		{"protected_material_budget", func(c *Config, i *Input, _ *time.Time) {
			c.MaxObjects, c.MaxEdges = 8, 8
			i.Uses = make([]MaterialUse, 9)
			for index := range i.Uses {
				i.Uses[index] = MaterialUse{Object: key, Hash: crypto.SHA256}
			}
		}, ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, in, at := config, input, now
			tc.change(&c, &in, &at)
			report, err := Validate(t.Context(), c, in, at, pki.Evidence{}, pki.Evidence{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate error = %v, want %v", err, tc.want)
			}
			if report == nil || !errors.Is(report.Cause, tc.want) || report.Indication != Indeterminate || !report.At.Equal(at) || report.Current != nil || report.Past != nil || report.Proofs != nil {
				t.Fatalf("Validate report = %+v, want input or policy failure with no certificate result or proofs", report)
			}
		})
	}
}

func TestValidateReturnsDelayComparisonErrorWithDiagnostics(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	config := workflowConfigForIssuer(t, issuer)
	now := testcert.Now()
	generation := now.Add(-time.Minute)
	delay := 5 * time.Minute
	config.TimestampDelay = &delay
	signature := []byte("signature bytes")
	key := sha256.Sum256(signature)
	stamp := issuer.issueStamp(t, 1, generation, new(time.Duration), false, signature)
	stamp.candidate.Covered = [][sha256.Size]byte{key}
	failure := errors.New("claimed signing time comparison unavailable")
	var called bool
	input := Input{
		Signature: key, Certificate: issuer.chain.Leaf.Raw, SignatureMethod: x509.ECDSAWithSHA256,
		Objects: []Object{{Bytes: signature, Kind: historicalproof.Signature}}, Timestamps: []Candidate{stamp.candidate},
		ClaimedTimeAfter: func(bound time.Time) (bool, error) {
			called = true
			if want := generation.Add(-delay); !bound.Equal(want) {
				t.Errorf("comparison bound = %v, want %v", bound, want)
			}
			return false, failure
		},
	}
	evidence := pki.Evidence{CRLs: [][]byte{testcert.CRL(t, issuer.chain)}}
	report, err := Validate(t.Context(), config, input, now, evidence, evidence)
	if !called || !errors.Is(err, failure) || report == nil || !errors.Is(report.Cause, failure) || report.Indication != Indeterminate {
		t.Fatalf("Validate = %+v, %v, adapter called %t; want an indeterminate result retaining the comparison error", report, err, called)
	}
	if report.Current == nil || report.Past != nil || len(report.Stamps) != 1 || report.Stamps[0].Indication != Passed || !report.Best.Equal(generation) {
		t.Fatalf("report = %+v, want retained certificate and timestamp results with best time %v", report, generation)
	}
}

func TestValidateChecksMaterialUseAtItsOwnProvenTime(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	now := testcert.Now()
	config := workflowConfigForIssuer(t, issuer)
	config.SignerHistory.CryptoConstraints = []pki.CryptoConstraint{{Hash: crypto.SHA384, ReliableUntil: now}}
	signature, payload := []byte("signature bytes"), []byte("document payload")
	key, payloadKey := sha256.Sum256(signature), sha256.Sum256(payload)
	evidence := pki.Evidence{CRLs: [][]byte{testcert.CRL(t, issuer.chain)}}
	for _, tc := range []struct {
		name      string
		timestamp bool
	}{
		{"observed_at_cutoff", false},
		{"timestamped_before_cutoff", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			input := Input{
				Signature: key, Certificate: issuer.chain.Leaf.Raw, SignatureMethod: x509.ECDSAWithSHA256,
				Hashes: []crypto.Hash{crypto.SHA256}, Uses: []MaterialUse{{Object: payloadKey, Hash: crypto.SHA384}},
				Objects: []Object{{Bytes: signature, Kind: historicalproof.Signature}, {Bytes: payload, Kind: historicalproof.Data}},
			}
			wantProof := now
			if tc.timestamp {
				wantProof = now.Add(-time.Minute)
				stamp := issuer.issueStamp(t, 1, wantProof, new(time.Duration), false, payload)
				stamp.candidate.Covered = [][sha256.Size]byte{payloadKey}
				stamp.candidate.Archive = true
				input.Timestamps = []Candidate{stamp.candidate}
			}
			report, err := Validate(t.Context(), config, input, now, evidence, evidence)
			if report == nil || report.Current == nil || report.Past != nil || !report.Best.Equal(now) {
				t.Fatalf("Validate = %+v, %v, want the current certificate result and the observation time for the signature", report, err)
			}
			if at, found := report.Proofs.Earliest(payloadKey); !found || !at.Equal(wantProof) {
				t.Fatalf("payload proof = %v, %t, want %v", at, found, wantProof)
			}
			if tc.timestamp {
				if err != nil || report.Indication != Passed || report.Cause != nil {
					t.Fatalf("Validate = %+v, %v, want success with a proof before the cutoff", report, err)
				}
				return
			}
			if !errors.Is(err, ErrValidation) || !errors.Is(report.Cause, ErrValidation) || report.Indication != Indeterminate || report.SubIndication != cryptoFailure {
				t.Fatalf("Validate = %+v, %v, want a cryptographic constraints failure", report, err)
			}
		})
	}
}

func TestValidateReturnsCauseWhenContextIsCanceledInDelayComparison(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	now := testcert.Now()
	config := workflowConfigForIssuer(t, issuer)
	delay := time.Hour
	config.TimestampDelay = &delay
	signature := []byte("signature bytes")
	key := sha256.Sum256(signature)
	stamp := issuer.issueStamp(t, 1, now.Add(-time.Minute), new(time.Duration), false, signature)
	stamp.candidate.Covered = [][sha256.Size]byte{key}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	input := Input{
		Signature: key, Certificate: issuer.chain.Leaf.Raw, SignatureMethod: x509.ECDSAWithSHA256,
		Objects: []Object{{Bytes: signature, Kind: historicalproof.Signature}}, Timestamps: []Candidate{stamp.candidate},
		ClaimedTimeAfter: func(time.Time) (bool, error) { cancel(); return true, nil },
	}
	evidence := pki.Evidence{CRLs: [][]byte{testcert.CRL(t, issuer.chain)}}
	report, err := Validate(ctx, config, input, now, evidence, evidence)
	if !errors.Is(err, context.Canceled) || report == nil || !errors.Is(report.Cause, context.Canceled) || report.Indication != Indeterminate || report.Current == nil {
		t.Fatalf("Validate = %+v, %v, want cancellation after certificate acceptance", report, err)
	}
}

func workflowConfigForIssuer(t *testing.T, issuer timestampIssuer) Config {
	t.Helper()

	signer, err := pki.NewVerifier(pki.Config{Roots: [][]byte{issuer.chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	return Config{Signer: signer, TSA: issuer.verifier}
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
					// Verification reports retain diagnostics on failure.
					//noinspection GoDfaErrorMayBeNotNil
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
		// Verification reports retain diagnostics on failure.
		//noinspection GoDfaErrorMayBeNotNil
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
			// Verification reports retain diagnostics on failure.
			//noinspection GoDfaErrorMayBeNotNil
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

func TestWorkflowCancellationNeverProducesPassingReport(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	now := testcert.Now()
	report, err := Validate(ctx, Config{}, Input{}, now, pki.Evidence{}, pki.Evidence{})
	// Verification reports retain diagnostics on failure.
	//noinspection GoDfaErrorMayBeNotNil
	if !errors.Is(err, context.Canceled) || report == nil || report.Indication != Indeterminate || !errors.Is(report.Cause, context.Canceled) || !report.At.Equal(now) || report.Proofs != nil || report.Current != nil || report.Past != nil {
		t.Fatal("failed workflow granted state", report, err)
	}
}
