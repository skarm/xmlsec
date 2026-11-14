package historical //nolint:testpackage // Exercises internal timestamp decisions and workflow outcomes.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"slices"
	"strconv"
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
	if got := currentSubIndication(pki.ErrRevoked, pki.Report{}, nil, testcert.Now()); got != revoked {
		t.Fatalf("revocation without a parsed certificate = %s; want %s", got, revoked)
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

func TestNormalizeSnapshotsPolicyAndBounds(t *testing.T) {
	t.Parallel()

	base := testWorkflowConfig(t)
	delay, accuracy, freshness := time.Hour, time.Minute, time.Second
	at := testcert.Now()
	base.TimestampDelay = &delay
	base.MissingAccuracy = &accuracy
	base.SignerHistory = pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: at}}, TrustAnchorSunsets: map[string]time.Time{"anchor": at}, RevocationFreshness: &freshness}
	got, err := Normalize(base)
	if err != nil {
		t.Fatal(err)
	}
	delay = 0
	accuracy = 0
	freshness = 0
	base.SignerHistory.CryptoConstraints[0].Hash = crypto.SHA512
	delete(base.SignerHistory.TrustAnchorSunsets, "anchor")
	if got.MaxObjects != 512 || got.MaxEdges != 4096 || got.MaxBytes != 16<<20 || got.MaxTimestamps != 16 || *got.TimestampDelay != time.Hour || *got.MissingAccuracy != time.Minute || *got.SignerHistory.RevocationFreshness != time.Second || got.SignerHistory.CryptoConstraints[0].Hash != crypto.SHA256 || !got.SignerHistory.TrustAnchorSunsets["anchor"].Equal(at) {
		t.Fatal("policy/defaults alias caller state")
	}
	for _, limits := range []struct{ objects, edges, bytes, timestamps int }{{1, 1, 1, 1}, {2048, 8192, 64 << 20, 64}} {
		exact := got
		exact.MaxObjects = limits.objects
		exact.MaxEdges = limits.edges
		exact.MaxBytes = limits.bytes
		exact.MaxTimestamps = limits.timestamps
		normalized, err := Normalize(exact)
		if err != nil || normalized.MaxObjects != limits.objects || normalized.MaxEdges != limits.edges || normalized.MaxBytes != limits.bytes || normalized.MaxTimestamps != limits.timestamps {
			t.Fatal("exact workflow limits rejected", limits, err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   error
	}{
		{"missing signer", func(c *Config) { c.Signer = nil }, ErrInput},
		{"object overflow", func(c *Config) { c.MaxObjects = 2049 }, ErrLimit},
		{"edge budget below objects", func(c *Config) { c.MaxEdges = 1 }, ErrLimit},
		{"byte overflow", func(c *Config) { c.MaxBytes = (64 << 20) + 1 }, ErrLimit},
		{"timestamp overflow", func(c *Config) { c.MaxTimestamps = 65 }, ErrLimit},
		{"negative precision", func(c *Config) { value := -time.Nanosecond; c.MissingAccuracy = &value }, ErrInput},
		{"precision overflow", func(c *Config) { value := 24*time.Hour + 1; c.MissingAccuracy = &value }, ErrInput},
		{"signer constraint overflow", func(c *Config) {
			c.SignerHistory.CryptoConstraints = make([]pki.CryptoConstraint, 129)
		}, ErrLimit},
		{"TSA sunset overflow", func(c *Config) {
			c.TSAHistory.TrustAnchorSunsets = make(map[string]time.Time, 65)
			for i := range 65 {
				c.TSAHistory.TrustAnchorSunsets[strconv.Itoa(i)] = at
			}
		}, ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			bad := got
			tc.mutate(&bad)
			if _, err := Normalize(bad); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		})
	}
}

func TestPrepareGraphValidatesMaterialUses(t *testing.T) {
	t.Parallel()

	signature := Object{Bytes: []byte("signature"), Kind: historicalproof.Signature}
	data := Object{Bytes: []byte("signed data"), Kind: historicalproof.Data}
	use := MaterialUse{Object: sha256.Sum256(data.Bytes), Hash: crypto.SHA256}
	for _, tc := range []struct {
		name    string
		uses    []MaterialUse
		wantErr error
	}{
		{"exact_edge_budget", []MaterialUse{use, use}, nil},
		{"above_edge_budget", []MaterialUse{use, use, use}, ErrLimit},
		{"unknown_object", []MaterialUse{{Object: sha256.Sum256([]byte("other data")), Hash: crypto.SHA256}}, ErrInput},
		{"missing_hash", []MaterialUse{{Object: use.Object}}, ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			workflow := validationWorkflow{
				ctx:    t.Context(),
				config: Config{MaxObjects: 2, MaxEdges: 2, MaxBytes: 64},
				input:  Input{Signature: sha256.Sum256(signature.Bytes), Objects: []Object{signature, data}, Uses: tc.uses},
				now:    testcert.Now(),
			}
			err := workflow.prepareGraph()
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || workflow.graph != nil {
					t.Fatalf("prepareGraph = %v, graph present = %t; want %v and no graph", err, workflow.graph != nil, tc.wantErr)
				}
				return
			}
			if err != nil || workflow.graph == nil {
				t.Fatalf("prepareGraph = %v, graph present = %t; want a graph", err, workflow.graph != nil)
			}
			if got := workflow.graph.objects[use.Object]; got.Kind != historicalproof.Data || !bytes.Equal(got.Bytes, data.Bytes) {
				t.Errorf("bound material = %+v, want data object with bytes %q", got, data.Bytes)
			}
		})
	}
}

func TestAdmitEvidenceRecordsEmbeddedOCSPCertificate(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	now := testcert.Now()
	request, err := pki.CreateOCSPRequest(chain.Leaf.Raw, chain.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := pki.CreateOCSPResponse(t.Context(), request, chain.Leaf.Raw, chain.Root.Raw, chain.Responder.Raw, chain.ResponderKey, pki.OCSPResponseTemplate{
		Status: pki.OCSPGood, ProducedAt: now, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	responderID := sha256.Sum256(chain.Responder.Raw)
	input := Input{
		Certificate: chain.Leaf.Raw,
		Objects:     []Object{{Bytes: response, Kind: historicalproof.Data}},
	}
	w := validationWorkflow{ctx: t.Context(), input: input, signerEvidence: pki.Evidence{OCSPResponses: [][]byte{response}}}
	if err := w.admitEvidence(); err != nil {
		t.Fatal(err)
	}
	want := []Object{
		{Bytes: response, Kind: historicalproof.OCSP, Contains: [][sha256.Size]byte{responderID}},
		{Bytes: chain.Leaf.Raw, Kind: historicalproof.Certificate},
		{Bytes: chain.Responder.Raw, Kind: historicalproof.Certificate},
	}
	if !reflect.DeepEqual(w.input.Objects, want) {
		t.Fatalf("admitted evidence = %+v, want OCSP with responder containment and exactly two certificates", w.input.Objects)
	}
	if got := input.Objects[0]; got.Kind != historicalproof.Data || len(got.Contains) != 0 {
		t.Errorf("caller OCSP object changed after admission: kind = %s, contains = %x", got.Kind, got.Contains)
	}
}

func TestPrepareTimestampsEnforcesAggregateCoverageBudget(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	now := testcert.Now()
	firstData, secondData := []byte("first object"), []byte("second object")
	first := issuer.issueStamp(t, 1, now.Add(-time.Minute), new(time.Duration), false, firstData)
	second := issuer.issueStamp(t, 2, now.Add(-time.Minute), new(time.Duration), false, secondData)
	first.candidate.Covered = [][sha256.Size]byte{sha256.Sum256(firstData)}
	second.candidate.Covered = [][sha256.Size]byte{sha256.Sum256(secondData)}
	firstID, secondID := first.assertion.TokenSHA256(), second.assertion.TokenSHA256()

	for _, tc := range []struct {
		name    string
		max     int
		want    [][sha256.Size]byte
		wantErr error
	}{
		{"at_limit", 2, [][sha256.Size]byte{firstID, secondID}, nil},
		{"over_limit", 1, [][sha256.Size]byte{firstID}, ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := validationWorkflow{
				ctx: t.Context(), now: now, report: &Report{},
				config: Config{MaxEdges: tc.max, TSA: issuer.verifier},
				input:  Input{Timestamps: []Candidate{first.candidate, second.candidate}},
			}
			if err := w.prepareTimestamps(); !errors.Is(err, tc.wantErr) {
				t.Fatalf("prepareTimestamps with %d edges = %v, want %v", tc.max, err, tc.wantErr)
			}
			got := make([][sha256.Size]byte, 0, len(w.prepared))
			for _, stamp := range w.prepared {
				got = append(got, stamp.assertion.TokenSHA256())
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("prepared timestamp identities = %x, want %x", got, tc.want)
			}
			_, admitted := w.admitted[secondID]
			if admitted != (tc.wantErr == nil) {
				t.Errorf("second timestamp admitted = %t with error %v", admitted, tc.wantErr)
			}
		})
	}
}

func TestProcessTimestampsRejectsInvertedArchiveChronology(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	now := testcert.Now()
	data := []byte("exact signed bytes")
	signatureID := sha256.Sum256(data)
	protected := issuer.issueStamp(t, 1, now.Add(-time.Minute), new(time.Duration), false, data)
	protected.candidate.Covered = [][sha256.Size]byte{signatureID}
	protectedID := protected.assertion.TokenSHA256()
	archive := issuer.issueStamp(t, 2, now.Add(-2*time.Minute), new(time.Duration), false, protected.candidate.Token.DER())
	archive.candidate.Archive = true
	archive.candidate.Covered = [][sha256.Size]byte{protectedID}
	archiveID := archive.assertion.TokenSHA256()
	crl := testcert.CRL(t, issuer.chain)

	for _, tc := range []struct {
		name     string
		required bool
		wantErr  error
		wantSub  string
	}{
		{"optional", false, nil, ""},
		{"required", true, ErrValidation, timestampOrderFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			session, err := issuer.verifier.NewHistoricalSession(t.Context(), pki.HistoricalOptions{}, now, pki.Evidence{CRLs: [][]byte{crl}})
			if err != nil {
				t.Fatal(err)
			}
			g := timestampGraph(protected, archive)
			g.objects[signatureID] = Object{Bytes: data, Kind: historicalproof.Signature}
			g.facts = []historicalproof.Fact{
				{Digest: signatureID, At: now, Kind: historicalproof.Signature},
				{Digest: archiveID, At: now, Kind: historicalproof.Timestamp},
				{Digest: protectedID, At: now, Kind: historicalproof.Timestamp},
			}
			w := validationWorkflow{
				ctx: t.Context(), now: now, graph: g, report: &Report{}, tsaSession: session,
				config: Config{RequireAllTimestamps: tc.required}, input: Input{Signature: signatureID},
				prepared: []preparedStamp{archive, protected},
			}
			if err := w.processTimestamps(); !errors.Is(err, tc.wantErr) {
				t.Fatalf("processTimestamps = %v, want %v", err, tc.wantErr)
			}
			stamps := w.report.Stamps
			if len(stamps) != 2 || stamps[0].Token != archiveID || stamps[0].Indication != Passed ||
				stamps[1].Token != protectedID || stamps[1].Indication != Indeterminate || stamps[1].SubIndication != timestampOrderFailure {
				t.Fatalf("timestamp decisions = %+v, want passing archive followed by chronology refusal", stamps)
			}
			if w.report.SubIndication != tc.wantSub || !w.report.Best.Equal(now) {
				t.Errorf("workflow sub-indication = %q, best = %v, want %q and %v", w.report.SubIndication, w.report.Best, tc.wantSub, now)
			}
			if steps := w.report.Steps; len(steps) != 1 || steps[0].Source != archiveID || steps[0].Action != stageExtractExactObjectPoe {
				t.Errorf("proof extraction steps = %+v, want a single step from the archive", steps)
			}
		})
	}
}

func TestValidateStampHonorsTrustAnchorSunset(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	now := testcert.Now()
	stamp := issuer.issueStamp(t, 1, now.Add(-time.Minute), new(time.Duration), false, []byte("timestamped document"))
	tokenID := stamp.assertion.TokenSHA256()
	anchorID := fmt.Sprintf("%x", sha256.Sum256(issuer.chain.Root.Raw))
	crl := testcert.CRL(t, issuer.chain)
	proofs := newProofSet(t, historicalproof.Fact{Digest: tokenID, At: now, Kind: historicalproof.Timestamp})

	for _, tc := range []struct {
		name       string
		sunset     time.Time
		wantStatus Indication
		wantSub    string
		wantErr    error
	}{
		{"before_sunset", now.Add(time.Nanosecond), Passed, "", nil},
		{"at_sunset", now, Indeterminate, noChain, ErrValidation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			options := pki.HistoricalOptions{TrustAnchorSunsets: map[string]time.Time{anchorID: tc.sunset}}
			session, err := issuer.verifier.NewHistoricalSession(t.Context(), options, now, pki.Evidence{CRLs: [][]byte{crl}})
			if err != nil {
				t.Fatal(err)
			}
			got, err := validateStamp(t.Context(), Config{TSAHistory: options}, stamp, now, session, proofs)
			if !errors.Is(err, tc.wantErr) || got.Indication != tc.wantStatus || got.SubIndication != tc.wantSub {
				t.Fatalf("validateStamp = %+v, %v, want indication %v, sub-indication %q, error %v", got, err, tc.wantStatus, tc.wantSub, tc.wantErr)
			}
			if got.Token != tokenID || !got.Best.Equal(now) {
				t.Errorf("stamp identity = %x, best time = %v, want %x at %v", got.Token, got.Best, tokenID, now)
			}
			wantValidation := now
			if tc.wantErr != nil {
				wantValidation = time.Time{}
			}
			if got.Path != nil || !got.Validation.Equal(wantValidation) {
				t.Errorf("stamp validation = %v, path = %v, want %v and no past path", got.Validation, got.Path, wantValidation)
			}
		})
	}
}

func TestVerifySignerRejectsProofBeforeCertificateIssuance(t *testing.T) {
	t.Parallel()

	now := testcert.Now()
	w := validationWorkflow{
		ctx: t.Context(), now: now,
		certificate: &x509.Certificate{NotBefore: now.Add(-time.Hour)},
		report:      &Report{Best: now.Add(-time.Hour - time.Nanosecond)},
	}
	if err := w.verifySigner(); !errors.Is(err, ErrValidation) {
		t.Fatalf("verifySigner = %v, want %v", err, ErrValidation)
	}
	if w.report.Indication != Failed || w.report.SubIndication != codeNotYetValid || w.report.Current != nil || w.report.Past != nil {
		t.Errorf("report = %+v, want before-issuance failure without an accepted signer", w.report)
	}
}

func testWorkflowConfig(t testing.TB) Config {
	t.Helper()
	chain := testcert.New(t)
	signer, err := pki.NewVerifier(pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{{1, 2, 3, 4}}})
	if err != nil {
		t.Fatal(err)
	}
	return Config{Signer: signer, TSA: tsa}
}

// Independent linear oracle retained from the pre-memo helper. These tests check
// admission state, not acceptance/authentication of an entire historical Input.
func linearAdmissionOracle(objects []Object, raw []byte, kind historicalproof.Kind) []Object {
	digest := sha256.Sum256(raw)
	for index, object := range objects {
		if sha256.Sum256(object.Bytes) == digest {
			if object.Kind == objectData {
				objects[index].Kind = kind
			}
			return objects
		}
	}
	return append(objects, Object{Bytes: raw, Kind: kind})
}

func checkAdmissionObjects(t *testing.T, got, want []Object) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("admission changed order/bytes/kind/metadata: got%+v want%+v", got, want)
	}
	for i := range got {
		if len(got[i].Bytes) > 0 && &got[i].Bytes[0] != &want[i].Bytes[0] {
			t.Fatalf("object%d copied or replaced first bytes", i)
		}
		if len(got[i].Contains) > 0 && &got[i].Contains[0] != &want[i].Contains[0] {
			t.Fatalf("object%d copied containment", i)
		}
		if len(got[i].Refs) > 0 && &got[i].Refs[0] != &want[i].Refs[0] {
			t.Fatalf("object%d copied references", i)
		}
	}
}

func TestAdmissionPrefixMatchesLinearFirstOccurrence(t *testing.T) {
	chain := testcert.New(t)
	certificate := chain.Leaf.Raw
	child := sha256.Sum256(certificate)
	parent := []byte(`<r><certificate>` + base64.StdEncoding.EncodeToString(certificate) + `</certificate><digest>` + base64.StdEncoding.EncodeToString(child[:]) + `</digest></r>`)
	metadata := Object{Bytes: parent, Kind: objectData, Contains: [][32]byte{child}, Refs: []HashReference{{Hash: crypto.SHA256, Digest: child[:], Target: child}}}
	initial := []Object{{Bytes: certificate, Kind: objectData}, {Bytes: bytes.Clone(certificate), Kind: historicalproof.Certificate}, metadata}
	want := slices.Clone(initial)
	w := validationWorkflow{input: Input{Objects: slices.Clone(initial)}}
	for _, step := range []struct {
		raw  []byte
		kind historicalproof.Kind
	}{
		{bytes.Clone(certificate), historicalproof.Certificate},
		{parent, objectData},
		{certificate, objectData},
		{[]byte("new exact data object"), objectData},
		{parent, objectData},
	} {
		want = linearAdmissionOracle(want, step.raw, step.kind)
		w.admit(step.raw, step.kind)
		checkAdmissionObjects(t, w.input.Objects, want)
	}
	if w.admitted[child] != 0 || w.input.Objects[0].Kind != historicalproof.Certificate || w.input.Objects[1].Kind != historicalproof.Certificate {
		t.Fatal("first duplicate promotion or retained non-Data kind changed")
	}
}

func TestAdmissionPrefixDoesNotSeedEarlyHitTail(t *testing.T) {
	raw := [][]byte{[]byte("first"), []byte("middle"), []byte("last"), []byte("miss")}
	initial := []Object{{Bytes: raw[0], Kind: objectData}, {Bytes: raw[1], Kind: objectData}, {Bytes: raw[2], Kind: objectData}}
	w := validationWorkflow{input: Input{Objects: slices.Clone(initial)}}
	want := slices.Clone(initial)
	for i, position := range []int{0, 0, 2, 3, 0, 1} {
		w.admit(raw[position], objectData)
		want = linearAdmissionOracle(want, raw[position], objectData)
		checkAdmissionObjects(t, w.input.Objects, want)
		if i < 2 && (w.admittedPrefix != 1 || len(w.admitted) != 1) {
			t.Fatal("first hit scanned or memoized the tail", w.admittedPrefix, len(w.admitted))
		}
	}
	if w.admittedPrefix != len(w.input.Objects) || len(w.admitted) != 4 {
		t.Fatal("late hit/miss did not complete the prefix")
	}
}

func TestAdmissionPrefixKeepsContainmentFirstParent(t *testing.T) {
	certificate := testcert.New(t).Leaf.Raw
	child := sha256.Sum256(certificate)
	parent := []byte(`<r><certificate>` + base64.StdEncoding.EncodeToString(certificate) + `</certificate></r>`)
	parentKey := sha256.Sum256(parent)
	initial := []Object{{Bytes: parent, Kind: objectData}, {Bytes: bytes.Clone(parent), Kind: objectData}}
	w := validationWorkflow{input: Input{Objects: slices.Clone(initial)}}
	w.containCertificates(parentKey, [][]byte{certificate})
	if len(w.input.Objects) != 3 || !slices.Equal(w.input.Objects[0].Contains, [][32]byte{child}) || len(w.input.Objects[1].Contains) != 0 {
		t.Fatal("legacy first-parent containment changed", w.input.Objects)
	}
	if &w.input.Objects[0].Bytes[0] != &initial[0].Bytes[0] || &w.input.Objects[1].Bytes[0] != &initial[1].Bytes[0] || &w.input.Objects[2].Bytes[0] != &certificate[0] {
		t.Fatal("containment changed byte ownership")
	}
	if w.admitted[parentKey] != 0 {
		t.Fatal("duplicate parent replaced the first memo position")
	}
}

func TestAdmissionPrefixIsLocalToWorkflow(t *testing.T) {
	a, b := []byte("a"), []byte("b")
	first := validationWorkflow{input: Input{Objects: []Object{{Bytes: a, Kind: objectData}}}}
	second := validationWorkflow{input: Input{Objects: []Object{{Bytes: b, Kind: objectData}}}}
	first.admit(a, objectData)
	first.admit(b, objectData)
	second.admit(b, objectData)
	second.admit(a, objectData)
	checkAdmissionObjects(t, first.input.Objects, []Object{{Bytes: a, Kind: objectData}, {Bytes: b, Kind: objectData}})
	checkAdmissionObjects(t, second.input.Objects, []Object{{Bytes: b, Kind: objectData}, {Bytes: a, Kind: objectData}})
	if first.admitted[sha256.Sum256(a)] != 0 || second.admitted[sha256.Sum256(a)] != 1 {
		t.Fatal("workflow indexes leaked positions")
	}
}

func historicalLimitCertificates(t testing.TB, chain testcert.Chain, count, padding int) [][]byte {
	t.Helper()
	var extra []pkix.Extension
	if padding > 0 {
		value, err := asn1.Marshal(bytes.Repeat([]byte{7}, padding))
		if err != nil {
			t.Fatal(err)
		}
		extra = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}, Value: value}}
	}
	raw := make([][]byte, count)
	seen := map[[32]byte]bool{sha256.Sum256(chain.Leaf.Raw): true}
	total := 0
	for i := range raw {
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(10000 + i)), Subject: pkix.Name{CommonName: fmt.Sprintf("bounded preflight certificate %d", i)}, NotBefore: chain.Leaf.NotBefore, NotAfter: chain.Leaf.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, ExtraExtensions: extra}
		cert := testcert.Issue(t, template, chain.Root, chain.LeafKey.Public(), chain.RootKey)
		if err := cert.CheckSignatureFrom(chain.Root); err != nil {
			t.Fatal(err)
		}
		raw[i] = cert.Raw
		key := sha256.Sum256(raw[i])
		if seen[key] {
			t.Fatal("fixture DER identities must be distinct")
		}
		seen[key] = true
		total += len(raw[i])
	}
	if total > 128<<10 {
		t.Fatal("fixture must remain below128KiB")
	}
	return raw
}

func historicalLimitWorkflow(t *testing.T, chain testcert.Chain, group string, raw [][]byte, maximum int) validationWorkflow {
	t.Helper()
	policy := pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL, MaxEvidenceBytes: maximum, MaxCRLs: 1, MaxOCSPResponses: 1}
	signer, err := pki.NewVerifier(policy)
	if err != nil {
		t.Fatal(err)
	}
	tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: policy, AllowedPolicies: []asn1.ObjectIdentifier{{1, 2, 3, 4}}})
	if err != nil {
		t.Fatal(err)
	}
	signature := []byte("already authenticated format adapter signature")
	w := validationWorkflow{ctx: t.Context(), config: Config{Signer: signer, TSA: tsa}, now: testcert.Now(), report: &Report{}, input: Input{Signature: sha256.Sum256(signature), Certificate: bytes.Clone(chain.Leaf.Raw), SignatureMethod: chain.Leaf.SignatureAlgorithm, Hashes: []crypto.Hash{crypto.SHA256}, Objects: []Object{{Bytes: signature, Kind: historicalproof.Signature}}}}
	if group == "signer" {
		w.signerEvidence.Intermediates = raw
	} else {
		w.tsaEvidence.Intermediates = raw
	}
	return w
}

// Invalid raw Evidence must not populate the pregraph object set.
func TestEvidenceLimitsBeforeAdmission(t *testing.T) {
	chain := testcert.New(t)
	counted := historicalLimitCertificates(t, chain, 65, 0)
	padded := historicalLimitCertificates(t, chain, 2, 2048)
	sum := len(padded[0]) + len(padded[1])
	cases := []struct {
		name    string
		raw     [][]byte
		maximum int
		over    bool
	}{
		{"count64", counted[:64], 128 << 10, false},
		{"count65", counted, 128 << 10, true},
		{"bytes_exact", padded, sum, false},
		{"bytes_over_one", padded, sum - 1, true},
	}
	for _, group := range []string{"signer", "TSA"} {
		for _, tc := range cases {
			t.Run(group+"/"+tc.name, func(t *testing.T) {
				w := historicalLimitWorkflow(t, chain, group, tc.raw, tc.maximum)
				snapshots := make([][]byte, len(tc.raw))
				for i, b := range tc.raw {
					snapshots[i] = bytes.Clone(b)
				}
				defer func() {
					for i, b := range tc.raw {
						if !bytes.Equal(b, snapshots[i]) {
							t.Errorf("caller DER%d changed", i)
						}
					}
				}()
				e := pki.Evidence{Intermediates: tc.raw}
				var directErr error
				if group == "signer" {
					_, directErr = w.config.Signer.NewHistoricalSession(t.Context(), w.config.SignerHistory, w.now, e)
				} else {
					_, directErr = w.config.TSA.NewHistoricalSession(t.Context(), w.config.TSAHistory, w.now, e)
				}
				if tc.over {
					if !errors.Is(directErr, pki.ErrLimit) {
						t.Fatalf("direct session should reject configured bound: %v", directErr)
					}
				} else if directErr != nil {
					t.Fatal("direct session positive control", directErr)
				}
				before := len(w.input.Objects)
				if err := w.initialize(); err != nil {
					if tc.over && errors.Is(err, pki.ErrLimit) && len(w.input.Objects) == before && w.report.Proofs == nil && w.report.Current == nil && w.report.Past == nil {
						return
					}
					t.Fatal("initialize", err)
				}
				err := w.admitEvidence()
				t.Logf("validDER=%d bytes=%d cap=%d beforeObjects=%d afterObjects=%d admission=%v directSession=%v", len(tc.raw), historicalLimitBytes(tc.raw), tc.maximum, before, len(w.input.Objects), err, directErr)
				if tc.over {
					if (!errors.Is(err, pki.ErrLimit) && !errors.Is(err, ErrLimit)) || len(w.input.Objects) != before {
						t.Fatalf("over-limit DER reached admitted state before session guard: objects=%d->%d err=%v", before, len(w.input.Objects), err)
					}
				} else if err != nil || len(w.input.Objects) != before+1+len(tc.raw) {
					t.Fatalf("positive admission: objects=%d err=%v", len(w.input.Objects), err)
				}
			})
		}
	}
}

func historicalLimitBytes(raw [][]byte) int {
	total := 0
	for _, b := range raw {
		total += len(b)
	}
	return total
}

func TestEvidenceLimitsStillCheckTimestampAdditions(t *testing.T) {
	issuer := newTimestampIssuer(t)
	raw := make([][]byte, 64)
	for i := range raw {
		raw[i] = issuer.chain.Root.Raw
	}
	w := historicalLimitWorkflow(t, issuer.chain, "TSA", raw, 128<<10)
	zero := time.Duration(0)
	w.config.MissingAccuracy = &zero
	stamp := issuer.issueStamp(t, 17, testcert.Now().Add(-time.Second), &zero, false, w.input.Objects[0].Bytes)
	stamp.candidate.Covered = [][32]byte{w.input.Signature}
	w.input.Timestamps = []Candidate{stamp.candidate}
	if err := w.initialize(); err != nil {
		t.Fatal("initial64 evidence", err)
	}
	if err := w.admitEvidence(); err != nil {
		t.Fatal(err)
	}
	if err := w.prepareTimestamps(); err != nil {
		t.Fatal("timestamp preparation", err)
	}
	if len(w.prepared) != 1 || len(w.tsaEvidence.Intermediates) <= 64 {
		t.Fatal("fixture did not add an authenticated token certificate")
	}
	if err := w.preparePaths(); !errors.Is(err, pki.ErrLimit) {
		t.Fatal("late session bound lost", err)
	}
	if w.graph != nil || w.report.Proofs != nil || w.report.Current != nil || w.report.Past != nil {
		t.Fatal("late limit published acceptance")
	}
	if len(raw) != 64 {
		t.Fatal("caller evidence slice changed")
	}
}

func TestEvidenceLimitsBeforeRevocationInspection(t *testing.T) {
	chain := testcert.New(t)
	crl := testcert.CRL(t, chain)
	for _, group := range []string{"signer", "TSA"} {
		for _, kind := range []string{"CRL", "OCSP"} {
			t.Run(group+"/"+kind, func(t *testing.T) {
				w := historicalLimitWorkflow(t, chain, group, nil, 128<<10)
				target := &w.signerEvidence
				if group == "TSA" {
					target = &w.tsaEvidence
				}
				if kind == "CRL" {
					target.CRLs = [][]byte{crl, crl}
				} else {
					target.OCSPResponses = [][]byte{{0x30, 0}, {0x30, 0}}
				}
				before := len(w.input.Objects)
				if err := w.initialize(); !errors.Is(err, pki.ErrLimit) || len(w.input.Objects) != before {
					t.Fatal("configured count checked after admission/inspection", kind, err, len(w.input.Objects))
				}
			})
		}
		t.Run(group+"/under-limit OCSP still inspected", func(t *testing.T) {
			w := historicalLimitWorkflow(t, chain, group, nil, 128<<10)
			if group == "TSA" {
				w.tsaEvidence.OCSPResponses = [][]byte{{0x30, 0}}
			} else {
				w.signerEvidence.OCSPResponses = [][]byte{{0x30, 0}}
			}
			if err := w.initialize(); err != nil {
				t.Fatal("under-limit metadata", err)
			}
			if err := w.admitEvidence(); !errors.Is(err, pki.ErrEvidence) || errors.Is(err, pki.ErrLimit) {
				t.Fatal("under-limit material parser changed", err)
			}
		})
	}
}

func TestWorkflowTimestampSourcesRetainCountLimit(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	signer, err := pki.NewVerifier(pki.Config{Roots: [][]byte{issuer.chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	signatureBytes := []byte("authenticated format signature encoding")
	signature := sha256.Sum256(signatureBytes)
	stamp := issuer.issueStamp(t, 1, testcert.Now().Add(-30*time.Second), new(time.Duration(0)), false, signatureBytes)
	stamp.candidate.Covered = [][32]byte{signature}
	source, err := evidence.NewObservation(t.Context(), evidence.Timestamp, stamp.candidate.Token.DER(), evidence.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	input := Input{
		Signature: signature, Certificate: issuer.chain.Leaf.Raw, SignatureMethod: issuer.chain.Leaf.SignatureAlgorithm,
		Hashes: []crypto.Hash{crypto.SHA256}, Objects: []Object{{Bytes: signatureBytes, Kind: historicalproof.Signature}},
		Timestamps: []Candidate{stamp.candidate},
	}
	crl := testcert.CRL(t, issuer.chain)
	for _, count := range []int{1024, 1025} {
		for _, group := range []string{"signer", "TSA"} {
			t.Run(group+"/"+strconv.Itoa(count), func(t *testing.T) {
				t.Parallel()

				sources := make([]*evidence.Observation, count)
				for index := range sources {
					sources[index] = source
				}
				signerEvidence, tsaEvidence := pki.Evidence{CRLs: [][]byte{crl}}, pki.Evidence{CRLs: [][]byte{crl}}
				if group == "signer" {
					signerEvidence.Sources = sources
				} else {
					tsaEvidence.Sources = sources
				}
				report, err := Validate(t.Context(), Config{Signer: signer, TSA: issuer.verifier}, input, testcert.Now(), signerEvidence, tsaEvidence)
				if count == 1024 {
					if err != nil || report.Indication != Passed || report.Current == nil || len(report.Stamps) != 1 || report.Stamps[0].Indication != Passed {
						t.Fatal("permitted observations changed valid signed-input acceptance", report, err)
					}

					return
				}
				// Verification reports retain diagnostics on failure.
				//noinspection GoDfaErrorMayBeNotNil
				if !errors.Is(err, ErrLimit) || report.Indication == Passed || !errors.Is(report.Cause, ErrLimit) || report.Current != nil || report.Past != nil || report.Proofs != nil {
					t.Fatal("timestamp filtering bypassed evidence source count", report, err)
				}
				if len(sources) != count || sources[0] != source || sources[len(sources)-1] != source {
					t.Fatal("source filtering mutated caller observations")
				}
			})
		}
	}
}
