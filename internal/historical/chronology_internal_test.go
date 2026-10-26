package historical

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

type timestampIssuer struct {
	chain    testcert.Chain
	verifier *timestamp.Verifier
}

func newTimestampIssuer(t *testing.T) timestampIssuer {
	t.Helper()
	chain := testcert.New(t)
	verifier, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{{1, 2, 3, 4}}})
	if err != nil {
		t.Fatal(err)
	}
	return timestampIssuer{chain, verifier}
}

// Assertions are authenticated RFC3161 tokens, not fabricated opaque objects.
// This fixture grants no PKIX or historical trust to the TSA's claims.
func (issuer timestampIssuer) issueStamp(t *testing.T, serial int64, at time.Time, accuracy *time.Duration, ordering bool, payload []byte) preparedStamp {
	t.Helper()
	request, err := timestamp.CreateRequest(t.Context(), payload, timestamp.RequestOptions{OmitNonce: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := timestamp.IssueResponse(t.Context(), request.DER(), issuer.chain.TSAKey, issuer.chain.TSA.Raw, timestamp.IssueOptions{SerialNumber: big.NewInt(serial), GenTime: at, Accuracy: accuracy, Ordering: ordering, Policy: asn1.ObjectIdentifier{1, 2, 3, 4}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := timestamp.ParseResponse(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	token, err := timestamp.ParseToken(t.Context(), response.TokenDER())
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := issuer.verifier.Authenticate(t.Context(), token, timestamp.Expectation{Imprint: request.Imprint()}, testcert.Now())
	if err != nil {
		t.Fatal(err)
	}
	upper := at
	if accuracy != nil {
		upper = upper.Add(*accuracy)
	}
	return preparedStamp{candidate: Candidate{Token: token, Imprint: request.Imprint()}, assertion: assertion, upper: upper, certificate: issuer.chain.TSA}
}

func timestampGraph(stamps ...preparedStamp) *graph {
	g := &graph{objects: make(map[[32]byte]Object), maximum: 32, now: testcert.Now()}
	for _, stamp := range stamps {
		g.objects[stamp.assertion.TokenSHA256()] = Object{Bytes: stamp.candidate.Token.DER(), Kind: historicalproof.Timestamp}
	}
	return g
}

func TestTimestampTopologicalOrderPrecedesGenerationTime(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	accuracy := 2 * time.Minute
	child := issuer.issueStamp(t, 1, testcert.Now().Add(-9*time.Minute), &accuracy, false, []byte("signature input"))
	archive := issuer.issueStamp(t, 2, testcert.Now().Add(-10*time.Minute), &accuracy, false, child.candidate.Token.DER())
	archive.candidate.Archive = true
	archive.candidate.Covered = [][32]byte{child.assertion.TokenSHA256()}
	independent := issuer.issueStamp(t, 3, testcert.Now().Add(-8*time.Minute), &accuracy, false, []byte("other signature input"))
	input := []preparedStamp{child, archive, independent}
	ordered, err := orderStamps(t.Context(), timestampGraph(input...), input)
	if err != nil {
		t.Fatal(err)
	}
	want := [][32]byte{independent.assertion.TokenSHA256(), archive.assertion.TokenSHA256(), child.assertion.TokenSHA256()}
	got := make([][32]byte, 0, len(ordered))
	for _, stamp := range ordered {
		got = append(got, stamp.assertion.TokenSHA256())
	}
	if !slices.Equal(got, want) {
		t.Fatal("generation sorting reversed a protecting dependency", got, want)
	}
	if input[0].assertion.TokenSHA256() != child.assertion.TokenSHA256() {
		t.Fatal("ordering mutated caller input")
	}
	// Independent equal-time tokens have a stable bytewise identity tie-break.
	tie := issuer.issueStamp(t, 4, independent.assertion.Info().GenTime(), &accuracy, false, []byte("tie input"))
	ordered, err = orderStamps(t.Context(), timestampGraph(independent, tie), []preparedStamp{independent, tie})
	if err != nil {
		t.Fatal(err)
	}
	first, second := independent.assertion.TokenSHA256(), tie.assertion.TokenSHA256()
	if bytes.Compare(first[:], second[:]) > 0 {
		first, second = second, first
	}
	if ordered[0].assertion.TokenSHA256() != first || ordered[1].assertion.TokenSHA256() != second {
		t.Fatal("equal-time token identity order changed")
	}
}

func TestTimestampOrderingRejectsInvalidCoverageCyclesAndCancellation(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	first := issuer.issueStamp(t, 1, testcert.Now().Add(-time.Minute), nil, false, []byte("first"))
	second := issuer.issueStamp(t, 2, testcert.Now().Add(-time.Minute), nil, false, []byte("second"))
	for _, test := range []struct {
		name          string
		covered       [][32]byte
		secondCovered [][32]byte
	}{
		{"self", [][32]byte{first.assertion.TokenSHA256()}, nil},
		{"missing", [][32]byte{sha256.Sum256([]byte("unadmitted"))}, nil},
		{"cycle", [][32]byte{second.assertion.TokenSHA256()}, [][32]byte{first.assertion.TokenSHA256()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			a, b := first, second
			a.candidate.Covered = test.covered
			b.candidate.Covered = test.secondCovered
			if result, err := orderStamps(t.Context(), timestampGraph(a, b), []preparedStamp{a, b}); result != nil || !errors.Is(err, ErrInput) {
				t.Fatal("malformed adapter coverage accepted", result, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := orderStamps(ctx, timestampGraph(first), []preparedStamp{first}); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled ordering produced candidates", result, err)
	}
}

func TestCoveredObjectsFollowContainmentAndUniqueObjectBudget(t *testing.T) {
	t.Parallel()

	root, leaf := sha256.Sum256([]byte("container")), sha256.Sum256([]byte("contained bytes"))
	g := &graph{maximum: 2, objects: map[[32]byte]Object{root: {Contains: [][32]byte{leaf}}, leaf: {}}}
	candidate := Candidate{Covered: [][32]byte{root, root}}
	covered, err := g.covered(t.Context(), candidate)
	if err != nil || len(covered) != 2 {
		t.Fatal("duplicate coverage consumed the unique-object budget", covered, err)
	}
	if _, ok := covered[leaf]; !ok {
		t.Fatal("transitive exact object was omitted")
	}
	g.maximum = 1
	if got, err := g.covered(t.Context(), candidate); got != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("coverage budget exceeded silently", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := g.covered(ctx, candidate); !errors.Is(err, context.Canceled) {
		t.Fatal("coverage ignored cancellation", err)
	}
}

func TestProtectedTokenChronologyUsesIntervalsAndAuthenticatedOrdering(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	accuracy := time.Second
	protected := issuer.issueStamp(t, 1, testcert.Now().Add(-time.Minute), &accuracy, false, []byte("protected"))
	covering := issuer.issueStamp(t, 2, protected.assertion.Info().GenTime().Add(-2*time.Second), &accuracy, false, protected.candidate.Token.DER())
	covering.candidate.Covered = [][32]byte{protected.assertion.TokenSHA256()}
	g := timestampGraph(protected, covering)
	if err := checkProtectedChronology(t.Context(), g, protected, []preparedStamp{covering}); err != nil {
		t.Fatal("touching accuracy intervals were rejected", err)
	}
	tooEarly := issuer.issueStamp(t, 5, covering.assertion.Info().GenTime().Add(-time.Nanosecond), &accuracy, false, protected.candidate.Token.DER())
	tooEarly.candidate.Covered = covering.candidate.Covered
	if err := checkProtectedChronology(t.Context(), g, protected, []preparedStamp{tooEarly}); !errors.Is(err, ErrValidation) {
		t.Fatal("non-overlapping impossible archive order accepted", err)
	}
	orderedChild := issuer.issueStamp(t, 3, protected.assertion.Info().GenTime(), &accuracy, true, []byte("ordered child"))
	orderedArchive := issuer.issueStamp(t, 4, covering.assertion.Info().GenTime(), &accuracy, true, orderedChild.candidate.Token.DER())
	orderedArchive.candidate.Covered = [][32]byte{orderedChild.assertion.TokenSHA256()}
	if err := checkProtectedChronology(t.Context(), timestampGraph(orderedChild, orderedArchive), orderedChild, []preparedStamp{orderedArchive}); !errors.Is(err, ErrValidation) {
		t.Fatal("same-TSA Ordering claim did not forbid inverted generation", err)
	}
	independent := orderedArchive
	independent.candidate.Covered = nil
	if err := checkProtectedChronology(t.Context(), g, protected, []preparedStamp{independent}); err != nil {
		t.Fatal("unrelated token constrained chronology", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := checkProtectedChronology(ctx, g, protected, []preparedStamp{covering}); !errors.Is(err, context.Canceled) {
		t.Fatal("chronology ignored coverage cancellation", err)
	}
}

func TestContentTimestampChronologyRequiresStrictPrecedence(t *testing.T) {
	t.Parallel()

	issuer := newTimestampIssuer(t)
	accuracy := time.Minute
	signature := issuer.issueStamp(t, 1, testcert.Now().Add(-5*time.Minute), &accuracy, true, []byte("signature"))
	content := issuer.issueStamp(t, 2, signature.assertion.Info().GenTime().Add(-time.Second), &accuracy, true, []byte("content"))
	content.candidate.Content = true
	if err := checkContentChronology(content, []preparedStamp{signature}); err != nil {
		t.Fatal("same-TSA ordered content was rejected despite overlapping accuracy", err)
	}
	equal := issuer.issueStamp(t, 3, signature.assertion.Info().GenTime(), &accuracy, true, []byte("equal content"))
	equal.candidate.Content = true
	if err := checkContentChronology(equal, []preparedStamp{signature}); !errors.Is(err, ErrValidation) {
		t.Fatal("equal ordered generation times accepted", err)
	}
	unord := issuer.issueStamp(t, 4, content.assertion.Info().GenTime(), &accuracy, false, []byte("unordered content"))
	unord.candidate.Content = true
	if err := checkContentChronology(unord, []preparedStamp{signature}); !errors.Is(err, ErrValidation) {
		t.Fatal("overlapping intervals without Ordering were accepted", err)
	}
	before := issuer.issueStamp(t, 5, signature.assertion.Info().GenTime().Add(-2*accuracy-time.Nanosecond), &accuracy, false, []byte("separated content"))
	before.candidate.Content = true
	if err := checkContentChronology(signature, []preparedStamp{before}); err != nil {
		t.Fatal("strictly separated intervals rejected in reverse argument order", err)
	}
	edge := issuer.issueStamp(t, 6, signature.assertion.Info().GenTime().Add(-2*accuracy), &accuracy, false, []byte("touching content"))
	edge.candidate.Content = true
	if err := checkContentChronology(signature, []preparedStamp{edge}); !errors.Is(err, ErrValidation) {
		t.Fatal("touching content/signature intervals accepted", err)
	}
	archive := content
	archive.candidate.Archive = true
	if err := checkContentChronology(archive, []preparedStamp{signature}); err != nil {
		t.Fatal("archive was treated as a content/signature pair", err)
	}
	if err := checkContentChronology(signature, []preparedStamp{signature}); err != nil {
		t.Fatal("same-class tokens constrained each other", err)
	}
}
