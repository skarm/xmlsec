package historical //nolint:testpackage // Exercises internal past signature recovery branches.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
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

func TestPastSignatureStopsAtProofBeforeCertificateIssuance(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	now := testcert.Now()
	crl := testcert.CRL(t, chain)
	session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{
		Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL,
	}}, now, pki.Evidence{CRLs: [][]byte{crl}})
	if err != nil {
		t.Fatal(err)
	}
	material := signedMaterial{
		digest: sha256.Sum256([]byte("exact signature encoding")), certificate: chain.Leaf.Raw, algorithm: x509.ECDSAWithSHA256,
	}
	before := chain.Leaf.NotBefore.Add(-time.Nanosecond)
	proofs := newProofSet(t,
		historicalproof.Fact{Digest: sha256.Sum256(chain.Root.Raw), Kind: historicalproof.Certificate, At: now},
		historicalproof.Fact{Digest: sha256.Sum256(chain.Leaf.Raw), Kind: historicalproof.Certificate, At: now},
		historicalproof.Fact{Digest: sha256.Sum256(crl), Kind: historicalproof.CRL, At: now},
		historicalproof.Fact{Digest: material.digest, Kind: historicalproof.Signature, At: before, Source: sha256.Sum256([]byte("archive token"))},
	)
	out := pastSignature(t.Context(), session, material, noChain, proofs, pki.HistoricalOptions{})
	if out.indication != Failed || out.sub != codeNotYetValid || !out.best.Equal(before) || out.result != nil || !errors.Is(out.err, ErrValidation) {
		t.Fatalf("past signature outcome = %+v, error = %v, want terminal not-yet-valid failure at %v", out, out.err, before)
	}
}

func TestCARevocationRecoveryRequiresTimelyLeafEvidence(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	now := testcert.Now()
	caKey := testcert.Key(t)
	issuer := testcert.Issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "archived issuer"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, chain.Root, caKey.Public(), chain.RootKey)
	leaf := testcert.Issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "archived signer"},
		NotBefore: now.Add(-12 * time.Hour), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}, issuer, chain.LeafKey.Public(), caKey)
	revokedAt := now.Add(-time.Hour)
	issuerCRL := testcert.CRL(t, chain, issuer)
	leafList := &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: now.Add(-2 * time.Hour), NextUpdate: now.Add(time.Hour)}
	leafCRL, err := x509.CreateRevocationList(rand.Reader, leafList, issuer, caKey)
	if err != nil {
		t.Fatal(err)
	}
	session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{
		Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL,
	}}, now, pki.Evidence{Intermediates: [][]byte{issuer.Raw}, CRLs: [][]byte{issuerCRL, leafCRL}})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := session.Paths(t.Context(), leaf.Raw)
	if err != nil || len(paths) != 1 {
		t.Fatalf("Paths = %d, %v; want one path", len(paths), err)
	}
	claims, err := session.AuthenticateEvidence(t.Context(), paths[0])
	if err != nil || len(claims) != 2 {
		t.Fatalf("AuthenticateEvidence = %d, %v; want both revocation claims", len(claims), err)
	}

	for _, tc := range []struct {
		name, wantSub string
		leafProof     time.Time
		best          time.Time
		wantAccept    bool
	}{
		{"proof_at_ca_revocation", revokedCA, revokedAt, revokedAt, true},
		{"proof_after_ca_revocation", revokedCA, revokedAt.Add(time.Nanosecond), revokedAt, false},
		{"proof_missing", revokedCA, time.Time{}, revokedAt, false},
		{"signature_after_leaf_expiry", outNotRevoked, revokedAt, leaf.NotAfter.Add(time.Nanosecond), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var facts []historicalproof.Fact
			if !tc.leafProof.IsZero() {
				facts = append(facts, historicalproof.Fact{
					Digest: sha256.Sum256(leafCRL), Source: sha256.Sum256([]byte("archive token")), At: tc.leafProof, Kind: historicalproof.CRL,
				})
			}
			evaluation := pastSignatureEvaluation{
				current: revokedCA, certificate: leaf, material: signedMaterial{certificate: leaf.Raw}, proofs: newProofSet(t, facts...),
			}
			out := pastOutcome{best: tc.best, sub: revokedCA}
			accept, terminal := evaluation.signatureProofRecovery(&out, claims)
			if accept != tc.wantAccept || terminal || out.sub != tc.wantSub {
				t.Errorf("recovery = (%t, %t, %q), want (%t, false, %q)", accept, terminal, out.sub, tc.wantAccept, tc.wantSub)
			}
		})
	}
}

func TestFreshForSignatureRequiresExplicitAgeWhenOCSPLacksNextUpdate(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	now := testcert.Now()
	thisUpdate := now.Add(-time.Minute)
	request, err := pki.CreateOCSPRequest(chain.Leaf.Raw, chain.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := pki.CreateOCSPResponse(t.Context(), request, chain.Leaf.Raw, chain.Root.Raw, chain.Root.Raw, chain.RootKey, pki.OCSPResponseTemplate{
		Status: pki.OCSPGood, ProducedAt: now, ThisUpdate: thisUpdate,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{
		Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireOCSP,
	}}, now, pki.Evidence{OCSPResponses: [][]byte{response}})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := session.Paths(t.Context(), chain.Leaf.Raw)
	if err != nil || len(paths) != 1 {
		t.Fatalf("Paths = %d, %v; want one path", len(paths), err)
	}
	claims, err := session.AuthenticateEvidence(t.Context(), paths[0])
	if err != nil || len(claims) != 1 || claims[0].AuthenticationStatus() != pki.Valid {
		t.Fatalf("AuthenticateEvidence = %v, %v; want one authenticated OCSP claim", claims, err)
	}
	for _, tc := range []struct {
		name    string
		maximum *time.Duration
		want    bool
	}{
		{"no_implicit_interval", nil, false},
		{"exact_explicit_age", new(time.Minute), false},
		{"within_explicit_age", new(time.Minute + time.Nanosecond), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := freshForSignature(chain.Leaf.Raw, claims, now, tc.maximum); got != tc.want {
				t.Errorf("freshForSignature = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestCryptoReliabilitySelectorsAndExclusiveCutoff(t *testing.T) {
	t.Parallel()

	cutoff := testcert.Now()
	certificate := &x509.Certificate{PublicKeyAlgorithm: x509.ECDSA, PublicKey: testcert.Key(t).Public()}
	for _, test := range []struct {
		name    string
		rule    pki.CryptoConstraint
		applies bool
	}{
		{"signature", pki.CryptoConstraint{SignatureAlgorithm: x509.ECDSAWithSHA256, ReliableUntil: cutoff}, true},
		{"different signature", pki.CryptoConstraint{SignatureAlgorithm: x509.SHA256WithRSA, ReliableUntil: cutoff}, false},
		{"hash", pki.CryptoConstraint{Hash: crypto.SHA256, ReliableUntil: cutoff}, true},
		{"different hash", pki.CryptoConstraint{Hash: crypto.SHA512, ReliableUntil: cutoff}, false},
		{"small key", pki.CryptoConstraint{PublicKeyAlgorithm: x509.ECDSA, MinimumKeyBits: 384, ReliableUntil: cutoff}, true},
		{"exact minimum key", pki.CryptoConstraint{PublicKeyAlgorithm: x509.ECDSA, MinimumKeyBits: 256, ReliableUntil: cutoff}, false},
		{"different key family", pki.CryptoConstraint{PublicKeyAlgorithm: x509.RSA, MinimumKeyBits: 3072, ReliableUntil: cutoff}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, at := range []time.Time{cutoff.Add(-time.Nanosecond), cutoff, cutoff.Add(time.Nanosecond)} {
				want := !test.applies || at.Before(cutoff)
				if got := signatureReliable(x509.ECDSAWithSHA256, crypto.SHA256, certificate, at, []pki.CryptoConstraint{test.rule}); got != want {
					t.Fatalf("signatureReliable at %s = %v; want %v", at, got, want)
				}
			}
		})
	}
	for _, test := range []struct {
		key  crypto.PublicKey
		bits int
	}{
		{&rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 2047), big.NewInt(1)), E: 65537}, 2048},
		{certificate.PublicKey, 256},
		{ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public(), 256},
		{(*rsa.PublicKey)(nil), 0},
		{&rsa.PublicKey{}, 0},
		{(*ecdsa.PublicKey)(nil), 0},
		{&ecdsa.PublicKey{}, 0},
		{struct{}{}, 0},
	} {
		if got := keyBits(test.key); got != test.bits {
			t.Fatalf("keyBits(%T) = %d; want %d", test.key, got, test.bits)
		}
	}
}

func newProofSet(t *testing.T, facts ...historicalproof.Fact) *historicalproof.Set {
	t.Helper()
	proofs, err := historicalproof.New(t.Context(), testcert.Now(), facts)
	if err != nil {
		t.Fatal(err)
	}
	return proofs
}

func TestHistoricalMaterialRequiresIndependentReferenceExistence(t *testing.T) { //nolint:tparallel // Subtests inspect material and rules that the parent subsequently mutates.
	t.Parallel()

	now := testcert.Now()
	cutoff := now.Add(-time.Hour)
	before := cutoff.Add(-time.Nanosecond)
	signature := sha256.Sum256([]byte("authenticated signature bytes"))
	reference := sha256.Sum256([]byte("independent reference input"))
	source := sha256.Sum256([]byte("separately validated archive token"))
	material := signedMaterial{digest: signature, algorithm: x509.ECDSAWithSHA256, hashes: []crypto.Hash{crypto.SHA512}, uses: []MaterialUse{{Object: reference, Hash: crypto.SHA256}}}
	rules := []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: cutoff}}
	for _, test := range []struct {
		name        string
		referenceAt time.Time
		want        bool
	}{
		{"signature proof cannot stand in for reference", time.Time{}, false},
		{"independent reference before cutoff", before, true},
		{"reference at cutoff", cutoff, false},
		{"reference after cutoff", cutoff.Add(time.Nanosecond), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := []historicalproof.Fact{{Digest: signature, Source: source, Kind: historicalproof.Signature, At: before}}
			if !test.referenceAt.IsZero() {
				facts = append(facts, historicalproof.Fact{Digest: reference, Source: source, Kind: historicalproof.Data, At: test.referenceAt})
			}
			if got := historicalMaterialReliable(material, nil, newProofSet(t, facts...), rules); got != test.want {
				t.Fatalf("historical material reliability = %v; want %v", got, test.want)
			}
		})
	}
	if historicalMaterialReliable(material, nil, newProofSet(t), rules) {
		t.Fatal("missing signature proof accepted")
	}
	material.uses = nil
	material.hashes = []crypto.Hash{crypto.SHA512, crypto.SHA256}
	proof := newProofSet(t, historicalproof.Fact{Digest: signature, Source: source, Kind: historicalproof.Signature, At: cutoff})
	if historicalMaterialReliable(material, nil, proof, rules) || materialReliable(material, nil, cutoff, rules) {
		t.Fatal("unreliable second hash was ignored")
	}
	if !materialReliable(material, nil, before, rules) {
		t.Fatal("reliable material before the cutoff rejected")
	}
	material.hashes = nil
	rules = []pki.CryptoConstraint{{SignatureAlgorithm: x509.ECDSAWithSHA256, ReliableUntil: cutoff}}
	if materialReliable(material, nil, cutoff, rules) || historicalMaterialReliable(material, nil, proof, rules) {
		t.Fatal("expired signature algorithm accepted")
	}
}
