package pki_test

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
)

func TestHistoricalSessionRejectsInvalidConstraints(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	now := testcert.Now()
	config := pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}
	negative := -time.Second
	fingerprint := sha256.Sum256(chain.Root.Raw)
	for _, tc := range []struct {
		name    string
		options pki.HistoricalOptions
	}{
		{"negative_freshness", pki.HistoricalOptions{RevocationFreshness: &negative}},
		{"zero_anchor_sunset", pki.HistoricalOptions{TrustAnchorSunsets: map[string]time.Time{hex.EncodeToString(fingerprint[:]): {}}}},
		{"zero_cutoff", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256}}}},
		{"unknown_hash", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.Hash(255), ReliableUntil: now}}}},
		{"unrecognized_key_family", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{PublicKeyAlgorithm: x509.PublicKeyAlgorithm(255), MinimumKeyBits: 2048, ReliableUntil: now}}}},
		{"missing_key_size", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{PublicKeyAlgorithm: x509.RSA, ReliableUntil: now}}}},
		{"size_without_key_family", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{MinimumKeyBits: 2048, ReliableUntil: now}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: config, HistoricalOptions: tc.options}, now, pki.Evidence{})
			if session != nil || !errors.Is(err, pki.ErrPolicy) {
				t.Errorf("NewHistoricalSession(%+v) = (%v, %v), want nil and ErrPolicy", tc.options, session, err)
			}
		})
	}
	if session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{}, now, pki.Evidence{}); session != nil || !errors.Is(err, pki.ErrPolicy) {
		t.Errorf("NewHistoricalSession without anchors = (%v, %v), want nil and ErrPolicy", session, err)
	}
}

func TestHistoricalPathAssessmentRetainsSessionPath(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	now := testcert.Now()
	config := pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}}
	first, err := pki.NewHistoricalSession(t.Context(), config, now, pki.Evidence{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := pki.NewHistoricalSession(t.Context(), config, now, pki.Evidence{})
	if err != nil {
		t.Fatal(err)
	}

	paths, err := first.Paths(t.Context(), chain.Leaf.Raw)
	if err != nil || len(paths) != 1 {
		t.Fatalf("Paths returned %d paths, err = %v", len(paths), err)
	}
	path := paths[0]
	assessment, err := first.CheckPath(t.Context(), path)
	if err != nil || assessment == nil {
		t.Fatalf("CheckPath = (%v, %v), want assessment", assessment, err)
	}
	wantChain := [][]byte{chain.Leaf.Raw, chain.Root.Raw}
	gotChain := assessment.Path().ChainDER()
	if assessment.Path() != path || assessment.Model() != pki.ShellModel || !assessment.ReferenceTime().Equal(chain.Leaf.NotBefore) ||
		!slices.EqualFunc(gotChain, wantChain, bytes.Equal) {
		t.Fatalf("assessment = (path preserved %t, model %s, time %s), want original path, shell model and %s in target-to-anchor order",
			assessment.Path() == path, assessment.Model(), assessment.ReferenceTime(), chain.Leaf.NotBefore)
	}
	clear(gotChain[0])
	paths[0] = nil
	cached, err := first.Paths(t.Context(), chain.Leaf.Raw)
	if err != nil || len(cached) != 1 || cached[0] != path || !slices.EqualFunc(cached[0].ChainDER(), wantChain, bytes.Equal) {
		t.Errorf("Paths returned a changed path after the caller mutated its copies: %v", err)
	}
	if assessment, err := second.CheckPath(t.Context(), path); assessment != nil || !errors.Is(err, pki.ErrPolicy) {
		t.Errorf("CheckPath with path from another session = (%v, %v), want nil and ErrPolicy", assessment, err)
	}
	if facts, err := second.AuthenticateEvidence(t.Context(), path); facts != nil || !errors.Is(err, pki.ErrPolicy) {
		t.Errorf("AuthenticateEvidence with path from another session = (%v, %v), want nil and ErrPolicy", facts, err)
	}
}
