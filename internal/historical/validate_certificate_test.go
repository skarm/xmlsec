package historical //nolint:testpackage // Uses the existing local timestamp issuer fixture.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
)

func TestValidateCertificateAcceptsAuthenticatedArchive(t *testing.T) {
	t.Parallel()
	issuer := newTimestampIssuer(t)
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{issuer.chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Normalize(Config{Signer: verifier, TSA: issuer.verifier, RequireAllTimestamps: true})
	if err != nil {
		t.Fatal(err)
	}
	now := testcert.Now()
	at := now.Add(-15 * time.Second)
	generation := now.Add(-30 * time.Second)
	leaf, anchor := issuer.chain.Leaf.Raw, issuer.chain.Root.Raw
	crl := testcert.CRL(t, issuer.chain)
	evidence := pki.Evidence{Intermediates: [][]byte{anchor}, CRLs: [][]byte{crl}}
	objects := [][]byte{leaf, anchor, crl}
	archive := make([]ObjectTimestamp, 0, len(objects))
	for i, encoded := range objects {
		token := issuer.issueStamp(t, int64(i+1), generation, new(time.Duration), false, encoded)
		archive = append(archive, ObjectTimestamp{TokenDER: token.candidate.Token.DER(), ObjectSHA256: sha256.Sum256(encoded)})
	}

	result, report, stamps, err := ValidateCertificate(t.Context(), cfg, leaf, at, now, archive, evidence, evidence)
	if err != nil || result == nil || report == nil || result.Path() == nil {
		t.Fatalf("past validation returned result=%v, report=%v, error=%v; want a validated path", result, report, err)
	}
	chain := result.Path().ChainDER()
	if !result.ValidationTime().Equal(at) || len(chain) != 2 || !bytes.Equal(chain[0], leaf) || !bytes.Equal(chain[1], anchor) {
		t.Fatalf("validation at %v, chain length %d; want historical time %v and the original leaf and anchor", result.ValidationTime(), len(chain), at)
	}
	if len(stamps) != len(archive) {
		t.Fatalf("got %d timestamp outcomes, want %d", len(stamps), len(archive))
	}
	wantTokens := make(map[[sha256.Size]byte]bool, len(archive))
	for _, item := range archive {
		wantTokens[sha256.Sum256(item.TokenDER)] = true
	}
	for _, stamp := range stamps {
		if !wantTokens[stamp.Token] || stamp.Indication != Passed || !stamp.Archive || !stamp.Generation.Equal(generation) {
			t.Errorf("unexpected archive outcome %+v", stamp)
		}
		delete(wantTokens, stamp.Token)
	}
}

func TestValidateCertificateChecksArchiveInputs(t *testing.T) {
	t.Parallel()
	issuer := newTimestampIssuer(t)
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{issuer.chain.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	config, err := Normalize(Config{Signer: verifier, TSA: issuer.verifier})
	if err != nil {
		t.Fatal(err)
	}
	certificate := issuer.chain.Leaf.Raw
	digest := sha256.Sum256(certificate)
	now := testcert.Now()
	at := now.Add(-time.Minute)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		at      time.Time
		stamps  []ObjectTimestamp
		budget  int
		wantErr error
	}{
		{"no_archive", t.Context(), at, nil, 0, ErrInput},
		{"time_is_not_in_the_past", t.Context(), now, []ObjectTimestamp{{ObjectSHA256: digest}}, 0, ErrInput},
		{"missing_object_is_reported_before_token_parsing", t.Context(), at, []ObjectTimestamp{{ObjectSHA256: sha256.Sum256([]byte("different object")), TokenDER: []byte("invalid token")}}, 0, ErrInput},
		{"malformed_token_for_known_object", t.Context(), at, []ObjectTimestamp{{ObjectSHA256: digest, TokenDER: []byte("invalid token")}}, 0, ErrValidation},
		{"archive_bytes_count_toward_budget", t.Context(), at, []ObjectTimestamp{{ObjectSHA256: digest, TokenDER: []byte("token")}}, len(certificate), ErrLimit},
		{"canceled", canceled, at, []ObjectTimestamp{{ObjectSHA256: digest}}, 0, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := config
			if tc.budget != 0 {
				cfg.MaxBytes = tc.budget
			}
			result, report, stamps, err := ValidateCertificate(tc.ctx, cfg, certificate, tc.at, now, tc.stamps, pki.Evidence{}, pki.Evidence{})
			if !errors.Is(err, tc.wantErr) || result != nil || report != nil || len(stamps) != 0 {
				t.Fatalf("result=%v, report=%v, stamps=%v, error=%v; want no output and %v", result, report, stamps, err, tc.wantErr)
			}
		})
	}
}
