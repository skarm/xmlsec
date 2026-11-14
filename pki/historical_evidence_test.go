package pki //nolint:testpackage // Exercises signature classification used by historical evidence policy.

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestHistoricalAlgorithmClassifiesEvidenceSignatures(t *testing.T) {
	t.Parallel()

	sha512 := der.Seq(der.OID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}), []byte{5, 0})
	mgf1SHA512 := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}), sha512)
	for _, tc := range []struct {
		name   string
		oid    asn1.ObjectIdentifier
		params []byte
		want   x509.SignatureAlgorithm
	}{
		{"rsa_sha256", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, nil, x509.SHA256WithRSA},
		{"rsa_sha384", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}, nil, x509.SHA384WithRSA},
		{"rsa_sha512", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}, nil, x509.SHA512WithRSA},
		{"ecdsa_sha384", asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, nil, x509.ECDSAWithSHA384},
		{"ecdsa_sha512", asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}, nil, x509.ECDSAWithSHA512},
		{"pss_sha512", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}, der.Seq(der.Ctx(0, sha512), der.Ctx(1, mgf1SHA512), der.Ctx(2, der.Int(64))), x509.SHA512WithRSAPSS},
		{"pss_missing_parameters", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}, nil, x509.UnknownSignatureAlgorithm},
		{"ed25519", asn1.ObjectIdentifier{1, 3, 101, 112}, nil, x509.PureEd25519},
		{"ed25519_with_parameters", asn1.ObjectIdentifier{1, 3, 101, 112}, []byte{5, 0}, x509.UnknownSignatureAlgorithm},
		{"unknown_signature", asn1.ObjectIdentifier{1, 2, 3, 4}, nil, x509.UnknownSignatureAlgorithm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			id := pkix.AlgorithmIdentifier{Algorithm: tc.oid, Parameters: asn1.RawValue{FullBytes: tc.params}}
			if got := historicalAlgorithm(id); got != tc.want {
				t.Errorf("historicalAlgorithm(%s, %x) = %v, want %v", tc.oid, tc.params, got, tc.want)
			}
		})
	}
}

func TestVerifiedEvidenceSignerMetadataRequiresAuthentication(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		evidence *VerifiedEvidence
	}{
		{"nil", nil},
		{"unauthenticated", &VerifiedEvidence{signerAuthority: evidenceAuthorityDelegated, signerChain: [][]byte{{1, 2}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if authority, chain := tc.evidence.SignerAuthority(), tc.evidence.SignerChainDER(); authority != "" || chain != nil {
				t.Errorf("unauthenticated signer metadata = (%q, %x), want empty authority and nil chain", authority, chain)
			}
		})
	}
}

func TestAuthenticateEvidenceUsesSessionObservationTime(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	now := testcert.Now()
	request, err := CreateOCSPRequest(chain.Leaf.Raw, chain.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		offset time.Duration
		want   int
	}{
		{"at_observation_time", 0, 2},
		{"issued_after_observation", time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			issued := now.Add(tc.offset)
			next := issued.Add(time.Minute)
			crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number: big.NewInt(3), ThisUpdate: issued, NextUpdate: next,
			}, chain.Root, chain.RootKey)
			if err != nil {
				t.Fatal(err)
			}
			response, err := CreateOCSPResponse(t.Context(), request, chain.Leaf.Raw, chain.Root.Raw, chain.Root.Raw, chain.RootKey,
				OCSPResponseTemplate{Status: OCSPGood, ProducedAt: issued, ThisUpdate: issued, NextUpdate: next})
			if err != nil {
				t.Fatal(err)
			}

			session, err := NewHistoricalSession(t.Context(), HistoricalConfig{PKI: Config{Roots: [][]byte{chain.Root.Raw}, Revocation: RequireCRL}},
				now, Evidence{CRLs: [][]byte{crl}, OCSPResponses: [][]byte{response}})
			if err != nil {
				t.Fatal(err)
			}
			paths, err := session.Paths(t.Context(), chain.Leaf.Raw)
			if err != nil || len(paths) != 1 {
				t.Fatalf("Paths returned %d paths, err = %v", len(paths), err)
			}
			facts, err := session.AuthenticateEvidence(t.Context(), paths[0])
			if err != nil || len(facts) != tc.want {
				t.Fatalf("AuthenticateEvidence returned %d facts, err = %v, want %d facts", len(facts), err, tc.want)
			}
			expected := map[EvidenceKind][]byte{EvidenceCRL: crl, EvidenceOCSP: response}
			for _, fact := range facts {
				want, found := expected[fact.Kind()]
				if !found || !bytes.Equal(fact.DER(), want) || fact.AuthenticationStatus() != Valid || !fact.IssuedAt().Equal(issued) {
					t.Errorf("unexpected evidence %s, authentication = %v, issued = %s", fact.Kind(), fact.AuthenticationStatus(), fact.IssuedAt())
				}
				delete(expected, fact.Kind())
			}
		})
	}
}
