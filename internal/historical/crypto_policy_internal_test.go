package historical

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
)

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

func TestCMSAlgorithmMapsAuthenticatedSignatureIdentifiers(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		oid  string
		hash crypto.Hash
		want x509.SignatureAlgorithm
	}{
		{"1.2.840.113549.1.1.11", crypto.SHA256, x509.SHA256WithRSA},
		{"1.2.840.113549.1.1.12", crypto.SHA384, x509.SHA384WithRSA},
		{"1.2.840.113549.1.1.13", crypto.SHA512, x509.SHA512WithRSA},
		{"1.2.840.10045.4.3.2", crypto.SHA256, x509.ECDSAWithSHA256},
		{"1.2.840.10045.4.3.3", crypto.SHA384, x509.ECDSAWithSHA384},
		{"1.2.840.10045.4.3.4", crypto.SHA512, x509.ECDSAWithSHA512},
		{"1.2.840.113549.1.1.10", crypto.SHA256, x509.SHA256WithRSAPSS},
		{"1.2.840.113549.1.1.10", crypto.SHA384, x509.SHA384WithRSAPSS},
		{"1.2.840.113549.1.1.10", crypto.SHA512, x509.SHA512WithRSAPSS},
		{"1.2.840.113549.1.1.10", crypto.SHA1, x509.UnknownSignatureAlgorithm},
		{"1.3.101.112", 0, x509.PureEd25519},
		{"1.2.3", crypto.SHA256, x509.UnknownSignatureAlgorithm},
	} {
		if got := cmsAlgorithm(test.oid, test.hash); got != test.want {
			t.Fatalf("CMS algorithm %s/%v = %v; want %v", test.oid, test.hash, got, test.want)
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
