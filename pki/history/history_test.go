package history_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/pki/history"
	"github.com/skarm/xmlsec/timestamp"
)

func TestValidateRejectsUninitializedValidator(t *testing.T) {
	now := testcert.Now()
	for _, tc := range []struct {
		name      string
		validator *history.Validator
	}{
		{name: "nil_receiver"},
		{name: "zero_value", validator: &history.Validator{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, report, err := tc.validator.Validate(t.Context(), nil, now.Add(-time.Hour), now, history.Evidence{})
			if !errors.Is(err, history.ErrInput) || result != nil {
				t.Fatalf("Validate returned result=%v, error=%v, want nil result and %v", result, err, history.ErrInput)
			}
			if report == nil || report.Certificate != nil || len(report.Timestamps) != 0 {
				t.Fatalf("Validate returned report=%+v, want an empty report", report)
			}
		})
	}
}

func TestValidateRejectsTooManyTimestampsBeforeReadingEvidence(t *testing.T) {
	chain := testcert.New(t)
	validator, err := history.NewValidator(history.Config{
		CertificatePKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}},
		TSA:            newTSA(t, chain.Root.Raw, asn1.ObjectIdentifier{1, 2, 3, 4}),
		MaxTimestamps:  1,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	now := testcert.Now()
	input := history.Evidence{Timestamps: make([]history.ObjectTimestamp, 2)}
	result, report, err := validator.Validate(t.Context(), chain.Leaf.Raw, now.Add(-time.Hour), now, input)
	if !errors.Is(err, history.ErrLimit) || result != nil {
		t.Fatalf("Validate with two timestamps returned result=%v, error=%v, want nil result and %v", result, err, history.ErrLimit)
	}
	if report == nil || report.Certificate != nil || len(report.Timestamps) != 0 {
		t.Fatalf("Validate with two timestamps returned report=%+v, want an empty report", report)
	}
}

func TestValidateExpiredCertificate(t *testing.T) {
	chain := testcert.New(t)
	now := testcert.Now()
	at := now.Add(-2 * time.Hour)
	target := testcert.Issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "archived certificate"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}, chain.Root, chain.LeafKey.Public(), chain.RootKey)
	policy := asn1.ObjectIdentifier{1, 2, 3, 4}
	tsa := newTSA(t, chain.Root.Raw, policy)
	currentCRL, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(2), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
	}, chain.Root, chain.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	archiveCRL := makeArchiveCRL(t, chain, at, target, false)
	accuracy := time.Second
	gen := at.Add(-2 * time.Second)
	issue := func(data []byte, serial int64, at time.Time, accuracy *time.Duration) history.ObjectTimestamp {
		return stampObject(t, chain, policy, data, serial, at, accuracy)
	}
	certificateStamp := issue(target.Raw, 1, gen, &accuracy)
	crlStamp := issue(archiveCRL, 2, gen, &accuracy)
	config := history.Config{
		CertificatePKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}},
		TSA:            tsa,
	}
	validator, err := history.NewValidator(config)
	if err != nil {
		t.Fatal(err)
	}
	makeEvidence := func(crl []byte, stamps ...history.ObjectTimestamp) history.Evidence {
		return history.Evidence{Certificate: pki.Evidence{CRLs: [][]byte{crl}}, TSA: pki.Evidence{CRLs: [][]byte{currentCRL}}, Timestamps: stamps}
	}

	t.Run("exact DER and explicit past time", func(t *testing.T) {
		result, report, err := validator.Validate(t.Context(), target.Raw, at, now, makeEvidence(archiveCRL, certificateStamp, crlStamp))
		if err != nil || result == nil || report.Certificate == nil || len(report.Timestamps) != 2 {
			t.Fatal(result, report, err)
		}
		if !result.ValidationTime().Equal(at) || !bytes.Equal(result.Path().ChainDER()[0], target.Raw) || len(result.Evidence()) != 1 || !bytes.Equal(result.Evidence()[0].DER(), archiveCRL) {
			t.Fatal("wrong accepted certificate, status source or validation time")
		}
		for _, stamp := range report.Timestamps {
			if !stamp.Accepted || !stamp.UpperBound.Equal(gen.Add(accuracy)) {
				t.Fatal(stamp)
			}
		}
	})

	swapped := crlStamp
	swapped.ObjectSHA256 = certificateStamp.ObjectSHA256
	revokedCRL := makeArchiveCRL(t, chain, at, target, true)
	revokedStamp := issue(revokedCRL, 3, gen, &accuracy)
	lateStamp := issue(target.Raw, 4, at, &accuracy)
	noAccuracy := issue(target.Raw, 5, gen, nil)
	untrustedConfig := config
	untrustedConfig.TSA = newTSA(t, testcert.New(t).Root.Raw, policy)
	untrusted, err := history.NewValidator(untrustedConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		validator *history.Validator
		input     history.Evidence
		want      error
	}{
		{"missing certificate timestamp", validator, makeEvidence(archiveCRL, crlStamp), pki.ErrUnavailable},
		{"missing CRL timestamp", validator, makeEvidence(archiveCRL, certificateStamp), pki.ErrUnavailable},
		{"wrong exact bytes", validator, makeEvidence(archiveCRL, certificateStamp, swapped), timestamp.ErrBinding},
		{"uncertainty reaches past validation time", validator, makeEvidence(archiveCRL, lateStamp, crlStamp), pki.ErrUnavailable},
		{"missing TSA accuracy", validator, makeEvidence(archiveCRL, noAccuracy, crlStamp), history.ErrTimestamp},
		{"untrusted TSA", untrusted, makeEvidence(archiveCRL, certificateStamp, crlStamp), history.ErrTimestamp},
		{"certificate revoked at requested time", validator, makeEvidence(revokedCRL, certificateStamp, revokedStamp), pki.ErrRevoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, report, err := tc.validator.Validate(t.Context(), target.Raw, at, now, tc.input)
			if result != nil || report == nil || !errors.Is(err, tc.want) {
				t.Fatal(result, report, err)
			}
		})
	}

	t.Run("expired CRL at requested time", func(t *testing.T) {
		result, report, err := validator.Validate(t.Context(), target.Raw, at.Add(2*time.Minute), now, makeEvidence(archiveCRL, certificateStamp, crlStamp))
		if result != nil || report.Certificate == nil || !errors.Is(err, pki.ErrUnavailable) {
			t.Fatal(result, report, err)
		}
	})

	t.Run("expired certificate at requested time", func(t *testing.T) {
		result, report, err := validator.Validate(t.Context(), target.Raw, target.NotAfter.Add(time.Second), now, makeEvidence(archiveCRL, certificateStamp, crlStamp))
		if result != nil || report.Certificate == nil || !errors.Is(err, pki.ErrCertificate) {
			t.Fatal(result, report, err)
		}
	})

	t.Run("OCSP archive", func(t *testing.T) {
		request, err := pki.CreateOCSPRequest(target.Raw, chain.Root.Raw, crypto.SHA256, nil)
		if err != nil {
			t.Fatal(err)
		}
		issued := at.Add(-time.Minute)
		response, err := pki.CreateOCSPResponse(t.Context(), request, target.Raw, chain.Root.Raw, chain.Root.Raw, chain.RootKey, pki.OCSPResponseTemplate{
			Status: pki.OCSPGood, ProducedAt: issued, ThisUpdate: issued, NextUpdate: at.Add(time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		ocspConfig := config
		ocspConfig.CertificatePKI.PKI.Revocation = pki.RequireOCSP
		ocspValidator, err := history.NewValidator(ocspConfig)
		if err != nil {
			t.Fatal(err)
		}
		input := history.Evidence{Certificate: pki.Evidence{OCSPResponses: [][]byte{response}}, TSA: pki.Evidence{CRLs: [][]byte{currentCRL}}, Timestamps: []history.ObjectTimestamp{certificateStamp, issue(response, 6, gen, &accuracy)}}
		result, report, err := ocspValidator.Validate(t.Context(), target.Raw, at, now, input)
		if err != nil || result == nil || len(result.Evidence()) != 1 || result.Evidence()[0].Kind() != pki.EvidenceOCSP {
			t.Fatal(result, report, err)
		}

		ocspConfig.CertificatePKI.PKI.OCSPMaxAge = 30 * time.Second
		strict, err := history.NewValidator(ocspConfig)
		if err != nil {
			t.Fatal(err)
		}
		if result, report, err := strict.Validate(t.Context(), target.Raw, at, now, input); result != nil || report.Certificate == nil || !errors.Is(err, pki.ErrUnavailable) {
			t.Fatal("OCSP age limit ignored", result, report, err)
		}
	})

	t.Run("archive renewal", func(t *testing.T) {
		old := chain
		old.TSA = testcert.Issue(t, &x509.Certificate{
			SerialNumber: big.NewInt(11), Subject: chain.TSA.Subject,
			NotBefore: chain.TSA.NotBefore, NotAfter: at.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: chain.TSA.Extensions,
		}, chain.Root, old.TSAKey.Public(), chain.RootKey)
		first := stampObject(t, old, policy, target.Raw, 7, gen, &accuracy)
		renewalTime := at.Add(10 * time.Second)
		archive := issue(first.TokenDER, 8, renewalTime, &accuracy)
		oldCertificate := issue(old.TSA.Raw, 9, renewalTime, &accuracy)
		oldCRL, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: at.Add(-time.Minute), NextUpdate: now.Add(time.Minute),
		}, chain.Root, chain.RootKey)
		if err != nil {
			t.Fatal(err)
		}
		oldStatus := issue(oldCRL, 10, renewalTime, &accuracy)
		input := makeEvidence(archiveCRL, first, crlStamp, archive, oldCertificate, oldStatus)
		input.TSA.Intermediates = [][]byte{old.TSA.Raw}
		input.TSA.CRLs = [][]byte{oldCRL}
		result, report, err := validator.Validate(t.Context(), target.Raw, at, now, input)
		if err != nil || result == nil || len(report.Timestamps) != len(input.Timestamps) {
			t.Fatal(result, report, err)
		}
		for _, stamp := range report.Timestamps {
			if !stamp.Accepted {
				t.Fatal(stamp)
			}
		}

		input.Timestamps = []history.ObjectTimestamp{first, crlStamp, oldCertificate, oldStatus}
		if result, _, err := validator.Validate(t.Context(), target.Raw, at, now, input); result != nil || !errors.Is(err, history.ErrTimestamp) {
			t.Fatal("expired TSA accepted without proof of its token", result, err)
		}
	})
}

func makeArchiveCRL(t *testing.T, chain testcert.Chain, at time.Time, target *x509.Certificate, revoked bool) []byte {
	t.Helper()
	crl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Minute)}
	if revoked {
		crl.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: target.SerialNumber, RevocationTime: at.Add(-time.Minute), ReasonCode: 1}}
	}

	raw, err := x509.CreateRevocationList(rand.Reader, crl, chain.Root, chain.RootKey)
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

func newTSA(t *testing.T, root []byte, policy asn1.ObjectIdentifier) *timestamp.Verifier {
	t.Helper()
	v, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{root}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{policy}})
	if err != nil {
		t.Fatal(err)
	}

	return v
}

func stampObject(t *testing.T, chain testcert.Chain, policy asn1.ObjectIdentifier, raw []byte, serial int64, gen time.Time, accuracy *time.Duration) history.ObjectTimestamp {
	t.Helper()
	request, err := timestamp.CreateRequest(t.Context(), raw, timestamp.RequestOptions{Policy: policy})
	if err != nil {
		t.Fatal(err)
	}

	der, err := timestamp.IssueResponse(t.Context(), request.DER(), chain.TSAKey, chain.TSA.Raw, timestamp.IssueOptions{
		Policy: policy, SerialNumber: big.NewInt(serial), GenTime: gen, Accuracy: accuracy,
	})
	if err != nil {
		t.Fatal(err)
	}

	response, err := timestamp.ParseResponse(t.Context(), der)
	if err != nil {
		t.Fatal(err)
	}

	return history.ObjectTimestamp{ObjectSHA256: sha256.Sum256(raw), TokenDER: response.TokenDER()}
}
