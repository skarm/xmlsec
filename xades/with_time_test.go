package xades_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/historical"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

type datedTSA struct {
	chain    testcert.Chain
	gen      time.Time
	accuracy *time.Duration
}

func (s datedTSA) RoundTrip(ctx context.Context, raw []byte) (io.ReadCloser, error) {
	b, e := timestamp.IssueResponse(ctx, raw, s.chain.TSAKey, s.chain.TSA.Raw, timestamp.IssueOptions{Policy: tsaPolicy(), SerialNumber: big.NewInt(101), GenTime: s.gen, Accuracy: s.accuracy, ExtraCertificates: [][]byte{s.chain.Root.Raw}})
	return io.NopCloser(bytes.NewReader(b)), e
}

func TestHistoricalExpiredTSAArchiveEvidence(t *testing.T) {
	chain, sufficient, insufficient, tsa := historicalArchivePair(t)
	zero := time.Duration(0)
	config := xades.HistoricalConfig{
		SignerPKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}},
		TSA:       tsa, MissingTSAAccuracy: &zero, RequireAllTimestamps: true,
		Baseline: xades.BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}}},
	}
	validator, err := xades.NewHistoricalValidator(config)
	if err != nil {
		t.Fatal(err)
	}
	at := testcert.Now().Add(48 * time.Hour)
	exportHistoricalPair(t, chain, sufficient, insufficient, at, at)
	result, report, err := validator.Validate(t.Context(), sufficient, xmldsig.Signatures(sufficient)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{})
	if err != nil || result == nil || report.Indication() != xades.Passed || !report.BestSignatureTime().Equal(testcert.Now().Add(-time.Second)) || result.PastSignerTrust() == nil || result.CurrentSignerTrust() != nil {
		t.Fatalf("sufficient archive: indication=%v sub=%s best=%s err=%v steps=%+v stamps=%+v", report.Indication(), report.SubIndication(), report.BestSignatureTime(), err, report.Steps(), report.Timestamps())
	}
	if len(report.Proofs()) == 0 || len(report.Timestamps()) != 2 {
		t.Fatal("missing historical explanation")
	}
	t.Run("one token per baseline signature timestamp", func(t *testing.T) {
		draft, err := tree.Clone(t.Context(), insufficient)
		if err != nil {
			t.Fatal(err)
		}
		var archive document.Element
		stack := []document.Element{draft.Root()}
		for len(stack) > 0 {
			element := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if element.Name() == (document.Name{Space: xades.Namespace, Local: "SignatureTimeStamp"}) {
				archive = element
			}
			stack = append(stack, element.Children()...)
		}
		if !archive.Valid() {
			t.Fatal("no archive")
		}
		_, parent := tree.Unwrap(archive)
		for _, child := range archive.Children() {
			if child.Name() == (document.Name{Space: xades.Namespace, Local: "EncapsulatedTimeStamp"}) {
				_, node := tree.Unwrap(child)
				duplicate := tree.ImportSubtree(node)
				duplicate.Parent = parent
				parent.Children = append(parent.Children, duplicate)
				break
			}
		}
		verifyOnlyXML(t, draft, chain)
		result, report, err := validator.Validate(t.Context(), draft, xmldsig.Signatures(draft)[0], chain.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{})
		if result != nil || !errors.Is(err, xades.ErrProfile) || report.Indication() == xades.Passed {
			t.Fatal("multiple baseline tokens accepted", err)
		}
	})
	for _, stamp := range report.Timestamps() {
		if stamp.Indication != xades.Passed {
			t.Fatalf("unverified required timestamp: %+v", stamp)
		}
	}
	proofs := report.Proofs()
	proofs[0].Kind = "forged"
	if report.Proofs()[0].Kind == "forged" {
		t.Fatal("mutable historical facts")
	}
	result, negative, err := validator.Validate(t.Context(), insufficient, xmldsig.Signatures(insufficient)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{})
	if result != nil || err == nil || negative.Indication() != xades.Indeterminate || negative.SubIndication() != "OUT_OF_BOUNDS_NO_POE" {
		t.Fatalf("missing archive: %v %s %v", negative.Indication(), negative.SubIndication(), err)
	}
	verifyOnlyXML(t, insufficient, chain)
	if !bytes.Equal(mustSignatureValue(t, sufficient), mustSignatureValue(t, insufficient)) {
		t.Fatal("paired input changed primary signature")
	}
	// Acquisition time is untrusted metadata, even for the exact right CRL.
	crl := historicalEmbeddedCRL(t, sufficient)
	source, err := evidence.NewObservation(t.Context(), evidence.CRL, crl, evidence.Provenance{RetrievedAt: testcert.Now()})
	if err != nil {
		t.Fatal(err)
	}
	result, withSource, err := validator.Validate(t.Context(), insufficient, xmldsig.Signatures(insufficient)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{crl}, Sources: []*evidence.Observation{source}}})
	if result != nil || err == nil || withSource.Indication() != xades.Indeterminate || withSource.SubIndication() != negative.SubIndication() {
		t.Fatal("retrieval metadata minted PoE", err)
	}
	// Missing accuracy is not silently interpreted as exact GenTime.
	config.MissingTSAAccuracy = nil
	unknownAccuracy, err := xades.NewHistoricalValidator(config)
	if err != nil {
		t.Fatal(err)
	}
	if r, report, err := unknownAccuracy.Validate(t.Context(), sufficient, xmldsig.Signatures(sufficient)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{}); r != nil || err == nil || report.Indication() == xades.Passed {
		t.Fatal("invented missing accuracy", err)
	}
	config.MissingTSAAccuracy = &zero
	config.TSAHistory.CryptoConstraints = []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: testcert.Now().Add(24 * time.Hour)}}
	obsolete, err := xades.NewHistoricalValidator(config)
	if err != nil {
		t.Fatal(err)
	}
	if r, report, err := obsolete.Validate(t.Context(), sufficient, xmldsig.Signatures(sufficient)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{}); r != nil || err == nil || report.Indication() == xades.Passed {
		t.Fatal("timestamp backdated its own obsolete hash", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if r, report, err := validator.Validate(canceled, sufficient, xmldsig.Signatures(sufficient)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{}); r != nil || !errors.Is(err, context.Canceled) || report.Indication() == xades.Passed {
		t.Fatal("cancellation", err)
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			r, report, err := validator.Validate(t.Context(), sufficient, xmldsig.Signatures(sufficient)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{})
			if err != nil || r == nil || report.Indication() != xades.Passed {
				t.Error("concurrent historical validation", err)
			}
		})
	}
	workers.Wait()
}

func TestHistoricalTSARevocationNeedsIndependentArchive(t *testing.T) {
	chain, archived, unarchived, tsa := historicalArchivePairWithArchiveKey(t, testcert.Key(t))
	zero := time.Duration(0)
	validator, err := xades.NewHistoricalValidator(xades.HistoricalConfig{
		SignerPKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}},
		TSA:       tsa, MissingTSAAccuracy: &zero, RequireAllTimestamps: true,
		Baseline: xades.BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	archiveAt := testcert.Now().Add(30 * time.Minute)
	at := testcert.Now().Add(90 * time.Minute)
	for _, reason := range []int{1, 6} {
		for _, tc := range []struct {
			name    string
			doc     *document.Document
			revoked time.Time
			pass    bool
		}{
			{"independent archive before revocation", archived, archiveAt.Add(time.Second), true},
			{"proof exactly at revocation boundary", archived, archiveAt, true},
			{"archive after revocation", archived, archiveAt.Add(-time.Second), false},
			{"GenTime cannot prove its own token", unarchived, archiveAt.Add(time.Second), false},
		} {
			t.Run(fmt.Sprintf("reason %d/%s", reason, tc.name), func(t *testing.T) {
				before, err := tc.doc.XML(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				verifyOnlyXML(t, tc.doc, chain)
				crl := datedCRL(t, chain, testcert.Now().Add(time.Hour), 2, x509.RevocationListEntry{SerialNumber: chain.TSA.SerialNumber, RevocationTime: tc.revoked, ReasonCode: reason})
				result, report, err := validator.Validate(t.Context(), tc.doc, xmldsig.Signatures(tc.doc)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{TSA: pki.Evidence{CRLs: [][]byte{crl}}})
				if tc.pass {
					if result == nil || err != nil || report.Indication() != xades.Passed || !report.BestSignatureTime().Equal(testcert.Now().Add(-time.Second)) || !report.VerificationTime().Equal(at) {
						t.Fatal("pre-revocation archive did not recover TSA", report.Indication(), report.SubIndication(), err)
					}
					found := false
					for _, stamp := range report.Timestamps() {
						if !stamp.Archive {
							found = true
							if stamp.Indication != xades.Passed || !stamp.ValidationTime.Equal(tc.revoked) || !stamp.BestSignatureTime.Equal(archiveAt) {
								t.Fatal("TSA recovery lost the independent proof or revocation bound", stamp)
							}
						}
					}
					if !found {
						t.Fatal("missing recovered signature timestamp")
					}
				} else {
					want := "REVOKED_NO_POE"
					if reason == 6 {
						want = "TRY_LATER"
					}
					if result != nil || !errors.Is(err, xades.ErrHistorical) || report.Indication() != xades.Indeterminate || report.SubIndication() != want {
						t.Fatal("late or absent archive repaired revoked TSA", report.Indication(), report.SubIndication(), err)
					}
				}
				after, err := tc.doc.XML(t.Context())
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("historical validation modified its input", err)
				}
			})
		}
	}
}

func TestHistoricalTSADelegatedOCSPResponder(t *testing.T) {
	chain, archived, unarchived, _ := historicalArchivePairWithArchiveKey(t, testcert.Key(t))
	archiveAt := testcert.Now().Add(30 * time.Minute)
	at := testcert.Now().Add(90 * time.Minute)
	// This responder has no nocheck exemption: its own status must be checked.
	template := *chain.Responder
	template.ExtraExtensions = nil
	responder := testcert.Issue(t, &template, chain.Root, chain.ResponderKey.Public(), chain.RootKey)
	node := baselineTestNode(tree.Root(archived), xades.Namespace141, "ArchiveTimeStamp")
	enc := baselineTestNode(node, xades.Namespace, "EncapsulatedTimeStamp")
	var encoded strings.Builder
	for _, child := range enc.Children {
		if child.Kind == tree.TextNode {
			encoded.WriteString(child.Data)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		t.Fatal(err)
	}
	token, err := timestamp.ParseToken(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	var archiveTSA *x509.Certificate
	for _, raw := range token.Certificates() {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatal(err)
		}
		if cert.SerialNumber.Cmp(big.NewInt(103)) == 0 {
			archiveTSA = cert
		}
	}
	if archiveTSA == nil {
		t.Fatal("archive TSA absent from control token")
	}
	response := func(cert, signer *x509.Certificate, key crypto.Signer) []byte {
		t.Helper()
		query, err := pki.CreateOCSPRequest(cert.Raw, chain.Root.Raw, crypto.SHA256, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := pki.CreateOCSPResponse(t.Context(), query, cert.Raw, chain.Root.Raw, signer.Raw, key, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: testcert.Now(), ThisUpdate: testcert.Now().Add(-time.Minute), NextUpdate: at.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// The protecting archive uses an independently authorized issuer response.
	responses := [][]byte{response(chain.TSA, responder, chain.ResponderKey), response(archiveTSA, chain.Root, chain.RootKey)}
	tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireOCSP}, AllowedPolicies: []asn1.ObjectIdentifier{tsaPolicy()}})
	if err != nil {
		t.Fatal(err)
	}
	zero := time.Duration(0)
	validator, err := xades.NewHistoricalValidator(xades.HistoricalConfig{SignerPKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}}, TSA: tsa, MissingTSAAccuracy: &zero, RequireAllTimestamps: true, Baseline: xades.BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		doc     *document.Document
		revoked time.Time
		pass    bool
	}{
		{"good responder", unarchived, time.Time{}, true},
		{"archive before responder revocation", archived, archiveAt.Add(time.Minute), true},
		{"archive after responder revocation", archived, archiveAt.Add(-time.Minute), false},
		{"no independent proof before responder revocation", unarchived, archiveAt.Add(time.Minute), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var entries []x509.RevocationListEntry
			if !tc.revoked.IsZero() {
				entries = []x509.RevocationListEntry{{SerialNumber: responder.SerialNumber, RevocationTime: tc.revoked, ReasonCode: 1}}
			}
			proof := pki.Evidence{OCSPResponses: responses, CRLs: [][]byte{datedCRL(t, chain, at, 2, entries...)}}
			verifyOnlyXML(t, tc.doc, chain)
			result, report, err := validator.Validate(t.Context(), tc.doc, xmldsig.Signatures(tc.doc)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{TSA: proof})
			if !tc.pass {
				if result != nil || !errors.Is(err, xades.ErrHistorical) || report.Indication() != xades.Indeterminate || report.SubIndication() != "REVOKED_NO_POE" {
					t.Fatal("unproven response from revoked responder repaired TSA", report.SubIndication(), err)
				}
				return
			}
			if result == nil || err != nil || report.Indication() != xades.Passed {
				t.Fatal("independent archive failed to recover delegated status", report.SubIndication(), err)
			}
			for _, stamp := range report.Timestamps() {
				if !stamp.Archive {
					want := at
					if !tc.revoked.IsZero() {
						want = tc.revoked
					}
					if !stamp.ValidationTime.Equal(want) || stamp.Indication != xades.Passed {
						t.Fatal("ignored delegated responder's historical bound", stamp)
					}
				}
			}
		})
	}
}

func TestHistoricalLocalOCSPGrantKeepsIssuerAndProofBoundaries(t *testing.T) {
	chain, archived, unarchived, _ := historicalArchivePairWithArchiveKey(t, testcert.Key(t))
	other := testcert.New(t)
	at := testcert.Now().Add(48 * time.Hour)
	responderTemplate := *other.Leaf
	responderTemplate.NotAfter = testcert.Now().Add(8 * 24 * time.Hour)
	responder := testcert.Issue(t, &responderTemplate, other.Root, other.LeafKey.Public(), other.RootKey)
	issuerTemplate := *chain.Root
	issuerTemplate.SerialNumber = big.NewInt(240)
	issuerAlias := testcert.Issue(t, &issuerTemplate, &issuerTemplate, chain.RootKey.Public(), chain.RootKey)
	if !bytes.Equal(chain.Root.RawSubject, issuerAlias.RawSubject) || !bytes.Equal(chain.Root.RawSubjectPublicKeyInfo, issuerAlias.RawSubjectPublicKeyInfo) || bytes.Equal(chain.Root.Raw, issuerAlias.Raw) {
		t.Fatal("issuer alias must share name/key but retain a distinct certificate")
	}
	var archiveTSA *x509.Certificate
	for _, raw := range historicalArchiveToken(t, archived).Certificates() {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatal(err)
		}
		if certificate.SerialNumber.Cmp(big.NewInt(103)) == 0 {
			archiveTSA = certificate
		}
	}
	if archiveTSA == nil {
		t.Fatal("missing protecting archive TSA")
	}
	response := func(certificate, signer *x509.Certificate, key crypto.Signer) []byte {
		t.Helper()
		request, err := pki.CreateOCSPRequest(certificate.Raw, chain.Root.Raw, crypto.SHA256, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := pki.CreateOCSPResponse(t.Context(), request, certificate.Raw, chain.Root.Raw, signer.Raw, key, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: testcert.Now(), ThisUpdate: testcert.Now().Add(-time.Minute), NextUpdate: at.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// The current archive has issuer-signed status; the expired signature TSA
	// relies on the separately configured, issuer-scoped external authority.
	proof := pki.Evidence{OCSPResponses: [][]byte{response(chain.TSA, responder, other.LeafKey), response(archiveTSA, chain.Root, chain.RootKey)}}
	exact := pki.OCSPAuthority{ResponderCertificateDER: responder.Raw, IssuerCertificateDER: chain.Root.Raw}
	alias := pki.OCSPAuthority{ResponderCertificateDER: responder.Raw, IssuerCertificateDER: issuerAlias.Raw}
	for _, tc := range []struct {
		name   string
		doc    *document.Document
		grants []pki.OCSPAuthority
		pass   bool
	}{
		{"explicit scoped authority with independent archive", archived, []pki.OCSPAuthority{exact}, true},
		{"received external responder has no grant", archived, nil, false},
		{"grant belongs to reissued CA with same key", archived, []pki.OCSPAuthority{alias}, false},
		{"unrelated grant does not mask exact authority", archived, []pki.OCSPAuthority{alias, exact}, true},
		{"authority alone does not prove timestamp existence", unarchived, []pki.OCSPAuthority{exact}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireOCSP, OCSPAuthorities: tc.grants}, AllowedPolicies: []asn1.ObjectIdentifier{tsaPolicy()}})
			if err != nil {
				t.Fatal(err)
			}
			zero := time.Duration(0)
			validator, err := xades.NewHistoricalValidator(xades.HistoricalConfig{SignerPKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}}, TSA: tsa, MissingTSAAccuracy: &zero, RequireAllTimestamps: true, Baseline: xades.BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}}}})
			if err != nil {
				t.Fatal(err)
			}
			verifyOnlyXML(t, tc.doc, chain)
			result, report, err := validator.Validate(t.Context(), tc.doc, xmldsig.Signatures(tc.doc)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{TSA: proof})
			if !tc.pass {
				if result != nil || !errors.Is(err, xades.ErrHistorical) || report.Indication() != xades.Indeterminate || report.SubIndication() != "OUT_OF_BOUNDS_NO_POE" {
					t.Fatal("issuer scope or independent proof was bypassed", report.Indication(), report.SubIndication(), err)
				}
			} else if result == nil || err != nil || report.Indication() != xades.Passed || result.CurrentSignerTrust() != nil || result.PastSignerTrust() == nil || !report.BestSignatureTime().Equal(testcert.Now().Add(-time.Second)) {
				t.Fatal("scoped authority failed historical recovery", report.SubIndication(), err)
			}
			if tc.doc == archived {
				stamps := report.Timestamps()
				if len(stamps) != 2 || !stamps[0].Archive || stamps[0].Indication != xades.Passed {
					t.Fatal("negative case must retain a valid independent protecting archive", stamps)
				}
			}
		})
	}
}

func TestHistoricalTrustAnchorSunsetNeedsMaterialProof(t *testing.T) {
	chain, archived, unarchived, tsa := historicalArchivePairWithArchiveKey(t, testcert.Key(t))
	archiveAt := testcert.Now().Add(30 * time.Minute)
	at := testcert.Now().Add(90 * time.Minute)
	anchor := sha256.Sum256(chain.Root.Raw)
	for _, tc := range []struct {
		name   string
		doc    *document.Document
		sunset time.Time
		pass   bool
	}{
		{"current trust without sunset", unarchived, time.Time{}, true},
		{"material protected before anchor sunset", archived, archiveAt.Add(time.Second), true},
		{"material protected exactly at sunset", archived, archiveAt, true},
		{"archive after anchor sunset", archived, archiveAt.Add(-time.Second), false},
		{"signature proof does not protect revocation material", unarchived, archiveAt.Add(time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sunsets map[string]time.Time
			if !tc.sunset.IsZero() {
				sunsets = map[string]time.Time{hex.EncodeToString(anchor[:]): tc.sunset}
			}
			zero := time.Duration(0)
			validator, err := xades.NewHistoricalValidator(xades.HistoricalConfig{SignerPKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, HistoricalOptions: pki.HistoricalOptions{TrustAnchorSunsets: sunsets}}, TSA: tsa, MissingTSAAccuracy: &zero, RequireAllTimestamps: true, Baseline: xades.BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}}}})
			if err != nil {
				t.Fatal(err)
			}
			verifyOnlyXML(t, tc.doc, chain)
			result, report, err := validator.Validate(t.Context(), tc.doc, xmldsig.Signatures(tc.doc)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{})
			for _, stamp := range report.Timestamps() {
				if stamp.Indication != xades.Passed {
					t.Fatal("signer-only sunset leaked into TSA policy", stamp)
				}
			}
			if !tc.pass {
				if result != nil || !errors.Is(err, xades.ErrHistorical) || report.Indication() != xades.Indeterminate || report.SubIndication() != "NO_CERTIFICATE_CHAIN_FOUND_NO_POE" {
					t.Fatal("late material proof bypassed anchor sunset", report.SubIndication(), err)
				}
				return
			}
			if result == nil || err != nil || report.Indication() != xades.Passed {
				t.Fatal("valid anchor policy rejected", report.SubIndication(), err)
			}
			if tc.sunset.IsZero() {
				if result.CurrentSignerTrust() == nil || result.PastSignerTrust() != nil || !report.ValidationTime().Equal(at) {
					t.Fatal("control must use current signer trust")
				}
			} else {
				past := result.PastSignerTrust()
				if result.CurrentSignerTrust() != nil || past == nil || !past.ValidationTime().Equal(tc.sunset) || !report.ValidationTime().Equal(tc.sunset) || !bytes.Equal(past.Path().ChainDER()[1], chain.Root.Raw) {
					t.Fatal("historical result lost exact anchor or sunset bound")
				}
				found := false
				for _, step := range report.Steps() {
					if step.Action == "trust-anchor-sunset" && step.ObjectSHA256 == hex.EncodeToString(anchor[:]) && step.After.Equal(tc.sunset) {
						found = true
					}
				}
				if !found {
					t.Fatal("anchor sunset missing from historical explanation")
				}
			}
		})
	}
}

func TestHistoricalTSAResponderCyclesAndAuthorizationDepth(t *testing.T) {
	chain := testcert.New(t)
	now := testcert.Now()
	basic := basicDocument(t, chain)
	timed, _, err := xades.AddSignatureTimestamp(t.Context(), basic, xmldsig.Signatures(basic)[0], chain.Leaf.Raw, &localTSA{chain: chain}, xades.AddTimestampOptions{Validation: timeOptions(t, chain)})
	if err != nil {
		t.Fatal(err)
	}
	before := mustXML(t, timed)
	// Named indirect CRLs prevent a complete issuer CRL from shortcutting the
	// source dependencies: TSA -> OCSP signer -> CRL signer -> issuer (or cycle).
	graph := func(t testing.TB, cyclic bool) pki.Evidence {
		t.Helper()
		pointName := func(uri string) []byte {
			return der.Ctx(0, der.Wrap(2, 0, true, der.Wrap(2, 6, false, []byte(uri))))
		}
		point := func(uri string, issuer []byte) pkix.Extension {
			fields := [][]byte{pointName(uri)}
			if len(issuer) != 0 {
				fields = append(fields, der.Wrap(2, 2, true, der.Ctx(4, issuer)))
			}
			return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: der.Seq(der.Seq(fields...))}
		}
		firstName, secondName := pkix.Name{CommonName: "TSA OCSP dependency"}, pkix.Name{CommonName: "TSA CRL dependency"}
		firstDER, err := asn1.Marshal(firstName.ToRDNSequence())
		if err != nil {
			t.Fatal(err)
		}
		secondDER, err := asn1.Marshal(secondName.ToRDNSequence())
		if err != nil {
			t.Fatal(err)
		}
		firstKey, secondKey := testcert.Key(t), testcert.Key(t)
		first := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(260), Subject: firstName, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, SubjectKeyId: []byte{2, 6, 0}, ExtraExtensions: []pkix.Extension{point("urn:tsa:second", secondDER)}}, chain.Root, firstKey.Public(), chain.RootKey)
		lastPoint := point("urn:tsa:root", nil)
		if cyclic {
			lastPoint = point("urn:tsa:first", firstDER)
		}
		second := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(261), Subject: secondName, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign, SubjectKeyId: []byte{2, 6, 1}, ExtraExtensions: []pkix.Extension{lastPoint}}, chain.Root, secondKey.Public(), chain.RootKey)
		crl := func(signer *x509.Certificate, key crypto.Signer, uri string, indirect bool) []byte {
			t.Helper()
			fields := [][]byte{pointName(uri)}
			if indirect {
				fields = append(fields, der.Wrap(2, 4, false, []byte{255}))
			}
			raw, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: der.Seq(fields...)}}}, signer, key)
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		lists := [][]byte{crl(second, secondKey, "urn:tsa:second", true)}
		if cyclic {
			lists = append(lists, crl(first, firstKey, "urn:tsa:first", true))
		} else {
			lists = append(lists, crl(chain.Root, chain.RootKey, "urn:tsa:root", false))
		}
		request, err := pki.CreateOCSPRequest(chain.TSA.Raw, chain.Root.Raw, crypto.SHA256, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := pki.CreateOCSPResponse(t.Context(), request, chain.TSA.Raw, chain.Root.Raw, first.Raw, firstKey, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: now, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return pki.Evidence{Intermediates: [][]byte{first.Raw, second.Raw}, CRLs: lists, OCSPResponses: [][]byte{raw}}
	}
	for _, tc := range []struct {
		name    string
		cyclic  bool
		maximum int
		want    error
	}{
		{"source dependencies fit exact depth", false, 3, nil},
		{"source dependencies exceed depth", false, 2, pki.ErrLimit},
		{"cyclic status dependencies", true, 3, pki.ErrUnavailable},
		{"larger depth does not authorize a cycle", true, 4, pki.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireOCSP, MaxChainDepth: tc.maximum}, AllowedPolicies: []asn1.ObjectIdentifier{tsaPolicy()}})
			if err != nil {
				t.Fatal(err)
			}
			zero := time.Duration(0)
			validator, err := xades.NewHistoricalValidator(xades.HistoricalConfig{SignerPKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}}, TSA: tsa, MissingTSAAccuracy: &zero, RequireAllTimestamps: true})
			if err != nil {
				t.Fatal(err)
			}
			verifyOnlyXML(t, timed, chain)
			result, report, err := validator.Validate(t.Context(), timed, xmldsig.Signatures(timed)[0], chain.Leaf.Raw, now, xades.ValidationEvidence{Signer: timeOptions(t, chain).Evidence, TSA: graph(t, tc.cyclic)})
			if tc.want == nil {
				if result == nil || err != nil || report.Indication() != xades.Passed || len(report.Timestamps()) != 1 || report.Timestamps()[0].Indication != xades.Passed {
					t.Fatal("valid TSA dependency rejected at exact depth", report.SubIndication(), err)
				}
			} else {
				if result != nil || !errors.Is(err, xades.ErrHistorical) || !errors.Is(err, tc.want) || !errors.Is(report.Cause(), tc.want) || report.Indication() != xades.Indeterminate {
					t.Fatal("TSA dependency failure lost its cause or returned partial trust", result != nil, report.SubIndication(), err)
				}
				if errors.Is(tc.want, pki.ErrLimit) {
					if !errors.Is(err, pki.ErrPolicy) || !strings.Contains(err.Error(), "authorization depth") {
						t.Fatal("wrong TSA depth failure", err)
					}
				} else if errors.Is(err, pki.ErrLimit) || !strings.Contains(err.Error(), "authorization cycle") {
					t.Fatal("cyclic responder accepted or misclassified as an ordinary limit", err)
				}
			}
			if !bytes.Equal(before, mustXML(t, timed)) {
				t.Fatal("historical dependency validation modified the signature")
			}
		})
	}
}

func historicalEmbeddedCRL(t testing.TB, doc *document.Document) []byte {
	t.Helper()
	stack := []document.Element{doc.Root()}
	for len(stack) > 0 {
		element := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if element.Name() == (document.Name{Space: xades.Namespace, Local: "EncapsulatedCRLValue"}) {
			raw, err := base64.StdEncoding.DecodeString(element.Text())
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		stack = append(stack, element.Children()...)
	}
	t.Fatal("missing embedded CRL")
	return nil
}

func historicalArchivePair(t testing.TB, digest ...string) (testcert.Chain, *document.Document, *document.Document, *timestamp.Verifier) {
	t.Helper()
	return historicalArchivePairWithArchiveKey(t, nil, digest...)
}

func historicalArchivePairWithArchiveKey(t testing.TB, archiveKey crypto.Signer, digest ...string) (testcert.Chain, *document.Document, *document.Document, *timestamp.Verifier) {
	t.Helper()
	chain := testcert.New(t)
	if archiveKey == nil {
		archiveKey = chain.TSAKey
	}
	newTSA := *chain.TSA
	newTSA.SerialNumber = big.NewInt(103)
	newTSA.NotAfter = testcert.Now().Add(8 * 24 * time.Hour)
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		t.Fatal(err)
	}
	newTSA.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}
	newTSA = *testcert.Issue(t, &newTSA, chain.Root, archiveKey.Public(), chain.RootKey)
	tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, Certificates: [][]byte{newTSA.Raw}, AllowedPolicies: []asn1.ObjectIdentifier{tsaPolicy()}})
	if err != nil {
		t.Fatal(err)
	}
	input, err := document.Parse(t.Context(), []byte(`<r ID="data" xmlns:unused="urn:archive-context"><amount>123</amount></r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	basic, _, err := xades.SignBasicEnveloped(t.Context(), input, chain.LeafKey, chain.Leaf.Raw, xades.SignOptions{SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: testcert.Now()})
	if len(digest) != 0 {
		basic, _, err = xades.SignBaseline(t.Context(), input, input.Root(), chain.LeafKey, chain.Leaf.Raw, xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#data", DigestMethod: digest[0], Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}, {Algorithm: c14n.Exclusive}}}}}, Properties: xades.BaselineProperties{SigningTime: testcert.Now()}, Validation: xades.BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}}}})
	}
	if err != nil {
		t.Fatal(err)
	}
	proof := pki.Evidence{CRLs: [][]byte{historicalLongCRL(t, chain)}}
	stamped, _, err := xades.AddSignatureTimestamp(t.Context(), basic, xmldsig.Signatures(basic)[0], chain.Leaf.Raw, &archiveTransport{key: chain.TSAKey, cert: chain.TSA.Raw, root: chain.Root.Raw, now: testcert.Now().Add(-time.Second)}, xades.AddTimestampOptions{Validation: xades.TimedOptions{TSA: tsa, At: testcert.Now(), Evidence: proof}})
	if err != nil {
		t.Fatal(err)
	}
	closed, err := xades.NewValidator(xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, TSA: tsa, MinimumLevel: xades.LevelLT})
	if err != nil {
		t.Fatal(err)
	}
	material, _, err := closed.EmbedValidationMaterial(t.Context(), stamped, xmldsig.Signatures(stamped)[0], chain.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{Signer: proof, TSA: proof})
	if err != nil {
		t.Fatal(err)
	}
	archived, _, err := closed.AddArchiveTimestamp(t.Context(), material, xmldsig.Signatures(material)[0], chain.Leaf.Raw, testcert.Now().Add(30*time.Minute), &archiveTransport{key: archiveKey, cert: newTSA.Raw, root: chain.Root.Raw, now: testcert.Now().Add(30 * time.Minute)}, xades.AddArchiveOptions{Canonicalization: c14n.Canonical11})
	if err != nil {
		t.Fatal(err)
	}
	return chain, archived, material, tsa
}

func TestHistoricalDigestMaterialRequiresItsOwnProof(t *testing.T) {
	chain, archived, onlySignature, tsa := historicalArchivePair(t, xmldsig.SHA384)
	zero := time.Duration(0)
	v, err := xades.NewHistoricalValidator(xades.HistoricalConfig{SignerPKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, HistoricalOptions: pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA384, ReliableUntil: testcert.Now().Add(6 * time.Hour)}}}}, TSA: tsa, MissingTSAAccuracy: &zero, RequireAllTimestamps: true, Baseline: xades.BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}}}})
	if err != nil {
		t.Fatal(err)
	}
	at := testcert.Now().Add(12 * time.Hour)
	result, report, err := v.Validate(t.Context(), onlySignature, xmldsig.Signatures(onlySignature)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{})
	if result != nil || err == nil || report.Indication() != xades.Indeterminate || report.SubIndication() != "CRYPTO_CONSTRAINTS_FAILURE_NO_POE" {
		t.Fatalf("borrowed SignatureValue proof for reference input: %v %s %v", report.Indication(), report.SubIndication(), err)
	}
	result, report, err = v.Validate(t.Context(), archived, xmldsig.Signatures(archived)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{})
	if result == nil || err != nil || report.Indication() != xades.Passed {
		t.Fatalf("exact archive reference proof: %v %s %v", report.Indication(), report.SubIndication(), err)
	}
}

func TestHistoricalExplicitPolicyDigestConstraints(t *testing.T) {
	chain := testcert.New(t)
	for _, tc := range []struct {
		name        string
		constraints []pki.CryptoConstraint
		maximum     int
		largePolicy bool
		want        error
		sub         string
	}{
		{"reliable policy digest", nil, 0, false, nil, ""},
		{"other digest unaffected", []pki.CryptoConstraint{{Hash: crypto.SHA384, ReliableUntil: testcert.Now()}}, 0, false, nil, ""},
		{"policy digest cutoff now", []pki.CryptoConstraint{{Hash: crypto.SHA512, ReliableUntil: testcert.Now()}}, 0, false, xades.ErrHistorical, "CRYPTO_CONSTRAINTS_FAILURE_NO_POE"},
		{"policy digest future cutoff", []pki.CryptoConstraint{{Hash: crypto.SHA512, ReliableUntil: testcert.Now().Add(time.Second)}}, 0, false, nil, ""},
		{"large policy under default budget", nil, 0, true, nil, ""},
		{"policy counts toward graph byte budget", nil, 64 << 10, true, historical.ErrLimit, "FORMAT_FAILURE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := []byte("explicit signature policy")
			if tc.largePolicy {
				policy = bytes.Repeat([]byte("p"), 1<<20)
			}
			source := input(t)
			options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#invoice-1", DigestMethod: xmldsig.SHA256, Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}}}}}, Properties: xades.BaselineProperties{SigningTime: testcert.Now(), Policy: &xades.SignaturePolicy{Identifier: xades.ObjectIdentifier{Identifier: "urn:policy"}, DigestMethod: xmldsig.SHA512}}, Validation: xades.BaselineVerifyOptions{PolicyDocument: policy}}
			signed, baseline, err := xades.SignBaseline(t.Context(), source, source.Root(), chain.LeafKey, chain.Leaf.Raw, options)
			if err != nil || baseline == nil {
				t.Fatal("baseline control failed", err)
			}
			zero := time.Duration(0)
			verifier, err := xades.NewHistoricalValidator(xades.HistoricalConfig{SignerPKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, CryptoConstraints: tc.constraints}, TSA: timeOptions(t, chain).TSA, MissingTSAAccuracy: &zero, Baseline: options.Validation, MaxBytes: tc.maximum})
			if err != nil {
				t.Fatal(err)
			}
			result, report, err := verifier.Validate(t.Context(), signed, baseline.Basic().Signature().Signature(), chain.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain)}}})
			if tc.want != nil {
				if result != nil || !errors.Is(err, tc.want) || report.SubIndication() != tc.sub || report.Cause() == nil {
					t.Fatalf("historical policy: %v, %s, %v; want %s, %v", result != nil, report.SubIndication(), err, tc.sub, tc.want)
				}
			} else if result == nil || err != nil || report.Indication() != xades.Passed || result.CurrentSignerTrust() == nil {
				t.Fatal("reliable explicit policy rejected", report.SubIndication(), err)
			}
		})
	}
}

func TestHistoricalEffectivePSSParameters(t *testing.T) {
	chain := testcert.New(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := testcert.Issue(t, chain.Leaf, chain.Root, &key.PublicKey, chain.RootKey)
	doc, err := document.Parse(t.Context(), []byte(`<r ID="data">parameterized PSS</r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	signed, _, err := xades.SignBaseline(t.Context(), doc, doc.Root(), key, leaf.Raw, xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.RSAPSS, SignatureParameters: xmldsig.SignatureParameters{PSS: &xmldsig.PSSParameters{Hash: crypto.SHA512, SaltLength: 24}}, References: []xmldsig.ReferenceTemplate{{URI: "#data", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}, {Algorithm: c14n.Exclusive}}}}}, Properties: xades.BaselineProperties{SigningTime: testcert.Now()}, Validation: xades.BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}, Policy: xmldsig.Policy{AllowedSignatureMethods: []string{xmldsig.RSAPSS}}}}})
	if err != nil {
		t.Fatal(err)
	}
	zero := time.Duration(0)
	config := xades.HistoricalConfig{SignerPKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}}, TSA: timeOptions(t, chain).TSA, MissingTSAAccuracy: &zero, Baseline: xades.BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}, Policy: xmldsig.Policy{AllowedSignatureMethods: []string{xmldsig.RSAPSS}}}}}
	v, err := xades.NewHistoricalValidator(config)
	if err != nil {
		t.Fatal(err)
	}
	input := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{historicalLongCRL(t, chain)}}}
	if result, report, err := v.Validate(t.Context(), signed, xmldsig.Signatures(signed)[0], leaf.Raw, testcert.Now(), input); err != nil || result == nil || report.Indication() != xades.Passed {
		t.Fatal("effective PSS profile", report.SubIndication(), err)
	}
	config.SignerPKI.CryptoConstraints = []pki.CryptoConstraint{{Hash: crypto.SHA512, ReliableUntil: testcert.Now()}}
	v, err = xades.NewHistoricalValidator(config)
	if err != nil {
		t.Fatal(err)
	}
	if result, report, err := v.Validate(t.Context(), signed, xmldsig.Signatures(signed)[0], leaf.Raw, testcert.Now(), input); err == nil || result != nil || report.SubIndication() != "CRYPTO_CONSTRAINTS_FAILURE_NO_POE" {
		t.Fatal("PSS parameters silently used default hash", report.SubIndication(), err)
	}
}

func historicalLongCRL(t testing.TB, chain testcert.Chain) []byte {
	t.Helper()
	raw, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: testcert.Now().Add(-2 * time.Minute), NextUpdate: testcert.Now().Add(7 * 24 * time.Hour)}, chain.Root, chain.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustSignatureValue(t testing.TB, doc *document.Document) []byte {
	t.Helper()
	for _, child := range xmldsig.Signatures(doc)[0].Children() {
		if child.Name() == (document.Name{Space: xmldsig.Namespace, Local: "SignatureValue"}) {
			raw, err := base64.StdEncoding.DecodeString(child.Text())
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
	}
	t.Fatal("missing signature")
	return nil
}

func exportHistoricalPair(t testing.TB, chain testcert.Chain, sufficient, insufficient *document.Document, at, negativeBest time.Time) {
	t.Helper()
	root := os.Getenv("XMLSEC_P7_EXPORT_FIXTURES")
	if root == "" {
		return
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]*document.Document{"sufficient.xml": sufficient, "insufficient.xml": insufficient} {
		raw, err := doc.XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.Root.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	anchor := sha256.Sum256(chain.Root.Raw)
	manifest := map[string]any{"version": "6.5.1", "validation_time": at.Format(time.RFC3339), "trust_anchor_sha256": hex.EncodeToString(anchor[:]), "pairs": []any{map[string]any{"name": "expired TSA archive recovery with distinct canonicalization", "sufficient": "sufficient.xml", "insufficient": "insufficient.xml", "want_sufficient": map[string]string{"indication": "TOTAL_PASSED", "best_signature_time": testcert.Now().Add(-time.Second).Format(time.RFC3339)}, "want_insufficient": map[string]string{"indication": "INDETERMINATE", "sub_indication": "OUT_OF_BOUNDS_NOT_REVOKED", "best_signature_time": negativeBest.Format(time.RFC3339)}}}}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWithTimeExpiredSignerAndCurrentProfile(t *testing.T) {
	c := expiredChain(t)
	proof := testcert.Now().Add(-2 * time.Hour)
	d := timedPastDocument(t, c, proof, nil)
	v := timeValidator(t, c)
	evidence := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{datedCRL(t, c, proof, 1)}}, TSA: timeOptions(t, c).Evidence}

	r, report, e := v.ValidateEnveloped(t.Context(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), evidence)
	if e != nil || r == nil || report.Indication() != xades.Passed || !r.ProofTime().Equal(proof) || !r.SignerTrust().VerificationTime().Equal(proof) || !r.Basic().Signature().CoversElement(d.Root()) {
		t.Fatal(report, e)
	}

	if !r.VerificationTime().Equal(testcert.Now()) || r.Profile() != "xmlsec-enveloped-with-time-v1" {
		t.Fatal("profile/time")
	}

	r.Timestamps()[0] = nil
	if r.Timestamps()[0] == nil {
		t.Fatal("mutable tokens")
	}

	current, e := xades.NewValidator(xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, TSA: timeOptions(t, c).TSA, MinimumLevel: xades.LevelBT})
	if e != nil {
		t.Fatal(e)
	}

	if r, e := current.ValidateEnveloped(t.Context(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), evidence); r != nil || !errors.Is(e, pki.ErrCertificate) {
		t.Fatal("current validator implicitly backdated", e)
	}

	var zero xades.WithTimeReport
	if zero.Indication() != xades.Indeterminate || zero.ProofTime() != (time.Time{}) {
		t.Fatal("zero reads valid")
	}
	// One immutable validator supports independent concurrent proofs/evidence.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			r, report, e := v.ValidateEnveloped(t.Context(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), evidence)
			if e != nil || r == nil || report.Indication() != xades.Passed {
				t.Error(e)
			}
		})
	}

	wg.Wait()
}

func TestWithTimeNoUntrustedRecovery(t *testing.T) {
	c := expiredChain(t)
	proof := testcert.Now().Add(-2 * time.Hour)
	d := timedPastDocument(t, c, proof, nil)
	v := timeValidator(t, c)
	good := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{datedCRL(t, c, proof, 1)}}, TSA: timeOptions(t, c).Evidence}
	assertReject := func(name string, doc *document.Document, evidence xades.ValidationEvidence, want error, status xades.Indication) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			r, report, e := v.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now(), evidence)
			if r != nil || e == nil || report.Indication() != status || want != nil && !errors.Is(e, want) {
				t.Fatal(r, report.Indication(), e)
			}
		})
	}
	assertReject("claimed SigningTime alone", basicDocument(t, c), good, xades.ErrTimestamp, xades.Indeterminate)
	missing := good
	missing.Signer = pki.Evidence{}
	assertReject("no fresh historical evidence", d, missing, pki.ErrUnavailable, xades.Indeterminate)
	missing = good
	missing.TSA = pki.Evidence{}
	assertReject("no current TSA evidence", d, missing, nil, xades.Indeterminate)

	revoked := good
	revoked.Signer.CRLs = [][]byte{datedCRL(t, c, proof, 1, x509.RevocationListEntry{SerialNumber: c.Leaf.SerialNumber, RevocationTime: proof.Add(-time.Hour), ReasonCode: 1})}
	assertReject("revoked at proof", d, revoked, pki.ErrRevoked, xades.Failed)
	revoked = good
	revoked.Signer.CRLs = append(append([][]byte(nil), good.Signer.CRLs...), datedCRL(t, c, testcert.Now(), 2, x509.RevocationListEntry{SerialNumber: c.Leaf.SerialNumber, RevocationTime: proof.Add(time.Minute), ReasonCode: 1}))
	assertReject("no later compromise recovery", d, revoked, xades.ErrLevel, xades.Indeterminate)
	for _, version1 := range []bool{false, true} {
		future := revoked.Signer.CRLs[1]
		if version1 {
			future = testcert.CRLV1(t, c, c.Leaf)
		}

		for _, folded := range []bool{false, true} {
			issuer := c.Root.Subject.CommonName
			if folded {
				issuer = strings.ToUpper(issuer)
			}

			changed := withTimeCRLIssuerEncoding(t, future, c, issuer, false)
			additional := good
			additional.Signer.CRLs = append(append([][]byte(nil), good.Signer.CRLs...), changed)
			name := "no later compromise recovery/" + map[bool]string{false: "v2", true: "v1"}[version1] + "/" + map[bool]string{false: "original issuer", true: "same issuer different case"}[folded]
			assertReject(name, d, additional, xades.ErrLevel, xades.Indeterminate)
		}
	}
	raw, _ := d.XML(t.Context())

	bad, e := document.Parse(t.Context(), bytes.Replace(raw, []byte(">123<"), []byte(">999<"), 1), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	if bytes.Equal(raw, mustXML(t, bad)) {
		t.Fatal("test mutation not applied")
	}

	assertReject("bad signed data", bad, good, xmldsig.ErrDigest, xades.Failed)
	// Corrupt a token rather than the signed XML: unsigned evidence cannot pass.
	text := string(raw)
	marker := "<xades:EncapsulatedTimeStamp"

	start := strings.Index(text, marker)
	if start < 0 {
		t.Fatal("timestamp marker")
	}

	start += strings.Index(text[start:], ">") + 1
	end := start + strings.Index(text[start:], "</")

	token, e := base64.StdEncoding.DecodeString(text[start:end])
	if e != nil {
		t.Fatal(e)
	}

	token[len(token)-1] ^= 1

	bad, e = document.Parse(t.Context(), []byte(text[:start]+base64.StdEncoding.EncodeToString(token)+text[end:]), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	assertReject("bad unsigned timestamp", bad, good, nil, xades.Indeterminate)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if r, report, e := v.ValidateEnveloped(ctx, d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), good); r != nil || !errors.Is(e, context.Canceled) || report.Indication() == xades.Passed {
		t.Fatal(e)
	}
}

func mustXML(t testing.TB, d *document.Document) []byte {
	t.Helper()

	raw, e := d.XML(t.Context())
	if e != nil {
		t.Fatal(e)
	}

	return raw
}

func TestWithTimeAccuracyAndEarliestProof(t *testing.T) {
	c := expiredChain(t)
	gen := c.Leaf.NotAfter.Add(-time.Second)
	accuracy := 2 * time.Second
	d := timedPastDocument(t, c, gen, &accuracy)
	evidence := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{datedCRL(t, c, gen, 1)}}, TSA: timeOptions(t, c).Evidence}

	v := timeValidator(t, c)
	if r, report, e := v.ValidateEnveloped(t.Context(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), evidence); r != nil || !errors.Is(e, xades.ErrLevel) || report.Indication() != xades.Indeterminate || !report.ProofTime().Equal(gen.Add(accuracy)) {
		t.Fatal("accuracy ignored", e)
	}

	early := testcert.Now().Add(-2 * time.Hour)
	d = timedPastDocument(t, c, early.Add(time.Minute), nil)

	d, _, e := xades.AddSignatureTimestamp(t.Context(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, datedTSA{chain: c, gen: early}, xades.AddTimestampOptions{Validation: timeOptions(t, c), Request: timestamp.RequestOptions{Policy: tsaPolicy()}})
	if e != nil {
		t.Fatal(e)
	}

	evidence.Signer.CRLs = [][]byte{datedCRL(t, c, early, 1)}

	r, report, e := v.ValidateEnveloped(t.Context(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), evidence)
	if e != nil || r == nil || !report.ProofTime().Equal(early) || len(r.Timestamps()) != 2 {
		t.Fatal("earliest POE changed", e)
	}

	if _, e := xades.NewWithTimeValidator(xades.WithTimeConfig{}); e == nil {
		t.Fatal("unchecked configuration")
	}
}

func datedCRL(t testing.TB, c testcert.Chain, at time.Time, number int64, entries ...x509.RevocationListEntry) []byte {
	t.Helper()

	b, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Hour), RevokedCertificateEntries: entries}, c.Root, c.RootKey)
	if e != nil {
		t.Fatal(e)
	}

	return b
}

func timeValidator(t testing.TB, c testcert.Chain) *xades.WithTimeValidator {
	t.Helper()
	o := timeOptions(t, c)

	v, e := xades.NewWithTimeValidator(xades.WithTimeConfig{SignerPKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, TSA: o.TSA})
	if e != nil {
		t.Fatal(e)
	}

	return v
}

func timedPastDocument(t *testing.T, c testcert.Chain, gen time.Time, accuracy *time.Duration) *document.Document {
	t.Helper()
	base := basicDocument(t, c)

	d, _, e := xades.AddSignatureTimestamp(t.Context(), base, xmldsig.Signatures(base)[0], c.Leaf.Raw, datedTSA{c, gen, accuracy}, xades.AddTimestampOptions{Validation: timeOptions(t, c), Request: timestamp.RequestOptions{Policy: tsaPolicy()}})
	if e != nil {
		t.Fatal(e)
	}

	return d
}

func expiredChain(t testing.TB) testcert.Chain {
	t.Helper()
	c := testcert.New(t)
	leaf := *c.Leaf
	leaf.NotAfter = testcert.Now().Add(-time.Hour)
	c.Leaf = testcert.Issue(t, &leaf, c.Root, &c.LeafKey.PublicKey, c.RootKey)

	return c
}

func TestWithTimeRelativeDistributionPointCertificate(t *testing.T) {
	chain := testcert.New(t)
	var relative []byte
	for _, test := range testcert.CertificateEncodings(t, chain) {
		if test.Name == "relative distribution point" {
			relative = test.DER
			break
		}
	}
	if len(relative) == 0 {
		t.Fatal("relative certificate fixture missing")
	}
	leaf := *chain.Leaf
	leaf.Raw = relative
	chain.Leaf = &leaf
	proof := testcert.Now().Add(-time.Hour)
	doc := timedPastDocument(t, chain, proof, nil)
	validator := timeValidator(t, chain)
	evidence := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{datedCRL(t, chain, proof, 1)}}, TSA: timeOptions(t, chain).Evidence}
	result, report, err := validator.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], relative, testcert.Now(), evidence)
	if err != nil || result == nil || report.Indication() != xades.Passed || !bytes.Equal(result.Basic().CertificateDER(), relative) {
		t.Fatal("with-time private certificate reparsing lost valid original DER", report, err)
	}
}

func withTimeCRLIssuerEncoding(t *testing.T, raw []byte, c testcert.Chain, commonName string, version1 bool) []byte {
	t.Helper()
	value, err := der.Read(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}
	outer, err := der.Sequence(value, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	body, err := der.Sequence(outer[0], 3, 7)
	if err != nil {
		t.Fatal(err)
	}
	issuerIndex := 1
	if body[0].Tag == asn1.TagInteger {
		issuerIndex++
	}
	name, err := asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: commonName}}})
	if err != nil {
		t.Fatal(err)
	}
	parts := make([][]byte, 0, len(body))
	for i, field := range body {
		if version1 && (i == 0 && issuerIndex == 2 || field.Class == 2 && field.Tag == 0) {
			continue
		}
		if i == issuerIndex {
			parts = append(parts, name)
		} else {
			parts = append(parts, field.FullBytes)
		}
	}
	tbs := der.Seq(parts...)
	algorithm, err := signature.Algorithm(outer[1])
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signature.Sign(t.Context(), c.RootKey, algorithm, tbs)
	if err != nil {
		t.Fatal(err)
	}
	bits, err := asn1.Marshal(asn1.BitString{Bytes: signed, BitLength: len(signed) * 8})
	if err != nil {
		t.Fatal(err)
	}
	return der.Seq(tbs, outer[1].FullBytes, bits)
}

func TestWithTimeV1CRLEvidence(t *testing.T) {
	c := expiredChain(t)
	proof := testcert.Now().Add(-2 * time.Hour)
	doc := timedPastDocument(t, c, proof, nil)
	validator := timeValidator(t, c)
	raw := withTimeCRLIssuerEncoding(t, datedCRL(t, c, proof, 1), c, strings.ToUpper(c.Root.Subject.CommonName), true)
	evidence := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{raw}}, TSA: timeOptions(t, c).Evidence}
	result, report, err := validator.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now(), evidence)
	if err != nil || result == nil || report.Indication() != xades.Passed {
		t.Fatal("already validated v1 CRL rejected during with-time reparse", report, err)
	}
}

func TestWithTimeAdvancedCRLInputScope(t *testing.T) {
	for _, kind := range []string{"delta", "indirect", "scoped"} {
		t.Run(kind, func(t *testing.T) {
			c := testcert.New(t)
			proof := testcert.Now().Add(-time.Hour)
			signer := *c.Root
			signerKey := c.RootKey
			var scope []byte
			pointName := func() []byte {
				return der.Ctx(0, der.Wrap(2, 0, true, der.Wrap(2, 6, false, []byte("urn:delegated-crl"))))
			}
			evidence := xades.ValidationEvidence{TSA: timeOptions(t, c).Evidence}
			if kind == "indirect" {
				template := &x509.Certificate{SerialNumber: big.NewInt(50), Subject: pkix.Name{CommonName: "delegated CRL signer"}, NotBefore: testcert.Now().Add(-24 * time.Hour), NotAfter: testcert.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCRLSign, SubjectKeyId: []byte{50, 51, 52}, BasicConstraintsValid: true}
				raw, e := x509.CreateCertificate(rand.Reader, template, c.Root, c.ResponderKey.Public(), c.RootKey)
				if e != nil {
					t.Fatal(e)
				}
				parsed, e := x509.ParseCertificate(raw)
				if e != nil {
					t.Fatal(e)
				}
				signer = *parsed
				signerKey = c.ResponderKey
				evidence.Signer.Intermediates = [][]byte{raw}
				leaf := *c.Leaf
				leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: der.Seq(der.Seq(pointName(), der.Wrap(2, 2, true, der.Ctx(4, signer.RawSubject))))}}
				raw, e = x509.CreateCertificate(rand.Reader, &leaf, c.Root, c.LeafKey.Public(), c.RootKey)
				if e != nil {
					t.Fatal(e)
				}
				c.Leaf, e = x509.ParseCertificate(raw)
				if e != nil {
					t.Fatal(e)
				}
				scope = der.Seq(pointName(), der.Wrap(2, 4, false, []byte{255}))
			}
			if kind == "scoped" {
				scope = der.Seq(der.Wrap(2, 1, false, []byte{255}))
			}
			makeList := func(number int64, at time.Time, revoke bool) []byte {
				template := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: at.Add(-time.Minute), NextUpdate: testcert.Now().Add(time.Hour)}
				if scope != nil {
					template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: scope})
				}
				if kind == "delta" && number == 2 {
					template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: der.Int(1)})
				}
				if revoke {
					entry := x509.RevocationListEntry{SerialNumber: c.Leaf.SerialNumber, RevocationTime: proof.Add(time.Minute), ReasonCode: 1}
					if kind == "indirect" {
						entry.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 29}, Critical: true, Value: der.Seq(der.Ctx(4, c.Root.RawSubject))}}
					}
					template.RevokedCertificateEntries = []x509.RevocationListEntry{entry}
				}
				raw, e := x509.CreateRevocationList(rand.Reader, template, &signer, signerKey)
				if e != nil {
					t.Fatal(e)
				}
				return raw
			}
			evidence.Signer.CRLs = [][]byte{makeList(1, proof, false), makeList(2, testcert.Now(), true)}
			policy := pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}
			current, e := pki.NewVerifier(policy)
			if e != nil {
				t.Fatal(e)
			}
			r, _, e := current.Verify(t.Context(), c.Leaf.Raw, testcert.Now(), evidence.Signer)
			if r != nil || !errors.Is(e, pki.ErrRevoked) {
				t.Fatal("current-time PKI lost authenticated future revocation", r, e)
			}
			r, _, e = current.Verify(t.Context(), c.Leaf.Raw, proof, evidence.Signer)
			if r == nil || e != nil {
				t.Fatal("proof-time fixture did not establish its old good status", r, e)
			}
			doc := timedPastDocument(t, c, proof, nil)
			v := timeValidator(t, c)
			result, report, e := v.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now(), evidence)
			if result != nil || !errors.Is(e, xades.ErrProfile) || report.Indication() != xades.Indeterminate {
				t.Fatal("broader current PKI input silently enabled historical recovery", result, report, e)
			}
			// Removing only the advanced future list leaves the direct base supported.
			// Scoped/indirect historical bases remain explicitly outside this B-T profile.
			evidence.Signer.CRLs = evidence.Signer.CRLs[:1]
			result, report, e = v.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now(), evidence)
			if kind == "delta" {
				if result == nil || e != nil || report.Indication() != xades.Passed {
					t.Fatal("ordinary direct complete proof input changed", result, report, e)
				}
			} else if result != nil || !errors.Is(e, xades.ErrProfile) {
				t.Fatal("historical scoped/indirect input escaped the closed profile", result, e)
			}
		})
	}
}

func TestWithTimeDirectCRLFreshestAdvertisementPolicy(t *testing.T) {
	c := testcert.New(t)
	proof := testcert.Now().Add(-time.Hour)
	point := der.Seq(der.Ctx(0, der.Wrap(2, 0, true, der.Wrap(2, 6, false, []byte("urn:delta-advertisement")))))
	template := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: proof.Add(-time.Minute), NextUpdate: testcert.Now().Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 46}, Value: der.Seq(point)}}}
	raw, err := x509.CreateRevocationList(rand.Reader, template, c.Root, c.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	doc := timedPastDocument(t, c, proof, nil)
	evidence := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{raw}}, TSA: timeOptions(t, c).Evidence}
	for _, disable := range []bool{false, true} {
		validator, err := xades.NewWithTimeValidator(xades.WithTimeConfig{SignerPKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL, CRL: pki.CRLOptions{DisableDeltaCRLs: disable}}, TSA: timeOptions(t, c).TSA})
		if err != nil {
			t.Fatal(err)
		}
		result, report, err := validator.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now(), evidence)
		if disable {
			if err != nil || result == nil || report.Indication() != xades.Passed {
				t.Fatal("unused advertisement changed the direct complete input scope", report, err)
			}
		} else if result != nil || !errors.Is(err, pki.ErrUnavailable) {
			t.Fatal("wrapper ignored PKI use-deltas policy", result, err)
		}
	}
}

// BenchmarkHistoricalValidation measures an offline LTA verification with an
// expired original TSA, exact archive coverage, embedded CRL and a second TSA.
// Certificate issuance, timestamp creation and policy setup are not timed.
func BenchmarkHistoricalValidation(b *testing.B) {
	chain, archived, insufficient, tsa := historicalArchivePair(b)
	zero := time.Duration(0)
	validator, err := xades.NewHistoricalValidator(xades.HistoricalConfig{
		SignerPKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}},
		TSA:       tsa, MissingTSAAccuracy: &zero, RequireAllTimestamps: true,
		Baseline: xades.BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}}},
	})
	if err != nil {
		b.Fatal(err)
	}
	at := testcert.Now().Add(48 * time.Hour)
	for name, doc := range map[string]*document.Document{"Archive": archived, "MissingArchive": insufficient} {
		b.Run(name, func(b *testing.B) {
			sig := xmldsig.Signatures(doc)[0]
			b.ReportAllocs()
			for b.Loop() {
				result, report, err := validator.Validate(b.Context(), doc, sig, chain.Leaf.Raw, at, xades.ValidationEvidence{})
				if name == "Archive" {
					if err != nil || result == nil || report.Indication() != xades.Passed {
						b.Fatal("historical archive rejected", err)
					}
				} else if err == nil || result != nil || report.SubIndication() != "OUT_OF_BOUNDS_NO_POE" {
					b.Fatal("missing proof accepted", err)
				}
			}
		})
	}
}
