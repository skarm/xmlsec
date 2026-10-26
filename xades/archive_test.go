package xades_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

type archiveTransport struct {
	key   crypto.Signer
	cert  []byte
	root  []byte
	now   time.Time
	calls int
}

func (t *archiveTransport) RoundTrip(ctx context.Context, q []byte) (io.ReadCloser, error) {
	t.calls++

	b, e := timestamp.IssueResponse(ctx, q, t.key, t.cert, timestamp.IssueOptions{Policy: tsaPolicy(), SerialNumber: big.NewInt(int64(t.calls)), GenTime: t.now, ExtraCertificates: [][]byte{t.root}})
	if e != nil {
		return nil, e
	}

	return io.NopCloser(bytes.NewReader(b)), nil
}

func TestEmbeddedMaterialAndArchiveRenewal(t *testing.T) {
	c, lt, lr, v := preparedLT(t)
	ctx := t.Context()
	m := lr.EmbeddedMaterial()

	m.Certificates[0][0] ^= 1
	if bytes.Equal(m.Certificates[0], lr.EmbeddedMaterial().Certificates[0]) {
		t.Fatal("material aliases result")
	}

	stricter := preservationValidator(t, c, xades.LevelLTA, 0)
	if r, e := stricter.ValidateEnveloped(ctx, lt, xmldsig.Signatures(lt)[0], c.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{}); r != nil || !errors.Is(e, xades.ErrLevel) {
		t.Fatal("LTA downgraded to LT", e)
	}

	input := lt

	for i, method := range []string{c14n.Exclusive, c14n.Canonical10, c14n.Canonical11} {
		t.Run(method, func(t *testing.T) {
			at := testcert.Now().Add(time.Duration(i) * time.Second)
			tr := &archiveTransport{key: c.TSAKey, cert: c.TSA.Raw, root: c.Root.Raw, now: at}
			before, _ := input.XML(ctx)

			archived, r, e := v.AddArchiveTimestamp(ctx, input, xmldsig.Signatures(input)[0], c.Leaf.Raw, at, tr, xades.AddArchiveOptions{Canonicalization: method})
			if e != nil {
				t.Fatal(e)
			}

			old, _ := input.XML(ctx)
			if !bytes.Equal(before, old) {
				t.Fatal("source changed")
			}

			if r.Level() != xades.LevelLTA || len(r.ArchiveTimestamps()) != i+1 || tr.calls != 1 {
				t.Fatal("archive count/transport")
			}

			attached, checked, err := v.AttachArchiveTimestamp(ctx, input, xmldsig.Signatures(input)[0], c.Leaf.Raw, at, r.ArchiveTimestamps()[i].TokenDER(), method)
			if err != nil || attached == nil || checked.Level() != xades.LevelLTA || len(checked.ArchiveTimestamps()) != i+1 {
				t.Fatal("archive attachment with default token budget", err)
			}

			roundtrip, _ := archived.XML(ctx)

			parsed, e := document.Parse(ctx, roundtrip, document.DefaultLimits())
			if e != nil {
				t.Fatal(e)
			}

			again, e := stricter.ValidateEnveloped(ctx, parsed, xmldsig.Signatures(parsed)[0], c.Leaf.Raw, at, xades.ValidationEvidence{})
			if e != nil || again.Level() != xades.LevelLTA {
				t.Fatal(e)
			}

			input = parsed
		})
	}

	if _, e := xades.VerifyTimedEnveloped(ctx, input, xmldsig.Signatures(input)[0], c.Leaf.Raw, xades.TimedOptions{TSA: mustTSA(t, c), At: testcert.Now().Add(2 * time.Second), Evidence: pki.Evidence{CRLs: [][]byte{testcert.CRL(t, c)}}}); e == nil {
		t.Fatal("lower timestamp API ignored archive properties")
	}
}

func mustTSA(t *testing.T, c testcert.Chain) *timestamp.Verifier {
	t.Helper()
	v, _ := archivePolicy(t, c)

	return v
}

func TestArchiveProtectsUnsignedMaterialAndNoFallback(t *testing.T) {
	c, lt, _, v := preparedLT(t)
	tr := &archiveTransport{key: c.TSAKey, cert: c.TSA.Raw, root: c.Root.Raw, now: testcert.Now()}

	doc, _, e := v.AddArchiveTimestamp(t.Context(), lt, xmldsig.Signatures(lt)[0], c.Leaf.Raw, testcert.Now(), tr, xades.AddArchiveOptions{})
	if e != nil {
		t.Fatal(e)
	}

	raw, _ := doc.XML(t.Context())

	mutated := bytes.Replace(raw, []byte("<xades:CertificateValues"), []byte(`<xades:CertificateValues Id="changed"`), 1)
	if bytes.Equal(raw, mutated) {
		t.Fatal("fixture mutation missed")
	}

	bad, e := document.Parse(t.Context(), mutated, document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	verifyOnlyXML(t, bad, c)
	evenBB := preservationValidator(t, c, xades.LevelBB, 0)

	r, e := evenBB.ValidateEnveloped(t.Context(), bad, xmldsig.Signatures(bad)[0], c.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{testcert.CRL(t, c)}}, TSA: pki.Evidence{CRLs: [][]byte{testcert.CRL(t, c)}}})
	if r != nil || e == nil {
		t.Fatal("invalid archive ignored at minimum BB")
	}
	// Remove the root certificate from validation material without altering any
	// SignedInfo/SignatureValue. Configured trust roots must not hide that gap.
	oldRoot := base64.StdEncoding.EncodeToString(c.Root.Raw)
	other := testcert.New(t)
	replace := base64.StdEncoding.EncodeToString(other.Root.Raw)
	noChain := bytes.Replace(raw, []byte(oldRoot), []byte(replace), 1)

	bad, e = document.Parse(t.Context(), noChain, document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	if r, e := v.ValidateEnveloped(t.Context(), bad, xmldsig.Signatures(bad)[0], c.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{}); r != nil || e == nil {
		t.Fatal("external roots hid missing embedded chain")
	}
	// Claimed/archived past time does not bypass CURRENT-time PKIX policy.
	if r, e := v.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now().Add(48*time.Hour), xades.ValidationEvidence{}); r != nil || e == nil {
		t.Fatal("silently switched to historical validation")
	}
}

func verifyOnlyXML(t *testing.T, d *document.Document, c testcert.Chain) {
	t.Helper()

	_, e := xmldsig.VerifySignature(t.Context(), d, xmldsig.Signatures(d)[0], c.Leaf.PublicKey, xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}, AdditionalIDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{{Space: xades.Namespace, Local: signedPropertiesLocal}}}}, ExpectedURIs: nil})
	if e != nil {
		t.Fatalf("test mutation damaged primary XMLDSig: %v", e)
	}
}

func TestArchiveBudgetsAndWrongToken(t *testing.T) {
	c, lt, lr, _ := preparedLT(t)
	small := preservationValidator(t, c, xades.LevelLT, 128)

	tr := &archiveTransport{key: c.TSAKey, cert: c.TSA.Raw, root: c.Root.Raw, now: testcert.Now()}
	if d, r, e := small.AddArchiveTimestamp(t.Context(), lt, xmldsig.Signatures(lt)[0], c.Leaf.Raw, testcert.Now(), tr, xades.AddArchiveOptions{}); d != nil || r != nil || e == nil || tr.calls != 0 {
		t.Fatal("budget not checked before transport", e, tr.calls)
	}

	v := preservationValidator(t, c, xades.LevelLT, 0)
	if d, r, e := v.AttachArchiveTimestamp(t.Context(), lt, xmldsig.Signatures(lt)[0], c.Leaf.Raw, testcert.Now(), lr.Timestamps()[0].TokenDER(), c14n.Exclusive); d != nil || r != nil || e == nil {
		t.Fatal("SignatureTimeStamp reused as ArchiveTimeStamp")
	}

	if d, r, e := v.EmbedValidationMaterial(t.Context(), lt, xmldsig.Signatures(lt)[0], c.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{}); d != nil || r != nil || e == nil {
		t.Fatal("existing evidence replaced")
	}
}

func TestArchiveRenewalChronologyAndReuse(t *testing.T) {
	chain, lt, _, validator := preparedLT(t)
	now := testcert.Now()
	server := &archiveTransport{key: chain.TSAKey, cert: chain.TSA.Raw, root: chain.Root.Raw, now: now}
	archived, first, err := validator.AddArchiveTimestamp(t.Context(), lt, xmldsig.Signatures(lt)[0], chain.Leaf.Raw, now, server, xades.AddArchiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := archived.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		at   time.Time
		pass bool
	}{
		{"equal generation time", now, true},
		{"later generation time", now.Add(time.Second), true},
		{"archive before previous archive", now.Add(-time.Nanosecond), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &archiveTransport{key: chain.TSAKey, cert: chain.TSA.Raw, root: chain.Root.Raw, now: tc.at}
			doc, result, err := validator.AddArchiveTimestamp(t.Context(), archived, xmldsig.Signatures(archived)[0], chain.Leaf.Raw, now.Add(2*time.Second), transport, xades.AddArchiveOptions{})
			if tc.pass {
				if doc == nil || result == nil || err != nil || result.Level() != xades.LevelLTA || len(result.ArchiveTimestamps()) != 2 || !result.ArchiveTimestamps()[1].Info().GenTime().Equal(tc.at) {
					t.Fatal("valid archive renewal failed", err)
				}
			} else if doc != nil || result != nil || !errors.Is(err, xades.ErrTimestamp) {
				t.Fatal("decreasing archive time accepted", doc != nil, result != nil, err)
			}
			after, err := archived.XML(t.Context())
			if err != nil || !bytes.Equal(before, after) || transport.calls != 1 {
				t.Fatal("renewal changed input or repeated TSA call", transport.calls, err)
			}
		})
	}
	token := first.ArchiveTimestamps()[0].TokenDER()
	if doc, result, err := validator.AttachArchiveTimestamp(t.Context(), archived, xmldsig.Signatures(archived)[0], chain.Leaf.Raw, now, token, ""); doc != nil || result != nil || !errors.Is(err, timestamp.ErrBinding) {
		t.Fatal("old archive token reused for a different archive input", err)
	}
	if doc, result, err := validator.AttachArchiveTimestamp(t.Context(), lt, xmldsig.Signatures(lt)[0], chain.Leaf.Raw, now, token, ""); doc == nil || result == nil || err != nil || result.Level() != xades.LevelLTA {
		t.Fatal("default canonicalization failed valid archive attachment", err)
	}
	tsa, _ := archivePolicy(t, chain)
	bounded, err := xades.NewValidator(xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, TSA: tsa, MinimumLevel: xades.LevelLTA, MaxArchiveTimestamps: 1})
	if err != nil {
		t.Fatal(err)
	}
	server.calls = 0
	if doc, result, err := bounded.AddArchiveTimestamp(t.Context(), archived, xmldsig.Signatures(archived)[0], chain.Leaf.Raw, now, server, xades.AddArchiveOptions{}); doc != nil || result != nil || !errors.Is(err, xades.ErrLevel) || server.calls != 0 {
		t.Fatal("archive count limit checked after TSA call", server.calls, err)
	}
	if doc, result, err := bounded.AttachArchiveTimestamp(t.Context(), archived, xmldsig.Signatures(archived)[0], chain.Leaf.Raw, now, token, ""); doc != nil || result != nil || !errors.Is(err, xades.ErrLevel) {
		t.Fatal("attachment bypassed archive count limit", err)
	}
	if doc, result, err := validator.AddArchiveTimestamp(t.Context(), lt, xmldsig.Signatures(lt)[0], chain.Leaf.Raw, now, server, xades.AddArchiveOptions{Canonicalization: "urn:unsupported"}); doc != nil || result != nil || !errors.Is(err, xades.ErrProfile) || server.calls != 0 {
		t.Fatal("unsupported canonicalization reached TSA", server.calls, err)
	}
}

func TestArchiveRejectsMalformedLatestWithoutFallback(t *testing.T) {
	chain, lt, _, validator := preparedLT(t)
	server := &archiveTransport{key: chain.TSAKey, cert: chain.TSA.Raw, root: chain.Root.Raw, now: testcert.Now()}
	first, _, err := validator.AddArchiveTimestamp(t.Context(), lt, xmldsig.Signatures(lt)[0], chain.Leaf.Raw, testcert.Now(), server, xades.AddArchiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server.now = testcert.Now().Add(time.Second)
	archived, _, err := validator.AddArchiveTimestamp(t.Context(), first, xmldsig.Signatures(first)[0], chain.Leaf.Raw, server.now, server, xades.AddArchiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*tree.Node)
		want   error
	}{
		{"two tokens in one archive", func(n *tree.Node) {
			duplicate := tree.ImportSubtree(n.Children[1])
			duplicate.Parent = n
			n.Children = append(n.Children, duplicate)
		}, xades.ErrProfile},
		{"missing canonicalization", func(n *tree.Node) { n.Children = n.Children[1:] }, xades.ErrTimestamp},
		{"unsupported canonicalization", func(n *tree.Node) { n.Children[0].Attrs[0].Value = "urn:unsupported" }, xades.ErrTimestamp},
		{"canonicalization has XML child", func(n *tree.Node) { baselineTestAppend(n.Children[0], xades.Namespace, "Child", "xades") }, xades.ErrTimestamp},
		{"empty token", func(n *tree.Node) { n.Children[1].Children = nil }, xades.ErrTimestamp},
		{"unknown token attribute", func(n *tree.Node) {
			n.Children[1].Attrs = append(n.Children[1].Attrs, tree.Attribute{Name: document.Name{Local: "unknown"}, Value: "1"})
		}, xades.ErrProfile},
		{"invalid token encoding", func(n *tree.Node) {
			n.Children[1].Attrs = []tree.Attribute{{Name: document.Name{Local: "Encoding"}, Value: "urn:unsupported"}}
		}, xades.ErrTimestamp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			draft, err := tree.Clone(t.Context(), archived)
			if err != nil {
				t.Fatal(err)
			}
			unsigned := baselineTestNode(tree.Root(draft), xades.Namespace, "UnsignedSignatureProperties")
			tc.mutate(unsigned.Children[len(unsigned.Children)-1])
			raw, err := draft.XML(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			doc, err := document.Parse(t.Context(), raw, document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			verifyOnlyXML(t, doc, chain)
			if result, err := validator.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], chain.Leaf.Raw, server.now, xades.ValidationEvidence{}); result != nil || !errors.Is(err, tc.want) {
				t.Fatal("bad latest archive fell back to an older valid archive", result != nil, err)
			}
		})
	}
}

func TestArchiveTSAChainMustBeEmbeddedAndExplicitlyTrusted(t *testing.T) {
	chain, other := testcert.New(t), testcert.New(t)
	rootTemplate := *other.Root
	rootTemplate.Subject = pkix.Name{CommonName: "independent archive TSA root"}
	rootTemplate.RawSubject, rootTemplate.RawIssuer = nil, nil
	rootTemplate.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: bytes.Repeat([]byte{7}, 16<<10)}}
	other.Root = testcert.Issue(t, &rootTemplate, &rootTemplate, other.RootKey.Public(), other.RootKey)
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		t.Fatal(err)
	}
	other.TSA = testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "new archive TSA"}, NotBefore: testcert.Now().Add(-time.Hour), NotAfter: testcert.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}}, other.Root, other.TSAKey.Public(), other.RootKey)
	makeValidator := func(trustOther bool, maximum int) (*xades.Validator, *timestamp.Verifier) {
		t.Helper()
		roots := [][]byte{chain.Root.Raw}
		if trustOther {
			roots = append(roots, other.Root.Raw)
		}
		tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: roots, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{tsaPolicy()}})
		if err != nil {
			t.Fatal(err)
		}
		validator, err := xades.NewValidator(xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, TSA: tsa, MinimumLevel: xades.LevelLT, MaxTokenBytes: maximum})
		if err != nil {
			t.Fatal(err)
		}
		return validator, tsa
	}
	validator, tsa := makeValidator(true, 0)
	rootCRL, otherCRL := testcert.CRL(t, chain), testcert.CRL(t, other)
	tsaProof := pki.Evidence{CRLs: [][]byte{rootCRL, otherCRL}}
	basic := basicDocument(t, chain)
	timed, _, err := xades.AddSignatureTimestamp(t.Context(), basic, xmldsig.Signatures(basic)[0], chain.Leaf.Raw, &archiveTransport{key: chain.TSAKey, cert: chain.TSA.Raw, root: chain.Root.Raw, now: testcert.Now().Add(-time.Second)}, xades.AddTimestampOptions{Validation: xades.TimedOptions{TSA: tsa, At: testcert.Now(), Evidence: tsaProof}})
	if err != nil {
		t.Fatal(err)
	}
	lt, _, err := validator.EmbedValidationMaterial(t.Context(), timed, xmldsig.Signatures(timed)[0], chain.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{rootCRL}}, TSA: tsaProof})
	if err != nil {
		t.Fatal(err)
	}
	before, err := lt.XML(t.Context())
	if err != nil || bytes.Contains(before, []byte(base64.StdEncoding.EncodeToString(other.Root.Raw))) {
		t.Fatal("control LT already embeds the new TSA root", err)
	}
	transport := func(embedRoot bool, calls *int) timestamp.Transport {
		return timestamp.TransportFunc(func(ctx context.Context, query []byte) (io.ReadCloser, error) {
			*calls++
			var extra [][]byte
			if embedRoot {
				extra = [][]byte{other.Root.Raw}
			}
			raw, err := timestamp.IssueResponse(ctx, query, other.TSAKey, other.TSA.Raw, timestamp.IssueOptions{Policy: tsaPolicy(), SerialNumber: big.NewInt(1), GenTime: testcert.Now(), ExtraCertificates: extra})
			if err != nil {
				return nil, err
			}
			return io.NopCloser(bytes.NewReader(raw)), nil
		})
	}
	calls := 0
	doc, result, err := validator.AddArchiveTimestamp(t.Context(), lt, xmldsig.Signatures(lt)[0], chain.Leaf.Raw, testcert.Now(), transport(true, &calls), xades.AddArchiveOptions{})
	if err != nil || doc == nil || result == nil || calls != 1 || result.Level() != xades.LevelLTA || len(result.ArchiveTimestamps()) != 1 {
		t.Fatal("trusted fully embedded TSA chain rejected", err)
	}
	archive := result.ArchiveTimestamps()[0]
	path := archive.Trust().ChainDER()
	if len(path) != 2 || !bytes.Equal(path[1], other.Root.Raw) || archive.Trust().RevocationStatus() != pki.Valid {
		t.Fatal("archive used the wrong trust anchor")
	}
	for _, tc := range []struct {
		name            string
		trust, embedded bool
		maximum         int
		want            error
	}{
		{"trusted root omitted from all embedded bytes", true, false, 0, xades.ErrLevel},
		{"embedded root is not a trust decision", false, true, 0, timestamp.ErrTrust},
		{"new token exceeds profile budget", true, true, 8 << 10, xades.ErrTimestamp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, _ := makeValidator(tc.trust, tc.maximum)
			calls := 0
			doc, result, err := policy.AddArchiveTimestamp(t.Context(), lt, xmldsig.Signatures(lt)[0], chain.Leaf.Raw, testcert.Now(), transport(tc.embedded, &calls), xades.AddArchiveOptions{})
			if doc != nil || result != nil || !errors.Is(err, tc.want) || calls != 1 {
				t.Fatalf("archive trust/budget: doc=%v result=%v calls=%d error=%v; want %v", doc != nil, result != nil, calls, err, tc.want)
			}
			if tc.maximum != 0 {
				if len(archive.TokenDER()) <= tc.maximum {
					t.Fatal("control token does not exceed configured budget")
				}
				if doc, result, err := policy.AttachArchiveTimestamp(t.Context(), lt, xmldsig.Signatures(lt)[0], chain.Leaf.Raw, testcert.Now(), archive.TokenDER(), ""); doc != nil || result != nil || !errors.Is(err, xades.ErrTimestamp) {
					t.Fatal("attachment bypassed token byte budget", err)
				}
			}
			after, err := lt.XML(t.Context())
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed archive generation modified LT input", err)
			}
		})
	}
}

func TestArchiveRejectsRevokedTSAWithoutFallback(t *testing.T) {
	chain := testcert.New(t)
	now := testcert.Now()
	key := testcert.Key(t)
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		t.Fatal(err)
	}
	revoked := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "revoked archive TSA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}}, chain.Root, key.Public(), chain.RootKey)
	// Embed this signed CRL before generating archive imprints. Editing evidence
	// afterwards would reject the archive's binding before reaching revocation.
	proof := pki.Evidence{CRLs: [][]byte{datedCRL(t, chain, now, 1, x509.RevocationListEntry{SerialNumber: revoked.SerialNumber, RevocationTime: now.Add(-time.Minute), ReasonCode: 1})}}
	tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{tsaPolicy()}})
	if err != nil {
		t.Fatal(err)
	}
	validator, err := xades.NewValidator(xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, TSA: tsa, MinimumLevel: xades.LevelLT})
	if err != nil {
		t.Fatal(err)
	}
	basic := basicDocument(t, chain)
	timed, _, err := xades.AddSignatureTimestamp(t.Context(), basic, xmldsig.Signatures(basic)[0], chain.Leaf.Raw, &archiveTransport{key: chain.TSAKey, cert: chain.TSA.Raw, root: chain.Root.Raw, now: now.Add(-time.Second)}, xades.AddTimestampOptions{Validation: xades.TimedOptions{TSA: tsa, At: now, Evidence: proof}})
	if err != nil {
		t.Fatal(err)
	}
	lt, _, err := validator.EmbedValidationMaterial(t.Context(), timed, xmldsig.Signatures(timed)[0], chain.Leaf.Raw, now, xades.ValidationEvidence{Signer: proof, TSA: proof})
	if err != nil {
		t.Fatal(err)
	}
	prior, good, err := validator.AddArchiveTimestamp(t.Context(), lt, xmldsig.Signatures(lt)[0], chain.Leaf.Raw, now, &archiveTransport{key: chain.TSAKey, cert: chain.TSA.Raw, root: chain.Root.Raw, now: now}, xades.AddArchiveOptions{})
	if err != nil || prior == nil || good == nil || good.Level() != xades.LevelLTA || len(good.ArchiveTimestamps()) != 1 {
		t.Fatal("unrevoked TSA must produce a valid preceding archive", err)
	}
	before, err := prior.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	at := now.Add(time.Second)
	var request *timestamp.Request
	var tokenDER []byte
	calls := 0
	transport := timestamp.TransportFunc(func(ctx context.Context, query []byte) (io.ReadCloser, error) {
		calls++
		request, err = timestamp.ParseRequest(query)
		if err != nil {
			return nil, err
		}
		raw, issueErr := timestamp.IssueResponse(ctx, query, key, revoked.Raw, timestamp.IssueOptions{Policy: tsaPolicy(), SerialNumber: big.NewInt(2), GenTime: at, ExtraCertificates: [][]byte{chain.Root.Raw}})
		if issueErr != nil {
			return nil, issueErr
		}
		response, parseErr := timestamp.ParseResponse(ctx, raw)
		if parseErr != nil {
			return nil, parseErr
		}
		tokenDER = response.TokenDER()
		return io.NopCloser(bytes.NewReader(raw)), nil
	})
	if doc, result, err := validator.AddArchiveTimestamp(t.Context(), prior, xmldsig.Signatures(prior)[0], chain.Leaf.Raw, at, transport, xades.AddArchiveOptions{}); doc != nil || result != nil || !errors.Is(err, pki.ErrRevoked) || calls != 1 {
		t.Fatal("archive issuance bypassed TSA revocation or returned partial output", calls, err)
	}
	token, err := timestamp.ParseToken(t.Context(), tokenDER)
	if err != nil {
		t.Fatal(err)
	}
	if authenticated, err := tsa.Authenticate(t.Context(), token, timestamp.Expectation{Imprint: request.Imprint(), Nonce: request.Nonce(), Policy: request.Policy()}, at); err != nil || authenticated == nil || !authenticated.Valid() || !bytes.Equal(authenticated.CertificateDER(), revoked.Raw) {
		t.Fatal("negative control must have a valid signature and exact archive binding", err)
	}
	if doc, result, err := validator.AttachArchiveTimestamp(t.Context(), prior, xmldsig.Signatures(prior)[0], chain.Leaf.Raw, at, tokenDER, c14n.Exclusive); doc != nil || result != nil || !errors.Is(err, pki.ErrRevoked) {
		t.Fatal("attachment bypassed TSA revocation or returned partial output", err)
	}

	// Construct received XML containing the rejected token without using the
	// augmentation API, which correctly refuses to publish it.
	draft, err := tree.Clone(t.Context(), prior)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := baselineTestNode(tree.Root(draft), xades.Namespace, "UnsignedSignatureProperties")
	archive := baselineTestAppend(unsigned, xades.Namespace141, "ArchiveTimeStamp", "xades141")
	archive.NS = []tree.Namespace{{Prefix: "xades141", URI: xades.Namespace141}, {Prefix: "ds", URI: xmldsig.Namespace}, {Prefix: "xades", URI: xades.Namespace}}
	method := baselineTestAppend(archive, xmldsig.Namespace, "CanonicalizationMethod", "ds")
	method.Attrs = []tree.Attribute{{Name: document.Name{Local: "Algorithm"}, Value: c14n.Exclusive}}
	enc := baselineTestAppend(archive, xades.Namespace, "EncapsulatedTimeStamp", "xades")
	enc.Children = []*tree.Node{{Kind: tree.TextNode, Data: base64.StdEncoding.EncodeToString(tokenDER), Parent: enc}}
	raw, err := draft.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	received, err := document.Parse(t.Context(), raw, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	verifyOnlyXML(t, received, chain)
	if result, err := validator.ValidateEnveloped(t.Context(), received, xmldsig.Signatures(received)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{}); result != nil || !errors.Is(err, xades.ErrTimestamp) || !errors.Is(err, pki.ErrRevoked) {
		t.Fatal("received archive with revoked TSA fell back to earlier valid archive", err)
	}
	after, err := prior.XML(t.Context())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed archive augmentation modified its source", err)
	}
}

func TestPreservationContainerOrderAndSchema(t *testing.T) {
	chain, original, _, validator := preparedLT(t)
	withCertificates := func(root *tree.Node) *tree.Node {
		tsvd := baselineTestNode(root, xades.Namespace141, "TimeStampValidationData")
		certificates := tree.ImportSubtree(baselineTestNode(root, xades.Namespace, "CertificateValues"))
		certificates.Parent = tsvd
		tsvd.Children = append([]*tree.Node{certificates}, tsvd.Children...)
		return tsvd
	}
	for _, tc := range []struct {
		name   string
		mutate func(*tree.Node)
		valid  bool
	}{
		{"TSA certificates before revocation data", func(root *tree.Node) { withCertificates(root) }, true},
		{"TSA certificates after revocation data", func(root *tree.Node) {
			n := withCertificates(root)
			n.Children[0], n.Children[1] = n.Children[1], n.Children[0]
		}, false},
		{"duplicate TSA certificate containers", func(root *tree.Node) {
			n := withCertificates(root)
			duplicate := tree.ImportSubtree(n.Children[0])
			duplicate.Parent = n
			n.Children[1] = duplicate
		}, false},
		{"duplicate TSA revocation containers", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace141, "TimeStampValidationData")
			duplicate := tree.ImportSubtree(n.Children[0])
			duplicate.Parent = n
			n.Children = append(n.Children, duplicate)
		}, false},
		{"empty TSA material", func(root *tree.Node) {
			baselineTestNode(root, xades.Namespace141, "TimeStampValidationData").Children = nil
		}, false},
		{"TSA material URI attribute", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace141, "TimeStampValidationData")
			n.Attrs = []tree.Attribute{{Name: document.Name{Local: "URI"}, Value: "https://example.test/evidence"}}
		}, false},
		{"unknown TSA material", func(root *tree.Node) {
			baselineTestNode(root, xades.Namespace141, "TimeStampValidationData").Children[0].Name.Local = "UnknownValues"
		}, false},
		{"invalid TSA certificate encoding", func(root *tree.Node) {
			n := withCertificates(root).Children[0].Children[0]
			n.Children = []*tree.Node{{Kind: tree.TextNode, Data: "***", Parent: n}}
		}, false},
		{"invalid TSA revocation encoding", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace141, "TimeStampValidationData").Children[0].Children[0].Children[0]
			n.Children = []*tree.Node{{Kind: tree.TextNode, Data: "***", Parent: n}}
		}, false},
		{"TSA material before timestamp", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace, "UnsignedSignatureProperties")
			n.Children[0], n.Children[1] = n.Children[1], n.Children[0]
		}, false},
		{"timestamp after signer certificates", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace, "UnsignedSignatureProperties")
			duplicate := tree.ImportSubtree(n.Children[0])
			duplicate.Parent = n
			n.Children = append(n.Children[:3], append([]*tree.Node{duplicate}, n.Children[3:]...)...)
		}, false},
		{"signer revocation before certificates", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace, "UnsignedSignatureProperties")
			n.Children[2], n.Children[3] = n.Children[3], n.Children[2]
		}, false},
		{"unknown unsigned property", func(root *tree.Node) {
			baselineTestAppend(baselineTestNode(root, xades.Namespace, "UnsignedSignatureProperties"), xades.Namespace, "UnknownProperty", "xades")
		}, false},
		{"invalid signer certificate encoding", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace, "CertificateValues").Children[0]
			n.Children = []*tree.Node{{Kind: tree.TextNode, Data: "***", Parent: n}}
		}, false},
		{"invalid signer revocation encoding", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace, "UnsignedSignatureProperties").Children[3].Children[0].Children[0]
			n.Children = []*tree.Node{{Kind: tree.TextNode, Data: "***", Parent: n}}
		}, false},
		{"duplicate signer revocation containers", func(root *tree.Node) {
			n := baselineTestNode(root, xades.Namespace, "UnsignedSignatureProperties")
			duplicate := tree.ImportSubtree(n.Children[3])
			duplicate.Parent = n
			n.Children = append(n.Children, duplicate)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			draft, err := tree.Clone(t.Context(), original)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(tree.Root(draft))
			raw, err := draft.XML(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			doc, err := document.Parse(t.Context(), raw, document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			verifyOnlyXML(t, doc, chain)
			result, err := validator.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], chain.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{})
			if tc.valid {
				if result == nil || err != nil || result.Level() != xades.LevelLT || len(result.Timestamps()) != 1 {
					t.Fatal("valid TSA validation material rejected", err)
				}
			} else if result != nil || !errors.Is(err, xades.ErrProfile) {
				t.Fatal("invalid preservation grammar accepted", result != nil, err)
			}
		})
	}
}

func preservationValidator(t *testing.T, c testcert.Chain, level xades.Level, limit int) *xades.Validator {
	t.Helper()
	tsa, _ := archivePolicy(t, c)

	v, e := xades.NewValidator(xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{c.Root.Raw}, KeyUsages: nil, Revocation: pki.RequireCRL}, TSA: tsa, MinimumLevel: level, MaxArchiveBytes: limit})
	if e != nil {
		t.Fatal(e)
	}

	return v
}

func preparedLT(t *testing.T) (testcert.Chain, *document.Document, *xades.ValidationResult, *xades.Validator) {
	t.Helper()
	c := testcert.New(t)
	tsa, proof := archivePolicy(t, c)
	doc := basicDocument(t, c)
	timed := xades.TimedOptions{TSA: tsa, At: testcert.Now(), Evidence: proof}
	tr := &archiveTransport{key: c.TSAKey, cert: c.TSA.Raw, root: c.Root.Raw, now: testcert.Now().Add(-time.Second)}

	bt, _, e := xades.AddSignatureTimestamp(t.Context(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, tr, xades.AddTimestampOptions{Validation: timed})
	if e != nil {
		t.Fatal(e)
	}

	v := preservationValidator(t, c, xades.LevelLT, 0)
	rawBefore, _ := bt.XML(t.Context())

	lt, r, e := v.EmbedValidationMaterial(t.Context(), bt, xmldsig.Signatures(bt)[0], c.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{Signer: proof, TSA: proof})
	if e != nil {
		t.Fatal(e)
	}

	after, _ := bt.XML(t.Context())
	if !bytes.Equal(rawBefore, after) {
		t.Fatal("input changed")
	}

	if r.Level() != xades.LevelLT || len(r.EmbeddedMaterial().Certificates) == 0 || len(r.EmbeddedMaterial().CRLs) == 0 {
		t.Fatal("missing material")
	}

	return c, lt, r, v
}

func TestValidationMaterialOCSPRoundTrip(t *testing.T) {
	c := testcert.New(t)
	response := func(certificate *x509.Certificate) []byte {
		t.Helper()
		request, err := pki.CreateOCSPRequest(certificate.Raw, c.Root.Raw, crypto.SHA256, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := pki.CreateOCSPResponse(t.Context(), request, certificate.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: testcert.Now(), ThisUpdate: testcert.Now().Add(-time.Minute), NextUpdate: testcert.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	leafOCSP, tsaOCSP := response(c.Leaf), response(c.TSA)
	tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireOCSP}, AllowedPolicies: []asn1.ObjectIdentifier{tsaPolicy()}})
	if err != nil {
		t.Fatal(err)
	}
	proof := xades.ValidationEvidence{Signer: pki.Evidence{OCSPResponses: [][]byte{leafOCSP}}, TSA: pki.Evidence{OCSPResponses: [][]byte{tsaOCSP}}}
	basic := basicDocument(t, c)
	timed, _, err := xades.AddSignatureTimestamp(t.Context(), basic, xmldsig.Signatures(basic)[0], c.Leaf.Raw, &localTSA{chain: c}, xades.AddTimestampOptions{Validation: xades.TimedOptions{TSA: tsa, At: testcert.Now(), Evidence: proof.TSA}})
	if err != nil {
		t.Fatal(err)
	}
	v, err := xades.NewValidator(xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireOCSP}, TSA: tsa, MinimumLevel: xades.LevelLT})
	if err != nil {
		t.Fatal(err)
	}
	before, err := timed.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	doc, result, err := v.EmbedValidationMaterial(t.Context(), timed, xmldsig.Signatures(timed)[0], c.Leaf.Raw, testcert.Now(), proof)
	if err != nil || doc == nil || result == nil || result.Level() != xades.LevelLT {
		t.Fatal("OCSP material did not produce LT", err)
	}
	after, err := timed.XML(t.Context())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("embedding modified source", err)
	}
	material := result.EmbeddedMaterial()
	if len(material.CRLs) != 0 || len(material.OCSPResponses) != 2 {
		t.Fatal("unexpected embedded evidence", len(material.CRLs), len(material.OCSPResponses))
	}
	material.OCSPResponses[0][0] ^= 1
	if checked, err := v.ValidateEnveloped(t.Context(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{}); checked == nil || err != nil || checked.Level() != xades.LevelLT {
		t.Fatal("embedded-only OCSP validation or getter ownership failed", err)
	}
}

func archivePolicy(t *testing.T, c testcert.Chain) (*timestamp.Verifier, pki.Evidence) {
	t.Helper()
	o := timeOptions(t, c)

	return o.TSA, o.Evidence
}

func TestHistoricalArchiveChronology(t *testing.T) {
	chain, original, _, tsa := historicalArchivePair(t)
	originalToken := historicalArchiveToken(t, original)
	var archiveCertificate []byte
	for _, raw := range originalToken.Certificates() {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatal(err)
		}
		if certificate.SerialNumber.Cmp(big.NewInt(103)) == 0 {
			archiveCertificate = raw
		}
	}
	if len(archiveCertificate) == 0 {
		t.Fatal("missing current archive TSA certificate")
	}

	zero := time.Duration(0)
	config := xades.HistoricalConfig{
		SignerPKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}},
		TSA:       tsa, MissingTSAAccuracy: &zero, RequireAllTimestamps: true,
		Baseline: xades.BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}}},
	}
	at := testcert.Now().Add(48 * time.Hour)
	variants := map[string]*document.Document{}
	for _, test := range []struct {
		name     string
		file     string
		issued   time.Time
		accuracy time.Duration
		want     string
	}{
		{"covering archive precedes protected token in processing", "overlap.xml", testcert.Now().Add(-time.Minute), 10 * time.Minute, ""},
		{"disjoint archive before protected token fails", "disjoint.xml", testcert.Now().Add(-2 * time.Hour), 0, "TIMESTAMP_ORDER_FAILURE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := reissueHistoricalArchive(t, original, chain.TSAKey, archiveCertificate, chain.Root.Raw, test.issued, test.accuracy)
			variants[test.file] = changed
			verifyOnlyXML(t, changed, chain)
			validator, err := xades.NewHistoricalValidator(config)
			if err != nil {
				t.Fatal(err)
			}
			result, report, err := validator.Validate(t.Context(), changed, xmldsig.Signatures(changed)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{})
			if test.want != "" {
				if result != nil || err == nil || report.Indication() != xades.Indeterminate || report.SubIndication() != test.want {
					t.Fatalf("indication=%v sub=%s result=%v err=%v", report.Indication(), report.SubIndication(), result != nil, err)
				}
				return
			}
			if result == nil || err != nil || report.Indication() != xades.Passed || !report.BestSignatureTime().Equal(testcert.Now().Add(-time.Second)) {
				t.Fatalf("indication=%v sub=%s best=%s err=%v", report.Indication(), report.SubIndication(), report.BestSignatureTime(), err)
			}
			stamps := report.Timestamps()
			if len(stamps) != 2 || !stamps[0].Archive || stamps[0].Indication != xades.Passed || stamps[1].Archive || stamps[1].Indication != xades.Passed {
				t.Fatal("covering proof was not accepted before protected token", stamps)
			}
		})
	}
	exportHistoricalChronology(t, chain, variants)

	t.Run("optional untrusted clock cannot reject covering archive", func(t *testing.T) {
		other := testcert.New(t)
		template := *other.TSA
		template.SerialNumber = big.NewInt(103)
		template.NotAfter = testcert.Now().Add(8 * 24 * time.Hour)
		eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
		if err != nil {
			t.Fatal(err)
		}
		template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}
		certificate := testcert.Issue(t, &template, other.Root, other.TSAKey.Public(), other.RootKey)
		otherTSA, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{other.Root.Raw}, Revocation: pki.RequireCRL}, Certificates: [][]byte{certificate.Raw}, AllowedPolicies: []asn1.ObjectIdentifier{tsaPolicy()}})
		if err != nil {
			t.Fatal(err)
		}
		archiveTime := testcert.Now().Add(-time.Minute)
		changed := reissueHistoricalArchive(t, original, other.TSAKey, certificate.Raw, other.Root.Raw, archiveTime, 0)
		verifyOnlyXML(t, changed, chain)
		config.TSA = otherTSA
		config.RequireAllTimestamps = false
		validator, err := xades.NewHistoricalValidator(config)
		if err != nil {
			t.Fatal(err)
		}
		result, report, err := validator.Validate(t.Context(), changed, xmldsig.Signatures(changed)[0], chain.Leaf.Raw, at, xades.ValidationEvidence{TSA: pki.Evidence{CRLs: [][]byte{historicalLongCRL(t, other)}}})
		if result == nil || err != nil || report.Indication() != xades.Passed || !report.BestSignatureTime().Equal(archiveTime) {
			t.Fatalf("optional foreign clock poisoned archive: %v/%s best=%s err=%v", report.Indication(), report.SubIndication(), report.BestSignatureTime(), err)
		}
		stamps := report.Timestamps()
		if len(stamps) != 2 || !stamps[0].Archive || stamps[0].Indication != xades.Passed || stamps[1].Archive || stamps[1].Indication == xades.Passed {
			t.Fatal("untrusted signature timestamp was treated as an accepted clock", stamps)
		}
	})
}

func exportHistoricalChronology(t testing.TB, chain testcert.Chain, documents map[string]*document.Document) {
	t.Helper()
	directory := os.Getenv("XMLSEC_P7_EXPORT_CHRONOLOGY_FIXTURES")
	if directory == "" {
		return
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, document := range documents {
		raw, err := document.XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.Root.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func historicalArchiveToken(t testing.TB, doc *document.Document) *timestamp.Token {
	t.Helper()
	var values []document.Element
	stack := []document.Element{doc.Root()}
	for len(stack) != 0 {
		element := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		stack = append(stack, element.Children()...)
		if element.Name() != (document.Name{Space: "http://uri.etsi.org/01903/v1.4.1#", Local: "ArchiveTimeStamp"}) {
			continue
		}
		for _, child := range element.Children() {
			if child.Name() == (document.Name{Space: xades.Namespace, Local: "EncapsulatedTimeStamp"}) {
				values = append(values, child)
			}
		}
	}
	if len(values) != 1 {
		t.Fatal("expected one archive timestamp token")
	}
	raw, err := base64.StdEncoding.DecodeString(values[0].Text())
	if err != nil {
		t.Fatal(err)
	}
	token, err := timestamp.ParseToken(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func reissueHistoricalArchive(t testing.TB, doc *document.Document, signer crypto.Signer, certificate, root []byte, at time.Time, accuracy time.Duration) *document.Document {
	t.Helper()
	previous := historicalArchiveToken(t, doc)
	info := previous.UnverifiedInfo()
	request, err := timestamp.CreateImprintRequest(info.Imprint(), timestamp.RequestOptions{Policy: info.Policy(), OmitNonce: true})
	if err != nil {
		t.Fatal(err)
	}
	responseDER, err := timestamp.IssueResponse(t.Context(), request.DER(), signer, certificate, timestamp.IssueOptions{GenTime: at, Accuracy: &accuracy, SerialNumber: big.NewInt(at.Unix()), Policy: info.Policy(), ExtraCertificates: [][]byte{root}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := timestamp.ParseResponse(t.Context(), responseDER)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	oldText := []byte(base64.StdEncoding.EncodeToString(previous.DER()))
	if bytes.Count(raw, oldText) != 1 {
		t.Fatal("archive token replacement must be exact and unique")
	}
	changed := bytes.Replace(raw, oldText, []byte(base64.StdEncoding.EncodeToString(response.TokenDER())), 1)
	result, err := document.Parse(t.Context(), changed, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustSignatureValue(t, doc), mustSignatureValue(t, result)) {
		t.Fatal("unsigned timestamp intervention changed primary SignatureValue")
	}
	return result
}

// FuzzValidatePreservation uses independently generated public evidence as its
// seed. No keys or local TSA calls are involved in fuzz executions; verifier and
// immutable certificate material are reused across inputs.
func FuzzValidatePreservation(f *testing.F) {
	root := "../testdata/evidence"
	name := "archive-ecdsa-exclusive"

	b, e := os.ReadFile(filepath.Join(root, "manifest.json"))
	if e != nil {
		f.Fatal(e)
	}

	var cases []struct {
		Name string
		At   string
	}
	if e = json.Unmarshal(b, &cases); e != nil {
		f.Fatal(e)
	}

	var at time.Time

	for _, c := range cases {
		if c.Name == name {
			at, e = time.Parse(time.RFC3339Nano, c.At)
			if e != nil {
				f.Fatal(e)
			}
		}
	}

	if at.IsZero() {
		f.Fatal("missing fixture timestamp")
	}

	read := func(p string) []byte {
		b, e := os.ReadFile(filepath.Join(root, name, p))
		if e != nil {
			f.Fatal(e)
		}

		return b
	}
	cert := read("signer.der")
	anchor := read("root.der")

	tsa, e := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{anchor}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{{1, 2, 3, 4, 1}}})
	if e != nil {
		f.Fatal(e)
	}

	verifier, e := xades.NewValidator(xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{anchor}, Revocation: pki.RequireCRL}, TSA: tsa, MinimumLevel: xades.LevelLTA})
	if e != nil {
		f.Fatal(e)
	}

	f.Add(read("signed.xml"))
	f.Add([]byte(`<r/>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}

		d, e := document.Parse(t.Context(), raw, document.DefaultLimits())
		if e != nil {
			return
		}

		sigs := xmldsig.Signatures(d)
		if len(sigs) != 1 {
			return
		}

		_, _ = verifier.ValidateEnveloped(t.Context(), d, sigs[0], cert, at, xades.ValidationEvidence{})
	})
}
