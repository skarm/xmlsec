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
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestEmbeddedMaterialAndArchiveRenewal(t *testing.T) {
	c, lt, lr, v := preparedLT(t)
	ctx := context.Background()
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

	doc, _, e := v.AddArchiveTimestamp(context.Background(), lt, xmldsig.Signatures(lt)[0], c.Leaf.Raw, testcert.Now(), tr, xades.AddArchiveOptions{})
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

	r, e := evenBB.ValidateEnveloped(context.Background(), bad, xmldsig.Signatures(bad)[0], c.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{testcert.CRL(t, c)}}, TSA: pki.Evidence{CRLs: [][]byte{testcert.CRL(t, c)}}})
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

	if r, e := v.ValidateEnveloped(context.Background(), bad, xmldsig.Signatures(bad)[0], c.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{}); r != nil || e == nil {
		t.Fatal("external roots hid missing embedded chain")
	}
	// Claimed/archived past time does not bypass CURRENT-time PKIX policy.
	if r, e := v.ValidateEnveloped(context.Background(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, testcert.Now().Add(48*time.Hour), xades.ValidationEvidence{}); r != nil || e == nil {
		t.Fatal("silently switched to historical validation")
	}
}

func verifyOnlyXML(t *testing.T, d *document.Document, c testcert.Chain) {
	t.Helper()

	_, e := xmldsig.VerifySignature(context.Background(), d, xmldsig.Signatures(d)[0], c.Leaf.PublicKey, xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}, AdditionalIDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{{Space: xades.Namespace, Local: signedPropertiesLocal}}}}, ExpectedURIs: nil})
	if e != nil {
		t.Fatalf("test mutation damaged primary XMLDSig: %v", e)
	}
}

func TestArchiveBudgetsAndWrongToken(t *testing.T) {
	c, lt, lr, _ := preparedLT(t)
	small := preservationValidator(t, c, xades.LevelLT, 128)

	tr := &archiveTransport{key: c.TSAKey, cert: c.TSA.Raw, root: c.Root.Raw, now: testcert.Now()}
	if d, r, e := small.AddArchiveTimestamp(context.Background(), lt, xmldsig.Signatures(lt)[0], c.Leaf.Raw, testcert.Now(), tr, xades.AddArchiveOptions{}); d != nil || r != nil || e == nil || tr.calls != 0 {
		t.Fatal("budget not checked before transport", e, tr.calls)
	}

	v := preservationValidator(t, c, xades.LevelLT, 0)
	if d, r, e := v.AttachArchiveTimestamp(context.Background(), lt, xmldsig.Signatures(lt)[0], c.Leaf.Raw, testcert.Now(), lr.Timestamps()[0].TokenDER(), c14n.Exclusive); d != nil || r != nil || e == nil {
		t.Fatal("SignatureTimeStamp reused as ArchiveTimeStamp")
	}

	if d, r, e := v.EmbedValidationMaterial(context.Background(), lt, xmldsig.Signatures(lt)[0], c.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{}); d != nil || r != nil || e == nil {
		t.Fatal("existing evidence replaced")
	}
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

		_, _ = verifier.ValidateEnveloped(context.Background(), d, sigs[0], cert, at, xades.ValidationEvidence{})
	})
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

	bt, _, e := xades.AddSignatureTimestamp(context.Background(), doc, xmldsig.Signatures(doc)[0], c.Leaf.Raw, tr, xades.AddTimestampOptions{Validation: timed})
	if e != nil {
		t.Fatal(e)
	}

	v := preservationValidator(t, c, xades.LevelLT, 0)
	rawBefore, _ := bt.XML(t.Context())

	lt, r, e := v.EmbedValidationMaterial(context.Background(), bt, xmldsig.Signatures(bt)[0], c.Leaf.Raw, testcert.Now(), xades.ValidationEvidence{Signer: proof, TSA: proof})
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

func archivePolicy(t *testing.T, c testcert.Chain) (*timestamp.Verifier, pki.Evidence) {
	t.Helper()
	o := timeOptions(t, c)

	return o.TSA, o.Evidence
}

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
