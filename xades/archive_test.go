package xades_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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
	noChain := strings.Replace(string(raw), oldRoot, replace, 1)

	bad, e = document.Parse(t.Context(), []byte(noChain), document.DefaultLimits())
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

	var cases []struct{ Name, At string }
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
	key        crypto.Signer
	cert, root []byte
	now        time.Time
	calls      int
}

func (t *archiveTransport) RoundTrip(ctx context.Context, q []byte) (io.ReadCloser, error) {
	t.calls++

	b, e := timestamp.IssueResponse(ctx, q, t.key, t.cert, timestamp.IssueOptions{Policy: tsaPolicy(), SerialNumber: big.NewInt(int64(t.calls)), GenTime: t.now, ExtraCertificates: [][]byte{t.root}})
	if e != nil {
		return nil, e
	}

	return io.NopCloser(bytes.NewReader(b)), nil
}
