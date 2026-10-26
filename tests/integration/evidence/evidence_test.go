package evidence_test

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

type evidenceFixture struct {
	Group    string
	Name     string
	At       string
	Nonce    string
	Status   string
	Valid    bool
	Detached bool
}

func TestIndependentEvidence(t *testing.T) {
	base := filepath.Join("..", "..", "..", "testdata", "evidence")

	m, e := os.ReadFile(filepath.Join(base, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}

	var cases []evidenceFixture

	if e = json.Unmarshal(m, &cases); e != nil {
		t.Fatal(e)
	}

	if len(cases) < 56 {
		t.Fatal("missing fixtures")
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) { testIndependentEvidenceCase(t, base, tc) })
	}
}

func testIndependentEvidenceCase(t *testing.T, base string, tc evidenceFixture) {
	read := func(n string) []byte {
		b, e := os.ReadFile(filepath.Join(base, tc.Name, n))
		if e != nil {
			t.Fatal(e)
		}

		return b
	}

	at, e := time.Parse(time.RFC3339, tc.At)
	if e != nil {
		t.Fatal(e)
	}

	ctx := t.Context()

	switch tc.Group {
	case "cms":
		s, e := cms.Parse(ctx, read("signature.der"), cms.DefaultLimits())
		if e != nil {
			t.Fatal(e)
		}

		content := read("content.bin")

		o := cms.VerifyOptions{ExpectedContentType: cms.DataOID()}
		if tc.Detached {
			o.DetachedContent = &content
		}

		r, e := s.Verify(ctx, [][]byte{read("signer.der")}, o)
		if e != nil || r == nil || !bytes.Equal(r.Content(), content) {
			t.Fatal(e)
		}
	case "ocsp":
		n, e := hex.DecodeString(tc.Nonce)
		if e != nil {
			t.Fatal(e)
		}

		r, rep, e := pki.VerifyOCSP(ctx, read("response.der"), read("leaf.der"), read("issuer.der"), at, pki.OCSPOptions{ExpectedNonce: n})
		if tc.Valid {
			if e != nil || r == nil {
				t.Fatalf("%v %+v", e, rep)
			}
		} else if e == nil || r != nil || string(rep.Status) != tc.Status {
			t.Fatalf("%v %+v", e, rep)
		}
	case "timestamp", "xades", "archive":
		checkTimedEvidence(t, tc, read, at)
	default:
		t.Fatal(tc.Group)
	}
}

func checkTimedEvidence(t *testing.T, tc evidenceFixture, read func(string) []byte, at time.Time) {
	t.Helper()

	ctx := t.Context()

	v, e := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{read("root.der")}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{{1, 2, 3, 4, 1}}, ClockSkew: time.Minute})
	if e != nil {
		t.Fatal(e)
	}

	ev := pki.Evidence{CRLs: [][]byte{read("crl.der")}}

	switch tc.Group {
	case "timestamp":
		q, e := timestamp.ParseRequest(read("request.der"))
		if e != nil {
			t.Fatal(e)
		}

		if r, e := v.VerifyResponse(ctx, read("response.der"), q, at, ev); e != nil || r == nil {
			t.Fatal(e)
		}
	case "archive":
		d, e := document.Parse(ctx, read("signed.xml"), document.DefaultLimits())
		if e != nil {
			t.Fatal(e)
		}

		val, e := xades.NewValidator(xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{read("root.der")}, Revocation: pki.RequireCRL}, TSA: v, MinimumLevel: xades.LevelLTA})
		if e != nil {
			t.Fatal(e)
		}

		r, e := val.ValidateEnveloped(ctx, d, xmldsig.Signatures(d)[0], read("signer.der"), at, xades.ValidationEvidence{})
		if e != nil || r == nil {
			t.Fatal(e)
		}

		checkInclusiveArchiveImprint(t, tc.Name, r, v, at, ev)
	default:
		d, e := document.Parse(ctx, read("signed.xml"), document.DefaultLimits())
		if e != nil {
			t.Fatal(e)
		}

		if r, e := xades.VerifyTimedEnveloped(ctx, d, xmldsig.Signatures(d)[0], read("signer.der"), xades.TimedOptions{TSA: v, At: at, Evidence: ev}); e != nil || r == nil {
			t.Fatal(e)
		}
	}
}

func checkInclusiveArchiveImprint(t *testing.T, name string, result *xades.ValidationResult, verifier *timestamp.Verifier, at time.Time, evidence pki.Evidence) {
	t.Helper()

	var correct, legacy string

	// Independent lxml/libxml2 archive inputs, signed and verified with OpenSSL.
	// EN 319 132-1, 5.5.2.3 applies archive C14N to SignedInfo too, although
	// these signatures select exclusive C14N and their archives select inclusive.
	switch name {
	case "archive-rsa-inclusive":
		correct = "4d7d5c9344290eb04f4edd7e8dcfb536d902f20a9c6bb9e0d25579dd1828317d"
		legacy = "33b9c9d0f072d22a8a9c2eb0093f674775de8e1de9ab6ff5a987ec9cef619fdc"
	case "archive-ecdsa-inclusive":
		correct = "7e13f90757431216e409eda4c4a32fbec332b4457b7133ef97b506fba4f314f2"
		legacy = "88d01f26d4701eda70a7e9c2d67cf80d599f233bb2effa670d01f365a94e50ff"
	default:
		return
	}

	archives := result.ArchiveTimestamps()
	if len(archives) != 1 {
		t.Fatal("expected one independently generated archive timestamp")
	}

	imprint := archives[0].Info().Imprint()
	if imprint.Hash != crypto.SHA256 || hex.EncodeToString(imprint.Digest) != correct || correct == legacy {
		t.Fatalf("archive imprint does not match independent inclusive input: %+v", imprint)
	}

	wrong, err := hex.DecodeString(legacy)
	if err != nil {
		t.Fatal(err)
	}

	want := timestamp.Expectation{Imprint: timestamp.Imprint{Hash: crypto.SHA256, Digest: wrong}}
	if accepted, err := verifier.Verify(t.Context(), archives[0].Token(), want, at, evidence); accepted != nil || !errors.Is(err, timestamp.ErrBinding) {
		t.Fatalf("legacy mixed-canonicalization archive input accepted: %v", err)
	}
}
