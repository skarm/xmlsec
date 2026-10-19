package evidence_test

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
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
	Group, Name, At, Nonce, Status string
	Valid, Detached                bool
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

	ctx := context.Background()

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
		checkTimedEvidence(t, tc.Group, read, at)
	default:
		t.Fatal(tc.Group)
	}
}

func checkTimedEvidence(t *testing.T, group string, read func(string) []byte, at time.Time) {
	t.Helper()

	ctx := context.Background()

	v, e := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{read("root.der")}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{{1, 2, 3, 4, 1}}, ClockSkew: time.Minute})
	if e != nil {
		t.Fatal(e)
	}

	ev := pki.Evidence{CRLs: [][]byte{read("crl.der")}}

	switch group {
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
