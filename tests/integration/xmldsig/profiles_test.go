package xmldsig_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

type nextFixture struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	File        string `json:"file"`
	PublicKey   string `json:"public_key"`
	Certificate string `json:"certificate"`
	Valid       bool   `json:"valid"`
}

func TestNextIndependentFixtures(t *testing.T) {
	dir := "../../../testdata/next"

	raw, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	// Explicit tags for snake_case key names.
	var wire struct {
		Cases []nextFixture
	}
	if e = json.Unmarshal(raw, &wire); e != nil {
		t.Fatal(e)
	}

	for _, tc := range wire.Cases {
		t.Run(tc.Name, func(t *testing.T) { testNextIndependentFixturesCase(t, dir, tc) })
	}
}

func testNextIndependentFixturesCase(t *testing.T, dir string, tc nextFixture) {
	b, e := os.ReadFile(filepath.Join(dir, tc.File))
	if e != nil {
		t.Fatal(e)
	}

	public := fixturePublicKey(t, filepath.Join(dir, tc.PublicKey))

	if tc.Kind == "redirect" {
		verifyRedirectFixture(t, b, public)

		return
	}

	doc, e := document.Parse(t.Context(), b, document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	sigs := xmldsig.Signatures(doc)
	if len(sigs) != 1 {
		t.Fatal("signature count")
	}

	switch tc.Kind {
	case "manifest":
		payload, e := os.ReadFile(filepath.Join(dir, "attachment.bin"))
		if e != nil {
			t.Fatal(e)
		}

		calls := 0
		o := xmldsig.SignatureOptions{Policy: xmldsig.ModernPolicy(), Manifests: xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive}, ExpectedURIs: []string{"#top"}, External: &xmldsig.ExternalReferences{AllowedURIs: []string{"urn:attachment"}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			calls++
			return io.NopCloser(bytes.NewReader(payload)), nil
		})}}

		result, report, e := xmldsig.VerifySignatureDetailed(t.Context(), doc, sigs[0], public, o)
		if tc.Valid {
			if e != nil {
				t.Fatal(e)
			}

			if len(result.Manifests()) != 2 || report.ManifestValidation != xmldsig.Valid || calls != 1 {
				t.Fatalf("%+v calls=%d", report, calls)
			}
		} else {
			var me *xmldsig.ManifestReferenceError
			if result != nil || !errors.As(e, &me) || me.ID != "leaf" || me.Reference.Index != 1 || report.SignatureValue != xmldsig.Valid || report.References[0].Status != xmldsig.Valid || calls != 0 {
				t.Fatalf("%v %+v calls=%d", e, report, calls)
			}
		}
	case "xades":
		der, e := os.ReadFile(filepath.Join(dir, tc.Certificate))
		if e != nil {
			t.Fatal(e)
		}

		r, e := xades.VerifyBasicEnveloped(t.Context(), doc, sigs[0], der, xades.VerifyOptions{Policy: xmldsig.ModernPolicy()})
		if e != nil || !r.Signature().CoversElement(doc.Root()) {
			t.Fatal(e)
		}
	default:
		t.Fatal("unknown fixture kind")
	}
}

func fixturePublicKey(t *testing.T, path string) crypto.PublicKey {
	t.Helper()

	p, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}

	block, _ := pem.Decode(p)
	if block == nil {
		t.Fatal("PEM")
	}

	public, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}

	return public
}

func verifyRedirectFixture(t *testing.T, b []byte, public crypto.PublicKey) {
	t.Helper()

	r, e := binding.VerifyRedirect(t.Context(), string(b), public, binding.Options{Policy: xmldsig.ModernPolicy()})
	if e != nil {
		t.Fatal(e)
	}

	value, present := r.RelayState()
	if !present || value != "state/ü?x=1&y=two" {
		t.Fatal("relay")
	}
}
