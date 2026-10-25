package xmldsig_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil"
	"github.com/skarm/xmlsec/xmldsig"
)

type coreFixtureCase struct {
	Name             string `json:"name"`
	File             string `json:"file"`
	PublicKey        string `json:"public_key"`
	Canonicalization string `json:"canonicalization"`
	SignatureIndex   int    `json:"signature_index"`
	Valid            bool   `json:"valid"`
	FailedReference  int    `json:"failed_reference"`
	References       int    `json:"references"`
}

func TestCoreIndependentFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "testdata", "core")

	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}

	var manifest struct {
		Cases []coreFixtureCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}

	if len(manifest.Cases) != 102 {
		t.Fatalf("expected 96 positive selections and six negative controls; got %d", len(manifest.Cases))
	}

	for _, tc := range manifest.Cases {
		t.Run(tc.Name, func(t *testing.T) { testCoreIndependentFixturesCase(t, &tc, &dir) })
	}
}

func coreFixtureKey(t testing.TB, name string) crypto.PublicKey {
	t.Helper()
	return testutil.ReadPublicKey(t, filepath.Join("..", "..", "..", "testdata", "core", name))
}

func testCoreIndependentFixturesCase(t *testing.T, tc *coreFixtureCase, dir *string) {
	key := coreFixtureKey(t, tc.PublicKey)

	data, err := os.ReadFile(filepath.Join(*dir, tc.File))
	if err != nil {
		t.Fatal(err)
	}

	d, err := document.Parse(t.Context(), data, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	result, report, err := xmldsig.VerifySignatureDetailed(context.Background(), d, xmldsig.Signatures(d)[tc.SignatureIndex], key, xmldsig.SignatureOptions{AllowedCanonicalizationMethods: []string{tc.Canonicalization}})
	if tc.Valid {
		if err != nil || result == nil || report.Status != xmldsig.Valid || len(result.References()) != tc.References {
			t.Fatal(err, report)
		}

		return
	}

	var re *xmldsig.ReferenceError
	if result != nil || !errors.Is(err, xmldsig.ErrDigest) || !errors.As(err, &re) || re.Index != tc.FailedReference || report.SignatureValue != xmldsig.Valid {
		t.Fatal(err, report)
	}

	for i, r := range report.References {
		expected := xmldsig.NotChecked
		if i < tc.FailedReference {
			expected = xmldsig.Valid
		}

		if i == tc.FailedReference {
			expected = xmldsig.Invalid
		}

		if r.Status != expected {
			t.Fatalf("reference %d: %+v", i, r)
		}
	}
}

type detachedFixtureCase struct {
	Name             string `json:"name"`
	File             string `json:"file"`
	PublicKey        string `json:"public_key"`
	Canonicalization string `json:"canonicalization"`
	Valid            bool   `json:"valid"`
	FailedReference  int    `json:"failed_reference"`
}

// TestDetachedIndependentFixtures verifies fixtures produced by the JDK's
// independent JSR 105 XMLDSig implementation.
// Normal Go tests need neither Java nor Python and ship no private keys.
func TestDetachedIndependentFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "testdata", "detached")

	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}

	var manifest struct {
		Cases []detachedFixtureCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}

	if len(manifest.Cases) != 42 {
		t.Fatal("expected 36 positive and 6 negative fixtures")
	}

	uris, resolver := loadDetachedResources(t)
	for _, tc := range manifest.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			key := loadDetachedKey(t, tc.PublicKey)

			source, err := os.ReadFile(filepath.Join(dir, tc.File))
			if err != nil {
				t.Fatal(err)
			}

			doc, err := document.Parse(t.Context(), source, document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}

			result, err := xmldsig.VerifyDetached(context.Background(), doc, key, resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: uris, AllowedCanonicalizationMethods: []string{tc.Canonicalization}})
			if tc.Valid {
				if err != nil || len(result.References()) != len(uris) {
					t.Fatal(result, err)
				}

				return
			}

			var detail *xmldsig.ReferenceError
			if result != nil || !errors.Is(err, xmldsig.ErrDigest) || !errors.As(err, &detail) || detail.Index != tc.FailedReference || detail.Stage != "digest" {
				t.Fatal(result, err)
			}
		})
	}
}

func loadDetachedResources(t testing.TB) ([]string, xmldsig.Resolver) {
	t.Helper()

	dir := filepath.Join("..", "..", "..", "testdata", "detached")

	data, err := os.ReadFile(filepath.Join(dir, "resources.json"))
	if err != nil {
		t.Fatal(err)
	}

	var entries []struct {
		URI  string `json:"uri"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}

	uris := make([]string, 0, len(entries))

	resources := map[string][]byte{}

	for _, e := range entries {
		contents, err := os.ReadFile(filepath.Join(dir, e.Path))
		if err != nil {
			t.Fatal(err)
		}

		resources[e.URI] = contents
		uris = append(uris, e.URI)
	}

	return uris, sourceMap(resources)
}

func loadDetachedKey(t testing.TB, name string) crypto.PublicKey {
	t.Helper()
	return testutil.ReadPublicKey(t, filepath.Join("..", "..", "..", "testdata", "detached", name))
}

// TestIndependentFixtures verifies signatures produced by lxml/libxml2 and
// cryptography. See testdata/interop/manifest.json for producer provenance;
// no private key is shipped.
func TestIndependentFixtures(t *testing.T) {
	for _, name := range []string{"rsa256", "rsa384", "rsa512", "ec256", "ec384", "ec521"} {
		t.Run(name, func(t *testing.T) { testIndependentFixturesCase(t, &name) })
	}
}

func testIndependentFixturesCase(t *testing.T, name *string) {
	prefix := filepath.Join("..", "..", "..", "testdata", "interop", *name)

	keyPEM, err := os.ReadFile(prefix + ".pub.pem")
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("bad public key fixture")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	good, err := os.ReadFile(prefix + ".xml")
	if err != nil {
		t.Fatal(err)
	}

	d, err := document.Parse(t.Context(), good, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	r, err := xmldsig.Verify(context.Background(), d, key, xmldsig.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if len(r.References()) != 3 {
		t.Fatal("reference result count")
	}

	bad, err := os.ReadFile(prefix + ".bad-second-digest.xml")
	if err != nil {
		t.Fatal(err)
	}

	d, err = document.Parse(t.Context(), bad, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	r, err = xmldsig.Verify(context.Background(), d, key, xmldsig.VerifyOptions{})
	// SignatureValue and the first reference are AUTHENTIC and correct.
	// Success here would mean the verifier had skipped the second reference.
	if r != nil || !errors.Is(err, xmldsig.ErrDigest) || !strings.Contains(err.Error(), "reference 1 (#one)") {
		t.Fatalf("wrong failure: %v, result %v", err, r)
	}
}
