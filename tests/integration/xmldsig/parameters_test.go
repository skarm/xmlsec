package xmldsig_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestParameterizedIndependentFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "testdata", "parameters")
	read := func(name string) []byte {
		t.Helper()

		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}

		return b
	}

	var m struct {
		Cases []struct {
			Name, XML, Kind, Stage string
			Valid                  bool
		}
		SPKI    string
		HMACKey string `json:"hmac_key"`
	}
	if e := json.Unmarshal(read("manifest.json"), &m); e != nil {
		t.Fatal(e)
	}

	if len(m.Cases) != 97 {
		t.Fatal("independent fixture corpus is incomplete")
	}

	pub, e := x509.ParsePKIXPublicKey(read(m.SPKI))
	if e != nil {
		t.Fatal(e)
	}

	testSecret := read(m.HMACKey) // public TEST material, not a real application key
	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) { testParameterizedIndependentFixturesCase(t, &read, &c, &testSecret, &pub) })
	}
}

func testParameterizedIndependentFixturesCase(t *testing.T, read *func(name string) []byte, c *struct {
	Name  string
	XML   string
	Kind  string
	Stage string
	Valid bool
}, testSecret *[]byte, pub *any,
) {
	d, e := document.Parse(t.Context(), (*read)(c.XML), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	var (
		report    *xmldsig.VerificationReport
		hasResult bool
	)

	options := xmldsig.SignatureOptions{Policy: xmldsig.ParameterizedPolicy(), ExpectedURIs: []string{"#a", "#b"}}
	if c.Kind == "hmac" {
		options.Policy = xmldsig.HMACPolicy()
		options.Policy.AllowHMACTruncation = true
		result, r, err := xmldsig.VerifyHMACSignatureDetailed(context.Background(), d, d.Root(), (*testSecret), options)
		report = r
		e = err
		hasResult = result != nil
	} else {
		result, r, err := xmldsig.VerifySignatureDetailed(context.Background(), d, d.Root(), (*pub), options)
		report = r
		e = err
		hasResult = result != nil
	}

	if c.Valid {
		if e != nil || !hasResult || report.Status != xmldsig.Valid || len(report.References) != 2 {
			t.Fatalf("valid fixture: %v %+v", e, report)
		}
	} else {
		if e == nil || hasResult || report == nil || report.FailureStage != c.Stage {
			t.Fatalf("negative fixture: %v %+v", e, report)
		}

		if c.Stage == "references" && (report.SignatureValue != xmldsig.Valid || report.References[0].Status != xmldsig.Valid || report.References[1].Status != xmldsig.Invalid) {
			t.Fatalf("wrong reference status: %+v", report)
		}

		if c.Stage == "signature-value" && report.References[0].Status != xmldsig.NotChecked {
			t.Fatalf("processed untrusted references: %+v", report)
		}
	}
}
