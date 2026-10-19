package xmldsig_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestKeyInfoIndependentPythonFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "testdata", "keyinfo")

	raw, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}

	var manifest struct {
		Cases []struct{ Name, KeyInfo, Signature, SPKI, Negative, SHA256 string }
	}
	if e = json.Unmarshal(raw, &manifest); e != nil {
		t.Fatal(e)
	}

	if len(manifest.Cases) != 10 {
		t.Fatal("fixture corpus missing")
	}

	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) { testKeyInfoIndependentPythonFixturesCase(t, &dir, &c) })
	}
}

func testKeyInfoIndependentPythonFixturesCase(t *testing.T, dir *string, c *struct {
	Name      string
	KeyInfo   string
	Signature string
	SPKI      string
	Negative  string
	SHA256    string
},
) {
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join((*dir), name))
		if e != nil {
			t.Fatal(e)
		}

		return b
	}
	spki := read(c.SPKI)

	fp := sha256.Sum256(spki)
	if hex.EncodeToString(fp[:]) != c.SHA256 {
		t.Fatal("fixture public key changed")
	}

	key, e := x509.ParsePKIXPublicKey(spki)
	if e != nil {
		t.Fatal(e)
	}

	info, e := document.Parse(t.Context(), read(c.KeyInfo), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	parsed, e := keyinfo.Parse(context.Background(), info, info.Root(), keyinfo.Options{})
	if e != nil {
		t.Fatal(e)
	}

	if len(parsed.Candidates()) != 1 || !bytes.Equal(parsed.Candidates()[0].SPKI(), spki) {
		t.Fatal("key extraction differs from Python")
	}

	for _, test := range []struct {
		path  string
		valid bool
	}{{c.Signature, true}, {c.Negative, false}} {
		d, e := document.Parse(t.Context(), read(test.path), document.DefaultLimits())
		if e != nil {
			t.Fatal(e)
		}

		sigs := xmldsig.Signatures(d)
		if len(sigs) != 1 {
			t.Fatal("signature count")
		}

		r, e := xmldsig.VerifySignatureWithKeyInfo(context.Background(), d, sigs[0], xmldsig.KeyInfoVerifyOptions{Signature: xmldsig.SignatureOptions{ExpectedURIs: []string{"#data"}, Policy: xmldsig.ModernPolicy()}, SelectTrustedKey: keySelector(t, key)})
		if test.valid {
			if e != nil || r == nil {
				t.Fatal(e)
			}
		} else if e == nil || r != nil {
			t.Fatal("tampered payload accepted")
		}
	}
}
