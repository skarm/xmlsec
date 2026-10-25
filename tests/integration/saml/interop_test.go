package saml_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
)

func TestIndependentSignedSAMLFixtures(t *testing.T) {
	base := filepath.Join("..", "..", "..", "testdata", "saml-interop")
	read := func(p string) []byte {
		b, e := os.ReadFile(filepath.Join(base, p))
		if e != nil {
			t.Fatal(e)
		}

		return b
	}

	var cases []struct {
		Name        string
		Kind        string
		Certificate string
		At          string
		Valid       bool
	}
	if e := json.Unmarshal(read("manifest.json"), &cases); e != nil {
		t.Fatal(e)
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			cert, e := x509.ParseCertificate(read(c.Certificate))
			if e != nil {
				t.Fatal(e)
			}

			at, e := time.Parse(time.RFC3339Nano, c.At)
			if e != nil {
				t.Fatal(e)
			}

			d, e := document.Parse(t.Context(), read(c.Name+".xml"), document.DefaultLimits())
			if e != nil {
				t.Fatal(e)
			}

			keys := []crypto.PublicKey{cert.PublicKey}
			ctx := context.Background()

			switch c.Kind {
			case "metadata":
				v, err := metadata.NewVerifier(metadata.Config{TrustedKeys: keys, Options: metadata.Options{}})
				if err != nil {
					t.Fatal(err)
				}

				_, e = v.Verify(ctx, read(c.Name+".xml"), at)
			case "request":
				_, e = protocol.VerifyAuthnRequest(ctx, d, keys, protocol.RequestOptions{Issuer: "https://sp.example/metadata", Destination: "https://idp.example/sso", ACS: []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: "https://sp.example/acs", Index: 0, Indexed: true}}, At: at})
			case "response":
				_, e = protocol.VerifyResponse(ctx, d, keys, protocol.ResponseOptions{Issuer: "https://idp.example/metadata", Audience: "https://sp.example/metadata", Destination: "https://sp.example/acs", ExpectedRequestID: "_request", At: at, ExpectedAuthnContexts: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}})
			default:
				t.Fatal("unknown fixture")
			}

			if (e == nil) != c.Valid {
				t.Fatalf("valid=%v err=%v", c.Valid, e)
			}
		})
	}
}
