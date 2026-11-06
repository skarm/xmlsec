package proof_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/proof"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestWholeSOAPProof(t *testing.T) {
	c := testcert.New(t)
	request := protocol.AuthnRequest{ID: "_proof", Issuer: "https://sp.test", Destination: "https://idp.test/sso", ACS: "https://sp.test/acs", IssueInstant: testcert.Now()}
	key := protocol.SigningKey{Key: c.TSAKey, CertificateDER: c.TSA.Raw, Canonicalization: c14n.Canonical10}
	d, err := protocol.SignAuthnRequest(t.Context(), request, key)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := protocol.SignSOAP(t.Context(), d, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments, c14n.Exclusive, c14n.ExclusiveWithComments} {
		t.Run(method, func(t *testing.T) {
			signed, err := proof.SignCS01CompatXML(t.Context(), envelope, proof.Signing{Key: c.LeafKey, Certificate: c.Leaf.Raw, Canonicalization: method})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := signed.XML(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			p, err := proof.VerifyCS01CompatXML(t.Context(), raw, proof.Options{Certificate: c.Leaf.Raw})
			if err != nil || !p.XML() || !bytes.Equal(p.Certificate(), c.Leaf.Raw) {
				t.Fatalf("proof: %v", err)
			}
			body, err := p.Payload(t.Context())
			if err != nil || !p.Covers(body) {
				t.Fatalf("scope: %v", err)
			}
			if _, err := protocol.VerifyAuthnRequest(t.Context(), body, []crypto.PublicKey{c.TSAKey.Public()}, protocol.RequestOptions{Issuer: request.Issuer, Destination: request.Destination, At: request.IssueInstant, ACS: []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: request.ACS}}}); err != nil {
				t.Fatalf("inner SAML signature: %v", err)
			}
			// Matching XML IDs or reparsing the same bytes must not transfer proof.
			if p.Covers(d) {
				t.Fatal("proof transferred to another document")
			}
			copyCert := p.Certificate()
			copyCert[0] ^= 1
			if !bytes.Equal(p.Certificate(), c.Leaf.Raw) {
				t.Fatal("mutable certificate escaped")
			}
			for name, bad := range map[string][]byte{
				"body":               bytes.Replace(raw, []byte(`ID="_proof"`), []byte(`ID="_other"`), 1),
				"inner signature":    bytes.Replace(raw, []byte(base64.StdEncoding.EncodeToString(c.TSA.Raw)), []byte(base64.StdEncoding.EncodeToString(c.Leaf.Raw)), 1),
				"header":             bytes.Replace(raw, []byte(`soap:mustUnderstand="1"`), []byte(`soap:mustUnderstand="0"`), 1),
				"external reference": bytes.Replace(raw, []byte(`<ds:Reference URI="">`), []byte(`<ds:Reference URI="https://attacker.test/">`), 1),
				"transforms":         bytes.Replace(raw, []byte(`<ds:Reference URI="">`), []byte(`<ds:Reference URI=""><ds:Transforms/>`), 1),
				"Object":             bytes.Replace(raw, []byte(`</ds:Signature>`), []byte(`<ds:Object/></ds:Signature>`), 1),
			} {
				t.Run(name, func(t *testing.T) {
					if _, err := proof.VerifyCS01CompatXML(t.Context(), bad, proof.Options{}); err == nil {
						t.Fatal("tampered proof accepted")
					}
				})
			}
			if _, err := proof.VerifyCS01CompatXML(t.Context(), raw, proof.Options{Certificate: c.TSA.Raw}); err == nil {
				t.Fatal("wrong certificate pin")
			}
			if _, err := proof.VerifyCS01CompatXML(t.Context(), raw, proof.Options{SOAP: binding.SOAPOptions{MaxBytes: 100}}); err == nil {
				t.Fatal("byte limit ignored")
			}
			if _, err := proof.VerifyCS01CompatXML(t.Context(), raw, proof.Options{Policy: xmldsig.Policy{MaxCanonicalBytes: 100}}); err == nil {
				t.Fatal("canonical byte budget ignored")
			}
			if _, err := proof.VerifyCS01CompatXML(t.Context(), raw, proof.Options{Policy: xmldsig.Policy{AllowedSignatureMethods: []string{xmldsig.RSASHA256}}}); err == nil {
				t.Fatal("algorithm restriction ignored")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := proof.VerifyCS01CompatXML(ctx, raw, proof.Options{}); err == nil {
				t.Fatal("cancellation ignored")
			}
			// Generic XMLDSig retains its ordinary empty-URI processing. This
			// literal ECP wire profile is not a generic enveloped XML signature.
			if _, err := xmldsig.Verify(t.Context(), signed, c.LeafKey.Public(), xmldsig.VerifyOptions{}); err == nil {
				t.Fatal("generic XMLDSig silently adopted ECP projection")
			}
		})
	}
}

func TestProofExclusivePrefixList(t *testing.T) {
	c := testcert.New(t)
	d, err := document.Parse(t.Context(), []byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:q="urn:test:q"><s:Body><p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/></s:Body></s:Envelope>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	key := proof.Signing{Key: c.LeafKey, Certificate: c.Leaf.Raw, InclusivePrefixes: []string{"q", "#default"}}
	signed, err := proof.SignCS01CompatXML(t.Context(), d, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := signed.XML(t.Context())
	if _, err := proof.VerifyCS01CompatXML(t.Context(), raw, proof.Options{}); err != nil {
		t.Fatal(err)
	}
	key.InclusivePrefixes = []string{"xmlns"}
	if _, err := proof.SignCS01CompatXML(t.Context(), d, key); err == nil {
		t.Fatal("invalid namespace prefix accepted")
	}
}

func TestSeparateXMLProofAPIs(t *testing.T) {
	c := testcert.New(t)
	d, err := document.Parse(t.Context(), []byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/></s:Body></s:Envelope>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, api := range []struct {
		name          string
		sign          func(context.Context, *document.Document, proof.Signing) (*document.Document, error)
		verify, other func(context.Context, []byte, proof.Options) (*proof.Verified, error)
		standard      bool
	}{
		{"CS01-compatibility", proof.SignCS01CompatXML, proof.VerifyCS01CompatXML, proof.VerifyEnvelopedXML, false},
		{"XMLDSig-enveloped", proof.SignEnvelopedXML, proof.VerifyEnvelopedXML, proof.VerifyCS01CompatXML, true},
	} {
		t.Run(api.name, func(t *testing.T) {
			signed, err := api.sign(t.Context(), d, proof.Signing{Key: c.LeafKey, Certificate: c.Leaf.Raw})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := signed.XML(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.verify(t.Context(), raw, proof.Options{}); err != nil {
				t.Fatal(err)
			}
			if _, err := api.other(t.Context(), raw, proof.Options{}); err == nil {
				t.Fatal("different XML proof format accepted")
			}
			signatures := xmldsig.Signatures(signed)
			if len(signatures) != 1 {
				t.Fatal("proof count")
			}
			_, err = xmldsig.VerifySignature(t.Context(), signed, signatures[0], c.LeafKey.Public(), xmldsig.SignatureOptions{})
			if (err == nil) != api.standard {
				t.Fatalf("ordinary XMLDSig verification: %v, standard format %v", err, api.standard)
			}
			changed := bytes.ReplaceAll(raw, []byte("AuthnRequest"), []byte("OtherRequest"))
			if _, err := api.verify(t.Context(), changed, proof.Options{}); err == nil {
				t.Fatal("modified SOAP body accepted")
			}
		})
	}
}

func FuzzECPXMLProof(f *testing.F) {
	raw := []byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/></s:Body></s:Envelope>`)
	f.Add(raw)
	c := testcert.New(f)
	d, err := document.Parse(f.Context(), raw, document.DefaultLimits())
	if err != nil {
		f.Fatal(err)
	}
	for _, sign := range []func(context.Context, *document.Document, proof.Signing) (*document.Document, error){proof.SignCS01CompatXML, proof.SignEnvelopedXML} {
		signed, err := sign(f.Context(), d, proof.Signing{Key: c.LeafKey, Certificate: c.Leaf.Raw})
		if err != nil {
			f.Fatal(err)
		}
		valid, err := signed.XML(f.Context())
		if err != nil {
			f.Fatal(err)
		}
		f.Add(valid)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			t.Skip()
		}
		for _, verify := range []func(context.Context, []byte, proof.Options) (*proof.Verified, error){proof.VerifyCS01CompatXML, proof.VerifyEnvelopedXML} {
			_, _ = verify(t.Context(), raw, proof.Options{SOAP: binding.SOAPOptions{MaxBytes: 8192}})
		}
	})
}

func TestRSAProofAndKeyMismatch(t *testing.T) {
	c := testcert.New(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := *c.Leaf
	template.SerialNumber = big.NewInt(99)
	cert := testcert.Issue(t, &template, c.Root, &rsaKey.PublicKey, c.RootKey)
	d, err := document.Parse(t.Context(), []byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/></s:Body></s:Envelope>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := proof.SignCS01CompatXML(t.Context(), d, proof.Signing{Key: rsaKey, Certificate: cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := signed.XML(t.Context())
	if !strings.Contains(string(raw), xmldsig.RSASHA256) {
		t.Fatal("RSA method")
	}
	if _, err := proof.VerifyCS01CompatXML(t.Context(), raw, proof.Options{}); err != nil {
		t.Fatal(err)
	}
	if !fips140.Enabled() {
		legacy := xmldsig.LegacyVerificationPolicy()
		legacy.AllowLegacySigning = true
		legacyKey := proof.Signing{Key: rsaKey, Certificate: cert.Raw, Method: xmldsig.RSASHA1, Digest: xmldsig.SHA1, Policy: legacy}
		old, err := proof.SignCS01CompatXML(t.Context(), d, legacyKey)
		if err != nil {
			t.Fatal(err)
		}
		oldRaw, _ := old.XML(t.Context())
		if _, err := proof.VerifyCS01CompatXML(t.Context(), oldRaw, proof.Options{}); err == nil {
			t.Fatal("legacy proof accepted by default")
		}
		if _, err := proof.VerifyCS01CompatXML(t.Context(), oldRaw, proof.Options{Policy: xmldsig.LegacyVerificationPolicy()}); err != nil {
			t.Fatal(err)
		}
		legacyKey.Policy.AllowLegacySigning = false
		if _, err := proof.SignCS01CompatXML(t.Context(), d, legacyKey); err == nil {
			t.Fatal("legacy verification policy enabled signing")
		}
	}
	if _, err := proof.SignCS01CompatXML(t.Context(), d, proof.Signing{Key: c.LeafKey, Certificate: cert.Raw}); err == nil {
		t.Fatal("mismatched key signed")
	}
	var zero proof.Verified
	if zero.Covers(d) || zero.Envelope() != nil || zero.Certificate() != nil {
		t.Fatal("zero proof trusted")
	}
}

func TestXMLProofSigningRejectsEmptyDocument(t *testing.T) {
	t.Parallel()
	c := testcert.New(t)
	for _, api := range []struct {
		name string
		sign func(context.Context, *document.Document, proof.Signing) (*document.Document, error)
	}{
		{"enveloped", proof.SignEnvelopedXML},
		{"CS01 compatibility", proof.SignCS01CompatXML},
	} {
		t.Run(api.name, func(t *testing.T) {
			t.Parallel()
			for _, input := range []*document.Document{nil, {}} {
				signed, err := api.sign(t.Context(), input, proof.Signing{Key: c.LeafKey, Certificate: c.Leaf.Raw})
				if signed != nil || !errors.Is(err, proof.ErrProof) {
					t.Fatalf("empty document: signed=%v, err=%v; want ErrProof", signed, err)
				}
			}
		})
	}
}
