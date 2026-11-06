//go:build interop

package interop_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/proof"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmldsig"
)

// Both engines authenticate the foreign attributes in actual SAML metadata.
func TestXMLSecECPMetadata(t *testing.T) {
	selected(t, "xmlsec")
	f := newInteropFixture(t)
	key := generateKey(t, f.work, nameRSASHA256)
	at := time.Now().UTC()
	spec := metadata.EntityDescriptor{ID: "_ecp_metadata", EntityID: "https://sp.test/entity", ValidUntil: at.Add(time.Hour), SP: &metadata.RoleDescriptor{Endpoints: map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {{Binding: metadata.HoKSSO, ProtocolBinding: metadata.PAOS, Location: "https://sp.test/acs", Indexed: true, SupportedChannelBindings: []string{"tls-server-end-point", "tls-exporter"}}}}}}
	d, err := metadata.Build(t.Context(), spec, at, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := metadata.Sign(t.Context(), d, key.signer, key.cert.Raw, xmldsig.RSASHA256, at, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	path := write(t, filepath.Join(f.work, "ecp-metadata.xml"), xmlBytes(t, signed))
	native(t, f, true, nameVerify, flagPublicKeyPEM, key.public, flagIDAttrID, "EntityDescriptor", path)
	out := filepath.Join(f.work, "native-ecp-metadata.xml")
	native(t, f, true, nameSign, "--privkey-pem", key.private, flagIDAttrID, "EntityDescriptor", flagNativeOutput, out, path)
	verifier, err := metadata.NewVerifier(metadata.Config{TrustedKeys: []crypto.PublicKey{key.signer.Public()}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := verifier.Verify(t.Context(), read(t, out), at)
	if err != nil {
		t.Fatal(err)
	}
	entity, err := snapshot.Find(spec.EntityID, at)
	if err != nil {
		t.Fatal(err)
	}
	role, err := entity.Role(metadata.ServiceProvider, at)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := role.HoKACS(metadata.PAOS, nil)
	if err != nil || !endpoint.SupportsChannelBinding("tls-exporter") {
		t.Fatal("independently signed metadata lost HoK/channel bindings", err)
	}
}

// Independent primitives, not an assertion that a third-party ECP stack adopts
// our interpretation of CS01 2.3.11's contradictory no-Transforms/self-exclusion
// clauses. libxml2 selects exactly the SOAP nodes minus the proof Signature;
// OpenSSL verifies and independently produces SignatureValue. xmlsec1's ordinary
// XMLDSig verifier rejects the literal no-Transforms empty-URI reference and
// accepts the profile declaring the standard enveloped-signature transform.
func TestECPXMLProofIndependentPrimitives(t *testing.T) {
	f := newInteropFixture(t)
	selected(t, "xmlsec")
	oracle := cOracle(t, f)
	for _, keyType := range []string{nameRSASHA256, nameECDSASHA256} {
		key := generateKey(t, f.work, keyType)
		for _, wire := range []struct {
			name    string
			sign    func(context.Context, *document.Document, proof.Signing) (*document.Document, error)
			verify  func(context.Context, []byte, proof.Options) (*proof.Verified, error)
			generic bool
		}{{"CS01-compatibility", proof.SignCS01CompatXML, proof.VerifyCS01CompatXML, false}, {"XMLDSig-enveloped", proof.SignEnvelopedXML, proof.VerifyEnvelopedXML, true}} {
			for _, algorithm := range canonicalizations() {
				t.Run(keyType+"/"+wire.name+"/"+algorithm, func(t *testing.T) {
					at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
					d, err := protocol.SignAuthnRequest(t.Context(), protocol.AuthnRequest{ID: "_native_proof", Issuer: "https://sp.test/entity", Destination: "https://idp.test/sso", ACS: "https://sp.test/acs", IssueInstant: at}, protocol.SigningKey{Key: key.signer})
					if err != nil {
						t.Fatal(err)
					}
					envelope, err := protocol.SignSOAP(t.Context(), d, protocol.SigningKey{Key: key.signer})
					if err != nil {
						t.Fatal(err)
					}
					signed, err := wire.sign(t.Context(), envelope, proof.Signing{Key: key.signer, Certificate: key.cert.Raw, Canonicalization: algorithm})
					if err != nil {
						t.Fatal(err)
					}
					raw := xmlBytes(t, signed)
					path := write(t, filepath.Join(f.work, "proof.xml"), raw)
					// Retain nested SAML signatures. Omit only the proof's exact
					// subtree, its attributes/namespaces, and empty-URI comments.
					proofPath := "/*[local-name()='Envelope']/*[local-name()='Header']/*[local-name()='Security']/*[local-name()='Signature']"
					exclude := "(//node() | //@* | //namespace::*)[not(ancestor-or-self::*[local-name()='Signature' and namespace-uri()='" + ds + "' and parent::*[local-name()='Security' and namespace-uri()='" + proof.SecurityNamespace + "']]) and not(self::comment())]"
					canonical, _ := command(t, f, true, nil, oracle, path, "0", "0", exclude, "-")
					digest := sha256.Sum256(canonical)
					sig := ecpProofElement(t, signed)
					ref := sig.Children()[0].Children()[2]
					if value := ref.Children()[len(ref.Children())-1].Text(); value != base64.StdEncoding.EncodeToString(digest[:]) {
						t.Fatalf("independent reference digest: %s", value)
					}
					mode, comments := "0", "0"
					if strings.HasPrefix(algorithm, c14n.Exclusive) {
						mode = "1"
					} else if strings.HasPrefix(algorithm, c14n.Canonical11) {
						mode = "2"
					}
					if strings.HasSuffix(algorithm, "WithComments") {
						comments = "1"
					}
					selectSI := "(" + proofPath + "/*[local-name()='SignedInfo']/descendant-or-self::node() | " + proofPath + "/*[local-name()='SignedInfo']/descendant-or-self::*/@* | " + proofPath + "/*[local-name()='SignedInfo']/descendant-or-self::*/namespace::*)"
					si, _ := command(t, f, true, nil, oracle, path, mode, comments, selectSI, "-")
					budget := len(canonical) + len(si)
					if _, err := wire.verify(t.Context(), raw, proof.Options{Policy: xmldsig.Policy{MaxCanonicalBytes: budget}}); err != nil {
						t.Fatalf("exact canonical budget: %v", err)
					}
					if _, err := wire.verify(t.Context(), raw, proof.Options{Policy: xmldsig.Policy{MaxCanonicalBytes: budget - 1}}); err == nil {
						t.Fatal("combined reference/SignedInfo budget exceeded")
					}
					siFile := write(t, filepath.Join(f.work, "proof-si.bin"), si)
					value, err := base64.StdEncoding.DecodeString(sig.Children()[1].Text())
					if err != nil {
						t.Fatal(err)
					}
					if _, ok := key.signer.(*ecdsa.PrivateKey); ok {
						value, err = asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(value[:len(value)/2]), new(big.Int).SetBytes(value[len(value)/2:])})
						if err != nil {
							t.Fatal(err)
						}
					}
					valueFile := write(t, filepath.Join(f.work, "proof-signature.bin"), value)
					command(t, f, true, nil, "openssl", "dgst", "-sha256", "-verify", key.public, "-signature", valueFile, siFile)
					nativeValue, _ := command(t, f, true, nil, "openssl", "dgst", "-sha256", "-sign", key.private, siFile)
					if ec, ok := key.signer.(*ecdsa.PrivateKey); ok {
						var parts struct{ R, S *big.Int }
						rest, err := asn1.Unmarshal(nativeValue, &parts)
						if err != nil || len(rest) != 0 {
							t.Fatal("OpenSSL ECDSA encoding", err)
						}
						size := (ec.Curve.Params().BitSize + 7) / 8
						nativeValue = append(parts.R.FillBytes(make([]byte, size)), parts.S.FillBytes(make([]byte, size))...)
					}
					nativeRaw := bytes.Replace(raw, []byte(sig.Children()[1].Text()), []byte(base64.StdEncoding.EncodeToString(nativeValue)), 1)
					if _, err := wire.verify(t.Context(), nativeRaw, proof.Options{}); err != nil {
						t.Fatalf("OpenSSL-produced ECP proof: %v", err)
					}
					// Independent XMLDSig checks accept the nested SAML signature;
					// the proof result depends on the declared transform profile.
					native(t, f, true, nameVerify, flagPublicKeyPEM, key.public, flagIDAttrID, "AuthnRequest", "--node-xpath", "(//*[local-name()='AuthnRequest']/*[local-name()='Signature'])[1]", path)
					native(t, f, wire.generic, nameVerify, flagPublicKeyPEM, key.public, "--node-xpath", proofPath, path)
					t.Log("libxml2/OpenSSL bidirectional proof; explicit XML profile versus ordinary xmlsec1; C14N mode=" + mode + ", comments=" + comments + ", signed bytes=" + strconv.Itoa(len(canonical)))
				})
			}
		}
	}
}

func ecpProofElement(t *testing.T, d *document.Document) document.Element {
	t.Helper()
	for _, h := range d.Root().Children() {
		if h.Name() != (document.Name{Space: binding.SOAPNamespace, Local: "Header"}) {
			continue
		}
		for _, s := range h.Children() {
			if s.Name() == (document.Name{Space: proof.SecurityNamespace, Local: "Security"}) {
				return s.Children()[0]
			}
		}
	}
	t.Fatal("missing ECP proof")
	return document.Element{}
}

// xmlsec1 independently recomputes both HoK assertion and Response signatures
// in their actual SOAP context. The ECP proof is then added without invalidating
// either signature; the SP checks the independently signed X.509 confirmation.
func TestXMLSecSAMLHolderOfKey(t *testing.T) {
	f := newInteropFixture(t)
	selected(t, "xmlsec")
	idpKey := generateKey(t, f.work, nameRSASHA256)
	client := generateKey(t, f.work, nameECDSASHA256)
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	for _, algorithm := range []string{c14n.Exclusive, c14n.Canonical10} {
		t.Run(algorithm, func(t *testing.T) {
			spec := protocol.Response{ID: "_response", Issuer: "https://idp.test/entity", Audience: "https://sp.test/entity", Destination: "https://sp.test/acs", InResponseTo: "_request", IssueInstant: at, SOAPContext: true, Assertion: protocol.AssertionData{ID: "_assertion", NameID: "alice", NotBefore: at, NotOnOrAfter: at.Add(time.Minute), AuthnInstant: at, AuthnContext: "urn:test:certificate", HolderOfKeyCertificate: client.cert.Raw}}
			response, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: idpKey.signer, Canonicalization: algorithm})
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := binding.WrapSOAP(t.Context(), response)
			if err != nil {
				t.Fatal(err)
			}
			path := write(t, filepath.Join(f.work, "hok-template.xml"), xmlBytes(t, envelope))
			for _, element := range []string{"Assertion", "Response"} {
				out := filepath.Join(f.work, "hok-"+element+".xml")
				selection := "(//*[local-name()='" + element + "']/*[local-name()='Signature'])[1]"
				native(t, f, true, nameSign, "--privkey-pem", idpKey.private, flagIDAttrID, element, "--node-xpath", selection, flagNativeOutput, out, path)
				path = out
			}
			m, err := binding.DecodeSOAP(t.Context(), read(t, path), binding.SOAPOptions{})
			if err != nil {
				t.Fatal(err)
			}
			signed, err := proof.SignCS01CompatXML(t.Context(), m.Envelope(), proof.Signing{Key: client.signer, Certificate: client.cert.Raw})
			if err != nil {
				t.Fatal(err)
			}
			raw := xmlBytes(t, signed)
			path = write(t, filepath.Join(f.work, "hok-proof.xml"), raw)
			for _, element := range []string{"Assertion", "Response"} {
				selection := "(//*[local-name()='" + element + "']/*[local-name()='Signature'])[1]"
				native(t, f, true, nameVerify, flagPublicKeyPEM, idpKey.public, flagIDAttrID, element, "--node-xpath", selection, path)
			}
			p, err := proof.VerifyCS01CompatXML(t.Context(), raw, proof.Options{})
			if err != nil {
				t.Fatal(err)
			}
			body, err := p.Payload(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			assertion, err := protocol.VerifyResponse(t.Context(), body, []crypto.PublicKey{idpKey.signer.Public()}, protocol.ResponseOptions{Issuer: spec.Issuer, Audience: spec.Audience, Destination: spec.Destination, ExpectedRequestID: spec.InResponseTo, At: at, Proof: p, RequireHolderOfKey: true})
			if err != nil || assertion.NameID() != "alice" || !bytes.Equal(assertion.HolderOfKeyCertificate(), client.cert.Raw) {
				t.Fatalf("independent HoK assertion: %v", err)
			}
		})
	}
}
