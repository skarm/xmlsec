package sp_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/ecp"
	"github.com/skarm/xmlsec/saml/idp"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/proof"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/saml/sp"
	"github.com/skarm/xmlsec/saml/state"
)

const hokSP, hokIDP = "https://sp.test/entity", "https://idp.test/entity"

func hokPartners(t *testing.T, c testcert.Chain, acs, sso, canonical string, encrypted, advertiseHoK bool) (*sp.ServiceProvider, *idp.IdentityProvider) {
	t.Helper()
	spRole := &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: c.Leaf.Raw}}, Endpoints: map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {{Binding: metadata.PAOS, Location: acs, Indexed: true}}}}
	idpEndpoint := metadata.Endpoint{Binding: metadata.SOAP, Location: sso}
	if advertiseHoK {
		spRole.Endpoints[metadata.AssertionConsumerService] = []metadata.Endpoint{{Binding: metadata.HoKSSO, ProtocolBinding: metadata.PAOS, Location: acs, Indexed: true, SupportedChannelBindings: []string{ecp.TLSServerEndPoint}}}
		idpEndpoint = metadata.Endpoint{Binding: metadata.HoKSSO, ProtocolBinding: metadata.SOAP, Location: sso, SupportedChannelBindings: []string{ecp.TLSServerEndPoint}}
	}
	var decryption *protocol.DecryptionOptions
	var encryption *protocol.EncryptionOptions
	if encrypted {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		template := *c.Leaf
		template.KeyUsage = x509.KeyUsageKeyEncipherment
		cert := testcert.Issue(t, &template, c.Root, &key.PublicKey, c.RootKey)
		spRole.Keys = append(spRole.Keys, metadata.KeyDescriptor{Use: "encryption", CertificateDER: cert.Raw})
		decryption = &protocol.DecryptionOptions{Keys: []crypto.Decrypter{key}}
		encryption = &protocol.EncryptionOptions{Targets: protocol.EncryptAssertion | protocol.EncryptNameID | protocol.EncryptAttributes}
	}
	var aggregate bytes.Buffer
	aggregate.WriteString(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">`)
	for _, spec := range []metadata.EntityDescriptor{
		{ID: "_sp", EntityID: hokSP, ValidUntil: testcert.Now().Add(time.Hour), SP: spRole},
		{ID: "_idp", EntityID: hokIDP, ValidUntil: testcert.Now().Add(time.Hour), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: c.TSA.Raw}}, Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {idpEndpoint}}}},
	} {
		d, err := metadata.Build(t.Context(), spec, testcert.Now(), metadata.Options{})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := d.XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		aggregate.Write(raw)
	}
	aggregate.WriteString(`</md:EntitiesDescriptor>`)
	partners, err := metadata.ParseTrusted(t.Context(), aggregate.Bytes(), testcert.Now(), metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	requests, err := state.NewMemoryStore(state.Config{})
	if err != nil {
		t.Fatal(err)
	}
	spReplay, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	idpReplay, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := sp.NewServiceProvider(sp.Config{EntityID: hokSP, Metadata: partners, Signing: protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Canonicalization: canonical}, Requests: requests, Replay: spReplay, Decryption: decryption})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := idp.NewIdentityProvider(idp.Config{EntityID: hokIDP, Metadata: partners, Signing: protocol.SigningKey{Key: c.TSAKey, CertificateDER: c.TSA.Raw, Canonicalization: canonical}, Replay: idpReplay, Encryption: encryption})
	if err != nil {
		t.Fatal(err)
	}
	return service, identity
}

type xmlProofMethods struct {
	name   string
	sign   func(context.Context, *document.Document, proof.Signing) (*document.Document, error)
	verify func(context.Context, []byte, proof.Options) (*proof.Verified, error)
	toIDP  func(*ecp.Exchange, context.Context, proof.Signing, []protocol.ChannelBinding) (*document.Document, error)
	finish func(*ecp.Exchange, context.Context, []byte, proof.Signing, binding.SOAPOptions) (*document.Document, error)
}

func TestECPHoKXMLRoles(t *testing.T) {
	for _, methods := range []xmlProofMethods{
		{"CS01-compatibility", proof.SignCS01CompatXML, ecp.VerifyCS01CompatXML, (*ecp.Exchange).ToIDPCS01CompatXML, (*ecp.Exchange).FinishCS01CompatXML},
		{"XMLDSig-enveloped", proof.SignEnvelopedXML, ecp.VerifyEnvelopedXML, (*ecp.Exchange).ToIDPEnvelopedXML, (*ecp.Exchange).FinishEnvelopedXML},
	} {
		t.Run(methods.name, func(t *testing.T) { testECPHoKXMLRoles(t, methods) })
	}
}

func TestHoKOnlyMetadataRejectsBearerBegin(t *testing.T) {
	c := testcert.New(t)
	service, _ := hokPartners(t, c, "https://sp.test/acs", "https://idp.test/sso", c14n.Exclusive, false, true)
	if _, err := service.Begin(t.Context(), sp.BeginOptions{IDP: hokIDP, Binding: metadata.PAOS, At: testcert.Now(), BrowserBinding: bytes.Repeat([]byte{19}, 32)}); err == nil {
		t.Fatal("bearer login selected HoK-only metadata")
	}
}

func testECPHoKXMLRoles(t *testing.T, methods xmlProofMethods) {
	c := testcert.New(t)
	client := proof.Signing{Key: c.ResponderKey, Certificate: c.Responder.Raw}
	for _, canonical := range []string{c14n.Exclusive, c14n.Canonical10} {
		for _, encrypted := range []bool{false, true} {
			t.Run(canonical+"/encrypted="+strconv.FormatBool(encrypted), func(t *testing.T) {
				const acs, sso = "https://sp.test/acs", "https://idp.test/sso"
				service, identity := hokPartners(t, c, acs, sso, canonical, encrypted, encrypted)
				at := testcert.Now()
				browser := bytes.Repeat([]byte{19}, 32)
				spChannel := protocol.ChannelBinding{Type: ecp.TLSServerEndPoint, Data: bytes.Repeat([]byte{1}, 32)}
				idpChannel := protocol.ChannelBinding{Type: ecp.TLSServerEndPoint, Data: bytes.Repeat([]byte{2}, 32)}
				out, err := service.Begin(t.Context(), sp.BeginOptions{IDP: hokIDP, Binding: metadata.PAOS, At: at, BrowserBinding: browser, HolderOfKey: true, ChannelBindings: []protocol.ChannelBinding{spChannel}})
				if err != nil {
					t.Fatal(err)
				}
				challenge, err := out.PAOS()
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := challenge.XML(t.Context())
				if _, err := ecp.ParseChallengeWithBindings(t.Context(), raw, "https://sp.test/resource", []protocol.ChannelBinding{spChannel}, binding.SOAPOptions{}); err == nil {
					t.Fatal("HoK challenge silently downgraded")
				}
				x, err := ecp.ParseHoKChallenge(t.Context(), raw, "https://sp.test/resource", c.Responder.Raw, []protocol.ChannelBinding{spChannel}, binding.SOAPOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if encrypted {
					plain, err := x.ToIDP(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					plainRaw, err := plain.XML(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if _, err := identity.AcceptSOAP(t.Context(), plainRaw, hokSP, sso, at); err == nil {
						t.Fatal("bearer receiver accepted a HoK-only metadata endpoint")
					}
				}
				toIDP, err := methods.toIDP(x, t.Context(), client, []protocol.ChannelBinding{idpChannel})
				if err != nil {
					t.Fatal(err)
				}
				raw, _ = toIDP.XML(t.Context())
				p, err := methods.verify(t.Context(), raw, proof.Options{})
				if err != nil {
					t.Fatal(err)
				}
				failed, err := identity.AcceptECP(t.Context(), p, hokSP, sso, at, []protocol.ChannelBinding{spChannel})
				if err == nil || failed == nil {
					t.Fatal("client/IdP channel mismatch accepted")
				}
				auth := idp.Authentication{NameID: "alice", AuthnInstant: at, AuthnContext: "urn:test:certificate", HolderOfKeyCertificate: c.Responder.Raw, Attributes: []protocol.Attribute{{Name: "role", Values: []string{"reader"}}}}
				if _, err := identity.Issue(t.Context(), failed, auth, at); err == nil {
					t.Fatal("failed channel request issued assertion")
				}
				request, err := identity.AcceptECP(t.Context(), p, hokSP, sso, at, []protocol.ChannelBinding{idpChannel})
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(request.HolderOfKeyCertificate(), c.Responder.Raw) {
					t.Fatal("wrong authentication key")
				}
				bad := auth
				bad.HolderOfKeyCertificate = nil
				if _, err := identity.Issue(t.Context(), request, bad, at); err == nil {
					t.Fatal("missing principal/key association accepted")
				}
				bad.HolderOfKeyCertificate = c.Leaf.Raw
				if _, err := identity.Issue(t.Context(), request, bad, at); err == nil {
					t.Fatal("another principal key accepted")
				}
				issued, err := identity.Issue(t.Context(), request, auth, at)
				if err != nil {
					t.Fatal(err)
				}
				idpEnvelope, err := issued.ECP(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				raw, _ = idpEnvelope.XML(t.Context())
				if !encrypted {
					data := hokConfirmationElements(idpEnvelope.Root())
					if len(data) != 2 {
						t.Fatalf("confirmation data count: %d", len(data))
					}
					var a, b bytes.Buffer
					if err := c14n.WriteElement(t.Context(), &a, data[0], c14n.Options{Algorithm: c14n.Exclusive}); err != nil {
						t.Fatal(err)
					}
					if err := c14n.WriteElement(t.Context(), &b, data[1], c14n.Options{Algorithm: c14n.Exclusive}); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(a.Bytes(), b.Bytes()) {
						t.Fatal("ECP/header assertion confirmation data differ")
					}
				}
				// A reissued certificate with the same key must not satisfy the
				// X509Certificate matching form (HoK 2.5), even with valid proof.
				template := *c.Responder
				template.SerialNumber = big.NewInt(123)
				reissued := testcert.Issue(t, &template, c.Root, c.ResponderKey.Public(), c.RootKey)
				wrong := bytes.Replace(raw, []byte(base64.StdEncoding.EncodeToString(c.Responder.Raw)), []byte(base64.StdEncoding.EncodeToString(reissued.Raw)), 1)
				if _, err := x.Finish(t.Context(), wrong, binding.SOAPOptions{}); err == nil {
					t.Fatal("different certificate accepted by ECP")
				}
				returned, err := x.Finish(t.Context(), raw, binding.SOAPOptions{})
				if err != nil {
					t.Fatal(err)
				}
				unsigned, _ := returned.XML(t.Context())
				if _, err := service.ConsumePAOS(t.Context(), unsigned, sp.ConsumeOptions{At: at, BrowserBinding: browser}); err == nil {
					t.Fatal("HoK accepted without proof")
				}
				wrongProof, err := methods.sign(t.Context(), returned, proof.Signing{Key: c.ResponderKey, Certificate: reissued.Raw})
				if err != nil {
					t.Fatal(err)
				}
				wrongRaw, _ := wrongProof.XML(t.Context())
				wrongP, err := methods.verify(t.Context(), wrongRaw, proof.Options{})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := service.ConsumeECP(t.Context(), wrongP, sp.ConsumeOptions{At: at, BrowserBinding: browser}); err == nil {
					t.Fatal("SP matched certificate by public key only")
				}
				final, err := methods.finish(x, t.Context(), raw, client, binding.SOAPOptions{})
				if err != nil {
					t.Fatal(err)
				}
				finalRaw, _ := final.XML(t.Context())
				verified, err := methods.verify(t.Context(), finalRaw, proof.Options{})
				if err != nil {
					t.Fatal(err)
				}
				assertion, err := service.ConsumeECP(t.Context(), verified, sp.ConsumeOptions{At: at, BrowserBinding: browser})
				if err != nil {
					t.Fatal(err)
				}
				if assertion.NameID() != "alice" || assertion.SubjectConfirmationMethod() != protocol.HolderOfKey || !bytes.Equal(assertion.HolderOfKeyCertificate(), c.Responder.Raw) {
					t.Fatal("wrong authenticated subject")
				}
				if _, err := service.ConsumeECP(t.Context(), verified, sp.ConsumeOptions{At: at, BrowserBinding: browser}); err == nil {
					t.Fatal("HoK response replay accepted")
				}
			})
		}
	}
}

func hokConfirmationElements(e document.Element) []document.Element {
	var out []document.Element
	if e.Name() == (document.Name{Space: protocol.AssertionNamespace, Local: "SubjectConfirmationData"}) {
		out = append(out, e)
	}
	for _, child := range e.Children() {
		out = append(out, hokConfirmationElements(child)...)
	}
	return out
}

// Both ECP hops use real mutually authenticated TLS; no synthetic TLS state or
// forwarded certificate headers are used to establish proof. HTTP Basic at the
// IdP independently maps the demonstrated certificate to the authenticated user.
func TestECPHoKMutualTLSAndBasic(t *testing.T) {
	c := testcert.New(t)
	var service *sp.ServiceProvider
	var identity *idp.IdentityProvider
	at := testcert.Now()
	browser := bytes.Repeat([]byte{39}, 32)
	spServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := ecp.VerifyTLSRequest(r.Context(), r, proof.Options{})
		if err != nil {
			t.Error(err)
			http.Error(w, "proof", 400)
			return
		}
		assertion, err := service.ConsumeECP(r.Context(), p, sp.ConsumeOptions{At: at, BrowserBinding: browser})
		if err != nil || assertion.NameID() != "alice" {
			t.Errorf("SP: %v", err)
			http.Error(w, "SAML", 400)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	spServer.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
	spServer.StartTLS()
	defer spServer.Close()
	idpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "alice" || password != "test-password" {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		p, err := ecp.VerifyTLSRequest(r.Context(), r, proof.Options{})
		if err != nil {
			t.Error(err)
			http.Error(w, "proof", 400)
			return
		}
		request, err := identity.AcceptECP(r.Context(), p, hokSP, "https://"+r.Host+r.URL.Path, at, nil)
		if err != nil {
			t.Error(err)
			http.Error(w, "request", 400)
			return
		}
		// This fixed mapping is application policy, independent of KeyInfo.
		if !bytes.Equal(request.HolderOfKeyCertificate(), c.Responder.Raw) {
			http.Error(w, "key association", http.StatusUnauthorized)
			return
		}
		issued, err := identity.Issue(r.Context(), request, idp.Authentication{NameID: user, AuthnInstant: at, AuthnContext: "urn:test:password", HolderOfKeyCertificate: c.Responder.Raw}, at)
		if err != nil {
			t.Error(err)
			http.Error(w, "issue", 400)
			return
		}
		envelope, err := issued.ECP(r.Context())
		if err != nil {
			t.Error(err)
			return
		}
		if err := ecp.WriteIDPResponse(r.Context(), w, envelope); err != nil {
			t.Error(err)
		}
	}))
	idpServer.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
	idpServer.StartTLS()
	defer idpServer.Close()
	service, identity = hokPartners(t, c, spServer.URL+"/acs", idpServer.URL+"/sso", c14n.Canonical10, false, true)
	out, err := service.Begin(t.Context(), sp.BeginOptions{IDP: hokIDP, Binding: metadata.PAOS, At: at, BrowserBinding: browser, HolderOfKey: true})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := out.PAOS()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := challenge.XML(t.Context())
	x, err := ecp.ParseHoKChallenge(t.Context(), raw, spServer.URL+"/resource", c.Responder.Raw, nil, binding.SOAPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	toIDP, err := x.ToIDP(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = toIDP.XML(t.Context())
	roots := x509.NewCertPool()
	roots.AddCert(spServer.Certificate())
	roots.AddCert(idpServer.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{c.Responder.Raw}, PrivateKey: c.ResponderKey}}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, idpServer.URL+"/sso", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/xml")
	req.SetBasicAuth("alice", "test-password")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	idpRaw, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	} else if response.StatusCode != http.StatusOK {
		t.Fatalf("IdP HTTP: %d %v %s", response.StatusCode, err, idpRaw)
	}
	final, err := x.Finish(t.Context(), idpRaw, binding.SOAPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = final.XML(t.Context())
	req, err = http.NewRequestWithContext(t.Context(), http.MethodPost, spServer.URL+"/acs", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", ecp.MediaType)
	response, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("SP HTTP: %d", response.StatusCode)
	}
	if _, err := ecp.VerifyTLSRequest(t.Context(), httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://plain.test", bytes.NewReader(raw)), proof.Options{}); err == nil {
		t.Fatal("plaintext or proxy-supplied certificate granted proof")
	}
}
