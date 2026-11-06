package sp_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/idp"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/saml/sp"
	"github.com/skarm/xmlsec/saml/state"
)

// Exercise metadata trust, encryption, browser correlation and replay in the
// same public API flow. Encryption-only certificates cannot sign requests.
func TestEncryptedWebSSO(t *testing.T) {
	const spID, idpID = "https://sp.example.test/entity", "https://idp.example.test/entity"
	const acs, sso = "https://sp.example.test/acs", "https://idp.example.test/sso"
	const innerFormat = "urn:test:subject-format"
	c := testcert.New(t)
	recipient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := *c.Leaf
	certificate.KeyUsage = x509.KeyUsageKeyEncipherment
	encryptionCert := testcert.Issue(t, &certificate, c.Root, &recipient.PublicKey, c.RootKey)
	for _, wireBinding := range []string{metadata.HTTPRedirect, metadata.HTTPPost} {
		for _, policy := range []struct {
			keyUse, requestedFormat            string
			producerDisabled, consumerDisabled bool
		}{{"encryption", "", false, false}, {"", "", false, false}, {"signing", "", false, false}, {"encryption", protocol.NameIDUnspecified, false, false}, {"encryption", protocol.NameIDEncrypted, false, false}, {"", protocol.NameIDEncrypted, false, false}, {"encryption", protocol.NameIDEncrypted, true, false}, {"encryption", protocol.NameIDEncrypted, false, true}} {
			name := wireBinding + "/" + policy.keyUse + "/" + policy.requestedFormat
			if policy.producerDisabled {
				name += "/producer-disabled"
			}
			if policy.consumerDisabled {
				name += "/consumer-disabled"
			}
			t.Run(name, func(t *testing.T) {
				keyUse := policy.keyUse
				at := testcert.Now()
				var aggregate bytes.Buffer
				aggregate.WriteString(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">`)
				for _, spec := range []metadata.EntityDescriptor{
					{ID: "_sp", EntityID: spID, ValidUntil: at.Add(time.Hour), SP: &metadata.RoleDescriptor{
						Keys:                []metadata.KeyDescriptor{{Use: "signing", CertificateDER: c.Leaf.Raw}, {Use: keyUse, CertificateDER: encryptionCert.Raw}},
						Endpoints:           map[string][]metadata.Endpoint{"AssertionConsumerService": {{Binding: metadata.HTTPPost, Location: acs, Indexed: true, Default: true}}},
						NameIDFormats:       []string{protocol.NameIDUnspecified, innerFormat},
						AuthnRequestsSigned: true, WantAssertionsSigned: true,
					}},
					{ID: "_idp", EntityID: idpID, ValidUntil: at.Add(time.Hour), IDP: &metadata.RoleDescriptor{
						Keys:                    []metadata.KeyDescriptor{{Use: "signing", CertificateDER: c.TSA.Raw}},
						Endpoints:               map[string][]metadata.Endpoint{"SingleSignOnService": {{Binding: wireBinding, Location: sso}}},
						NameIDFormats:           []string{protocol.NameIDUnspecified, innerFormat},
						WantAuthnRequestsSigned: true,
					}},
				} {
					d, err := metadata.Build(t.Context(), spec, at, metadata.Options{})
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
				partners, err := metadata.ParseTrusted(t.Context(), aggregate.Bytes(), at, metadata.Options{})
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
				all := protocol.EncryptAssertion | protocol.EncryptNameID | protocol.EncryptAttributes
				encryption := &protocol.EncryptionOptions{Targets: all}
				requireEncryption := all
				if policy.requestedFormat == protocol.NameIDEncrypted {
					// The request itself requires EncryptedID, independently of
					// the SP's default policy and the IdP's other target choices.
					encryption.Targets = protocol.EncryptAssertion | protocol.EncryptAttributes
					requireEncryption = 0
				}
				producerPolicy := encryption
				if policy.producerDisabled {
					producerPolicy = nil
				}
				identity, err := idp.NewIdentityProvider(idp.Config{EntityID: idpID, Metadata: partners, Replay: idpReplay, Signing: protocol.SigningKey{Key: c.TSAKey}, Encryption: producerPolicy})
				if err != nil {
					t.Fatal(err)
				}
				decryption := &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}}
				consumerPolicy := decryption
				if policy.consumerDisabled {
					consumerPolicy = nil
				}
				service, err := sp.NewServiceProvider(sp.Config{EntityID: spID, Metadata: partners, Requests: requests, Replay: spReplay, Signing: protocol.SigningKey{Key: c.LeafKey}, Decryption: consumerPolicy, RequireEncryption: requireEncryption})
				if err != nil {
					t.Fatal(err)
				}
				// Constructors own policy slices; caller mutation cannot change them.
				encryption.Targets = 0
				decryption.Keys[0] = nil
				browser := bytes.Repeat([]byte{42}, 32)
				outbound, err := service.Begin(t.Context(), sp.BeginOptions{IDP: idpID, Binding: wireBinding, NameIDFormat: policy.requestedFormat, BrowserBinding: browser, At: at})
				if policy.consumerDisabled {
					if outbound != nil || !errors.Is(err, sp.ErrPolicy) || requests.Len() != 0 {
						t.Fatalf("unsatisfiable encryption request was saved: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				var request *idp.Request
				if wireBinding == metadata.HTTPRedirect {
					request, err = identity.AcceptRedirect(t.Context(), outbound.RawQuery(), spID, sso, at)
				} else {
					var form bytes.Buffer
					if _, err := outbound.WritePOST(t.Context(), &form); err != nil {
						t.Fatal(err)
					}
					request, err = identity.AcceptPOST(t.Context(), form.Bytes(), spID, sso, at)
				}
				if err != nil {
					t.Fatal(err)
				}
				response, err := identity.Issue(t.Context(), request, idp.Authentication{NameID: "alice", NameIDFormat: innerFormat, AuthnInstant: at, AuthnContext: "urn:test:password", Attributes: []protocol.Attribute{{Name: "role", Values: []string{"reader"}}}}, at)
				if keyUse == "signing" || policy.producerDisabled {
					if response != nil || !errors.Is(err, idp.ErrPolicy) {
						t.Fatalf("signing-only key authorized encryption: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				var form bytes.Buffer
				if _, err := response.WritePOST(t.Context(), &form); err != nil {
					t.Fatal(err)
				}
				if policy.requestedFormat == protocol.NameIDEncrypted {
					encoded, err := url.ParseQuery(form.String())
					if err != nil {
						t.Fatal(err)
					}
					relay := encoded.Get("RelayState")
					bad, err := protocol.SignResponse(t.Context(), protocol.Response{ID: "_downgrade", Issuer: idpID, Audience: spID, Destination: acs, InResponseTo: outbound.RequestID(), IssueInstant: at, Encryption: &protocol.EncryptionOptions{Targets: protocol.EncryptAssertion, Recipient: &recipient.PublicKey}, Assertion: protocol.AssertionData{ID: "_downgrade-assertion", NameID: "alice", NotBefore: at, NotOnOrAfter: at.Add(time.Minute), AuthnInstant: at, AuthnContext: "urn:test:password"}}, protocol.SigningKey{Key: c.TSAKey})
					if err != nil {
						t.Fatal(err)
					}
					post, err := binding.EncodePOST(t.Context(), bad, binding.Response, &relay, binding.POSTLimits{})
					if err != nil {
						t.Fatal(err)
					}
					if result, err := service.ConsumePOST(t.Context(), post, sp.ConsumeOptions{BrowserBinding: browser, At: at}); result != nil || !errors.Is(err, protocol.ErrEncryption) {
						t.Fatalf("NameIDPolicy downgrade accepted: %v", err)
					}
				}
				wrong := bytes.Clone(browser)
				wrong[0] ^= 1
				if result, err := service.ConsumePOST(t.Context(), form.Bytes(), sp.ConsumeOptions{BrowserBinding: wrong, At: at}); result != nil || !errors.Is(err, sp.ErrCorrelation) {
					t.Fatalf("browser correlation bypassed: %v", err)
				}
				result, err := service.ConsumePOST(t.Context(), form.Bytes(), sp.ConsumeOptions{BrowserBinding: browser, At: at})
				if err != nil || result == nil || result.NameID() != "alice" || result.NameIDFormat() != innerFormat || result.Encryption() != all {
					t.Fatalf("encrypted WebSSO: %v", err)
				}
				if result, err := service.ConsumePOST(t.Context(), form.Bytes(), sp.ConsumeOptions{BrowserBinding: browser, At: at}); result != nil || !errors.Is(err, replay.ErrReplay) {
					t.Fatalf("encrypted replay accepted: %v", err)
				}
			})
		}
	}
}
