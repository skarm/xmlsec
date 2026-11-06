package protocol_test

import (
	"bytes"
	"crypto"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmldsig"
)

// Core 3.6 / Errata E12: formats do not change; SPProvidedID is retained.
// Core 3.7 / Profiles 4.4: signatures cover the identifier and session indices.
func TestControlMessages(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	header := protocol.MessageHeader{ID: "_control", Issuer: idp, Destination: acs, IssueInstant: testcert.Now()}
	name := protocol.NameIdentifier{Value: "alice", Format: protocol.NameIDPersistent, NameQualifier: idp, SPNameQualifier: sp, SPProvidedID: "sp-alias"}
	opts := protocol.ExchangeOptions{Issuer: idp, Destination: acs, At: testcert.Now()}
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	d, err := protocol.SignLogoutRequest(t.Context(), protocol.LogoutRequest{MessageHeader: header, NameID: name, SessionIndexes: []string{"device-2", "device-1"}, NotOnOrAfter: testcert.Now().Add(time.Minute), Reason: "relative-reason"}, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := protocol.VerifyLogoutRequest(t.Context(), d, keys, opts)
	if err != nil || r.Request().NameID != name || strings.Join(r.Request().SessionIndexes, ",") != "device-2,device-1" {
		t.Fatalf("logout: %v", err)
	}
	copyRequest := r.Request()
	copyRequest.SessionIndexes[0] = "mutated"
	if r.Request().SessionIndexes[0] != "device-2" {
		t.Fatal("mutable verified request")
	}
	bad := opts
	bad.At = testcert.Now().Add(time.Minute)
	if _, err := protocol.VerifyLogoutRequest(t.Context(), d, keys, bad); !errors.Is(err, protocol.ErrConditions) {
		t.Fatalf("exclusive expiry: %v", err)
	}
	bad = opts
	bad.Destination = sso
	if _, err := protocol.VerifyLogoutRequest(t.Context(), d, keys, bad); err == nil {
		t.Fatal("wrong destination")
	}
	if _, err := protocol.VerifyLogoutRequest(t.Context(), d, []crypto.PublicKey{c.TSAKey.Public()}, opts); err == nil {
		t.Fatal("wrong signer")
	}
	raw, _ := d.XML(t.Context())
	tampered, err := document.Parse(t.Context(), bytes.Replace(raw, []byte("alice"), []byte("mallory"), 1), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.VerifyLogoutRequest(t.Context(), tampered, keys, opts); err == nil {
		t.Fatal("tampered identifier accepted")
	}
	query, err := binding.SignRedirect(t.Context(), d, binding.Request, nil, c.LeafKey, binding.Options{SignatureMethod: xmldsig.ECDSASHA256})
	if err != nil {
		t.Fatal(err)
	}
	if redirected, _, err := protocol.VerifyRedirectLogoutRequest(t.Context(), query, keys, opts, binding.Options{}); err != nil || redirected.Request().NameID != name {
		t.Fatalf("redirect: %v", err)
	}
	for _, terminate := range []bool{false, true} {
		request := protocol.ManageNameIDRequest{MessageHeader: header, NameID: name, NewID: "new-value"}
		if terminate {
			request.NewID = ""
			request.Terminate = true
		}
		d, err := protocol.SignManageNameIDRequest(t.Context(), request, key)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := protocol.VerifyManageNameIDRequest(t.Context(), d, keys, opts)
		if err != nil || verified.Request().NameID != name || verified.Request().NewID != request.NewID || verified.Request().Terminate != terminate {
			t.Fatalf("manage: %v", err)
		}
	}
}

func TestEncryptedControlIdentifiers(t *testing.T) {
	c, recipient := testcert.New(t), encryptionKey(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	s := protocol.ManageNameIDRequest{ID: "_encrypted", Issuer: idp, Destination: acs, IssueInstant: testcert.Now(), NameID: protocol.NameIdentifier{Value: "old-secret", Format: protocol.NameIDPersistent}, NewID: "new-secret", Encryption: &protocol.EncryptionOptions{Targets: protocol.EncryptNameID, Recipient: &recipient.PublicKey}}
	d, err := protocol.SignManageNameIDRequest(t.Context(), s, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := d.XML(t.Context())
	if bytes.Contains(raw, []byte("old-secret")) || bytes.Contains(raw, []byte("new-secret")) || !bytes.Contains(raw, []byte("samlp:NewEncryptedID")) {
		t.Fatal("plaintext or wrong NewEncryptedID namespace")
	}
	o := protocol.ExchangeOptions{Issuer: idp, Destination: acs, At: testcert.Now(), Decryption: &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}}}
	r, err := protocol.VerifyManageNameIDRequest(t.Context(), d, []crypto.PublicKey{c.LeafKey.Public()}, o)
	if err != nil || r.Request().NameID.Value != "old-secret" || r.Request().NewID != "new-secret" {
		t.Fatalf("decrypt: %v", err)
	}
	o.Decryption = nil
	if _, err := protocol.VerifyManageNameIDRequest(t.Context(), d, []crypto.PublicKey{c.LeafKey.Public()}, o); err == nil {
		t.Fatal("encrypted names without key accepted")
	}
}

// An independently written wire fixture exercises explicit Issuer Format, nested
// status codes, alternative namespace prefixes and invalid signed structures.
func TestControlIndependentWire(t *testing.T) {
	c := testcert.New(t)
	template := `<p:ManageNameIDRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion" ID="_wire" Version="2.0" IssueInstant="` + testcert.Now().Format(time.RFC3339Nano) + `" Destination="` + acs + `"><a:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">` + idp + `</a:Issuer><a:NameID Format="` + protocol.NameIDPersistent + `">alice</a:NameID><p:NewID>bob</p:NewID></p:ManageNameIDRequest>`
	sign := func(raw string) *document.Document {
		t.Helper()
		d, err := document.Parse(t.Context(), []byte(raw), document.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		d, err = xmlsig.Sign(t.Context(), d, d.Root(), xmlsig.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Method: xmldsig.ECDSASHA256}, true)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	o := protocol.ExchangeOptions{Issuer: idp, Destination: acs, At: testcert.Now()}
	if _, err := protocol.VerifyManageNameIDRequest(t.Context(), sign(template), []crypto.PublicKey{c.LeafKey.Public()}, o); err != nil {
		t.Fatal(err)
	}
	withoutDestination := sign(strings.Replace(template, ` Destination="`+acs+`"`, "", 1))
	if _, err := protocol.VerifyManageNameIDRequest(t.Context(), withoutDestination, []crypto.PublicKey{c.LeafKey.Public()}, o); err == nil {
		t.Fatal("front-channel Destination requirement bypassed")
	}
	soapOptions := o
	soapOptions.Binding = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
	if _, err := protocol.VerifyManageNameIDRequest(t.Context(), withoutDestination, []crypto.PublicKey{c.LeafKey.Public()}, soapOptions); err != nil {
		t.Fatalf("SOAP Destination is optional: %v", err)
	}
	for _, raw := range []string{
		strings.Replace(template, protocol.NameIDPersistent, protocol.NameIDTransient, 1),
		strings.Replace(template, "<p:NewID>bob</p:NewID>", "<p:Terminate/><p:NewID>bob</p:NewID>", 1),
		strings.Replace(template, "<p:NewID>bob</p:NewID>", "<p:Terminate>unexpected</p:Terminate>", 1),
		strings.Replace(template, "<p:NewID>bob</p:NewID>", "<p:NewID><p:NewID>bob</p:NewID></p:NewID>", 1),
	} {
		if _, err := protocol.VerifyManageNameIDRequest(t.Context(), sign(raw), []crypto.PublicKey{c.LeafKey.Public()}, o); err == nil {
			t.Fatal("invalid signed management accepted")
		}
	}
}

func TestControlResponseAndSOAPCanonicalization(t *testing.T) {
	c := testcert.New(t)
	for _, method := range []string{c14n.Exclusive, c14n.Canonical10} {
		t.Run(method, func(t *testing.T) {
			key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Canonicalization: method}
			d, err := protocol.SignStatusResponse(t.Context(), protocol.StatusResponse{ID: "_reply", Issuer: idp, Destination: acs, IssueInstant: testcert.Now(), Kind: "LogoutResponse", InResponseTo: "_request", Status: protocol.Status{Code: protocol.Success, Subcodes: []string{protocol.PartialLogout}, Message: "one participant unavailable"}}, key)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := protocol.SignSOAP(t.Context(), d, key)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := envelope.XML(t.Context())
			m, err := binding.DecodeSOAP(t.Context(), raw, binding.SOAPOptions{})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := m.Payload(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			o := protocol.ExchangeOptions{Issuer: idp, Destination: acs, ExpectedRequestID: "_request", At: testcert.Now()}
			r, err := protocol.VerifyStatusResponse(t.Context(), payload, []crypto.PublicKey{c.LeafKey.Public()}, o)
			if err != nil || r.Status().Code != protocol.Success || r.Status().Subcodes[0] != protocol.PartialLogout {
				t.Fatalf("SOAP status: %v", err)
			}
			s := r.Status()
			s.Subcodes[0] = "mutated"
			if r.Status().Subcodes[0] != protocol.PartialLogout {
				t.Fatal("mutable status")
			}
			o.ExpectedRequestID = "_other"
			if _, err := protocol.VerifyStatusResponse(t.Context(), payload, []crypto.PublicKey{c.LeafKey.Public()}, o); !errors.Is(err, protocol.ErrCorrelation) {
				t.Fatalf("correlation: %v", err)
			}
		})
	}
}

func TestNameIdentifierFormatBounds(t *testing.T) {
	for _, tc := range []struct {
		name  protocol.NameIdentifier
		valid bool
	}{
		{protocol.NameIdentifier{Value: strings.Repeat("界", 256), Format: protocol.NameIDPersistent}, true},
		{protocol.NameIdentifier{Value: strings.Repeat("界", 257), Format: protocol.NameIDPersistent}, false},
		{protocol.NameIdentifier{Value: "_opaque-123", Format: protocol.NameIDTransient}, true},
		{protocol.NameIdentifier{Value: "not:an:NCName", Format: protocol.NameIDTransient}, false},
		{protocol.NameIdentifier{Value: "https://idp.test/entity", Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"}, true},
		{protocol.NameIdentifier{Value: "https://idp.test/entity", Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", SPProvidedID: "forbidden"}, false},
	} {
		if err := tc.name.Validate(); (err == nil) != tc.valid {
			t.Fatalf("format constraint: %+v %v", tc.name, err)
		}
	}
	a, err := protocol.NewPersistentNameID(idp, sp)
	if err != nil || a.Validate() != nil || a.NameQualifier != idp || a.SPNameQualifier != sp {
		t.Fatal("persistent identifier generation")
	}
	b, err := protocol.NewPersistentNameID(idp, sp)
	if err != nil || a.Value == b.Value {
		t.Fatal("persistent identifiers reused")
	}
}

func TestSOAPInheritedContextWithEncryptedNames(t *testing.T) {
	c := testcert.New(t)
	recipient := encryptionKey(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Canonicalization: c14n.Canonical10}
	d, err := protocol.SignManageNameIDRequest(t.Context(), protocol.ManageNameIDRequest{ID: "_context", Issuer: idp, Destination: acs, IssueInstant: testcert.Now(), NameID: protocol.NameIdentifier{Value: "old-secret", Format: protocol.NameIDPersistent}, NewID: "new-secret", Encryption: &protocol.EncryptionOptions{Targets: protocol.EncryptNameID, Recipient: &recipient.PublicKey}}, key)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := protocol.SignSOAP(t.Context(), d, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := envelope.XML(t.Context())
	raw = bytes.ReplaceAll(raw, []byte("env:"), []byte("S:"))
	raw = bytes.ReplaceAll(raw, []byte("xmlns:env="), []byte("xmlns:S="))
	raw = bytes.Replace(raw, []byte("<S:Envelope"), []byte(`<S:Envelope xml:lang="ru" xml:space="preserve"`), 1)
	m, err := binding.DecodeSOAP(t.Context(), raw, binding.SOAPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := m.Payload(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// Re-sign after changing the wire context, as a sender would do.
	envelope, err = protocol.SignSOAP(t.Context(), payload, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = envelope.XML(t.Context())
	m, err = binding.DecodeSOAP(t.Context(), raw, binding.SOAPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err = m.Payload(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r, err := protocol.VerifyManageNameIDRequest(t.Context(), payload, []crypto.PublicKey{c.LeafKey.Public()}, protocol.ExchangeOptions{Issuer: idp, Destination: acs, At: testcert.Now(), Decryption: &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}}})
	if err != nil || r.Request().NameID.Value != "old-secret" || r.Request().NewID != "new-secret" {
		t.Fatalf("inherited context lost during decryption: %v", err)
	}
	duplicate := bytes.Replace(raw, []byte("<S:Body"), []byte(`<S:Header><x:header xmlns:x="urn:outside" ID="_context"/></S:Header><S:Body`), 1)
	m, err = binding.DecodeSOAP(t.Context(), duplicate, binding.SOAPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err = m.Payload(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.VerifyManageNameIDRequest(t.Context(), payload, []crypto.PublicKey{c.LeafKey.Public()}, protocol.ExchangeOptions{Issuer: idp, Destination: acs, At: testcert.Now(), Decryption: &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}}}); err == nil {
		t.Fatal("scoping hid a duplicate ID in the SOAP header")
	}
}
