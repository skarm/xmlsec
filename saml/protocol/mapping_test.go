package protocol_test

import (
	"crypto"
	"crypto/fips140"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmlenc"
)

// Core 3.8 / Profiles 7: mapping targets a different federation and may return
// an identifier the requester cannot decrypt. This does not rename its source ID.
func TestNameIDMapping(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey}
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	target := encryptionKey(t)
	q := protocol.NameIDMappingRequest{ID: "_mapping", Issuer: sp, Destination: sso, IssueInstant: testcert.Now(), NameID: protocol.NameIdentifier{Value: "source-alice", Format: protocol.NameIDPersistent, SPNameQualifier: sp}, Policy: protocol.NameIDPolicy{Format: protocol.NameIDPersistent, SPNameQualifier: "https://target.test/entity", AllowCreate: true}, Encryption: &protocol.EncryptionOptions{Targets: protocol.EncryptNameID, Recipient: &target.PublicKey}}
	d, err := protocol.SignNameIDMappingRequest(t.Context(), q, key)
	if err != nil {
		t.Fatal(err)
	}
	o := protocol.ExchangeOptions{Issuer: sp, Destination: sso, Binding: metadata.SOAP, At: testcert.Now(), Decryption: &protocol.DecryptionOptions{Keys: []crypto.Decrypter{target}}}
	v, err := protocol.VerifyNameIDMappingRequest(t.Context(), d, keys, o)
	if err != nil || v.Request().NameID != q.NameID || v.Request().Policy != q.Policy {
		t.Fatalf("mapping request: %v", err)
	}
	bad := o
	bad.Decryption = nil
	if _, err = protocol.VerifyNameIDMappingRequest(t.Context(), d, keys, bad); err == nil {
		t.Fatal("encrypted input accepted without key")
	}
	mapped := protocol.NameIdentifier{Value: "pairwise-target-alice", Format: q.Policy.Format, SPNameQualifier: q.Policy.SPNameQualifier}
	plain, err := protocol.NameIDDocument(t.Context(), mapped)
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := protocol.EncryptMappedIdentifier(t.Context(), plain, &protocol.EncryptionOptions{Targets: protocol.EncryptNameID, Recipient: &target.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []*document.Document{plain, opaque} {
		response, err := protocol.SignNameIDMappingResponse(t.Context(), protocol.NameIDMappingResponse{ID: "_mapped", Issuer: idp, IssueInstant: testcert.Now(), InResponseTo: q.ID, Identifier: id}, key)
		if err != nil {
			t.Fatal(err)
		}
		options := protocol.ExchangeOptions{Issuer: idp, ExpectedRequestID: q.ID, At: testcert.Now(), Binding: metadata.SOAP}
		result, err := protocol.VerifyNameIDMappingResponse(t.Context(), response, keys, options)
		if err != nil || result.Identifier() == nil {
			t.Fatalf("mapping response: %v", err)
		}
		if err = protocol.CheckMappedPolicy(t.Context(), result.Identifier(), q.Policy); err != nil {
			t.Fatal(err)
		}
		got, err := protocol.DecryptMappedNameID(t.Context(), result.Identifier(), &protocol.DecryptionOptions{Keys: []crypto.Decrypter{target}})
		if err != nil || got != mapped {
			t.Fatalf("target identifier: %v", err)
		}
		options.ExpectedRequestID = "_different"
		if _, err = protocol.VerifyNameIDMappingResponse(t.Context(), response, keys, options); err == nil {
			t.Fatal("uncorrelated mapping accepted")
		}
	}
	wrong := q.Policy
	wrong.Format = protocol.NameIDEmail
	if err = protocol.CheckMappedPolicy(t.Context(), plain, wrong); err == nil {
		t.Fatal("wrong output format accepted")
	}
	wrong = q.Policy
	wrong.SPNameQualifier = sp
	if err = protocol.CheckMappedPolicy(t.Context(), plain, wrong); err == nil {
		t.Fatal("wrong target federation accepted")
	}
	failure, err := protocol.SignNameIDMappingResponse(t.Context(), protocol.NameIDMappingResponse{Issuer: idp, IssueInstant: testcert.Now(), InResponseTo: q.ID, Status: protocol.Status{Code: protocol.Requester, Subcodes: []string{protocol.UnknownPrincipal}}, Identifier: v.ErrorIdentifier()}, key)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := protocol.VerifyNameIDMappingResponse(t.Context(), failure, keys, protocol.ExchangeOptions{Issuer: idp, At: testcert.Now(), Binding: metadata.SOAP, ExpectedRequestID: q.ID})
	if err != nil || failed.Identifier() != nil || failed.Status().Code != protocol.Requester {
		t.Fatalf("authenticated mapping failure: %v", err)
	}
}

func TestLimitedUseMappedIdentifier(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey}
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	recipient := encryptionKey(t)
	sub, _ := protocol.NewSubject(t.Context(), protocol.NameIdentifier{Value: "limited", Format: protocol.NameIDPersistent})
	conditions := queryXML(t, `<saml:Conditions xmlns:saml="`+protocol.AssertionNamespace+`" NotOnOrAfter="`+testcert.Now().Add(time.Minute).Format(time.RFC3339)+`"><saml:AudienceRestriction><saml:Audience>`+sp+`</saml:Audience></saml:AudienceRestriction></saml:Conditions>`)
	d, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: "_limited", Issuer: idp, IssueInstant: testcert.Now(), Subject: sub, Conditions: conditions}, key)
	if err != nil {
		t.Fatal(err)
	}
	o := protocol.AssertionOptions{Issuer: idp, Audience: sp, At: testcert.Now(), Decryption: &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}}}
	a, err := protocol.VerifyAuthorityAssertion(t.Context(), d, keys, o)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := protocol.EncryptMappedAssertion(t.Context(), a, &protocol.EncryptionOptions{Targets: protocol.EncryptNameID, Recipient: &recipient.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	limited, err := protocol.DecryptMappedAssertion(t.Context(), encrypted, keys, o)
	if err != nil || limited.ID() != "_limited" || len(limited.Statements()) != 0 {
		t.Fatalf("limited identifier: %v", err)
	}
	bad := o
	bad.Audience = idp
	if _, err = protocol.DecryptMappedAssertion(t.Context(), encrypted, keys, bad); err == nil {
		t.Fatal("wrong audience accepted")
	}
	bad = o
	bad.At = testcert.Now().Add(time.Minute)
	if _, err = protocol.DecryptMappedAssertion(t.Context(), encrypted, keys, bad); err == nil {
		t.Fatal("expired limited identifier accepted")
	}
	if _, err = protocol.DecryptMappedNameID(t.Context(), encrypted, o.Decryption); err == nil {
		t.Fatal("limited assertion treated as bare NameID")
	}
}

func TestMappingLegacyEncryptionNeedsVerifiedEnvelope(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy algorithms are disabled in FIPS mode")
	}
	c := testcert.New(t)
	recipient := encryptionKey(t)
	want := protocol.NameIdentifier{Value: "target-alice", Format: protocol.NameIDPersistent}
	plain, err := protocol.NameIDDocument(t.Context(), want)
	if err != nil {
		t.Fatal(err)
	}
	data := xmlenc.Options{DataAlgorithm: xmlenc.AES256CBC, AllowLegacy: true}
	enc, err := protocol.EncryptMappedIdentifier(t.Context(), plain, &protocol.EncryptionOptions{Targets: protocol.EncryptNameID, Recipient: &recipient.PublicKey, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	decryption := &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}, Data: data}
	if _, err = protocol.DecryptMappedNameID(t.Context(), enc, decryption); err == nil {
		t.Fatal("unauthenticated CBC identifier accepted")
	}
	d, err := protocol.SignNameIDMappingResponse(t.Context(), protocol.NameIDMappingResponse{Issuer: idp, IssueInstant: testcert.Now(), InResponseTo: "_legacy_mapping", Identifier: enc}, protocol.SigningKey{Key: c.LeafKey})
	if err != nil {
		t.Fatal(err)
	}
	r, err := protocol.VerifyNameIDMappingResponse(t.Context(), d, []crypto.PublicKey{c.LeafKey.Public()}, protocol.ExchangeOptions{Issuer: idp, ExpectedRequestID: "_legacy_mapping", At: testcert.Now(), Binding: metadata.SOAP})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.DecryptNameID(t.Context(), decryption); err != nil || got != want {
		t.Fatalf("authenticated CBC mapping: %v", err)
	}
	if _, err = r.DecryptNameID(t.Context(), &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}}); err == nil {
		t.Fatal("CBC accepted without explicit legacy policy")
	}
}
