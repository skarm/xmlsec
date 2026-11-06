package protocol_test

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestAuthorityNamespaceAndValueIntegrity(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey}
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	q := queryRequest(t, protocol.AttributeQuery)
	value := `<saml:Attribute xmlns:saml="` + protocol.AssertionNamespace + `" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:t="urn:original:type" Name="role"><saml:AttributeValue xsi:type="t:Role">reader</saml:AttributeValue></saml:Attribute>`
	q.Attributes = []*document.Document{queryXML(t, value)}
	statement := queryXML(t, `<saml:AttributeStatement xmlns:saml="`+protocol.AssertionNamespace+`">`+value+`</saml:AttributeStatement>`)
	issued, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: "_typed", Issuer: idp, IssueInstant: testcert.Now(), Subject: q.Subject, Statements: []*document.Document{statement}}, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := issued.XML(t.Context())
	mutant := bytes.ReplaceAll(raw, []byte("urn:original:type"), []byte("urn:modified:type"))
	changed, err := document.Parse(t.Context(), mutant, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = protocol.VerifyAuthorityAssertion(t.Context(), changed, keys, protocol.AssertionOptions{Issuer: idp, At: testcert.Now()}); err == nil {
		t.Fatal("QName namespace changed outside signature")
	}
	v, err := protocol.VerifyAuthorityAssertion(t.Context(), issued, keys, protocol.AssertionOptions{Issuer: idp, At: testcert.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err = protocol.MatchQueryResponse(t.Context(), q, []*protocol.VerifiedAuthorityAssertion{v}, protocol.QueryMatchOptions{}); err != nil {
		t.Fatal(err)
	}
	q.Attributes = []*document.Document{queryXML(t, strings.ReplaceAll(value, "urn:original:type", "urn:other:type"))}
	if err = protocol.MatchQueryResponse(t.Context(), q, []*protocol.VerifiedAuthorityAssertion{v}, protocol.QueryMatchOptions{}); err == nil {
		t.Fatal("different QName-valued attribute type matched")
	}
	q = queryRequest(t, protocol.AttributeQuery)
	q.Limits.MaxValueBytes = 16
	if _, err = protocol.SignQuery(t.Context(), q, key); err == nil {
		t.Fatal("attribute XML byte budget ignored")
	}
}

func TestAuthorityConditionsAndContexts(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey}
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	q := queryRequest(t, protocol.AuthenticationQuery)
	a := authorityAssertion(t, q, "_context", key)
	v, err := protocol.VerifyAuthorityAssertion(t.Context(), a, keys, protocol.AssertionOptions{Issuer: idp, At: testcert.Now()})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"minimum", "maximum", "better"} {
		t.Run(mode, func(t *testing.T) {
			q.Context.Comparison = mode
			if err = protocol.MatchQueryResponse(t.Context(), q, []*protocol.VerifiedAuthorityAssertion{v}, protocol.QueryMatchOptions{}); err == nil {
				t.Fatal("context ordering guessed")
			}
			called := false
			matcher := protocol.QueryMatchOptions{Context: func(_ context.Context, ac document.Element, w protocol.RequestedContext) (bool, error) {
				called = true
				return ac.Children()[0].Text() == "urn:example:strong" && w.Comparison == mode, nil
			}}
			if err = protocol.MatchQueryResponse(t.Context(), q, []*protocol.VerifiedAuthorityAssertion{v}, matcher); err != nil || !called {
				t.Fatalf("explicit ordering %s: %v", mode, err)
			}
		})
	}
	for _, condition := range []struct {
		name, xml string
		valid     bool
	}{
		{"audience-or-and", `<saml:AudienceRestriction><saml:Audience>urn:other</saml:Audience><saml:Audience>` + sp + `</saml:Audience></saml:AudienceRestriction><saml:AudienceRestriction><saml:Audience>` + sp + `</saml:Audience></saml:AudienceRestriction>`, true},
		{"audience-and-fails", `<saml:AudienceRestriction><saml:Audience>` + sp + `</saml:Audience></saml:AudienceRestriction><saml:AudienceRestriction><saml:Audience>urn:other</saml:Audience></saml:AudienceRestriction>`, false},
		{"unknown-condition", `<custom:Condition xmlns:custom="urn:unknown"/>`, false},
		{"duplicate-one-time", `<saml:OneTimeUse/><saml:OneTimeUse/>`, false},
		{"large-proxy-count", `<saml:ProxyRestriction Count="9999999999999999999999999999999999"/>`, true},
	} {
		t.Run(condition.name, func(t *testing.T) {
			d, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: "_condition", Issuer: idp, IssueInstant: testcert.Now(), Subject: q.Subject, Statements: []*document.Document{queryStatement(t, protocol.AuthenticationQuery)}, Conditions: queryXML(t, `<saml:Conditions xmlns:saml="`+protocol.AssertionNamespace+`">`+condition.xml+`</saml:Conditions>`)}, key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = protocol.VerifyAuthorityAssertion(t.Context(), d, keys, protocol.AssertionOptions{Issuer: idp, Audience: sp, At: testcert.Now()})
			if (err == nil) != condition.valid {
				t.Fatalf("condition validity %v: %v", condition.valid, err)
			}
		})
	}
}

// Core 2.6.1 / 2.7.4.3 distinguish extensible Advice from closed Evidence.
func TestAuthorityAdviceAndEvidence(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey}
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	q := queryRequest(t, protocol.AuthorizationQuery)
	for _, test := range []struct {
		name, body string
		valid      bool
	}{
		{"empty", "", true},
		{"references", `<saml:AssertionIDRef>_proof</saml:AssertionIDRef><saml:AssertionURIRef>https://issuer.test/proof</saml:AssertionURIRef>`, true},
		{"foreign", `<e:Extra xmlns:e="urn:example:advice"/>`, true},
		{"bad-ID", `<saml:AssertionIDRef>not an ID</saml:AssertionIDRef>`, false},
		{"empty-reference", `<saml:AssertionURIRef/>`, false},
		{"unknown-saml", `<saml:Unknown/>`, false},
		{"unqualified", `<Extra/>`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			advice := queryXML(t, `<saml:Advice xmlns:saml="`+protocol.AssertionNamespace+`">`+test.body+`</saml:Advice>`)
			d, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: "_advice", Issuer: idp, IssueInstant: testcert.Now(), Subject: q.Subject, Statements: []*document.Document{queryStatement(t, q.Kind)}, Advice: advice}, key)
			if (err == nil) != test.valid {
				t.Fatalf("Advice validity %v: %v", test.valid, err)
			}
			if test.valid {
				if _, err = protocol.VerifyAuthorityAssertion(t.Context(), d, keys, protocol.AssertionOptions{Issuer: idp, At: testcert.Now()}); err != nil {
					t.Fatal(err)
				}
			}
			q.Evidence = queryXML(t, `<saml:Evidence xmlns:saml="`+protocol.AssertionNamespace+`">`+test.body+`</saml:Evidence>`)
			_, err = protocol.SignQuery(t.Context(), q, key)
			want := test.name == "references"
			if (err == nil) != want {
				t.Fatalf("Evidence validity %v: %v", want, err)
			}
		})
	}
}

func TestQuerySubjectConfirmationAndExtensions(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey}
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	q := queryRequest(t, protocol.AuthenticationQuery)
	q.Subject = queryXML(t, `<saml:Subject xmlns:saml="`+protocol.AssertionNamespace+`"><saml:SubjectConfirmation Method="`+protocol.Bearer+`"><saml:SubjectConfirmationData Recipient="https://requester.test/query"/></saml:SubjectConfirmation></saml:Subject>`)
	q.Consent = "urn:oasis:names:tc:SAML:2.0:consent:obtained"
	q.Extensions = queryXML(t, `<samlp:Extensions xmlns:samlp="`+protocol.ProtocolNamespace+`"><e:Policy xmlns:e="urn:example:extension">strict</e:Policy></samlp:Extensions>`)
	d, err := protocol.SignQuery(t.Context(), q, key)
	if err != nil {
		t.Fatal(err)
	}
	vq, err := protocol.VerifyQuery(t.Context(), d, keys, protocol.ExchangeOptions{Issuer: sp, Destination: sso, At: testcert.Now(), Binding: metadata.SOAP})
	if err != nil || vq.Query().Extensions == nil || vq.Query().Consent != q.Consent {
		t.Fatalf("protocol extensions: %v", err)
	}
	a := authorityAssertion(t, q, "_confirmation", key)
	v, err := protocol.VerifyAuthorityAssertion(t.Context(), a, keys, protocol.AssertionOptions{Issuer: idp, At: testcert.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err = protocol.MatchQueryResponse(t.Context(), q, []*protocol.VerifiedAuthorityAssertion{v}, protocol.QueryMatchOptions{}); err == nil {
		t.Fatal("confirmation treated as name equality")
	}
	matcher := protocol.QueryMatchOptions{Confirm: func(_ context.Context, a, b document.Element) (bool, error) {
		x, _ := a.Children()[0].Attribute(document.Name{Local: "Recipient"})
		y, _ := b.Children()[0].Attribute(document.Name{Local: "Recipient"})
		return x == y, nil
	}}
	if err = protocol.MatchQueryResponse(t.Context(), q, []*protocol.VerifiedAuthorityAssertion{v}, matcher); err != nil {
		t.Fatal(err)
	}
	q.Subject = queryXML(t, `<saml:Subject xmlns:saml="`+protocol.AssertionNamespace+`"><saml:SubjectConfirmation Method="`+protocol.Bearer+`"><saml:SubjectConfirmationData/><saml:SubjectConfirmationData/></saml:SubjectConfirmation></saml:Subject>`)
	if _, err = protocol.SignQuery(t.Context(), q, key); err == nil {
		t.Fatal("duplicate confirmation data accepted")
	}
}

func FuzzAuthorityQueryParsers(f *testing.F) {
	c := testcert.New(f)
	key := protocol.SigningKey{Key: c.LeafKey}
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	sub, _ := protocol.NewSubject(f.Context(), protocol.NameIdentifier{Value: "alice"})
	q := protocol.Query{ID: "_fuzz", Issuer: sp, Destination: sso, IssueInstant: testcert.Now(), Kind: protocol.AttributeQuery, Subject: sub}
	d, err := protocol.SignQuery(f.Context(), q, key)
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := d.XML(f.Context())
	f.Add(raw)
	response, err := protocol.SignQueryResponse(f.Context(), protocol.QueryResponse{Issuer: idp, IssueInstant: testcert.Now(), InResponseTo: q.ID}, key)
	if err != nil {
		f.Fatal(err)
	}
	raw, _ = response.XML(f.Context())
	f.Add(raw)
	identifier, err := protocol.NameIDDocument(f.Context(), protocol.NameIdentifier{Value: "alice"})
	if err != nil {
		f.Fatal(err)
	}
	mapping, err := protocol.SignNameIDMappingResponse(f.Context(), protocol.NameIDMappingResponse{Issuer: idp, IssueInstant: testcert.Now(), InResponseTo: q.ID, Identifier: identifier}, key)
	if err != nil {
		f.Fatal(err)
	}
	raw, _ = mapping.XML(f.Context())
	f.Add(raw)
	f.Add([]byte(`<invalid/>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 16384 {
			t.Skip()
		}
		d, err := document.Parse(t.Context(), raw, document.DefaultLimits())
		if err != nil {
			return
		}
		o := protocol.ExchangeOptions{Issuer: sp, Destination: sso, At: testcert.Now(), Binding: metadata.SOAP}
		_, _ = protocol.VerifyQuery(t.Context(), d, keys, o)
		_, _ = protocol.VerifyNameIDMappingRequest(t.Context(), d, keys, o)
		o.Issuer, o.Destination, o.ExpectedRequestID = idp, "", q.ID
		_, _ = protocol.VerifyQueryResponse(t.Context(), d, keys, q, protocol.QueryResponseOptions{ExchangeOptions: o})
		_, _ = protocol.VerifyNameIDMappingResponse(t.Context(), d, keys, o)
	})
}

func TestIndependentAssertionIssuerTrust(t *testing.T) {
	c := testcert.New(t)
	q := queryRequest(t, protocol.AttributeQuery)
	a, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: "_delegated", Issuer: "urn:delegated:authority", IssueInstant: testcert.Now(), Subject: q.Subject, Statements: []*document.Document{queryStatement(t, q.Kind)}}, protocol.SigningKey{Key: c.TSAKey})
	if err != nil {
		t.Fatal(err)
	}
	spec := protocol.QueryResponse{ID: "_delegated_response", Issuer: idp, IssueInstant: testcert.Now(), InResponseTo: q.ID, Assertions: []*document.Document{a}}
	if _, err = protocol.SignQueryResponse(t.Context(), spec, protocol.SigningKey{Key: c.LeafKey}); err == nil {
		t.Fatal("foreign signature preserved without its key")
	}
	key := protocol.SigningKey{Key: c.LeafKey, PreserveKeys: func(_ context.Context, parent document.Element) ([]crypto.PublicKey, error) {
		if parent.Children()[0].Text() != "urn:delegated:authority" {
			return nil, protocol.ErrSignature
		}
		return []crypto.PublicKey{c.TSAKey.Public()}, nil
	}}
	r, err := protocol.SignQueryResponse(t.Context(), spec, key)
	if err != nil {
		t.Fatal(err)
	}
	o := protocol.QueryResponseOptions{Issuer: idp, ExpectedRequestID: q.ID, At: testcert.Now(), Binding: metadata.SOAP, Audience: sp}
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	if _, err = protocol.VerifyQueryResponse(t.Context(), r, keys, q, o); err == nil {
		t.Fatal("envelope issuer trusted for a different assertion issuer")
	}
	o.AssertionTrust = func(_ context.Context, who string) ([]crypto.PublicKey, error) {
		if who != "urn:delegated:authority" {
			return nil, protocol.ErrSignature
		}
		return []crypto.PublicKey{c.TSAKey.Public()}, nil
	}
	v, err := protocol.VerifyQueryResponse(t.Context(), r, keys, q, o)
	if err != nil || v.Assertions()[0].Issuer() != "urn:delegated:authority" {
		t.Fatalf("separately trusted issuer: %v", err)
	}
}

func queryXML(t *testing.T, s string) *document.Document {
	t.Helper()
	d, err := document.Parse(t.Context(), []byte(s), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func queryStatement(t *testing.T, kind protocol.QueryKind) *document.Document {
	t.Helper()
	switch kind {
	case protocol.AuthenticationQuery:
		return queryXML(t, `<saml:AuthnStatement xmlns:saml="`+protocol.AssertionNamespace+`" AuthnInstant="`+testcert.Now().Add(-time.Hour).Format(time.RFC3339)+`" SessionIndex="past-session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:example:strong</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`)
	case protocol.AttributeQuery:
		return queryXML(t, `<saml:AttributeStatement xmlns:saml="`+protocol.AssertionNamespace+`"><saml:Attribute Name="role"><saml:AttributeValue><v:Role xmlns:v="urn:example:value">reader</v:Role></saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`)
	default:
		return queryXML(t, `<saml:AuthzDecisionStatement xmlns:saml="`+protocol.AssertionNamespace+`" Resource="urn:example:resource" Decision="Permit"><saml:Action Namespace="urn:example:actions">read</saml:Action></saml:AuthzDecisionStatement>`)
	}
}

func queryRequest(t *testing.T, kind protocol.QueryKind) protocol.Query {
	t.Helper()
	sub, err := protocol.NewSubject(t.Context(), protocol.NameIdentifier{Value: "alice", Format: protocol.NameIDPersistent, NameQualifier: idp, SPNameQualifier: sp})
	if err != nil {
		t.Fatal(err)
	}
	q := protocol.Query{ID: "_query", Issuer: sp, Destination: sso, IssueInstant: testcert.Now(), Kind: kind, Subject: sub}
	switch kind {
	case protocol.AuthenticationQuery:
		q.SessionIndex = "past-session"
		q.Context = &protocol.RequestedContext{Classes: []string{"urn:example:strong"}}
	case protocol.AttributeQuery:
		q.Attributes = []*document.Document{queryXML(t, `<saml:Attribute xmlns:saml="`+protocol.AssertionNamespace+`" Name="role"><saml:AttributeValue><v:Role xmlns:v="urn:example:value">reader</v:Role></saml:AttributeValue></saml:Attribute>`)}
	case protocol.AuthorizationQuery:
		q.Resource = "urn:example:resource"
		q.Actions = []protocol.Action{{Namespace: "urn:example:actions", Value: "read"}}
	case protocol.AssertionRequest:
		q.Subject = nil
		q.AssertionIDs = []string{"_assertion"}
	}
	return q
}

func authorityAssertion(t *testing.T, q protocol.Query, id string, key protocol.SigningKey) *document.Document {
	t.Helper()
	sub := q.Subject
	if sub == nil {
		sub, _ = protocol.NewSubject(t.Context(), protocol.NameIdentifier{Value: "alice"})
	}
	s := protocol.AuthorityAssertion{ID: id, Issuer: idp, IssueInstant: testcert.Now(), Subject: sub, Statements: []*document.Document{queryStatement(t, q.Kind)}}
	d, err := protocol.SignAuthorityAssertion(t.Context(), s, key)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Core 3.3: three distinct query contracts, empty Success, multiple assertions,
// complete subject matching, independently signed assertions and SOAP context.
func TestAuthorityQueries(t *testing.T) {
	c := testcert.New(t)
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	for _, canonical := range []string{c14n.Exclusive, c14n.Canonical10} {
		for _, kind := range []protocol.QueryKind{protocol.AuthenticationQuery, protocol.AttributeQuery, protocol.AuthorizationQuery, protocol.AssertionRequest} {
			t.Run(canonical+"/"+string(kind), func(t *testing.T) {
				key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Canonicalization: canonical}
				q := queryRequest(t, kind)
				d, err := protocol.SignQuery(t.Context(), q, key)
				if err != nil {
					t.Fatal(err)
				}
				soap, err := protocol.SignSOAP(t.Context(), d, key)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := soap.XML(t.Context())
				m, err := binding.DecodeSOAP(t.Context(), raw, binding.SOAPOptions{})
				if err != nil {
					t.Fatal(err)
				}
				payload, _ := m.Payload(t.Context())
				v, err := protocol.VerifyQuery(t.Context(), payload, keys, protocol.ExchangeOptions{Issuer: sp, Destination: sso, At: testcert.Now(), Binding: metadata.SOAP})
				if err != nil || v.Query().Kind != kind {
					t.Fatalf("verify query: %v", err)
				}
				var assertions []*document.Document
				for _, id := range []string{"_assertion", "_second"} {
					if kind == protocol.AssertionRequest && id == "_second" {
						continue
					}
					assertions = append(assertions, authorityAssertion(t, q, id, key))
				}
				for _, list := range [][]*document.Document{nil, assertions} {
					r, err := protocol.SignQueryResponse(t.Context(), protocol.QueryResponse{ID: "_result", Issuer: idp, IssueInstant: testcert.Now(), InResponseTo: q.ID, Assertions: list}, key)
					if err != nil {
						t.Fatal(err)
					}
					soap, err = protocol.SignSOAP(t.Context(), r, key)
					if err != nil {
						t.Fatal(err)
					}
					raw, _ = soap.XML(t.Context())
					m, err = binding.DecodeSOAP(t.Context(), raw, binding.SOAPOptions{})
					if err != nil {
						t.Fatal(err)
					}
					payload, _ = m.Payload(t.Context())
					o := protocol.QueryResponseOptions{Issuer: idp, ExpectedRequestID: q.ID, At: testcert.Now(), Binding: metadata.SOAP, Audience: sp}
					verified, err := protocol.VerifyQueryResponse(t.Context(), payload, keys, q, o)
					if err != nil || len(verified.Assertions()) != len(list) {
						t.Fatalf("verify response %d: %v", len(list), err)
					}
					bad := o
					bad.ExpectedRequestID = "_other"
					if _, err = protocol.VerifyQueryResponse(t.Context(), payload, keys, q, bad); err == nil {
						t.Fatal("wrong correlation accepted")
					}
					bad = o
					bad.At = testcert.Now().Add(time.Hour)
					if _, err = protocol.VerifyQueryResponse(t.Context(), payload, keys, q, bad); err == nil {
						t.Fatal("stale response accepted")
					}
					changed := bytes.Replace(raw, []byte(`ID="_result"`), []byte(`ID="_changed"`), 1)
					broken, _ := binding.DecodeSOAP(t.Context(), changed, binding.SOAPOptions{})
					b, _ := broken.Payload(t.Context())
					if _, err = protocol.VerifyQueryResponse(t.Context(), b, keys, q, o); err == nil {
						t.Fatal("tampered envelope accepted")
					}
				}
			})
		}
	}
}

func TestQueryFiltersRejectDisclosure(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey}
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	for _, kind := range []protocol.QueryKind{protocol.AuthenticationQuery, protocol.AttributeQuery, protocol.AuthorizationQuery, protocol.AssertionRequest} {
		t.Run(string(kind), func(t *testing.T) {
			q := queryRequest(t, kind)
			a := authorityAssertion(t, q, "_assertion", key)
			v, err := protocol.VerifyAuthorityAssertion(t.Context(), a, keys, protocol.AssertionOptions{Issuer: idp, At: testcert.Now()})
			if err != nil {
				t.Fatal(err)
			}
			bad := q
			switch kind {
			case protocol.AuthenticationQuery:
				bad.SessionIndex = "other-session"
			case protocol.AttributeQuery:
				bad.Attributes = []*document.Document{queryXML(t, `<saml:Attribute xmlns:saml="`+protocol.AssertionNamespace+`" Name="different"/>`)}
			case protocol.AuthorizationQuery:
				bad.Actions = []protocol.Action{{Namespace: "urn:example:actions", Value: "write"}}
			case protocol.AssertionRequest:
				bad.AssertionIDs = []string{"_different"}
			}
			if err = protocol.MatchQueryResponse(t.Context(), bad, []*protocol.VerifiedAuthorityAssertion{v}, protocol.QueryMatchOptions{}); err == nil {
				t.Fatal("unrequested data accepted")
			}
			if kind != protocol.AssertionRequest {
				bad = q
				bad.Subject, _ = protocol.NewSubject(t.Context(), protocol.NameIdentifier{Value: "mallory"})
				if err = protocol.MatchQueryResponse(t.Context(), bad, []*protocol.VerifiedAuthorityAssertion{v}, protocol.QueryMatchOptions{}); err == nil {
					t.Fatal("different subject accepted")
				}
			}
		})
	}
	q := queryRequest(t, protocol.AuthenticationQuery)
	a := authorityAssertion(t, q, "_assertion", key)
	v, _ := protocol.VerifyAuthorityAssertion(t.Context(), a, keys, protocol.AssertionOptions{Issuer: idp, At: testcert.Now()})
	q.Context = &protocol.RequestedContext{Classes: []string{"urn:example:unavailable"}}
	err := protocol.MatchQueryResponse(t.Context(), q, []*protocol.VerifiedAuthorityAssertion{v}, protocol.QueryMatchOptions{})
	var status *protocol.StatusError
	if !errors.As(err, &status) || len(status.Subcodes) != 1 || status.Subcodes[0] != protocol.NoAuthnContext {
		t.Fatalf("NoAuthnContext: %v", err)
	}
	q = queryRequest(t, protocol.AttributeQuery)
	q.Attributes = append(q.Attributes, q.Attributes[0])
	if _, err = protocol.SignQuery(t.Context(), q, key); err == nil {
		t.Fatal("duplicate requested attribute accepted")
	}
}

func TestEncryptedAuthorityQueries(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey}
	recipient := encryptionKey(t)
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	q := queryRequest(t, protocol.AttributeQuery)
	q.Encryption = &protocol.EncryptionOptions{Targets: protocol.EncryptNameID, Recipient: &recipient.PublicKey}
	d, err := protocol.SignQuery(t.Context(), q, key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := protocol.VerifyQuery(t.Context(), d, keys, protocol.ExchangeOptions{Issuer: sp, Destination: sso, At: testcert.Now(), Binding: metadata.SOAP, Decryption: &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}}})
	if err != nil {
		t.Fatal(err)
	}
	if v.Query().Subject.Root().Children()[0].Text() != "alice" {
		t.Fatal("wrong decrypted query subject")
	}
	for targets := protocol.EncryptionTargets(1); targets < 8; targets++ {
		t.Run(fmt.Sprint(targets), func(t *testing.T) {
			a, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: "_encrypted_assertion", Issuer: idp, IssueInstant: testcert.Now(), Subject: q.Subject, Statements: []*document.Document{queryStatement(t, q.Kind)}, Encryption: &protocol.EncryptionOptions{Targets: targets, Recipient: &recipient.PublicKey}}, key)
			if err != nil {
				t.Fatal(err)
			}
			r, err := protocol.SignQueryResponse(t.Context(), protocol.QueryResponse{ID: "_response", Issuer: idp, IssueInstant: testcert.Now(), InResponseTo: q.ID, Assertions: []*document.Document{a}}, key)
			if err != nil {
				t.Fatal(err)
			}
			o := protocol.QueryResponseOptions{Issuer: idp, ExpectedRequestID: q.ID, At: testcert.Now(), Binding: metadata.SOAP, Decryption: &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}}, Audience: sp}
			got, err := protocol.VerifyQueryResponse(t.Context(), r, keys, q, o)
			if err != nil || len(got.Assertions()) != 1 {
				t.Fatalf("encrypted assertion %d: %v", targets, err)
			}
		})
	}
}

func TestAuthorityTimeWindowAttributePresence(t *testing.T) {
	at := testcert.Now()
	key := testcert.Key(t)
	for _, tc := range []struct {
		name, start, end string
		bad              bool
	}{
		{"absent", "", "", false},
		{"absent_start_future_end", "", at.Add(time.Minute).Format(time.RFC3339), false},
		{"zero_start_future_end", "0001-01-01T00:00:00Z", at.Add(time.Minute).Format(time.RFC3339), true},
		{"1990_start_future_end", "1990-01-01T00:00:00Z", at.Add(time.Minute).Format(time.RFC3339), true},
		{"small_window", at.Add(-time.Minute).Format(time.RFC3339), at.Add(time.Minute).Format(time.RFC3339), false},
		{"exact_window", at.Add(-time.Minute).Format(time.RFC3339), at.Add(9 * time.Minute).Format(time.RFC3339), false},
		{"long_window", at.Add(-time.Minute).Format(time.RFC3339), at.Add(10 * time.Minute).Format(time.RFC3339), true},
		{"future_start", at.Add(time.Minute).Format(time.RFC3339), at.Add(2 * time.Minute).Format(time.RFC3339), true},
		{"zero_start_only", "0001-01-01T00:00:00Z", "", false},
		{"zero_end", "", "0001-01-01T00:00:00Z", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := ""
			if tc.start != "" {
				attrs += ` NotBefore="` + tc.start + `"`
			}
			if tc.end != "" {
				attrs += ` NotOnOrAfter="` + tc.end + `"`
			}
			cond, err := document.Parse(t.Context(), []byte(`<a:Conditions xmlns:a="`+protocol.AssertionNamespace+`"`+attrs+`/>`), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			d, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: "_presence", Issuer: "https://issuer.test/entity", IssueInstant: at, Conditions: cond}, protocol.SigningKey{Key: key})
			if err != nil {
				t.Fatal(err)
			}
			got, err := protocol.VerifyAuthorityAssertion(t.Context(), d, []crypto.PublicKey{key.Public()}, protocol.AssertionOptions{Issuer: "https://issuer.test/entity", At: at, Limits: protocol.Limits{MaxAssertionLifetime: 10 * time.Minute}})
			if tc.bad {
				if got != nil || !errors.Is(err, protocol.ErrConditions) {
					t.Fatalf("oversized/invalid window accepted: result=%v err=%v", got != nil, err)
				}
			} else if got == nil || err != nil {
				t.Fatalf("valid optional/window rejected: %v", err)
			}
		})
	}
}

func TestQueryResponseSignatureBudget(t *testing.T) {
	at := testcert.Now()
	key := testcert.Key(t)
	signing := protocol.SigningKey{Key: key}
	const issuer = "https://issuer.test/entity"
	assertions := make([]*document.Document, 64)
	ids := make([]string, 64)
	for i := range assertions {
		ids[i] = fmt.Sprintf("_assertion-%d", i)
		var err error
		assertions[i], err = protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: ids[i], Issuer: issuer, IssueInstant: at}, signing)
		if err != nil {
			t.Fatal(err)
		}
	}
	spec := protocol.QueryResponse{ID: "_response", Issuer: issuer, IssueInstant: at, InResponseTo: "_query", Assertions: assertions[:63]}
	response, err := protocol.SignQueryResponse(t.Context(), spec, signing)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(xmldsig.Signatures(response)); got != 64 {
		t.Fatalf("response plus 63 assertions signatures=%d, want 64", got)
	}
	query := protocol.Query{ID: "_query", Kind: protocol.AssertionRequest, AssertionIDs: ids[:63]}
	verified, err := protocol.VerifyQueryResponse(t.Context(), response, []crypto.PublicKey{key.Public()}, query, protocol.QueryResponseOptions{Issuer: issuer, ExpectedRequestID: "_query", At: at, Binding: metadata.SOAP})
	if err != nil || verified == nil || len(verified.Assertions()) != 63 {
		t.Fatalf("63 signed assertions failed: result=%v err=%v", verified != nil, err)
	}
	spec.Assertions = assertions
	if response, err = protocol.SignQueryResponse(t.Context(), spec, signing); response != nil || !errors.Is(err, protocol.ErrProfile) {
		t.Fatalf("64 assertions exceed shared signature budget: result=%v err=%v", response != nil, err)
	}
}
