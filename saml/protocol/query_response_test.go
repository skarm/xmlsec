package protocol_test

import (
	"crypto"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
)

func TestVerifyAuthorityAssertionRetainsConditionsAndSnapshot(t *testing.T) {
	t.Parallel()

	q := queryRequest(t, protocol.AuthenticationQuery)
	at := testcert.Now()
	end := at.Add(time.Minute)
	statement := queryStatement(t, q.Kind)
	conditions := queryXML(t, `<saml:Conditions xmlns:saml="`+protocol.AssertionNamespace+`" NotOnOrAfter="`+end.Format(time.RFC3339)+`"><saml:OneTimeUse/></saml:Conditions>`)
	key := testcert.Key(t)
	d, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{
		ID: "_authority", Issuer: idp, IssueInstant: at, Subject: q.Subject,
		Conditions: conditions, Statements: []*document.Document{statement},
	}, protocol.SigningKey{Key: key})
	if err != nil {
		t.Fatalf("SignAuthorityAssertion: %v", err)
	}

	o := protocol.AssertionOptions{Issuer: idp, At: at, Audience: sp}
	keys := []crypto.PublicKey{key.Public()}
	got, err := protocol.VerifyAuthorityAssertion(t.Context(), d, keys, o)
	if err != nil || got == nil {
		t.Fatalf("VerifyAuthorityAssertion = %v, %v, want an assertion", got, err)
	}
	if got.ID() != "_authority" || got.Issuer() != idp || !got.OneTimeUse() || !got.NotOnOrAfter().Equal(end) || got.Document() != d {
		t.Errorf("authority assertion = id %q, issuer %q, one-time %t, expiry %v, original snapshot %t", got.ID(), got.Issuer(), got.OneTimeUse(), got.NotOnOrAfter(), got.Document() == d)
	}
	subject := got.Subject()
	if want := (document.Name{Space: protocol.AssertionNamespace, Local: "Subject"}); subject.Name() != want {
		t.Errorf("Subject.Name = %v, want %v", subject.Name(), want)
	}
	statements := got.Statements()
	if len(statements) != 1 || statements[0].Name() != statement.Root().Name() {
		t.Fatalf("verified statements = %v, want one %v", statements, statement.Root().Name())
	}
	statements[0] = document.Element{}
	if !got.Statements()[0].Valid() {
		t.Error("Statements exposes the verified assertion's slice")
	}

	o.At = end
	if expired, err := protocol.VerifyAuthorityAssertion(t.Context(), d, keys, o); expired != nil || !errors.Is(err, protocol.ErrConditions) {
		t.Errorf("VerifyAuthorityAssertion at expiry = %v, %v, want nil and %v", expired, err, protocol.ErrConditions)
	}
}

func TestVerifyAuthorityAssertionValidatesProxyCount(t *testing.T) {
	t.Parallel()

	key := testcert.Key(t)
	at := testcert.Now()
	opts := protocol.AssertionOptions{Issuer: idp, Audience: sp, At: at}
	keys := []crypto.PublicKey{key.Public()}
	for _, tc := range []struct {
		name, count string
		wantErr     error
	}{
		{"explicit_plus_and_xml_whitespace", " +12 ", nil},
		{"negative_zero", "-000", nil},
		{"negative_one", "-001", protocol.ErrConditions},
		{"sign_without_digits", "+", protocol.ErrConditions},
		{"exact_lexical_limit", strings.Repeat("9", 4096), nil},
		{"above_lexical_limit", strings.Repeat("9", 4097), protocol.ErrConditions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{
				ID: "_authority", Issuer: idp, IssueInstant: at,
				Conditions: queryXML(t, `<saml:Conditions xmlns:saml="`+protocol.AssertionNamespace+`"><saml:ProxyRestriction Count="`+tc.count+`"/></saml:Conditions>`),
			}, protocol.SigningKey{Key: key})
			if err != nil {
				t.Fatalf("SignAuthorityAssertion: %v", err)
			}
			got, err := protocol.VerifyAuthorityAssertion(t.Context(), d, keys, opts)
			if !errors.Is(err, tc.wantErr) || (got == nil) != (tc.wantErr != nil) {
				t.Fatalf("VerifyAuthorityAssertion = assertion present %t, %v, want %v", got != nil, err, tc.wantErr)
			}
			if got != nil && (got.ID() != "_authority" || got.OneTimeUse() || !got.NotOnOrAfter().IsZero()) {
				t.Errorf("verified authority = id %q, one-time %t, expiry %v", got.ID(), got.OneTimeUse(), got.NotOnOrAfter())
			}
		})
	}
}

func TestVerifyQueryResponseRetainsAuthenticatedFailure(t *testing.T) {
	t.Parallel()

	at := testcert.Now()
	key := testcert.Key(t)
	q := queryRequest(t, protocol.AttributeQuery)
	want := protocol.Status{Code: protocol.Requester, Subcodes: []string{protocol.UnsupportedBinding}, Message: "binding unavailable"}
	d, err := protocol.SignQueryResponse(t.Context(), protocol.QueryResponse{
		ID: "_result", Issuer: idp, IssueInstant: at, InResponseTo: q.ID, Status: want,
	}, protocol.SigningKey{Key: key})
	if err != nil {
		t.Fatalf("SignQueryResponse: %v", err)
	}
	o := protocol.QueryResponseOptions{Issuer: idp, ExpectedRequestID: q.ID, At: at, Binding: metadata.SOAP}
	got, err := protocol.VerifyQueryResponse(t.Context(), d, []crypto.PublicKey{key.Public()}, q, o)
	if err != nil || got == nil {
		t.Fatalf("VerifyQueryResponse = %v, %v, want authenticated failure status", got, err)
	}
	if h := got.Header(); h.ID != "_result" || h.Issuer != idp || !h.IssueInstant.Equal(at) || h.Destination != "" {
		t.Errorf("Header = %+v, want the signed result header", h)
	}
	status := got.Status()
	if status.Code != want.Code || status.Message != want.Message || !slices.Equal(status.Subcodes, want.Subcodes) || len(got.Assertions()) != 0 {
		t.Fatalf("authenticated failure = status %+v, %d assertions, want %+v and no assertions", status, len(got.Assertions()), want)
	}
	status.Subcodes[0] = "urn:test:changed"
	if got.Status().Subcodes[0] != protocol.UnsupportedBinding {
		t.Error("Status exposes the authenticated response's subcode slice")
	}
}
