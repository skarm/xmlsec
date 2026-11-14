package protocol_test

import (
	"crypto"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/protocol"
)

func TestVerifyResponseRetainsAuthenticatedSessionAndIdentifier(t *testing.T) {
	t.Parallel()

	at := testcert.Now()
	sessionEnd := at.Add(2 * time.Minute)
	spec := responseSpec()
	spec.Assertion.NameQualifier = idp
	spec.Assertion.SPNameQualifier = sp
	spec.Assertion.SPProvidedID = "local-alias"
	spec.Assertion.SessionNotOnOrAfter = sessionEnd

	chain := testcert.New(t)
	d, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw})
	if err != nil {
		t.Fatalf("SignResponse: %v", err)
	}

	got, err := protocol.VerifyResponse(t.Context(), d, []crypto.PublicKey{chain.LeafKey.Public()}, options())
	if err != nil || got == nil {
		t.Fatalf("VerifyResponse = %v, %v, want an assertion", got, err)
	}
	if got.ResponseID() != spec.ID || got.Issuer() != idp || got.Audience() != sp || got.Recipient() != acs || got.NameIDFormat() != protocol.NameIDPersistent || got.SessionIndex() != "session-1" || got.AuthnContext() != password {
		t.Errorf("authenticated response = id %q, issuer %q, audience %q, recipient %q, format %q, session %q, context %q", got.ResponseID(), got.Issuer(), got.Audience(), got.Recipient(), got.NameIDFormat(), got.SessionIndex(), got.AuthnContext())
	}
	wantID := protocol.NameIdentifier{Value: "alice", Format: protocol.NameIDPersistent, NameQualifier: idp, SPNameQualifier: sp, SPProvidedID: "local-alias"}
	if gotID := got.Identifier(); gotID != wantID {
		t.Errorf("Identifier = %+v, want %+v", gotID, wantID)
	}
	if !got.IssueInstant().Equal(at) || !got.AuthnInstant().Equal(at.Add(-time.Minute)) || !got.SessionNotOnOrAfter().Equal(sessionEnd) || !got.NotOnOrAfter().Equal(sessionEnd) {
		t.Errorf("issue/authentication/session expiry/assertion expiry = %v/%v/%v/%v, want %v/%v/%v/%v", got.IssueInstant(), got.AuthnInstant(), got.SessionNotOnOrAfter(), got.NotOnOrAfter(), at, at.Add(-time.Minute), sessionEnd, sessionEnd)
	}
}

func TestVerifyResponseEnforcesAddressAndExclusiveSessionExpiry(t *testing.T) {
	t.Parallel()

	at := testcert.Now()
	spec := responseSpec()
	spec.Assertion.SessionNotOnOrAfter = at.Add(time.Minute)
	chain := testcert.New(t)
	d, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw})
	if err != nil {
		t.Fatalf("SignResponse: %v", err)
	}
	d = resign(t, d, chain, func(root *tree.Node) {
		set(find(root, "SubjectConfirmationData"), "Address", "2001:db8::1")
	})
	keys := []crypto.PublicKey{chain.LeafKey.Public()}

	for _, tc := range []struct {
		name, expectedAddress string
		offset                time.Duration
		wantErr               error
	}{
		{"equivalent_ipv6", "2001:0db8:0:0:0:0:0:1", time.Minute - time.Nanosecond, nil},
		{"different_ipv6", "2001:db8::2", 0, protocol.ErrConditions},
		{"exclusive_session_expiry", "2001:db8::1", time.Minute, protocol.ErrConditions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			o := options()
			o.At, o.ExpectedAddress = at.Add(tc.offset), tc.expectedAddress
			got, err := protocol.VerifyResponse(t.Context(), d, keys, o)
			if !errors.Is(err, tc.wantErr) || (got == nil) != (tc.wantErr != nil) {
				t.Fatalf("VerifyResponse at %v for %q = assertion present %t, %v, want %v", o.At, o.ExpectedAddress, got != nil, err, tc.wantErr)
			}
			if got != nil && (!got.NotOnOrAfter().Equal(spec.Assertion.SessionNotOnOrAfter) || got.NameID() != "alice") {
				t.Errorf("verified NameID/expiry = %q/%v, want alice/%v", got.NameID(), got.NotOnOrAfter(), spec.Assertion.SessionNotOnOrAfter)
			}
		})
	}
}

func TestVerifyResponseEnforcesAssertionMetadataProfile(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	d, err := protocol.SignResponse(t.Context(), responseSpec(), protocol.SigningKey{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw})
	if err != nil {
		t.Fatalf("SignResponse: %v", err)
	}
	keys := []crypto.PublicKey{chain.LeafKey.Public()}
	for _, tc := range []struct {
		name, element, attribute, value string
		wantErr                         error
	}{
		{"future_assertion", "Assertion", "IssueInstant", profile.Time(testcert.Now().Add(time.Nanosecond)), protocol.ErrConditions},
		{"unsupported_version", "Assertion", "Version", "1.1", protocol.ErrProfile},
		{"future_authentication", "AuthnStatement", "AuthnInstant", profile.Time(testcert.Now().Add(time.Nanosecond)), protocol.ErrConditions},
		{"overlong_session_index", "AuthnStatement", "SessionIndex", strings.Repeat("s", 1025), protocol.ErrProfile},
		{"wrong_service_provider_qualifier", "NameID", "SPNameQualifier", "https://other.example.test", protocol.ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fixture := resign(t, d, chain, func(root *tree.Node) { set(find(root, tc.element), tc.attribute, tc.value) })
			got, err := protocol.VerifyResponse(t.Context(), fixture, keys, options())
			if got != nil || !errors.Is(err, tc.wantErr) {
				t.Errorf("VerifyResponse = assertion present %t, %v, want no assertion and %v", got != nil, err, tc.wantErr)
			}
		})
	}
}

func TestAcceptanceWindowReturnsNormalizedLimits(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                string
		limits              protocol.Limits
		age, lifetime, skew time.Duration
		wantErr             error
	}{
		{"defaults", protocol.Limits{}, 5 * time.Minute, 10 * time.Minute, 0, nil},
		{"explicit", protocol.Limits{MaxMessageAge: time.Hour, MaxAssertionLifetime: time.Hour, ClockSkew: 5 * time.Minute}, time.Hour, time.Hour, 5 * time.Minute, nil},
		{"excessive_skew", protocol.Limits{ClockSkew: 5*time.Minute + time.Nanosecond}, 0, 0, 0, protocol.ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			age, lifetime, skew, err := protocol.AcceptanceWindow(tc.limits)
			if age != tc.age || lifetime != tc.lifetime || skew != tc.skew || !errors.Is(err, tc.wantErr) {
				t.Errorf("AcceptanceWindow = (%v, %v, %v, %v), want (%v, %v, %v, %v)", age, lifetime, skew, err, tc.age, tc.lifetime, tc.skew, tc.wantErr)
			}
			if err := protocol.ValidatePolicy(tc.limits); !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidatePolicy = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
