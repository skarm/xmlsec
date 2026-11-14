package protocol_test

import (
	"crypto"
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/protocol"
)

func TestVerifyStatusResponseRetainsArtifactMessage(t *testing.T) {
	t.Parallel()

	at := testcert.Now()
	key := testcert.Key(t)
	payload := queryXML(t, `<samlp:LogoutRequest xmlns:samlp="`+protocol.ProtocolNamespace+`" ID="_embedded"/>`)
	status := protocol.Status{Code: protocol.Success, Subcodes: []string{protocol.PartialLogout}, Message: "partial logout"}
	d, err := protocol.SignStatusResponse(t.Context(), protocol.StatusResponse{
		ID: "_artifact", Issuer: idp, Destination: acs, IssueInstant: at, Kind: protocol.ArtifactResponse,
		InResponseTo: "_resolution", Status: status, Message: payload,
	}, protocol.SigningKey{Key: key})
	if err != nil {
		t.Fatalf("SignStatusResponse: %v", err)
	}

	o := protocol.ExchangeOptions{Issuer: idp, Destination: acs, At: at, ExpectedRequestID: "_resolution"}
	keys := []crypto.PublicKey{key.Public()}
	got, err := protocol.VerifyStatusResponse(t.Context(), d, keys, o)
	if err != nil || got == nil {
		t.Fatalf("VerifyStatusResponse = %v, %v, want authenticated response", got, err)
	}

	if h := got.Header(); h.ID != "_artifact" || h.Issuer != idp || h.Destination != acs || !h.IssueInstant.Equal(at) {
		t.Errorf("Header = %+v, want the artifact response header", h)
	}
	if got.Kind() != protocol.ArtifactResponse || got.InResponseTo() != "_resolution" {
		t.Errorf("Kind/InResponseTo = %q/%q, want ArtifactResponse/_resolution", got.Kind(), got.InResponseTo())
	}
	if s := got.Status(); s.Code != status.Code || s.Message != status.Message || !slices.Equal(s.Subcodes, status.Subcodes) {
		t.Errorf("Status = %+v, want %+v", s, status)
	}

	message := got.Message()
	if message == nil || message.Root().Name() != payload.Root().Name() {
		t.Fatalf("Message = %v, want scoped %v", message, payload.Root().Name())
	}
	if id, ok := message.Root().Attribute(document.Name{Local: "ID"}); !ok || id != "_embedded" {
		t.Errorf("Message ID = %q, present %t, want _embedded", id, ok)
	}

	o.ExpectedRequestID = "_another_resolution"
	if got, err := protocol.VerifyStatusResponse(t.Context(), d, keys, o); got != nil || !errors.Is(err, protocol.ErrCorrelation) {
		t.Errorf("VerifyStatusResponse with a different pending request = %v, %v, want nil and %v", got, err, protocol.ErrCorrelation)
	}
}

func TestSignStatusResponseRejectsIncompatiblePayload(t *testing.T) {
	t.Parallel()

	key := protocol.SigningKey{Key: testcert.Key(t)}
	at := testcert.Now()
	payload := queryXML(t, `<samlp:LogoutRequest xmlns:samlp="`+protocol.ProtocolNamespace+`" ID="_embedded"/>`)
	foreign := queryXML(t, `<example:Payload xmlns:example="urn:test:payload"/>`)
	for _, tc := range []struct {
		name, kind, status string
		message            *document.Document
	}{
		{"ordinary_status_response_with_payload", protocol.LogoutResponse, protocol.Success, payload},
		{"failed_artifact_response_with_payload", protocol.ArtifactResponse, protocol.Responder, payload},
		{"artifact_payload_in_wrong_namespace", protocol.ArtifactResponse, protocol.Success, foreign},
		{"successful_web_response_requires_assertion", "Response", protocol.Success, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := protocol.SignStatusResponse(t.Context(), protocol.StatusResponse{
				ID: "_response", Issuer: idp, Destination: acs, IssueInstant: at, Kind: tc.kind,
				InResponseTo: "_request", Status: protocol.Status{Code: tc.status}, Message: tc.message,
			}, key)
			if got != nil || !errors.Is(err, protocol.ErrProfile) {
				t.Errorf("SignStatusResponse = %v, %v, want nil and %v", got, err, protocol.ErrProfile)
			}
		})
	}
}
