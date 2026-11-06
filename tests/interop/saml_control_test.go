//go:build interop

package interop_test

import (
	"bytes"
	"crypto"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/protocol"
)

// Native xmlsec1 verifies our control signatures and independently recomputes
// signatures in the full SOAP namespace context, including Inclusive C14N.
func TestXMLSecSAMLControlSOAP(t *testing.T) {
	f := newInteropFixture(t)
	selected(t, "xmlsec")
	signer := generateKey(t, f.work, nameRSASHA256)
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	header := protocol.MessageHeader{ID: "_request", Issuer: "https://idp.test/entity", Destination: "https://sp.test/soap", IssueInstant: at}
	name := protocol.NameIdentifier{Value: "managed-primary", Format: protocol.NameIDPersistent, NameQualifier: header.Issuer, SPNameQualifier: "https://sp.test/entity", SPProvidedID: "managed-alias"}
	for _, algorithm := range []string{c14n.Exclusive, c14n.Canonical10} {
		key := protocol.SigningKey{Key: signer.signer, Canonicalization: algorithm}
		logout, err := protocol.SignLogoutRequest(t.Context(), protocol.LogoutRequest{MessageHeader: header, NameID: name, SessionIndexes: []string{"session-1", "session-2"}, NotOnOrAfter: at.Add(time.Minute)}, key)
		if err != nil {
			t.Fatal(err)
		}
		manage, err := protocol.SignManageNameIDRequest(t.Context(), protocol.ManageNameIDRequest{MessageHeader: header, NameID: name, NewID: "new-primary"}, key)
		if err != nil {
			t.Fatal(err)
		}
		resolve, err := protocol.SignArtifactResolve(t.Context(), protocol.ArtifactResolve{MessageHeader: header, Artifact: "AAQAADE x"}, key)
		if err != nil {
			t.Fatal(err)
		}
		response, err := protocol.SignStatusResponse(t.Context(), protocol.StatusResponse{MessageHeader: header, Kind: protocol.LogoutResponse, InResponseTo: "_request", Status: protocol.Status{Code: protocol.Success, Subcodes: []string{protocol.PartialLogout}}}, key)
		if err != nil {
			t.Fatal(err)
		}
		for i, message := range []*document.Document{logout, manage, resolve, response} {
			t.Run(fmt.Sprintf("%s/%d", algorithm, i), func(t *testing.T) {
				envelope, err := protocol.SignSOAP(t.Context(), message, key)
				if err != nil {
					t.Fatal(err)
				}
				kind := message.Root().Name().Local
				path := write(t, filepath.Join(f.work, "control-go.xml"), xmlBytes(t, envelope))
				selection := "(//*[local-name()='" + kind + "']/*[local-name()='Signature'])[1]"
				native(t, f, true, nameVerify, flagPublicKeyPEM, signer.public, flagIDAttrID, kind, "--node-xpath", selection, path)
				nativePath := filepath.Join(f.work, "control-native.xml")
				native(t, f, true, nameSign, "--privkey-pem", signer.private, flagIDAttrID, kind, "--node-xpath", selection, flagNativeOutput, nativePath, path)
				soap, err := binding.DecodeSOAP(t.Context(), read(t, nativePath), binding.SOAPOptions{})
				if err != nil {
					t.Fatal(err)
				}
				d, err := soap.Payload(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				verify := func(d *document.Document) {
					opts := protocol.ExchangeOptions{Issuer: header.Issuer, Destination: header.Destination, At: at, ExpectedRequestID: "_request", Binding: "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"}
					keys := []crypto.PublicKey{signer.signer.Public()}
					switch kind {
					case "LogoutRequest":
						_, err = protocol.VerifyLogoutRequest(t.Context(), d, keys, opts)
					case "ManageNameIDRequest":
						_, err = protocol.VerifyManageNameIDRequest(t.Context(), d, keys, opts)
					case "ArtifactResolve":
						_, err = protocol.VerifyArtifactResolve(t.Context(), d, keys, opts)
					case protocol.LogoutResponse:
						_, err = protocol.VerifyStatusResponse(t.Context(), d, keys, opts)
					default:
						t.Fatal("unexpected message")
					}
					if err != nil {
						t.Fatalf("native signature: %v", err)
					}
				}
				verify(d)
				if algorithm == c14n.Canonical10 {
					wire := bytes.ReplaceAll(read(t, nativePath), []byte("env:"), []byte("S:"))
					wire = bytes.ReplaceAll(wire, []byte("xmlns:env="), []byte("xmlns:S="))
					wire = bytes.Replace(wire, []byte("<S:Envelope"), []byte(`<S:Envelope xml:lang="ru" xml:space="preserve"`), 1)
					contextPath := write(t, filepath.Join(f.work, "control-context-template.xml"), wire)
					native(t, f, true, nameSign, "--privkey-pem", signer.private, flagIDAttrID, kind, "--node-xpath", selection, flagNativeOutput, nativePath, contextPath)
					soap, err = binding.DecodeSOAP(t.Context(), read(t, nativePath), binding.SOAPOptions{})
					if err != nil {
						t.Fatal(err)
					}
					scoped, err := soap.Payload(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					verify(scoped)
					forwarded, err := binding.WrapSOAP(t.Context(), scoped)
					if err != nil {
						t.Fatal(err)
					}
					forwardedPath := write(t, filepath.Join(f.work, "control-context-forwarded.xml"), xmlBytes(t, forwarded))
					native(t, f, true, nameVerify, flagPublicKeyPEM, signer.public, flagIDAttrID, kind, "--node-xpath", selection, forwardedPath)
				}
			})
		}
	}
}
