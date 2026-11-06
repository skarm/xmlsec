//go:build interop

package interop_test

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
)

const (
	gsaHTTPTimeout = 10 * time.Second
	gsaHeapFlag    = "-Xmx256m"
)

// The official Google example supplies ACL policy; its released adaptor owns
// the HTTP server, SOAP codec, SAML processing and decision generation. The
// product authenticates responses by HTTPS rather than an XML signature.
func TestGoogleGSAAuthorityHTTP(t *testing.T) {
	selected(t, "authority-http")
	dist := os.Getenv("GSA_DIST")
	if dist == "" {
		t.Fatal("GSA_DIST is required")
	}
	f := newInteropFixture(t)
	jar := filepath.Join(dist, "gsa-adaptor.jar")
	source := filepath.Join(dist, "library-4.1.4/src/com/google/enterprise/adaptor/examples/AdaptorWithCrawlTimeMetadataTemplate.java")
	command(t, f, true, nil, "javac", "-cp", jar, "-d", f.work, source)
	cert, key, p12 := filepath.Join(f.work, "gsa.crt"), filepath.Join(f.work, "gsa.key"), filepath.Join(f.work, "gsa.p12")
	command(t, f, true, nil, "openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", key, "-out", cert)
	command(t, f, true, nil, "openssl", "pkcs12", "-export", "-name", "adaptor", "-inkey", key, "-in", cert, "-out", p12, "-passout", "pass:xmlsec-gsa-only")
	port := authorityFreePort(t)
	origin := "https://127.0.0.1:" + port
	startAuthorityProcess(t, f, "gsa", "java", gsaHeapFlag, "-Djavax.net.ssl.keyStore="+p12, "-Djavax.net.ssl.keyStoreType=PKCS12", "-Djavax.net.ssl.keyStorePassword=xmlsec-gsa-only", "-cp", f.work+string(os.PathListSeparator)+jar, "com.google.enterprise.adaptor.examples.AdaptorWithCrawlTimeMetadataTemplate", "-Dgsa.hostname=127.0.0.1", "-Dgsa.version=7.0.14-114", "-Dserver.hostname=127.0.0.1", "-Dserver.port="+port, "-Dserver.dashboardPort="+authorityFreePort(t), "-Dserver.secure=true", "-Dadaptor.pushDocIdsOnStartup=false", "-Dserver.samlEntityId=https://gsa.test/entity", "-Dgsa.samlEntityId="+shibbolethRequester)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(read(t, cert)) {
		t.Fatal("bad test TLS certificate")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: gsaHTTPTimeout}
	waitAuthorityHTTP(t, client, origin+"/saml-authz", http.StatusMethodNotAllowed)
	recorder := &authorityHTTPRecorder{base: transport, directory: t.ArtifactDir()}
	client.Transport = recorder
	signing := generateKey(t, f.work, nameRSASHA256)

	for _, tc := range []struct{ name, user, resource, decision string }{
		{"permit", "vin", origin + "/doc/7007", "Permit"},
		{"deny", "chico", origin + "/doc/7007", "Deny"},
		{"unknown-document", "vin", origin + "/doc/unknown", "Deny"},
		{"foreign-resource", "vin", "https://foreign.test/doc/7007", "Indeterminate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subject, err := protocol.NewSubject(t.Context(), protocol.NameIdentifier{Value: tc.user, Format: protocol.NameIDUnspecified})
			if err != nil {
				t.Fatal(err)
			}
			q := protocol.Query{MessageHeader: protocol.MessageHeader{ID: "_gsa_" + tc.name, Issuer: shibbolethRequester, IssueInstant: time.Now().UTC()}, Kind: protocol.AuthorizationQuery, Subject: subject, Resource: tc.resource, Actions: []protocol.Action{{Namespace: "urn:oasis:names:tc:SAML:1.0:action:ghpp", Value: "GET"}}}
			// SOAP permits an absent Destination. GSA 4.1.4's decoder cannot
			// determine the receiver URI of its own HttpExchange adapter when
			// Destination is present, so use that standard optional form.
			query, err := protocol.SignQuery(t.Context(), q, protocol.SigningKey{Key: signing.signer})
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := protocol.SignSOAP(t.Context(), query, protocol.SigningKey{Key: signing.signer})
			if err != nil {
				t.Fatal(err)
			}
			response, err := (binding.SOAPClient{Client: client}).RoundTrip(t.Context(), origin+"/saml-authz", envelope)
			if err != nil {
				t.Fatal(err)
			}
			unsigned, err := response.Payload(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			result, err := protocol.VerifyQueryResponse(t.Context(), unsigned, []crypto.PublicKey{signing.signer.Public()}, q, protocol.QueryResponseOptions{ExchangeOptions: protocol.ExchangeOptions{Issuer: "https://gsa.test/entity", ExpectedRequestID: q.ID, At: time.Now().UTC(), Binding: metadata.SOAP}})
			if !errors.Is(err, protocol.ErrSignature) || result != nil {
				t.Fatalf("unsigned GSA response crossed the XML-signature boundary: %v", err)
			}
			// Inspect the response obtained over the verified, explicitly pinned TLS
			// connection. This is wire interoperability, not signed-message acceptance.
			path := filepath.Join(recorder.directory, "authority-response-"+strconv.FormatUint(recorder.sequence.Load(), 10)+".xml")
			message, err := binding.DecodeSOAP(t.Context(), read(t, path), binding.SOAPOptions{})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := message.Payload(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			root := payload.Root()
			id, _ := root.Attribute(document.Name{Local: "InResponseTo"})
			if root.Name() != (document.Name{Space: protocol.ProtocolNamespace, Local: "Response"}) || id != q.ID {
				t.Fatal("uncorrelated independent response")
			}
			issuer := onlyAuthorityChild(t, root, protocol.AssertionNamespace, "Issuer")
			if issuer.Text() != "https://gsa.test/entity" {
				t.Fatal("wrong issuer")
			}
			status := onlyAuthorityChild(t, root, protocol.ProtocolNamespace, "Status")
			code := onlyAuthorityChild(t, status, protocol.ProtocolNamespace, "StatusCode")
			value, _ := code.Attribute(document.Name{Local: "Value"})
			if value != protocol.Success {
				t.Fatal("unexpected SAML status")
			}
			assertion := onlyAuthorityChild(t, root, protocol.AssertionNamespace, "Assertion")
			returnedSubject := onlyAuthorityChild(t, assertion, protocol.AssertionNamespace, "Subject")
			name := onlyAuthorityChild(t, returnedSubject, protocol.AssertionNamespace, "NameID")
			if name.Text() != tc.user {
				t.Fatal("changed query subject")
			}
			decision := onlyAuthorityChild(t, assertion, protocol.AssertionNamespace, "AuthzDecisionStatement")
			value, _ = decision.Attribute(document.Name{Local: "Decision"})
			resource, _ := decision.Attribute(document.Name{Local: "Resource"})
			if value != tc.decision || resource != tc.resource {
				t.Fatalf("unexpected authorization result: %s %s", value, resource)
			}
			action := onlyAuthorityChild(t, decision, protocol.AssertionNamespace, "Action")
			namespace, _ := action.Attribute(document.Name{Local: "Namespace"})
			if action.Text() != "GET" || namespace != q.Actions[0].Namespace {
				t.Fatal("changed query action")
			}
		})
	}
}

func onlyAuthorityChild(t *testing.T, parent document.Element, space, local string) document.Element {
	t.Helper()
	var result document.Element
	count := 0
	for _, child := range parent.Children() {
		if child.Name() == (document.Name{Space: space, Local: local}) {
			result = child
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected one %s, got %d", local, count)
	}
	return result
}
