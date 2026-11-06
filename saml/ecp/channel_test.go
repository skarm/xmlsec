package ecp_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/ecp"
	"github.com/skarm/xmlsec/saml/protocol"
)

func TestServerCertificateBinding(t *testing.T) {
	certs := testcert.New(t)
	for _, algorithm := range []x509.SignatureAlgorithm{x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512} {
		t.Run(algorithm.String(), func(t *testing.T) {
			template := *certs.Leaf
			template.SignatureAlgorithm = algorithm
			certificate := testcert.Issue(t, &template, certs.Root, certs.LeafKey.Public(), certs.RootKey)
			var expected []byte
			switch algorithm {
			case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256:
				hash := sha256.Sum256(certificate.Raw)
				expected = hash[:]
			case x509.ECDSAWithSHA384:
				hash := sha512.Sum384(certificate.Raw)
				expected = hash[:]
			case x509.ECDSAWithSHA512:
				hash := sha512.Sum512(certificate.Raw)
				expected = hash[:]
			default:
				t.Fatal("unhandled test signature algorithm")
			}
			got, err := ecp.ServerCertificateBinding(certificate)
			if err != nil {
				t.Fatal(err)
			} else if got.Type != "tls-server-end-point" || !bytes.Equal(got.Data, expected) {
				t.Fatalf("RFC 5929 4.1 certificate hash: %x %v", got.Data, err)
			}
			// A mutable parsed field cannot change the algorithm associated with
			// the exact certificate bytes presented by the TLS server.
			certificate.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
			got, err = ecp.ServerCertificateBinding(certificate)
			if err != nil || !bytes.Equal(got.Data, expected) {
				t.Fatal("caller changed hashing by altering parsed certificate metadata")
			}
		})
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(9), NotBefore: certs.Leaf.NotBefore, NotAfter: certs.Leaf.NotAfter}
	cert := testcert.Issue(t, template, template, public, private)
	if _, err := ecp.ServerCertificateBinding(cert); err == nil {
		t.Fatal("guessed an undefined RFC 5929 hash for an Ed25519 certificate")
	}
}

func TestECPChannelHeadersAndComparison(t *testing.T) {
	h := http.Header{}
	ecp.AdvertiseChannelBindings(h)
	if !ecp.Negotiated(h) || !ecp.NegotiatedChannelBindings(h) {
		t.Fatal("comma-delimited PAOS channel binding option was not negotiated")
	}
	ecp.Advertise(h)
	if ecp.NegotiatedChannelBindings(h) {
		t.Fatal("legacy negotiation implied channel binding support")
	}
	// Independently written XML exercises arbitrary prefixes and XML Schema
	// base64Binary whitespace, rather than relying on our own header generator.
	wire := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header><x:ChannelBindings xmlns:x="urn:oasis:names:tc:SAML:protocol:ext:channel-binding" s:actor="http://schemas.xmlsoap.org/soap/actor/next" s:mustUnderstand="1" Type="tls-server-end-point"> A Q I D &#x9; BA== </x:ChannelBindings></s:Header><s:Body><p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/></s:Body></s:Envelope>`
	m, err := binding.DecodeSOAP(t.Context(), []byte(wire), binding.SOAPOptions{Understood: []document.Name{{Space: protocol.ChannelBindingNamespace, Local: "ChannelBindings"}}})
	if err != nil {
		t.Fatal(err)
	}
	values, err := ecp.ReadChannelHeaders(m.Headers(), false)
	if err != nil || len(values) != 1 || !bytes.Equal(values[0].Data, []byte{1, 2, 3, 4}) {
		t.Fatalf("independent channel header: %v %v", values, err)
	}
	matched, err := ecp.MatchChannelBindings([]protocol.ChannelBinding{{Type: ecp.TLSServerEndPoint, Data: []byte{1, 2, 3, 4}}}, values)
	if err != nil || len(matched) != 1 {
		t.Fatalf("binary channel comparison: %v", err)
	}
	values[0].Data[0] = 7
	if matched[0].Data[0] != 1 {
		t.Fatal("verified channel bytes alias the received input")
	}
	if _, err := ecp.MatchChannelBindings(matched, values); err == nil {
		t.Fatal("mismatched channel accepted")
	}
	if _, err := ecp.MatchChannelBindings(matched, nil); err == nil {
		t.Fatal("signed channel without client channel accepted")
	}
	if _, err := ecp.MatchChannelBindings(nil, matched); err == nil {
		t.Fatal("client channel without signed SP channel accepted")
	}
	bad := protocol.CloneChannelBindings(matched)
	bad[0].Type = "tls-unique"
	if _, err := ecp.MatchChannelBindings(matched, bad); err == nil {
		t.Fatal("different named channel types matched")
	}
	if err := protocol.ValidateChannelBindings(append(matched, matched...), false); err == nil {
		t.Fatal("duplicate channel types accepted")
	}
	if base64.StdEncoding.EncodeToString(matched[0].Data) != "AQIDBA==" {
		t.Fatal("channel bytes changed during comparison")
	}
}

func TestTLSExporterChannelBinding(t *testing.T) {
	serverChannel := make(chan protocol.ChannelBinding, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := ecp.TLSExporterBinding(r.TLS)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		serverChannel <- got
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 9266 4.1: do not reuse a channel after the authentication instance.
	request.Close = true
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent || response.TLS.Version != tls.VersionTLS13 {
		t.Fatal("expected a completed TLS 1.3 exchange")
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	client, err := ecp.TLSExporterBinding(response.TLS)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-serverChannel
	expected, err := response.TLS.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
	if err != nil || client.Type != "tls-exporter" || !bytes.Equal(client.Data, expected) || !bytes.Equal(client.Data, peer.Data) {
		t.Fatalf("RFC 9266 exporter inputs or peer equality: %v", err)
	}
	if _, err := ecp.TLSExporterBinding(&tls.ConnectionState{Version: tls.VersionTLS12, HandshakeComplete: true}); err == nil {
		t.Fatal("legacy TLS accepted without EMS/renegotiation guarantees")
	}
}
