//go:build interop

package interop_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/authority"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/xmlenc"
)

const (
	shibbolethHTTPTimeout         = 10 * time.Second
	shibbolethProcessWaitDelay    = 5 * time.Second
	shibbolethStartupTimeout      = 90 * time.Second
	shibbolethStartupPollInterval = 250 * time.Millisecond
	shibbolethLogExcerptBytes     = 18_000
	shibbolethStatusBytes         = 65_536
	shibbolethStatusLogRunes      = 200
	authorityRecordedBodyBytes    = 3 << 20
	shibbolethHeapFlag            = "-Xmx768m"
)

const (
	shibbolethEntity    = "https://authority.test/entity"
	shibbolethRequester = "https://requester.test/entity"
)

// This runs the released, unmodified IdP WAR in Jetty. Request decoding, peer
// authentication, resolution, filtering, encryption and signing are all upstream
// Shibboleth code, with only deployment configuration supplied by this test.
func TestShibbolethAuthorityHTTP(t *testing.T) {
	selected(t, "shibboleth")
	dist, jetty := os.Getenv("SHIBBOLETH_DIST"), os.Getenv("JETTY_HOME")
	if dist == "" || jetty == "" {
		t.Fatal("SHIBBOLETH_DIST and JETTY_HOME are required for the selected deployed Authority test")
	}
	f := newInteropFixture(t)
	key := generateKey(t, f.work, nameRSASHA256)
	home := installShibboleth(t, f, dist, key)
	endpoint, httpClient := startShibboleth(t, f, home, jetty)
	recorder := &authorityHTTPRecorder{base: httpClient.Transport, directory: t.ArtifactDir()}
	httpClient.Transport = recorder
	block, _ := pem.Decode(read(t, filepath.Join(home, "credentials/idp-signing.crt")))
	if block == nil {
		t.Fatal("missing upstream signing certificate")
	}
	at := time.Now().UTC()
	md, err := metadata.Build(t.Context(), metadata.EntityDescriptor{EntityID: shibbolethEntity, ValidUntil: at.Add(time.Hour), AttributeAuthority: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{CertificateDER: block.Bytes}}, Endpoints: map[string][]metadata.Endpoint{metadata.AttributeService: {{Binding: metadata.SOAP, Location: endpoint}}}}}, at, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := metadata.ParseTrusted(t.Context(), xmlBytes(t, md), at, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	store, _ := replay.NewMemoryStore(replay.Config{})
	c := authority.Client{EntityID: shibbolethRequester, Peer: shibbolethEntity, Role: metadata.AttributeAuthority, Metadata: snapshot, Signing: protocol.SigningKey{Key: key.signer, CertificateDER: key.cert.Raw}, Replay: store, SOAP: binding.SOAPClient{Client: httpClient}, Options: protocol.QueryResponseOptions{ExchangeOptions: protocol.ExchangeOptions{Decryption: &protocol.DecryptionOptions{Keys: []crypto.Decrypter{key.signer.(crypto.Decrypter)}, Data: xmlenc.Options{DataAlgorithm: xmlenc.AES128GCM}}}}}
	subject, err := protocol.NewSubject(t.Context(), protocol.NameIdentifier{Value: "alice", Format: protocol.NameIDUnspecified})
	if err != nil {
		t.Fatal(err)
	}
	filter, err := document.Parse(t.Context(), []byte(`<saml:Attribute xmlns:saml="`+protocol.AssertionNamespace+`" Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	q := protocol.Query{MessageHeader: protocol.MessageHeader{ID: "_live_query"}, Kind: protocol.AttributeQuery, Subject: subject, Attributes: []*document.Document{filter}}
	t.Run("signed-encrypted-attribute-query", func(t *testing.T) {
		r, err := c.Query(t.Context(), q, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if r.Status().Code != protocol.Success || len(r.Assertions()) != 1 {
			t.Fatalf("independent Authority status: %+v, assertions=%d", r.Status(), len(r.Assertions()))
		}
		message, err := binding.DecodeSOAP(t.Context(), read(t, filepath.Join(recorder.directory, "authority-response-1.xml")), binding.SOAPOptions{})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := message.Payload(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		signed, encrypted := false, false
		for _, child := range payload.Root().Children() {
			signed = signed || child.Name() == (document.Name{Space: ds, Local: "Signature"})
			encrypted = encrypted || child.Name() == (document.Name{Space: protocol.AssertionNamespace, Local: "EncryptedAssertion"})
		}
		if !signed || !encrypted {
			t.Fatal("wire response lacks signed envelope or encrypted assertion")
		}
		statements := r.Assertions()[0].Statements()
		if len(statements) != 1 || len(statements[0].Children()) != 1 || statements[0].Children()[0].Children()[0].Text() != "alice@example.org" {
			t.Fatal("incorrect independent resolution or query filter")
		}
	})
	t.Run("replay-rejected-by-authority", func(t *testing.T) {
		fresh := c
		fresh.Replay, _ = replay.NewMemoryStore(replay.Config{})
		r, err := fresh.Query(t.Context(), q, time.Now().UTC())
		checkAuthorityDenial(t, recorder, q.ID, r, err)
	})
	t.Run("untrusted-signing-key", func(t *testing.T) {
		other := generateKey(t, t.TempDir(), nameRSASHA256)
		bad := c
		bad.Signing = protocol.SigningKey{Key: other.signer}
		query := q
		query.ID = "_untrusted_query"
		r, err := bad.Query(t.Context(), query, time.Now().UTC())
		checkAuthorityDenial(t, recorder, query.ID, r, err)
	})
}

func checkAuthorityDenial(t *testing.T, recorder *authorityHTTPRecorder, requestID string, result *protocol.VerifiedQueryResponse, err error) {
	t.Helper()
	// The early Shibboleth security failures have no outbound signing parameters.
	// Their wire status is authenticated by the verified TLS connection. The Go
	// message-signature profile must continue to reject an unsigned envelope.
	if err != nil && (!errors.Is(err, protocol.ErrSignature) || result != nil) {
		t.Fatalf("unexpected client failure: %v", err)
	}
	if err == nil && (result.Status().Code != protocol.Requester || len(result.Assertions()) != 0) {
		t.Fatal("client accepted a rejected Authority request")
	}
	path := filepath.Join(recorder.directory, fmt.Sprintf("authority-response-%d.xml", recorder.sequence.Load()))
	message, decodeErr := binding.DecodeSOAP(t.Context(), read(t, path), binding.SOAPOptions{})
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	payload, decodeErr := message.Payload(t.Context())
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if payload.Root().Name() != (document.Name{Space: protocol.ProtocolNamespace, Local: "Response"}) {
		t.Fatal("unexpected rejection message type")
	}
	id, _ := payload.Root().Attribute(document.Name{Local: "InResponseTo"})
	if id != requestID {
		t.Fatal("uncorrelated wire rejection")
	}
	found, issuer := false, false
	for _, child := range payload.Root().Children() {
		issuer = issuer || child.Name() == (document.Name{Space: protocol.AssertionNamespace, Local: "Issuer"}) && child.Text() == shibbolethEntity
		if child.Name() == (document.Name{Space: protocol.ProtocolNamespace, Local: "Status"}) {
			codes := child.Children()
			if len(codes) > 0 {
				code, _ := codes[0].Attribute(document.Name{Local: "Value"})
				inner := codes[0].Children()
				if code == protocol.Requester && len(inner) == 1 {
					subcode, _ := inner[0].Attribute(document.Name{Local: "Value"})
					found = subcode == "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
				}
			}
		}
		if child.Name().Space == protocol.AssertionNamespace && child.Name().Local != "Issuer" {
			t.Fatal("failure response disclosed an assertion")
		}
	}
	if !found || !issuer {
		t.Fatal("Authority did not report Requester/RequestDenied over authenticated HTTPS")
	}
}

type authorityHTTPRecorder struct {
	base      http.RoundTripper
	directory string
	sequence  atomic.Uint64
}

func (r *authorityHTTPRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := r.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, authorityRecordedBodyBytes))
	closeErr := response.Body.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err = os.WriteFile(filepath.Join(r.directory, fmt.Sprintf("authority-response-%d.xml", r.sequence.Add(1))), raw, fixtureFileMode); err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(raw))
	return response, nil
}

func installShibboleth(t *testing.T, f *interopFixture, dist string, key testKey) string {
	t.Helper()
	home := filepath.Join(f.work, "idp")
	props := write(t, filepath.Join(f.work, "install.properties"), []byte("idp.scope=example.test\n"))
	out, stderr := command(t, f, true, nil, "bash", filepath.Join(dist, "bin/install.sh"), "--noPrompt", "--propertyFile", props, "--targetDir", home, "--hostName", "localhost", "--entityID", shibbolethEntity, "--keystorePassword", "xmlsec-interop-only", "--sealerPassword", "xmlsec-interop-only")
	if !strings.Contains(string(out)+string(stderr), "Version: 5.2.3") {
		t.Fatal("Shibboleth 5.2.3 installer version was not observed")
	}
	md, err := metadata.Build(t.Context(), metadata.EntityDescriptor{EntityID: shibbolethRequester, ValidUntil: time.Now().UTC().Add(time.Hour), SP: &metadata.RoleDescriptor{WantAssertionsSigned: true, Keys: []metadata.KeyDescriptor{{CertificateDER: key.cert.Raw}}, Endpoints: map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {{Binding: metadata.HTTPPost, Location: "https://requester.test/acs", Index: 0}}}}}, time.Now().UTC(), metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(home, "metadata/requester.xml"), xmlBytes(t, md))
	conf := filepath.Join(home, "conf")
	write(t, filepath.Join(conf, "metadata-providers.xml"), []byte(`<MetadataProvider xmlns="urn:mace:shibboleth:2.0:metadata" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:mace:shibboleth:2.0:metadata http://shibboleth.net/schema/idp/shibboleth-metadata.xsd" id="LocalRequester" xsi:type="FilesystemMetadataProvider" metadataFile="%{idp.home}/metadata/requester.xml"/>`))
	beans := `<beans xmlns="http://www.springframework.org/schema/beans" xmlns:p="http://www.springframework.org/schema/p" xmlns:util="http://www.springframework.org/schema/util" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/util http://www.springframework.org/schema/util/spring-util.xsd" default-init-method="initialize">`
	write(t, filepath.Join(conf, "relying-party.xml"), []byte(beans+`<bean id="InteropEncryption" parent="shibboleth.EncryptionConfiguration.GCM"><property name="keyTransportEncryptionAlgorithms"><list><value>http://www.w3.org/2009/xmlenc11#rsa-oaep</value></list></property><property name="RSAOAEPParameters"><bean class="org.opensaml.xmlsec.encryption.support.RSAOAEPParameters"><constructor-arg value="http://www.w3.org/2001/04/xmlenc#sha256"/><constructor-arg value="http://www.w3.org/2009/xmlenc11#mgf1sha256"/><constructor-arg><null/></constructor-arg></bean></property></bean><bean id="InteropSecurity" parent="shibboleth.DefaultSecurityConfiguration" p:encryptionConfiguration-ref="InteropEncryption"/><bean id="shibboleth.UnverifiedRelyingParty" parent="RelyingParty"/><bean id="shibboleth.DefaultRelyingParty" parent="RelyingParty"><property name="profileConfigurations"><list><bean parent="SAML2.AttributeQuery" p:securityConfiguration-ref="InteropSecurity" p:signResponses="true" p:signAssertions="true" p:encryptAssertions="true"/></list></property></bean><util:list id="shibboleth.RelyingPartyOverrides"/></beans>`))
	path := filepath.Join(conf, "c14n/subject-c14n.xml")
	text := string(read(t, path))
	old := `<!-- <value>https://sp.example.org</value> -->`
	if strings.Count(text, old) != 1 {
		t.Fatal("upstream NameID consumption configuration changed")
	}
	write(t, path, []byte(strings.Replace(text, old, "<value>"+shibbolethRequester+"</value>", 1)))
	write(t, filepath.Join(conf, "attribute-filter.xml"), []byte(`<AttributeFilterPolicyGroup xmlns="urn:mace:shibboleth:2.0:afp" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:mace:shibboleth:2.0:afp http://shibboleth.net/schema/idp/shibboleth-afp.xsd" id="TestRelease"><AttributeFilterPolicy id="RequesterOnly"><PolicyRequirementRule xsi:type="Requester" value="`+shibbolethRequester+`"/><AttributeRule attributeID="mail" permitAny="true"/><AttributeRule attributeID="uid" permitAny="true"/></AttributeFilterPolicy></AttributeFilterPolicyGroup>`))
	return home
}

func startShibboleth(t *testing.T, f *interopFixture, home, jetty string) (string, *http.Client) {
	t.Helper()
	base := filepath.Join(f.work, "jetty-base")
	if err := os.MkdirAll(base, fixtureDirectoryMode); err != nil {
		t.Fatal(err)
	}
	command(t, f, true, nil, "java", "-Djetty.base="+base, "-jar", filepath.Join(jetty, "start.jar"), "--add-modules=ee9-deploy,ee9-annotations,ee9-jstl,ssl,https", "--approve-all-licenses")
	cert, key, keystore := filepath.Join(base, "tls.crt"), filepath.Join(base, "tls.key"), filepath.Join(base, "tls.p12")
	command(t, f, true, nil, "openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", key, "-out", cert)
	command(t, f, true, nil, "openssl", "pkcs12", "-export", "-inkey", key, "-in", cert, "-out", keystore, "-passout", "pass:xmlsec-interop-only")
	write(t, filepath.Join(base, "webapps/idp.xml"), []byte(`<!DOCTYPE Configure PUBLIC "-//Jetty//Configure//EN" "https://jetty.org/configure_10_0.dtd"><Configure class="org.eclipse.jetty.ee9.webapp.WebAppContext"><Set name="war">`+home+`/war/idp.war</Set><Set name="contextPath">/idp</Set><Set name="extractWAR">false</Set><Set name="copyWebInf">true</Set></Configure>`))
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_, port, _ := net.SplitHostPort(address)
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(read(t, cert)) {
		t.Fatal("invalid local TLS certificate")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: shibbolethHTTPTimeout}
	ctx, cancel := context.WithCancel(t.Context())
	logPath := filepath.Join(t.ArtifactDir(), "shibboleth.log")
	log, err := os.Create(logPath)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "java", shibbolethHeapFlag, "-Didp.home="+home, "-Djetty.base="+base, "-jar", filepath.Join(jetty, "start.jar"), "jetty.ssl.host=127.0.0.1", "jetty.ssl.port="+port, "jetty.sslContext.keyStorePath="+keystore, "jetty.sslContext.keyStorePassword=xmlsec-interop-only", "jetty.sslContext.keyManagerPassword=xmlsec-interop-only")
	cmd.Stdout, cmd.Stderr = log, log
	cmd.WaitDelay = shibbolethProcessWaitDelay
	if err = cmd.Start(); err != nil {
		cancel()
		_ = log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = log.Close()
		if t.Failed() {
			for _, path := range []string{logPath, filepath.Join(home, "logs/idp-process.log")} {
				text, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				if len(text) > shibbolethLogExcerptBytes {
					text = text[len(text)-shibbolethLogExcerptBytes:]
				}
				t.Log(string(text))
			}
		}
	})
	deadline := time.NewTimer(shibbolethStartupTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(shibbolethStartupPollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-deadline.C:
			t.Fatal("Shibboleth startup timed out")
		case err := <-done:
			done <- err
			t.Fatalf("Shibboleth exited during startup: %v", err)
		case <-tick.C:
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/idp/status", nil)
			response, err := client.Do(request)
			if err != nil {
				continue
			}
			raw, err := io.ReadAll(io.LimitReader(response.Body, shibbolethStatusBytes))
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK && len(raw) > 0 {
				t.Logf("startup probe HTTP %d: %.*s", response.StatusCode, shibbolethStatusLogRunes, raw)
			}
			if err == nil && response.StatusCode == http.StatusOK {
				if !strings.Contains(string(raw), "5.2.3") {
					t.Fatalf("unexpected deployed IdP version: %s", raw)
				}
				t.Log("deployed Shibboleth Identity Provider 5.2.3 over HTTPS")
				return "https://" + address + "/idp/profile/SAML2/SOAP/AttributeQuery", client
			}
		}
	}
}
