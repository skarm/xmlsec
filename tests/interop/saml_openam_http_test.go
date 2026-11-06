//go:build interop

package interop_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/authority"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/xmlenc"
)

const (
	openAMHTTPTimeout               = 15 * time.Second
	authorityReadinessTimeout       = 2 * time.Minute
	authorityReadinessPollInterval  = 200 * time.Millisecond
	authorityProcessWaitDelay       = 20 * time.Second
	authorityProcessLogExcerptBytes = 16_000
	authorityHTTPBodyBytes          = 4 << 20
	openAMSOAPLogExcerptBytes       = 10_000
	openAMInstallLogExcerptBytes    = 12_000
	openAMSSODiagnosticRunes        = 500
	authorityHTTPDiagnosticRunes    = 300
	openAMHeapFlag                  = "-Xmx768m"
)

const (
	openAMEntity  = "https://openam.test/entity"
	mappingTarget = "https://target.test/entity"
)

// Deployment uses the released OpenAM WAR with the documented test-only
// NameIDMappingResponse serialization-order correction. All SOAP parsing, query
// resolution, account federation, mapping and signatures are upstream code.
func TestOpenAMAuthorityHTTP(t *testing.T) {
	selected(t, "authority-http")
	dist, tomcat := os.Getenv("OPENAM_DIST"), os.Getenv("TOMCAT_HOME")
	if dist == "" || tomcat == "" {
		t.Fatal("OPENAM_DIST and TOMCAT_HOME are required")
	}
	f := newInteropFixture(t)
	key := generateKey(t, f.work, nameRSASHA256)
	base, client, cert := installOpenAM(t, f, dist, tomcat, key)
	recorder := &authorityHTTPRecorder{base: client.Transport, directory: t.ArtifactDir()}
	client.Transport = recorder
	t.Cleanup(func() {
		if t.Failed() {
			for n := uint64(1); n <= recorder.sequence.Load(); n++ {
				b, e := os.ReadFile(filepath.Join(recorder.directory, fmt.Sprintf("authority-response-%d.xml", n)))
				if e == nil && strings.Contains(string(b), "Envelope") {
					b = regexp.MustCompile(`(?s)<ds:Signature\b.*?</ds:Signature>`).ReplaceAll(b, []byte("[signature omitted]"))
					if len(b) > openAMSOAPLogExcerptBytes {
						b = b[:openAMSOAPLogExcerptBytes]
					}
					t.Logf("SOAP %d: %s", n, b)
				}
			}
		}
	})
	// Seed through the product's public authentication and WebSSO endpoints.
	signingCert, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	token := openAMLogin(t, client, base)
	source := openAMSSO(t, client, base, token, shibbolethRequester, signingCert.PublicKey)
	at := time.Now().UTC()
	endpoint := func(path string) []metadata.Endpoint {
		return []metadata.Endpoint{{Binding: metadata.SOAP, Location: base + path}}
	}
	role := &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{CertificateDER: cert}}, Endpoints: map[string][]metadata.Endpoint{
		metadata.AuthnQueryService:         endpoint("/AuthnQueryServiceSoap/metaAlias/authn"),
		metadata.AssertionIDRequestService: endpoint("/AIDReqSoap/AuthnAuthRole/metaAlias/authn"),
	}}
	idp := &metadata.RoleDescriptor{Keys: role.Keys, Endpoints: map[string][]metadata.Endpoint{
		"SingleSignOnService":         {{Binding: metadata.HTTPPost, Location: base + "/SSOPOST/metaAlias/idp"}},
		metadata.NameIDMappingService: endpoint("/NIMSoap/metaAlias/idp"),
	}}
	md, err := metadata.Build(t.Context(), metadata.EntityDescriptor{EntityID: openAMEntity, ValidUntil: at.Add(time.Hour), AuthnAuthority: role, IDP: idp}, at, metadata.Options{AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := metadata.ParseTrusted(t.Context(), xmlBytes(t, md), at, metadata.Options{AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	store, _ := replay.NewMemoryStore(replay.Config{})
	c := authority.Client{EntityID: shibbolethRequester, Peer: openAMEntity, Role: metadata.AuthenticationAuthority, Metadata: snapshot, Signing: protocol.SigningKey{Key: key.signer, CertificateDER: key.cert.Raw}, Replay: store, SOAP: binding.SOAPClient{Client: client, AllowHTTP: true}}
	subject, err := protocol.NewSubject(t.Context(), source.name)
	if err != nil {
		t.Fatal(err)
	}
	q := protocol.Query{MessageHeader: protocol.MessageHeader{ID: "_openam_authn"}, Kind: protocol.AuthenticationQuery, Subject: subject, SessionIndex: source.session, Context: &protocol.RequestedContext{Classes: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}}}
	t.Run("AuthnQuery/past-authentication", func(t *testing.T) {
		r, err := c.Query(t.Context(), q, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		requireIssuedAssertion(t, r, source)
	})
	t.Run("AuthnQuery/unknown-session", func(t *testing.T) {
		missing := q
		missing.ID = "_openam_unknown_session"
		missing.SessionIndex = "_not_an_existing_session"
		r, err := c.Query(t.Context(), missing, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if r.Status().Code != protocol.Success || len(r.Assertions()) != 0 {
			t.Fatal("unknown session returned authentication statements")
		}
	})
	t.Run("AssertionIDRequest/issued-assertion", func(t *testing.T) {
		r, err := c.Query(t.Context(), protocol.Query{MessageHeader: protocol.MessageHeader{ID: "_openam_assertion"}, Kind: protocol.AssertionRequest, AssertionIDs: []string{source.id}}, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		requireIssuedAssertion(t, r, source)
	})
	t.Run("AssertionIDRequest/unknown-id", func(t *testing.T) {
		r, err := c.Query(t.Context(), protocol.Query{MessageHeader: protocol.MessageHeader{ID: "_openam_unknown_id"}, Kind: protocol.AssertionRequest, AssertionIDs: []string{"_absent_assertion"}}, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if r.Status().Code != protocol.Success || len(r.Assertions()) != 0 {
			t.Fatal("unknown ID returned an assertion")
		}
	})
	target := openAMSSO(t, client, base, token, mappingTarget, signingCert.PublicKey)
	if source.name.Value == target.name.Value {
		t.Fatal("upstream did not create pairwise identifiers")
	}
	c.Role = metadata.IdentityProvider
	mapping := protocol.NameIDMappingRequest{MessageHeader: protocol.MessageHeader{ID: "_openam_mapping"}, NameID: source.name, Policy: protocol.NameIDPolicy{Format: protocol.NameIDPersistent, SPNameQualifier: mappingTarget}}
	t.Run("NameIDMapping/encrypted-target-identifier", func(t *testing.T) {
		r, err := c.Map(t.Context(), mapping, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if r.Status().Code != protocol.Success || r.Identifier() == nil || r.Identifier().Root().Name().Local != "EncryptedID" {
			t.Fatal("missing encrypted mapped identifier")
		}
		// OpenAM's released Mapping implementation encrypts to the requester. The
		// envelope signature is verified before its explicitly configured CBC policy.
		id, err := r.DecryptNameID(t.Context(), &protocol.DecryptionOptions{Keys: []crypto.Decrypter{key.signer.(crypto.Decrypter)}, Data: xmlenc.Options{DataAlgorithm: xmlenc.AES128CBC, KeyTransportAlgorithm: xmlenc.RSA15, AllowLegacy: true}})
		if err != nil {
			t.Fatal(err)
		}
		if id != target.name {
			t.Fatalf("mapped identifier differs from independently issued target NameID: %+v", id)
		}
	})
	t.Run("NameIDMapping/unsupported-policy", func(t *testing.T) {
		bad := mapping
		bad.ID = "_openam_bad_mapping"
		bad.Policy.Format = protocol.NameIDTransient
		r, err := c.Map(t.Context(), bad, time.Now().UTC())
		// OpenAM incorrectly uses the subordinate InvalidNameIDPolicy as the
		// top-level StatusCode (Core 3.2.2.2). Keep this known peer defect visible
		// and require the strict client to reject it without an identifier.
		if !errors.Is(err, protocol.ErrProfile) || r != nil {
			t.Fatalf("nonconforming peer status accepted: %v", err)
		}
		path := filepath.Join(recorder.directory, fmt.Sprintf("authority-response-%d.xml", recorder.sequence.Load()))
		message, err := binding.DecodeSOAP(t.Context(), read(t, path), binding.SOAPOptions{})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := message.Payload(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		status := onlyAuthorityChild(t, payload.Root(), protocol.ProtocolNamespace, "Status")
		code := onlyAuthorityChild(t, status, protocol.ProtocolNamespace, "StatusCode")
		value, _ := code.Attribute(document.Name{Local: "Value"})
		if value != protocol.InvalidNameIDPolicy {
			t.Fatal("unexpected upstream mapping failure")
		}
		id, _ := payload.Root().Attribute(document.Name{Local: "InResponseTo"})
		if id != bad.ID {
			t.Fatal("uncorrelated upstream failure")
		}
	})
}

type issuedOpenAMAssertion struct {
	id, session string
	name        protocol.NameIdentifier
}

func requireIssuedAssertion(t *testing.T, r *protocol.VerifiedQueryResponse, want issuedOpenAMAssertion) {
	t.Helper()
	if r.Status().Code != protocol.Success || len(r.Assertions()) != 1 || r.Assertions()[0].ID() != want.id {
		t.Fatal("Authority did not return the independently issued assertion")
	}
	statements := r.Assertions()[0].Statements()
	if len(statements) != 1 || statements[0].Name().Local != "AuthnStatement" {
		t.Fatal("missing authentication statement")
	}
	session, _ := statements[0].Attribute(document.Name{Local: "SessionIndex"})
	if session != want.session {
		t.Fatal("Authority changed the original session")
	}
}

func openAMLogin(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/json/authenticate", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Openam-Username", "alice")
	req.Header.Set("X-Openam-Password", "TestPassword123!")
	req.Header.Set(lexicon.HeaderContentType, "application/json")
	body := authorityReadHTTP(t, client, req)
	var result struct {
		Token string `json:"tokenId"`
	}
	if err = json.Unmarshal(body, &result); err != nil || result.Token == "" {
		t.Fatal("OpenAM fixture login failed")
	}
	return result.Token
}

func openAMSSO(t *testing.T, client *http.Client, base, token, sp string, key crypto.PublicKey) issuedOpenAMAssertion {
	t.Helper()
	u := base + "/idpssoinit?metaAlias=/idp&binding=HTTP-POST&spEntityID=" + url.QueryEscape(sp) + "&NameIDFormat=" + url.QueryEscape(protocol.NameIDPersistent)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "iPlanetDirectoryPro", Value: token})
	body := authorityReadHTTP(t, client, req)
	match := regexp.MustCompile(`name="SAMLResponse"\s+value="([^"]+)"`).FindSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("OpenAM did not return a POST response: %.*s", openAMSSODiagnosticRunes, body)
	}
	raw, err := base64.StdEncoding.DecodeString(html.UnescapeString(string(match[1])))
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(t.ArtifactDir(), "sso-"+url.PathEscape(sp)+".xml"), raw)
	d, err := document.Parse(t.Context(), raw, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var result issuedOpenAMAssertion
	for _, a := range d.Root().Children() {
		if a.Name() != (document.Name{Space: protocol.AssertionNamespace, Local: "Assertion"}) {
			continue
		}
		signed, err := tree.ScopeDocument(d, a)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = protocol.VerifyAuthorityAssertion(t.Context(), signed, []crypto.PublicKey{key}, protocol.AssertionOptions{Issuer: openAMEntity, Audience: sp, At: time.Now().UTC()}); err != nil {
			t.Fatalf("upstream WebSSO assertion signature/conditions: %v", err)
		}
		result.id, _ = a.Attribute(document.Name{Local: "ID"})
		for _, e := range a.Children() {
			if e.Name().Local == "AuthnStatement" {
				result.session, _ = e.Attribute(document.Name{Local: "SessionIndex"})
			}
			if e.Name().Local == "Subject" {
				for _, n := range e.Children() {
					if n.Name().Local == "NameID" {
						result.name = protocol.NameIdentifier{Value: n.Text()}
						result.name.Format, _ = n.Attribute(document.Name{Local: "Format"})
						result.name.NameQualifier, _ = n.Attribute(document.Name{Local: "NameQualifier"})
						result.name.SPNameQualifier, _ = n.Attribute(document.Name{Local: "SPNameQualifier"})
					}
				}
			}
		}
	}
	if result.id == "" || result.session == "" || result.name.Format != protocol.NameIDPersistent || result.name.SPNameQualifier != sp {
		t.Fatal("incomplete upstream WebSSO assertion")
	}
	return result
}

func authorityReadHTTP(t *testing.T, client *http.Client, req *http.Request) []byte {
	t.Helper()
	r, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, authorityHTTPBodyBytes))
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusOK {
		t.Fatalf("Authority HTTP %s: %.*s", r.Status, authorityHTTPDiagnosticRunes, b)
	}
	return b
}

func installOpenAM(t *testing.T, f *interopFixture, dist, tomcat string, key testKey) (string, *http.Client, []byte) {
	t.Helper()
	home := filepath.Join(f.work, "openam-config")
	t.Cleanup(func() {
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(home, "install.log"))
			if len(b) > openAMInstallLogExcerptBytes {
				b = b[len(b)-openAMInstallLogExcerptBytes:]
			}
			t.Logf("OpenAM install: %s", b)
		}
	})
	base := filepath.Join(f.work, "tomcat")
	command(t, f, true, nil, "cp", "-R", filepath.Join(tomcat, "conf"), base)
	// cp creates base as the conf directory; move it into the Tomcat layout.
	conf := base + "-conf"
	if err := os.Rename(base, conf); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"logs", "temp", "work", "webapps"} {
		if err := os.MkdirAll(filepath.Join(base, p), fixtureDirectoryMode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(conf, filepath.Join(base, "conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dist, "openam.war"), filepath.Join(base, "webapps/openam.war")); err != nil {
		t.Fatal(err)
	}
	port := authorityFreePort(t)
	serverXML := string(read(t, filepath.Join(base, "conf/server.xml")))
	serverXML = strings.Replace(serverXML, `<Connector port="8080"`, `<Connector address="127.0.0.1" port="`+port+`"`, 1)
	serverXML = strings.Replace(serverXML, `<Server port="8005"`, `<Server port="-1"`, 1)
	write(t, filepath.Join(base, "conf/server.xml"), []byte(serverXML))
	hosts := filepath.Join(f.work, "hosts")
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	write(t, hosts, []byte("127.0.0.1 localhost authority.test "+hostname+"\n"))
	// JVM-only name resolution keeps this test independent of the host's DNS/hosts.
	javaOptions := "-Djdk.net.hosts.file=" + hosts
	args := []string{openAMHeapFlag, "-Dcom.sun.identity.saml.xmlsig.xmlSigAlgorithm=" + more + "rsa-sha256", "-Dcom.sun.identity.saml.xmlsig.digestAlgorithm=" + enc + "sha256", "--add-exports=java.base/sun.security.util=ALL-UNNAMED", "--add-exports=java.security.jgss/sun.security.krb5=ALL-UNNAMED", "--add-exports=java.base/sun.security.x509=ALL-UNNAMED", "--add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED", "--add-exports=java.xml/com.sun.org.apache.xerces.internal.dom=ALL-UNNAMED", "-Dcom.iplanet.services.configpath=" + home, "-Dcom.sun.identity.configuration.directory=" + home, "-Dcatalina.home=" + tomcat, "-Dcatalina.base=" + base, "-Djava.io.tmpdir=" + filepath.Join(base, "temp"), javaOptions, "-cp", filepath.Join(tomcat, "bin/bootstrap.jar") + string(os.PathListSeparator) + filepath.Join(tomcat, "bin/tomcat-juli.jar"), "org.apache.catalina.startup.Bootstrap", "start"}
	stop := startAuthorityProcess(t, f, "openam-setup", "java", args...)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, p, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		if host == "authority.test" {
			host = "127.0.0.1"
		}
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host, p))
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: openAMHTTPTimeout}
	endpoint := "http://authority.test:" + port + "/openam"
	waitAuthorityHTTP(t, client, endpoint+"/", http.StatusOK)
	config := fmt.Sprintf("SERVER_URL=http://authority.test:%s\nDEPLOYMENT_URI=/openam\nBASE_DIR=%s\nlocale=en_US\nPLATFORM_LOCALE=en_US\nAM_ENC_KEY=\nADMIN_PWD=TestPassword123!\nAMLDAPUSERPASSWD=AgentPassword123!\nCOOKIE_DOMAIN=authority.test\nACCEPT_LICENSES=true\nDATA_STORE=embedded\nDIRECTORY_SSL=SIMPLE\nDIRECTORY_SERVER=authority.test\nDIRECTORY_PORT=%s\nDIRECTORY_ADMIN_PORT=%s\nDIRECTORY_JMX_PORT=%s\nROOT_SUFFIX=dc=openam,dc=example,dc=org\nDS_DIRMGRDN=cn=Directory Manager\nDS_DIRMGRPASSWD=TestPassword123!\n", port, home, authorityFreePort(t), authorityFreePort(t), authorityFreePort(t))
	configPath := filepath.Join(f.work, "openam.conf")
	write(t, configPath, []byte(config))
	command(t, f, true, nil, "java", javaOptions, "-jar", filepath.Join(dist, "configurator/openam-configurator-tool-16.1.4.jar"), "--file", configPath)
	admin := filepath.Join(f.work, "admin")
	command(t, f, true, nil, "cp", "-R", filepath.Join(dist, "admin"), admin)
	java, err := exec.LookPath("java")
	if err != nil {
		t.Fatal(err)
	}
	java, err = filepath.EvalSymlinks(java)
	if err != nil {
		t.Fatal(err)
	}
	setup := exec.CommandContext(t.Context(), "bash", "setup", "--acceptLicense", "--path", home, "--debug", filepath.Join(f.work, "admin-debug"), "--log", filepath.Join(f.work, "admin-log"))
	setup.Dir = admin
	setup.Env = append(os.Environ(), "JAVA_HOME="+filepath.Dir(filepath.Dir(java)), "JAVA_TOOL_OPTIONS="+javaOptions)
	if out, err := setup.CombinedOutput(); err != nil {
		t.Fatalf("OpenAM admin setup: %v: %s", err, out)
	}
	pwd := filepath.Join(f.work, "admin.pwd")
	write(t, pwd, []byte("TestPassword123!"))
	if err = os.Chmod(pwd, fixtureReadOnlyFileMode); err != nil {
		t.Fatal(err)
	}
	adm := func(sub string, args ...string) {
		t.Helper()
		all := append([]string{sub, "--adminid", "amadmin", "--password-file", pwd}, args...)
		cmd := exec.CommandContext(t.Context(), "bash", append([]string{filepath.Join(admin, "openam/bin/ssoadm")}, all...)...)
		cmd.Dir = filepath.Join(admin, "openam/bin")
		cmd.Env = append(os.Environ(), "JAVA_TOOL_OPTIONS="+javaOptions)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ssoadm %s: %v: %s", sub, err, out)
		}
	}
	adm("set-attr-defs", "--servicename", "sunFAMFederationCommon", "--schematype", "Global", "--attributevalues", "SignatureAlgorithm="+more+"rsa-sha256", "DigestAlgorithm="+enc+"sha256")
	keystore := filepath.Join(home, "openam/keystore.jceks")
	command(t, f, true, nil, "keytool", "-genkeypair", "-alias", "live", "-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA256withRSA", "-dname", "CN=OpenAM-test", "-validity", "2", "-keystore", keystore, "-storetype", "JCEKS", "-storepass:file", filepath.Join(home, "openam/.storepass"), "-keypass", "changeit")
	idp, ext := filepath.Join(f.work, "idp.xml"), filepath.Join(f.work, "idp-ext.xml")
	adm("create-cot", "--realm", "/", "--cot", "test")
	adm("create-metadata-templ", "--entityid", openAMEntity, "--identityprovider", "/idp", "--authnauthority", "/authn", "--idpscertalias", "live", "--authnascertalias", "live", "--meta-data-file", idp, "--extended-data-file", ext)
	configXML := string(read(t, ext))
	configXML = regexp.MustCompile(`(<Attribute name="assertionNotBeforeTimeSkew">\s*<Value>)[^<]*`).ReplaceAllString(configXML, "${1}0")
	configXML = regexp.MustCompile(`(<Attribute name="assertionEffectiveTime">\s*<Value>)[^<]*`).ReplaceAllString(configXML, "${1}300")
	old := "<Attribute name=\"assertionCacheEnabled\">\n            <Value>false</Value>"
	if !strings.Contains(configXML, old) {
		t.Fatal("upstream assertion cache configuration changed")
	}
	write(t, ext, []byte(strings.Replace(configXML, old, strings.Replace(old, "false", "true", 1), 1)))
	adm("import-entity", "--realm", "/", "--cot", "test", "--meta-data-file", idp, "--extended-data-file", ext)
	for i, entity := range []string{shibbolethRequester, mappingTarget} {
		md, err := metadata.Build(t.Context(), metadata.EntityDescriptor{EntityID: entity, ValidUntil: time.Now().Add(time.Hour), SP: &metadata.RoleDescriptor{WantAssertionsSigned: true, Keys: []metadata.KeyDescriptor{{CertificateDER: key.cert.Raw}}, Endpoints: map[string][]metadata.Endpoint{"AssertionConsumerService": {{Binding: metadata.HTTPPost, Location: entity + "/acs", Index: 0, Default: true}}}}}, time.Now(), metadata.Options{})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(f.work, fmt.Sprintf("sp-%d.xml", i))
		write(t, path, xmlBytes(t, md))
		adm("import-entity", "--realm", "/", "--cot", "test", "--meta-data-file", path)
	}
	adm("create-identity", "--realm", "/", "--idname", "alice", "--idtype", "User", "--attributevalues", "userpassword=TestPassword123!", "cn=Alice", "sn=Test", "inetuserstatus=Active")
	certFile := filepath.Join(f.work, "openam-signing.pem")
	command(t, f, true, nil, "keytool", "-exportcert", "-rfc", "-alias", "live", "-keystore", keystore, "-storetype", "JCEKS", "-storepass:file", filepath.Join(home, "openam/.storepass"), "-file", certFile)
	block, _ := pem.Decode(read(t, certFile))
	if block == nil {
		t.Fatal("missing OpenAM signing certificate")
	}
	stop()
	startAuthorityProcess(t, f, "openam", "java", args...)
	waitAuthorityHTTP(t, client, endpoint+"/isAlive.jsp", http.StatusOK)
	return endpoint, client, block.Bytes
}

func authorityFreePort(t *testing.T) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func startAuthorityProcess(t *testing.T, f *interopFixture, label, program string, args ...string) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	logPath := filepath.Join(t.ArtifactDir(), label+".log")
	log, err := os.Create(logPath)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Dir = f.work
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = authorityProcessWaitDelay
	if err = cmd.Start(); err != nil {
		cancel()
		_ = log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stop := func() {
		if !stopped {
			cancel()
			<-done
			_ = log.Close()
			stopped = true
		}
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			if len(b) > authorityProcessLogExcerptBytes {
				b = b[len(b)-authorityProcessLogExcerptBytes:]
			}
			t.Logf("%s: %s", label, b)
		}
	})
	return stop
}

func waitAuthorityHTTP(t *testing.T, client *http.Client, endpoint string, status int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), authorityReadinessTimeout)
	defer cancel()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		r, err := client.Do(req)
		if err == nil {
			_ = r.Body.Close()
			if r.StatusCode == status {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("Authority did not become ready at %s: %v", endpoint, errors.Join(ctx.Err(), err))
		case <-time.After(authorityReadinessPollInterval):
		}
	}
}
