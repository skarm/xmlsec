package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xades"
)

const testRequestID = "_request"

func TestPKICMSAndProtectedIdentityCommands(t *testing.T) {
	f := evidenceSetup(t)

	report := cli(t, nil, "pki", nameVerify, "-certificate", f.cert, "-trust", f.trust, "-at", f.at)
	if !bytes.Contains(report, []byte(`"chain": "valid"`)) {
		t.Fatal(string(report))
	}

	rejectCLI(t, nil, "pki", nameVerify, "-certificate", f.cert, "-trust", f.trust, "-at", testcert.Now().Add(48*time.Hour).Format(time.RFC3339))
	request := cli(t, nil, "pki", "ocsp-request", "-certificate", f.cert, "-issuer", f.root)

	parsed, err := pki.ParseOCSPRequest(request)
	if err != nil || len(parsed.Nonce()) != 32 {
		t.Fatal(err)
	}

	nonce := testutil.WriteFile(t, f.dir, "nonce", parsed.Nonce())
	spec := pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: testcert.Now(), ThisUpdate: testcert.Now().Add(-time.Minute), NextUpdate: testcert.Now().Add(time.Hour)}
	config := testutil.WriteJSON(t, f.dir, "ocsp.json", spec)
	response := cli(t, request, "pki", "ocsp-issue", "-certificate", f.cert, "-issuer", f.root, "-responder", f.responderCert, flagKey, f.responderKey, "-config", config)
	cli(t, response, "pki", "ocsp-verify", "-certificate", f.cert, "-issuer", f.root, "-nonce-file", nonce, "-at", f.at)
	wrongNonce := testutil.WriteFile(t, f.dir, "wrong-nonce", []byte("wrong"))
	rejectCLI(t, response, "pki", "ocsp-verify", "-certificate", f.cert, "-issuer", f.root, "-nonce-file", wrongNonce, "-at", f.at)

	data := []byte("authenticated CMS content\x00\xff")

	for _, detached := range []bool{false, true} {
		args := []string{nameCMS, nameSign, flagKey, f.key, "-certificate", f.cert}
		if detached {
			args = append(args, "-detached")
		}

		signed := cli(t, data, args...)
		cli(t, signed, nameCMS, nameInspect)

		verify := []string{nameCMS, nameVerify, "-expect-certificate", f.cert, "-trust", f.trust, "-at", f.at}
		if detached {
			content := testutil.WriteFile(t, f.dir, "content", data)
			verify = append(verify, "-content", content)
		}

		extract := filepath.Join(f.dir, "extracted")
		verify = append(verify, "-extract", extract)
		cli(t, signed, verify...)

		restored, err := os.ReadFile(extract)
		if err != nil || !bytes.Equal(restored, data) {
			t.Fatal("CMS extraction changed bytes", err)
		}

		failure := rejectCLI(t, signed, nameCMS, nameVerify, "-expect-certificate", f.tsaCert)
		if !bytes.Contains(failure, []byte(`"status": "invalid"`)) {
			t.Fatal(string(failure))
		}
	}

	signers := testutil.WriteJSON(t, f.dir, "signers.json", []cmsSignerFile{{Key: "leaf.key", Certificate: "leaf.der"}, {Key: "tsa.key", Certificate: "tsa.der"}})
	signed := cli(t, data, nameCMS, nameSign, "-signers", signers)
	cli(t, signed, nameCMS, nameVerify, "-expect-certificate", f.cert, "-expect-certificate", f.tsaCert)
	password := testutil.WriteFile(t, f.dir, "password", []byte("password\n"))
	identity := cli(t, nil, "key", "convert", "-in", f.key, "-output-format", namePKCS12, "-certificate", f.cert, "-extra-certificate", f.root, "-output-password-file", password, "-iterations", "1000")
	identityFile := testutil.WriteFile(t, f.dir, "identity.p12", identity)
	cli(t, nil, "key", nameInspect, "-in", identityFile, "-kind", namePKCS12, "-password-file", password)
	cli(t, nil, "key", namePublic, "-in", identityFile, "-key-format", namePKCS12, "-password-file", password)
}

func TestTimestampAndXAdESLifecycle(t *testing.T) {
	f := evidenceSetup(t)
	issue := func(request []byte, serial string) []byte {
		return cli(t, request, "timestamp", nameIssue, flagKey, f.tsaKey, "-certificate", f.tsaCert, "-at", f.at, "-serial", serial, "-tsa-policy", "1.2.3.4")
	}
	data := []byte("time-stamped bytes")
	request := cli(t, data, "timestamp", nameRequest, "-tsa-policy", "1.2.3.4")
	requestFile := testutil.WriteFile(t, f.dir, "request.tsq", request)
	cli(t, request, "timestamp", nameInspect, "-kind", nameRequest)
	response := issue(request, "1")
	cli(t, response, "timestamp", nameInspect)

	tokenPath := filepath.Join(f.dir, "token.der")
	cli(t, response, "timestamp", nameVerify, "-request", requestFile, "-trust", f.tsaTrust, "-at", f.at, "-token-out", tokenPath)

	token, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}

	dataFile := testutil.WriteFile(t, f.dir, "data", data)
	cli(t, token, "timestamp", nameVerify, "-kind", nameToken, "-data", dataFile, "-trust", f.tsaTrust, "-at", f.at, "-tsa-policy", "1.2.3.4")
	wrong := testutil.WriteFile(t, f.dir, "wrong", []byte("wrong"))
	rejectCLI(t, token, "timestamp", nameVerify, "-kind", nameToken, "-data", wrong, "-trust", f.tsaTrust, "-at", f.at)

	source := []byte(`<invoice ID="invoice"><amount>123</amount></invoice>`)
	signed := cli(t, source, "xades", nameSign, flagKey, f.key, "-certificate", f.cert, "-at", f.at)
	cli(t, signed, "xades", nameVerify, "-certificate", f.cert, "-at", f.at)

	var trust trustConfig

	raw, err := os.ReadFile(f.trust)
	if err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(raw, &trust); err != nil {
		t.Fatal(err)
	}

	cfg := xadesConfig{SignerTrust: trust, TSAConfig: "tsa-trust.json", Level: xades.LevelBB}
	validator := testutil.WriteJSON(t, f.dir, "xades.json", cfg)
	cli(t, signed, "xades", "validate", "-certificate", f.cert, "-trust", validator, "-at", f.at)
	req := cli(t, signed, "xades", nameTimestampRequest, "-certificate", f.cert, "-tsa-trust", f.tsaTrust, "-at", f.at)
	resp := issue(req, "2")

	parsed, err := timestamp.ParseResponse(t.Context(), resp)
	if err != nil {
		t.Fatal(err)
	}

	signatureToken := testutil.WriteFile(t, f.dir, "signature-token.der", parsed.TokenDER())
	timed := cli(t, signed, "xades", "timestamp", "-certificate", f.cert, "-tsa-trust", f.tsaTrust, "-at", f.at, "-token", signatureToken)
	cfg.Level = xades.LevelBT
	validator = testutil.WriteJSON(t, f.dir, "xades.json", cfg)
	cli(t, timed, "xades", "validate", "-certificate", f.cert, "-trust", validator, "-at", f.at)
	cli(t, timed, "xades", "validate", "-certificate", f.cert, "-trust", validator, "-at", f.at, "-validation-profile", "with-time")

	cfg.Level = xades.LevelLT
	validator = testutil.WriteJSON(t, f.dir, "xades.json", cfg)
	material := cli(t, timed, "xades", "material", "-certificate", f.cert, "-trust", validator, "-at", f.at)
	cli(t, material, "xades", "validate", "-certificate", f.cert, "-trust", validator, "-at", f.at)
	archiveReq := cli(t, material, "xades", "archive-request", "-certificate", f.cert, "-trust", validator, "-at", f.at)
	archiveResp := issue(archiveReq, "3")

	archiveParsed, err := timestamp.ParseResponse(t.Context(), archiveResp)
	if err != nil {
		t.Fatal(err)
	}

	archiveToken := testutil.WriteFile(t, f.dir, "archive-token.der", archiveParsed.TokenDER())
	archived := cli(t, material, "xades", "archive", "-certificate", f.cert, "-trust", validator, "-at", f.at, "-token", archiveToken)
	cfg.Level = xades.LevelLTA
	validator = testutil.WriteJSON(t, f.dir, "xades.json", cfg)

	report := cli(t, archived, "xades", "validate", "-certificate", f.cert, "-trust", validator, "-at", f.at)
	if !bytes.Contains(report, []byte(`"level": "B-LTA"`)) {
		t.Fatal(string(report))
	}

	rejectCLI(t, timed, "xades", "validate", "-certificate", f.cert, "-trust", validator, "-at", f.at)
}

func TestSAMLCommands(t *testing.T) {
	f := evidenceSetup(t)

	const (
		issuer = "https://sp.example.test/metadata"
		idp    = "https://idp.example.test/metadata"
		sso    = "https://idp.example.test/sso"
		acs    = "https://sp.example.test/acs"
		authn  = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	)

	req := protocol.AuthnRequest{ID: testRequestID, Issuer: issuer, Destination: sso, ACS: acs, IssueInstant: testcert.Now()}
	requestConfig := testutil.WriteJSON(t, f.dir, "request.json", req)
	unsigned := cli(t, nil, "saml", "request-build", "-config", requestConfig)
	form := cli(t, unsigned, "saml", namePostEncode, "-relay-state", "")

	decoded := cli(t, form, "saml", "post-decode")
	if !bytes.Contains(decoded, []byte(`"status": "unverified"`)) || !bytes.Contains(decoded, []byte(`"relay_state_present": true`)) {
		t.Fatal(string(decoded))
	}

	query := cli(t, unsigned, "saml", nameRedirectSign, flagKey, f.key, "-relay-state", "hello")
	cli(t, query, "saml", nameRedirectVerify, flagKey, f.public)
	rejectCLI(t, bytes.Replace(query, []byte("hello"), []byte("wrong"), 1), "saml", nameRedirectVerify, flagKey, f.public)
	signed := cli(t, nil, "saml", "request-build", "-config", requestConfig, flagKey, f.key, "-certificate", f.cert)
	expectation := protocol.RequestOptions{Issuer: issuer, Destination: sso, ACS: []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: acs, Indexed: true, Index: 0, Default: true, DefaultSet: true}}, At: testcert.Now()}
	expectedRequest := testutil.WriteJSON(t, f.dir, "expect-request.json", expectation)
	cli(t, signed, "saml", "request-verify", "-config", expectedRequest, "-trust-key", f.public)
	cli(t, query, "saml", nameRedirectRequestVerify, "-config", expectedRequest, "-trust-key", f.public)

	spec := protocol.Response{ID: "_response", Issuer: idp, Audience: issuer, Destination: acs, InResponseTo: testRequestID, IssueInstant: testcert.Now(), Assertion: protocol.AssertionData{ID: "_assertion", NameID: "alice", NameIDFormat: protocol.NameIDPersistent, NotBefore: testcert.Now().Add(-time.Minute), NotOnOrAfter: testcert.Now().Add(4 * time.Minute), AuthnInstant: testcert.Now().Add(-time.Minute), AuthnContext: authn, Attributes: []protocol.Attribute{{Name: "role", Values: []string{"reader"}}}}}
	responseConfig := testutil.WriteJSON(t, f.dir, "response.json", spec)
	response := cli(t, nil, "saml", "response-build", "-config", responseConfig, flagKey, f.key, "-certificate", f.cert)
	responseOptions := protocol.ResponseOptions{Issuer: idp, Audience: issuer, Destination: acs, ExpectedRequestID: testRequestID, At: testcert.Now(), AllowedNameIDFormats: []string{protocol.NameIDPersistent}, ExpectedAuthnContexts: []string{authn}}
	expectedResponse := testutil.WriteJSON(t, f.dir, "expect-response.json", responseOptions)

	report := cli(t, response, "saml", "response-verify", "-config", expectedResponse, "-trust-key", f.public)
	if !bytes.Contains(report, []byte(`"name_id": "alice"`)) || !bytes.Contains(report, []byte(`"replay_checked": false`)) {
		t.Fatal(string(report))
	}

	responseOptions.Audience = "urn:wrong"
	wrong := testutil.WriteJSON(t, f.dir, "wrong-response.json", responseOptions)
	rejectCLI(t, response, "saml", "response-verify", "-config", wrong, "-trust-key", f.public)
	md := metadata.EntityDescriptor{EntityID: idp, ValidUntil: testcert.Now().Add(time.Hour), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: f.chain.Leaf.Raw}}, Endpoints: map[string][]metadata.Endpoint{"SingleSignOnService": {{Binding: metadata.HTTPRedirect, Location: sso}}}}}
	mdConfig := testutil.WriteJSON(t, f.dir, "metadata.json", md)
	xml := cli(t, nil, "saml", nameMetadataBuild, "-config", mdConfig, "-at", f.at, flagKey, f.key, "-certificate", f.cert)
	cli(t, xml, "saml", "metadata-verify", "-trust-key", f.public, "-at", f.at)
	unsignedMD := cli(t, nil, "saml", nameMetadataBuild, "-config", mdConfig, "-at", f.at)
	cli(t, unsignedMD, "saml", "metadata-verify", "-document-sha256", fingerprint(unsignedMD), "-at", f.at)
	rejectCLI(t, unsignedMD, "saml", "metadata-verify", "-document-sha256", strings.Repeat("0", 64), "-at", f.at)
}

func TestProtocolJSONDoesNotOverrideSignaturePolicy(t *testing.T) {
	for _, command := range []string{"request-verify", "response-verify"} {
		for _, tc := range []struct {
			name, policy string
			reject       bool
		}{
			{"empty policy", `{}`, false},
			{"null policy", `null`, false},
			{"empty algorithm list", `{"AllowedSignatureMethods":[]}`, true},
			{"empty digest list", `{"AllowedDigestMethods":[]}`, true},
			{"key limit", `{"MinRSABits":2048}`, true},
			{"algorithm flag", `{"AllowHMACTruncation":true}`, true},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				config := testutil.WriteFile(t, t.TempDir(), "protocol.json", []byte(`{"Policy":`+tc.policy+`}`))
				err := runSAML(t.Context(), []string{command, "-config", config}, strings.NewReader(""), io.Discard, io.Discard)

				rejected := err != nil && strings.Contains(err.Error(), "signature policy in protocol JSON must be omitted")
				if rejected != tc.reject {
					t.Fatalf("policy rejection = %t, want %t: %v", rejected, tc.reject, err)
				}
			})
		}
	}
}

type evidenceFixture struct {
	chain                                                                                                testcert.Chain
	dir, key, cert, root, tsaKey, tsaCert, responderKey, responderCert, public, trust, tsaTrust, crl, at string
}

func evidenceSetup(t *testing.T) evidenceFixture {
	t.Helper()
	c := testcert.New(t)
	dir := t.TempDir()
	f := evidenceFixture{chain: c, dir: dir, at: testcert.Now().Format(time.RFC3339)}
	f.key = testutil.WritePrivateKey(t, dir, "leaf.key", c.LeafKey)
	f.cert = testutil.WriteFile(t, dir, "leaf.der", c.Leaf.Raw)
	f.root = testutil.WriteFile(t, dir, "root.der", c.Root.Raw)
	f.tsaCert = testutil.WriteFile(t, dir, "tsa.der", c.TSA.Raw)
	f.tsaKey = testutil.WritePrivateKey(t, dir, "tsa.key", c.TSAKey)
	f.responderCert = testutil.WriteFile(t, dir, "responder.der", c.Responder.Raw)
	f.responderKey = testutil.WritePrivateKey(t, dir, "responder.key", c.ResponderKey)
	f.public = testutil.WritePublicKey(t, dir, "leaf.pub", c.LeafKey.Public())
	f.crl = testutil.WriteFile(t, dir, "root.crl", testcert.CRL(t, c))
	trust := trustConfig{Roots: []string{"root.der"}, Usages: []string{"codeSigning"}, Revocation: pki.RequireCRL, Evidence: evidenceFiles{CRLs: []string{"root.crl"}}}
	f.trust = testutil.WriteJSON(t, dir, "trust.json", trust)
	trust.Usages = nil
	f.tsaTrust = testutil.WriteJSON(t, dir, "tsa-trust.json", tsaConfig{Trust: trust, Policies: []string{"1.2.3.4"}, Certificates: []string{"tsa.der"}})

	return f
}
