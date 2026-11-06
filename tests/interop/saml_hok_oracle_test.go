//go:build interop

package interop_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/ecp"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/proof"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/saml/sp"
	"github.com/skarm/xmlsec/saml/state"
)

func TestECPProofJava(t *testing.T) {
	selected(t, "portable")
	f := newInteropFixture(t)
	for _, kind := range []string{nameRSASHA256, nameECDSASHA256} {
		key := generateKey(t, f.work, kind)
		at := time.Now().UTC()
		request := protocol.AuthnRequest{ID: "_java_proof", Issuer: "https://sp.test/entity", Destination: "https://idp.test/sso", ACS: "https://sp.test/acs", IssueInstant: at}
		body, err := protocol.SignAuthnRequest(t.Context(), request, protocol.SigningKey{Key: key.signer})
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := protocol.SignSOAP(t.Context(), body, protocol.SigningKey{Key: key.signer})
		if err != nil {
			t.Fatal(err)
		}
		input := write(t, filepath.Join(f.work, "java-proof-input.xml"), xmlBytes(t, envelope))
		for _, canonical := range canonicalizations() {
			t.Run(kind+"/"+canonical, func(t *testing.T) {
				signing := proof.Signing{Key: key.signer, Certificate: key.cert.Raw, Canonicalization: canonical}
				ours, err := proof.SignEnvelopedXML(t.Context(), envelope, signing)
				if err != nil {
					t.Fatal(err)
				}
				path := write(t, filepath.Join(f.work, "go-standard.xml"), xmlBytes(t, ours))
				verifyJava(t, java(t, f, "CoreOracle", nameVerify, key.public, path, "0"), true)
				compat, err := proof.SignCS01CompatXML(t.Context(), envelope, signing)
				if err != nil {
					t.Fatal(err)
				}
				compatPath := write(t, filepath.Join(f.work, "go-cs01.xml"), xmlBytes(t, compat))
				verifyJava(t, java(t, f, "CoreOracle", nameVerify, key.public, compatPath, "0"), false)
				output := filepath.Join(f.work, "jdk-proof.xml")
				java(t, f, "ECPProofOracle", key.private, key.certificate, input, output, canonical, key.method)
				verifyJava(t, java(t, f, "CoreOracle", nameVerify, key.public, output, "0"), true)
				raw := read(t, output)
				p, err := proof.VerifyEnvelopedXML(t.Context(), raw, proof.Options{})
				if err != nil {
					t.Fatalf("JDK-produced proof: %v", err)
				}
				payload, err := p.Payload(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := protocol.VerifyAuthnRequest(t.Context(), payload, []crypto.PublicKey{key.signer.Public()}, protocol.RequestOptions{Issuer: request.Issuer, Destination: request.Destination, At: at, ACS: []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: request.ACS}}}); err != nil {
					t.Fatalf("nested SAML signature: %v", err)
				}
				if _, err := proof.VerifyCS01CompatXML(t.Context(), raw, proof.Options{}); err == nil {
					t.Fatal("declared transform accepted as CS01 compatibility")
				}
				for name, changed := range map[string][]byte{
					"body":   bytes.Replace(raw, []byte(`ID="_java_proof"`), []byte(`ID="_changed"`), 1),
					"header": bytes.Replace(raw, []byte(`soap:mustUnderstand="1"`), []byte(`soap:mustUnderstand="0"`), 1),
				} {
					if bytes.Equal(raw, changed) {
						t.Fatalf("%s tamper control did not alter input", name)
					}
					if _, err := proof.VerifyEnvelopedXML(t.Context(), changed, proof.Options{}); err == nil {
						t.Fatalf("modified %s accepted in JDK proof", name)
					}
					mutant := write(t, filepath.Join(f.work, "modified-jdk-proof.xml"), changed)
					verifyJava(t, java(t, f, "CoreOracle", nameVerify, key.public, mutant, "0"), false)
				}
			})
		}
	}
}

func openSAMLOracle(t *testing.T, f *interopFixture) func(*testing.T, ...string) []byte {
	t.Helper()
	classpath := os.Getenv("OPENSAML_CLASSPATH")
	if classpath == "" {
		t.Fatal("selected OpenSAML suite requires OPENSAML_CLASSPATH with OpenSAML 5.2.3 and dependencies")
	}
	compileJava(t, f)
	classpath = f.work + string(os.PathListSeparator) + classpath
	command(t, f, true, nil, "javac", "-cp", classpath, "-d", f.work, filepath.Join(f.root, "tests/interop/testdata/OpenSAMLHoKOracle.java"))
	logConfig := write(t, filepath.Join(f.work, "oracle-logback.xml"), []byte(`<configuration><root level="OFF"/></configuration>`))
	return func(t *testing.T, args ...string) []byte {
		t.Helper()
		params := []string{"-Dlogback.configurationFile=" + logConfig, "-cp", classpath, "OpenSAMLHoKOracle"}
		out, _ := command(t, f, true, nil, "java", append(params, args...)...)
		return out
	}
}

func hokOracleKey(t *testing.T, f *interopFixture, name, kind string) testKey {
	t.Helper()
	dir := filepath.Join(f.work, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return generateKey(t, dir, kind)
}

func reissuedCertificate(t *testing.T, f *interopFixture, key testKey) string {
	t.Helper()
	template := *key.cert
	template.SerialNumber = big.NewInt(97)
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, key.signer.Public(), key.signer)
	if err != nil {
		t.Fatal(err)
	}
	return write(t, filepath.Join(f.work, "reissued.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestOpenSAMLHolderOfKey(t *testing.T) {
	selected(t, "opensaml")
	f := newInteropFixture(t)
	oracle := openSAMLOracle(t, f)
	idpKey := hokOracleKey(t, f, "idp", nameRSASHA256)
	client := hokOracleKey(t, f, "presenter", nameECDSASHA256)
	at := time.Now().UTC()
	const recipient, requestID = "https://sp.test/acs", "_opensaml_request"
	spec := protocol.Response{ID: "_response", Issuer: "https://idp.test/entity", Audience: "https://sp.test/entity", Destination: recipient, InResponseTo: requestID, IssueInstant: at, SOAPContext: true, Assertion: protocol.AssertionData{ID: "_assertion", NameID: "alice", NotBefore: at, NotOnOrAfter: at.Add(5 * time.Minute), AuthnInstant: at, AuthnContext: "urn:test:certificate", HolderOfKeyCertificate: client.cert.Raw}}
	d, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: idpKey.signer})
	if err != nil {
		t.Fatal(err)
	}
	soap, err := binding.WrapSOAP(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	path := write(t, filepath.Join(f.work, "go-hok.xml"), xmlBytes(t, soap))
	for _, test := range []struct {
		name, certificate, recipient, request string
		accept                                bool
	}{
		{"matching-certificate", client.certificate, recipient, requestID, true},
		{"other-key", idpKey.certificate, recipient, requestID, false},
		{"same-key-different-certificate", reissuedCertificate(t, f, client), recipient, requestID, false},
		{"wrong-recipient", client.certificate, "https://other.test/acs", requestID, false},
		{"wrong-request", client.certificate, recipient, "_other_request", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := oracle(t, "verify", path, idpKey.public, test.certificate, test.recipient, test.request)
			var result struct {
				Engine                string `json:"engine"`
				Signatures, Confirmed bool
			}
			decode(t, raw, &result)
			if result.Engine != "OpenSAML 5.2.3" || !result.Signatures || result.Confirmed != test.accept {
				t.Fatalf("OpenSAML result: %s", raw)
			}
		})
	}
	t.Run("modified-signed-assertion", func(t *testing.T) {
		raw := read(t, path)
		changed := bytes.Replace(raw, []byte("alice"), []byte("mallory"), 1)
		if bytes.Equal(raw, changed) {
			t.Fatal("tamper control did not alter assertion")
		}
		mutant := write(t, filepath.Join(f.work, "modified-signed-assertion.xml"), changed)
		var result struct{ Signatures, Confirmed bool }
		decode(t, oracle(t, "verify", mutant, idpKey.public, client.certificate, recipient, requestID), &result)
		if result.Signatures || result.Confirmed {
			t.Fatal("OpenSAML accepted modified signed assertion")
		}
	})
}

func TestOpenSAMLChannelBindings(t *testing.T) {
	selected(t, "opensaml")
	f := newInteropFixture(t)
	oracle := openSAMLOracle(t, f)
	signed := protocol.ChannelBinding{Type: ecp.TLSServerEndPoint, Data: bytes.Repeat([]byte{17}, 32)}
	for _, test := range []struct {
		name   string
		peer   protocol.ChannelBinding
		accept bool
	}{
		{"matching", signed, true},
		{"different-data", protocol.ChannelBinding{Type: signed.Type, Data: bytes.Repeat([]byte{18}, 32)}, false},
		{"different-type", protocol.ChannelBinding{Type: "tls-exporter", Data: signed.Data}, false},
		{"missing-peer-data", protocol.ChannelBinding{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var result struct{ Matched bool }
			decode(t, oracle(t, "channels", signed.Type, base64.StdEncoding.EncodeToString(signed.Data), test.peer.Type, base64.StdEncoding.EncodeToString(test.peer.Data)), &result)
			if result.Matched != test.accept {
				t.Fatalf("OpenSAML channel comparison: %+v", result)
			}
			var peer []protocol.ChannelBinding
			if len(test.peer.Data) != 0 {
				peer = []protocol.ChannelBinding{test.peer}
			}
			_, err := ecp.MatchChannelBindings([]protocol.ChannelBinding{signed}, peer)
			if (err == nil) != test.accept {
				t.Fatalf("Go channel comparison: %v", err)
			}
		})
	}
}

func TestOpenSAMLHoKECPReturn(t *testing.T) {
	selected(t, "opensaml")
	f := newInteropFixture(t)
	oracle := openSAMLOracle(t, f)
	idpKey := hokOracleKey(t, f, "idp", nameRSASHA256)
	spKey := hokOracleKey(t, f, "sp", nameECDSASHA256)
	client := hokOracleKey(t, f, "presenter", nameECDSASHA256)
	at := time.Now().UTC()
	const issuer, audience, recipient = "https://idp.test/entity", "https://sp.test/entity", "https://sp.test/acs"
	var aggregate bytes.Buffer
	aggregate.WriteString(`<md:EntitiesDescriptor xmlns:md="` + metadata.Namespace + `">`)
	for _, spec := range []metadata.EntityDescriptor{
		{EntityID: issuer, ValidUntil: at.Add(time.Hour), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: idpKey.cert.Raw}}, Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.HoKSSO, ProtocolBinding: metadata.SOAP, Location: "https://idp.test/sso"}}}}},
		{EntityID: audience, ValidUntil: at.Add(time.Hour), SP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: spKey.cert.Raw}}, Endpoints: map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {{Binding: metadata.HoKSSO, ProtocolBinding: metadata.PAOS, Location: recipient, Indexed: true}}}}},
	} {
		d, err := metadata.Build(t.Context(), spec, at, metadata.Options{})
		if err != nil {
			t.Fatal(err)
		}
		aggregate.Write(xmlBytes(t, d))
	}
	aggregate.WriteString(`</md:EntitiesDescriptor>`)
	partners, err := metadata.ParseTrusted(t.Context(), aggregate.Bytes(), at, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	requests, err := state.NewMemoryStore(state.Config{})
	if err != nil {
		t.Fatal(err)
	}
	replays, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := sp.NewServiceProvider(sp.Config{EntityID: audience, Metadata: partners, Signing: protocol.SigningKey{Key: spKey.signer}, Requests: requests, Replay: replays})
	if err != nil {
		t.Fatal(err)
	}
	for _, alternative := range []bool{false, true} {
		t.Run(map[bool]string{false: "single-keyinfo", true: "alternative-keyinfo"}[alternative], func(t *testing.T) {
			browser := bytes.Repeat([]byte{31}, 32)
			out, err := service.Begin(t.Context(), sp.BeginOptions{IDP: issuer, Binding: metadata.PAOS, HolderOfKey: true, At: at, BrowserBinding: browser})
			if err != nil {
				t.Fatal(err)
			}
			challenge, err := out.PAOS()
			if err != nil {
				t.Fatal(err)
			}
			x, err := ecp.ParseHoKChallenge(t.Context(), xmlBytes(t, challenge), "https://sp.test/resource", client.cert.Raw, nil, binding.SOAPOptions{})
			if err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(f.work, "opensaml-response.xml")
			args := []string{"issue", idpKey.private, idpKey.certificate, client.certificate, output, issuer, audience, recipient, out.RequestID(), at.Format(time.RFC3339Nano)}
			if alternative {
				args = append(args, spKey.certificate)
			}
			oracle(t, args...)
			raw := read(t, output)
			returned, err := x.Finish(t.Context(), raw, binding.SOAPOptions{})
			if err != nil {
				t.Fatalf("OpenSAML ECP headers: %v", err)
			}
			input := write(t, filepath.Join(f.work, "paos-input.xml"), xmlBytes(t, returned))
			proofFile := filepath.Join(f.work, "jdk-paos-proof.xml")
			java(t, f, "ECPProofOracle", client.private, client.certificate, input, proofFile, c14n.Exclusive, client.method)
			p, err := ecp.VerifyEnvelopedXML(t.Context(), read(t, proofFile), proof.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.ConsumeECP(t.Context(), p, sp.ConsumeOptions{At: at, BrowserBinding: bytes.Repeat([]byte{32}, 32)}); err == nil {
				t.Fatal("independent HoK return accepted for another browser")
			}
			wrongProof := filepath.Join(f.work, "wrong-key-paos-proof.xml")
			java(t, f, "ECPProofOracle", idpKey.private, idpKey.certificate, input, wrongProof, c14n.Exclusive, idpKey.method)
			wrong, err := ecp.VerifyEnvelopedXML(t.Context(), read(t, wrongProof), proof.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.ConsumeECP(t.Context(), wrong, sp.ConsumeOptions{At: at, BrowserBinding: browser}); err == nil {
				t.Fatal("independent HoK return accepted proof of another key")
			}
			assertion, err := service.ConsumeECP(t.Context(), p, sp.ConsumeOptions{At: at, BrowserBinding: browser})
			if err != nil || assertion.NameID() != "alice" || !bytes.Equal(assertion.HolderOfKeyCertificate(), client.cert.Raw) {
				t.Fatalf("independently produced HoK return: %v", err)
			}
			if _, err := service.ConsumeECP(t.Context(), p, sp.ConsumeOptions{At: at, BrowserBinding: browser}); err == nil {
				t.Fatal("independent HoK return replay accepted")
			}
		})
	}
}
