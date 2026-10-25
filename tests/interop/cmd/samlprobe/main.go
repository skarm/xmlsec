// Command samlprobe is a private interoperability test adapter.
// Test-only local-file interoperability helper. Not an HTTP endpoint or CLI API.

package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmldsig"
)

func main() {
	mode := flag.String("mode", "", "mode")
	in := flag.String("in", "", "input")
	out := flag.String("out", "", "output")
	certPath := flag.String("cert", "", "DER cert")
	keyPath := flag.String("key", "", "PKCS8 PEM")
	atString := flag.String("at", "", "explicit UTC instant")

	flag.Parse()
	at, e := time.Parse(time.RFC3339Nano, *atString)
	must(e)
	cert, e := x509.ParseCertificate(read(*certPath))
	must(e)

	var key crypto.Signer

	if *keyPath != "" {
		p, _ := pem.Decode(read(*keyPath))
		if p == nil {
			must(errors.New("key"))
		}

		k, e := x509.ParsePKCS8PrivateKey(p.Bytes)
		must(e)

		var ok bool

		key, ok = k.(crypto.Signer)
		if !ok {
			must(errors.New("private key does not implement crypto.Signer"))
		}
	}

	ctx := context.Background()

	var input []byte

	switch *mode {
	case modeVerifyResponse, "verify-request", "verify-metadata":
		input = read(*in)
	}

	doc, err := process(ctx, *mode, input, cert, key, at)
	must(err)

	if *out != "" {
		encoded := input
		if doc != nil {
			encoded, err = doc.XML(ctx)
			must(err)
		}

		must(os.WriteFile(*out, encoded, 0o600))
	}

	fmt.Println("OK", *mode)
}

func process(ctx context.Context, mode string, input []byte, cert *x509.Certificate, key crypto.Signer, at time.Time) (*document.Document, error) {
	if cert == nil {
		return nil, errors.New("certificate is required")
	}

	method := xmldsig.ECDSASHA256
	if _, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		method = xmldsig.RSASHA256
	}

	const (
		sp   = "https://sp.example/metadata"
		idp  = "https://idp.example/metadata"
		acs  = "https://sp.example/acs"
		sso  = "https://idp.example/sso"
		auth = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	)

	signing := protocol.SigningKey{Key: key, CertificateDER: cert.Raw, SignatureMethod: method}

	switch mode {
	case "sign-response":
		return protocol.SignResponse(ctx, protocol.Response{ID: "_response", Issuer: idp, Audience: sp, Destination: acs, InResponseTo: nameRequest, IssueInstant: at, Assertion: protocol.AssertionData{ID: "_assertion", NameID: "alice@example.test", NameIDFormat: protocol.NameIDEmail, NotBefore: at.Add(-time.Minute), NotOnOrAfter: at.Add(5 * time.Minute), AuthnInstant: at.Add(-time.Second), AuthnContext: auth, SessionIndex: "session", Attributes: []protocol.Attribute{{Name: "role", Values: []string{"reader"}}}}}, signing)
	case "sign-request":
		return protocol.SignAuthnRequest(ctx, protocol.AuthnRequest{ID: nameRequest, Issuer: sp, Destination: sso, ACS: acs, IssueInstant: at, NameIDFormat: protocol.NameIDEmail, RequestedContexts: []string{auth}}, signing)
	case modeVerifyResponse, "verify-request":
		doc, err := document.Parse(ctx, input, document.DefaultLimits())
		if err != nil {
			return nil, err
		}

		if mode == modeVerifyResponse {
			_, err = protocol.VerifyResponse(ctx, doc, []crypto.PublicKey{cert.PublicKey}, protocol.ResponseOptions{Issuer: idp, Audience: sp, Destination: acs, ExpectedRequestID: nameRequest, At: at, ExpectedAuthnContexts: []string{auth}})
		} else {
			_, err = protocol.VerifyAuthnRequest(ctx, doc, []crypto.PublicKey{cert.PublicKey}, protocol.RequestOptions{Issuer: sp, Destination: sso, ACS: []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: acs, Index: 0, Indexed: true}}, At: at})
		}

		return doc, err
	case "sign-metadata":
		doc, err := metadata.Build(ctx, metadata.EntityDescriptor{ID: "_metadata", EntityID: sp, ValidUntil: at.Add(time.Hour), SP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{CertificateDER: cert.Raw, Use: "signing"}}, AuthnRequestsSigned: true, WantAssertionsSigned: true, Endpoints: map[string][]metadata.Endpoint{"AssertionConsumerService": {{Binding: metadata.HTTPPost, Location: acs, Index: 0, Indexed: true, Default: true}}}}}, at, metadata.Options{})
		if err != nil {
			return nil, err
		}

		return metadata.Sign(ctx, doc, key, cert.Raw, method, at, metadata.Options{})
	case "verify-metadata":
		verifier, err := metadata.NewVerifier(metadata.Config{TrustedKeys: []crypto.PublicKey{cert.PublicKey}, Options: metadata.Options{}})
		if err != nil {
			return nil, err
		}

		_, err = verifier.Verify(ctx, input, at)

		return nil, err
	default:
		return nil, errors.New("mode")
	}
}

func must(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func read(p string) []byte {
	b, e := os.ReadFile(p) // #nosec G304 -- The local interoperability harness supplies fixture paths.
	must(e)

	return b
}
